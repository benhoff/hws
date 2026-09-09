// SPDX-License-Identifier: GPL-2.0-only
#include <linux/io.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/moduleparam.h>
#include <linux/seq_file.h>

#include "hws.h"
#include "hws_stall.h"
#include "hws_stall_policy.h"

/* No timer/workqueue of our own: the existing monitor owns BAR lifetime. */
static unsigned int stall_timeout_ms = 2000;
module_param(stall_timeout_ms, uint, 0444);
MODULE_PARM_DESC(stall_timeout_ms,
	"Report stalled frame delivery after this many ms (1000..60000; 0 disables diagnostics)");
static unsigned int stall_heartbeat_ms = 30000;
module_param(stall_heartbeat_ms, uint, 0444);
MODULE_PARM_DESC(stall_heartbeat_ms,
	"Progress summary interval in ms (minimum 1000; 0 disables healthy summaries)");

struct hws_stall_snapshot {
	u64 now, epoch, start, sample, progress, report;
	u64 irq, accepted, delivered, frames, no_buffer, recoveries;
	u64 queue_empty, starved, orphaned;
	u64 duplicate, overlap_reports, continuity, failures;
	u64 irq_ns, pending_ns, generation, frame_generation;
	u64 delta_irq, delta_delivered, delta_recoveries;
	u32 queued, active, completion, phase, toggle, overlap;
	u32 deadlines, guards;
	bool streaming, capturing, stopping, half_valid, stalled;
};

static u64 hws_stall_timeout_ns(void)
{
	return stall_timeout_ms ?
		(u64)clamp_t(unsigned int, stall_timeout_ms, 1000, 60000) *
		NSEC_PER_MSEC : 0;
}

/* No state_lock: an ioctl holding it must not hide a capture stall. */
static void hws_stall_snapshot_locked(struct hws_video *v,
				      struct hws_stall_snapshot *s)
{
	lockdep_assert_held(&v->irq_lock);
	s->now = ktime_get_mono_fast_ns();
	s->epoch = v->evidence_stream_epoch;
	s->start = v->stall_start_ns;
	s->sample = v->stall_sample_ns;
	s->progress = v->stall_progress_ns;
	s->report = v->stall_report_ns;
	s->stalled = v->stall_reported;
	s->irq = v->evidence_vdone_observed;
	s->accepted = v->evidence_vdone_accepted;
	s->delivered = v->evidence_frames_delivered;
	s->frames = v->evidence_frames_completed;
	s->no_buffer = v->evidence_frames_no_buffer;
	s->queue_empty = v->evidence_queue_empty;
	s->starved = v->evidence_frames_starved;
	s->orphaned = v->evidence_frames_orphaned;
	s->recoveries = v->evidence_recovery_reports;
	s->duplicate = v->evidence_duplicate_reports;
	s->overlap_reports = v->evidence_overlap_reports;
	s->continuity = v->evidence_continuity_reports;
	s->failures = v->evidence_queue_failures;
	s->irq_ns = v->last_vdone_timestamp_ns;
	s->pending_ns = v->completion_timestamp_ns;
	s->generation = v->next_completion_generation;
	s->frame_generation = v->frame_generation;
	s->delta_irq = s->irq - v->stall_observed;
	s->delta_delivered = s->delivered - v->stall_delivered;
	s->delta_recoveries = s->recoveries - v->stall_recoveries;
	s->queued = v->queued_count;
	s->active = v->active ? v->active->vb.vb2_buf.index : U32_MAX;
	s->completion = v->completion_state;
	s->phase = v->half_phase;
	s->toggle = v->last_buf_half_toggle;
	s->overlap = v->overlap_events_pending;
	s->half_valid = v->frame_half0_valid;
	s->deadlines = v->deadline_misses;
	s->guards = v->guard_errors;
	s->streaming = vb2_is_streaming(&v->buffer_queue);
	s->capturing = READ_ONCE(v->cap_active);
	s->stopping = READ_ONCE(v->stop_requested);
}

static u64 age_ms(u64 now, u64 then)
{
	return div_u64(hws_stall_age(now, then), NSEC_PER_MSEC);
}

/* These are observations, not a claim that any single component is faulty. */
static const char *hws_stall_hint(const struct hws_stall_snapshot *s)
{
	if (!s->capturing || s->stopping)
		return "capture-disabled";
	if (hws_stall_age(s->now, s->irq_ns ? s->irq_ns : s->start) >=
	    hws_stall_timeout_ns())
		return "no-recent-vdone";
	if (s->completion != HWS_VIDEO_COMPLETION_IDLE && s->pending_ns &&
	    hws_stall_age(s->now, s->pending_ns) >= hws_stall_timeout_ns())
		return "completion-pending";
	if (!s->queued && s->active == U32_MAX)
		return "no-driver-buffers";
	if (s->delta_recoveries)
		return "recovering-without-delivery";
	return "no-frame-delivery";
}

static void hws_stall_log(struct hws_video *v, struct hws_stall_snapshot *s,
			  const char *event, bool detail)
{
	struct hws_pcie_dev *hws = v->parent;

	dev_info(&hws->pdev->dev,
		 "capture-diag %s ch=%d epoch=%llu mono_ns=%llu sample_ms=%llu delivery_idle_ms=%llu irq_age_ms=%llu irq=%llu accepted=%llu delivered=%llu frames=%llu no_buffer=%llu queue_empty=%llu starved=%llu orphaned=%llu recoveries=%llu delta_irq=%llu delta_delivered=%llu delta_recoveries=%llu\n",
		 event, v->channel_index, s->epoch, s->now,
		 age_ms(s->now, s->sample ? s->sample : s->start),
		 s->delta_delivered ? 0 : age_ms(s->now, s->progress),
		 age_ms(s->now, s->irq_ns ? s->irq_ns : s->start),
		 s->irq, s->accepted, s->delivered, s->frames, s->no_buffer,
		 s->queue_empty, s->starved, s->orphaned,
		 s->recoveries, s->delta_irq, s->delta_delivered, s->delta_recoveries);
	if (!detail)
		return;
	dev_info(&hws->pdev->dev,
		 "capture-diag state ch=%d epoch=%llu hint=%s stalled_ms=%llu streaming=%u cap_active=%u stop=%u queued=%u active=%u completion=%u pending_age_ms=%llu phase=%u half_valid=%u toggle=%u generation=%llu frame_generation=%llu overlap_pending=%u duplicate=%llu overlap=%llu continuity=%llu queue_failures=%llu deadlines=%u guards=%u state_lock_busy=%u source_status=%d source_change=%u pci_lost=%u dma_failed=%u\n",
		 v->channel_index, s->epoch, s->delta_delivered ? "progress" : hws_stall_hint(s),
		 age_ms(s->now, s->progress), s->streaming, s->capturing, s->stopping,
		 s->queued, s->active, s->completion,
		 s->pending_ns ? age_ms(s->now, s->pending_ns) : 0,
		 s->phase, s->half_valid, s->toggle, s->generation, s->frame_generation,
		 s->overlap, s->duplicate, s->overlap_reports, s->continuity,
		 s->failures, s->deadlines, s->guards,
		 mutex_is_locked(&v->state_lock), READ_ONCE(v->detected_dv_status),
		 READ_ONCE(v->source_change_pending), READ_ONCE(hws->pci_lost),
		 READ_ONCE(hws->dma_failed));
}

static void hws_stall_registers(struct hws_video *v, u64 epoch)
{
	struct hws_pcie_dev *hws = v->parent;
	u32 status, gate, control, capture, signal, toggle, split;

	lockdep_assert_held(&hws->monitor_lock);
	if (!hws->bar0_base || READ_ONCE(hws->suspended) ||
	    READ_ONCE(hws->pci_lost) || READ_ONCE(hws->dma_failed))
		return;
	/* Raw observational reads only: no acknowledgment, toggle helper with
	 * failure side effects, DMA memory access, or reset. Not an atomic image.
	 * A single toggle sample cannot prove whether DMA is advancing.
	 */
	status = readl(hws->bar0_base + HWS_REG_INT_STATUS);
	gate = readl(hws->bar0_base + INT_EN_REG_BASE);
	control = readl(hws->bar0_base + HWS_REG_CTL);
	capture = readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);
	signal = readl(hws->bar0_base + HWS_REG_ACTIVE_STATUS);
	toggle = readl(hws->bar0_base + HWS_REG_VBUF_TOGGLE(v->channel_index));
	split = readl(hws->bar0_base + HWS_REG_VIDEO_HALF_SIZE(v->channel_index));
	dev_info(&hws->pdev->dev,
		 "capture-diag registers ch=%d epoch=%llu irq=%d status=0x%08x gate=0x%08x control=0x%08x vcap=0x%08x signal=0x%08x toggle=0x%08x split16=0x%08x\n",
		 v->channel_index, epoch, hws->irq, status, gate, control,
		 capture, signal, toggle, split);
}

static void hws_duplicate_log(struct hws_video *v, bool ending)
{
	struct hws_irq_observation records[5];
	u64 now, epoch, window, suppressed, period, trigger;
	unsigned long flags;
	unsigned int count, i;

	spin_lock_irqsave(&v->irq_lock, flags);
	now = ktime_get_mono_fast_ns();
	count = v->duplicate_window_count;
	if (!v->duplicate_window_pending ||
	    (!ending && count < 5 &&
	     hws_stall_age(now, v->duplicate_window_ns) < 2ULL * NSEC_PER_SEC)) {
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return;
	}
	for (i = 0; i < count; i++)
		records[i] = v->duplicate_window[i];
	epoch = v->evidence_stream_epoch;
	window = v->duplicate_windows;
	suppressed = v->duplicate_suppressed;
	period = v->duplicate_window_period_ns;
	trigger = v->duplicate_window_ns;
	v->duplicate_window_pending = false;
	spin_unlock_irqrestore(&v->irq_lock, flags);

	dev_info(&v->parent->pdev->dev,
		 "VDONE context ch=%d epoch=%llu window=%llu trigger_ns=%llu expected_half_ns=%llu records=%u post_missing=%u suppressed=%llu\n",
		 v->channel_index, epoch, window, trigger, period, count,
		 5 - count, suppressed);
	for (i = 0; i < count; i++) {
		const struct hws_irq_observation *o = &records[i];
		u64 interval = i && records[i - 1].generation ?
			hws_stall_age(o->timestamp_ns, records[i - 1].timestamp_ns) : 0;

		if (!o->generation)
			continue; /* fewer than two preceding IRQs since STREAMON */
		dev_info(&v->parent->pdev->dev,
			 "VDONE sample ch=%d epoch=%llu window=%llu offset=%d generation=%llu ns=%llu interval_ns=%llu status=0x%08x ack_status=0x%08x before=%u after=%u previous=%u stable=%u reasserted=%u phase=%u completion=%u pending_ns=%llu queued=%u active=%u half_valid=%u result=%u ambiguity=%u\n",
			 v->channel_index, epoch, window, (int)i - 2,
			 o->generation, o->timestamp_ns, interval, o->status,
			 o->ack_status, o->before, o->after, o->previous, o->stable,
			 o->reasserted, o->phase, o->completion, o->pending_ns,
			 o->queued, o->active, o->half_valid, o->result, o->ambiguity);
	}
}

void hws_stall_monitor(struct hws_pcie_dev *hws)
{
	u64 timeout = hws_stall_timeout_ns();
	u64 heartbeat = stall_heartbeat_ms ?
		(u64)max(stall_heartbeat_ms, 1000U) * NSEC_PER_MSEC : 0;
	unsigned int ch;

	lockdep_assert_held(&hws->monitor_lock);
	if (!timeout)
		return;
	for (ch = 0; ch < hws->cur_max_video_ch; ch++) {
		struct hws_video *v = &hws->video[ch];
		struct hws_stall_snapshot s;
		enum hws_stall_event event;
		unsigned long flags;
		const char *name;

		hws_duplicate_log(v, false);
		spin_lock_irqsave(&v->irq_lock, flags);
		hws_stall_snapshot_locked(v, &s);
		if (!s.epoch || (!s.streaming && !s.capturing)) {
			spin_unlock_irqrestore(&v->irq_lock, flags);
			continue;
		}
		event = hws_stall_event(s.now, s.progress, s.report, timeout,
				       10ULL * NSEC_PER_SEC, heartbeat,
				       s.stalled, !!s.delta_delivered);
		v->stall_sample_ns = s.now;
		v->stall_observed = s.irq;
		v->stall_delivered = s.delivered;
		v->stall_recoveries = s.recoveries;
		if (s.delta_delivered) {
			v->stall_progress_ns = s.now;
			v->stall_reported = false;
		} else if (event == HWS_STALL_BEGIN) {
			v->stall_reported = true;
		}
		if (event != HWS_STALL_QUIET)
			v->stall_report_ns = s.now;
		spin_unlock_irqrestore(&v->irq_lock, flags);
		if (event == HWS_STALL_QUIET)
			continue;
		name = event == HWS_STALL_BEGIN ? "STALL" :
		       event == HWS_STALL_REPEAT ? "STILL-STALLED" :
		       event == HWS_STALL_RESUMED ? "RESUMED" : "progress";
		hws_stall_log(v, &s, name, event != HWS_STALL_HEARTBEAT);
		if (event == HWS_STALL_BEGIN || event == HWS_STALL_REPEAT)
			hws_stall_registers(v, s.epoch);
	}
}

void hws_stall_streamoff(struct hws_video *v)
{
	struct hws_stall_snapshot s;
	unsigned long flags;

	if (!hws_stall_timeout_ns())
		return;
	hws_duplicate_log(v, true);
	spin_lock_irqsave(&v->irq_lock, flags);
	hws_stall_snapshot_locked(v, &s);
	spin_unlock_irqrestore(&v->irq_lock, flags);
	if (s.epoch)
		hws_stall_log(v, &s, "STREAMOFF", true);
}

int hws_stall_show(struct seq_file *m, void *unused)
{
	struct hws_video *v = m->private;
	struct hws_stall_snapshot s;
	unsigned long flags;

	spin_lock_irqsave(&v->irq_lock, flags);
	hws_stall_snapshot_locked(v, &s);
	spin_unlock_irqrestore(&v->irq_lock, flags);
	/* CPU state only, safe even if an open debugfs FD outlives removal. */
#define SHOW(field) seq_printf(m, #field "=%llu\n", (unsigned long long)s.field)
	SHOW(now); SHOW(epoch); SHOW(start); SHOW(sample); SHOW(progress); SHOW(report);
	SHOW(stalled); SHOW(streaming); SHOW(capturing); SHOW(stopping);
	SHOW(irq); SHOW(accepted); SHOW(delivered); SHOW(frames); SHOW(no_buffer);
	SHOW(queue_empty); SHOW(starved); SHOW(orphaned);
	SHOW(recoveries); SHOW(duplicate); SHOW(overlap_reports); SHOW(continuity);
	SHOW(failures); SHOW(irq_ns); SHOW(pending_ns); SHOW(generation);
	SHOW(frame_generation); SHOW(queued); SHOW(active); SHOW(completion);
	SHOW(phase); SHOW(toggle); SHOW(overlap); SHOW(half_valid);
#undef SHOW
	seq_printf(m, "timeout_ms=%llu\n", div_u64(hws_stall_timeout_ns(), NSEC_PER_MSEC));
	return 0;
}
