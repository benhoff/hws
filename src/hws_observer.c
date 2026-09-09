// SPDX-License-Identifier: GPL-2.0-only
#include <linux/io.h>
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <linux/string.h>

#include "hws.h"
#include "hws_stall.h"

static unsigned int irq_observer_run;
module_param(irq_observer_run, uint, 0644);
MODULE_PARM_DESC(irq_observer_run,
	"Opt-in: write a new nonzero run number to sample outside the IRQ handler; zero cancels");
static unsigned int irq_observer_channel = 1;
module_param(irq_observer_channel, uint, 0444);
MODULE_PARM_DESC(irq_observer_channel, "Channel for IRQ observer (default 1)");
static unsigned int irq_observer_ms = 15000;
module_param(irq_observer_ms, uint, 0444);
MODULE_PARM_DESC(irq_observer_ms,
	"Observer timeout, 100..30000 ms; finishes sooner after first duplicate (default 15000)");

void hws_irq_observer_stop(struct hws_pcie_dev *hws, const char *reason)
{
	struct hws_observer *o = &hws->irq_observer;
	u64 max_gap = 0;
	u32 i, pending_pairs = 0, toggle_pairs = 0, raced = 0;
	u32 bit;
	unsigned int first;

	if (!o->active)
		return;
	bit = HWS_INT_VDONE_BIT(irq_observer_channel);
	o->active = false;
	first = (o->head + HWS_OBSERVER_RECORDS - o->count) % HWS_OBSERVER_RECORDS;
	for (i = 0; i < o->count; i++) {
		const struct hws_observer_sample *s =
			&o->records[(first + i) % HWS_OBSERVER_RECORDS];

		raced += s->raced || s->generation_before != s->generation_after;
		if (i) {
			const struct hws_observer_sample *p =
				&o->records[(first + i - 1) % HWS_OBSERVER_RECORDS];

			if (s->end_ns >= p->begin_ns)
				max_gap = max(max_gap, s->end_ns - p->begin_ns);
			if (hws_observer_pair_valid(p, s, 4ULL * NSEC_PER_MSEC)) {
				pending_pairs += !!(p->status_before & p->status_after &
						   s->status_before & s->status_after & bit);
				toggle_pairs += (p->toggle & 1) != (s->toggle & 1);
			}
		}
	}
	dev_info(&hws->pdev->dev,
		 "IRQ observer end ch=%u run=%u epoch=%llu reason=%s triggered=%u samples=%u post_remaining=%u max_pair_span_ns=%llu raced=%u pending_pairs_no_record=%u toggle_changes_no_record=%u\n",
		 irq_observer_channel, o->run, o->epoch, reason, o->triggered, o->count,
		 o->post, max_gap, raced, pending_pairs, toggle_pairs);
	/* Emit the saved rows after sampling; normal monitor logs can still run. */
	for (i = 0; i < o->count; i++) {
		unsigned int index = (first + i) % HWS_OBSERVER_RECORDS;
		const struct hws_observer_sample *s = &o->records[index];

		dev_info(&hws->pdev->dev,
			 "IRQ observer sample ch=%u run=%u epoch=%llu index=%u trigger=%u begin_ns=%llu end_ns=%llu generation_before=%llu generation_after=%llu duplicates=%llu status_before=0x%08x toggle=0x%08x status_after=0x%08x raced=%u\n",
			 irq_observer_channel, o->run, o->epoch, i,
			 o->triggered && index == o->trigger_index,
			 s->begin_ns, s->end_ns, s->generation_before, s->generation_after,
			 s->duplicates, s->status_before, s->toggle, s->status_after, s->raced);
	}
}

bool hws_irq_observer_poll(struct hws_pcie_dev *hws)
{
	struct hws_observer *o = &hws->irq_observer;
	struct hws_observer_sample s = {};
	struct hws_video *v;
	unsigned long flags;
	u64 now = ktime_get_mono_fast_ns(), epoch, duplicates;
	u32 run = READ_ONCE(irq_observer_run);
	bool running, finished;

	lockdep_assert_held(&hws->monitor_lock);
	if (o->active && run != o->run)
		hws_irq_observer_stop(hws, "cancelled-or-rearmed");
	if (!o->active && (!run || run == o->last_run)) {
		o->last_run = run;
		return false;
	}
	if (irq_observer_channel >= hws->cur_max_video_ch) {
		o->last_run = run;
		dev_info(&hws->pdev->dev, "IRQ observer skipped ch=%u run=%u: channel unavailable\n",
			 irq_observer_channel, run);
		return false;
	}
	v = &hws->video[irq_observer_channel];
	spin_lock_irqsave(&v->irq_lock, flags);
	epoch = v->evidence_stream_epoch;
	duplicates = v->evidence_duplicate_reports + v->evidence_resync_reports;
	s.generation_before = v->next_completion_generation;
	running = READ_ONCE(v->cap_active) && !READ_ONCE(v->stop_requested);
	spin_unlock_irqrestore(&v->irq_lock, flags);
	if (!o->active) {
		o->last_run = run;
		if (!running || !epoch) {
			dev_info(&hws->pdev->dev, "IRQ observer skipped ch=%u run=%u: capture not running\n",
				 irq_observer_channel, run);
			return false;
		}
		memset(o, 0, sizeof(*o));
		o->run = o->last_run = run;
		o->epoch = epoch;
		o->baseline_duplicates = duplicates;
		o->started_ns = now;
		o->deadline_ns = now + (u64)clamp_t(unsigned int, irq_observer_ms, 100, 30000) * NSEC_PER_MSEC;
		o->active = true;
		dev_info(&hws->pdev->dev,
			 "IRQ observer begin ch=%u run=%u epoch=%llu timeout_ms=%u; read-only status/toggle polling, timing may be perturbed\n",
			 irq_observer_channel, run, epoch,
			 clamp_t(unsigned int, irq_observer_ms, 100, 30000));
	}
	if (!running || epoch != o->epoch || !hws->bar0_base ||
	    READ_ONCE(hws->pci_lost) || READ_ONCE(hws->suspended) || READ_ONCE(hws->dma_failed)) {
		hws_irq_observer_stop(hws, "stream-or-device-changed");
		return false;
	}
	if (now >= o->deadline_ns || now < o->started_ns) {
		hws_irq_observer_stop(hws, "timeout-or-clock-change");
		return false;
	}
	/* No spinlock is held across MMIO. Generation metadata brackets the
	 * reads to expose overlap with the normal IRQ path. No W1C writes or
	 * hws_read_toggle() calls (that helper can schedule device failure).
	 * monitor_lock and kthread teardown retain BAR lifetime, as for the
	 * normal format monitor. This does not open/reconfigure a video node.
	 */
	s.begin_ns = ktime_get_mono_fast_ns();
	s.status_before = readl(hws->bar0_base + HWS_REG_INT_STATUS);
	s.toggle = readl(hws->bar0_base + HWS_REG_VBUF_TOGGLE(irq_observer_channel));
	s.status_after = readl(hws->bar0_base + HWS_REG_INT_STATUS);
	s.end_ns = ktime_get_mono_fast_ns();
	spin_lock_irqsave(&v->irq_lock, flags);
	s.generation_after = v->next_completion_generation;
	s.duplicates = v->evidence_duplicate_reports + v->evidence_resync_reports;
	s.raced = v->evidence_stream_epoch != o->epoch ||
		!READ_ONCE(v->cap_active) || READ_ONCE(v->stop_requested);
	spin_unlock_irqrestore(&v->irq_lock, flags);
	if (s.status_before == U32_MAX || s.status_after == U32_MAX ||
	    s.toggle == U32_MAX || s.end_ns < s.begin_ns)
		s.raced = true;
	finished = hws_observer_append(o, &s);
	if (s.raced || finished) {
		hws_irq_observer_stop(hws, s.raced ? "invalid-or-raced-sample" : "duplicate-window-complete");
		return false;
	}
	return true;
}
