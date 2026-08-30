// SPDX-License-Identifier: GPL-2.0-only
#include <linux/compiler.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/minmax.h>
#include <linux/string.h>

#include "hws_irq.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws.h"
#include "hws_audio.h"

#define MAX_INT_LOOPS 100
/* Characterized minimum reuse was 7,950 us at 1080p60. */
#define HWS_VIDEO_COPY_DEADLINE_NS (7500ULL * NSEC_PER_USEC)
#define HWS_VIDEO_REUSE_MARGIN_NS  (500ULL * NSEC_PER_USEC)
#define HWS_VIDEO_SYNC_EVENTS 2

struct hws_vdone_event {
	u64 timestamp_ns;
	u64 deadline_ns;
	u64 generation;
	u8 toggle;
};

enum hws_vdone_record_result {
	HWS_VDONE_IGNORED,
	HWS_VDONE_QUEUED,
	HWS_VDONE_OVERRUN,
};

enum hws_vdone_ambiguity {
	HWS_VDONE_AMBIG_NONE,
	HWS_VDONE_AMBIG_INFLIGHT,
	HWS_VDONE_AMBIG_DUPLICATE,
	HWS_VDONE_AMBIG_TIMESTAMP,
	HWS_VDONE_AMBIG_CADENCE,
};

static u64 hws_video_phase_period_ns(const struct hws_video *v)
{
	u32 fps = READ_ONCE(v->current_fps);

	if (!fps || fps > 240)
		return 0;
	return div_u64(NSEC_PER_SEC, (u64)fps * 2);
}

static u64 hws_video_copy_deadline_ns(const struct hws_video *v)
{
	u64 period_ns = hws_video_phase_period_ns(v);

	if (!period_ns || period_ns <= HWS_VIDEO_REUSE_MARGIN_NS)
		return 0;
	/* Faster modes get a tighter limit than the characterized 7.5 ms. */
	return min_t(u64, HWS_VIDEO_COPY_DEADLINE_NS,
		     period_ns - HWS_VIDEO_REUSE_MARGIN_NS);
}

static bool hws_video_deadline_expired(u64 deadline_ns, u64 irq_ns,
				       u64 now_ns)
{
	return !deadline_ns || !irq_ns || now_ns < irq_ns ||
	       now_ns - irq_ns >= deadline_ns;
}

static bool hws_video_cadence_ambiguous(const struct hws_video *v,
					u64 previous_ns, u64 current_ns)
{
	u64 period_ns = hws_video_phase_period_ns(v);
	u64 interval_ns;

	if (!period_ns || !previous_ns || current_ns <= previous_ns)
		return true;
	interval_ns = current_ns - previous_ns;
	/* Match the diagnostic's 2/3-to-3/2 cadence acceptance window. */
	return interval_ns > period_ns + period_ns / 2 ||
	       interval_ns + interval_ns / 2 < period_ns;
}

static const char *
hws_vdone_ambiguity_name(enum hws_vdone_ambiguity ambiguity)
{
	switch (ambiguity) {
	case HWS_VDONE_AMBIG_INFLIGHT:
		return "completion still pending";
	case HWS_VDONE_AMBIG_DUPLICATE:
		return "duplicate toggle after W1C coalescing";
	case HWS_VDONE_AMBIG_TIMESTAMP:
		return "non-monotonic completion timestamp";
	case HWS_VDONE_AMBIG_CADENCE:
		return "completion cadence outside half-period bounds";
	case HWS_VDONE_AMBIG_NONE:
	default:
		return "none";
	}
}

static void hws_irq_reset_completion_locked(struct hws_video *v)
{
	lockdep_assert_held(&v->irq_lock);

	v->completion_state = HWS_VIDEO_COMPLETION_IDLE;
	v->completion_timestamp_ns = 0;
	v->completion_deadline_ns = 0;
	v->completion_generation = 0;
	v->completion_toggle = 0;
}

static void hws_irq_mark_failure_locked(struct hws_video *v, int ret)
{
	lockdep_assert_held(&v->irq_lock);

	if (v->completion_state != HWS_VIDEO_COMPLETION_OVERRUN) {
		v->completion_overruns++;
		v->error_count++;
	}
	if (ret == -ETIME) {
		v->deadline_misses++;
		v->timeout_count++;
	} else if (ret == -EILSEQ || ret == -EOVERFLOW) {
		v->phase_errors++;
	} else if (ret == -EBADMSG) {
		v->copy_mismatches++;
	} else if (ret == -EUCLEAN) {
		v->guard_errors++;
		WRITE_ONCE(v->ring_corrupt, true);
	}
	v->completion_state = HWS_VIDEO_COMPLETION_OVERRUN;
}

static struct hwsvideo_buffer *
hws_irq_take_queued_buffer_locked(struct hws_video *v)
{
	struct hwsvideo_buffer *buf;

	lockdep_assert_held(&v->irq_lock);
	if (list_empty(&v->capture_queue))
		return NULL;

	buf = list_first_entry(&v->capture_queue, struct hwsvideo_buffer, list);
	list_del_init(&buf->list);
	if (v->queued_count)
		v->queued_count--;
	return buf;
}

static int hws_video_copy_completed_half(struct hws_video *v,
					 const struct hws_vdone_event *event,
					 struct hwsvideo_buffer **done)
{
	struct hws_pcie_dev *hws = v->parent;
	unsigned int ch = v->channel_index;
	struct hwsvideo_buffer *buf;
	struct vb2_v4l2_buffer *vb2v;
	unsigned long flags;
	void *ring;
	void *dst;
	size_t offset;
	size_t length;
	u8 completed_half = event->toggle ^ 1;
	u8 toggle_after_copy;
	u8 toggle_after_verify;
	u8 live_toggle;
	u64 verify_ns;
	bool skip_copy = false;

	*done = NULL;
	if (hws_video_deadline_expired(event->deadline_ns, event->timestamp_ns,
				       ktime_get_mono_fast_ns()))
		return -ETIME;
	ring = hws_video_ring_cpu(hws, ch);
	if (!ring || !v->ring_split || v->ring_split >= v->pix.sizeimage ||
	    v->ring_extent < v->pix.sizeimage)
		return -ENODEV;

	live_toggle = readl_relaxed(hws->bar0_base +
				    HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
	if (live_toggle != event->toggle)
		return -EOVERFLOW;

	/* Establish steady-state cadence before accepting an assembly half. */
	spin_lock_irqsave(&v->irq_lock, flags);
	if (v->completion_state != HWS_VIDEO_COMPLETION_COPYING ||
	    v->completion_generation != event->generation) {
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return -EOVERFLOW;
	}
	if (v->half_phase == HWS_VIDEO_PHASE_SYNC) {
		if (v->phase_generation &&
		    event->generation != v->phase_generation + 1) {
			spin_unlock_irqrestore(&v->irq_lock, flags);
			return -EILSEQ;
		}
		v->phase_generation = event->generation;
		v->sync_events++;
		if (v->sync_events >= HWS_VIDEO_SYNC_EVENTS)
			v->half_phase = completed_half ?
				HWS_VIDEO_PHASE_EXPECT_HALF0 :
				HWS_VIDEO_PHASE_EXPECT_HALF1;
		skip_copy = true;
		buf = NULL;
	} else if ((!completed_half &&
		    v->half_phase != HWS_VIDEO_PHASE_EXPECT_HALF0) ||
		   (completed_half &&
		    v->half_phase != HWS_VIDEO_PHASE_EXPECT_HALF1) ||
		   !v->phase_generation ||
		   event->generation != v->phase_generation + 1) {
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return -EILSEQ;
	} else if (!completed_half) {
		if (v->active || v->frame_half0_valid) {
			spin_unlock_irqrestore(&v->irq_lock, flags);
			return -EILSEQ;
		}
		v->phase_generation = event->generation;
		v->half_phase = HWS_VIDEO_PHASE_EXPECT_HALF1;
		buf = hws_irq_take_queued_buffer_locked(v);
		if (!buf) {
			v->frame_generation = 0;
			v->frame_timestamp_ns = 0;
			skip_copy = true;
		} else {
			v->active = buf;
			v->frame_generation = event->generation;
			v->frame_half0_valid = false;
			v->frame_timestamp_ns = event->timestamp_ns;
		}
	} else {
		v->phase_generation = event->generation;
		v->half_phase = HWS_VIDEO_PHASE_EXPECT_HALF0;
		if (!v->active) {
			if (v->frame_half0_valid || v->frame_generation) {
				spin_unlock_irqrestore(&v->irq_lock, flags);
				return -EILSEQ;
			}
			skip_copy = true;
			buf = NULL;
		} else {
			if (!v->frame_half0_valid || !v->frame_generation ||
			    event->generation != v->frame_generation + 1) {
				spin_unlock_irqrestore(&v->irq_lock, flags);
				return -EILSEQ;
			}
			buf = v->active;
		}
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);
	if (skip_copy)
		goto verify_phase;

	vb2v = &buf->vb;
	if (vb2_plane_size(&vb2v->vb2_buf, 0) < v->pix.sizeimage)
		return -EMSGSIZE;
	dst = vb2_plane_vaddr(&vb2v->vb2_buf, 0);
	if (!dst)
		return -EFAULT;
	offset = completed_half ? v->ring_split : 0;
	length = completed_half ? v->pix.sizeimage - v->ring_split :
				  v->ring_split;

	dma_rmb();
	memcpy((u8 *)dst + offset, (u8 *)ring + offset, length);
	dma_rmb();
	toggle_after_copy = readl_relaxed(hws->bar0_base +
					  HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
	if (memcmp((u8 *)dst + offset, (u8 *)ring + offset, length))
		return -EBADMSG;
	verify_ns = ktime_get_mono_fast_ns();
	toggle_after_verify = readl_relaxed(hws->bar0_base +
					    HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
	if (toggle_after_copy != event->toggle ||
	    toggle_after_verify != event->toggle)
		return -EOVERFLOW;
	if (hws_video_deadline_expired(event->deadline_ns,
				       event->timestamp_ns, verify_ns))
		return -ETIME;

verify_phase:
	verify_ns = ktime_get_mono_fast_ns();
	live_toggle = readl_relaxed(hws->bar0_base +
				    HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
	if (live_toggle != event->toggle)
		return -EOVERFLOW;
	if (hws_video_deadline_expired(event->deadline_ns,
				       event->timestamp_ns, verify_ns))
		return -ETIME;
	if (!hws_video_ring_guards_ok(hws, ch, v->ring_extent))
		return -EUCLEAN;
	if (skip_copy)
		return 0;

	spin_lock_irqsave(&v->irq_lock, flags);
	if (v->completion_state != HWS_VIDEO_COMPLETION_COPYING ||
	    v->completion_generation != event->generation ||
	    v->active != buf) {
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return -EOVERFLOW;
	}
	if (!completed_half) {
		if (v->frame_generation != event->generation ||
		    v->half_phase != HWS_VIDEO_PHASE_EXPECT_HALF1) {
			spin_unlock_irqrestore(&v->irq_lock, flags);
			return -EILSEQ;
		}
		v->frame_half0_valid = true;
	} else {
		if (!v->frame_half0_valid ||
		    event->generation != v->frame_generation + 1 ||
		    v->half_phase != HWS_VIDEO_PHASE_EXPECT_HALF0) {
			spin_unlock_irqrestore(&v->irq_lock, flags);
			return -EILSEQ;
		}
		/*
		 * Keep the assembled buffer attached until the caller rechecks the
		 * event state. A hard IRQ can report an overrun while this copy is
		 * running, in which case STREAMOFF must still be able to return it.
		 */
		*done = buf;
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);
	return 0;
}

static void hws_video_handle_vdone(struct hws_video *v)
{
	struct hws_pcie_dev *hws = v->parent;
	unsigned int ch = v->channel_index;
	struct hws_vdone_event event = { };
	struct hwsvideo_buffer *done = NULL;
	unsigned long flags;
	bool abort = false;
	bool fail = false;
	int ret = 0;

	spin_lock_irqsave(&v->irq_lock, flags);
	if (v->completion_state == HWS_VIDEO_COMPLETION_OVERRUN) {
		event.timestamp_ns = v->completion_timestamp_ns;
		event.deadline_ns = v->completion_deadline_ns;
		event.generation = v->completion_generation;
		event.toggle = v->completion_toggle;
		ret = -EOVERFLOW;
		fail = true;
	} else if (v->completion_state != HWS_VIDEO_COMPLETION_PENDING) {
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return;
	} else {
		event.timestamp_ns = v->completion_timestamp_ns;
		event.deadline_ns = v->completion_deadline_ns;
		event.generation = v->completion_generation;
		event.toggle = v->completion_toggle;
		v->completion_state = HWS_VIDEO_COMPLETION_COPYING;
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	if (fail)
		goto fail_queue;
	if (READ_ONCE(hws->suspended) || READ_ONCE(v->stop_requested) ||
	    !READ_ONCE(v->cap_active)) {
		spin_lock_irqsave(&v->irq_lock, flags);
		if (v->completion_state == HWS_VIDEO_COMPLETION_COPYING &&
		    v->completion_generation == event.generation)
			hws_irq_reset_completion_locked(v);
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return;
	}

	ret = hws_video_copy_completed_half(v, &event, &done);

	spin_lock_irqsave(&v->irq_lock, flags);
	if (v->completion_state == HWS_VIDEO_COMPLETION_OVERRUN) {
		fail = true;
	} else if (READ_ONCE(hws->suspended) ||
		   READ_ONCE(v->stop_requested) ||
		   !READ_ONCE(v->cap_active)) {
		hws_irq_reset_completion_locked(v);
		abort = true;
	} else {
		if (!ret &&
		    hws_video_deadline_expired(event.deadline_ns,
					       event.timestamp_ns,
					       ktime_get_mono_fast_ns()))
			ret = -ETIME;
		if (!ret &&
		    (v->completion_state != HWS_VIDEO_COMPLETION_COPYING ||
		     v->completion_generation != event.generation))
			ret = -EILSEQ;
		if (!ret && done &&
		    (v->active != done || !v->frame_half0_valid ||
		     event.generation != v->frame_generation + 1))
			ret = -EILSEQ;
		if (ret) {
			hws_irq_mark_failure_locked(v, ret);
			fail = true;
		} else if (done) {
			v->active = NULL;
			v->frame_generation = 0;
			v->frame_half0_valid = false;
			done->vb.vb2_buf.timestamp = v->frame_timestamp_ns;
			v->frame_timestamp_ns = 0;
			vb2_set_plane_payload(&done->vb.vb2_buf, 0,
					      v->pix.sizeimage);
			done->vb.field = v->pix.field;
			done->vb.sequence =
				(u32)atomic_fetch_inc(&v->sequence_number);
		}
		if (!fail)
			hws_irq_reset_completion_locked(v);
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	if (abort)
		return;
	if (fail)
		goto fail_queue;

	if (done) {
		dev_dbg(&hws->pdev->dev,
			"bh_video(ch=%u): assembled buf=%p generation=%llu toggle=%u seq=%u\n",
			ch, done, (unsigned long long)event.generation,
			event.toggle, done->vb.sequence);
		vb2_buffer_done(&done->vb.vb2_buf, VB2_BUF_STATE_DONE);
	}
	return;

fail_queue:
	{
		u64 now_ns = ktime_get_mono_fast_ns();
		u64 elapsed_us = event.timestamp_ns && now_ns >= event.timestamp_ns ?
			div_u64(now_ns - event.timestamp_ns, NSEC_PER_USEC) : 0;

		dev_err_ratelimited(&hws->pdev->dev,
			"VDONE half-ring failure ch=%u generation=%llu toggle=%u phase=%u elapsed=%lluus ret=%d ambiguity=%u phase_errors=%u deadlines=%u mismatches=%u guards=%u\n",
			ch, (unsigned long long)event.generation,
			event.toggle, READ_ONCE(v->half_phase),
			(unsigned long long)elapsed_us, ret,
			READ_ONCE(v->w1c_ambiguities),
			READ_ONCE(v->phase_errors),
			READ_ONCE(v->deadline_misses),
			READ_ONCE(v->copy_mismatches),
			READ_ONCE(v->guard_errors));
	}
	hws_video_fail_queue(v,
		"ambiguous VDONE phase, generation, copy, guard, or deadline");
}

static void hws_irq_ack_status(struct hws_pcie_dev *pdx, u32 int_state)
{
	if (!int_state || !pdx || !pdx->bar0_base)
		return;

	writel(int_state, pdx->bar0_base + HWS_REG_INT_STATUS);
	(void)readl(pdx->bar0_base + HWS_REG_INT_STATUS);
}

static void hws_irq_queue_vdone_work(struct hws_pcie_dev *pdx,
				     unsigned int ch)
{
	unsigned long flags;

	if (!pdx || ch >= MAX_VID_CHANNELS)
		return;

	spin_lock_irqsave(&pdx->irq_thread_lock, flags);
	pdx->irq_pending_vdone[ch] = true;
	spin_unlock_irqrestore(&pdx->irq_thread_lock, flags);
}

static enum hws_vdone_record_result
hws_irq_record_vdone(struct hws_pcie_dev *pdx, unsigned int ch, u8 toggle,
		     u64 timestamp_ns)
{
	struct hws_video *v;
	unsigned long flags;
	enum hws_vdone_ambiguity ambiguity = HWS_VDONE_AMBIG_NONE;
	enum hws_vdone_record_result result;
	u64 generation = 0;
	u64 previous_ns = 0;

	if (!pdx || ch >= MAX_VID_CHANNELS)
		return HWS_VDONE_IGNORED;

	v = &pdx->video[ch];
	spin_lock_irqsave(&v->irq_lock, flags);
	if (!READ_ONCE(v->cap_active) || READ_ONCE(v->stop_requested)) {
		result = HWS_VDONE_IGNORED;
	} else {
		v->next_completion_generation++;
		if (!v->next_completion_generation)
			v->next_completion_generation++;
		generation = v->next_completion_generation;
		previous_ns = v->last_vdone_timestamp_ns;

		if (v->completion_state != HWS_VIDEO_COMPLETION_IDLE)
			ambiguity = HWS_VDONE_AMBIG_INFLIGHT;
		else if (v->half_seen && timestamp_ns <= previous_ns)
			ambiguity = HWS_VDONE_AMBIG_TIMESTAMP;
		else if (v->half_seen &&
			 toggle == v->last_buf_half_toggle)
			ambiguity = HWS_VDONE_AMBIG_DUPLICATE;
		else if (v->half_seen &&
			 hws_video_cadence_ambiguous(v, previous_ns,
						     timestamp_ns))
			ambiguity = HWS_VDONE_AMBIG_CADENCE;

		v->completion_timestamp_ns = timestamp_ns;
		v->completion_deadline_ns = hws_video_copy_deadline_ns(v);
		v->completion_generation = generation;
		v->completion_toggle = toggle;
		if (ambiguity != HWS_VDONE_AMBIG_NONE) {
			hws_irq_mark_failure_locked(v, -EOVERFLOW);
			v->w1c_ambiguities++;
			WRITE_ONCE(v->stop_requested, true);
			WRITE_ONCE(v->cap_active, false);
			result = HWS_VDONE_OVERRUN;
		} else {
			v->completion_state = HWS_VIDEO_COMPLETION_PENDING;
			WRITE_ONCE(v->last_buf_half_toggle, toggle);
			WRITE_ONCE(v->half_seen, true);
			WRITE_ONCE(v->last_vdone_timestamp_ns, timestamp_ns);
			result = HWS_VDONE_QUEUED;
		}
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	if (result == HWS_VDONE_OVERRUN) {
		u64 interval_us = timestamp_ns > previous_ns ?
			div_u64(timestamp_ns - previous_ns, NSEC_PER_USEC) : 0;

		hws_enable_video_capture(pdx, ch, false);
		dev_err_ratelimited(&pdx->pdev->dev,
				    "VDONE ambiguity ch=%u generation=%llu toggle=%u interval=%lluus: %s\n",
				    ch, (unsigned long long)generation, toggle,
				    (unsigned long long)interval_us,
				    hws_vdone_ambiguity_name(ambiguity));
	}
	if (result != HWS_VDONE_IGNORED)
		hws_irq_queue_vdone_work(pdx, ch);

	return result;
}

static bool hws_irq_take_vdone(struct hws_pcie_dev *pdx, unsigned int *ch)
{
	unsigned long flags;
	unsigned int i;

	if (!pdx || !ch)
		return false;

	spin_lock_irqsave(&pdx->irq_thread_lock, flags);
	for (i = 0; i < pdx->cur_max_video_ch && i < MAX_VID_CHANNELS; i++) {
		if (pdx->irq_pending_vdone[i]) {
			pdx->irq_pending_vdone[i] = false;
			*ch = i;
			spin_unlock_irqrestore(&pdx->irq_thread_lock, flags);
			return true;
		}
	}
	spin_unlock_irqrestore(&pdx->irq_thread_lock, flags);
	return false;
}

static bool hws_irq_queue_video(struct hws_pcie_dev *pdx, u32 int_state,
				u64 timestamp_ns)
{
	bool wake_thread = false;
	unsigned int ch;

	for (ch = 0; ch < pdx->cur_max_video_ch; ++ch) {
		u32 vbit = HWS_INT_VDONE_BIT(ch);
		enum hws_vdone_record_result result;
		u8 toggle;

		if (!(int_state & vbit))
			continue;

		if (READ_ONCE(pdx->video[ch].cap_active) &&
		    !READ_ONCE(pdx->video[ch].stop_requested)) {
			toggle = readl_relaxed(pdx->bar0_base +
					       HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
			result = hws_irq_record_vdone(pdx, ch, toggle,
						      timestamp_ns);
			if (result != HWS_VDONE_IGNORED)
				wake_thread = true;
			if (result == HWS_VDONE_QUEUED)
				dev_dbg(&pdx->pdev->dev,
					"irq: VDONE ch=%u identity queued toggle=%u\n",
					ch, toggle);
		} else {
			dev_dbg(&pdx->pdev->dev,
				"irq: VDONE ch=%u ignored (cap=%d stop=%d)\n",
				ch,
				READ_ONCE(pdx->video[ch].cap_active),
				READ_ONCE(pdx->video[ch].stop_requested));
		}
	}

	return wake_thread;
}

static void hws_irq_handle_audio(struct hws_pcie_dev *pdx, u32 int_state)
{
	unsigned int ch;

	for (ch = 0; ch < pdx->cur_max_audio_ch; ++ch) {
		u32 abit = HWS_INT_ADONE_BIT(ch);
		u8 cur_toggle;

		if (!(int_state & abit))
			continue;

		/* Only service running streams */
		if (!READ_ONCE(pdx->audio[ch].cap_active) ||
		    !READ_ONCE(pdx->audio[ch].stream_running) ||
		    READ_ONCE(pdx->audio[ch].stop_requested))
			continue;

		/*
		 * Baseline read ABUF_TOGGLE for every ADONE interrupt.
		 * The register reports the half the device is filling now, so
		 * the completed packet is the opposite half. Read it in the
		 * hard handler so the deferred audio work receives the edge's
		 * toggle value, not a later one.
		 */
		cur_toggle = readl_relaxed(pdx->bar0_base +
					   HWS_REG_ABUF_TOGGLE(ch)) & 0x01;
		hws_audio_queue_interrupt(pdx, ch, cur_toggle);
	}
}

irqreturn_t hws_irq_handler(int irq, void *info)
{
	struct hws_pcie_dev *pdx = info;
	u64 timestamp_ns;
	u32 int_state;
	bool wake_thread;

	(void)irq;

	if (!pdx || READ_ONCE(pdx->suspended) || !pdx->bar0_base)
		return IRQ_NONE;

	dev_dbg(&pdx->pdev->dev, "irq: entry\n");
	dev_dbg(&pdx->pdev->dev,
		"irq: INT_EN=0x%08x INT_STATUS=0x%08x\n",
		readl(pdx->bar0_base + INT_EN_REG_BASE),
		readl(pdx->bar0_base + HWS_REG_INT_STATUS));
	int_state = readl_relaxed(pdx->bar0_base + HWS_REG_INT_STATUS);
	if (!int_state || int_state == 0xFFFFFFFF) {
		dev_dbg(&pdx->pdev->dev,
			"irq: spurious or device-gone int_state=0x%08x\n",
			int_state);
		return IRQ_NONE;
	}
	timestamp_ns = ktime_get_mono_fast_ns();
	dev_dbg(&pdx->pdev->dev, "irq: entry INT_STATUS=0x%08x\n", int_state);

	wake_thread = hws_irq_queue_video(pdx, int_state, timestamp_ns);
	hws_irq_handle_audio(pdx, int_state);
	hws_irq_ack_status(pdx, int_state);

	return wake_thread ? IRQ_WAKE_THREAD : IRQ_HANDLED;
}

irqreturn_t hws_irq_thread(int irq, void *info)
{
	struct hws_pcie_dev *pdx = info;
	unsigned int ch;
	unsigned int count = 0;
	bool handled = false;

	(void)irq;

	if (!pdx || !pdx->bar0_base)
		return IRQ_NONE;

	while (hws_irq_take_vdone(pdx, &ch)) {
		handled = true;
		if (READ_ONCE(pdx->suspended))
			continue;

		hws_video_handle_vdone(&pdx->video[ch]);
		count++;
		if (count == MAX_INT_LOOPS)
			dev_warn_ratelimited(&pdx->pdev->dev,
					     "threaded IRQ processing many VDONE events\n");
	}

	return handled ? IRQ_HANDLED : IRQ_NONE;
}
