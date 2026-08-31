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

/* Characterized minimum reuse was 7,950 us at 1080p60. */
#define HWS_VIDEO_COPY_DEADLINE_NS (7500ULL * NSEC_PER_USEC)
#define HWS_VIDEO_REUSE_MARGIN_NS  (500ULL * NSEC_PER_USEC)
#define HWS_VIDEO_SYNC_EVENTS 8

struct hws_vdone_event {
	u64 timestamp_ns;
	u64 deadline_ns;
	u64 generation;
	u8 toggle;
};

struct hws_vdone_toggle_sample {
	u8 before_ack;
	u8 after_ack;
	bool post_ack_stable;
	bool status_reasserted;
};

struct hws_adone_toggle_sample {
	u8 before_ack;
	u8 after_ack;
	bool post_ack_stable;
	bool status_reasserted;
};

enum hws_vdone_record_result {
	HWS_VDONE_IGNORED,
	HWS_VDONE_QUEUED,
	HWS_VDONE_RESYNCED,
	HWS_VDONE_RECOVERED,
	HWS_VDONE_DEFERRED,
	HWS_VDONE_OVERRUN,
};

enum hws_vdone_ambiguity {
	HWS_VDONE_AMBIG_NONE,
	HWS_VDONE_AMBIG_INFLIGHT,
	HWS_VDONE_AMBIG_DUPLICATE,
	HWS_VDONE_AMBIG_TIMESTAMP,
	HWS_VDONE_AMBIG_TOGGLE_UNSTABLE,
	HWS_VDONE_AMBIG_STATUS_REASSERTED,
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
	case HWS_VDONE_AMBIG_TOGGLE_UNSTABLE:
		return "post-W1C toggle sample was unstable";
	case HWS_VDONE_AMBIG_STATUS_REASSERTED:
		return "VDONE reasserted during W1C acknowledgment";
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

static void hws_irq_clear_overlap_locked(struct hws_video *v)
{
	lockdep_assert_held(&v->irq_lock);

	v->overlap_pending = false;
	v->overlap_toggle = 0;
	v->overlap_events_pending = 0;
	v->overlap_timestamp_ns = 0;
	v->overlap_generation = 0;
}

static bool hws_irq_recover_phase_locked(struct hws_video *v, u64 generation,
					 u64 timestamp_ns, u8 toggle)
{
	bool dropped_partial = !!v->active;

	lockdep_assert_held(&v->irq_lock);
	if (v->active) {
		/*
		 * The buffer remains driver-owned. Put it first so a later verified
		 * half pair overwrites both halves before userspace can dequeue it.
		 */
		list_add(&v->active->list, &v->capture_queue);
		v->queued_count++;
	}
	v->active = NULL;
	v->frame_generation = 0;
	v->frame_half0_valid = false;
	/* The next changed toggle completes the half named by this toggle. */
	v->half_phase = toggle ? HWS_VIDEO_PHASE_EXPECT_HALF1 :
				       HWS_VIDEO_PHASE_EXPECT_HALF0;
	v->sync_events = 0;
	v->phase_generation = generation;
	hws_irq_reset_completion_locked(v);
	WRITE_ONCE(v->last_buf_half_toggle, toggle);
	WRITE_ONCE(v->half_seen, true);
	WRITE_ONCE(v->last_vdone_timestamp_ns, timestamp_ns);
	return dropped_partial;
}

static bool hws_video_copy_error_recoverable(int ret)
{
	return ret == -ETIME || ret == -EILSEQ || ret == -EOVERFLOW;
}

static void
hws_vdone_note_recovery_locked(struct hws_video *v, u64 generation,
			       u64 interval_us, u8 toggle, u8 attempt,
			       enum hws_vdone_ambiguity reason,
			       bool dropped_partial, bool steady, u32 reports);

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
					 struct hwsvideo_buffer **done,
					 bool *frame_complete)
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
	u8 live_toggle;
	u64 verify_ns;
	bool completes_frame = false;
	bool skip_copy = false;

	*done = NULL;
	*frame_complete = false;
	if (hws_video_deadline_expired(event->deadline_ns, event->timestamp_ns,
				       ktime_get_mono_fast_ns()))
		return -ETIME;
	ring = hws_video_ring_cpu(hws, ch);
	if (!ring || !v->ring_split || v->ring_split >= v->pix.sizeimage ||
	    v->ring_extent < v->pix.sizeimage)
		return -ENODEV;

	live_toggle = readl(hws->bar0_base + HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
	if (live_toggle != event->toggle)
		return -EOVERFLOW;

	/* Establish steady-state phase before accepting an assembly half. */
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
		if (v->sync_events >= HWS_VIDEO_SYNC_EVENTS) {
			v->half_phase = completed_half ?
				HWS_VIDEO_PHASE_EXPECT_HALF0 :
				HWS_VIDEO_PHASE_EXPECT_HALF1;
			v->sync_restart_streak = 0;
		}
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
			skip_copy = true;
		} else {
			v->active = buf;
			v->frame_generation = event->generation;
			v->frame_half0_valid = false;
		}
	} else {
		completes_frame = true;
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
	toggle_after_copy = readl(hws->bar0_base +
				  HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
	verify_ns = ktime_get_mono_fast_ns();
	if (toggle_after_copy != event->toggle)
		return -EOVERFLOW;
	if (hws_video_deadline_expired(event->deadline_ns,
				       event->timestamp_ns, verify_ns))
		return -ETIME;

verify_phase:
	verify_ns = ktime_get_mono_fast_ns();
	live_toggle = readl(hws->bar0_base + HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
	if (live_toggle != event->toggle)
		return -EOVERFLOW;
	if (hws_video_deadline_expired(event->deadline_ns,
				       event->timestamp_ns, verify_ns))
		return -ETIME;
	if (!hws_video_ring_guards_ok(hws, ch, v->ring_extent))
		return -EUCLEAN;
	if (skip_copy) {
		*frame_complete = completes_frame;
		return 0;
	}

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
	*frame_complete = completes_frame;
	return 0;
}

static void hws_video_handle_vdone(struct hws_video *v)
{
	struct hws_pcie_dev *hws = v->parent;
	unsigned int ch = v->channel_index;
	struct hws_vdone_event event = { };
	struct hwsvideo_buffer *done = NULL;
	unsigned long flags;
	u64 recovery_generation = 0;
	u64 recovery_timestamp_ns = 0;
	u64 recovery_interval_us = 0;
	u32 recovery_reports = 0;
	u32 frame_sequence = 0;
	u8 recovery_toggle = 0;
	bool abort = false;
	bool fail = false;
	bool frame_complete = false;
	bool recovered = false;
	bool dropped_partial = false;
	int ret = 0;

	spin_lock_irqsave(&v->irq_lock, flags);
	if (v->completion_state == HWS_VIDEO_COMPLETION_OVERRUN) {
		event.timestamp_ns = v->completion_timestamp_ns;
		event.deadline_ns = v->completion_deadline_ns;
		event.generation = v->completion_generation;
		event.toggle = v->completion_toggle;
		ret = -EOVERFLOW;
		hws_irq_clear_overlap_locked(v);
		hws_irq_reset_completion_locked(v);
		fail = true;
	} else {
		if (v->completion_state != HWS_VIDEO_COMPLETION_PENDING) {
			spin_unlock_irqrestore(&v->irq_lock, flags);
			return;
		}
		event.timestamp_ns = v->completion_timestamp_ns;
		event.deadline_ns = v->completion_deadline_ns;
		event.generation = v->completion_generation;
		event.toggle = v->completion_toggle;
		if (v->overlap_pending) {
			recovery_generation = v->overlap_generation;
			recovery_timestamp_ns = v->overlap_timestamp_ns;
			recovery_toggle = v->overlap_toggle;
			recovery_reports = max_t(u32, v->overlap_events_pending, 1);
			dropped_partial =
				hws_irq_recover_phase_locked(v, recovery_generation,
							     recovery_timestamp_ns,
							     recovery_toggle);
			hws_irq_clear_overlap_locked(v);
			v->overlap_recoveries += recovery_reports;
			hws_vdone_note_recovery_locked(v, recovery_generation, 0,
						       recovery_toggle, 0,
						       HWS_VDONE_AMBIG_INFLIGHT,
						       dropped_partial, true,
						       recovery_reports);
			recovered = true;
		} else {
			v->completion_state = HWS_VIDEO_COMPLETION_COPYING;
		}
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	if (fail)
		goto fail_queue;
	if (recovered) {
		schedule_work(&v->recovery_work);
		return;
	}
	if (READ_ONCE(hws->suspended) || READ_ONCE(v->stop_requested) ||
	    !READ_ONCE(v->cap_active)) {
		spin_lock_irqsave(&v->irq_lock, flags);
		if (v->completion_state == HWS_VIDEO_COMPLETION_COPYING &&
		    v->completion_generation == event.generation)
			hws_irq_reset_completion_locked(v);
		hws_irq_clear_overlap_locked(v);
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return;
	}

	ret = hws_video_copy_completed_half(v, &event, &done,
					    &frame_complete);

	spin_lock_irqsave(&v->irq_lock, flags);
	if (v->completion_state == HWS_VIDEO_COMPLETION_OVERRUN) {
		hws_irq_clear_overlap_locked(v);
		hws_irq_reset_completion_locked(v);
		fail = true;
	} else if (READ_ONCE(hws->suspended) ||
		   READ_ONCE(v->stop_requested) ||
		   !READ_ONCE(v->cap_active)) {
		hws_irq_reset_completion_locked(v);
		hws_irq_clear_overlap_locked(v);
		abort = true;
	} else if (v->overlap_pending &&
		   (!ret || hws_video_copy_error_recoverable(ret))) {
		recovery_generation = v->overlap_generation;
		recovery_timestamp_ns = v->overlap_timestamp_ns;
		recovery_toggle = v->overlap_toggle;
		recovery_reports = max_t(u32, v->overlap_events_pending, 1);
		dropped_partial =
			hws_irq_recover_phase_locked(v, recovery_generation,
						     recovery_timestamp_ns,
						     recovery_toggle);
		hws_irq_clear_overlap_locked(v);
		v->overlap_recoveries += recovery_reports;
		hws_vdone_note_recovery_locked(v, recovery_generation, 0,
					       recovery_toggle, 0,
					       HWS_VDONE_AMBIG_INFLIGHT,
					       dropped_partial, true,
					       recovery_reports);
		done = NULL;
		frame_complete = false;
		recovered = true;
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
		if (hws_video_copy_error_recoverable(ret)) {
			recovery_timestamp_ns = ktime_get_mono_fast_ns();
			recovery_generation = event.generation;
			recovery_toggle = readl(hws->bar0_base +
						     HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
			if (recovery_timestamp_ns >= event.timestamp_ns)
				recovery_interval_us =
					div_u64(recovery_timestamp_ns -
						event.timestamp_ns,
					NSEC_PER_USEC);
			if (ret == -ETIME) {
				v->deadline_misses++;
				v->timeout_count++;
			} else {
				v->phase_errors++;
			}
			dropped_partial =
				hws_irq_recover_phase_locked(v, recovery_generation,
							     recovery_timestamp_ns,
							     recovery_toggle);
			v->overlap_recoveries++;
			hws_vdone_note_recovery_locked(v, recovery_generation,
						       recovery_interval_us,
						       recovery_toggle, 0,
						       HWS_VDONE_AMBIG_INFLIGHT,
						       dropped_partial, true, 1);
			done = NULL;
			frame_complete = false;
			recovered = true;
		} else if (ret) {
			hws_irq_clear_overlap_locked(v);
			hws_irq_mark_failure_locked(v, ret);
			fail = true;
		} else if (frame_complete) {
			frame_sequence =
				(u32)atomic_fetch_inc(&v->sequence_number);
			if (done) {
				v->active = NULL;
				v->frame_generation = 0;
				v->frame_half0_valid = false;
				done->vb.vb2_buf.timestamp = event.timestamp_ns;
				vb2_set_plane_payload(&done->vb.vb2_buf, 0,
						      v->pix.sizeimage);
				done->vb.field = v->pix.field;
				done->vb.sequence = frame_sequence;
			}
		}
		if (!fail && !recovered)
			hws_irq_reset_completion_locked(v);
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	if (abort)
		return;
	if (fail)
		goto fail_queue;
	if (recovered) {
		schedule_work(&v->recovery_work);
		return;
	}

	if (done) {
		dev_dbg(&hws->pdev->dev,
			"bh_video(ch=%u): assembled buf=%p generation=%llu toggle=%u seq=%u\n",
			ch, done, (unsigned long long)event.generation,
			event.toggle, done->vb.sequence);
		vb2_buffer_done(&done->vb.vb2_buf, VB2_BUF_STATE_DONE);
	} else if (frame_complete) {
		dev_dbg(&hws->pdev->dev,
			"bh_video(ch=%u): dropped complete frame generation=%llu seq=%u (no queued VB2 buffer)\n",
			ch, (unsigned long long)event.generation,
			frame_sequence);
	}
	return;

fail_queue:
	{
		u64 now_ns = ktime_get_mono_fast_ns();
		u64 elapsed_us = event.timestamp_ns && now_ns >= event.timestamp_ns ?
			div_u64(now_ns - event.timestamp_ns, NSEC_PER_USEC) : 0;

		dev_err_ratelimited(&hws->pdev->dev,
				    "VDONE half-ring failure ch=%u generation=%llu toggle=%u phase=%u elapsed=%lluus ret=%d ambiguity=%u resamples=%u sample_errors=%u phase_errors=%u deadlines=%u guards=%u\n",
				    ch, (unsigned long long)event.generation,
				    event.toggle, READ_ONCE(v->half_phase),
				    (unsigned long long)elapsed_us, ret,
				    READ_ONCE(v->w1c_ambiguities),
				    READ_ONCE(v->toggle_resamples),
				    READ_ONCE(v->toggle_sample_errors),
				    READ_ONCE(v->phase_errors),
				    READ_ONCE(v->deadline_misses),
				    READ_ONCE(v->guard_errors));
	}
	hws_video_fail_queue(v,
			     "ambiguous VDONE phase, generation, copy, guard, or deadline");
}

static void hws_video_vdone_work(struct work_struct *work)
{
	struct hws_video *v = container_of(work, struct hws_video, vdone_work);

	hws_video_handle_vdone(v);
}

static void hws_video_recovery_work(struct work_struct *work)
{
	struct hws_video *v = container_of(work, struct hws_video,
					   recovery_work);
	struct hws_pcie_dev *hws = v->parent;
	unsigned long flags;
	u64 generation;
	u64 interval_us;
	u32 reports;
	u8 toggle;
	u8 attempt;
	enum hws_vdone_ambiguity reason;
	bool dropped_partial;
	bool steady;

	spin_lock_irqsave(&v->irq_lock, flags);
	reports = v->recovery_reports_pending;
	v->recovery_reports_pending = 0;
	generation = v->recovery_report_generation;
	interval_us = v->recovery_report_interval_us;
	toggle = v->recovery_report_toggle;
	attempt = v->recovery_report_attempt;
	reason = v->recovery_report_reason;
	dropped_partial = v->recovery_report_dropped_partial;
	steady = v->recovery_report_steady;
	spin_unlock_irqrestore(&v->irq_lock, flags);
	if (!reports)
		return;

	if (steady) {
		if (reason == HWS_VDONE_AMBIG_DUPLICATE)
			dev_warn_ratelimited(&hws->pdev->dev,
					     "VDONE duplicate recovered ch=%u generation=%llu toggle=%u interval=%lluus dropped_partial=%u streak=%u reports=%u\n",
					     v->channel_index,
					     (unsigned long long)generation,
					     toggle,
					     (unsigned long long)interval_us,
					     dropped_partial, attempt, reports);
		else
			dev_warn_ratelimited(&hws->pdev->dev,
					     "VDONE overlap recovered ch=%u generation=%llu toggle=%u elapsed=%lluus dropped_partial=%u reports=%u\n",
					     v->channel_index,
					     (unsigned long long)generation,
					     toggle,
					     (unsigned long long)interval_us,
					     dropped_partial, reports);
	} else {
		dev_info_ratelimited(&hws->pdev->dev,
				     "VDONE phase resync ch=%u generation=%llu toggle=%u interval=%lluus reason=%s streak=%u reports=%u\n",
				     v->channel_index,
				     (unsigned long long)generation, toggle,
				     (unsigned long long)interval_us,
				     hws_vdone_ambiguity_name(reason), attempt, reports);
	}
}

void hws_irq_init_video_work(struct hws_video *vid)
{
	INIT_WORK(&vid->vdone_work, hws_video_vdone_work);
	INIT_WORK(&vid->recovery_work, hws_video_recovery_work);
}

static u32 hws_irq_ack_status(struct hws_pcie_dev *pdx, u32 int_state)
{
	if (!int_state || !pdx || !pdx->bar0_base)
		return 0;

	writel(int_state, pdx->bar0_base + HWS_REG_INT_STATUS);
	return readl(pdx->bar0_base + HWS_REG_INT_STATUS);
}

static u32 hws_irq_owned_status_mask(const struct hws_pcie_dev *pdx)
{
	u32 mask = 0;
	unsigned int ch;

	for (ch = 0; ch < pdx->cur_max_video_ch; ch++)
		mask |= HWS_INT_VDONE_BIT(ch);
	for (ch = 0; ch < pdx->cur_max_audio_ch; ch++)
		mask |= HWS_INT_ADONE_BIT(ch);

	return mask;
}

static void hws_irq_queue_vdone_work(struct hws_pcie_dev *pdx,
				     unsigned int ch)
{
	struct workqueue_struct *wq;
	struct hws_video *v;

	if (!pdx || ch >= MAX_VID_CHANNELS)
		return;

	v = &pdx->video[ch];
	wq = READ_ONCE(pdx->video_wq);
	if (WARN_ON_ONCE(!wq)) {
		WRITE_ONCE(v->stop_requested, true);
		WRITE_ONCE(v->cap_active, false);
		hws_enable_video_capture(pdx, ch, false);
		return;
	}

	/* One work item per channel prevents one channel's copy from blocking another. */
	queue_work(wq, &v->vdone_work);
}

static void hws_irq_queue_recovery_work(struct hws_pcie_dev *pdx,
					unsigned int ch)
{
	if (!pdx || ch >= MAX_VID_CHANNELS)
		return;
	schedule_work(&pdx->video[ch].recovery_work);
}

static void
hws_vdone_note_recovery_locked(struct hws_video *v, u64 generation,
			       u64 interval_us, u8 toggle, u8 attempt,
			       enum hws_vdone_ambiguity reason,
			       bool dropped_partial, bool steady, u32 reports)
{
	lockdep_assert_held(&v->irq_lock);

	v->recovery_reports_pending += reports;
	v->recovery_report_generation = generation;
	v->recovery_report_interval_us = interval_us;
	v->recovery_report_toggle = toggle;
	v->recovery_report_attempt = attempt;
	v->recovery_report_reason = reason;
	v->recovery_report_dropped_partial = dropped_partial;
	v->recovery_report_steady = steady;
}

static enum hws_vdone_record_result
hws_irq_record_vdone(struct hws_pcie_dev *pdx, unsigned int ch,
		     const struct hws_vdone_toggle_sample *sample,
		     u64 timestamp_ns)
{
	struct hws_video *v;
	unsigned long flags;
	enum hws_vdone_ambiguity ambiguity = HWS_VDONE_AMBIG_NONE;
	enum hws_vdone_record_result result;
	u64 generation = 0;
	u64 previous_ns = 0;
	u64 interval_us = 0;
	u8 sync_attempt = 0;
	bool dropped_partial = false;
	bool report_recovery = false;
	u8 toggle;

	if (!pdx || ch >= MAX_VID_CHANNELS || !sample)
		return HWS_VDONE_IGNORED;

	toggle = sample->after_ack;
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
		if (timestamp_ns > previous_ns)
			interval_us = div_u64(timestamp_ns - previous_ns,
					      NSEC_PER_USEC);

		/* W1C uncertainty remains fatal even if an older copy is active. */
		if (sample->status_reasserted)
			ambiguity = HWS_VDONE_AMBIG_STATUS_REASSERTED;
		else if (!sample->post_ack_stable)
			ambiguity = HWS_VDONE_AMBIG_TOGGLE_UNSTABLE;
		/*
		 * ktime_get_mono_fast_ns() may return the same value for two
		 * back-to-back IRQ entries. Equality preserves event ordering and
		 * must not turn an otherwise recoverable overlap into a queue error.
		 * A genuinely backward timestamp remains fail-closed.
		 */
		else if (v->half_seen && timestamp_ns < previous_ns)
			ambiguity = HWS_VDONE_AMBIG_TIMESTAMP;
		else if (v->completion_state != HWS_VIDEO_COMPLETION_IDLE)
			ambiguity = HWS_VDONE_AMBIG_INFLIGHT;
		else if (v->half_seen &&
			 toggle == v->last_buf_half_toggle)
			ambiguity = HWS_VDONE_AMBIG_DUPLICATE;

		if (ambiguity == HWS_VDONE_AMBIG_INFLIGHT) {
			/*
			 * Baseline skipped an interrupt while its copy tasklet was busy.
			 * Preserve the latest stable identity so the active worker can
			 * recycle any partial destination after it leaves memcpy(). Never
			 * mutate that worker's completion slot from hard-IRQ context.
			 */
			if (sample->before_ack != sample->after_ack)
				v->toggle_resamples++;
			v->overlap_pending = true;
			v->overlap_toggle = toggle;
			v->overlap_timestamp_ns = timestamp_ns;
			v->overlap_generation = generation;
			if (v->overlap_events_pending != U32_MAX)
				v->overlap_events_pending++;
			WRITE_ONCE(v->last_buf_half_toggle, toggle);
			WRITE_ONCE(v->half_seen, true);
			WRITE_ONCE(v->last_vdone_timestamp_ns, timestamp_ns);
			result = HWS_VDONE_DEFERRED;
		} else if (ambiguity == HWS_VDONE_AMBIG_DUPLICATE &&
			   v->half_phase == HWS_VIDEO_PHASE_SYNC && !v->active &&
			   !v->frame_generation && !v->frame_half0_valid) {
			/*
			 * Some rapid enables expose a stale first boundary while the
			 * native ring settles.  No VB2 memory has been touched in SYNC,
			 * so discard the acquisition sequence and require a new run of
			 * alternating events. Repeated clean duplicates can stall delivery,
			 * but do not make any userspace buffer unsafe and are not fatal.
			 */
			v->sync_events = 0;
			if (v->sync_restart_streak != U8_MAX)
				v->sync_restart_streak++;
			sync_attempt = v->sync_restart_streak;
			v->sync_restarts++;
			v->phase_generation = 0;
			hws_irq_reset_completion_locked(v);
			WRITE_ONCE(v->last_buf_half_toggle, toggle);
			WRITE_ONCE(v->half_seen, true);
			WRITE_ONCE(v->last_vdone_timestamp_ns, timestamp_ns);
			hws_vdone_note_recovery_locked(v, generation, interval_us,
						       toggle, sync_attempt,
						       ambiguity, false, false, 1);
			report_recovery = true;
			result = HWS_VDONE_RESYNCED;
		} else if (ambiguity == HWS_VDONE_AMBIG_DUPLICATE) {
			/*
			 * A stable same-toggle report contains no new half identity. Baseline
			 * discarded its partial state and waited for a changed toggle. Recycle
			 * the driver-owned destination and do the same; an orphan half 1 is
			 * discarded by the normal phase machine. Repeated clean duplicates
			 * remain nonfatal because no questionable data reaches userspace.
			 */
			if (v->sync_restart_streak != U8_MAX)
				v->sync_restart_streak++;
			sync_attempt = v->sync_restart_streak;
			v->sync_restarts++;
			v->duplicate_recoveries++;
			dropped_partial =
				hws_irq_recover_phase_locked(v, generation,
							     timestamp_ns, toggle);
			hws_vdone_note_recovery_locked(v, generation, interval_us,
						       toggle, sync_attempt,
						       ambiguity, dropped_partial,
						       true, 1);
			report_recovery = true;
			result = HWS_VDONE_RECOVERED;
		} else if (ambiguity != HWS_VDONE_AMBIG_NONE) {
			if (v->completion_state == HWS_VIDEO_COMPLETION_IDLE) {
				v->completion_timestamp_ns = timestamp_ns;
				v->completion_deadline_ns =
					hws_video_copy_deadline_ns(v);
				v->completion_generation = generation;
				v->completion_toggle = toggle;
			}
			hws_irq_mark_failure_locked(v, -EOVERFLOW);
			hws_irq_clear_overlap_locked(v);
			v->w1c_ambiguities++;
			if (ambiguity == HWS_VDONE_AMBIG_TOGGLE_UNSTABLE ||
			    ambiguity == HWS_VDONE_AMBIG_STATUS_REASSERTED)
				v->toggle_sample_errors++;
			WRITE_ONCE(v->stop_requested, true);
			WRITE_ONCE(v->cap_active, false);
			result = HWS_VDONE_OVERRUN;
		} else {
			if (sample->before_ack != sample->after_ack)
				v->toggle_resamples++;
			if (v->half_phase != HWS_VIDEO_PHASE_SYNC)
				v->sync_restart_streak = 0;
			v->completion_timestamp_ns = timestamp_ns;
			v->completion_deadline_ns = hws_video_copy_deadline_ns(v);
			v->completion_generation = generation;
			v->completion_toggle = toggle;
			v->completion_state = HWS_VIDEO_COMPLETION_PENDING;
			WRITE_ONCE(v->last_buf_half_toggle, toggle);
			WRITE_ONCE(v->half_seen, true);
			WRITE_ONCE(v->last_vdone_timestamp_ns, timestamp_ns);
			result = HWS_VDONE_QUEUED;
		}
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);
	if (report_recovery)
		hws_irq_queue_recovery_work(pdx, ch);

	if (result == HWS_VDONE_OVERRUN) {
		hws_enable_video_capture(pdx, ch, false);
		dev_err_ratelimited(&pdx->pdev->dev,
				    "VDONE ambiguity ch=%u generation=%llu toggle=%u pre_ack=%u post_stable=%u reasserted=%u interval=%lluus: %s\n",
				    ch, (unsigned long long)generation, toggle,
				    sample->before_ack, sample->post_ack_stable,
				    sample->status_reasserted,
				    (unsigned long long)interval_us,
				    hws_vdone_ambiguity_name(ambiguity));
	}
	return result;
}

static void
hws_irq_sample_video_before_ack(struct hws_pcie_dev *pdx, u32 int_state,
				struct hws_vdone_toggle_sample samples[])
{
	unsigned int ch;

	for (ch = 0; ch < pdx->cur_max_video_ch; ch++) {
		if (!(int_state & HWS_INT_VDONE_BIT(ch)))
			continue;
		samples[ch].before_ack = readl(pdx->bar0_base +
					       HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
		samples[ch].after_ack = samples[ch].before_ack;
	}
}

static u32
hws_irq_record_video(struct hws_pcie_dev *pdx, u32 int_state,
		     u32 status_after_ack,
		     struct hws_vdone_toggle_sample samples[], u64 timestamp_ns)
{
	u32 work_mask = 0;
	unsigned int ch;

	for (ch = 0; ch < pdx->cur_max_video_ch; ++ch) {
		u32 vbit = HWS_INT_VDONE_BIT(ch);
		enum hws_vdone_record_result result;
		u8 first, second;

		if (!(int_state & vbit))
			continue;

		if (READ_ONCE(pdx->video[ch].cap_active) &&
		    !READ_ONCE(pdx->video[ch].stop_requested)) {
			first = readl(pdx->bar0_base +
				      HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
			second = readl(pdx->bar0_base +
				       HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
			samples[ch].after_ack = second;
			samples[ch].post_ack_stable = first == second;
			samples[ch].status_reasserted = status_after_ack & vbit;
			result = hws_irq_record_vdone(pdx, ch, &samples[ch],
						      timestamp_ns);
			if (result == HWS_VDONE_QUEUED ||
			    result == HWS_VDONE_OVERRUN)
				work_mask |= BIT(ch);
			if (result == HWS_VDONE_QUEUED &&
			    samples[ch].before_ack != samples[ch].after_ack)
				dev_info_ratelimited(&pdx->pdev->dev,
						     "VDONE toggle resampled ch=%u pre_ack=%u post_ack=%u total=%u\n",
						     ch, samples[ch].before_ack,
						     samples[ch].after_ack,
						     READ_ONCE(pdx->video[ch].toggle_resamples));
			else if (result == HWS_VDONE_QUEUED)
				dev_dbg(&pdx->pdev->dev,
					"irq: VDONE ch=%u queued pre_ack=%u post_ack=%u\n",
					ch, samples[ch].before_ack,
					samples[ch].after_ack);
		} else {
			dev_dbg(&pdx->pdev->dev,
				"irq: VDONE ch=%u ignored (cap=%d stop=%d)\n",
				ch,
				READ_ONCE(pdx->video[ch].cap_active),
				READ_ONCE(pdx->video[ch].stop_requested));
		}
	}

	return work_mask;
}

static void hws_irq_queue_video_work(struct hws_pcie_dev *pdx, u32 work_mask)
{
	unsigned int ch;

	for (ch = 0; ch < pdx->cur_max_video_ch; ch++) {
		if (work_mask & BIT(ch))
			hws_irq_queue_vdone_work(pdx, ch);
	}
}

static void
hws_irq_sample_audio_before_ack(struct hws_pcie_dev *pdx, u32 int_state,
				struct hws_adone_toggle_sample samples[])
{
	unsigned int ch;

	for (ch = 0; ch < pdx->cur_max_audio_ch; ch++) {
		if (!(int_state & HWS_INT_ADONE_BIT(ch)))
			continue;
		samples[ch].before_ack = readl(pdx->bar0_base +
						 HWS_REG_ABUF_TOGGLE(ch)) & 0x01;
		samples[ch].after_ack = samples[ch].before_ack;
	}
}

static u32
hws_irq_record_audio(struct hws_pcie_dev *pdx, u32 int_state,
		     u32 status_after_ack,
		     struct hws_adone_toggle_sample samples[], u64 timestamp_ns)
{
	u32 work_mask = 0;
	unsigned int ch;

	for (ch = 0; ch < pdx->cur_max_audio_ch; ++ch) {
		u32 abit = HWS_INT_ADONE_BIT(ch);
		enum hws_audio_xrun_reason ambiguity = HWS_AUDIO_XRUN_NONE;
		u8 first, second;

		if (!(int_state & abit))
			continue;

		/* Only service running streams */
		if (!READ_ONCE(pdx->audio[ch].cap_active) ||
		    !READ_ONCE(pdx->audio[ch].stream_running) ||
		    READ_ONCE(pdx->audio[ch].stop_requested))
			continue;

		/*
		 * Sticky ADONE cannot identify multiple packets. Sample after W1C
		 * with ordered reads and fail closed if another completion can have
		 * crossed the acknowledge window.
		 */
		first = readl(pdx->bar0_base + HWS_REG_ABUF_TOGGLE(ch)) & 0x01;
		second = readl(pdx->bar0_base + HWS_REG_ABUF_TOGGLE(ch)) & 0x01;
		samples[ch].after_ack = second;
		samples[ch].post_ack_stable = first == second;
		samples[ch].status_reasserted = status_after_ack & abit;
		if (samples[ch].status_reasserted)
			ambiguity = HWS_AUDIO_XRUN_W1C_STATUS_REASSERTED;
		else if (!samples[ch].post_ack_stable)
			ambiguity = HWS_AUDIO_XRUN_W1C_TOGGLE_UNSTABLE;
		else if (samples[ch].before_ack != samples[ch].after_ack)
			ambiguity = HWS_AUDIO_XRUN_W1C_TOGGLE_CHANGED;

		if (hws_audio_record_interrupt(pdx, ch, second, timestamp_ns,
					       ambiguity))
			work_mask |= BIT(ch);
		if (ambiguity != HWS_AUDIO_XRUN_NONE)
			dev_err_ratelimited(&pdx->pdev->dev,
					    "ADONE ambiguity ch=%u pre_ack=%u post_ack=%u post_stable=%u reasserted=%u\n",
					    ch, samples[ch].before_ack,
					    samples[ch].after_ack,
					    samples[ch].post_ack_stable,
					    samples[ch].status_reasserted);
	}

	return work_mask;
}

static void hws_irq_queue_audio_work(struct hws_pcie_dev *pdx, u32 work_mask)
{
	unsigned int ch;

	for (ch = 0; ch < pdx->cur_max_audio_ch; ch++) {
		if (work_mask & BIT(ch))
			hws_audio_queue_work(pdx, ch);
	}
}

irqreturn_t hws_irq_handler(int irq, void *info)
{
	struct hws_pcie_dev *pdx = info;
	struct hws_adone_toggle_sample audio_samples[MAX_VID_CHANNELS] = { };
	struct hws_vdone_toggle_sample video_samples[MAX_VID_CHANNELS] = { };
	u64 timestamp_ns;
	u32 status_after_ack;
	u32 int_state;
	u32 audio_work;
	u32 video_work;

	(void)irq;

	if (!pdx || !pdx->bar0_base)
		return IRQ_NONE;
	if (READ_ONCE(pdx->suspended)) {
		/*
		 * A failed device-local mask must not leave a shared level IRQ
		 * asserted while lifecycle teardown is draining the device.  Ack
		 * causes without sampling DMA buffers or queueing any work.
		 */
		int_state = readl(pdx->bar0_base + HWS_REG_INT_STATUS);
		if (int_state != U32_MAX)
			int_state &= hws_irq_owned_status_mask(pdx);
		if (!int_state || int_state == U32_MAX)
			return IRQ_NONE;
		(void)hws_irq_ack_status(pdx, int_state);
		return IRQ_HANDLED;
	}

	dev_dbg(&pdx->pdev->dev, "irq: entry\n");
	dev_dbg(&pdx->pdev->dev,
		"irq: INT_EN=0x%08x INT_STATUS=0x%08x\n",
		readl(pdx->bar0_base + INT_EN_REG_BASE),
		readl(pdx->bar0_base + HWS_REG_INT_STATUS));
	int_state = readl(pdx->bar0_base + HWS_REG_INT_STATUS);
	if (!int_state || int_state == 0xFFFFFFFF) {
		dev_dbg(&pdx->pdev->dev,
			"irq: spurious or device-gone int_state=0x%08x\n",
			int_state);
		return IRQ_NONE;
	}
	timestamp_ns = ktime_get_mono_fast_ns();
	dev_dbg(&pdx->pdev->dev, "irq: entry INT_STATUS=0x%08x\n", int_state);

	hws_irq_sample_video_before_ack(pdx, int_state, video_samples);
	hws_irq_sample_audio_before_ack(pdx, int_state, audio_samples);
	status_after_ack = hws_irq_ack_status(pdx, int_state);
	audio_work = hws_irq_record_audio(pdx, int_state, status_after_ack,
					  audio_samples, timestamp_ns);
	video_work = hws_irq_record_video(pdx, int_state, status_after_ack,
					  video_samples, timestamp_ns);
	/* No DMA-backed copy may start until the sticky causes are acknowledged. */
	hws_irq_queue_audio_work(pdx, audio_work);
	hws_irq_queue_video_work(pdx, video_work);

	return IRQ_HANDLED;
}
