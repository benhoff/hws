// SPDX-License-Identifier: GPL-2.0-only
#include <linux/compiler.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/ktime.h>
#include <linux/minmax.h>
#include <linux/string.h>

#include "hws_irq.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws.h"

#define MAX_INT_LOOPS 100

struct hws_vdone_event {
	struct hwsvideo_buffer *buf;
	u64 cookie;
	u64 timestamp_ns;
	int slot;
	u8 toggle;
};

enum hws_vdone_record_result {
	HWS_VDONE_IGNORED,
	HWS_VDONE_QUEUED,
	HWS_VDONE_OVERRUN,
};

static void hws_irq_reset_completion_locked(struct hws_video *v)
{
	lockdep_assert_held(&v->irq_lock);

	v->completion_state = HWS_VIDEO_COMPLETION_IDLE;
	v->completion_buf = NULL;
	v->completion_cookie = 0;
	v->completion_timestamp_ns = 0;
	v->completion_slot = HWS_VIDEO_DIRECT_SLOT;
	v->completion_toggle = 0;
}

static int hws_arm_next(struct hws_pcie_dev *hws, u32 ch)
{
	struct hws_video *v = &hws->video[ch];
	unsigned long flags;
	struct hwsvideo_buffer *buf;
	int ret;

	dev_dbg(&hws->pdev->dev,
		"arm_next(ch=%u): stop=%d cap=%d queued=%u\n",
		ch, READ_ONCE(v->stop_requested), READ_ONCE(v->cap_active),
		READ_ONCE(v->queued_count));

	if (READ_ONCE(hws->suspended)) {
		dev_dbg(&hws->pdev->dev, "arm_next(ch=%u): suspended\n", ch);
		return -EBUSY;
	}

	if (READ_ONCE(v->stop_requested) || !READ_ONCE(v->cap_active)) {
		dev_dbg(&hws->pdev->dev,
			"arm_next(ch=%u): stop=%d cap=%d -> cancel\n", ch,
			v->stop_requested, v->cap_active);
		return -ECANCELED;
	}

	spin_lock_irqsave(&v->irq_lock, flags);
	if (v->active) {
		buf = v->active;
		spin_unlock_irqrestore(&v->irq_lock, flags);
		dev_dbg(&hws->pdev->dev,
			"arm_next(ch=%u): active buffer already armed %p\n",
			ch, buf);
		return 0;
	}
	if (v->next_prepared) {
		buf = v->next_prepared;
		v->active = buf;
		v->next_prepared = NULL;
		spin_unlock_irqrestore(&v->irq_lock, flags);
		dev_dbg(&hws->pdev->dev,
			"arm_next(ch=%u): promoted prepared buffer %p\n",
			ch, buf);
		return 0;
	}
	if (list_empty(&v->capture_queue)) {
		hws_enable_video_capture(hws, ch, false);
		spin_unlock_irqrestore(&v->irq_lock, flags);
		dev_dbg(&hws->pdev->dev, "arm_next(ch=%u): queue empty\n", ch);
		return -EAGAIN;
	}

	buf = list_first_entry(&v->capture_queue, struct hwsvideo_buffer, list);
	list_del_init(&buf->list);	/* keep buffer safe for later cleanup */
	if (v->queued_count)
		v->queued_count--;
	v->active = buf;

	/* Publish descriptor(s) before MMIO capture updates. */
	wmb();

	/* Avoid MMIO during suspend */
	if (READ_ONCE(hws->suspended)) {
		dev_dbg(&hws->pdev->dev,
			"arm_next(ch=%u): suspended after pick\n", ch);
		list_add(&buf->list, &v->capture_queue);
		v->queued_count++;
		v->active = NULL;
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return -EBUSY;
	}

	/* Program the baseline DMA window; use arena bounce if needed. */
	ret = hws_program_dma_for_buffer(hws, ch, buf);
	if (ret) {
		v->active = NULL;
		list_add(&buf->list, &v->capture_queue);
		v->queued_count++;
		WRITE_ONCE(v->stop_requested, true);
		hws_enable_video_capture(hws, ch, false);
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return ret;
	}

	dev_dbg(&hws->pdev->dev, "arm_next(ch=%u): programmed buffer %p\n", ch,
		buf);
	(void)hws_prime_next_locked(v);
	spin_unlock_irqrestore(&v->irq_lock, flags);
	return 0;
}

static void hws_video_handle_vdone(struct hws_video *v)
{
	struct hws_pcie_dev *hws = v->parent;
	unsigned int ch = v->channel_index;
	struct hws_vdone_event event = { };
	struct hwsvideo_buffer *promoted_active = NULL;
	unsigned long flags;
	enum vb2_buffer_state buffer_state = VB2_BUF_STATE_DONE;
	bool abort = false;
	bool fail = false;
	bool promoted = false;
	int prepare_ret;
	int prime_ret = 0;
	int ret;

	spin_lock_irqsave(&v->irq_lock, flags);
	if (v->completion_state == HWS_VIDEO_COMPLETION_OVERRUN) {
		fail = true;
	} else if (v->completion_state != HWS_VIDEO_COMPLETION_PENDING) {
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return;
	}
	if (!fail) {
		event.buf = v->completion_buf;
		event.cookie = v->completion_cookie;
		event.timestamp_ns = v->completion_timestamp_ns;
		event.slot = v->completion_slot;
		event.toggle = v->completion_toggle;

		if (!event.buf || !event.cookie || v->active != event.buf ||
		    event.buf->dma_cookie != event.cookie ||
		    event.buf->slot != event.slot) {
			v->completion_state = HWS_VIDEO_COMPLETION_OVERRUN;
			v->completion_overruns++;
			v->error_count++;
			fail = true;
		} else {
			v->completion_state = HWS_VIDEO_COMPLETION_COPYING;
		}
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	if (fail)
		goto fail_queue;

	/* STREAMOFF owns the buffers once it has published the stop flags. */
	if (READ_ONCE(hws->suspended) || READ_ONCE(v->stop_requested) ||
	    !READ_ONCE(v->cap_active)) {
		spin_lock_irqsave(&v->irq_lock, flags);
		if (v->completion_state == HWS_VIDEO_COMPLETION_COPYING &&
		    v->completion_buf == event.buf &&
		    v->completion_cookie == event.cookie)
			hws_irq_reset_completion_locked(v);
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return;
	}

	prepare_ret = hws_video_prepare_done_buffer(v, event.buf,
						    event.timestamp_ns);
	if (prepare_ret) {
		dev_warn_ratelimited(&hws->pdev->dev,
				     "bh_video(ch=%u): failed to prepare completed buffer ret=%d\n",
				     ch, prepare_ret);
		buffer_state = VB2_BUF_STATE_ERROR;
	}

	/*
	 * Keep the completion in COPYING state until the bounce copy is done.
	 * A second hard-IRQ edge changes it to OVERRUN and stops the engine.
	 */
	spin_lock_irqsave(&v->irq_lock, flags);
	if (v->completion_state == HWS_VIDEO_COMPLETION_OVERRUN) {
		fail = true;
	} else if (READ_ONCE(hws->suspended) ||
		   READ_ONCE(v->stop_requested) ||
		   !READ_ONCE(v->cap_active)) {
		hws_irq_reset_completion_locked(v);
		abort = true;
	} else if (v->completion_state != HWS_VIDEO_COMPLETION_COPYING ||
		   v->completion_buf != event.buf ||
		   v->completion_cookie != event.cookie ||
		   v->active != event.buf ||
		   event.buf->dma_cookie != event.cookie) {
		v->completion_state = HWS_VIDEO_COMPLETION_OVERRUN;
		v->completion_overruns++;
		v->error_count++;
		fail = true;
	} else {
		if (v->next_prepared) {
			v->active = v->next_prepared;
			v->next_prepared = NULL;
			promoted_active = v->active;
			promoted = true;
		} else {
			v->active = NULL;
		}

		if (promoted)
			prime_ret = hws_prime_next_locked(v);
		hws_irq_reset_completion_locked(v);
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	if (abort)
		return;
	if (fail)
		goto fail_queue;

	dev_dbg(&hws->pdev->dev,
		"bh_video(ch=%u): complete buf=%p cookie=%llu slot=%d toggle=%u seq=%u\n",
		ch, event.buf, (unsigned long long)event.cookie, event.slot,
		event.toggle, event.buf->vb.sequence);
	vb2_buffer_done(&event.buf->vb.vb2_buf, buffer_state);

	if (prime_ret) {
		dev_warn_ratelimited(&hws->pdev->dev,
				     "bh_video(ch=%u): failed to pre-arm next buffer ret=%d\n",
				     ch, prime_ret);
		hws_video_fail_queue(v, "failed to pre-arm next buffer");
		return;
	}

	if (READ_ONCE(hws->suspended))
		return;

	if (promoted) {
		dev_dbg(&hws->pdev->dev,
			"bh_video(ch=%u): promoted pre-armed buffer active=%p\n",
			ch, promoted_active);
		return;
	}

	/* 2) Immediately arm the next queued buffer (if present) */
	ret = hws_arm_next(hws, ch);
	if (ret == -EAGAIN) {
		dev_dbg(&hws->pdev->dev,
			"bh_video(ch=%u): no queued buffer to arm\n", ch);
		return;
	}
	if (ret) {
		if (ret != -ECANCELED && ret != -EBUSY)
			hws_video_fail_queue(v, "failed to arm next buffer");
		return;
	}
	dev_dbg(&hws->pdev->dev,
		"bh_video(ch=%u): armed next buffer, active=%p\n", ch,
		v->active);
	/* On success the engine now points at v->active's DMA address */
	return;

fail_queue:
	hws_video_fail_queue(v, "VDONE completion overrun or identity mismatch");
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
	enum hws_vdone_record_result result;

	if (!pdx || ch >= MAX_VID_CHANNELS)
		return HWS_VDONE_IGNORED;

	v = &pdx->video[ch];
	spin_lock_irqsave(&v->irq_lock, flags);
	if (!READ_ONCE(v->cap_active) || READ_ONCE(v->stop_requested)) {
		result = HWS_VDONE_IGNORED;
	} else if (v->completion_state != HWS_VIDEO_COMPLETION_IDLE ||
		   !v->active || !v->active->dma_cookie) {
		/*
		 * The two-slot pipeline can protect only one deferred copy. A
		 * second edge means hardware may reuse the slot being copied.
		 */
		v->completion_state = HWS_VIDEO_COMPLETION_OVERRUN;
		v->completion_overruns++;
		v->error_count++;
		WRITE_ONCE(v->stop_requested, true);
		WRITE_ONCE(v->cap_active, false);
		result = HWS_VDONE_OVERRUN;
	} else {
		v->completion_buf = v->active;
		v->completion_cookie = v->active->dma_cookie;
		v->completion_timestamp_ns = timestamp_ns;
		v->completion_slot = v->active->slot;
		v->completion_toggle = toggle;
		v->completion_state = HWS_VIDEO_COMPLETION_PENDING;
		WRITE_ONCE(v->last_buf_half_toggle, toggle);
		WRITE_ONCE(v->half_seen, true);
		result = HWS_VDONE_QUEUED;
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	if (result == HWS_VDONE_OVERRUN) {
		hws_enable_video_capture(pdx, ch, false);
		dev_err_ratelimited(&pdx->pdev->dev,
				    "VDONE overrun ch=%u: deferred completion still owns a bounce slot\n",
				    ch);
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
	timestamp_ns = ktime_get_ns();
	dev_dbg(&pdx->pdev->dev, "irq: entry INT_STATUS=0x%08x\n", int_state);

	wake_thread = hws_irq_queue_video(pdx, int_state, timestamp_ns);
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
