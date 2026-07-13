// SPDX-License-Identifier: GPL-2.0-only
#include <linux/compiler.h>
#include <linux/moduleparam.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/minmax.h>
#include <linux/string.h>

#include "hws_irq.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws.h"
#include "hws_audio.h"

#define MAX_INT_LOOPS 100

static bool hws_toggle_debug;
module_param_named(toggle_debug, hws_toggle_debug, bool, 0644);
MODULE_PARM_DESC(toggle_debug,
		 "Read toggle registers in IRQ handler for debug logging");

static int hws_arm_next(struct hws_pcie_dev *hws, u32 ch)
{
	struct hws_video *v = &hws->video[ch];
	unsigned long flags;
	struct hwsvideo_buffer *buf;

	dev_dbg(&hws->pdev->dev,
		"arm_next(ch=%u): stop=%d cap=%d queued=%d\n",
		ch, READ_ONCE(v->stop_requested), READ_ONCE(v->cap_active),
		!list_empty(&v->capture_queue));

	if (READ_ONCE(hws->suspended) || READ_ONCE(hws->irq_faulted)) {
		dev_dbg(&hws->pdev->dev,
			"arm_next(ch=%u): unavailable (suspended=%d irq_faulted=%d)\n",
			ch, READ_ONCE(hws->suspended),
			READ_ONCE(hws->irq_faulted));
		return READ_ONCE(hws->irq_faulted) ? -EIO : -EBUSY;
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
		spin_unlock_irqrestore(&v->irq_lock, flags);
		dev_dbg(&hws->pdev->dev, "arm_next(ch=%u): queue empty\n", ch);
		return -EAGAIN;
	}

	buf = list_first_entry(&v->capture_queue, struct hwsvideo_buffer, list);
	list_del_init(&buf->list);	/* keep buffer safe for later cleanup */
	if (v->queued_count)
		v->queued_count--;
	v->active = buf;
	spin_unlock_irqrestore(&v->irq_lock, flags);
	dev_dbg(&hws->pdev->dev, "arm_next(ch=%u): picked buffer %p\n", ch,
		buf);

	/* Publish descriptor(s) before MMIO capture updates. */
	wmb();

	/* Avoid MMIO during suspend */
	if (READ_ONCE(hws->suspended) || READ_ONCE(hws->irq_faulted)) {
		unsigned long f;

		dev_dbg(&hws->pdev->dev,
			"arm_next(ch=%u): unavailable after pick\n", ch);
		spin_lock_irqsave(&v->irq_lock, f);
		if (v->active == buf) {
			list_add(&buf->list, &v->capture_queue);
			v->queued_count++;
			v->active = NULL;
		}
		spin_unlock_irqrestore(&v->irq_lock, f);
		return READ_ONCE(hws->irq_faulted) ? -EIO : -EBUSY;
	}

	/* Program the baseline DMA window; use arena bounce if needed. */
	{
		int ret = hws_program_dma_for_buffer(hws, ch, buf);

		if (ret) {
			unsigned long f;

			spin_lock_irqsave(&v->irq_lock, f);
			if (v->active == buf) {
				v->active = NULL;
				list_add(&buf->list, &v->capture_queue);
				v->queued_count++;
			}
			spin_unlock_irqrestore(&v->irq_lock, f);
			return ret;
		}
	}

	dev_dbg(&hws->pdev->dev, "arm_next(ch=%u): programmed buffer %p\n", ch,
		buf);
	spin_lock_irqsave(&v->irq_lock, flags);
	hws_prime_next_locked(v);
	spin_unlock_irqrestore(&v->irq_lock, flags);
	return 0;
}

static void hws_video_handle_vdone(struct hws_video *v)
{
	struct hws_pcie_dev *hws = v->parent;
	unsigned int ch = v->channel_index;
	struct hwsvideo_buffer *done;
	struct hwsvideo_buffer *promoted_active = NULL;
	unsigned long flags;
	bool promoted = false;
	int ret;

	dev_dbg(&hws->pdev->dev,
		"bh_video(ch=%u): stop=%d cap=%d active=%p\n",
		ch, READ_ONCE(v->stop_requested), READ_ONCE(v->cap_active),
		v->active);

	dev_dbg(&hws->pdev->dev,
		"bh_video(ch=%u): entry stop=%d cap=%d\n", ch,
		v->stop_requested, v->cap_active);
	if (READ_ONCE(hws->suspended))
		return;

	if (READ_ONCE(v->stop_requested) || !READ_ONCE(v->cap_active))
		return;

	spin_lock_irqsave(&v->irq_lock, flags);
	done = v->active;
	if (done && v->next_prepared) {
		v->active = v->next_prepared;
		v->next_prepared = NULL;
		promoted_active = v->active;
		promoted = true;
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	/* 1) Complete the buffer the HW just finished (if any) */
	if (done) {
		struct vb2_v4l2_buffer *vb2v = &done->vb;
		enum vb2_buffer_state state = VB2_BUF_STATE_DONE;

		ret = hws_video_prepare_done_buffer(v, done);
		if (ret) {
			dev_warn_ratelimited(&hws->pdev->dev,
					     "bh_video(ch=%u): failed to prepare completed buffer ret=%d\n",
					     ch, ret);
			state = VB2_BUF_STATE_ERROR;
		} else {
			dev_dbg(&hws->pdev->dev,
				"bh_video(ch=%u): DONE buf=%p seq=%u half_seen=%d toggle=%u\n",
				ch, done, vb2v->sequence, v->half_seen,
				v->last_buf_half_toggle);
		}

		spin_lock_irqsave(&v->irq_lock, flags);
		if (v->active == done) {
			if (v->next_prepared) {
				v->active = v->next_prepared;
				v->next_prepared = NULL;
				promoted_active = v->active;
				promoted = true;
			} else {
				v->active = NULL;
			}
		} else if (v->active) {
			promoted_active = v->active;
			promoted = true;
		}
		spin_unlock_irqrestore(&v->irq_lock, flags);

		vb2_buffer_done(&vb2v->vb2_buf, state);
	}

	if (READ_ONCE(hws->suspended))
		return;

	if (promoted) {
		dev_dbg(&hws->pdev->dev,
			"bh_video(ch=%u): promoted pre-armed buffer active=%p\n",
			ch, promoted_active);
		spin_lock_irqsave(&v->irq_lock, flags);
		ret = hws_prime_next_locked(v);
		spin_unlock_irqrestore(&v->irq_lock, flags);
		if (ret)
			dev_warn_ratelimited(&hws->pdev->dev,
					     "bh_video(ch=%u): failed to pre-arm next buffer ret=%d\n",
					     ch, ret);
		return;
	}

arm_next:
	/* 2) Immediately arm the next queued buffer (if present) */
	ret = hws_arm_next(hws, ch);
	if (ret == -EAGAIN) {
		dev_dbg(&hws->pdev->dev,
			"bh_video(ch=%u): no queued buffer to arm\n", ch);
		return;
	}
	if (ret) {
		dev_warn_ratelimited(&hws->pdev->dev,
				     "bh_video(ch=%u): stopping video queue after DMA arm failure ret=%d\n",
				     ch, ret);
		hws_enable_video_capture(hws, ch, false);
		WRITE_ONCE(v->cap_active, false);
		WRITE_ONCE(v->stop_requested, true);
		vb2_queue_error(&v->buffer_queue);
		return;
	}
	dev_dbg(&hws->pdev->dev,
		"bh_video(ch=%u): armed next buffer, active=%p\n", ch,
		v->active);
	/* On success the engine now points at v->active's DMA address */
}

static void hws_irq_ack_status(struct hws_pcie_dev *pdx, u32 int_state)
{
	if (!int_state || !pdx || !pdx->bar0_base)
		return;

	writel(int_state, pdx->bar0_base + HWS_REG_INT_STATUS);
	(void)readl(pdx->bar0_base + HWS_REG_INT_STATUS);
}

static void hws_irq_record_vdone(struct hws_pcie_dev *pdx, unsigned int ch)
{
	unsigned long flags;

	if (!pdx || ch >= MAX_VID_CHANNELS)
		return;

	spin_lock_irqsave(&pdx->irq_thread_lock, flags);
	pdx->irq_pending_vdone[ch]++;
	spin_unlock_irqrestore(&pdx->irq_thread_lock, flags);
}

static void hws_irq_record_fault(struct hws_pcie_dev *pdx, u32 status)
{
	unsigned long flags;

	WRITE_ONCE(pdx->irq_faulted, true);
	spin_lock_irqsave(&pdx->irq_thread_lock, flags);
	pdx->irq_fault_status |= status;
	memset(pdx->irq_pending_vdone, 0,
	       sizeof(pdx->irq_pending_vdone));
	spin_unlock_irqrestore(&pdx->irq_thread_lock, flags);
}

static u32 hws_irq_take_fault(struct hws_pcie_dev *pdx)
{
	unsigned long flags;
	u32 status;

	spin_lock_irqsave(&pdx->irq_thread_lock, flags);
	status = pdx->irq_fault_status;
	pdx->irq_fault_status = 0;
	spin_unlock_irqrestore(&pdx->irq_thread_lock, flags);

	return status;
}

static void hws_irq_contain_fault(struct hws_pcie_dev *pdx)
{
	/* Mask at the device; disable_irq() is invalid for a shared INTx line. */
	writel(0, pdx->bar0_base + INT_EN_REG_BASE);

	/* Do not leave DMA running after completion delivery has been disabled. */
	writel(0, pdx->bar0_base + HWS_REG_VCAP_ENABLE);
	writel(0, pdx->bar0_base + HWS_REG_ACAP_ENABLE);
	(void)readl(pdx->bar0_base + HWS_REG_INT_STATUS);
}

static void hws_irq_fail_video_streams(struct hws_pcie_dev *pdx)
{
	unsigned int ch;

	for (ch = 0; ch < pdx->cur_max_video_ch &&
	     ch < MAX_VID_CHANNELS; ch++) {
		struct hws_video *v = &pdx->video[ch];

		if (!READ_ONCE(v->cap_active) &&
		    !vb2_is_streaming(&v->buffer_queue))
			continue;

		WRITE_ONCE(v->stop_requested, true);
		smp_wmb(); /* publish stop before MMIO disable and queue error */
		hws_enable_video_capture(pdx, ch, false);
		vb2_queue_error(&v->buffer_queue);
	}
}

static void hws_irq_handle_fault(struct hws_pcie_dev *pdx, u32 status)
{
	hws_irq_fail_video_streams(pdx);
	hws_audio_handle_irq_fault(pdx);

	dev_err(&pdx->pdev->dev,
		"IRQ-fabric fault status=0x%08x: DMA stopped; V4L2 queues report EIO and ALSA streams report XRUN; reload the driver\n",
		status);
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
			pdx->irq_pending_vdone[i]--;
			*ch = i;
			spin_unlock_irqrestore(&pdx->irq_thread_lock, flags);
			return true;
		}
	}
	spin_unlock_irqrestore(&pdx->irq_thread_lock, flags);
	return false;
}

static bool hws_irq_queue_video(struct hws_pcie_dev *pdx, u32 int_state)
{
	bool wake_thread = false;
	unsigned int ch;

	for (ch = 0; ch < pdx->cur_max_video_ch; ++ch) {
		u32 vbit = HWS_INT_VDONE_BIT(ch);

		if (!(int_state & vbit))
			continue;

		if (READ_ONCE(pdx->video[ch].cap_active) &&
		    !READ_ONCE(pdx->video[ch].stop_requested)) {
			if (hws_toggle_debug) {
				u32 toggle =
				    readl_relaxed(pdx->bar0_base +
						  HWS_REG_VBUF_TOGGLE(ch)) & 0x01;

				WRITE_ONCE(pdx->video[ch].last_buf_half_toggle,
					   toggle);
			}
			WRITE_ONCE(pdx->video[ch].half_seen, true);
			hws_irq_record_vdone(pdx, ch);
			wake_thread = true;
			dev_dbg(&pdx->pdev->dev,
				"irq: VDONE ch=%u queued for threaded completion\n",
				ch);
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
	bool handled = false;
	bool wake_thread = false;
	unsigned int loops;
	u32 serviced = 0;

	(void)irq;

	if (!pdx || !pdx->bar0_base)
		return IRQ_NONE;
	if (READ_ONCE(pdx->irq_faulted))
		return IRQ_NONE;

	dev_dbg(&pdx->pdev->dev, "irq: entry\n");
	if (pdx->bar0_base) {
		dev_dbg(&pdx->pdev->dev,
			"irq: INT_EN=0x%08x INT_STATUS=0x%08x\n",
			readl(pdx->bar0_base + INT_EN_REG_BASE),
			readl(pdx->bar0_base + HWS_REG_INT_STATUS));
	}

	/*
	 * Drain all currently latched causes before returning. With legacy INTx,
	 * an uncleared source keeps the level-triggered line asserted and naturally
	 * invokes us again. MSI is message-based and has no asserted line to rely
	 * on, so returning with a cause still latched risks waiting indefinitely
	 * for a later event. The vendor baseline used the same bounded-drain model.
	 *
	 * Dispatch each cause at most once per hard-handler entry. A bit latch
	 * cannot distinguish a genuinely new same-source event from a failed W1C,
	 * so dispatching it twice could manufacture a completion. Different source
	 * bits which arrive while draining are still handled normally.
	 */
	for (loops = 0; loops < MAX_INT_LOOPS; loops++) {
		u32 int_state, fresh;

		int_state = readl_relaxed(pdx->bar0_base + HWS_REG_INT_STATUS);
		if (!int_state || int_state == 0xFFFFFFFF) {
			if (!handled)
				dev_dbg(&pdx->pdev->dev,
					"irq: spurious or device-gone int_state=0x%08x\n",
					int_state);
			break;
		}

		handled = true;
		fresh = int_state & ~serviced;
		if (!fresh) {
			u32 retry;

			/* Retry W1C once, but never dispatch these causes again. */
			hws_irq_ack_status(pdx, int_state);
			retry = readl_relaxed(pdx->bar0_base +
					      HWS_REG_INT_STATUS);
			if (!retry || retry == 0xFFFFFFFF) {
				dev_warn_ratelimited(&pdx->pdev->dev,
					"IRQ status 0x%08x needed a second W1C; duplicate completion suppressed\n",
					int_state);
				break;
			}

			if (retry & serviced) {
				u32 stuck = retry & serviced;

				hws_irq_record_fault(pdx, stuck);
				hws_irq_contain_fault(pdx);
				wake_thread = true;
				break;
			}

			/* Only previously unseen sources remain; process them. */
			continue;
		}

		/* During suspend teardown, acknowledge without scheduling work. */
		if (!READ_ONCE(pdx->suspended)) {
			wake_thread |= hws_irq_queue_video(pdx, fresh);
			hws_irq_handle_audio(pdx, fresh);
		}
		serviced |= fresh;
		hws_irq_ack_status(pdx, int_state);
	}

	if (loops == MAX_INT_LOOPS)
		dev_warn_ratelimited(&pdx->pdev->dev,
				     "IRQ status did not drain after %u passes\n",
				     MAX_INT_LOOPS);

	if (wake_thread)
		return IRQ_WAKE_THREAD;

	return handled ? IRQ_HANDLED : IRQ_NONE;
}

irqreturn_t hws_irq_thread(int irq, void *info)
{
	struct hws_pcie_dev *pdx = info;
	unsigned int ch;
	unsigned int count = 0;
	bool handled = false;
	u32 fault;

	(void)irq;

	if (!pdx || !pdx->bar0_base)
		return IRQ_NONE;

	for (;;) {
		fault = hws_irq_take_fault(pdx);
		if (fault) {
			handled = true;
			hws_irq_handle_fault(pdx, fault);
			continue;
		}

		if (!hws_irq_take_vdone(pdx, &ch))
			break;

		handled = true;
		if (READ_ONCE(pdx->suspended) ||
		    READ_ONCE(pdx->irq_faulted))
			continue;

		hws_video_handle_vdone(&pdx->video[ch]);
		count++;
		if (count == MAX_INT_LOOPS)
			dev_warn_ratelimited(&pdx->pdev->dev,
					     "threaded IRQ processing many VDONE events\n");
	}

	return handled ? IRQ_HANDLED : IRQ_NONE;
}
