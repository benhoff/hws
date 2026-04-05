// SPDX-License-Identifier: GPL-2.0-only
#include <linux/compiler.h>
#include <linux/moduleparam.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/minmax.h>
#include <linux/string.h>

#include <media/videobuf2-dma-contig.h>

#include "hws_irq.h"
#include "hws_capture.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws.h"

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
	struct hws_vfh_ctx *owner;

	dev_dbg(&hws->pdev->dev,
		"arm_next(ch=%u): stop=%d cap=%d owner=%p active=%p\n",
		ch, READ_ONCE(v->stop_requested), READ_ONCE(v->cap_active),
		READ_ONCE(v->engine.direct_owner), v->engine.active);

	if (unlikely(READ_ONCE(hws->suspended))) {
		dev_dbg(&hws->pdev->dev, "arm_next(ch=%u): suspended\n", ch);
		return -EBUSY;
	}

	if (unlikely(READ_ONCE(v->stop_requested) || !READ_ONCE(v->cap_active))) {
		dev_dbg(&hws->pdev->dev,
			"arm_next(ch=%u): stop=%d cap=%d -> cancel\n", ch,
			v->stop_requested, v->cap_active);
		return -ECANCELED;
	}
	if (READ_ONCE(v->engine.mode) != HWS_CAPTURE_MODE_DIRECT)
		return -EAGAIN;

	spin_lock_irqsave(&v->irq_lock, flags);
	buf = hws_take_direct_buffer_locked(v);
	if (!buf) {
		spin_unlock_irqrestore(&v->irq_lock, flags);
		dev_dbg(&hws->pdev->dev,
			"arm_next(ch=%u): owner queue empty\n", ch);
		return -EAGAIN;
	}

	v->engine.active = buf;
	spin_unlock_irqrestore(&v->irq_lock, flags);
	dev_dbg(&hws->pdev->dev, "arm_next(ch=%u): picked buffer %p\n", ch,
		buf);

	/* Publish descriptor(s) before doorbell/MMIO kicks. */
	wmb();

	/* Avoid MMIO during suspend */
	if (unlikely(READ_ONCE(hws->suspended))) {
		unsigned long f;

		dev_dbg(&hws->pdev->dev,
			"arm_next(ch=%u): suspended after pick\n", ch);
		spin_lock_irqsave(&v->irq_lock, f);
		if (v->engine.active) {
			owner = READ_ONCE(v->engine.direct_owner);
			if (owner) {
				unsigned long qflags;

				spin_lock_irqsave(&owner->qlock, qflags);
				list_add(&buf->list, &owner->buf_queue);
				spin_unlock_irqrestore(&owner->qlock, qflags);
			}
			v->engine.active = NULL;
		}
		spin_unlock_irqrestore(&v->irq_lock, f);
		return -EBUSY;
	}

	/* Also program the DMA address register directly */
	{
		dma_addr_t dma_addr =
		    vb2_dma_contig_plane_dma_addr(&buf->vb.vb2_buf, 0);
		hws_program_dma_for_addr(hws, ch, dma_addr);
		iowrite32(lower_32_bits(dma_addr),
			  hws->bar0_base + HWS_REG_DMA_ADDR(ch));
	}

	dev_dbg(&hws->pdev->dev, "arm_next(ch=%u): programmed buffer %p\n", ch,
		buf);
	spin_lock_irqsave(&v->irq_lock, flags);
	hws_prime_next_locked(v);
	spin_unlock_irqrestore(&v->irq_lock, flags);
	return 0;
}

static struct hwsvideo_buffer *
hws_pop_ctx_buffer(struct hws_vfh_ctx *ctx)
{
	struct hwsvideo_buffer *buf = NULL;
	unsigned long flags;

	if (!ctx)
		return NULL;

	spin_lock_irqsave(&ctx->qlock, flags);
	if (!list_empty(&ctx->buf_queue)) {
		buf = list_first_entry(&ctx->buf_queue,
				       struct hwsvideo_buffer, list);
		list_del_init(&buf->list);
	}
	spin_unlock_irqrestore(&ctx->qlock, flags);
	return buf;
}

static bool hws_video_handle_vdone_fanout(struct hws_video *v)
{
	struct hws_pcie_dev *hws = v->parent;
	unsigned int ch = v->channel_index;
	struct hws_vfh_ctx *ctx;
	unsigned long flags;
	size_t expected;
	u64 ts;
	u32 frame_seq = 0;
	bool have_seq = false;

	if (unlikely(READ_ONCE(hws->suspended)))
		return false;
	if (unlikely(READ_ONCE(v->stop_requested) || !READ_ONCE(v->cap_active)))
		return false;
	if (!READ_ONCE(v->engine.fanout_cpu))
		return false;

	expected = READ_ONCE(v->pix.sizeimage);
	ts = ktime_get_ns();
	dma_rmb();

	spin_lock_irqsave(&v->consumers_lock, flags);
	list_for_each_entry(ctx, &v->consumers, node) {
		struct hwsvideo_buffer *buf;
		struct vb2_v4l2_buffer *vb2v;
		void *dst;

		if (!ctx->streaming)
			continue;
		buf = hws_pop_ctx_buffer(ctx);
		if (!buf)
			continue;

		spin_unlock_irqrestore(&v->consumers_lock, flags);
		vb2v = &buf->vb;
		dst = vb2_plane_vaddr(&vb2v->vb2_buf, 0);
		if (!dst || vb2_plane_size(&vb2v->vb2_buf, 0) < expected) {
			vb2_buffer_done(&vb2v->vb2_buf, VB2_BUF_STATE_ERROR);
		} else {
			if (!have_seq) {
				frame_seq =
				    (u32)(atomic_inc_return(&v->engine.sequence_number) - 1);
				have_seq = true;
			}
			memcpy(dst, v->engine.fanout_cpu, expected);
			vb2_set_plane_payload(&vb2v->vb2_buf, 0, expected);
			vb2v->sequence = frame_seq;
			vb2v->field = v->pix.field;
			vb2v->vb2_buf.timestamp = ts;
			vb2_buffer_done(&vb2v->vb2_buf, VB2_BUF_STATE_DONE);
		}
		spin_lock_irqsave(&v->consumers_lock, flags);
	}
	spin_unlock_irqrestore(&v->consumers_lock, flags);

	if (!READ_ONCE(v->cap_active))
		return false;

	if (hws_capture_has_pending(v))
		return true;

	{
		dma_addr_t dma_addr = READ_ONCE(v->engine.fanout_dma);

		hws_program_dma_for_addr(hws, ch, dma_addr);
		iowrite32(lower_32_bits(dma_addr),
			  hws->bar0_base + HWS_REG_DMA_ADDR(ch));
	}
	return false;
}

static bool hws_video_handle_vdone(struct hws_video *v)
{
	struct hws_pcie_dev *hws = v->parent;
	unsigned int ch = v->channel_index;
	struct hwsvideo_buffer *done;
	unsigned long flags;
	bool promoted = false;

	dev_dbg(&hws->pdev->dev,
		"bh_video(ch=%u): stop=%d cap=%d active=%p\n",
		ch, READ_ONCE(v->stop_requested), READ_ONCE(v->cap_active),
		v->engine.active);

	int ret;

	dev_dbg(&hws->pdev->dev,
		"bh_video(ch=%u): entry stop=%d cap=%d\n", ch,
		v->stop_requested, v->cap_active);
	if (unlikely(READ_ONCE(hws->suspended)))
		return false;

	if (unlikely(READ_ONCE(v->stop_requested) || !READ_ONCE(v->cap_active)))
		return false;

	spin_lock_irqsave(&v->irq_lock, flags);
	done = v->engine.active;
	if (done && v->engine.next_prepared) {
		v->engine.active = v->engine.next_prepared;
		v->engine.next_prepared = NULL;
		promoted = true;
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	/* 1) Complete the buffer the HW just finished (if any) */
	if (done) {
		struct vb2_v4l2_buffer *vb2v = &done->vb;
		size_t expected = v->pix.sizeimage;
		size_t plane_size = vb2_plane_size(&vb2v->vb2_buf, 0);

		if (unlikely(expected > plane_size)) {
			dev_warn_ratelimited(&hws->pdev->dev,
					     "bh_video(ch=%u): sizeimage %zu > plane %zu, dropping seq=%u\n",
					     ch, expected, plane_size,
					     (u32)atomic_read(&v->engine.sequence_number));
			vb2_buffer_done(&vb2v->vb2_buf, VB2_BUF_STATE_ERROR);
			goto arm_next;
		}
		vb2_set_plane_payload(&vb2v->vb2_buf, 0, expected);

		dma_rmb();	/* device writes visible before userspace sees it */

		vb2v->sequence =
		    (u32)(atomic_inc_return(&v->engine.sequence_number) - 1);
		vb2v->field = v->pix.field;
		vb2v->vb2_buf.timestamp = ktime_get_ns();
		dev_dbg(&hws->pdev->dev,
			"bh_video(ch=%u): DONE buf=%p seq=%u half_seen=%d toggle=%u\n",
			ch, done, vb2v->sequence, v->half_seen,
			v->last_buf_half_toggle);

		if (!promoted)
			v->engine.active = NULL; /* engine no longer owns this buffer */
		vb2_buffer_done(&vb2v->vb2_buf, VB2_BUF_STATE_DONE);
	}

	if (unlikely(READ_ONCE(hws->suspended)))
		return false;

	if (promoted) {
		if (hws_capture_has_pending(v))
			return true;
		dev_dbg(&hws->pdev->dev,
			"bh_video(ch=%u): promoted pre-armed buffer active=%p\n",
			ch, v->engine.active);
		spin_lock_irqsave(&v->irq_lock, flags);
		hws_prime_next_locked(v);
		spin_unlock_irqrestore(&v->irq_lock, flags);
		return false;
	}

arm_next:
	if (hws_capture_has_pending(v))
		return true;

	/* 2) Immediately arm the next queued buffer (if present) */
	ret = hws_arm_next(hws, ch);
	if (ret == -EAGAIN) {
		dev_dbg(&hws->pdev->dev,
			"bh_video(ch=%u): no queued buffer to arm\n", ch);
		return false;
	}
	dev_dbg(&hws->pdev->dev,
		"bh_video(ch=%u): armed next buffer, active=%p\n", ch,
		v->engine.active);
	/* On success the engine now points at engine.active’s DMA address */
	return false;
}

irqreturn_t hws_irq_handler(int irq, void *info)
{
	struct hws_pcie_dev *pdx = info;
	u32 int_state;
	bool wake_thread = false;

	dev_dbg(&pdx->pdev->dev, "irq: entry\n");
	if (likely(pdx->bar0_base)) {
		dev_dbg(&pdx->pdev->dev,
			"irq: INT_EN=0x%08x INT_STATUS=0x%08x\n",
			readl(pdx->bar0_base + INT_EN_REG_BASE),
			readl(pdx->bar0_base + HWS_REG_INT_STATUS));
	}

	/* Fast path: if suspended, quietly ack and exit */
	if (unlikely(READ_ONCE(pdx->suspended))) {
		int_state = readl_relaxed(pdx->bar0_base + HWS_REG_INT_STATUS);
		if (int_state) {
			writel(int_state, pdx->bar0_base + HWS_REG_INT_STATUS);
			(void)readl_relaxed(pdx->bar0_base + HWS_REG_INT_STATUS);
		}
		return int_state ? IRQ_HANDLED : IRQ_NONE;
	}
	// u32 sys_status = readl(pdx->bar0_base + HWS_REG_SYS_STATUS);

	int_state = readl_relaxed(pdx->bar0_base + HWS_REG_INT_STATUS);
	if (!int_state || int_state == 0xFFFFFFFF) {
		dev_dbg(&pdx->pdev->dev,
			"irq: spurious or device-gone int_state=0x%08x\n",
			int_state);
		return IRQ_NONE;
	}
	dev_dbg(&pdx->pdev->dev, "irq: entry INT_STATUS=0x%08x\n", int_state);

	/* Loop until all pending bits are serviced (max 100 iterations) */
	for (u32 cnt = 0; int_state && cnt < MAX_INT_LOOPS; ++cnt) {
		for (unsigned int ch = 0; ch < pdx->cur_max_video_ch; ++ch) {
			u32 vbit = HWS_INT_VDONE_BIT(ch);

			if (!(int_state & vbit))
				continue;

			if (likely(READ_ONCE(pdx->video[ch].cap_active) &&
				   !READ_ONCE(pdx->video[ch].stop_requested))) {
					if (READ_ONCE(pdx->video[ch].engine.mode) ==
					    HWS_CAPTURE_MODE_FANOUT) {
						set_bit(ch, &pdx->capture_work_mask);
						wake_thread = true;
					} else {
						if (unlikely(hws_toggle_debug)) {
						u32 toggle =
						    readl_relaxed(pdx->bar0_base +
								  HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
						WRITE_ONCE(pdx->video[ch].last_buf_half_toggle,
							   toggle);
					}
					dma_rmb();
					WRITE_ONCE(pdx->video[ch].half_seen, true);
						dev_dbg(&pdx->pdev->dev,
							"irq: VDONE ch=%u toggle=%u handling inline (cap=%d)\n",
							ch,
							READ_ONCE(pdx->video[ch].last_buf_half_toggle),
							READ_ONCE(pdx->video[ch].cap_active));
						if (hws_video_handle_vdone(&pdx->video[ch])) {
							set_bit(ch, &pdx->capture_work_mask);
							wake_thread = true;
						}
					}
				} else {
				dev_dbg(&pdx->pdev->dev,
					"irq: VDONE ch=%u ignored (cap=%d stop=%d)\n",
					ch,
					READ_ONCE(pdx->video[ch].cap_active),
					READ_ONCE(pdx->video[ch].stop_requested));
			}

			writel(vbit, pdx->bar0_base + HWS_REG_INT_STATUS);
			(void)readl_relaxed(pdx->bar0_base + HWS_REG_INT_STATUS);
		}

		/* Re‐read in case new interrupt bits popped while processing */
		int_state = readl_relaxed(pdx->bar0_base + HWS_REG_INT_STATUS);
		dev_dbg(&pdx->pdev->dev,
			"irq: loop cnt=%u new INT_STATUS=0x%08x\n", cnt,
			int_state);
		if (cnt + 1 == MAX_INT_LOOPS)
			dev_warn_ratelimited(&pdx->pdev->dev,
					     "IRQ storm? status=0x%08x\n",
					     int_state);
	}

	return wake_thread ? IRQ_WAKE_THREAD : IRQ_HANDLED;
}

irqreturn_t hws_irq_thread(int irq, void *info)
{
	struct hws_pcie_dev *pdx = info;
	unsigned int ch;

		(void)irq;
	for (ch = 0; ch < pdx->cur_max_video_ch; ch++) {
		struct hws_video *v = &pdx->video[ch];
		bool apply_pending = false;

		if (!test_and_clear_bit(ch, &pdx->capture_work_mask))
			continue;
		if (unlikely(READ_ONCE(pdx->suspended)))
			continue;

		if (READ_ONCE(v->engine.mode) == HWS_CAPTURE_MODE_FANOUT) {
			if (unlikely(READ_ONCE(v->stop_requested) ||
				     !READ_ONCE(v->cap_active)))
				continue;
			apply_pending = hws_video_handle_vdone_fanout(v);
		} else {
			apply_pending = hws_capture_has_pending(v);
		}

		if (!apply_pending && !hws_capture_has_pending(v))
			continue;

		mutex_lock(&v->state_lock);
		(void)hws_capture_apply_pending_locked(v);
		mutex_unlock(&v->state_lock);
	}

	return IRQ_HANDLED;
}
