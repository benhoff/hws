/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/compiler.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>

#include <sound/pcm.h>
#include <media/videobuf2-dma-contig.h>

#include "hws_irq.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws_audio.h"

#define MAX_INT_LOOPS 100


static int hws_arm_next(struct hws_pcie_dev *hws, u32 ch)
{
    struct hws_video *v = &hws->video[ch];
    unsigned long flags;
    struct hwsvideo_buffer *buf;
    pr_debug("arm_next(ch=%u): stop=%d cap=%d queued=%d\n",
             ch, READ_ONCE(v->stop_requested), READ_ONCE(v->cap_active), !list_empty(&v->capture_queue));

    if (unlikely(READ_ONCE(hws->suspended))) {
        pr_debug("arm_next(ch=%u): suspended\n", ch);
        return -EBUSY;
    }

    if (unlikely(READ_ONCE(v->stop_requested) || !READ_ONCE(v->cap_active))) {
        pr_debug("arm_next(ch=%u): stop=%d cap=%d -> cancel\n",
                   ch, v->stop_requested, v->cap_active);
        return -ECANCELED;
    }


    spin_lock_irqsave(&v->irq_lock, flags);
    if (list_empty(&v->capture_queue)) {
        spin_unlock_irqrestore(&v->irq_lock, flags);
        pr_debug("arm_next(ch=%u): queue empty\n", ch);
        return -EAGAIN;
    }

    buf = list_first_entry(&v->capture_queue, struct hwsvideo_buffer, list);
    list_del(&buf->list);
    v->active = buf;
    spin_unlock_irqrestore(&v->irq_lock, flags);
    pr_debug("arm_next(ch=%u): picked buffer %p\n", ch, buf);

    /* Publish descriptor(s) before doorbell/MMIO kicks. */
    wmb();

    /* Avoid MMIO during suspend */
    if (unlikely(READ_ONCE(hws->suspended))) {
        pr_debug("arm_next(ch=%u): suspended after pick\n", ch);
        return -EBUSY;
    }

    hws_program_video_from_vb2(hws, ch, &buf->vb.vb2_buf);
    
    /* Also program the DMA address register directly */
    {
        dma_addr_t dma_addr = vb2_dma_contig_plane_dma_addr(&buf->vb.vb2_buf, 0);
        iowrite32(lower_32_bits(dma_addr), hws->bar0_base + HWS_REG_DMA_ADDR(ch));
        /* Ensure DMA is ready for device access */
        dma_sync_single_for_device(&hws->pdev->dev, dma_addr, 
                                  vb2_plane_size(&buf->vb.vb2_buf, 0), 
                                  DMA_FROM_DEVICE);
    }
    
    pr_debug("arm_next(ch=%u): programmed buffer %p\n", ch, buf);
    return 0;
}

void hws_bh_video(struct tasklet_struct *t)
{
    struct hws_video *v = from_tasklet(v, t, bh_tasklet);
    struct hws_pcie_dev *hws = v->parent;
    unsigned int ch = v->channel_index;
    struct hwsvideo_buffer *done;

    pr_debug("bh_video(ch=%u): stop=%d cap=%d active=%p\n",
             ch, READ_ONCE(v->stop_requested), READ_ONCE(v->cap_active), v->active);

    int ret;
    pr_debug("bh_video(ch=%u): entry stop=%d cap=%d\n", ch, v->stop_requested, v->cap_active);
    if (unlikely(READ_ONCE(hws->suspended)))
        return;

    if (unlikely(READ_ONCE(v->stop_requested) || !READ_ONCE(v->cap_active)))
        return;

    /* 1) Complete the buffer the HW just finished (if any) */
    done = v->active;
    if (done) {
        struct vb2_v4l2_buffer *vb2v = &done->vb;

        dma_rmb(); /* device writes visible before userspace sees it */

        vb2v->sequence = ++v->sequence_number;          /* BH-only increment */
        vb2v->vb2_buf.timestamp = ktime_get_ns();
        pr_debug("bh_video(ch=%u): DONE buf=%p seq=%u half_seen=%d toggle=%u\n",
                 ch, done, vb2v->sequence, v->half_seen, v->last_buf_half_toggle);


        v->active = NULL; /* channel no longer owns this buffer */
        vb2_buffer_done(&vb2v->vb2_buf, VB2_BUF_STATE_DONE);
    }

    if (unlikely(READ_ONCE(hws->suspended)))
        return;

    /* 2) Immediately arm the next queued buffer (if present) */
    ret = hws_arm_next(hws, ch);
    if (ret == -EAGAIN) {
        pr_debug("bh_video(ch=%u): no queued buffer to arm\n", ch);
        return;
    }
    pr_debug("bh_video(ch=%u): armed next buffer, active=%p\n", ch, v->active);
    /* On success the engine now points at v->active’s DMA address */
}


irqreturn_t hws_irq_handler(int irq, void *info)
{
    struct hws_pcie_dev *pdx = info;
    u32 int_state, ack_mask = 0;
    pr_debug("irq: entry\n");
    if (likely(pdx->bar0_base)) {
        pr_debug("irq: INT_EN=0x%08x INT_STATUS=0x%08x\n",
                 readl(pdx->bar0_base + INT_EN_REG_BASE), readl(pdx->bar0_base + HWS_REG_INT_STATUS));
    }

    /* Fast path: if suspended, quietly ack and exit */
    if (unlikely(READ_ONCE(pdx->suspended))) {
        int_state = readl(pdx->bar0_base + HWS_REG_INT_STATUS);
        if (int_state) {
            writel(int_state, pdx->bar0_base + HWS_REG_INT_STATUS);
            (void)readl(pdx->bar0_base + HWS_REG_INT_STATUS);
        }
        return int_state ? IRQ_HANDLED : IRQ_NONE;
    }

    // u32 sys_status = readl(pdx->bar0_base + HWS_REG_SYS_STATUS);

    int_state = readl(pdx->bar0_base + HWS_REG_INT_STATUS);
    if (!int_state || int_state == 0xFFFFFFFF) {
        pr_debug("irq: spurious or device-gone int_state=0x%08x\n", int_state);
        return IRQ_NONE;
    }
    pr_debug("irq: entry INT_STATUS=0x%08x\n", int_state);

    /* Loop until all pending bits are serviced (max 100 iterations) */
    for (u32 cnt = 0; int_state && cnt < MAX_INT_LOOPS; ++cnt) {
        for (unsigned int ch = 0; ch < pdx->cur_max_video_ch; ++ch) {
            u32 vbit = HWS_INT_VDONE_BIT(ch);

            if (!(int_state & vbit))
                continue;

            ack_mask |= vbit;
            /* Always schedule BH while streaming; don't gate on toggle bit */
            if (likely(READ_ONCE(pdx->video[ch].cap_active) &&
                       !READ_ONCE(pdx->video[ch].stop_requested))) {
                /* Optional: snapshot toggle for debug visibility */
                u32 toggle = readl(pdx->bar0_base + HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
                dma_rmb(); /* ensure DMA writes visible before we inspect */
                WRITE_ONCE(pdx->video[ch].half_seen, true);
                WRITE_ONCE(pdx->video[ch].last_buf_half_toggle, toggle);
                pr_debug("irq: VDONE ch=%u toggle=%u scheduling BH (cap=%d)\n",
                         ch, toggle, pdx->video[ch].cap_active);
                tasklet_schedule(&pdx->video[ch].bh_tasklet);
            } else {
                pr_debug("irq: VDONE ch=%u ignored (cap=%d stop=%d)\n",
                         ch, pdx->video[ch].cap_active, pdx->video[ch].stop_requested);
            }
        }

        for (unsigned int ch = 0; ch < pdx->cur_max_linein_ch; ++ch) {
            u32 abit = HWS_INT_ADONE_BIT(ch);
            if (!(int_state & abit))
                continue;

            ack_mask |= abit;

            /* Only service running streams */
            if (!READ_ONCE(pdx->audio[ch].cap_active) ||
                !READ_ONCE(pdx->audio[ch].stream_running))
                continue;

            /* If your HW exposes a 0/1 toggle, read it (optional) */
            pdx->audio[ch].last_period_toggle =
                readl(pdx->bar0_base + HWS_REG_ABUF_TOGGLE(ch)) & 0x01;

            /* Make device writes visible before notifying ALSA */
            dma_rmb();
		/* Period accounting + rearm + notify ALSA. */
		{
			struct hws_audio *a = &pdx->audio[ch];
			struct snd_pcm_substream *ss = READ_ONCE(a->pcm_substream);

			if (likely(ss)) {
				struct snd_pcm_runtime *rt = READ_ONCE(ss->runtime);
				if (likely(rt)) {
					/* Advance write pointer by exactly one period (frames). */
					snd_pcm_uframes_t pos = READ_ONCE(a->ring_wpos_byframes);
					pos += rt->period_size; /* see note below on equivalence */
					if (pos >= rt->buffer_size)
						pos -= rt->buffer_size;
					WRITE_ONCE(a->ring_wpos_byframes, pos);

					/* Small race guard: avoid arming if a stop just landed. */
					if (likely(!READ_ONCE(a->stop_requested))) {
						/* Program the period the HW will fill next.
						 * This helper MUST include a posted-write flush/readback
						 * of the MMIO sequence so the writes are visible before ACK.
						 */
						hws_audio_program_next_period(pdx, ch);
					}

					/* Now tell ALSA a period elapsed (after re-arming). */
					snd_pcm_period_elapsed(ss);
				}
			}
		}
        }

        /* Acknowledge (clear) all bits we just handled */
        writel(ack_mask, pdx->bar0_base + HWS_REG_INT_STATUS);
        (void)readl(pdx->bar0_base + HWS_REG_INT_STATUS);
        pr_debug("irq: ACK mask=0x%08x\n", ack_mask);

        /* Immediately clear ack_mask to avoid re-acknowledging stale bits */
        ack_mask = 0;

        /* Re‐read in case new interrupt bits popped while processing */
        int_state = readl(pdx->bar0_base + HWS_REG_INT_STATUS);
        pr_debug("irq: loop cnt=%u new INT_STATUS=0x%08x\n", cnt, int_state);
        if (cnt + 1 == MAX_INT_LOOPS)
            dev_warn_ratelimited(&pdx->pdev->dev,
                                 "IRQ storm? status=0x%08x\n", int_state);
    }

    return IRQ_HANDLED;
}
