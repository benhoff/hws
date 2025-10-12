/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/compiler.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/timer.h>

#include <sound/pcm.h>
#include <media/videobuf2-dma-contig.h>

#include "hws_irq.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws_audio.h"


#define MAX_INT_LOOPS 100


static void hws_arm_next(struct hws_pcie_dev *hws, u32 ch)
{
	struct hws_video *v = &hws->video[ch];
	unsigned long flags;

	spin_lock_irqsave(&v->irq_lock, flags);
	if (!v->active && !list_empty(&v->capture_queue)) {
		v->active = list_first_entry(&v->capture_queue,
					     struct hwsvideo_buffer, list);
		list_del_init(&v->active->list);
		if (v->queued_count)
			v->queued_count--;
		v->active->slot = 0;
		v->ring_first_half_copied = false;
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);
}

void hws_bh_video(struct tasklet_struct *t)
{
	struct hws_video *v = from_tasklet(v, t, bh_tasklet);
	struct hws_pcie_dev *hws = v->parent;
	struct device *dev = &hws->pdev->dev;
	unsigned int ch = v->channel_index;
	unsigned long flags;
	unsigned int toggle, completed_slot;
	struct hwsvideo_buffer *buf;
	bool finished = false;
	bool new_half = false;
	size_t half;
	u32 queue_depth = 0;
	bool ring_mode = !READ_ONCE(v->zero_copy);
	bool rearm_timer = READ_ONCE(v->cap_active);
	const unsigned long timeout_period = msecs_to_jiffies(2000);

	if (unlikely(READ_ONCE(hws->suspended)))
		return;

	if (unlikely(READ_ONCE(v->stop_requested) || !READ_ONCE(v->cap_active)))
		return;

	if (ring_mode) {
		unsigned int prev = READ_ONCE(v->ring_toggle_prev) & 0x1;

		toggle = READ_ONCE(v->ring_toggle_hw) & 0x1;
		if (toggle == prev)
			goto out_rearm;
		WRITE_ONCE(v->ring_toggle_prev, toggle);
	} else {
		toggle = READ_ONCE(v->last_buf_half_toggle) & 0x1;
	}

	completed_slot = toggle ^ 1;

	half = v->half_bytes ? v->half_bytes : v->pix.half_size;
	if (!half)
		half = HWS_HALF_ALIGN_BYTES;

	spin_lock_irqsave(&v->irq_lock, flags);
	v->dma_slot = toggle;
	buf = v->active;
	queue_depth = v->queued_count;
	if (buf && !(buf->slot & BIT(completed_slot))) {
		buf->slot |= BIT(completed_slot);
		new_half = true;
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	if (!buf) {
		if (ring_mode)
			WRITE_ONCE(v->ring_first_half_copied, false);
		WRITE_ONCE(v->ring_last_toggle_jiffies, jiffies);
		rearm_timer = false;
		goto out_rearm;
	}

	if (ring_mode && new_half) {
		void *dst = vb2_plane_vaddr(&buf->vb.vb2_buf, 0);

		if (dst)
			memcpy(dst + (size_t)completed_slot * half,
			       v->half_cpu[completed_slot], half);
		else
			dev_warn_ratelimited(dev,
					     "ch%u: no CPU mapping for buffer, dropping half %u\n",
					     ch, completed_slot);

		hws_set_dma_doorbell(hws, ch, v->ring_dma, NULL);
		WRITE_ONCE(v->ring_first_half_copied,
			   (buf->slot & 0x3) != 0x3);
	}

	if (new_half) {
		WRITE_ONCE(v->ring_last_toggle_jiffies, jiffies);
		dev_dbg_ratelimited(dev,
				    "bh: ch%u half%u seq=%u queued=%u\n",
				    ch, completed_slot, v->sequence_number,
				    queue_depth);
	}

	finished = ((buf->slot & 0x3) == 0x3);

	if (finished) {
		struct vb2_v4l2_buffer *vb2v = &buf->vb;
		bool have_active_after = false;
		struct hwsvideo_buffer *next = NULL;

		spin_lock_irqsave(&v->irq_lock, flags);
		if (v->active == buf) {
			if (!list_empty(&v->capture_queue)) {
				next = list_first_entry(&v->capture_queue,
							struct hwsvideo_buffer, list);
				list_del_init(&next->list);
				if (v->queued_count)
					v->queued_count--;
				next->slot = 0;
				v->active = next;
			} else {
				v->active = NULL;
			}
		}
		have_active_after = v->active != NULL;
		spin_unlock_irqrestore(&v->irq_lock, flags);

		vb2_set_plane_payload(&vb2v->vb2_buf, 0, v->pix.sizeimage);
		vb2v->sequence = ++v->sequence_number;
		vb2v->vb2_buf.timestamp = ktime_get_ns();
		vb2_buffer_done(&vb2v->vb2_buf, VB2_BUF_STATE_DONE);
		v->last_frame_jiffies = jiffies;
		WRITE_ONCE(v->ring_first_half_copied, false);
		WRITE_ONCE(v->ring_last_toggle_jiffies, jiffies);

		if (!ring_mode) {
			if (next) {
				dma_addr_t dma =
					vb2_dma_contig_plane_dma_addr(&next->vb.vb2_buf, 0);

				hws_program_video_from_vb2(hws, v, &next->vb.vb2_buf);
				wmb();
				hws_set_dma_doorbell(hws, v->channel_index, dma,
						     "bh_next_zero");
				rearm_timer = true;
			} else {
				hws_enable_video_capture(hws, v->channel_index, false);
				WRITE_ONCE(v->cap_active, false);
				rearm_timer = false;
			}
		} else {
			rearm_timer = have_active_after;
		}

		goto out_rearm;
	}

out_rearm:
	if (rearm_timer && READ_ONCE(v->cap_active)) {
		unsigned long last = READ_ONCE(v->ring_last_toggle_jiffies);
		unsigned long expires = last + timeout_period;

		mod_timer(&v->dma_timeout_timer, expires);
	}

	hws_arm_next(hws, ch);
}


irqreturn_t hws_irq_handler(int irq, void *info)
{
    struct hws_pcie_dev *pdx = info;
    struct device *dev = &pdx->pdev->dev;
    u32 int_state, ack_mask = 0;
    dev_dbg_ratelimited(dev, "irq: entry\n");
    if (likely(pdx->bar0_base)) {
        dev_dbg_ratelimited(dev, "irq: INT_EN=0x%08x INT_STATUS=0x%08x\n",
                readl(pdx->bar0_base + INT_EN_REG_BASE),
                readl(pdx->bar0_base + HWS_REG_INT_STATUS));
    }

    /* Fast path: if suspended, quietly ack and exit */
    if (unlikely(READ_ONCE(pdx->suspended))) {
        int_state = readl(pdx->bar0_base + HWS_REG_INT_STATUS);
        if (int_state)
            writel(int_state, pdx->bar0_base + HWS_REG_INT_ACK);
        return int_state ? IRQ_HANDLED : IRQ_NONE;
    }

    // u32 sys_status = readl(pdx->bar0_base + HWS_REG_SYS_STATUS);

    int_state = readl(pdx->bar0_base + HWS_REG_INT_STATUS);
    if (!int_state || int_state == 0xFFFFFFFF) {
        dev_dbg(dev, "irq: spurious or device-gone int_state=0x%08x\n",
                int_state);
        return IRQ_NONE;
    }
        dev_dbg_ratelimited(dev, "irq: entry INT_STATUS=0x%08x\n", int_state);

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
                u32 dma_reg = readl(pdx->bar0_base + HWS_REG_DMA_ADDR(ch));
                dma_rmb(); /* ensure DMA writes visible before we inspect */
                WRITE_ONCE(pdx->video[ch].half_seen, true);
                WRITE_ONCE(pdx->video[ch].last_buf_half_toggle, toggle);
                WRITE_ONCE(pdx->video[ch].ring_toggle_hw, toggle);
                dev_dbg_ratelimited(dev,
                                    "irq: VDONE ch%u toggle=%u dma=0x%08x status=0x%08x\n",
                                    ch, toggle, dma_reg, int_state);
                dev_dbg_ratelimited(dev,
                                    "irq: VDONE ch=%u toggle=%u scheduling BH (cap=%d)\n",
                                    ch, toggle, pdx->video[ch].cap_active);
                tasklet_schedule(&pdx->video[ch].bh_tasklet);
            } else {
                dev_dbg(dev, "irq: VDONE ch=%u ignored (cap=%d stop=%d)\n",
                        ch, pdx->video[ch].cap_active,
                        pdx->video[ch].stop_requested);
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
        writel(ack_mask, pdx->bar0_base + HWS_REG_INT_ACK);
        dev_dbg_ratelimited(dev, "irq: ACK mask=0x%08x\n", ack_mask);

        /* Immediately clear ack_mask to avoid re-acknowledging stale bits */
        ack_mask = 0;

        /* Re‐read in case new interrupt bits popped while processing */
        int_state = readl(pdx->bar0_base + HWS_REG_INT_STATUS);
        dev_dbg_ratelimited(dev, "irq: loop cnt=%u new INT_STATUS=0x%08x\n",
                            cnt, int_state);
        if (cnt + 1 == MAX_INT_LOOPS)
            dev_warn_ratelimited(&pdx->pdev->dev,
                                 "IRQ storm? status=0x%08x\n", int_state);
    }

    return IRQ_HANDLED;
}
