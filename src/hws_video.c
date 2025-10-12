// SPDX-License-Identifier: GPL-2.0-only
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/overflow.h>
#include <linux/delay.h>
#include <linux/bits.h>
#include <linux/timer.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/string.h>

#include <media/v4l2-ioctl.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-dev.h>
#include <media/v4l2-event.h>
#include <media/videobuf2-v4l2.h>
#include <media/videobuf2-core.h>
#include <media/v4l2-device.h>
#include <media/videobuf2-dma-contig.h>

#include "hws.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws_audio.h"
#include "hws_irq.h"
#include "hws_v4l2_ioctl.h"

#include <sound/core.h>
#include <sound/control.h>
#include <sound/pcm.h>
#include <sound/rawmidi.h>
#include <sound/initval.h>

#define HWS_MAX_BUFS 32
#define HWS_REMAP_SLOT_OFF(ch)   (0x208 + (ch) * 8)     /* one 64-bit slot per ch */
#define HWS_BUF_BASE_OFF(ch)     (CVBS_IN_BUF_BASE  + (ch) * PCIE_BARADDROFSIZE)
#define HWS_HALF_SZ_OFF(ch)      (CVBS_IN_BUF_BASE2 + (ch) * PCIE_BARADDROFSIZE)
enum hws_zcopy_mode {
	HWS_ZC_ALWAYS = 0,
	HWS_ZC_AUTO   = 1,
	HWS_ZC_NEVER  = 2,
};

static int zero_copy_mode = HWS_ZC_AUTO;
module_param(zero_copy_mode, int, 0644);
MODULE_PARM_DESC(zero_copy_mode,
		 "0=always zero copy (two buffers), 1=auto fallback (default), 2=never zero copy (always copy-out)");

struct hws_ring_buf {
    struct hws_video *vid;
    unsigned int      slot;
    void             *cpu;
    dma_addr_t        dma;
    size_t            size;
    bool              external;
};

static void update_live_resolution(struct hws_pcie_dev *pdx, unsigned int ch);
static bool hws_update_active_interlace(struct hws_pcie_dev *pdx,
					unsigned int ch);
static void handle_hwv2_path(struct hws_pcie_dev *hws, unsigned int ch);
static void handle_legacy_path(struct hws_pcie_dev *hws, unsigned int ch);
static u32 hws_calc_sizeimage(struct hws_video *v, u16 w, u16 h,
			      bool interlaced);
static u32 hws_frame_bytes(struct hws_video *vid);
static void hws_ring_release(struct hws_video *vid);
static int hws_ring_setup(struct hws_video *vid);
static int hws_program_video_ring(struct hws_pcie_dev *hws,
                                  struct hws_video *vid);
void hws_queue_assign_locked(struct hws_video *vid);
static void hws_video_drain_queue_locked(struct hws_video *vid);

/* DMA timeout handler */
static void hws_dma_timeout_handler(struct timer_list *t)
{
        struct hws_video *vid = container_of(t, struct hws_video, dma_timeout_timer);
	struct hws_pcie_dev *hws = vid->parent;
	unsigned long flags;
	
	dev_warn(&hws->pdev->dev,
		 "DMA timeout on channel %d (slot0=%pK slot1=%pK)\n",
		 vid->channel_index,
		 vid->half_owner[0] ? &vid->half_owner[0]->vb : NULL,
		 vid->half_owner[1] ? &vid->half_owner[1]->vb : NULL);
	{
		u32 ch = vid->channel_index;
		u32 dma_reg = readl(hws->bar0_base + HWS_REG_DMA_ADDR(ch));
		u32 int_status = readl(hws->bar0_base + HWS_REG_INT_STATUS);
		u32 vcap = readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);
		u32 sys = readl(hws->bar0_base + HWS_REG_SYS_STATUS);
		u32 toggle = readl(hws->bar0_base + HWS_REG_VBUF_TOGGLE(ch)) & 0x01;
		u32 table_off = HWS_REMAP_SLOT_OFF(ch);
		u32 remap_hi = readl(hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off);
		u32 remap_lo = readl(hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off + PCIE_BARADDROFSIZE);
		u32 buf_base = readl(hws->bar0_base + HWS_BUF_BASE_OFF(ch));
		dev_info(&hws->pdev->dev,
			 "timeout diag ch%u: DMA_REG=0x%08x VBUF_TOGGLE=%u INT_STATUS=0x%08x VCAP=0x%08x SYS_STATUS=0x%08x remap_hi=0x%08x remap_lo=0x%08x buf_base=0x%08x\n",
			 ch, dma_reg, toggle, int_status, vcap, sys, remap_hi, remap_lo, buf_base);
	}

	vid->timeout_count++;
	
	/* Reset the channel and complete current buffers with error */
	spin_lock_irqsave(&vid->irq_lock, flags);
	hws_video_drain_queue_locked(vid);
	spin_unlock_irqrestore(&vid->irq_lock, flags);
	
	/* Try to restart capture if we have queued buffers */
	tasklet_schedule(&vid->bh_tasklet);
}

static bool hws_wait_dma_idle(struct hws_pcie_dev *hws, unsigned int ch,
			      unsigned long timeout_ms)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(timeout_ms);

	if (!hws || !hws->bar0_base)
		return true;

	for (;;) {
		u32 sys = readl(hws->bar0_base + HWS_REG_SYS_STATUS);
		if (!(sys & HWS_SYS_DMA_BUSY_BIT))
			return true;
		if (time_after(jiffies, timeout)) {
			dev_warn(&hws->pdev->dev,
				 "wait_dma_idle timeout ch%u SYS_STATUS=0x%08x\n",
				 ch, sys);
			return false;
		}
		usleep_range(500, 1000);
	}
}

static void hws_ring_release(struct hws_video *vid)
{
	struct hws_pcie_dev *hws = vid->parent;

	if (vid->ring_cpu) {
		dma_free_coherent(&hws->pdev->dev, vid->ring_bytes,
				  vid->ring_cpu, vid->ring_dma);
		vid->ring_cpu = NULL;
	}
	vid->ring_dma = 0;
	vid->ring_bytes = 0;
	vid->half_bytes = 0;
	vid->half_cpu[0] = vid->half_cpu[1] = NULL;
	vid->half_dma[0] = vid->half_dma[1] = 0;
	vid->half_owner[0] = vid->half_owner[1] = NULL;
	vid->alloc_slots = 0;
	vid->queued_slots = 0;
	vid->ring_ready = false;
}

static int hws_ring_setup(struct hws_video *vid)
{
	struct hws_pcie_dev *hws = vid->parent;
	void *cpu;
	dma_addr_t dma;
	u32 half = hws_frame_bytes(vid);
	u32 need;

	need = half * 2;
	if (vid->ring_ready && vid->half_bytes == half)
		return 0;

	hws_ring_release(vid);

	cpu = dma_alloc_coherent(&hws->pdev->dev, need, &dma, GFP_KERNEL);
	if (!cpu)
		return -ENOMEM;

	vid->ring_cpu = cpu;
	vid->ring_dma = dma;
	vid->ring_bytes = need;
	vid->half_bytes = half;
	vid->half_cpu[0] = cpu;
	vid->half_cpu[1] = (u8 *)cpu + half;
	vid->half_dma[0] = dma;
	vid->half_dma[1] = dma + half;
	vid->half_owner[0] = vid->half_owner[1] = NULL;
	vid->alloc_slots = 0;
	vid->queued_slots = 0;
	vid->dma_slot = 0;
	vid->ring_ready = true;
	return 0;
}

static int hws_program_video_ring(struct hws_pcie_dev *hws,
				       struct hws_video *vid)
{
	const u32 addr_mask     = PCI_E_BAR_ADD_MASK;
	const u32 addr_low_mask = PCI_E_BAR_ADD_LOWMASK;
	const u32 table_off     = HWS_REMAP_SLOT_OFF(vid->channel_index);
	dma_addr_t paddr;
	u32 lo, hi, pci_addr;

	if (!vid->ring_ready)
		return -EINVAL;

	paddr = vid->ring_dma;
	lo = lower_32_bits(paddr);
	hi = upper_32_bits(paddr);
	pci_addr = lo & addr_low_mask;

	writel(hi, hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off + 0);
	(void)readl(hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off + 0);
	writel(lo & addr_mask,
	       hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off + PCIE_BARADDROFSIZE);
	(void)readl(hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off + PCIE_BARADDROFSIZE);

	writel((vid->channel_index + 1) * PCIEBAR_AXI_BASE + pci_addr,
	       hws->bar0_base + CVBS_IN_BUF_BASE + vid->channel_index * PCIE_BARADDROFSIZE);
	(void)readl(hws->bar0_base + CVBS_IN_BUF_BASE + vid->channel_index * PCIE_BARADDROFSIZE);

	writel(vid->half_bytes / 16,
	       hws->bar0_base + CVBS_IN_BUF_BASE2 + vid->channel_index * PCIE_BARADDROFSIZE);
	(void)readl(hws->bar0_base + CVBS_IN_BUF_BASE2 + vid->channel_index * PCIE_BARADDROFSIZE);

	hws_set_dma_doorbell(hws, vid->channel_index, vid->ring_dma, "ring_program");
	return 0;
}

void hws_queue_assign_locked(struct hws_video *vid)
{
	struct hwsvideo_buffer *buf, *tmp;

	list_for_each_entry_safe(buf, tmp, &vid->capture_queue, list) {
		struct hws_ring_buf *rb = buf->vb.vb2_buf.planes[0].mem_priv;
		unsigned int slot = rb->slot;

		if (!vid->ring_mode) {
			if (slot >= 2 || vid->half_owner[slot]) {
				slot = vid->half_owner[0] ? (vid->half_owner[1] ? 2 : 1) : 0;
				rb->slot = slot;
			}
		} else {
			if (slot >= 2)
				continue;
		}

		if (slot >= 2)
			continue;
		if (vid->half_owner[slot])
			continue;
		list_del_init(&buf->list);
		vid->half_owner[slot] = buf;
		vid->queued_slots |= BIT(slot);
	}
}

void hws_prepare_vb(struct hws_video *vid, struct hwsvideo_buffer *buf,
		       unsigned int slot)
{
	struct hws_ring_buf *rb;
	size_t payload = vid->half_bytes;

	if (!buf)
		return;

	rb = buf->vb.vb2_buf.planes[0].mem_priv;
	if (!vid->ring_mode && rb) {
		size_t copy = min(payload, rb->size);
		memcpy(rb->cpu, vid->half_cpu[slot], copy);
		dma_sync_single_for_device(&vid->parent->pdev->dev, rb->dma, copy,
					 DMA_TO_DEVICE);
		rb->slot = 2;
	}

	vb2_set_plane_payload(&buf->vb.vb2_buf, 0, payload);
}

static void *hws_ring_alloc(struct vb2_buffer *vb, struct device *dev,
			    unsigned long size)
{
	struct hws_video *vid = vb->vb2_queue->drv_priv;
	struct hws_ring_buf *rb;
	unsigned int slot;
	int ret;
	struct hws_pcie_dev *hws = vid->parent;
	size_t need;

	ret = hws_ring_setup(vid);
	if (ret)
		return ERR_PTR(ret);

	rb = kzalloc(sizeof(*rb), GFP_KERNEL);
	if (!rb)
		return ERR_PTR(-ENOMEM);

	rb->vid = vid;

	if (vid->ring_mode) {
	if (size && size > vid->half_bytes)
		goto err_inval;
		for (slot = 0; slot < 2; slot++) {
			if (!(vid->alloc_slots & BIT(slot)))
				break;
		}
	if (slot >= 2)
		goto err_busy;

		vid->alloc_slots |= BIT(slot);
		rb->slot = slot;
		rb->cpu = vid->half_cpu[slot];
		rb->dma = vid->half_dma[slot];
		rb->size = vid->half_bytes;
		rb->external = false;
		return rb;
	}

	/* fallback copy-out: allocate dedicated buffer */
	need = vid->pix.sizeimage ? vid->pix.sizeimage : vid->half_bytes;
	if (!need)
		need = size ? size : PAGE_SIZE;
	need = ALIGN(need, 64);
	rb->cpu = dma_alloc_coherent(&hws->pdev->dev, need, &rb->dma, GFP_KERNEL);
	if (!rb->cpu)
		goto err_nomem;

	rb->slot = 2; /* assigned when queued */
	rb->size = need;
	rb->external = true;
	return rb;

err_busy:
	kfree(rb);
	return ERR_PTR(-ENOSPC);

err_inval:
	kfree(rb);
	return ERR_PTR(-EINVAL);

err_nomem:
	kfree(rb);
	return ERR_PTR(-ENOMEM);
}

static void hws_ring_put(void *buf_priv)
{
	struct hws_ring_buf *rb = buf_priv;
	struct hws_video *vid = rb->vid;
	struct hws_pcie_dev *hws = vid->parent;

	if (vid->ring_mode && rb->slot < 2)
		vid->alloc_slots &= ~BIT(rb->slot);
	if (rb->external && rb->cpu)
		dma_free_coherent(&hws->pdev->dev, rb->size, rb->cpu, rb->dma);
	kfree(rb);
}

static void *hws_ring_vaddr(struct vb2_buffer *vb, void *buf_priv)
{
	struct hws_ring_buf *rb = buf_priv;

	return rb->cpu;
}

static void *hws_ring_cookie(struct vb2_buffer *vb, void *buf_priv)
{
	struct hws_ring_buf *rb = buf_priv;

	return &rb->dma;
}

static unsigned int hws_ring_num_users(void *buf_priv)
{
	return 1;
}

static int hws_ring_mmap(void *buf_priv, struct vm_area_struct *vma)
{
	struct hws_ring_buf *rb = buf_priv;
	struct hws_video *vid = rb->vid;
	struct hws_pcie_dev *hws = vid->parent;

	return dma_mmap_coherent(&hws->pdev->dev, vma,
				  rb->cpu, rb->dma, rb->size);
}

static const struct vb2_mem_ops hws_ring_memops = {
	.alloc      = hws_ring_alloc,
	.put        = hws_ring_put,
	.vaddr      = hws_ring_vaddr,
	.cookie     = hws_ring_cookie,
	.num_users  = hws_ring_num_users,
	.mmap       = hws_ring_mmap,
};

static int hws_ctrls_init(struct hws_video *vid)
{
	struct v4l2_ctrl_handler *hdl = &vid->control_handler;

	/* Create BCHS + one DV status control */
	v4l2_ctrl_handler_init(hdl, 4);

	vid->ctrl_brightness = v4l2_ctrl_new_std(hdl, &hws_ctrl_ops,
						 V4L2_CID_BRIGHTNESS,
						 MIN_VAMP_BRIGHTNESS_UNITS,
						 MAX_VAMP_BRIGHTNESS_UNITS, 1,
						 HWS_BRIGHTNESS_DEFAULT);

	vid->ctrl_contrast = v4l2_ctrl_new_std(hdl, &hws_ctrl_ops, V4L2_CID_CONTRAST,
					       MIN_VAMP_CONTRAST_UNITS, MAX_VAMP_CONTRAST_UNITS,
					       1, HWS_CONTRAST_DEFAULT);

	vid->ctrl_saturation = v4l2_ctrl_new_std(hdl, &hws_ctrl_ops,
						 V4L2_CID_SATURATION,
						 MIN_VAMP_SATURATION_UNITS,
						 MAX_VAMP_SATURATION_UNITS, 1,
						 HWS_SATURATION_DEFAULT);

	vid->ctrl_hue = v4l2_ctrl_new_std(hdl, &hws_ctrl_ops, V4L2_CID_HUE,
					  MIN_VAMP_HUE_UNITS,
					  MAX_VAMP_HUE_UNITS, 1, HWS_HUE_DEFAULT);


	if (vid->detect_tx_5v_control)
		vid->detect_tx_5v_control->flags |= V4L2_CTRL_FLAG_VOLATILE |
						    V4L2_CTRL_FLAG_READ_ONLY;

	if (hdl->error) {
		int err = hdl->error;

		v4l2_ctrl_handler_free(hdl);
		return err;
	}
	return 0;
}

static void hws_dump_irq_regs(struct hws_pcie_dev *hws, const char *tag)
{
       u32 ien = 0, ist = 0, ack = 0, vcap = 0, dec = 0;
       if (!hws || !hws->bar0_base)
               return;
       ien  = readl(hws->bar0_base + INT_EN_REG_BASE);
       ist  = readl(hws->bar0_base + HWS_REG_INT_STATUS);
       vcap = readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);
       dec  = readl(hws->bar0_base + HWS_REG_DEC_MODE);
       dev_info(&hws->pdev->dev,
                "[%s] INT_EN=0x%08x INT_STATUS=0x%08x VCAP_EN=0x%08x DEC_MODE=0x%08x\n",
                tag ? tag : "dump", ien, ist, vcap, dec);
}

int hws_video_init_channel(struct hws_pcie_dev *pdev, int ch)
{
	struct hws_video *vid;
	struct v4l2_ctrl_handler *hdl;

	/* basic sanity */
	if (!pdev || ch < 0 || ch >= pdev->max_channels)
		return -EINVAL;

	vid = &pdev->video[ch];

	/* hard reset the per-channel struct (safe here since we init everything next) */
	memset(vid, 0, sizeof(*vid));

	/* identity */
	vid->parent = pdev;
	vid->channel_index = ch;

	/* locks & lists */
	mutex_init(&vid->state_lock);
    mutex_init(&vid->qlock);
	spin_lock_init(&vid->irq_lock);
	INIT_LIST_HEAD(&vid->capture_queue);
	vid->sequence_number = 0;

	/* typed tasklet: bind handler once */
	tasklet_setup(&vid->bh_tasklet, hws_bh_video);

	/* DMA timeout timer setup */
	timer_setup(&vid->dma_timeout_timer, hws_dma_timeout_handler, 0);
	vid->last_frame_jiffies = jiffies;
	vid->timeout_count = 0;
	vid->error_count = 0;

	/* default format (adjust to your HW) */
	vid->pix.width = 1920;
	vid->pix.height = 1080;
	vid->pix.fourcc = V4L2_PIX_FMT_YUYV;
	vid->pix.bytesperline = ALIGN(vid->pix.width * 2, 64);
	vid->pix.colorspace = V4L2_COLORSPACE_REC709;
	vid->pix.ycbcr_enc = V4L2_YCBCR_ENC_DEFAULT;
	vid->pix.quantization = V4L2_QUANTIZATION_LIM_RANGE;
	vid->pix.xfer_func = V4L2_XFER_FUNC_DEFAULT;
	vid->pix.field = V4L2_FIELD_NONE;
	vid->pix.interlaced = false;
	vid->pix.sizeimage = hws_calc_sizeimage(vid, vid->pix.width,
						     vid->pix.height, false);
	vid->alloc_sizeimage = vid->pix.sizeimage;

	/* color controls default (mid-scale) */
	vid->current_brightness = 0x80;
	vid->current_contrast = 0x80;
	vid->current_saturation = 0x80;
	vid->current_hue = 0x80;

	/* capture state */
	vid->cap_active = false;
	vid->stop_requested = false;
	vid->last_buf_half_toggle = 0;
	vid->half_seen = false;
	vid->signal_loss_cnt = 0;
	vid->ring_cpu = NULL;
	vid->ring_dma = 0;
	vid->ring_bytes = 0;
	vid->half_bytes = 0;
	vid->half_cpu[0] = vid->half_cpu[1] = NULL;
	vid->half_dma[0] = vid->half_dma[1] = 0;
	vid->half_owner[0] = vid->half_owner[1] = NULL;
	vid->alloc_slots = 0;
	vid->queued_slots = 0;
	vid->ring_ready = false;
	vid->dma_slot = 0;
	vid->ring_mode = (zero_copy_mode != HWS_ZC_NEVER);

	/* Create BCHS + DV power-present as modern controls */
	{
		int err = hws_ctrls_init(vid);

		if (err) {
			dev_err(&pdev->pdev->dev,
				"v4l2 ctrl init failed on ch%d: %d\n", ch, err);
			return err;
		}
	}

	return 0;
}

static void hws_video_drain_queue_locked(struct hws_video *vid)
{
	for (int slot = 0; slot < 2; slot++) {
		if (vid->half_owner[slot]) {
			vb2_buffer_done(&vid->half_owner[slot]->vb.vb2_buf,
				       VB2_BUF_STATE_ERROR);
			if (!vid->ring_mode) {
				struct hws_ring_buf *rb = vid->half_owner[slot]->vb.vb2_buf.planes[0].mem_priv;
				if (rb)
					rb->slot = 2;
			}
			vid->half_owner[slot] = NULL;
		}
	}

	while (!list_empty(&vid->capture_queue)) {
		struct hwsvideo_buffer *b = list_first_entry(&vid->capture_queue,
						     struct hwsvideo_buffer,
						     list);
		list_del_init(&b->list);
		vb2_buffer_done(&b->vb.vb2_buf, VB2_BUF_STATE_ERROR);
		if (!vid->ring_mode) {
			struct hws_ring_buf *rb = b->vb.vb2_buf.planes[0].mem_priv;
			if (rb)
				rb->slot = 2;
		}
	}
	vid->queued_slots = 0;
}

void hws_video_cleanup_channel(struct hws_pcie_dev *pdev, int ch)
{
	struct hws_video *vid;
	unsigned long flags;

	if (!pdev || ch < 0 || ch >= pdev->max_channels)
		return;

	vid = &pdev->video[ch];

	/* 1) Stop HW best-effort for this channel */
	hws_enable_video_capture(vid->parent, vid->channel_index, false);

	/* 2) Flip software state so IRQ/BH will be no-ops if they run */
	WRITE_ONCE(vid->stop_requested, true);
	WRITE_ONCE(vid->cap_active, false);

	/* 3) Make sure the tasklet can’t run anymore (prevents races with drain) */
	tasklet_kill(&vid->bh_tasklet);

	/* 4) Drain SW capture queue & in-flight under lock */
	spin_lock_irqsave(&vid->irq_lock, flags);
	hws_video_drain_queue_locked(vid);
	spin_unlock_irqrestore(&vid->irq_lock, flags);

	/* 5) Release VB2 queue if initialized */
	if (vid->buffer_queue.ops)
		vb2_queue_release(&vid->buffer_queue);

	/* 6) Free V4L2 controls */
	v4l2_ctrl_handler_free(&vid->control_handler);

	/* 7) Unregister the video_device if we own it */
	if (vid->video_device && video_is_registered(vid->video_device))
		video_unregister_device(vid->video_device);
	/* If you allocated it with video_device_alloc(), release it here:
	 * video_device_release(vid->video_device);
	 */
	vid->video_device = NULL;

	/* 8) Reset simple state (don’t memset the whole struct here) */
	mutex_destroy(&vid->state_lock);
	mutex_destroy(&vid->qlock);
	INIT_LIST_HEAD(&vid->capture_queue);
	vid->stop_requested = false;
	vid->last_buf_half_toggle = 0;
	vid->half_seen = false;
	vid->signal_loss_cnt = 0;
	hws_ring_release(vid);
}

/* Convenience cast */
static inline struct hwsvideo_buffer *to_hwsbuf(struct vb2_buffer *vb)
{
	return container_of(to_vb2_v4l2_buffer(vb), struct hwsvideo_buffer, vb);
}

static int hws_buf_init(struct vb2_buffer *vb)
{
    struct hwsvideo_buffer *b = to_hwsbuf(vb);
    INIT_LIST_HEAD(&b->list);
    return 0;
}

static void hws_buf_finish(struct vb2_buffer *vb)
{
	struct hws_video *vid = vb->vb2_queue->drv_priv;
	struct hws_ring_buf *rb = vb->planes[0].mem_priv;
	struct hws_pcie_dev *hws = vid->parent;

	if (!rb)
		return;

	dma_sync_single_for_cpu(&hws->pdev->dev, rb->dma,
				  rb->size, DMA_FROM_DEVICE);
}

static void hws_buf_cleanup(struct vb2_buffer *vb)
{
    struct hwsvideo_buffer *b = to_hwsbuf(vb);
    if (!list_empty(&b->list))
        list_del_init(&b->list);
}


void hws_program_video_from_vb2(struct hws_pcie_dev *hws, unsigned int ch,
                                struct vb2_buffer *vb)
{
	struct hws_video *vid = &hws->video[ch];

	hws_program_video_ring(hws, vid);
}

void hws_set_dma_doorbell(struct hws_pcie_dev *hws,
			  unsigned int ch,
			  dma_addr_t dma_addr,
			  const char *tag)
{
	u32 bar_base = (ch + 1) * PCIEBAR_AXI_BASE;
	u32 dma_offset = (u32)(dma_addr & PCI_E_BAR_ADD_LOWMASK);
	u32 programmed = dma_offset; /* legacy doorbell expects PCI window offset */
	u32 window_addr = bar_base + dma_offset;
	u32 before = readl(hws->bar0_base + HWS_REG_DMA_ADDR(ch));

	iowrite32(programmed, hws->bar0_base + HWS_REG_DMA_ADDR(ch));

	if (tag) {
		u32 after = readl(hws->bar0_base + HWS_REG_DMA_ADDR(ch));
		u32 table_off = HWS_REMAP_SLOT_OFF(ch);
		u32 remap_hi = readl(hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off);
		u32 remap_lo = readl(hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off + PCIE_BARADDROFSIZE);
		u32 buf_base = readl(hws->bar0_base + HWS_BUF_BASE_OFF(ch));
		u32 half_sz = readl(hws->bar0_base + HWS_HALF_SZ_OFF(ch));
		dev_info(&hws->pdev->dev,
			 "%s doorbell ch%u: dma=0x%llx offset=0x%08x bar=0x%08x window=0x%08x programmed=0x%08x reg_before=0x%08x reg_after=0x%08x remap_hi=0x%08x remap_lo=0x%08x buf_base=0x%08x half16B=0x%08x\n",
			 tag, ch, (unsigned long long)dma_addr, dma_offset, bar_base,
			 window_addr, programmed, before, after, remap_hi, remap_lo, buf_base, half_sz);
	}
}

static inline u32 hws_read_port_hpd(struct hws_pcie_dev *hws, unsigned int port)
{
	u32 v0, v1;
	unsigned int pipe0, pipe1;

	if (!hws || !hws->bar0_base)
		return 0;

	/* Each HDMI jack uses two pipes: 2*port and 2*port+1.
	 * Use cur_max_video_ch since it reflects the active HW config.
	 */
	pipe0 = port * 2;
	pipe1 = pipe0 + 1;
	if (pipe1 >= hws->cur_max_video_ch)
		return 0;

	v0 = readl(hws->bar0_base + HWS_REG_HPD(pipe0));
	v1 = readl(hws->bar0_base + HWS_REG_HPD(pipe1));

	/* Treat all-ones as device-gone and avoid propagating garbage. */
	if (unlikely(v0 == 0xFFFFFFFF || v1 == 0xFFFFFFFF)) {
		hws->pci_lost = true;
		return 0;
	}

	return v0 | v1;
}

static int check_video_capture(struct hws_pcie_dev *hws, unsigned int ch)
{
	u32 status;

	if (!hws || !hws->bar0_base)
		return -ENODEV;
	if (ch >= hws->max_channels)
		return -EINVAL;

	status = readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);

	/* Common pattern for a dead/removed PCIe device */
	if (unlikely(status == 0xFFFFFFFF)) {
		hws->pci_lost = true;
		return -ENODEV;
	}

	return !!(status & BIT(ch));
}

void hws_enable_video_capture(struct hws_pcie_dev *hws, unsigned int chan,
			      bool on)
{
	u32 status;

	if (!hws || hws->pci_lost || chan >= hws->max_channels)
		return;

	status = readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);
	status = on ? (status | BIT(chan)) : (status & ~BIT(chan));
	writel(status, hws->bar0_base + HWS_REG_VCAP_ENABLE);
	(void)readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);

	hws->video[chan].cap_active = on;

	dev_dbg(&hws->pdev->dev, "vcap %s ch%u (reg=0x%08x)\n",
		on ? "ON" : "OFF", chan, status);
}


#define LOG_DEC(tag) dev_info(&hws->pdev->dev, "DEC_MODE %s = 0x%08x\n", tag, readl(hws->bar0_base + HWS_REG_DEC_MODE))

static void hws_ack_all_irqs(struct hws_pcie_dev *hws)
{
    u32 st = readl(hws->bar0_base + HWS_REG_INT_STATUS);
    if (st) {
        writel(st, hws->bar0_base + HWS_REG_INT_STATUS); /* W1C */
        (void)readl(hws->bar0_base + HWS_REG_INT_STATUS);
    }
}

static void hws_open_irq_fabric(struct hws_pcie_dev *hws)
{
    /* Route all sources to vector 0 (same value you’re already using) */
    writel(0x00000000, hws->bar0_base + PCIE_INT_DEC_REG_BASE);
    (void)readl(hws->bar0_base + PCIE_INT_DEC_REG_BASE);

    /* Turn on the bridge if your IP needs it */
    writel(0x00000001, hws->bar0_base + PCIEBR_EN_REG_BASE);
    (void)readl(hws->bar0_base + PCIEBR_EN_REG_BASE);

    /* Open the global/bridge gate (legacy 0x3FFFF) */
    writel(0x0003FFFF, hws->bar0_base + INT_EN_REG_BASE);
    (void)readl(hws->bar0_base + INT_EN_REG_BASE);
}

void hws_init_video_sys(struct hws_pcie_dev *hws, bool enable)
{
	int i;

	if (hws->start_run && !enable)
		return;

	/* 1) reset the decoder mode register to 0 */
    writel(0x00000000, hws->bar0_base + HWS_REG_DEC_MODE); LOG_DEC("after reset");

	/* 3) on a full reset, clear all per-channel status and indices */
	if (!enable) {
		for (i = 0; i < hws->max_channels; i++) {
			/* helpers to arm/disable capture engines */
			hws_enable_video_capture(hws, i, false);
			hws_enable_audio_capture(hws, i, false);
		}
	}


	/* 4) enable all interrupts */
	writel(0x3ffff, hws->bar0_base + INT_EN_REG_BASE); LOG_DEC("after runbit");

	/* 5) “Start run”: set bit31, wait a bit, then program low 24 bits */
	writel(0x80000000, hws->bar0_base + HWS_REG_DEC_MODE); LOG_DEC("start run");
	// udelay(500);
	writel(0x80FFFFFF, hws->bar0_base + HWS_REG_DEC_MODE); LOG_DEC("after mask");
	writel(0x13, hws->bar0_base + HWS_REG_DEC_MODE); LOG_DEC("final");
    hws_ack_all_irqs(hws);
    hws_open_irq_fabric(hws);
	/* 6) record that we're now running */
	hws->start_run = true;
}

int hws_check_card_status(struct hws_pcie_dev *hws)
{
	u32 status;

	if (!hws || !hws->bar0_base)
		return -ENODEV;

	status = readl(hws->bar0_base + HWS_REG_SYS_STATUS);

	/* Common “device missing” pattern */
	if (unlikely(status == 0xFFFFFFFF)) {
		hws->pci_lost = true;
		dev_err(&hws->pdev->dev, "PCIe device not responding\n");
		return -ENODEV;
	}

	/* If RUN/READY bit (bit0) isn’t set, (re)initialize the video core */
	if (!(status & BIT(0))) {
		dev_dbg(&hws->pdev->dev,
			"SYS_STATUS not ready (0x%08x), reinitializing\n",
			status);
		hws_init_video_sys(hws, true);
		/* Optional: verify the core cleared its busy bit, if you have one */
		/* int ret = hws_check_busy(hws); */
		/* if (ret) return ret; */
	}

	return 0;
}

void check_video_format(struct hws_pcie_dev *pdx)
{
	int i;

	for (i = 0; i < pdx->cur_max_video_ch; i++) {
		// FIXME: I don't think this works?
		// if (!update_hpd_status(pdx, ch))
		//    return 1;                         /* no +5 V / HPD */

		if (!hws_update_active_interlace(pdx, i)) {
			// return 1;                         /* no active video */
			pdx->video[i].signal_loss_cnt = 1;
		} else {
			if (pdx->hw_ver > 0)
				handle_hwv2_path(pdx, i);
			else
				// FIXME: legacy struct names in subfunction
				handle_legacy_path(pdx, i);

			update_live_resolution(pdx, i);
			pdx->video[i].signal_loss_cnt = 0;
		}

		/* If we just detected a loss on an active capture channel… */
		if (pdx->video[i].signal_loss_cnt == 1 &&
		    pdx->video[i].cap_active) {
			/* …schedule the “no‐video” handler on the vido_wq workqueue */
			// FIXME: this is where we can catch if the system has blanked on us
			// probably need to rewire this, because we removed the videowork
			// https://chatgpt.com/s/t_689fce8c84308191a15ec967d75165a7
			// queue_work(pdx->vido_wq, &pdx->video[i].videowork);
		}
	}
}

static inline void hws_write_if_diff(struct hws_pcie_dev *hws, u32 reg_off,
				     u32 new_val)
{
	void __iomem *addr;
	u32 old;

	if (!hws || !hws->bar0_base)
		return;

	addr = hws->bar0_base + reg_off;

	old = readl(addr);
	/* Treat all-ones as device gone; avoid writing garbage. */
	if (unlikely(old == 0xFFFFFFFF)) {
		hws->pci_lost = true;
		return;
	}

	if (old != new_val) {
		writel(new_val, addr);
		/* Post the write on some bridges / enforce ordering. */
		(void)readl(addr);
	}
}

static bool update_hpd_status(struct hws_pcie_dev *pdx, unsigned int ch)
{
	u32 hpd = hws_read_port_hpd(pdx, ch); /* jack-level status   */
	bool power = !!(hpd & HWS_5V_BIT); /* +5 V present        */
	bool hpd_hi = !!(hpd & HWS_HPD_BIT); /* HPD line asserted   */

	/* Cache the +5 V state in V4L2 ctrl core (only when it changes) */
	if (power != pdx->video[ch].detect_tx_5v_control->cur.val)
		v4l2_ctrl_s_ctrl(pdx->video[ch].detect_tx_5v_control, power);

	/* “Signal present” means *both* rails up. Tweak if your HW differs. */
	return power && hpd_hi;
}

static bool hws_update_active_interlace(struct hws_pcie_dev *pdx,
					unsigned int ch)
{
	u32 reg;
	bool active, interlace;

	if (ch >= pdx->cur_max_video_ch)
		return false;

	reg = readl(pdx->bar0_base + HWS_REG_ACTIVE_STATUS);
	active = !!(reg & BIT(ch));
	interlace = !!(reg & BIT(8 + ch));

	WRITE_ONCE(pdx->video[ch].pix.interlaced, interlace);
	return active;
}

/* Modern hardware path: keep HW registers in sync with current per-channel
 * software state. Adjust the OUT_* bits below to match your HW contract.
 */
static void handle_hwv2_path(struct hws_pcie_dev *hws, unsigned int ch)
{
	struct hws_video *vid;
	u32 reg, in_fps, cur_out_res, want_out_res;

	if (!hws || !hws->bar0_base || ch >= hws->max_channels)
		return;

	vid = &hws->video[ch];

	/* 1) Input frame rate (read-only; log or export via debugfs if wanted) */
	in_fps = readl(hws->bar0_base + HWS_REG_FRAME_RATE(ch));
	/* dev_dbg(&hws->pdev->dev, "ch%u input fps=%u\n", ch, in_fps); */

	/* 2) Output resolution programming
	 * If your HW expects a separate “scaled” size, add fields to track it.
	 * For now, mirror the current format (fmt_curr) to OUT_RES.
	 */
	want_out_res = (vid->pix.height << 16) | vid->pix.width;
	cur_out_res = readl(hws->bar0_base + HWS_REG_OUT_RES(ch));
	if (cur_out_res != want_out_res)
		hws_write_if_diff(hws, HWS_REG_OUT_RES(ch), want_out_res);

	/* 3) Output FPS: only program if you actually track a target.
	 * Example heuristic (disabled by default):
	 *
	 *   u32 out_fps = (vid->fmt_curr.height >= 1080) ? 60 : 30;
	 *   hws_write_if_diff(hws, HWS_REG_OUT_FRAME_RATE(ch), out_fps);
	 */

	/* 4) BCHS controls: pack from per-channel current_* fields */
	reg = readl(hws->bar0_base + HWS_REG_BCHS(ch));
	{
		u8 br = reg & 0xFF;
		u8 co = (reg >> 8) & 0xFF;
		u8 hu = (reg >> 16) & 0xFF;
		u8 sa = (reg >> 24) & 0xFF;

		if (br != vid->current_brightness ||
		    co != vid->current_contrast || hu != vid->current_hue ||
		    sa != vid->current_saturation) {
			u32 packed = (vid->current_saturation << 24) |
				     (vid->current_hue << 16) |
				     (vid->current_contrast << 8) |
				     vid->current_brightness;
			hws_write_if_diff(hws, HWS_REG_BCHS(ch), packed);
		}
	}

	/* 5) HDCP detect: read only (no cache field in your structs today) */
	reg = readl(hws->bar0_base + HWS_REG_HDCP_STATUS);
	/* bool hdcp = !!(reg & BIT(ch)); // use if you later add a field/control */
}

static void handle_legacy_path(struct hws_pcie_dev *hws, unsigned int ch)
{
	/* No-op by default. If you introduce a SW FPS accumulator, map it here.
	 *
	 * Example skeleton:
	 *
	 *   u32 sw_rate = READ_ONCE(hws->sw_fps[ch]); // incremented elsewhere
	 *   if (sw_rate > THRESHOLD) {
	 *       u32 fps = pick_fps_from_rate(sw_rate);
	 *       hws_write_if_diff(hws, HWS_REG_OUT_FRAME_RATE(ch), fps);
	 *       WRITE_ONCE(hws->sw_fps[ch], 0);
	 *   }
	 */
	(void)hws;
	(void)ch;
}

static void hws_video_apply_mode_change(struct hws_pcie_dev *pdx,
					unsigned int ch, u16 w, u16 h,
					bool interlaced)
{
	struct hws_video *v = &pdx->video[ch];
	unsigned long flags;
	u32 new_size;
	bool reenable = false;

	if (!pdx || !pdx->bar0_base)
		return;
	if (ch >= pdx->max_channels)
		return;
	if (!w || !h || w > MAX_VIDEO_HW_W ||
	    (!interlaced && h > MAX_VIDEO_HW_H) ||
	    (interlaced && (h * 2) > MAX_VIDEO_HW_H))
		return;

	WRITE_ONCE(v->stop_requested, true);
	WRITE_ONCE(v->cap_active, false);
	/* Publish software stop first so the hardirq/BH see the stop before
	 * we touch MMIO or the lists. Pairs with READ_ONCE() checks in
	 * hws_bh_video() and hws_arm_next(). Required to prevent the BH/ISR
	 * from completing/arming buffers while we are changing modes.
	 */
	smp_wmb();

hws_enable_video_capture(pdx, ch, false);
readl(pdx->bar0_base + HWS_REG_INT_STATUS);

tasklet_kill(&v->bh_tasklet);

spin_lock_irqsave(&v->irq_lock, flags);
for (int slot = 0; slot < 2; slot++) {
	if (v->half_owner[slot]) {
		vb2_buffer_done(&v->half_owner[slot]->vb.vb2_buf,
			       VB2_BUF_STATE_ERROR);
		v->half_owner[slot] = NULL;
	}
}
while (!list_empty(&v->capture_queue)) {
	struct hwsvideo_buffer *b = list_first_entry(&v->capture_queue,
				struct hwsvideo_buffer, list);
		list_del_init(&b->list);
		vb2_buffer_done(&b->vb.vb2_buf, VB2_BUF_STATE_ERROR);
}
v->queued_slots = 0;
spin_unlock_irqrestore(&v->irq_lock, flags);

	/* Update software pixel state */
	v->pix.width = w;
	v->pix.height = h;
	v->pix.interlaced = interlaced;

	new_size = hws_calc_sizeimage(v, w, h, interlaced);

	/* If buffers are smaller than new requirement, signal src-change & error the queue */
	if (vb2_is_busy(&v->buffer_queue) && new_size > v->alloc_sizeimage) {
		struct v4l2_event ev = {
			.type = V4L2_EVENT_SOURCE_CHANGE,
		};
		ev.u.src_change.changes = V4L2_EVENT_SRC_CH_RESOLUTION;

		v4l2_event_queue(v->video_device, &ev);
		vb2_queue_error(&v->buffer_queue);
		return;
	}

	/* Program HW with new resolution */
	hws_write_if_diff(pdx, HWS_REG_OUT_RES(ch), (h << 16) | w);

	/* Legacy half-buffer programming */
	writel(v->pix.half_size / 16,
	       pdx->bar0_base + CVBS_IN_BUF_BASE2 + ch * PCIE_BARADDROFSIZE);
	(void)readl(pdx->bar0_base + CVBS_IN_BUF_BASE2 +
		    ch * PCIE_BARADDROFSIZE);

	/* Reset per-channel toggles/counters */
	WRITE_ONCE(v->last_buf_half_toggle, 0);
	v->sequence_number = 0;

	hws_ring_release(v);
}

static void update_live_resolution(struct hws_pcie_dev *pdx, unsigned int ch)
{
	u32 reg = readl(pdx->bar0_base + HWS_REG_IN_RES(ch));
	u16 res_w = reg & 0xFFFF;
	u16 res_h = (reg >> 16) & 0xFFFF;
	bool interlace = READ_ONCE(pdx->video[ch].pix.interlaced);

	bool within_hw = (res_w <= MAX_VIDEO_HW_W) &&
			 ((!interlace && res_h <= MAX_VIDEO_HW_H) ||
			  (interlace && (res_h * 2) <= MAX_VIDEO_HW_H));

	if (!within_hw)
		return;

	if (res_w != pdx->video[ch].pix.width ||
	    res_h != pdx->video[ch].pix.height) {
		hws_video_apply_mode_change(pdx, ch, res_w, res_h, interlace);
	}
}

static int hws_open(struct file *file)
{
	int ret;
	struct hws_video *vid;

	/* Create V4L2 file handle so events & priorities work */
	ret = v4l2_fh_open(file);
	if (ret)
		return ret;

	vid = video_drvdata(file);

	/* Hard-fail additional opens while a capture is active */
	if (!v4l2_fh_is_singular_file(file) &&
	    vb2_is_busy(&vid->buffer_queue)) {
		v4l2_fh_release(file);
		return -EBUSY;
	}

	return 0;
}

static int hws_release(struct file *file)
{
	return vb2_fop_release(file);
}

static const struct v4l2_file_operations hws_fops = {
	.owner = THIS_MODULE,
	.open = hws_open,
	.release = hws_release,
	.poll = vb2_fop_poll,
	.unlocked_ioctl = video_ioctl2,
	.mmap = vb2_fop_mmap,
};

static int hws_subscribe_event(struct v4l2_fh *fh,
			       const struct v4l2_event_subscription *sub)
{
	switch (sub->type) {
	case V4L2_EVENT_SOURCE_CHANGE:
		return v4l2_src_change_event_subscribe(fh, sub);
	case V4L2_EVENT_CTRL:
		return v4l2_ctrl_subscribe_event(fh, sub);
	default:
		return -EINVAL;
	}
}

static const struct v4l2_ioctl_ops hws_ioctl_fops = {
	/* Core caps/info */
	.vidioc_querycap = hws_vidioc_querycap,

	/* Pixel format: still needed to report YUYV etc. */
	.vidioc_enum_fmt_vid_cap = hws_vidioc_enum_fmt_vid_cap,
	.vidioc_g_fmt_vid_cap = hws_vidioc_g_fmt_vid_cap,
	.vidioc_s_fmt_vid_cap = hws_vidioc_s_fmt_vid_cap,
	.vidioc_try_fmt_vid_cap = hws_vidioc_try_fmt_vid_cap,

	/* Buffer queueing / streaming */
	.vidioc_reqbufs = vb2_ioctl_reqbufs,
	.vidioc_prepare_buf = vb2_ioctl_prepare_buf,
	.vidioc_create_bufs = vb2_ioctl_create_bufs,
	.vidioc_querybuf = vb2_ioctl_querybuf,
	.vidioc_qbuf = vb2_ioctl_qbuf,
	.vidioc_dqbuf = vb2_ioctl_dqbuf,
	.vidioc_streamon = vb2_ioctl_streamon,
	.vidioc_streamoff = vb2_ioctl_streamoff,

	/* Inputs */
	.vidioc_enum_input = hws_vidioc_enum_input,
	.vidioc_g_input = hws_vidioc_g_input,
	.vidioc_s_input = hws_vidioc_s_input,

	/* DV timings (HDMI/DVI/VESA modes) */
	.vidioc_query_dv_timings = hws_vidioc_query_dv_timings,
	.vidioc_enum_dv_timings = hws_vidioc_enum_dv_timings,
	.vidioc_g_dv_timings = hws_vidioc_g_dv_timings,
	.vidioc_s_dv_timings = hws_vidioc_s_dv_timings,
	.vidioc_dv_timings_cap = hws_vidioc_dv_timings_cap,

	.vidioc_log_status = vidioc_log_status,
	.vidioc_subscribe_event = hws_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,
	.vidioc_g_parm = hws_vidioc_g_parm,
	.vidioc_s_parm = hws_vidioc_s_parm,
};

static u32 hws_calc_sizeimage(struct hws_video *v, u16 w, u16 h,
			      bool interlaced)
{
	u32 bytesperline = ALIGN(w * 2, 64);
	size_t size;

	if (!bytesperline)
		bytesperline = ALIGN(2U, 64);

	size = (size_t)bytesperline * (size_t)max_t(u16, h, 1);
	size = rounddown(size, HWS_HALF_ALIGN_BYTES);
	if (!size)
		size = HWS_HALF_ALIGN_BYTES;
	if (size > U32_MAX)
		size = U32_MAX;

	v->pix.bytesperline = bytesperline;
	v->pix.sizeimage = (u32)size;
	v->pix.half_size = v->pix.sizeimage;
	v->pix.field = interlaced ? V4L2_FIELD_INTERLACED : V4L2_FIELD_NONE;

	return v->pix.sizeimage;
}

static u32 hws_frame_bytes(struct hws_video *vid)
{
	u32 size = vid->pix.sizeimage;

	if (!size) {
		bool interlaced = vid->pix.field == V4L2_FIELD_INTERLACED;
		size = hws_calc_sizeimage(vid, vid->pix.width, vid->pix.height,
					  interlaced);
	}

	if (!size) {
		size = HWS_HALF_ALIGN_BYTES;
		vid->pix.sizeimage = size;
	}
	if (!vid->pix.half_size)
		vid->pix.half_size = size;

	return size;
}

static int hws_queue_setup(struct vb2_queue *q, unsigned int *num_buffers,
			   unsigned int *nplanes, unsigned int sizes[],
			   struct device *alloc_devs[])
{
	struct hws_video *vid = q->drv_priv;
	struct hws_pcie_dev *hws = vid->parent;
	unsigned int have = vb2_get_num_buffers(q);
	unsigned int requested = *num_buffers ? *num_buffers : 1;
	u32 frame_bytes = hws_frame_bytes(vid);

	if (have == 0) {
		switch (zero_copy_mode) {
		case HWS_ZC_ALWAYS:
			vid->ring_mode = true;
			break;
		case HWS_ZC_NEVER:
			vid->ring_mode = false;
			break;
		case HWS_ZC_AUTO:
			vid->ring_mode = (requested <= 2);
			break;
		}
	} else {
		/* keep existing mode once buffers are allocated */
	}

	if (vid->ring_mode && zero_copy_mode == HWS_ZC_AUTO && requested > 2)
		vid->ring_mode = false;

	if (!frame_bytes)
		return -EINVAL;

	if (*nplanes) {
		if (*nplanes != 1)
			return -EINVAL;
		if (sizes[0] < frame_bytes)
			sizes[0] = frame_bytes;
	} else {
		*nplanes = 1;
		sizes[0] = frame_bytes;
	}

	if (alloc_devs)
		alloc_devs[0] = &hws->pdev->dev;

	if (*num_buffers == 0) {
		vid->alloc_sizeimage = frame_bytes;
		return 0;
	}

	if (vid->ring_mode) {
		if (*num_buffers > 2)
			*num_buffers = 2;
		if (have >= 2)
			*num_buffers = 0;
		else if (have + *num_buffers > 2)
			*num_buffers = 2 - have;
		if (*num_buffers == 0)
			return have >= 2 ? 0 : -ENOBUFS;
	} else {
		if (*num_buffers > HWS_MAX_BUFS)
			*num_buffers = HWS_MAX_BUFS;
		if (*num_buffers == 0)
			*num_buffers = 1;
	}

	vid->alloc_sizeimage = frame_bytes;
	return 0;
}

static int hws_buffer_prepare(struct vb2_buffer *vb)
{
	struct hws_video *vid = vb->vb2_queue->drv_priv;
	struct hws_ring_buf *rb = vb->planes[0].mem_priv;

	if (!rb)
		return -EINVAL;

	vb2_set_plane_payload(vb, 0, vid->half_bytes);
	return 0;
}

static void hws_buffer_queue(struct vb2_buffer *vb)
{
	struct hws_video *vid = vb->vb2_queue->drv_priv;
	struct hwsvideo_buffer *buf = to_hwsbuf(vb);
	struct hws_ring_buf *rb = vb->planes[0].mem_priv;
	unsigned long flags;

	if (!vid->ring_mode && rb)
		rb->slot = 2;

	spin_lock_irqsave(&vid->irq_lock, flags);
	if (!list_empty(&buf->list))
		list_del_init(&buf->list);
	list_add_tail(&buf->list, &vid->capture_queue);
	hws_queue_assign_locked(vid);
	spin_unlock_irqrestore(&vid->irq_lock, flags);
}

static inline u32 hws_r32(void __iomem *base, u32 off)
{
	/* Single place to add barriers or tracing if needed */
	return readl(base + off);
}

static void hws_dump_pipe_regs(struct hws_pcie_dev *hws, int ch)
{
	struct device *dev = &hws->pdev->dev;
	u32 hpd      = hws_r32(hws->bar0_base, HWS_REG_HPD(ch));
	u32 vtoggle  = hws_r32(hws->bar0_base, HWS_REG_VBUF_TOGGLE(ch));
	u32 atoggle  = hws_r32(hws->bar0_base, HWS_REG_ABUF_TOGGLE(ch));
	u32 in_res   = hws_r32(hws->bar0_base, HWS_REG_IN_RES(ch));
	u32 bchs     = hws_r32(hws->bar0_base, HWS_REG_BCHS(ch));
	u32 infps    = hws_r32(hws->bar0_base, HWS_REG_FRAME_RATE(ch));
	u32 out_res  = hws_r32(hws->bar0_base, HWS_REG_OUT_RES(ch));
	u32 outfps   = hws_r32(hws->bar0_base, HWS_REG_OUT_FRAME_RATE(ch));

	/* NEW: per-channel buffer base & half-size */
	u32 buf_base = hws_r32(hws->bar0_base, HWS_BUF_BASE_OFF(ch));
	u32 half_sz  = hws_r32(hws->bar0_base, HWS_HALF_SZ_OFF(ch)); /* units of 16 bytes per your program path */

	/* NEW: remap slot (legacy order: HI at +0, page-LO at +4) */
	u32 remap_hi = hws_r32(hws->bar0_base, PCI_ADDR_TABLE_BASE + HWS_REMAP_SLOT_OFF(ch) + 0);
	u32 remap_lo = hws_r32(hws->bar0_base, PCI_ADDR_TABLE_BASE + HWS_REMAP_SLOT_OFF(ch) + PCIE_BARADDROFSIZE);

	u16 in_w  = (in_res  >> 16) & 0xFFFF;
	u16 in_h  = (in_res  >>  0) & 0xFFFF;
	u16 out_w = (out_res >> 16) & 0xFFFF;
	u16 out_h = (out_res >>  0) & 0xFFFF;

	dev_dbg(dev, "  [CH%u]\n", ch);
	dev_dbg(dev, "    HPD=0x%08x (HPD=%d, +5V=%d)\n",
		hpd, !!(hpd & HWS_HPD_BIT), !!(hpd & HWS_5V_BIT));
	dev_dbg(dev, "    VBUF_TOGGLE=%u  ABUF_TOGGLE=%u\n", vtoggle & 1, atoggle & 1);
	dev_dbg(dev, "    IN_RES=%ux%u  (raw=0x%08x)  IN_FPS=%u\n",
		in_w, in_h, in_res, infps);
	dev_dbg(dev, "    OUT_RES=%ux%u (raw=0x%08x)  OUT_FPS=%u\n",
		out_w, out_h, out_res, outfps);
	dev_dbg(dev, "    BCHS=0x%08x  [B=%u C=%u H=%u S=%u]\n",
		bchs, (bchs >> 24) & 0xFF, (bchs >> 16) & 0xFF,
		(bchs >> 8) & 0xFF, bchs & 0xFF);

	/* NEW: buffer programming visibility */
	dev_dbg(dev, "    BUF_BASE=0x%08x  HALF_SZ(16B)=0x%08x\n", buf_base, half_sz);
	dev_dbg(dev, "    REMAP_SLOT: HI=0x%08x  page-LO=0x%08x\n", remap_hi, remap_lo);
}

void hws_video_dump_all_regs(struct hws_pcie_dev *hws, const char *tag)
{
	struct device *dev = &hws->pdev->dev;
	u32 sys_status   = hws_r32(hws->bar0_base, HWS_REG_SYS_STATUS);
	u32 dec_mode     = hws_r32(hws->bar0_base, HWS_REG_DEC_MODE);
	u32 int_status   = hws_r32(hws->bar0_base, HWS_REG_INT_STATUS);
	u32 int_en_gate  = hws_r32(hws->bar0_base, INT_EN_REG_BASE);
	u32 int_route    = hws_r32(hws->bar0_base, PCIE_INT_DEC_REG_BASE);
	u32 br_en        = hws_r32(hws->bar0_base, PCIEBR_EN_REG_BASE);

	u32 v_en         = hws_r32(hws->bar0_base, HWS_REG_VCAP_ENABLE);
	u32 a_en         = hws_r32(hws->bar0_base, HWS_REG_ACAP_ENABLE);
	u32 active       = hws_r32(hws->bar0_base, HWS_REG_ACTIVE_STATUS);
	u32 hdcp         = hws_r32(hws->bar0_base, HWS_REG_HDCP_STATUS);
	u32 dma_max      = hws_r32(hws->bar0_base, HWS_REG_DMA_MAX_SIZE);
	/* NOTE: VBUF1_ADDR kept for reference; real per-channel bases printed above */
	u32 vbuf1_addr   = hws_r32(hws->bar0_base, HWS_REG_VBUF1_ADDR);
	u32 dev_info     = hws_r32(hws->bar0_base, HWS_REG_DEVICE_INFO);

	u8  dev_ver    = (dev_info >>  0) & 0xFF;
	u8  dev_subver = (dev_info >>  8) & 0xFF;
	u8  port_id    = (dev_info >> 16) & 0x1F;
	u8  yv12_flags = (dev_info >> 28) & 0x0F;

	dev_dbg(dev, "=============== HWS REG DUMP (%s) ===============\n", tag ? tag : "");
	dev_dbg(dev, " BAR0=%pK\n", hws->bar0_base);

	/* Core / global */
	dev_dbg(dev, "-- CORE/GLOBAL --\n");
	dev_dbg(dev, " SYS_STATUS     = 0x%08x  [DMA_BUSY=%d]\n",
		sys_status, !!(sys_status & HWS_SYS_DMA_BUSY_BIT));
	dev_dbg(dev, " DEC_MODE       = 0x%08x\n", dec_mode);

	/* Interrupt fabric */
	dev_dbg(dev, "-- INTERRUPTS --\n");
	dev_dbg(dev, " INT_STATUS     = 0x%08x\n", int_status);
	dev_dbg(dev, " INT_EN_GATE    = 0x%08x  (global/bridge gate)\n", int_en_gate);
	dev_dbg(dev, " INT_ROUTE      = 0x%08x  (router/decoder)\n", int_route);
	dev_dbg(dev, " BRIDGE_EN      = 0x%08x\n", br_en);

	/* Capture on/off + activity */
	dev_dbg(dev, "-- CAPTURE/STATUS --\n");
	dev_dbg(dev, " VCAP_ENABLE    = 0x%08x (bits0-3 CH0..CH3)\n", v_en);
	dev_dbg(dev, " ACAP_ENABLE    = 0x%08x (bits0-3 CH0..CH3)\n", a_en);
	dev_dbg(dev, " ACTIVE_STATUS  = 0x%08x (sig bits0-3 | interlace bits8-11)\n", active);
	dev_dbg(dev, " HDCP_STATUS    = 0x%08x\n", hdcp);

	/* DMA / buffers */
	dev_dbg(dev, "-- DMA/BUFFERS --\n");
	dev_dbg(dev, " DMA_MAX_SIZE   = 0x%08x\n", dma_max);
	dev_dbg(dev, " VBUF1_ADDR     = 0x%08x  (legacy/global; per-channel bases below)\n", vbuf1_addr);

	/* Device info */
	dev_dbg(dev, "-- DEVICE --\n");
	dev_dbg(dev, " DEVICE_INFO    = 0x%08x  (ver=%u subver=%u port=%u yv12=0x%x)\n",
		dev_info, dev_ver, dev_subver, port_id, yv12_flags);

	/* Per-channel block (now includes buffer & remap info) */
	dev_dbg(dev, "-- PER-CHANNEL --\n");
	for (int ch = 0; ch < MAX_VID_CHANNELS; ch++)
		hws_dump_pipe_regs(hws, ch);

	/* Per-channel diagnostics */
	dev_dbg(dev, "-- CHANNEL DIAGNOSTICS --\n");
	for (int ch = 0; ch < hws->cur_max_video_ch; ch++) {
		struct hws_video *v = &hws->video[ch];
		u32 dma_addr_reg = hws_r32(hws->bar0_base, HWS_REG_DMA_ADDR(ch));
		dev_dbg(dev,
			"  CH%u: cap_active=%d stop_req=%d queued_mask=0x%lx seq=%u timeout_cnt=%u err_cnt=%u\n",
			ch, v->cap_active, v->stop_requested, v->queued_slots,
			v->sequence_number, v->timeout_count, v->error_count);
		dev_dbg(dev, "       DMA_ADDR_REG=0x%08x queue_len=%d\n",
			dma_addr_reg, !list_empty(&v->capture_queue));
	}

	/* Decoded INT_STATUS */
	dev_dbg(dev, "-- INT_STATUS DECODE --\n");
	for (int ch = 0; ch < MAX_VID_CHANNELS; ch++) {
		bool vdone = !!(int_status & HWS_INT_VDONE_BIT(ch));
		bool adone = !!(int_status & HWS_INT_ADONE_BIT(ch));
		dev_dbg(dev, "  CH%u: VDONE=%d ADONE=%d\n", ch, vdone, adone);
	}

	dev_dbg(dev, "============== END HWS REG DUMP (%s) ==============\n", tag ? tag : "");
}



static int hws_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct hws_video *v = q->drv_priv;
	struct hws_pcie_dev *hws = v->parent;
	struct device *dev = &hws->pdev->dev;
	unsigned long flags;
	int ret;

	dev_dbg(dev, "start_streaming(ch=%u): entry, count=%u\n",
		v->channel_index, count);

	ret = hws_check_card_status(hws);
	if (ret)
		return ret;

	ret = hws_ring_setup(v);
	if (ret)
		return ret;

	spin_lock_irqsave(&v->irq_lock, flags);
	hws_queue_assign_locked(v);
	if (!v->half_owner[0] || !v->half_owner[1]) {
		spin_unlock_irqrestore(&v->irq_lock, flags);
		dev_warn(dev, "start_streaming(ch=%u): insufficient buffers queued\n",
			 v->channel_index);
		return -ENOBUFS;
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	ret = hws_program_video_ring(hws, v);
	if (ret)
		return ret;

	mutex_lock(&v->state_lock);
	WRITE_ONCE(v->stop_requested, false);
	WRITE_ONCE(v->cap_active, true);
	WRITE_ONCE(v->half_seen, false);
	WRITE_ONCE(v->last_buf_half_toggle, 0);
	mutex_unlock(&v->state_lock);

	hws_enable_video_capture(hws, v->channel_index, true);
	mod_timer(&v->dma_timeout_timer, jiffies + msecs_to_jiffies(2000));
	return 0;
}

static inline bool list_node_unlinked(const struct list_head *n)
{
    return n->next == LIST_POISON1 || n->prev == LIST_POISON2;
}

static void hws_stop_streaming(struct vb2_queue *q)
{
    struct hws_video *v = q->drv_priv;
    unsigned long flags;
    struct hwsvideo_buffer *b, *tmp;
    LIST_HEAD(done);

    /* 1) Quiesce SW/HW first */
    mutex_lock(&v->state_lock);
    WRITE_ONCE(v->cap_active, false);
    WRITE_ONCE(v->stop_requested, true);
    mutex_unlock(&v->state_lock);

    /* Cancel any pending timeout */
    timer_delete_sync(&v->dma_timeout_timer);

    hws_enable_video_capture(v->parent, v->channel_index, false);

    /* 2) Collect in-flight + queued under the IRQ lock */
    spin_lock_irqsave(&v->irq_lock, flags);

    for (int slot = 0; slot < 2; slot++) {
        if (v->half_owner[slot]) {
            list_add_tail(&v->half_owner[slot]->list, &done);
            v->half_owner[slot] = NULL;
        }
    }
    v->queued_slots = 0;

    while (!list_empty(&v->capture_queue)) {
        b = list_first_entry(&v->capture_queue, struct hwsvideo_buffer, list);
        /* Move (not del+add) to preserve invariants and avoid touching poisons */
        list_move_tail(&b->list, &done);
    }

    spin_unlock_irqrestore(&v->irq_lock, flags);

    /* 3) Complete outside the lock */
    list_for_each_entry_safe(b, tmp, &done, list) {
        /* Unlink from 'done' before completing */
        list_del_init(&b->list);
        vb2_buffer_done(&b->vb.vb2_buf, VB2_BUF_STATE_ERROR);
    }

    hws_ring_release(v);
}

static const struct vb2_ops hwspcie_video_qops = {
	.queue_setup = hws_queue_setup,
	.buf_prepare = hws_buffer_prepare,
    .buf_init        = hws_buf_init,
    .buf_finish      = hws_buf_finish,
    .buf_cleanup     = hws_buf_cleanup,
	// .buf_finish = hws_buffer_finish,
	.buf_queue = hws_buffer_queue,
	.wait_prepare = vb2_ops_wait_prepare,
	.wait_finish = vb2_ops_wait_finish,
	.start_streaming = hws_start_streaming,
	.stop_streaming = hws_stop_streaming,
};

int hws_video_register(struct hws_pcie_dev *dev)
{
	int i, ret;

	ret = v4l2_device_register(&dev->pdev->dev, &dev->v4l2_device);
	if (ret) {
		dev_err(&dev->pdev->dev, "v4l2_device_register failed: %d\n",
			ret);
		return ret;
	}

	for (i = 0; i < dev->cur_max_video_ch; i++) {
		struct hws_video *ch = &dev->video[i];
		struct video_device *vdev;
		struct vb2_queue *q;

		/* hws_video_init_channel() should have set:
		 * - ch->parent, ch->channel_index
		 * - locks (state_lock, irq_lock)
		 * - capture_queue (INIT_LIST_HEAD)
		 * - control_handler + controls
		 * - fmt_curr (width/height)
		 * Don’t reinitialize any of those here.
		 */

		vdev = video_device_alloc();
		if (!vdev) {
			dev_err(&dev->pdev->dev,
				"video_device_alloc ch%u failed\n", i);
			ret = -ENOMEM;
			goto err_unwind;
		}
		ch->video_device = vdev;

		/* Basic V4L2 node setup */
		snprintf(vdev->name, sizeof(vdev->name), "%s-hdmi%u",
			 KBUILD_MODNAME, i);
		vdev->v4l2_dev = &dev->v4l2_device;
		vdev->fops = &hws_fops; /* your file_ops */
		vdev->ioctl_ops = &hws_ioctl_fops; /* your ioctl_ops */
		vdev->device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING;
		vdev->lock = &ch->state_lock; /* serialize file ops */
		vdev->ctrl_handler = &ch->control_handler;
		vdev->vfl_dir = VFL_DIR_RX;
		vdev->release = video_device_release_empty;
		if (ch->control_handler.error)
			goto err_unwind;
		video_set_drvdata(vdev, ch);

		/* vb2 queue init (dma-contig) */
		q = &ch->buffer_queue;
		memset(q, 0, sizeof(*q));
		q->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		q->io_modes = VB2_MMAP;
		q->drv_priv = ch;
		q->buf_struct_size = sizeof(struct hwsvideo_buffer);
		q->ops = &hwspcie_video_qops; /* your vb2_ops */
		q->mem_ops = &hws_ring_memops;
		q->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
		q->lock = &ch->qlock;
        q->max_num_buffers = HWS_MAX_BUFS;
        q->min_queued_buffers = 1;
        q->min_reqbufs_allocation = 1;
		q->dev = &dev->pdev->dev;

		ret = vb2_queue_init(q);
		vdev->queue = q;
		if (ret) {
			dev_err(&dev->pdev->dev,
				"vb2_queue_init ch%u failed: %d\n", i, ret);
			goto err_unwind;
		}

		/* Make controls live (no-op if none or already set up) */
		if (ch->control_handler.error) {
			ret = ch->control_handler.error;
			dev_err(&dev->pdev->dev,
				"ctrl handler ch%u error: %d\n", i, ret);
			goto err_unwind;
		}
		v4l2_ctrl_handler_setup(&ch->control_handler);
		ret = video_register_device(vdev, VFL_TYPE_VIDEO, -1);
		if (ret) {
			dev_err(&dev->pdev->dev,
				"video_register_device ch%u failed: %d\n", i,
				ret);
			goto err_unwind;
		}
	}

	return 0;

err_unwind:
	for (i = i - 1; i >= 0; i--) {
		struct hws_video *ch = &dev->video[i];

		if (video_is_registered(ch->video_device))
			video_unregister_device(ch->video_device);

		if (ch->buffer_queue.ops)
			vb2_queue_release(&ch->buffer_queue);
		v4l2_ctrl_handler_free(&ch->control_handler);
		if (ch->video_device) {
			/* If not registered, we must free the alloc’d vdev ourselves */
			if (!video_is_registered(ch->video_device))
				video_device_release(ch->video_device);
			ch->video_device = NULL;
		}
	}
	v4l2_device_unregister(&dev->v4l2_device);
	return ret;
}

void hws_video_unregister(struct hws_pcie_dev *dev)
{
	int i;

	if (!dev)
		return;

	for (i = 0; i < dev->cur_max_video_ch; i++) {
		struct hws_video *ch = &dev->video[i];
		unsigned long flags;

		/* 1) Stop hardware capture for this channel (if running). */
		if (ch->cap_active)
			hws_enable_video_capture(dev, i, false);

		/* 2) Drain SW queue + complete in-flight buffer as ERROR. */
		spin_lock_irqsave(&ch->irq_lock, flags);
		hws_video_drain_queue_locked(ch);
		spin_unlock_irqrestore(&ch->irq_lock, flags);

		/* 3) Release vb2 queue (safe to call once if it was inited). */
		if (ch->buffer_queue.ops)
			vb2_queue_release(&ch->buffer_queue);

		/* 4) Free V4L2 controls. */
		v4l2_ctrl_handler_free(&ch->control_handler);

		/* 5) Unregister the video node (if it was registered). */
		if (ch->video_device) {
			if (video_is_registered(ch->video_device))
				video_unregister_device(ch->video_device);
			else
				video_device_release(ch->video_device);
			ch->video_device = NULL;
		}
		/* 6) Reset lightweight state (optional). */
		ch->cap_active = false;
		ch->stop_requested = false;
		ch->last_buf_half_toggle = 0;
		ch->half_seen = false;
		ch->signal_loss_cnt = 0;
		INIT_LIST_HEAD(&ch->capture_queue);
	}
	v4l2_device_unregister(&dev->v4l2_device);
}

int hws_video_pm_suspend(struct hws_pcie_dev *hws)
{
	int i, ret = 0;

	for (i = 0; i < hws->cur_max_video_ch; i++) {
		struct hws_video *vid = &hws->video[i];
		struct vb2_queue *q = &vid->buffer_queue;

		if (!q || !q->ops)
			continue;
		if (vb2_is_streaming(q)) {
			/* Stop via vb2 (runs your .stop_streaming) */
			int r = vb2_streamoff(q, q->type);

			if (r && !ret)
				ret = r;
		}
	}
	return ret;
}

void hws_video_pm_resume(struct hws_pcie_dev *hws)
{
	/* Nothing mandatory to do here for vb2 — userspace will STREAMON again.
	 * If you track per-channel 'auto-restart' policy, re-arm it here.
	 */
}
