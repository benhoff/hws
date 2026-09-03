// SPDX-License-Identifier: GPL-2.0-only
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/overflow.h>
#include <linux/delay.h>
#include <linux/bits.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/interrupt.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/mm.h>

#include <media/v4l2-ioctl.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-dev.h>
#include <media/v4l2-event.h>
#include <media/videobuf2-v4l2.h>
#include <media/v4l2-device.h>
#include <media/videobuf2-dma-contig.h>

#include "hws.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws_audio.h"
#include "hws_irq.h"
#include "hws_v4l2_ioctl.h"

#define HWS_BUF_BASE_OFF(ch)     (CVBS_IN_BUF_BASE  + (ch) * PCIE_BARADDROFSIZE)
#define HWS_HALF_SZ_OFF(ch)      (CVBS_IN_BUF_BASE2 + (ch) * PCIE_BARADDROFSIZE)

static void update_live_resolution(struct hws_pcie_dev *pdx, unsigned int ch,
				   bool interlace);
static bool hws_read_active_state(struct hws_pcie_dev *pdx, unsigned int ch,
				  bool *interlace);
static void handle_hwv2_path(struct hws_pcie_dev *hws, unsigned int ch);
static void handle_legacy_path(struct hws_pcie_dev *hws, unsigned int ch);
static u32 hws_calc_sizeimage(struct hws_video *v, u16 w, u16 h,
			      bool interlaced);

/* DMA helper functions */
static int hws_program_video_ring_locked(struct hws_video *vid);
static struct hwsvideo_buffer *
hws_take_queued_buffer_locked(struct hws_video *vid);
static void hws_video_reset_completion_locked(struct hws_video *vid);

static unsigned long long hws_elapsed_us(u64 start_ns)
{
	return div_u64(ktime_get_mono_fast_ns() - start_ns, 1000);
}

static inline bool list_node_unlinked(const struct list_head *n)
{
	return n->next == LIST_POISON1 || n->prev == LIST_POISON2;
}

static bool dma_window_verify;
module_param_named(dma_window_verify, dma_window_verify, bool, 0644);
MODULE_PARM_DESC(dma_window_verify,
		 "Read back DMA window registers after programming (debug)");

static size_t hws_video_native_split(size_t frame_size)
{
	return round_down(frame_size / 2, (size_t)SZ_2K);
}

static size_t hws_video_dma_extent(size_t frame_size)
{
	return PAGE_ALIGN(frame_size);
}

static void hws_ack_video_pending(struct hws_pcie_dev *hws, unsigned int ch)
{
	u32 vbit = HWS_INT_VDONE_BIT(ch);

	if (!hws || !hws->bar0_base)
		return;

	writel(vbit, hws->bar0_base + HWS_REG_INT_STATUS);
	(void)readl(hws->bar0_base + HWS_REG_INT_STATUS);
}

static int hws_program_video_ring_locked(struct hws_video *vid)
{
	const u32 addr_mask = PCI_E_BAR_ADD_MASK;
	const u32 addr_low_mask = PCI_E_BAR_ADD_LOWMASK;
	struct hws_pcie_dev *hws = vid->parent;
	unsigned int ch = vid->channel_index;
	u32 table_off = HWS_VIDEO_REMAP_SLOT_OFF(ch);
	dma_addr_t dma;
	size_t extent;
	size_t split;
	u32 lo;
	u32 hi;
	u32 pci_addr;
	u32 page_lo;
	bool wrote = false;

	lockdep_assert_held(&vid->irq_lock);

	dma = hws_video_ring_dma(hws, ch);
	extent = hws_video_dma_extent(vid->pix.sizeimage);
	split = hws_video_native_split(vid->pix.sizeimage);
	if (!dma || !split || split >= vid->pix.sizeimage ||
	    extent > hws_video_ring_capacity() ||
	    !hws_dma_fits_remap_window(dma, extent + PAGE_SIZE))
		return -ERANGE;

	lo = lower_32_bits(dma);
	hi = upper_32_bits(dma);
	pci_addr = lo & addr_low_mask;
	page_lo = lo & addr_mask;

	/* Never retarget the video engine while its VCAP bit is live. */
	if (READ_ONCE(vid->cap_active) &&
	    (!vid->window_valid || vid->last_dma_hi != hi ||
	     vid->last_dma_page != page_lo ||
	     vid->last_pci_addr != pci_addr ||
	     vid->last_half16 != split / 16))
		return -EBUSY;

	/* Remap entry only when DMA crosses into a new 512 MB page */
	if (!vid->window_valid || vid->last_dma_hi != hi ||
	    vid->last_dma_page != page_lo) {
		writel(hi, hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off);
		writel(page_lo,
		       hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off +
		       PCIE_BARADDROFSIZE);
		vid->last_dma_hi = hi;
		vid->last_dma_page = page_lo;
		wrote = true;
	}

	/* Base pointer only needs low 29 bits */
	if (!vid->window_valid || vid->last_pci_addr != pci_addr) {
		writel((ch + 1) * PCIEBAR_AXI_BASE + pci_addr,
		       hws->bar0_base + HWS_BUF_BASE_OFF(ch));
		vid->last_pci_addr = pci_addr;
		wrote = true;
	}

	/* Half-size only changes when resolution changes */
	if (!vid->window_valid || vid->last_half16 != split / 16) {
		writel(split / 16,
		       hws->bar0_base + HWS_HALF_SZ_OFF(ch));
		vid->last_half16 = split / 16;
		wrote = true;
	}

	vid->pix.half_size = split;
	vid->ring_extent = extent;
	vid->ring_split = split;
	vid->window_valid = true;

	if (dma_window_verify && wrote) {
		u32 r_hi =
		    readl(hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off);
		u32 r_lo =
		    readl(hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off +
			  PCIE_BARADDROFSIZE);
		u32 r_base = readl(hws->bar0_base + HWS_BUF_BASE_OFF(ch));
		u32 r_half = readl(hws->bar0_base + HWS_HALF_SZ_OFF(ch));

		dev_dbg(&hws->pdev->dev,
			"ch%u remap verify: hi=0x%08x page_lo=0x%08x exp_page=0x%08x base=0x%08x exp_base=0x%08x half16B=0x%08x exp_half=0x%08x\n",
			ch, r_hi, r_lo, page_lo, r_base,
			(ch + 1) * PCIEBAR_AXI_BASE + pci_addr, r_half,
			split / 16);
	} else if (wrote) {
		/* Flush posted writes before arming DMA */
		readl_relaxed(hws->bar0_base + HWS_HALF_SZ_OFF(ch));
	}

	return 0;
}

static struct hwsvideo_buffer *
hws_take_queued_buffer_locked(struct hws_video *vid)
{
	struct hwsvideo_buffer *buf;

	if (!vid || list_empty(&vid->capture_queue))
		return NULL;

	buf = list_first_entry(&vid->capture_queue,
			       struct hwsvideo_buffer, list);
	list_del_init(&buf->list);
	if (vid->queued_count)
		vid->queued_count--;
	return buf;
}

static bool hws_force_no_signal_frame(struct hws_video *v, const char *tag)
{
	struct hws_pcie_dev *hws;
	unsigned long flags;
	struct hwsvideo_buffer *buf = NULL;
	size_t extent;
	bool completed = false;
	int ret = 0;

	if (!v)
		return false;
	hws = v->parent;
	if (!hws || !mutex_trylock(&v->state_lock))
		return false;
	if (READ_ONCE(v->stop_requested) || !READ_ONCE(v->cap_active))
		goto out_unlock;

	/* Stop DMA and drain threaded completion before taking its buffer. */
	hws_enable_video_capture(hws, v->channel_index, false);
	if (hws->irq >= 0)
		synchronize_irq(hws->irq);
	ret = hws_try_wait_dma_idle(hws, tag ? tag : "no-signal",
				    v->channel_index);
	if (ret || READ_ONCE(hws->pci_lost)) {
		WRITE_ONCE(v->stop_requested, true);
		vb2_queue_error(&v->buffer_queue);
		goto out_unlock;
	}
	extent = hws_video_dma_extent(v->pix.sizeimage);
	if (v->ring_extent &&
	    !hws_video_ring_guards_ok(hws, v->channel_index,
				      v->ring_extent)) {
		ret = -EOVERFLOW;
		goto fail_queue;
	}
	ret = hws_video_ring_prepare(hws, v->channel_index, extent);
	if (ret)
		goto fail_queue;

	spin_lock_irqsave(&v->irq_lock, flags);
	hws_video_reset_completion_locked(v);
	WRITE_ONCE(v->half_seen, false);
	v->frame_half0_valid = false;
	if (v->active) {
		buf = v->active;
		v->active = NULL;
	} else {
		buf = hws_take_queued_buffer_locked(v);
	}
	ret = hws_program_video_ring_locked(v);
	spin_unlock_irqrestore(&v->irq_lock, flags);
	if (ret)
		goto fail_buffer;
	if (!buf)
		goto restart_capture;

	/* Complete buffer with a neutral frame so dequeuers keep running. */
	{
		struct vb2_v4l2_buffer *vb2v = &buf->vb;
		void *dst = vb2_plane_vaddr(&vb2v->vb2_buf, 0);

		if (!dst) {
			ret = -EFAULT;
			vb2_buffer_done(&vb2v->vb2_buf, VB2_BUF_STATE_ERROR);
			goto fail_queue;
		}
		memset(dst, 0x10, v->pix.sizeimage);
		vb2_set_plane_payload(&vb2v->vb2_buf, 0, v->pix.sizeimage);
		vb2v->field = v->pix.field;
		vb2v->sequence = (u32)atomic_fetch_inc(&v->sequence_number);
		vb2v->vb2_buf.timestamp = ktime_get_ns();
		vb2_buffer_done(&vb2v->vb2_buf, VB2_BUF_STATE_DONE);
		completed = true;
	}

restart_capture:
	hws_ack_video_pending(hws, v->channel_index);
	wmb(); /* publish the fixed ring before re-enabling VCAP */
	hws_enable_video_capture(hws, v->channel_index, true);
	if (!READ_ONCE(v->cap_active))
		vb2_queue_error(&v->buffer_queue);
	goto out_unlock;

fail_buffer:
	if (buf)
		vb2_buffer_done(&buf->vb.vb2_buf, VB2_BUF_STATE_ERROR);
fail_queue:
	WRITE_ONCE(v->stop_requested, true);
	vb2_queue_error(&v->buffer_queue);
	dev_warn_ratelimited(&hws->pdev->dev,
			     "%s: failed to restart guarded ring ch=%u ret=%d\n",
			     tag, v->channel_index, ret);

out_unlock:
	mutex_unlock(&v->state_lock);
	return completed;
}

static int hws_ctrls_init(struct hws_video *vid)
{
	struct v4l2_ctrl_handler *hdl = &vid->control_handler;

	/* Create BCHS controls. */
	v4l2_ctrl_handler_init(hdl, 4);

	vid->ctrl_brightness = v4l2_ctrl_new_std(hdl, &hws_ctrl_ops,
						 V4L2_CID_BRIGHTNESS,
						 MIN_VAMP_BRIGHTNESS_UNITS,
						 MAX_VAMP_BRIGHTNESS_UNITS, 1,
						 HWS_BRIGHTNESS_DEFAULT);

	vid->ctrl_contrast =
	    v4l2_ctrl_new_std(hdl, &hws_ctrl_ops, V4L2_CID_CONTRAST,
			      MIN_VAMP_CONTRAST_UNITS, MAX_VAMP_CONTRAST_UNITS,
			      1, HWS_CONTRAST_DEFAULT);

	vid->ctrl_saturation = v4l2_ctrl_new_std(hdl, &hws_ctrl_ops,
						 V4L2_CID_SATURATION,
						 MIN_VAMP_SATURATION_UNITS,
						 MAX_VAMP_SATURATION_UNITS, 1,
						 HWS_SATURATION_DEFAULT);

	vid->ctrl_hue = v4l2_ctrl_new_std(hdl, &hws_ctrl_ops, V4L2_CID_HUE,
					  MIN_VAMP_HUE_UNITS,
					  MAX_VAMP_HUE_UNITS, 1,
					  HWS_HUE_DEFAULT);
	if (hdl->error) {
		int err = hdl->error;

		v4l2_ctrl_handler_free(hdl);
		return err;
	}
	return 0;
}

int hws_video_init_channel(struct hws_pcie_dev *pdev, int ch)
{
	struct hws_video *vid;

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
	spin_lock_init(&vid->irq_lock);
	INIT_LIST_HEAD(&vid->capture_queue);
	atomic_set(&vid->sequence_number, 0);
	vid->active = NULL;
	vid->completion_timestamp_ns = 0;
	vid->completion_generation = 0;
	vid->next_completion_generation = 0;
	vid->completion_state = HWS_VIDEO_COMPLETION_IDLE;
	vid->completion_toggle = 0;
	vid->frame_half0_valid = false;
	vid->frame_timestamp_ns = 0;

	/* DMA watchdog removed; retain counters for diagnostics */
	vid->timeout_count = 0;
	vid->error_count = 0;
	vid->completion_overruns = 0;

	vid->queued_count = 0;
	vid->window_valid = false;

	/* Default format. */
	vid->pix.width = 1920;
	vid->pix.height = 1080;
	vid->pix.fourcc = V4L2_PIX_FMT_YUYV;
	vid->pix.bytesperline = ALIGN(vid->pix.width * 2, 64);
	vid->pix.sizeimage = vid->pix.bytesperline * vid->pix.height;
	vid->pix.field = V4L2_FIELD_NONE;
	vid->pix.colorspace = V4L2_COLORSPACE_REC709;
	vid->pix.ycbcr_enc = V4L2_YCBCR_ENC_DEFAULT;
	vid->pix.quantization = V4L2_QUANTIZATION_FULL_RANGE;
	vid->pix.xfer_func = V4L2_XFER_FUNC_DEFAULT;
	vid->pix.interlaced = false;
	vid->pix.half_size = hws_video_native_split(vid->pix.sizeimage);
	vid->ring_extent = hws_video_dma_extent(vid->pix.sizeimage);
	vid->ring_split = vid->pix.half_size;
	hws_set_current_dv_timings(vid, vid->pix.width,
				   vid->pix.height, vid->pix.interlaced);
	vid->current_fps = 60;

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

static void hws_video_reset_completion_locked(struct hws_video *vid)
{
	lockdep_assert_held(&vid->irq_lock);

	vid->completion_state = HWS_VIDEO_COMPLETION_IDLE;
	vid->completion_timestamp_ns = 0;
	vid->completion_generation = 0;
	vid->completion_toggle = 0;
}

static void hws_video_drain_queue_locked(struct hws_video *vid)
{
	hws_video_reset_completion_locked(vid);

	/* Return in-flight first */
	if (vid->active) {
		vb2_buffer_done(&vid->active->vb.vb2_buf, VB2_BUF_STATE_ERROR);
		vid->active = NULL;
	}
	/* Then everything queued */
	while (!list_empty(&vid->capture_queue)) {
		struct hwsvideo_buffer *b =
		    list_first_entry(&vid->capture_queue,
				     struct hwsvideo_buffer,
				     list);
		list_del_init(&b->list);
		vb2_buffer_done(&b->vb.vb2_buf, VB2_BUF_STATE_ERROR);
	}
	vid->queued_count = 0;
}

static void hws_video_release_registration(struct hws_video *vid)
{
	if (!vid->video_device)
		return;

	if (video_is_registered(vid->video_device)) {
		/* Unpublish first, then release the queue under its file-op lock. */
		vb2_video_unregister_device(vid->video_device);
	} else {
		/* A never-published node cannot have an open file descriptor. */
		if (vid->queue_initialized)
			vb2_queue_release(&vid->buffer_queue);
		video_device_release(vid->video_device);
	}

	vid->queue_initialized = false;
	vid->video_device = NULL;
}

static void hws_video_collect_done_locked(struct hws_video *vid,
					  struct list_head *done)
{
	struct hwsvideo_buffer *b;

	if (vid->active) {
		if (!list_node_unlinked(&vid->active->list)) {
			list_move_tail(&vid->active->list, done);
		} else {
			INIT_LIST_HEAD(&vid->active->list);
			list_add_tail(&vid->active->list, done);
		}
		vid->active = NULL;
	}

	while (!list_empty(&vid->capture_queue)) {
		b = list_first_entry(&vid->capture_queue, struct hwsvideo_buffer,
				     list);
		list_move_tail(&b->list, done);
	}

	vid->queued_count = 0;
	hws_video_reset_completion_locked(vid);
}

void hws_video_fail_queue(struct hws_video *vid, const char *reason)
{
	struct hws_pcie_dev *hws;

	if (!vid || !vid->parent)
		return;

	hws = vid->parent;
	WRITE_ONCE(vid->stop_requested, true);
	WRITE_ONCE(vid->cap_active, false);
	hws_enable_video_capture(hws, vid->channel_index, false);

	/*
	 * This can run in the threaded IRQ handler, where waiting on this IRQ
	 * would deadlock. Leave every DMA-owned buffer attached to the queue;
	 * the sleepable STREAMOFF path returns it only after proving DMA idle.
	 */
	vb2_queue_error(&vid->buffer_queue);

	dev_warn_ratelimited(&hws->pdev->dev,
			     "video queue failed ch=%u: %s\n",
			     vid->channel_index, reason);
}

void hws_video_cleanup_channel(struct hws_pcie_dev *pdev, int ch)
{
	struct hws_video *vid;
	unsigned long flags;
	bool was_active;
	int ret;

	if (!pdev || ch < 0 || ch >= pdev->max_channels)
		return;

	vid = &pdev->video[ch];
	was_active = READ_ONCE(vid->cap_active);

	/* 1) Stop HW best-effort for this channel */
	hws_enable_video_capture(vid->parent, vid->channel_index, false);

	/* 2) Flip software state so IRQ/BH will be no-ops if they run */
	WRITE_ONCE(vid->stop_requested, true);
	WRITE_ONCE(vid->cap_active, false);

	/* 3) Ensure the IRQ handler finished any in-flight completions */
	if (vid->parent && vid->parent->irq >= 0)
		synchronize_irq(vid->parent->irq);
	ret = 0;
	if (was_active)
		ret = hws_wait_dma_idle(pdev, "video cleanup", ch);
	if (ret) {
		dev_crit(&pdev->pdev->dev,
			 "video cleanup ch=%d retained DMA-owned buffers: %d\n",
			 ch, ret);
		return;
	}

	/* 4) Drain SW capture queue & in-flight under lock */
	spin_lock_irqsave(&vid->irq_lock, flags);
	hws_video_drain_queue_locked(vid);
	spin_unlock_irqrestore(&vid->irq_lock, flags);

	/* 5) Release VB2 queue if initialized */
	hws_video_release_registration(vid);

	/* 6) Free V4L2 controls */
	v4l2_ctrl_handler_free(&vid->control_handler);

	/* 8) Reset simple state; do not memset the whole struct here. */
	mutex_destroy(&vid->state_lock);
	INIT_LIST_HEAD(&vid->capture_queue);
	vid->active = NULL;
	vid->frame_half0_valid = false;
	vid->stop_requested = false;
	vid->last_buf_half_toggle = 0;
	vid->half_seen = false;
	vid->signal_loss_cnt = 0;
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
	/* vb2 core handles cache maintenance for dma-contig buffers */
	(void)vb;
}

static void hws_buf_cleanup(struct vb2_buffer *vb)
{
	struct hwsvideo_buffer *b = to_hwsbuf(vb);

	if (!list_empty(&b->list))
		list_del_init(&b->list);
}

void hws_enable_video_capture(struct hws_pcie_dev *hws, unsigned int chan,
			      bool on)
{
	unsigned long flags;
	u32 status;

	if (!hws || chan >= hws->max_channels)
		return;

	spin_lock_irqsave(&hws->capture_lock, flags);
	if (READ_ONCE(hws->dma_quiesced)) {
		WRITE_ONCE(hws->video[chan].cap_active, false);
		spin_unlock_irqrestore(&hws->capture_lock, flags);
		return;
	}
	if (on && (READ_ONCE(hws->pci_lost) ||
		   READ_ONCE(hws->suspended))) {
		WRITE_ONCE(hws->video[chan].cap_active, false);
		spin_unlock_irqrestore(&hws->capture_lock, flags);
		return;
	}
	status = readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);
	status = on ? (status | BIT(chan)) : (status & ~BIT(chan));
	writel(status, hws->bar0_base + HWS_REG_VCAP_ENABLE);
	(void)readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);
	WRITE_ONCE(hws->video[chan].cap_active, on);
	spin_unlock_irqrestore(&hws->capture_lock, flags);

	dev_dbg(&hws->pdev->dev, "vcap %s ch%u (reg=0x%08x)\n",
		on ? "ON" : "OFF", chan, status);
}

static void hws_seed_dma_windows(struct hws_pcie_dev *hws)
{
	const u32 addr_mask = PCI_E_BAR_ADD_MASK;
	const u32 addr_low_mask = PCI_E_BAR_ADD_LOWMASK;
	unsigned long flags;
	unsigned int ch;

	if (!hws || !hws->bar0_base)
		return;

	/* Keep arena DMA addresses stable while taking each channel IRQ lock. */
	mutex_lock(&hws->scratch_lock);

	/* If cur_max_video_ch is not set yet, default to max_channels. */
	if (!hws->cur_max_video_ch || hws->cur_max_video_ch > hws->max_channels)
		hws->cur_max_video_ch = hws->max_channels;

	for (ch = 0; ch < hws->cur_max_video_ch; ch++) {
		struct hws_video *vid = &hws->video[ch];

		if (!hws->scratch_vid[ch].cpu)
			continue;

		/* Serialize the shared remap slot with runtime video and audio. */
		spin_lock_irqsave(&vid->irq_lock, flags);

		/* Program 64-bit BAR remap entry for this channel */
		{
			dma_addr_t p = hws_video_ring_dma(hws, ch);
			u32 lo = lower_32_bits(p) & addr_mask;
			u32 hi = upper_32_bits(p);
			u32 pci_addr_low = lower_32_bits(p) & addr_low_mask;
			u32 table = HWS_VIDEO_REMAP_SLOT_OFF(ch);

			writel_relaxed(hi,
				       hws->bar0_base + PCI_ADDR_TABLE_BASE +
				       table);
			writel_relaxed(lo,
				       hws->bar0_base + PCI_ADDR_TABLE_BASE +
				       table + PCIE_BARADDROFSIZE);

			/* Per-channel AXI base + PCI low */
			writel_relaxed((ch + 1) * PCIEBAR_AXI_BASE +
				       pci_addr_low,
				       hws->bar0_base + CVBS_IN_BUF_BASE +
				       ch * PCIE_BARADDROFSIZE);

			/*
			 * Native half-ring split in /16 units. The base points
			 * after the leading guard page and remains fixed while VCAP
			 * is enabled.
			 */
			{
				u32 half_bytes = hws_video_native_split(
					vid->pix.sizeimage ? vid->pix.sizeimage :
					MAX_VIDEO_SCALER_SIZE);

				writel_relaxed(half_bytes / 16,
					       hws->bar0_base + CVBS_IN_BUF_BASE2 +
					       ch * PCIE_BARADDROFSIZE);
			}
		}

		/* The next stream revalidates the fixed mapping and cached split. */
		vid->window_valid = false;
		(void)readl(hws->bar0_base + HWS_REG_INT_STATUS);
		spin_unlock_irqrestore(&vid->irq_lock, flags);
	}

	/* Post writes so device sees them before we move on */
	(void)readl(hws->bar0_base + HWS_REG_INT_STATUS);
	mutex_unlock(&hws->scratch_lock);
}

static void hws_ack_all_irqs(struct hws_pcie_dev *hws)
{
	u32 st = readl(hws->bar0_base + HWS_REG_INT_STATUS);

	if (st) {
		writel(st, hws->bar0_base + HWS_REG_INT_STATUS);	/* W1C */
		(void)readl(hws->bar0_base + HWS_REG_INT_STATUS);
	}
}

static void hws_configure_irq_fabric(struct hws_pcie_dev *hws)
{
	/* Route all sources to vector 0. */
	writel(0x00000000, hws->bar0_base + PCIE_INT_DEC_REG_BASE);
	(void)readl(hws->bar0_base + PCIE_INT_DEC_REG_BASE);

	/* Enable the PCIe bridge. */
	writel(0x00000001, hws->bar0_base + PCIEBR_EN_REG_BASE);
	(void)readl(hws->bar0_base + PCIEBR_EN_REG_BASE);
}

void hws_init_video_sys(struct hws_pcie_dev *hws, bool enable)
{
	int i;

	if (hws->start_run && !enable)
		return;

	/* 1) reset the decoder mode register to 0 */
	writel(0x00000000, hws->bar0_base + HWS_REG_DEC_MODE);
	hws_seed_dma_windows(hws);
	hws_audio_seed_channels(hws);

	/* 3) on a full reset, clear all per-channel status and indices */
	if (!enable) {
		for (i = 0; i < hws->max_channels; i++) {
			/* helpers to arm/disable capture engines */
			hws_enable_video_capture(hws, i, false);
			hws_enable_audio_capture(hws, i, false);
		}
	}

	/* 4) Start run: set bit31, wait a bit, then program low 24 bits. */
	writel(0x80000000, hws->bar0_base + HWS_REG_DEC_MODE);
	writel(0x80FFFFFF, hws->bar0_base + HWS_REG_DEC_MODE);
	writel(0x13, hws->bar0_base + HWS_REG_DEC_MODE);
	hws_ack_all_irqs(hws);
	hws_configure_irq_fabric(hws);
	/* 6) record that we're now running */
	hws->start_run = true;
}

int hws_check_card_status(struct hws_pcie_dev *hws)
{
	u32 status;

	if (!hws || !hws->bar0_base)
		return -ENODEV;
	if (READ_ONCE(hws->pci_lost) || READ_ONCE(hws->dma_quiesced))
		return -ENODEV;
	if (READ_ONCE(hws->suspended))
		return -EBUSY;

	status = readl(hws->bar0_base + HWS_REG_SYS_STATUS);

	/* Common device-missing pattern. */
	if (status == 0xFFFFFFFF) {
		hws->pci_lost = true;
		dev_err(&hws->pdev->dev, "PCIe device not responding\n");
		return -ENODEV;
	}

	/*
	 * Runtime callers cannot safely reset this shared core: doing so would
	 * invalidate every channel's programmed DMA window and buffer ownership.
	 * Probe and resume perform reset only while all capture paths are quiesced.
	 */
	if (!(status & BIT(0))) {
		dev_warn_ratelimited(&hws->pdev->dev,
				     "SYS_STATUS not ready (0x%08x); runtime core reset refused\n",
				     status);
		return -EIO;
	}

	return 0;
}

void check_video_format(struct hws_pcie_dev *pdx)
{
	int i;

	for (i = 0; i < pdx->cur_max_video_ch; i++) {
		bool interlace = false;

		if (!hws_read_active_state(pdx, i, &interlace)) {
			/* No active video; optionally feed neutral frames to keep streaming. */
			if (pdx->video[i].signal_loss_cnt == 0)
				pdx->video[i].signal_loss_cnt = 1;
			if (READ_ONCE(pdx->video[i].cap_active))
				hws_force_no_signal_frame(&pdx->video[i],
							  "monitor_nosignal");
		} else {
			if (pdx->hw_ver > 0)
				handle_hwv2_path(pdx, i);
			else
				/* Legacy path stub; see handle_legacy_path() comment. */
				handle_legacy_path(pdx, i);

			update_live_resolution(pdx, i, interlace);
			pdx->video[i].signal_loss_cnt = 0;
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
	if (old == 0xFFFFFFFF) {
		hws->pci_lost = true;
		return;
	}

	if (old != new_val) {
		writel(new_val, addr);
		/* Post the write on some bridges / enforce ordering. */
		(void)readl(addr);
	}
}

static bool hws_read_active_state(struct hws_pcie_dev *pdx, unsigned int ch,
				  bool *interlace)
{
	u32 reg;
	bool active;

	if (ch >= pdx->cur_max_video_ch)
		return false;

	reg = readl(pdx->bar0_base + HWS_REG_ACTIVE_STATUS);
	active = !!(reg & BIT(ch));
	if (interlace)
		*interlace = !!(reg & BIT(8 + ch));
	return active;
}

/* Modern hardware path: keep HW registers in sync with current per-channel
 * software state.
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
	(void)in_fps;

	/* 2) Output resolution programming.
	 * For now, mirror the current format to OUT_RES.
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
	/*
	 * Legacy (hw_ver == 0) expected behavior:
	 * - A per-channel SW FPS accumulator incremented on each VDONE.
	 * - A once-per-second poll mapped the count to discrete FPS:
	 *   >55*2 => 60, >45*2 => 50, >25*2 => 30, >20*2 => 25, else 60,
	 *   then reset the accumulator to 0.
	 * - The *2 factor assumed VDONE fired per-field; if legacy VDONE is
	 *   per-frame, drop the factor.
	 *
	 * Current code keeps this path as a no-op; vid->current_fps stays at the
	 * default or mode-derived value. If accurate legacy FPS reporting is
	 * needed (V4L2 g_parm/timeperframe), reintroduce the accumulator in the
	 * IRQ path and perform the mapping/reset here.
	 *
	 * No-op by default. If you introduce a SW FPS accumulator, map it here.
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
					bool interlaced, u32 fps)
{
	struct hws_video *v = &pdx->video[ch];
	unsigned long flags;
	bool queue_busy;
	bool geometry_changed;
	struct list_head done;
	struct hwsvideo_buffer *b, *tmp;
	int ret;

	if (!pdx || !pdx->bar0_base)
		return;
	if (ch >= pdx->max_channels)
		return;
	if (!w || !h || w > MAX_VIDEO_HW_W ||
	    (!interlaced && h > MAX_VIDEO_HW_H) ||
	    (interlaced && (h * 2) > MAX_VIDEO_HW_H))
		return;
	if (!fps || fps == 0xFFFFFFFF || fps > 240)
		fps = (h == 576) ? 50 : 60;

	geometry_changed = w != v->pix.width || h != v->pix.height ||
		interlaced != v->pix.interlaced;
	if (!geometry_changed && fps == v->current_fps)
		return;

	if (!geometry_changed) {
		/* Refresh cached live timing state, but don't emit a resolution
		 * change event when only the frame rate changes.
		 */
		mutex_lock(&v->state_lock);
		v->pix.interlaced = interlaced;
		v->pix.field = interlaced ? V4L2_FIELD_INTERLACED :
					    V4L2_FIELD_NONE;
		hws_set_current_dv_timings(v, w, h, interlaced);
		v->current_fps = fps;
		mutex_unlock(&v->state_lock);
		return;
	}

	if (!mutex_trylock(&v->state_lock))
		return;

	INIT_LIST_HEAD(&done);
	queue_busy = vb2_is_busy(&v->buffer_queue);

	WRITE_ONCE(v->stop_requested, true);
	WRITE_ONCE(v->cap_active, false);
	/* Publish software stop first so the IRQ completion path sees the stop
	 * before we touch MMIO or the lists. Pairs with READ_ONCE() checks in the
	 * VDONE handler to prevent half copies while modes change.
	 */
	smp_wmb();

	hws_enable_video_capture(pdx, ch, false);
	readl(pdx->bar0_base + HWS_REG_INT_STATUS);

	if (v->parent && v->parent->irq >= 0)
		synchronize_irq(v->parent->irq);
	ret = hws_try_wait_dma_idle(pdx, "video mode change", ch);
	if (ret || READ_ONCE(pdx->pci_lost)) {
		vb2_queue_error(&v->buffer_queue);
		mutex_unlock(&v->state_lock);
		return;
	}

	spin_lock_irqsave(&v->irq_lock, flags);
	hws_video_collect_done_locked(v, &done);
	v->window_valid = false;
	spin_unlock_irqrestore(&v->irq_lock, flags);

	/* Update software pixel state */
	v->pix.width = w;
	v->pix.height = h;
	v->pix.interlaced = interlaced;
	hws_set_current_dv_timings(v, w, h, interlaced);
	v->current_fps = fps;

	hws_calc_sizeimage(v, w, h, interlaced);

	/* Geometry changes require userspace renegotiation once buffers exist.
	 * Emit SOURCE_CHANGE, mark the queue in error, and let userspace
	 * STREAMOFF/REQBUFS/STREAMON rather than trying to restart capture
	 * with partially drained in-flight state.
	 */
	if (queue_busy) {
		struct v4l2_event ev = {
			.type = V4L2_EVENT_SOURCE_CHANGE,
		};

		ev.u.src_change.changes = V4L2_EVENT_SRC_CH_RESOLUTION;
		v4l2_event_queue(v->video_device, &ev);
		vb2_queue_error(&v->buffer_queue);
	} else {
		WRITE_ONCE(v->stop_requested, false);
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
	atomic_set(&v->sequence_number, 0);

	mutex_unlock(&v->state_lock);

	list_for_each_entry_safe(b, tmp, &done, list) {
		list_del_init(&b->list);
		vb2_buffer_done(&b->vb.vb2_buf, VB2_BUF_STATE_ERROR);
	}
}

static void update_live_resolution(struct hws_pcie_dev *pdx, unsigned int ch,
				   bool interlace)
{
	u32 reg = readl(pdx->bar0_base + HWS_REG_IN_RES(ch));
	u32 fps = readl(pdx->bar0_base + HWS_REG_FRAME_RATE(ch));
	u16 res_w = reg & 0xFFFF;
	u16 res_h = (reg >> 16) & 0xFFFF;
	struct hws_video *vid = &pdx->video[ch];
	bool geometry_changed;
	bool fps_changed;

	bool within_hw = (res_w <= MAX_VIDEO_HW_W) &&
	    ((!interlace && res_h <= MAX_VIDEO_HW_H) ||
	     (interlace && (res_h * 2) <= MAX_VIDEO_HW_H));

	if (!within_hw)
		return;

	geometry_changed = res_w != vid->pix.width ||
		res_h != vid->pix.height ||
		interlace != vid->pix.interlaced;
	fps_changed = fps && fps != 0xFFFFFFFF && fps <= 240 &&
		fps != vid->current_fps;

	if (geometry_changed || fps_changed)
		hws_video_apply_mode_change(pdx, ch, res_w, res_h, interlace,
					    fps);
}

static int hws_open(struct file *file)
{
	return v4l2_fh_open(file);
}

static const struct v4l2_file_operations hws_fops = {
	.owner = THIS_MODULE,
	.open = hws_open,
	.release = vb2_fop_release,
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
	.vidioc_expbuf = vb2_ioctl_expbuf,
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

	.vidioc_log_status = v4l2_ctrl_log_status,
	.vidioc_subscribe_event = hws_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,
	.vidioc_g_parm = hws_vidioc_g_parm,
};

static u32 hws_calc_sizeimage(struct hws_video *v, u16 w, u16 h,
			      bool interlaced)
{
	/* HWS captures packed YUYV only; stride is 16 bpp aligned to 64 bytes. */
	u32 lines = h;		/* full frame lines for sizeimage */
	u32 bytesperline = ALIGN(w * 2, 64);
	u32 sizeimage, half0;

	/* publish into pix, since we now carry these in-state */
	v->pix.bytesperline = bytesperline;
	sizeimage = bytesperline * lines;

	half0 = hws_video_native_split(sizeimage);

	v->pix.sizeimage = sizeimage;
	v->pix.half_size = half0;	/* native first half; second is remainder */
	v->ring_extent = hws_video_dma_extent(sizeimage);
	v->ring_split = half0;
	v->pix.field = interlaced ? V4L2_FIELD_INTERLACED : V4L2_FIELD_NONE;

	return v->pix.sizeimage;
}

static int hws_queue_setup(struct vb2_queue *q, unsigned int *num_buffers,
			   unsigned int *nplanes, unsigned int sizes[],
			   struct device *alloc_devs[])
{
	struct hws_video *vid = q->drv_priv;

	if (*nplanes) {
		if (sizes[0] < vid->pix.sizeimage)
			return -EINVAL;
	} else {
		*nplanes = 1;
		sizes[0] = vid->pix.sizeimage;
	}

	return 0;
}

static int hws_buffer_prepare(struct vb2_buffer *vb)
{
	struct hws_video *vid = vb->vb2_queue->drv_priv;
	size_t need = vid->pix.sizeimage;

	if (vb2_plane_size(vb, 0) < need)
		return -EINVAL;
	if (!vb2_plane_vaddr(vb, 0))
		return -EFAULT;

	vb2_set_plane_payload(vb, 0, need);
	return 0;
}

static void hws_buffer_queue(struct vb2_buffer *vb)
{
	struct hws_video *vid = vb->vb2_queue->drv_priv;
	struct hwsvideo_buffer *buf = to_hwsbuf(vb);
	struct hws_pcie_dev *hws = vid->parent;
	unsigned long flags;

	dev_dbg(&hws->pdev->dev,
		"buffer_queue(ch=%u): vb=%p sizeimage=%u q_active=%d\n",
		vid->channel_index, vb, vid->pix.sizeimage,
		READ_ONCE(vid->cap_active));

	spin_lock_irqsave(&vid->irq_lock, flags);
	list_add_tail(&buf->list, &vid->capture_queue);
	vid->queued_count++;
	spin_unlock_irqrestore(&vid->irq_lock, flags);
}

static int hws_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct hws_video *v = q->drv_priv;
	struct hws_pcie_dev *hws = v->parent;
	struct hwsvideo_buffer *b, *tmp;
	unsigned long flags;
	dma_addr_t ring_dma;
	size_t extent;
	LIST_HEAD(queued);
	bool scratch_acquired = false;
	int ret;

	dev_dbg(&hws->pdev->dev, "start_streaming: ch=%u count=%u\n",
		v->channel_index, count);

	ret = hws_check_card_status(hws);
	if (ret)
		goto fail_return_buffers;

	ret = hws_alloc_channel_scratch(hws, v->channel_index);
	if (ret)
		goto fail_return_buffers;
	scratch_acquired = true;
	extent = hws_video_dma_extent(v->pix.sizeimage);
	ret = hws_video_ring_prepare(hws, v->channel_index, extent);
	if (ret)
		goto fail_return_buffers;

	(void)hws_read_active_state(hws, v->channel_index,
				       &v->pix.interlaced);

	lockdep_assert_held(&v->state_lock);
	/* init per-stream state */
	WRITE_ONCE(v->stop_requested, false);
	WRITE_ONCE(v->cap_active, false);
	WRITE_ONCE(v->half_seen, false);
	WRITE_ONCE(v->last_buf_half_toggle, 0);
	atomic_set(&v->sequence_number, 0);

	/* Program the permanent ring once, before enabling VCAP. */
	spin_lock_irqsave(&v->irq_lock, flags);
	hws_video_reset_completion_locked(v);
	v->active = NULL;
	v->frame_half0_valid = false;
	v->frame_timestamp_ns = 0;
	v->next_completion_generation = 0;
	ret = hws_program_video_ring_locked(v);
	if (!ret) {
		hws_ack_video_pending(hws, v->channel_index);
		(void)readl(hws->bar0_base + HWS_REG_INT_STATUS);
		wmb(); /* publish ring registers before enabling VCAP */
		hws_enable_video_capture(hws, v->channel_index, true);
		if (!READ_ONCE(v->cap_active))
			ret = -ENODEV;
	}
	if (ret) {
		WRITE_ONCE(v->cap_active, false);
		WRITE_ONCE(v->stop_requested, true);
		hws_video_collect_done_locked(v, &queued);
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);

	if (ret)
		goto complete_return_buffers;

	ring_dma = hws_video_ring_dma(hws, v->channel_index);
	dev_dbg(&hws->pdev->dev,
		"start_streaming: ch=%u fixed ring dma=%pad extent=%zu split=%zu\n",
		v->channel_index, &ring_dma, v->ring_extent, v->ring_split);
	return 0;

fail_return_buffers:
	spin_lock_irqsave(&v->irq_lock, flags);
	hws_video_collect_done_locked(v, &queued);
	spin_unlock_irqrestore(&v->irq_lock, flags);

complete_return_buffers:
	{
		list_for_each_entry_safe(b, tmp, &queued, list) {
			list_del_init(&b->list);
			vb2_buffer_done(&b->vb.vb2_buf, VB2_BUF_STATE_QUEUED);
		}
		if (scratch_acquired)
			hws_release_channel_scratch(hws, v->channel_index,
						    true);
	}
	return ret;
}

static void hws_log_video_state(struct hws_video *v, const char *action,
				const char *phase)
{
	struct hws_pcie_dev *hws = v->parent;
	unsigned long flags;
	unsigned int queued = 0;
	unsigned int tracked = 0;
	unsigned int seq = 0;
	struct hwsvideo_buffer *b;
	bool streaming = vb2_is_streaming(&v->buffer_queue);
	bool cap_active;
	bool stop_requested;
	struct hwsvideo_buffer *active;

	spin_lock_irqsave(&v->irq_lock, flags);
	list_for_each_entry(b, &v->capture_queue, list)
		queued++;
	cap_active = READ_ONCE(v->cap_active);
	stop_requested = READ_ONCE(v->stop_requested);
	active = v->active;
	tracked = v->queued_count;
	seq = (u32)atomic_read(&v->sequence_number);
	spin_unlock_irqrestore(&v->irq_lock, flags);

	dev_dbg(&hws->pdev->dev,
		"video:%s:%s ch=%u streaming=%d cap=%d stop=%d assembly=%p queued=%u tracked=%u seq=%u\n",
		action, phase, v->channel_index, streaming, cap_active,
		stop_requested, active, queued, tracked, seq);
}

static void hws_stop_streaming(struct vb2_queue *q)
{
	struct hws_video *v = q->drv_priv;
	struct hws_pcie_dev *hws = v->parent;
	unsigned long flags;
	struct hwsvideo_buffer *b, *tmp;
	LIST_HEAD(done);
	unsigned int done_cnt = 0;
	u64 start_ns = ktime_get_mono_fast_ns();
	bool guards_ok = true;
	bool was_active;
	int ret;

	hws_log_video_state(v, "streamoff", "begin");
	was_active = READ_ONCE(v->cap_active);

	/* 1) Quiesce SW/HW first */
	lockdep_assert_held(&v->state_lock);
	WRITE_ONCE(v->cap_active, false);
	WRITE_ONCE(v->stop_requested, true);

	hws_enable_video_capture(v->parent, v->channel_index, false);

	/* The threaded handler may be copying a completed ring half. */
	if (hws->irq >= 0)
		synchronize_irq(hws->irq);
	ret = 0;
	if (was_active)
		ret = hws_wait_dma_idle(hws, "video STREAMOFF",
					v->channel_index);
	if (ret) {
		vb2_queue_error(&v->buffer_queue);
		dev_crit(&hws->pdev->dev,
			 "video STREAMOFF ch=%u retained DMA-owned buffers: %d\n",
			 v->channel_index, ret);
		return;
	}
	if (v->ring_extent)
		guards_ok = hws_video_ring_guards_ok(hws, v->channel_index,
						     v->ring_extent);
	if (!guards_ok) {
		vb2_queue_error(&v->buffer_queue);
		dev_crit(&hws->pdev->dev,
			 "video STREAMOFF ch=%u detected DMA guard corruption\n",
			 v->channel_index);
	}

	/* 2) Collect in-flight + queued under the IRQ lock */
	spin_lock_irqsave(&v->irq_lock, flags);
	hws_video_collect_done_locked(v, &done);
	spin_unlock_irqrestore(&v->irq_lock, flags);

	/* 3) Complete outside the lock */
	list_for_each_entry_safe(b, tmp, &done, list) {
		/* Unlink from 'done' before completing */
		list_del_init(&b->list);
		vb2_buffer_done(&b->vb.vb2_buf, VB2_BUF_STATE_ERROR);
		done_cnt++;
	}
	dev_dbg(&hws->pdev->dev,
		"video:streamoff:done ch=%u completed=%u (%lluus)\n",
		v->channel_index, done_cnt, hws_elapsed_us(start_ns));
	hws_log_video_state(v, "streamoff", "end");
	hws_release_channel_scratch(hws, v->channel_index, true);
}

static const struct vb2_ops hwspcie_video_qops = {
	.queue_setup = hws_queue_setup,
	.buf_prepare = hws_buffer_prepare,
	.buf_init = hws_buf_init,
	.buf_finish = hws_buf_finish,
	.buf_cleanup = hws_buf_cleanup,
	.buf_queue = hws_buffer_queue,
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
	dev->v4l2_ref_held = true;

	/* Prepare every channel before publishing the first device node. */
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
		 * Do not reinitialize any of those here.
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
		vdev->fops = &hws_fops;
		vdev->ioctl_ops = &hws_ioctl_fops;
		vdev->device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING;
		vdev->lock = &ch->state_lock;	/* serialize file ops */
		vdev->ctrl_handler = &ch->control_handler;
		vdev->vfl_dir = VFL_DIR_RX;
		vdev->release = video_device_release;
		if (ch->control_handler.error) {
			ret = ch->control_handler.error;
			goto err_unwind;
		}
		video_set_drvdata(vdev, ch);

		/* vb2 queue init (dma-contig) */
		q = &ch->buffer_queue;
		memset(q, 0, sizeof(*q));
		q->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		q->io_modes = VB2_MMAP;
		q->drv_priv = ch;
		q->buf_struct_size = sizeof(struct hwsvideo_buffer);
		q->ops = &hwspcie_video_qops;
		q->mem_ops = &vb2_dma_contig_memops;
		q->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
		q->lock = &ch->state_lock;
		q->min_queued_buffers = 1;
		q->dev = &dev->pdev->dev;

		ret = vb2_queue_init(q);
		vdev->queue = q;
		if (ret) {
			dev_err(&dev->pdev->dev,
				"vb2_queue_init ch%u failed: %d\n", i, ret);
			goto err_unwind;
		}
		ch->queue_initialized = true;

		/* Make controls live (no-op if none or already set up) */
		if (ch->control_handler.error) {
			ret = ch->control_handler.error;
			dev_err(&dev->pdev->dev,
				"ctrl handler ch%u error: %d\n", i, ret);
			goto err_unwind;
		}
		ret = v4l2_ctrl_handler_setup(&ch->control_handler);
		if (ret) {
			dev_err(&dev->pdev->dev,
				"ctrl handler setup ch%u failed: %d\n", i, ret);
			goto err_unwind;
		}
	}

	for (i = 0; i < dev->cur_max_video_ch; i++) {
		struct video_device *vdev = dev->video[i].video_device;

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
	for (i = 0; i < dev->cur_max_video_ch; i++) {
		struct hws_video *ch = &dev->video[i];

		hws_video_release_registration(ch);
	}
	return ret;
}

void hws_video_unregister(struct hws_pcie_dev *dev)
{
	int i;

	if (!dev)
		return;

	for (i = 0; i < dev->cur_max_video_ch; i++) {
		struct hws_video *ch = &dev->video[i];

		hws_video_release_registration(ch);
	}
}

int hws_video_quiesce(struct hws_pcie_dev *hws, const char *reason)
{
	int i, ret = 0;
	u64 start_ns = ktime_get_mono_fast_ns();

	dev_dbg(&hws->pdev->dev, "video:%s:begin channels=%u\n", reason,
		hws->cur_max_video_ch);
	for (i = 0; i < hws->cur_max_video_ch; i++) {
		struct hws_video *vid = &hws->video[i];
		struct vb2_queue *q = &vid->buffer_queue;
		u64 ch_start_ns = ktime_get_mono_fast_ns();
		bool streaming;

		if (!vid->queue_initialized) {
			dev_dbg(&hws->pdev->dev,
				"video:%s:ch=%d skipped queue-unavailable\n",
				reason, i);
			continue;
		}

		mutex_lock(&vid->state_lock);
		streaming = vb2_is_streaming(q);
		hws_log_video_state(vid, reason, "channel");
		if (streaming) {
			/* Stop via vb2, which runs .stop_streaming. */
			int r = vb2_streamoff(q, q->type);

			dev_dbg(&hws->pdev->dev,
				"video:%s:ch=%d streamoff ret=%d (%lluus)\n",
				reason, i, r, hws_elapsed_us(ch_start_ns));
			if (r && !ret)
				ret = r;
		} else {
			dev_dbg(&hws->pdev->dev,
				"video:%s:ch=%d idle (%lluus)\n",
				reason, i, hws_elapsed_us(ch_start_ns));
		}
		mutex_unlock(&vid->state_lock);
	}
	dev_dbg(&hws->pdev->dev, "video:%s:done ret=%d (%lluus)\n", reason,
		ret, hws_elapsed_us(start_ns));
	return ret;
}

void hws_video_pm_resume(struct hws_pcie_dev *hws)
{
	/* Nothing mandatory to do here for vb2; userspace will STREAMON
	 * again when ready.
	 */
}
