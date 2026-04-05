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
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#include <media/v4l2-ioctl.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-dev.h>
#include <media/v4l2-event.h>
#include <media/videobuf2-v4l2.h>
#include <media/v4l2-device.h>
#include <media/videobuf2-dma-contig.h>

#include "hws.h"
#include "hws_capture.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws_irq.h"
#include "hws_v4l2_ioctl.h"

#define HWS_REMAP_SLOT_OFF(ch)   (0x208 + (ch) * 8)	/* one 64-bit slot per ch */
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
static void hws_program_dma_window(struct hws_video *vid, dma_addr_t dma);
static struct hws_vfh_ctx *hws_ctx_from_file(struct file *file);
static const struct vb2_ops hws_consumer_qops;

static unsigned long long hws_elapsed_us(u64 start_ns)
{
	return div_u64(ktime_get_mono_fast_ns() - start_ns, 1000);
}

#if IS_ENABLED(CONFIG_SYSFS)
static ssize_t resolution_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct video_device *vdev = to_video_device(dev);
	struct hws_video *vid = video_get_drvdata(vdev);
	struct hws_pcie_dev *hws;
	u32 res_reg;
	u16 w, h;
	bool interlaced;

	if (!vid)
		return -ENODEV;

	hws = vid->parent;
	if (!hws || !hws->bar0_base)
		return sysfs_emit(buf, "unknown\n");

	res_reg = readl(hws->bar0_base + HWS_REG_IN_RES(vid->channel_index));
	if (!res_reg || res_reg == 0xFFFFFFFF)
		return sysfs_emit(buf, "unknown\n");

	w = res_reg & 0xFFFF;
	h = (res_reg >> 16) & 0xFFFF;

	interlaced =
	    !!(readl(hws->bar0_base + HWS_REG_ACTIVE_STATUS) &
	       BIT(8 + vid->channel_index));

	return sysfs_emit(buf, "%ux%u%s\n", w, h, interlaced ? "i" : "p");
}
static DEVICE_ATTR_RO(resolution);

static inline int hws_resolution_create(struct video_device *vdev)
{
	return device_create_file(&vdev->dev, &dev_attr_resolution);
}

static inline void hws_resolution_remove(struct video_device *vdev)
{
	device_remove_file(&vdev->dev, &dev_attr_resolution);
}
#else
static inline int hws_resolution_create(struct video_device *vdev)
{
	return 0;
}

static inline void hws_resolution_remove(struct video_device *vdev)
{
}
#endif

static bool dma_window_verify;
module_param_named(dma_window_verify, dma_window_verify, bool, 0644);
MODULE_PARM_DESC(dma_window_verify,
		 "Read back DMA window registers after programming (debug)");

void hws_set_dma_doorbell(struct hws_pcie_dev *hws, unsigned int ch,
			  dma_addr_t dma, const char *tag)
{
	iowrite32(lower_32_bits(dma), hws->bar0_base + HWS_REG_DMA_ADDR(ch));
	dev_dbg(&hws->pdev->dev, "dma_doorbell ch%u: dma=0x%llx tag=%s\n", ch,
		(u64)dma, tag ? tag : "");
}

static void hws_program_dma_window(struct hws_video *vid, dma_addr_t dma)
{
	const u32 addr_mask = PCI_E_BAR_ADD_MASK;	// 0xE0000000
	const u32 addr_low_mask = PCI_E_BAR_ADD_LOWMASK;	// 0x1FFFFFFF
	struct hws_pcie_dev *hws = vid->parent;
	unsigned int ch = vid->channel_index;
	u32 table_off = HWS_REMAP_SLOT_OFF(ch);
	u32 lo = lower_32_bits(dma);
	u32 hi = upper_32_bits(dma);
	u32 pci_addr = lo & addr_low_mask;	// low 29 bits inside 512MB window
	u32 page_lo = lo & addr_mask;	// bits 31..29 only (page bits)

	bool wrote = false;

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
	if (!vid->window_valid || vid->last_half16 != vid->pix.half_size / 16) {
		writel(vid->pix.half_size / 16,
		       hws->bar0_base + HWS_HALF_SZ_OFF(ch));
		vid->last_half16 = vid->pix.half_size / 16;
		wrote = true;
	}

	vid->window_valid = true;

	if (unlikely(dma_window_verify) && wrote) {
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
			vid->pix.half_size / 16);
	} else if (wrote) {
		/* Flush posted writes before arming DMA */
		readl_relaxed(hws->bar0_base + HWS_HALF_SZ_OFF(ch));
	}
}

static bool hws_force_no_signal_frame(struct hws_video *v, const char *tag)
{
	struct hws_pcie_dev *hws;
	unsigned long flags;
	struct hwsvideo_buffer *buf = NULL, *next = NULL;
	bool have_next = false;
	bool doorbell = false;

	if (!v)
		return false;
	hws = v->parent;
	if (!hws || READ_ONCE(v->stop_requested) || !READ_ONCE(v->cap_active))
		return false;
	if (READ_ONCE(v->engine.mode) != HWS_CAPTURE_MODE_DIRECT)
		return false;
	spin_lock_irqsave(&v->irq_lock, flags);
	if (v->engine.active) {
		buf = v->engine.active;
		v->engine.active = NULL;
		buf->slot = 0;
	} else {
		buf = hws_take_direct_buffer_locked(v);
		if (buf)
			buf->slot = 0;
	}
	if (v->engine.next_prepared) {
		next = v->engine.next_prepared;
		v->engine.next_prepared = NULL;
		next->slot = 0;
		v->engine.active = next;
		have_next = true;
	} else {
		next = hws_take_direct_buffer_locked(v);
		if (next) {
			next->slot = 0;
			v->engine.active = next;
			have_next = true;
		} else {
			v->engine.active = NULL;
		}
	}
	spin_unlock_irqrestore(&v->irq_lock, flags);
	if (!buf)
		return false;
	/* Complete buffer with a neutral frame so dequeuers keep running. */
	{
		struct vb2_v4l2_buffer *vb2v = &buf->vb;
		void *dst = vb2_plane_vaddr(&vb2v->vb2_buf, 0);

		if (dst)
			memset(dst, 0x10, v->pix.sizeimage);
		vb2_set_plane_payload(&vb2v->vb2_buf, 0, v->pix.sizeimage);
		vb2v->sequence =
		    (u32)(atomic_inc_return(&v->engine.sequence_number) - 1);
		vb2v->field = v->pix.field;
		vb2v->vb2_buf.timestamp = ktime_get_ns();
		vb2_buffer_done(&vb2v->vb2_buf, VB2_BUF_STATE_DONE);
	}
	if (have_next && next) {
		dma_addr_t dma =
		    vb2_dma_contig_plane_dma_addr(&next->vb.vb2_buf, 0);
		hws_program_dma_for_addr(hws, v->channel_index, dma);
		hws_set_dma_doorbell(hws, v->channel_index, dma,
				     tag ? tag : "nosignal_zero");
		doorbell = true;
	}
	if (doorbell) {
		wmb(); /* ensure descriptors visible before enabling capture */
		hws_enable_video_capture(hws, v->channel_index, true);
	}
	return true;
}

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
	spin_lock_init(&vid->irq_lock);
	spin_lock_init(&vid->consumers_lock);
	INIT_LIST_HEAD(&vid->consumers);
	hws_capture_engine_init(vid);

	/* DMA watchdog removed; retain counters for diagnostics */
	vid->timeout_count = 0;
	vid->error_count = 0;

	vid->window_valid = false;

	/* default format (adjust to your HW) */
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
	vid->pix.half_size = vid->pix.sizeimage / 2;
	vid->alloc_sizeimage = vid->pix.sizeimage;
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

static void hws_video_drain_queue_locked(struct hws_video *vid)
{
	if (vid->engine.active) {
		vb2_buffer_done(&vid->engine.active->vb.vb2_buf,
				VB2_BUF_STATE_ERROR);
		vid->engine.active = NULL;
	}
	if (vid->engine.next_prepared) {
		vb2_buffer_done(&vid->engine.next_prepared->vb.vb2_buf,
				VB2_BUF_STATE_ERROR);
		vid->engine.next_prepared = NULL;
	}
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

	/* 3) Ensure the IRQ handler finished any in-flight completions */
	if (vid->parent && vid->parent->irq >= 0)
		synchronize_irq(vid->parent->irq);

	/* 4) Drain SW capture queue & in-flight under lock */
	spin_lock_irqsave(&vid->irq_lock, flags);
	hws_video_drain_queue_locked(vid);
	spin_unlock_irqrestore(&vid->irq_lock, flags);

	/* 5) Free V4L2 controls */
	v4l2_ctrl_handler_free(&vid->control_handler);

	/* 6) Unregister the video_device if we own it */
	if (vid->video_device) {
		if (video_is_registered(vid->video_device)) {
			hws_resolution_remove(vid->video_device);
			video_unregister_device(vid->video_device);
		} else {
			video_device_release(vid->video_device);
		}
		vid->video_device = NULL;
	}

	/* 7) Reset simple state (don’t memset the whole struct here) */
	hws_capture_engine_cleanup(vid);
	INIT_LIST_HEAD(&vid->consumers);
	mutex_destroy(&vid->state_lock);
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

void hws_program_dma_for_addr(struct hws_pcie_dev *hws, unsigned int ch,
			      dma_addr_t dma)
{
	struct hws_video *vid = &hws->video[ch];

	hws_program_dma_window(vid, dma);
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

	WRITE_ONCE(hws->video[chan].cap_active, on);

	dev_dbg(&hws->pdev->dev, "vcap %s ch%u (reg=0x%08x)\n",
		on ? "ON" : "OFF", chan, status);
}

static void hws_seed_dma_windows(struct hws_pcie_dev *hws)
{
	const u32 addr_mask = PCI_E_BAR_ADD_MASK;
	const u32 addr_low_mask = PCI_E_BAR_ADD_LOWMASK;
	u32 table = 0x208;	/* one 64-bit entry per channel */
	unsigned int ch;

	if (!hws || !hws->bar0_base)
		return;

	/* If cur_max_video_ch isn’t set yet, default to max_channels */
	if (!hws->cur_max_video_ch || hws->cur_max_video_ch > hws->max_channels)
		hws->cur_max_video_ch = hws->max_channels;

	for (ch = 0; ch < hws->cur_max_video_ch; ch++, table += 8) {
		/* 1) Ensure a tiny, valid DMA buf exists (1 page is plenty) */
		if (!hws->scratch_vid[ch].cpu) {
			hws->scratch_vid[ch].size = PAGE_SIZE;
			hws->scratch_vid[ch].cpu =
			    dma_alloc_coherent(&hws->pdev->dev,
					       hws->scratch_vid[ch].size,
					       &hws->scratch_vid[ch].dma,
					       GFP_KERNEL);
			if (!hws->scratch_vid[ch].cpu) {
				dev_warn(&hws->pdev->dev,
					 "ch%u: scratch DMA alloc failed, skipping seed\n",
					 ch);
				continue;
			}
		}

		/* 2) Program 64-bit BAR remap entry for this channel */
		{
			dma_addr_t p = hws->scratch_vid[ch].dma;
			u32 lo = lower_32_bits(p) & addr_mask;
			u32 hi = upper_32_bits(p);
			u32 pci_addr_low = lower_32_bits(p) & addr_low_mask;

			writel_relaxed(hi,
				       hws->bar0_base + PCI_ADDR_TABLE_BASE +
				       table);
			writel_relaxed(lo,
				       hws->bar0_base + PCI_ADDR_TABLE_BASE +
				       table + PCIE_BARADDROFSIZE);

			/* 3) Per-channel AXI base + PCI low */
			writel_relaxed((ch + 1) * PCIEBAR_AXI_BASE +
				       pci_addr_low,
				       hws->bar0_base + CVBS_IN_BUF_BASE +
				       ch * PCIE_BARADDROFSIZE);

			/* 4) Half-frame length in /16 units.
			 * Prefer the current channel’s computed half_size if available.
			 * Fall back to PAGE_SIZE/2.
			 */
			{
				u32 half_bytes = hws->video[ch].pix.half_size ?
				    hws->video[ch].pix.half_size :
				    (PAGE_SIZE / 2);
				writel_relaxed(half_bytes / 16,
					       hws->bar0_base +
					       CVBS_IN_BUF_BASE2 +
					       ch * PCIE_BARADDROFSIZE);
			}
		}
	}

	/* Post writes so device sees them before we move on */
	(void)readl(hws->bar0_base + HWS_REG_INT_STATUS);
}

static void hws_ack_all_irqs(struct hws_pcie_dev *hws)
{
	u32 st = readl(hws->bar0_base + HWS_REG_INT_STATUS);

	if (st) {
		writel(st, hws->bar0_base + HWS_REG_INT_STATUS);	/* W1C */
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
	writel(HWS_INT_EN_MASK, hws->bar0_base + INT_EN_REG_BASE);
	(void)readl(hws->bar0_base + INT_EN_REG_BASE);
}

void hws_init_video_sys(struct hws_pcie_dev *hws, bool enable)
{
	int i;

	if (hws->start_run && !enable)
		return;

	/* 1) reset the decoder mode register to 0 */
	writel(0x00000000, hws->bar0_base + HWS_REG_DEC_MODE);
	hws_seed_dma_windows(hws);

	/* 3) on a full reset, clear all per-channel status and indices */
	if (!enable) {
		for (i = 0; i < hws->max_channels; i++) {
			/* helpers to arm/disable capture engines */
			hws_enable_video_capture(hws, i, false);
		}
	}

	/* 4) “Start run”: set bit31, wait a bit, then program low 24 bits */
	writel(0x80000000, hws->bar0_base + HWS_REG_DEC_MODE);
	// udelay(500);
	writel(0x80FFFFFF, hws->bar0_base + HWS_REG_DEC_MODE);
	writel(0x13, hws->bar0_base + HWS_REG_DEC_MODE);
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
	(void)in_fps;

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
	u32 new_size;
	bool queue_busy;
	bool needs_realloc;
	bool geometry_changed;
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

	if (!mutex_trylock(&v->state_lock)) {
		return;
	}

	if (!geometry_changed) {
		v->pix.interlaced = interlaced;
		v->pix.field = interlaced ? V4L2_FIELD_INTERLACED :
					    V4L2_FIELD_NONE;
		hws_set_current_dv_timings(v, w, h, interlaced);
		v->current_fps = fps;
		mutex_unlock(&v->state_lock);
		return;
	}

	queue_busy = hws_any_queue_busy(v);

	WRITE_ONCE(v->stop_requested, true);
	WRITE_ONCE(v->cap_active, false);
	/* Publish software stop first so the IRQ completion path sees the stop
	 * before we touch MMIO or engine state. Pairs with READ_ONCE() checks in the
	 * VDONE handler and hws_arm_next() to prevent completions while modes
	 * change.
	 */
	smp_wmb();

	hws_enable_video_capture(pdx, ch, false);
	readl(pdx->bar0_base + HWS_REG_INT_STATUS);

	if (v->parent && v->parent->irq >= 0)
		synchronize_irq(v->parent->irq);

	/* Update software pixel state */
	v->pix.width = w;
	v->pix.height = h;
	v->pix.interlaced = interlaced;
	v->pix.field = interlaced ? V4L2_FIELD_INTERLACED : V4L2_FIELD_NONE;
	hws_set_current_dv_timings(v, w, h, interlaced);
	v->current_fps = fps;

	new_size = hws_calc_sizeimage(v, w, h, interlaced);
	v->window_valid = false;
	needs_realloc = queue_busy && new_size > v->alloc_sizeimage;

	/* Notify listeners that the resolution changed whenever we have
	 * an active queue, regardless of whether we can continue streaming
	 * with the existing buffers. This ensures user space sees a source
	 * change event instead of an empty queue (VIDIOC_DQEVENT -> -ENOENT).
	 */
	if (queue_busy) {
		struct v4l2_event ev = {
			.type = V4L2_EVENT_SOURCE_CHANGE,
		};
		ev.u.src_change.changes = V4L2_EVENT_SRC_CH_RESOLUTION;
		v4l2_event_queue(v->video_device, &ev);

		/* If buffers are smaller than new requirement, error the queue
		 * so users re-request buffers before we restart streaming.
		 */
		if (needs_realloc) {
			hws_capture_engine_stop_locked(v);
			hws_capture_engine_cleanup(v);
			hws_set_all_queues_error(v);
			goto out_unlock;
		}
	} else {
		v->alloc_sizeimage = PAGE_ALIGN(new_size);
	}

	hws_capture_prepare_reconfigure_locked(v);

	/* Program HW with new resolution */
	hws_write_if_diff(pdx, HWS_REG_OUT_RES(ch), (h << 16) | w);

	/* Legacy half-buffer programming */
	writel(v->pix.half_size / 16,
	       pdx->bar0_base + CVBS_IN_BUF_BASE2 + ch * PCIE_BARADDROFSIZE);
	(void)readl(pdx->bar0_base + CVBS_IN_BUF_BASE2 +
		    ch * PCIE_BARADDROFSIZE);

	/* Reset per-channel toggles/counters */
	WRITE_ONCE(v->last_buf_half_toggle, 0);
	atomic_set(&v->engine.sequence_number, 0);

	ret = hws_capture_restart_after_reconfigure_locked(v);
	if (ret < 0)
		hws_set_all_queues_error(v);

out_unlock:
	mutex_unlock(&v->state_lock);
}

static struct hws_vfh_ctx *hws_ctx_from_file(struct file *file)
{
	struct v4l2_fh *fh = file ? file->private_data : NULL;

	if (!fh)
		return NULL;
	return container_of(fh, struct hws_vfh_ctx, fh);
}

static struct vb2_queue *hws_vb2q_from_file(struct file *file)
{
	struct hws_vfh_ctx *ctx = hws_ctx_from_file(file);

	return ctx ? &ctx->vbq : NULL;
}

static struct hwsvideo_buffer *
hws_ctx_pop_buffer_locked(struct hws_vfh_ctx *ctx)
{
	struct hwsvideo_buffer *buf;

	if (!ctx || list_empty(&ctx->buf_queue))
		return NULL;
	buf = list_first_entry(&ctx->buf_queue, struct hwsvideo_buffer, list);
	list_del_init(&buf->list);
	return buf;
}

static void hws_ctx_return_all_buffers(struct hws_vfh_ctx *ctx,
				       enum vb2_buffer_state state)
{
	unsigned long flags;
	struct hwsvideo_buffer *buf, *tmp;
	LIST_HEAD(done);

	if (!ctx)
		return;

	spin_lock_irqsave(&ctx->qlock, flags);
	while (!list_empty(&ctx->buf_queue)) {
		buf = list_first_entry(&ctx->buf_queue, struct hwsvideo_buffer, list);
		list_move_tail(&buf->list, &done);
	}
	spin_unlock_irqrestore(&ctx->qlock, flags);

	list_for_each_entry_safe(buf, tmp, &done, list) {
		list_del_init(&buf->list);
		vb2_buffer_done(&buf->vb.vb2_buf, state);
	}
}

static void hws_collect_direct_done_locked(struct hws_video *vid,
					   struct list_head *done)
{
	lockdep_assert_held(&vid->irq_lock);
	if (vid->engine.active) {
		INIT_LIST_HEAD(&vid->engine.active->list);
		list_add_tail(&vid->engine.active->list, done);
		vid->engine.active = NULL;
	}
	if (vid->engine.next_prepared) {
		list_add_tail(&vid->engine.next_prepared->list, done);
		vid->engine.next_prepared = NULL;
	}
}

bool hws_any_queue_busy(struct hws_video *vid)
{
	struct hws_vfh_ctx *ctx;
	unsigned long flags;
	bool busy = false;

	if (!vid)
		return false;

	spin_lock_irqsave(&vid->consumers_lock, flags);
	list_for_each_entry(ctx, &vid->consumers, node) {
		if (vb2_is_busy(&ctx->vbq)) {
			busy = true;
			break;
		}
	}
	spin_unlock_irqrestore(&vid->consumers_lock, flags);
	return busy;
}

void hws_set_all_queues_error(struct hws_video *vid)
{
	struct hws_vfh_ctx *ctx;
	unsigned long flags;

	if (!vid)
		return;

	spin_lock_irqsave(&vid->consumers_lock, flags);
	list_for_each_entry(ctx, &vid->consumers, node)
		vb2_queue_error(&ctx->vbq);
	spin_unlock_irqrestore(&vid->consumers_lock, flags);
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
	struct hws_video *vid = video_drvdata(file);
	struct hws_vfh_ctx *ctx;
	struct vb2_queue *q;
	int ret;
	unsigned long flags;

	if (!vid || !vid->video_device)
		return -ENODEV;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->video = vid;
	ctx->streaming = false;
	INIT_LIST_HEAD(&ctx->buf_queue);
	INIT_LIST_HEAD(&ctx->node);
	spin_lock_init(&ctx->qlock);

	v4l2_fh_init(&ctx->fh, vid->video_device);
	file->private_data = &ctx->fh;
	v4l2_fh_add(&ctx->fh, file);

	q = &ctx->vbq;
	memset(q, 0, sizeof(*q));
	q->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	q->io_modes = VB2_MMAP | VB2_DMABUF;
	q->drv_priv = ctx;
	q->buf_struct_size = sizeof(struct hwsvideo_buffer);
	q->ops = &hws_consumer_qops;
	q->mem_ops = &vb2_dma_contig_memops;
	q->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
	q->lock = &vid->state_lock;
	q->min_queued_buffers = 1;
	q->dev = &vid->parent->pdev->dev;

	ret = vb2_queue_init(q);
	if (ret) {
		v4l2_fh_del(&ctx->fh, file);
		v4l2_fh_exit(&ctx->fh);
		file->private_data = NULL;
		kfree(ctx);
		return ret;
	}
	/* Each open file handle owns its own queue for its entire lifetime. */
	q->owner = &ctx->fh;

	spin_lock_irqsave(&vid->consumers_lock, flags);
	list_add_tail(&ctx->node, &vid->consumers);
	spin_unlock_irqrestore(&vid->consumers_lock, flags);
	return 0;
}

static int hws_release(struct file *file)
{
	struct hws_vfh_ctx *ctx = hws_ctx_from_file(file);
	struct hws_video *vid;
	unsigned long flags;

	if (!ctx)
		return 0;
	vid = ctx->video;
	if (vb2_is_streaming(&ctx->vbq))
		vb2_streamoff(&ctx->vbq, ctx->vbq.type);

	mutex_lock(&vid->state_lock);
	ctx->streaming = false;
	(void)hws_capture_recompute_stream_mode_locked(vid, ctx, true);
	mutex_unlock(&vid->state_lock);

	hws_ctx_return_all_buffers(ctx, VB2_BUF_STATE_ERROR);

	spin_lock_irqsave(&vid->consumers_lock, flags);
	if (!list_empty(&ctx->node))
		list_del_init(&ctx->node);
	spin_unlock_irqrestore(&vid->consumers_lock, flags);

	vb2_queue_release(&ctx->vbq);
	ctx->vbq.owner = NULL;
	v4l2_fh_del(&ctx->fh, file);
	v4l2_fh_exit(&ctx->fh);
	file->private_data = NULL;
	kfree(ctx);
	return 0;
}

static long hws_unlocked_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct hws_vfh_ctx *ctx = hws_ctx_from_file(file);

	if (!ctx)
		return -EINVAL;
	if (!ctx->video || !ctx->video->video_device)
		return -ENODEV;
	return video_ioctl2(file, cmd, arg);
}

static __poll_t hws_poll(struct file *file, struct poll_table_struct *wait)
{
	struct hws_vfh_ctx *ctx = hws_ctx_from_file(file);

	if (!ctx)
		return EPOLLERR;
	if (!ctx->video || !ctx->video->video_device)
		return EPOLLERR;
	return vb2_poll(&ctx->vbq, file, wait);
}

static int hws_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct hws_vfh_ctx *ctx = hws_ctx_from_file(file);

	if (!ctx)
		return -EINVAL;
	if (!ctx->video || !ctx->video->video_device)
		return -ENODEV;
	return vb2_mmap(&ctx->vbq, vma);
}

static const struct v4l2_file_operations hws_fops = {
	.owner = THIS_MODULE,
	.open = hws_open,
	.release = hws_release,
	.poll = hws_poll,
	.unlocked_ioctl = hws_unlocked_ioctl,
	.mmap = hws_mmap,
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

static int hws_vidioc_reqbufs(struct file *file, void *priv,
			      struct v4l2_requestbuffers *req)
{
	struct vb2_queue *q = hws_vb2q_from_file(file);

	(void)priv;
	if (!q)
		return -EINVAL;
	return vb2_reqbufs(q, req);
}

static int hws_vidioc_prepare_buf(struct file *file, void *priv,
				  struct v4l2_buffer *buf)
{
	struct vb2_queue *q = hws_vb2q_from_file(file);

	(void)priv;
	if (!q)
		return -EINVAL;
	return vb2_prepare_buf(q, NULL, buf);
}

static int hws_vidioc_create_bufs(struct file *file, void *priv,
				  struct v4l2_create_buffers *create)
{
	struct vb2_queue *q = hws_vb2q_from_file(file);

	(void)priv;
	if (!q)
		return -EINVAL;
	return vb2_create_bufs(q, create);
}

static int hws_vidioc_querybuf(struct file *file, void *priv,
			       struct v4l2_buffer *buf)
{
	struct vb2_queue *q = hws_vb2q_from_file(file);

	(void)priv;
	if (!q)
		return -EINVAL;
	return vb2_querybuf(q, buf);
}

static int hws_vidioc_qbuf(struct file *file, void *priv,
			   struct v4l2_buffer *buf)
{
	struct vb2_queue *q = hws_vb2q_from_file(file);

	(void)priv;
	if (!q)
		return -EINVAL;
	return vb2_qbuf(q, NULL, buf);
}

static int hws_vidioc_dqbuf(struct file *file, void *priv,
			    struct v4l2_buffer *buf)
{
	struct vb2_queue *q = hws_vb2q_from_file(file);

	(void)priv;
	if (!q)
		return -EINVAL;
	return vb2_dqbuf(q, buf, file->f_flags & O_NONBLOCK);
}

static int hws_vidioc_expbuf(struct file *file, void *priv,
			     struct v4l2_exportbuffer *eb)
{
	struct vb2_queue *q = hws_vb2q_from_file(file);

	(void)priv;
	if (!q)
		return -EINVAL;
	return vb2_expbuf(q, eb);
}

static int hws_vidioc_streamon(struct file *file, void *priv,
			       enum v4l2_buf_type type)
{
	struct vb2_queue *q = hws_vb2q_from_file(file);

	(void)priv;
	if (!q)
		return -EINVAL;
	return vb2_streamon(q, type);
}

static int hws_vidioc_streamoff(struct file *file, void *priv,
				enum v4l2_buf_type type)
{
	struct vb2_queue *q = hws_vb2q_from_file(file);

	(void)priv;
	if (!q)
		return -EINVAL;
	return vb2_streamoff(q, type);
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
	.vidioc_reqbufs = hws_vidioc_reqbufs,
	.vidioc_prepare_buf = hws_vidioc_prepare_buf,
	.vidioc_create_bufs = hws_vidioc_create_bufs,
	.vidioc_querybuf = hws_vidioc_querybuf,
	.vidioc_qbuf = hws_vidioc_qbuf,
	.vidioc_dqbuf = hws_vidioc_dqbuf,
	.vidioc_expbuf = hws_vidioc_expbuf,
	.vidioc_streamon = hws_vidioc_streamon,
	.vidioc_streamoff = hws_vidioc_streamoff,

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
	/* example for packed 16bpp (YUYV); replace with your real math/align */
	u32 lines = h;		/* full frame lines for sizeimage */
	u32 bytesperline = ALIGN(w * 2, 64);
	u32 sizeimage, half0;

	/* publish into pix, since we now carry these in-state */
	v->pix.bytesperline = bytesperline;
	sizeimage = bytesperline * lines;

	half0 = sizeimage / 2;

	v->pix.sizeimage = sizeimage;
	v->pix.half_size = half0;	/* first half; second = sizeimage - half0 */
	v->pix.field = interlaced ? V4L2_FIELD_INTERLACED : V4L2_FIELD_NONE;

	return v->pix.sizeimage;
}

static int hws_consumer_queue_setup(struct vb2_queue *q,
				    unsigned int *num_buffers,
				    unsigned int *nplanes,
				    unsigned int sizes[],
				    struct device *alloc_devs[])
{
	struct hws_vfh_ctx *ctx = q->drv_priv;
	struct hws_video *vid = ctx->video;

	(void)num_buffers;
	(void)alloc_devs;
	if (!vid->pix.sizeimage) {
		vid->pix.bytesperline = ALIGN(vid->pix.width * 2, 64);
		vid->pix.sizeimage = vid->pix.bytesperline * vid->pix.height;
	}
	if (*nplanes) {
		if (sizes[0] < vid->pix.sizeimage)
			return -EINVAL;
	} else {
		*nplanes = 1;
		sizes[0] = PAGE_ALIGN(vid->pix.sizeimage);
	}

	vid->alloc_sizeimage = PAGE_ALIGN(vid->pix.sizeimage);
	return 0;
}

static int hws_consumer_buffer_prepare(struct vb2_buffer *vb)
{
	struct hws_vfh_ctx *ctx = vb->vb2_queue->drv_priv;
	struct hws_video *vid = ctx->video;
	struct hws_pcie_dev *hws = vid->parent;
	size_t need = vid->pix.sizeimage;
	dma_addr_t dma_addr;

	if (vb2_plane_size(vb, 0) < need)
		return -EINVAL;

	dma_addr = vb2_dma_contig_plane_dma_addr(vb, 0);
	if (dma_addr & 0x3F) {
		dev_err(&hws->pdev->dev,
			"Buffer DMA address 0x%llx not 64-byte aligned\n",
			(unsigned long long)dma_addr);
		return -EINVAL;
	}

	vb2_set_plane_payload(vb, 0, need);
	return 0;
}

static void hws_consumer_buffer_queue(struct vb2_buffer *vb)
{
	struct hws_vfh_ctx *ctx = vb->vb2_queue->drv_priv;
	struct hws_video *vid = ctx->video;
	struct hwsvideo_buffer *buf = to_hwsbuf(vb);
	unsigned long flags;

	lockdep_assert_held(&vid->state_lock);
	buf->slot = 0;
	spin_lock_irqsave(&ctx->qlock, flags);
	list_add_tail(&buf->list, &ctx->buf_queue);
	spin_unlock_irqrestore(&ctx->qlock, flags);

	if (READ_ONCE(vid->engine.mode) == HWS_CAPTURE_MODE_DIRECT &&
	    READ_ONCE(vid->engine.direct_owner) == ctx)
		hws_capture_kick_direct_locked(vid);
}

static int hws_consumer_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct hws_vfh_ctx *ctx = q->drv_priv;
	struct hws_video *vid = ctx->video;
	int ret;

	(void)count;
	lockdep_assert_held(&vid->state_lock);
	ctx->streaming = true;
	ret = hws_capture_recompute_stream_mode_locked(vid, ctx, false);
	if (ret) {
		ctx->streaming = false;
		hws_ctx_return_all_buffers(ctx, VB2_BUF_STATE_QUEUED);
	}
	return ret;
}

static void hws_consumer_stop_streaming(struct vb2_queue *q)
{
	struct hws_vfh_ctx *ctx = q->drv_priv;
	struct hws_video *vid = ctx->video;

	lockdep_assert_held(&vid->state_lock);
	ctx->streaming = false;
	(void)hws_capture_recompute_stream_mode_locked(vid, ctx, true);
	hws_ctx_return_all_buffers(ctx, VB2_BUF_STATE_ERROR);
}

static const struct vb2_ops hws_consumer_qops = {
	.queue_setup = hws_consumer_queue_setup,
	.buf_prepare = hws_consumer_buffer_prepare,
	.buf_init = hws_buf_init,
	.buf_finish = hws_buf_finish,
	.buf_cleanup = hws_buf_cleanup,
	.buf_queue = hws_consumer_buffer_queue,
	.start_streaming = hws_consumer_start_streaming,
	.stop_streaming = hws_consumer_stop_streaming,
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

		/* hws_video_init_channel() should have set:
		 * - ch->parent, ch->channel_index
		 * - locks (state_lock, irq_lock)
		 * - engine state
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
		vdev->fops = &hws_fops;	/* your file_ops */
		vdev->ioctl_ops = &hws_ioctl_fops;	/* your ioctl_ops */
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

		ret = hws_resolution_create(vdev);
		if (ret) {
			dev_err(&dev->pdev->dev,
				"device_create_file(resolution) ch%u failed: %d\n",
				i, ret);
			video_unregister_device(vdev);
			goto err_unwind;
		}
	}

	return 0;

err_unwind:
	for (; i >= 0; i--) {
		struct hws_video *ch = &dev->video[i];

		v4l2_ctrl_handler_free(&ch->control_handler);
		if (!ch->video_device)
			continue;
		if (video_is_registered(ch->video_device)) {
			hws_resolution_remove(ch->video_device);
			video_unregister_device(ch->video_device);
		} else {
			video_device_release(ch->video_device);
		}
		ch->video_device = NULL;
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
		struct hws_vfh_ctx *ctx;
		unsigned long flags;

		mutex_lock(&ch->state_lock);
		hws_capture_engine_stop_locked(ch);
		hws_capture_engine_cleanup(ch);
		spin_lock_irqsave(&ch->consumers_lock, flags);
		list_for_each_entry(ctx, &ch->consumers, node) {
			ctx->streaming = false;
			vb2_queue_error(&ctx->vbq);
		}
		spin_unlock_irqrestore(&ch->consumers_lock, flags);
		mutex_unlock(&ch->state_lock);

		if (ch->video_device) {
			if (video_is_registered(ch->video_device)) {
				hws_resolution_remove(ch->video_device);
				video_unregister_device(ch->video_device);
			} else {
				video_device_release(ch->video_device);
			}
			ch->video_device = NULL;
		}
		v4l2_ctrl_handler_free(&ch->control_handler);
	}
	v4l2_device_unregister(&dev->v4l2_device);
}

int hws_video_quiesce(struct hws_pcie_dev *hws, const char *reason)
{
	int i;
	u64 start_ns = ktime_get_mono_fast_ns();

	dev_dbg(&hws->pdev->dev, "video:%s:begin channels=%u\n", reason,
		hws->cur_max_video_ch);

	for (i = 0; i < hws->cur_max_video_ch; i++) {
		struct hws_video *vid = &hws->video[i];
		struct hws_vfh_ctx *ctx;
		unsigned long flags;
		u64 ch_start_ns = ktime_get_mono_fast_ns();

		mutex_lock(&vid->state_lock);
		hws_capture_engine_stop_locked(vid);
		hws_capture_engine_cleanup(vid);
		spin_lock_irqsave(&vid->consumers_lock, flags);
		list_for_each_entry(ctx, &vid->consumers, node) {
			ctx->streaming = false;
			vb2_queue_error(&ctx->vbq);
		}
		spin_unlock_irqrestore(&vid->consumers_lock, flags);
		mutex_unlock(&vid->state_lock);

		dev_dbg(&hws->pdev->dev,
			"video:%s:ch=%d quiesced (%lluus)\n",
			reason, i, hws_elapsed_us(ch_start_ns));
	}
	dev_dbg(&hws->pdev->dev, "video:%s:done ret=0 (%lluus)\n", reason,
		hws_elapsed_us(start_ns));
	return 0;
}

void hws_video_pm_resume(struct hws_pcie_dev *hws)
{
	/* Nothing mandatory to do here for vb2 — userspace will STREAMON again.
	 * If you track per-channel 'auto-restart' policy, re-arm it here.
	 */
}
