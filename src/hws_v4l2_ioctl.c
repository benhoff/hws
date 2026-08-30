// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/math64.h>
#include <linux/v4l2-dv-timings.h>

#include <media/v4l2-ioctl.h>
#include <media/v4l2-dev.h>
#include <media/v4l2-dv-timings.h>
#include <media/videobuf2-core.h>
#include <media/videobuf2-v4l2.h>

#include "hws.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws_v4l2_ioctl.h"

struct hws_dv_mode {
	struct v4l2_dv_timings timings;
	u32 refresh_hz;
};

static const struct hws_dv_mode *
hws_find_dv_by_wh_fps(u32 w, u32 h, bool interlaced, u32 fps);
static u32 hws_input_status(struct hws_video *vid);

static const struct hws_dv_mode hws_dv_modes[] = {
	{
		.timings = V4L2_DV_BT_CEA_1920X1080P60,
		.refresh_hz = 60,
	},
	{
		.timings = V4L2_DV_BT_CEA_1920X1080P30,
		.refresh_hz = 30,
	},
	{
		.timings = V4L2_DV_BT_CEA_1280X720P60,
		.refresh_hz = 60,
	},
	{
		.timings = V4L2_DV_BT_CEA_720X480P59_94,
		.refresh_hz = 60,
	},
	{
		.timings = V4L2_DV_BT_CEA_720X576P50,
		.refresh_hz = 50,
	},
	{
		.timings = V4L2_DV_BT_DMT_800X600P60,
		.refresh_hz = 60,
	},
	{
		.timings = V4L2_DV_BT_DMT_640X480P60,
		.refresh_hz = 60,
	},
	{
		.timings = V4L2_DV_BT_DMT_1024X768P60,
		.refresh_hz = 60,
	},
	{
		.timings = V4L2_DV_BT_DMT_1280X768P60,
		.refresh_hz = 60,
	},
	{
		.timings = V4L2_DV_BT_DMT_1280X800P60,
		.refresh_hz = 60,
	},
	{
		.timings = V4L2_DV_BT_DMT_1280X1024P60,
		.refresh_hz = 60,
	},
	{
		.timings = V4L2_DV_BT_DMT_1360X768P60,
		.refresh_hz = 60,
	},
	{
		.timings = V4L2_DV_BT_DMT_1440X900P60,
		.refresh_hz = 60,
	},
	{
		.timings = V4L2_DV_BT_DMT_1680X1050P60,
		.refresh_hz = 60,
	},
};

static const size_t hws_dv_modes_cnt = ARRAY_SIZE(hws_dv_modes);

static inline u32 hws_calc_half_size(u32 sizeimage)
{
	return hws_video_native_split(sizeimage);
}

static inline void hws_hw_write_bchs(struct hws_pcie_dev *hws, unsigned int ch,
				     u8 br, u8 co, u8 hu, u8 sa)
{
	u32 packed = (sa << 24) | (hu << 16) | (co << 8) | br;

	if (!hws || !hws->bar0_base || ch >= hws->max_channels)
		return;
	writel_relaxed(packed, hws->bar0_base + HWS_REG_BCHS(ch));
	(void)readl(hws->bar0_base + HWS_REG_BCHS(ch)); /* post write */
}

/* S_DV_TIMINGS accepts only complete timings returned by our enumeration. */
static const struct hws_dv_mode *
hws_match_supported_dv(const struct v4l2_dv_timings *req)
{
	size_t i;

	if (!req || req->type != V4L2_DV_BT_656_1120)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(hws_dv_modes); i++) {
		if (v4l2_match_dv_timings(req, &hws_dv_modes[i].timings,
					  0, true))
			return &hws_dv_modes[i];
	}
	return NULL;
}

static const struct hws_dv_mode *
hws_find_dv_by_wh_fps(u32 w, u32 h, bool interlaced, u32 fps)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(hws_dv_modes); i++) {
		const struct hws_dv_mode *t = &hws_dv_modes[i];
		const struct v4l2_bt_timings *bt = &t->timings.bt;

		if (t->timings.type != V4L2_DV_BT_656_1120)
			continue;

		if (bt->width == w && bt->height == h &&
		    !!bt->interlaced == interlaced &&
		    t->refresh_hz == fps)
			return t;
	}
	return NULL;
}

int hws_dv_timings_from_mode(u32 width, u32 height, bool interlaced, u32 fps,
			     struct v4l2_dv_timings *timings)
{
	const struct hws_dv_mode *m;

	if (!timings)
		return -EINVAL;

	m = hws_find_dv_by_wh_fps(width, height, interlaced, fps);
	if (!m)
		return -EINVAL;

	*timings = m->timings;
	return 0;
}

int hws_detect_dv_timings(struct hws_video *vid,
			  struct v4l2_dv_timings *timings, u32 *fps)
{
	struct hws_pcie_dev *pdx;
	const struct hws_dv_mode *m;
	u32 active0, active1, res0, res1, live_fps;
	u32 channel_mask;
	u32 width, height;
	bool interlaced;

	if (!timings)
		return -EINVAL;

	memset(timings, 0, sizeof(*timings));
	if (fps)
		*fps = 0;
	if (!vid)
		return -ENODEV;

	pdx = vid->parent;
	if (!pdx || !pdx->bar0_base ||
	    vid->channel_index < 0 || vid->channel_index >= pdx->max_channels)
		return -ENODEV;

	channel_mask = BIT(vid->channel_index) |
		       BIT(8 + vid->channel_index);
	active0 = readl(pdx->bar0_base + HWS_REG_ACTIVE_STATUS);
	if (active0 == U32_MAX)
		return -ENODEV;
	if (!(active0 & BIT(vid->channel_index)))
		return -ENOLINK;

	res0 = readl(pdx->bar0_base + HWS_REG_IN_RES(vid->channel_index));
	live_fps = readl(pdx->bar0_base +
			 HWS_REG_FRAME_RATE(vid->channel_index));
	res1 = readl(pdx->bar0_base + HWS_REG_IN_RES(vid->channel_index));
	active1 = readl(pdx->bar0_base + HWS_REG_ACTIVE_STATUS);
	if (res0 == U32_MAX || res1 == U32_MAX || active1 == U32_MAX ||
	    live_fps == U32_MAX)
		return -ENODEV;
	if (!(active1 & BIT(vid->channel_index)))
		return -ENOLINK;

	width = res1 & 0xffff;
	height = res1 >> 16;
	interlaced = !!(active1 & BIT(8 + vid->channel_index));
	*timings = (struct v4l2_dv_timings) {
		.type = V4L2_DV_BT_656_1120,
		.bt = {
			.width = width,
			.height = height,
			.interlaced = interlaced,
		},
	};
	if (fps)
		*fps = live_fps;

	/* A mode transition between the paired samples is not a stable lock. */
	if ((active0 & channel_mask) != (active1 & channel_mask) ||
	    res0 != res1 || !width || !height || !live_fps || live_fps > 240)
		return -ENOLCK;

	m = hws_find_dv_by_wh_fps(width, height, interlaced, live_fps);
	if (!m)
		return -ERANGE;

	*timings = m->timings;
	return 0;
}

static u32 hws_input_status(struct hws_video *vid)
{
	struct v4l2_dv_timings timings;
	int ret;

	if (!vid)
		return V4L2_IN_ST_NO_SIGNAL;

	ret = hws_detect_dv_timings(vid, &timings, NULL);
	if (ret == -ENOLCK)
		return V4L2_IN_ST_NO_SYNC;
	if (ret == -ENOLINK || ret == -ENODEV)
		return V4L2_IN_ST_NO_SIGNAL;
	return 0;
}

/* QUERY reports only what the receiver detects and never changes state. */
int hws_vidioc_query_dv_timings(struct file *file, void *fh,
				struct v4l2_dv_timings *timings)
{
	struct hws_video *vid = video_drvdata(file);

	if (!timings)
		return -EINVAL;

	return hws_detect_dv_timings(vid, timings, NULL);
}

/* Enumerate the Nth supported DV timings from our static table. */
int hws_vidioc_enum_dv_timings(struct file *file, void *fh,
			       struct v4l2_enum_dv_timings *edv)
{
	if (!edv)
		return -EINVAL;

	if (edv->pad)
		return -EINVAL;

	if (edv->index >= hws_dv_modes_cnt)
		return -EINVAL;

	edv->timings = hws_dv_modes[edv->index].timings;
	return 0;
}

/* Get the *currently configured* DV timings. */
int hws_vidioc_g_dv_timings(struct file *file, void *fh,
			    struct v4l2_dv_timings *timings)
{
	struct hws_video *vid = video_drvdata(file);

	if (!timings)
		return -EINVAL;

	*timings = vid->cur_dv_timings;
	return 0;
}

/* Set DV timings: must match one of our supported modes.
 * If buffers are queued and this implies a size change, we reject with -EBUSY.
 * Otherwise we update pix state and (optionally) reprogram the HW.
 */
int hws_vidioc_s_dv_timings(struct file *file, void *fh,
			    struct v4l2_dv_timings *timings)
{
	struct hws_video *vid = video_drvdata(file);
	const struct hws_dv_mode *m;
	const struct v4l2_bt_timings *bt;
	bool timing_changed;

	if (!timings)
		return -EINVAL;

	m = hws_match_supported_dv(timings);
	if (!m)
		return -EINVAL;

	bt = &m->timings.bt;
	if (bt->interlaced)
		return -EINVAL;

	lockdep_assert_held(&vid->state_lock);
	timing_changed = !v4l2_match_dv_timings(&vid->cur_dv_timings,
						&m->timings, 0, true);

	/* Timing changes also change the default capture format and its size. */
	if (vb2_is_busy(&vid->buffer_queue)) {
		if (timing_changed)
			return -EBUSY;
		*timings = m->timings;
		return 0;
	}

	vid->pix.width      = bt->width;
	vid->pix.height     = bt->height;
	vid->pix.field      = V4L2_FIELD_NONE;
	vid->pix.interlaced = false;
	vid->pix.fourcc     = V4L2_PIX_FMT_YUYV;
	hws_set_pix_colorimetry(&vid->pix);

	/* Recompute stride, sizeimage, and half_size. */
	vid->pix.bytesperline = hws_yuyv_packed_stride(bt->width);
	vid->pix.sizeimage = (u32)hws_yuyv_packed_size(bt->width, bt->height);
	vid->pix.half_size    = hws_calc_half_size(vid->pix.sizeimage);
	vid->cur_dv_timings   = m->timings;
	vid->current_fps      = m->refresh_hz;
	if (vid->parent && vid->parent->bar0_base &&
	    !READ_ONCE(vid->parent->pci_lost)) {
		writel((bt->height << 16) | bt->width,
		       vid->parent->bar0_base +
		       HWS_REG_OUT_RES(vid->channel_index));
		(void)readl(vid->parent->bar0_base +
			    HWS_REG_OUT_RES(vid->channel_index));
	}
	*timings = m->timings;
	return 0;
}

/* Report DV timings capability: advertise BT.656/1120 with
 * the min/max WxH derived from our table and basic progressive support.
 */
int hws_vidioc_dv_timings_cap(struct file *file, void *fh,
			      struct v4l2_dv_timings_cap *cap)
{
	u32 min_w = ~0U, min_h = ~0U;
	u32 max_w = 0,       max_h = 0;
	u64 min_pixelclock = U64_MAX, max_pixelclock = 0;
	u32 standards = 0;
	size_t i, n = 0;

	if (!cap)
		return -EINVAL;
	if (cap->pad)
		return -EINVAL;

	memset(cap, 0, sizeof(*cap));
	cap->type = V4L2_DV_BT_656_1120;

	for (i = 0; i < ARRAY_SIZE(hws_dv_modes); i++) {
		const struct v4l2_bt_timings *bt = &hws_dv_modes[i].timings.bt;

		if (hws_dv_modes[i].timings.type != V4L2_DV_BT_656_1120)
			continue;
		n++;

		if (bt->width  < min_w)
			min_w = bt->width;
		if (bt->height < min_h)
			min_h = bt->height;
		if (bt->width  > max_w)
			max_w = bt->width;
		if (bt->height > max_h)
			max_h = bt->height;
		if (bt->pixelclock < min_pixelclock)
			min_pixelclock = bt->pixelclock;
		if (bt->pixelclock > max_pixelclock)
			max_pixelclock = bt->pixelclock;
		standards |= bt->standards;
	}

	/* If the table was empty, fail gracefully. */
	if (!n || min_w == U32_MAX)
		return -ENODATA;

	cap->bt.min_width  = min_w;
	cap->bt.max_width  = max_w;
	cap->bt.min_height = min_h;
	cap->bt.max_height = max_h;
	cap->bt.min_pixelclock = min_pixelclock;
	cap->bt.max_pixelclock = max_pixelclock;
	cap->bt.standards = standards;

	/* Only progressive modes are advertised. */
	cap->bt.capabilities = V4L2_DV_BT_CAP_PROGRESSIVE;

	return 0;
}

static int hws_s_ctrl(struct v4l2_ctrl *ctrl)
{
	struct hws_video *vid =
		container_of(ctrl->handler, struct hws_video, control_handler);
	struct hws_pcie_dev *pdx = vid->parent;
	bool program = false;

	switch (ctrl->id) {
	case V4L2_CID_BRIGHTNESS:
		vid->current_brightness = ctrl->val;
		program = true;
		break;
	case V4L2_CID_CONTRAST:
		vid->current_contrast = ctrl->val;
		program = true;
		break;
	case V4L2_CID_SATURATION:
		vid->current_saturation = ctrl->val;
		program = true;
		break;
	case V4L2_CID_HUE:
		vid->current_hue = ctrl->val;
		program = true;
		break;
	default:
		return -EINVAL;
	}

	if (program) {
		hws_hw_write_bchs(pdx, vid->channel_index,
				  (u8)vid->current_brightness,
				  (u8)vid->current_contrast,
				  (u8)vid->current_hue,
				  (u8)vid->current_saturation);
	}
	return 0;
}

const struct v4l2_ctrl_ops hws_ctrl_ops = {
	.s_ctrl = hws_s_ctrl,
};

int hws_vidioc_querycap(struct file *file, void *priv, struct v4l2_capability *cap)
{
	struct hws_video *vid = video_drvdata(file);
	int vi_index = vid->channel_index + 1; /* keep it simple */

	strscpy(cap->driver, KBUILD_MODNAME, sizeof(cap->driver));
	snprintf(cap->card, sizeof(cap->card),
		 "AVMatrix HWS Capture %d", vi_index);
	if (vid->parent && vid->parent->pdev)
		snprintf(cap->bus_info, sizeof(cap->bus_info), "PCI:%s",
			 pci_name(vid->parent->pdev));
	return 0;
}

int hws_vidioc_enum_fmt_vid_cap(struct file *file, void *priv_fh, struct v4l2_fmtdesc *f)
{
	if (f->index != 0)
		return -EINVAL; /* only one format */

	f->pixelformat = V4L2_PIX_FMT_YUYV;
	return 0;
}

int hws_vidioc_g_fmt_vid_cap(struct file *file, void *fh, struct v4l2_format *fmt)
{
	struct hws_video *vid = video_drvdata(file);

	fmt->fmt.pix.width        = vid->pix.width;
	fmt->fmt.pix.height       = vid->pix.height;
	fmt->fmt.pix.pixelformat  = V4L2_PIX_FMT_YUYV;
	fmt->fmt.pix.field        = vid->pix.field;
	fmt->fmt.pix.bytesperline = vid->pix.bytesperline;
	fmt->fmt.pix.sizeimage    = vid->pix.sizeimage;
	fmt->fmt.pix.colorspace   = vid->pix.colorspace;
	fmt->fmt.pix.ycbcr_enc    = vid->pix.ycbcr_enc;
	fmt->fmt.pix.quantization = vid->pix.quantization;
	fmt->fmt.pix.xfer_func    = vid->pix.xfer_func;
	return 0;
}

static inline void hws_set_colorimetry_fmt(struct v4l2_pix_format *p)
{
	bool sd = p->height <= 576;

	p->colorspace   = sd ? V4L2_COLORSPACE_SMPTE170M : V4L2_COLORSPACE_REC709;
	p->ycbcr_enc    = V4L2_YCBCR_ENC_601;
	p->quantization = V4L2_QUANTIZATION_FULL_RANGE;
	p->xfer_func    = V4L2_XFER_FUNC_DEFAULT;
}

int hws_vidioc_try_fmt_vid_cap(struct file *file, void *fh, struct v4l2_format *f)
{
	struct hws_video *vid = file ? video_drvdata(file) : NULL;
	struct hws_pcie_dev *pdev = vid ? vid->parent : NULL;
	struct v4l2_pix_format *pix = &f->fmt.pix;
	u32 req_w = pix->width, req_h = pix->height;
	u32 w, h, bpl;
	u64 size;
	size_t max_frame = pdev ? pdev->max_hw_video_buf_sz : MAX_MM_VIDEO_SIZE;

	/* Only YUYV */
	pix->pixelformat = V4L2_PIX_FMT_YUYV;

	/* Defaults then clamp */
	w = (req_w ? req_w : 640);
	h = (req_h ? req_h : 480);
	if (w > MAX_VIDEO_HW_W)
		w = MAX_VIDEO_HW_W;
	if (h > MAX_VIDEO_HW_H)
		h = MAX_VIDEO_HW_H;
	if (!w)
		w = 640; /* hard fallback in case macros are odd */
	if (!h)
		h = 480;

	/* Field policy */
	pix->field = V4L2_FIELD_NONE;

	/* Ignore requested padding: the hardware and API layout is packed YUYV. */
	bpl = hws_yuyv_packed_stride(w);
	size = hws_yuyv_packed_size(w, h);
	if (size > U32_MAX || size > max_frame)
		return -ERANGE;

	pix->width        = w;
	pix->height       = h;
	pix->bytesperline = bpl;
	pix->sizeimage    = (u32)size;

	hws_set_colorimetry_fmt(pix);
	if (pdev)
		dev_dbg(&pdev->pdev->dev,
			"try_fmt: w=%u h=%u bpl=%u size=%u field=%u\n",
			pix->width, pix->height, pix->bytesperline,
			pix->sizeimage, pix->field);
	return 0;
}

int hws_vidioc_s_fmt_vid_cap(struct file *file, void *priv, struct v4l2_format *f)
{
	struct hws_video *vid = video_drvdata(file);
	int ret;

	if (f->type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
		return -EINVAL;

	/* Normalize the request */
	ret = hws_vidioc_try_fmt_vid_cap(file, priv, f);
	if (ret)
		return ret;

	/* Don't allow buffer layout changes while buffers are queued. */
	if (vb2_is_busy(&vid->buffer_queue)) {
		if (f->fmt.pix.width  != vid->pix.width  ||
		    f->fmt.pix.height != vid->pix.height ||
		    f->fmt.pix.bytesperline != vid->pix.bytesperline)
			return -EBUSY;
	}

	/* Apply to driver state */
	vid->pix.width        = f->fmt.pix.width;
	vid->pix.height       = f->fmt.pix.height;
	vid->pix.fourcc       = V4L2_PIX_FMT_YUYV;
	vid->pix.field        = f->fmt.pix.field;
	vid->pix.colorspace   = f->fmt.pix.colorspace;
	vid->pix.ycbcr_enc    = f->fmt.pix.ycbcr_enc;
	vid->pix.quantization = f->fmt.pix.quantization;
	vid->pix.xfer_func    = f->fmt.pix.xfer_func;

	/* Update negotiated buffer sizes. */
	vid->pix.bytesperline = hws_yuyv_packed_stride(vid->pix.width);
	vid->pix.sizeimage = (u32)hws_yuyv_packed_size(vid->pix.width,
							vid->pix.height);
	vid->pix.half_size    = hws_calc_half_size(vid->pix.sizeimage);
	vid->pix.interlaced   = false;

	dev_dbg(&vid->parent->pdev->dev,
		"s_fmt:   w=%u h=%u bpl=%u size=%u\n",
		vid->pix.width, vid->pix.height, vid->pix.bytesperline,
		vid->pix.sizeimage);

	return 0;
}

int hws_vidioc_g_parm(struct file *file, void *fh, struct v4l2_streamparm *param)
{
	struct hws_video *vid = video_drvdata(file);
	struct v4l2_dv_timings detected;
	u32 fps;

	if (param->type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
		return -EINVAL;

	if (hws_detect_dv_timings(vid, &detected, &fps))
		fps = vid->current_fps ? vid->current_fps : 60;

	/* HDMI receivers report the detected frame period, they don't set it. */
	param->parm.capture.capability           = 0;
	param->parm.capture.capturemode          = 0;
	param->parm.capture.timeperframe.numerator   = 1;
	param->parm.capture.timeperframe.denominator = fps;
	param->parm.capture.extendedmode         = 0;
	param->parm.capture.readbuffers          = 0;

	return 0;
}

int hws_vidioc_enum_input(struct file *file, void *priv,
			  struct v4l2_input *input)
{
	struct hws_video *vid = video_drvdata(file);

	if (input->index)
		return -EINVAL;
	input->type         = V4L2_INPUT_TYPE_CAMERA;
	strscpy(input->name, KBUILD_MODNAME, sizeof(input->name));
	input->capabilities = V4L2_IN_CAP_DV_TIMINGS;
	input->status       = hws_input_status(vid);

	return 0;
}

int hws_vidioc_g_input(struct file *file, void *priv, unsigned int *index)
{
	*index = 0;
	return 0;
}

int hws_vidioc_s_input(struct file *file, void *priv, unsigned int i)
{
	return i ? -EINVAL : 0;
}
