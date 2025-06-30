/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_V4L2_IOCTL_H
#define HWS_V4L2_IOCTL_H 

#include <media/v4l2-ctrls.h>
#include <linux/fs.h>

extern const struct v4l2_ctrl_ops hws_ctrl_ops;

int hws_vidioc_querycap(struct file *file, void *priv, struct v4l2_capability *cap);
int hws_vidioc_enum_fmt_vid_cap(struct file *file, void *priv_fh, struct v4l2_fmtdesc *f);
int hws_vidioc_g_fmt_vid_cap(struct file *file, void *fh, struct v4l2_format *fmt);
int hws_vidioc_try_fmt_vid_cap(struct file *file, void *fh, struct v4l2_format *f);
int vidioc_s_fmt_vid_cap(struct file *file, void *priv, struct v4l2_format *f);
int hws_vidioc_g_std(struct file *file, void *priv, v4l2_std_id *tvnorms);
int hws_vidioc_s_std(struct file *file, void *priv, v4l2_std_id tvnorms);
int hws_vidioc_g_parm(struct file *file, void *fh, struct v4l2_streamparm *setfps);
int hws_vidioc_enum_framesizes(struct file *file, void *fh, struct v4l2_frmsizeenum *fsize);
int hws_vidioc_enum_input(struct file *file, void *priv, struct v4l2_input *i);
int hws_vidioc_g_input(struct file *file, void *priv, unsigned int *i);
int hws_vidioc_s_input(struct file *file, void *priv, unsigned int i);
int vidioc_log_status(struct file *file, void *priv);
int hws_vidioc_g_ctrl(struct file *file, void *fh, struct v4l2_control *a);
int hws_vidioc_s_ctrl(struct file *file, void *fh, struct v4l2_control *a);

int hws_vidioc_queryctrl(struct file *file, void *fh, struct v4l2_queryctrl *a);
int hws_vidioc_enum_frameintervals(struct file *file, void *fh, struct v4l2_frmivalenum *fival);
int hws_vidioc_s_parm(struct file *file, void *fh, struct v4l2_streamparm *a);

#endif
