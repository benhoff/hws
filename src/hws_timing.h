/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_TIMING_H
#define HWS_TIMING_H

/* Progressive configured/inferred timings, not a measurement of HDMI clocks. */
static inline int hws_dv_frame_period(const struct v4l2_dv_timings *timings,
				      struct v4l2_fract *period)
{
	const struct v4l2_bt_timings *bt = &timings->bt;
	u64 ht, vt, num, den, a, b;

	period->numerator = period->denominator = 0;
	if (timings->type != V4L2_DV_BT_656_1120 || bt->interlaced ||
	    !bt->width || !bt->height || !bt->pixelclock)
		return -EINVAL;
	ht = (u64)bt->width + bt->hfrontporch + bt->hsync + bt->hbackporch;
	vt = (u64)bt->height + bt->vfrontporch + bt->vsync + bt->vbackporch;
	if (ht > U32_MAX || vt > U32_MAX)
		return -ERANGE;
	/* Both totals fit u32, so this multiplication cannot overflow u64. */
	num = ht * vt;
	den = bt->pixelclock;
	a = num;
	b = den;
	while (b) {
		u64 rem = a - div64_u64(a, b) * b;

		a = b;
		b = rem;
	}
	num = div64_u64(num, a);
	den = div64_u64(den, a);
	if (num > U32_MAX || den > U32_MAX)
		return -ERANGE;
	period->numerator = num;
	period->denominator = den;
	return 0;
}
#endif
