// SPDX-License-Identifier: GPL-2.0-only
#define main probe_main
#include "hws_drm_timing_probe.c"
#undef main
#include <assert.h>

int main(void)
{
	const int64_t period = 16666667, t = 1000000000;
	struct measurements m = {0};
	/* i915 may deliver during blanking before the timestamp's scanout epoch. */
	observe(&m, 100, t, t - 600000, period);
	observe(&m, 101, t + period, t + period - 500000, period);
	assert(!m.invalid && m.receipt_max == -500000 && !m.missing);
	observe(&m, 103, t + 3 * period, t + 3 * period + 200000, period);
	assert(!m.invalid && m.missing == 1);
	/* Frozen NVIDIA sequence with otherwise increasing timestamps fails. */
	m = (struct measurements){0};
	observe(&m, 0, t, t + 1000, period);
	observe(&m, 0, t + period, t + period + 1000, period);
	assert(m.invalid == 1);
	/* Zero timestamps and half-second stale fallback timestamps fail. */
	m = (struct measurements){0};
	observe(&m, 2, 0, t, period);
	assert(m.invalid == 1);
	m = (struct measurements){0};
	observe(&m, 2, t, t + 500000000, period);
	assert(m.invalid == 1);
	m = (struct measurements){0};
	observe(&m, 10, t, t + 1000, period);
	observe(&m, 11, t + 2 * period, t + 2 * period + 1000, period);
	assert(m.invalid == 1);
	assert(number("-1") == 0 && number("0") == 0 && number("12x") == 0);
	puts("DRM timing probe analysis PASS");
	return 0;
}
