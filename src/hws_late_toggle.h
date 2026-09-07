/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_LATE_TOGGLE_H
#define HWS_LATE_TOGGLE_H

#define HWS_LATE_TOGGLE_WINDOWS 16U
#define HWS_LATE_TOGGLE_SAMPLES 4U
#define HWS_LATE_TOGGLE_BUDGET_NS 50000ULL
#define HWS_LATE_TOGGLE_BUDGET 1U
#define HWS_LATE_TOGGLE_STOPPED 2U
#define HWS_LATE_TOGGLE_FAULT 4U
#define HWS_LATE_TOGGLE_CLOCK 8U

struct hws_late_toggle_observation {
	u64 irq_ns, started_ns, finished_ns;
	u64 start[HWS_LATE_TOGGLE_SAMPLES], end[HWS_LATE_TOGGLE_SAMPLES];
	u32 toggle[HWS_LATE_TOGGLE_SAMPLES], status[HWS_LATE_TOGGLE_SAMPLES];
	u32 window, count, flags;
	u8 baseline;
};
#endif
