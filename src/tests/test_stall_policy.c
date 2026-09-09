// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint64_t u64;
#include "../hws_stall_policy.h"

/* Use seconds as the time unit; the production policy is unit independent. */
int main(void)
{
	/* Startup/no first frame, threshold, and bounded repeat logging. */
	assert(hws_stall_event(101, 100, 100, 2, 10, 30, false, false) == HWS_STALL_QUIET);
	assert(hws_stall_event(102, 100, 100, 2, 10, 30, false, false) == HWS_STALL_BEGIN);
	assert(hws_stall_event(111, 100, 102, 2, 10, 30, true, false) == HWS_STALL_QUIET);
	assert(hws_stall_event(112, 100, 102, 2, 10, 30, true, false) == HWS_STALL_REPEAT);
	/* A delivered frame resolves a stall even after a long monitor delay. */
	assert(hws_stall_event(140, 100, 112, 2, 10, 30, true, true) == HWS_STALL_RESUMED);
	assert(hws_stall_event(141, 140, 140, 2, 10, 30, false, true) == HWS_STALL_QUIET);
	assert(hws_stall_event(142, 140, 140, 2, 10, 30, false, false) == HWS_STALL_BEGIN);
	/* Healthy summaries and disabled diagnostics do not create stalls. */
	assert(hws_stall_event(130, 129, 100, 2, 10, 30, false, true) == HWS_STALL_HEARTBEAT);
	assert(hws_stall_event(130, 129, 100, 2, 10, 0, false, true) == HWS_STALL_QUIET);
	assert(hws_stall_event(999, 100, 100, 0, 10, 30, false, false) == HWS_STALL_QUIET);
	assert(hws_stall_event(999, 100, 100, 0, 10, 30, true, true) == HWS_STALL_QUIET);
	/* Progress seen now wins over stale timestamps/heartbeat deadlines. */
	assert(hws_stall_event(200, 100, 100, 2, 10, 30, false, true) == HWS_STALL_HEARTBEAT);
	assert(hws_stall_event(130, 100, 100, 2, 10, 30, false, false) == HWS_STALL_BEGIN);
	assert(hws_stall_age(99, 100) == 0);
	assert(hws_stall_event(99, 100, 100, 2, 10, 30, false, false) == HWS_STALL_QUIET);
	puts("stall policy: startup, repeat, resume, recurrence, heartbeat, disable, clock checks passed");
	return 0;
}
