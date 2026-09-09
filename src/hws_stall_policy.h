/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_STALL_POLICY_H
#define HWS_STALL_POLICY_H

/* u64 and bool are supplied by the caller (kernel or host regression test). */
enum hws_stall_event {
	HWS_STALL_QUIET,
	HWS_STALL_BEGIN,
	HWS_STALL_REPEAT,
	HWS_STALL_RESUMED,
	HWS_STALL_HEARTBEAT,
};

static inline u64 hws_stall_age(u64 now, u64 then)
{
	return now >= then ? now - then : 0;
}

/* Progress wins over a pending timeout. A backward clock never underflows. */
static inline enum hws_stall_event
hws_stall_event(u64 now, u64 progress, u64 report, u64 timeout,
		u64 repeat, u64 heartbeat, bool stalled, bool advanced)
{
	if (!timeout)
		return HWS_STALL_QUIET;
	if (stalled && advanced)
		return HWS_STALL_RESUMED;
	if (!advanced && hws_stall_age(now, progress) >= timeout) {
		if (!stalled)
			return HWS_STALL_BEGIN;
		return hws_stall_age(now, report) >= repeat ?
			HWS_STALL_REPEAT : HWS_STALL_QUIET;
	}
	return heartbeat && hws_stall_age(now, report) >= heartbeat ?
		HWS_STALL_HEARTBEAT : HWS_STALL_QUIET;
}

#endif
