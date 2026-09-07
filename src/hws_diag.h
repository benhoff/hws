/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_DIAG_H
#define HWS_DIAG_H
#include <linux/ktime.h>
#include "hws.h"
#include "hws_trace.h"

enum hws_diag_action {
	HWS_DIAG_QBUF = 1, HWS_DIAG_TAKE, HWS_DIAG_EMPTY,
	HWS_DIAG_RECYCLE, HWS_DIAG_COMPLETE, HWS_DIAG_STOP,
	HWS_DIAG_IRQ, HWS_DIAG_WORK, HWS_DIAG_START,
};

/* Caller already holds irq_lock. No pointers, extra MMIO, allocation or printk.
 * Pre-STREAMON QBUF records carry the previous epoch; START snapshots the new
 * epoch's initial queue depth. Cap resets with the normal stream evidence. */
static inline void hws_diag_locked(struct hws_video *v, u32 action, u32 buffer,
				   u64 generation, u64 value1, u64 value2)
{
	if (!trace_hws_video_diag_enabled())
		return;
	lockdep_assert_held(&v->irq_lock);
	if (v->diag_records >= HWS_VIDEO_DIAG_LIMIT) {
		if (v->diag_suppressed != U32_MAX)
			v->diag_suppressed++;
		return;
	}
	v->diag_records++;
	trace_hws_video_diag(pci_name(v->parent->pdev), v->channel_index,
		v->evidence_stream_epoch, generation, action, v->queued_count,
		v->active ? v->active->vb.vb2_buf.index : U32_MAX, buffer,
		ktime_get_mono_fast_ns(), value1, value2);
}
#endif
