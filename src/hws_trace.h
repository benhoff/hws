/* SPDX-License-Identifier: GPL-2.0-only */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM hws

#if !defined(_HWS_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _HWS_TRACE_H

#include <linux/tracepoint.h>
#include "hws_probe.h"

TRACE_EVENT(hws_vdone_probe,
	TP_PROTO(const char *device, u32 channel, u64 epoch, u64 generation,
		 u32 index, const struct hws_dma_probe *p),
	TP_ARGS(device, channel, epoch, generation, index, p),
	TP_STRUCT__entry(
		__string(device, device)
		__field(u32, channel)
		__field(u64, epoch)
		__field(u64, generation)
		__field(u32, index)
		__field(u32, window)
		__field(u8, position)
		__field(u64, started_ns)
		__field(u64, duration_ns)
		__field(u32, status)
		__field(u8, before)
		__field(u8, after)
		__array(u64, code, 4)
		__array(u32, offset, 2)
		__array(u8, contrast, 4)
	),
	TP_fast_assign(
		__assign_str(device);
		__entry->channel = channel;
		__entry->epoch = epoch;
		__entry->generation = generation;
		__entry->index = index;
		__entry->window = p->window;
		__entry->position = p->position;
		__entry->started_ns = p->started_ns;
		__entry->duration_ns = p->duration_ns;
		__entry->status = p->status;
		__entry->before = p->before;
		__entry->after = p->after;
		memcpy(__entry->code, p->code, sizeof(p->code));
		memcpy(__entry->offset, p->offset, sizeof(p->offset));
		memcpy(__entry->contrast, p->contrast, sizeof(p->contrast));
	),
	TP_printk("device=%s ch=%u epoch=%llu generation=%llu index=%u window=%u position=%u started_ns=%llu duration_ns=%llu before=%u after=%u status=0x%08x offset0=%u offset1=%u code0=0x%016llx code1=0x%016llx code2=0x%016llx code3=0x%016llx contrast0=%u contrast1=%u contrast2=%u contrast3=%u",
		  __get_str(device), __entry->channel,
		  (unsigned long long)__entry->epoch,
		  (unsigned long long)__entry->generation, __entry->index,
		  __entry->window, __entry->position,
		  (unsigned long long)__entry->started_ns,
		  (unsigned long long)__entry->duration_ns,
		  __entry->before, __entry->after, __entry->status,
		  __entry->offset[0], __entry->offset[1],
		  (unsigned long long)__entry->code[0],
		  (unsigned long long)__entry->code[1],
		  (unsigned long long)__entry->code[2],
		  (unsigned long long)__entry->code[3],
		  __entry->contrast[0], __entry->contrast[1],
		  __entry->contrast[2], __entry->contrast[3])
);

TRACE_EVENT(hws_vdone_stream,
	TP_PROTO(const char *device, u32 channel, u64 epoch, u8 action,
		 u32 width, u32 height, u32 fourcc, u32 fps, u32 sizeimage,
		 u64 extent, u64 split, u32 split16),
	TP_ARGS(device, channel, epoch, action, width, height, fourcc, fps,
		sizeimage, extent, split, split16),
	TP_STRUCT__entry(
		__string(device, device)
		__field(u32, channel)
		__field(u64, epoch)
		__field(u8, action)
		__field(u32, width)
		__field(u32, height)
		__field(u32, fourcc)
		__field(u32, fps)
		__field(u32, sizeimage)
		__field(u64, extent)
		__field(u64, split)
		__field(u32, split16)
	),
	TP_fast_assign(
		__assign_str(device);
		__entry->channel = channel;
		__entry->epoch = epoch;
		__entry->action = action;
		__entry->width = width;
		__entry->height = height;
		__entry->fourcc = fourcc;
		__entry->fps = fps;
		__entry->sizeimage = sizeimage;
		__entry->extent = extent;
		__entry->split = split;
		__entry->split16 = split16;
	),
	TP_printk("device=%s ch=%u epoch=%llu action=%u width=%u height=%u fourcc=0x%08x fps=%u sizeimage=%u extent=%llu split=%llu split16=%u",
		  __get_str(device), __entry->channel,
		  (unsigned long long)__entry->epoch, __entry->action,
		  __entry->width, __entry->height, __entry->fourcc,
		  __entry->fps, __entry->sizeimage,
		  (unsigned long long)__entry->extent,
		  (unsigned long long)__entry->split, __entry->split16)
);

TRACE_EVENT(hws_vdone_irq,
	TP_PROTO(const char *device, u32 channel, u64 epoch, u64 timestamp_ns,
		 u64 generation, u32 int_status, u32 status_after_ack,
		 u32 samples, u64 interval_us, u32 disposition),
	TP_ARGS(device, channel, epoch, timestamp_ns, generation, int_status,
		status_after_ack, samples, interval_us, disposition),
	TP_STRUCT__entry(
		__string(device, device)
		__field(u32, channel)
		__field(u64, epoch)
		__field(u64, timestamp_ns)
		__field(u64, generation)
		__field(u32, int_status)
		__field(u32, status_after_ack)
		__field(u8, before_ack)
		__field(u8, after_ack)
		__field(bool, stable)
		__field(bool, reasserted)
		__field(u8, previous_toggle)
		__field(u64, interval_us)
		__field(u8, result)
		__field(u8, ambiguity)
		__field(u8, phase)
		__field(u8, completed_half)
	),
	TP_fast_assign(
		__assign_str(device);
		__entry->channel = channel;
		__entry->epoch = epoch;
		__entry->timestamp_ns = timestamp_ns;
		__entry->generation = generation;
		__entry->int_status = int_status;
		__entry->status_after_ack = status_after_ack;
		__entry->before_ack = samples & 0x01;
		__entry->after_ack = (samples >> 1) & 0x01;
		__entry->stable = (samples >> 2) & 0x01;
		__entry->reasserted = (samples >> 3) & 0x01;
		__entry->previous_toggle = (samples >> 4) & 0x01;
		__entry->interval_us = interval_us;
		__entry->result = disposition & 0xff;
		__entry->ambiguity = (disposition >> 8) & 0xff;
		__entry->phase = (disposition >> 16) & 0xff;
		__entry->completed_half = (disposition >> 24) & 0xff;
	),
	TP_printk("device=%s ch=%u epoch=%llu timestamp_ns=%llu generation=%llu int_status=0x%08x status_after_ack=0x%08x before=%u after=%u stable=%u reasserted=%u previous=%u interval_us=%llu result=%u ambiguity=%u phase=%u completed_half=%u",
		  __get_str(device), __entry->channel,
		  (unsigned long long)__entry->epoch,
		  (unsigned long long)__entry->timestamp_ns,
		  (unsigned long long)__entry->generation, __entry->int_status,
		  __entry->status_after_ack, __entry->before_ack,
		  __entry->after_ack, __entry->stable, __entry->reasserted,
		  __entry->previous_toggle,
		  (unsigned long long)__entry->interval_us, __entry->result,
		  __entry->ambiguity, __entry->phase, __entry->completed_half)
);

TRACE_EVENT(hws_vdone_copy,
	TP_PROTO(const char *device, u32 channel, u64 epoch, u64 generation,
		 u64 offset, u64 length, u64 duration_ns, u32 observation,
		 int result),
	TP_ARGS(device, channel, epoch, generation, offset, length, duration_ns,
		observation, result),
	TP_STRUCT__entry(
		__string(device, device)
		__field(u32, channel)
		__field(u64, epoch)
		__field(u64, generation)
		__field(u8, toggle)
		__field(u8, completed_half)
		__field(u64, offset)
		__field(u64, length)
		__field(u64, duration_ns)
		__field(u8, toggle_before)
		__field(u8, toggle_after)
		__field(bool, guard_checked)
		__field(bool, guard_ok)
		__field(bool, frame_complete)
		__field(int, result)
	),
	TP_fast_assign(
		__assign_str(device);
		__entry->channel = channel;
		__entry->epoch = epoch;
		__entry->generation = generation;
		__entry->toggle = observation & 0x01;
		__entry->completed_half = (observation >> 1) & 0x01;
		__entry->offset = offset;
		__entry->length = length;
		__entry->duration_ns = duration_ns;
		__entry->toggle_before = (observation >> 2) & 0xff;
		__entry->toggle_after = (observation >> 10) & 0xff;
		__entry->guard_checked = (observation >> 18) & 0x01;
		__entry->guard_ok = (observation >> 19) & 0x01;
		__entry->frame_complete = (observation >> 20) & 0x01;
		__entry->result = result;
	),
	TP_printk("device=%s ch=%u epoch=%llu generation=%llu toggle=%u completed_half=%u offset=%llu length=%llu duration_ns=%llu toggle_before=%u toggle_after=%u guard_checked=%u guard_ok=%u frame_complete=%u result=%d",
		  __get_str(device), __entry->channel,
		  (unsigned long long)__entry->epoch,
		  (unsigned long long)__entry->generation, __entry->toggle,
		  __entry->completed_half, (unsigned long long)__entry->offset,
		  (unsigned long long)__entry->length,
		  (unsigned long long)__entry->duration_ns,
		  __entry->toggle_before, __entry->toggle_after,
		  __entry->guard_checked, __entry->guard_ok,
		  __entry->frame_complete, __entry->result)
);

TRACE_EVENT(hws_vdone_frame,
	TP_PROTO(const char *device, u32 channel, u64 epoch, u64 half0_generation,
		 u64 half1_generation, u32 sequence, u64 timestamp_ns,
		 bool delivered, bool no_buffer, bool dropped_partial),
	TP_ARGS(device, channel, epoch, half0_generation, half1_generation,
		sequence, timestamp_ns, delivered, no_buffer, dropped_partial),
	TP_STRUCT__entry(
		__string(device, device)
		__field(u32, channel)
		__field(u64, epoch)
		__field(u64, half0_generation)
		__field(u64, half1_generation)
		__field(u32, sequence)
		__field(u64, timestamp_ns)
		__field(bool, delivered)
		__field(bool, no_buffer)
		__field(bool, dropped_partial)
	),
	TP_fast_assign(
		__assign_str(device);
		__entry->channel = channel;
		__entry->epoch = epoch;
		__entry->half0_generation = half0_generation;
		__entry->half1_generation = half1_generation;
		__entry->sequence = sequence;
		__entry->timestamp_ns = timestamp_ns;
		__entry->delivered = delivered;
		__entry->no_buffer = no_buffer;
		__entry->dropped_partial = dropped_partial;
	),
	TP_printk("device=%s ch=%u epoch=%llu half0_generation=%llu half1_generation=%llu sequence=%u timestamp_ns=%llu delivered=%u no_buffer=%u dropped_partial=%u",
		  __get_str(device), __entry->channel,
		  (unsigned long long)__entry->epoch,
		  (unsigned long long)__entry->half0_generation,
		  (unsigned long long)__entry->half1_generation,
		  __entry->sequence, (unsigned long long)__entry->timestamp_ns,
		  __entry->delivered, __entry->no_buffer,
		  __entry->dropped_partial)
);

TRACE_EVENT(hws_vdone_recovery,
	TP_PROTO(const char *device, u32 channel, u64 epoch, u64 generation,
		 u64 interval_us, u8 toggle, u8 attempt, u8 reason,
		 bool dropped_partial, bool steady, u32 reports),
	TP_ARGS(device, channel, epoch, generation, interval_us, toggle,
		attempt, reason, dropped_partial, steady, reports),
	TP_STRUCT__entry(
		__string(device, device)
		__field(u32, channel)
		__field(u64, epoch)
		__field(u64, generation)
		__field(u64, interval_us)
		__field(u8, toggle)
		__field(u8, attempt)
		__field(u8, reason)
		__field(bool, dropped_partial)
		__field(bool, steady)
		__field(u32, reports)
	),
	TP_fast_assign(
		__assign_str(device);
		__entry->channel = channel;
		__entry->epoch = epoch;
		__entry->generation = generation;
		__entry->interval_us = interval_us;
		__entry->toggle = toggle;
		__entry->attempt = attempt;
		__entry->reason = reason;
		__entry->dropped_partial = dropped_partial;
		__entry->steady = steady;
		__entry->reports = reports;
	),
	TP_printk("device=%s ch=%u epoch=%llu generation=%llu interval_us=%llu toggle=%u attempt=%u reason=%u dropped_partial=%u steady=%u reports=%u",
		  __get_str(device), __entry->channel,
		  (unsigned long long)__entry->epoch,
		  (unsigned long long)__entry->generation,
		  (unsigned long long)__entry->interval_us, __entry->toggle,
		  __entry->attempt, __entry->reason, __entry->dropped_partial,
		  __entry->steady, __entry->reports)
);

#endif /* _HWS_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE hws_trace

#include <trace/define_trace.h>
