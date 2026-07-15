/* SPDX-License-Identifier: GPL-2.0-only */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM hws

#if !defined(HWS_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define HWS_TRACE_H

#include <linux/tracepoint.h>

TRACE_EVENT(hws_mmio,
	TP_PROTO(const char *device, u32 offset, u32 value, u8 operation,
		 bool relaxed, int channel, const char *name, const char *caller),

	TP_ARGS(device, offset, value, operation, relaxed, channel, name, caller),

	TP_STRUCT__entry(
		__array(char, device, 32)
		__field(u32, offset)
		__field(u32, value)
		__field(u8, operation)
		__field(bool, relaxed)
		__field(int, channel)
		__array(char, name, 48)
		__array(char, caller, 64)
	),

	TP_fast_assign(
		strscpy(__entry->device, device, sizeof(__entry->device));
		__entry->offset = offset;
		__entry->value = value;
		__entry->operation = operation;
		__entry->relaxed = relaxed;
		__entry->channel = channel;
		strscpy(__entry->name, name, sizeof(__entry->name));
		strscpy(__entry->caller, caller, sizeof(__entry->caller));
	),

	TP_printk("device=%s operation=%s%s offset=0x%04x value=0x%08x channel=%d register=%s caller=%s",
		  __entry->device, __entry->operation ? "write" : "read",
		  __entry->relaxed ? "_relaxed" : "", __entry->offset,
		  __entry->value, __entry->channel, __entry->name,
		  __entry->caller)
);

#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE hws_trace

#include <trace/define_trace.h>
