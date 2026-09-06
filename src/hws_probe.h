/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_PROBE_H
#define HWS_PROBE_H

#include <linux/types.h>

/* Fixed work and storage bounds; no allocation or printk in the observer. */
#define HWS_DMA_PROBE_LIMIT 4096U
#define HWS_DMA_PROBE_BITS 64U
#define HWS_DMA_PROBE_READ_LIMIT 131072U
#define HWS_DMA_ANOMALY_WINDOWS 16U
#define HWS_DMA_ANOMALY_POST 2U

struct hws_dma_probe {
	u64 code[4]; /* upper/lower, then an independent second read of both */
	u64 started_ns;
	u64 duration_ns;
	u32 offset[2]; /* absolute private-ring byte offsets of sampled rows */
	u32 status;
	u8 contrast[4];
	u8 before;
	u8 after;
	u32 window; /* zero = initial mapping; nonzero = bounded anomaly window */
	u8 position; /* 0 = previous, 1 = trigger, 2/3 = following IRQs */
};

struct hws_dma_probe_state {
	struct hws_dma_probe previous;
	u64 previous_generation;
	u32 reads;
	u32 windows;
	u32 records;
	u32 triggers;
	u32 suppressed;
	u8 remaining;
};

#endif
