/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_MMIO_H
#define HWS_MMIO_H

#include <linux/types.h>

struct hws_pcie_dev;

u32 __hws_mmio_read32(struct hws_pcie_dev *hws, u32 offset, bool relaxed,
		      const char *caller);
void __hws_mmio_write32(struct hws_pcie_dev *hws, u32 offset, u32 value,
			bool relaxed, const char *caller);

#define hws_readl(hws, offset) \
	__hws_mmio_read32((hws), (offset), false, __func__)
#define hws_readl_relaxed(hws, offset) \
	__hws_mmio_read32((hws), (offset), true, __func__)
#define hws_writel(hws, value, offset) \
	__hws_mmio_write32((hws), (offset), (value), false, __func__)
#define hws_writel_relaxed(hws, value, offset) \
	__hws_mmio_write32((hws), (offset), (value), true, __func__)

#endif
