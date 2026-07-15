// SPDX-License-Identifier: GPL-2.0-only
#include <linux/io.h>
#include <linux/pci.h>

#include "hws.h"
#include "hws_mmio.h"
#include "hws_reg_atlas.h"
#include "hws_trace.h"

static void hws_mmio_trace(struct hws_pcie_dev *hws, u32 offset, u32 value,
			   bool write, bool relaxed, const char *caller)
{
	const struct hws_reg_desc *reg;
	int channel;

	if (!trace_hws_mmio_enabled())
		return;

	reg = hws_reg_lookup(offset, &channel);
	trace_hws_mmio(hws && hws->pdev ? pci_name(hws->pdev) : "unknown",
		       offset, value, write, relaxed, channel,
		       reg ? reg->id : "UNKNOWN", caller);
}

u32 __hws_mmio_read32(struct hws_pcie_dev *hws, u32 offset, bool relaxed,
		      const char *caller)
{
	u32 value;

	if (relaxed)
		value = readl_relaxed(hws->bar0_base + offset);
	else
		value = readl(hws->bar0_base + offset);
	hws_mmio_trace(hws, offset, value, false, relaxed, caller);
	return value;
}

void __hws_mmio_write32(struct hws_pcie_dev *hws, u32 offset, u32 value,
			bool relaxed, const char *caller)
{
	if (relaxed)
		writel_relaxed(value, hws->bar0_base + offset);
	else
		writel(value, hws->bar0_base + offset);
	hws_mmio_trace(hws, offset, value, true, relaxed, caller);
}
