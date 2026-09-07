/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_FAULT_H
#define HWS_FAULT_H

/* Include after hws.h. Never turn the missing-device sentinel into toggle 1. */
static inline u8 hws_read_toggle(struct hws_pcie_dev *hws, u32 offset)
{
	u32 raw;

	if (READ_ONCE(hws->pci_lost))
		return 0xff;
	raw = readl(hws->bar0_base + offset);
	if (raw == U32_MAX) {
		hws_device_lost(hws, "all-ones DMA toggle");
		return 0xff;
	}
	return raw & 1;
}
#endif
