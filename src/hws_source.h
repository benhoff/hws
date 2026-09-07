/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_SOURCE_H
#define HWS_SOURCE_H

/* Worker context only. Six bounded reads, no retry and no configuration writes.
 * This checks observable native geometry/nominal rate, NOT physical DMA bounds
 * or exact timing. A transition away and back between samples is unobservable.
 * STREAMOFF drains the worker before configured pix/current_fps can change.
 */
static int hws_video_source_matches(struct hws_video *v)
{
	struct hws_pcie_dev *hws = v->parent;
	u32 a0, a1, r0, r1, f0, f1;
	u32 mask = BIT(v->channel_index) | BIT(8 + v->channel_index);
	u32 expected = v->pix.width | (v->pix.height << 16);

	if (READ_ONCE(hws->pci_lost) || READ_ONCE(hws->dma_failed))
		return -ENODEV;
	if (READ_ONCE(hws->suspended) || READ_ONCE(v->stop_requested))
		return -ECANCELED;
	a0 = readl(hws->bar0_base + HWS_REG_ACTIVE_STATUS);
	r0 = readl(hws->bar0_base + HWS_REG_IN_RES(v->channel_index));
	f0 = readl(hws->bar0_base + HWS_REG_FRAME_RATE(v->channel_index));
	r1 = readl(hws->bar0_base + HWS_REG_IN_RES(v->channel_index));
	f1 = readl(hws->bar0_base + HWS_REG_FRAME_RATE(v->channel_index));
	a1 = readl(hws->bar0_base + HWS_REG_ACTIVE_STATUS);
	if (a0 == U32_MAX || a1 == U32_MAX || r0 == U32_MAX ||
	    r1 == U32_MAX || f0 == U32_MAX || f1 == U32_MAX) {
		hws_device_lost(hws, "all-ones capture source snapshot");
		return -ENODEV;
	}
	if ((a0 & mask) != BIT(v->channel_index) ||
	    (a1 & mask) != BIT(v->channel_index) ||
	    r0 != expected || r1 != expected ||
	    !v->current_fps || f0 != v->current_fps || f1 != v->current_fps)
		return -EPIPE;
	return 0;
}
#endif
