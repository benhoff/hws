/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_DMA_CONFIG_H
#define HWS_DMA_CONFIG_H

/* Include after hws.h. Only the known-readable DMA window registers use this. */
static int hws_dma_readback(struct hws_pcie_dev *hws, u32 offset,
			    u32 expected, bool exact)
{
	u32 actual = readl(hws->bar0_base + offset);

	if (actual == U32_MAX) {
		hws_device_lost(hws, "all-ones DMA configuration readback");
		return -ENODEV;
	}
	/* The sole non-exact case is the documented idle-audio zero readback. */
	if (actual != expected && (exact || actual != 0)) {
		return -EIO;
	}
	return 0;
}

/*
 * Caller holds channel IRQ lock (also serializes audio/video shared-slot use).
 * capture_lock closes the check/program versus capture-enable race. No writes
 * to a shared remap slot while its peer producer is active, even equal writes.
 * This verifies programming, not DMA idle: callers still own that prerequisite.
 */
static int hws_program_dma_window(struct hws_pcie_dev *hws, unsigned int ch,
				  dma_addr_t dma, u32 split16, bool audio,
				  bool exact_audio_base)
{
	u32 table = PCI_ADDR_TABLE_BASE + HWS_VIDEO_REMAP_SLOT_OFF(ch);
	u32 hi = upper_32_bits(dma);
	u32 lo = lower_32_bits(dma) & PCI_E_BAR_ADD_MASK;
	u32 base = (ch + 1u) * PCIEBAR_AXI_BASE +
		   (lower_32_bits(dma) & PCI_E_BAR_ADD_LOWMASK);
	u32 base_reg = audio ? HWS_REG_AUD_DMA_ADDR(ch) : HWS_REG_VIDEO_DMA_ADDR(ch);
	u32 vcap, acap;
	unsigned long flags;
	bool peer_active;
	int ret = 0;

	lockdep_assert_held(&hws->video[ch].irq_lock);
	spin_lock_irqsave(&hws->capture_lock, flags);
	if (READ_ONCE(hws->pci_lost) || READ_ONCE(hws->dma_failed)) {
		ret = -ENODEV;
		goto out;
	}
	vcap = readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);
	acap = readl(hws->bar0_base + HWS_REG_ACAP_ENABLE);
	if (vcap == U32_MAX || acap == U32_MAX) {
		hws_device_lost(hws, "all-ones DMA configuration capture status");
		ret = -ENODEV;
		goto out;
	}
	if ((audio ? acap : vcap) & BIT(ch)) {
		ret = -EBUSY;
		goto out;
	}
	peer_active = (audio ? vcap : acap) & BIT(ch);
	if (!peer_active) {
		writel(hi, hws->bar0_base + table);
		writel(lo, hws->bar0_base + table + PCIE_BARADDROFSIZE);
	}
	ret = hws_dma_readback(hws, table, hi, true);
	if (ret)
		goto out;
	ret = hws_dma_readback(hws, table + PCIE_BARADDROFSIZE, lo, true);
	if (ret)
		goto out;
	writel(base, hws->bar0_base + base_reg);
	if (!audio)
		writel(split16, hws->bar0_base + HWS_REG_VIDEO_HALF_SIZE(ch));
	/* Idle audio base can read zero at probe/resume; stream start is exact. */
	ret = hws_dma_readback(hws, base_reg, base, !audio || exact_audio_base);
	if (!ret && !audio)
		ret = hws_dma_readback(hws, HWS_REG_VIDEO_HALF_SIZE(ch), split16, true);
	if (!ret && READ_ONCE(hws->pci_lost))
		ret = -ENODEV;
out:
	spin_unlock_irqrestore(&hws->capture_lock, flags);
	return ret;
}
#endif
