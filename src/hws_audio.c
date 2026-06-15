// SPDX-License-Identifier: GPL-2.0-only
#include "hws_audio.h"

#include "hws.h"
#include "hws_reg.h"

#include <sound/core.h>
#include <sound/pcm_params.h>
#include <sound/control.h>
#include <sound/pcm.h>
#include <sound/rawmidi.h>
#include <sound/initval.h>
#include <linux/preempt.h>
#include "hws_video.h"

static const struct snd_pcm_hardware audio_pcm_hardware = {
	.info = (SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_INTERLEAVED |
		 SNDRV_PCM_INFO_BLOCK_TRANSFER | SNDRV_PCM_INFO_RESUME |
		 SNDRV_PCM_INFO_MMAP_VALID),
	.formats = SNDRV_PCM_FMTBIT_S16_LE,
	.rates = SNDRV_PCM_RATE_48000,
	.rate_min = 48000,
	.rate_max = 48000,
	.channels_min = 2,
	.channels_max = 2,
	.buffer_bytes_max = 64 * 1024,
	.period_bytes_min = 512,
	.period_bytes_max = 16 * 1024,
	.periods_min = 2,
	.periods_max = 255,
};

static bool hws_audio_select_buffer(struct hws_pcie_dev *hws, unsigned int ch,
				    void **cpu_base, dma_addr_t *dma_base,
				    size_t *size)
{
	struct hws_scratch_dma *scratch;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return false;

	scratch = &hws->scratch_aud[ch];
	if (!scratch->cpu || !scratch->size)
		return false;

	if (cpu_base)
		*cpu_base = scratch->cpu;
	if (dma_base)
		*dma_base = scratch->dma;
	if (size)
		*size = scratch->size;
	return true;
}

static void hws_audio_program_remap_slot(struct hws_pcie_dev *hws,
					 u32 table_off, u32 hi, u32 page_lo)
{
	writel_relaxed(hi, hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off);
	writel_relaxed(page_lo, hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off +
		       PCIE_BARADDROFSIZE);
}

static int hws_audio_seed_capture_buffer(struct hws_pcie_dev *hws, unsigned int ch)
{
	dma_addr_t dma;
	u32 lo, hi, pci_addr;
	u32 audio_table_off;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return -EINVAL;

	if (!hws_audio_select_buffer(hws, ch, NULL, &dma, NULL))
		return -ENOMEM;

	lo = lower_32_bits(dma);
	hi = upper_32_bits(dma);
	pci_addr = lo & PCI_E_BAR_ADD_LOWMASK;
	lo &= PCI_E_BAR_ADD_MASK;
	audio_table_off = HWS_AUDIO_REMAP_SLOT_OFF(ch);
	hws_audio_program_remap_slot(hws, audio_table_off, hi, lo);
	writel_relaxed((ch + 1u) * PCIEBAR_AXI_BASE + pci_addr,
		       hws->bar0_base + HWS_REG_AUD_DMA_ADDR(ch));
	(void)readl(hws->bar0_base + HWS_REG_AUD_DMA_ADDR(ch));
	return 0;
}

void hws_audio_seed_channels(struct hws_pcie_dev *hws)
{
	unsigned int ch;

	if (!hws || !hws->bar0_base)
		return;

	for (ch = 0; ch < hws->cur_max_audio_ch; ch++) {
		int ret = hws_audio_seed_capture_buffer(hws, ch);

		if (ret)
			dev_warn(&hws->pdev->dev,
				 "audio seed ch%u failed ret=%d\n", ch, ret);
	}
}

static size_t hws_audio_packet_offset(const struct hws_audio *a, u8 cur_toggle)
{
	size_t packet = a->hw_packet_bytes;

	/*
	 * ABUF_TOGGLE reports the half the device is filling now, so the
	 * completed packet is the other half.
	 */
	return cur_toggle ? 0 : packet;
}

static void hws_audio_deliver_packet(struct hws_audio *a, const void *src)
{
	struct snd_pcm_substream *ss;
	struct snd_pcm_runtime *rt;
	snd_pcm_uframes_t frames, ring_pos, ring_frames, period_frames;
	size_t frame_bytes, packet_bytes, ring_bytes, first;
	unsigned long flags;
	unsigned int elapsed = 0;
	char *dst;

	ss = a->pcm_substream;
	if (!ss)
		return;

	rt = ss->runtime;
	if (!rt || !rt->dma_area)
		return;

	frame_bytes = a->frame_bytes;
	packet_bytes = a->hw_packet_bytes;
	ring_frames = a->ring_size_byframes;
	period_frames = a->period_size_byframes;
	if (!frame_bytes || !packet_bytes || !ring_frames || !period_frames)
		return;
	if (packet_bytes % frame_bytes)
		return;

	frames = packet_bytes / frame_bytes;
	if (!frames)
		return;

	spin_lock_irqsave(&a->ring_lock, flags);
	ring_pos = a->ring_wpos_byframes;
	ring_bytes = ring_frames * frame_bytes;
	dst = rt->dma_area + ring_pos * frame_bytes;
	first = min(packet_bytes, ring_bytes - ring_pos * frame_bytes);
	memcpy(dst, src, first);
	if (first < packet_bytes)
		memcpy(rt->dma_area, (const char *)src + first, packet_bytes - first);

	ring_pos += frames;
	if (ring_pos >= ring_frames)
		ring_pos %= ring_frames;
	a->ring_wpos_byframes = ring_pos;

	a->period_used_byframes += frames;
	while (a->period_used_byframes >= period_frames) {
		a->period_used_byframes -= period_frames;
		elapsed++;
	}
	spin_unlock_irqrestore(&a->ring_lock, flags);

	while (elapsed--)
		snd_pcm_period_elapsed(ss);
}

void hws_audio_handle_interrupt(struct hws_pcie_dev *hws, unsigned int ch, u8 cur_toggle)
{
	struct hws_audio *a;
	void *cpu;
	size_t size;
	size_t offset;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return;

	a = &hws->audio[ch];
	if (!hws_audio_select_buffer(hws, ch, &cpu, NULL, &size) ||
	    !a->stream_running)
		return;

	a->last_period_toggle = cur_toggle;
	a->irq_count++;
	offset = hws_audio_packet_offset(a, cur_toggle);
	if (offset + a->hw_packet_bytes > size)
		return;

	dma_rmb();
	hws_audio_deliver_packet(a, (char *)cpu + offset);
	a->delivered_count++;
}

static void hws_audio_hw_stop(struct hws_pcie_dev *hws, unsigned int ch)
{
	if (!hws || ch >= hws->cur_max_audio_ch)
		return;

	/* Disable the channel */
	hws_enable_audio_capture(hws, ch, false);

	/* Flush posted write */
	readl(hws->bar0_base + HWS_REG_INT_STATUS);

	/* Ack any latched ADONE so we don't get re-triggers */
	{
		u32 abit = HWS_INT_ADONE_BIT(ch);
		u32 st = readl(hws->bar0_base + HWS_REG_INT_STATUS);

		if (st & abit) {
			writel(abit, hws->bar0_base + HWS_REG_INT_ACK);
			readl(hws->bar0_base + HWS_REG_INT_STATUS);
		}
	}
}

int hws_audio_init_channel(struct hws_pcie_dev *pdev, int ch)
{
	struct hws_audio *aud;

	if (!pdev || ch < 0 || ch >= pdev->max_channels)
		return -EINVAL;

	aud = &pdev->audio[ch];
	memset(aud, 0, sizeof(*aud));     /* ok: no embedded locks yet */

	/* identity */
	aud->parent        = pdev;
	aud->channel_index = ch;
	spin_lock_init(&aud->ring_lock);

	/* defaults */
	aud->output_sample_rate = 48000;
	aud->channel_count      = 2;
	aud->bits_per_sample    = 16;
	aud->hw_packet_bytes    = pdev->audio_pkt_size;

	/* ALSA linkage */
	aud->pcm_substream = NULL;

	/* stream state */
	aud->cap_active     = false;
	aud->stream_running = false;
	aud->stop_requested = false;

	/* HW readback sentinel */
	aud->last_period_toggle = 0xFF;
	aud->irq_count = 0;
	aud->delivered_count = 0;

	return 0;
}

void hws_audio_cleanup_channel(struct hws_pcie_dev *pdev, int ch, bool device_removal)
{
	struct hws_audio *aud;

	if (!pdev || ch < 0 || ch >= pdev->cur_max_audio_ch)
		return;

	aud = &pdev->audio[ch];

	/* 1) Make IRQ path a no-op first */
	aud->stream_running = false;
	aud->cap_active = false;
	aud->stop_requested = true;
	smp_wmb();  /* publish flags before touching HW */

	/* 2) Quiesce hardware (disable ch, flush, ack pending ADONE) */
	hws_audio_hw_stop(pdev, ch);  /* should disable capture and ack pending */

	/* 3) If device is going away and stream was open, tell ALSA */
	if (device_removal && aud->pcm_substream) {
		unsigned long flags;

		snd_pcm_stream_lock_irqsave(aud->pcm_substream, flags);
		if (aud->pcm_substream->runtime)
			snd_pcm_stop(aud->pcm_substream, SNDRV_PCM_STATE_DISCONNECTED);
		snd_pcm_stream_unlock_irqrestore(aud->pcm_substream, flags);
		aud->pcm_substream = NULL;
	}

	/* 4) Clear book-keeping (optional) */
	aud->ring_size_byframes = 0;
	aud->ring_wpos_byframes = 0;
	aud->period_size_byframes = 0;
	aud->period_used_byframes = 0;
	aud->frame_bytes = 0;
	aud->last_period_toggle = 0xFF;
	aud->irq_count = 0;
	aud->delivered_count = 0;
}

static inline bool hws_check_audio_capture(struct hws_pcie_dev *hws, unsigned int ch)
{
	u32 reg = readl(hws->bar0_base + HWS_REG_ACAP_ENABLE);

	return !!(reg & BIT(ch));
}

static inline void hws_audio_ack_pending(struct hws_pcie_dev *hws,
					 unsigned int ch);

int hws_start_audio_capture(struct hws_pcie_dev *hws, unsigned int ch)
{
	int ret;
	u32 gate, bridge;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return -EINVAL;

	/* Already running? Re-assert HW if needed. */
	if (hws->audio[ch].stream_running) {
		if (!hws_check_audio_capture(hws, ch)) {
			ret = hws_check_card_status(hws);
			if (ret)
				return ret;
			ret = hws_audio_seed_capture_buffer(hws, ch);
			if (ret)
				return ret;
			hws_enable_audio_capture(hws, ch, true);
		}
		dev_dbg(&hws->pdev->dev, "audio ch%u already running (re-enabled)\n", ch);
		return 0;
	}

	ret = hws_check_card_status(hws);
	if (ret)
		return ret;

	hws_enable_global_irq(hws);

	gate = readl(hws->bar0_base + INT_EN_REG_BASE);
	bridge = readl(hws->bar0_base + PCIEBR_EN_REG_BASE);
	if (!bridge || !(gate & HWS_INT_ADONE_BIT(ch)))
		hws_restore_irq_fabric(hws);

	ret = hws_audio_seed_capture_buffer(hws, ch);
	if (ret)
		return ret;

	/* Flip state visible to IRQ */
	hws->audio[ch].stop_requested = false;
	hws->audio[ch].stream_running = true;
	hws->audio[ch].cap_active = true;
	hws->audio[ch].irq_count = 0;
	hws->audio[ch].delivered_count = 0;
	hws->audio[ch].last_period_toggle = 0xFF;
	/*
	 * ADONE can fire as soon as capture is enabled. Publish the stream
	 * state before ACAP_ENABLE so the IRQ path accepts the first packet.
	 */
	smp_wmb();

	/* Kick HW */
	hws_enable_audio_capture(hws, ch, true);
	return 0;
}

static inline void hws_audio_ack_pending(struct hws_pcie_dev *hws, unsigned int ch)
{
	u32 abit = HWS_INT_ADONE_BIT(ch);

	u32 st = readl(hws->bar0_base + HWS_REG_INT_STATUS);

	if (st & abit) {
		writel(abit, hws->bar0_base + HWS_REG_INT_ACK);
		/* flush posted write */
		readl(hws->bar0_base + HWS_REG_INT_STATUS);
	}
}

static inline void hws_audio_ack_all(struct hws_pcie_dev *hws)
{
	u32 mask = 0;

	for (unsigned int ch = 0; ch < hws->cur_max_audio_ch; ch++)
		mask |= HWS_INT_ADONE_BIT(ch);
	if (mask) {
		writel(mask, hws->bar0_base + HWS_REG_INT_ACK);
		readl(hws->bar0_base + HWS_REG_INT_STATUS);
	}
}

void hws_stop_audio_capture(struct hws_pcie_dev *hws, unsigned int ch)
{
	if (!hws || ch >= hws->cur_max_audio_ch)
		return;

	if (!hws->audio[ch].stream_running)
		return;

	/* 1) Publish software state so IRQ path becomes a no-op */
	hws->audio[ch].stream_running = false;
	hws->audio[ch].cap_active = false;
	hws->audio[ch].stop_requested = true;
	smp_wmb(); /* make sure flags are visible before HW disable */

	/* 2) Disable channel in HW */
	hws_enable_audio_capture(hws, ch, false);
	/* flush posted write */
	readl(hws->bar0_base + HWS_REG_INT_STATUS);

	/* 3) Wait for non-IRQ-triggered stops to stop racing the handler. */
	if (hws->irq >= 0 && !in_interrupt())
		synchronize_irq(hws->irq);

	/* 4) Ack any latched ADONE to prevent retrigger storms */
	hws_audio_ack_pending(hws, ch);
	spin_lock(&hws->audio[ch].ring_lock);
	hws->audio[ch].ring_wpos_byframes = 0;
	hws->audio[ch].period_used_byframes = 0;
	spin_unlock(&hws->audio[ch].ring_lock);

	dev_dbg(&hws->pdev->dev, "audio capture stopped on ch %u\n", ch);
}

void hws_enable_audio_capture(struct hws_pcie_dev *hws,
			      unsigned int ch, bool enable)
{
	u32 reg, mask = BIT(ch);

	if (!hws || ch >= hws->cur_max_audio_ch || hws->pci_lost)
		return;

	reg = readl(hws->bar0_base + HWS_REG_ACAP_ENABLE);
	if (enable)
		reg |= mask;
	else
		reg &= ~mask;

	writel(reg, hws->bar0_base + HWS_REG_ACAP_ENABLE);

	dev_dbg(&hws->pdev->dev, "audio capture %s ch%u, reg=0x%08x\n",
		enable ? "enabled" : "disabled", ch, reg);
}

static snd_pcm_uframes_t hws_pcie_audio_pointer(struct snd_pcm_substream *substream)
{
	struct hws_audio *a = snd_pcm_substream_chip(substream);

	return a->ring_wpos_byframes;
}

int hws_pcie_audio_open(struct snd_pcm_substream *substream)
{
	struct hws_audio *a = snd_pcm_substream_chip(substream);
	struct snd_pcm_runtime *rt = substream->runtime;

	rt->hw = audio_pcm_hardware;
	a->pcm_substream = substream;

	snd_pcm_hw_constraint_integer(rt, SNDRV_PCM_HW_PARAM_PERIODS);
	snd_pcm_hw_constraint_step(rt, 0, SNDRV_PCM_HW_PARAM_PERIOD_BYTES, 32);
	snd_pcm_hw_constraint_step(rt, 0, SNDRV_PCM_HW_PARAM_BUFFER_BYTES, 32);
	return 0;
}

int hws_pcie_audio_close(struct snd_pcm_substream *substream)
{
	struct hws_audio *a = snd_pcm_substream_chip(substream);

	a->pcm_substream = NULL;
	return 0;
}

int hws_pcie_audio_hw_params(struct snd_pcm_substream *substream,
			     struct snd_pcm_hw_params *hw_params)
{
	return snd_pcm_lib_malloc_pages(substream, params_buffer_bytes(hw_params));
}

int hws_pcie_audio_hw_free(struct snd_pcm_substream *substream)
{
	return snd_pcm_lib_free_pages(substream);
}

int hws_pcie_audio_prepare(struct snd_pcm_substream *substream)
{
	struct hws_audio *a = snd_pcm_substream_chip(substream);
	struct snd_pcm_runtime *rt = substream->runtime;
	unsigned long flags;
	size_t frame_bytes;

	frame_bytes = snd_pcm_format_physical_width(rt->format) / 8;
	frame_bytes *= rt->channels;
	if (!frame_bytes || a->hw_packet_bytes % frame_bytes)
		return -EINVAL;

	spin_lock_irqsave(&a->ring_lock, flags);
	a->ring_size_byframes = rt->buffer_size;
	a->ring_wpos_byframes = 0;
	a->period_size_byframes = rt->period_size;
	a->period_used_byframes = 0;
	a->frame_bytes = frame_bytes;
	spin_unlock_irqrestore(&a->ring_lock, flags);

	/* Optional: clear HW toggle readback */
	a->last_period_toggle = 0xFF;
	a->irq_count = 0;
	a->delivered_count = 0;
	return 0;
}

int hws_pcie_audio_trigger(struct snd_pcm_substream *substream, int cmd)
{
	struct hws_audio *a = snd_pcm_substream_chip(substream);
	struct hws_pcie_dev *hws = a->parent;
	unsigned int ch = a->channel_index;

	dev_dbg(&hws->pdev->dev, "audio trigger %d on ch %u\n", cmd, ch);

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
		return hws_start_audio_capture(hws, ch);
	case SNDRV_PCM_TRIGGER_STOP:
		hws_stop_audio_capture(hws, ch);
		return 0;
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
		return hws_start_audio_capture(hws, ch);
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
		hws_stop_audio_capture(hws, ch);
		return 0;
	default:
		return -EINVAL;
	}
}

static const struct snd_pcm_ops hws_pcie_pcm_ops = {
	.open      = hws_pcie_audio_open,
	.close     = hws_pcie_audio_close,
	.ioctl     = snd_pcm_lib_ioctl,
	.hw_params = hws_pcie_audio_hw_params,
	.hw_free   = hws_pcie_audio_hw_free,
	.prepare   = hws_pcie_audio_prepare,
	.trigger   = hws_pcie_audio_trigger,
	.pointer   = hws_pcie_audio_pointer,
};

int hws_audio_register(struct hws_pcie_dev *hws)
{
	struct snd_card *card = NULL;
	struct snd_pcm  *pcm  = NULL;
	char card_id[16];
	char card_name[64];
	int i, ret;

	if (!hws)
		return -EINVAL;
	if (!hws->cur_max_audio_ch)
		return 0;

	/* ---- Create a single ALSA card for this PCI function ---- */
	snprintf(card_id, sizeof(card_id), "hws%u", hws->port_id);     /* <=16 chars */
	snprintf(card_name, sizeof(card_name), "HWS HDMI Audio %u", hws->port_id);

	ret = snd_card_new(&hws->pdev->dev, -1 /* auto index */,
			   card_id, THIS_MODULE, 0, &card);
	if (ret < 0) {
		dev_err(&hws->pdev->dev, "snd_card_new failed: %d\n", ret);
		return ret;
	}

	snd_card_set_dev(card, &hws->pdev->dev);
	strscpy(card->driver,   KBUILD_MODNAME, sizeof(card->driver));
	strscpy(card->shortname, card_name,      sizeof(card->shortname));
	strscpy(card->longname,  card->shortname, sizeof(card->longname));

	/* ---- Create one PCM capture device per HDMI input ---- */
	for (i = 0; i < hws->cur_max_audio_ch; i++) {
		char pcm_name[32];

		snprintf(pcm_name, sizeof(pcm_name), "HDMI In %d", i);

		/* device number = i, so userspace sees hw:X,i */
		ret = snd_pcm_new(card, pcm_name, i,
				  0 /* playback */, 1 /* capture */, &pcm);
		if (ret < 0) {
			dev_err(&hws->pdev->dev, "snd_pcm_new(%d) failed: %d\n", i, ret);
			goto error_card;
		}

		/* Tie this PCM to channel i */
		hws->audio[i].parent        = hws;
		hws->audio[i].channel_index = i;
		hws->audio[i].pcm_substream = NULL;
		hws->audio[i].cap_active    = false;
		hws->audio[i].stream_running = false;
		hws->audio[i].stop_requested = false;
		hws->audio[i].last_period_toggle = 0xFF;
		hws->audio[i].output_sample_rate = 48000;
		hws->audio[i].channel_count      = 2;
		hws->audio[i].bits_per_sample    = 16;

		pcm->private_data = &hws->audio[i];
		strscpy(pcm->name, pcm_name, sizeof(pcm->name));
		snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_CAPTURE, &hws_pcie_pcm_ops);

		/*
		 * snd_pcm_lib_malloc_pages() requires a valid DMA buffer type.
		 * Keep allocation dynamic at HW_PARAMS time, but advertise the
		 * maximum buffer size up front for modern ALSA.
		 */
		ret = snd_pcm_set_managed_buffer_all(pcm,
						     SNDRV_DMA_TYPE_DEV,
						     &hws->pdev->dev,
						     0,
						     audio_pcm_hardware.buffer_bytes_max);
		if (ret < 0) {
			dev_err(&hws->pdev->dev,
				"snd_pcm_set_managed_buffer_all(%d) failed: %d\n",
				i, ret);
			goto error_card;
		}
	}

	/* Register the card once all PCMs are created */
	ret = snd_card_register(card);
	if (ret < 0) {
		dev_err(&hws->pdev->dev, "snd_card_register failed: %d\n", ret);
		goto error_card;
	}

	/* Store the single card handle (optional: also mirror to each channel if you like) */
	hws->snd_card = card;
	dev_info(&hws->pdev->dev, "audio registration complete (%d HDMI inputs)\n",
		 hws->cur_max_audio_ch);
	return 0;

error_card:
	/* Frees all PCMs created on it as well */
	snd_card_free(card);
	return ret;
}

void hws_audio_unregister(struct hws_pcie_dev *hws)
{
	if (!hws)
		return;

	/* Prevent new opens and mark existing streams disconnected */
	if (hws->snd_card)
		snd_card_disconnect(hws->snd_card);

	for (unsigned int i = 0; i < hws->cur_max_audio_ch; i++) {
		struct hws_audio *a = &hws->audio[i];

		/* Flip flags first so IRQ path won't call ALSA anymore */
		a->stream_running = false;
		a->cap_active = false;
		a->stop_requested = true;
		/* Publish stop flags before disabling capture in HW.
		 * Ensures that any CPU/core handling an ADONE IRQ or bottom half
		 * observes stream_running/cap_active=false before it sees the
		 * effect of the MMIO write below. Pairs with flag checks
		 * in the IRQ/BH paths so ALSA callbacks are never invoked after
		 * the stream has been marked stopped.
		 */
		smp_wmb();
		hws_enable_audio_capture(hws, i, false);
	}
	/* Flush and ack any pending audio interrupts across all channels */
	readl(hws->bar0_base + HWS_REG_INT_STATUS);
	hws_audio_ack_all(hws);
	if (hws->snd_card) {
		snd_card_free_when_closed(hws->snd_card);
		hws->snd_card = NULL;
	}

	dev_info(&hws->pdev->dev, "audio unregistered (%u channels)\n",
		 hws->cur_max_audio_ch);
}

int hws_audio_pm_suspend_all(struct hws_pcie_dev *hws)
{
	struct snd_pcm *seen[ARRAY_SIZE(hws->audio)];
	int seen_cnt = 0;
	int i, j, ret = 0;

	if (!hws || !hws->snd_card)
		return 0;

	/* Iterate audio channels and suspend each unique PCM device */
	for (i = 0; i < hws->cur_max_audio_ch && i < ARRAY_SIZE(hws->audio); i++) {
		struct hws_audio *a = &hws->audio[i];
		struct snd_pcm_substream *ss = a->pcm_substream;
		struct snd_pcm *pcm;
		bool already = false;

		if (!ss)
			continue;

		pcm = ss->pcm;
		if (!pcm)
			continue;

		/* De-duplicate in case multiple channels share a PCM */
		for (j = 0; j < seen_cnt; j++) {
			if (seen[j] == pcm) {
				already = true;
				break;
			}
		}
		if (already)
			continue;

		if (seen_cnt < ARRAY_SIZE(seen))
			seen[seen_cnt++] = pcm;

		if (!ret) {
			int r = snd_pcm_suspend_all(pcm);

			if (r)
				ret = r;  /* remember first error, keep going */
		}

		if (seen_cnt == ARRAY_SIZE(seen))
			break; /* defensive: shouldn't happen with sane config */
	}

	return ret;
}

void hws_audio_pm_resume(struct hws_pcie_dev *hws)
{
	unsigned int ch;

	if (!hws || !hws->bar0_base)
		return;

	for (ch = 0; ch < hws->cur_max_audio_ch && ch < MAX_VID_CHANNELS; ch++) {
		struct hws_audio *a = &hws->audio[ch];

		a->stream_running = false;
		a->cap_active = false;
		a->stop_requested = true;
		a->last_period_toggle = 0xFF;
		a->irq_count = 0;
		a->delivered_count = 0;
	}
	hws_audio_seed_channels(hws);
	hws_audio_ack_all(hws);
}
