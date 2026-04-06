// SPDX-License-Identifier: GPL-2.0-only
#include "hws_audio.h"

#include "hws.h"
#include "hws_reg.h"

#include <linux/crc32.h>
#include <linux/moduleparam.h>
#include <sound/core.h>
#include <sound/pcm_params.h>
#include <sound/control.h>
#include <sound/pcm.h>
#include <sound/rawmidi.h>
#include <sound/initval.h>
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
	.periods_max = 64,
};

static bool hws_audio_trace;
module_param_named(audio_trace, hws_audio_trace, bool, 0644);
MODULE_PARM_DESC(audio_trace,
		 "Log audio DMA/remap state and the first few audio interrupts");

bool hws_audio_trace_enabled(void)
{
	return hws_audio_trace;
}

static u32 hws_audio_shared_slot_off(unsigned int ch)
{
	return 0x208 + ch * 8;
}

static bool hws_audio_select_buffer(struct hws_pcie_dev *hws, unsigned int ch,
				    void **cpu_base, dma_addr_t *dma_base,
				    size_t *size, bool *using_shared_tail)
{
	struct hws_scratch_dma *scratch;

	if (!hws || ch >= hws->cur_max_linein_ch)
		return false;

	if (using_shared_tail)
		*using_shared_tail = false;

	if (ch < hws->cur_max_video_ch &&
	    hws->scratch_vid[ch].cpu &&
	    hws->scratch_vid[ch].size >= MAX_AUDIO_CAP_SIZE &&
	    !READ_ONCE(hws->video[ch].cap_active)) {
		if (cpu_base)
			*cpu_base = (char *)hws->scratch_vid[ch].cpu +
				    hws->scratch_vid[ch].size - MAX_AUDIO_CAP_SIZE;
		if (dma_base)
			*dma_base = hws->scratch_vid[ch].dma +
				    hws->scratch_vid[ch].size - MAX_AUDIO_CAP_SIZE;
		if (size)
			*size = MAX_AUDIO_CAP_SIZE;
		if (using_shared_tail)
			*using_shared_tail = true;
		return true;
	}

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

static void hws_audio_trace_probe_work(struct work_struct *work)
{
	struct hws_audio *a =
		container_of(to_delayed_work(work), struct hws_audio, trace_probe_work);
	struct hws_pcie_dev *hws = a->parent;
	void *cpu;
	size_t probe_len;
	u32 crc_now;
	unsigned int ch;

	if (!hws_audio_trace || !hws)
		return;

	ch = a->channel_index;
	if (ch >= hws->cur_max_linein_ch || !READ_ONCE(a->stream_running))
		return;

	if (!hws_audio_select_buffer(hws, ch, &cpu, NULL, &probe_len, NULL))
		return;

	probe_len = min_t(size_t, probe_len, 4096);
	crc_now = crc32_le(0, cpu, probe_len);
	dev_info(&hws->pdev->dev,
		 "audio-trace:probe ch%u crc=%08x->%08x len=%zu irq=%u delivered=%u int=%08x toggle=%u\n",
		 ch, a->trace_probe_crc, crc_now, probe_len,
		 READ_ONCE(a->irq_count), READ_ONCE(a->delivered_count),
		 readl_relaxed(hws->bar0_base + HWS_REG_INT_STATUS),
		 readl_relaxed(hws->bar0_base + HWS_REG_ABUF_TOGGLE(ch)) & 0x01);
}

static void hws_audio_trace_state(struct hws_pcie_dev *hws, unsigned int ch,
				  const char *tag)
{
	u32 shared_off, audio_off;
	u32 shared_hi, shared_lo, audio_hi, audio_lo;
	u32 aud_base, acap, int_status, sys_status, active_status, abuf_toggle;
	u32 int_en_gate, bridge_en, int_decode;
	struct hws_audio *a;
	dma_addr_t dma;
	size_t size;
	bool using_shared_tail;

	if (!hws_audio_trace || !hws || ch >= hws->cur_max_linein_ch)
		return;

	a = &hws->audio[ch];
	if (!hws_audio_select_buffer(hws, ch, NULL, &dma, &size, &using_shared_tail))
		return;
	shared_off = hws_audio_shared_slot_off(ch);
	audio_off = HWS_AUDIO_REMAP_SLOT_OFF(ch);

	shared_hi = readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE + shared_off);
	shared_lo = readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE + shared_off +
				  PCIE_BARADDROFSIZE);
	audio_hi = readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE + audio_off);
	audio_lo = readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE + audio_off +
				 PCIE_BARADDROFSIZE);
	aud_base = readl_relaxed(hws->bar0_base + HWS_REG_AUD_DMA_ADDR(ch));
	acap = readl_relaxed(hws->bar0_base + HWS_REG_ACAP_ENABLE);
	int_status = readl_relaxed(hws->bar0_base + HWS_REG_INT_STATUS);
	sys_status = readl_relaxed(hws->bar0_base + HWS_REG_SYS_STATUS);
	active_status = readl_relaxed(hws->bar0_base + HWS_REG_ACTIVE_STATUS);
	abuf_toggle = readl_relaxed(hws->bar0_base + HWS_REG_ABUF_TOGGLE(ch)) & 0x01;
	int_en_gate = readl_relaxed(hws->bar0_base + INT_EN_REG_BASE);
	bridge_en = readl_relaxed(hws->bar0_base + PCIEBR_EN_REG_BASE);
	int_decode = readl_relaxed(hws->bar0_base + PCIE_INT_DEC_REG_BASE);

	dev_info(&hws->pdev->dev,
		 "audio-trace:%s ch%u dma=%pad size=%zu src=%s shared=[%08x/%08x] audio=[%08x/%08x] base=%08x acap=%08x int=%08x gate=%08x br=%08x dec=%08x sys=%08x input=%08x toggle=%u active=%d running=%d irq=%u delivered=%u\n",
		 tag, ch, &dma, size, using_shared_tail ? "vidtail" : "audscratch",
		 shared_hi, shared_lo,
		 audio_hi, audio_lo, aud_base, acap, int_status, int_en_gate,
		 bridge_en, int_decode, sys_status, active_status,
		 abuf_toggle, READ_ONCE(a->cap_active), READ_ONCE(a->stream_running),
		 READ_ONCE(a->irq_count), READ_ONCE(a->delivered_count));
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
	size_t size;
	dma_addr_t dma;
	u32 lo, hi, pci_addr;
	u32 audio_table_off;
	bool using_shared_tail;

	if (!hws || ch >= hws->cur_max_linein_ch)
		return -EINVAL;

	if (!hws_audio_select_buffer(hws, ch, NULL, &dma, &size, &using_shared_tail))
		return -ENOMEM;

	lo = lower_32_bits(dma);
	hi = upper_32_bits(dma);
	pci_addr = lo & PCI_E_BAR_ADD_LOWMASK;
	lo &= PCI_E_BAR_ADD_MASK;
	audio_table_off = HWS_AUDIO_REMAP_SLOT_OFF(ch);
	hws_audio_program_remap_slot(hws, audio_table_off, hi, lo);
	if (using_shared_tail) {
		hws_audio_program_remap_slot(hws, 0x208 + ch * 8, hi, lo);
		/*
		 * The shared slot cache now no longer matches hardware. Force the
		 * next video stream-on for this channel to reprogram its window.
		 */
		WRITE_ONCE(hws->video[ch].window_valid, false);
	}
	writel_relaxed((ch + 1u) * PCIEBAR_AXI_BASE + pci_addr,
		       hws->bar0_base + HWS_REG_AUD_DMA_ADDR(ch));
	(void)readl(hws->bar0_base + HWS_REG_AUD_DMA_ADDR(ch));
	hws_audio_trace_state(hws, ch, "seed");
	return 0;
}

void hws_audio_seed_channels(struct hws_pcie_dev *hws)
{
	unsigned int ch;

	if (!hws || !hws->bar0_base)
		return;

	for (ch = 0; ch < hws->cur_max_linein_ch; ch++) {
		int ret = hws_audio_seed_capture_buffer(hws, ch);

		if (ret && hws_audio_trace)
			dev_warn(&hws->pdev->dev,
				 "audio-trace:seed ch%u failed ret=%d\n", ch, ret);
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

	ss = READ_ONCE(a->pcm_substream);
	if (!ss)
		return;

	rt = READ_ONCE(ss->runtime);
	if (!rt || !rt->dma_area)
		return;

	frame_bytes = READ_ONCE(a->frame_bytes);
	packet_bytes = READ_ONCE(a->hw_packet_bytes);
	ring_frames = READ_ONCE(a->ring_size_byframes);
	period_frames = READ_ONCE(a->period_size_byframes);
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
	u32 irq_count;

	if (!hws || ch >= hws->cur_max_linein_ch)
		return;

	a = &hws->audio[ch];
	if (!hws_audio_select_buffer(hws, ch, &cpu, NULL, &size, NULL) ||
	    !READ_ONCE(a->stream_running))
		return;

	WRITE_ONCE(a->last_period_toggle, cur_toggle);
	irq_count = ++a->irq_count;
	if (hws_audio_trace && irq_count == 1)
		hws_trace_bar0_snapshot(hws, "audio.first_irq");
	offset = hws_audio_packet_offset(a, cur_toggle);
	if (offset + a->hw_packet_bytes > size)
		return;

	if (hws_audio_trace && irq_count <= 8) {
			dev_info(&hws->pdev->dev,
				 "audio-trace:irq ch%u irq=%u toggle=%u offset=%zu pkt=%zu scratch=%zu\n",
				 ch, irq_count, cur_toggle, offset, a->hw_packet_bytes,
				 size);
			hws_audio_trace_state(hws, ch, "irq");
		}

	dma_rmb();
	hws_audio_deliver_packet(a, (char *)cpu + offset);
	if (hws_audio_trace && ++a->delivered_count <= 8)
		dev_info(&hws->pdev->dev,
			 "audio-trace:deliver ch%u delivered=%u ring=%lu/%lu period=%lu used=%lu\n",
			 ch, a->delivered_count,
			 (unsigned long)a->ring_wpos_byframes,
			 (unsigned long)a->ring_size_byframes,
			 (unsigned long)a->period_size_byframes,
			 (unsigned long)a->period_used_byframes);
}

static void hws_audio_hw_stop(struct hws_pcie_dev *hws, unsigned int ch)
{
	if (!hws || ch >= hws->cur_max_linein_ch)
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
	INIT_DELAYED_WORK(&aud->trace_probe_work, hws_audio_trace_probe_work);

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

	if (!pdev || ch < 0 || ch >= pdev->cur_max_linein_ch)
		return;

	aud = &pdev->audio[ch];

	/* 1) Make IRQ path a no-op first */
	cancel_delayed_work_sync(&aud->trace_probe_work);
	WRITE_ONCE(aud->stream_running, false);
	WRITE_ONCE(aud->cap_active,     false);
	WRITE_ONCE(aud->stop_requested, true);
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

int hws_start_audio_capture(struct hws_pcie_dev *hws, unsigned int ch)
{
	int ret;
	u32 gate, bridge;

	if (!hws || ch >= hws->cur_max_linein_ch)
		return -EINVAL;

	/* Already running? Re-assert HW if needed. */
	if (READ_ONCE(hws->audio[ch].stream_running)) {
		if (!hws_check_audio_capture(hws, ch)) {
			ret = hws_check_card_status(hws);
			if (ret)
				return ret;
			ret = hws_audio_seed_capture_buffer(hws, ch);
			if (ret)
				return ret;
			hws_enable_audio_capture(hws, ch, true);
			hws_audio_trace_state(hws, ch, "restart");
		}
		dev_dbg(&hws->pdev->dev, "audio ch%u already running (re-enabled)\n", ch);
		return 0;
	}

	ret = hws_check_card_status(hws);
	if (ret)
		return ret;

	hws_trace_bar0_snapshot(hws, "audio.prestart");

	gate = readl(hws->bar0_base + INT_EN_REG_BASE);
	bridge = readl(hws->bar0_base + PCIEBR_EN_REG_BASE);
	if (!bridge || !(gate & HWS_INT_ADONE_BIT(ch))) {
		u32 gate_after, bridge_after, dec_after;

		hws_restore_irq_fabric(hws);
		gate_after = readl(hws->bar0_base + INT_EN_REG_BASE);
		bridge_after = readl(hws->bar0_base + PCIEBR_EN_REG_BASE);
		dec_after = readl(hws->bar0_base + PCIE_INT_DEC_REG_BASE);
		if (hws_audio_trace)
			dev_info(&hws->pdev->dev,
				 "audio-trace:restore ch%u gate=%08x->%08x br=%08x->%08x dec=%08x\n",
				 ch, gate, gate_after, bridge, bridge_after, dec_after);
	}

	ret = hws_audio_seed_capture_buffer(hws, ch);
	if (ret)
		return ret;
	hws_trace_bar0_snapshot(hws, "audio.seed");

	/* Flip state visible to IRQ */
	cancel_delayed_work_sync(&hws->audio[ch].trace_probe_work);
	WRITE_ONCE(hws->audio[ch].stop_requested, false);
	WRITE_ONCE(hws->audio[ch].stream_running, true);
	WRITE_ONCE(hws->audio[ch].cap_active, true);
	WRITE_ONCE(hws->audio[ch].irq_count, 0);
	WRITE_ONCE(hws->audio[ch].delivered_count, 0);
	if (hws_audio_trace) {
		void *cpu;
		size_t probe_len;

		if (hws_audio_select_buffer(hws, ch, &cpu, NULL, &probe_len, NULL)) {
			probe_len = min_t(size_t, probe_len, 4096);
			hws->audio[ch].trace_probe_crc = crc32_le(0, cpu, probe_len);
			schedule_delayed_work(&hws->audio[ch].trace_probe_work,
					      msecs_to_jiffies(200));
		}
	}

	/* Kick HW */
	hws_enable_audio_capture(hws, ch, true);
	hws_audio_trace_state(hws, ch, "start");
	hws_trace_bar0_snapshot(hws, "audio.start");
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

	for (unsigned int ch = 0; ch < hws->cur_max_linein_ch; ch++)
		mask |= HWS_INT_ADONE_BIT(ch);
	if (mask) {
		writel(mask, hws->bar0_base + HWS_REG_INT_ACK);
		readl(hws->bar0_base + HWS_REG_INT_STATUS);
	}
}

void hws_stop_audio_capture(struct hws_pcie_dev *hws, unsigned int ch)
{
	if (!hws || ch >= hws->cur_max_linein_ch)
		return;

	if (!READ_ONCE(hws->audio[ch].stream_running))
		return;

	/* 1) Publish software state so IRQ path becomes a no-op */
	cancel_delayed_work_sync(&hws->audio[ch].trace_probe_work);
	WRITE_ONCE(hws->audio[ch].stream_running, false);
	WRITE_ONCE(hws->audio[ch].cap_active,     false);
	WRITE_ONCE(hws->audio[ch].stop_requested, true);
	smp_wmb(); /* make sure flags are visible before HW disable */

	/* 2) Disable channel in HW */
	hws_enable_audio_capture(hws, ch, false);
	/* flush posted write */
	readl(hws->bar0_base + HWS_REG_INT_STATUS);

	/* 3) Ack any latched ADONE to prevent retrigger storms */
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

	if (!hws || ch >= hws->cur_max_linein_ch || hws->pci_lost)
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

	return READ_ONCE(a->ring_wpos_byframes);
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
	/* Using preallocation done at registration time; nothing to do. */
	return 0;
}

int hws_pcie_audio_hw_free(struct snd_pcm_substream *substream)
{
	return 0;
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
	if (!hws->cur_max_linein_ch)
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
	for (i = 0; i < hws->cur_max_linein_ch; i++) {
		char pcm_name[32];

		snprintf(pcm_name, sizeof(pcm_name), "HDMI In %d", i);

		/* device number = i → userspace sees hw:X,i */
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

		/* ALSA-managed ring buffer for software packet delivery. */
		ret = snd_pcm_set_managed_buffer_all(pcm,
						     SNDRV_DMA_TYPE_DEV,
						     &hws->pdev->dev,
						     audio_pcm_hardware.buffer_bytes_max,
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
		 hws->cur_max_linein_ch);
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

	for (unsigned int i = 0; i < hws->cur_max_linein_ch; i++) {
		struct hws_audio *a = &hws->audio[i];

		/* Flip flags first so IRQ path won’t call ALSA anymore */
		WRITE_ONCE(a->stream_running, false);
		WRITE_ONCE(a->cap_active,     false);
		WRITE_ONCE(a->stop_requested, true);
		/* Publish stop flags before disabling capture in HW.
		 * Ensures that any CPU/core handling an ADONE IRQ or bottom half
		 * observes stream_running/cap_active=false before it sees the
		 * effect of the MMIO write below. Pairs with READ_ONCE() checks
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
		 hws->cur_max_linein_ch);
}

int hws_audio_pm_suspend_all(struct hws_pcie_dev *hws)
{
	struct snd_pcm *seen[ARRAY_SIZE(hws->audio)];
	int seen_cnt = 0;
	int i, j, ret = 0;

	if (!hws || !hws->snd_card)
		return 0;

	/* Iterate audio channels and suspend each unique PCM device */
	for (i = 0; i < hws->cur_max_linein_ch && i < ARRAY_SIZE(hws->audio); i++) {
		struct hws_audio *a = &hws->audio[i];
		struct snd_pcm_substream *ss = READ_ONCE(a->pcm_substream);
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
