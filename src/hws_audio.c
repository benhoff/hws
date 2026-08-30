// SPDX-License-Identifier: GPL-2.0-only
#include <linux/interrupt.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <sound/core.h>
#include <sound/pcm.h>

#include "hws.h"
#include "hws_audio.h"
#include "hws_reg.h"
#include "hws_video.h"

static inline void hws_audio_ack_pending(struct hws_pcie_dev *hws,
					 unsigned int ch);
static void hws_audio_disable_capture_and_ack(struct hws_pcie_dev *hws,
					      unsigned int ch);
static void hws_audio_clear_pending(struct hws_audio *a);
static void hws_audio_deliver_work(struct work_struct *work);
static void hws_audio_drain_channel_work(struct hws_audio *a);
static void
hws_audio_count_failure_locked(struct hws_audio *a,
			       enum hws_audio_xrun_reason reason);
static void hws_audio_discard_stale_done(struct hws_pcie_dev *hws,
					 struct hws_audio *a,
					 unsigned int ch);

static void hws_audio_reset_ring_state(struct hws_audio *a)
{
	unsigned long flags;

	if (!a)
		return;

	spin_lock_irqsave(&a->ring_lock, flags);
	a->ring_size_byframes = 0;
	a->ring_wpos_byframes = 0;
	a->period_size_byframes = 0;
	a->period_used_byframes = 0;
	a->frame_bytes = 0;
	spin_unlock_irqrestore(&a->ring_lock, flags);
}

static void hws_audio_reset_counters(struct hws_audio *a)
{
	if (!a)
		return;

	WRITE_ONCE(a->irq_count, 0);
	WRITE_ONCE(a->delivered_count, 0);
	WRITE_ONCE(a->primed_packets, 0);
	WRITE_ONCE(a->dropped_packets, 0);
	WRITE_ONCE(a->cadence_errors, 0);
	WRITE_ONCE(a->w1c_ambiguities, 0);
	WRITE_ONCE(a->toggle_errors, 0);
	WRITE_ONCE(a->generation_errors, 0);
	WRITE_ONCE(a->deadline_misses, 0);
	WRITE_ONCE(a->guard_errors, 0);
	WRITE_ONCE(a->observed_dma_extent,
		   2 * (size_t)MAX_DMA_AUDIO_PK_SIZE);
	WRITE_ONCE(a->last_work_latency_ns, 0);
	WRITE_ONCE(a->max_work_latency_ns, 0);
	WRITE_ONCE(a->xrun_reason, HWS_AUDIO_XRUN_NONE);
}

static void hws_audio_reset_runtime_state(struct hws_audio *a)
{
	if (!a)
		return;

	hws_audio_clear_pending(a);
	hws_audio_reset_ring_state(a);
	hws_audio_reset_counters(a);
}

static bool hws_audio_publish_stopped(struct hws_audio *a)
{
	unsigned long flags;
	bool was_running;

	if (!a)
		return false;

	spin_lock_irqsave(&a->ring_lock, flags);
	was_running = READ_ONCE(a->stream_running) ||
		      READ_ONCE(a->cap_active);
	WRITE_ONCE(a->stream_running, false);
	WRITE_ONCE(a->cap_active, false);
	WRITE_ONCE(a->stop_requested, true);
	spin_unlock_irqrestore(&a->ring_lock, flags);
	/*
	 * IRQ handlers test these flags before touching scratch buffers or
	 * ALSA pointers. Publish the no-stream state before ACAP is disabled
	 * and before any teardown clears pcm_substream.
	 */
	smp_wmb();
	return was_running;
}

static void hws_audio_quiesce_capture(struct hws_pcie_dev *hws,
				      unsigned int ch, bool sync_irq)
{
	struct hws_audio *a;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return;

	a = &hws->audio[ch];
	hws_audio_publish_stopped(a);

	hws_audio_disable_capture_and_ack(hws, ch);

	if (sync_irq && hws->irq >= 0 && !in_interrupt())
		synchronize_irq(hws->irq);

	if (!in_interrupt())
		hws_audio_drain_channel_work(a);

	hws_audio_reset_runtime_state(a);
}

#define HWS_AUDIO_PACKET_BYTES      MAX_DMA_AUDIO_PK_SIZE
#define HWS_AUDIO_PERIODS_MIN       4U
#define HWS_AUDIO_PERIODS_MAX       16U
#define HWS_AUDIO_PERIOD_BYTES_MAX  (HWS_AUDIO_PACKET_BYTES * 4U)
#define HWS_AUDIO_BUFFER_BYTES_MAX  (HWS_AUDIO_PACKET_BYTES * HWS_AUDIO_PERIODS_MAX)
#define HWS_AUDIO_CADENCE_EARLY_NUM 2U
#define HWS_AUDIO_CADENCE_EARLY_DEN 3U
#define HWS_AUDIO_CADENCE_LATE_NUM  3U
#define HWS_AUDIO_CADENCE_LATE_DEN  2U

/*
 * Audio DMA completes in fixed-size packets. The driver copies whole packets
 * into ALSA's ring and advances the pointer after each copy, so expose batch
 * timing together with packet-sized period and buffer granularity.
 */
static const struct snd_pcm_hardware audio_pcm_hardware = {
	.info = (SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_INTERLEAVED |
		 SNDRV_PCM_INFO_BLOCK_TRANSFER | SNDRV_PCM_INFO_RESUME |
		 SNDRV_PCM_INFO_MMAP_VALID | SNDRV_PCM_INFO_BATCH),
	.formats = SNDRV_PCM_FMTBIT_S16_LE,
	.rates = SNDRV_PCM_RATE_48000,
	.rate_min = 48000,
	.rate_max = 48000,
	.channels_min = 2,
	.channels_max = 2,
	.buffer_bytes_max = HWS_AUDIO_BUFFER_BYTES_MAX,
	.period_bytes_min = HWS_AUDIO_PACKET_BYTES,
	.period_bytes_max = HWS_AUDIO_PERIOD_BYTES_MAX,
	.periods_min = HWS_AUDIO_PERIODS_MIN,
	.periods_max = HWS_AUDIO_PERIODS_MAX,
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

static int hws_guard_audio_video_remap_page_locked(struct hws_pcie_dev *hws,
						   unsigned int ch)
{
	struct hws_video *vid;
	dma_addr_t audio_dma;
	u32 audio_hi, audio_page;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return -EINVAL;
	if (ch >= hws->cur_max_video_ch)
		return 0;

	vid = &hws->video[ch];
	lockdep_assert_held(&vid->irq_lock);

	if (!READ_ONCE(vid->cap_active) || !vid->window_valid)
		return 0;

	if (!hws_audio_select_buffer(hws, ch, NULL, &audio_dma, NULL))
		return -ENOMEM;

	audio_hi = upper_32_bits(audio_dma);
	audio_page = lower_32_bits(audio_dma) & PCI_E_BAR_ADD_MASK;
	if (audio_hi == vid->last_dma_hi && audio_page == vid->last_dma_page)
		return 0;

	dev_warn_ratelimited(&hws->pdev->dev,
			     "audio ch%u DMA page differs from active video remap slot; refusing shared-window conflict (audio=%pad video_hi=0x%08x video_page=0x%08x)\n",
			     ch, &audio_dma, vid->last_dma_hi,
			     vid->last_dma_page);
	return -EBUSY;
}

static void hws_audio_program_remap_slot(struct hws_pcie_dev *hws,
					 u32 table_off, u32 hi, u32 page_lo)
{
	writel_relaxed(hi, hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off);
	writel_relaxed(page_lo, hws->bar0_base + PCI_ADDR_TABLE_BASE + table_off +
		       PCIE_BARADDROFSIZE);
}

static int hws_audio_seed_capture_buffer_locked(struct hws_pcie_dev *hws,
						unsigned int ch)
{
	struct hws_video *vid;
	dma_addr_t dma;
	u32 lo, hi, pci_addr;
	u32 audio_table_off;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return -EINVAL;

	vid = &hws->video[ch];
	lockdep_assert_held(&vid->irq_lock);

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

static int hws_guard_audio_video_remap_page(struct hws_pcie_dev *hws,
					    unsigned int ch)
{
	struct hws_video *vid;
	unsigned long flags;
	int ret;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return -EINVAL;

	vid = &hws->video[ch];
	spin_lock_irqsave(&vid->irq_lock, flags);
	ret = hws_guard_audio_video_remap_page_locked(hws, ch);
	spin_unlock_irqrestore(&vid->irq_lock, flags);
	return ret;
}

static int hws_audio_seed_capture_buffer(struct hws_pcie_dev *hws,
					 unsigned int ch)
{
	struct hws_video *vid;
	unsigned long flags;
	int ret;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return -EINVAL;

	vid = &hws->video[ch];
	spin_lock_irqsave(&vid->irq_lock, flags);
	ret = hws_audio_seed_capture_buffer_locked(hws, ch);
	spin_unlock_irqrestore(&vid->irq_lock, flags);
	return ret;
}

static int hws_audio_guard_and_seed_capture_buffer(struct hws_pcie_dev *hws,
						   unsigned int ch)
{
	struct hws_video *vid;
	unsigned long flags;
	int ret;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return -EINVAL;

	vid = &hws->video[ch];
	spin_lock_irqsave(&vid->irq_lock, flags);
	ret = hws_guard_audio_video_remap_page_locked(hws, ch);
	if (!ret)
		ret = hws_audio_seed_capture_buffer_locked(hws, ch);
	spin_unlock_irqrestore(&vid->irq_lock, flags);
	return ret;
}

void hws_audio_seed_channels(struct hws_pcie_dev *hws)
{
	unsigned int ch;

	if (!hws || !hws->bar0_base)
		return;

	/* Match scratch teardown's scratch_lock -> channel irq_lock order. */
	mutex_lock(&hws->scratch_lock);
	for (ch = 0; ch < hws->cur_max_audio_ch; ch++) {
		int ret;

		if (!hws->scratch_aud[ch].cpu)
			continue;

		ret = hws_audio_seed_capture_buffer(hws, ch);
		if (ret)
			dev_warn(&hws->pdev->dev,
				 "audio seed ch%u failed ret=%d\n", ch, ret);
	}
	mutex_unlock(&hws->scratch_lock);
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

static const char *hws_audio_xrun_reason_name(enum hws_audio_xrun_reason reason)
{
	switch (reason) {
	case HWS_AUDIO_XRUN_NONE:
		return "none";
	case HWS_AUDIO_XRUN_PACKET_IN_FLIGHT:
		return "packet-in-flight";
	case HWS_AUDIO_XRUN_DUPLICATE_TOGGLE:
		return "duplicate-toggle";
	case HWS_AUDIO_XRUN_IRQ_TIMESTAMP:
		return "irq-timestamp";
	case HWS_AUDIO_XRUN_CADENCE:
		return "cadence";
	case HWS_AUDIO_XRUN_W1C_STATUS_REASSERTED:
		return "w1c-status-reasserted";
	case HWS_AUDIO_XRUN_W1C_TOGGLE_UNSTABLE:
		return "w1c-toggle-unstable";
	case HWS_AUDIO_XRUN_W1C_TOGGLE_CHANGED:
		return "w1c-toggle-changed";
	case HWS_AUDIO_XRUN_WORK_DEADLINE:
		return "work-deadline";
	case HWS_AUDIO_XRUN_POST_COPY_TOGGLE:
		return "post-copy-toggle";
	case HWS_AUDIO_XRUN_GENERATION:
		return "generation";
	case HWS_AUDIO_XRUN_STREAM_STATE:
		return "stream-state";
	case HWS_AUDIO_XRUN_SUBSTREAM_MISSING:
		return "substream-missing";
	case HWS_AUDIO_XRUN_RUNTIME_MISSING:
		return "runtime-missing";
	case HWS_AUDIO_XRUN_RING_INVALID:
		return "ring-invalid";
	case HWS_AUDIO_XRUN_SCRATCH_MISSING:
		return "scratch-missing";
	case HWS_AUDIO_XRUN_SCRATCH_BOUNDS:
		return "scratch-bounds";
	case HWS_AUDIO_XRUN_STAGING_MISSING:
		return "staging-missing";
	case HWS_AUDIO_XRUN_WORKQUEUE_MISSING:
		return "workqueue-missing";
	case HWS_AUDIO_XRUN_DMA_GUARD:
		return "dma-guard";
	default:
		return "unknown";
	}
}

static void hws_audio_log_telemetry(struct hws_audio *a, const char *event,
				    bool error)
{
	struct hws_pcie_dev *hws;
	struct hws_scratch_dma *scratch;
	enum hws_audio_packet_state packet_state;
	enum hws_audio_xrun_reason reason;
	unsigned long flags;
	dma_addr_t scratch_dma;
	u64 generation, last_interval_ns, last_latency_ns, max_latency_ns;
	u32 irq_count, delivered_count, primed_packets, dropped_packets;
	u32 cadence_errors, w1c_ambiguities;
	u32 toggle_errors, generation_errors, deadline_misses, guard_errors;
	u32 acap, int_status, audio_dma, remap_hi, remap_lo;
	u8 last_toggle, live_toggle;
	unsigned int ch;
	size_t observed_dma_extent, scratch_size;
	bool scratch_corrupt;

	if (!a || !a->parent || !a->parent->bar0_base)
		return;

	hws = a->parent;
	ch = a->channel_index;
	if (ch >= hws->cur_max_audio_ch)
		return;

	spin_lock_irqsave(&a->pending_lock, flags);
	packet_state = a->packet_state;
	reason = a->xrun_reason;
	last_toggle = a->last_irq_toggle;
	irq_count = a->irq_count;
	delivered_count = a->delivered_count;
	primed_packets = a->primed_packets;
	dropped_packets = a->dropped_packets;
	generation = a->next_generation;
	last_interval_ns = a->last_irq_interval_ns;
	cadence_errors = a->cadence_errors;
	w1c_ambiguities = a->w1c_ambiguities;
	toggle_errors = a->toggle_errors;
	generation_errors = a->generation_errors;
	deadline_misses = a->deadline_misses;
	guard_errors = a->guard_errors;
	last_latency_ns = a->last_work_latency_ns;
	max_latency_ns = a->max_work_latency_ns;
	spin_unlock_irqrestore(&a->pending_lock, flags);
	observed_dma_extent = READ_ONCE(a->observed_dma_extent);
	scratch_corrupt = READ_ONCE(a->scratch_corrupt);

	scratch = &hws->scratch_aud[ch];
	scratch_dma = scratch->dma;
	scratch_size = scratch->size;
	acap = readl(hws->bar0_base + HWS_REG_ACAP_ENABLE);
	int_status = readl(hws->bar0_base + HWS_REG_INT_STATUS);
	live_toggle = readl(hws->bar0_base + HWS_REG_ABUF_TOGGLE(ch)) & 0x01;
	audio_dma = readl(hws->bar0_base + HWS_REG_AUD_DMA_ADDR(ch));
	remap_hi = readl(hws->bar0_base + PCI_ADDR_TABLE_BASE +
			 HWS_AUDIO_REMAP_SLOT_OFF(ch));
	remap_lo = readl(hws->bar0_base + PCI_ADDR_TABLE_BASE +
			 HWS_AUDIO_REMAP_SLOT_OFF(ch) + PCIE_BARADDROFSIZE);

#define HWS_AUDIO_TELEMETRY_FMT \
	"audio telemetry event=%s ch=%u reason=%s state=%u running=%d cap=%d stop=%d irq=%u generation=%llu cadence_last=%lluus cadence_errors=%u w1c_ambiguities=%u last_toggle=%u live_toggle=%u toggle_errors=%u generation_errors=%u deadline_misses=%u guard_errors=%u dma_extent=%zu dma_capacity=%zu scratch_corrupt=%d primed=%u delivered=%u dropped=%u work_last=%lluus work_max=%lluus ACAP=0x%08x INT_STATUS=0x%08x AUD_DMA=0x%08x REMAP_HI=0x%08x REMAP_LO=0x%08x scratch=%pad/%zu\n"
	if (error)
		dev_err(&hws->pdev->dev, HWS_AUDIO_TELEMETRY_FMT,
			event, ch, hws_audio_xrun_reason_name(reason),
			packet_state, READ_ONCE(a->stream_running),
			READ_ONCE(a->cap_active), READ_ONCE(a->stop_requested),
			irq_count, (unsigned long long)generation,
			(unsigned long long)div_u64(last_interval_ns,
						      NSEC_PER_USEC),
			cadence_errors, w1c_ambiguities, last_toggle, live_toggle,
			toggle_errors, generation_errors, deadline_misses,
			guard_errors, observed_dma_extent,
			hws_audio_dma_capacity(), scratch_corrupt, primed_packets,
			delivered_count, dropped_packets,
			(unsigned long long)div_u64(last_latency_ns,
						      NSEC_PER_USEC),
			(unsigned long long)div_u64(max_latency_ns,
						      NSEC_PER_USEC),
			acap, int_status, audio_dma, remap_hi, remap_lo,
			&scratch_dma, scratch_size);
	else
		dev_info(&hws->pdev->dev, HWS_AUDIO_TELEMETRY_FMT,
			 event, ch, hws_audio_xrun_reason_name(reason),
			 packet_state, READ_ONCE(a->stream_running),
			 READ_ONCE(a->cap_active), READ_ONCE(a->stop_requested),
			 irq_count, (unsigned long long)generation,
			 (unsigned long long)div_u64(last_interval_ns,
						       NSEC_PER_USEC),
			 cadence_errors, w1c_ambiguities, last_toggle, live_toggle,
			 toggle_errors, generation_errors, deadline_misses,
			 guard_errors, observed_dma_extent,
			 hws_audio_dma_capacity(), scratch_corrupt, primed_packets,
			 delivered_count, dropped_packets,
			 (unsigned long long)div_u64(last_latency_ns,
						       NSEC_PER_USEC),
			 (unsigned long long)div_u64(max_latency_ns,
						       NSEC_PER_USEC),
			 acap, int_status, audio_dma, remap_hi, remap_lo,
			 &scratch_dma, scratch_size);
#undef HWS_AUDIO_TELEMETRY_FMT
}

static void hws_audio_clear_pending(struct hws_audio *a)
{
	unsigned long flags;

	if (!a)
		return;

	spin_lock_irqsave(&a->pending_lock, flags);
	a->packet_state = HWS_AUDIO_PACKET_IDLE;
	a->pending_toggle = 0;
	a->pending_publish = false;
	a->pending_irq_ns = 0;
	a->pending_generation = 0;
	a->last_irq_toggle = 0xff;
	a->last_irq_ns = 0;
	a->last_irq_interval_ns = 0;
	a->xrun_reason = HWS_AUDIO_XRUN_NONE;
	spin_unlock_irqrestore(&a->pending_lock, flags);
}

static void hws_audio_report_xrun(struct hws_audio *a)
{
	struct hws_pcie_dev *hws;
	struct snd_pcm_substream *ss;
	unsigned int ch;

	if (!a)
		return;

	hws = a->parent;
	ch = a->channel_index;
	ss = READ_ONCE(a->pcm_substream);

	hws_audio_log_telemetry(a, "xrun", true);
	hws_audio_publish_stopped(a);
	hws_audio_disable_capture_and_ack(hws, ch);
	hws_audio_clear_pending(a);

	if (!ss)
		return;

	if (READ_ONCE(a->pcm_substream) == ss)
		snd_pcm_stop_xrun(ss);
}

static void hws_audio_drain_channel_work(struct hws_audio *a)
{
	if (!a)
		return;

	if (!in_interrupt())
		cancel_work_sync(&a->deliver_work);
	hws_audio_clear_pending(a);
}

static int
hws_audio_reclaim_scratch_locked(struct hws_audio *a, bool dma_idle,
				 const char *owner)
{
	struct hws_pcie_dev *hws;
	unsigned long flags;
	size_t observed = 0;
	unsigned int ch;
	int ret;

	lockdep_assert_held(&a->scratch_state_lock);
	if (!READ_ONCE(a->dma_armed))
		return READ_ONCE(a->scratch_corrupt) ? -EUCLEAN : 0;
	if (READ_ONCE(a->cap_active) || READ_ONCE(a->stream_running))
		return -EBUSY;

	hws = a->parent;
	if (!hws)
		return -ENODEV;
	ch = a->channel_index;
	dma_idle = dma_idle || READ_ONCE(hws->dma_quiesced);
	if (!dma_idle) {
		ret = hws_try_wait_dma_idle(hws, owner, ch);
		if (ret) {
			dev_dbg(&hws->pdev->dev,
				"%s ch=%u: audio DMA arena remains quarantined: %d\n",
				owner, ch, ret);
			return ret == -ETIMEDOUT ? -EBUSY : ret;
		}
	}

	ret = hws_audio_scratch_verify(hws, ch, &observed);
	if (observed > READ_ONCE(a->observed_dma_extent))
		WRITE_ONCE(a->observed_dma_extent, observed);
	/* DMA is idle even when guard verification finds corruption. */
	WRITE_ONCE(a->dma_armed, false);
	if (ret) {
		spin_lock_irqsave(&a->pending_lock, flags);
		a->xrun_reason = HWS_AUDIO_XRUN_DMA_GUARD;
		hws_audio_count_failure_locked(a, a->xrun_reason);
		spin_unlock_irqrestore(&a->pending_lock, flags);
		WRITE_ONCE(a->scratch_corrupt, true);
		dev_crit(&hws->pdev->dev,
			 "audio DMA guard corruption ch=%u ring=%zu observed=%zu capacity=%zu ret=%d\n",
			 ch, 2 * (size_t)MAX_DMA_AUDIO_PK_SIZE, observed,
			 hws_audio_dma_capacity(), ret);
		return ret;
	}

	dev_info(&hws->pdev->dev,
		 "audio DMA bounds ch=%u ring=%zu observed=%zu capacity=%zu guard=ok\n",
		 ch, 2 * (size_t)MAX_DMA_AUDIO_PK_SIZE, observed,
		 hws_audio_dma_capacity());
	return 0;
}

static int hws_audio_prepare_scratch(struct hws_audio *a, const char *owner)
{
	struct hws_pcie_dev *hws;
	unsigned int ch;
	int ret;

	if (!a || !a->parent)
		return -EINVAL;

	mutex_lock(&a->scratch_state_lock);
	if (!READ_ONCE(a->scratch_acquired)) {
		ret = -ENOMEM;
		goto out_unlock;
	}
	if (READ_ONCE(a->scratch_corrupt)) {
		ret = -EUCLEAN;
		goto out_unlock;
	}

	hws = a->parent;
	ch = a->channel_index;
	ret = hws_audio_reclaim_scratch_locked(a, false, owner);
	if (!ret)
		ret = hws_audio_scratch_prepare(hws, ch);
	if (ret == -EOVERFLOW)
		WRITE_ONCE(a->scratch_corrupt, true);

out_unlock:
	mutex_unlock(&a->scratch_state_lock);
	return ret;
}

static int hws_audio_acquire_scratch(struct hws_audio *a)
{
	struct hws_pcie_dev *hws;
	unsigned int ch;
	int ret;

	if (!a || !a->parent)
		return -EINVAL;

	mutex_lock(&a->scratch_state_lock);
	if (READ_ONCE(a->scratch_corrupt)) {
		mutex_unlock(&a->scratch_state_lock);
		return -EUCLEAN;
	}
	if (READ_ONCE(a->scratch_acquired)) {
		ret = hws_audio_reclaim_scratch_locked(a, false,
						       "audio hw_params");
		if (!ret)
			ret = hws_audio_scratch_prepare(a->parent,
							a->channel_index);
		if (ret == -EOVERFLOW)
			WRITE_ONCE(a->scratch_corrupt, true);
		mutex_unlock(&a->scratch_state_lock);
		return ret;
	}

	hws = a->parent;
	ch = a->channel_index;
	ret = hws_alloc_channel_scratch(hws, ch);
	if (ret) {
		mutex_unlock(&a->scratch_state_lock);
		return ret;
	}
	ret = hws_audio_reclaim_scratch_locked(a, false, "audio hw_params");
	if (!ret)
		ret = hws_audio_scratch_prepare(hws, ch);
	if (ret) {
		if (ret == -EOVERFLOW)
			WRITE_ONCE(a->scratch_corrupt, true);
		hws_release_channel_scratch(hws, ch);
		mutex_unlock(&a->scratch_state_lock);
		return ret;
	}

	WRITE_ONCE(a->scratch_acquired, true);
	WRITE_ONCE(a->dma_armed, false);
	mutex_unlock(&a->scratch_state_lock);
	return 0;
}

static void hws_audio_release_scratch(struct hws_audio *a, bool dma_idle)
{
	struct hws_pcie_dev *hws;
	unsigned int ch;
	bool acquired;
	bool quarantined;

	if (!a)
		return;

	mutex_lock(&a->scratch_state_lock);
	hws = a->parent;
	acquired = READ_ONCE(a->scratch_acquired);
	dma_idle = dma_idle || (hws && READ_ONCE(hws->dma_quiesced));
	if (!acquired && !(dma_idle && READ_ONCE(a->dma_armed))) {
		mutex_unlock(&a->scratch_state_lock);
		return;
	}

	ch = a->channel_index;
	if (dma_idle && READ_ONCE(a->dma_armed))
		hws_audio_reclaim_scratch_locked(a, true,
						 "audio global teardown");
	WRITE_ONCE(a->scratch_acquired, false);
	quarantined = READ_ONCE(a->dma_armed);
	mutex_unlock(&a->scratch_state_lock);

	if (hws && acquired)
		hws_release_channel_scratch(hws, ch);
	if (hws && quarantined)
		dev_dbg(&hws->pdev->dev,
			"audio stop ch=%u quarantined DMA arena\n", ch);
}

static bool hws_audio_deliver_packet(struct hws_audio *a, const void *src,
				     u64 generation,
				     enum hws_audio_xrun_reason *failure)
{
	struct snd_pcm_substream *ss;
	struct snd_pcm_runtime *rt;
	snd_pcm_uframes_t frames, ring_pos, ring_frames, period_frames;
	size_t frame_bytes, packet_bytes, ring_bytes, first;
	unsigned long flags;
	unsigned int elapsed = 0;
	bool delivered = false;
	char *dst;

	if (failure)
		*failure = HWS_AUDIO_XRUN_NONE;
	if (!READ_ONCE(a->stream_running) || !READ_ONCE(a->cap_active) ||
	    READ_ONCE(a->stop_requested)) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_STREAM_STATE;
		return false;
	}

	ss = READ_ONCE(a->pcm_substream);
	if (!ss) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_SUBSTREAM_MISSING;
		return false;
	}

	rt = ss->runtime;
	if (!rt || !rt->dma_area) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_RUNTIME_MISSING;
		return false;
	}

	/*
	 * Keep lifecycle invalidation and a new ADONE generation out of the
	 * userspace-visible copy. Trigger-stop never nests these locks in the
	 * opposite order: it publishes ring state, drops ring_lock, then clears
	 * pending state.
	 */
	spin_lock_irqsave(&a->pending_lock, flags);
	if (a->packet_state != HWS_AUDIO_PACKET_COPYING ||
	    a->pending_generation != generation) {
		spin_unlock_irqrestore(&a->pending_lock, flags);
		if (failure)
			*failure = HWS_AUDIO_XRUN_GENERATION;
		return false;
	}
	spin_lock(&a->ring_lock);
	if (!READ_ONCE(a->stream_running) || !READ_ONCE(a->cap_active) ||
	    READ_ONCE(a->stop_requested) ||
	    READ_ONCE(a->pcm_substream) != ss) {
		spin_unlock(&a->ring_lock);
		spin_unlock_irqrestore(&a->pending_lock, flags);
		if (failure)
			*failure = HWS_AUDIO_XRUN_STREAM_STATE;
		return false;
	}

	frame_bytes = a->frame_bytes;
	packet_bytes = a->hw_packet_bytes;
	ring_frames = a->ring_size_byframes;
	period_frames = a->period_size_byframes;
	if (!frame_bytes || !packet_bytes || !ring_frames || !period_frames) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_RING_INVALID;
		goto out_unlock;
	}
	if (packet_bytes % frame_bytes) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_RING_INVALID;
		goto out_unlock;
	}

	frames = packet_bytes / frame_bytes;
	if (!frames) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_RING_INVALID;
		goto out_unlock;
	}

	ring_pos = a->ring_wpos_byframes;
	ring_bytes = ring_frames * frame_bytes;
	dst = rt->dma_area + ring_pos * frame_bytes;
	first = min(packet_bytes, ring_bytes - ring_pos * frame_bytes);
	memcpy(dst, src, first);
	if (first < packet_bytes)
		memcpy(rt->dma_area, (const char *)src + first, packet_bytes - first);
	delivered = true;

	ring_pos += frames;
	if (ring_pos >= ring_frames)
		ring_pos %= ring_frames;
	a->ring_wpos_byframes = ring_pos;

	a->period_used_byframes += frames;
	while (a->period_used_byframes >= period_frames) {
		a->period_used_byframes -= period_frames;
		elapsed++;
	}
out_unlock:
	spin_unlock(&a->ring_lock);
	spin_unlock_irqrestore(&a->pending_lock, flags);

	if (!READ_ONCE(a->stream_running) || !READ_ONCE(a->cap_active) ||
	    READ_ONCE(a->stop_requested))
		return delivered;

	while (elapsed--)
		snd_pcm_period_elapsed(ss);
	return delivered;
}

static u64 hws_audio_packet_period_ns(const struct hws_audio *a)
{
	size_t frame_bytes;
	u32 rate;
	u64 frames;

	if (!a)
		return 0;

	frame_bytes = READ_ONCE(a->frame_bytes);
	rate = READ_ONCE(a->output_sample_rate);
	if (!frame_bytes || !rate || a->hw_packet_bytes % frame_bytes)
		return 0;

	frames = a->hw_packet_bytes / frame_bytes;
	if (!frames)
		return 0;

	return div_u64(frames * NSEC_PER_SEC, rate);
}

static bool hws_audio_cadence_valid(u64 period_ns, u64 interval_ns)
{
	u64 early_ns, late_ns;

	if (!period_ns || !interval_ns)
		return false;

	early_ns = div_u64(period_ns * HWS_AUDIO_CADENCE_EARLY_NUM,
			   HWS_AUDIO_CADENCE_EARLY_DEN);
	late_ns = div_u64(period_ns * HWS_AUDIO_CADENCE_LATE_NUM,
			  HWS_AUDIO_CADENCE_LATE_DEN);
	return interval_ns >= early_ns && interval_ns <= late_ns;
}

static bool hws_audio_deadline_expired(const struct hws_audio *a, u64 irq_ns,
				       u64 now_ns)
{
	u64 period_ns = hws_audio_packet_period_ns(a);

	if (!period_ns || !irq_ns || now_ns < irq_ns)
		return true;

	return now_ns - irq_ns >= period_ns;
}

static bool hws_audio_generation_valid(struct hws_audio *a, u64 generation)
{
	unsigned long flags;
	bool valid;

	spin_lock_irqsave(&a->pending_lock, flags);
	valid = a->packet_state == HWS_AUDIO_PACKET_COPYING &&
		a->pending_generation == generation;
	spin_unlock_irqrestore(&a->pending_lock, flags);
	return valid;
}

static bool hws_audio_stage_one_packet(struct hws_audio *a, u8 cur_toggle,
				       u64 generation, u64 irq_ns,
				       enum hws_audio_xrun_reason *failure)
{
	struct hws_pcie_dev *hws;
	unsigned int ch;
	void *cpu;
	void *staging;
	u64 now_ns;
	size_t size;
	size_t offset;
	u8 live_toggle;

	if (failure)
		*failure = HWS_AUDIO_XRUN_NONE;
	if (!a) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_STREAM_STATE;
		return false;
	}

	hws = a->parent;
	ch = a->channel_index;
	if (!hws || !hws->bar0_base || ch >= hws->cur_max_audio_ch) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_STREAM_STATE;
		return false;
	}

	if (!READ_ONCE(a->stream_running) || !READ_ONCE(a->cap_active) ||
	    READ_ONCE(a->stop_requested)) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_STREAM_STATE;
		return false;
	}
	staging = READ_ONCE(a->staging_buffer);
	if (!staging || READ_ONCE(a->staging_size) < a->hw_packet_bytes) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_STAGING_MISSING;
		return false;
	}
	if (!hws_audio_generation_valid(a, generation)) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_GENERATION;
		return false;
	}

	now_ns = ktime_get_mono_fast_ns();
	if (hws_audio_deadline_expired(a, irq_ns, now_ns)) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_WORK_DEADLINE;
		return false;
	}

	live_toggle = readl_relaxed(hws->bar0_base +
				    HWS_REG_ABUF_TOGGLE(ch)) & 0x01;
	if (live_toggle != cur_toggle) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_POST_COPY_TOGGLE;
		return false;
	}

	if (!hws_audio_select_buffer(hws, ch, &cpu, NULL, &size)) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_SCRATCH_MISSING;
		return false;
	}

	offset = hws_audio_packet_offset(a, cur_toggle);
	if (offset + a->hw_packet_bytes > size) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_SCRATCH_BOUNDS;
		return false;
	}

	dma_rmb();
	memcpy(staging, (char *)cpu + offset, a->hw_packet_bytes);
	/* Order the DMA read before observing whether hardware changed halves. */
	dma_rmb();
	live_toggle = readl_relaxed(hws->bar0_base +
				    HWS_REG_ABUF_TOGGLE(ch)) & 0x01;
	if (live_toggle != cur_toggle) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_POST_COPY_TOGGLE;
		return false;
	}

	now_ns = ktime_get_mono_fast_ns();
	if (hws_audio_deadline_expired(a, irq_ns, now_ns)) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_WORK_DEADLINE;
		return false;
	}
	if (!hws_audio_generation_valid(a, generation)) {
		if (failure)
			*failure = HWS_AUDIO_XRUN_GENERATION;
		return false;
	}

	return true;
}

static void
hws_audio_count_failure_locked(struct hws_audio *a,
			       enum hws_audio_xrun_reason reason)
{
	lockdep_assert_held(&a->pending_lock);

	switch (reason) {
	case HWS_AUDIO_XRUN_DUPLICATE_TOGGLE:
	case HWS_AUDIO_XRUN_POST_COPY_TOGGLE:
		a->toggle_errors++;
		break;
	case HWS_AUDIO_XRUN_IRQ_TIMESTAMP:
	case HWS_AUDIO_XRUN_CADENCE:
		a->cadence_errors++;
		break;
	case HWS_AUDIO_XRUN_W1C_STATUS_REASSERTED:
	case HWS_AUDIO_XRUN_W1C_TOGGLE_UNSTABLE:
	case HWS_AUDIO_XRUN_W1C_TOGGLE_CHANGED:
		a->w1c_ambiguities++;
		break;
	case HWS_AUDIO_XRUN_GENERATION:
		a->generation_errors++;
		break;
	case HWS_AUDIO_XRUN_WORK_DEADLINE:
		a->deadline_misses++;
		break;
	case HWS_AUDIO_XRUN_DMA_GUARD:
		a->guard_errors++;
		break;
	default:
		break;
	}
}

static void hws_audio_deliver_work(struct work_struct *work)
{
	struct hws_audio *a = container_of(work, struct hws_audio, deliver_work);
	enum hws_audio_xrun_reason delivery_failure;
	unsigned long flags;
	bool delivered;
	bool publish;
	bool staged;
	u64 generation;
	u64 latency_ns;
	u64 irq_ns;
	u8 toggle;

	for (;;) {
		spin_lock_irqsave(&a->pending_lock, flags);
		if (a->packet_state == HWS_AUDIO_PACKET_XRUN) {
			spin_unlock_irqrestore(&a->pending_lock, flags);
			hws_audio_report_xrun(a);
			break;
		}
		if (a->packet_state != HWS_AUDIO_PACKET_PENDING) {
			spin_unlock_irqrestore(&a->pending_lock, flags);
			break;
		}
		toggle = a->pending_toggle;
		publish = a->pending_publish;
		irq_ns = a->pending_irq_ns;
		generation = a->pending_generation;
		a->packet_state = HWS_AUDIO_PACKET_COPYING;
		spin_unlock_irqrestore(&a->pending_lock, flags);

		latency_ns = ktime_get_mono_fast_ns() - irq_ns;
		spin_lock_irqsave(&a->pending_lock, flags);
		a->last_work_latency_ns = latency_ns;
		if (latency_ns > a->max_work_latency_ns)
			a->max_work_latency_ns = latency_ns;
		spin_unlock_irqrestore(&a->pending_lock, flags);

		staged = hws_audio_stage_one_packet(a, toggle, generation,
						    irq_ns,
						    &delivery_failure);
		if (staged && publish)
			delivered = hws_audio_deliver_packet(a, a->staging_buffer,
							     generation,
							     &delivery_failure);
		else
			delivered = staged;

		spin_lock_irqsave(&a->pending_lock, flags);
		if (a->packet_state == HWS_AUDIO_PACKET_COPYING &&
		    a->pending_generation != generation) {
			a->packet_state = HWS_AUDIO_PACKET_XRUN;
			a->xrun_reason = HWS_AUDIO_XRUN_GENERATION;
			a->dropped_packets++;
			hws_audio_count_failure_locked(a, a->xrun_reason);
		} else if (a->packet_state == HWS_AUDIO_PACKET_COPYING) {
			if (!READ_ONCE(a->stream_running) ||
			    !READ_ONCE(a->cap_active) ||
			    READ_ONCE(a->stop_requested)) {
				a->packet_state = HWS_AUDIO_PACKET_IDLE;
				a->pending_publish = false;
				a->pending_irq_ns = 0;
				a->pending_generation = 0;
			} else if (delivered) {
				a->packet_state = HWS_AUDIO_PACKET_IDLE;
				a->pending_publish = false;
				a->pending_irq_ns = 0;
				a->pending_generation = 0;
				if (publish)
					a->delivered_count++;
				else
					a->primed_packets++;
			} else {
				a->packet_state = HWS_AUDIO_PACKET_XRUN;
				a->xrun_reason = delivery_failure;
				a->dropped_packets++;
				hws_audio_count_failure_locked(a, delivery_failure);
			}
		}
		spin_unlock_irqrestore(&a->pending_lock, flags);
	}
}

bool hws_audio_record_interrupt(struct hws_pcie_dev *hws, unsigned int ch,
				u8 cur_toggle, u64 irq_ns,
				enum hws_audio_xrun_reason ambiguity)
{
	struct hws_audio *a;
	enum hws_audio_packet_state state;
	bool xrun = false;
	u64 generation;
	u64 interval_ns = 0;
	u64 period_ns;
	u8 last_toggle;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return false;

	a = &hws->audio[ch];
	if (!READ_ONCE(a->stream_running) || !READ_ONCE(a->cap_active) ||
	    READ_ONCE(a->stop_requested))
		return false;
	if (!irq_ns)
		irq_ns = ktime_get_mono_fast_ns();
	period_ns = hws_audio_packet_period_ns(a);

	spin_lock(&a->pending_lock);
	state = a->packet_state;
	last_toggle = a->last_irq_toggle;
	a->irq_count++;
	generation = ++a->next_generation;
	if (!generation)
		generation = ++a->next_generation;
	if (a->last_irq_ns && irq_ns > a->last_irq_ns)
		interval_ns = irq_ns - a->last_irq_ns;
	a->last_irq_interval_ns = interval_ns;
	if (ambiguity != HWS_AUDIO_XRUN_NONE) {
		a->dropped_packets++;
		a->packet_state = HWS_AUDIO_PACKET_XRUN;
		a->xrun_reason = ambiguity;
		hws_audio_count_failure_locked(a, ambiguity);
		xrun = true;
	} else if (state != HWS_AUDIO_PACKET_IDLE) {
		if (state != HWS_AUDIO_PACKET_XRUN) {
			a->dropped_packets++;
			a->xrun_reason = HWS_AUDIO_XRUN_PACKET_IN_FLIGHT;
		}
		a->packet_state = HWS_AUDIO_PACKET_XRUN;
		xrun = true;
	} else if (!period_ns) {
		a->dropped_packets++;
		a->packet_state = HWS_AUDIO_PACKET_XRUN;
		a->xrun_reason = HWS_AUDIO_XRUN_RING_INVALID;
		xrun = true;
	} else if (a->last_irq_ns && irq_ns <= a->last_irq_ns) {
		a->dropped_packets++;
		a->packet_state = HWS_AUDIO_PACKET_XRUN;
		a->xrun_reason = HWS_AUDIO_XRUN_IRQ_TIMESTAMP;
		hws_audio_count_failure_locked(a, a->xrun_reason);
		xrun = true;
	} else if (last_toggle != 0xff && cur_toggle == last_toggle) {
		a->dropped_packets++;
		a->packet_state = HWS_AUDIO_PACKET_XRUN;
		a->xrun_reason = HWS_AUDIO_XRUN_DUPLICATE_TOGGLE;
		hws_audio_count_failure_locked(a, a->xrun_reason);
		xrun = true;
	} else if (a->last_irq_ns &&
		   !hws_audio_cadence_valid(period_ns, interval_ns)) {
		a->dropped_packets++;
		a->packet_state = HWS_AUDIO_PACKET_XRUN;
		a->xrun_reason = HWS_AUDIO_XRUN_CADENCE;
		hws_audio_count_failure_locked(a, a->xrun_reason);
		xrun = true;
	} else {
		a->pending_toggle = cur_toggle;
		/* The first staged packet establishes cadence; do not publish it. */
		a->pending_publish = !!a->last_irq_ns;
		a->pending_irq_ns = irq_ns;
		a->pending_generation = generation;
		a->last_irq_toggle = cur_toggle;
		a->last_irq_ns = irq_ns;
		a->packet_state = HWS_AUDIO_PACKET_PENDING;
	}
	spin_unlock(&a->pending_lock);

	if (xrun) {
		/* Stop reuse of the DMA halves before deferred XRUN reporting. */
		WRITE_ONCE(a->cap_active, false);
		smp_wmb(); /* publish stopped state before posting ACAP disable */
		hws_enable_audio_capture(hws, ch, false);
	}

	return true;
}

void hws_audio_queue_work(struct hws_pcie_dev *hws, unsigned int ch)
{
	struct workqueue_struct *wq;
	struct hws_audio *a;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return;

	a = &hws->audio[ch];
	wq = READ_ONCE(hws->audio_wq);
	if (!wq) {
		spin_lock(&a->pending_lock);
		if (a->packet_state != HWS_AUDIO_PACKET_XRUN)
			a->dropped_packets++;
		a->packet_state = HWS_AUDIO_PACKET_XRUN;
		a->xrun_reason = HWS_AUDIO_XRUN_WORKQUEUE_MISSING;
		spin_unlock(&a->pending_lock);
		WRITE_ONCE(a->cap_active, false);
		smp_wmb(); /* publish stopped state before posting ACAP disable */
		hws_enable_audio_capture(hws, ch, false);
		hws_audio_log_telemetry(a, "xrun-irq", true);
		return;
	}

	queue_work(wq, &a->deliver_work);
}

static void hws_audio_free_staging(struct hws_audio *a)
{
	void *staging;

	if (!a)
		return;

	staging = xchg(&a->staging_buffer, NULL);
	WRITE_ONCE(a->staging_size, 0);
	kfree(staging);
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
	spin_lock_init(&aud->pending_lock);
	mutex_init(&aud->scratch_state_lock);
	INIT_WORK(&aud->deliver_work, hws_audio_deliver_work);

	/* defaults */
	aud->output_sample_rate = 48000;
	aud->channel_count      = 2;
	aud->bits_per_sample    = 16;
	aud->hw_packet_bytes    = pdev->audio_pkt_size;
	if (ch < pdev->cur_max_audio_ch) {
		if (!aud->hw_packet_bytes ||
		    aud->hw_packet_bytes > HWS_AUDIO_PACKET_BYTES)
			return -EINVAL;
		aud->staging_buffer = kmalloc(aud->hw_packet_bytes, GFP_KERNEL);
		if (!aud->staging_buffer)
			return -ENOMEM;
		aud->staging_size = aud->hw_packet_bytes;
	}

	/* ALSA linkage */
	WRITE_ONCE(aud->pcm_substream, NULL);

	/* stream state */
	WRITE_ONCE(aud->cap_active, false);
	WRITE_ONCE(aud->stream_running, false);
	WRITE_ONCE(aud->stop_requested, false);
	WRITE_ONCE(aud->scratch_acquired, false);
	WRITE_ONCE(aud->dma_armed, false);
	WRITE_ONCE(aud->scratch_corrupt, false);

	hws_audio_clear_pending(aud);
	hws_audio_reset_counters(aud);

	return 0;
}

void hws_audio_cleanup_channel(struct hws_pcie_dev *pdev, int ch, bool device_removal)
{
	struct hws_audio *aud;
	struct snd_pcm_substream *ss;

	if (!pdev || ch < 0 || ch >= pdev->cur_max_audio_ch)
		return;

	aud = &pdev->audio[ch];
	hws_audio_quiesce_capture(pdev, ch, true);

	/* If device is going away and stream was open, tell ALSA. */
	ss = READ_ONCE(aud->pcm_substream);
	if (device_removal && ss) {
		unsigned long flags;

		snd_pcm_stream_lock_irqsave(ss, flags);
		if (ss->runtime)
			snd_pcm_stop(ss, SNDRV_PCM_STATE_DISCONNECTED);
		snd_pcm_stream_unlock_irqrestore(ss, flags);
		WRITE_ONCE(aud->pcm_substream, NULL);
	}

	hws_audio_release_scratch(aud, false);
	hws_audio_free_staging(aud);
}

static inline bool hws_check_audio_capture(struct hws_pcie_dev *hws, unsigned int ch)
{
	u32 reg = readl(hws->bar0_base + HWS_REG_ACAP_ENABLE);

	return !!(reg & BIT(ch));
}

static int hws_audio_hw_ready(struct hws_pcie_dev *hws)
{
	u32 status;

	if (!hws || !hws->bar0_base)
		return -ENODEV;
	if (READ_ONCE(hws->pci_lost) || READ_ONCE(hws->dma_quiesced))
		return -ENODEV;
	if (READ_ONCE(hws->suspended))
		return -EBUSY;

	status = readl(hws->bar0_base + HWS_REG_SYS_STATUS);
	if (status == 0xFFFFFFFF) {
		hws->pci_lost = true;
		dev_err(&hws->pdev->dev, "PCIe device not responding\n");
		return -ENODEV;
	}

	if (!(status & BIT(0))) {
		dev_warn_ratelimited(&hws->pdev->dev,
				     "audio start refused while device is not ready (SYS_STATUS=0x%08x)\n",
				     status);
		return -EIO;
	}

	return 0;
}

static int hws_start_audio_capture(struct hws_pcie_dev *hws, unsigned int ch)
{
	struct hws_audio *a;
	int ret;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return -EINVAL;
	if (READ_ONCE(hws->suspended))
		return -EBUSY;
	a = &hws->audio[ch];

	/* Already running? Re-assert HW if needed. */
	if (READ_ONCE(a->stream_running)) {
		if (!hws_check_audio_capture(hws, ch)) {
			ret = hws_audio_hw_ready(hws);
			if (ret)
				return ret;
			ret = hws_audio_guard_and_seed_capture_buffer(hws, ch);
			if (ret)
				return ret;
			WRITE_ONCE(a->cap_active, false);
			smp_wmb(); /* publish inactive before stale ADONE ack */
			hws_audio_discard_stale_done(hws, a, ch);
			WRITE_ONCE(a->cap_active, true);
			smp_wmb(); /* publish active before ACAP_ENABLE */
			WRITE_ONCE(a->dma_armed, true);
			hws_enable_audio_capture(hws, ch, true);
			if (!READ_ONCE(a->cap_active)) {
				hws_audio_publish_stopped(a);
				return -ENODEV;
			}
		}
		hws_audio_log_telemetry(a, "restart", false);
		dev_dbg(&hws->pdev->dev, "audio ch%u already running (re-enabled)\n", ch);
		return 0;
	}

	/* ALSA prepare must reclaim a quarantined arena before a fresh START. */
	if (READ_ONCE(a->dma_armed))
		return -EBUSY;
	if (READ_ONCE(a->scratch_corrupt))
		return -EUCLEAN;
	if (!READ_ONCE(a->scratch_acquired))
		return -ENOMEM;

	ret = hws_audio_hw_ready(hws);
	if (ret)
		return ret;

	ret = hws_audio_guard_and_seed_capture_buffer(hws, ch);
	if (ret)
		return ret;

	hws_audio_discard_stale_done(hws, a, ch);
	hws_audio_reset_counters(a);

	/*
	 * ADONE can fire as soon as capture is enabled. Discard any completion
	 * latched before this start, then publish the stream state before
	 * ACAP_ENABLE so the IRQ path accepts the first fresh packet.
	 */
	WRITE_ONCE(a->stop_requested, false);
	WRITE_ONCE(a->stream_running, true);
	WRITE_ONCE(a->cap_active, true);
	smp_wmb(); /* publish start state before ACAP_ENABLE */

	/* Kick HW */
	WRITE_ONCE(a->dma_armed, true);
	hws_enable_audio_capture(hws, ch, true);
	if (!READ_ONCE(a->cap_active)) {
		hws_audio_publish_stopped(a);
		return -ENODEV;
	}
	hws_audio_log_telemetry(a, "start", false);
	return 0;
}

static inline void hws_audio_ack_pending(struct hws_pcie_dev *hws, unsigned int ch)
{
	u32 abit = HWS_INT_ADONE_BIT(ch);
	u32 st;

	if (!hws || !hws->bar0_base || ch >= hws->cur_max_audio_ch)
		return;

	st = readl(hws->bar0_base + HWS_REG_INT_STATUS);

	if (st & abit) {
		writel(abit, hws->bar0_base + HWS_REG_INT_ACK);
		/* flush posted write */
		readl(hws->bar0_base + HWS_REG_INT_STATUS);
	}
}

static void hws_audio_discard_stale_done(struct hws_pcie_dev *hws,
					 struct hws_audio *a,
					 unsigned int ch)
{
	hws_audio_clear_pending(a);
	hws_audio_ack_pending(hws, ch);
}

static void hws_audio_disable_capture_and_ack(struct hws_pcie_dev *hws,
					      unsigned int ch)
{
	if (!hws || !hws->bar0_base || ch >= hws->cur_max_audio_ch)
		return;

	hws_enable_audio_capture(hws, ch, false);
	readl(hws->bar0_base + HWS_REG_INT_STATUS);
	hws_audio_ack_pending(hws, ch);
}

static inline void hws_audio_ack_all(struct hws_pcie_dev *hws)
{
	u32 mask = 0;

	if (!hws || !hws->bar0_base)
		return;

	for (unsigned int ch = 0; ch < hws->cur_max_audio_ch; ch++)
		mask |= HWS_INT_ADONE_BIT(ch);
	if (mask) {
		writel(mask, hws->bar0_base + HWS_REG_INT_ACK);
		readl(hws->bar0_base + HWS_REG_INT_STATUS);
	}
}

static void hws_stop_audio_capture(struct hws_pcie_dev *hws, unsigned int ch)
{
	struct hws_audio *a;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return;

	a = &hws->audio[ch];
	if (!READ_ONCE(a->stream_running) && !READ_ONCE(a->cap_active))
		return;

	hws_audio_log_telemetry(a, "stop", false);
	hws_audio_publish_stopped(a);
	hws_audio_disable_capture_and_ack(hws, ch);
	hws_audio_clear_pending(a);
	dev_dbg(&hws->pdev->dev, "audio capture stopped on ch %u\n", ch);
}

void hws_enable_audio_capture(struct hws_pcie_dev *hws,
			      unsigned int ch, bool enable)
{
	unsigned long flags;
	u32 reg, mask = BIT(ch);

	if (!hws || ch >= hws->cur_max_audio_ch)
		return;

	spin_lock_irqsave(&hws->capture_lock, flags);
	if (READ_ONCE(hws->dma_quiesced)) {
		WRITE_ONCE(hws->audio[ch].cap_active, false);
		spin_unlock_irqrestore(&hws->capture_lock, flags);
		return;
	}
	if (enable && (READ_ONCE(hws->pci_lost) ||
		       READ_ONCE(hws->suspended))) {
		WRITE_ONCE(hws->audio[ch].cap_active, false);
		spin_unlock_irqrestore(&hws->capture_lock, flags);
		return;
	}
	reg = readl(hws->bar0_base + HWS_REG_ACAP_ENABLE);
	if (enable)
		reg |= mask;
	else
		reg &= ~mask;

	writel(reg, hws->bar0_base + HWS_REG_ACAP_ENABLE);
	(void)readl(hws->bar0_base + HWS_REG_ACAP_ENABLE);
	spin_unlock_irqrestore(&hws->capture_lock, flags);

	dev_dbg(&hws->pdev->dev, "audio capture %s ch%u, reg=0x%08x\n",
		enable ? "enabled" : "disabled", ch, reg);
}

static snd_pcm_uframes_t hws_pcie_audio_pointer(struct snd_pcm_substream *substream)
{
	struct hws_audio *a = snd_pcm_substream_chip(substream);
	snd_pcm_uframes_t pos;
	unsigned long flags;

	spin_lock_irqsave(&a->ring_lock, flags);
	pos = a->ring_wpos_byframes;
	spin_unlock_irqrestore(&a->ring_lock, flags);
	return pos;
}

static int hws_pcie_audio_open(struct snd_pcm_substream *substream)
{
	struct hws_audio *a = snd_pcm_substream_chip(substream);
	struct snd_pcm_runtime *rt = substream->runtime;
	int ret;

	rt->hw = audio_pcm_hardware;

	ret = snd_pcm_hw_constraint_integer(rt, SNDRV_PCM_HW_PARAM_PERIODS);
	if (ret < 0)
		return ret;
	ret = snd_pcm_hw_constraint_step(rt, 0, SNDRV_PCM_HW_PARAM_PERIOD_BYTES,
					 HWS_AUDIO_PACKET_BYTES);
	if (ret < 0)
		return ret;
	ret = snd_pcm_hw_constraint_step(rt, 0, SNDRV_PCM_HW_PARAM_BUFFER_BYTES,
					 HWS_AUDIO_PACKET_BYTES);
	if (ret < 0)
		return ret;

	WRITE_ONCE(a->pcm_substream, substream);
	return 0;
}

static int hws_pcie_audio_close(struct snd_pcm_substream *substream)
{
	struct hws_audio *a = snd_pcm_substream_chip(substream);

	hws_audio_quiesce_capture(a->parent, a->channel_index, true);
	hws_audio_release_scratch(a, false);
	WRITE_ONCE(a->pcm_substream, NULL);
	return 0;
}

static int hws_pcie_audio_hw_params(struct snd_pcm_substream *substream,
				    struct snd_pcm_hw_params *hw_params)
{
	struct hws_audio *a = snd_pcm_substream_chip(substream);
	struct hws_pcie_dev *hws = a->parent;
	int ret;

	(void)hw_params;
	if (!hws)
		return -ENODEV;
	if (READ_ONCE(hws->suspended))
		return -EBUSY;

	ret = hws_check_card_status(hws);
	if (ret)
		return ret;

	ret = hws_audio_acquire_scratch(a);
	if (ret)
		return ret;

	ret = hws_guard_audio_video_remap_page(hws, a->channel_index);
	if (ret) {
		hws_audio_release_scratch(a, true);
		return ret;
	}

	return 0;
}

static int hws_pcie_audio_hw_free(struct snd_pcm_substream *substream)
{
	struct hws_audio *a = snd_pcm_substream_chip(substream);

	hws_audio_quiesce_capture(a->parent, a->channel_index, true);
	hws_audio_release_scratch(a, false);
	return 0;
}

static int hws_pcie_audio_prepare(struct snd_pcm_substream *substream)
{
	struct hws_audio *a = snd_pcm_substream_chip(substream);
	struct snd_pcm_runtime *rt = substream->runtime;
	unsigned long flags;
	size_t frame_bytes;
	int ret;

	ret = hws_audio_prepare_scratch(a, "audio prepare");
	if (ret)
		return ret;

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

	hws_audio_reset_counters(a);
	hws_audio_clear_pending(a);
	return 0;
}

static int hws_pcie_audio_trigger(struct snd_pcm_substream *substream, int cmd)
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
		return hws_start_audio_capture(hws, ch);
	case SNDRV_PCM_TRIGGER_SUSPEND:
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
	snprintf(card_name, sizeof(card_name), "HWS Embedded Audio %u",
		 hws->port_id);

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

	/* ---- Create one PCM capture device per embedded-audio input ---- */
	for (i = 0; i < hws->cur_max_audio_ch; i++) {
		char pcm_name[32];

		snprintf(pcm_name, sizeof(pcm_name), "Embedded In %d", i);

		/* device number = i, so userspace sees hw:X,i */
		ret = snd_pcm_new(card, pcm_name, i,
				  0 /* playback */, 1 /* capture */, &pcm);
		if (ret < 0) {
			dev_err(&hws->pdev->dev, "snd_pcm_new(%d) failed: %d\n", i, ret);
			goto error_card;
		}

		pcm->private_data = &hws->audio[i];
		strscpy(pcm->name, pcm_name, sizeof(pcm->name));
		snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_CAPTURE, &hws_pcie_pcm_ops);

		/* Allocate ALSA-managed DMA storage up to the advertised maximum. */
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
	dev_info(&hws->pdev->dev,
		 "audio registration complete (%d embedded inputs)\n",
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

		hws_audio_publish_stopped(a);
		hws_enable_audio_capture(hws, i, false);
	}

	/* Flush ACAP disables before waiting for any running IRQ handler. */
	if (hws->bar0_base)
		readl(hws->bar0_base + HWS_REG_INT_STATUS);
	if (hws->irq >= 0 && !in_interrupt())
		synchronize_irq(hws->irq);

	hws_audio_drain_work(hws);
	hws_audio_ack_all(hws);

	for (unsigned int i = 0; i < hws->cur_max_audio_ch; i++) {
		struct hws_audio *a = &hws->audio[i];
		struct snd_pcm_substream *ss = READ_ONCE(a->pcm_substream);

		if (ss) {
			unsigned long flags;

			snd_pcm_stream_lock_irqsave(ss, flags);
			if (ss->runtime)
				snd_pcm_stop(ss, SNDRV_PCM_STATE_DISCONNECTED);
			snd_pcm_stream_unlock_irqrestore(ss, flags);
		}

		WRITE_ONCE(a->pcm_substream, NULL);
		hws_audio_reset_runtime_state(a);
		hws_audio_release_scratch(a, false);
		hws_audio_free_staging(a);
	}

	if (hws->snd_card) {
		/* No PCM callback may outlive the final parent reference. */
		snd_card_free(hws->snd_card);
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
		struct snd_pcm_substream *ss = READ_ONCE(a->pcm_substream);
		struct snd_pcm *pcm;
		bool already = false;
		int r;

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

		r = snd_pcm_suspend_all(pcm);
		if (r && !ret)
			ret = r;

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
		int ret = 0;

		WRITE_ONCE(a->stream_running, false);
		WRITE_ONCE(a->cap_active, false);
		WRITE_ONCE(a->stop_requested, true);
		hws_audio_reset_counters(a);
		hws_audio_clear_pending(a);

		/* Suspend established device-global idle before entering D3. */
		mutex_lock(&a->scratch_state_lock);
		if (READ_ONCE(a->dma_armed))
			ret = hws_audio_reclaim_scratch_locked(a, true, "audio PM resume");
		if (!ret && READ_ONCE(a->scratch_acquired))
			ret = hws_audio_scratch_prepare(hws, ch);
		if (ret == -EOVERFLOW)
			WRITE_ONCE(a->scratch_corrupt, true);
		mutex_unlock(&a->scratch_state_lock);
		if (ret)
			dev_err(&hws->pdev->dev,
				"audio PM resume scratch validation failed ch=%u: %d\n",
				ch, ret);
	}
	hws_audio_ack_all(hws);
}

void hws_audio_drain_work(struct hws_pcie_dev *hws)
{
	unsigned int ch;

	if (!hws)
		return;

	for (ch = 0; ch < hws->cur_max_audio_ch && ch < MAX_VID_CHANNELS; ch++)
		hws_audio_drain_channel_work(&hws->audio[ch]);
}

void hws_audio_dma_fault_all(struct hws_pcie_dev *hws)
{
	unsigned int ch;

	/* No PCM can be live before the card has been registered. */
	if (!hws || !hws->snd_card)
		return;

	for (ch = 0; ch < hws->cur_max_audio_ch; ch++) {
		struct hws_audio *a = &hws->audio[ch];
		struct snd_pcm_substream *ss = READ_ONCE(a->pcm_substream);

		hws_audio_publish_stopped(a);
		hws_audio_clear_pending(a);
		if (ss && READ_ONCE(a->pcm_substream) == ss)
			snd_pcm_stop_xrun(ss);
	}
}
