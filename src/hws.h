/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_PCIE_H
#define HWS_PCIE_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/dma-mapping.h>
#include <linux/kthread.h>
#include <linux/pci.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/sizes.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/workqueue.h>

#include <sound/pcm.h>
#include <sound/core.h>

#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <media/v4l2-dv-timings.h>
#include <media/videobuf2-dma-sg.h>

#include "hws_reg.h"

struct snd_pcm_substream;

struct hwsmem_param {
	u32 index;
	u32 type;
	u32 status;
};

struct hws_pix_state {
	u32 width;
	u32 height;
	u32 fourcc;		/* V4L2_PIX_FMT_* (YUYV only here) */
	u32 bytesperline;	/* stride */
	u32 sizeimage;		/* full frame */
	enum v4l2_field field;	/* V4L2_FIELD_NONE or INTERLACED */
	enum v4l2_colorspace colorspace;	/* e.g., REC709 */
	enum v4l2_ycbcr_encoding ycbcr_enc;	/* V4L2_YCBCR_ENC_601 */
	enum v4l2_quantization quantization;	/* V4L2_QUANTIZATION_FULL_RANGE */
	enum v4l2_xfer_func xfer_func;	/* V4L2_XFER_FUNC_DEFAULT */
	bool interlaced;	/* cached hardware state */
	u32 half_size;		/* hardware half-frame size */
};

static inline void hws_set_pix_colorimetry(struct hws_pix_state *pix)
{
	bool sd = pix->height <= 576;

	/*
	 * Measurements show BT.601 Y'CbCr coefficients and full range at both
	 * SD and HD. Keep resolution-derived primaries/transfer metadata, but
	 * explicitly describe the matrix used for the captured YUYV samples.
	 */
	pix->colorspace = sd ? V4L2_COLORSPACE_SMPTE170M :
				 V4L2_COLORSPACE_REC709;
	pix->ycbcr_enc = V4L2_YCBCR_ENC_601;
	pix->quantization = V4L2_QUANTIZATION_FULL_RANGE;
	pix->xfer_func = V4L2_XFER_FUNC_DEFAULT;
}

static inline u32 hws_yuyv_packed_stride(u32 width)
{
	return width * 2;
}

static inline u64 hws_yuyv_packed_size(u32 width, u32 height)
{
	return (u64)hws_yuyv_packed_stride(width) * height;
}

static inline u32 hws_video_native_split(u32 frame_size)
{
	return round_down(frame_size / 2, (u32)SZ_2K);
}

/* Hardware characterization shows a write tail beyond packed sizeimage. */
#define HWS_VIDEO_DMA_TAIL_BYTES SZ_2K

/* Lifecycle paths drain W1C causes while every producer is disabled. */
#define HWS_IRQ_CLEAR_RETRIES 8U

static inline bool hws_yuyv_layout_valid(const struct hws_pix_state *pix)
{
	u64 stride, size;
	u32 split;

	if (!pix || pix->fourcc != V4L2_PIX_FMT_YUYV ||
	    pix->width < MIN_VIDEO_HW_W || pix->width > MAX_VIDEO_HW_W ||
	    pix->height < MIN_VIDEO_HW_H || pix->height > MAX_VIDEO_HW_H ||
	    !IS_ALIGNED(pix->width, 2) || pix->interlaced ||
	    pix->field != V4L2_FIELD_NONE)
		return false;

	stride = (u64)pix->width * 2;
	size = stride * pix->height;
	split = size <= U32_MAX ? hws_video_native_split((u32)size) : 0;
	return stride <= U32_MAX && size <= U32_MAX &&
		size <= MAX_VIDEO_SCALER_SIZE && split && split < size &&
		pix->bytesperline == stride && pix->sizeimage == size &&
		pix->half_size == split;
}

#define	UNSET	(-1U)

struct hws_pcie_dev;
struct hws_adapter;
struct hws_video;

struct hwsvideo_buffer {
	struct vb2_v4l2_buffer vb;
	struct list_head list;
};

enum hws_video_completion_state {
	HWS_VIDEO_COMPLETION_IDLE,
	HWS_VIDEO_COMPLETION_PENDING,
	HWS_VIDEO_COMPLETION_COPYING,
	HWS_VIDEO_COMPLETION_OVERRUN,
};

enum hws_video_half_phase {
	HWS_VIDEO_PHASE_SYNC,
	HWS_VIDEO_PHASE_EXPECT_HALF0,
	HWS_VIDEO_PHASE_EXPECT_HALF1,
};

struct hws_video {
	/* Linkage */
	struct hws_pcie_dev *parent;
	struct video_device *video_device;

	struct vb2_queue buffer_queue;
	bool queue_initialized;
	struct list_head capture_queue;
	struct work_struct vdone_work;
	struct work_struct recovery_work;
	/* VB2 buffer receiving the current ordered half pair. */
	struct hwsvideo_buffer *active;
	u64 completion_timestamp_ns;
	u64 completion_deadline_ns;
	u64 completion_generation;
	u64 next_completion_generation;
	enum hws_video_completion_state completion_state;
	u8 completion_toggle;
	enum hws_video_half_phase half_phase;
	u8 sync_events;
	u8 sync_restart_streak;
	bool sync_account_frames;
	u64 phase_generation;
	u64 frame_generation;
	bool frame_half0_valid;
	size_t ring_extent;
	size_t ring_split;

	/* Locking */
	struct mutex state_lock;
	spinlock_t irq_lock;	/* Protects capture_queue and active buffers. */

	/* Indices */
	int channel_index;

	/* Color controls */
	int current_brightness;
	int current_contrast;
	int current_saturation;
	int current_hue;

	/* V4L2 controls */
	struct v4l2_ctrl_handler control_handler;
	struct v4l2_ctrl *ctrl_brightness;
	struct v4l2_ctrl *ctrl_contrast;
	struct v4l2_ctrl *ctrl_saturation;
	struct v4l2_ctrl *ctrl_hue;
	struct v4l2_ctrl *ctrl_dv_rx_power_present;

	/* Capture queue status */
	struct hws_pix_state pix;
	struct v4l2_dv_timings cur_dv_timings; /* configured DV timings */
	struct v4l2_dv_timings detected_dv_timings;
	int detected_dv_status;
	u32 detected_fps;
	bool source_state_initialized;
	u32 current_fps; /* configured/active rate used by the completion deadline */

	/* Per-channel capture state */
	bool cap_active;
	bool stop_requested;
	bool dma_needs_idle;
	bool ring_corrupt;
	u8 last_buf_half_toggle;
	bool half_seen;
	u64 last_vdone_timestamp_ns;
	/* Verified full hardware frames, including frames without a VB2 buffer. */
	atomic_t sequence_number;
	u32 queued_count;

	/* Timeout and error handling */
	u32 timeout_count;
	u32 error_count;
	u32 completion_overruns;
	u32 w1c_ambiguities;
	u32 toggle_resamples;
	u32 toggle_sample_errors;
	u32 sync_restarts;
	u32 duplicate_recoveries;
	u32 recovery_reports_pending;
	u64 recovery_report_generation;
	u64 recovery_report_interval_us;
	u8 recovery_report_toggle;
	u8 recovery_report_attempt;
	u8 recovery_report_reason;
	bool recovery_report_dropped_partial;
	bool recovery_report_steady;
	u32 phase_errors;
	u32 deadline_misses;
	u32 guard_errors;

	bool window_valid;
	u32 last_dma_hi;
	u32 last_dma_page;
	u32 last_pci_addr;
	u32 last_half16;

	/* Misc counters */
	int signal_loss_cnt;
};

enum hws_audio_packet_state {
	HWS_AUDIO_PACKET_IDLE,
	HWS_AUDIO_PACKET_PENDING,
	HWS_AUDIO_PACKET_COPYING,
	HWS_AUDIO_PACKET_XRUN,
};

enum hws_audio_xrun_reason {
	HWS_AUDIO_XRUN_NONE,
	HWS_AUDIO_XRUN_PACKET_IN_FLIGHT,
	HWS_AUDIO_XRUN_DUPLICATE_TOGGLE,
	HWS_AUDIO_XRUN_IRQ_TIMESTAMP,
	HWS_AUDIO_XRUN_CADENCE,
	HWS_AUDIO_XRUN_W1C_STATUS_REASSERTED,
	HWS_AUDIO_XRUN_W1C_TOGGLE_UNSTABLE,
	HWS_AUDIO_XRUN_W1C_TOGGLE_CHANGED,
	HWS_AUDIO_XRUN_WORK_DEADLINE,
	HWS_AUDIO_XRUN_POST_COPY_TOGGLE,
	HWS_AUDIO_XRUN_GENERATION,
	HWS_AUDIO_XRUN_STREAM_STATE,
	HWS_AUDIO_XRUN_SUBSTREAM_MISSING,
	HWS_AUDIO_XRUN_RUNTIME_MISSING,
	HWS_AUDIO_XRUN_RING_INVALID,
	HWS_AUDIO_XRUN_SCRATCH_MISSING,
	HWS_AUDIO_XRUN_SCRATCH_BOUNDS,
	HWS_AUDIO_XRUN_STAGING_MISSING,
	HWS_AUDIO_XRUN_WORKQUEUE_MISSING,
	HWS_AUDIO_XRUN_DMA_GUARD,
};

struct hws_audio {
	/* linkage */
	struct hws_pcie_dev *parent;
	int channel_index;

	/* ALSA */
	struct snd_pcm_substream *pcm_substream;
	spinlock_t ring_lock; /* protects ring and period position fields */
	snd_pcm_uframes_t ring_size_byframes;
	snd_pcm_uframes_t ring_wpos_byframes;
	snd_pcm_uframes_t period_size_byframes;
	snd_pcm_uframes_t period_used_byframes;
	size_t frame_bytes;
	size_t hw_packet_bytes;
	void *staging_buffer;
	size_t staging_size;

	/* stream state */
	bool cap_active;
	bool stream_running;
	bool stop_requested;
	struct mutex scratch_state_lock; /* protects scratch ownership/quarantine */
	bool scratch_acquired;
	bool dma_armed; /* scratch remains quarantined until DMA idle is proved */

	/* minimal HW packet tracking */
	struct work_struct deliver_work;
	spinlock_t pending_lock; /* protects packet/cadence/generation state */
	enum hws_audio_packet_state packet_state;
	u8 pending_toggle;
	bool pending_publish;
	u64 pending_irq_ns;
	u64 pending_generation;
	u64 next_generation;
	u8 last_irq_toggle;
	u64 last_irq_ns;
	u64 last_irq_interval_ns;
	u32 irq_count;
	u32 delivered_count;
	u32 primed_packets;
	u32 dropped_packets;
	u32 cadence_errors;
	u32 w1c_ambiguities;
	u32 toggle_errors;
	u32 generation_errors;
	u32 deadline_misses;
	u32 guard_errors;
	size_t observed_dma_extent;
	u64 last_work_latency_ns;
	u64 max_work_latency_ns;
	enum hws_audio_xrun_reason xrun_reason;
	bool scratch_corrupt;

	/* PCM format */
	u32 output_sample_rate;
	u16 channel_count;
	u16 bits_per_sample;
};

struct hws_scratch_dma {
	void *cpu;
	dma_addr_t dma;
	size_t size;
	bool owned;
};

struct hws_pcie_dev {
	/* Core objects */
	struct pci_dev *pdev;
	struct hws_audio audio[MAX_VID_CHANNELS];
	struct hws_video video[MAX_VID_CHANNELS];

	/* BAR and workqueues */
	void __iomem *bar0_base;
	struct workqueue_struct *video_wq;
	struct workqueue_struct *audio_wq;

	/* Device identity and capabilities */
	u16 vendor_id;
	u16 device_id;
	u16 device_ver;
	u16 hw_ver;
	u32 sub_ver;
	u32 port_id;
	/* Tri-state support flag used by set_video_format_size(). */
	u32 support_yv12;
	u32 max_hw_video_buf_sz;
	u8 max_channels;
	u8 cur_max_video_ch;
	/* Independently capturable embedded audio inputs exposed as ALSA PCMs. */
	u8 cur_max_audio_ch;
	bool start_run;

	bool buf_allocated;
	u32 audio_pkt_size;

	/* V4L2 framework objects */
	struct v4l2_device v4l2_device;
	bool v4l2_ref_held;

	struct snd_card *snd_card;

	/* Kernel thread */
	struct task_struct *main_task;
	struct mutex monitor_lock; /* serializes monitor and lifecycle changes */
	struct mutex dma_lock; /* serializes DMA-idle checks and fatal shutdown */
	bool dma_quiesced; /* no device DMA can still target host memory */
	bool dma_failed; /* fatal shutdown invalidated all stream ownership */
	struct mutex scratch_lock; /* protects scratch DMA arenas and user refs */
	unsigned int scratch_users[MAX_VID_CHANNELS];
	struct hws_scratch_dma scratch_vid[MAX_VID_CHANNELS];
	struct hws_scratch_dma scratch_aud[MAX_VID_CHANNELS];

	bool suspended;
	int irq;
	spinlock_t capture_lock; /* serializes capture-enable register updates */

	/* Error flags */
	int pci_lost;
	struct kref lifetime_ref;
};

static inline bool hws_dma_fits_remap_window(dma_addr_t dma, size_t size)
{
	dma_addr_t end;

	if (!size)
		return false;

	end = dma + size - 1;
	if (end < dma)
		return false;

	return upper_32_bits(dma) == upper_32_bits(end) &&
	       (lower_32_bits(dma) & PCI_E_BAR_ADD_MASK) ==
	       (lower_32_bits(end) & PCI_E_BAR_ADD_MASK);
}

int hws_alloc_channel_scratch(struct hws_pcie_dev *hws, unsigned int ch);
void hws_release_channel_scratch(struct hws_pcie_dev *hws, unsigned int ch);
void *hws_video_ring_cpu(struct hws_pcie_dev *hws, unsigned int ch);
dma_addr_t hws_video_ring_dma(struct hws_pcie_dev *hws, unsigned int ch);
size_t hws_video_ring_capacity(void);
int hws_video_ring_prepare(struct hws_pcie_dev *hws, unsigned int ch,
			   size_t extent);
bool hws_video_ring_guards_ok(struct hws_pcie_dev *hws, unsigned int ch,
			      size_t extent);
size_t hws_audio_dma_capacity(void);
int hws_audio_scratch_prepare(struct hws_pcie_dev *hws, unsigned int ch);
int hws_audio_scratch_verify(struct hws_pcie_dev *hws, unsigned int ch,
			     size_t *observed_extent);
int hws_try_wait_dma_idle(struct hws_pcie_dev *hws, const char *owner, int ch);
int hws_wait_dma_idle(struct hws_pcie_dev *hws, const char *owner, int ch);
void hws_get_device(struct hws_pcie_dev *hws);
void hws_put_device(struct hws_pcie_dev *hws);

#endif
