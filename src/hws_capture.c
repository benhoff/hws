// SPDX-License-Identifier: GPL-2.0-only
#include <linux/io.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>

#include <media/videobuf2-dma-contig.h>
#include <media/videobuf2-v4l2.h>

#include "hws.h"
#include "hws_capture.h"
#include "hws_video.h"
#include "hws_reg.h"

static void hws_return_buffer_to_ctx_head(struct hws_vfh_ctx *ctx,
					  struct hwsvideo_buffer *buf)
{
	unsigned long flags;

	if (!ctx || !buf)
		return;

	spin_lock_irqsave(&ctx->qlock, flags);
	list_add(&buf->list, &ctx->buf_queue);
	spin_unlock_irqrestore(&ctx->qlock, flags);
}

static void hws_clear_pending_locked(struct hws_video *vid)
{
	lockdep_assert_held(&vid->state_lock);
	vid->engine.pending_mode = HWS_CAPTURE_MODE_NONE;
	vid->engine.pending_direct_owner = NULL;
	WRITE_ONCE(vid->engine.mode_pending, false);
}

static void hws_collect_direct_done_locked(struct hws_video *vid,
					   struct list_head *done)
{
	lockdep_assert_held(&vid->irq_lock);
	if (vid->engine.active) {
		INIT_LIST_HEAD(&vid->engine.active->list);
		list_add_tail(&vid->engine.active->list, done);
		vid->engine.active = NULL;
	}
	if (vid->engine.next_prepared) {
		list_add_tail(&vid->engine.next_prepared->list, done);
		vid->engine.next_prepared = NULL;
	}
}

static void hws_complete_done_list(struct list_head *done,
				   enum vb2_buffer_state state)
{
	struct hwsvideo_buffer *buf, *tmp;

	list_for_each_entry_safe(buf, tmp, done, list) {
		list_del_init(&buf->list);
		vb2_buffer_done(&buf->vb.vb2_buf, state);
	}
}

static void hws_quiesce_engine_locked(struct hws_video *vid)
{
	lockdep_assert_held(&vid->state_lock);

	WRITE_ONCE(vid->cap_active, false);
	WRITE_ONCE(vid->stop_requested, true);
	hws_enable_video_capture(vid->parent, vid->channel_index, false);
}

static int hws_fanout_alloc(struct hws_video *vid, size_t need)
{
	struct hws_pcie_dev *hws = vid->parent;
	void *cpu;

	need = PAGE_ALIGN(need);
	if (!need)
		return -EINVAL;

	if (vid->engine.fanout_cpu && vid->engine.fanout_size >= need)
		return 0;

	if (vid->engine.fanout_cpu) {
		dma_free_coherent(&hws->pdev->dev, vid->engine.fanout_size,
				  vid->engine.fanout_cpu,
				  vid->engine.fanout_dma);
		vid->engine.fanout_cpu = NULL;
		vid->engine.fanout_size = 0;
	}

	cpu = dma_alloc_coherent(&hws->pdev->dev, need,
				 &vid->engine.fanout_dma, GFP_KERNEL);
	if (!cpu)
		return -ENOMEM;

	vid->engine.fanout_cpu = cpu;
	vid->engine.fanout_size = need;
	memset(vid->engine.fanout_cpu, 0x10, need);
	return 0;
}

static void hws_fanout_free(struct hws_video *vid)
{
	struct hws_pcie_dev *hws = vid->parent;

	if (!vid->engine.fanout_cpu)
		return;

	dma_free_coherent(&hws->pdev->dev, vid->engine.fanout_size,
			  vid->engine.fanout_cpu,
			  vid->engine.fanout_dma);
	vid->engine.fanout_cpu = NULL;
	vid->engine.fanout_size = 0;
}

void hws_capture_engine_init(struct hws_video *vid)
{
	atomic_set(&vid->engine.sequence_number, 0);
	vid->engine.active = NULL;
	vid->engine.next_prepared = NULL;
	vid->engine.mode = HWS_CAPTURE_MODE_NONE;
	vid->engine.direct_owner = NULL;
	vid->engine.pending_mode = HWS_CAPTURE_MODE_NONE;
	vid->engine.pending_direct_owner = NULL;
	vid->engine.mode_pending = false;
	vid->engine.fanout_cpu = NULL;
	vid->engine.fanout_dma = (dma_addr_t)0;
	vid->engine.fanout_size = 0;
}

void hws_capture_engine_cleanup(struct hws_video *vid)
{
	hws_fanout_free(vid);
	hws_capture_engine_init(vid);
}

struct hwsvideo_buffer *hws_take_direct_buffer_locked(struct hws_video *vid)
{
	struct hws_vfh_ctx *owner;
	struct hwsvideo_buffer *buf;
	unsigned long flags;

	if (!vid)
		return NULL;

	owner = READ_ONCE(vid->engine.direct_owner);
	if (!owner)
		return NULL;

	spin_lock_irqsave(&owner->qlock, flags);
	buf = NULL;
	if (!list_empty(&owner->buf_queue)) {
		buf = list_first_entry(&owner->buf_queue,
				       struct hwsvideo_buffer, list);
		list_del_init(&buf->list);
	}
	spin_unlock_irqrestore(&owner->qlock, flags);
	return buf;
}

void hws_prime_next_locked(struct hws_video *vid)
{
	struct hws_pcie_dev *hws;
	struct hwsvideo_buffer *next;
	dma_addr_t dma;

	if (!vid)
		return;

	hws = vid->parent;
	if (!hws || !hws->bar0_base)
		return;

	if (READ_ONCE(vid->engine.mode) != HWS_CAPTURE_MODE_DIRECT)
		return;
	if (!READ_ONCE(vid->cap_active) || !vid->engine.active ||
	    vid->engine.next_prepared || READ_ONCE(vid->engine.mode_pending))
		return;

	next = hws_take_direct_buffer_locked(vid);
	if (!next)
		return;

	vid->engine.next_prepared = next;
	dma = vb2_dma_contig_plane_dma_addr(&next->vb.vb2_buf, 0);
	hws_program_dma_for_addr(hws, vid->channel_index, dma);
	iowrite32(lower_32_bits(dma),
		  hws->bar0_base + HWS_REG_DMA_ADDR(vid->channel_index));
	dev_dbg(&hws->pdev->dev,
		"ch%u pre-armed next buffer %p dma=0x%llx\n",
		vid->channel_index, next, (u64)dma);
}

void hws_capture_engine_stop_locked(struct hws_video *vid)
{
	unsigned long flags;
	LIST_HEAD(done);

	lockdep_assert_held(&vid->state_lock);

	hws_quiesce_engine_locked(vid);

	spin_lock_irqsave(&vid->irq_lock, flags);
	hws_collect_direct_done_locked(vid, &done);
	spin_unlock_irqrestore(&vid->irq_lock, flags);

	hws_complete_done_list(&done, VB2_BUF_STATE_ERROR);
}

static int hws_start_direct_locked(struct hws_video *vid)
{
	struct hws_pcie_dev *hws = vid->parent;
	struct hwsvideo_buffer *to_program = NULL;
	struct vb2_buffer *prog_vb2 = NULL;
	unsigned long flags;
	int ret;

	lockdep_assert_held(&vid->state_lock);

	ret = hws_check_card_status(hws);
	if (ret)
		return ret;

	atomic_set(&vid->engine.sequence_number, 0);
	WRITE_ONCE(vid->stop_requested, false);
	WRITE_ONCE(vid->cap_active, true);
	WRITE_ONCE(vid->half_seen, false);
	WRITE_ONCE(vid->last_buf_half_toggle, 0);

	spin_lock_irqsave(&vid->irq_lock, flags);
	if (!vid->engine.active) {
		to_program = hws_take_direct_buffer_locked(vid);
		if (to_program)
			vid->engine.active = to_program;
	}
	if (vid->engine.active) {
		to_program = vid->engine.active;
		prog_vb2 = &to_program->vb.vb2_buf;
	}
	spin_unlock_irqrestore(&vid->irq_lock, flags);

	if (!to_program)
		return 0;

	{
		dma_addr_t dma_addr = vb2_dma_contig_plane_dma_addr(prog_vb2, 0);

		hws_program_dma_for_addr(hws, vid->channel_index, dma_addr);
		iowrite32(lower_32_bits(dma_addr),
			  hws->bar0_base + HWS_REG_DMA_ADDR(vid->channel_index));
		wmb();
		hws_enable_video_capture(hws, vid->channel_index, true);
		spin_lock_irqsave(&vid->irq_lock, flags);
		hws_prime_next_locked(vid);
		spin_unlock_irqrestore(&vid->irq_lock, flags);
	}

	return 0;
}

static int hws_start_fanout_locked(struct hws_video *vid)
{
	struct hws_pcie_dev *hws = vid->parent;
	dma_addr_t dma_addr;
	int ret;

	lockdep_assert_held(&vid->state_lock);

	ret = hws_check_card_status(hws);
	if (ret)
		return ret;

	ret = hws_fanout_alloc(vid, max_t(size_t, vid->pix.sizeimage, PAGE_SIZE));
	if (ret)
		return ret;

	atomic_set(&vid->engine.sequence_number, 0);
	WRITE_ONCE(vid->stop_requested, false);
	WRITE_ONCE(vid->cap_active, true);
	WRITE_ONCE(vid->half_seen, false);
	WRITE_ONCE(vid->last_buf_half_toggle, 0);

	dma_addr = vid->engine.fanout_dma;
	hws_program_dma_for_addr(hws, vid->channel_index, dma_addr);
	iowrite32(lower_32_bits(dma_addr),
		  hws->bar0_base + HWS_REG_DMA_ADDR(vid->channel_index));
	wmb();
	hws_enable_video_capture(hws, vid->channel_index, true);
	return 0;
}

static bool hws_ctx_supports_fanout(const struct hws_vfh_ctx *ctx)
{
	return ctx && ctx->vbq.memory == VB2_MEMORY_MMAP;
}

static bool hws_all_streamers_support_fanout_locked(struct hws_video *vid)
{
	struct hws_vfh_ctx *ctx;
	unsigned long flags;
	bool supported = true;

	spin_lock_irqsave(&vid->consumers_lock, flags);
	list_for_each_entry(ctx, &vid->consumers, node) {
		if (!ctx->streaming)
			continue;
		if (!hws_ctx_supports_fanout(ctx)) {
			supported = false;
			break;
		}
	}
	spin_unlock_irqrestore(&vid->consumers_lock, flags);
	return supported;
}

static unsigned int
hws_count_streaming_ctxs_locked(struct hws_video *vid,
				struct hws_vfh_ctx **single_streamer)
{
	struct hws_vfh_ctx *ctx;
	unsigned long flags;
	unsigned int count = 0;
	struct hws_vfh_ctx *single = NULL;

	spin_lock_irqsave(&vid->consumers_lock, flags);
	list_for_each_entry(ctx, &vid->consumers, node) {
		if (!ctx->streaming)
			continue;
		count++;
		single = ctx;
	}
	spin_unlock_irqrestore(&vid->consumers_lock, flags);

	if (single_streamer)
		*single_streamer = (count == 1) ? single : NULL;
	return count;
}

static int hws_apply_target_locked(struct hws_video *vid,
				   enum hws_capture_mode target,
				   struct hws_vfh_ctx *direct_owner)
{
	int ret = 0;

	lockdep_assert_held(&vid->state_lock);

	if (target != HWS_CAPTURE_MODE_FANOUT)
		hws_fanout_free(vid);

	vid->engine.direct_owner = NULL;
	WRITE_ONCE(vid->engine.mode, HWS_CAPTURE_MODE_NONE);

	if (target == HWS_CAPTURE_MODE_NONE)
		return 0;

	if (target == HWS_CAPTURE_MODE_DIRECT) {
		vid->engine.direct_owner = direct_owner;
		WRITE_ONCE(vid->engine.mode, HWS_CAPTURE_MODE_DIRECT);
		ret = hws_start_direct_locked(vid);
		if (ret) {
			WRITE_ONCE(vid->engine.mode, HWS_CAPTURE_MODE_NONE);
			vid->engine.direct_owner = NULL;
		}
		return ret;
	}

	WRITE_ONCE(vid->engine.mode, HWS_CAPTURE_MODE_FANOUT);
	ret = hws_start_fanout_locked(vid);
	if (ret) {
		WRITE_ONCE(vid->engine.mode, HWS_CAPTURE_MODE_NONE);
		hws_fanout_free(vid);
	}
	return ret;
}

void hws_capture_kick_direct_locked(struct hws_video *vid)
{
	struct hws_pcie_dev *hws = vid->parent;
	struct hwsvideo_buffer *to_program = NULL;
	dma_addr_t dma_addr;
	unsigned long flags;

	lockdep_assert_held(&vid->state_lock);

	if (READ_ONCE(vid->engine.mode) != HWS_CAPTURE_MODE_DIRECT)
		return;
	if (!READ_ONCE(vid->cap_active))
		return;
	if (!READ_ONCE(vid->engine.direct_owner))
		return;

	spin_lock_irqsave(&vid->irq_lock, flags);
	if (!vid->engine.active) {
		to_program = hws_take_direct_buffer_locked(vid);
		if (to_program)
			vid->engine.active = to_program;
	}
	if (vid->engine.active)
		hws_prime_next_locked(vid);
	spin_unlock_irqrestore(&vid->irq_lock, flags);

	if (!to_program)
		return;

	dma_addr = vb2_dma_contig_plane_dma_addr(&to_program->vb.vb2_buf, 0);
	hws_program_dma_for_addr(hws, vid->channel_index, dma_addr);
	iowrite32(lower_32_bits(dma_addr),
		  hws->bar0_base + HWS_REG_DMA_ADDR(vid->channel_index));
	wmb();
	hws_enable_video_capture(hws, vid->channel_index, true);
}

bool hws_capture_has_pending(const struct hws_video *vid)
{
	return vid && READ_ONCE(vid->engine.mode_pending);
}

static bool hws_capture_can_apply_pending_locked(struct hws_video *vid)
{
	lockdep_assert_held(&vid->state_lock);

	if (!hws_capture_has_pending(vid))
		return false;

	switch (READ_ONCE(vid->engine.mode)) {
	case HWS_CAPTURE_MODE_NONE:
		return true;
	case HWS_CAPTURE_MODE_DIRECT:
		return !vid->engine.active && !vid->engine.next_prepared;
	case HWS_CAPTURE_MODE_FANOUT:
		return true;
	default:
		return false;
	}
}

int hws_capture_apply_pending_locked(struct hws_video *vid)
{
	enum hws_capture_mode mode_cur;
	enum hws_capture_mode target;
	struct hws_vfh_ctx *direct_owner;
	int ret;

	lockdep_assert_held(&vid->state_lock);

	if (!hws_capture_can_apply_pending_locked(vid))
		return 0;

	mode_cur = READ_ONCE(vid->engine.mode);
	target = vid->engine.pending_mode;
	direct_owner = vid->engine.pending_direct_owner;

	if (mode_cur == target &&
	    (target != HWS_CAPTURE_MODE_DIRECT ||
	     READ_ONCE(vid->engine.direct_owner) == direct_owner)) {
		hws_clear_pending_locked(vid);
		if (target == HWS_CAPTURE_MODE_DIRECT)
			hws_capture_kick_direct_locked(vid);
		return 1;
	}

	hws_clear_pending_locked(vid);
	hws_quiesce_engine_locked(vid);
	ret = hws_apply_target_locked(vid, target, direct_owner);
	if (ret)
		hws_set_all_queues_error(vid);
	return ret ? ret : 1;
}

void hws_capture_prepare_reconfigure_locked(struct hws_video *vid)
{
	struct hws_vfh_ctx *owner;
	unsigned long flags;

	lockdep_assert_held(&vid->state_lock);

	if (READ_ONCE(vid->engine.mode) != HWS_CAPTURE_MODE_DIRECT)
		return;

	owner = READ_ONCE(vid->engine.direct_owner);

	spin_lock_irqsave(&vid->irq_lock, flags);
	if (vid->engine.next_prepared && owner) {
		struct hwsvideo_buffer *buf = vid->engine.next_prepared;

		vid->engine.next_prepared = NULL;
		INIT_LIST_HEAD(&buf->list);
		spin_unlock_irqrestore(&vid->irq_lock, flags);
		hws_return_buffer_to_ctx_head(owner, buf);
		return;
	}
	spin_unlock_irqrestore(&vid->irq_lock, flags);
}

int hws_capture_restart_after_reconfigure_locked(struct hws_video *vid)
{
	lockdep_assert_held(&vid->state_lock);

	switch (READ_ONCE(vid->engine.mode)) {
	case HWS_CAPTURE_MODE_NONE:
		return 0;
	case HWS_CAPTURE_MODE_DIRECT:
		return hws_start_direct_locked(vid);
	case HWS_CAPTURE_MODE_FANOUT:
		return hws_start_fanout_locked(vid);
	default:
		return -EINVAL;
	}
}

int hws_capture_recompute_stream_mode_locked(struct hws_video *vid,
					     struct hws_vfh_ctx *ctx,
					     bool stopping)
{
	struct hws_vfh_ctx *single = NULL;
	unsigned int streamers;
	enum hws_capture_mode target;
	enum hws_capture_mode mode_cur;
	int ret;

	lockdep_assert_held(&vid->state_lock);

	mode_cur = READ_ONCE(vid->engine.mode);
	streamers = hws_count_streaming_ctxs_locked(vid, &single);
	if (streamers == 0)
		target = HWS_CAPTURE_MODE_NONE;
	else if (streamers == 1)
		target = HWS_CAPTURE_MODE_DIRECT;
	else
		target = HWS_CAPTURE_MODE_FANOUT;

	if (target == HWS_CAPTURE_MODE_FANOUT &&
	    !hws_all_streamers_support_fanout_locked(vid))
		return -EOPNOTSUPP;

	if (target == mode_cur &&
	    (target != HWS_CAPTURE_MODE_DIRECT ||
	     READ_ONCE(vid->engine.direct_owner) == single)) {
		hws_clear_pending_locked(vid);
		if (target == HWS_CAPTURE_MODE_DIRECT)
			hws_capture_kick_direct_locked(vid);
		return 0;
	}

	if (mode_cur == HWS_CAPTURE_MODE_NONE) {
		hws_clear_pending_locked(vid);
		return hws_apply_target_locked(vid, target, single);
	}

	if (target == HWS_CAPTURE_MODE_NONE) {
		hws_clear_pending_locked(vid);
		hws_capture_engine_stop_locked(vid);
		hws_capture_engine_cleanup(vid);
		return 0;
	}

	if (mode_cur == HWS_CAPTURE_MODE_DIRECT &&
	    stopping && READ_ONCE(vid->engine.direct_owner) == ctx) {
		hws_clear_pending_locked(vid);
		hws_capture_engine_stop_locked(vid);
		hws_capture_engine_cleanup(vid);
		return hws_apply_target_locked(vid, target, single);
	}

	vid->engine.pending_mode = target;
	vid->engine.pending_direct_owner =
		(target == HWS_CAPTURE_MODE_DIRECT) ? single : NULL;
	WRITE_ONCE(vid->engine.mode_pending, true);

	if (mode_cur == HWS_CAPTURE_MODE_DIRECT &&
	    !vid->engine.active && !vid->engine.next_prepared) {
		ret = hws_capture_apply_pending_locked(vid);
		return ret < 0 ? ret : 0;
	}

	return 0;
}
