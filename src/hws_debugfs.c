// SPDX-License-Identifier: GPL-2.0-only
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include "hws.h"
#include "hws_timing.h"
#include "hws_debugfs.h"
#include "hws_reg.h"
#include "hws_probe.h"

struct hws_video_evidence_snapshot {
	u64 stream_epoch;
	u64 vdone_observed;
	u64 vdone_ignored;
	u64 vdone_accepted;
	u64 vdone_deferred;
	u64 vdone_resynced;
	u64 vdone_recovered;
	u64 vdone_fatal;
	u64 completed_half0;
	u64 completed_half1;
	u64 frames_completed;
	u64 frames_delivered;
	u64 frames_no_buffer;
	u64 partial_recycles;
	u64 recovery_reports;
	u64 duplicate_reports;
	u64 overlap_reports;
	u64 continuity_reports;
	u64 continuity_gaps;
	u64 resync_reports;
	u64 queue_failures;
	u64 generation;
	u32 probe_count;
	u32 probe_reads, anomaly_windows, anomaly_records, anomaly_triggers;
	u32 anomaly_suppressed;
	u32 sequence;
	u32 completion_overruns;
	u32 w1c_ambiguities;
	u32 toggle_resamples;
	u32 toggle_sample_errors;
	u32 sync_restarts;
	u32 duplicate_recoveries;
	u32 overlap_recoveries;
	u32 phase_errors;
	u32 deadline_misses;
	u32 guard_errors;
	u8 phase;
	bool streaming;
	bool cap_active;
	bool stop_requested;
	bool ring_corrupt;
};

static void hws_debugfs_snapshot(struct hws_video *v,
				 struct hws_video_evidence_snapshot *s)
{
	unsigned long flags;

	memset(s, 0, sizeof(*s));
	spin_lock_irqsave(&v->irq_lock, flags);
	s->stream_epoch = v->evidence_stream_epoch;
	s->vdone_observed = v->evidence_vdone_observed;
	s->vdone_ignored = v->evidence_vdone_ignored;
	s->vdone_accepted = v->evidence_vdone_accepted;
	s->vdone_deferred = v->evidence_vdone_deferred;
	s->vdone_resynced = v->evidence_vdone_resynced;
	s->vdone_recovered = v->evidence_vdone_recovered;
	s->vdone_fatal = v->evidence_vdone_fatal;
	s->completed_half0 = v->evidence_completed_half[0];
	s->completed_half1 = v->evidence_completed_half[1];
	s->frames_completed = v->evidence_frames_completed;
	s->frames_delivered = v->evidence_frames_delivered;
	s->frames_no_buffer = v->evidence_frames_no_buffer;
	s->partial_recycles = v->evidence_partial_recycles;
	s->recovery_reports = v->evidence_recovery_reports;
	s->duplicate_reports = v->evidence_duplicate_reports;
	s->overlap_reports = v->evidence_overlap_reports;
	s->continuity_reports = v->evidence_continuity_reports;
	s->continuity_gaps = v->continuity_gaps;
	s->resync_reports = v->evidence_resync_reports;
	s->queue_failures = v->evidence_queue_failures;
	s->generation = v->next_completion_generation;
	s->probe_count = v->evidence_probe_count;
	s->probe_reads = v->evidence_probe.reads;
	s->anomaly_windows = v->evidence_probe.windows;
	s->anomaly_records = v->evidence_probe.records;
	s->anomaly_triggers = v->evidence_probe.triggers;
	s->anomaly_suppressed = v->evidence_probe.suppressed;
	s->sequence = (u32)atomic_read(&v->sequence_number);
	s->completion_overruns = v->completion_overruns;
	s->w1c_ambiguities = v->w1c_ambiguities;
	s->toggle_resamples = v->toggle_resamples;
	s->toggle_sample_errors = v->toggle_sample_errors;
	s->sync_restarts = v->sync_restarts;
	s->duplicate_recoveries = v->duplicate_recoveries;
	s->overlap_recoveries = v->overlap_recoveries;
	s->phase_errors = v->phase_errors;
	s->deadline_misses = v->deadline_misses;
	s->guard_errors = v->guard_errors;
	s->phase = v->half_phase;
	s->streaming = vb2_is_streaming(&v->buffer_queue);
	s->cap_active = READ_ONCE(v->cap_active);
	s->stop_requested = READ_ONCE(v->stop_requested);
	s->ring_corrupt = READ_ONCE(v->ring_corrupt);
	spin_unlock_irqrestore(&v->irq_lock, flags);
}

static int hws_debugfs_config_show(struct seq_file *m, void *unused)
{
	struct hws_video *v = m->private;
	struct hws_pcie_dev *hws = v->parent;
	struct pci_dev *pdev = hws->pdev;
	const struct v4l2_bt_timings *bt = &v->cur_dv_timings.bt;
	struct v4l2_fract period;
	int timing_status;
	u32 htotal;
	u32 vtotal;
	u32 split16_readback = U32_MAX;
	u32 toggle = U32_MAX;
	u32 int_status = U32_MAX;

	(void)unused;
	/* Match ioctl/monitor configuration publication; no mixed timing/layout. */
	mutex_lock(&v->state_lock);
	timing_status = hws_dv_frame_period(&v->cur_dv_timings, &period);
	if (hws->bar0_base && !READ_ONCE(hws->suspended) &&
	    !READ_ONCE(hws->pci_lost)) {
		split16_readback = readl(hws->bar0_base +
					 HWS_REG_VIDEO_HALF_SIZE(v->channel_index));
		toggle = readl(hws->bar0_base +
			       HWS_REG_VBUF_TOGGLE(v->channel_index));
		int_status = readl(hws->bar0_base + HWS_REG_INT_STATUS);
	}
	htotal = READ_ONCE(bt->width) + READ_ONCE(bt->hfrontporch) +
		 READ_ONCE(bt->hsync) + READ_ONCE(bt->hbackporch);
	vtotal = READ_ONCE(bt->height) + READ_ONCE(bt->vfrontporch) +
		 READ_ONCE(bt->vsync) + READ_ONCE(bt->vbackporch);

	seq_printf(m, "pci_bdf=%s\n", pci_name(pdev));
	seq_printf(m, "vendor=0x%04x\n", pdev->vendor);
	seq_printf(m, "device=0x%04x\n", pdev->device);
	seq_printf(m, "subsystem_vendor=0x%04x\n", pdev->subsystem_vendor);
	seq_printf(m, "subsystem_device=0x%04x\n", pdev->subsystem_device);
	seq_printf(m, "revision=0x%02x\n", pdev->revision);
	seq_printf(m, "device_ver=%u\n", hws->device_ver);
	seq_printf(m, "hw_ver=%u\n", hws->hw_ver);
	seq_printf(m, "sub_ver=%u\n", hws->sub_ver);
	seq_printf(m, "port_id=%u\n", hws->port_id);
	seq_printf(m, "irq=%d\n", hws->irq);
	seq_printf(m, "irq_mode=%s\n",
		   pci_dev_msi_enabled(pdev) ? "msi" : "intx");
	seq_printf(m, "channel=%d\n", v->channel_index);
	seq_printf(m, "width=%u\n", READ_ONCE(v->pix.width));
	seq_printf(m, "height=%u\n", READ_ONCE(v->pix.height));
	seq_printf(m, "fourcc=0x%08x\n", READ_ONCE(v->pix.fourcc));
	seq_printf(m, "bytesperline=%u\n", READ_ONCE(v->pix.bytesperline));
	seq_printf(m, "sizeimage=%u\n", READ_ONCE(v->pix.sizeimage));
	seq_printf(m, "fps=%u\n", READ_ONCE(v->current_fps));
	seq_printf(m, "interlaced=%u\n", READ_ONCE(bt->interlaced));
	seq_printf(m, "pixelclock=%llu\n",
		   (unsigned long long)READ_ONCE(bt->pixelclock));
	seq_printf(m, "htotal=%u\n", htotal);
	seq_printf(m, "vtotal=%u\n", vtotal);
	/* Preserve the evidence ABI's pixelclock/total-pixels representation. */
	seq_printf(m, "refresh_num=%llu\n", (unsigned long long)bt->pixelclock);
	seq_printf(m, "refresh_den=%llu\n", (unsigned long long)htotal * vtotal);
	seq_printf(m, "frame_period_num=%u\n", period.numerator);
	seq_printf(m, "frame_period_den=%u\n", period.denominator);
	seq_printf(m, "timing_status=%d\n", timing_status);
	seq_puts(m, "timing_basis=configured-mode; receiver query is table-inferred\n");
	seq_printf(m, "dma_extent=%zu\n", READ_ONCE(v->ring_extent));
	seq_printf(m, "split_bytes=%zu\n", READ_ONCE(v->ring_split));
	seq_printf(m, "split16_cached=%u\n", READ_ONCE(v->last_half16));
	seq_printf(m, "split16_readback=%u\n", split16_readback);
	seq_printf(m, "toggle_readback=%u\n", toggle);
	seq_printf(m, "int_status_readback=0x%08x\n", int_status);
	mutex_unlock(&v->state_lock);
	return 0;
}

static int hws_debugfs_stats_show(struct seq_file *m, void *unused)
{
	struct hws_video *v = m->private;
	struct hws_video_evidence_snapshot s;
	u64 dispositions;

	(void)unused;
	hws_debugfs_snapshot(v, &s);
	dispositions = s.vdone_ignored + s.vdone_accepted +
		       s.vdone_deferred + s.vdone_resynced +
		       s.vdone_recovered + s.vdone_fatal;

	seq_printf(m, "stream_epoch=%llu\n",
		   (unsigned long long)s.stream_epoch);
	seq_printf(m, "streaming=%u\n", s.streaming);
	seq_printf(m, "cap_active=%u\n", s.cap_active);
	seq_printf(m, "stop_requested=%u\n", s.stop_requested);
	seq_printf(m, "phase=%u\n", s.phase);
	seq_printf(m, "generation=%llu\n", (unsigned long long)s.generation);
	seq_printf(m, "probe_count=%u\n", s.probe_count);
	seq_printf(m, "probe_limit=%u\n", HWS_DMA_PROBE_LIMIT);
	seq_printf(m, "probe_reads=%u\nprobe_read_limit=%u\n",
		   s.probe_reads, HWS_DMA_PROBE_READ_LIMIT);
	seq_printf(m, "anomaly_windows=%u\nanomaly_records=%u\nanomaly_triggers=%u\nanomaly_suppressed=%u\nanomaly_window_limit=%u\n",
		   s.anomaly_windows, s.anomaly_records, s.anomaly_triggers,
		   s.anomaly_suppressed, HWS_DMA_ANOMALY_WINDOWS);
	seq_printf(m, "sequence=%u\n", s.sequence);
	seq_printf(m, "vdone_observed=%llu\n",
		   (unsigned long long)s.vdone_observed);
	seq_printf(m, "vdone_dispositions=%llu\n",
		   (unsigned long long)dispositions);
	seq_printf(m, "vdone_ignored=%llu\n",
		   (unsigned long long)s.vdone_ignored);
	seq_printf(m, "vdone_accepted=%llu\n",
		   (unsigned long long)s.vdone_accepted);
	seq_printf(m, "vdone_deferred=%llu\n",
		   (unsigned long long)s.vdone_deferred);
	seq_printf(m, "vdone_resynced=%llu\n",
		   (unsigned long long)s.vdone_resynced);
	seq_printf(m, "vdone_recovered=%llu\n",
		   (unsigned long long)s.vdone_recovered);
	seq_printf(m, "vdone_fatal=%llu\n",
		   (unsigned long long)s.vdone_fatal);
	seq_printf(m, "completed_half0=%llu\n",
		   (unsigned long long)s.completed_half0);
	seq_printf(m, "completed_half1=%llu\n",
		   (unsigned long long)s.completed_half1);
	seq_printf(m, "frames_completed=%llu\n",
		   (unsigned long long)s.frames_completed);
	seq_printf(m, "frames_delivered=%llu\n",
		   (unsigned long long)s.frames_delivered);
	seq_printf(m, "frames_no_buffer=%llu\n",
		   (unsigned long long)s.frames_no_buffer);
	seq_printf(m, "partial_recycles=%llu\n",
		   (unsigned long long)s.partial_recycles);
	seq_printf(m, "recovery_reports=%llu\n",
		   (unsigned long long)s.recovery_reports);
	seq_printf(m, "duplicate_reports=%llu\n",
		   (unsigned long long)s.duplicate_reports);
	seq_printf(m, "overlap_reports=%llu\n",
		   (unsigned long long)s.overlap_reports);
	seq_printf(m, "continuity_reports=%llu\ncontinuity_gaps=%llu\n",
		   (unsigned long long)s.continuity_reports,
		   (unsigned long long)s.continuity_gaps);
	seq_printf(m, "resync_reports=%llu\n",
		   (unsigned long long)s.resync_reports);
	seq_printf(m, "queue_failures=%llu\n",
		   (unsigned long long)s.queue_failures);
	seq_printf(m, "completion_overruns=%u\n", s.completion_overruns);
	seq_printf(m, "w1c_ambiguities=%u\n", s.w1c_ambiguities);
	seq_printf(m, "toggle_resamples=%u\n", s.toggle_resamples);
	seq_printf(m, "toggle_sample_errors=%u\n", s.toggle_sample_errors);
	seq_printf(m, "sync_restarts=%u\n", s.sync_restarts);
	seq_printf(m, "duplicate_recoveries=%u\n", s.duplicate_recoveries);
	seq_printf(m, "overlap_recoveries=%u\n", s.overlap_recoveries);
	seq_printf(m, "phase_errors=%u\n", s.phase_errors);
	seq_printf(m, "deadline_misses=%u\n", s.deadline_misses);
	seq_printf(m, "guard_errors=%u\n", s.guard_errors);
	seq_printf(m, "ring_corrupt=%u\n", s.ring_corrupt);
	return 0;
}

static int hws_debugfs_open(struct inode *inode, struct file *file,
			    int (*show)(struct seq_file *, void *))
{
	struct hws_video *v = inode->i_private;
	int ret;

	if (!v || !v->parent)
		return -ENODEV;
	hws_get_device(v->parent);
	get_device(&v->parent->pdev->dev);
	ret = single_open(file, show, v);
	if (ret) {
		put_device(&v->parent->pdev->dev);
		hws_put_device(v->parent);
	}
	return ret;
}

static int hws_debugfs_config_open(struct inode *inode, struct file *file)
{
	return hws_debugfs_open(inode, file, hws_debugfs_config_show);
}

static int hws_debugfs_stats_open(struct inode *inode, struct file *file)
{
	return hws_debugfs_open(inode, file, hws_debugfs_stats_show);
}

static int hws_debugfs_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	struct hws_video *v = m ? m->private : NULL;
	int ret;

	ret = single_release(inode, file);
	if (v) {
		put_device(&v->parent->pdev->dev);
		hws_put_device(v->parent);
	}
	return ret;
}

static const struct file_operations hws_debugfs_config_fops = {
	.owner = THIS_MODULE,
	.open = hws_debugfs_config_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = hws_debugfs_release,
};

static const struct file_operations hws_debugfs_stats_fops = {
	.owner = THIS_MODULE,
	.open = hws_debugfs_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = hws_debugfs_release,
};

void hws_debugfs_init(struct hws_pcie_dev *hws)
{
	struct dentry *channel_dir;
	char root_name[48];
	char channel_name[16];
	unsigned int ch;

	if (!hws || !hws->pdev || !debugfs_initialized())
		return;

	scnprintf(root_name, sizeof(root_name), "hws-%s", pci_name(hws->pdev));
	hws->debugfs_root = debugfs_create_dir(root_name, NULL);
	if (IS_ERR_OR_NULL(hws->debugfs_root)) {
		hws->debugfs_root = NULL;
		return;
	}

	for (ch = 0; ch < hws->cur_max_video_ch; ch++) {
		scnprintf(channel_name, sizeof(channel_name), "video%u", ch);
		channel_dir = debugfs_create_dir(channel_name, hws->debugfs_root);
		if (IS_ERR_OR_NULL(channel_dir))
			continue;
		debugfs_create_file("config", 0444, channel_dir,
				    &hws->video[ch], &hws_debugfs_config_fops);
		debugfs_create_file("stats", 0444, channel_dir,
				    &hws->video[ch], &hws_debugfs_stats_fops);
	}
}

void hws_debugfs_cleanup(struct hws_pcie_dev *hws)
{
	if (!hws)
		return;
	debugfs_remove_recursive(hws->debugfs_root);
	hws->debugfs_root = NULL;
}
