// SPDX-License-Identifier: GPL-2.0-only
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/iopoll.h>
#include <linux/bitfield.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/minmax.h>
#include <linux/pm.h>
#include <linux/freezer.h>
#include <linux/pci_regs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string.h>

#include <media/v4l2-ctrls.h>

#include "hws.h"
#include "hws_audio.h"
#include "hws_debugfs.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws_irq.h"
#include "hws_v4l2_ioctl.h"

#define DRV_NAME "hws"
#define HWS_BUSY_POLL_DELAY_US 10
#define HWS_BUSY_POLL_TIMEOUT_US 1000000
#define HWS_DMA_IDLE_GRACE_US 100000
#define HWS_VIDEO_GUARD_POISON 0xa5
#define HWS_AUDIO_CANARY_SEED 0x6d

static bool hws_enable_audio = true;
module_param_named(enable_audio, hws_enable_audio, bool, 0444);
MODULE_PARM_DESC(enable_audio,
		 "Enable ALSA embedded audio capture devices; set to 0 for video-only mode");

static bool hws_force_intx;
module_param_named(force_intx, hws_force_intx, bool, 0444);
MODULE_PARM_DESC(force_intx,
		 "Force legacy INTx instead of preferring MSI/MSI-X (load-time diagnostic)");

static unsigned long long hws_elapsed_us(u64 start_ns)
{
	return div_u64(ktime_get_mono_fast_ns() - start_ns, 1000);
}

/* register layout inside HWS_REG_DEVICE_INFO */
#define DEVINFO_VER GENMASK(7, 0)
#define DEVINFO_SUBVER GENMASK(15, 8)
#define DEVINFO_YV12 GENMASK(31, 28)
#define DEVINFO_HWKEY GENMASK(27, 24)
#define DEVINFO_PORTID GENMASK(25, 24) /* low 2 bits of HW-key */

#define MAKE_ENTRY(__vend, __chip, __subven, __subdev, __configptr) \
	{ .vendor = (__vend),                                       \
	  .device = (__chip),                                       \
	  .subvendor = (__subven),                                  \
	  .subdevice = (__subdev),                                  \
	  .driver_data = (unsigned long)(__configptr) }

/*
 * PCI IDs for HWS family cards.
 *
 * The subsystem IDs are fixed at 0x8888:0x0007 for this family. Some boards
 * enumerate with vendor ID 0x8888 or 0x1f33. Exact SKU names are not fully
 * pinned down yet; update these comments when vendor documentation or INF
 * strings are available.
 */
static const struct pci_device_id hws_pci_table[] = {
	/* HWS family, SKU unknown. */
	MAKE_ENTRY(0x8888, 0x9534, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x1F33, 0x8534, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x1F33, 0x8554, 0x8888, 0x0007, NULL),

	/* HWS 2x2 HDMI family. */
	MAKE_ENTRY(0x8888, 0x8524, 0x8888, 0x0007, NULL),
	/* HWS 2x2 SDI family. */
	MAKE_ENTRY(0x1F33, 0x6524, 0x8888, 0x0007, NULL),

	/* HWS X4 HDMI family. */
	MAKE_ENTRY(0x8888, 0x8504, 0x8888, 0x0007, NULL),
	/* HWS X4 SDI family. */
	MAKE_ENTRY(0x8888, 0x6504, 0x8888, 0x0007, NULL),

	/* HWS family, SKU unknown. */
	MAKE_ENTRY(0x8888, 0x8532, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x8888, 0x8512, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x8888, 0x8501, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x1F33, 0x6502, 0x8888, 0x0007, NULL),

	/* HWS X4 HDMI family (alternate vendor ID). */
	MAKE_ENTRY(0x1F33, 0x8504, 0x8888, 0x0007, NULL),
	/* HWS 2x2 HDMI family (alternate vendor ID). */
	MAKE_ENTRY(0x1F33, 0x8524, 0x8888, 0x0007, NULL),

	{}
};

static int hws_enforce_pcie_ordering(struct pci_dev *dev)
{
	const u16 unsafe = PCI_EXP_DEVCTL_RELAX_EN |
			   PCI_EXP_DEVCTL_NOSNOOP_EN;
	int ret;
	u16 control;

	ret = pcie_capability_clear_word(dev, PCI_EXP_DEVCTL, unsafe);
	if (ret)
		return ret;
	ret = pcie_capability_read_word(dev, PCI_EXP_DEVCTL, &control);
	if (ret)
		return ret;
	if (control & unsafe)
		return -EIO;

	return 0;
}

static int hws_configure_hardware_capabilities(struct hws_pcie_dev *hdev)
{
	u16 id = hdev->device_id;
	u32 dma_max;
	u32 readback;

	/* select per-chip channel counts */
	switch (id) {
	case 0x9534:
	case 0x6524:
	case 0x8524:
	case 0x8504:
	case 0x6504:
		hdev->cur_max_video_ch = 4;
		hdev->cur_max_audio_ch = 4;
		break;
	case 0x8532:
		hdev->cur_max_video_ch = 2;
		hdev->cur_max_audio_ch = 2;
		break;
	case 0x8512:
	case 0x6502:
		hdev->cur_max_video_ch = 2;
		hdev->cur_max_audio_ch = 0;
		break;
	case 0x8501:
		hdev->cur_max_video_ch = 1;
		hdev->cur_max_audio_ch = 0;
		break;
	default:
		hdev->cur_max_video_ch = 4;
		hdev->cur_max_audio_ch = 0;
		break;
	}

	if (hdev->cur_max_audio_ch > hdev->cur_max_video_ch)
		hdev->cur_max_audio_ch = hdev->cur_max_video_ch;
	if (!hws_enable_audio)
		hdev->cur_max_audio_ch = 0;

	/* universal buffer capacity */
	hdev->max_hw_video_buf_sz = MAX_MM_VIDEO_SIZE;

	/* decide hardware-version and program DMA max size if needed */
	if (hdev->device_ver > 121) {
		if (id == 0x8501 && hdev->device_ver == 122) {
			hdev->hw_ver = 0;
		} else {
			hdev->hw_ver = 1;
			dma_max = (u32)(MAX_VIDEO_SCALER_SIZE / 16);

			writel(dma_max, hdev->bar0_base + HWS_REG_DMA_MAX_SIZE);
			readback = readl(hdev->bar0_base + HWS_REG_DMA_MAX_SIZE);
			if (readback == U32_MAX)
				return -ENODEV;
			if (readback != dma_max)
				return -EIO;
		}
	} else {
		hdev->hw_ver = 0;
	}

	return 0;
}

static int hws_stop_device(struct hws_pcie_dev *hws);
static void hws_free_seed_buffers(struct hws_pcie_dev *hws);
static void hws_publish_stop_flags(struct hws_pcie_dev *hws);
static int hws_disable_pci_dma_checked(struct hws_pcie_dev *hws,
				       const char *owner, int ch,
				       bool wait_pending);

static void hws_failure_work(struct work_struct *work)
{
	struct hws_pcie_dev *hws = container_of(work, struct hws_pcie_dev,
					      failure_work);
	unsigned long flags;
	unsigned int ch;
	int ret;

	/* Finish any enable transaction which overlapped the fast latch. */
	spin_lock_irqsave(&hws->capture_lock, flags);
	hws_publish_stop_flags(hws);
	spin_unlock_irqrestore(&hws->capture_lock, flags);
	mutex_lock(&hws->dma_lock);
	ret = hws_disable_pci_dma_checked(hws, "runtime device failure", -1, true);
	WRITE_ONCE(hws->dma_quiesced, !ret);
	mutex_unlock(&hws->dma_lock);

	/* Never hold DMA/state/monitor locks while waiting for a copy worker. */
	mutex_lock(&hws->irq_lifetime_lock);
	if (hws->irq_registered)
		synchronize_irq(hws->irq);
	mutex_unlock(&hws->irq_lifetime_lock);
	mutex_lock(&hws->monitor_lock);
	mutex_unlock(&hws->monitor_lock);
	hws_video_drain_work(hws);
	hws_audio_drain_work(hws);
	hws_video_device_error(hws);
	hws_audio_dma_fault_all(hws);
	for (ch = 0; ch < hws->cur_max_audio_ch; ch++)
		flush_work(&hws->audio[ch].deliver_work);

	/* Only CPU-copy destinations were returned, never the DMA arenas. */
}

/* May be called with capture/IRQ/ring locks held. Never wait or touch MMIO. */
void hws_device_lost(struct hws_pcie_dev *hws, const char *reason)
{
	unsigned long flags;

	spin_lock_irqsave(&hws->failure_lock, flags);
	if (!hws->failure_latched) {
		hws->failure_latched = true;
		hws->failure_reason = reason;
	}
	WRITE_ONCE(hws->pci_lost, true);
	WRITE_ONCE(hws->dma_failed, true);
	WRITE_ONCE(hws->start_run, false);
	hws_publish_stop_flags(hws);
	if (hws->failure_enabled && !hws->failure_scheduled) {
		hws->failure_scheduled = true;
		queue_work(system_long_wq, &hws->failure_work);
	}
	spin_unlock_irqrestore(&hws->failure_lock, flags);
}

static void hws_failure_enable(struct hws_pcie_dev *hws)
{
	unsigned long flags;

	spin_lock_irqsave(&hws->failure_lock, flags);
	hws->failure_enabled = true;
	if (hws->failure_latched && !hws->failure_scheduled) {
		hws->failure_scheduled = true;
		queue_work(system_long_wq, &hws->failure_work);
	}
	spin_unlock_irqrestore(&hws->failure_lock, flags);
}

static void hws_failure_cancel(struct hws_pcie_dev *hws)
{
	unsigned long flags;

	/* Same lock as enqueue: no enqueue can sneak past cancellation. */
	spin_lock_irqsave(&hws->failure_lock, flags);
	hws->failure_enabled = false;
	spin_unlock_irqrestore(&hws->failure_lock, flags);
	cancel_work_sync(&hws->failure_work);
}

static void hws_log_lifecycle_snapshot(struct hws_pcie_dev *hws,
				       const char *action,
				       const char *phase)
{
	struct device *dev;
	u32 int_en, int_status, vcap, sys_status, dec_mode;

	if (!hws || !hws->pdev)
		return;

	dev = &hws->pdev->dev;
	if (!hws->bar0_base || READ_ONCE(hws->pci_lost)) {
		dev_dbg(dev,
			"lifecycle:%s:%s bar0-unmapped suspended=%d start_run=%d pci_lost=%d dma_failed=%d irq=%d\n",
			action, phase, READ_ONCE(hws->suspended), hws->start_run,
			hws->pci_lost, READ_ONCE(hws->dma_failed), hws->irq);
		return;
	}

	int_en = readl(hws->bar0_base + INT_EN_REG_BASE);
	int_status = readl(hws->bar0_base + HWS_REG_INT_STATUS);
	vcap = readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);
	sys_status = readl(hws->bar0_base + HWS_REG_SYS_STATUS);
	dec_mode = readl(hws->bar0_base + HWS_REG_DEC_MODE);

	dev_dbg(dev,
		"lifecycle:%s:%s suspended=%d start_run=%d pci_lost=%d dma_failed=%d irq=%d INT_EN=0x%08x INT_STATUS=0x%08x VCAP=0x%08x SYS=0x%08x DEC=0x%08x\n",
		action, phase, READ_ONCE(hws->suspended), hws->start_run,
		hws->pci_lost, READ_ONCE(hws->dma_failed), hws->irq,
		int_en, int_status, vcap,
		sys_status, dec_mode);
}

static void hws_init_probe_state(struct hws_pcie_dev *hdev)
{
	hdev->max_hw_video_buf_sz = MAX_MM_VIDEO_SIZE;
	hdev->max_channels = 4;
	hdev->buf_allocated = false;
	hdev->main_task = NULL;
	hdev->start_run = false;
	hdev->pci_lost = 0;
	hdev->dma_quiesced = false;
	hdev->dma_failed = false;
}

static int read_chip_id(struct hws_pcie_dev *hdev)
{
	u32 reg;
	int ret;
	/* mirror PCI IDs for later switches */
	hdev->device_id = hdev->pdev->device;
	hdev->vendor_id = hdev->pdev->vendor;

	reg = readl(hdev->bar0_base + HWS_REG_DEVICE_INFO);
	if (reg == U32_MAX) {
		hws_device_lost(hdev, "all-ones chip identity");
		dev_err(&hdev->pdev->dev,
			"PCIe device did not respond while reading chip identity\n");
		return -ENODEV;
	}

	hdev->device_ver = FIELD_GET(DEVINFO_VER, reg);
	hdev->sub_ver = FIELD_GET(DEVINFO_SUBVER, reg);
	hdev->support_yv12 = FIELD_GET(DEVINFO_YV12, reg);
	hdev->port_id = FIELD_GET(DEVINFO_PORTID, reg);

	ret = hws_configure_hardware_capabilities(hdev);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to restore hardware capabilities: %d\n", ret);
		return ret;
	}

	dev_info(&hdev->pdev->dev,
		 "chip detected: ver=%u subver=%u port=%u yv12=%u\n",
		 hdev->device_ver, hdev->sub_ver, hdev->port_id,
		 hdev->support_yv12);

	return 0;
}

static int main_ks_thread_handle(void *data)
{
	struct hws_pcie_dev *pdx = data;

	set_freezable();

	for (;;) {
		/*
		 * Freezable kthreads must combine the freezer and stop checks.  A
		 * direct try_to_freeze() can remain refrigerated after
		 * kthread_stop() asks the task to exit.
		 */
		if (kthread_freezable_should_stop(NULL))
			break;

		/* If we're suspending, don't touch hardware; just sleep/freeze. */
		if (READ_ONCE(pdx->suspended) || READ_ONCE(pdx->pci_lost)) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		mutex_lock(&pdx->monitor_lock);
		if (!READ_ONCE(pdx->suspended) && !READ_ONCE(pdx->pci_lost))
			check_video_format(pdx);
		mutex_unlock(&pdx->monitor_lock);

		/* Sleep 1s or until signaled to wake/stop */
		schedule_timeout_interruptible(msecs_to_jiffies(1000));
	}

	dev_dbg(&pdx->pdev->dev, "%s: exiting\n", __func__);
	return 0;
}

static void hws_stop_kthread_action(void *data)
{
	struct hws_pcie_dev *hws = data;
	struct task_struct *t;
	u64 start_ns;

	if (!hws)
		return;

	t = READ_ONCE(hws->main_task);
	if (!IS_ERR_OR_NULL(t)) {
		start_ns = ktime_get_mono_fast_ns();
		dev_dbg(&hws->pdev->dev,
			"lifecycle:kthread-stop:begin task=%s[%d]\n",
			t->comm, t->pid);
		WRITE_ONCE(hws->main_task, NULL);
		kthread_stop(t);
		dev_dbg(&hws->pdev->dev,
			"lifecycle:kthread-stop:done (%lluus)\n",
			hws_elapsed_us(start_ns));
	}
}

static void hws_destroy_audio_workqueue(struct hws_pcie_dev *hws)
{
	struct workqueue_struct *wq;

	if (!hws)
		return;

	wq = hws->audio_wq;
	if (!wq)
		return;

	WRITE_ONCE(hws->audio_wq, NULL);
	destroy_workqueue(wq);
}

static void hws_destroy_video_workqueue(struct hws_pcie_dev *hws)
{
	struct workqueue_struct *wq;

	if (!hws)
		return;

	wq = hws->video_wq;
	if (!wq)
		return;

	hws_video_drain_work(hws);
	WRITE_ONCE(hws->video_wq, NULL);
	destroy_workqueue(wq);
}

static size_t hws_video_scratch_bytes(void)
{
	return PAGE_SIZE + hws_video_ring_capacity() + PAGE_SIZE;
}

static size_t hws_audio_scratch_bytes(void)
{
	return hws_audio_dma_capacity() + PAGE_SIZE;
}

size_t hws_audio_dma_capacity(void)
{
	return PAGE_ALIGN((size_t)MAX_AUDIO_CAP_SIZE);
}

size_t hws_video_ring_capacity(void)
{
	return PAGE_ALIGN((size_t)MAX_VIDEO_SCALER_SIZE +
			  HWS_VIDEO_DMA_TAIL_BYTES);
}

void *hws_video_ring_cpu(struct hws_pcie_dev *hws, unsigned int ch)
{
	struct hws_scratch_dma *arena;

	if (!hws || ch >= MAX_VID_CHANNELS)
		return NULL;
	arena = &hws->scratch_vid[ch];
	if (!arena->cpu || arena->size < hws_video_scratch_bytes())
		return NULL;
	return (u8 *)arena->cpu + PAGE_SIZE;
}

dma_addr_t hws_video_ring_dma(struct hws_pcie_dev *hws, unsigned int ch)
{
	struct hws_scratch_dma *arena;

	if (!hws || ch >= MAX_VID_CHANNELS)
		return 0;
	arena = &hws->scratch_vid[ch];
	if (!arena->cpu || arena->size < hws_video_scratch_bytes())
		return 0;
	return arena->dma + PAGE_SIZE;
}

static bool hws_video_fixed_guards_ok(struct hws_scratch_dma *arena)
{
	u8 *suffix;

	if (!arena || !arena->cpu || arena->size < hws_video_scratch_bytes())
		return false;
	suffix = (u8 *)arena->cpu + PAGE_SIZE + hws_video_ring_capacity();
	return !memchr_inv(arena->cpu, HWS_VIDEO_GUARD_POISON, PAGE_SIZE) &&
	       !memchr_inv(suffix, HWS_VIDEO_GUARD_POISON, PAGE_SIZE);
}

int hws_video_ring_prepare(struct hws_pcie_dev *hws, unsigned int ch,
			   size_t extent)
{
	struct hws_scratch_dma *arena;
	u8 *ring;
	int ret = 0;

	if (!hws || ch >= hws->cur_max_video_ch || !PAGE_ALIGNED(extent) ||
	    !extent || extent > hws_video_ring_capacity())
		return -EINVAL;

	mutex_lock(&hws->scratch_lock);
	arena = &hws->scratch_vid[ch];
	if (!arena->cpu || arena->size < hws_video_scratch_bytes()) {
		ret = -ENOMEM;
		goto out_unlock;
	}
	if (!hws_video_fixed_guards_ok(arena)) {
		ret = -EOVERFLOW;
		goto out_unlock;
	}

	ring = (u8 *)arena->cpu + PAGE_SIZE;
	memset(arena->cpu, HWS_VIDEO_GUARD_POISON, PAGE_SIZE);
	memset(ring + extent, HWS_VIDEO_GUARD_POISON, PAGE_SIZE);
	/* Publish guard initialization before VCAP can be enabled. */
	dma_wmb();

out_unlock:
	mutex_unlock(&hws->scratch_lock);
	return ret;
}

bool hws_video_ring_guards_ok(struct hws_pcie_dev *hws, unsigned int ch,
			      size_t extent)
{
	struct hws_scratch_dma *arena;
	u8 *bad;
	u8 *ring;
	long leading_bad = -1;
	long trailing_bad = -1;
	bool ok;

	if (!hws || ch >= hws->cur_max_video_ch || !PAGE_ALIGNED(extent) ||
	    !extent || extent > hws_video_ring_capacity())
		return false;

	mutex_lock(&hws->scratch_lock);
	arena = &hws->scratch_vid[ch];
	if (!arena->cpu || arena->size < hws_video_scratch_bytes()) {
		ok = false;
		goto out_unlock;
	}
	ring = (u8 *)arena->cpu + PAGE_SIZE;
	dma_rmb();
	bad = memchr_inv(arena->cpu, HWS_VIDEO_GUARD_POISON, PAGE_SIZE);
	if (bad)
		leading_bad = bad - (u8 *)arena->cpu;
	bad = memchr_inv(ring + extent, HWS_VIDEO_GUARD_POISON, PAGE_SIZE);
	if (bad)
		trailing_bad = bad - (ring + extent);
	ok = leading_bad < 0 && trailing_bad < 0;

out_unlock:
	mutex_unlock(&hws->scratch_lock);
	if (!ok)
		dev_err_ratelimited(&hws->pdev->dev,
				    "video DMA guard mismatch ch=%u extent=%zu leading_off=%ld trailing_off=%ld\n",
				    ch, extent, leading_bad, trailing_bad);
	return ok;
}

static size_t hws_audio_ring_bytes(void)
{
	return 2 * (size_t)MAX_DMA_AUDIO_PK_SIZE;
}

static u8 hws_audio_canary_value(size_t offset)
{
	return HWS_AUDIO_CANARY_SEED ^ (u8)offset ^ (u8)(offset >> 8) ^
	       (u8)(offset >> 16);
}

static void hws_audio_fill_canary(u8 *base, size_t first, size_t end)
{
	size_t offset;

	for (offset = first; offset < end; offset++)
		base[offset] = hws_audio_canary_value(offset);
}

static bool hws_audio_scratch_view_valid(struct hws_pcie_dev *hws,
					 unsigned int ch)
{
	struct hws_scratch_dma *owner = &hws->scratch_vid[ch];
	struct hws_scratch_dma *audio = &hws->scratch_aud[ch];
	size_t need = hws_video_scratch_bytes() + hws_audio_scratch_bytes();

	return owner->cpu && owner->size >= need && audio->cpu &&
	       audio->size == hws_audio_dma_capacity() &&
	       audio->cpu == (u8 *)owner->cpu + hws_video_scratch_bytes();
}

int hws_audio_scratch_prepare(struct hws_pcie_dev *hws, unsigned int ch)
{
	struct hws_scratch_dma *audio;
	u8 *base;
	size_t offset;
	size_t capacity = hws_audio_dma_capacity();
	size_t total = hws_audio_scratch_bytes();
	int ret = 0;

	if (!hws || ch >= hws->cur_max_audio_ch)
		return -EINVAL;

	mutex_lock(&hws->scratch_lock);
	if (!hws_audio_scratch_view_valid(hws, ch)) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	audio = &hws->scratch_aud[ch];
	base = audio->cpu;
	dma_rmb();
	if (memchr_inv(base - PAGE_SIZE, HWS_VIDEO_GUARD_POISON, PAGE_SIZE)) {
		ret = -EOVERFLOW;
		goto out_unlock;
	}
	for (offset = capacity; offset < total; offset++) {
		if (base[offset] != hws_audio_canary_value(offset)) {
			ret = -EOVERFLOW;
			goto out_unlock;
		}
	}

	hws_audio_fill_canary(base, hws_audio_ring_bytes(), total);
	/* Publish padding and trailing-guard canaries before ACAP can start. */
	dma_wmb();

out_unlock:
	mutex_unlock(&hws->scratch_lock);
	return ret;
}

int hws_audio_scratch_verify(struct hws_pcie_dev *hws, unsigned int ch,
			     size_t *observed_extent)
{
	struct hws_scratch_dma *audio;
	u8 *base;
	size_t capacity = hws_audio_dma_capacity();
	size_t observed = hws_audio_ring_bytes();
	size_t total = hws_audio_scratch_bytes();
	size_t offset;
	bool guard_ok = true;
	int ret = 0;

	if (observed_extent)
		*observed_extent = 0;
	if (!hws || ch >= hws->cur_max_audio_ch)
		return -EINVAL;

	mutex_lock(&hws->scratch_lock);
	if (!hws_audio_scratch_view_valid(hws, ch)) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	audio = &hws->scratch_aud[ch];
	base = audio->cpu;
	/* The caller must prove DMA idle before this snapshot is authoritative. */
	dma_rmb();
	if (memchr_inv(base - PAGE_SIZE, HWS_VIDEO_GUARD_POISON, PAGE_SIZE))
		guard_ok = false;
	for (offset = hws_audio_ring_bytes(); offset < total; offset++) {
		if (base[offset] == hws_audio_canary_value(offset))
			continue;
		observed = offset + 1;
		if (offset >= capacity)
			guard_ok = false;
	}
	if (!guard_ok)
		ret = -EOVERFLOW;

out_unlock:
	if (observed_extent)
		*observed_extent = observed;
	mutex_unlock(&hws->scratch_lock);
	return ret;
}

static void hws_clear_scratch(struct hws_scratch_dma *scratch)
{
	scratch->cpu = NULL;
	scratch->dma = 0;
	scratch->size = 0;
	scratch->owned = false;
}

static void hws_free_channel_scratch_locked(struct hws_pcie_dev *hws,
					    unsigned int ch)
{
	struct hws_scratch_dma *vid;
	struct hws_scratch_dma *aud;
	unsigned long flags;

	if (!hws || ch >= MAX_VID_CHANNELS)
		return;

	vid = &hws->scratch_vid[ch];
	aud = &hws->scratch_aud[ch];

	/* Scratch cannot exist before the per-channel IRQ lock is initialized. */
	if (ch < hws->cur_max_video_ch && (vid->cpu || aud->cpu)) {
		spin_lock_irqsave(&hws->video[ch].irq_lock, flags);
		hws->video[ch].window_valid = false;
		hws->video[ch].last_dma_hi = 0;
		hws->video[ch].last_dma_page = 0;
		hws->video[ch].last_pci_addr = 0;
		hws->video[ch].last_half16 = 0;
		spin_unlock_irqrestore(&hws->video[ch].irq_lock, flags);
	}
	hws->scratch_users[ch] = 0;

	if (aud->cpu && aud->owned)
		dma_free_coherent(&hws->pdev->dev, aud->size, aud->cpu,
				  aud->dma);
	hws_clear_scratch(aud);

	if (vid->cpu && vid->owned)
		dma_free_coherent(&hws->pdev->dev, vid->size, vid->cpu,
				  vid->dma);
	hws_clear_scratch(vid);
}

int hws_alloc_channel_scratch(struct hws_pcie_dev *hws, unsigned int ch)
{
	size_t aud_off = hws_video_scratch_bytes();
	size_t arena_need = aud_off;
	bool has_audio;

	if (!hws || ch >= max_t(unsigned int, hws->cur_max_video_ch,
				hws->cur_max_audio_ch))
		return -EINVAL;

	has_audio = ch < hws->cur_max_audio_ch;
	if (has_audio)
		arena_need = ALIGN(aud_off + hws_audio_scratch_bytes(), 64);

	/*
	 * One permanent coherent per-channel arena backs the guarded native video
	 * half-ring and audio DMA. The video region is a leading guard page, the
	 * maximum page-rounded ring, and a trailing guard page. Audio starts at
	 * aud_off with a page-rounded DMA capacity followed by its own canary page.
	 * The whole arena must fit inside one 512 MiB remap page because video and
	 * audio share the channel remap slot.
	 */
	mutex_lock(&hws->scratch_lock);
	if (hws->scratch_vid[ch].cpu) {
		hws->scratch_users[ch]++;
		mutex_unlock(&hws->scratch_lock);
		return 0;
	}

	{
#if defined(CONFIG_HAS_DMA) /* normal on PCIe platforms */
		dma_addr_t dma = 0;
		void *cpu = NULL;

		cpu = dma_alloc_coherent(&hws->pdev->dev, arena_need, &dma,
					 GFP_KERNEL);
#else
		void *cpu = NULL;
		dma_addr_t dma = 0;
#endif
		if (!cpu) {
			dev_warn(&hws->pdev->dev,
				 "scratch arena: dma_alloc_coherent failed ch=%u\n",
				 ch);
			mutex_unlock(&hws->scratch_lock);
			return -ENOMEM;
		}
		if (!hws_dma_fits_remap_window(dma, arena_need)) {
			dev_err_ratelimited(&hws->pdev->dev,
					    "scratch arena: ch=%u dma=%pad size=%zu crosses 512 MiB remap window\n",
					    ch, &dma, arena_need);
			dma_free_coherent(&hws->pdev->dev, arena_need, cpu, dma);
			mutex_unlock(&hws->scratch_lock);
			return -ERANGE;
		}

		hws->scratch_vid[ch].dma = dma;
		hws->scratch_vid[ch].cpu = cpu;
		hws->scratch_vid[ch].size = arena_need;
		hws->scratch_vid[ch].owned = true;
		memset(cpu, HWS_VIDEO_GUARD_POISON, hws_video_scratch_bytes());

		if (has_audio) {
			struct hws_scratch_dma *audio = &hws->scratch_aud[ch];

			audio->dma = dma + aud_off;
			audio->cpu = (u8 *)cpu + aud_off;
			audio->size = hws_audio_dma_capacity();
			audio->owned = false;
			hws_audio_fill_canary(audio->cpu, hws_audio_ring_bytes(),
					      hws_audio_scratch_bytes());
		}
	}
	hws->scratch_users[ch] = 1;

	dev_dbg(&hws->pdev->dev,
		"scratch arena: allocated ch=%u size=%zu audio=%d\n",
		ch, arena_need, has_audio);
	mutex_unlock(&hws->scratch_lock);
	return 0;
}

void hws_release_channel_scratch(struct hws_pcie_dev *hws, unsigned int ch)
{
	if (!hws || ch >= MAX_VID_CHANNELS)
		return;

	mutex_lock(&hws->scratch_lock);
	if (!hws->scratch_users[ch]) {
		mutex_unlock(&hws->scratch_lock);
		return;
	}

	hws->scratch_users[ch]--;
	mutex_unlock(&hws->scratch_lock);
}

static void hws_free_seed_buffers(struct hws_pcie_dev *hws)
{
	unsigned long flags;
	bool allocated = false;
	int ch;
	int ret;

	if (!hws)
		return;

	mutex_lock(&hws->scratch_lock);
	for (ch = 0; ch < MAX_VID_CHANNELS; ch++) {
		if (hws->scratch_vid[ch].cpu || hws->scratch_aud[ch].cpu) {
			allocated = true;
			break;
		}
	}
	mutex_unlock(&hws->scratch_lock);
	if (!allocated)
		return;

	/* Some probe-unwind paths arrive here without hws_stop_device(). */
	spin_lock_irqsave(&hws->capture_lock, flags);
	writel(0, hws->bar0_base + HWS_REG_VCAP_ENABLE);
	writel(0, hws->bar0_base + HWS_REG_ACAP_ENABLE);
	(void)readl(hws->bar0_base + HWS_REG_ACAP_ENABLE);
	spin_unlock_irqrestore(&hws->capture_lock, flags);
	if (hws->irq >= 0)
		synchronize_irq(hws->irq);
	hws_video_drain_work(hws);
	if (hws->audio_wq)
		hws_audio_drain_work(hws);
	ret = hws_wait_dma_idle(hws, "scratch teardown", -1);
	if (ret) {
		dev_crit(&hws->pdev->dev,
			 "retaining scratch arenas: DMA did not quiesce (%d)\n",
			 ret);
		return;
	}
	ret = hws_disable_pci_dma_checked(hws, "scratch teardown", -1, true);
	if (ret) {
		WRITE_ONCE(hws->dma_quiesced, false);
		WRITE_ONCE(hws->dma_failed, true);
		WRITE_ONCE(hws->pci_lost, true);
		dev_crit(&hws->pdev->dev,
			 "retaining scratch arenas: PCI DMA isolation failed (%d)\n",
			 ret);
		return;
	}
	WRITE_ONCE(hws->dma_quiesced, true);

	/* Teardown-only force-free path after DMA and PCI isolation are proven. */
	mutex_lock(&hws->scratch_lock);
	for (ch = 0; ch < MAX_VID_CHANNELS; ch++)
		hws_free_channel_scratch_locked(hws, ch);
	mutex_unlock(&hws->scratch_lock);
}

static int hws_irq_mask_gate(struct hws_pcie_dev *hws)
{
	u32 bridge;
	u32 control;
	u32 posted;
	int ret = 0;

	if (!hws || !hws->bar0_base)
		return -ENODEV;

	/* INT_EN is non-echoing, so use this read only for posting/liveness. */
	writel(0x00000000, hws->bar0_base + INT_EN_REG_BASE);
	posted = readl(hws->bar0_base + INT_EN_REG_BASE);
	if (posted == U32_MAX)
		return -ENODEV;

	/* The bridge-enable register is the readable hard IRQ-delivery gate. */
	writel(0, hws->bar0_base + PCIEBR_EN_REG_BASE);
	bridge = readl(hws->bar0_base + PCIEBR_EN_REG_BASE);
	if (bridge == U32_MAX)
		return -ENODEV;
	if (bridge) {
		dev_err(&hws->pdev->dev,
			"IRQ bridge gate remained enabled: 0x%08x\n", bridge);
		ret = -EIO;
	}

	/*
	 * Also request core-output disable.  Bit 0 reads as set on this hardware
	 * even after a successful clear, so its readback is only a posting and
	 * MMIO-liveness check; the bridge register above is the verified gate.
	 */
	control = readl(hws->bar0_base + HWS_REG_CTL);
	if (control == U32_MAX)
		return -ENODEV;
	control &= ~HWS_CTL_IRQ_ENABLE_BIT;
	writel(control, hws->bar0_base + HWS_REG_CTL);
	control = readl(hws->bar0_base + HWS_REG_CTL);
	if (control == U32_MAX)
		return -ENODEV;
	return ret;
}

static u32 hws_irq_source_mask(const struct hws_pcie_dev *hws)
{
	u32 mask = 0;
	unsigned int ch;

	for (ch = 0; ch < hws->cur_max_video_ch; ch++)
		mask |= HWS_INT_VDONE_BIT(ch);
	for (ch = 0; ch < hws->cur_max_audio_ch; ch++)
		mask |= HWS_INT_ADONE_BIT(ch);
	return mask;
}

static int hws_irq_unmask_gate(struct hws_pcie_dev *hws)
{
	u32 mask = hws_irq_source_mask(hws);
	u32 readback;

	writel(mask, hws->bar0_base + INT_EN_REG_BASE);
	readback = readl(hws->bar0_base + INT_EN_REG_BASE);
	if (readback == U32_MAX)
		return -ENODEV;
	/*
	 * INT_EN is not an echo register on this bridge.  Known-good firmware
	 * reports values such as 0x00000100 or 0x00030100 after source masks
	 * that do not match either value.  Use the read as a posted-write and
	 * MMIO-liveness check; HWS_REG_CTL and the IRQ route remain exactly
	 * verified before this gate is opened.
	 */
	return 0;
}

static int hws_irq_clear_pending(struct hws_pcie_dev *hws)
{
	u32 mask;
	u32 pending = 0;
	unsigned int attempt;

	if (!hws || !hws->bar0_base)
		return -ENODEV;
	mask = hws_irq_source_mask(hws);

	for (attempt = 0; attempt <= HWS_IRQ_CLEAR_RETRIES; attempt++) {
		u32 st = readl(hws->bar0_base + HWS_REG_INT_STATUS);

		if (st == U32_MAX)
			return -ENODEV;
		pending = st & mask;
		if (!pending)
			return 0;
		if (attempt == HWS_IRQ_CLEAR_RETRIES)
			break;
		writel(pending, hws->bar0_base + HWS_REG_INT_STATUS); /* W1C */
	}

	dev_err(&hws->pdev->dev,
		"interrupt causes remained pending after %u clears: 0x%08x\n",
		HWS_IRQ_CLEAR_RETRIES, pending);
	return -EBUSY;
}

static int hws_irq_enable_control(struct hws_pcie_dev *hws)
{
	u32 control = readl(hws->bar0_base + HWS_REG_CTL);

	if (control == U32_MAX)
		return -ENODEV;
	control |= HWS_CTL_IRQ_ENABLE_BIT;
	writel(control, hws->bar0_base + HWS_REG_CTL);
	control = readl(hws->bar0_base + HWS_REG_CTL);
	if (control == U32_MAX)
		return -ENODEV;
	return control & HWS_CTL_IRQ_ENABLE_BIT ? 0 : -EIO;
}

static int hws_quiesce_probe_hardware(struct hws_pcie_dev *hws)
{
	unsigned long flags;
	u32 readback;
	int ret;

	ret = hws_irq_mask_gate(hws);
	if (ret)
		return ret;
	spin_lock_irqsave(&hws->capture_lock, flags);
	writel(0, hws->bar0_base + HWS_REG_VCAP_ENABLE);
	writel(0, hws->bar0_base + HWS_REG_ACAP_ENABLE);
	writel(0, hws->bar0_base + HWS_REG_DEC_MODE);
	readback = readl(hws->bar0_base + HWS_REG_DEC_MODE);
	spin_unlock_irqrestore(&hws->capture_lock, flags);
	if (readback == U32_MAX)
		return -ENODEV;
	ret = hws_irq_clear_pending(hws);
	hws->start_run = false;
	return ret;
}

static void hws_free_irq_vectors(void *data)
{
	struct pci_dev *pdev = data;

	pci_free_irq_vectors(pdev);
}

static void hws_release_irq(void *data)
{
	struct hws_pcie_dev *hws = data;

	/* Registered after BAR/vector resources: runs before they disappear. */
	mutex_lock(&hws->irq_lifetime_lock);
	if (hws->irq_registered) {
		free_irq(hws->irq, hws);
		hws->irq_registered = false;
	}
	WRITE_ONCE(hws->irq, -1);
	mutex_unlock(&hws->irq_lifetime_lock);
}

static int hws_alloc_irq(struct hws_pcie_dev *hws, unsigned long *irq_flags)
{
	struct pci_dev *pdev = hws->pdev;
	unsigned int irq_types;
	int irq;
	int ret;

	/*
	 * One vector is sufficient because HWS_REG_INT_STATUS demultiplexes all
	 * video and audio causes. Let PCI core prefer MSI-X, then MSI, and fall
	 * back to INTx when neither message-signaled mode is available.
	 */
	irq_types = hws_force_intx ? PCI_IRQ_INTX : PCI_IRQ_ALL_TYPES;
	ret = pci_alloc_irq_vectors(pdev, 1, 1, irq_types);
	if (ret < 0)
		return dev_err_probe(&pdev->dev, ret,
				     "failed to allocate PCI IRQ vector\n");

	irq = pci_irq_vector(pdev, 0);
	if (irq < 0) {
		pci_free_irq_vectors(pdev);
		return dev_err_probe(&pdev->dev, irq,
				     "failed to resolve PCI IRQ vector 0\n");
	}

	/* Registered before the IRQ action so devres releases the action first. */
	ret = devm_add_action_or_reset(&pdev->dev, hws_free_irq_vectors, pdev);
	if (ret)
		return dev_err_probe(&pdev->dev, ret,
				     "failed to register PCI IRQ vector cleanup\n");

	hws->irq = irq;
	*irq_flags = pci_dev_msi_enabled(pdev) ? 0 : IRQF_SHARED;
	dev_info(&pdev->dev, "IRQ mode: %s%s, irq=%d\n",
		 pci_dev_msi_enabled(pdev) ? "MSI/MSI-X" : "legacy INTx",
		 hws_force_intx ? " (forced)" : "", irq);

	return 0;
}

static int hws_block_hotpaths(struct hws_pcie_dev *hws)
{
	int gate_ret = 0;

	WRITE_ONCE(hws->suspended, true);
	/* Publish the stop state before a racing handler can enter MMIO. */
	smp_mb();

	if (hws->bar0_base)
		gate_ret = hws_irq_mask_gate(hws);

	/*
	 * Do not disable the shared descriptor. Wait for any invocation of this
	 * handler that raced with the device-local gate instead.
	 */
	if (hws->irq >= 0)
		synchronize_irq(hws->irq);

	/* Wait for a monitor pass that started before suspended was set. */
	mutex_lock(&hws->monitor_lock);
	mutex_unlock(&hws->monitor_lock);

	/* The monitor can stop/restart a channel, so drain only after it exits. */
	hws_video_drain_work(hws);
	if (hws->audio_wq)
		hws_audio_drain_work(hws);

	return gate_ret;
}

static void hws_v4l2_release(struct v4l2_device *v4l2_dev)
{
	struct hws_pcie_dev *hws =
		container_of(v4l2_dev, struct hws_pcie_dev, v4l2_device);
	unsigned int i;

	/* All video-device references, including open files, are gone. */
	for (i = 0; i < hws->max_channels; i++) {
		v4l2_ctrl_handler_free(&hws->video[i].control_handler);
		mutex_destroy(&hws->video[i].state_lock);
	}

	v4l2_device_unregister(v4l2_dev);
	hws_put_device(hws);
}

static void hws_release_device(struct kref *ref)
{
	struct hws_pcie_dev *hws =
		container_of(ref, struct hws_pcie_dev, lifetime_ref);

	kfree(hws);
}

void hws_get_device(struct hws_pcie_dev *hws)
{
	kref_get(&hws->lifetime_ref);
}

void hws_put_device(struct hws_pcie_dev *hws)
{
	if (hws)
		kref_put(&hws->lifetime_ref, hws_release_device);
}

/*
 * Registered before all other managed resources, so this runs after their
 * teardown. Open V4L2 or ALSA files keep independent references and defer the
 * final hws release until their disconnected release paths have finished.
 */
static void hws_put_device_action(void *data)
{
	struct hws_pcie_dev *hws = data;

	if (hws->pdev && pci_get_drvdata(hws->pdev) == hws)
		pci_set_drvdata(hws->pdev, NULL);

	if (hws->v4l2_ref_held) {
		hws->v4l2_ref_held = false;
		v4l2_device_put(&hws->v4l2_device);
	}
	hws_put_device(hws);
}

static int hws_probe(struct pci_dev *pdev, const struct pci_device_id *pci_id)
{
	struct hws_pcie_dev *hws;
	int i, ret, irq, scratch_ch;
	unsigned long irqf = 0;
	bool audio_registered = false;

	/* V4L2 and ALSA files can outlive PCI remove, so hws is refcounted. */
	hws = kzalloc_obj(*hws);
	if (!hws)
		return -ENOMEM;
	kref_init(&hws->lifetime_ref);
	hws->pdev = pdev;
	ret = devm_add_action_or_reset(&pdev->dev, hws_put_device_action, hws);
	if (ret)
		return ret;

	hws->irq = -1;
	spin_lock_init(&hws->failure_lock);
	INIT_WORK(&hws->failure_work, hws_failure_work);
	mutex_init(&hws->irq_lifetime_lock);
	hws->suspended = false;
	mutex_init(&hws->monitor_lock);
	mutex_init(&hws->dma_lock);
	hws->v4l2_device.release = hws_v4l2_release;
	mutex_init(&hws->scratch_lock);
	spin_lock_init(&hws->capture_lock);
	pci_set_drvdata(pdev, hws);

	/* 1) Enable the function, but do not permit DMA during construction. */
	ret = pcim_enable_device(pdev);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "pcim_enable_device\n");
	ret = hws_disable_pci_dma_checked(hws, "probe", -1, true);
	if (ret)
		return dev_err_probe(&pdev->dev, ret,
				     "failed to quarantine PCI DMA during probe\n");

	/* 2) Map BAR0 (managed) */
	ret = pcim_iomap_regions(pdev, BIT(0), KBUILD_MODNAME);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "pcim_iomap_regions BAR0\n");
	hws->bar0_base = pcim_iomap_table(pdev)[0];

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_warn(&pdev->dev,
			 "64-bit DMA mask unavailable, falling back to 32-bit (%d)\n",
			 ret);
		ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (ret)
			return dev_err_probe(&pdev->dev, ret,
					     "No suitable DMA configuration\n");
	} else {
		dev_dbg(&pdev->dev, "Using 64-bit DMA mask\n");
	}

	/* 3) Enforce ordered requester transactions for DMA completion. */
	ret = hws_enforce_pcie_ordering(pdev);
	if (ret)
		return dev_err_probe(&pdev->dev, ret,
				     "failed to enforce PCIe requester ordering\n");
	dev_info(&pdev->dev,
		 "PCIe requester ordering: Relaxed Ordering off, No Snoop off\n");
#ifdef CONFIG_ARCH_TI816X
	pcie_set_readrq(pdev, 128);
#endif

	/* 4) Hold every engine and interrupt gate closed before discovery. */
	hws_init_probe_state(hws);
	ret = hws_quiesce_probe_hardware(hws);
	if (ret)
		return dev_err_probe(&pdev->dev, ret,
				     "failed to quarantine capture hardware\n");
	hws->audio_pkt_size = MAX_DMA_AUDIO_PK_SIZE;
	ret = read_chip_id(hws);
	if (ret)
		return dev_err_probe(&pdev->dev, ret,
				     "failed to read chip identity\n");
	dev_info(&pdev->dev, "Device VID=0x%04x DID=0x%04x\n",
		 pdev->vendor, pdev->device);

	/* 5) Init channels (video/audio state, locks, vb2, ctrls) */
	for (i = 0; i < hws->max_channels; i++) {
		ret = hws_video_init_channel(hws, i);
		if (ret) {
			dev_err(&pdev->dev, "video channel init failed (ch=%d)\n", i);
			goto err_unwind_channels;
		}
		ret = hws_audio_init_channel(hws, i);
		if (ret) {
			dev_err(&pdev->dev, "audio channel init failed (ch=%d)\n", i);
			hws_video_cleanup_channel(hws, i);
			goto err_unwind_channels;
		}
	}

	/*
	 * Allocate every channel's guarded DMA arena before publishing ALSA or
	 * V4L2 nodes. These mappings remain stable until PCI teardown; stream
	 * users only take and drop references to them.
	 */
	for (scratch_ch = 0;
	     scratch_ch < max_t(unsigned int, hws->cur_max_video_ch,
				 hws->cur_max_audio_ch);
	     scratch_ch++) {
		ret = hws_alloc_channel_scratch(hws, scratch_ch);
		if (ret) {
			dev_err(&pdev->dev,
				"permanent DMA arena allocation failed (ch=%d): %d\n",
				scratch_ch, ret);
			goto err_unwind_channels;
		}
		hws_release_channel_scratch(hws, scratch_ch);
	}

	hws->video_wq = alloc_workqueue("hws-video",
					WQ_HIGHPRI | WQ_UNBOUND | WQ_MEM_RECLAIM,
					hws->cur_max_video_ch);
	if (!hws->video_wq) {
		ret = -ENOMEM;
		dev_err(&pdev->dev, "video workqueue allocation failed\n");
		goto err_unwind_channels;
	}

	if (hws->cur_max_audio_ch) {
		hws->audio_wq = alloc_workqueue("hws-audio",
						WQ_HIGHPRI | WQ_UNBOUND | WQ_MEM_RECLAIM,
						0);
		if (!hws->audio_wq) {
			ret = -ENOMEM;
			dev_err(&pdev->dev, "audio workqueue allocation failed\n");
			goto err_unwind_channels;
		}
	} else {
		dev_info(&pdev->dev, "audio capture disabled; video-only mode\n");
	}

	/* A) Prefer the card's single MSI vector; retain shared INTx fallback. */
	ret = hws_alloc_irq(hws, &irqf);
	if (ret)
		goto err_unwind_channels;
	irq = hws->irq;

	/* B) Mask the device's global/bridge gate (INT_EN_REG_BASE) */
	ret = hws_irq_mask_gate(hws);
	if (ret) {
		dev_err(&pdev->dev, "failed to mask interrupt sources: %d\n", ret);
		goto err_unwind_channels;
	}

	/* C) Clear any sticky pending interrupt status (W1C) before we arm the line */
	ret = hws_irq_clear_pending(hws);
	if (ret) {
		dev_err(&pdev->dev, "failed to clear pending interrupts: %d\n",
			ret);
		goto err_unwind_channels;
	}

	/* D) The hard handler demultiplexes causes into per-channel workers. */
	ret = request_irq(irq, hws_irq_handler, irqf, dev_name(&pdev->dev), hws);
	if (ret) {
		dev_err(&pdev->dev, "request_irq(%d) failed: %d\n",
			irq, ret);
		hws->irq = -1;
		goto err_unwind_channels;
	}
	mutex_lock(&hws->irq_lifetime_lock);
	hws->irq_registered = true;
	mutex_unlock(&hws->irq_lifetime_lock);
	ret = devm_add_action_or_reset(&pdev->dev, hws_release_irq, hws);
	if (ret)
		goto err_unwind_channels;

	/* E) Initialize the idle core while PCI bus mastering remains disabled. */
	ret = hws_init_video_sys(hws);
	if (ret) {
		dev_err(&pdev->dev, "failed to initialize capture core: %d\n",
			ret);
		goto err_stop_private;
	}

	/* F) Enable the core IRQ output while the source gate remains masked. */
	ret = hws_irq_enable_control(hws);
	if (ret) {
		dev_err(&pdev->dev, "failed to enable interrupt control: %d\n",
			ret);
		goto err_stop_private;
	}

	/* G) Permit DMA only after targets, workers, and the handler are ready. */
	pci_set_master(pdev);

	/* H) Unmask only sources decoded by the installed handler. */
	ret = hws_irq_unmask_gate(hws);
	if (ret) {
		dev_err(&pdev->dev, "failed to unmask interrupt sources: %d\n",
			ret);
		goto err_stop_private;
	}
	dev_info(&pdev->dev, "INT_EN_GATE readback=0x%08x\n",
		 readl(hws->bar0_base + INT_EN_REG_BASE));

	/* 11) Finish private initialization before exposing user-visible nodes. */
	hws->main_task = kthread_run(main_ks_thread_handle, hws, "hws-mon");
	if (IS_ERR(hws->main_task)) {
		ret = PTR_ERR(hws->main_task);
		hws->main_task = NULL;
		dev_err(&pdev->dev, "kthread_run: %d\n", ret);
		goto err_stop_private;
	}
	ret = devm_add_action_or_reset(&pdev->dev, hws_stop_kthread_action, hws);
	if (ret) {
		dev_err(&pdev->dev, "devm_add_action kthread_stop: %d\n", ret);
		goto err_stop_private; /* reset already stopped the thread */
	}

	/* 12) Register ALSA before making V4L2 the final visible interface. */
	ret = hws_audio_register(hws);
	if (ret) {
		dev_err(&pdev->dev, "audio_register: %d\n", ret);
		goto err_stop_private;
	}
	audio_registered = !!hws->snd_card;

	ret = hws_video_register(hws);
	if (ret) {
		dev_err(&pdev->dev, "video_register: %d\n", ret);
		goto err_stop_private;
	}
	hws_debugfs_init(hws);
	hws_failure_enable(hws);

	/* 13) Final: show the line is armed */
	dev_info(&pdev->dev, "irq handler installed on irq=%d\n", irq);
	return 0;

err_stop_private:
	hws_failure_cancel(hws);
	(void)hws_block_hotpaths(hws);
	hws_stop_kthread_action(hws);
	hws_stop_device(hws);
	if (audio_registered)
		hws_audio_unregister(hws);
	hws_free_seed_buffers(hws);
	/* V4L2 owns initialized channel state once its parent ref is live. */
	if (!hws->v4l2_ref_held) {
		while (--i >= 0) {
			hws_video_cleanup_channel(hws, i);
			hws_audio_cleanup_channel(hws, i, true);
		}
	}
	hws_destroy_audio_workqueue(hws);
	hws_destroy_video_workqueue(hws);
	return ret;
err_unwind_channels:
	hws_failure_cancel(hws);
	hws_free_seed_buffers(hws);
	while (--i >= 0) {
		hws_video_cleanup_channel(hws, i);
		hws_audio_cleanup_channel(hws, i, true);
	}
	hws_destroy_audio_workqueue(hws);
	hws_destroy_video_workqueue(hws);
	return ret;
}

static int hws_poll_dma_idle(struct hws_pcie_dev *hws,
			     unsigned int timeout_us, u32 *last_status)
{
	void __iomem *reg = hws->bar0_base + HWS_REG_SYS_STATUS;
	u32 val;
	int ret;

	ret = readl_poll_timeout(reg, val,
				 val == U32_MAX || !(val & HWS_SYS_DMA_BUSY_BIT),
				 HWS_BUSY_POLL_DELAY_US,
				 timeout_us);
	if (last_status)
		*last_status = val;
	if (ret)
		return -ETIMEDOUT;
	if (val == U32_MAX) {
		hws_device_lost(hws, "all-ones DMA idle status");
		return -ENODEV;
	}
	return 0;
}

static void hws_fail_active_video_queues(struct hws_pcie_dev *hws)
{
	unsigned int ch;

	for (ch = 0; ch < hws->cur_max_video_ch; ch++) {
		struct hws_video *vid = &hws->video[ch];

		if (vid->queue_initialized &&
		    vb2_is_streaming(&vid->buffer_queue))
			vb2_queue_error(&vid->buffer_queue);
	}
}

static int hws_disable_pci_dma_checked(struct hws_pcie_dev *hws,
				       const char *owner, int ch,
				       bool wait_pending)
{
	u16 command = U16_MAX;
	int ret;

	if (!hws || !hws->pdev)
		return -ENODEV;
	if (!owner)
		owner = "PCI DMA quarantine";

	/*
	 * PCI_COMMAND_MASTER is the generic containment boundary for transitions
	 * that stop every engine. Read it back before allowing DMA-owned memory to
	 * be returned. A missing function is safe too: it can no longer reach host
	 * memory through this PCIe link.
	 */
	pci_clear_master(hws->pdev);
	ret = pci_read_config_word(hws->pdev, PCI_COMMAND, &command);
	if (ret || command == U16_MAX) {
		/* Presence probing is kept out of the IRQ-disabled noirq phase. */
		if (wait_pending && !pci_device_is_present(hws->pdev)) {
			WRITE_ONCE(hws->pci_lost, true);
			dev_warn(&hws->pdev->dev,
				 "%s ch=%d: PCI function disappeared while stopping DMA\n",
				 owner, ch);
			return 0;
		}
		dev_crit(&hws->pdev->dev,
			 "%s ch=%d: cannot verify PCI bus-master disable: %d command=0x%04x\n",
			 owner, ch, ret, command);
		return ret ? pcibios_err_to_errno(ret) : -EIO;
	}
	if (command & PCI_COMMAND_MASTER) {
		dev_crit(&hws->pdev->dev,
			 "%s ch=%d: PCI bus-master bit remained set (command=0x%04x)\n",
			 owner, ch, command);
		return -EIO;
	}

	if (wait_pending && !pci_wait_for_pending_transaction(hws->pdev)) {
		dev_crit(&hws->pdev->dev,
			 "%s ch=%d: PCI transaction-pending bit remained set after bus-master disable\n",
			 owner, ch);
		return -ETIMEDOUT;
	}

	return 0;
}

static int hws_isolate_pci_dma(struct hws_pcie_dev *hws,
			       const char *owner, int ch)
{
	int ret;

	ret = hws_disable_pci_dma_checked(hws, owner, ch, true);
	if (ret)
		return ret;

	dev_err(&hws->pdev->dev,
		"%s ch=%d: disabled PCI bus mastering after stuck DMA busy indication\n",
		owner, ch);
	return 0;
}

static int hws_force_dma_quiesce_locked(struct hws_pcie_dev *hws,
					const char *owner, int ch)
{
	unsigned long flags;
	u32 status = 0;
	int mask_ret;
	int ret;

	lockdep_assert_held(&hws->dma_lock);

	dev_err(&hws->pdev->dev,
		"%s ch=%d: channel DMA did not become idle; stopping all streams\n",
		owner, ch);

	/* Refuse every subsequent start before globally disabling capture. */
	hws_device_lost(hws, "DMA stop timeout");
	smp_mb(); /* block racing starts before global capture disable */
	mask_ret = hws_irq_mask_gate(hws);
	if (mask_ret)
		dev_crit(&hws->pdev->dev,
			 "%s ch=%d: failed to close the device IRQ gate: %d\n",
			 owner, ch, mask_ret);

	spin_lock_irqsave(&hws->capture_lock, flags);
	writel(0, hws->bar0_base + HWS_REG_VCAP_ENABLE);
	writel(0, hws->bar0_base + HWS_REG_ACAP_ENABLE);
	(void)readl(hws->bar0_base + HWS_REG_ACAP_ENABLE);
	spin_unlock_irqrestore(&hws->capture_lock, flags);

	if (hws->irq >= 0)
		synchronize_irq(hws->irq);
	hws_video_drain_work(hws);
	if (hws->audio_wq)
		hws_audio_drain_work(hws);
	hws_fail_active_video_queues(hws);
	hws_audio_dma_fault_all(hws);

	ret = hws_poll_dma_idle(hws, HWS_BUSY_POLL_TIMEOUT_US, &status);
	if (!ret)
		goto quiesced;

	/*
	 * A stuck or inaccessible device-specific busy indication cannot
	 * justify returning DMA-owned memory. Disable and verify PCI bus
	 * mastering so the function can no longer target host addresses.
	 */
	ret = hws_isolate_pci_dma(hws, owner, ch);
	if (ret)
		return ret;

quiesced:
	WRITE_ONCE(hws->dma_quiesced, true);
	return 0;
}

static int __hws_wait_dma_idle(struct hws_pcie_dev *hws, const char *owner,
			       int ch, bool force)
{
	u32 status = 0;
	int ret;

	if (!hws || !hws->bar0_base)
		return -ENODEV;
	might_sleep();
	if (!owner)
		owner = "DMA stop";

	mutex_lock(&hws->dma_lock);
	if (READ_ONCE(hws->dma_quiesced)) {
		ret = 0;
		goto out_unlock;
	}
	/*
	 * Once MMIO liveness or the fatal stop path has failed, a later clear
	 * device busy bit is not sufficient evidence that DMA is safe.  Forced
	 * teardown may retry only the PCI isolation proof; speculative per-channel
	 * reclaim must keep the arena quarantined.
	 */
	if (READ_ONCE(hws->dma_failed) || READ_ONCE(hws->pci_lost)) {
		if (!force) {
			ret = READ_ONCE(hws->dma_failed) ? -EIO : -ENODEV;
			goto out_unlock;
		}
		ret = hws_isolate_pci_dma(hws, owner, ch);
		if (!ret)
			WRITE_ONCE(hws->dma_quiesced, true);
		goto out_unlock;
	}

	/*
	 * There is no per-channel idle bit. Once the caller has posted the
	 * target channel's disable, observing the global busy bit clear proves
	 * that every older DMA from that channel has drained. Other channels
	 * remain running unless they prevent that observation for the grace
	 * period. Speculative recovery callers then fail without touching other
	 * streams; callers that must release memory request the fatal global-stop
	 * path below.
	 */
	ret = hws_poll_dma_idle(hws, HWS_DMA_IDLE_GRACE_US, &status);
	if (!ret)
		goto out_unlock;
	if (ret == -ENODEV) {
		/* Never retry BAR idle after a missing-device observation. */
		if (force) {
			ret = hws_isolate_pci_dma(hws, owner, ch);
			if (!ret)
				WRITE_ONCE(hws->dma_quiesced, true);
		}
		goto out_unlock;
	}

	if (force)
		ret = hws_force_dma_quiesce_locked(hws, owner, ch);

out_unlock:
	mutex_unlock(&hws->dma_lock);
	return ret;
}

int hws_try_wait_dma_idle(struct hws_pcie_dev *hws, const char *owner, int ch)
{
	return __hws_wait_dma_idle(hws, owner, ch, false);
}

int hws_wait_dma_idle(struct hws_pcie_dev *hws, const char *owner, int ch)
{
	return __hws_wait_dma_idle(hws, owner, ch, true);
}

static void hws_stop_dsp(struct hws_pcie_dev *hws)
{
	u32 status;

	/* Read the decoder mode/status register */
	status = readl(hws->bar0_base + HWS_REG_DEC_MODE);
	dev_dbg(&hws->pdev->dev, "%s: status=0x%08x\n", __func__, status);

	/* If the device looks unplugged/stuck, bail out */
	if (status == 0xFFFFFFFF)
		return;

	/* Tell the DSP to stop */
	writel(0x10, hws->bar0_base + HWS_REG_DEC_MODE);
	/* Disable video capture engine in the DSP */
	writel(0x0, hws->bar0_base + HWS_REG_VCAP_ENABLE);
	(void)readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);
}

/* Publish stop so ISR/BH will not touch ALSA/VB2 anymore. */
static void hws_publish_stop_flags(struct hws_pcie_dev *hws)
{
	unsigned int i;

	for (i = 0; i < hws->cur_max_video_ch; ++i) {
		struct hws_video *v = &hws->video[i];

		WRITE_ONCE(v->cap_active,     false);
		WRITE_ONCE(v->stop_requested, true);
	}

	for (i = 0; i < hws->cur_max_audio_ch; ++i) {
		struct hws_audio *a = &hws->audio[i];

		WRITE_ONCE(a->stream_running, false);
		WRITE_ONCE(a->cap_active, false);
		WRITE_ONCE(a->stop_requested, true);
	}

	smp_wmb(); /* make flags visible before we touch MMIO/queues */
}

/* Drain engines + ISR/BH after flags are published. */
static int hws_drain_after_stop(struct hws_pcie_dev *hws)
{
	unsigned long flags;
	u64 start_ns = ktime_get_mono_fast_ns();
	int idle_ret;
	int irq_ret;

	/* Mask device enables: no new DMA starts. */
	spin_lock_irqsave(&hws->capture_lock, flags);
	writel(0x0, hws->bar0_base + HWS_REG_VCAP_ENABLE);
	writel(0x0, hws->bar0_base + HWS_REG_ACAP_ENABLE);
	(void)readl(hws->bar0_base + HWS_REG_ACAP_ENABLE);
	spin_unlock_irqrestore(&hws->capture_lock, flags);

	/* Stop the shared DSP before taking the final DMA-idle observation. */
	if (!READ_ONCE(hws->pci_lost))
		hws_stop_dsp(hws);

	/* No new hard IRQ can queue work after the published stop. */
	if (hws->irq >= 0)
		synchronize_irq(hws->irq);
	hws_video_drain_work(hws);
	hws_audio_drain_work(hws);

	/* Do not release any DMA-owned memory until the engine is idle. */
	idle_ret = hws_wait_dma_idle(hws, "device stop", -1);

	/* Producers are stopped, so every owned W1C cause must now drain. */
	irq_ret = hws_irq_clear_pending(hws);

	dev_dbg(&hws->pdev->dev, "lifecycle:drain-after-stop:done (%lluus)\n",
		hws_elapsed_us(start_ns));
	return idle_ret ?: irq_ret;
}

static int hws_stop_device(struct hws_pcie_dev *hws)
{
	u32 status;
	u64 start_ns = ktime_get_mono_fast_ns();
	bool live;
	int dma_ret;
	int stop_ret = 0;
	int ret = 0;

	/*
	 * Publish and drain software ownership before probing device liveness.
	 * The missing-function path must not leave ALSA/VB2 work touching MMIO.
	 */
	hws_publish_stop_flags(hws);
	if (hws->irq >= 0)
		synchronize_irq(hws->irq);
	hws_video_drain_work(hws);
	if (hws->audio_wq)
		hws_audio_drain_work(hws);

	status = READ_ONCE(hws->pci_lost) ? U32_MAX :
		readl(hws->bar0_base + HWS_REG_SYS_STATUS);
	live = status != U32_MAX;
	dev_dbg(&hws->pdev->dev, "%s: status=0x%08x\n", __func__, status);
	if (!live) {
		hws_device_lost(hws, "device stop: MMIO unavailable");
		dma_ret = hws_disable_pci_dma_checked(hws, "device stop", -1,
						      true);
		if (dma_ret) {
			WRITE_ONCE(hws->dma_quiesced, false);
			WRITE_ONCE(hws->dma_failed, true);
		} else {
			WRITE_ONCE(hws->dma_quiesced, true);
		}
		ret = dma_ret;
		goto out;
	}
	hws_log_lifecycle_snapshot(hws, "stop-device", "begin");

	/* Software is stopped; now drain the live engines and IRQ state. */
	stop_ret = hws_drain_after_stop(hws);
	if (stop_ret)
		dev_crit(&hws->pdev->dev,
			 "device stop could not drain every engine/IRQ source: %d\n",
			 stop_ret);

	/* Always close and verify the generic PCI DMA boundary before teardown. */
	dma_ret = hws_disable_pci_dma_checked(hws, "device stop", -1, true);
	if (dma_ret) {
		WRITE_ONCE(hws->dma_quiesced, false);
		WRITE_ONCE(hws->dma_failed, true);
		WRITE_ONCE(hws->pci_lost, true);
	} else {
		WRITE_ONCE(hws->dma_quiesced, true);
	}
	ret = dma_ret ?: stop_ret;

out:
	hws->start_run = false;
	if (live)
		hws_log_lifecycle_snapshot(hws, "stop-device", "end");
	else
		dev_dbg(&hws->pdev->dev, "lifecycle:stop-device:device-lost\n");
	dev_dbg(&hws->pdev->dev, "lifecycle:stop-device:done (%lluus)\n",
		hws_elapsed_us(start_ns));
	dev_dbg(&hws->pdev->dev, "%s: complete\n", __func__);
	return ret;
}

static int hws_quiesce_for_transition(struct hws_pcie_dev *hws,
				      const char *action,
				      bool stop_thread,
				      bool quiesce_video)
{
	struct device *dev = &hws->pdev->dev;
	u64 start_ns = ktime_get_mono_fast_ns();
	u64 step_ns;
	int block_ret;
	int stop_ret;
	int video_ret;

	hws_failure_cancel(hws);
	hws_log_lifecycle_snapshot(hws, action, "begin");

	step_ns = ktime_get_mono_fast_ns();
	block_ret = hws_block_hotpaths(hws);
	dev_dbg(dev, "lifecycle:%s:block-hotpaths (%lluus)\n", action,
		hws_elapsed_us(step_ns));
	if (block_ret)
		dev_crit(dev,
			 "lifecycle:%s could not verify the device IRQ gate: %d\n",
			 action, block_ret);
	hws_log_lifecycle_snapshot(hws, action, "blocked");

	if (stop_thread) {
		step_ns = ktime_get_mono_fast_ns();
		hws_stop_kthread_action(hws);
		dev_dbg(dev, "lifecycle:%s:stop-kthread (%lluus)\n", action,
			hws_elapsed_us(step_ns));
	}

	step_ns = ktime_get_mono_fast_ns();
	stop_ret = hws_stop_device(hws);
	dev_dbg(dev, "lifecycle:%s:stop-device (%lluus)\n", action,
		hws_elapsed_us(step_ns));

	video_ret = 0;
	if (quiesce_video) {
		/*
		 * VB2 buffers are software copy targets, not direct device DMA
		 * targets. Fixed DMA scratch arenas are retained separately unless
		 * PCI isolation is proved.
		 */
		step_ns = ktime_get_mono_fast_ns();
		video_ret = hws_video_quiesce(hws, action);
		dev_dbg(dev,
			"lifecycle:%s:video-quiesce ret=%d (%lluus)\n",
			action, video_ret, hws_elapsed_us(step_ns));
		if (video_ret)
			dev_warn(dev,
				 "lifecycle:%s video quiesce returned %d\n",
				 action, video_ret);
	}
	hws_log_lifecycle_snapshot(hws, action, "end");
	dev_dbg(dev, "lifecycle:%s:quiesce-done ret=%d (%lluus)\n", action,
		block_ret ?: stop_ret ?: video_ret, hws_elapsed_us(start_ns));

	return block_ret ?: stop_ret ?: video_ret;
}

static void hws_remove(struct pci_dev *pdev)
{
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);
	u64 start_ns;
	int ret;

	if (!hws)
		return;

	start_ns = ktime_get_mono_fast_ns();
	dev_info(&pdev->dev, "lifecycle:remove begin\n");
	hws_log_lifecycle_snapshot(hws, "remove", "begin");

	/* Establish one device-wide DMA boundary before unpublishing interfaces. */
	ret = hws_quiesce_for_transition(hws, "remove", true, true);
	if (ret)
		dev_crit(&pdev->dev,
			 "remove could not establish complete DMA quiescence: %d\n",
			 ret);

	/* Disconnect user interfaces only after IRQ, work, and DMA are stopped. */
	hws_debugfs_cleanup(hws);
	hws_audio_unregister(hws);
	hws_video_unregister(hws);
	hws_destroy_audio_workqueue(hws);

	/* Release seeded DMA buffers */
	hws_free_seed_buffers(hws);
	hws_destroy_video_workqueue(hws);
	/* kthread is stopped by the devm action registered in probe. */
	hws_log_lifecycle_snapshot(hws, "remove", "end");
	dev_info(&pdev->dev, "lifecycle:remove done (%lluus)\n",
		 hws_elapsed_us(start_ns));
}

#ifdef CONFIG_PM_SLEEP
static int hws_keep_resume_quarantined(struct hws_pcie_dev *hws)
{
	unsigned long flags;
	u32 readback = U32_MAX;
	int dma_ret;
	int gate_ret;
	int irq_ret = 0;

	WRITE_ONCE(hws->suspended, true);
	smp_mb(); /* keep every MMIO hot path behind the quarantine state */
	gate_ret = hws_irq_mask_gate(hws);
	if (hws->bar0_base) {
		spin_lock_irqsave(&hws->capture_lock, flags);
		writel(0, hws->bar0_base + HWS_REG_VCAP_ENABLE);
		writel(0, hws->bar0_base + HWS_REG_ACAP_ENABLE);
		readback = readl(hws->bar0_base + HWS_REG_ACAP_ENABLE);
		spin_unlock_irqrestore(&hws->capture_lock, flags);
		if (readback == U32_MAX && !gate_ret)
			gate_ret = -ENODEV;
		irq_ret = hws_irq_clear_pending(hws);
	}
	dma_ret = hws_disable_pci_dma_checked(hws, "resume quarantine", -1, true);
	if (dma_ret) {
		WRITE_ONCE(hws->dma_quiesced, false);
		WRITE_ONCE(hws->dma_failed, true);
		WRITE_ONCE(hws->pci_lost, true);
	} else {
		WRITE_ONCE(hws->dma_quiesced, true);
	}
	if (gate_ret || irq_ret)
		WRITE_ONCE(hws->pci_lost, true);
	WRITE_ONCE(hws->start_run, false);
	return dma_ret ?: gate_ret ?: irq_ret;
}

static int hws_enable_pci_dma_checked(struct hws_pcie_dev *hws)
{
	u16 command = U16_MAX;
	int isolate_ret;
	int ret;

	pci_set_master(hws->pdev);
	ret = pci_read_config_word(hws->pdev, PCI_COMMAND, &command);
	if (ret)
		ret = pcibios_err_to_errno(ret);
	else if (command == U16_MAX)
		ret = -ENODEV;
	else if (!(command & PCI_COMMAND_MASTER))
		ret = -EIO;
	else
		return 0;

	/* A failed enable attempt must not leave BME in an unknown state. */
	isolate_ret = hws_isolate_pci_dma(hws, "resume rollback", -1);
	if (isolate_ret) {
		mutex_lock(&hws->dma_lock);
		WRITE_ONCE(hws->dma_failed, true);
		WRITE_ONCE(hws->pci_lost, true);
		WRITE_ONCE(hws->dma_quiesced, false);
		mutex_unlock(&hws->dma_lock);
		return isolate_ret;
	}
	return ret;
}

static int hws_restart_quiesced_core(struct hws_pcie_dev *hws)
{
	unsigned long flags;
	int ret;

	if (READ_ONCE(hws->failure_latched) || READ_ONCE(hws->dma_failed))
		return -EIO;
	ret = hws_init_video_sys(hws);
	if (ret)
		goto err_quarantine;
	ret = hws_audio_pm_resume(hws);
	if (ret)
		goto err_quarantine;
	ret = hws_video_pm_resume(hws);
	if (ret)
		goto err_quarantine;
	ret = hws_irq_clear_pending(hws);
	if (ret)
		goto err_quarantine;
	ret = hws_irq_enable_control(hws);
	if (ret)
		goto err_quarantine;
	/* No producer is enabled, so verify the source gate before enabling BME. */
	ret = hws_irq_unmask_gate(hws);
	if (ret)
		goto err_quarantine;
	ret = hws_enable_pci_dma_checked(hws);
	if (ret)
		goto err_quarantine;

	mutex_lock(&hws->dma_lock);
	spin_lock_irqsave(&hws->failure_lock, flags);
	if (hws->failure_latched) {
		spin_unlock_irqrestore(&hws->failure_lock, flags);
		mutex_unlock(&hws->dma_lock);
		return -EIO;
	}
	WRITE_ONCE(hws->pci_lost, false);
	WRITE_ONCE(hws->dma_quiesced, false);
	WRITE_ONCE(hws->suspended, false);
	spin_unlock_irqrestore(&hws->failure_lock, flags);
	mutex_unlock(&hws->dma_lock);

	/* Publish live state and restored arenas after every commit check passed. */
	smp_mb();
	return 0;

err_quarantine:
	return ret;
}

static int hws_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);
	int aret;
	int vret;
	u64 start_ns = ktime_get_mono_fast_ns();

	dev_info(dev, "lifecycle:pm_suspend begin\n");
	/*
	 * Establish the only fallible safety boundary before changing ALSA or
	 * VB2 state.  Once DMA is quiesced, subsystem transition failures are
	 * reported to their streams but must not turn this into a partial abort.
	 */
	vret = hws_quiesce_for_transition(hws, "pm_suspend", false, false);
	if (vret) {
		dev_err(dev,
			"lifecycle:pm_suspend aborted before stream transition: %d\n",
			vret);
		hws_fail_active_video_queues(hws);
		hws_audio_dma_fault_all(hws);
		return vret;
	}

	aret = hws_audio_pm_suspend_all(hws);
	if (aret) {
		dev_err(dev,
			"lifecycle:pm_suspend audio transition failed %d; forcing XRUN\n",
			aret);
		hws_audio_dma_fault_all(hws);
	}
	vret = hws_video_quiesce(hws, "pm_suspend");
	if (vret) {
		dev_err(dev,
			"lifecycle:pm_suspend video transition failed %d; failing queues\n",
			vret);
		hws_fail_active_video_queues(hws);
	}

	/* hws_stop_device() verified BME clear before subsystem state changed. */
	dev_info(dev,
		 "lifecycle:pm_suspend done audio=%d video=%d (%lluus)\n",
		 aret, vret,
		 hws_elapsed_us(start_ns));

	return 0;
}

static int hws_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);
	int quarantine_ret;
	int ret;
	u64 start_ns = ktime_get_mono_fast_ns();
	u64 step_ns;

	dev_info(dev, "lifecycle:pm_resume begin\n");
	if (READ_ONCE(hws->dma_failed)) {
		ret = hws_keep_resume_quarantined(hws);
		return ret ?: -EIO;
	}

	/* PCI core restored D0/config in noirq; retain quarantine until reinit. */
	step_ns = ktime_get_mono_fast_ns();
	ret = hws_disable_pci_dma_checked(hws, "pm resume", -1, true);
	if (ret)
		goto err_quarantine;
	ret = hws_irq_mask_gate(hws);
	if (ret)
		goto err_quarantine;
	dev_dbg(dev, "lifecycle:pm_resume:pci-quarantined (%lluus)\n",
		hws_elapsed_us(step_ns));

	/* Restore the conservative requester-ordering contract lost across D3. */
	ret = hws_enforce_pcie_ordering(pdev);
	if (ret) {
		dev_err(dev, "failed to enforce PCIe requester ordering: %d\n",
			ret);
		goto err_quarantine;
	}

	/* Reinitialize chip-side capabilities / registers */
	step_ns = ktime_get_mono_fast_ns();
	ret = read_chip_id(hws);
	if (ret) {
		dev_err(dev, "failed to restore chip identity: %d\n", ret);
		goto err_quarantine;
	}
	/* Restore retained DMA windows while every producer and IRQ is masked. */
	ret = hws_restart_quiesced_core(hws);
	if (ret) {
		dev_err(dev, "capture-core resume transaction failed: %d\n", ret);
		goto err_quarantine;
	}
	dev_dbg(dev, "lifecycle:pm_resume:chip-reinit (%lluus)\n",
		hws_elapsed_us(step_ns));
	hws_log_lifecycle_snapshot(hws, "pm_resume", "end");
	dev_info(dev, "lifecycle:pm_resume done (%lluus)\n",
		 hws_elapsed_us(start_ns));
	hws_failure_enable(hws);

	return 0;

err_quarantine:
	quarantine_ret = hws_keep_resume_quarantined(hws);
	return quarantine_ret ?: ret;
}

static int hws_pm_resume_noirq(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);
	int dma_ret;
	int gate_ret;

	if (!hws)
		return -ENODEV;

	/*
	 * PCI core has restored D0 and config space, but system IRQs are still
	 * disabled. Reassert both generic DMA isolation and the device-local IRQ
	 * quarantine before resume_device_irqs() can expose this function.
	 */
	dma_ret = hws_disable_pci_dma_checked(hws, "pm resume_noirq", -1, false);
	gate_ret = hws_irq_mask_gate(hws);
	if (dma_ret) {
		WRITE_ONCE(hws->dma_quiesced, false);
		WRITE_ONCE(hws->dma_failed, true);
		WRITE_ONCE(hws->pci_lost, true);
	}

	/* Pending W1C causes are drained after regular resume disables producers. */
	return dma_ret ?: gate_ret;
}

static const struct dev_pm_ops hws_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(hws_pm_suspend, hws_pm_resume)
	.resume_noirq = hws_pm_resume_noirq,
	.thaw_noirq = hws_pm_resume_noirq,
	.restore_noirq = hws_pm_resume_noirq,
};

# define HWS_PM_OPS (&hws_pm_ops)
#else
# define HWS_PM_OPS NULL
#endif

static void hws_shutdown(struct pci_dev *pdev)
{
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);
	int vret = 0;
	u64 start_ns = ktime_get_mono_fast_ns();

	if (!hws)
		return;

	dev_info(&pdev->dev, "lifecycle:pci_shutdown begin\n");
	/*
	 * Hibernation shutdown/reboot reaches device_shutdown() while freezable
	 * kthreads remain frozen.  The suspended flag and monitor_lock barrier
	 * keep this thread away from hardware; do not wait for it to exit here.
	 */
	vret = hws_quiesce_for_transition(hws, "pci_shutdown", false, true);
	dev_info(&pdev->dev, "lifecycle:pci_shutdown done ret=%d (%lluus)\n",
		 vret, hws_elapsed_us(start_ns));
}

static struct pci_driver hws_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = hws_pci_table,
	.probe = hws_probe,
	.remove = hws_remove,
	.shutdown = hws_shutdown,
	.driver = {
		.pm = HWS_PM_OPS,
	},
};

MODULE_DEVICE_TABLE(pci, hws_pci_table);

static int __init pcie_hws_init(void)
{
	return pci_register_driver(&hws_pci_driver);
}

static void __exit pcie_hws_exit(void)
{
	pci_unregister_driver(&hws_pci_driver);
}

module_init(pcie_hws_init);
module_exit(pcie_hws_exit);

MODULE_DESCRIPTION(DRV_NAME);
MODULE_AUTHOR("Ben Hoff <hoff.benjamin.k@gmail.com>");
MODULE_AUTHOR("Sales <sales@avmatrix.com>");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("DMA_BUF");
