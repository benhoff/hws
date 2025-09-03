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
#include <linux/pm.h>
#include <linux/freezer.h>

#include <media/v4l2-ctrls.h>

#include "hws.h"
#include "hws_audio.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws_irq.h"
#include "hws_v4l2_ioctl.h"

#define DRV_NAME "hws"
#define HWS_REG_DEVICE_INFO 0x0000
#define HWS_REG_DEC_MODE 0x0004
#define HWS_BUSY_POLL_DELAY_US 10
#define HWS_BUSY_POLL_TIMEOUT_US 1000000

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

#define CH_SHIFT 2 /* need 2 bits for 0-3            */

static const struct pci_device_id hws_pci_table[] = {
	MAKE_ENTRY(0x8888, 0x9534, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x1F33, 0x8534, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x1F33, 0x8554, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x8888, 0x8524, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x1F33, 0x6524, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x8888, 0x8504, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x8888, 0x6504, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x8888, 0x8532, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x8888, 0x8512, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x8888, 0x8501, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x1F33, 0x6502, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x1F33, 0x8504, 0x8888, 0x0007, NULL),
	MAKE_ENTRY(0x1F33, 0x8524, 0x8888, 0x0007, NULL),

	{}
};

static void enable_pcie_relaxed_ordering(struct pci_dev *dev)
{
	pcie_capability_set_word(dev, PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_RELAX_EN);
}

static void hws_configure_hardware_capabilities(struct hws_pcie_dev *hdev)
{
	u16 id = hdev->device_id;

	/* select per-chip channel counts */
	switch (id) {
	case 0x9534:
	case 0x6524:
	case 0x8524:
		hdev->cur_max_video_ch = 4;
		hdev->cur_max_linein_ch = 1;
		break;
	case 0x8532:
		hdev->cur_max_video_ch = 2;
		hdev->cur_max_linein_ch = 1;
		break;
	case 0x8512:
	case 0x6502:
		hdev->cur_max_video_ch = 2;
		hdev->cur_max_linein_ch = 0;
		break;
	case 0x8501:
		hdev->cur_max_video_ch = 1;
		hdev->cur_max_linein_ch = 0;
		break;
	default:
		hdev->cur_max_video_ch = 4;
		hdev->cur_max_linein_ch = 0;
		break;
	}

	/* universal buffer capacity */
	hdev->max_hw_video_buf_sz = MAX_MM_VIDEO_SIZE;

	/* decide hardware-version and program DMA max size if needed */
	if (hdev->device_ver > 121) {
		if (id == 0x8501 && hdev->device_ver == 122) {
			hdev->hw_ver = 0;
		} else {
			hdev->hw_ver = 1;
			u32 dma_max = (u32)(MAX_VIDEO_SCALER_SIZE / 16);

			writel(dma_max, hdev->bar0_base + HWS_REG_DMA_MAX_SIZE);
			/* readback to flush posted MMIO write */
			(void)readl(hdev->bar0_base + HWS_REG_DMA_MAX_SIZE);
		}
	} else {
		hdev->hw_ver = 0;
	}
}

static void hws_stop_device(struct hws_pcie_dev *hws);

static int read_chip_id(struct hws_pcie_dev *hdev)
{
	u32 reg;
	int i;
	/* mirror PCI IDs for later switches */
	hdev->device_id = hdev->pdev->device;
	hdev->vendor_id = hdev->pdev->vendor;

	reg = readl(hdev->bar0_base + HWS_REG_DEVICE_INFO);

	hdev->device_ver = FIELD_GET(DEVINFO_VER, reg);
	hdev->sub_ver = FIELD_GET(DEVINFO_SUBVER, reg);
	hdev->support_yv12 = FIELD_GET(DEVINFO_YV12, reg);
	hdev->port_id = FIELD_GET(DEVINFO_PORTID, reg);

	hdev->max_hw_video_buf_sz = MAX_MM_VIDEO_SIZE;
	hdev->max_channels = 4;
	hdev->buf_allocated = false;
	hdev->main_task = NULL;
	hdev->audio_pkt_size = MAX_DMA_AUDIO_PK_SIZE;
	hdev->start_run = false;
	hdev->pci_lost = 0;

	writel(0x00, hdev->bar0_base + HWS_REG_DEC_MODE);
	writel(0x10, hdev->bar0_base + HWS_REG_DEC_MODE);

	hws_configure_hardware_capabilities(hdev);

	dev_info(&hdev->pdev->dev,
		 "chip detected: ver=%u subver=%u port=%u yv12=%u\n",
		 hdev->device_ver, hdev->sub_ver, hdev->port_id,
		 hdev->support_yv12);

	return 0;
}

static void hws_free_irq_vectors_action(void *data)
{
	pci_free_irq_vectors((struct pci_dev *)data);
}

static int main_ks_thread_handle(void *data)
{
	struct hws_pcie_dev *pdx = data;
	int i;
	bool need_check;

	set_freezable();

	while (!kthread_should_stop()) {
		/* If we’re suspending, don’t touch hardware; just sleep/freeeze */
		if (READ_ONCE(pdx->suspended)) {
			try_to_freeze();
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		need_check = false;

		/* See if any channel is running */
		for (i = 0; i < pdx->max_channels; i++) {
			if (pdx->video[i].cap_active) {
				need_check = true;
				break;
			}
		}

		if (need_check)
			/* avoid MMIO when suspended (guarded above) */
			check_video_format(pdx);

		try_to_freeze(); /* cooperate with freezer each loop */

		/* Sleep 1s or until signaled to wake/stop */
		schedule_timeout_interruptible(msecs_to_jiffies(1000));
	}

	pr_debug("%s: exiting\n", __func__);
	return 0;
}

static void hws_stop_kthread_action(void *data)
{
	struct task_struct *t = data;

	if (!IS_ERR_OR_NULL(t))
		kthread_stop(t);
}

static int hws_probe(struct pci_dev *pdev, const struct pci_device_id *pci_id)
{
	struct hws_pcie_dev *hws;
	void __iomem *bar0;
	int i, ret, nvec, irq;

	/* devres-backed device object */
	hws = devm_kzalloc(&pdev->dev, sizeof(*hws), GFP_KERNEL);
	if (!hws)
		return -ENOMEM;

	hws->pdev = pdev;
	hws->irq = -1;
	hws->suspended = false;
	pci_set_drvdata(pdev, hws);

	/* 1) Managed enable + bus mastering */
	ret = pcim_enable_device(pdev);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "pcim_enable_device\n");

	pci_set_master(pdev);

	/* 2) Map BAR0 with PCIM (auto request_regions + iounmap on detach) */
	ret = pcim_iomap_regions(pdev, BIT(0), KBUILD_MODNAME);
	if (ret)
		return dev_err_probe(&pdev->dev, ret,
				     "pcim_iomap_regions BAR0\n");
	hws->bar0_base = pcim_iomap_table(pdev)[0];

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "No 32-bit DMA support\n");

	/* 4) Relaxed Ordering, ReadRQ, etc. if you need them */
	enable_pcie_relaxed_ordering(pdev);
#ifdef CONFIG_ARCH_TI816X
	pcie_set_readrq(pdev, 128);
#endif

	/* 5) Identify chip & set capabilities */
	read_chip_id(hws);

	dev_info(&pdev->dev, "Device VID=0x%04x, DID=0x%04x\n", pdev->vendor,
		 pdev->device);
	/* 6) Init channels (explicit unwind on failure is fine here) */
	for (i = 0; i < hws->max_channels; i++) {
		ret = hws_video_init_channel(hws, i);
		if (ret) {
            dev_err(&pdev->dev, "video channel init (ch=%d)", i);
			goto err_unwind_channels;
        }
		ret = hws_audio_init_channel(hws, i);
		if (ret) {
            dev_err(&pdev->dev, "audio channel init (ch=%d)", i);
			goto err_unwind_channels;
        }
	}

	/* 8) Allocate IRQ vector(s) the modern way; free via devm action */
	nvec = pci_alloc_irq_vectors(pdev, 1, 1,
				     PCI_IRQ_ALL_TYPES | PCI_IRQ_AFFINITY);
	if (nvec < 0) {
		ret = nvec;
		dev_err(&pdev->dev, "pci_alloc_irq_vectors: %d\n", ret);
		goto err_unwind_channels;
	}
	ret = devm_add_action_or_reset(&pdev->dev, hws_free_irq_vectors_action,
				       pdev);
	if (ret) {
		dev_err(&pdev->dev, "devm_add_action: free_irq_vectors: %d\n",
			ret);
		goto err_unwind_channels; /* add_action already called reset */
	}

	irq = pci_irq_vector(pdev, 0);
	ret = devm_request_irq(&pdev->dev, irq, hws_irq_handler, IRQF_SHARED,
			       dev_name(&pdev->dev), hws);
	if (ret) {
		dev_err(&pdev->dev, "request_irq(%d): %d\n", irq, ret);
		goto err_unwind_channels;
	}

	hws->irq = irq;

	/* 10) Register V4L2/ALSA */
	ret = hws_video_register(hws);
	if (ret) {
		dev_err(&pdev->dev, "video_register: %d\n", ret);
		goto err_unwind_channels;
	}
	ret = hws_audio_register(hws);
	if (ret) {
		dev_err(&pdev->dev, "audio_register: %d\n", ret);
		hws_video_unregister(hws);
		goto err_unwind_channels;
	}

	/* 11) Background monitor thread (managed stop via devm action) */
	hws->main_task = kthread_run(main_ks_thread_handle, hws, "hws-mon");
	if (IS_ERR(hws->main_task)) {
		ret = PTR_ERR(hws->main_task);
		hws->main_task = NULL;
		dev_err(&pdev->dev, "kthread_run: %d\n", ret);
		goto err_unregister_va;
	}
	ret = devm_add_action_or_reset(&pdev->dev, hws_stop_kthread_action,
				       hws->main_task);
	if (ret) {
		dev_err(&pdev->dev, "devm_add_action: kthread_stop: %d\n", ret);
		goto err_unregister_va; /* reset already stopped the thread */
	}

	return 0;

err_unregister_va:
	hws_stop_device(hws);
	hws_audio_unregister(hws);
	hws_video_unregister(hws);
err_unwind_channels:
	/* explicit per-channel teardown for any initted channels */
	while (--i >= 0) {
		hws_video_cleanup_channel(hws, i);
		hws_audio_cleanup_channel(hws, i, true);
	}
	return ret;
}

static int hws_check_busy(struct hws_pcie_dev *pdx)
{
	void __iomem *reg = pdx->bar0_base + HWS_REG_SYS_STATUS;
	u32 val;
	int ret;

	/* poll until !(val & BUSY_BIT), sleeping HWS_BUSY_POLL_DELAY_US between reads */
	ret = readl_poll_timeout(reg, val, !(val & HWS_SYS_DMA_BUSY_BIT),
				 HWS_BUSY_POLL_DELAY_US,
				 HWS_BUSY_POLL_TIMEOUT_US);
	if (ret) {
		dev_err(&pdx->pdev->dev,
			"SYS_STATUS busy bit never cleared (0x%08x)\n", val);
		return -ETIMEDOUT;
	}

	return 0;
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

	if (hws_check_busy(hws))
		dev_warn(&hws->pdev->dev, "DSP busy timeout on stop\n");
	/* Disable video capture engine in the DSP */
	writel(0x0, hws->bar0_base + HWS_REG_VCAP_ENABLE);
}

/* Publish stop so ISR/BH won’t touch ALSA/VB2 anymore. */
static void hws_publish_stop_flags(struct hws_pcie_dev *hws)
{
	unsigned int i;

	for (i = 0; i < hws->cur_max_video_ch; ++i) {
		struct hws_video *v = &hws->video[i];

		WRITE_ONCE(v->cap_active,     false);
		WRITE_ONCE(v->stop_requested, true);
	}

	for (i = 0; i < hws->cur_max_linein_ch; ++i) {
		struct hws_audio *a = &hws->audio[i];

		WRITE_ONCE(a->stream_running, false);
		WRITE_ONCE(a->cap_active,     false);
		WRITE_ONCE(a->stop_requested, true);
	}

	smp_wmb(); /* make flags visible before we touch MMIO/queues */
}

/* Drain engines + ISR/BH after flags are published. */
static void hws_drain_after_stop(struct hws_pcie_dev *hws)
{
	u32 ackmask = 0;
	unsigned int i;

	/* Mask device enables: no new DMA starts. */
	writel(0x0, hws->bar0_base + HWS_REG_VCAP_ENABLE);
	writel(0x0, hws->bar0_base + HWS_REG_ACAP_ENABLE);
	(void)readl(hws->bar0_base + HWS_REG_INT_STATUS); /* flush */

	/* Let any in-flight DMAs finish (best-effort). */
	(void)hws_check_busy(hws);

	/* Kill video tasklets to avoid late BH completions. */
	for (i = 0; i < hws->cur_max_video_ch; ++i)
		tasklet_kill(&hws->video[i].bh_tasklet);

	/* Ack any latched VDONE/ADONE. */
	for (i = 0; i < hws->cur_max_video_ch; ++i)
		ackmask |= HWS_INT_VDONE_BIT(i);
	for (i = 0; i < hws->cur_max_linein_ch; ++i)
		ackmask |= HWS_INT_ADONE_BIT(i);
	if (ackmask) {
		writel(ackmask, hws->bar0_base + HWS_REG_INT_ACK);
		(void)readl(hws->bar0_base + HWS_REG_INT_STATUS);
	}

	/* Ensure no hard IRQ is still running. */
	if (hws->irq >= 0)
		synchronize_irq(hws->irq);
}

static void hws_stop_device(struct hws_pcie_dev *hws)
{
	u32 status = readl(hws->bar0_base + HWS_REG_PIPE_BASE(0));

	dev_dbg(&hws->pdev->dev, "%s: status=0x%08x\n", __func__, status);
	if (status == 0xFFFFFFFF) {
		hws->pci_lost = true;
		goto out;
	}

	/* Make ISR/BH a no-op, then drain engines/IRQ. */
	hws_publish_stop_flags(hws);
	hws_drain_after_stop(hws);

	/* 1) Stop the on-board DSP */
	hws_stop_dsp(hws);

out:
	hws->start_run = false;
	dev_dbg(&hws->pdev->dev, "%s: complete\n", __func__);
}

static void hws_remove(struct pci_dev *pdev)
{
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);
	int i;

	if (!hws)
		return;

	/* Stop hardware / capture cleanly (your helper) */
	hws_stop_device(hws);

	/* Unregister subsystems you registered */
	hws_audio_unregister(hws);
	hws_video_unregister(hws);

	/* Per-channel teardown */
	for (i = 0; i < hws->max_channels; i++) {
		hws_video_cleanup_channel(hws, i);
		hws_audio_cleanup_channel(hws, i, true);
	}
	/* kthread is stopped by the devm action you added in probe */
}

#ifdef CONFIG_PM_SLEEP
static int hws_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);

	/* Block monitor thread / any hot path from MMIO */
	WRITE_ONCE(hws->suspended, true);
	if (hws->irq >= 0)
		disable_irq(hws->irq);

	/* Gracefully quiesce userspace I/O first */
	hws_audio_pm_suspend_all(hws);          /* ALSA: stop substreams */
	hws_video_pm_suspend(hws);               /* VB2: streamoff + drain + discard */

	/* Quiesce hardware (DSP/engines) */
	hws_stop_device(hws);

	pci_save_state(pdev);
	pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3hot);

	return 0;
}

static int hws_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);
	int ret;

	/* Back to D0 and re-enable the function */
	pci_set_power_state(pdev, PCI_D0);

	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(dev, "pci_enable_device: %d\n", ret);
		return ret;
	}
	pci_restore_state(pdev);
	pci_set_master(pdev);

	/* Reapply any PCIe tuning lost across D3 */
	enable_pcie_relaxed_ordering(pdev);

	/* Reinitialize chip-side capabilities / registers */
	read_chip_id(hws);

	/* IRQs can be re-enabled now that MMIO is sane */
	if (hws->irq >= 0)
		enable_irq(hws->irq);

	WRITE_ONCE(hws->suspended, false);

	/* vb2: nothing mandatory; userspace will STREAMON again when ready */
	hws_video_pm_resume(hws);

	return 0;
}

static SIMPLE_DEV_PM_OPS(hws_pm_ops, hws_pm_suspend, hws_pm_resume);
# define HWS_PM_OPS (&hws_pm_ops)
#else
# define HWS_PM_OPS NULL
#endif

static struct pci_driver hws_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = hws_pci_table,
	.probe = hws_probe,
	.remove = hws_remove,
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
