/* SPDX-License-Identifier: GPL-2.0-only */
#include "hws_pci.h"

#include <media/v4l2-ctrls.h>

#include "hws.h"
#include "hws_init.h"
#include "hws_dma.h"
#include "hws_video_pipeline.h"
#include "hws_audio_pipeline.h"
#include "hws_interrupt.h"
#include "hws_video.h"

#define DRV_NAME "HWS driver

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

	{ }
};

static void enable_pcie_relaxed_ordering(struct pci_dev *dev)
{
	pcie_capability_set_word(dev, PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_RELAX_EN);
}

static int read_chip_id(struct hws_pcie_dev *pdx)
{
	//  CCIR_PACKET      reg;
	//int Chip_id1 = 0;
	int ret = 0;
	//int reg_vaule = 0;
	//int nResult;
	int i;
	//------read Dvice Version
	ULONG m_dev_ver;
	ULONG m_tmpVersion;
	ULONG m_tmpHWKey;
	//ULONG m_OEM_code_data;
	m_dev_ver = READ_REGISTER_ULONG(pdx, HWS_REG_DEVICE_INFO);

	/* Bits 7:0   = device version */
	m_tmpVersion = m_dev_ver >> 8;
	pdx->m_Device_Version = (m_tmpVersion & 0xFF);

	/* Bits 15:8  = device subversion */
	m_tmpVersion = m_dev_ver >> 16;
	pdx->m_Device_SubVersion = (m_tmpVersion & 0xFF);

	/* Bits 31:28 = YV12 support flags (4 bits) */
	pdx->m_Device_SupportYV12 = ((m_dev_ver >> 28) & 0x0F);

	/* Bits 27:24 = HW key; low two bits of that = port ID */
	m_tmpHWKey = (m_dev_ver >> 24) & 0x0F;
	pdx->m_Device_PortID = (m_tmpHWKey & 0x03);

	//n_VideoModle =	READ_REGISTER_ULONG(pdx,0x4000+(4*PCIE_BARADDROFSIZE));
	//n_VideoModle = (n_VideoModle>>8)&0xFF;
	//pdx->m_IsHDModel = 1;
	pdx->m_MaxHWVideoBufferSize = MAX_MM_VIDEO_SIZE;
	pdx->m_nMaxChl = 4;
	pdx->m_bBufferAllocate = FALSE;
	pdx->mMain_tsk = NULL;
	pdx->m_dwAudioPTKSize = MAX_DMA_AUDIO_PK_SIZE; //128*16*4;
	pdx->m_bStartRun = 0;
	pdx->m_PciDeviceLost = 0;

	//--------
	for (i = 0; i < MAX_VID_CHANNELS; i++) {
		SetVideoFormatSize(pdx, i, 1920, 1080);
	}
	//-------
	WRITE_REGISTER_ULONG(pdx, HWS_REG_DEC_MODE, 0x0);
	//ssleep(100);
	WRITE_REGISTER_ULONG(pdx, HWS_REG_DEC_MODE, 0x10);
	//ssleep(500);
	//-------
	SetHardWareInfo(pdx);
	printk("************[HW]-[VIDV]=[%d]-[%d]-[%d] ************\n",
	       pdx->m_Device_Version, pdx->m_Device_SubVersion,
	       pdx->m_Device_PortID);
	return ret;
}

int hws_video_init_channel(struct hws_pcie_dev *dev, int idx);
int hws_audio_init_channel(struct hws_pcie_dev *dev, int idx);

static int hws_probe(struct pci_dev *pci_dev, const struct pci_device_id *pci_id)
{
	struct hws_pcie_dev *hws_dev= NULL;
	int err = 0, ret = -ENODEV;
	int j, i;

	hws_dev = hws_alloc_dev_instance(pci_dev);
	hws_dev->pdev = pci_dev;

	hws_dev->device_id = hws_dev->pci_dev->device;
	hws_dev->vendor_id = hws_dev->pci_dev->vendor;
	dev_info(&pci_dev->dev, "Device VID=0x%04x, DID=0x%04x\n",
		 pci_dev->vendor, pci_dev->device);

	err = pci_enable_device(pci_dev);
	if (err) {
		dev_err(&pci_dev->dev, "%s: pci_enable_device failed: %d\n",
			__func__, err);
		goto err_alloc;
	}

    err = pci_request_regions(pci_dev, DRV_NAME);
    if (err) {
        dev_err(&pci_dev->dev, "pci_request_regions failed: %d\n", err);
        goto disable_device;
    }

    /* map BAR0 via the PCI core: */
    hws_dev->bar0_base = pci_iomap(pci_dev, 0,
                                pci_resource_len(pci_dev, 0));
    if (!hws_dev->bar0_base) {
        dev_err(&pci_dev->dev, "pci_iomap failed\n");
        err = -ENOMEM;
        goto release_regions;
    }


	enable_pcie_relaxed_ordering(pci_dev);
	pci_set_master(pci_dev);
	ret = probe_scan_for_msi(hws_dev, pci_dev);

	if (ret < 0)
		goto disable_msi;

#ifdef CONFIG_ARCH_TI816X
	pcie_set_readrq(pci_dev, 128);
#endif

	hws_dev->video_wq = NULL;
	hws_dev->audio_w = NULL;

	ret = hws_irq_setup(hws_dev, pci_dev);
	if (ret)
		goto err_register;

	pci_set_drvdata(pci_dev, hws_dev);
	read_chip_id(hws_dev);
    /* Initialize each video/audio channel */
    for (i = 0; i < dev->max_channels; i++) {
        ret = hws_video_init_channel(dev, i);
        if (ret)
            goto err_cleanup;
        ret = hws_audio_init_channel(dev, i);
        if (ret)
            goto err_cleanup;
    }
	//---------------------
	tasklet_init(&hws_dev->dpc_video_tasklet[0], DpcForIsr_Video0,
		     (unsigned long)hws_dev);
	tasklet_init(&hws_dev->dpc_video_tasklet[1], DpcForIsr_Video1,
		     (unsigned long)hws_dev);
	tasklet_init(&hws_dev->dpc_video_tasklet[2], DpcForIsr_Video2,
		     (unsigned long)hws_dev);
	tasklet_init(&hws_dev->dpc_video_tasklet[3], DpcForIsr_Video3,
		     (unsigned long)hws_dev);

	tasklet_init(&hws_dev->dpc_audio_tasklet[0], DpcForIsr_Audio0,
		     (unsigned long)hws_dev);
	tasklet_init(&hws_dev->dpc_audio_tasklet[1], DpcForIsr_Audio1,
		     (unsigned long)hws_dev);
	tasklet_init(&hws_dev->dpc_audio_tasklet[2], DpcForIsr_Audio2,
		     (unsigned long)hws_dev);
	tasklet_init(&hws_dev->dpc_audio_tasklet[3], DpcForIsr_Audio3,
		     (unsigned long)hws_dev);

	//----------------------
	ret = dma_mem_alloc_pool(hws_dev);
	if (ret != 0) {
		goto err_mem_alloc;
	}

	InitVideoSys(hws_dev, 0);
	StartKSThread(hws_dev);

	hws_adapters_init(hws_dev);
	hws_dev->wq = create_singlethread_workqueue("hws");
	hws_dev->auwq = create_singlethread_workqueue("hws-audio");

	if (hws_video_register(hws_dev))
		goto err_mem_alloc;

	if (hws_audio_register(hws_dev))
		goto err_mem_alloc;
	return 0;
err_mem_alloc:

	hws_dev->m_bBufferAllocate = TRUE;
	dma_mem_free_pool(hws_dev);
	hws_dev->m_bBufferAllocate = FALSE;
err_ctrl:
	while (--i >= 0)
		v4l2_ctrl_handler_free(&hws_dev->video[i].ctrl_handler);
err_register:
	iounmap(hws_dev->info.mem[0].internal_addr);
	hws_free_irqs(hws_dev);
disable_msi:
	if (hws_dev->msix_enabled) {
		pci_disable_msix(pci_dev);
		hws_dev->msix_enabled = 0;
	} else if (hws_dev->msi_enabled) {
		pci_disable_msi(pci_dev);
		hws_dev->msi_enabled = 0;
	}
release_regions:
    pci_release_regions(pci_dev);
disable_device:
    pci_disable_device(pci_dev);
err_release:
	pci_release_regions(pci_dev);
	pci_disable_device(pci_dev);
	return err;
err_alloc:
	return -1;
}

void hws_remove(struct pci_dev *pdev)
{
	int i;
	struct video_device *vdev;
	struct hws_pcie_dev *dev = (struct hws_pcie_dev *)pci_get_drvdata(pdev);
	//----------------------------
	if (dev->map_bar0_addr == NULL)
		return;
	//StopSys(dev);
	StopDevice(dev);
	/* disable interrupts */
	hws_free_irqs(dev);
	StopKSThread(dev);
	//printk("hws_remove  0\n");
	for (i = 0; i < MAX_VID_CHANNELS; i++) {
		tasklet_kill(&dev->dpc_video_tasklet[i]);
		tasklet_kill(&dev->dpc_audio_tasklet[i]);
	}
	//-------------------------
	//printk("hws_remove  1\n");
	for (i = 0; i < dev->m_nCurreMaxVideoChl; i++) {
		if (dev->audio[i].resampled_buf) {
			vfree(dev->audio[i].resampled_buf);
			dev->audio[i].resampled_buf = NULL;
		}
		if (dev->audio[i].card) {
			snd_card_free(dev->audio[i].card);
			dev->audio[i].card = NULL;
		}
	}
	for (i = 0; i < dev->m_nCurreMaxVideoChl; i++) {
		vdev = &dev->video[i].vdev;
		video_unregister_device(vdev);
		v4l2_device_unregister(&dev->video[i].v4l2_dev);
		v4l2_ctrl_handler_free(&dev->video[i].ctrl_handler);
	}
	//-----------------
	if (dev->wq) {
		destroy_workqueue(dev->wq);
	}

	if (dev->auwq) {
		destroy_workqueue(dev->auwq);
	}
	dev->wq = NULL;
	dev->auwq = NULL;
	//free_irq(dev->pdev->irq, dev);

	iounmap(dev->info.mem[0].internal_addr);

	//pci_disable_device(pdev);
	if (dev->msix_enabled) {
		pci_disable_msix(pdev);
		dev->msix_enabled = 0;
	} else if (dev->msi_enabled) {
		pci_disable_msi(pdev);
		dev->msi_enabled = 0;
	}
	// FIXME: is this no longer needed because we're using device managed memory?
	kfree(dev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	//printk("hws_remove  Done\n");
}

/* ─────────────────────────────────────────────────────────── */
/* Per-video-channel initialisation                            */

static int hws_video_init_channel(struct hws_pcie_dev *pdev, int ch)
{
	struct hws_video              *vid  = &pdev->video[ch];
	struct v4l2_ctrl_handler      *hdl  = &vid->control_handler;
	int                            q;

	/* ── zero and basic identity ─────────────────────────── */
	memset(vid, 0, sizeof(*vid));
	vid->parent         = pdev;
	vid->channel_index  = ch;
	vid->query_index    = 0;
	vid->tv_standard    = V4L2_STD_NTSC_M;
	vid->pixel_format   = V4L2_PIX_FMT_YUYV;
	vid->output_width   = 1920;
	vid->output_height  = 1080;
	vid->output_frame_rate   = 60;
	vid->output_pixel_format = V4L2_PIX_FMT_YUYV;
	vid->output_size_index   = 0;
	vid->current_brightness  =
	vid->current_contrast    =
	vid->current_saturation  =
	vid->current_hue         = 0x80;     /* mid-range defaults */

	/* ── locking & async helpers ─────────────────────────── */
	mutex_init(&vid->state_lock);
	mutex_init(&vid->capture_queue_lock);
	spin_lock_init(&vid->irq_lock);
	INIT_WORK(&vid->video_work, hws_video_work_fn);
	INIT_LIST_HEAD(&vid->capture_queue);

	/* ── V4L2 control handler (detect-5 V + IT-content) ─── */
	v4l2_ctrl_handler_init(hdl, 2);

	vid->detect_tx_5v_control = v4l2_ctrl_new_std(
		hdl, &hws_ctrl_ops,
		V4L2_CID_DV_RX_POWER_PRESENT, 0, 1, 1, 0);
	if (vid->detect_tx_5v_control)
		vid->detect_tx_5v_control->flags |=
			V4L2_CTRL_FLAG_VOLATILE | V4L2_CTRL_FLAG_READ_ONLY;

	vid->content_type_control = v4l2_ctrl_new_std(
		hdl, &hws_ctrl_ops,
		V4L2_CID_DV_RX_IT_CONTENT_TYPE,
		V4L2_DV_IT_CONTENT_TYPE_NO_ITC,
		V4L2_DV_IT_CONTENT_TYPE_GRAPHICS, 1,
		V4L2_DV_IT_CONTENT_TYPE_NO_ITC);
	if (vid->content_type_control)
		vid->content_type_control->flags |=
			V4L2_CTRL_FLAG_VOLATILE | V4L2_CTRL_FLAG_READ_ONLY;

	if (hdl->error) {
		dev_err(&pdev->pdev->dev,
			"V4L2 ctrl init failed on ch %d: %d\n",
			ch, hdl->error);
		return hdl->error;
	}

	/* ── per-queue status defaults ───────────────────────── */
	for (q = 0; q < MAX_VIDEO_QUEUE; q++) {
		vid->info.status[q].lock       = MEM_UNLOCK;
		vid->vcap_status[q].byLock     = MEM_UNLOCK;
		vid->vcap_status[q].byField    = 0;
		vid->vcap_status[q].byPath     = 2;
		vid->vcap_status[q].dwWidth    = 1920;
		vid->vcap_status[q].dwHeight   = 1080;
		vid->vcap_status[q].dwinterlace= 0;
		vid->vcap_status[q].dwFrameRate= 60;
		vid->vcap_status[q].dwOutWidth = 1920;
		vid->vcap_status[q].dwOutHeight= 1080;
		vid->info.video_buf[q]         = NULL;
	}

	/* ── runtime flags ───────────────────────────────────── */
	vid->busy           = false;
	vid->stop           = false;
	vid->int_done       = false;
	vid->sequence_number= 0;

	return 0;
}

/* ─────────────────────────────────────────────────────────── */
/* Per-audio-channel initialisation                            */

static int hws_audio_init_channel(struct hws_pcie_dev *pdev, int ch)
{
	struct hws_audio *aud = &pdev->audio[ch];
	int               q, err;

	memset(aud, 0, sizeof(*aud));
	aud->parent        = pdev;
	aud->channel_index = ch;
	aud->output_sample_rate = 48000;
	aud->channel_count      = 2;
	aud->bits_per_sample    = 16;

	spin_lock_init(&aud->ring_lock);
	INIT_WORK(&aud->audio_work, hws_audio_work_fn);

	/* ring-buffer bookkeeping defaults */
	aud->ring_size_frames       = 0;
	aud->ring_write_pos_frames  = 0;
	aud->period_size_frames     = 0;
	aud->period_used_frames     = 0;
	aud->ring_offset_bytes      = 0;
	aud->ring_overflow_bytes    = 0;

	/* ALSA card skeleton */
	err = snd_card_new(&pdev->pdev->dev, -1, NULL,
			   THIS_MODULE, 0, &aud->sound_card);
	if (err)
		return err;

	/* you would typically create PCM device(s) here, e.g.:
	 * err = hws_pcm_create(aud);
	 * if (err)
	 *     return err;
	 */

	/* init per-queue status */
	for (q = 0; q < MAX_AUDIO_QUEUE; q++) {
		pdev->audio_info[ch].status[q].lock = MEM_UNLOCK;
		pdev->audio_info[ch].audio_buf[q]   = NULL;
	}

	return 0;
}


static struct hws_pcie_dev *hws_alloc_dev_instance(struct pci_dev *pdev)
{
    struct hws_pcie_dev *lro;

    if (WARN_ON(!pdev))
        return ERR_PTR(-EINVAL);

    lro = devm_kzalloc(&pdev->dev, sizeof(*lro), GFP_KERNEL);
    if (!lro) {
        dev_err(&pdev->dev, "failed to alloc hws_pcie_dev\n");
        return ERR_PTR(-ENOMEM);
    }

    /* no IRQ yet */
    lro->irq_line = -1;

    dev_set_drvdata(&pdev->dev, lro);
    lro->pdev = pdev;


    return lro;
}
//--------------------------------------

/* type = PCI_CAP_ID_MSI or PCI_CAP_ID_MSIX */
int msi_msix_capable(struct pci_dev *dev, int type)
{
	struct pci_bus *bus;
	int ret;
	//printk("msi_msix_capable in \n");
	if (!dev || dev->no_msi) {
		printk("msi_msix_capable no_msi exit \n");
		return 0;
	}

	for (bus = dev->bus; bus; bus = bus->parent) {
		if (bus->bus_flags & PCI_BUS_FLAGS_NO_MSI) {
			printk("msi_msix_capable PCI_BUS_FLAGS_NO_MSI \n");
			return 0;
		}
	}
	ret = arch_msi_check_device(dev, 1, type);
	if (ret) {
		return 0;
	}
	ret = pci_find_capability(dev, type);
	if (!ret) {
		printk("msi_msix_capable pci_find_capability =%d\n", ret);
		return 0;
	}

	return 1;
}

int probe_scan_for_msi(struct hws_pcie_dev *lro, struct pci_dev *pdev)
{
	//int i;
	int rc = 0;
	//int req_nvec = MAX_NUM_ENGINES + MAX_USER_IRQ;

	//BUG_ON(!lro);
	//BUG_ON(!pdev);
	//if (msi_msix_capable(pdev, PCI_CAP_ID_MSIX)) {
	//		printk("Enabling MSI-X\n");
	//		for (i = 0; i < req_nvec; i++)
	//			lro->entry[i].entry = i;
	//
	//		rc = pci_enable_msix(pdev, lro->entry, req_nvec);
	//		if (rc < 0)
	//			printk("Couldn't enable MSI-X mode: rc = %d\n", rc);

	//		lro->msix_enabled = 1;
	//		lro->msi_enabled = 0;
	//	}
	//else

	if (msi_msix_capable(pdev, PCI_CAP_ID_MSI)) {
		/* enable message signalled interrupts */
		//printk("pci_enable_msi()\n");
		rc = pci_enable_msi(pdev);
		if (rc < 0) {
			printk("Couldn't enable MSI mode: rc = %d\n", rc);
		}
		lro->msi_enabled = 1;
		lro->msix_enabled = 0;
	} else {
		//printk("MSI/MSI-X not detected - using legacy interrupts\n");
		lro->msi_enabled = 0;
		lro->msix_enabled = 0;
	}

	return rc;
}

void WRITE_REGISTER_ULONG(struct hws_pcie_dev *pdx, u32 RegisterOffset,
			  u32 Value)
{
	//map_bar0_addr[RegisterOffset/4] = Value;
	char *bar0;
	bar0 = (char *)pdx->map_bar0_addr;
	iowrite32(Value, bar0 + RegisterOffset);
	//map_bar0_addr[RegisterOffset/4] = Value;
}

u32 READ_REGISTER_ULONG(struct hws_pcie_dev *pdx, u32 RegisterOffset)
{
	char *bar0;
	bar0 = (char *)pdx->map_bar0_addr;
	//return(map_bar0_addr[RegisterOffset/4]);
	return (ioread32(bar0 + RegisterOffset));
}

static struct pci_driver hws_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = hws_pci_table,
	.probe = hws_probe,
	.remove = hws_remove,
};
/*
*/
#ifndef arch_msi_check_device
int arch_msi_check_device(struct pci_dev *dev, int nvec, int type)
{
	return 0;
}
#endif

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
MODULE_AUTHOR("Sales <sales@avmatrix.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
