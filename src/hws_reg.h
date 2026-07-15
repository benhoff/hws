/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _HWS_PCIE_REG_H
#define _HWS_PCIE_REG_H

#include <linux/bits.h>
#include <linux/sizes.h>

#include "hws_reg_atlas_offsets.h"

#define XDMA_CHANNEL_NUM_MAX (1)
#define MAX_NUM_ENGINES (XDMA_CHANNEL_NUM_MAX * 2)

#define  PCIE_BARADDROFSIZE 4u

#define PCI_BUS_ACCESS_BASE       0x00000000U
#define INT_EN_REG_BASE           HWS_ATLAS_INT_ENABLE_OFFSET
#define PCIEBR_EN_REG_BASE        HWS_ATLAS_PCIE_BRIDGE_ENABLE_OFFSET
#define PCIE_INT_DEC_REG_BASE     HWS_ATLAS_INT_DECODE_OFFSET

#define HWS_INT_EN_MASK           0x0003FFFFU

#define PCIEBAR_AXI_BASE 0x20000000U

#define CTL_REG_ACC_BASE 0x0
#define PCI_ADDR_TABLE_BASE CTL_REG_ACC_BASE

#define CVBS_IN_BASE              0x00004000U
#define CVBS_IN_BUF_BASE          HWS_ATLAS_VIDEO_DMA_BASE_OFFSET
#define CVBS_IN_BUF_BASE2         HWS_ATLAS_VIDEO_HALF_SIZE_OFFSET

/* 2 Mib */
#define MAX_L_VIDEO_SIZE            0x200000U

#define PCI_E_BAR_PAGE_SIZE 0x20000000
#define PCI_E_BAR_ADD_MASK 0xE0000000
#define PCI_E_BAR_ADD_LOWMASK 0x1FFFFFFF

#define MAX_DMA_AUDIO_PK_SIZE      (128U * 16U * 2U)
/*
 * The legacy driver reserved a 10 KiB hardware capture window per audio
 * channel even though the delivered packet size is 4 KiB. Keep that headroom
 * for the split-buffer DMA engine.
 */
#define MAX_AUDIO_CAP_SIZE         (10U * 1024U)

#define MAX_VID_CHANNELS            4

#define MAX_MM_VIDEO_SIZE            SZ_4M

#define MAX_VIDEO_HW_W 1920
#define MAX_VIDEO_HW_H 1080
#define MAX_VIDEO_SCALER_SIZE     (1920U * 1080U * 2U)

#define MIN_VAMP_BRIGHTNESS_UNITS   0
#define MAX_VAMP_BRIGHTNESS_UNITS   0xff

#define MIN_VAMP_CONTRAST_UNITS     0
#define MAX_VAMP_CONTRAST_UNITS     0xff

#define MIN_VAMP_SATURATION_UNITS   0
#define MAX_VAMP_SATURATION_UNITS   0xff

#define MIN_VAMP_HUE_UNITS          0
#define MAX_VAMP_HUE_UNITS          0xff

#define HWS_BRIGHTNESS_DEFAULT       0x80
#define HWS_CONTRAST_DEFAULT         0x80
#define HWS_SATURATION_DEFAULT       0x80
#define HWS_HUE_DEFAULT              0x00

/* Core/global status. */
#define HWS_REG_SYS_STATUS            HWS_ATLAS_SYSTEM_STATUS_DECODER_CONTROL_OFFSET
/* bit3: DMA busy, bit2: int, ... */

#define HWS_SYS_DMA_BUSY_BIT          BIT(3) /* 0x08 = DMA busy flag */

#define HWS_REG_DEC_MODE       HWS_ATLAS_SYSTEM_STATUS_DECODER_CONTROL_OFFSET
/* Main control register */
#define HWS_REG_CTL            HWS_ATLAS_CONTROL_OFFSET
#define HWS_CTL_IRQ_ENABLE_BIT BIT(0)   /* Global interrupt enable bit */
/*  Write 0x00 to fully reset decoder,
 *  set bit 31=1 to "start run",
 *  low byte=0x13 selects YUYV/BT.709/etc,
 *  in ReadChipId() we also write 0x00 and 0x10 here for chip-ID sequencing.
 */

/* Per-channel done flags. */
#define HWS_REG_INT_STATUS            HWS_ATLAS_INT_STATUS_OFFSET
#define HWS_SYS_IRQ_PENDING_BIT       BIT(2)

/* Capture enable switches. */
/* bit0-3: CH0-CH3 video enable */
#define HWS_REG_VCAP_ENABLE           HWS_ATLAS_VIDEO_CAPTURE_ENABLE_OFFSET
#define HWS_REG_ACAP_ENABLE           HWS_ATLAS_AUDIO_CAPTURE_ENABLE_OFFSET
/* bits0-3: signal present, bits8-11: interlace */
#define HWS_REG_ACTIVE_STATUS          HWS_ATLAS_ACTIVE_STATUS_OFFSET
/* bits0-3: HDCP detected */
#define HWS_REG_HDCP_STATUS            HWS_ATLAS_HDCP_STATUS_OFFSET
#define HWS_REG_DMA_MAX_SIZE           HWS_ATLAS_DMA_MAX_SIZE_OFFSET

/*
 * Buffer base registers follow the vendor/baseline layout:
 *
 *   video base: CVBS_IN_BUF_BASE + ch * 4
 *   audio base: CVBS_IN_BUF_BASE + (8 + ch) * 4
 *
 * Do not add a video doorbell at CVBS_IN_BASE + (26 + ch) * 4.  Those
 * offsets alias the audio base bank for low video channel numbers.
 */
/* Per-channel audio DMA address window. */
#define HWS_REG_VID_DMA_ADDR(ch) \
	(HWS_ATLAS_VIDEO_DMA_BASE_OFFSET + \
	 (ch) * HWS_ATLAS_VIDEO_DMA_BASE_STRIDE)
#define HWS_REG_AUD_DMA_ADDR(ch) \
	(HWS_ATLAS_AUDIO_DMA_BASE_OFFSET + \
	 (ch) * HWS_ATLAS_AUDIO_DMA_BASE_STRIDE)

#define HWS_VIDEO_REMAP_SLOT_OFF(ch) \
	(HWS_ATLAS_DMA_REMAP_HIGH_OFFSET + \
	 (ch) * HWS_ATLAS_DMA_REMAP_HIGH_STRIDE)
#define HWS_VIDEO_REMAP_LOW_SLOT_OFF(ch) \
	(HWS_ATLAS_DMA_REMAP_LOW_OFFSET + \
	 (ch) * HWS_ATLAS_DMA_REMAP_LOW_STRIDE)

/*
 * BAR remap slots are selected by the high bits of the programmed device-side
 * base address.  Both video and audio program (ch + 1) * PCIEBAR_AXI_BASE, so
 * audio shares the same remap slot as video for that channel.  The audio base
 * registers live at CVBS_IN_BUF_BASE + (8 + ch) * 4, but that is a register
 * bank offset, not a second remap-table bank.
 */
#define HWS_AUDIO_REMAP_SLOT_OFF(ch)  HWS_VIDEO_REMAP_SLOT_OFF(ch)
#define HWS_AUDIO_REMAP_LOW_SLOT_OFF(ch) HWS_VIDEO_REMAP_LOW_SLOT_OFF(ch)

#define HWS_REG_VIDEO_HALF_SIZE(ch) \
	(HWS_ATLAS_VIDEO_HALF_SIZE_OFFSET + \
	 (ch) * HWS_ATLAS_VIDEO_HALF_SIZE_STRIDE)

/* Per-channel live buffer toggles (read-only). */
#define HWS_REG_VBUF_TOGGLE(ch) \
	(HWS_ATLAS_VIDEO_BUFFER_TOGGLE_OFFSET + \
	 (ch) * HWS_ATLAS_VIDEO_BUFFER_TOGGLE_STRIDE)
/*
 * Returns 0 or 1 = which half of the video ring the DMA engine is
 * currently filling for channel *ch* (0-3).
 */

#define HWS_REG_ABUF_TOGGLE(ch) \
	(HWS_ATLAS_AUDIO_BUFFER_TOGGLE_OFFSET + \
	 (ch) * HWS_ATLAS_AUDIO_BUFFER_TOGGLE_STRIDE)
/*
 * Returns 0 or 1 = which half of the audio ring the DMA engine is
 * currently filling for channel *ch* (0-3).
 */

/* Per-interrupt bits (video 0-3, audio 0-3). */
#define HWS_INT_VDONE_BIT(ch)     BIT(ch)         /* 0x01,0x02,0x04,0x08  */
#define HWS_INT_ADONE_BIT(ch)     BIT(8 + (ch))   /* 0x100 .. 0x800 */

/* Legacy hardware clears interrupt bits by W1C on INT_STATUS. */
#define HWS_REG_INT_ACK           HWS_REG_INT_STATUS

/* 16-bit W | 16-bit H. */
#define HWS_REG_IN_RES(ch) \
	(HWS_ATLAS_INPUT_RESOLUTION_OFFSET + \
	 (ch) * HWS_ATLAS_INPUT_RESOLUTION_STRIDE)
/* B|C|H|S packed bytes. */
#define HWS_REG_BCHS(ch) \
	(HWS_ATLAS_BCHS_OFFSET + (ch) * HWS_ATLAS_BCHS_STRIDE)

/* Input fps. */
#define HWS_REG_FRAME_RATE(ch) \
	(HWS_ATLAS_INPUT_FRAME_RATE_OFFSET + \
	 (ch) * HWS_ATLAS_INPUT_FRAME_RATE_STRIDE)
/* Programmed out W|H. */
#define HWS_REG_OUT_RES(ch) \
	(HWS_ATLAS_OUTPUT_RESOLUTION_OFFSET + \
	 (ch) * HWS_ATLAS_OUTPUT_RESOLUTION_STRIDE)
/* Programmed out fps. */
#define HWS_REG_OUT_FRAME_RATE(ch) \
	(HWS_ATLAS_OUTPUT_FRAME_RATE_OFFSET + \
	 (ch) * HWS_ATLAS_OUTPUT_FRAME_RATE_STRIDE)

/* Device version/port ID/subversion register. */
#define HWS_REG_DEVICE_INFO   HWS_ATLAS_DEVICE_INFO_OFFSET
#define HWS_DEVINFO_VER       GENMASK(15, 8)
#define HWS_DEVINFO_SUBVER    GENMASK(23, 16)
#define HWS_DEVINFO_HWKEY     GENMASK(27, 24)
#define HWS_DEVINFO_PORTID    GENMASK(25, 24)
#define HWS_DEVINFO_YV12      GENMASK(31, 28)
/*
 * Reading this 32-bit word returns:
 *   bits 7:0   = unused by the baseline driver
 *   bits 15:8  = device version
 *   bits 23:16 = device sub-version
 *   bits 27:24 = HW key (port ID in bits 25:24)
 *   bits 31:28 = "support YV12" flags
 */

/* Convenience aliases for individual channels. */
#define HWS_REG_VBUF_TOGGLE_CH0       HWS_REG_VBUF_TOGGLE(0)
#define HWS_REG_VBUF_TOGGLE_CH1       HWS_REG_VBUF_TOGGLE(1)
#define HWS_REG_VBUF_TOGGLE_CH2       HWS_REG_VBUF_TOGGLE(2)
#define HWS_REG_VBUF_TOGGLE_CH3       HWS_REG_VBUF_TOGGLE(3)

#define HWS_REG_ABUF_TOGGLE_CH0       HWS_REG_ABUF_TOGGLE(0)
#define HWS_REG_ABUF_TOGGLE_CH1       HWS_REG_ABUF_TOGGLE(1)
#define HWS_REG_ABUF_TOGGLE_CH2       HWS_REG_ABUF_TOGGLE(2)
#define HWS_REG_ABUF_TOGGLE_CH3       HWS_REG_ABUF_TOGGLE(3)
#endif /* _HWS_PCIE_REG_H */
