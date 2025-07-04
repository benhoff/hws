/* SPDX-License-Identifier: GPL-2.0-only */
#include "hws_dma.h"
#include "hws_pci.h"

void dma_mem_free_pool(struct hws_pcie_dev *pdx)
{
	//Trace t("dma_mem_free_pool()");
	int i = 0, k;

	unsigned long phyvirt_addr;

	if (pdx->m_bBufferAllocate == TRUE) {
		//---------------
		for (i = 0; i < pdx->m_nMaxChl; i++) {
			if (pdx->m_pbyVideoBuffer[i]) {
				dma_free_coherent(&pdx->pdev->dev,
						  pdx->m_MaxHWVideoBufferSize,
						  pdx->m_pbyVideoBuffer[i],
						  pdx->m_pbyVideo_phys[i]);
				pdx->m_pbyVideoBuffer[i] = NULL;
			}
		}
		for (i = 0; i < pdx->m_nCurreMaxVideoChl; i++) {
			if (pdx->m_VideoInfo[i].m_pVideoScalerBuf) {
				vfree(pdx->m_VideoInfo[i].m_pVideoScalerBuf);
				pdx->m_VideoInfo[i].m_pVideoScalerBuf = NULL;
			}

			if (pdx->m_VideoInfo[i].m_pVideoYUV2Buf) {
				vfree(pdx->m_VideoInfo[i].m_pVideoYUV2Buf);
				pdx->m_VideoInfo[i].m_pVideoYUV2Buf = NULL;
			}

			if (pdx->m_VideoInfo[i].m_pRotateVideoBuf) {
				vfree(pdx->m_VideoInfo[i].m_pRotateVideoBuf);
				pdx->m_VideoInfo[i].m_pRotateVideoBuf = NULL;
			}
			for (k = 0; k < MAX_VIDEO_QUEUE; k++) {
				if (pdx->m_VideoInfo[i].m_pVideoBufData[k]) {
					for (phyvirt_addr =
						     (unsigned long)pdx
							     ->m_VideoInfo[i]
							     .m_pVideoData_area
								     [k];
					     phyvirt_addr <
					     ((unsigned long)pdx->m_VideoInfo[i]
						      .m_pVideoData_area[k] +
					      pdx->m_MaxHWVideoBufferSize);
					     phyvirt_addr += PAGE_SIZE) {
						// clear all pages
						ClearPageReserved(virt_to_page(
							phyvirt_addr));
					}
					kfree(pdx->m_VideoInfo[i]
						      .m_pVideoBufData[k]);
					pdx->m_VideoInfo[i].m_pVideoBufData[k] =
						NULL;
				}
			}
			//----audio release
			for (k = 0; k < MAX_AUDIO_QUEUE; k++) {
				if (pdx->m_AudioInfo[i].m_pAudioBufData[k]) {
					for (phyvirt_addr =
						     (unsigned long)pdx
							     ->m_AudioInfo[i]
							     .m_pAudioData_area
								     [k];
					     phyvirt_addr <
					     ((unsigned long)pdx->m_AudioInfo[i]
						      .m_pAudioData_area[k] +
					      pdx->m_dwAudioPTKSize);
					     phyvirt_addr += PAGE_SIZE) {
						// clear all pages
						ClearPageReserved(virt_to_page(
							phyvirt_addr));
					}
					kfree(pdx->m_AudioInfo[i]
						      .m_pAudioBufData[k]);
					pdx->m_AudioInfo[i].m_pAudioBufData[k] =
						NULL;
				}
			}
		}
		pdx->m_bBufferAllocate = FALSE;
	}
}

int dma_mem_alloc_pool(struct hws_pcie_dev *pdx)
{
	u32 status = 0;
	u8 i, k;
	dma_addr_t phy_addr;

	unsigned long phyvirt_addr;

	if (pdx->m_bBufferAllocate == TRUE) {
		dma_mem_free_pool(pdx);
	}
	//------------
	for (i = 0; i < pdx->m_nMaxChl; i++) {
		pdx->m_pbyVideoBuffer[i] = dma_alloc_coherent(
			&pdx->pdev->dev, pdx->m_MaxHWVideoBufferSize,
			&pdx->m_pbyVideo_phys[i], GFP_KERNEL);

		if (!pdx->m_pbyVideoBuffer[i]) {
			pdx->m_bBufferAllocate = TRUE;
			dma_mem_free_pool(pdx);
			pdx->m_bBufferAllocate = FALSE;
			status = -1;
			return status;
		}
		phy_addr = pdx->m_pbyVideo_phys[i];

		pdx->m_dwVideoBuffer[i] = ((u64)phy_addr) & 0xFFFFFFFF;
		pdx->m_dwVideoHighBuffer[i] = ((u64)phy_addr >> 32) &
					      0xFFFFFFFF;
		;

		pdx->m_pbyAudioBuffer[i] =
			(BYTE *)(pdx->m_pbyVideoBuffer[i] +
				 pdx->m_MaxHWVideoBufferSize -
				 MAX_AUDIO_CAP_SIZE);
		phy_addr = pdx->m_pbyVideo_phys[i] +
			   (pdx->m_MaxHWVideoBufferSize - MAX_AUDIO_CAP_SIZE);
		pdx->m_pbyAudio_phys[i] = phy_addr;

		pdx->m_dwAudioBuffer[i] = pdx->m_dwVideoBuffer[i] +
					  pdx->m_MaxHWVideoBufferSize -
					  MAX_AUDIO_CAP_SIZE;
		pdx->m_dwAudioBufferHigh[i] = pdx->m_dwVideoHighBuffer[i];
	}

	//KdPrint(("Mem allocate::m_dwAudioBuffer[%d] = %x\n", i, pdx->m_dwAudioBuffer));
	//-------------- video buffer
	for (i = 0; i < pdx->m_nCurreMaxVideoChl; i++) {
		pdx->m_VideoInfo[i].m_pVideoScalerBuf =
			vmalloc(MAX_VIDEO_HW_W * MAX_VIDEO_HW_H * 2);
		if (!pdx->m_VideoInfo[i].m_pVideoScalerBuf) {
			pdx->m_bBufferAllocate = TRUE;
			dma_mem_free_pool(pdx);
			pdx->m_bBufferAllocate = FALSE;
			status = -1;
			return status;
		}

		pdx->m_VideoInfo[i].m_pVideoYUV2Buf =
			vmalloc(MAX_VIDEO_HW_W * MAX_VIDEO_HW_H * 2);
		if (!pdx->m_VideoInfo[i].m_pVideoYUV2Buf) {
			pdx->m_bBufferAllocate = TRUE;
			dma_mem_free_pool(pdx);
			pdx->m_bBufferAllocate = FALSE;
			status = -1;
			return status;
		}

		pdx->m_VideoInfo[i].m_pRotateVideoBuf =
			vmalloc(MAX_VIDEO_HW_W * MAX_VIDEO_HW_H * 2);
		if (!pdx->m_VideoInfo[i].m_pRotateVideoBuf) {
			pdx->m_bBufferAllocate = TRUE;
			dma_mem_free_pool(pdx);
			pdx->m_bBufferAllocate = FALSE;
			status = -1;
			return status;
		}

		for (k = 0; k < MAX_VIDEO_QUEUE; k++) {
			pdx->m_VideoInfo[i].m_pVideoBufData[k] = kmalloc(
				(pdx->m_MaxHWVideoBufferSize), GFP_KERNEL);
			if (!pdx->m_VideoInfo[i].m_pVideoBufData[k]) {
				pdx->m_bBufferAllocate = TRUE;
				dma_mem_free_pool(pdx);
				pdx->m_bBufferAllocate = FALSE;
				status = -1;
				return status;

			} else {
				pdx->m_VideoInfo[i].m_pVideoData_area[k] =
					(char *)(((unsigned long)pdx
							  ->m_VideoInfo[i]
							  .m_pVideoBufData[k] +
						  PAGE_SIZE - 1) &
						 PAGE_MASK);
				for (phyvirt_addr =
					     (unsigned long)pdx->m_VideoInfo[i]
						     .m_pVideoData_area[k];
				     phyvirt_addr <
				     ((unsigned long)pdx->m_VideoInfo[i]
					      .m_pVideoData_area[k] +
				      (pdx->m_MaxHWVideoBufferSize));
				     phyvirt_addr += PAGE_SIZE) {
					// reserve all pages to make them remapable
					SetPageReserved(
						virt_to_page(phyvirt_addr));
				}
				memset(pdx->m_VideoInfo[i].m_pVideoBufData[k],
				       0x0, pdx->m_MaxHWVideoBufferSize);
			}
		}
	}

//----------audio alloc
	for (i = 0; i < pdx->m_nCurreMaxVideoChl; i++) {
		for (k = 0; k < MAX_AUDIO_QUEUE; k++) {
			pdx->m_AudioInfo[i].m_pAudioBufData[k] =
				kmalloc(pdx->m_dwAudioPTKSize, GFP_KERNEL);
			if (!pdx->m_AudioInfo[i].m_pAudioBufData[k]) {
				pdx->m_bBufferAllocate = TRUE;
				dma_mem_free_pool(pdx);
				pdx->m_bBufferAllocate = FALSE;
				status = -1;
				return status;
			} else {
				pdx->m_AudioInfo[i].pStatusInfo[k].byLock =
					MEM_UNLOCK;
				pdx->m_AudioInfo[i].m_pAudioData_area[k] =
					(char *)(((unsigned long)pdx
							  ->m_AudioInfo[i]
							  .m_pAudioBufData[k] +
						  PAGE_SIZE - 1) &
						 PAGE_MASK);
				for (phyvirt_addr =
					     (unsigned long)pdx->m_AudioInfo[i]
						     .m_pAudioData_area[k];
				     phyvirt_addr <
				     ((unsigned long)pdx->m_AudioInfo[i]
					      .m_pAudioData_area[k] +
				      pdx->m_dwAudioPTKSize);
				     phyvirt_addr += PAGE_SIZE) {
					// reserve all pages to make them remapable
					SetPageReserved(
						virt_to_page(phyvirt_addr));
				}
			}
		}
	}
	//------------------------------------------------------------
	//KdPrint(("Mem allocate::m_pAudioData = %x\n",  pdx->m_pAudioData));
	pdx->m_bBufferAllocate = TRUE;
	//KdPrint(("DmaMemAllocPool  ed\n"));
	return 0;
}

void set_dma_address(struct hws_pcie_dev *pdx)
{
	//-------------------------------------

	u32 Addrmsk;
	u32 AddrLowmsk;
	//u32 AddrPageSize;
	//u32 Addr2PageSize;
	u32 PhyAddr_A_Low;
	u32 PhyAddr_A_High;

	//u32 PhyAddr_A_Low2;
	//u32 PhyAddr_A_High2;
	//u32 PCI_Addr2;

	u32 PCI_Addr;
	//u32 AVALON_Addr;
	u32 cnt;
	//u64 m_tmp64cnt = 0;
	//u32 RDAvalon = 0;
	//u32 m_AddreeSpace = 0;
	int i = 0;
	u32 m_ReadTmp;
	u32 m_ReadTmp2;
	//u32 m_ReadTmp3;
	//u32 m_ReadTmp4;
	DWORD halfframe_length = 0;
	//DWORD m_Valude;
	PhyAddr_A_High = 0;
	PhyAddr_A_Low = 0;
	PCI_Addr = 0;

	//------------------------------------------ // re write dma register

	Addrmsk = PCI_E_BAR_ADD_MASK;
	AddrLowmsk = PCI_E_BAR_ADD_LOWMASK;

	cnt = 0x208; // Table address
	for (i = 0; i < pdx->m_nMaxChl; i++) {
		//printk("[MV] pdx->m_pbyVideoBuffer[%d]=%x\n", i, pdx->m_pbyVideoBuffer[i]);
		if (pdx->m_pbyVideoBuffer[i]) {
			PhyAddr_A_Low = pdx->m_dwVideoBuffer[i];
			PhyAddr_A_High = pdx->m_dwVideoHighBuffer[i];

			PCI_Addr = (PhyAddr_A_Low & AddrLowmsk);
			PhyAddr_A_Low = (PhyAddr_A_Low & Addrmsk);

			//printk("[MV]1-pdx->m_dwVideoBuffer[%d]-%X\n",i,pdx->m_dwVideoBuffer[i]);
			//--------------------------------------------------------------
			WRITE_REGISTER_ULONG(pdx, (PCI_ADDR_TABLE_BASE + cnt),
					     PhyAddr_A_High);
			WRITE_REGISTER_ULONG(pdx,
					     (PCI_ADDR_TABLE_BASE + cnt +
					      PCIE_BARADDROFSIZE),
					     PhyAddr_A_Low); //Entry 0
			//----------------------------------------
			m_ReadTmp = READ_REGISTER_ULONG(
				pdx, (PCI_ADDR_TABLE_BASE + cnt));
			m_ReadTmp2 = READ_REGISTER_ULONG(
				pdx, (PCI_ADDR_TABLE_BASE + cnt +
				      PCIE_BARADDROFSIZE));

			//--------------------------
			WRITE_REGISTER_ULONG(pdx, (CBVS_IN_BUF_BASE + (i * PCIE_BARADDROFSIZE)),
					     ((i + 1) * PCIEBAR_AXI_BASE) +
					PCI_Addr); //Buffer 1 address
			halfframe_length = pdx->m_format[i].HLAF_SIZE / 16;
			WRITE_REGISTER_ULONG(pdx,
                    (CBVS_IN_BUF_BASE2 + (i * PCIE_BARADDROFSIZE)),
					     halfframe_length); //Buffer 1 address

			m_ReadTmp = READ_REGISTER_ULONG(pdx, (CBVS_IN_BUF_BASE + (i * PCIE_BARADDROFSIZE)));
			m_ReadTmp2 = READ_REGISTER_ULONG(pdx, (CBVS_IN_BUF_BASE2 + (i * PCIE_BARADDROFSIZE)));

			//---------------------------
		}
		cnt += 8;
		if (pdx->m_pbyAudioBuffer[i]) {
			PhyAddr_A_Low = pdx->m_dwAudioBuffer[i];
			PhyAddr_A_High = pdx->m_dwAudioBufferHigh[i];
			PCI_Addr = (PhyAddr_A_Low & AddrLowmsk);
			PhyAddr_A_Low = (PhyAddr_A_Low & Addrmsk);

			WRITE_REGISTER_ULONG(pdx,
					     (CBVS_IN_BUF_BASE +
					      ((8 + i) * PCIE_BARADDROFSIZE)),
					     ((i + 1) * PCIEBAR_AXI_BASE +
					      PCI_Addr)); //Buffer 1 address
			m_ReadTmp = READ_REGISTER_ULONG(pdx, (CBVS_IN_BUF_BASE +
				      ((8 + i) * PCIE_BARADDROFSIZE)));
		}
	}
	WRITE_REGISTER_ULONG(pdx, INT_EN_REG_BASE,
			     0x3ffff); //enable PCI Interruput
}
