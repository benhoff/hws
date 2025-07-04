/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_DMA_H
#define HWS_DMA_H

#include "hws.h"

int dma_mem_alloc_pool(struct hws_pcie_dev *pdx);
void dma_mem_free_pool(struct hws_pcie_dev *pdx);
void set_dma_address(struct hws_pcie_dev *pdx);

#endif // HWS_DMA_H
