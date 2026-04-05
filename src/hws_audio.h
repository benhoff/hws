/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_AUDIO_PIPELINE_H
#define HWS_AUDIO_PIPELINE_H

#include <linux/workqueue.h>
#include <sound/pcm.h>
#include "hws.h"

int hws_audio_register(struct hws_pcie_dev *dev);
void hws_audio_unregister(struct hws_pcie_dev *hws);
void hws_audio_handle_interrupt(struct hws_pcie_dev *hws, unsigned int ch,
				u8 cur_toggle);
void hws_enable_audio_capture(struct hws_pcie_dev *hws,
			      unsigned int ch,
			      bool enable);

int  hws_start_audio_capture(struct hws_pcie_dev *pdx, unsigned int index);
void hws_stop_audio_capture(struct hws_pcie_dev *pdx, unsigned int index);
int hws_audio_init_channel(struct hws_pcie_dev *pdev, int ch);
void hws_audio_cleanup_channel(struct hws_pcie_dev *pdev, int ch, bool device_removal);
int hws_audio_pm_suspend_all(struct hws_pcie_dev *hws);

#endif /* HWS_AUDIO_PIPELINE_H */
