/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _HWS_DEBUGFS_H
#define _HWS_DEBUGFS_H

struct hws_pcie_dev;

void hws_debugfs_init(struct hws_pcie_dev *hws);
void hws_debugfs_cleanup(struct hws_pcie_dev *hws);

#endif
