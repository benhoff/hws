/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_DEBUGFS_H
#define HWS_DEBUGFS_H

struct hws_pcie_dev;

int hws_debugfs_init(void);
void hws_debugfs_exit(void);
void hws_debugfs_add_device(struct hws_pcie_dev *hws);
void hws_debugfs_remove_device(struct hws_pcie_dev *hws);

#endif
