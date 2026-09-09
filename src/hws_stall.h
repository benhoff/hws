/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_STALL_H
#define HWS_STALL_H

struct hws_pcie_dev;
struct hws_video;
struct seq_file;

void hws_stall_monitor(struct hws_pcie_dev *hws);
void hws_stall_streamoff(struct hws_video *v);
int hws_stall_show(struct seq_file *m, void *unused);
bool hws_irq_observer_poll(struct hws_pcie_dev *hws);
void hws_irq_observer_stop(struct hws_pcie_dev *hws, const char *reason);

#endif
