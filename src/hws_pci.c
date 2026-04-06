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
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/pm.h>
#include <linux/freezer.h>
#include <linux/pci_regs.h>
#include <linux/seq_file.h>

#include <media/v4l2-ctrls.h>

#include "hws.h"
#include "hws_audio.h"
#include "hws_reg.h"
#include "hws_video.h"
#include "hws_irq.h"
#include "hws_v4l2_ioctl.h"

#define DRV_NAME "hws"
#define HWS_BUSY_POLL_DELAY_US 10
#define HWS_BUSY_POLL_TIMEOUT_US 1000000

static unsigned long long hws_elapsed_us(u64 start_ns)
{
	return div_u64(ktime_get_mono_fast_ns() - start_ns, 1000);
}

static struct dentry *hws_debugfs_root;

void hws_trace_bar0_snapshot(struct hws_pcie_dev *hws, const char *tag)
{
	unsigned int slot, ch;

	if (!hws || !hws->bar0_base || !tag || !hws_audio_trace_enabled())
		return;

	dev_info(&hws->pdev->dev,
		 "bar0-snap:%s core dec_mode=%08x ctl=%08x sys=%08x int=%08x int_en=%08x br=%08x dec=%08x active=%08x vcap=%08x acap=%08x dma_max=%08x\n",
		 tag,
		 readl_relaxed(hws->bar0_base + HWS_REG_DEC_MODE),
		 readl_relaxed(hws->bar0_base + HWS_REG_CTL),
		 readl_relaxed(hws->bar0_base + HWS_REG_SYS_STATUS),
		 readl_relaxed(hws->bar0_base + HWS_REG_INT_STATUS),
		 readl_relaxed(hws->bar0_base + INT_EN_REG_BASE),
		 readl_relaxed(hws->bar0_base + PCIEBR_EN_REG_BASE),
		 readl_relaxed(hws->bar0_base + PCIE_INT_DEC_REG_BASE),
		 readl_relaxed(hws->bar0_base + HWS_REG_ACTIVE_STATUS),
		 readl_relaxed(hws->bar0_base + HWS_REG_VCAP_ENABLE),
		 readl_relaxed(hws->bar0_base + HWS_REG_ACAP_ENABLE),
		 readl_relaxed(hws->bar0_base + HWS_REG_DMA_MAX_SIZE));

	for (slot = 0; slot < 16; slot++) {
		u32 base_reg = CVBS_IN_BUF_BASE + slot * PCIE_BARADDROFSIZE;
		u32 table_off = 0x208 + slot * 8;

		dev_info(&hws->pdev->dev,
			 "bar0-snap:%s slot%u base=%08x remap_hi=%08x remap_lo=%08x\n",
			 tag, slot,
			 readl_relaxed(hws->bar0_base + base_reg),
			 readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE +
				       table_off),
			 readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE +
				       table_off + PCIE_BARADDROFSIZE));
	}

	for (ch = 0; ch < hws->cur_max_linein_ch && ch < MAX_VID_CHANNELS; ch++) {
		dev_info(&hws->pdev->dev,
			 "bar0-snap:%s ach%u base=%08x toggle=%08x stream=%u active=%u irq=%u delivered=%u\n",
			 tag, ch,
			 readl_relaxed(hws->bar0_base + HWS_REG_AUD_DMA_ADDR(ch)),
			 readl_relaxed(hws->bar0_base + HWS_REG_ABUF_TOGGLE(ch)),
			 READ_ONCE(hws->audio[ch].stream_running),
			 READ_ONCE(hws->audio[ch].cap_active),
			 READ_ONCE(hws->audio[ch].irq_count),
			 READ_ONCE(hws->audio[ch].delivered_count));
	}
}

static int hws_reg_probe_append_snapshot(struct hws_pcie_dev *hws, char *buf,
					 size_t len, const char *section)
{
	unsigned int ch;
	int n = 0;

	if (!hws || !buf || !len)
		return 0;

	n += scnprintf(buf + n, len - n, "[%s]\n", section);
	n += scnprintf(buf + n, len - n, "INT_EN=0x%08x\n",
		       readl_relaxed(hws->bar0_base + INT_EN_REG_BASE));
	n += scnprintf(buf + n, len - n, "PCIEBR_EN=0x%08x\n",
		       readl_relaxed(hws->bar0_base + PCIEBR_EN_REG_BASE));
	n += scnprintf(buf + n, len - n, "PCIE_INT_DEC=0x%08x\n",
		       readl_relaxed(hws->bar0_base + PCIE_INT_DEC_REG_BASE));
	n += scnprintf(buf + n, len - n, "ACTIVE_STATUS=0x%08x\n",
		       readl_relaxed(hws->bar0_base + HWS_REG_ACTIVE_STATUS));
	n += scnprintf(buf + n, len - n, "ACAP_ENABLE=0x%08x\n",
		       readl_relaxed(hws->bar0_base + HWS_REG_ACAP_ENABLE));
	n += scnprintf(buf + n, len - n, "INT_STATUS=0x%08x\n",
		       readl_relaxed(hws->bar0_base + HWS_REG_INT_STATUS));

	for (ch = 0; ch < hws->cur_max_linein_ch && n < len; ch++) {
		n += scnprintf(buf + n, len - n,
			       "ch%u.audio_base=0x%08x shared_hi=0x%08x shared_lo=0x%08x audio_hi=0x%08x audio_lo=0x%08x abuf_toggle=0x%08x stream=%u active=%u irq=%u delivered=%u\n",
			       ch,
			       readl_relaxed(hws->bar0_base + HWS_REG_AUD_DMA_ADDR(ch)),
			       readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE +
					     0x208 + ch * 8),
			       readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE +
					     0x20c + ch * 8),
			       readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE +
					     0x208 + (8 + ch) * 8),
			       readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE +
					     0x20c + (8 + ch) * 8),
			       readl_relaxed(hws->bar0_base + HWS_REG_ABUF_TOGGLE(ch)),
			       READ_ONCE(hws->audio[ch].stream_running),
			       READ_ONCE(hws->audio[ch].cap_active),
			       READ_ONCE(hws->audio[ch].irq_count),
			       READ_ONCE(hws->audio[ch].delivered_count));
	}

	return n;
}

static int hws_reg_probe_append_busy(struct hws_pcie_dev *hws, char *buf,
				     size_t len)
{
	unsigned int ch;
	int n = 0;

	if (!hws || !buf || !len)
		return 0;

	for (ch = 0; ch < hws->cur_max_video_ch && n < len; ch++) {
		if (!READ_ONCE(hws->video[ch].cap_active))
			continue;

		n += scnprintf(buf + n, len - n, "busy=video ch%u active\n", ch);
		return n;
	}

	for (ch = 0; ch < hws->cur_max_linein_ch && n < len; ch++) {
		if (!READ_ONCE(hws->audio[ch].stream_running))
			continue;

		n += scnprintf(buf + n, len - n, "busy=audio ch%u running\n",
			       ch);
		return n;
	}

	return 0;
}

static void hws_reg_probe_write_read_restore(struct hws_pcie_dev *hws, u32 reg,
					     u32 test, u32 *orig, u32 *readback,
					     u32 *restored)
{
	*orig = readl(hws->bar0_base + reg);
	writel(test, hws->bar0_base + reg);
	*readback = readl(hws->bar0_base + reg);
	writel(*orig, hws->bar0_base + reg);
	*restored = readl(hws->bar0_base + reg);
}

static int hws_reg_probe_append_write_probe(struct hws_pcie_dev *hws, char *buf,
					    size_t len)
{
	unsigned int ch;
	int n = 0;
	u32 orig, readback, restored;

	if (!hws || !buf || !len)
		return 0;

	n += scnprintf(buf + n, len - n, "[write_probe]\n");

	hws_reg_probe_write_read_restore(hws, INT_EN_REG_BASE, HWS_INT_EN_MASK,
					 &orig, &readback, &restored);
	n += scnprintf(buf + n, len - n,
		       "INT_EN.probe orig=0x%08x test=0x%08x readback=0x%08x restored=0x%08x\n",
		       orig, HWS_INT_EN_MASK, readback, restored);

	hws_reg_probe_write_read_restore(hws, PCIEBR_EN_REG_BASE, 0x00000001,
					 &orig, &readback, &restored);
	n += scnprintf(buf + n, len - n,
		       "PCIEBR_EN.probe orig=0x%08x test=0x%08x readback=0x%08x restored=0x%08x\n",
		       orig, 0x00000001, readback, restored);

	hws_reg_probe_write_read_restore(hws, PCIE_INT_DEC_REG_BASE, 0x00000000,
					 &orig, &readback, &restored);
	n += scnprintf(buf + n, len - n,
		       "PCIE_INT_DEC.probe orig=0x%08x test=0x%08x readback=0x%08x restored=0x%08x\n",
		       orig, 0x00000000, readback, restored);

	for (ch = 0; ch < hws->cur_max_linein_ch && n < len; ch++) {
		u32 reg = HWS_REG_AUD_DMA_ADDR(ch);
		u32 test = ((ch + 1) * PCIEBAR_AXI_BASE + 0x00123000);

		hws_reg_probe_write_read_restore(hws, reg, test,
						 &orig, &readback, &restored);
		n += scnprintf(buf + n, len - n,
			       "ch%u.audio_base.probe reg=0x%04x orig=0x%08x test=0x%08x readback=0x%08x restored=0x%08x\n",
			       ch, reg, orig, test, readback, restored);
	}

	return n;
}

static int hws_reg_probe_append_slot_probe(struct hws_pcie_dev *hws, char *buf,
					   size_t len)
{
	unsigned int slot;
	int n = 0;

	if (!hws || !buf || !len)
		return 0;

	n += scnprintf(buf + n, len - n, "[slot_probe]\n");
	for (slot = 0; slot < 16 && n < len; slot++) {
		u32 reg = CVBS_IN_BUF_BASE + slot * PCIE_BARADDROFSIZE;
		u32 test = 0x80000000 | (slot << 16) | 0x00123000;
		u32 orig, readback, restored;

		hws_reg_probe_write_read_restore(hws, reg, test,
						 &orig, &readback, &restored);
		n += scnprintf(buf + n, len - n,
			       "slot%u.base.probe reg=0x%04x orig=0x%08x test=0x%08x readback=0x%08x restored=0x%08x\n",
			       slot, reg, orig, test, readback, restored);
	}

	return n;
}

static int hws_reg_probe_append_remap_probe(struct hws_pcie_dev *hws, char *buf,
					    size_t len)
{
	unsigned int slot;
	int n = 0;

	if (!hws || !buf || !len)
		return 0;

	n += scnprintf(buf + n, len - n, "[remap_slot_probe]\n");
	for (slot = 0; slot < 16 && n < len; slot++) {
		u32 hi_reg = PCI_ADDR_TABLE_BASE + 0x208 + slot * 8;
		u32 lo_reg = hi_reg + PCIE_BARADDROFSIZE;
		u32 hi_test = 0x00010000 | slot;
		u32 lo_test = 0xE0000000u | (slot << 12);
		u32 orig, readback, restored;

		hws_reg_probe_write_read_restore(hws, hi_reg, hi_test,
						 &orig, &readback, &restored);
		n += scnprintf(buf + n, len - n,
			       "slot%u.remap_hi.probe reg=0x%04x orig=0x%08x test=0x%08x readback=0x%08x restored=0x%08x\n",
			       slot, hi_reg, orig, hi_test, readback, restored);

		hws_reg_probe_write_read_restore(hws, lo_reg, lo_test,
						 &orig, &readback, &restored);
		n += scnprintf(buf + n, len - n,
			       "slot%u.remap_lo.probe reg=0x%04x orig=0x%08x test=0x%08x readback=0x%08x restored=0x%08x\n",
			       slot, lo_reg, orig, lo_test, readback, restored);
	}

	return n;
}

static ssize_t audio_reg_probe_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct hws_pcie_dev *hws = dev_get_drvdata(dev);
	ssize_t n;

	if (!hws || !hws->bar0_base)
		return -ENODEV;

	mutex_lock(&hws->reg_probe_lock);
	if (hws->reg_probe_valid) {
		n = sysfs_emit(buf, "%s", hws->reg_probe_report);
	} else {
		n = hws_reg_probe_append_snapshot(hws, buf, PAGE_SIZE,
						  "snapshot.live");
	}
	mutex_unlock(&hws->reg_probe_lock);
	return n;
}

static ssize_t audio_reg_probe_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct hws_pcie_dev *hws = dev_get_drvdata(dev);
	int n = 0;
	int busy_n;

	if (!hws || !hws->bar0_base)
		return -ENODEV;

	if (!sysfs_streq(buf, "run") && !sysfs_streq(buf, "snapshot"))
		return -EINVAL;

	mutex_lock(&hws->reg_probe_lock);
	memset(hws->reg_probe_report, 0, sizeof(hws->reg_probe_report));
	n += scnprintf(hws->reg_probe_report + n,
		       sizeof(hws->reg_probe_report) - n,
		       "pci=%s\n", pci_name(hws->pdev));

	if (sysfs_streq(buf, "snapshot")) {
		n += hws_reg_probe_append_snapshot(hws,
						   hws->reg_probe_report + n,
						   sizeof(hws->reg_probe_report) - n,
						   "snapshot.live");
		hws->reg_probe_valid = true;
		mutex_unlock(&hws->reg_probe_lock);
		return count;
	}

	busy_n = hws_reg_probe_append_busy(hws, hws->reg_probe_report + n,
					   sizeof(hws->reg_probe_report) - n);
	n += busy_n;
	if (busy_n) {
		hws->reg_probe_valid = true;
		mutex_unlock(&hws->reg_probe_lock);
		return -EBUSY;
	}

	n += hws_reg_probe_append_snapshot(hws,
					   hws->reg_probe_report + n,
					   sizeof(hws->reg_probe_report) - n,
					   "snapshot.before");
	n += hws_reg_probe_append_write_probe(hws, hws->reg_probe_report + n,
					      sizeof(hws->reg_probe_report) - n);
	n += hws_reg_probe_append_snapshot(hws,
					   hws->reg_probe_report + n,
					   sizeof(hws->reg_probe_report) - n,
					   "snapshot.after");
	hws->reg_probe_valid = true;
	mutex_unlock(&hws->reg_probe_lock);
	return count;
}

static ssize_t audio_reg_probe_run_show(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	struct hws_pcie_dev *hws = dev_get_drvdata(dev);
	int n = 0;
	int busy_n;

	if (!hws || !hws->bar0_base)
		return -ENODEV;

	mutex_lock(&hws->reg_probe_lock);
	memset(hws->reg_probe_report, 0, sizeof(hws->reg_probe_report));
	n += scnprintf(hws->reg_probe_report + n,
		       sizeof(hws->reg_probe_report) - n,
		       "pci=%s\n", pci_name(hws->pdev));

	busy_n = hws_reg_probe_append_busy(hws, hws->reg_probe_report + n,
					   sizeof(hws->reg_probe_report) - n);
	n += busy_n;
	if (busy_n)
		goto out_emit;

	n += hws_reg_probe_append_snapshot(hws,
					   hws->reg_probe_report + n,
					   sizeof(hws->reg_probe_report) - n,
					   "snapshot.before");
	n += hws_reg_probe_append_write_probe(hws, hws->reg_probe_report + n,
					      sizeof(hws->reg_probe_report) - n);
	n += hws_reg_probe_append_snapshot(hws,
					   hws->reg_probe_report + n,
					   sizeof(hws->reg_probe_report) - n,
					   "snapshot.after");
out_emit:
	hws->reg_probe_valid = true;
	n = sysfs_emit(buf, "%s", hws->reg_probe_report);
	mutex_unlock(&hws->reg_probe_lock);
	return n;
}

static DEVICE_ATTR_RW(audio_reg_probe);
static DEVICE_ATTR_RO(audio_reg_probe_run);

static ssize_t audio_reg_probe_slots_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct hws_pcie_dev *hws = dev_get_drvdata(dev);
	int n = 0;
	int busy_n;

	if (!hws || !hws->bar0_base)
		return -ENODEV;

	mutex_lock(&hws->reg_probe_lock);
	n += scnprintf(buf + n, PAGE_SIZE - n, "pci=%s\n", pci_name(hws->pdev));
	busy_n = hws_reg_probe_append_busy(hws, buf + n, PAGE_SIZE - n);
	n += busy_n;
	if (!busy_n)
		n += hws_reg_probe_append_slot_probe(hws, buf + n,
						     PAGE_SIZE - n);
	mutex_unlock(&hws->reg_probe_lock);
	return n;
}

static ssize_t audio_reg_probe_remap_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct hws_pcie_dev *hws = dev_get_drvdata(dev);
	int n = 0;
	int busy_n;

	if (!hws || !hws->bar0_base)
		return -ENODEV;

	mutex_lock(&hws->reg_probe_lock);
	n += scnprintf(buf + n, PAGE_SIZE - n, "pci=%s\n", pci_name(hws->pdev));
	busy_n = hws_reg_probe_append_busy(hws, buf + n, PAGE_SIZE - n);
	n += busy_n;
	if (!busy_n)
		n += hws_reg_probe_append_remap_probe(hws, buf + n,
						      PAGE_SIZE - n);
	mutex_unlock(&hws->reg_probe_lock);
	return n;
}

static DEVICE_ATTR_RO(audio_reg_probe_slots);
static DEVICE_ATTR_RO(audio_reg_probe_remap);

static ssize_t hws_debugfs_bar0_read(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct hws_pcie_dev *hws = file->private_data;
	size_t size;
	void *snapshot;
	ssize_t ret;

	if (!hws || !hws->bar0_base)
		return -ENODEV;

	size = pci_resource_len(hws->pdev, 0);
	if (!size || size > SZ_64K)
		size = SZ_64K;

	snapshot = kmalloc(size, GFP_KERNEL);
	if (!snapshot)
		return -ENOMEM;

	memcpy_fromio(snapshot, hws->bar0_base, size);
	ret = simple_read_from_buffer(user_buf, count, ppos, snapshot, size);
	kfree(snapshot);
	return ret;
}

static int hws_debugfs_audio_state_show(struct seq_file *m, void *unused)
{
	struct hws_pcie_dev *hws = m->private;
	unsigned int ch;

	if (!hws || !hws->bar0_base)
		return -ENODEV;

	seq_printf(m, "pci=%s\n", pci_name(hws->pdev));
	seq_printf(m, "cur_max_video_ch=%u\n", hws->cur_max_video_ch);
	seq_printf(m, "cur_max_linein_ch=%u\n", hws->cur_max_linein_ch);

	for (ch = 0; ch < hws->cur_max_linein_ch; ch++) {
		struct hws_scratch_dma *scratch = &hws->scratch_aud[ch];
		u32 shared_hi_off = 0x208 + ch * 8;
		u32 shared_lo_off = 0x20c + ch * 8;
		u32 audio_hi_off = 0x208 + (8 + ch) * 8;
		u32 audio_lo_off = 0x20c + (8 + ch) * 8;
		u32 aud_base = readl_relaxed(hws->bar0_base + HWS_REG_AUD_DMA_ADDR(ch));
		u32 abuf_toggle = readl_relaxed(hws->bar0_base +
						HWS_REG_ABUF_TOGGLE(ch)) & 0x01;

		seq_printf(m, "[channel %u]\n", ch);
		seq_printf(m, "scratch_dma=%pad\n", &scratch->dma);
		seq_printf(m, "scratch_size=%zu\n", scratch->size);
		seq_printf(m, "shared_hi=0x%08x\n",
			   readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE +
					 shared_hi_off));
		seq_printf(m, "shared_lo=0x%08x\n",
			   readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE +
					 shared_lo_off));
		seq_printf(m, "audio_hi=0x%08x\n",
			   readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE +
					 audio_hi_off));
		seq_printf(m, "audio_lo=0x%08x\n",
			   readl_relaxed(hws->bar0_base + PCI_ADDR_TABLE_BASE +
					 audio_lo_off));
		seq_printf(m, "aud_base=0x%08x\n", aud_base);
		seq_printf(m, "acap_enable=0x%08x\n",
			   readl_relaxed(hws->bar0_base + HWS_REG_ACAP_ENABLE));
		seq_printf(m, "int_status=0x%08x\n",
			   readl_relaxed(hws->bar0_base + HWS_REG_INT_STATUS));
		seq_printf(m, "sys_status=0x%08x\n",
			   readl_relaxed(hws->bar0_base + HWS_REG_SYS_STATUS));
		seq_printf(m, "active_status=0x%08x\n",
			   readl_relaxed(hws->bar0_base + HWS_REG_ACTIVE_STATUS));
		seq_printf(m, "abuf_toggle=%u\n", abuf_toggle);
		seq_printf(m, "stream_running=%u\n",
			   READ_ONCE(hws->audio[ch].stream_running));
		seq_printf(m, "cap_active=%u\n",
			   READ_ONCE(hws->audio[ch].cap_active));
		seq_printf(m, "irq_count=%u\n", READ_ONCE(hws->audio[ch].irq_count));
		seq_printf(m, "delivered_count=%u\n",
			   READ_ONCE(hws->audio[ch].delivered_count));
	}

	return 0;
}

static int hws_debugfs_audio_state_open(struct inode *inode, struct file *file)
{
	return single_open(file, hws_debugfs_audio_state_show, inode->i_private);
}

static ssize_t hws_debugfs_audio_scratch_read(struct file *file,
					      char __user *user_buf, size_t count,
					      loff_t *ppos)
{
	struct hws_audio *audio = file->private_data;
	struct hws_scratch_dma *scratch;

	if (!audio || !audio->parent)
		return -ENODEV;

	scratch = &audio->parent->scratch_aud[audio->channel_index];
	if (!scratch->cpu || !scratch->size)
		return -ENODATA;

	dma_rmb();
	return simple_read_from_buffer(user_buf, count, ppos, scratch->cpu,
				       scratch->size);
}

static const struct file_operations hws_debugfs_bar0_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = hws_debugfs_bar0_read,
	.llseek = default_llseek,
};

static const struct file_operations hws_debugfs_audio_state_fops = {
	.owner = THIS_MODULE,
	.open = hws_debugfs_audio_state_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations hws_debugfs_audio_scratch_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = hws_debugfs_audio_scratch_read,
	.llseek = default_llseek,
};

static void hws_debugfs_cleanup(struct hws_pcie_dev *hws)
{
	if (!hws)
		return;

	debugfs_remove_recursive(hws->debugfs_dir);
	hws->debugfs_dir = NULL;
}

static void hws_debugfs_init(struct hws_pcie_dev *hws)
{
	char name[32];
	unsigned int ch;

	if (!hws)
		return;

	if (!hws_debugfs_root)
		hws_debugfs_root = debugfs_create_dir("hws", NULL);
	if (IS_ERR_OR_NULL(hws_debugfs_root))
		return;

	hws->debugfs_dir = debugfs_create_dir(pci_name(hws->pdev), hws_debugfs_root);
	if (IS_ERR_OR_NULL(hws->debugfs_dir)) {
		hws->debugfs_dir = NULL;
		return;
	}

	debugfs_create_file("bar0_snapshot", 0400, hws->debugfs_dir, hws,
			    &hws_debugfs_bar0_fops);
	debugfs_create_file("audio_state", 0400, hws->debugfs_dir, hws,
			    &hws_debugfs_audio_state_fops);

	for (ch = 0; ch < hws->cur_max_linein_ch; ch++) {
		snprintf(name, sizeof(name), "audio_scratch_ch%u", ch);
		debugfs_create_file(name, 0400, hws->debugfs_dir, &hws->audio[ch],
				    &hws_debugfs_audio_scratch_fops);
	}
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
	case 0x6504:
		hdev->cur_max_video_ch = 4;
		hdev->cur_max_linein_ch = 1;
		break;
	case 0x8504:
		/*
		 * Baseline exposed one ALSA capture device per video input on
		 * the X4 HDMI board, so keep four audio inputs here to match
		 * the expected userspace-visible topology.
		 */
		hdev->cur_max_video_ch = 4;
		hdev->cur_max_linein_ch = 4;
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
static void hws_free_seed_buffers(struct hws_pcie_dev *hws);

static void hws_log_lifecycle_snapshot(struct hws_pcie_dev *hws,
				       const char *action,
				       const char *phase)
{
	struct device *dev;
	u32 int_en, int_status, vcap, sys_status, dec_mode;

	if (!hws || !hws->pdev)
		return;

	dev = &hws->pdev->dev;
	if (!hws->bar0_base) {
		dev_dbg(dev,
			"lifecycle:%s:%s bar0-unmapped suspended=%d start_run=%d pci_lost=%d irq=%d\n",
			action, phase, READ_ONCE(hws->suspended), hws->start_run,
			hws->pci_lost, hws->irq);
		return;
	}

	int_en = readl(hws->bar0_base + INT_EN_REG_BASE);
	int_status = readl(hws->bar0_base + HWS_REG_INT_STATUS);
	vcap = readl(hws->bar0_base + HWS_REG_VCAP_ENABLE);
	sys_status = readl(hws->bar0_base + HWS_REG_SYS_STATUS);
	dec_mode = readl(hws->bar0_base + HWS_REG_DEC_MODE);

	dev_dbg(dev,
		"lifecycle:%s:%s suspended=%d start_run=%d pci_lost=%d irq=%d INT_EN=0x%08x INT_STATUS=0x%08x VCAP=0x%08x SYS=0x%08x DEC=0x%08x\n",
		action, phase, READ_ONCE(hws->suspended), hws->start_run,
		hws->pci_lost, hws->irq, int_en, int_status, vcap,
		sys_status, dec_mode);
}

static int read_chip_id(struct hws_pcie_dev *hdev)
{
	u32 reg;
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

static int main_ks_thread_handle(void *data)
{
	struct hws_pcie_dev *pdx = data;

	set_freezable();

	while (!kthread_should_stop()) {
		/* If we’re suspending, don’t touch hardware; just sleep/freeeze */
		if (READ_ONCE(pdx->suspended)) {
			try_to_freeze();
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		/* avoid MMIO when suspended (guarded above) */
		check_video_format(pdx);

		try_to_freeze(); /* cooperate with freezer each loop */

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

static int hws_alloc_seed_buffers(struct hws_pcie_dev *hws)
{
	int ch;
	size_t need;
	size_t aud_need = ALIGN(hws->audio_pkt_size * 2, 64);

	/*
	 * Baseline reserved a full hardware-sized video DMA region per channel
	 * and placed audio at the tail of that region. Keep the same backing
	 * size here so the shared channel window matches baseline geometry.
	 */
	need = ALIGN(hws->max_hw_video_buf_sz ? hws->max_hw_video_buf_sz :
		     MAX_MM_VIDEO_SIZE, 64);

	/*
	 * Baseline reserved a 10 KiB capture window per audio input. The
	 * hardware only delivers 4 KiB packets, but it toggles within a larger
	 * two-half buffer, so keep the larger legacy window here as well.
	 */
	if (aud_need < MAX_AUDIO_CAP_SIZE)
		aud_need = MAX_AUDIO_CAP_SIZE;

	for (ch = 0; ch < hws->cur_max_video_ch; ch++) {
#if defined(CONFIG_HAS_DMA) /* normal on PCIe platforms */
		void *cpu = dma_alloc_coherent(&hws->pdev->dev, need,
					       &hws->scratch_vid[ch].dma,
					       GFP_KERNEL);
#else
		void *cpu = NULL;
#endif
		if (!cpu) {
			dev_warn(&hws->pdev->dev,
				 "scratch: dma_alloc_coherent failed ch=%d\n", ch);
			/* not fatal: free earlier ones and continue without seeding */
			while (--ch >= 0) {
				if (hws->scratch_vid[ch].cpu)
					dma_free_coherent(&hws->pdev->dev,
							  hws->scratch_vid[ch].size,
							  hws->scratch_vid[ch].cpu,
							  hws->scratch_vid[ch].dma);
				hws->scratch_vid[ch].cpu = NULL;
				hws->scratch_vid[ch].size = 0;
			}
			return -ENOMEM;
		}
		hws->scratch_vid[ch].cpu  = cpu;
		hws->scratch_vid[ch].size = need;
	}

	for (ch = 0; ch < hws->cur_max_linein_ch; ch++) {
#if defined(CONFIG_HAS_DMA)
		void *cpu = dma_alloc_coherent(&hws->pdev->dev, aud_need,
					       &hws->scratch_aud[ch].dma,
					       GFP_KERNEL);
#else
		void *cpu = NULL;
#endif
		if (!cpu) {
			dev_warn(&hws->pdev->dev,
				 "audio scratch: dma_alloc_coherent failed ch=%d\n",
				 ch);
			hws_free_seed_buffers(hws);
			return -ENOMEM;
		}
		hws->scratch_aud[ch].cpu = cpu;
		hws->scratch_aud[ch].size = aud_need;
	}
	return 0;
}

static void hws_free_seed_buffers(struct hws_pcie_dev *hws)
{
	int ch;

	for (ch = 0; ch < hws->cur_max_video_ch; ch++) {
		if (hws->scratch_vid[ch].cpu) {
			dma_free_coherent(&hws->pdev->dev,
					  hws->scratch_vid[ch].size,
					  hws->scratch_vid[ch].cpu,
					  hws->scratch_vid[ch].dma);
			hws->scratch_vid[ch].cpu = NULL;
			hws->scratch_vid[ch].size = 0;
		}
	}

	for (ch = 0; ch < hws->cur_max_linein_ch; ch++) {
		if (hws->scratch_aud[ch].cpu) {
			dma_free_coherent(&hws->pdev->dev,
					  hws->scratch_aud[ch].size,
					  hws->scratch_aud[ch].cpu,
					  hws->scratch_aud[ch].dma);
			hws->scratch_aud[ch].cpu = NULL;
			hws->scratch_aud[ch].size = 0;
		}
	}
}

static void hws_seed_channel(struct hws_pcie_dev *hws, int ch)
{
	dma_addr_t paddr = hws->scratch_vid[ch].dma;
	u32 lo = lower_32_bits(paddr);
	u32 hi = upper_32_bits(paddr);
	u32 pci_addr = lo & PCI_E_BAR_ADD_LOWMASK;

	lo &= PCI_E_BAR_ADD_MASK;

	/* Program 64-bit BAR remap entry for this channel (table @ 0x208 + ch * 8) */
	writel_relaxed(hi, hws->bar0_base +
			    PCI_ADDR_TABLE_BASE + 0x208 + ch * 8);
	writel_relaxed(lo, hws->bar0_base +
			    PCI_ADDR_TABLE_BASE + 0x208 + ch * 8 +
			    PCIE_BARADDROFSIZE);

	/* Program capture engine per-channel base/half */
	writel_relaxed((ch + 1) * PCIEBAR_AXI_BASE + pci_addr,
		       hws->bar0_base + CVBS_IN_BUF_BASE +
		       ch * PCIE_BARADDROFSIZE);

	/* half size: use either the current format’s half or half of scratch */
	{
		u32 half = hws->video[ch].pix.half_size ?
			hws->video[ch].pix.half_size :
			(u32)(hws->scratch_vid[ch].size / 2);

		writel_relaxed(half / 16,
			       hws->bar0_base + CVBS_IN_BUF_BASE2 +
			       ch * PCIE_BARADDROFSIZE);
	}

	(void)readl(hws->bar0_base + HWS_REG_INT_STATUS); /* flush posted writes */
}

static void hws_seed_all_channels(struct hws_pcie_dev *hws)
{
	int ch;

	for (ch = 0; ch < hws->cur_max_video_ch; ch++) {
		if (hws->scratch_vid[ch].cpu)
			hws_seed_channel(hws, ch);
	}
}

static void hws_irq_mask_gate(struct hws_pcie_dev *hws)
{
	writel(0x00000000, hws->bar0_base + PCIEBR_EN_REG_BASE);
	(void)readl(hws->bar0_base + PCIEBR_EN_REG_BASE);
	writel(0x00000000, hws->bar0_base + INT_EN_REG_BASE);
	(void)readl(hws->bar0_base + INT_EN_REG_BASE);
}

static void hws_irq_unmask_gate(struct hws_pcie_dev *hws)
{
	/*
	 * Baseline reopened the full interrupt fabric together:
	 * route -> bridge enable -> interrupt gate.
	 */
	writel(0x00000000, hws->bar0_base + PCIE_INT_DEC_REG_BASE);
	(void)readl(hws->bar0_base + PCIE_INT_DEC_REG_BASE);
	writel(0x00000001, hws->bar0_base + PCIEBR_EN_REG_BASE);
	(void)readl(hws->bar0_base + PCIEBR_EN_REG_BASE);
	writel(HWS_INT_EN_MASK, hws->bar0_base + INT_EN_REG_BASE);
	(void)readl(hws->bar0_base + INT_EN_REG_BASE);
}

void hws_restore_irq_fabric(struct hws_pcie_dev *hws)
{
	u32 gate, bridge, decode;

	if (!hws || !hws->bar0_base)
		return;

	hws_irq_unmask_gate(hws);

	decode = readl(hws->bar0_base + PCIE_INT_DEC_REG_BASE);
	bridge = readl(hws->bar0_base + PCIEBR_EN_REG_BASE);
	gate = readl(hws->bar0_base + INT_EN_REG_BASE);
	dev_info(&hws->pdev->dev,
		 "irq-fabric:restore dec=%08x br=%08x gate=%08x\n",
		 decode, bridge, gate);
}

static void hws_irq_clear_pending(struct hws_pcie_dev *hws)
{
	u32 st = readl(hws->bar0_base + HWS_REG_INT_STATUS);

	if (st) {
		writel(st, hws->bar0_base + HWS_REG_INT_STATUS); /* W1C */
		(void)readl(hws->bar0_base + HWS_REG_INT_STATUS);
	}
}

static void hws_block_hotpaths(struct hws_pcie_dev *hws)
{
	WRITE_ONCE(hws->suspended, true);
	if (hws->irq >= 0)
		disable_irq(hws->irq);

	if (!hws->bar0_base)
		return;

	hws_irq_mask_gate(hws);
	hws_irq_clear_pending(hws);
}

static int hws_probe(struct pci_dev *pdev, const struct pci_device_id *pci_id)
{
	struct hws_pcie_dev *hws;
	int i, ret, irq;
	unsigned long irqf = 0;
	bool v4l2_registered = false;
	bool audio_registered = false;

	/* devres-backed device object */
	hws = devm_kzalloc(&pdev->dev, sizeof(*hws), GFP_KERNEL);
	if (!hws)
		return -ENOMEM;

	hws->pdev = pdev;
	hws->irq = -1;
	hws->suspended = false;
	mutex_init(&hws->reg_probe_lock);
	pci_set_drvdata(pdev, hws);

	/* 1) Enable device + bus mastering (managed) */
	ret = pcim_enable_device(pdev);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "pcim_enable_device\n");
	pci_set_master(pdev);

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

	/* 3) Optional PCIe tuning (same as before) */
	enable_pcie_relaxed_ordering(pdev);
#ifdef CONFIG_ARCH_TI816X
	pcie_set_readrq(pdev, 128);
#endif

	/* 4) Identify chip & capabilities */
	read_chip_id(hws);
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
			goto err_unwind_channels;
		}
	}

	/* 6) Allocate scratch DMA and seed BAR table + channel base/half (legacy SetDMAAddress) */
	ret = hws_alloc_seed_buffers(hws);
	if (!ret)
		hws_seed_all_channels(hws);

	/* 7) Force legacy INTx; baseline requested IRQ before InitVideoSys. */
	pci_intx(pdev, 1);
	irqf = IRQF_SHARED;
	irq = pdev->irq;
	hws->irq = irq;
	dev_info(&pdev->dev, "IRQ mode: legacy INTx (shared), irq=%d\n", irq);

	/* 8) Clear any sticky pending interrupt status (W1C) before we arm the line */
	hws_irq_clear_pending(hws);

	/* 9) Request the legacy shared interrupt line (no vectors/MSI/MSI-X) */
	ret = devm_request_irq(&pdev->dev, irq, hws_irq_handler, irqf,
			       dev_name(&pdev->dev), hws);
	if (ret) {
		dev_err(&pdev->dev, "request_irq(%d) failed: %d\n", irq, ret);
		goto err_unwind_channels;
	}

	/* 10) Set the global interrupt enable bit in main control register */
	{
		u32 ctl_reg = readl(hws->bar0_base + HWS_REG_CTL);

		ctl_reg |= HWS_CTL_IRQ_ENABLE_BIT;
		writel(ctl_reg, hws->bar0_base + HWS_REG_CTL);
		(void)readl(hws->bar0_base + HWS_REG_CTL); /* flush write */
		dev_info(&pdev->dev, "Global IRQ enable bit set in control register\n");
	}

	/* 11) Single start-run sequence (like baseline InitVideoSys) */
	hws_init_video_sys(hws, false);
	dev_info(&pdev->dev, "INT_EN_GATE readback=0x%08x\n",
		 readl(hws->bar0_base + INT_EN_REG_BASE));

	/* 12) Register V4L2/ALSA */
	ret = hws_video_register(hws);
	if (ret) {
		dev_err(&pdev->dev, "video_register: %d\n", ret);
		goto err_unwind_channels;
	}
	v4l2_registered = true;
	ret = hws_audio_register(hws);
	if (ret) {
		dev_err(&pdev->dev, "audio_register: %d\n", ret);
		hws_video_unregister(hws);
		goto err_unwind_channels;
	}
	audio_registered = true;
	hws_debugfs_init(hws);
	ret = device_create_file(&pdev->dev, &dev_attr_audio_reg_probe);
	if (ret)
		dev_warn(&pdev->dev, "audio_reg_probe sysfs create failed: %d\n",
			 ret);
	ret = device_create_file(&pdev->dev, &dev_attr_audio_reg_probe_run);
	if (ret)
		dev_warn(&pdev->dev, "audio_reg_probe_run sysfs create failed: %d\n",
			 ret);
	ret = device_create_file(&pdev->dev, &dev_attr_audio_reg_probe_slots);
	if (ret)
		dev_warn(&pdev->dev, "audio_reg_probe_slots sysfs create failed: %d\n",
			 ret);
	ret = device_create_file(&pdev->dev, &dev_attr_audio_reg_probe_remap);
	if (ret)
		dev_warn(&pdev->dev, "audio_reg_probe_remap sysfs create failed: %d\n",
			 ret);

	/* 12) Background monitor thread (managed) */
	hws->main_task = kthread_run(main_ks_thread_handle, hws, "hws-mon");
	if (IS_ERR(hws->main_task)) {
		ret = PTR_ERR(hws->main_task);
		hws->main_task = NULL;
		dev_err(&pdev->dev, "kthread_run: %d\n", ret);
		goto err_unregister_va;
	}
	ret = devm_add_action_or_reset(&pdev->dev, hws_stop_kthread_action, hws);
	if (ret) {
		dev_err(&pdev->dev, "devm_add_action kthread_stop: %d\n", ret);
		goto err_unregister_va; /* reset already stopped the thread */
	}

	/* 13) Final: show the line is armed */
	dev_info(&pdev->dev, "irq handler installed on irq=%d\n", irq);
	hws_trace_bar0_snapshot(hws, "probe.ready");
	return 0;

err_unregister_va:
	hws_stop_device(hws);
	device_remove_file(&pdev->dev, &dev_attr_audio_reg_probe);
	device_remove_file(&pdev->dev, &dev_attr_audio_reg_probe_run);
	device_remove_file(&pdev->dev, &dev_attr_audio_reg_probe_slots);
	device_remove_file(&pdev->dev, &dev_attr_audio_reg_probe_remap);
	hws_debugfs_cleanup(hws);
	if (audio_registered)
		hws_audio_unregister(hws);
	if (v4l2_registered)
		hws_video_unregister(hws);
	hws_free_seed_buffers(hws);
	return ret;
err_unwind_channels:
	hws_free_seed_buffers(hws);
	while (--i >= 0) {
		if (!v4l2_registered)
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
	u64 start_ns = ktime_get_mono_fast_ns();

	/* Mask device enables: no new DMA starts. */
	writel(0x0, hws->bar0_base + HWS_REG_VCAP_ENABLE);
	writel(0x0, hws->bar0_base + HWS_REG_ACAP_ENABLE);
	(void)readl(hws->bar0_base + HWS_REG_INT_STATUS); /* flush */

	/* Let any in-flight DMAs finish (best-effort). */
	(void)hws_check_busy(hws);

	/* Ack any latched VDONE/ADONE. */
	for (i = 0; i < hws->cur_max_video_ch; ++i)
		ackmask |= HWS_INT_VDONE_BIT(i);
	for (i = 0; i < hws->cur_max_linein_ch; ++i)
		ackmask |= HWS_INT_ADONE_BIT(i);
	if (ackmask) {
		writel(ackmask, hws->bar0_base + HWS_REG_INT_STATUS);
		(void)readl(hws->bar0_base + HWS_REG_INT_STATUS);
	}

	/* Ensure no hard IRQ is still running. */
	if (hws->irq >= 0)
		synchronize_irq(hws->irq);

	dev_dbg(&hws->pdev->dev, "lifecycle:drain-after-stop:done (%lluus)\n",
		hws_elapsed_us(start_ns));
}

static void hws_stop_device(struct hws_pcie_dev *hws)
{
	u32 status = readl(hws->bar0_base + HWS_REG_SYS_STATUS);
	u64 start_ns = ktime_get_mono_fast_ns();
	bool live = status != 0xFFFFFFFF;

	dev_dbg(&hws->pdev->dev, "%s: status=0x%08x\n", __func__, status);
	if (!live) {
		hws->pci_lost = true;
		goto out;
	}
	hws_log_lifecycle_snapshot(hws, "stop-device", "begin");

	/* Make ISR/BH a no-op, then drain engines/IRQ. */
	hws_publish_stop_flags(hws);
	hws_drain_after_stop(hws);

	/* 1) Stop the on-board DSP */
	hws_stop_dsp(hws);

out:
	hws->start_run = false;
	if (live)
		hws_log_lifecycle_snapshot(hws, "stop-device", "end");
	else
		dev_dbg(&hws->pdev->dev, "lifecycle:stop-device:device-lost\n");
	dev_dbg(&hws->pdev->dev, "lifecycle:stop-device:done (%lluus)\n",
		hws_elapsed_us(start_ns));
	dev_dbg(&hws->pdev->dev, "%s: complete\n", __func__);
}

static int hws_quiesce_for_transition(struct hws_pcie_dev *hws,
				      const char *action,
				      bool stop_thread)
{
	struct device *dev = &hws->pdev->dev;
	u64 start_ns = ktime_get_mono_fast_ns();
	u64 step_ns;
	int vret;

	hws_log_lifecycle_snapshot(hws, action, "begin");

	step_ns = ktime_get_mono_fast_ns();
	hws_block_hotpaths(hws);
	dev_dbg(dev, "lifecycle:%s:block-hotpaths (%lluus)\n", action,
		hws_elapsed_us(step_ns));
	hws_log_lifecycle_snapshot(hws, action, "blocked");

	if (stop_thread) {
		step_ns = ktime_get_mono_fast_ns();
		hws_stop_kthread_action(hws);
		dev_dbg(dev, "lifecycle:%s:stop-kthread (%lluus)\n", action,
			hws_elapsed_us(step_ns));
	}

	step_ns = ktime_get_mono_fast_ns();
	vret = hws_video_quiesce(hws, action);
	dev_dbg(dev, "lifecycle:%s:video-quiesce ret=%d (%lluus)\n", action,
		vret, hws_elapsed_us(step_ns));
	if (vret)
		dev_warn(dev, "lifecycle:%s video quiesce returned %d\n",
			 action, vret);

	step_ns = ktime_get_mono_fast_ns();
	hws_stop_device(hws);
	dev_dbg(dev, "lifecycle:%s:stop-device (%lluus)\n", action,
		hws_elapsed_us(step_ns));
	hws_log_lifecycle_snapshot(hws, action, "end");
	dev_dbg(dev, "lifecycle:%s:quiesce-done ret=%d (%lluus)\n", action,
		vret, hws_elapsed_us(start_ns));

	return vret;
}

static void hws_remove(struct pci_dev *pdev)
{
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);
	u64 start_ns;

	if (!hws)
		return;

	start_ns = ktime_get_mono_fast_ns();
	dev_info(&pdev->dev, "lifecycle:remove begin\n");
	hws_log_lifecycle_snapshot(hws, "remove", "begin");

	/* Stop the monitor thread before tearing down V4L2/vb2 objects. */
	hws_block_hotpaths(hws);
	hws_stop_kthread_action(hws);

	/* Stop hardware / capture cleanly (your helper) */
	hws_stop_device(hws);

	/* Unregister subsystems you registered */
	device_remove_file(&pdev->dev, &dev_attr_audio_reg_probe);
	device_remove_file(&pdev->dev, &dev_attr_audio_reg_probe_run);
	device_remove_file(&pdev->dev, &dev_attr_audio_reg_probe_slots);
	device_remove_file(&pdev->dev, &dev_attr_audio_reg_probe_remap);
	hws_debugfs_cleanup(hws);
	hws_audio_unregister(hws);
	hws_video_unregister(hws);

	/* Release seeded DMA buffers */
	hws_free_seed_buffers(hws);
	/* kthread is stopped by the devm action you added in probe */
	hws_log_lifecycle_snapshot(hws, "remove", "end");
	dev_info(&pdev->dev, "lifecycle:remove done (%lluus)\n",
		 hws_elapsed_us(start_ns));
}

#ifdef CONFIG_PM_SLEEP
static int hws_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);
	int aret;
	int vret;
	u64 start_ns = ktime_get_mono_fast_ns();
	u64 step_ns;

	dev_info(dev, "lifecycle:pm_suspend begin\n");
	aret = hws_audio_pm_suspend_all(hws);
	if (aret)
		dev_warn(dev, "lifecycle:pm_suspend audio quiesce returned %d\n",
			 aret);
	vret = hws_quiesce_for_transition(hws, "pm_suspend", false);

	step_ns = ktime_get_mono_fast_ns();
	pci_save_state(pdev);
	pci_clear_master(pdev);
	pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3hot);
	dev_dbg(dev, "lifecycle:pm_suspend:pci-d3hot (%lluus)\n",
		hws_elapsed_us(step_ns));
	dev_info(dev, "lifecycle:pm_suspend done ret=%d (%lluus)\n", vret,
		 hws_elapsed_us(start_ns));

	return 0;
}

static int hws_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);
	int ret;
	u64 start_ns = ktime_get_mono_fast_ns();
	u64 step_ns;

	dev_info(dev, "lifecycle:pm_resume begin\n");

	/* Back to D0 and re-enable the function */
	step_ns = ktime_get_mono_fast_ns();
	pci_set_power_state(pdev, PCI_D0);

	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(dev, "pci_enable_device: %d\n", ret);
		return ret;
	}
	pci_restore_state(pdev);
	pci_set_master(pdev);
	dev_dbg(dev, "lifecycle:pm_resume:pci-enable (%lluus)\n",
		hws_elapsed_us(step_ns));

	/* Reapply any PCIe tuning lost across D3 */
	enable_pcie_relaxed_ordering(pdev);

	/* Reinitialize chip-side capabilities / registers */
	step_ns = ktime_get_mono_fast_ns();
	read_chip_id(hws);
	/* Re-seed BAR remaps/DMA windows and restart the capture core */
	hws_seed_all_channels(hws);
	hws_init_video_sys(hws, true);
	hws_irq_clear_pending(hws);
	dev_dbg(dev, "lifecycle:pm_resume:chip-reinit (%lluus)\n",
		hws_elapsed_us(step_ns));

	/* IRQs can be re-enabled now that MMIO is sane */
	step_ns = ktime_get_mono_fast_ns();
	if (hws->irq >= 0)
		enable_irq(hws->irq);

	WRITE_ONCE(hws->suspended, false);
	dev_dbg(dev, "lifecycle:pm_resume:irq-unsuspend (%lluus)\n",
		hws_elapsed_us(step_ns));

	/* vb2: nothing mandatory; userspace will STREAMON again when ready */
	step_ns = ktime_get_mono_fast_ns();
	hws_video_pm_resume(hws);
	dev_dbg(dev, "lifecycle:pm_resume:video-resume (%lluus)\n",
		hws_elapsed_us(step_ns));
	hws_log_lifecycle_snapshot(hws, "pm_resume", "end");
	dev_info(dev, "lifecycle:pm_resume done (%lluus)\n",
		 hws_elapsed_us(start_ns));

	return 0;
}

static SIMPLE_DEV_PM_OPS(hws_pm_ops, hws_pm_suspend, hws_pm_resume);
# define HWS_PM_OPS (&hws_pm_ops)
#else
# define HWS_PM_OPS NULL
#endif

static void hws_shutdown(struct pci_dev *pdev)
{
	struct hws_pcie_dev *hws = pci_get_drvdata(pdev);
	int vret = 0;
	u64 start_ns = ktime_get_mono_fast_ns();
	u64 step_ns;

	if (!hws)
		return;

	dev_info(&pdev->dev, "lifecycle:pci_shutdown begin\n");
	vret = hws_quiesce_for_transition(hws, "pci_shutdown", true);

	step_ns = ktime_get_mono_fast_ns();
	pci_clear_master(pdev);
	dev_dbg(&pdev->dev, "lifecycle:pci_shutdown:clear-master (%lluus)\n",
		hws_elapsed_us(step_ns));
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
