// SPDX-License-Identifier: GPL-2.0-only
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/pci.h>
#include <linux/seq_file.h>

#include "hws.h"
#include "hws_debugfs.h"
#include "hws_mmio.h"
#include "hws_reg_atlas.h"

static struct dentry *hws_debugfs_root;

static int hws_debugfs_atlas_show(struct seq_file *s, void *unused)
{
	size_t i;

	seq_puts(s, "schema_version=1 bar=0 default_read=deny default_write=deny\n");
	for (i = 0; i < hws_reg_atlas_count; i++) {
		const struct hws_reg_desc *reg = &hws_reg_atlas[i];
		unsigned int field_index;
		unsigned int typical_index;

		seq_printf(s,
			   "register id=%s name=\"%s\" offset=0x%04x width=%u access=%s count=%u stride=%u snapshot_safe=%u confidence=%s reset=",
			   reg->id, reg->name, reg->offset, reg->width_bits,
			   hws_reg_access_name(reg->access), reg->count,
			   reg->stride, reg->snapshot_safe,
			   hws_reg_confidence_name(reg->confidence));
		if (reg->reset_known)
			seq_printf(s, "0x%08x", reg->reset_value);
		else
			seq_puts(s, "unknown");
		seq_printf(s, " evidence=\"%s\"\n", reg->evidence);

		for (field_index = 0; field_index < reg->field_count;
		     field_index++) {
			const struct hws_reg_field_desc *field =
				&hws_reg_fields[reg->field_first + field_index];

			seq_printf(s, " field register=%s name=%s lsb=%u msb=%u context=%s\n",
				   reg->id, field->name, field->lsb, field->msb,
				   hws_reg_field_context_name(field->context));
		}
		for (typical_index = 0; typical_index < reg->typical_count;
		     typical_index++)
			seq_printf(s, " typical register=%s value=0x%08x\n",
				   reg->id,
				   hws_reg_typical_values[reg->typical_first +
							  typical_index]);
	}

	return 0;
}

static int hws_debugfs_snapshot_show(struct seq_file *s, void *unused)
{
	struct hws_pcie_dev *hws = s->private;
	resource_size_t bar_size;
	u64 start_ns;
	size_t i;

	if (!hws || !hws->pdev || !hws->bar0_base) {
		seq_puts(s, "state=unavailable\n");
		return 0;
	}

	mutex_lock(&hws->mmio_snapshot_lock);
	if (READ_ONCE(hws->suspended) || READ_ONCE(hws->pci_lost)) {
		seq_printf(s, "state=offline suspended=%u pci_lost=%u\n",
			   READ_ONCE(hws->suspended), READ_ONCE(hws->pci_lost));
		goto out_unlock;
	}

	bar_size = pci_resource_len(hws->pdev, 0);
	start_ns = ktime_get_mono_fast_ns();
	seq_printf(s,
		   "schema_version=1 device=%s bar=0 bar_size=0x%llx timestamp_start_ns=%llu atomic=0 allowlist_only=1\n",
		   pci_name(hws->pdev), (unsigned long long)bar_size,
		   (unsigned long long)start_ns);

	for (i = 0; i < hws_reg_atlas_count; i++) {
		const struct hws_reg_desc *reg = &hws_reg_atlas[i];
		unsigned int instance;

		if (!reg->snapshot_safe || reg->access == HWS_REG_WO)
			continue;
		for (instance = 0; instance < reg->count; instance++) {
			u32 offset = reg->offset + instance * reg->stride;
			u32 value;
			unsigned int field_index;

			if ((resource_size_t)offset + sizeof(value) > bar_size)
				continue;
			value = hws_readl(hws, offset);
			seq_printf(s,
				   "register id=%s offset=0x%04x value=0x%08x channel=%d access=%s confidence=%s\n",
				   reg->id, offset, value,
				   reg->count > 1 ? (int)instance : -1,
				   hws_reg_access_name(reg->access),
				   hws_reg_confidence_name(reg->confidence));
			for (field_index = 0; field_index < reg->field_count;
			     field_index++) {
				const struct hws_reg_field_desc *field =
					&hws_reg_fields[reg->field_first + field_index];

				if (field->context == HWS_REG_FIELD_WRITE)
					continue;
				seq_printf(s, " field register=%s channel=%d name=%s value=0x%x\n",
					   reg->id,
					   reg->count > 1 ? (int)instance : -1,
					   field->name,
					   hws_reg_field_value(value, field));
			}
		}
	}

	seq_printf(s, "timestamp_end_ns=%llu\n",
		   (unsigned long long)ktime_get_mono_fast_ns());

out_unlock:
	mutex_unlock(&hws->mmio_snapshot_lock);
	return 0;
}

static int hws_debugfs_atlas_open(struct inode *inode, struct file *file)
{
	return single_open(file, hws_debugfs_atlas_show, inode->i_private);
}

static int hws_debugfs_snapshot_open(struct inode *inode, struct file *file)
{
	return single_open(file, hws_debugfs_snapshot_show, inode->i_private);
}

static const struct file_operations hws_debugfs_atlas_fops = {
	.owner = THIS_MODULE,
	.open = hws_debugfs_atlas_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations hws_debugfs_snapshot_fops = {
	.owner = THIS_MODULE,
	.open = hws_debugfs_snapshot_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int hws_debugfs_init(void)
{
	hws_debugfs_root = debugfs_create_dir("hws", NULL);
	if (IS_ERR_OR_NULL(hws_debugfs_root)) {
		hws_debugfs_root = NULL;
		return 0;
	}
	return 0;
}

void hws_debugfs_exit(void)
{
	debugfs_remove(hws_debugfs_root);
	hws_debugfs_root = NULL;
}

void hws_debugfs_add_device(struct hws_pcie_dev *hws)
{
	struct dentry *snapshot;

	if (!hws || !hws->pdev || !hws_debugfs_root)
		return;

	hws->debugfs_dir = debugfs_create_dir(pci_name(hws->pdev),
					       hws_debugfs_root);
	if (IS_ERR_OR_NULL(hws->debugfs_dir)) {
		hws->debugfs_dir = NULL;
		return;
	}

	debugfs_create_file("register_atlas", 0400, hws->debugfs_dir, hws,
			    &hws_debugfs_atlas_fops);
	snapshot = debugfs_create_file("register_snapshot", 0400,
				       hws->debugfs_dir, hws,
				       &hws_debugfs_snapshot_fops);
	if (!IS_ERR_OR_NULL(snapshot))
		debugfs_create_file("bar0_snapshot", 0400, hws->debugfs_dir,
				    hws, &hws_debugfs_snapshot_fops);
}

void hws_debugfs_remove_device(struct hws_pcie_dev *hws)
{
	if (!hws)
		return;
	debugfs_remove(hws->debugfs_dir);
	hws->debugfs_dir = NULL;
}
