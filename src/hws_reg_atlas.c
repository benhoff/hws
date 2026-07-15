// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>

#include "hws_reg_atlas.h"

#include "hws_reg_atlas_generated.inc"

const struct hws_reg_desc *hws_reg_lookup(u32 offset, int *channel)
{
	size_t i;

	if (channel)
		*channel = -1;

	for (i = 0; i < hws_reg_atlas_count; i++) {
		const struct hws_reg_desc *reg = &hws_reg_atlas[i];
		unsigned int instance;

		for (instance = 0; instance < reg->count; instance++) {
			u32 instance_offset = reg->offset + instance * reg->stride;

			if (instance_offset != offset)
				continue;
			if (channel && reg->count > 1)
				*channel = instance;
			return reg;
		}
	}

	return NULL;
}

const char *hws_reg_access_name(enum hws_reg_access access)
{
	switch (access) {
	case HWS_REG_RO:
		return "ro";
	case HWS_REG_RW:
		return "rw";
	case HWS_REG_W1C:
		return "w1c";
	case HWS_REG_WO:
		return "wo";
	case HWS_REG_R_STATUS_W_CONTROL:
		return "r-status-w-control";
	default:
		return "unknown";
	}
}

const char *hws_reg_confidence_name(enum hws_reg_confidence confidence)
{
	switch (confidence) {
	case HWS_REG_MEASURED:
		return "measured";
	case HWS_REG_VENDOR_CODE:
		return "vendor-code";
	case HWS_REG_INFERRED:
		return "inferred";
	case HWS_REG_UNKNOWN:
	default:
		return "unknown";
	}
}

const char *hws_reg_field_context_name(enum hws_reg_field_context context)
{
	switch (context) {
	case HWS_REG_FIELD_READ:
		return "read";
	case HWS_REG_FIELD_WRITE:
		return "write";
	case HWS_REG_FIELD_BOTH:
	default:
		return "both";
	}
}

u32 hws_reg_field_value(u32 value, const struct hws_reg_field_desc *field)
{
	u64 mask;

	if (!field || field->msb > 31 || field->lsb > field->msb)
		return 0;

	mask = GENMASK_ULL(field->msb, field->lsb);
	return (value & mask) >> field->lsb;
}
