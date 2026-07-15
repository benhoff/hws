/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_REG_ATLAS_H
#define HWS_REG_ATLAS_H

#include <linux/types.h>

enum hws_reg_access {
	HWS_REG_RO,
	HWS_REG_RW,
	HWS_REG_W1C,
	HWS_REG_WO,
	HWS_REG_R_STATUS_W_CONTROL,
};

enum hws_reg_confidence {
	HWS_REG_MEASURED,
	HWS_REG_VENDOR_CODE,
	HWS_REG_INFERRED,
	HWS_REG_UNKNOWN,
};

enum hws_reg_field_context {
	HWS_REG_FIELD_BOTH,
	HWS_REG_FIELD_READ,
	HWS_REG_FIELD_WRITE,
};

struct hws_reg_field_desc {
	const char *name;
	u8 lsb;
	u8 msb;
	enum hws_reg_field_context context;
};

struct hws_reg_desc {
	const char *id;
	const char *name;
	u32 offset;
	u16 stride;
	u8 width_bits;
	u8 count;
	enum hws_reg_access access;
	bool snapshot_safe;
	bool reset_known;
	u32 reset_value;
	u16 typical_first;
	u8 typical_count;
	u16 field_first;
	u8 field_count;
	enum hws_reg_confidence confidence;
	const char *evidence;
};

extern const struct hws_reg_desc hws_reg_atlas[];
extern const size_t hws_reg_atlas_count;
extern const struct hws_reg_field_desc hws_reg_fields[];
extern const size_t hws_reg_field_count;
extern const u32 hws_reg_typical_values[];
extern const size_t hws_reg_typical_value_count;

const struct hws_reg_desc *hws_reg_lookup(u32 offset, int *channel);
const char *hws_reg_access_name(enum hws_reg_access access);
const char *hws_reg_confidence_name(enum hws_reg_confidence confidence);
const char *hws_reg_field_context_name(enum hws_reg_field_context context);
u32 hws_reg_field_value(u32 value, const struct hws_reg_field_desc *field);

#endif
