/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_FRAME_PATTERN_H
#define HWS_FRAME_PATTERN_H

#include <stdint.h>

#define HWS_PATTERN_VERSION "hws-bw-tiles-v1"
#ifndef HWS_PATTERN_SHA256
#define HWS_PATTERN_SHA256 "unrecorded"
#endif

/* All active pixels are specified. Neutral black/white avoids matrix-dependent
 * RGB->YUV coefficients. The two legacy barcode bands keep their geometry.
 * Outside them, position and frame ID select 32x16 pixel tiles. */
static inline uint8_t hws_pattern_crc(uint32_t id)
{
	uint8_t crc = 0;
	int shift, bit;
	for (shift = 24; shift >= 0; shift -= 8) {
		crc ^= id >> shift;
		for (bit = 0; bit < 8; bit++)
			crc = (crc & 128) ? (crc << 1) ^ 7 : crc << 1;
	}
	return crc;
}

static inline uint64_t hws_pattern_code(uint32_t id)
{
	return (UINT64_C(0xa5) << 56) | ((uint64_t)id << 24) |
	       ((uint64_t)(uint16_t)~id << 8) | hws_pattern_crc(id);
}

static inline unsigned int hws_pattern_white(uint32_t id, uint64_t code,
		unsigned int x, unsigned int y, unsigned int w, unsigned int h)
{
	unsigned int half, x0 = w * 5 / 100, span = w * 90 / 100;
	for (half = 0; half < 2; half++) {
		unsigned int center = h * (half ? 80 : 20) / 100;
		unsigned int radius = h * 4 / 100;
		if (y >= center - radius && y <= center + radius &&
		    x >= x0 && x < x0 + span) {
			/* Inverse of floor(cell * span / 64), including odd widths. */
			unsigned int cell = ((x - x0 + 1) * 64 - 1) / span;
			return (code >> (63 - cell)) & 1;
		}
	}
	uint32_t value = id ^ ((x / 32 + 1) * UINT32_C(0x9e3779b9)) ^
		((y / 16 + 1) * UINT32_C(0x85ebca6b));
	value ^= value >> 16;
	value *= UINT32_C(0x7feb352d);
	value ^= value >> 15;
	return value & 1;
}
#endif
