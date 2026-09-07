// SPDX-License-Identifier: GPL-2.0-only
/* Actual mode selection and restoration code; mocked DRM, no device access. */
#define drmModeSetCrtc mocked_set_crtc
#define drmModeGetCrtc mocked_get_crtc
#define drmModeFreeCrtc mocked_free_crtc
#define main kms_source_main
#include "hws_frame_id_kms.c"
#undef main
#include <assert.h>

static drmModeCrtc expected, observed;
static int set_error, missing_readback, set_calls, get_calls;

int mocked_set_crtc(int fd, uint32_t crtc, uint32_t fb, uint32_t x, uint32_t y,
		    uint32_t *connectors, int count, drmModeModeInfoPtr mode)
{
	assert(fd == 123 && crtc == expected.crtc_id && fb == expected.buffer_id);
	assert(x == expected.x && y == expected.y && count == 1 && connectors[0] == 84);
	assert(same_scanout(mode, &expected.mode));
	set_calls++;
	return set_error;
}

drmModeCrtcPtr mocked_get_crtc(int fd, uint32_t crtc)
{
	assert(fd == 123 && crtc == expected.crtc_id);
	get_calls++;
	return missing_readback ? NULL : &observed;
}

void mocked_free_crtc(drmModeCrtcPtr crtc) { assert(crtc == &observed); }

int main(void)
{
	drmModeModeInfo good = { .clock=148500, .hdisplay=1920, .hsync_start=2008,
		.hsync_end=2052, .htotal=2200, .vdisplay=1080, .vsync_start=1084,
		.vsync_end=1089, .vtotal=1125, .flags=DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC };
	drmModeModeInfo modes[3] = {good, good, good}, chosen = {0};
	modes[0].clock = 148352; /* 59.94 is not exact 60. */
	modes[1].hdisplay = 4096;
	drmModeConnector connector = {.count_modes=3, .modes=modes};
	assert(!choose_1080p60(&connector, &chosen) && same_scanout(&chosen, &good));
	connector.count_modes = 2;
	assert(choose_1080p60(&connector, &chosen) == -1);
	connector.count_modes = 0;
	assert(choose_1080p60(&connector, &chosen) == -1);
	const unsigned int bad_flags[] = {DRM_MODE_FLAG_INTERLACE, DRM_MODE_FLAG_DBLSCAN,
		DRM_MODE_FLAG_DBLCLK, DRM_MODE_FLAG_CLKDIV2, DRM_MODE_FLAG_NHSYNC, DRM_MODE_FLAG_NVSYNC};
	for (unsigned int i=0; i<sizeof(bad_flags)/sizeof(*bad_flags); i++) {
		chosen=good; chosen.flags |= bad_flags[i]; assert(!exact_1080p60(&chosen));
	}
	chosen=good; chosen.flags=0; assert(!exact_1080p60(&chosen));
	chosen=good; chosen.vscan=2; assert(!exact_1080p60(&chosen));
	chosen=good; chosen.hsync_start++; assert(!exact_1080p60(&chosen));
	chosen=good; chosen.vsync_end++; assert(!exact_1080p60(&chosen));
	chosen=good; chosen.hskew++; assert(!exact_1080p60(&chosen));
	assert(exact_1080p60(&good));
	/* Original geometry, viewport and FB are restored, not the test mode. */
	expected = (drmModeCrtc){.crtc_id=81, .buffer_id=95, .x=12, .y=34, .mode_valid=1, .mode=good};
	expected.mode.hdisplay=4096; expected.mode.vdisplay=2160; expected.mode.clock=594000;
	observed=expected;
	assert(!restore_crtc(123, &expected, 84) && set_calls==1 && get_calls==1);
	set_error=1;
	assert(restore_crtc(123, &expected, 84)==-1 && get_calls==1);
	set_error=0; missing_readback=1;
	assert(restore_crtc(123, &expected, 84)==-1);
	missing_readback=0;
	for (int i=0; i<5; i++) {
		observed=expected;
		if (i==0) observed.mode.clock++;
		if (i==1) observed.x++;
		if (i==2) observed.y++;
		if (i==3) observed.buffer_id++;
		if (i==4) observed.mode_valid=0;
		assert(restore_crtc(123, &expected, 84)==-1);
	}
	puts("KMS exact-mode selection/restoration PASS (modeled DRM; no physical display access)");
	return 0;
}
