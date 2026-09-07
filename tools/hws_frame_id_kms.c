// SPDX-License-Identifier: GPL-2.0-only
/* Two-region barcode source with synchronous KMS page-flip evidence.
 * Uses an explicitly selected, already active, uncloned CRTC. An opt-in
 * 1080p60 modeset selects only exact advertised CTA timing and restores it.
 * Run from a VT/SSH with DRM master available; restores the original CRTC.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <xf86drm.h>
#include <xf86drmMode.h>
#include "hws_frame_pattern.h"

#ifndef HWS_SOURCE_SHA256
#define HWS_SOURCE_SHA256 "unrecorded"
#endif

struct surface {
	uint32_t handle, fb, pitch;
	uint64_t size;
	uint8_t *map;
};

struct presentation {
	FILE *out;
	uint32_t id, fb, count;
	uint64_t submitted_ns, render_started_ns, render_finished_ns, ioctl_finished_ns;
	bool pending;
};

static volatile sig_atomic_t stopping;

static void stop(int signo)
{
	(void)signo;
	stopping = 1;
}

static uint64_t now_ns(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t))
		return 0;
	return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

static void draw(struct surface *s, unsigned int w, unsigned int h, uint32_t id,
		 uint32_t *scratch)
{
	uint64_t code = hws_pattern_code(id);
	unsigned int x0 = w * 5 / 100, span = w * 90 / 100;
	unsigned int radius = h * 4 / 100;
	unsigned int upper = h * 20 / 100, lower = h * 80 / 100;
	bool previous_band = false;

	/* Pattern colors change only at tile or barcode boundaries. Build each
	 * distinct row in ordinary RAM, then write it to the scanout mapping.
	 * Never read back scanout memory to reuse a row: that mapping can be WC.
	 * scratch holds w pixels and is allocated once before presentation starts.
	 */
	for (unsigned int y = 0; y < h; y++) {
		bool band = (y >= upper - radius && y <= upper + radius) ||
			    (y >= lower - radius && y <= lower + radius);
		if (!y || y % 16 == 0 || band != previous_band) {
			for (unsigned int x = 0; x < w;) {
				unsigned int end = (x / 32 + 1) * 32;
				if (band && x >= x0 && x < x0 + span) {
					unsigned int cell = ((x - x0 + 1) * 64 - 1) / span;
					end = x0 + (cell + 1) * span / 64;
				} else if (band && x < x0 && end > x0) {
					end = x0;
				}
				if (end > w)
					end = w;
				uint32_t color = hws_pattern_white(id, code, x, y, w, h) ?
						 0xffffff : 0;
				for (; x < end; x++)
					scratch[x] = color;
			}
		}
		memcpy(s->map + (size_t)y * s->pitch, scratch, (size_t)w * sizeof(*scratch));
		previous_band = band;
	}
}

static int create_surface(int fd, struct surface *s, uint32_t w, uint32_t h)
{
	struct drm_mode_create_dumb create = { .width = w, .height = h, .bpp = 32 };
	struct drm_mode_map_dumb map = { 0 };

	if (drmIoctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &create))
		return -1;
	s->handle = create.handle;
	s->size = create.size;
	s->pitch = create.pitch;
	if (drmModeAddFB(fd, w, h, 24, 32, s->pitch, s->handle, &s->fb))
		return -1;
	map.handle = s->handle;
	if (drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &map))
		return -1;
	s->map = mmap(NULL, s->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, map.offset);
	if (s->map == MAP_FAILED) {
		s->map = NULL;
		return -1;
	}
	return 0;
}

static void destroy_surface(int fd, struct surface *s)
{
	struct drm_mode_destroy_dumb destroy = { .handle = s->handle };

	if (s->map)
		munmap(s->map, s->size);
	if (s->fb)
		drmModeRmFB(fd, s->fb);
	if (s->handle)
		drmIoctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &destroy);
}

static void flipped(int fd, unsigned int sequence, unsigned int sec,
		    unsigned int usec, void *data)
{
	struct presentation *p = data;
	(void)fd;
	fprintf(p->out,
		"{\"type\":\"present\",\"id\":%u,\"fb_id\":%u,\"sequence\":%u,\"submitted_ns\":%" PRIu64 ",\"presented_ns\":%" PRIu64 ",\"callback_ns\":%" PRIu64 ",\"render_started_ns\":%" PRIu64 ",\"render_finished_ns\":%" PRIu64 ",\"ioctl_finished_ns\":%" PRIu64 "}\n",
		p->id, p->fb, sequence, p->submitted_ns,
		(uint64_t)sec * 1000000000 + (uint64_t)usec * 1000, now_ns(),
		p->render_started_ns, p->render_finished_ns, p->ioctl_finished_ns);
	p->pending = false;
	p->count++;
}

static int wait_flip(int fd, struct presentation *p)
{
	drmEventContext events = { .version = 2, .page_flip_handler = flipped };
	uint64_t deadline = now_ns() + 3000000000ULL;

	/* Drain even after SIGINT: never reuse a buffer with a pending flip. */
	while (p->pending && now_ns() < deadline) {
		struct pollfd pollfd = { .fd = fd, .events = POLLIN };
		int ret = poll(&pollfd, 1, 100);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0 || (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
			return -1;
		if (ret > 0 && drmHandleEvent(fd, &events))
			return -1;
	}
	return p->pending ? -1 : 0;
}

static uint32_t number(const char *s)
{
	char *end;
	unsigned long n;

	errno = 0;
	n = strtoul(s, &end, 10);
	if (errno || !*s || *end || !n || n > UINT32_MAX)
		return 0;
	return n;
}

static bool same_scanout(const drmModeModeInfo *a, const drmModeModeInfo *b)
{
	return a->clock == b->clock && a->hdisplay == b->hdisplay &&
		a->hsync_start == b->hsync_start && a->hsync_end == b->hsync_end &&
		a->htotal == b->htotal && a->hskew == b->hskew &&
		a->vdisplay == b->vdisplay && a->vsync_start == b->vsync_start &&
		a->vsync_end == b->vsync_end && a->vtotal == b->vtotal &&
		a->vscan == b->vscan && a->flags == b->flags;
}

static bool exact_1080p60(const drmModeModeInfo *m)
{
	return m->clock == 148500 && m->hdisplay == 1920 &&
		m->hsync_start == 2008 && m->hsync_end == 2052 && m->htotal == 2200 &&
		!m->hskew && m->vdisplay == 1080 && m->vsync_start == 1084 &&
		m->vsync_end == 1089 && m->vtotal == 1125 && m->vscan <= 1 &&
		(m->flags & (DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC)) ==
			(DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC) &&
		!(m->flags & (DRM_MODE_FLAG_INTERLACE | DRM_MODE_FLAG_DBLSCAN |
			DRM_MODE_FLAG_DBLCLK | DRM_MODE_FLAG_CLKDIV2 |
			DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC));
}

static int choose_1080p60(const drmModeConnector *connector, drmModeModeInfo *mode)
{
	for (int i = 0; i < connector->count_modes; i++)
		if (exact_1080p60(&connector->modes[i])) {
			*mode = connector->modes[i];
			return 0;
		}
	return -1;
}

static int restore_crtc(int fd, drmModeCrtc *saved, uint32_t connector_id)
{
	if (drmModeSetCrtc(fd, saved->crtc_id, saved->buffer_id, saved->x,
			  saved->y, &connector_id, 1, &saved->mode))
		return -1;
	drmModeCrtc *actual = drmModeGetCrtc(fd, saved->crtc_id);
	bool ok = actual && actual->mode_valid && actual->buffer_id == saved->buffer_id &&
		actual->x == saved->x && actual->y == saved->y &&
		same_scanout(&actual->mode, &saved->mode);
	if (actual)
		drmModeFreeCrtc(actual);
	return ok ? 0 : -1;
}

int main(int argc, char **argv)
{
	struct surface surfaces[2] = { 0 };
	struct presentation p = { 0 };
	drmModeRes *resources = NULL;
	drmModeConnector *connector = NULL;
	drmModeCrtc *saved = NULL;
	drmModeModeInfo mode;
	uint32_t *render_row = NULL;
	uint32_t connector_id, crtc_id, seconds, seed, connected = 0;
	uint64_t cap = 0, deadline;
	struct stat card_stat;
	char boot_id[40] = { 0 };
	FILE *boot;
	int fd = -1, ret = 1, i;
	bool touched = false, restored = false;
	bool set_1080 = argc == 7 && !strcmp(argv[6], "--mode-1080p60");
	const char *run_id = getenv("HWS_RUN_ID");
	if (!run_id) run_id = "";
	if (strlen(run_id) > 64 || strspn(run_id,
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != strlen(run_id)) {
		fprintf(stderr, "Invalid HWS_RUN_ID\n");
		return 2;
	}

	if (argc != 6 && !set_1080) {
		fprintf(stderr, "Usage: %s CARD CONNECTOR_ID CRTC_ID SECONDS OUTPUT.jsonl [--mode-1080p60]\n"
			"Default: current active mode. Optional exact advertised 1080p60; original CRTC restored.\n"
			"Requires DRM master. SECONDS: 1..3600.\n", argv[0]);
		return argc == 2 && !strcmp(argv[1], "--help") ? 0 : 2;
	}
	connector_id = number(argv[2]);
	crtc_id = number(argv[3]);
	seconds = number(argv[4]);
	if (!connector_id || !crtc_id || !seconds || seconds > 3600)
		return 2;
	boot = fopen("/proc/sys/kernel/random/boot_id", "r");
	if (!boot)
		return 2;
	if (fscanf(boot, "%36[0-9a-f-]", boot_id) != 1) {
		fclose(boot);
		return 2;
	}
	fclose(boot);
	if (getrandom(&seed, sizeof(seed), 0) != sizeof(seed))
		return 2;
	p.id = seed & 0x7fffffff; /* avoid wrap, distinguish concurrent sources */
	fd = open(argv[1], O_RDWR | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &card_stat) || drmSetMaster(fd) ||
	    drmGetCap(fd, DRM_CAP_TIMESTAMP_MONOTONIC, &cap) || cap != 1) {
		fprintf(stderr, "Cannot acquire DRM master with monotonic flip timestamps\n");
		goto out;
	}
	resources = drmModeGetResources(fd);
	connector = drmModeGetConnector(fd, connector_id);
	saved = drmModeGetCrtc(fd, crtc_id);
	if (!resources || !connector || !saved || !saved->mode_valid ||
	    !saved->buffer_id || connector->connection != DRM_MODE_CONNECTED ||
	    saved->mode.hdisplay < 640 || saved->mode.vdisplay < 480 ||
	    (saved->mode.flags & (DRM_MODE_FLAG_INTERLACE | DRM_MODE_FLAG_DBLSCAN)))
		goto out;
	for (i = 0; i < resources->count_connectors; i++) {
		drmModeConnector *c = drmModeGetConnector(fd, resources->connectors[i]);
		drmModeEncoder *e = c ? drmModeGetEncoder(fd, c->encoder_id) : NULL;
		if (e && e->crtc_id == crtc_id) {
			connected++;
			if (c->connector_id != connector_id)
				connected += 100; /* refuse clones or mismatched target */
		}
		if (e)
			drmModeFreeEncoder(e);
		if (c)
			drmModeFreeConnector(c);
	}
	if (connected != 1) {
		fprintf(stderr, "Selected CRTC must drive only the selected connector\n");
		goto out;
	}
	mode = saved->mode;
	if (set_1080 && choose_1080p60(connector, &mode)) {
		fprintf(stderr, "Connector does not advertise exact 1920x1080p60 CTA timings\n");
		goto out;
	}
	render_row = malloc((size_t)mode.hdisplay * sizeof(*render_row));
	if (!render_row)
		goto out;
	for (i = 0; i < 2; i++)
		if (create_surface(fd, &surfaces[i], mode.hdisplay, mode.vdisplay))
			goto out;
	p.out = fopen(argv[5], "wx");
	if (!p.out)
		goto out;
	setvbuf(p.out, NULL, _IOLBF, 0);
	signal(SIGINT, stop);
	signal(SIGTERM, stop);
	/* Mark the attempt before the ioctl: restore even on a modeset error.
	 * ID zero is unmeasured. Read back the applied timing before publishing
	 * source_config; the controller must not start capture from a planned mode.
	 */
	draw(&surfaces[1], mode.hdisplay, mode.vdisplay, 0, render_row);
	if (stopping)
		goto out;
	touched = true;
	if (drmModeSetCrtc(fd, crtc_id, surfaces[1].fb, 0, 0, &connector_id, 1, &mode)) {
		perror("initial drmModeSetCrtc");
		goto out;
	}
	drmModeCrtc *actual = drmModeGetCrtc(fd, crtc_id);
	bool applied = actual && actual->mode_valid && actual->buffer_id == surfaces[1].fb &&
		!actual->x && !actual->y && same_scanout(&actual->mode, &mode);
	if (actual)
		drmModeFreeCrtc(actual);
	if (!applied) {
		fprintf(stderr, "Applied CRTC mode/framebuffer did not match requested scanout\n");
		goto out;
	}
	fprintf(p.out,
		"{\"type\":\"source_config\",\"pattern\":\"" HWS_PATTERN_VERSION "\",\"pattern_sha256\":\"" HWS_PATTERN_SHA256 "\",\"schema\":1,\"backend\":\"drm-kms\",\"run_id\":\"%s\",\"source_sha256\":\"%s\",\"card_rdev\":%ju,\"clock\":\"CLOCK_MONOTONIC\",\"boot_id\":\"%s\",\"connector_id\":%u,\"crtc_id\":%u,\"width\":%u,\"height\":%u,\"clock_khz\":%u,\"htotal\":%u,\"vtotal\":%u,\"mode_flags\":%u,\"vscan\":%u,\"async_flip\":false}\n",
		run_id, HWS_SOURCE_SHA256, (uintmax_t)card_stat.st_rdev,
		boot_id, connector_id, crtc_id, mode.hdisplay, mode.vdisplay,
		mode.clock, mode.htotal, mode.vtotal, mode.flags, mode.vscan);
	deadline = now_ns() + (uint64_t)seconds * 1000000000;
	ret = 0;
	while (!stopping && now_ns() < deadline && p.count < 1000000) {
		struct surface *s = &surfaces[p.count & 1];
		p.id++;
		p.render_started_ns = now_ns();
		draw(s, mode.hdisplay, mode.vdisplay, p.id, render_row);
		p.render_finished_ns = now_ns();
		p.fb = s->fb;
		p.submitted_ns = now_ns();
		if (drmModePageFlip(fd, crtc_id, s->fb, DRM_MODE_PAGE_FLIP_EVENT, &p)) {
			perror("drmModePageFlip");
			ret = 1;
			break;
		}
		p.ioctl_finished_ns = now_ns();
		touched = true;
		p.pending = true;
		if (wait_flip(fd, &p) || ferror(p.out)) {
			fprintf(stderr, "Page-flip completion or telemetry write failed\n");
			ret = 1;
			break;
		}
	}
out:
	free(render_row);
	if (touched) {
		restored = restore_crtc(fd, saved, connector_id) == 0;
		if (!restored) {
			fprintf(stderr, "Failed to restore/verify original CRTC\n");
			ret = 1;
		}
	}
	if (p.out) {
		fprintf(p.out, "{\"type\":\"source_summary\",\"result\":\"%s\",\"presentations\":%u,\"restored\":%s}\n",
			ret ? "fail" : "pass", p.count, restored ? "true" : "false");
		if (fclose(p.out))
			ret = 1;
	}
	for (i = 0; i < 2; i++)
		if (fd >= 0)
			destroy_surface(fd, &surfaces[i]);
	if (saved)
		drmModeFreeCrtc(saved);
	if (connector)
		drmModeFreeConnector(connector);
	if (resources)
		drmModeFreeResources(resources);
	if (fd >= 0)
		close(fd);
	fprintf(stderr, "KMS source result=%s presentations=%u\n", ret ? "FAIL" : "PASS", p.count);
	return ret;
}
