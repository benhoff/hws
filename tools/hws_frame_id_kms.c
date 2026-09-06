// SPDX-License-Identifier: GPL-2.0-only
/* Two-region barcode source with synchronous KMS page-flip evidence.
 * Uses an explicitly selected, already active, uncloned CRTC and its mode.
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
	uint64_t submitted_ns;
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

static void draw(struct surface *s, unsigned int w, unsigned int h, uint32_t id)
{
	uint64_t code = hws_pattern_code(id);
	unsigned int x, y;

	for (y = 0; y < h; y++) {
		uint32_t *row = (uint32_t *)(s->map + (size_t)y * s->pitch);
		for (x = 0; x < w; x++)
			row[x] = hws_pattern_white(id, code, x, y, w, h) ? 0xffffff : 0;
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
		"{\"type\":\"present\",\"id\":%u,\"fb_id\":%u,\"sequence\":%u,\"submitted_ns\":%" PRIu64 ",\"presented_ns\":%" PRIu64 ",\"callback_ns\":%" PRIu64 "}\n",
		p->id, p->fb, sequence, p->submitted_ns,
		(uint64_t)sec * 1000000000 + (uint64_t)usec * 1000, now_ns());
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

int main(int argc, char **argv)
{
	struct surface surfaces[2] = { 0 };
	struct presentation p = { 0 };
	drmModeRes *resources = NULL;
	drmModeConnector *connector = NULL;
	drmModeCrtc *saved = NULL;
	uint32_t connector_id, crtc_id, seconds, seed, connected = 0;
	uint64_t cap = 0, deadline;
	struct stat card_stat;
	char boot_id[40] = { 0 };
	FILE *boot;
	int fd = -1, ret = 1, i;
	bool touched = false;

	if (argc != 6) {
		fprintf(stderr, "Usage: %s CARD CONNECTOR_ID CRTC_ID SECONDS OUTPUT.jsonl\n"
			"Uses the current active mode; requires DRM master. SECONDS: 1..3600.\n", argv[0]);
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
	for (i = 0; i < 2; i++)
		if (create_surface(fd, &surfaces[i], saved->mode.hdisplay, saved->mode.vdisplay))
			goto out;
	p.out = fopen(argv[5], "wx");
	if (!p.out)
		goto out;
	setvbuf(p.out, NULL, _IOLBF, 0);
	fprintf(p.out,
		"{\"type\":\"source_config\",\"pattern\":\"" HWS_PATTERN_VERSION "\",\"pattern_sha256\":\"" HWS_PATTERN_SHA256 "\",\"schema\":1,\"backend\":\"drm-kms\",\"source_sha256\":\"%s\",\"card_rdev\":%ju,\"clock\":\"CLOCK_MONOTONIC\",\"boot_id\":\"%s\",\"connector_id\":%u,\"crtc_id\":%u,\"width\":%u,\"height\":%u,\"clock_khz\":%u,\"htotal\":%u,\"vtotal\":%u,\"mode_flags\":%u,\"vscan\":%u,\"async_flip\":false}\n",
		HWS_SOURCE_SHA256, (uintmax_t)card_stat.st_rdev,
		boot_id, connector_id, crtc_id, saved->mode.hdisplay, saved->mode.vdisplay,
		saved->mode.clock, saved->mode.htotal, saved->mode.vtotal,
		saved->mode.flags, saved->mode.vscan);
	signal(SIGINT, stop);
	signal(SIGTERM, stop);
	/* Establish a viewport at (0,0) using the selected CRTC's existing mode.
	 * ID zero is only the initial unmeasured image; evidence starts at the
	 * first flip-complete event below. Preserve saved x/y for restoration.
	 */
	draw(&surfaces[1], saved->mode.hdisplay, saved->mode.vdisplay, 0);
	if (drmModeSetCrtc(fd, crtc_id, surfaces[1].fb, 0, 0,
			   &connector_id, 1, &saved->mode)) {
		perror("initial drmModeSetCrtc");
		goto out;
	}
	touched = true;
	deadline = now_ns() + (uint64_t)seconds * 1000000000;
	ret = 0;
	while (!stopping && now_ns() < deadline && p.count < 1000000) {
		struct surface *s = &surfaces[p.count & 1];
		p.id++;
		draw(s, saved->mode.hdisplay, saved->mode.vdisplay, p.id);
		p.fb = s->fb;
		p.submitted_ns = now_ns();
		if (drmModePageFlip(fd, crtc_id, s->fb, DRM_MODE_PAGE_FLIP_EVENT, &p)) {
			perror("drmModePageFlip");
			ret = 1;
			break;
		}
		touched = true;
		p.pending = true;
		if (wait_flip(fd, &p) || ferror(p.out)) {
			fprintf(stderr, "Page-flip completion or telemetry write failed\n");
			ret = 1;
			break;
		}
	}
out:
	if (touched && drmModeSetCrtc(fd, crtc_id, saved->buffer_id, saved->x,
				    saved->y, &connector_id, 1, &saved->mode)) {
		fprintf(stderr, "Failed to restore original CRTC\n");
		ret = 1;
	}
	if (p.out) {
		fprintf(p.out, "{\"type\":\"source_summary\",\"result\":\"%s\",\"presentations\":%u}\n",
			ret ? "fail" : "pass", p.count);
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
