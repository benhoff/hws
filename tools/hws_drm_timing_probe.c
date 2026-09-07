// SPDX-License-Identifier: GPL-2.0-only
/* Read-only CRTC sequence preflight. Never acquires DRM master or modesets.
 * A usable sequence stream is not proof of page-flip or optical timing.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <xf86drm.h>
#include <xf86drmMode.h>

struct measurements {
	uint64_t sequence, first, last, missing;
	unsigned count, invalid;
	double min_ns, max_ns, sum_ns;
	int64_t receipt_min, receipt_max;
};

static volatile sig_atomic_t stopped;
static void stop(int sig) { (void)sig; stopped = 1; }

static uint64_t monotonic_ns(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t))
		return 0;
	return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static void observe(struct measurements *m, uint64_t seq, int64_t ns,
		    int64_t receipt, double period)
{
	int64_t offset = receipt - ns;
	bool valid = ns > 0 && receipt > 0 && fabs((double)offset) <= period;
	if (m->count) {
		if (seq <= m->sequence || ns <= (int64_t)m->last) {
			valid = false;
		} else {
			double dt = ns - m->last;
			uint64_t delta = seq - m->sequence;
			m->missing += delta - 1;
			if (fabs(dt - delta * period) > period * .25)
				valid = false;
			if (dt < m->min_ns) m->min_ns = dt;
			if (dt > m->max_ns) m->max_ns = dt;
			m->sum_ns += dt;
		}
	} else {
		m->first = ns;
		m->min_ns = INFINITY;
		m->receipt_min = INT64_MAX;
		m->receipt_max = INT64_MIN;
	}
	if (!valid) m->invalid++;
	if (offset < m->receipt_min) m->receipt_min = offset;
	if (offset > m->receipt_max) m->receipt_max = offset;
	m->sequence = seq;
	m->last = ns;
	m->count++;
}

static uint32_t number(const char *s)
{
	char *end;
	errno = 0;
	unsigned long n = strtoul(s, &end, 10);
	return errno || !*s || *end || n > UINT32_MAX ? 0 : (uint32_t)n;
}

static int list(int fd)
{
	drmModeRes *r = drmModeGetResources(fd);
	if (!r) return 1;
	for (int i = 0; i < r->count_connectors; i++) {
		drmModeConnector *c = drmModeGetConnector(fd, r->connectors[i]);
		drmModeEncoder *e = c && c->encoder_id ? drmModeGetEncoder(fd, c->encoder_id) : NULL;
		drmModeCrtc *crtc = e && e->crtc_id ? drmModeGetCrtc(fd, e->crtc_id) : NULL;
		if (c)
			printf("connector=%u name=%s-%u connected=%d crtc=%u active=%d width=%u height=%u\n",
			       c->connector_id, drmModeGetConnectorTypeName(c->connector_type),
			       c->connector_type_id, c->connection == DRM_MODE_CONNECTED,
			       e ? e->crtc_id : 0, crtc ? crtc->mode_valid : 0,
			       crtc ? crtc->mode.hdisplay : 0, crtc ? crtc->mode.vdisplay : 0);
		if (crtc) drmModeFreeCrtc(crtc);
		if (e) drmModeFreeEncoder(e);
		if (c) drmModeFreeConnector(c);
	}
	drmModeFreeResources(r);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 5 && !(argc == 3 && !strcmp(argv[2], "--list"))) {
		fprintf(stderr, "Usage: %s CARD --list\n       %s CARD CRTC_ID SAMPLES OUTPUT.jsonl\n"
			"SAMPLES: 2..3600; 120-second deadline. No display changes.\n", argv[0], argv[0]);
		return argc == 2 && !strcmp(argv[1], "--help") ? 0 : 2;
	}
	int fd = open(argv[1], O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) { perror("open card"); return 1; }
	if (argc == 3) { int rc = list(fd); close(fd); return rc; }
	uint32_t crtc_id = number(argv[2]), target = number(argv[3]);
	if (!crtc_id || target < 2 || target > 3600) { close(fd); return 2; }
	drmModeCrtc *crtc = drmModeGetCrtc(fd, crtc_id);
	if (!crtc || !crtc->mode_valid || !crtc->mode.clock || !crtc->mode.htotal ||
	    !crtc->mode.vtotal || crtc->mode.vscan > 1 ||
	    crtc->mode.flags & (DRM_MODE_FLAG_INTERLACE | DRM_MODE_FLAG_DBLSCAN)) {
		fprintf(stderr, "Requires an active progressive CRTC\n");
		if (crtc) drmModeFreeCrtc(crtc);
		close(fd); return 1;
	}
	FILE *out = fopen(argv[4], "wx");
	if (!out) { perror("create output"); drmModeFreeCrtc(crtc); close(fd); return 1; }
	char boot[40] = {0};
	FILE *b = fopen("/proc/sys/kernel/random/boot_id", "r");
	if (b) { if (fscanf(b, "%36[0-9a-f-]", boot) != 1) boot[0] = 0; fclose(b); }
	double period = 1e6 * crtc->mode.htotal * crtc->mode.vtotal / crtc->mode.clock;
	fprintf(out, "{\"type\":\"config\",\"schema\":1,\"clock\":\"CLOCK_MONOTONIC\",\"boot_id\":\"%s\","
		"\"crtc_id\":%u,\"width\":%u,\"height\":%u,\"clock_khz\":%u,\"htotal\":%u,\"vtotal\":%u,"
		"\"requested_samples\":%u,\"nominal_period_ns\":%.3f,\"page_flips_tested\":false}\n",
		boot, crtc_id, crtc->mode.hdisplay, crtc->mode.vdisplay, crtc->mode.clock,
		crtc->mode.htotal, crtc->mode.vtotal, target, period);
	uint64_t cap = 0, seq = 0, stamp = 0;
	errno = 0;
	int cap_ret = drmGetCap(fd, DRM_CAP_TIMESTAMP_MONOTONIC, &cap);
	int cap_errno = errno;
	errno = 0;
	int query_ret = drmCrtcGetSequence(fd, crtc_id, &seq, &stamp);
	int query_errno = errno;
	fprintf(out, "{\"type\":\"query\",\"cap_return\":%d,\"cap_errno\":%d,\"monotonic_cap\":%" PRIu64 ","
		"\"sequence_return\":%d,\"sequence_errno\":%d,\"sequence\":%" PRIu64 ",\"timestamp_ns\":%" PRIu64 "}\n",
		cap_ret, cap_errno, cap, query_ret, query_errno, seq, stamp);
	struct measurements m = {0};
	int error = cap_ret || cap != 1 || query_ret || !boot[0];
	const char *stage = error ? "capability_or_query" : "complete";
	signal(SIGINT, stop); signal(SIGTERM, stop);
	uint64_t deadline = monotonic_ns() + 120000000000ULL;
	while (!error && !stopped && m.count < target && monotonic_ns() < deadline) {
		errno = 0;
		if (drmCrtcQueueSequence(fd, crtc_id, DRM_CRTC_SEQUENCE_RELATIVE, 1, &seq, 0)) {
			error = errno ? errno : EIO; stage = "queue_sequence"; break;
		}
		struct pollfd p = {.fd = fd, .events = POLLIN};
		int ret = poll(&p, 1, 2000);
		if (ret <= 0 || p.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			error = ret == 0 ? ETIMEDOUT : EIO; stage = "wait_event"; break;
		}
		struct drm_event_crtc_sequence ev;
		if (read(fd, &ev, sizeof(ev)) != sizeof(ev) ||
		    ev.base.type != DRM_EVENT_CRTC_SEQUENCE || ev.base.length != sizeof(ev)) {
			error = EIO; stage = "read_event"; break;
		}
		uint64_t receipt = monotonic_ns();
		fprintf(out, "{\"type\":\"sequence\",\"sequence\":%" PRIu64 ",\"timestamp_ns\":%" PRId64
			",\"receipt_ns\":%" PRIu64 "}\n", (uint64_t)ev.sequence, (int64_t)ev.time_ns, receipt);
		observe(&m, ev.sequence, ev.time_ns, receipt, period);
		if (ferror(out)) { error = EIO; stage = "write_event"; }
	}
	/* Recheck the mode: events spanning a mode change are not a valid sample. */
	drmModeCrtc *after = drmModeGetCrtc(fd, crtc_id);
	if (!after || !after->mode_valid || memcmp(&after->mode, &crtc->mode, sizeof(after->mode))) {
		error = EIO; stage = "mode_changed_or_unreadable";
	}
	if (after) drmModeFreeCrtc(after);
	bool usable = !error && !stopped && m.count == target && !m.invalid;
	fprintf(out, "{\"type\":\"summary\",\"sequence_stream\":\"%s\",\"stage\":\"%s\",\"error\":%d,"
		"\"samples\":%u,\"invalid_samples\":%u,\"unobserved_sequences\":%" PRIu64 ",\"page_flips_tested\":false",
		usable ? "usable" : "unqualified", m.count != target && !error ? "interrupted_or_deadline" : stage,
		error, m.count, m.invalid, m.missing);
	if (m.count > 1 && !m.invalid) {
		fprintf(out, ",\"interval_mean_ns\":%.3f,\"interval_min_ns\":%.3f,\"interval_max_ns\":%.3f,"
			"\"receipt_minus_timestamp_min_ns\":%" PRId64 ",\"receipt_minus_timestamp_max_ns\":%" PRId64,
			m.sum_ns / (m.count - 1), m.min_ns, m.max_ns, m.receipt_min, m.receipt_max);
	}
	fprintf(out, "}\n");
	if (fclose(out)) usable = false;
	drmModeFreeCrtc(crtc); close(fd);
	fprintf(stderr, "CRTC sequence stream %s; samples=%u invalid=%u; page flips not tested\n",
		usable ? "usable" : "unqualified", m.count, m.invalid);
	return usable ? 0 : 1;
}
