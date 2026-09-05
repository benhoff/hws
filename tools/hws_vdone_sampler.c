// SPDX-License-Identifier: GPL-2.0-only
/* Read-only, independently timed BAR sampler for diagnostic VDONE runs. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define HWS_REG_INT_STATUS 0x4004U
#define HWS_REG_VBUF_TOGGLE(ch) (0x4080U + (uint32_t)(ch) * 4U)
#define DEFAULT_INTERVAL_US 250U
#define DEFAULT_SECONDS 60U

struct options {
	const char *bdf;
	const char *output;
	uint32_t channel;
	uint32_t interval_us;
	uint32_t seconds;
};

static volatile sig_atomic_t stop_requested;

static void handle_signal(int signo)
{
	(void)signo;
	stop_requested = 1;
}

static uint64_t monotonic_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)now.tv_nsec;
}

static struct timespec ns_timespec(uint64_t ns)
{
	return (struct timespec) {
		.tv_sec = (time_t)(ns / UINT64_C(1000000000)),
		.tv_nsec = (long)(ns % UINT64_C(1000000000)),
	};
}

static int parse_u32(const char *text, uint32_t minimum, uint32_t maximum,
		     uint32_t *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !end || *end || parsed < minimum || parsed > maximum)
		return -1;
	*value = (uint32_t)parsed;
	return 0;
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
		"Usage: %s --bdf PCI_BDF --channel N --output FILE [options]\n\n"
		"Read-only BAR0 sampling records toggle/status transitions, not every poll.\n"
		"Run separately from the primary semantics proof because MMIO polling is intrusive.\n\n"
		"  --bdf BDF             PCI address, for example 0000:05:00.0\n"
		"  -c, --channel N       Video channel 0..3\n"
		"  -o, --output FILE     Exclusive JSONL output\n"
		"  -i, --interval-us N   Sampling interval, 50..5000 (default %u)\n"
		"  -s, --seconds N       Duration, 1..3600 (default %u)\n"
		"  -h, --help\n",
		program, DEFAULT_INTERVAL_US, DEFAULT_SECONDS);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "bdf", required_argument, NULL, 1000 },
		{ "channel", required_argument, NULL, 'c' },
		{ "output", required_argument, NULL, 'o' },
		{ "interval-us", required_argument, NULL, 'i' },
		{ "seconds", required_argument, NULL, 's' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int option;
	bool channel_set = false;

	*options = (struct options) {
		.interval_us = DEFAULT_INTERVAL_US,
		.seconds = DEFAULT_SECONDS,
	};
	while ((option = getopt_long(argc, argv, "c:o:i:s:h", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 1000: options->bdf = optarg; break;
		case 'c':
			if (parse_u32(optarg, 0, 3, &options->channel))
				return -1;
			channel_set = true;
			break;
		case 'o': options->output = optarg; break;
		case 'i':
			if (parse_u32(optarg, 50, 5000, &options->interval_us))
				return -1;
			break;
		case 's':
			if (parse_u32(optarg, 1, 3600, &options->seconds))
				return -1;
			break;
		case 'h': usage(stdout, argv[0]); exit(0);
		default: return -1;
		}
	}
	return optind == argc && options->bdf && options->output && channel_set ?
		0 : -1;
}

static bool valid_bdf(const char *bdf)
{
	unsigned int domain;
	unsigned int bus;
	unsigned int slot;
	unsigned int function;
	char trailing;

	return bdf && sscanf(bdf, "%x:%x:%x.%x%c", &domain, &bus, &slot,
			     &function, &trailing) == 4 && domain <= 0xffff &&
	       bus <= 0xff && slot <= 0x1f && function <= 7;
}

int main(int argc, char **argv)
{
	struct options options;
	char resource_path[160];
	struct stat resource_stat;
	volatile uint32_t *bar;
	FILE *output = NULL;
	uint64_t interval_ns;
	uint64_t started_ns;
	uint64_t deadline_ns;
	uint64_t target_ns;
	uint64_t previous_ns;
	uint64_t max_gap_ns = 0;
	uint64_t samples = 0;
	uint64_t transitions = 0;
	uint64_t status_changes = 0;
	uint64_t gaps = 0;
	uint32_t previous_toggle;
	uint32_t previous_status;
	int fd = -1;
	int result = 2;

	if (parse_options(argc, argv, &options)) {
		usage(stderr, argv[0]);
		return 2;
	}
	if (!valid_bdf(options.bdf)) {
		fprintf(stderr, "invalid PCI BDF: %s\n", options.bdf);
		return 2;
	}
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	if (snprintf(resource_path, sizeof(resource_path),
		     "/sys/bus/pci/devices/%s/resource0", options.bdf) >=
	    (int)sizeof(resource_path)) {
		fprintf(stderr, "PCI BDF is too long\n");
		return 2;
	}
	fd = open(resource_path, O_RDONLY | O_SYNC);
	if (fd < 0 || fstat(fd, &resource_stat)) {
		perror(resource_path);
		goto out;
	}
	if ((uint64_t)resource_stat.st_size <= HWS_REG_VBUF_TOGGLE(options.channel)) {
		fprintf(stderr, "BAR0 is too small for requested registers\n");
		goto out;
	}
	bar = mmap(NULL, (size_t)resource_stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (bar == MAP_FAILED) {
		bar = NULL;
		perror("mmap BAR0");
		goto out;
	}
	output = fopen(options.output, "wx");
	if (!output) {
		perror(options.output);
		munmap((void *)bar, (size_t)resource_stat.st_size);
		goto out;
	}

	interval_ns = (uint64_t)options.interval_us * 1000;
	started_ns = monotonic_ns();
	deadline_ns = started_ns + (uint64_t)options.seconds * UINT64_C(1000000000);
	target_ns = started_ns;
	previous_ns = started_ns;
	previous_status = bar[HWS_REG_INT_STATUS / 4];
	previous_toggle = bar[HWS_REG_VBUF_TOGGLE(options.channel) / 4] & 1;
	fprintf(output,
		"{\"type\":\"config\",\"bdf\":\"%s\",\"channel\":%u,\"interval_us\":%u,\"seconds\":%u,\"started_ns\":%" PRIu64 ",\"initial_toggle\":%u,\"initial_status\":%u}\n",
		options.bdf, options.channel, options.interval_us, options.seconds,
		started_ns, previous_toggle, previous_status);

	while (!stop_requested) {
		struct timespec target;
		uint64_t now_ns;
		uint64_t gap_ns;
		uint32_t status;
		uint32_t toggle;

		target_ns += interval_ns;
		target = ns_timespec(target_ns);
		while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &target, NULL) == EINTR &&
		       !stop_requested)
			;
		now_ns = monotonic_ns();
		if (!now_ns || now_ns >= deadline_ns)
			break;
		status = bar[HWS_REG_INT_STATUS / 4];
		toggle = bar[HWS_REG_VBUF_TOGGLE(options.channel) / 4] & 1;
		gap_ns = now_ns - previous_ns;
		samples++;
		if (gap_ns > max_gap_ns)
			max_gap_ns = gap_ns;
		if (gap_ns > interval_ns * 2) {
			gaps++;
			fprintf(output,
				"{\"type\":\"gap\",\"timestamp_ns\":%" PRIu64 ",\"gap_ns\":%" PRIu64 "}\n",
				now_ns, gap_ns);
		}
		if (toggle != previous_toggle || status != previous_status) {
			if (toggle != previous_toggle)
				transitions++;
			if (status != previous_status)
				status_changes++;
			fprintf(output,
				"{\"type\":\"transition\",\"timestamp_ns\":%" PRIu64 ",\"previous_toggle\":%u,\"toggle\":%u,\"previous_status\":%u,\"status\":%u}\n",
				now_ns, previous_toggle, toggle, previous_status, status);
			previous_toggle = toggle;
			previous_status = status;
		}
		previous_ns = now_ns;
	}

	result = stop_requested ? 1 : 0;
	fprintf(output,
		"{\"type\":\"summary\",\"result\":\"%s\",\"samples\":%" PRIu64 ",\"toggle_transitions\":%" PRIu64 ",\"status_changes\":%" PRIu64 ",\"sampling_gaps\":%" PRIu64 ",\"max_gap_ns\":%" PRIu64 "}\n",
		result ? "interrupted" : "pass", samples, transitions,
		status_changes, gaps, max_gap_ns);
	fprintf(stderr,
		"sampler result=%s samples=%" PRIu64 " transitions=%" PRIu64 " gaps=%" PRIu64 " evidence=%s\n",
		result ? "INTERRUPTED" : "PASS", samples, transitions, gaps,
		options.output);
	munmap((void *)bar, (size_t)resource_stat.st_size);

out:
	if (output)
		fclose(output);
	if (fd >= 0)
		close(fd);
	return result;
}
