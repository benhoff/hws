// SPDX-License-Identifier: GPL-2.0-only
/*
 * HwsCapture video EOF timestamp and hardware-frame sequence test.
 *
 * Build:
 *   cc -std=c11 -O2 -g -Wall -Wextra -Wpedantic \
 *      -o hws_video_metadata_test hws_video_metadata_test.c
 *
 * The test captures through MMAP, validates monotonic EOF metadata and normal
 * frame cadence, then holds every dequeued buffer so the VB2 queue is empty.
 * After a bounded starvation interval it queues one buffer and requires the
 * next completed buffer to expose the intervening hardware frames as a
 * sequence gap.  It also correlates that gap with the EOF timestamp delta.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/videodev2.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_DEVICE "/dev/video3"
#define DEFAULT_BUFFER_COUNT 3U
#define DEFAULT_WARMUP_FRAMES 12U
#define DEFAULT_STARVE_MS 250U
#define DEFAULT_TIMEOUT_MS 3000U
#define DEFAULT_CADENCE_TOLERANCE_PCT 35U
#define DEFAULT_MAX_EOF_AGE_PCT 45U

enum test_exit_code {
	TEST_PASS = 0,
	TEST_VALIDATION_FAILURE = 1,
	TEST_RUNTIME_ERROR = 2,
};

struct options {
	const char *device;
	unsigned int buffer_count;
	unsigned int warmup_frames;
	unsigned int starve_ms;
	unsigned int timeout_ms;
	unsigned int cadence_tolerance_pct;
	unsigned int max_eof_age_pct;
	bool keep_timings;
};

struct mapped_buffer {
	void *addr;
	size_t length;
};

struct video_context {
	int fd;
	bool streaming;
	bool buffers_requested;
	struct mapped_buffer *buffers;
	unsigned int buffer_count;
	uint32_t sizeimage;
	uint64_t frame_period_ns;
};

struct sample_state {
	bool have_previous;
	uint32_t previous_sequence;
	uint64_t previous_timestamp_ns;
	uint64_t minimum_age_ns;
};

static volatile sig_atomic_t stop_requested;

static void handle_signal(int signo)
{
	(void)signo;
	stop_requested = 1;
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
		"Usage: %s [options]\n\n"
		"Validate HwsCapture EOF timestamps and hardware-frame sequences.\n\n"
		"Options:\n"
		"  -d, --device DEV        V4L2 capture node (default: %s)\n"
		"  -b, --buffers N         MMAP buffers, 2..32 (default: %u)\n"
		"  -w, --warmup N          Normal frames before starvation (default: %u)\n"
		"  -s, --starve-ms N       Queue-empty interval (default: %u ms)\n"
		"  -t, --timeout-ms N      Per-buffer timeout (default: %u ms)\n"
		"      --cadence-tolerance-pct N\n"
		"                         Allowed timestamp cadence error, 1..90\n"
		"                         (default: %u%%)\n"
		"      --max-eof-age-pct N\n"
		"                         At least one normal DQBUF must be younger\n"
		"                         than this percentage of one frame, 1..90\n"
		"                         (default: %u%%)\n"
		"      --keep-timings      Do not QUERY/S_DV_TIMINGS before capture\n"
		"  -h, --help              Show this help\n\n"
		"The input must have a stable live progressive signal. The test does\n"
		"not reload the driver or write PCI registers.\n",
		program, DEFAULT_DEVICE, DEFAULT_BUFFER_COUNT,
		DEFAULT_WARMUP_FRAMES, DEFAULT_STARVE_MS, DEFAULT_TIMEOUT_MS,
		DEFAULT_CADENCE_TOLERANCE_PCT, DEFAULT_MAX_EOF_AGE_PCT);
}

static int parse_uint(const char *text, unsigned int minimum,
		      unsigned int maximum, unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !end || *end != '\0' || parsed < minimum ||
	    parsed > maximum)
		return -1;
	*value = (unsigned int)parsed;
	return 0;
}

static int parse_options(int argc, char **argv, struct options *options)
{
	enum {
		OPT_CADENCE_TOLERANCE = 1000,
		OPT_MAX_EOF_AGE,
		OPT_KEEP_TIMINGS,
	};
	static const struct option long_options[] = {
		{ "device", required_argument, NULL, 'd' },
		{ "buffers", required_argument, NULL, 'b' },
		{ "warmup", required_argument, NULL, 'w' },
		{ "starve-ms", required_argument, NULL, 's' },
		{ "timeout-ms", required_argument, NULL, 't' },
		{ "cadence-tolerance-pct", required_argument, NULL,
		  OPT_CADENCE_TOLERANCE },
		{ "max-eof-age-pct", required_argument, NULL,
		  OPT_MAX_EOF_AGE },
		{ "keep-timings", no_argument, NULL, OPT_KEEP_TIMINGS },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int option;

	*options = (struct options) {
		.device = DEFAULT_DEVICE,
		.buffer_count = DEFAULT_BUFFER_COUNT,
		.warmup_frames = DEFAULT_WARMUP_FRAMES,
		.starve_ms = DEFAULT_STARVE_MS,
		.timeout_ms = DEFAULT_TIMEOUT_MS,
		.cadence_tolerance_pct = DEFAULT_CADENCE_TOLERANCE_PCT,
		.max_eof_age_pct = DEFAULT_MAX_EOF_AGE_PCT,
	};

	while ((option = getopt_long(argc, argv, "d:b:w:s:t:h", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 'd':
			options->device = optarg;
			break;
		case 'b':
			if (parse_uint(optarg, 2, 32, &options->buffer_count))
				return -1;
			break;
		case 'w':
			if (parse_uint(optarg, 2, 10000,
				       &options->warmup_frames))
				return -1;
			break;
		case 's':
			if (parse_uint(optarg, 1, 60000, &options->starve_ms))
				return -1;
			break;
		case 't':
			if (parse_uint(optarg, 1, 60000, &options->timeout_ms))
				return -1;
			break;
		case OPT_CADENCE_TOLERANCE:
			if (parse_uint(optarg, 1, 90,
				       &options->cadence_tolerance_pct))
				return -1;
			break;
		case OPT_MAX_EOF_AGE:
			if (parse_uint(optarg, 1, 90,
				       &options->max_eof_age_pct))
				return -1;
			break;
		case OPT_KEEP_TIMINGS:
			options->keep_timings = true;
			break;
		case 'h':
			usage(stdout, argv[0]);
			exit(TEST_PASS);
		default:
			return -1;
		}
	}
	return optind == argc ? 0 : -1;
}

static int ioctl_retry(int fd, unsigned long request, void *argument)
{
	int ret;

	do {
		ret = ioctl(fd, request, argument);
	} while (ret < 0 && errno == EINTR && !stop_requested);
	return ret;
}

static int monotonic_ns(uint64_t *value)
{
	struct timespec timestamp;

	if (clock_gettime(CLOCK_MONOTONIC, &timestamp))
		return -1;
	*value = (uint64_t)timestamp.tv_sec * UINT64_C(1000000000) +
		 (uint64_t)timestamp.tv_nsec;
	return 0;
}

static int sleep_ms(unsigned int milliseconds, uint64_t *elapsed_ns)
{
	struct timespec request = {
		.tv_sec = milliseconds / 1000U,
		.tv_nsec = (long)(milliseconds % 1000U) * 1000000L,
	};
	uint64_t start_ns;
	uint64_t end_ns;

	if (monotonic_ns(&start_ns))
		return -1;
	while (nanosleep(&request, &request)) {
		if (errno != EINTR || stop_requested)
			return -1;
	}
	if (monotonic_ns(&end_ns))
		return -1;
	*elapsed_ns = end_ns - start_ns;
	return 0;
}

static uint64_t timeval_ns(const struct timeval *timestamp)
{
	if (timestamp->tv_sec < 0 || timestamp->tv_usec < 0 ||
	    timestamp->tv_usec >= 1000000)
		return 0;
	return (uint64_t)timestamp->tv_sec * UINT64_C(1000000000) +
	       (uint64_t)timestamp->tv_usec * UINT64_C(1000);
}

static uint64_t absolute_difference(uint64_t left, uint64_t right)
{
	return left > right ? left - right : right - left;
}

static int apply_detected_timings(int fd)
{
	struct v4l2_dv_timings timings = { 0 };

	if (ioctl_retry(fd, VIDIOC_QUERY_DV_TIMINGS, &timings)) {
		fprintf(stderr, "VIDIOC_QUERY_DV_TIMINGS: %s\n", strerror(errno));
		return -1;
	}
	if (ioctl_retry(fd, VIDIOC_S_DV_TIMINGS, &timings)) {
		fprintf(stderr, "VIDIOC_S_DV_TIMINGS: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static void release_video(struct video_context *video)
{
	unsigned int index;

	if (video->fd < 0)
		return;
	if (video->streaming) {
		enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

		if (ioctl_retry(video->fd, VIDIOC_STREAMOFF, &type))
			fprintf(stderr, "cleanup VIDIOC_STREAMOFF: %s\n",
				strerror(errno));
		video->streaming = false;
	}
	for (index = 0; index < video->buffer_count; ++index) {
		if (video->buffers[index].addr &&
		    video->buffers[index].addr != MAP_FAILED)
			munmap(video->buffers[index].addr,
			       video->buffers[index].length);
	}
	free(video->buffers);
	video->buffers = NULL;
	video->buffer_count = 0;
	if (video->buffers_requested) {
		struct v4l2_requestbuffers request = {
			.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
			.memory = V4L2_MEMORY_MMAP,
		};

		if (ioctl_retry(video->fd, VIDIOC_REQBUFS, &request))
			fprintf(stderr, "cleanup VIDIOC_REQBUFS(0): %s\n",
				strerror(errno));
		video->buffers_requested = false;
	}
	close(video->fd);
	video->fd = -1;
}

static int prepare_video(struct video_context *video,
			 const struct options *options)
{
	struct v4l2_capability capability = { 0 };
	struct v4l2_format format = {
		.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
	};
	struct v4l2_streamparm parameter = {
		.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
	};
	struct v4l2_requestbuffers request = {
		.count = options->buffer_count,
		.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
		.memory = V4L2_MEMORY_MMAP,
	};
	uint32_t capabilities;
	unsigned int index;

	*video = (struct video_context) { .fd = -1 };
	video->fd = open(options->device, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (video->fd < 0) {
		fprintf(stderr, "open %s: %s\n", options->device, strerror(errno));
		return -1;
	}
	if (ioctl_retry(video->fd, VIDIOC_QUERYCAP, &capability)) {
		fprintf(stderr, "VIDIOC_QUERYCAP: %s\n", strerror(errno));
		goto fail;
	}
	capabilities = capability.capabilities;
	if (capabilities & V4L2_CAP_DEVICE_CAPS)
		capabilities = capability.device_caps;
	if (!(capabilities & V4L2_CAP_VIDEO_CAPTURE) ||
	    !(capabilities & V4L2_CAP_STREAMING)) {
		fprintf(stderr, "%s is not a streaming single-plane capture node\n",
			options->device);
		goto fail;
	}
	if (!options->keep_timings && apply_detected_timings(video->fd))
		goto fail;
	if (ioctl_retry(video->fd, VIDIOC_G_FMT, &format)) {
		fprintf(stderr, "VIDIOC_G_FMT: %s\n", strerror(errno));
		goto fail;
	}
	if (!format.fmt.pix.sizeimage) {
		fprintf(stderr, "invalid capture sizeimage=0\n");
		goto fail;
	}
	video->sizeimage = format.fmt.pix.sizeimage;
	if (ioctl_retry(video->fd, VIDIOC_G_PARM, &parameter)) {
		fprintf(stderr, "VIDIOC_G_PARM: %s\n", strerror(errno));
		goto fail;
	}
	if (!parameter.parm.capture.timeperframe.numerator ||
	    !parameter.parm.capture.timeperframe.denominator) {
		fprintf(stderr, "driver returned an invalid frame period\n");
		goto fail;
	}
	video->frame_period_ns =
		(uint64_t)parameter.parm.capture.timeperframe.numerator *
		UINT64_C(1000000000) /
		parameter.parm.capture.timeperframe.denominator;
	if (!video->frame_period_ns) {
		fprintf(stderr, "calculated frame period is zero\n");
		goto fail;
	}
	if (ioctl_retry(video->fd, VIDIOC_REQBUFS, &request)) {
		fprintf(stderr, "VIDIOC_REQBUFS: %s\n", strerror(errno));
		goto fail;
	}
	video->buffers_requested = true;
	if (request.count < 2) {
		fprintf(stderr, "driver allocated only %u MMAP buffer(s)\n",
			request.count);
		goto fail;
	}
	video->buffers = calloc(request.count, sizeof(*video->buffers));
	if (!video->buffers) {
		fprintf(stderr, "calloc buffers: %s\n", strerror(errno));
		goto fail;
	}
	video->buffer_count = request.count;
	for (index = 0; index < video->buffer_count; ++index) {
		struct v4l2_buffer buffer = {
			.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
			.memory = V4L2_MEMORY_MMAP,
			.index = index,
		};

		if (ioctl_retry(video->fd, VIDIOC_QUERYBUF, &buffer)) {
			fprintf(stderr, "VIDIOC_QUERYBUF(%u): %s\n", index,
				strerror(errno));
			goto fail;
		}
		video->buffers[index].length = buffer.length;
		video->buffers[index].addr = mmap(NULL, buffer.length,
						  PROT_READ | PROT_WRITE,
						  MAP_SHARED, video->fd,
						  buffer.m.offset);
		if (video->buffers[index].addr == MAP_FAILED) {
			fprintf(stderr, "mmap buffer %u: %s\n", index,
				strerror(errno));
			goto fail;
		}
	}
	printf("device=%s driver=%s card=\"%s\" format=%ux%u sizeimage=%u "
	       "buffers=%u frame_period_us=%.3f\n",
	       options->device, capability.driver, capability.card,
	       format.fmt.pix.width, format.fmt.pix.height,
	       format.fmt.pix.sizeimage, video->buffer_count,
	       (double)video->frame_period_ns / 1000.0);
	return 0;

fail:
	release_video(video);
	return -1;
}

static int queue_buffer(const struct video_context *video, unsigned int index)
{
	struct v4l2_buffer buffer = {
		.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
		.memory = V4L2_MEMORY_MMAP,
		.index = index,
	};

	if (ioctl_retry(video->fd, VIDIOC_QBUF, &buffer)) {
		fprintf(stderr, "VIDIOC_QBUF(%u): %s\n", index, strerror(errno));
		return -1;
	}
	return 0;
}

static int start_streaming(struct video_context *video)
{
	enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	unsigned int index;

	for (index = 0; index < video->buffer_count; ++index) {
		if (queue_buffer(video, index))
			return -1;
	}
	if (ioctl_retry(video->fd, VIDIOC_STREAMON, &type)) {
		fprintf(stderr, "VIDIOC_STREAMON: %s\n", strerror(errno));
		return -1;
	}
	video->streaming = true;
	return 0;
}

static int dequeue_buffer(const struct video_context *video,
			  unsigned int timeout_ms, struct v4l2_buffer *buffer,
			  uint64_t *dequeue_ns)
{
	uint64_t start_ns;
	uint64_t deadline_ns;

	if (monotonic_ns(&start_ns))
		return -1;
	deadline_ns = start_ns + (uint64_t)timeout_ms * UINT64_C(1000000);
	for (;;) {
		struct pollfd descriptor = {
			.fd = video->fd,
			.events = POLLIN | POLLPRI,
		};
		uint64_t now_ns;
		uint64_t remaining_ns;
		int poll_timeout;
		int ret;

		if (stop_requested) {
			errno = EINTR;
			return -1;
		}
		if (monotonic_ns(&now_ns))
			return -1;
		if (now_ns >= deadline_ns) {
			errno = ETIMEDOUT;
			return -1;
		}
		remaining_ns = deadline_ns - now_ns;
		poll_timeout = (int)((remaining_ns + UINT64_C(999999)) /
					 UINT64_C(1000000));
		ret = poll(&descriptor, 1, poll_timeout);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!ret)
			continue;
		if (descriptor.revents & POLLNVAL) {
			errno = ENODEV;
			return -1;
		}
		*buffer = (struct v4l2_buffer) {
			.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
			.memory = V4L2_MEMORY_MMAP,
		};
		if (!ioctl_retry(video->fd, VIDIOC_DQBUF, buffer)) {
			if (monotonic_ns(dequeue_ns))
				return -1;
			return 0;
		}
		if (errno != EAGAIN)
			return -1;
	}
}

static int validate_sample(const struct video_context *video,
			   const struct options *options,
			   struct sample_state *state,
			   const struct v4l2_buffer *buffer,
			   uint64_t dequeue_ns, const char *phase,
			   bool require_consecutive)
{
	uint64_t timestamp_ns = timeval_ns(&buffer->timestamp);
	uint64_t age_ns;
	uint64_t cadence_ns = 0;
	uint64_t tolerance_ns = video->frame_period_ns *
		options->cadence_tolerance_pct / 100U;
	uint32_t sequence_delta = 0;

	if (buffer->index >= video->buffer_count) {
		fprintf(stderr, "%s: invalid buffer index %u\n", phase,
			buffer->index);
		return -1;
	}
	if ((buffer->flags & V4L2_BUF_FLAG_TIMESTAMP_MASK) !=
	    V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC) {
		fprintf(stderr, "%s: sequence %u lacks a monotonic timestamp "
			"(flags=0x%08x)\n", phase, buffer->sequence,
			buffer->flags);
		return -1;
	}
	if ((buffer->flags & V4L2_BUF_FLAG_TSTAMP_SRC_MASK) !=
	    V4L2_BUF_FLAG_TSTAMP_SRC_EOF) {
		fprintf(stderr, "%s: sequence %u is not marked EOF "
			"(flags=0x%08x)\n", phase, buffer->sequence,
			buffer->flags);
		return -1;
	}
	if (buffer->flags & V4L2_BUF_FLAG_ERROR) {
		fprintf(stderr, "%s: sequence %u has V4L2_BUF_FLAG_ERROR\n",
			phase, buffer->sequence);
		return -1;
	}
	if (!timestamp_ns || timestamp_ns > dequeue_ns) {
		fprintf(stderr, "%s: sequence %u has invalid timestamp "
			"%ld.%06ld\n", phase, buffer->sequence,
			(long)buffer->timestamp.tv_sec,
			(long)buffer->timestamp.tv_usec);
		return -1;
	}
	age_ns = dequeue_ns - timestamp_ns;
	if (age_ns < state->minimum_age_ns)
		state->minimum_age_ns = age_ns;
	if (state->have_previous) {
		sequence_delta = buffer->sequence - state->previous_sequence;
		if (!sequence_delta) {
			fprintf(stderr, "%s: duplicate sequence %u\n", phase,
				buffer->sequence);
			return -1;
		}
		if (timestamp_ns <= state->previous_timestamp_ns) {
			fprintf(stderr, "%s: non-monotonic timestamp at sequence %u\n",
				phase, buffer->sequence);
			return -1;
		}
		cadence_ns = timestamp_ns - state->previous_timestamp_ns;
		if (require_consecutive && sequence_delta != 1) {
			fprintf(stderr, "%s: unexpected normal-capture sequence gap "
				"%u -> %u\n", phase, state->previous_sequence,
				buffer->sequence);
			return -1;
		}
		if (require_consecutive &&
		    absolute_difference(cadence_ns, video->frame_period_ns) >
		    tolerance_ns) {
			fprintf(stderr, "%s: sequence %u timestamp cadence %.3f ms "
				"does not match %.3f ms\n", phase, buffer->sequence,
				(double)cadence_ns / 1000000.0,
				(double)video->frame_period_ns / 1000000.0);
			return -1;
		}
	}
	printf("sample phase=%s index=%u sequence=%u timestamp=%ld.%06ld "
	       "age_us=%.3f",
	       phase, buffer->index, buffer->sequence,
	       (long)buffer->timestamp.tv_sec, (long)buffer->timestamp.tv_usec,
	       (double)age_ns / 1000.0);
	if (state->have_previous)
		printf(" sequence_delta=%u timestamp_delta_us=%.3f",
		       sequence_delta, (double)cadence_ns / 1000.0);
	putchar('\n');
	state->have_previous = true;
	state->previous_sequence = buffer->sequence;
	state->previous_timestamp_ns = timestamp_ns;
	return 0;
}

static int run_test(struct video_context *video, const struct options *options)
{
	struct sample_state state = {
		.minimum_age_ns = UINT64_MAX,
	};
	unsigned int *held_indices = NULL;
	struct v4l2_buffer buffer;
	uint64_t dequeue_ns;
	uint64_t starvation_ns;
	uint64_t last_timestamp_ns;
	uint64_t resumed_timestamp_ns;
	uint64_t expected_timestamp_delta_ns;
	uint64_t actual_timestamp_delta_ns;
	uint64_t gap_tolerance_ns;
	uint64_t eof_age_limit_ns;
	uint64_t expected_dropped_min;
	uint32_t last_sequence;
	uint32_t sequence_delta;
	uint32_t skipped_frames;
	unsigned int index;
	int ret = TEST_RUNTIME_ERROR;

	held_indices = calloc(video->buffer_count, sizeof(*held_indices));
	if (!held_indices) {
		fprintf(stderr, "calloc held indices: %s\n", strerror(errno));
		return TEST_RUNTIME_ERROR;
	}
	if (start_streaming(video))
		goto out;
	for (index = 0; index < options->warmup_frames; ++index) {
		if (dequeue_buffer(video, options->timeout_ms, &buffer,
				   &dequeue_ns)) {
			fprintf(stderr, "warmup DQBUF %u: %s\n", index,
				strerror(errno));
			goto out;
		}
		if (validate_sample(video, options, &state, &buffer, dequeue_ns,
				    "warmup", true)) {
			ret = TEST_VALIDATION_FAILURE;
			goto out;
		}
		if (queue_buffer(video, buffer.index))
			goto out;
	}
	eof_age_limit_ns = video->frame_period_ns * options->max_eof_age_pct /
			   100U;
	if (state.minimum_age_ns >= eof_age_limit_ns) {
		fprintf(stderr,
			"no promptly dequeued EOF timestamp was younger than %.3f ms; "
			"minimum age was %.3f ms\n",
			(double)eof_age_limit_ns / 1000000.0,
			(double)state.minimum_age_ns / 1000000.0);
		ret = TEST_VALIDATION_FAILURE;
		goto out;
	}
	printf("PASS: monotonic EOF flags, cadence, and completion age validated "
	       "across %u normal frame(s)\n", options->warmup_frames);

	/* Drain every MMAP buffer and deliberately leave the queue empty. */
	for (index = 0; index < video->buffer_count; ++index) {
		if (dequeue_buffer(video, options->timeout_ms, &buffer,
				   &dequeue_ns)) {
			fprintf(stderr, "drain DQBUF %u: %s\n", index,
				strerror(errno));
			goto out;
		}
		if (validate_sample(video, options, &state, &buffer, dequeue_ns,
				    "drain", true)) {
			ret = TEST_VALIDATION_FAILURE;
			goto out;
		}
		held_indices[index] = buffer.index;
	}
	last_sequence = state.previous_sequence;
	last_timestamp_ns = state.previous_timestamp_ns;
	printf("queue_starved=1 held_buffers=%u last_sequence=%u\n",
	       video->buffer_count, last_sequence);
	if (sleep_ms(options->starve_ms, &starvation_ns)) {
		fprintf(stderr, "starvation sleep interrupted: %s\n",
			strerror(errno));
		goto out;
	}
	if (queue_buffer(video, held_indices[0]))
		goto out;
	if (dequeue_buffer(video, options->timeout_ms, &buffer, &dequeue_ns)) {
		fprintf(stderr, "post-starvation DQBUF: %s\n", strerror(errno));
		goto out;
	}
	if (validate_sample(video, options, &state, &buffer, dequeue_ns,
			    "resume", false)) {
		ret = TEST_VALIDATION_FAILURE;
		goto out;
	}
	resumed_timestamp_ns = timeval_ns(&buffer.timestamp);
	sequence_delta = buffer.sequence - last_sequence;
	if (sequence_delta <= 1) {
		fprintf(stderr,
			"post-starvation sequence did not expose a gap: %u -> %u\n",
			last_sequence, buffer.sequence);
		ret = TEST_VALIDATION_FAILURE;
		goto out;
	}
	skipped_frames = sequence_delta - 1;
	expected_dropped_min = starvation_ns / video->frame_period_ns;
	if (expected_dropped_min > 2)
		expected_dropped_min -= 2;
	else
		expected_dropped_min = 1;
	if (skipped_frames < expected_dropped_min) {
		fprintf(stderr,
			"sequence gap reports only %u skipped frame(s), expected at "
			"least %" PRIu64 " during %.3f ms starvation\n",
			skipped_frames, expected_dropped_min,
			(double)starvation_ns / 1000000.0);
		ret = TEST_VALIDATION_FAILURE;
		goto out;
	}
	actual_timestamp_delta_ns = resumed_timestamp_ns - last_timestamp_ns;
	expected_timestamp_delta_ns =
		(uint64_t)sequence_delta * video->frame_period_ns;
	gap_tolerance_ns = video->frame_period_ns *
		options->cadence_tolerance_pct / 100U;
	if (absolute_difference(actual_timestamp_delta_ns,
				 expected_timestamp_delta_ns) > gap_tolerance_ns) {
		fprintf(stderr,
			"sequence gap %u predicts %.3f ms but EOF timestamps span "
			"%.3f ms\n", sequence_delta,
			(double)expected_timestamp_delta_ns / 1000000.0,
			(double)actual_timestamp_delta_ns / 1000000.0);
		ret = TEST_VALIDATION_FAILURE;
		goto out;
	}
	printf("PASS: %.3f ms with no queued VB2 buffer skipped %u hardware "
	       "frame(s); sequence %u -> %u and EOF delta %.3f ms agree\n",
	       (double)starvation_ns / 1000000.0, skipped_frames,
	       last_sequence, buffer.sequence,
	       (double)actual_timestamp_delta_ns / 1000000.0);
	ret = TEST_PASS;

out:
	free(held_indices);
	return ret;
}

int main(int argc, char **argv)
{
	struct options options;
	struct video_context video = { .fd = -1 };
	struct sigaction action = {
		.sa_handler = handle_signal,
	};
	int result;

	if (parse_options(argc, argv, &options)) {
		usage(stderr, argv[0]);
		return TEST_RUNTIME_ERROR;
	}
	sigemptyset(&action.sa_mask);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (prepare_video(&video, &options)) {
		fprintf(stderr, "RESULT: ERROR\n");
		return TEST_RUNTIME_ERROR;
	}
	printf("warmup_frames=%u starve_ms=%u cadence_tolerance=%u%% "
	       "max_eof_age=%u%%\n",
	       options.warmup_frames, options.starve_ms,
	       options.cadence_tolerance_pct, options.max_eof_age_pct);
	result = run_test(&video, &options);
	release_video(&video);
	if (result == TEST_PASS)
		printf("RESULT: PASS\n");
	else if (result == TEST_VALIDATION_FAILURE)
		fprintf(stderr, "RESULT: FAIL\n");
	else
		fprintf(stderr, "RESULT: ERROR\n");
	return result;
}
