// SPDX-License-Identifier: GPL-2.0-only
/*
 * Capture and validate the two-region frame IDs rendered by
 * hws_frame_id_source.html. Detailed results go to JSONL; stderr receives
 * only periodic progress and the terminal verdict.
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
#include "hws_frame_pattern.h"
#ifndef HWS_CAPTURE_SHA256
#define HWS_CAPTURE_SHA256 "unrecorded"
#endif

#define DEFAULT_DEVICE "/dev/video1"
#define DEFAULT_OUTPUT "captured-frames.jsonl"
#define DEFAULT_FRAMES 3600U
#define DEFAULT_BUFFERS 4U
#define DEFAULT_TIMEOUT_MS 3000
#define BARCODE_BITS 64U
#define BARCODE_X_PERCENT 5U
#define BARCODE_WIDTH_PERCENT 90U
#define UPPER_Y_PERCENT 20U
#define LOWER_Y_PERCENT 80U
#define MIN_BARCODE_CONTRAST 80U
#define POISON_BLOCKS_PER_HALF 32U
#define MAX_ANOMALY_DUMPS 16U

struct options {
	const char *device;
	const char *output;
	const char *anomaly_dir;
	uint32_t frames;
	uint32_t buffers;
	uint32_t split;
	int timeout_ms;
	bool keep_timings;
	bool self_test;
};

struct mapped_buffer {
	void *addr;
	size_t length;
	uint64_t queue_count;
	uint64_t poison_half0_hash;
	uint64_t poison_half1_hash;
	uint64_t poison_half0_blocks[POISON_BLOCKS_PER_HALF];
	uint64_t poison_half1_blocks[POISON_BLOCKS_PER_HALF];
};

struct barcode_result {
	uint32_t id;
	uint8_t contrast;
	bool valid;
};

struct counters {
	uint64_t captured;
	uint64_t valid;
	uint64_t decode_errors;
	uint64_t id_mismatches;
	uint64_t backwards_ids;
	uint64_t repeated_ids;
	uint64_t sequence_errors;
	uint64_t payload_errors;
	uint64_t flagged_errors;
	uint64_t poison_errors;
	uint64_t anomaly_dumps;
	uint64_t anomaly_dumps_suppressed;
	uint64_t content_errors;
};

/* Every active YUYV byte is tested; no sparse hash is treated as proof of a
 * complete copy. Black accepts 0..24 and white 227..255 (full/limited range,
 * eight levels of tolerance). Neutral chroma accepts 120..136. No pixels,
 * edges, or rows are masked. Padding is rejected by capture preflight. */
static uint64_t content_bad_bytes(const uint8_t *frame, uint32_t width,
		uint32_t height, uint32_t stride, uint32_t id)
{
	uint64_t bad = 0, code = hws_pattern_code(id);
	uint32_t x, y;
	for (y = 0; y < height; y++) {
		for (x = 0; x < width; x++) {
			const uint8_t *p = frame + (size_t)y * stride + x * 2;
			bool white = hws_pattern_white(id, code, x, y, width, height);
			bad += white ? p[0] < 227 : p[0] > 24;
			bad += p[1] < 120 || p[1] > 136;
		}
	}
	return bad;
}

/* Count successful QBUFs, not DQBUFs, to stop replenishing early enough to
 * drain every completion even if the consumer falls behind the device. */
static bool queue_budget_available(uint64_t submitted, uint64_t target)
{
	return submitted < target;
}

static volatile sig_atomic_t stop_requested;

static void signal_handler(int signo)
{
	(void)signo;
	stop_requested = 1;
}

static int ioctl_retry(int fd, unsigned long request, void *argument)
{
	int ret;

	do {
		ret = ioctl(fd, request, argument);
	} while (ret < 0 && errno == EINTR && !stop_requested);
	return ret;
}

static uint64_t monotonic_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)now.tv_nsec;
}

static uint64_t timeval_ns(const struct timeval *timestamp)
{
	if (timestamp->tv_sec < 0 || timestamp->tv_usec < 0 ||
	    timestamp->tv_usec >= 1000000)
		return 0;
	return (uint64_t)timestamp->tv_sec * UINT64_C(1000000000) +
	       (uint64_t)timestamp->tv_usec * UINT64_C(1000);
}

static uint64_t hash64(const uint8_t *data, size_t length)
{
	uint64_t hash = UINT64_C(0x9e3779b97f4a7c15) ^ length;
	uint64_t word;

	while (length >= sizeof(word)) {
		memcpy(&word, data, sizeof(word));
		hash ^= word + UINT64_C(0x9e3779b97f4a7c15) +
			(hash << 6) + (hash >> 2);
		data += sizeof(word);
		length -= sizeof(word);
	}
	while (length--) {
		hash ^= *data++;
		hash *= UINT64_C(0x100000001b3);
	}
	return hash;
}

static uint64_t xorshift64(uint64_t *state)
{
	uint64_t x = *state;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	*state = x;
	return x;
}

static void hash_blocks(const uint8_t *data, size_t length,
			uint64_t hashes[POISON_BLOCKS_PER_HALF])
{
	unsigned int block;

	for (block = 0; block < POISON_BLOCKS_PER_HALF; block++) {
		size_t first = (size_t)block * length / POISON_BLOCKS_PER_HALF;
		size_t last = (size_t)(block + 1) * length /
			      POISON_BLOCKS_PER_HALF;

		hashes[block] = hash64(data + first, last - first);
	}
}

static unsigned int matching_blocks(const uint8_t *data, size_t length,
				    const uint64_t expected[POISON_BLOCKS_PER_HALF])
{
	unsigned int matches = 0;
	unsigned int block;

	for (block = 0; block < POISON_BLOCKS_PER_HALF; block++) {
		size_t first = (size_t)block * length / POISON_BLOCKS_PER_HALF;
		size_t last = (size_t)(block + 1) * length /
			      POISON_BLOCKS_PER_HALF;

		if (hash64(data + first, last - first) == expected[block])
			matches++;
	}
	return matches;
}

static void poison_buffer(struct mapped_buffer *buffer, uint32_t index,
			  uint32_t sizeimage, uint32_t split)
{
	uint8_t *bytes = buffer->addr;
	uint64_t state;
	uint64_t word;
	uint64_t seed;
	size_t offset;
	size_t chunk;

	buffer->queue_count++;
	seed = UINT64_C(0x9e3779b97f4a7c15) ^
	       ((uint64_t)(index + 1) << 32) ^ buffer->queue_count;
	state = seed;
	for (offset = 0; offset < sizeimage; offset += chunk) {
		word = xorshift64(&state);
		chunk = sizeimage - offset < sizeof(word) ?
			sizeimage - offset : sizeof(word);
		memcpy(bytes + offset, &word, chunk);
	}
	buffer->poison_half0_hash = hash64(bytes, split);
	buffer->poison_half1_hash = hash64(bytes + split,
					       sizeimage - split);
	hash_blocks(bytes, split, buffer->poison_half0_blocks);
	hash_blocks(bytes + split, sizeimage - split,
		    buffer->poison_half1_blocks);
}

static uint8_t crc8_id(uint32_t id)
{
	uint8_t bytes[4] = {
		(uint8_t)(id >> 24), (uint8_t)(id >> 16),
		(uint8_t)(id >> 8), (uint8_t)id,
	};
	uint8_t crc = 0;
	unsigned int i;
	unsigned int bit;

	for (i = 0; i < 4; i++) {
		crc ^= bytes[i];
		for (bit = 0; bit < 8; bit++)
			crc = (uint8_t)((crc & 0x80) ?
				((crc << 1) ^ 0x07) : (crc << 1));
	}
	return crc;
}

static bool bits_value(const bool bits[], unsigned int first,
		       unsigned int count, uint32_t *value)
{
	uint32_t result = 0;
	unsigned int i;

	if (count > 32)
		return false;
	for (i = 0; i < count; i++)
		result = (result << 1) | bits[first + i];
	*value = result;
	return true;
}

static struct barcode_result decode_barcode(const uint8_t *frame,
					     uint32_t width, uint32_t height,
					     uint32_t bytesperline,
					     unsigned int y_percent)
{
	struct barcode_result result = { 0 };
	unsigned int luminance[BARCODE_BITS];
	bool bits[BARCODE_BITS];
	uint32_t x0 = width * BARCODE_X_PERCENT / 100;
	uint32_t barcode_width = width * BARCODE_WIDTH_PERCENT / 100;
	uint32_t y = height * y_percent / 100;
	uint32_t preamble;
	uint32_t complement;
	uint32_t crc;
	unsigned int minimum = 255;
	unsigned int maximum = 0;
	unsigned int threshold;
	unsigned int cell;

	if (!frame || width < BARCODE_BITS || height < 16 ||
	    bytesperline < width * 2)
		return result;

	for (cell = 0; cell < BARCODE_BITS; cell++) {
		uint32_t x = x0 +
			(uint32_t)(((uint64_t)(2 * cell + 1) * barcode_width) /
				   (2 * BARCODE_BITS));
		unsigned int sum = 0;
		unsigned int samples = 0;
		int dx;
		int dy;

		for (dy = -2; dy <= 2; dy++) {
			for (dx = -2; dx <= 2; dx++) {
				uint32_t sx = (uint32_t)((int)x + dx);
				uint32_t sy = (uint32_t)((int)y + dy);

				if (sx >= width || sy >= height)
					continue;
				sum += frame[(size_t)sy * bytesperline +
					     (size_t)sx * 2];
				samples++;
			}
		}
		if (!samples)
			return result;
		luminance[cell] = sum / samples;
		if (luminance[cell] < minimum)
			minimum = luminance[cell];
		if (luminance[cell] > maximum)
			maximum = luminance[cell];
	}

	result.contrast = (uint8_t)(maximum - minimum);
	if (result.contrast < MIN_BARCODE_CONTRAST)
		return result;
	threshold = minimum + (maximum - minimum) / 2;
	for (cell = 0; cell < BARCODE_BITS; cell++)
		bits[cell] = luminance[cell] > threshold;

	if (!bits_value(bits, 0, 8, &preamble) || preamble != 0xa5 ||
	    !bits_value(bits, 8, 32, &result.id) ||
	    !bits_value(bits, 40, 16, &complement) ||
	    !bits_value(bits, 56, 8, &crc))
		return result;
	if ((uint16_t)complement != (uint16_t)~result.id ||
	    (uint8_t)crc != crc8_id(result.id))
		return result;
	result.valid = true;
	return result;
}

static bool encoded_bit(uint32_t id, unsigned int bit)
{
	uint32_t value;
	unsigned int offset;
	unsigned int width;

	if (bit < 8) {
		value = 0xa5;
		offset = bit;
		width = 8;
	} else if (bit < 40) {
		value = id;
		offset = bit - 8;
		width = 32;
	} else if (bit < 56) {
		value = (uint16_t)~id;
		offset = bit - 40;
		width = 16;
	} else {
		value = crc8_id(id);
		offset = bit - 56;
		width = 8;
	}
	return (value >> (width - 1 - offset)) & 1;
}

static void draw_synthetic_barcode(uint8_t *frame, uint32_t width,
				   uint32_t height, uint32_t bytesperline,
				   uint32_t id, unsigned int y_percent)
{
	uint32_t x0 = width * BARCODE_X_PERCENT / 100;
	uint32_t barcode_width = width * BARCODE_WIDTH_PERCENT / 100;
	uint32_t center_y = height * y_percent / 100;
	unsigned int cell;

	for (cell = 0; cell < BARCODE_BITS; cell++) {
		uint32_t left = x0 +
			(uint32_t)((uint64_t)cell * barcode_width / BARCODE_BITS);
		uint32_t right = x0 +
			(uint32_t)((uint64_t)(cell + 1) * barcode_width /
				   BARCODE_BITS);
		uint8_t y_value = encoded_bit(id, cell) ? 235 : 16;
		uint32_t y;

		for (y = center_y - 8; y <= center_y + 8; y++) {
			uint32_t x;

			for (x = left; x < right; x++)
				frame[(size_t)y * bytesperline + (size_t)x * 2] =
					y_value;
		}
	}
}

static int self_test_decoder(void)
{
	static const uint32_t identifiers[] = {
		1, 2, UINT32_C(0x12345678), UINT32_C(0xfffffffe),
	};
	const uint32_t width = 640;
	const uint32_t height = 480;
	const uint32_t bytesperline = width * 2;
	uint8_t *frame = malloc((size_t)bytesperline * height);
	unsigned int i;

	if (!frame)
		return 2;
	for (i = 0; i < sizeof(identifiers) / sizeof(identifiers[0]); i++) {
		struct barcode_result upper;
		struct barcode_result lower;

		memset(frame, 128, (size_t)bytesperline * height);
		draw_synthetic_barcode(frame, width, height, bytesperline,
				       identifiers[i], UPPER_Y_PERCENT);
		draw_synthetic_barcode(frame, width, height, bytesperline,
				       identifiers[i], LOWER_Y_PERCENT);
		upper = decode_barcode(frame, width, height, bytesperline,
				       UPPER_Y_PERCENT);
		lower = decode_barcode(frame, width, height, bytesperline,
				       LOWER_Y_PERCENT);
		if (!upper.valid || !lower.valid || upper.id != identifiers[i] ||
		    lower.id != identifiers[i]) {
			fprintf(stderr, "frame-ID decoder self-test failed at 0x%08x\n",
				identifiers[i]);
			free(frame);
			return 1;
		}
	}
	free(frame);
	fprintf(stderr, "frame-ID decoder self-test PASS\n");
	return 0;
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

static int dump_frame(const char *directory, const char *name,
		      const void *frame, size_t size)
{
	char path[4096];
	FILE *output;
	int written;
	bool failed;

	if (!directory)
		return 0;
	written = snprintf(path, sizeof(path), "%s/%s", directory, name);
	if (written < 0 || (size_t)written >= sizeof(path))
		return -1;
	output = fopen(path, "wx");
	if (!output)
		return -1;
	failed = fwrite(frame, 1, size, output) != size;
	if (fclose(output))
		failed = true;
	return failed ? -1 : 0;
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
		"Usage: %s [options]\n\n"
		"Capture and validate HWS two-region frame IDs.\n\n"
		"  -d, --device DEV       V4L2 node (default %s)\n"
		"  -o, --output FILE      JSONL evidence (default %s)\n"
		"      --anomaly-dir DIR  Save first frame and at most %u anomalous frames\n"
		"  -n, --frames N         Frames to capture (default %u)\n"
		"  -b, --buffers N        MMAP buffers, 2..32 (default %u)\n"
		"  -s, --split BYTES      Native split; default round_down(size/2, 2048)\n"
		"  -t, --timeout-ms N     Per-frame timeout (default %d)\n"
		"      --keep-timings     Do not QUERY/S_DV_TIMINGS before capture\n"
		"      --self-test        Validate the barcode codec without hardware\n"
		"  -h, --help\n",
		program, DEFAULT_DEVICE, DEFAULT_OUTPUT, MAX_ANOMALY_DUMPS,
		DEFAULT_FRAMES,
		DEFAULT_BUFFERS, DEFAULT_TIMEOUT_MS);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	enum { OPT_KEEP_TIMINGS = 1000, OPT_SELF_TEST, OPT_ANOMALY_DIR };
	static const struct option long_options[] = {
		{ "device", required_argument, NULL, 'd' },
		{ "output", required_argument, NULL, 'o' },
		{ "anomaly-dir", required_argument, NULL, OPT_ANOMALY_DIR },
		{ "frames", required_argument, NULL, 'n' },
		{ "buffers", required_argument, NULL, 'b' },
		{ "split", required_argument, NULL, 's' },
		{ "timeout-ms", required_argument, NULL, 't' },
		{ "keep-timings", no_argument, NULL, OPT_KEEP_TIMINGS },
		{ "self-test", no_argument, NULL, OPT_SELF_TEST },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int option;
	uint32_t parsed;

	*options = (struct options) {
		.device = DEFAULT_DEVICE,
		.output = DEFAULT_OUTPUT,
		.frames = DEFAULT_FRAMES,
		.buffers = DEFAULT_BUFFERS,
		.timeout_ms = DEFAULT_TIMEOUT_MS,
	};
	while ((option = getopt_long(argc, argv, "d:o:n:b:s:t:h",
				     long_options, NULL)) != -1) {
		switch (option) {
		case 'd': options->device = optarg; break;
		case 'o': options->output = optarg; break;
		case OPT_ANOMALY_DIR: options->anomaly_dir = optarg; break;
		case 'n':
			if (parse_u32(optarg, 1, UINT32_MAX, &options->frames))
				return -1;
			break;
		case 'b':
			if (parse_u32(optarg, 2, 32, &options->buffers))
				return -1;
			break;
		case 's':
			if (parse_u32(optarg, 2048, UINT32_MAX, &options->split))
				return -1;
			break;
		case 't':
			if (parse_u32(optarg, 1, 60000, &parsed))
				return -1;
			options->timeout_ms = (int)parsed;
			break;
		case OPT_KEEP_TIMINGS: options->keep_timings = true; break;
		case OPT_SELF_TEST: options->self_test = true; break;
		case 'h': usage(stdout, argv[0]); exit(0);
		default: return -1;
		}
	}
	return optind == argc ? 0 : -1;
}

static int queue_buffer(int fd, struct mapped_buffer *mapped, uint32_t index,
			uint32_t sizeimage, uint32_t split)
{
	struct v4l2_buffer buffer = {
		.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
		.memory = V4L2_MEMORY_MMAP,
		.index = index,
	};

	poison_buffer(&mapped[index], index, sizeimage, split);
	return ioctl_retry(fd, VIDIOC_QBUF, &buffer);
}

int main(int argc, char **argv)
{
	struct options options;
	struct v4l2_dv_timings timings = { 0 };
	struct v4l2_format format = { .type = V4L2_BUF_TYPE_VIDEO_CAPTURE };
	struct v4l2_requestbuffers request = {
		.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
		.memory = V4L2_MEMORY_MMAP,
	};
	struct mapped_buffer *mapped = NULL;
	struct counters counters = { 0 };
	enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	FILE *output = NULL;
	uint64_t previous_progress_ns;
	uint32_t previous_id = 0;
	uint32_t previous_sequence = 0;
	uint32_t split;
	uint32_t i;
	bool have_previous = false;
	uint64_t submitted = 0;
	bool streaming = false;
	bool capture_failed = false;
	int fd = -1;
	int result = 2;

	if (parse_options(argc, argv, &options)) {
		usage(stderr, argv[0]);
		return 2;
	}
	if (options.self_test)
		return self_test_decoder();
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	output = fopen(options.output, "wx");
	if (!output) {
		perror(options.output);
		goto out;
	}
	fd = open(options.device, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror(options.device);
		goto out;
	}
	if (!options.keep_timings) {
		if (ioctl_retry(fd, VIDIOC_QUERY_DV_TIMINGS, &timings) ||
		    ioctl_retry(fd, VIDIOC_S_DV_TIMINGS, &timings)) {
			perror("QUERY/S_DV_TIMINGS");
			goto out;
		}
	}
	if (ioctl_retry(fd, VIDIOC_G_FMT, &format)) {
		perror("VIDIOC_G_FMT");
		goto out;
	}
	if (format.fmt.pix.pixelformat != V4L2_PIX_FMT_YUYV ||
	    format.fmt.pix.width < 640 || format.fmt.pix.height < 480 ||
	    format.fmt.pix.width > 4096 || format.fmt.pix.height > 2160 ||
	    (format.fmt.pix.width & 1) ||
	    format.fmt.pix.bytesperline != format.fmt.pix.width * 2 ||
	    format.fmt.pix.sizeimage != format.fmt.pix.bytesperline * format.fmt.pix.height) {
		fprintf(stderr, "unsupported capture layout\n");
		goto out;
	}
	split = options.split ? options.split :
		(format.fmt.pix.sizeimage / 2U) & ~UINT32_C(2047);
	if (!split || split >= format.fmt.pix.sizeimage) {
		fprintf(stderr, "invalid split %u for sizeimage %u\n", split,
			format.fmt.pix.sizeimage);
		goto out;
	}
	request.count = options.buffers;
	if (ioctl_retry(fd, VIDIOC_REQBUFS, &request) || request.count < 2) {
		perror("VIDIOC_REQBUFS");
		goto out;
	}
	mapped = calloc(request.count, sizeof(*mapped));
	if (!mapped) {
		perror("calloc");
		goto out;
	}
	for (i = 0; i < request.count; i++) {
		struct v4l2_buffer buffer = {
			.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
			.memory = V4L2_MEMORY_MMAP,
			.index = i,
		};

		if (ioctl_retry(fd, VIDIOC_QUERYBUF, &buffer)) {
			perror("VIDIOC_QUERYBUF");
			goto out;
		}
		mapped[i].length = buffer.length;
		mapped[i].addr = mmap(NULL, buffer.length, PROT_READ | PROT_WRITE,
				      MAP_SHARED, fd, buffer.m.offset);
		if (mapped[i].addr == MAP_FAILED) {
			mapped[i].addr = NULL;
			perror("mmap");
			goto out;
		}
		if (mapped[i].length < format.fmt.pix.sizeimage) {
			fprintf(stderr, "mapped buffer is shorter than sizeimage\n");
			goto out;
		}
		if (!queue_budget_available(submitted, options.frames))
			continue;
		if (queue_buffer(fd, mapped, i, format.fmt.pix.sizeimage, split)) {
			perror("initial VIDIOC_QBUF");
			goto out;
		}
		submitted++;
	}
	if (ioctl_retry(fd, VIDIOC_STREAMON, &type)) {
		perror("VIDIOC_STREAMON");
		goto out;
	}
	streaming = true;
	fprintf(output,
		"{\"type\":\"config\",\"capture_source_sha256\":\"" HWS_CAPTURE_SHA256 "\",\"pattern\":\"" HWS_PATTERN_VERSION "\",\"pattern_sha256\":\"" HWS_PATTERN_SHA256 "\",\"device\":\"%s\",\"width\":%u,\"height\":%u,\"fourcc\":%u,\"bytesperline\":%u,\"sizeimage\":%u,\"split\":%u,\"buffers\":%u,\"target_frames\":%u}\n",
		options.device, format.fmt.pix.width, format.fmt.pix.height,
		format.fmt.pix.pixelformat, format.fmt.pix.bytesperline,
		format.fmt.pix.sizeimage, split, request.count, options.frames);
	previous_progress_ns = monotonic_ns();

	while (!stop_requested && counters.captured < options.frames) {
		struct pollfd pollfd = { .fd = fd, .events = POLLIN };
		struct v4l2_buffer buffer = {
			.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
			.memory = V4L2_MEMORY_MMAP,
		};
		struct barcode_result upper;
		struct barcode_result lower;
		uint64_t half0_hash;
		uint64_t half1_hash;
		uint64_t now_ns;
		bool poison_half0;
		bool poison_half1;
		unsigned int poison_half0_blocks;
		unsigned int poison_half1_blocks;
		bool ids_match;
		bool monotonic = true;
		bool sequence_ok = true;
		bool payload_ok;
		bool flags_ok;
		bool frame_ok;
		uint64_t bad_bytes;
		int ready;

		ready = poll(&pollfd, 1, options.timeout_ms);
		if (ready <= 0) {
			if (!ready)
				fprintf(stderr, "capture timed out\n");
			else if (errno != EINTR)
				perror("poll");
			break;
		}
		if (ioctl_retry(fd, VIDIOC_DQBUF, &buffer)) {
			if (errno == EAGAIN)
				continue;
			perror("VIDIOC_DQBUF");
			break;
		}
		if (buffer.index >= request.count) {
			fprintf(stderr, "driver returned invalid buffer index %u\n",
				buffer.index);
			break;
		}
		half0_hash = hash64(mapped[buffer.index].addr, split);
		half1_hash = hash64((uint8_t *)mapped[buffer.index].addr + split,
				     format.fmt.pix.sizeimage - split);
		poison_half0_blocks = matching_blocks(mapped[buffer.index].addr,
			split, mapped[buffer.index].poison_half0_blocks);
		poison_half1_blocks = matching_blocks(
			(uint8_t *)mapped[buffer.index].addr + split,
			format.fmt.pix.sizeimage - split,
			mapped[buffer.index].poison_half1_blocks);
		poison_half0 = poison_half0_blocks != 0 ||
			half0_hash == mapped[buffer.index].poison_half0_hash;
		poison_half1 = poison_half1_blocks != 0 ||
			half1_hash == mapped[buffer.index].poison_half1_hash;
		upper = decode_barcode(mapped[buffer.index].addr,
				       format.fmt.pix.width, format.fmt.pix.height,
				       format.fmt.pix.bytesperline,
				       UPPER_Y_PERCENT);
		lower = decode_barcode(mapped[buffer.index].addr,
				       format.fmt.pix.width, format.fmt.pix.height,
				       format.fmt.pix.bytesperline,
				       LOWER_Y_PERCENT);
		ids_match = upper.valid && lower.valid && upper.id == lower.id;
		bad_bytes = ids_match ? content_bad_bytes(mapped[buffer.index].addr,
			format.fmt.pix.width, format.fmt.pix.height,
			format.fmt.pix.bytesperline, upper.id) : format.fmt.pix.sizeimage;
		if (bad_bytes)
			counters.content_errors++;
		payload_ok = buffer.bytesused == format.fmt.pix.sizeimage;
		flags_ok = !(buffer.flags & V4L2_BUF_FLAG_ERROR);
		if (have_previous && ids_match) {
			if (upper.id < previous_id)
				monotonic = false;
			else if (upper.id == previous_id)
				counters.repeated_ids++;
			if ((int32_t)(buffer.sequence - previous_sequence) <= 0)
				sequence_ok = false;
		}

		counters.captured++;
		if (!upper.valid || !lower.valid)
			counters.decode_errors++;
		if (upper.valid && lower.valid && !ids_match)
			counters.id_mismatches++;
		if (!monotonic)
			counters.backwards_ids++;
		if (!sequence_ok)
			counters.sequence_errors++;
		if (!payload_ok)
			counters.payload_errors++;
		if (!flags_ok)
			counters.flagged_errors++;
		if (poison_half0 || poison_half1)
			counters.poison_errors++;
		frame_ok = ids_match && monotonic && sequence_ok && payload_ok &&
			   flags_ok && !poison_half0 && !poison_half1 && !bad_bytes;
		if (frame_ok)
			counters.valid++;

		fprintf(output,
			"{\"type\":\"frame\",\"content_bad_bytes\":%" PRIu64 ",\"content_checked_bytes\":%u,\"capture_index\":%" PRIu64 ",\"buffer_index\":%u,\"v4l2_sequence\":%u,\"timestamp_ns\":%" PRIu64 ",\"flags\":%u,\"bytesused\":%u,\"upper_valid\":%s,\"lower_valid\":%s,\"upper_id\":%u,\"lower_id\":%u,\"upper_contrast\":%u,\"lower_contrast\":%u,\"ids_match\":%s,\"monotonic\":%s,\"sequence_ok\":%s,\"payload_ok\":%s,\"poison_half0\":%s,\"poison_half1\":%s,\"poison_half0_blocks\":%u,\"poison_half1_blocks\":%u,\"half0_hash\":\"%016" PRIx64 "\",\"half1_hash\":\"%016" PRIx64 "\"}\n",
			bad_bytes, ids_match ? format.fmt.pix.sizeimage : 0,
			counters.captured - 1, buffer.index, buffer.sequence,
			timeval_ns(&buffer.timestamp), buffer.flags, buffer.bytesused,
			upper.valid ? "true" : "false",
			lower.valid ? "true" : "false", upper.id, lower.id,
			upper.contrast, lower.contrast,
			ids_match ? "true" : "false",
			monotonic ? "true" : "false",
			sequence_ok ? "true" : "false",
			payload_ok ? "true" : "false",
			poison_half0 ? "true" : "false",
			poison_half1 ? "true" : "false",
			poison_half0_blocks, poison_half1_blocks,
			half0_hash, half1_hash);
		if (counters.captured == 1 && options.anomaly_dir &&
		    dump_frame(options.anomaly_dir, "first-frame.yuyv",
			       mapped[buffer.index].addr, format.fmt.pix.sizeimage)) {
			fprintf(stderr, "failed to preserve first frame\n");
			capture_failed = true;
			break;
		}
		if (!frame_ok && options.anomaly_dir) {
			if (counters.anomaly_dumps < MAX_ANOMALY_DUMPS) {
				char name[64];

				snprintf(name, sizeof(name), "anomaly-%06" PRIu64 ".yuyv",
					 counters.captured - 1);
				if (dump_frame(options.anomaly_dir, name,
					       mapped[buffer.index].addr,
					       format.fmt.pix.sizeimage)) {
					fprintf(stderr, "failed to preserve anomalous frame\n");
					capture_failed = true;
					break;
				}
				counters.anomaly_dumps++;
			} else {
				counters.anomaly_dumps_suppressed++;
			}
		}
		if (ids_match) {
			previous_id = upper.id;
			previous_sequence = buffer.sequence;
			have_previous = true;
		}
		if (queue_budget_available(submitted, options.frames)) {
			if (queue_buffer(fd, mapped, buffer.index,
					 format.fmt.pix.sizeimage, split)) {
				perror("VIDIOC_QBUF");
				capture_failed = true;
				break;
			}
			submitted++;
		}
		now_ns = monotonic_ns();
		if (now_ns - previous_progress_ns >= UINT64_C(30000000000)) {
			fprintf(stderr,
				"capture progress frames=%" PRIu64 "/%u invalid=%" PRIu64 "\n",
				counters.captured, options.frames,
				counters.captured - counters.valid);
			previous_progress_ns = now_ns;
		}
	}

	if (streaming) {
		if (ioctl_retry(fd, VIDIOC_STREAMOFF, &type)) {
			perror("VIDIOC_STREAMOFF");
			capture_failed = true;
		}
		streaming = false;
	}
	if (fflush(output))
		capture_failed = true;
	result = !capture_failed && submitted == counters.captured &&
		 counters.captured == options.frames &&
		 counters.valid == counters.captured ? 0 : 1;
	fprintf(output,
		"{\"type\":\"summary\",\"submitted\":%" PRIu64 ",\"outstanding\":%" PRIu64 ",\"content_errors\":%" PRIu64 ",\"result\":\"%s\",\"captured\":%" PRIu64 ",\"valid\":%" PRIu64 ",\"decode_errors\":%" PRIu64 ",\"id_mismatches\":%" PRIu64 ",\"backwards_ids\":%" PRIu64 ",\"repeated_ids\":%" PRIu64 ",\"sequence_errors\":%" PRIu64 ",\"payload_errors\":%" PRIu64 ",\"flagged_errors\":%" PRIu64 ",\"poison_errors\":%" PRIu64 ",\"anomaly_dumps\":%" PRIu64 ",\"anomaly_dumps_suppressed\":%" PRIu64 "}\n",
		submitted, submitted - counters.captured, counters.content_errors,
		result ? "fail" : "pass", counters.captured, counters.valid,
		counters.decode_errors, counters.id_mismatches,
		counters.backwards_ids, counters.repeated_ids,
		counters.sequence_errors, counters.payload_errors,
		counters.flagged_errors, counters.poison_errors,
		counters.anomaly_dumps, counters.anomaly_dumps_suppressed);
	if (fflush(output)) {
		perror("flush frame-ID evidence");
		result = 2;
	}
	fprintf(stderr,
		"frame-ID result=%s captured=%" PRIu64 " valid=%" PRIu64 " evidence=%s\n",
		result ? "FAIL" : "PASS", counters.captured, counters.valid,
		options.output);

out:
	if (streaming)
		(void)ioctl_retry(fd, VIDIOC_STREAMOFF, &type);
	if (mapped) {
		for (i = 0; i < request.count; i++) {
			if (mapped[i].addr)
				munmap(mapped[i].addr, mapped[i].length);
		}
		free(mapped);
	}
	if (fd >= 0)
		close(fd);
	if (output)
		fclose(output);
	return result;
}
