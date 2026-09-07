// SPDX-License-Identifier: GPL-2.0-only
/* Exercise the actual KMS rasterizer against the existing capture decoder.
 * No device is opened; padded XRGB rows are converted to synthetic YUYV.
 */
#define main kms_source_main
#include "hws_frame_id_kms.c"
#undef main
#define main capture_main
#include "hws_frame_id_capture.c"
#undef main
#include <assert.h>

static void test_partial_payload(void)
{
	const uint32_t w = 1920, h = 1080, size = w * h * 2;
	const uint32_t split = (size / 2) & ~2047U;
	struct mapped_buffer b = { .length = size };
	uint8_t *data = malloc(size);
	b.addr = data;
	assert(data);
	poison_buffer(&b, 0, size, split);
	draw_synthetic_barcode(data, w, h, w * 2, 1234, 20);
	draw_synthetic_barcode(data, w, h, w * 2, 1234, 80);
	for (unsigned int half = 0; half < 2; half++) {
		size_t offset = half ? split : 0, length = half ? size - split : split;
		for (unsigned int block = 0; block < POISON_BLOCKS_PER_HALF; block++)
			data[offset + (size_t)block * length / POISON_BLOCKS_PER_HALF] ^= 1;
	}
	assert(decode_barcode(data, w, h, w * 2, 20).valid);
	assert(decode_barcode(data, w, h, w * 2, 80).valid);
	assert(!matching_blocks(data, split, b.poison_half0_blocks));
	assert(!matching_blocks(data + split, size - split, b.poison_half1_blocks));
	assert(content_bad_bytes(data, w, h, w * 2, 1234) > size / 2);
	free(data);
}

static void test_queue_drain(void)
{
	/* Worst case: the device completes EVERY queued buffer before the
	 * consumer processes one. Replenish only while total QBUFs < target. */
	for (unsigned int buffers = 2; buffers <= 8; buffers++) {
		for (unsigned int target = 1; target <= 100; target++) {
			uint64_t submitted = 0, captured = 0, done = 0;
			for (unsigned int i = 0; i < buffers; i++)
				if (queue_budget_available(submitted, target))
					submitted++;
			while (captured < target) {
				done = submitted; /* delayed consumer, all in flight finish */
				assert(done > captured);
				captured++;
				if (queue_budget_available(submitted, target))
					submitted++;
				assert(submitted <= target);
			}
			assert(submitted == captured && done == captured);
		}
	}
}
static void test_queue_diagnostics(void)
{
	queue_records = queue_suppressed = queue_submitted = queue_dequeued = 0;
	queue_log = NULL;
	queue_event("qbuf", 0, 1, 2, 3, 0);
	assert(queue_records == 0 && queue_submitted == 0);
	queue_log = tmpfile();
	assert(queue_log);
	queue_event("qbuf", 0, 1, 2, 3, -EBADF);
	assert(queue_records == 1 && queue_submitted == 0);
	queue_event("qbuf", 0, 4, 5, 6, 0);
	queue_event("dqbuf", 0, 7, 8, 9, 0);
	assert(queue_submitted == 1 && queue_dequeued == 1);
	for (unsigned int i = 3; i < QUEUE_LOG_LIMIT + 1; i++)
		queue_event("test", 0, i, i, i, 0);
	assert(queue_records == QUEUE_LOG_LIMIT && queue_suppressed == 1);
	assert(!fclose(queue_log));
	queue_log = NULL;
}

int main(void)
{
	assert(!delay_due(0, 60, 64, 1000));
	assert(!delay_due(80, 0, 4, 1000));
	assert(!delay_due(80, 59, 63, 1000));
	assert(delay_due(80, 60, 63, 1000));
	assert(!delay_due(80, 60, 60, 60));
	assert(!delay_due(80, 960, 1000, 1000));
	assert(thread_cpu_ns() > 0);
	/* Cancellation must not sleep for the injected delay or submit a buffer. */
	stop_requested = 1;
	assert(inject_requeue_delay(100, 0) == -EINTR);
	stop_requested = 0;
	{
		uint64_t start = monotonic_ns();
		assert(!inject_requeue_delay(1, 0));
		assert(monotonic_ns() - start >= 1000000);
	}
	test_queue_diagnostics();
	static const unsigned int modes[][2] = {
		{640, 480}, {720, 480}, {720, 576}, {800, 600}, {1024, 768},
		{1280, 720}, {1280, 768}, {1280, 800}, {1280, 1024},
		{1360, 768}, {1440, 900}, {1680, 1050}, {1920, 1080},
	};
	static const uint32_t ids[] = {1, 0x12345678, 0xfffffffe};
	unsigned int mode, id;

	test_partial_payload();
	test_queue_drain();
	assert(hws_pattern_code(1) == UINT64_C(0xa500000001fffe07));

	for (mode = 0; mode < sizeof(modes) / sizeof(modes[0]); mode++) {
		unsigned int w = modes[mode][0], h = modes[mode][1];
		struct surface s = { .pitch = w * 4 + 64 };
		uint8_t *yuyv = malloc((size_t)w * h * 2);
		uint32_t *scratch = malloc((size_t)w * sizeof(*scratch));
		s.map = malloc((size_t)s.pitch * h);
		if (!yuyv || !s.map || !scratch)
			return 2;
		for (id = 0; id < sizeof(ids) / sizeof(ids[0]); id++) {
			struct barcode_result upper, lower;
			unsigned int x, y;
			draw(&s, w, h, ids[id], scratch);
			memset(yuyv, 128, (size_t)w * h * 2);
			for (y = 0; y < h; y++) {
				uint32_t *row = (uint32_t *)(s.map + (size_t)y * s.pitch);
				for (x = 0; x < w; x++)
					yuyv[((size_t)y * w + x) * 2] =
						16 + (row[x] & 255) * 219 / 255;
			}
			upper = decode_barcode(yuyv, w, h, w * 2, 20);
			lower = decode_barcode(yuyv, w, h, w * 2, 80);
			assert(content_bad_bytes(yuyv, w, h, w * 2, ids[id]) == 0);
			/* Single-byte holes/corruption must fail without changing IDs. */
			uint8_t saved_y = yuyv[0], saved_uv = yuyv[1];
			yuyv[0] = 128;
			assert(content_bad_bytes(yuyv, w, h, w * 2, ids[id]) == 1);
			yuyv[0] = saved_y;
			yuyv[1] = 0;
			assert(content_bad_bytes(yuyv, w, h, w * 2, ids[id]) == 1);
			yuyv[1] = saved_uv;
			if (!mode && !id) {
				yuyv[0] = saved_y == 16 ? 24 : 227;
				assert(content_bad_bytes(yuyv, w, h, w * 2, ids[id]) == 0);
				yuyv[0] = saved_y == 16 ? 25 : 226;
				assert(content_bad_bytes(yuyv, w, h, w * 2, ids[id]) == 1);
				yuyv[0] = saved_y;
				yuyv[1] = 136;
				assert(content_bad_bytes(yuyv, w, h, w * 2, ids[id]) == 0);
				yuyv[1] = 137;
				assert(content_bad_bytes(yuyv, w, h, w * 2, ids[id]) == 1);
				yuyv[1] = saved_uv;
			}
			/* Stale row outside either barcode band. */
			for (x = 0; x < w; x++)
				yuyv[x * 2] = hws_pattern_white(ids[id] ^ 1,
					hws_pattern_code(ids[id] ^ 1), x, 0, w, h) ? 235 : 16;
			assert(content_bad_bytes(yuyv, w, h, w * 2, ids[id]) > 0);
			/* Wrong copy offset: barcodes still decode, whole pixels do not. */
			memmove(yuyv + 2, yuyv, (size_t)w * h * 2 - 2);
			assert(decode_barcode(yuyv, w, h, w * 2, 20).valid);
			assert(decode_barcode(yuyv, w, h, w * 2, 80).valid);
			assert(content_bad_bytes(yuyv, w, h, w * 2, ids[id]) > 0);
			if (!upper.valid || !lower.valid ||
			    upper.id != ids[id] || lower.id != ids[id]) {
				fprintf(stderr, "KMS raster/decoder mismatch %ux%u id=%u\n", w, h, ids[id]);
				free(yuyv);
				free(s.map);
				free(scratch);
				return 1;
			}
		}
		free(yuyv);
		free(s.map);
		free(scratch);
	}
	fprintf(stderr, "KMS raster/capture decoder PASS: 13 modes, 3 IDs each\n");
	return 0;
}
