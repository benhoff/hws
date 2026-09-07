// SPDX-License-Identifier: GPL-2.0-only
/* Exact raster equivalence and a benchmark that never changes display state. */
#define main kms_source_main
#include "hws_frame_id_kms.c"
#undef main
#include <assert.h>

/* The original per-pixel renderer is retained only as a benchmark/reference. */
static void draw_reference(struct surface *s, unsigned int w, unsigned int h, uint32_t id)
{
	uint64_t code = hws_pattern_code(id);
	for (unsigned int y = 0; y < h; y++) {
		uint32_t *row = (uint32_t *)(s->map + (size_t)y * s->pitch);
		for (unsigned int x = 0; x < w; x++)
			row[x] = hws_pattern_white(id, code, x, y, w, h) ? 0xffffff : 0;
	}
}

static int compare_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static void report(const char *name, uint64_t *samples, unsigned int count)
{
	qsort(samples, count, sizeof(*samples), compare_u64);
	printf("{\"renderer\":\"%s\",\"frames\":%u,\"min_ns\":%" PRIu64
	       ",\"median_ns\":%" PRIu64 ",\"p95_ns\":%" PRIu64
	       ",\"max_ns\":%" PRIu64 "}\n", name, count, samples[0],
	       samples[count / 2], samples[(count - 1) * 95 / 100], samples[count - 1]);
}

static int benchmark(const char *memory, unsigned int count)
{
	const unsigned int w = 1920, h = 1080;
	struct surface s = { .pitch = w * 4, .size = (uint64_t)w * h * 4 };
	uint32_t *scratch = malloc((size_t)w * sizeof(*scratch));
	uint64_t *old = calloc(count, sizeof(*old)), *fast = calloc(count, sizeof(*fast));
	int fd = -1, ret = 1;
	bool heap = !strcmp(memory, "heap");
	if (!scratch || !old || !fast)
		goto out;
	if (heap) {
		s.map = malloc(s.size);
		if (!s.map)
			goto out;
	} else {
		fd = open(memory, O_RDWR | O_CLOEXEC);
		if (fd < 0 || create_surface(fd, &s, w, h)) {
			perror("benchmark surface");
			goto out;
		}
	}
	/* Private, unattached buffer: no DRM master, modeset or page flip. */
	draw_reference(&s, w, h, 0);
	draw(&s, w, h, 1, scratch);
	for (unsigned int i = 0; i < count; i++) {
		/* Alternate order so neither renderer is always measured first. */
		for (unsigned int turn = 0; turn < 2; turn++) {
			bool optimized = (i + turn) & 1;
			uint64_t start = now_ns();
			if (optimized)
				draw(&s, w, h, i + 2, scratch);
			else
				draw_reference(&s, w, h, i + 2);
			(optimized ? fast : old)[i] = now_ns() - start;
		}
	}
	printf("{\"memory\":\"%s\",\"width\":%u,\"height\":%u,\"pitch\":%u,"
	       "\"scope\":\"CPU draw duration; no presentation measurement\"}\n",
	       heap ? "heap" : "DRM-dumb-mapping", w, h, s.pitch);
	report("per-pixel-reference", old, count);
	report("row-runs", fast, count);
	ret = 0;
out:
	if (heap)
		free(s.map);
	else if (fd >= 0) {
		destroy_surface(fd, &s);
		close(fd);
	}
	free(scratch);
	free(old);
	free(fast);
	return ret;
}

static void exact_pixels(void)
{
	/* Odd sizes exercise rounded barcode cells and band/tile boundaries. */
	static const unsigned int modes[][2] = {
		{640, 480}, {641, 481}, {643, 483}, {720, 576}, {800, 600},
		{1024, 768}, {1280, 720}, {1360, 768}, {1919, 1079},
		{1920, 1080}, {1921, 1081}, {2560, 1440}, {4096, 2160},
	};
	static const uint32_t ids[] = {0, 1, 0x12345678, 0x7fffffff, 0x80000000, UINT32_MAX};
	for (unsigned int m = 0; m < sizeof(modes) / sizeof(modes[0]); m++) {
		unsigned int w = modes[m][0], h = modes[m][1];
		struct surface s = { .pitch = w * 4 + 64 };
		size_t size = (size_t)s.pitch * h;
		uint8_t *allocation = malloc(size + 128);
		uint32_t *scratch = malloc((w + 2) * sizeof(*scratch));
		assert(allocation && scratch);
		s.map = allocation + 64;
		for (unsigned int n = 0; n < sizeof(ids) / sizeof(ids[0]); n++) {
			uint64_t code = hws_pattern_code(ids[n]);
			memset(allocation, 0xa5, size + 128);
			scratch[0] = scratch[w + 1] = 0xdeadbeef;
			draw(&s, w, h, ids[n], scratch + 1);
			for (unsigned int y = 0; y < h; y++) {
				uint32_t *row = (uint32_t *)(s.map + (size_t)y * s.pitch);
				for (unsigned int x = 0; x < w; x++)
					assert(row[x] == (hws_pattern_white(ids[n], code, x, y, w, h) ? 0xffffffU : 0));
				for (unsigned int x = w * 4; x < s.pitch; x++)
					assert(s.map[(size_t)y * s.pitch + x] == 0xa5);
			}
			for (unsigned int i = 0; i < 64; i++)
				assert(allocation[i] == 0xa5 && allocation[64 + size + i] == 0xa5);
			assert(scratch[0] == 0xdeadbeef && scratch[w + 1] == 0xdeadbeef);
		}
		free(scratch);
		free(allocation);
	}
	puts("Exact XRGB raster PASS: 13 geometries, 6 IDs, odd cells/bands, stride and scratch guards");
}

int main(int argc, char **argv)
{
	if (argc == 4 && !strcmp(argv[1], "--bench")) {
		unsigned int count = number(argv[3]);
		if (count < 10 || count > 1000)
			return 2;
		return benchmark(argv[2], count);
	}
	if (argc != 1) {
		fprintf(stderr, "Usage: %s [--bench heap|CARD FRAMES(10..1000)]\n", argv[0]);
		return 2;
	}
	exact_pixels();
	return 0;
}
