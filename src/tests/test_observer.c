/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long long u64;
typedef uint32_t u32;
#include "../hws_observer.h"

#define NSEC_PER_MSEC 1000000ULL
#define U32_MAX UINT32_MAX
#define BIT(n) (1U << (n))
#define READ_ONCE(x) (x)
#define max(a, b) ((a) > (b) ? (a) : (b))
#define clamp_t(t, x, lo, hi) ((t)(x) < (lo) ? (lo) : ((t)(x) > (hi) ? (hi) : (t)(x)))
#define module_param(...) _Static_assert(1, "module parameter shim")
#define MODULE_PARM_DESC(...) _Static_assert(1, "module description shim")
#define lockdep_assert_held(p) assert(*(p))
#define spin_lock_irqsave(p, flags) do { assert(!*(p)); *(p) = 1; (flags) = 0; } while (0)
#define spin_unlock_irqrestore(p, flags) do { assert(*(p)); *(p) = 0; (void)(flags); } while (0)
#define dev_info(dev, ...) record_log(__VA_ARGS__)

struct hws_video {
	int irq_lock;
	u64 evidence_stream_epoch, evidence_duplicate_reports;
	u64 evidence_resync_reports, next_completion_generation;
	bool cap_active, stop_requested;
};
struct hws_pcie_dev {
	struct hws_observer irq_observer;
	struct hws_video video[4];
	unsigned int cur_max_video_ch;
	int monitor_lock;
	unsigned char *bar0_base;
	bool pci_lost, suspended, dma_failed;
};
static struct hws_pcie_dev card;
static unsigned char bar[0x5000];
static u64 clock_ns;
static unsigned int reads, inject;
static char logs[65536];
static size_t log_used;

static u64 ktime_get_mono_fast_ns(void) { return clock_ns++; }
static void record_log(const char *format, ...)
{
	va_list ap;
	int n;
	va_start(ap, format);
	n = vsnprintf(logs + log_used, sizeof(logs) - log_used, format, ap);
	va_end(ap);
	assert(n >= 0 && (size_t)n < sizeof(logs) - log_used);
	log_used += n;
}
static u32 readl(const void *address);
#include HWS_OBSERVER_UNDER_TEST

static u32 readl(const void *address)
{
	size_t offset = (const unsigned char *)address - bar;
	u32 value;
	/* No writes or other register accesses are supplied by this shim. */
	assert(offset == (reads % 3 == 1 ? HWS_REG_VBUF_TOGGLE(1) : HWS_REG_INT_STATUS));
	assert(!card.video[1].irq_lock);
	assert(offset + sizeof(value) <= sizeof(bar));
	memcpy(&value, bar + offset, sizeof(value));
	reads++;
	if (inject == 1) card.video[1].next_completion_generation++;
	if (inject == 2) card.video[1].evidence_stream_epoch++;
	if (inject == 3) value = U32_MAX;
	inject = 0;
	return value;
}

static void reg_set(size_t offset, u32 value) { memcpy(bar + offset, &value, sizeof(value)); }
static void reset(void)
{
	memset(&card, 0, sizeof(card));
	memset(bar, 0, sizeof(bar));
	memset(logs, 0, sizeof(logs));
	clock_ns = NSEC_PER_MSEC;
	reads = inject = log_used = 0;
	card.monitor_lock = 1;
	card.bar0_base = bar;
	card.cur_max_video_ch = 2;
	card.video[1].cap_active = true;
	card.video[1].evidence_stream_epoch = 1;
	irq_observer_run = 0;
	irq_observer_channel = 1;
	irq_observer_ms = 15000;
}
static bool poll(void) { clock_ns += NSEC_PER_MSEC; return hws_irq_observer_poll(&card); }
static void arm(void) { irq_observer_run = 1; assert(poll()); }

static void test_window(void)
{
	struct hws_observer o = { .baseline_duplicates = 10 };
	struct hws_observer_sample s = { .duplicates = 10 };
	unsigned int i, first;
	for (i = 0; i < 200; i++) {
		s.begin_ns = i;
		assert(!hws_observer_append(&o, &s));
	}
	assert(o.count == HWS_OBSERVER_RECORDS && !o.triggered);
	s.duplicates++;
	s.begin_ns = 200;
	assert(!hws_observer_append(&o, &s));
	assert(o.triggered && o.post == HWS_OBSERVER_POST);
	for (i = 1; i <= HWS_OBSERVER_POST; i++) {
		s.begin_ns = 200 + i;
		assert(hws_observer_append(&o, &s) == (i == HWS_OBSERVER_POST));
	}
	first = (o.head + HWS_OBSERVER_RECORDS - o.count) % HWS_OBSERVER_RECORDS;
	for (i = 0; i < o.count; i++)
		assert(o.records[(first + i) % HWS_OBSERVER_RECORDS].begin_ns == 145 + i);
	assert(o.records[o.trigger_index].begin_ns == 200);
}

static void test_pair_filters(void)
{
	struct hws_observer_sample a = { .begin_ns = 10, .end_ns = 11 };
	struct hws_observer_sample b = { .begin_ns = 20, .end_ns = 21 }, bad;
	assert(hws_observer_pair_valid(&a, &b, 11));
	assert(!hws_observer_pair_valid(&a, &b, 10));
	bad = b; bad.raced = true; assert(!hws_observer_pair_valid(&a, &bad, 100));
	bad = a; bad.raced = true; assert(!hws_observer_pair_valid(&bad, &b, 100));
	bad = b; bad.generation_after++; assert(!hws_observer_pair_valid(&a, &bad, 100));
	bad = a; bad.generation_after++; assert(!hws_observer_pair_valid(&bad, &b, 100));
	bad = b; bad.generation_before = bad.generation_after = 1;
	assert(!hws_observer_pair_valid(&a, &bad, 100));
	bad = b; bad.begin_ns = 9; assert(!hws_observer_pair_valid(&a, &bad, 100));
	bad = b; bad.end_ns = 19; assert(!hws_observer_pair_valid(&a, &bad, 100));
	bad = a; bad.end_ns = 9; assert(!hws_observer_pair_valid(&bad, &b, 100));
}

static void test_lifecycle(void)
{
	unsigned int i, before;
	reset(); assert(!poll() && reads == 0); arm(); assert(reads == 3);
	irq_observer_run = 0; assert(!poll() && reads == 3);
	arm(); assert(reads == 6); /* Zero then the same run number rearms. */
	clock_ns = card.irq_observer.deadline_ns;
	assert(!poll() && reads == 6 && !card.irq_observer.active);
	assert(!poll() && reads == 6); /* Completed runs do not restart. */
	irq_observer_run = 2; assert(poll() && reads == 9);
	irq_observer_run = 3; assert(poll() && reads == 12 && card.irq_observer.run == 3);
	for (i = 0; i < 7; i++) {
		reset(); arm(); before = reads;
		switch (i) {
		case 0: card.video[1].cap_active = false; break;
		case 1: card.video[1].stop_requested = true; break;
		case 2: card.video[1].evidence_stream_epoch++; break;
		case 3: card.pci_lost = true; break;
		case 4: card.suspended = true; break;
		case 5: card.dma_failed = true; break;
		case 6: card.bar0_base = NULL; break;
		}
		assert(!poll() && reads == before && !card.irq_observer.active);
	}
	reset(); irq_observer_channel = 99; irq_observer_run = 1;
	assert(!poll() && reads == 0);
	hws_irq_observer_stop(&card, "inactive-invalid-channel");
	reset(); card.video[1].cap_active = false; irq_observer_run = 1;
	assert(!poll() && reads == 0);
	reset(); irq_observer_ms = 0; arm();
	assert(card.irq_observer.deadline_ns - card.irq_observer.started_ns == 100 * NSEC_PER_MSEC);
	reset(); irq_observer_ms = UINT32_MAX; arm();
	assert(card.irq_observer.deadline_ns - card.irq_observer.started_ns == 30000 * NSEC_PER_MSEC);
	clock_ns = 0; assert(!hws_irq_observer_poll(&card));
	for (i = 1; i <= 3; i++) {
		reset(); arm(); inject = i;
		assert(poll() == (i == 1));
		assert(card.irq_observer.active == (i == 1));
		assert(!hws_observer_pair_valid(&card.irq_observer.records[0],
			&card.irq_observer.records[1], 4 * NSEC_PER_MSEC));
	}
}

static void test_evidence(void)
{
	unsigned int i;
	reset(); reg_set(HWS_REG_INT_STATUS, HWS_INT_VDONE_BIT(1)); arm();
	reg_set(HWS_REG_VBUF_TOGGLE(1), 1); assert(poll());
	card.video[1].evidence_duplicate_reports++;
	card.video[1].next_completion_generation++;
	reg_set(HWS_REG_INT_STATUS, 0); assert(poll());
	assert(card.irq_observer.triggered);
	for (i = 1; i <= HWS_OBSERVER_POST; i++) assert(poll() == (i != HWS_OBSERVER_POST));
	assert(strstr(logs, "pending_pairs_no_record=1 toggle_changes_no_record=1"));
	assert(strstr(logs, "reason=duplicate-window-complete triggered=1"));
	assert(!poll());
	/* An IRQ during reads or a long gap cannot support those conclusions. */
	for (i = 0; i < 2; i++) {
		reset(); reg_set(HWS_REG_INT_STATUS, HWS_INT_VDONE_BIT(1)); arm();
		reg_set(HWS_REG_VBUF_TOGGLE(1), 1);
		if (i) clock_ns += 10 * NSEC_PER_MSEC; else inject = 1;
		assert(poll()); hws_irq_observer_stop(&card, "test");
		assert(strstr(logs, "pending_pairs_no_record=0 toggle_changes_no_record=0"));
	}
}

int main(void)
{
	test_window(); test_pair_filters(); test_lifecycle(); test_evidence();
	puts("observer: window, race/gap filters, lifecycle, MMIO and evidence tests passed");
	return 0;
}
