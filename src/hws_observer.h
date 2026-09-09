/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_OBSERVER_H
#define HWS_OBSERVER_H

/* u64/u32/bool supplied by kernel types or the host regression test. */
#define HWS_OBSERVER_RECORDS 64U
#define HWS_OBSERVER_POST 8U

struct hws_observer_sample {
	u64 begin_ns, end_ns, generation_before, generation_after, duplicates;
	u32 status_before, status_after, toggle;
	bool raced;
};

struct hws_observer {
	struct hws_observer_sample records[HWS_OBSERVER_RECORDS];
	u64 epoch, baseline_duplicates, started_ns, deadline_ns;
	u32 run, last_run, head, count, post, trigger_index;
	bool active, triggered;
};

/* Monitor-thread owned. Returns true after eight post-trigger samples. */
static inline bool hws_observer_append(struct hws_observer *o,
				       const struct hws_observer_sample *s)
{
	bool finished = false;

	o->records[o->head] = *s;
	if (!o->triggered && s->duplicates > o->baseline_duplicates) {
		o->triggered = true;
		o->trigger_index = o->head;
		o->post = HWS_OBSERVER_POST;
	} else if (o->triggered && o->post) {
		finished = --o->post == 0;
	}
	o->head = (o->head + 1) % HWS_OBSERVER_RECORDS;
	if (o->count < HWS_OBSERVER_RECORDS)
		o->count++;
	return finished;
}

/* A positive observation is evidence of the pending latch, NOT proof that
 * the device transmitted an MSI. Racy metadata and long sample gaps cannot
 * support this comparison. Units supplied by caller must be consistent.
 */
static inline bool
hws_observer_pair_valid(const struct hws_observer_sample *a,
			const struct hws_observer_sample *b, u64 max_gap)
{
	return !a->raced && !b->raced && a->end_ns >= a->begin_ns &&
		b->end_ns >= b->begin_ns && b->begin_ns >= a->end_ns &&
		b->end_ns - a->begin_ns <= max_gap &&
		a->generation_before == a->generation_after &&
		b->generation_before == b->generation_after &&
		a->generation_after == b->generation_before;
}

#endif
