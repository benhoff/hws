// SPDX-License-Identifier: GPL-2.0-only
/* Reuse the existing hardware model and execute the real production bodies. */
#define main hws_existing_irq_tests
#include "../../tools/test_hws_irq.c"
#undef main

static void test_missing_buffer_attribution(void)
{
    test_case = "diagnostic buffer attribution";
    initialize(); synchronize_stream();
    for (unsigned i = 0; i < 16; i++) step(true);
    assert(video()->evidence_queue_empty == 4);
    assert(video()->evidence_frames_starved == 4);
    assert(video()->evidence_frames_orphaned == 0);
    assert(video()->evidence_frames_no_buffer == 4);

    initialize(); synchronize_stream(); step(true); duplicate(); step(true);
    assert(video()->queued_count == BUFFER_COUNT);
    assert(video()->evidence_queue_empty == 0);
    assert(video()->evidence_frames_starved == 0);
    assert(video()->evidence_frames_orphaned == 1);
    assert(video()->evidence_frames_no_buffer == 1);
    assert(video()->evidence_partial_recycles == 1);
    prove_forward_progress();
}

static void test_duplicate_context(void)
{
    test_case = "diagnostic duplicate context";
    initialize(); synchronize_stream(); step(true);
    u64 previous_ns = now;
    unsigned reads = read_count, writes = ack_writes;
    duplicate();
    unsigned duplicate_reads = read_count - reads;
    assert(ack_writes == writes + 1);
    assert(video()->duplicate_windows == 1 && video()->duplicate_window_count == 3);
    struct hws_irq_observation *trigger = &video()->duplicate_window[2];
    assert(trigger->generation == 10 && trigger->timestamp_ns == previous_ns + PERIOD_NS);
    assert(trigger->before == 1 && trigger->after == 1 && trigger->previous == 1);
    assert(trigger->status == 1 && trigger->ack_status == 0 && trigger->stable);
    assert(!trigger->reasserted && trigger->completion == HWS_VIDEO_COMPLETION_IDLE);
    assert(trigger->active != U32_MAX && trigger->half_valid);
    assert(trigger->ambiguity == HWS_VDONE_AMBIG_DUPLICATE);
    assert(trigger->result == HWS_VDONE_RECOVERED);
    assert(video()->duplicate_window[0].generation == 8);
    assert(video()->duplicate_window[1].generation == 9);
    step(true); step(true);
    assert(video()->duplicate_window_count == 5);
    assert(video()->duplicate_window[3].generation == 11);
    assert(video()->duplicate_window[4].generation == 12);
    duplicate();
    assert(video()->duplicate_windows == 1 && video()->duplicate_suppressed == 1);
    assert(video()->duplicate_window[2].generation == 10); /* first trigger retained */

    /* Model the monitor consuming this window, then verify its ten-second gate. */
    video()->duplicate_window_pending = false;
    duplicate();
    assert(video()->duplicate_windows == 1 && video()->duplicate_suppressed == 2);
    now = video()->duplicate_next_ns;
    duplicate();
    assert(video()->duplicate_windows == 2 && video()->duplicate_window_count == 3);

    unsigned long flags;
    spin_lock_irqsave(&video()->irq_lock, flags);
    hws_video_reset_evidence_locked(video());
    spin_unlock_irqrestore(&video()->irq_lock, flags);
    assert(!video()->duplicate_window_pending && !video()->duplicate_window_count);
    assert(!video()->duplicate_windows && !video()->duplicate_suppressed);
    assert(!video()->duplicate_next_ns && !video()->irq_previous[1].generation);
    assert(!video()->evidence_frames_starved && !video()->evidence_frames_orphaned);

    /* Diagnostic enablement must not add reads or acknowledgments. */
    completion_diagnostics = false;
    initialize(); synchronize_stream(); step(true);
    reads = read_count; writes = ack_writes;
    duplicate();
    assert(read_count - reads == duplicate_reads && ack_writes == writes + 1);
    assert(!video()->duplicate_windows);
    completion_diagnostics = true;
}

static void test_observation_limit(void)
{
    test_case = "missing IRQ versus missing transition observability";
    initialize(); synchronize_stream(); step(true);
    /* Hardware advances twice, but software observes only the second IRQ. */
    now += PERIOD_NS; hardware_boundary(); step(true);
    struct hws_irq_observation missed = video()->duplicate_window[2];
    assert(missed.timestamp_ns - video()->duplicate_window[1].timestamp_ns == 2 * PERIOD_NS);

    initialize(); synchronize_stream(); step(true);
    /* Same elapsed time and notification, with no physical toggle transition. */
    now += 2 * PERIOD_NS;
    reg_set(HWS_REG_INT_STATUS, 1); interrupt_only(); run_work();
    struct hws_irq_observation held = video()->duplicate_window[2];
    assert(missed.timestamp_ns == held.timestamp_ns && missed.generation == held.generation);
    assert(missed.before == held.before && missed.after == held.after);
    assert(missed.status == held.status && missed.ack_status == held.ack_status);
    assert(missed.result == held.result && missed.ambiguity == held.ambiguity);
    assert(missed.stable == held.stable && missed.reasserted == held.reasserted);
    puts("Observability limit confirmed: a missed IRQ and a held DMA toggle can produce identical register observations.");
}

int main(void)
{
    test_missing_buffer_attribution();
    test_duplicate_context();
    test_observation_limit();
    puts("IRQ diagnostics PASS: true starvation/orphans, pre/post window, suppression, reset, unchanged MMIO.");
    return hws_existing_irq_tests();
}
