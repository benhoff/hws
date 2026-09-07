#!/usr/bin/env python3
"""Explain observed losses without treating correlation as physical IRQ proof."""
from collections import Counter

NONE = 0xffffffff
QBUF, TAKE, EMPTY, RECYCLE, COMPLETE, STOP, IRQ, WORK, START = range(1, 10)


def number(record, key):
    value = record[key]
    return int(value, 0) if isinstance(value, str) else int(value)


def distribution(values):
    values = sorted(values)
    if not values:
        return {"samples": 0, "min_ns": None, "p50_ns": None, "p99_ns": None, "max_ns": None}
    return dict(samples=len(values), min_ns=values[0], p50_ns=values[len(values)//2],
                p99_ns=values[min(len(values)-1, int(len(values)*.99))], max_ns=values[-1])


def _diagnose(trace, userspace, stats, target):
    """Incomplete evidence never supplies a definite per-drop classification.

    Kernel records are serialized under irq_lock; userspace ioctl intervals can
    overlap them. Only successful QBUF returns strictly preceding EMPTY are
    used to infer exhaustion of the submission budget.
    """
    errors = []
    diag = trace.get("diag", [])
    events = [r for r in userspace if r.get("type") == "queue"]
    summaries = [r for r in userspace if r.get("type") == "summary"]
    configs = [r for r in userspace if r.get("type") == "config"]
    try:
        if (len(configs) != 1 or configs[0].get("schema") != 1
                or configs[0].get("clock") != "CLOCK_MONOTONIC"
                or configs[0].get("limit") != 8192):
            errors.append("missing/unsupported userspace clock or schema")
        if (len(summaries) != 1 or userspace[-1] != summaries[0]
                or summaries[0].get("records") != len(events)
                or summaries[0].get("suppressed") != 0):
            errors.append("userspace diagnostic log incomplete or capped")
        if (number(stats, "diag_records") != len(diag) or not diag
                or number(stats, "diag_suppressed") != 0
                or number(stats, "diag_limit") != 32768):
            errors.append("kernel diagnostic log incomplete or capped")
        if trace.get("loss"):
            errors.append("trace contains lost-event markers")
        if len([r for r in diag if number(r, "action") == START]) != 1:
            errors.append("missing/duplicate start snapshot")
        if len([r for r in diag if number(r, "action") == STOP]) != 1:
            errors.append("missing/duplicate stop snapshot")
        stamps = [number(r, "timestamp_ns") for r in diag]
        if any(b < a for a, b in zip(stamps, stamps[1:])):
            errors.append("kernel diagnostic timestamps reordered")
        depth = None
        for r in diag:
            action, observed = number(r, "action"), number(r, "queued")
            if action == START:
                depth = observed
            elif depth is not None:
                depth += 1 if action in (QBUF, RECYCLE) else -1 if action == TAKE else 0
                if depth < 0 or observed != depth:
                    errors.append("kernel queue-depth transitions disagree")
                if action == EMPTY and (observed != 0 or number(r, "active") != NONE):
                    errors.append("EMPTY reported with queued/active destination")
        qcount = dcount = 0
        held = set()
        previous = 0
        for r in events:
            start, called, ended = (number(r, k) for k in ("started_ns", "ioctl_ns", "ended_ns"))
            if not previous <= start <= called <= ended:
                errors.append("userspace ioctl timestamps reordered")
            previous = ended
            if number(r, "result") != 0:
                errors.append("userspace ioctl failure")
            index = number(r, "buffer")
            if r["action"] == "qbuf":
                if index in held:
                    errors.append("buffer requeued without dequeue")
                held.add(index)
                qcount += 1
            elif r["action"] == "dqbuf":
                if index not in held:
                    errors.append("dequeued buffer not submitted")
                held.discard(index)
                dcount += 1
            elif r["action"] == "requeue_delay" and index in held:
                errors.append("delay injection refers to buffer still owned by kernel")
            if number(r, "submitted") != qcount or number(r, "dequeued") != dcount:
                errors.append("userspace queue counters disagree")
        if held or qcount != target or dcount != target:
            errors.append("userspace queue not fully drained to target")
    except (KeyError, ValueError, TypeError, IndexError) as error:
        errors.append(f"missing/invalid diagnostic field: {error}")

    irq = {number(r, "generation"): r for r in trace["irq"]}
    recoveries = {number(r, "generation"): r for r in trace["recovery"]}
    empties = {number(r, "generation"): r for r in diag if number(r, "action") == EMPTY}
    complete = [r for r in diag if number(r, "action") == COMPLETE]
    qbufs = [r for r in events if r.get("action") == "qbuf" and number(r, "result") == 0]
    losses = []
    for frame in trace["frame"]:
        if not number(frame, "no_buffer"):
            continue
        generation = number(frame, "half1_generation")
        category = "unresolved"
        empty = empties.get(generation - 1)
        if not errors:
            if empty is not None:
                stamp = number(empty, "timestamp_ns")
                budget_done = any(number(q, "submitted") == target and number(q, "ended_ns") <= stamp for q in qbufs)
                delivered = sum(number(c, "timestamp_ns") <= stamp for c in complete)
                final_dequeued = any(e.get("action") == "dqbuf" and number(e, "dequeued") == target
                                     and number(e, "ended_ns") <= stamp for e in events)
                category = ("after_final_delivery" if budget_done and delivered == target and final_dequeued else
                            "queue_empty_budget_draining" if budget_done else "queue_empty_midstream")
            elif generation - 1 in recoveries:
                category = "orphan_half_after_recovery"
        losses.append(dict(generation=generation, sequence=number(frame, "sequence"), classification=category,
                           queue_window=[r for r in diag if abs(number(r, "generation")-generation) <= 2
                                         and number(r, "action") not in (IRQ, WORK)][:16]))

    irq_ack, ack_record, worker_delay = [], [], []
    for r in diag:
        action = number(r, "action")
        now, first, second = (number(r, k) for k in ("timestamp_ns", "value1", "value2"))
        if action == IRQ:
            if 0 < first <= second <= now:
                irq_ack.append(second-first)
                ack_record.append(now-second)
            else:
                errors.append("invalid IRQ entry/ack timing")
        if action == WORK:
            if 0 < first <= now:
                worker_delay.append(now-first)
            else:
                errors.append("invalid worker timing")
    if errors:
        for loss in losses:
            loss["classification"] = "unresolved"
    recovery_rows = []
    for gen, r in recoveries.items():
        observation = irq.get(gen, {})
        recovery_rows.append(dict(generation=gen, reason=number(r, "reason"),
            interval_us=number(r, "interval_us"), dropped_partial=number(r, "dropped_partial"),
            toggle=r.get("toggle"), stable=observation.get("stable"),
            reasserted=observation.get("reasserted"),
            irq_window=[irq[g] for g in range(max(0, gen-1), gen+2) if g in irq],
            dispatch_window=[d for d in diag if abs(number(d, "generation")-gen) <= 1
                             and number(d, "action") in (IRQ, WORK)],
            attribution=("partial-frame continuity rejected; physical loss count/cause unresolved"
                         if number(r, "reason") == 6 else
                         "unresolved: observed toggle behavior does not locate a lost physical boundary")))
    holds, preparation, ioctl_time, cpu_time, non_cpu = [], [], [], [], []
    injections = [e for e in events if e["action"] == "requeue_delay"]
    last_dequeue = {}
    for e in events:
        index = number(e, "buffer")
        if e["action"] == "dqbuf":
            last_dequeue[index] = number(e, "ended_ns")
        elif e["action"] == "qbuf":
            start, called, ended = (number(e, k) for k in ("started_ns", "ioctl_ns", "ended_ns"))
            preparation.append(called-start)
            ioctl_time.append(ended-called)
            if index in last_dequeue:
                wall = start-last_dequeue.pop(index)
                holds.append(wall)
                if "processing_cpu_ns" in e:
                    cpu = number(e, "processing_cpu_ns")
                    if configs[0].get("processing_cpu_clock") != "CLOCK_THREAD_CPUTIME_ID":
                        errors.append("missing/unsupported processing CPU clock")
                    elif not 0 <= cpu <= wall:
                        errors.append("invalid/missing userspace processing CPU time")
                    else:
                        cpu_time.append(cpu)
                        non_cpu.append(wall-cpu)
    for injection in injections:
        if not (number(injection, "result") == 0 and number(injection, "dequeued") > 0
                and number(injection, "dequeued") % 60 == 0
                and number(injection, "submitted") < target):
            errors.append("invalid delay injection or injection after submission budget")
    delay_ms = number(configs[0], "requeue_delay_ms") if "requeue_delay_ms" in configs[0] else 0
    if not 0 <= delay_ms <= 100:
        errors.append("invalid requested delay")
    if delay_ms and configs[0].get("requeue_delay_every_frames") != 60:
        errors.append("unsupported delay cadence")
    expected_delays = [(number(e, "buffer"), number(e, "dequeued")) for e in events
                       if delay_ms and e["action"] == "dqbuf" and number(e, "dequeued") % 60 == 0
                       and number(e, "submitted") < target]
    if expected_delays != [(number(e, "buffer"), number(e, "dequeued")) for e in injections]:
        errors.append("missing/unexpected delay injections")
    if any(number(e, "ended_ns")-number(e, "started_ns") < delay_ms * 1000000 for e in injections):
        errors.append("injected delay shorter than requested")
    # Correlation only: hardware EMPTY occurring during the intentional hold.
    overlapping_empty = [number(e, "generation") for e in empties.values()
                         if any(number(i, "started_ns") <= number(e, "timestamp_ns") <= number(i, "ended_ns")
                                for i in injections)]
    if errors:
        for loss in losses:
            loss["classification"] = "unresolved"
    return dict(schema=1, evidence_status="inconclusive" if errors else "complete",
        failures=sorted(set(errors)), drops=losses,
        drop_counts=dict(Counter(r["classification"] for r in losses)), recoveries=recovery_rows,
        injected_delay=dict(count=len(injections), requested_ms=delay_ms,
                            duration=distribution([number(i, "ended_ns")-number(i, "started_ns") for i in injections]),
                            overlapping_empty_generations=overlapping_empty if not errors else []),
        timing=dict(irq_entry_to_ack=distribution(irq_ack), ack_to_record=distribution(ack_record),
                    irq_observation_to_worker=distribution(worker_delay),
                    userspace_processing_before_requeue=distribution(holds),
                    userspace_processing_cpu=distribution(cpu_time),
                    userspace_processing_non_cpu=distribution(non_cpu),
                    poison_preparation=distribution(preparation), qbuf_ioctl=distribution(ioctl_time)),
        limits="No physical IRQ-assertion timestamp; IRQ entry latency and hardware causality remain unproven. "
               "Non-CPU wall time includes sleep, blocking I/O and descheduling, not just scheduler latency. "
               "Delay/EMPTY overlap is correlation only. No buffer-safety or source-timing gates are waived.")


def diagnose_late_toggle(trace, stats, enabled=None):
    """Observation only. Never infer safe completion or a physical IRQ cause."""
    rows, errors = [], []
    result = dict(evidence_status="not_observed", enabled=enabled, failures=[],
                  windows=rows, counts={}, suppressed=0,
                  limits="No deliberate delay or physical IRQ-assertion timestamp. "
                         "A late register change does not prove safe DMA completion; "
                         "no change in this short window does not rule out a later change.")
    records = trace.get("late_toggle", [])
    if "late_toggle_windows" not in stats and not records:
        result["evidence_status"] = "unavailable"
        return result
    try:
        windows, samples, suppressed, budget_exits, max_ns = (number(stats,k) for k in (
            "late_toggle_windows", "late_toggle_samples", "late_toggle_suppressed",
            "late_toggle_budget_exits", "late_toggle_max_ns"))
        result["suppressed"] = suppressed
        if (not 0 <= windows <= 16 or windows != len(records) or
                not 0 <= samples <= windows*4 or not 0 <= budget_exits <= windows or
                not 0 <= suppressed <= 0xffffffff or max_ns < 0 or
                (suppressed and windows != 16)):
            errors.append("late-toggle inventory missing, invalid or capped incorrectly")
        if enabled == "N" and windows:
            errors.append("late-toggle records contradict disabled module parameter")
        irqs = {number(r,"generation"): r for r in trace.get("irq", [])}
        recoveries = {number(r,"generation"): r for r in trace.get("recovery", [])}
        generations, durations, count_sum, budget_sum = set(), [], 0, 0
        for index, r in enumerate(records, 1):
            gen, window, count, flags, baseline, irq_ns, started, finished, ch = (
                number(r,k) for k in ("generation", "window", "count", "flags",
                    "baseline", "irq_ns", "started_ns", "finished_ns", "ch"))
            if (gen in generations or window != index or not 0 <= count <= 4 or
                    flags & ~15 or flags < 0 or baseline not in (0,1) or not 0 <= ch < 4 or
                    (not flags and count != 4)):
                raise ValueError("invalid/repeated late-toggle window")
            generations.add(gen)
            context = irqs.get(gen, {})
            recovery = recoveries.get(gen, {})
            for linked in (context, recovery):
                if (linked["device"] != r["device"] or number(linked,"ch") != ch or
                        number(linked,"epoch") != number(r,"epoch")):
                    raise ValueError("late-toggle source/epoch mismatch")
            if (sum(number(x,"generation")==gen for x in trace.get("irq",[])) != 1 or
                    sum(number(x,"generation")==gen for x in trace.get("recovery",[])) != 1):
                raise ValueError("ambiguous duplicate linkage")
            if (number(recovery,"reason") != 2 or number(recovery,"toggle") != baseline or
                    number(context,"previous") != baseline or number(context,"after") != baseline or
                    number(context,"stable") != 1 or number(context,"reasserted") != 0 or
                    number(context,"timestamp_ns") != irq_ns):
                raise ValueError("late-toggle window lacks matching duplicate IRQ/recovery")
            arrays = {k:[int(v,0) for v in r[k].split(",")] for k in ("start","end","toggle","status")}
            if any(len(v) != 4 for v in arrays.values()):
                raise ValueError("late-toggle array size mismatch")
            observations = []
            previous = started
            for i in range(count):
                a,b,t,s = (arrays[k][i] for k in ("start","end","toggle","status"))
                if not 0 <= t <= 0xffffffff or not 0 <= s <= 0xffffffff:
                    raise ValueError("late-toggle register outside u32")
                if not flags & 8 and not 0 < irq_ns <= started <= previous <= a <= b <= finished:
                    raise ValueError("late-toggle timestamps reordered")
                if not flags & 8 and a-started >= 50000:
                    raise ValueError("late-toggle sample began beyond budget")
                if (t == 0xffffffff or s == 0xffffffff) and not flags & 4:
                    raise ValueError("unflagged late-toggle MMIO fault")
                previous = b
                observations.append(dict(started_ns=a, finished_ns=b, raw_toggle=t, status=s))
            if not flags & 8 and not 0 < irq_ns <= started <= finished:
                raise ValueError("invalid late-toggle window timestamps")
            if not flags and finished-started >= 50000:
                raise ValueError("unflagged late-toggle budget exit")
            changed = [s for s in observations if (s["raw_toggle"] & 1) != baseline]
            reasserted = any(s["status"] & (1 << ch) for s in observations)
            classification = ("incomplete_window" if flags else
                "status_reasserted_in_window" if reasserted else
                "toggle_changed_without_sampled_vdone" if changed else
                "no_toggle_change_observed")
            rows.append(dict(generation=gen, window=window, flags=flags, baseline=baseline,
                classification=classification, samples=observations,
                first_change_read_window_after_irq_ns=(
                    [changed[0]["started_ns"]-irq_ns, changed[0]["finished_ns"]-irq_ns]
                    if changed and not flags else None)))
            count_sum += count
            budget_sum += bool(flags & 1)
            durations.append(max(0,finished-started))
        if (count_sum != samples or budget_sum != budget_exits or max(durations,default=0) != max_ns):
            errors.append("late-toggle samples/timing inventory disagrees")
        if trace.get("loss"):
            errors.append("trace loss prevents complete late-toggle evidence")
        result["duration"] = distribution(durations)
        result["evidence_status"] = "capped" if suppressed else "complete" if windows else "not_observed"
    except (KeyError, ValueError, TypeError, IndexError, AttributeError) as error:
        errors.append(f"malformed late-toggle evidence: {error}")
    if errors:
        result["evidence_status"] = "inconclusive"
        result["failures"] = sorted(set(errors))
        for row in rows:
            row["classification"] = "inconclusive"
            row["first_change_read_window_after_irq_ns"] = None
    result["counts"] = dict(Counter(r["classification"] for r in rows))
    return result


def diagnose(trace, userspace, stats, target, late_toggle_enabled=None):
    try:
        result = _diagnose(trace, userspace, stats, target)
    except (KeyError, ValueError, TypeError, IndexError) as error:
        result = dict(schema=1, evidence_status="inconclusive", failures=[f"malformed diagnostics: {error}"],
                    drops=[], drop_counts={}, recoveries=[], timing={},
                    limits="Malformed or missing evidence cannot establish a cause.")
    result["late_toggle"] = diagnose_late_toggle(trace, stats, late_toggle_enabled)
    return result
