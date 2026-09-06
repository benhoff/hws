#!/usr/bin/env python3
"""Independent DMA-content and source-presentation evidence checks."""

from collections import Counter
from typing import Any


PROBE_LIMIT = 4096
MIN_MAPPING_TRANSITIONS = 32
PATTERN_VERSION = "hws-bw-tiles-v1"
PROBE_READ_LIMIT = 131072
ANOMALY_WINDOWS = 16
ANOMALY_POST = 2


def measure_vdone(irqs: list[dict[str, str]]) -> tuple[dict[str, Any], list[str]]:
    """Count intervals over exactly the matching active-IRQ timestamp span."""
    active = [r for r in irqs if int(r["generation"], 0) > 0]
    times = [int(r["timestamp_ns"], 0) for r in active]
    failures = []
    if [int(r["generation"], 0) for r in active] != list(range(1, len(active) + 1)):
        failures.append("active IRQ generations are missing, duplicated, or unordered")
    intervals = [b - a for a, b in zip(times, times[1:])]
    span = times[-1] - times[0] if times else 0
    if len(times) < 2 or span <= 0 or any(t < 0 for t in intervals) or any(t <= 0 for t in times):
        failures.append("invalid active IRQ timing window")
    ordered = sorted(intervals)
    return {
        "basis": "active-irq-first-last-intervals",
        "events": len(times), "interval_count": len(intervals),
        "first_timestamp_ns": times[0] if times else None,
        "last_timestamp_ns": times[-1] if times else None,
        "elapsed_seconds": span / 1e9 if span > 0 else None,
        "rate_hz": len(intervals) * 1e9 / span if span > 0 and not failures else None,
        "interval_ns": {
            "min": min(intervals) if intervals else None,
            "max": max(intervals) if intervals else None,
            "p50": ordered[(len(ordered) - 1) // 2] if ordered else None,
            "p99": ordered[(len(ordered) - 1) * 99 // 100] if ordered else None,
            "zero_count": intervals.count(0),
        },
    }, failures


def validate_content(frames: list[dict[str, Any]], config: dict[str, Any],
                     summary: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    failures = []
    size = config.get("sizeimage")
    if (config.get("pattern") != PATTERN_VERSION or not manifest.get("pattern_sha256")
            or config.get("pattern_sha256") != manifest["pattern_sha256"]):
        failures.append("capture lacks the recorded full-frame pattern implementation")
    if (not manifest.get("capture_source_sha256")
            or config.get("capture_source_sha256") != manifest["capture_source_sha256"]):
        failures.append("capture binary source digest differs from recorded source code")
    if (not isinstance(size, int) or size <= 0
            or config.get("bytesperline") != config.get("width", 0) * 2
            or size != config.get("bytesperline", 0) * config.get("height", 0)):
        failures.append("full-frame content coverage requires tightly packed YUYV")
    if (summary.get("submitted") != len(frames) or summary.get("outstanding") != 0
            or summary.get("content_errors") != 0):
        failures.append("capture queue was not fully drained or content errors occurred")
    if [f.get("capture_index") for f in frames] != list(range(len(frames))):
        failures.append("capture indexes are missing, duplicated, or unordered")
    previous = None
    for f in frames:
        if (f.get("content_checked_bytes") != size or f.get("content_bad_bytes") != 0
                or f.get("bytesused") != size or f.get("flags", 0) & 0x40):
            failures.append(f"frame {f.get('capture_index')} lacks complete expected-content verification")
        upper, lower = f.get("upper_id"), f.get("lower_id")
        if not isinstance(upper, int) or not 0 <= upper <= 0xffffffff or upper != lower:
            failures.append("captured IDs disagree or are invalid")
        if previous:
            if isinstance(upper, int) and upper < previous["upper_id"]:
                failures.append("captured IDs moved backwards")
            delta = (int(f["v4l2_sequence"]) - int(previous["v4l2_sequence"])) & 0xffffffff
            if not 0 < delta < 0x80000000:
                failures.append("captured sequences are duplicated or moved backwards")
        previous = f
    return failures


def decode_code(code: int, contrast: int) -> int | None:
    """Decode the preserved raw record without using any driver-selected half."""
    if not 0 <= code < 1 << 64 or not 80 <= contrast <= 255 or code >> 56 != 0xA5:
        return None
    frame_id = (code >> 24) & 0xFFFFFFFF
    if (code >> 8) & 0xFFFF != (~frame_id) & 0xFFFF:
        return None
    crc = 0
    for shift in (24, 16, 8, 0):
        crc ^= (frame_id >> shift) & 255
        for _ in range(8):
            crc = ((crc << 1) ^ (7 if crc & 128 else 0)) & 255
    return frame_id if code & 255 == crc else None


def validate_mapping(
    probes: list[dict[str, str]],
    irqs: list[dict[str, str]],
    deliveries: list[dict[str, str]],
    frames: list[dict[str, Any]],
    config: dict[str, str],
    probe_count: int,
) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    num, den = (int(config[k], 0) for k in ("refresh_num", "refresh_den"))
    if num <= 0 or den <= 0:
        return {"result": "fail", "method": "two-physical-region-raw-barcode-per-irq",
                "limit": PROBE_LIMIT, "records": len(probes), "counts": {},
                "mapping": "unproven"}, ["invalid timing for independent mapping observation"]
    half_ns = 1e9 * den / num / 2
    height, stride = (int(config[k], 0) for k in ("height", "bytesperline"))
    split, size = (int(config[k], 0) for k in ("split_bytes", "sizeimage"))
    offsets = [height * p // 100 * stride for p in (20, 80)]
    if not (offsets[0] + stride <= split <= offsets[1] and offsets[1] + stride <= size):
        failures.append("probe barcode rows do not lie in complementary physical regions")
    active = [r for r in irqs if int(r["generation"], 0) > 0]
    irq_by_gen = {int(r["generation"], 0): r for r in active}
    expected = min(len(active), PROBE_LIMIT)
    if len(probes) != probe_count or probe_count != expected or not probes:
        failures.append(f"independent probe accounting mismatch: trace={len(probes)} stats={probe_count} expected={expected}")
    counts: Counter[str] = Counter({key: 0 for key in (
        "half0_supports_xor1", "half1_supports_xor1", "contradictions",
        "unchanged", "both_regions_changed", "ambiguous_interval",
        "unstable_or_undecodable",
    )})
    valid_by_gen: dict[int, tuple[int, int]] = {}
    previous = None
    max_duration = max_latency = 0
    for index, p in enumerate(probes, 1):
        n = lambda key: int(p[key], 0)
        generation = n("generation")
        if n("index") != index or index > PROBE_LIMIT:
            failures.append("independent probe indexes have gaps, duplicates, or exceed cap")
        irq = irq_by_gen.get(generation)
        max_duration = max(max_duration, n("duration_ns"))
        if irq:
            max_latency = max(max_latency, n("started_ns") - int(irq["timestamp_ns"], 0))
        if irq is None or generation in valid_by_gen:
            failures.append(f"probe lacks a unique IRQ at generation {generation}")
        if index <= len(active) and generation != int(active[index - 1]["generation"], 0):
            failures.append("probe does not cover the initial consecutive IRQ window")
        if [n("offset0"), n("offset1")] != offsets:
            failures.append(f"probe physical offsets differ at generation {generation}")
        codes = [n(f"code{i}") for i in range(4)]
        ids = [decode_code(codes[i], n(f"contrast{i}")) for i in range(4)]
        timing_ok = bool(irq) and (
            0 <= n("started_ns") - int(irq["timestamp_ns"], 0) < half_ns / 4
            and 0 <= n("duration_ns") < half_ns / 8
        )
        stable = bool(irq) and timing_ok and (
            n("before") == n("after") == int(irq["after"], 0)
            and n("before") in (0, 1)
            and int(irq["stable"], 0) == 1
            and int(irq["reasserted"], 0) == 0
            and not n("status") & (1 << int(config["channel"], 0))
            and codes[:2] == codes[2:]
            and all(i is not None for i in ids)
        )
        if not stable:
            counts["unstable_or_undecodable"] += 1
            previous = None
            continue
        pair = (ids[0], ids[1])
        valid_by_gen[generation] = pair
        if previous:
            old, old_pair = previous
            interval = n("started_ns") - int(old["started_ns"], 0)
            if any(pair[i] < old_pair[i] for i in (0, 1)):
                failures.append(f"private-ring ID moved backward at generation {generation}")
            if (generation != int(old["generation"], 0) + 1
                    or n("before") == int(old["before"], 0)
                    or not half_ns * .65 <= interval <= half_ns * 1.35):
                counts["ambiguous_interval"] += 1
            else:
                changed = [i for i in (0, 1) if pair[i] != old_pair[i]]
                if not changed:
                    counts["unchanged"] += 1
                elif len(changed) == 2:
                    counts["both_regions_changed"] += 1
                else:
                    # Infer which physical region changed FIRST, then test the
                    # competing mapping. Never read completed_half here.
                    observed_half = changed[0]
                    if observed_half == (n("before") ^ 1):
                        counts[f"half{observed_half}_supports_xor1"] += 1
                    else:
                        counts["contradictions"] += 1
                        failures.append(f"independent content contradicts toggle^1 at generation {generation}")
        previous = p, pair
    for half in (0, 1):
        if counts[f"half{half}_supports_xor1"] < MIN_MAPPING_TRANSITIONS:
            failures.append(f"insufficient independent mapping transitions for physical half {half}")
    captured = {int(f["v4l2_sequence"]): f for f in frames}
    last_gen = max((int(p["generation"], 0) for p in probes), default=0)
    linked = 0
    for d in deliveries:
        g0, g1 = (int(d[k], 0) for k in ("half0_generation", "half1_generation"))
        if g1 > last_gen or not int(d["delivered"], 0):
            continue
        f = captured.get(int(d["sequence"], 0))
        p0, p1 = valid_by_gen.get(g0), valid_by_gen.get(g1)
        if not f or not p0 or not p1 or p0[0] != f["upper_id"] or p1[1] != f["lower_id"]:
            failures.append(f"delivered frame lacks matching independent ring IDs at generations {g0}/{g1}")
        else:
            linked += 1
    if linked < 16:
        failures.append("fewer than 16 delivered frames link to independent ring content")
    return {
        "result": "pass" if not failures else "fail",
        "method": "two-physical-region-raw-barcode-per-irq",
        "limit": PROBE_LIMIT, "records": len(probes),
        "first_generation": int(probes[0]["generation"], 0) if probes else None,
        "last_generation": last_gen, "linked_deliveries": linked,
        "max_duration_ns": max_duration, "max_start_latency_ns": max_latency,
        "minimum_transitions_per_region": MIN_MAPPING_TRANSITIONS,
        "counts": dict(counts),
        "mapping": "toggle_xor_1" if not failures else "unproven",
    }, failures


def validate_anomalies(probes: list[dict[str, str]], irqs: list[dict[str, str]],
                       config: dict[str, str], stats: dict[str, str],
                       source: list[dict[str, Any]], source_valid: bool) -> tuple[dict[str, Any], list[str]]:
    """Bounded classifications: consistency evidence, never a claimed cause."""
    failures: list[str] = []
    active = [r for r in irqs if int(r["generation"], 0) > 0]
    by_gen = {int(r["generation"], 0): r for r in active}
    nstats = lambda k: int(stats.get(k, "-1"), 0)
    reads, windows = nstats("probe_reads"), nstats("anomaly_windows")
    records = [p for p in probes if int(p.get("window", "0"), 0) != 0]
    if (reads != min(len(active), PROBE_READ_LIMIT)
            or nstats("probe_read_limit") != PROBE_READ_LIMIT
            or not 0 <= windows <= ANOMALY_WINDOWS
            or nstats("anomaly_window_limit") != ANOMALY_WINDOWS
            or nstats("anomaly_records") != len(records)
            or len(records) > ANOMALY_WINDOWS * (2 + ANOMALY_POST)
            or nstats("anomaly_triggers") != windows + nstats("anomaly_suppressed")
            or nstats("anomaly_suppressed") < 0
            or any("window" not in p or "position" not in p for p in probes)):
        failures.append("bounded anomaly probe accounting mismatch")
    if [int(p["index"], 0) for p in records] != list(range(1, len(records) + 1)):
        failures.append("anomaly probe record indexes are missing or duplicated")
    grouped: dict[int, list[dict[str, str]]] = {}
    for p in records:
        grouped.setdefault(int(p["window"], 0), []).append(p)
    if sorted(grouped) != list(range(1, windows + 1)):
        failures.append("anomaly probe windows are missing or exceed cap")
    half_ns = 1e9 * int(config["refresh_den"], 0) / max(1, int(config["refresh_num"], 0)) / 2
    presents = {int(r["id"]): r for r in source if r.get("type") == "present"}
    height, stride = int(config["height"], 0), int(config["bytesperline"], 0)

    def decoded(p):
        n = lambda key: int(p[key], 0)
        irq = by_gen.get(n("generation"))
        codes = [n(f"code{i}") for i in range(4)]
        ids = [decode_code(codes[i], n(f"contrast{i}")) for i in range(4)]
        if (not irq or not 1 <= n("generation") <= reads
                or [n("offset0"), n("offset1")] != [height * v // 100 * stride for v in (20, 80)]
                or codes[:2] != codes[2:] or any(i is None for i in ids)
                or not (n("before") == n("after") == int(irq["after"], 0) in (0, 1))
                or int(irq["stable"], 0) != 1 or int(irq["reasserted"], 0)
                or n("status") & (1 << int(config["channel"], 0))
                or not 0 <= n("started_ns") - int(irq["timestamp_ns"], 0) < half_ns / 4
                or not 0 <= n("duration_ns") < half_ns / 8):
            return None
        return tuple(ids[:2])

    def source_bounds(ids, stamp):
        return source_valid and all(
            i in presents and i + 1 in presents
            and presents[i]["presented_ns"] <= stamp <= presents[i + 1]["presented_ns"] + half_ns * 4
            for i in ids
        )

    results = []
    previous_trigger = 0
    captured_triggers = set()
    for window, samples in sorted(grouped.items()):
        positions = [int(p["position"], 0) for p in samples]
        trigger = next((p for p in samples if int(p["position"], 0) == 1), None)
        if not trigger:
            failures.append(f"anomaly window {window} lacks trigger")
            continue
        generation = int(trigger["generation"], 0)
        captured_triggers.add(generation)
        expected = 2 + min(ANOMALY_POST, max(0, reads - generation))
        if (positions != list(range(expected)) or generation < 2
                or generation > reads or generation <= previous_trigger + (ANOMALY_POST if previous_trigger else 0)
                or [int(p["generation"], 0) for p in samples] != list(range(generation - 1, generation - 1 + expected))):
            failures.append(f"anomaly window {window} has missing or inconsistent samples")
        previous_trigger = generation
        pairs = [decoded(p) for p in samples]
        category = "inconclusive"
        delta = int(trigger["started_ns"], 0) - int(samples[0]["started_ns"], 0)
        toggle = int(trigger["before"], 0)
        stable = len(samples) == 4 and all(p is not None for p in pairs)
        if stable:
            before, current = pairs[:2]
            same_toggle = int(samples[0]["before"], 0) == toggle
            following = all(
                int(samples[i]["before"], 0) != int(samples[i - 1]["before"], 0)
                and half_ns * .65 <= int(samples[i]["started_ns"], 0) - int(samples[i - 1]["started_ns"], 0) <= half_ns * 1.35
                for i in (2, 3)
            )
            source_ok = all(source_bounds(pair, int(p["started_ns"], 0)) for pair, p in zip(pairs, samples))
            if any(b < a for a, b in zip(before, current)):
                category = "content_regressed"
                failures.append(f"ring content moved backwards in anomaly window {window}")
            elif same_toggle and before == current:
                category = "unchanged_content_unresolved"
                i = current[0]
                if (source_ok and current[0] == current[1]
                        and presents[i]["presented_ns"] <= int(samples[0]["started_ns"], 0)
                        and int(trigger["started_ns"], 0) <= presents[i + 1]["presented_ns"]):
                    category = "unchanged_content_source_held"
            elif (same_toggle and following and source_ok
                    and half_ns * 1.65 <= delta <= half_ns * 2.35
                    and all(b == a + 1 for a, b in zip(before, current))
                    and before[0] - before[1] == (1 if toggle == 1 else 0)
                    and current[0] - current[1] == (1 if toggle == 1 else 0)):
                category = "consistent_with_missed_or_coalesced_boundary"
            elif same_toggle and before != current:
                category = "advancing_content_unresolved"
        results.append({"window": window, "trigger_generation": generation,
                        "classification": category, "interval_ns": delta,
                        "generations": [int(p["generation"], 0) for p in samples],
                        "region_ids": pairs})
    same_toggle = {
        int(b["generation"], 0) for a, b in zip(active, active[1:])
        if int(a["after"], 0) == int(b["after"], 0)
    }
    return {
        "result": "fail" if failures else "pass", "read_limit": PROBE_READ_LIMIT,
        "reads": reads, "read_budget_exhausted": reads == PROBE_READ_LIMIT,
        "window_limit": ANOMALY_WINDOWS, "records": len(records),
        "windows": results, "suppressed_triggers": nstats("anomaly_suppressed"),
        "same_toggle_irq_pairs": len(same_toggle),
        "unobserved_same_toggle_irq_pairs": len(same_toggle - captured_triggers),
        "counts": dict(Counter(r["classification"] for r in results)),
    }, failures


def validate_source(
    records: list[dict[str, Any]], frames: list[dict[str, Any]],
    config: dict[str, str], boot_id: str | None,
) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    configs = [r for r in records if r.get("type") == "source_config"]
    presents = [r for r in records if r.get("type") == "present"]
    if len(configs) != 1 or len(presents) < 2:
        return {"result": "fail", "repeat_attribution": "unknown"}, ["missing source configuration or page-flip telemetry"]
    if records[0].get("type") != "source_config":
        failures.append("source configuration must precede presentation records")
    summaries = [r for r in records if r.get("type") == "source_summary"]
    if len(summaries) > 1 or (summaries and (
        records[-1].get("type") != "source_summary"
        or summaries[0].get("presentations") != len(presents)
    )):
        failures.append("source summary ordering or presentation count is invalid")
    if any(r.get("type") not in ("source_config", "present", "source_summary") for r in records):
        failures.append("source telemetry contains unsupported records")
    source = configs[0]
    if (source.get("schema") != 1 or source.get("backend") != "drm-kms"
            or source.get("clock") != "CLOCK_MONOTONIC"
            or source.get("async_flip") is not False):
        failures.append("source telemetry is not synchronous monotonic KMS presentation evidence")
    same_clock = bool(boot_id) and source.get("boot_id") == boot_id
    if not same_clock:
        failures.append("source/capture clock domains differ; calibrated cross-host timing is required")
    for key in ("width", "height", "htotal", "vtotal"):
        if source.get(key) != int(config[key], 0):
            failures.append(f"source presentation mode differs for {key}")
    if abs(source.get("clock_khz", 0) * 1000 - int(config["pixelclock"], 0)) > 1000:
        failures.append("source presentation pixelclock differs from capture mode")
    if source.get("vscan", 0) > 1 or source.get("mode_flags", 0) & ((1 << 4) | (1 << 5)):
        failures.append("source presentation is interlaced or doublescan")
    by_id = {}
    previous = None
    spans = {}
    num, den = (int(config[k], 0) for k in ("refresh_num", "refresh_den"))
    if num <= 0 or den <= 0:
        return {"result": "fail", "repeat_attribution": "unknown"}, ["invalid timing for source presentation observation"]
    nominal_ns = 1e9 * den / num
    for r in presents:
        frame_id = int(r["id"])
        if not 0 <= r["sequence"] <= 0xFFFFFFFF:
            failures.append("invalid source vblank sequence")
        if frame_id in by_id or not 0 <= frame_id <= 0xFFFFFFFF:
            failures.append("source has duplicate or invalid presentation IDs")
        if not (0 < r["submitted_ns"] <= r["presented_ns"] <= r["callback_ns"]):
            failures.append("invalid source submission/presentation/callback timestamps")
        if previous:
            delta = (r["sequence"] - previous["sequence"]) & 0xFFFFFFFF
            elapsed = r["presented_ns"] - previous["presented_ns"]
            if frame_id != previous["id"] + 1 or not 0 < delta < 0x80000000 or elapsed <= 0:
                failures.append("source presentation IDs, sequences, or timestamps are not ordered")
            elif abs(elapsed - delta * nominal_ns) > nominal_ns * .25:
                failures.append("source vblank sequence disagrees with presentation timing")
            spans[previous["id"]] = delta
        by_id[frame_id] = r
        previous = r
    captured_counts = Counter(int(f["upper_id"]) for f in frames)
    held_repeats = excess_repeats = 0
    for frame_id, count in captured_counts.items():
        if frame_id not in spans:
            failures.append(f"captured ID {frame_id} lacks a bounded presentation interval")
            continue
        held_repeats += min(max(0, count - 1), max(0, spans[frame_id] - 1))
        excess_repeats += max(0, count - spans[frame_id])
    for f in frames:
        if f.get("flags", 0) & 0x7E000 != 0x2000:
            failures.append("capture timestamps are not marked monotonic EOF")
        r = by_id.get(int(f["upper_id"]))
        if not r or not same_clock:
            continue
        # Capture timestamps describe received EOF, so a frame must have
        # started presentation earlier; use a deliberately bounded allowance
        # of two refresh periods for receiver/IRQ latency after replacement.
        end = by_id.get(r["id"] + 1)
        if not end or not r["presented_ns"] <= f["timestamp_ns"] <= end["presented_ns"] + nominal_ns * 2:
            failures.append(f"captured ID {r['id']} falls outside its source presentation window")
    if excess_repeats:
        failures.append("captured repetition exceeds source-observed refresh occupancy")
    if any(r.get("type") == "source_summary" and r.get("result") != "pass" for r in records):
        failures.append("source reported a presentation failure")
    return {
        "result": "pass" if not failures else "fail", "backend": source.get("backend"),
        "presentations": len(presents), "same_clock": same_clock,
        "source_held_refreshes": sum(max(0, n - 1) for n in spans.values()),
        "captured_repeats_supported_by_source": held_repeats,
        "captured_repeats_exceeding_source": excess_repeats,
        "repeat_attribution": "consistent-with-source-occupancy" if not failures else "unresolved",
    }, failures
