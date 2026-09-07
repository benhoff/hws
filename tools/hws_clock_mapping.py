#!/usr/bin/env python3
"""Conservative source-monotonic to capture-monotonic bounds, from raw exchanges.

The model assumes relative clock rate stays within 1000 ppm. It does not assume
network symmetry or infer offset from video. Integer arithmetic preserves ns at
long uptimes. Bounds are conditional on the declared rate/clock-read model.
"""
from bisect import bisect_left
import json
from pathlib import Path

SCHEMA = 1
METHOD = "bounded-rate-envelope-v1"
RATE_PPM = 1000
SLACK_NS = 5000
MAX_GAP_NS = 250_000_000
MAX_UNCERTAINTY_NS = 500_000
MAX_BYTES = 64 * 1024 * 1024
MAX_SAMPLES = 100_000


class ClockError(ValueError):
    pass


def integer(value):
    if type(value) is not int or not 0 <= value < 1 << 63:
        raise ClockError("invalid integer timestamp/count")
    return value


def drift(distance):
    return (abs(distance) * RATE_PPM + 999_999) // 1_000_000


def read_records(path):
    with Path(path).open("rb") as stream:
        payload = stream.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES or not payload.endswith(b"\n"):
        raise ClockError("clock evidence exceeds size limit or has a torn record")
    try:
        rows = [json.loads(line) for line in payload.splitlines()]
    except (ValueError, UnicodeError) as exc:
        raise ClockError("invalid clock JSONL") from exc
    if not all(isinstance(r, dict) for r in rows):
        raise ClockError("clock records must be objects")
    return rows


def marker_bounds(marker):
    a, b, boot, real = (integer(marker[k]) for k in ("mono_before_ns", "mono_after_ns", "boottime_ns", "realtime_ns"))
    if not a <= b or b - a > 1_000_000:
        raise ClockError("clock-read bracket invalid or too wide")
    return (boot - b, boot - a), (real - b, real - a)


class ClockMap:
    def __init__(self, records, source_boot, capture_boot, run_id):
        try:
            self._load(records, source_boot, capture_boot, run_id)
        except (KeyError, TypeError, IndexError, OverflowError) as exc:
            raise ClockError(f"malformed clock evidence: {type(exc).__name__}") from exc

    def _load(self, records, source_boot, capture_boot, run_id):
        if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
            raise ClockError("clock evidence must contain object records")
        if len(records) < 4 or len(records) > MAX_SAMPLES + 2:
            raise ClockError("clock evidence needs configuration, samples, and final summary")
        c, summary = records[0], records[-1]
        self.config = c
        if (c.get("type") != "clock_config" or c.get("schema") != SCHEMA
                or c.get("clock") != "CLOCK_MONOTONIC" or c.get("method") != METHOD
                or c.get("rate_bound_ppm") != RATE_PPM or c.get("timestamp_slack_ns") != SLACK_NS):
            raise ClockError("unsupported clock evidence model")
        if (not run_id or c.get("run_id") != run_id or not source_boot or not capture_boot
                or c.get("source_boot_id") != source_boot or c.get("capture_boot_id") != capture_boot):
            raise ClockError("clock evidence run/boot identity mismatch")
        rows = records[1:-1]
        if (summary.get("type") != "clock_summary" or summary.get("result") != "pass"
                or summary.get("samples") != len(rows) or summary.get("run_id") != run_id):
            raise ClockError("clock acquisition incomplete or unsuccessful")
        self.centres, self.lows, self.highs = [], [], []
        previous_s = previous_f = 0
        marker_intersections = {}
        self.rtts = []
        for i, r in enumerate(rows):
            if r.get("type") != "clock_sample" or r.get("index") != i or r.get("run_id") != run_id:
                raise ClockError("clock sample identity/order mismatch")
            s1, f2, f3, s4 = (integer(r[k]) for k in ("s1_ns", "f2_ns", "f3_ns", "s4_ns"))
            if not 0 < s1 < s4 or (i and previous_s >= s1) or not 0 < f2 <= f3:
                raise ClockError("clock sample timestamps reordered")
            if i and f2 <= previous_f:
                raise ClockError("capture clock moved backwards")
            previous_s, previous_f = s4, f3
            for host, lower, upper in (("source", s1, s4), ("capture", f2, f3)):
                marker = r[host + "_clock"]
                mb = integer(marker["mono_before_ns"])
                me = integer(marker["mono_after_ns"])
                # Markers are taken within the remote service interval and
                # just before the source send. Bound association explicitly.
                if host == "capture" and not lower <= mb <= me <= upper:
                    raise ClockError("capture clock marker outside exchange")
                if host == "source" and not 0 <= lower - me <= MAX_GAP_NS:
                    raise ClockError("source clock marker is stale")
                for kind, interval in zip(("boot", "real"), marker_bounds(marker)):
                    key = host, kind
                    lo, hi = interval[0] - 100_000, interval[1] + 100_000
                    old = marker_intersections.get(key, (lo, hi))
                    combined = max(lo, old[0]), min(hi, old[1])
                    if combined[0] > combined[1]:
                        raise ClockError("suspend or clock discontinuity detected")
                    marker_intersections[key] = combined
            mid = (s1 + s4) // 2
            lo = f3 - s4 - drift(s4 - mid) - SLACK_NS
            hi = f2 - s1 + drift(mid - s1) + SLACK_NS
            if lo > hi:
                raise ClockError("exchange violates bounded clock rate/causality")
            self.centres.append(mid)
            self.lows.append(lo)
            self.highs.append(hi)
            self.rtts.append((s4 - s1) - (f3 - f2))
        # Intersect all constraints in linear time under a Lipschitz rate bound.
        for order in (range(1, len(rows)), range(len(rows) - 2, -1, -1)):
            for j in order:
                k = j - 1 if order.step == 1 else j + 1
                growth = drift(self.centres[j] - self.centres[k])
                self.lows[j] = max(self.lows[j], self.lows[k] - growth)
                self.highs[j] = min(self.highs[j], self.highs[k] + growth)
        if any(lo > hi for lo, hi in zip(self.lows, self.highs)):
            raise ClockError("clock samples have no consistent bounded-rate mapping")

    def bounds(self, source_ns):
        source_ns = integer(source_ns)
        pos = bisect_left(self.centres, source_ns)
        if source_ns < self.centres[0] or source_ns > self.centres[-1]:
            raise ClockError("presentation outside clock calibration coverage")
        indexes = {max(0, pos - 1), min(pos, len(self.centres) - 1)}
        if len(indexes) > 1 and self.centres[max(indexes)] - self.centres[min(indexes)] > MAX_GAP_NS:
            raise ClockError("clock sample gap exceeds 250 ms")
        lo = max(self.lows[i] - drift(source_ns - self.centres[i]) for i in indexes)
        hi = min(self.highs[i] + drift(source_ns - self.centres[i]) for i in indexes)
        if lo > hi:
            raise ClockError("empty mapped timestamp interval")
        if hi - lo > 2 * MAX_UNCERTAINTY_NS:
            raise ClockError("clock mapping uncertainty exceeds 500 us")
        return source_ns + lo, source_ns + hi

    def report(self):
        centres = self.centres
        gaps = [b - a for a, b in zip(centres, centres[1:])]
        # Checking endpoints plus gap midpoints gives a conservative full-span
        # width bound: grow each endpoint's envelope to the midpoint.
        width_bound = max(hi - lo for lo, hi in zip(self.lows, self.highs))
        for i, gap in enumerate(gaps):
            width_bound = max(width_bound, min(self.highs[i] - self.lows[i],
                                               self.highs[i+1] - self.lows[i+1]) + 2 * drift(gap))
        return dict(schema=SCHEMA, method=METHOD, samples=len(centres),
                    source_start_ns=centres[0], source_end_ns=centres[-1],
                    rate_bound_ppm=RATE_PPM, timestamp_slack_ns=SLACK_NS,
                    max_gap_ns=max(gaps), max_uncertainty_bound_ns=(width_bound + 1)//2,
                    minimum_exchange_rtt_ns=min(self.rtts),
                    result="pass" if max(gaps) <= MAX_GAP_NS and width_bound <= 2*MAX_UNCERTAINTY_NS else "inconclusive")


def presentation_bounds(record, mapping=None):
    stamp = record["presented_ns"]
    return mapping.bounds(stamp) if mapping else (stamp, stamp)
