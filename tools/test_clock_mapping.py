#!/usr/bin/env python3
"""Adversarial clock evidence and cross-host presentation tests."""
import copy
import unittest

from hws_clock_mapping import ClockMap, ClockError, METHOD, RATE_PPM, SLACK_NS
from hws_vdone_observers import validate_source, validate_anomalies
from test_vdone_observers import source_fixture, CONFIG
from test_vdone_integrity import anomaly_fixture


def marker(t):
    return dict(mono_before_ns=t, mono_after_ns=t+100,
                boottime_ns=t+1_000_000_000, realtime_ns=t+1_700_000_000_000_000_000)


def clock_fixture(offset=5_000_000_000, start=800_000_000, samples=50,
                  up=50_000, down=150_000, slope_ppm=0):
    config = dict(type="clock_config", schema=1, method=METHOD, clock="CLOCK_MONOTONIC",
                  rate_bound_ppm=RATE_PPM, timestamp_slack_ns=SLACK_NS,
                  run_id="run", source_boot_id="source", capture_boot_id="capture")
    rows = [config]
    for i in range(samples):
        s1 = start + i*50_000_000
        delta = offset + (s1-start)*slope_ppm//1_000_000
        f2 = s1 + delta + up
        f3 = f2 + 1000
        s4 = s1 + up + down + 1000
        rows.append(dict(type="clock_sample", index=i, run_id="run", s1_ns=s1,
                         s4_ns=s4, f2_ns=f2, f3_ns=f3,
                         source_clock=marker(s1-1000), capture_clock=marker(f2+100)))
    rows.append(dict(type="clock_summary", result="pass", samples=samples, run_id="run"))
    return rows


def mapping(rows=None):
    return ClockMap(rows or clock_fixture(), "source", "capture", "run")


class ClockTests(unittest.TestCase):
    def test_asymmetric_exchange_contains_true_time(self):
        m = mapping()
        lo, hi = m.bounds(1_000_000_000)
        self.assertLessEqual(lo, 6_000_000_000)
        self.assertGreaterEqual(hi, 6_000_000_000)
        self.assertLessEqual(hi-lo, 1_000_000)
        self.assertEqual(m.report()["result"], "pass")

    def test_drift_and_long_uptime_keep_integer_precision(self):
        start = 10**16
        m = mapping(clock_fixture(start=start, slope_ppm=200))
        stamp = start + 1_000_000_003
        expected = stamp + 5_000_000_000 + (stamp-start)*200//1_000_000
        lo, hi = m.bounds(stamp)
        self.assertIsInstance(lo, int)
        self.assertLessEqual(lo, expected)
        self.assertGreaterEqual(hi, expected)

    def test_no_extrapolation(self):
        m = mapping()
        for t in (1, m.centres[-1]+1):
            with self.assertRaises(ClockError): m.bounds(t)

    def test_gap_and_large_uncertainty(self):
        rows = clock_fixture(samples=30)
        del rows[5:15]
        for i, r in enumerate(rows[1:-1]): r["index"] = i
        rows[-1]["samples"] = len(rows)-2
        m = mapping(rows)
        with self.assertRaises(ClockError): m.bounds(1_200_000_000)
        wide = mapping(clock_fixture(up=2_000_000, down=2_000_000))
        self.assertEqual(wide.report()["result"], "inconclusive")
        with self.assertRaises(ClockError): wide.bounds(1_200_000_000)

    def test_discontinuity_and_reboot_fail(self):
        for key in ("boottime_ns", "realtime_ns"):
            rows = clock_fixture()
            rows[20]["capture_clock"][key] += 1_000_000_000
            with self.assertRaises(ClockError): mapping(rows)
        with self.assertRaises(ClockError): ClockMap(clock_fixture(), "new-boot", "capture", "run")
        with self.assertRaises(ClockError): ClockMap(clock_fixture(), "source", "capture", "wrong-run")

    def test_unfinished_missing_duplicate_and_malformed(self):
        for mutate in (
            lambda r: r.pop(),
            lambda r: r[5].update(index=3),
            lambda r: r[-1].update(samples=1),
            lambda r: r[4].update(s1_ns=True),
            lambda r: r[4].update(s4_ns=0),
            lambda r: r[4].update(run_id="other"),
            lambda r: r[0].update(rate_bound_ppm=1),
            lambda r: r[4].pop("capture_clock"),
        ):
            rows = clock_fixture()
            mutate(rows)
            with self.assertRaises(ClockError): mapping(rows)

    def test_impossible_rate_change_is_not_fitted_away(self):
        rows = clock_fixture()
        for r in rows[20:-1]:
            r["f2_ns"] += 100_000_000
            r["f3_ns"] += 100_000_000
            r["capture_clock"] = marker(r["f2_ns"]+100)
        with self.assertRaises(ClockError): mapping(rows)

    def source(self):
        records, frames = source_fixture()
        records[0].update(boot_id="source", run_id="run")
        for f in frames: f["timestamp_ns"] += 5_000_000_000
        return records, frames

    def test_cross_host_source_success_and_clock_required(self):
        records, frames = self.source()
        result, errors = validate_source(records, frames, CONFIG, "capture", clock_mapping=mapping())
        self.assertEqual(errors, [])
        self.assertFalse(result["same_clock"])
        self.assertEqual(result["temporal_association"]["inside"], len(frames))
        self.assertTrue(validate_source(records, frames, CONFIG, "capture")[1])

    def test_frame_at_uncertain_start_is_ambiguous(self):
        records, frames = self.source()
        m = mapping()
        lo, hi = m.bounds(records[1]["presented_ns"])
        frames[0]["timestamp_ns"] = (lo+hi)//2
        result, errors = validate_source(records, frames, CONFIG, "capture", clock_mapping=m)
        self.assertEqual(result["temporal_association"]["ambiguous"], 1)
        self.assertTrue(errors)

    def test_frame_definitely_outside_and_wrong_run(self):
        records, frames = self.source()
        frames[0]["timestamp_ns"] -= 1_000_000_000
        result, errors = validate_source(records, frames, CONFIG, "capture", clock_mapping=mapping())
        self.assertEqual(result["temporal_association"]["outside"], 1)
        records[0]["run_id"] = "other"
        self.assertIn("identities differ", " ".join(validate_source(records, frames, CONFIG, "capture", clock_mapping=mapping())[1]))

    def test_flip_counter_wrap_and_frozen_counter(self):
        records, frames = self.source()
        for i, r in enumerate(records[1:]): r["sequence"] = (0xfffffffc+i) & 0xffffffff
        self.assertEqual(validate_source(records, frames, CONFIG, "capture", clock_mapping=mapping())[1], [])
        for r in records[1:]: r["sequence"] = 0
        self.assertTrue(validate_source(records, frames, CONFIG, "capture", clock_mapping=mapping())[1])

    def test_anomaly_uses_mapped_time(self):
        data = anomaly_fixture()
        expected = validate_anomalies(*data)[0]["counts"]
        for r in data[0]: r["started_ns"] = str(int(r["started_ns"]) + 5_000_000_000)
        for r in data[1]: r["timestamp_ns"] = str(int(r["timestamp_ns"]) + 5_000_000_000)
        result, errors = validate_anomalies(*data, clock_mapping=mapping())
        self.assertEqual(errors, [])
        self.assertEqual(result["counts"], expected)
        self.assertNotEqual(validate_anomalies(*data)[0]["counts"], expected)


if __name__ == "__main__": unittest.main()
