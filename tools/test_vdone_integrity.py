#!/usr/bin/env python3
"""Payload, timing and bounded anomaly regression tests; no hardware access."""
import copy
import unittest
from unittest.mock import patch

from hws_vdone_observers import (
    ANOMALY_WINDOWS, PATTERN_VERSION, PROBE_READ_LIMIT,
    measure_vdone, validate_anomalies, validate_content,
)
from test_vdone_observers import CONFIG, PERIOD, code, mapping_fixture


def content_fixture():
    config = dict(width=1920, height=1080, bytesperline=3840, sizeimage=4147200,
                  pattern=PATTERN_VERSION, pattern_sha256="test-pattern", capture_source_sha256="capture")
    frames = [dict(capture_index=i, upper_id=i+1, lower_id=i+1,
                   v4l2_sequence=i, bytesused=4147200, flags=0x2000,
                   content_checked_bytes=4147200, content_bad_bytes=0) for i in range(3)]
    summary = dict(submitted=3, outstanding=0, content_errors=0)
    return frames, config, summary, dict(pattern_sha256="test-pattern", capture_source_sha256="capture")


def anomaly_fixture():
    pairs = [(101, 100), (102, 101), (102, 102), (103, 102)]
    times = [1_000_000_000 + round(PERIOD * v) for v in (2, 3, 3.5, 4)]
    probes, irqs = [], []
    for index, (pair, stamp, toggle) in enumerate(zip(pairs, times, (1, 1, 0, 1)), 1):
        p = dict(window=1, position=index-1, generation=index, index=index,
                 started_ns=stamp+1000, duration_ns=10000, before=toggle, after=toggle,
                 status=0, offset0=829440, offset1=3317760)
        for i in range(4):
            p[f"code{i}"] = code(pair[i % 2])
            p[f"contrast{i}"] = 219
        probes.append({k: str(v) for k, v in p.items()})
        irqs.append({k: str(v) for k, v in dict(generation=index, timestamp_ns=stamp,
                    after=toggle, stable=1, reasserted=0).items()})
    stats = dict(probe_reads="4", probe_read_limit=str(PROBE_READ_LIMIT),
                 anomaly_windows="1", anomaly_window_limit=str(ANOMALY_WINDOWS),
                 anomaly_records="4", anomaly_triggers="1", anomaly_suppressed="0")
    source = [dict(type="present", id=i, presented_ns=1_000_000_000+round((i-99.5)*PERIOD))
              for i in range(100, 105)]
    return probes, irqs, copy.deepcopy(CONFIG), stats, source, True


class IntegrityTests(unittest.TestCase):
    def test_expected_payload_and_drained_queue(self):
        self.assertEqual(validate_content(*content_fixture()), [])

    def test_missing_old_payload_evidence_rejected(self):
        data = content_fixture()
        del data[0][0]["content_checked_bytes"]
        self.assertTrue(validate_content(*data))

    def test_payload_counter_layout_and_queue_corruption(self):
        for field, value in (("content_bad_bytes", 1), ("content_checked_bytes", 1),
                             ("bytesused", 1), ("flags", 0x2040), ("lower_id", 99),
                             ("capture_index", 99), ("v4l2_sequence", 2)):
            with self.subTest(field=field):
                data = content_fixture()
                data[0][0][field] = value
                self.assertTrue(validate_content(*data))
        for field, value in (("submitted", 4), ("outstanding", 1), ("content_errors", 1)):
            data = content_fixture()
            data[2][field] = value
            self.assertTrue(validate_content(*data))
        data = content_fixture()
        data[1]["bytesperline"] += 16
        self.assertTrue(validate_content(*data))

    def test_ids_checked_without_trusting_booleans(self):
        data = content_fixture()
        data[0][2].update(upper_id=0, lower_id=0, ids_match=True, monotonic=True)
        self.assertTrue(validate_content(*data))

    def test_rate_uses_intervals_not_orchestration_or_event_count(self):
        irqs = mapping_fixture(events=121)[1]
        rate, failures = measure_vdone(irqs)
        self.assertFalse(failures)
        self.assertEqual(rate["events"], 121)
        self.assertEqual(rate["interval_count"], 120)
        self.assertEqual(rate["elapsed_seconds"], 1)
        self.assertEqual(rate["rate_hz"], 120)
        ignored = dict(generation="0", timestamp_ns="999999999999")
        self.assertEqual(measure_vdone([ignored, *irqs, ignored]), (rate, failures))

    def test_rate_rejects_missing_reordered_and_invalid_windows(self):
        for irqs in ([], mapping_fixture(events=1)[1], mapping_fixture(events=4)[1][1:],
                     list(reversed(mapping_fixture(events=4)[1]))):
            self.assertTrue(measure_vdone(irqs)[1])

    def test_same_timestamp_preserves_accounting(self):
        irqs = mapping_fixture(events=4)[1]
        irqs[1]["timestamp_ns"] = irqs[0]["timestamp_ns"]
        timing, errors = measure_vdone(irqs)
        self.assertFalse(errors)
        self.assertEqual(timing["interval_ns"]["zero_count"], 1)

    def test_missed_boundary_consistency(self):
        result, errors = validate_anomalies(*anomaly_fixture())
        self.assertEqual(errors, [])
        self.assertEqual(result["counts"], {"consistent_with_missed_or_coalesced_boundary": 1})
        self.assertEqual(result["unobserved_same_toggle_irq_pairs"], 0)

    def test_late_anomaly_after_initial_probe_cap(self):
        data = list(anomaly_fixture())
        prefix = mapping_fixture(events=4100)[1]
        for p, irq in zip(data[0], data[1]):
            p["generation"] = irq["generation"] = str(int(p["generation"]) + 4100)
        data[1] = prefix + data[1]
        data[3]["probe_reads"] = "4104"
        result, errors = validate_anomalies(*data)
        self.assertFalse(errors)
        self.assertEqual(result["windows"][0]["trigger_generation"], 4102)

    def test_anomaly_needs_source_and_stable_observations(self):
        data = list(anomaly_fixture())
        data[-1] = False
        result, errors = validate_anomalies(*data)
        self.assertFalse(errors)
        self.assertNotIn("consistent_with_missed_or_coalesced_boundary", result["counts"])
        data = anomaly_fixture()
        data[0][1]["code2"] = str(code(999))
        self.assertEqual(validate_anomalies(*data)[0]["counts"], {"inconclusive": 1})

    def test_anomaly_loss_and_caps(self):
        data = anomaly_fixture()
        del data[0][2]
        self.assertTrue(validate_anomalies(*data)[1])
        for key, value in (("anomaly_windows", "17"), ("anomaly_records", "65"),
                           ("probe_reads", str(PROBE_READ_LIMIT+1)), ("anomaly_suppressed", "1")):
            data = anomaly_fixture()
            data[3][key] = value
            self.assertTrue(validate_anomalies(*data)[1])

    def test_end_of_stream_window_is_explicitly_inconclusive(self):
        data = list(anomaly_fixture())
        data[0], data[1] = data[0][:2], data[1][:2]
        data[3].update(probe_reads="2", anomaly_records="2")
        result, errors = validate_anomalies(*data)
        self.assertFalse(errors)
        self.assertEqual(result["counts"], {"inconclusive": 1})

    def test_read_budget_exhaustion_is_reported(self):
        data = anomaly_fixture()
        data[3]["probe_read_limit"] = "4"
        with patch("hws_vdone_observers.PROBE_READ_LIMIT", 4):
            result, errors = validate_anomalies(*data)
        self.assertFalse(errors)
        self.assertTrue(result["read_budget_exhausted"])

    def test_source_hold_does_not_become_spurious_irq_claim(self):
        data = anomaly_fixture()
        for p in data[0]:
            for i in range(4):
                p[f"code{i}"] = str(code(101))
        for r in data[4]:
            r["presented_ns"] = {100: 900000000, 101: 1000000000,
                                  102: 1100000000, 103: 1200000000, 104: 1300000000}[r["id"]]
        result, errors = validate_anomalies(*data)
        self.assertFalse(errors)
        self.assertEqual(result["counts"], {"unchanged_content_source_held": 1})


if __name__ == "__main__":
    unittest.main()
