#!/usr/bin/env python3
"""Adversarial synthetic evidence: false driver mapping must not validate."""

import copy
import unittest

from hws_vdone_observers import decode_code, validate_mapping, validate_source


CONFIG = dict(channel="1", width="1920", height="1080", bytesperline="3840",
              split_bytes="2072576", sizeimage="4147200", refresh_num="148500000",
              refresh_den="2475000", pixelclock="148500000", htotal="2200", vtotal="1125")
PERIOD = 1_000_000_000 / 60


def code(frame_id):
    crc = 0
    for byte in frame_id.to_bytes(4, "big"):
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ (7 if crc & 128 else 0)) & 255
    return (0xA5 << 56) | (frame_id << 24) | ((~frame_id & 65535) << 8) | crc


def mapping_fixture(reverse=False, repeats=False, events=180):
    probes, irqs, deliveries, frames = [], [], [], []
    ids = [100, 100]
    for gen in range(1, events + 1):
        half = (gen - 1) % 2
        # Reversed hardware behavior, while software still reports xor1.
        physical = half ^ int(reverse)
        ids[physical] = 101 + (gen - 1) // (4 if repeats else 2)
        stamp = 1_000_000_000 + round(gen * PERIOD / 2)
        fields = dict(generation=gen, index=gen, started_ns=stamp + 1000,
                      duration_ns=10000, before=half ^ 1, after=half ^ 1, status=0,
                      offset0=829440, offset1=3317760)
        for i in range(4):
            fields[f"code{i}"] = code(ids[i % 2])
            fields[f"contrast{i}"] = 219
        probes.append({k: str(v) for k, v in fields.items()})
        irqs.append({k: str(v) for k, v in dict(generation=gen, timestamp_ns=stamp,
                     after=half ^ 1, stable=1, reasserted=0, completed_half=half).items()})
        if gen % 2 == 0:
            seq = gen // 2
            deliveries.append(dict(half0_generation=str(gen - 1), half1_generation=str(gen),
                                   delivered="1", sequence=str(seq)))
            frames.append(dict(v4l2_sequence=seq, upper_id=ids[0], lower_id=ids[1]))
    return probes, irqs, deliveries, frames


def mapping_result(data):
    return validate_mapping(*data, CONFIG, len(data[0]))


def source_fixture(held=False):
    config = dict(type="source_config", schema=1, backend="drm-kms",
                  clock="CLOCK_MONOTONIC", boot_id="boot", async_flip=False,
                  width=1920, height=1080, htotal=2200, vtotal=1125, clock_khz=148500)
    presents = []
    sequence = 100
    for frame_id in range(10, 21):
        timestamp = 1_000_000_000 + round((sequence - 100) * PERIOD)
        presents.append(dict(type="present", id=frame_id, sequence=sequence,
                             submitted_ns=timestamp - 1_000_000, presented_ns=timestamp,
                             callback_ns=timestamp + 100_000))
        sequence += 2 if held else 1
    frames = []
    for r in presents[:-1]:
        for i in range(2 if held else 1):
            frames.append(dict(upper_id=r["id"], flags=0x2000,
                               timestamp_ns=r["presented_ns"] + round((i + 1) * PERIOD)))
    return [config, *presents], frames


class ObserverTests(unittest.TestCase):
    def test_decode_reference_and_crc_damage(self):
        # Independently known CRC-8/ATM values for 32-bit big-endian IDs.
        self.assertEqual(decode_code(0xA500000001FFFE07, 219), 1)
        self.assertIsNone(decode_code(0xA500000001FFFE06, 219))
        self.assertIsNone(decode_code(0xA500000001FFFE07, 79))

    def test_native_mapping(self):
        result, failures = mapping_result(mapping_fixture())
        self.assertEqual(failures, [])
        self.assertEqual(result["mapping"], "toggle_xor_1")
        self.assertEqual(result["linked_deliveries"], 90)

    def test_reverse_hardware_rejects_self_consistent_driver(self):
        result, failures = mapping_result(mapping_fixture(reverse=True))
        self.assertGreater(result["counts"]["contradictions"], 32)
        self.assertEqual(result["mapping"], "unproven")
        self.assertTrue(failures)

    def test_driver_claim_not_used_to_infer_region(self):
        data = mapping_fixture()
        for r in data[1]:
            r["completed_half"] = "99"
        self.assertEqual(mapping_result(data)[1], [])

    def test_repeated_source_ids_are_neutral(self):
        result, failures = mapping_result(mapping_fixture(repeats=True))
        self.assertEqual(failures, [])
        self.assertGreater(result["counts"]["unchanged"], 0)

    def test_static_content_cannot_prove_mapping(self):
        data = mapping_fixture()
        for p in data[0]:
            for i in range(4):
                p[f"code{i}"] = str(code(100))
        self.assertTrue(mapping_result(data)[1])

    def test_missing_probe_is_not_silent(self):
        data = mapping_fixture()
        del data[0][40]
        self.assertTrue(mapping_result(data)[1])

    def test_probe_cap_preserves_explicit_window(self):
        data = mapping_fixture(events=4100)
        del data[0][4096:]
        result, failures = mapping_result(data)
        self.assertEqual(failures, [])
        self.assertEqual(result["last_generation"], 4096)
        self.assertEqual(result["linked_deliveries"], 2048)

    def test_probe_cap_overflow_rejected(self):
        self.assertTrue(mapping_result(mapping_fixture(events=4097))[1])

    def test_torn_second_read_is_not_accepted(self):
        data = mapping_fixture()
        data[0][40]["code2"] = str(code(999))
        self.assertTrue(mapping_result(data)[1])

    def test_wrong_offset_and_sample_duration_fail(self):
        for key, value in (("offset0", "2072576"), ("duration_ns", "8000000"), ("status", "2")):
            with self.subTest(key=key):
                data = mapping_fixture()
                for p in data[0]:
                    p[key] = value
                self.assertTrue(mapping_result(data)[1])

    def test_delivery_substituted_id_fails(self):
        data = mapping_fixture()
        data[3][40]["upper_id"] = 999
        self.assertTrue(mapping_result(data)[1])

    def test_source_normal(self):
        records, frames = source_fixture()
        self.assertEqual(validate_source(records, frames, CONFIG, "boot")[1], [])

    def test_source_held_refresh_explains_repeat(self):
        records, frames = source_fixture(held=True)
        result, failures = validate_source(records, frames, CONFIG, "boot")
        self.assertEqual(failures, [])
        self.assertEqual(result["captured_repeats_supported_by_source"], 10)

    def test_excess_capture_repeat_fails(self):
        records, frames = source_fixture()
        frames.append(copy.deepcopy(frames[0]))
        result, failures = validate_source(records, frames, CONFIG, "boot")
        self.assertEqual(result["captured_repeats_exceeding_source"], 1)
        self.assertTrue(failures)

    def test_missing_source_fails(self):
        self.assertTrue(validate_source([], [], CONFIG, "boot")[1])

    def test_unknown_capture_clock_fails(self):
        records, frames = source_fixture()
        frames[0]["flags"] = 0
        self.assertTrue(validate_source(records, frames, CONFIG, "boot")[1])

    def test_zero_timing_fails_without_exception(self):
        invalid = dict(CONFIG, refresh_num="0")
        data = mapping_fixture()
        self.assertTrue(validate_mapping(*data, invalid, len(data[0]))[1])
        records, frames = source_fixture()
        self.assertTrue(validate_source(records, frames, invalid, "boot")[1])

    def test_browser_and_clock_mismatch_fail(self):
        records, frames = source_fixture()
        records[0]["backend"] = "browser-raf"
        self.assertTrue(validate_source(records, frames, CONFIG, "boot")[1])
        records[0]["backend"] = "drm-kms"
        self.assertTrue(validate_source(records, frames, CONFIG, "other-boot")[1])

    def test_source_sequence_and_time_disagree(self):
        records, frames = source_fixture()
        records[2]["sequence"] += 4
        self.assertTrue(validate_source(records, frames, CONFIG, "boot")[1])

    def test_missing_last_boundary_is_incomplete(self):
        records, frames = source_fixture()
        self.assertTrue(validate_source(records[:-1], frames, CONFIG, "boot")[1])


if __name__ == "__main__":
    unittest.main()
