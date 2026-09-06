#!/usr/bin/env python3
"""End-to-end validator fixtures. Trace decoding is mocked; no hardware claims."""
import copy
import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import hws_vdone_evidence as evidence
import hws_vdone_matrix as matrix
from hws_vdone_observers import PATTERN_VERSION, PROBE_READ_LIMIT
from test_vdone_observers import CONFIG, PERIOD, mapping_fixture


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hws-validator-test-")
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name)
        probes, irqs, deliveries, frames = mapping_fixture()
        for p in probes:
            p.update(window="0", position="0")
        copies = []
        for irq in irqs:
            irq.update(result="1")
            half = int(irq["completed_half"])
            copies.append(dict(irq, result="0", toggle=irq["after"],
                               toggle_before=irq["after"], toggle_after=irq["after"],
                               guard_checked="1", guard_ok="1", offset=str(2072576 if half else 0),
                               length=str(2074624 if half else 2072576), frame_complete=str(half)))
        for d in deliveries:
            d.update(no_buffer="0", dropped_partial="0")
        config = dict(CONFIG, pci_bdf="0000:05:00.0", vendor="0x8888", device="0x8504",
                      subsystem_vendor="0x8888", subsystem_device="0x0007", revision="1",
                      device_ver="1", hw_ver="1", sub_ver="1", port_id="0", irq="30", irq_mode="msi",
                      fourcc=str(0x56595559), fps="60", interlaced="0", dma_extent="4149248",
                      split16_cached="129536", split16_readback="129536")
        self.config = config
        stream = dict(width="1920", height="1080", fourcc=config["fourcc"], fps="60",
                      sizeimage="4147200", extent="4149248", split="2072576", split16="129536")
        self.trace = dict(probe=probes, irq=irqs, frame=deliveries, copy=copies, recovery=[], loss=[],
                          stream=[dict(stream, action="1"), dict(stream, action="0")])
        stats = dict(stream_epoch="1", streaming="0", cap_active="0", vdone_observed="180",
                     vdone_accepted="180", vdone_ignored="0", vdone_deferred="0", vdone_resynced="0",
                     vdone_recovered="0", vdone_fatal="0", completed_half0="90", completed_half1="90",
                     frames_completed="90", frames_delivered="90", frames_no_buffer="0", queue_failures="0",
                     ring_corrupt="0", guard_errors="0", recovery_reports="0", duplicate_reports="0",
                     overlap_reports="0", resync_reports="0", partial_recycles="0", probe_count="180",
                     probe_reads="180", probe_read_limit=str(PROBE_READ_LIMIT), anomaly_windows="0",
                     anomaly_records="0", anomaly_triggers="0", anomaly_suppressed="0", anomaly_window_limit="16")
        for name, kv in (("config-before", config), ("config-after", config),
                         ("stats-before", dict(stats, stream_epoch="0")), ("stats-after", stats)):
            (self.bundle/(name+".txt")).write_text("".join(f"{k}={v}\n" for k,v in kv.items()))
        self.manifest = dict(schema=3, channel=1, pci_bdf=config["pci_bdf"], tracked_status=[],
                             untracked_reproducible_inputs=[], target_frames=90, run_id="synthetic-fixture",
                             elapsed_seconds=9999, capture_exit_code=0, boot_id="boot",
                             kms_source_sha256="kms-source", pattern_sha256="pattern-source",
                             capture_source_sha256="capture-source", git_head="synthetic",
                             created_utc="2026-09-06T00:00:00+00:00")
        self.save_manifest()
        capture_config = dict(type="config", width=1920, height=1080, bytesperline=3840,
                              fourcc=int(config["fourcc"]), sizeimage=4147200, split=2072576,
                              pattern=PATTERN_VERSION, pattern_sha256="pattern-source",
                              capture_source_sha256="capture-source")
        for i, frame in enumerate(frames):
            frame.update(type="frame", capture_index=i, flags=0x2000, bytesused=4147200,
                         timestamp_ns=int(irqs[(i+1)*2-1]["timestamp_ns"]),
                         upper_valid=True, lower_valid=True, ids_match=True, monotonic=True,
                         sequence_ok=True, payload_ok=True, poison_half0=False, poison_half1=False,
                         content_checked_bytes=4147200, content_bad_bytes=0)
        self.capture = [capture_config, *frames, dict(type="summary", result="pass", captured=90,
                         submitted=90, outstanding=0, content_errors=0,
                         id_mismatches=0, backwards_ids=0, poison_errors=0)]
        self.save_capture()
        source_config = dict(type="source_config", schema=1, backend="drm-kms", clock="CLOCK_MONOTONIC",
                             boot_id="boot", async_flip=False, width=1920, height=1080,
                             htotal=2200, vtotal=1125, clock_khz=148500, source_sha256="kms-source",
                             pattern=PATTERN_VERSION, pattern_sha256="pattern-source")
        presents = []
        for i in range(100, 193):
            t = 1_000_000_000 + round((i-101)*PERIOD)
            presents.append(dict(type="present", id=i, sequence=i, submitted_ns=t-1_000_000,
                                 presented_ns=t, callback_ns=t+100_000))
        (self.bundle/"source-presentation.jsonl").write_text("".join(json.dumps(r)+"\n" for r in [source_config,*presents]))
        (self.bundle/"kernel.log").write_text("")
        (self.bundle/"kernel-trace.dat").write_bytes(b"synthetic fixture, not hardware evidence")
        (self.bundle/"trace-stat.txt").write_text("overrun: 0\ndropped events: 0\ncommit overrun: 0\n")

    def save_manifest(self):
        (self.bundle/"manifest.json").write_text(json.dumps(self.manifest))

    def save_capture(self):
        (self.bundle/"captured-frames.jsonl").write_text("".join(json.dumps(r)+"\n" for r in self.capture))

    def validate(self):
        with patch.object(evidence, "trace_records", return_value=copy.deepcopy(self.trace)):
            return evidence.validate_bundle(self.bundle)

    def test_complete_synthetic_bundle(self):
        summary = self.validate()
        self.assertEqual(summary["failures"], [])
        self.assertEqual(summary["schema"], 3)
        self.assertAlmostEqual(summary["vdone_rate_hz"], 120, places=5)
        self.assertLess(summary["vdone_timing"]["elapsed_seconds"], 2)

    def test_old_bundle_fails_closed(self):
        self.manifest["schema"] = 2
        self.save_manifest()
        self.assertIn("predates", " ".join(self.validate()["failures"]))

    def test_sparse_or_missing_content_cannot_validate(self):
        self.capture[1]["content_bad_bytes"] = 4_000_000
        self.save_capture()
        self.assertEqual(self.validate()["result"], "fail")
        del self.capture[1]["content_bad_bytes"]
        self.save_capture()
        self.assertEqual(self.validate()["result"], "fail")

    def test_last_delivery_must_be_examined(self):
        del self.capture[-2]
        self.save_capture()
        self.assertIn("delivered sequences lack content", " ".join(self.validate()["failures"]))

    def test_drained_queue_is_required(self):
        self.capture[-1].update(submitted=91, outstanding=1)
        self.save_capture()
        self.assertIn("fully drained", " ".join(self.validate()["failures"]))

    def test_trace_loss_remains_fatal(self):
        (self.bundle/"trace-stat.txt").write_text("overrun: 1\n")
        self.assertEqual(self.validate()["result"], "fail")

    def test_stale_capture_binary_rejected(self):
        self.capture[0]["capture_source_sha256"] = "older-binary"
        self.save_capture()
        self.assertIn("capture binary source digest", " ".join(self.validate()["failures"]))

    def test_multiple_or_nonterminal_summary_rejected(self):
        self.capture.append(copy.deepcopy(self.capture[-1]))
        self.save_capture()
        with self.assertRaises(evidence.EvidenceError):
            self.validate()

    def test_checksums_preserve_full_inventory(self):
        evidence.write_bundle_checksums(self.bundle)
        evidence.verify_bundle_checksums(self.bundle)
        (self.bundle/"unexpected.txt").write_text("not part of sealed evidence")
        with self.assertRaises(evidence.EvidenceError):
            evidence.verify_bundle_checksums(self.bundle)

    def test_summary_matches_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("optional jsonschema package is not installed")
        schema = json.loads((evidence.ROOT/"doc/evidence/vdone-result.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(json.loads(json.dumps(self.validate())), schema)

    def test_matrix_uses_irq_span_not_manifest_wall_time(self):
        evidence.write_bundle_checksums(self.bundle)
        args = SimpleNamespace(bundle=self.bundle, status="validated", evidence_id="SYNTHETIC",
                               source_commit="", artifact_uri="synthetic-not-hardware", notes="test only")
        with matrix.DEFAULT_MATRIX.open() as stream:
            header = next(csv.reader(stream))
        with patch.object(evidence, "trace_records", return_value=copy.deepcopy(self.trace)):
            row = dict(zip(header, matrix.make_row(args, header)))
        self.assertEqual(row["vdone_count"], "180")
        self.assertLess(float(row["elapsed_seconds"]), 2)
        self.assertAlmostEqual(float(row["vdone_rate_hz"]), 120, places=5)
        self.assertIn("rate_intervals=179", row["notes"])


if __name__ == "__main__":
    unittest.main()
