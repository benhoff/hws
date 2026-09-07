"""Hardware-free tests for the all-tests runner and scoped result reporting."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("hws_test_report", HERE / "hws-test-report.py")
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


class TransportReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "capture.log"
        self.before = self.root / "before.txt"
        self.after = self.root / "after.txt"
        self.log.write_text("<<<< 60.00 fps\n")
        self.before.write_text("stream_epoch=1\nguard_errors=0\n")
        self.stats = dict(stream_epoch=2, streaming=0, cap_active=0, vdone_fatal=0,
                          queue_failures=0, ring_corrupt=0, guard_errors=0,
                          frames_completed=4, frames_delivered=4, frames_no_buffer=0,
                          vdone_recovered=0, vdone_deferred=0, vdone_resynced=0)

    def check(self):
        self.after.write_text("".join(f"{k}={v}\n" for k, v in self.stats.items()))
        return report.transport(self.log, 4, self.before, self.after)

    def test_complete_transport(self):
        self.assertEqual(self.check()[0], 0)

    def test_drops_are_not_silent_success(self):
        self.log.write_text("<<<< 59.75 fps, dropped buffers: 1\n")
        self.assertEqual(self.check()[0], 3)

    def test_recovery_is_not_silent_success(self):
        self.stats["vdone_recovered"] = 1
        self.assertEqual(self.check()[0], 3)

    def test_continuity_recovery_is_not_silent_success(self):
        self.stats.update(continuity_gaps=1, continuity_reports=1)
        status, note = self.check()
        self.assertEqual(status, 3)
        self.assertIn("continuity_gaps=1", note)
        self.stats["continuity_reports"] = 0
        self.assertEqual(self.check()[0], 1)
        del self.stats["continuity_reports"]
        self.assertEqual(self.check()[0], 2)

    def test_guard_failure(self):
        self.stats["guard_errors"] = 1
        self.assertEqual(self.check()[0], 1)

    def test_fatal_queue_and_unstopped_stream(self):
        for field in ("vdone_fatal", "queue_failures", "ring_corrupt", "streaming", "cap_active"):
            with self.subTest(field=field):
                self.stats[field] = 1
                self.assertEqual(self.check()[0], 1)
                self.stats[field] = 0

    def test_missing_snapshots_are_inconclusive(self):
        self.before.unlink()
        self.assertEqual(self.check()[0], 2)

    def test_missing_frames_fail_even_without_snapshots(self):
        self.before.unlink()
        self.log.write_text("<<<")
        self.assertEqual(self.check()[0], 1)

    def test_bad_epoch_or_accounting_fails(self):
        self.stats["stream_epoch"] = 3
        self.assertEqual(self.check()[0], 1)
        self.stats["stream_epoch"] = 2
        self.stats["frames_completed"] = 5
        self.assertEqual(self.check()[0], 1)

    def test_nonzero_capture_exit_overrides_good_log(self):
        self.check()
        result = subprocess.run(["python3", str(HERE / "hws-test-report.py"), "transport",
                                 str(self.log), "4", str(self.before), str(self.after), "124"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)


class RunnerCliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(["bash", str(HERE / "hws-test-all.sh"), *args],
                              capture_output=True, text=True)

    def test_help_has_no_hardware_effects(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--with-pattern", result.stdout)

    def test_unknown_option_rejected(self):
        self.assertEqual(self.run_cli("--unknown").returncode, 2)

    def test_conflicting_options_rejected(self):
        for option in ("--no-sudo", "--software-only"):
            self.assertEqual(self.run_cli("--with-pattern", option).returncode, 2)

    def test_quick_cannot_shorten_strict_pattern_validation(self):
        result = subprocess.run(["bash", str(HERE / "hws-nvidia-validation.sh"), "--quick"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--quick requires --content-only", result.stderr)

    def test_help_describes_short_pattern_run(self):
        result = self.run_cli("--help")
        self.assertIn("pattern calibration only (1,000 frames)", result.stdout)

    def test_comparison_cannot_run_without_privileges(self):
        self.assertEqual(self.run_cli("--compare-drops", "--no-sudo").returncode, 2)

    def test_latency_comparison_must_be_separate(self):
        self.assertEqual(self.run_cli("--compare-drops", "--irq-latency").returncode, 2)

    def test_starvation_is_separate_and_requires_hardware_privileges(self):
        for flag in ("--compare-drops", "--irq-latency", "--software-only", "--no-sudo"):
            with self.subTest(flag=flag):
                self.assertEqual(self.run_cli("--test-starvation", flag).returncode, 2)

    def test_guard_cannot_skip_authentication(self):
        for flag in ("--software-only", "--no-sudo"):
            self.assertEqual(self.run_cli("--require-vblank-off", flag).returncode, 2)

    def test_launcher_rejects_confounded_comparisons_before_authentication(self):
        for flag in ("--compare-drops", "--irq-latency"):
            result = subprocess.run(["bash", str(HERE / "hws-nvidia-validation.sh"),
                                     "--content-only", "--test-starvation", flag],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("separately", result.stderr)

    def test_vblank_guard_accepts_only_loaded_off_value(self):
        for value in ("N", "Y", "", "unavailable"):
            result = subprocess.run(["python3", str(HERE / "hws-test-report.py"),
                                     "vblank-off", value], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0 if value == "N" else 2)

    def test_capture_delay_bounds_and_required_diagnostics(self):
        capture = HERE.parent / "tools/hws_frame_id_capture"
        for args in (("--requeue-delay-ms", "80"),
                     ("--requeue-delay-ms", "101", "--queue-log", "unused"),
                     ("--requeue-delay-ms", "-1", "--queue-log", "unused")):
            result = subprocess.run([str(capture), "--self-test", *args], capture_output=True)
            self.assertEqual(result.returncode, 2)
        result = subprocess.run([str(capture), "--self-test", "--requeue-delay-ms", "80",
                                 "--queue-log", "unused"], capture_output=True)
        self.assertEqual(result.returncode, 0)


class ComparisonReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name)
        self.manifest = dict(buffers_requested=4, probe_mode="full", queue_diagnostics=True,
                             capture_exit_code=0, requeue_delay_ms=80, require_vblank_off=True,
                             nvidia_vblank="N")
        self.summary = dict(vdone_timing=dict(elapsed_seconds=17), captured_frames=1000,
                            result="fail", capture_checks=dict(result="pass"),
                            frame_id_summary=dict(result="pass"))
        self.diagnostic = dict(evidence_status="complete", injected_delay=dict(
            count=16, requested_ms=80, duration=dict(min_ns=80000000)))
        for name in ("stats-before.txt", "stats-after.txt"):
            (self.bundle / name).write_text("vdone_recovered=1\nframes_no_buffer=1\n"
                                           "vdone_fatal=0\nqueue_failures=0\nring_corrupt=0\nguard_errors=0\n")
        (self.bundle / "trace-stat.txt").write_text("overrun: 0\ndropped events: 0\ncommit overrun: 0\n")

    def check(self):
        for name, data in (("manifest", self.manifest), ("summary", self.summary),
                           ("diagnostics", self.diagnostic)):
            (self.bundle / f"{name}.json").write_text(json.dumps(data))
        output = io.StringIO()
        with patch.object(report, "verify_bundle_checksums") as verify, contextlib.redirect_stdout(output):
            result = report.comparison_row(self.bundle)
        verify.assert_called_once_with(self.bundle)
        return result, json.loads(output.getvalue())

    def test_full_checks_and_metadata_preserved(self):
        status, row = self.check()
        self.assertEqual(status, 0)
        self.assertEqual(row["strict"], "fail")
        self.assertEqual(row["collection_status"], "diagnostic_only")
        self.assertEqual(row["requeue_delay_ms"], 80)
        self.assertEqual(row["nvidia_vblank"], "N")

    def test_missing_or_short_injection_fails(self):
        self.diagnostic["injected_delay"]["count"] = 0
        self.assertEqual(self.check()[0], 1)
        self.diagnostic["injected_delay"]["count"] = 16
        self.diagnostic["injected_delay"]["duration"]["min_ns"] = 79999999
        self.assertEqual(self.check()[0], 1)

    def test_incomplete_baseline_fails(self):
        self.manifest["requeue_delay_ms"] = 0
        self.diagnostic["evidence_status"] = "inconclusive"
        self.assertEqual(self.check()[0], 1)

    def test_wrong_loaded_vblank_or_content_failure_fails(self):
        self.manifest["nvidia_vblank"] = "Y"
        self.assertEqual(self.check()[0], 1)
        self.manifest["nvidia_vblank"] = "N"
        self.summary["capture_checks"]["result"] = "fail"
        self.assertEqual(self.check()[0], 1)


class PatternGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name)
        self.summary = dict(result="fail", capture_checks=dict(result="pass", failures=[]),
                            source_presentation=dict(result="fail"),
                            provenance=dict(result="fail"), anomaly_observation=dict(result="pass"))

    def check(self):
        (self.bundle / "summary.json").write_text(json.dumps(self.summary))
        with patch.object(report, "verify_bundle_checksums") as verify:
            result = report.pattern_gate(self.bundle)
        verify.assert_called_once_with(self.bundle)
        return result

    def test_diagnostic_success_preserves_strict_failure(self):
        status, note = self.check()
        self.assertEqual(status, 0)
        self.assertIn("strict=fail", note)
        self.assertIn("presentation=fail", note)
        self.assertIn("provenance=fail", note)

    def test_late_observation_never_becomes_capture_or_timing_proof(self):
        (self.bundle / "diagnostics.json").write_text(json.dumps(dict(
            evidence_status="complete", drop_counts={}, late_toggle=dict(
                evidence_status="complete", counts={"toggle_changed_without_sampled_vdone":1}))))
        status, note = self.check()
        self.assertEqual(status, 0)
        self.assertIn("late_toggle=complete",note)
        self.assertIn("toggle_changed_without_sampled_vdone",note)
        self.assertIn("strict=fail",note)
        self.summary["capture_checks"] = dict(result="fail",failures=["mixed frame"])
        self.assertEqual(self.check()[0],1)

    def test_capture_failure_stops_progress(self):
        self.summary["capture_checks"] = dict(result="fail", failures=["guard failure"])
        self.assertEqual(self.check()[0], 1)

    def test_inconsistent_success_is_rejected(self):
        self.summary["capture_checks"]["failures"] = ["trace loss"]
        self.assertEqual(self.check()[0], 1)


if __name__ == "__main__":
    unittest.main()
