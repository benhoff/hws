"""Synthetic attribution fixtures; no hardware or physical IRQ claims."""
import unittest

from hws_vdone_diagnostics import diagnose, START, STOP, EMPTY, COMPLETE, IRQ, WORK
from hws_vdone_evidence import parser, capture_trace_events, require_vblank_off, EvidenceError


def diag(action, generation, stamp, **extra):
    return dict(action=action, generation=generation, timestamp_ns=stamp,
                buffer=0xffffffff, active=0xffffffff, queued=0, value1=0, value2=0, **extra)


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.trace = dict(irq=[], recovery=[], loss=[], frame=[
            dict(no_buffer=1, half1_generation=4, sequence=1),
            dict(no_buffer=1, half1_generation=10, sequence=4)], diag=[
                diag(START, 0, 10), diag(COMPLETE, 2, 20), diag(EMPTY, 3, 30),
                diag(COMPLETE, 6, 50), diag(COMPLETE, 8, 80), diag(EMPTY, 9, 90), diag(STOP, 10, 100)])
        self.events = [dict(type="config", schema=1, clock="CLOCK_MONOTONIC", limit=8192)]
        submitted = dequeued = 0
        for action, stamp in (("qbuf", 1), ("dqbuf", 25), ("qbuf", 40),
                              ("dqbuf", 55), ("qbuf", 60), ("dqbuf", 85)):
            submitted += action == "qbuf"
            dequeued += action == "dqbuf"
            self.events.append(dict(type="queue", action=action, buffer=0,
                               started_ns=stamp, ioctl_ns=stamp, ended_ns=stamp,
                               result=0, submitted=submitted, dequeued=dequeued))
        self.events.append(dict(type="summary", records=6, suppressed=0))
        self.stats = dict(diag_records=7, diag_suppressed=0, diag_limit=32768)

    def run_diagnosis(self):
        self.stats["diag_records"] = len(self.trace["diag"])
        return diagnose(self.trace, self.events, self.stats, 3)

    def test_midstream_and_intentional_tail_are_distinct(self):
        result = self.run_diagnosis()
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["drop_counts"], {"queue_empty_midstream": 1, "after_final_delivery": 1})

    def test_recovery_orphan_is_not_queue_starvation(self):
        self.trace["diag"] = [r for r in self.trace["diag"] if r["generation"] != 3]
        self.trace["recovery"] = [dict(generation=3, reason=2, interval_us=8300, dropped_partial=1)]
        result = self.run_diagnosis()
        self.assertEqual(result["drops"][0]["classification"], "orphan_half_after_recovery")
        self.assertIn("unresolved", result["recoveries"][0]["attribution"])

    def test_budget_draining_before_last_delivery(self):
        for r in self.trace["diag"]:
            if r["generation"] == 9:
                r["timestamp_ns"] = 70
        self.trace["diag"].sort(key=lambda r: r["timestamp_ns"])
        self.assertEqual(self.run_diagnosis()["drops"][1]["classification"], "queue_empty_budget_draining")

    def test_continuity_recovery_is_explicit_not_physical_attribution(self):
        self.trace["recovery"] = [dict(generation=3, reason=6, interval_us=25000,
                                      dropped_partial=1)]
        row = self.run_diagnosis()["recoveries"][0]
        self.assertEqual(row["reason"], 6)
        self.assertIn("continuity rejected", row["attribution"])
        self.assertIn("unresolved", row["attribution"])

    def test_loss_and_caps_remove_classification(self):
        for kind in ("kernel", "user", "trace"):
            with self.subTest(kind=kind):
                if kind == "kernel": self.stats["diag_suppressed"] = 1
                if kind == "user": self.events[-1]["suppressed"] = 1
                if kind == "trace": self.trace["loss"] = [{"line": "lost event"}]
                result = self.run_diagnosis()
                self.assertEqual(result["evidence_status"], "inconclusive")
                self.assertEqual(result["drop_counts"], {"unresolved": 2})

    def test_counter_corruption_or_wrong_clock_is_inconclusive(self):
        self.events[1]["submitted"] = 99
        self.events[0]["clock"] = "CLOCK_REALTIME"
        self.assertEqual(self.run_diagnosis()["drop_counts"], {"unresolved": 2})

    def test_incomplete_shutdown_is_inconclusive(self):
        self.trace["diag"].pop()
        self.assertEqual(self.run_diagnosis()["evidence_status"], "inconclusive")

    def test_irq_and_worker_intervals(self):
        irq = diag(IRQ, 1, 12)
        irq.update(value1=2, value2=8)
        work = diag(WORK, 1, 15)
        work.update(value1=5)
        self.trace["diag"].extend([irq, work])
        self.trace["diag"].sort(key=lambda r: r["timestamp_ns"])
        result = self.run_diagnosis()
        self.assertEqual(result["timing"]["irq_entry_to_ack"]["max_ns"], 6)
        self.assertEqual(result["timing"]["irq_observation_to_worker"]["max_ns"], 10)
        irq["value2"] = 0
        self.assertEqual(self.run_diagnosis()["evidence_status"], "inconclusive")

    def test_profile_defaults_and_comparison_are_explicit(self):
        normal = parser().parse_args([])
        self.assertEqual(normal.buffers, 4)
        self.assertIn("hws:hws_vdone_probe", capture_trace_events(normal))
        self.assertNotIn("hws:hws_video_diag", capture_trace_events(normal))
        full = parser().parse_args(["--buffers", "16", "--queue-diagnostics"])
        self.assertIn("hws:hws_video_diag", capture_trace_events(full))
        minimal = parser().parse_args(["--probe-mode", "off"])
        self.assertNotIn("hws:hws_vdone_probe", capture_trace_events(minimal))
        self.assertIn("hws:hws_vdone_irq", capture_trace_events(minimal))

    def test_malformed_record_fails_closed(self):
        del self.trace["diag"][0]["action"]
        self.assertEqual(self.run_diagnosis()["evidence_status"], "inconclusive")

    def test_cpu_and_wall_time_are_separate(self):
        self.events[0]["processing_cpu_clock"] = "CLOCK_THREAD_CPUTIME_ID"
        self.events[3]["processing_cpu_ns"] = 6
        self.events[5]["processing_cpu_ns"] = 2
        result = self.run_diagnosis()
        self.assertEqual(result["evidence_status"], "complete")
        self.assertEqual(result["timing"]["userspace_processing_cpu"]["max_ns"], 6)
        self.assertEqual(result["timing"]["userspace_processing_non_cpu"]["max_ns"], 9)
        self.events[3]["processing_cpu_ns"] = 16
        self.assertEqual(self.run_diagnosis()["drop_counts"], {"unresolved": 2})

    def test_missing_cpu_clock_is_not_treated_as_zero_work(self):
        self.events[3]["processing_cpu_ns"] = -1
        self.assertEqual(self.run_diagnosis()["evidence_status"], "inconclusive")

    def test_unscheduled_delay_is_invalid_not_a_causal_claim(self):
        self.events.insert(3, dict(type="queue", action="requeue_delay", buffer=0,
                                  started_ns=26, ioctl_ns=26, ended_ns=39,
                                  result=0, submitted=1, dequeued=1))
        self.events[-1]["records"] += 1
        result = self.run_diagnosis()
        self.assertEqual(result["evidence_status"], "inconclusive")
        self.assertEqual(result["injected_delay"]["overlapping_empty_generations"], [])

    def test_vblank_off_requires_actual_disabled_value(self):
        require_vblank_off("N")
        for value in ("Y", "", "unavailable", "0", "nvidia_drm.vblank=0"):
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                require_vblank_off(value)

    def test_delay_and_guard_are_opt_in(self):
        normal = parser().parse_args([])
        self.assertEqual(normal.requeue_delay_ms, 0)
        self.assertFalse(normal.require_vblank_off)
        delayed = parser().parse_args(["--queue-diagnostics", "--requeue-delay-ms", "80",
                                       "--require-vblank-off"])
        self.assertEqual(delayed.requeue_delay_ms, 80)
        self.assertTrue(delayed.require_vblank_off)
        self.assertIn("hws:hws_vdone_probe", capture_trace_events(delayed))

    def test_complete_delay_intervention_and_missing_event(self):
        self.events[0].update(requeue_delay_ms=80, requeue_delay_every_frames=60)
        records = [self.events[0]]
        stamp = 1
        for index in range(61):
            for action in ("qbuf", "dqbuf"):
                records.append(dict(type="queue", action=action, buffer=0,
                                    started_ns=stamp, ioctl_ns=stamp, ended_ns=stamp,
                                    result=0, submitted=index+1, dequeued=index+(action == "dqbuf")))
                stamp += 1
            if index == 59:
                records.append(dict(type="queue", action="requeue_delay", buffer=0,
                                    started_ns=stamp, ioctl_ns=stamp, ended_ns=stamp+80000000,
                                    result=0, submitted=60, dequeued=60))
                stamp += 80000001
        records.append(dict(type="summary", records=len(records)-1, suppressed=0))
        trace = dict(irq=[], recovery=[], loss=[], frame=[], diag=[
            diag(START, 0, 1), diag(EMPTY, 120, 1000), diag(STOP, 122, stamp+1)])
        stats = dict(diag_records=3, diag_suppressed=0, diag_limit=32768)
        result = diagnose(trace, records, stats, 61)
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["injected_delay"]["overlapping_empty_generations"], [120])
        self.assertIn("correlation only", result["limits"])
        records[:] = [e for e in records if e.get("action") != "requeue_delay"]
        records[-1]["records"] -= 1
        self.assertEqual(diagnose(trace, records, stats, 61)["evidence_status"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
