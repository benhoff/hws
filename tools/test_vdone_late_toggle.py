"""Bounded late-toggle observation, never a completion/cause qualification."""
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hws_vdone_diagnostics import diagnose_late_toggle
from hws_vdone_evidence import trace_records, capture_trace_events, parser


class LateToggleTests(unittest.TestCase):
    def setUp(self):
        identity = dict(device="0000:17:00.0", ch=3, epoch=22, generation=10)
        self.record = dict(identity, window=1, count=4, flags=0, baseline=1,
            irq_ns=9000, started_ns=10000, finished_ns=18000,
            start="10000,12000,14000,16000", end="11000,13000,15000,17000",
            toggle="0x81,0x80,0x80,0x80", status="0,0,0,0")
        self.trace = dict(late_toggle=[self.record], loss=[],
            irq=[dict(identity, timestamp_ns=9000, previous=1, after=1, stable=1, reasserted=0)],
            recovery=[dict(identity, reason=2, toggle=1)])
        self.stats = dict(late_toggle_windows=1, late_toggle_samples=4,
            late_toggle_suppressed=0, late_toggle_budget_exits=0, late_toggle_max_ns=8000)

    def report(self):
        return diagnose_late_toggle(self.trace,self.stats,"Y")

    def test_observed_change_is_not_a_causal_or_safety_claim(self):
        result = self.report()
        self.assertEqual(result["evidence_status"], "complete")
        self.assertEqual(result["counts"], {"toggle_changed_without_sampled_vdone":1})
        self.assertEqual(result["windows"][0]["first_change_read_window_after_irq_ns"], [3000,4000])
        self.assertEqual(result["windows"][0]["samples"][0]["raw_toggle"], 0x81)
        self.assertIn("does not prove safe",result["limits"])

    def test_no_change_is_only_a_short_observation(self):
        self.record["toggle"] = "1,1,1,1"
        self.assertEqual(self.report()["counts"], {"no_toggle_change_observed":1})

    def test_status_reassertion_makes_new_boundary_possible(self):
        self.record["status"] = "0,0x8,0,0"
        self.assertEqual(self.report()["counts"], {"status_reasserted_in_window":1})
        self.record["status"] = "0,0x2,0,0" # peer's interrupt is not this channel's VDONE
        self.assertEqual(self.report()["counts"], {"toggle_changed_without_sampled_vdone":1})

    def test_disabled_absent_and_no_duplicates_are_not_success(self):
        self.assertEqual(diagnose_late_toggle({}, {})["evidence_status"], "unavailable")
        zero = {k:0 for k in self.stats}
        self.assertEqual(diagnose_late_toggle({},zero,"N")["evidence_status"],"not_observed")
        self.assertEqual(diagnose_late_toggle({},zero,"Y")["evidence_status"],"not_observed")
        self.assertEqual(diagnose_late_toggle(self.trace,self.stats,"N")["evidence_status"],"inconclusive")

    def test_caps_preserve_samples_but_report_incomplete_coverage(self):
        self.trace["late_toggle"] = []
        base_irq=self.trace["irq"][0]; base_rec=self.trace["recovery"][0]
        self.trace["irq"]=[]; self.trace["recovery"]=[]
        for i in range(16):
            self.trace["late_toggle"].append(dict(self.record,generation=10+i,window=1+i))
            self.trace["irq"].append(dict(base_irq,generation=10+i))
            self.trace["recovery"].append(dict(base_rec,generation=10+i))
        self.stats.update(late_toggle_windows=16,late_toggle_samples=64,late_toggle_suppressed=3)
        self.assertEqual(self.report()["evidence_status"],"capped")

    def test_loss_missing_record_and_counter_corruption_fail_closed(self):
        for change in ("loss","missing","samples","max","generation","device","epoch","duplicate"):
            with self.subTest(change=change):
                self.setUp()
                if change=="loss": self.trace["loss"]=[{"line":"LOST 1 EVENTS"}]
                if change=="missing": self.trace["late_toggle"]=[]
                if change=="samples": self.stats["late_toggle_samples"]=3
                if change=="max": self.stats["late_toggle_max_ns"]=1
                if change=="generation": self.record["generation"]=11
                if change=="device": self.record["device"]="wrong"
                if change=="epoch": self.record["epoch"]=23
                if change=="duplicate": self.trace["irq"] *= 2
                result=self.report()
                self.assertEqual(result["evidence_status"],"inconclusive")
                self.assertFalse(any(r["first_change_read_window_after_irq_ns"] for r in result["windows"]))

    def test_incomplete_and_fault_windows_cannot_explain_a_toggle(self):
        for flags in (1,2,4,8):
            with self.subTest(flags=flags):
                self.setUp(); self.record.update(flags=flags,count=0)
                self.stats.update(late_toggle_samples=0,late_toggle_budget_exits=int(flags==1))
                self.assertEqual(self.report()["counts"], {"incomplete_window":1})
        self.setUp(); self.record["status"]="0xffffffff,0,0,0"
        self.assertEqual(self.report()["evidence_status"],"inconclusive")
        self.record["flags"]=4
        self.assertEqual(self.report()["counts"], {"incomplete_window":1})

    def test_time_budget_is_soft_but_cannot_start_another_sample_after_it(self):
        self.record.update(flags=1,count=1,end="90000,0,0,0",finished_ns=90000)
        self.stats.update(late_toggle_samples=1,late_toggle_budget_exits=1,late_toggle_max_ns=80000)
        self.assertEqual(self.report()["evidence_status"],"complete")
        self.record.update(count=2,start="10000,90000,0,0",end="90000,91000,0,0",finished_ns=91000)
        self.stats.update(late_toggle_samples=2,late_toggle_max_ns=81000)
        self.assertEqual(self.report()["evidence_status"],"inconclusive")

    def test_malformed_fields_and_reordered_timestamps(self):
        for field,value in (("count",5),("flags",16),("start","3,2,1,0"),
                            ("toggle","1,0"),("toggle",None),("baseline",3)):
            with self.subTest(field=field):
                self.setUp(); self.record[field]=value
                self.assertEqual(self.report()["evidence_status"],"inconclusive")

    def test_trace_parser_preserves_arrays_and_filters_device_epoch_channel(self):
        lines=[]
        for updates in ({},{"device":"wrong"},{"epoch":21},{"ch":2}):
            row=dict(self.record,**updates)
            lines.append("hws_vdone_late_toggle: "+" ".join(f"{k}={v}" for k,v in row.items())+"\n")
        fake=SimpleNamespace(stdout=io.StringIO("".join(lines)),returncode=0,communicate=lambda: (None,""))
        with patch("hws_vdone_evidence.subprocess.Popen",return_value=fake):
            records=trace_records(Path("unused"),3,22,"0000:17:00.0")
        self.assertEqual(len(records["late_toggle"]),1)
        self.assertEqual(records["late_toggle"][0]["toggle"],self.record["toggle"])
        self.assertIn("hws:hws_vdone_late_toggle",capture_trace_events(parser().parse_args([])))


if __name__ == '__main__':
    unittest.main()
