#!/usr/bin/env python3
"""Scoped diagnostic verdicts; never a universal driver-correctness claim."""
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from hws_vdone_evidence import EvidenceError, verify_bundle_checksums, trace_loss


def read_stats(path):
    return dict(line.split("=", 1) for line in Path(path).read_text().splitlines()
                if "=" in line)


def transport(log, target, before_path, after_path):
    output = Path(log).read_text()
    completed = output.count("<")
    drops = sum(map(int, re.findall(r"dropped buffers: (\d+)", output)))
    notes = [f"received={completed}/{target}", f"reported_drops={drops}"]
    if completed != target or re.search(r"\b(?:failed|error)\b", output, re.I):
        return 1, "; ".join(notes + ["capture output/count failure; inspect log"])
    try:
        before, after = read_stats(before_path), read_stats(after_path)
        fields = ("stream_epoch", "streaming", "cap_active", "vdone_fatal",
                  "queue_failures", "ring_corrupt", "guard_errors",
                  "frames_completed", "frames_delivered", "frames_no_buffer",
                  "vdone_recovered", "vdone_deferred", "vdone_resynced")
        a = {k: int(after[k], 0) for k in fields}
        continuity_fields = ("continuity_gaps", "continuity_reports")
        if any(k in after for k in continuity_fields):
            a.update({k: int(after[k], 0) for k in continuity_fields})
        b = {k: int(before[k], 0) for k in ("stream_epoch", "guard_errors")}
        if any(value < 0 for value in (*a.values(), *b.values())):
            raise ValueError("negative counter")
    except (OSError, KeyError, ValueError):
        return 2, "; ".join(notes + ["driver snapshots unavailable/incomplete"])
    bad = [k for k in ("streaming", "cap_active", "vdone_fatal", "queue_failures",
                       "ring_corrupt") if a[k] != 0]
    if a["guard_errors"] != b["guard_errors"]:
        bad.append("guard_errors changed")
    if a["stream_epoch"] != b["stream_epoch"] + 1:
        bad.append("unexpected stream epoch")
    if a["frames_delivered"] < target:
        bad.append("insufficient driver deliveries")
    if a["frames_completed"] != a["frames_delivered"] + a["frames_no_buffer"]:
        bad.append("inconsistent frame accounting")
    if "continuity_gaps" in a:
        notes.append(f"continuity_gaps={a['continuity_gaps']}")
        if a["continuity_gaps"] != a["continuity_reports"]:
            bad.append("inconsistent continuity accounting")
    notes += [f"{k}={a[k]}" for k in ("frames_no_buffer", "vdone_recovered",
              "vdone_deferred", "vdone_resynced", "vdone_fatal", "queue_failures")]
    if bad:
        return 1, "; ".join(notes + bad)
    warning = drops or a.get("continuity_gaps", 0) or any(a[k] for k in ("frames_no_buffer", "vdone_recovered",
                                         "vdone_deferred", "vdone_resynced"))
    return (3 if warning else 0), "; ".join(notes)


def pattern_gate(bundle):
    bundle = Path(bundle)
    verify_bundle_checksums(bundle)
    summary = json.loads((bundle / "summary.json").read_text())
    scope = summary["capture_checks"]
    if scope["result"] != "pass" or scope["failures"]:
        return 1, "capture checks failed: " + "; ".join(scope["failures"])
    diagnostic_note = ""
    if (bundle / "diagnostics.json").exists():
        diagnosis = json.loads((bundle / "diagnostics.json").read_text())
        diagnostic_note = (f"; queue_evidence={diagnosis['evidence_status']}"
                           f"; drop_classes={diagnosis['drop_counts']}")
        late = diagnosis.get("late_toggle", {})
        if late:
            diagnostic_note += (f"; late_toggle={late['evidence_status']}"
                                f"; late_classes={late['counts']}")
    # Do not infer source/provenance success from the capture-only verdict.
    return 0, (f"capture_checks=pass; strict={summary['result']}; "
               f"presentation={summary['source_presentation']['result']}; "
               f"provenance={summary['provenance']['result']}; "
               f"anomaly_evidence={summary['anomaly_observation'].get('result', 'unknown')}" + diagnostic_note)


def comparison_row(bundle):
    bundle = Path(bundle)
    verify_bundle_checksums(bundle)
    summary = json.loads((bundle / "summary.json").read_text())
    manifest = json.loads((bundle / "manifest.json").read_text())
    stats = read_stats(bundle / "stats-after.txt")
    before = read_stats(bundle / "stats-before.txt")
    duration = summary["vdone_timing"]["elapsed_seconds"]
    diagnosis = bundle / "diagnostics.json"
    diagnostic = json.loads(diagnosis.read_text()) if diagnosis.exists() else None
    row = dict(run=bundle.name, buffers=manifest["buffers_requested"],
               requeue_delay_ms=manifest.get("requeue_delay_ms", 0),
               nvidia_vblank=manifest.get("nvidia_vblank", "unrecorded"),
               late_toggle_probe=manifest.get("late_toggle_probe", "unrecorded"),
               source_transition_checks=manifest.get("source_transition_checks", "unrecorded"),
               require_vblank_off=manifest.get("require_vblank_off", False),
               kernel=manifest.get("kernel"), boot_id=manifest.get("boot_id"),
               probe_mode=manifest["probe_mode"], queue_diagnostics=manifest["queue_diagnostics"],
               irq_seconds=duration, captured=summary["captured_frames"],
               recoveries=int(stats["vdone_recovered"]), no_buffer=int(stats["frames_no_buffer"]),
               recoveries_per_second=int(stats["vdone_recovered"])/duration if duration else None,
               strict=summary["result"], capture_checks=summary["capture_checks"]["result"],
               diagnostic=diagnostic)
    # Worker-level continuity rejections are separate from IRQ dispositions.
    if any(k in stats for k in ("continuity_gaps", "continuity_reports")):
        gaps, reports = (int(stats[k]) for k in ("continuity_gaps", "continuity_reports"))
        if gaps < 0 or gaps != reports:
            raise ValueError("inconsistent continuity accounting")
        row.update(continuity_gaps=gaps,
                   continuity_gaps_per_second=gaps/duration if duration else None)
    # Minimal observations deliberately cannot pass the independent mapping
    # gate. Do not relabel that bundle as passing or certify driver safety here.
    bad = bool(manifest["capture_exit_code"] or summary["frame_id_summary"]["result"] != "pass")
    bad |= any(int(stats[k]) for k in ("vdone_fatal", "queue_failures", "ring_corrupt"))
    bad |= int(stats["guard_errors"]) != int(before["guard_errors"])
    bad |= bool(trace_loss((bundle / "trace-stat.txt").read_text()))
    if manifest["probe_mode"] == "full":
        bad |= summary["capture_checks"]["result"] != "pass"
    if manifest["queue_diagnostics"]:
        bad |= not diagnostic or diagnostic.get("evidence_status") != "complete"
        if diagnostic:
            bad |= diagnostic.get("injected_delay", {}).get("requested_ms", 0) != manifest.get("requeue_delay_ms", 0)
    if manifest.get("require_vblank_off"):
        bad |= manifest.get("nvidia_vblank") != "N"
    if manifest.get("requeue_delay_ms"):
        # An unobserved/capped intervention must not masquerade as a comparison.
        bad |= not diagnostic or diagnostic.get("evidence_status") != "complete"
        if diagnostic:
            injections = diagnostic.get("injected_delay", {})
            bad |= not injections.get("count")
            minimum = injections.get("duration", {}).get("min_ns")
            bad |= minimum is None or minimum < manifest["requeue_delay_ms"] * 1000000
    row["collection_status"] = "failure" if bad else "diagnostic_only"
    print(json.dumps(row))
    return 1 if bad else 0


def main():
    try:
        if len(sys.argv) == 7 and sys.argv[1] == "transport":
            status, note = transport(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5])
            # The final argument is the capture process status, not inferred from text.
            if int(sys.argv[6]) != 0:
                status, note = 1, f"capture exit={sys.argv[6]}; " + note
        elif len(sys.argv) == 3 and sys.argv[1] == "pattern-gate":
            status, note = pattern_gate(sys.argv[2])
        elif len(sys.argv) == 3 and sys.argv[1] == "comparison-row":
            return comparison_row(sys.argv[2])
        elif len(sys.argv) == 3 and sys.argv[1] == "vblank-off":
            from hws_vdone_evidence import require_vblank_off
            require_vblank_off(sys.argv[2])
            status, note = 0, 'Loaded NVIDIA vblank=N; no module parameters changed'
        else:
            raise ValueError("expected transport LOG TARGET BEFORE AFTER EXIT or pattern-gate BUNDLE")
        print(note)
        return status
    except (EvidenceError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"Evidence unavailable or invalid: {error}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
