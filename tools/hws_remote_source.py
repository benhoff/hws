#!/usr/bin/env python3
"""Coordinate Intel KMS source, continuous clock mapping and remote HWS capture.

Run from the laptop's desktop terminal. --run explicitly permits a temporary
VT/display takeover; sudo authenticates in that terminal. The remote capture
runner asks for its own sudo authentication over an interactive SSH terminal.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time
import uuid

from hws_clock_mapping import read_records, ClockMap, ClockError

ROOT = Path(__file__).resolve().parents[1]

CAPTURE_BOOTSTRAP = '''import sys,subprocess,time,os
from pathlib import Path
d=Path(sys.argv[1]); command=sys.argv[2:]
subprocess.run(command+["--preflight-only"],check=True)
(d/"auth-ready").write_text("ready\\n")
deadline=time.monotonic()+120
while not (d/"source-ready").exists():
 if time.monotonic()>deadline: raise SystemExit("Source startup timed out")
 time.sleep(.1)
os.execvp(command[0],command)
'''

# Root helper owns the source process and the VT restoration. A closed parent
# pipe, signal, source failure or deadline stops the source and restores the VT.
SEAT_HELPER = '''import os,sys,subprocess,time,select,signal
binary,card,connector,crtc,duration,output,run_id,test_vt,old_vt=sys.argv[1:]
source=None; stop=False; status=1
def shutdown(*args):
 global stop
 stop=True
signal.signal(signal.SIGTERM,shutdown); signal.signal(signal.SIGINT,shutdown)
try:
 subprocess.run(["chvt",test_vt],check=True); time.sleep(1)
 env=dict(os.environ,HWS_RUN_ID=run_id)
 source=subprocess.Popen([binary,card,connector,crtc,duration,output],env=env)
 deadline=time.monotonic()+int(duration)+5
 while not stop and time.monotonic()<deadline:
  if source.poll() is not None:
   status=source.returncode; break
  ready,_,_=select.select([sys.stdin],[],[],.1)
  if ready:
   line=sys.stdin.readline()
   status=0 if line.strip()=="stop" else 1
   break
finally:
 if source and source.poll() is None:
  source.terminate()
  try: source.wait(timeout=5)
  except subprocess.TimeoutExpired: source.kill(); source.wait(); status=1
 if source and source.returncode: status=1
 if subprocess.run(["chvt",old_vt]).returncode: status=1
sys.exit(status)
'''


def run(command, **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


def remote(host, args, **kwargs):
    return run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
                shlex.join([str(a) for a in args])], **kwargs)


def upload(host, local, target):
    # Temporary remote pathname then atomic rename; no torn transfer is ready.
    code = "import sys,os; p=sys.argv[1]; f=open(p+'.partial','xb'); f.write(sys.stdin.buffer.read()); f.close(); os.replace(p+'.partial',p)"
    with Path(local).open("rb") as stream:
        subprocess.run(["ssh", "-T", "-o", "BatchMode=yes", host,
                        shlex.join(["python3", "-c", code, str(target)])],
                       stdin=stream, check=True)


def wait_for(predicate, seconds, processes=()):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate(): return
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("a source, clock, or capture process exited early; inspect run logs")
        time.sleep(.2)
    raise RuntimeError("timed out waiting for run phase")


def finished(process, timeout=10):
    if process is None: return
    if process.poll() is None:
        process.terminate()
    try: process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait()


def configured_output(config, name, mode_id):
    outputs = [o for o in config["outputs"] if o["name"] == name and o["connected"] and o["enabled"]]
    if len(outputs) != 1:
        raise RuntimeError("selected HDMI output is not uniquely active")
    output = outputs[0]
    modes = [m for m in output["modes"] if m["id"] == mode_id]
    if (len(modes) != 1 or modes[0]["size"] != {"width": 1920, "height": 1080}
            or abs(modes[0]["refreshRate"] - 60) > .02
            or output.get("scale") != 1 or output.get("replicationSource", 0)):
        raise RuntimeError("source requires an unscaled, unreplicated 1080p60 mode")
    return str(output["id"]), output["currentModeId"]


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--host", default="father")
    parser.add_argument("--remote-root", default="/home/hoff/swdev/hws")
    parser.add_argument("--channel", type=int, choices=range(4), default=2)
    parser.add_argument("--card", default="/dev/dri/card1")
    parser.add_argument("--connector", type=int, default=135)
    parser.add_argument("--crtc", type=int, default=84)
    parser.add_argument("--output-name", default="HDMI-A-2")
    parser.add_argument("--mode-id", default="12")
    parser.add_argument("--test-vt", type=int, choices=range(2, 13), default=3)
    parser.add_argument("--frames", type=int, default=1000, metavar="1..36000")
    parser.add_argument("--runs", type=int, choices=range(1, 101), default=1, metavar="1..100",
                        help="repeat captures with fresh evidence budgets; batches require <=1000 frames and full/queue diagnostics")
    parser.add_argument("--buffers", type=int, choices=range(2, 33), default=4,
                        help="capture buffers on the remote host (16 for low-starvation comparisons)")
    parser.add_argument("--queue-diagnostics", action="store_true",
                        help="retain remote queue/IRQ and userspace buffer timing evidence")
    parser.add_argument("--probe-mode", choices=("full", "off"), default="full",
                        help="full retains independent DMA mapping evidence; off is an overhead control")
    parser.add_argument("--require-vblank-off", action="store_true",
                        help="verify remote NVIDIA vblank remains off without changing it")
    parser.add_argument("--allow-dirty", action="store_true", help="diagnostics only; strict provenance still fails")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def capture_command(args, run_id, remote_dir):
    command = ["python3", args.remote_root + "/tools/hws_vdone_evidence.py", "--run",
               "--device", f"/dev/video{args.channel}", "--channel", str(args.channel),
               "--frames", str(args.frames), "--buffers", str(args.buffers),
               "--probe-mode", args.probe_mode,
               "--run-id", run_id, "--bundle", remote_dir + "/bundle",
               "--source-telemetry", remote_dir + "/source.jsonl",
               "--clock-evidence", remote_dir + "/clock.jsonl",
               "--remote-ready", remote_dir + "/ready"]
    if args.queue_diagnostics: command.append("--queue-diagnostics")
    if args.require_vblank_off: command.append("--require-vblank-off")
    if args.allow_dirty: command.append("--allow-dirty")
    return command


def run_once(args):
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    run_id = str(uuid.uuid4())
    remote_dir = f"/tmp/hws-remote-{run_id}"
    bundle = remote_dir + "/bundle"
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *unused: (_ for _ in ()).throw(KeyboardInterrupt()))
    run(["make", "-C", str(ROOT / "tools"), "hws_frame_id_kms"])
    # Refuse differing source implementations: both builds must carry the same
    # source/pattern identity before either display or capture is changed.
    hashes = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
              for p in ("tools/hws_frame_id_kms.c", "tools/hws_frame_pattern.h")}
    check = remote(args.host, ["sha256sum", *[args.remote_root + "/" + p for p in hashes]], capture_output=True)
    if [line.split()[0] for line in check.stdout.splitlines()] != list(hashes.values()):
        raise RuntimeError("source/pattern files differ between hosts; integrate and build both checkouts first")
    remote(args.host, ["python3", args.remote_root + "/tools/hws_vdone_evidence.py", "--help"], stdout=subprocess.DEVNULL)
    # Authenticate before display changes. Remote authentication is handled by
    # the capture runner's interactive SSH PTY, with its output on this terminal.
    run(["sudo", "-v"])
    config = json.loads(run(["kscreen-doctor", "-j"], capture_output=True).stdout)
    output_id, old_mode = configured_output(config, args.output_name, args.mode_id)
    old_vt = Path("/sys/class/tty/tty0/active").read_text().strip().removeprefix("tty")
    if not old_vt.isdigit() or old_vt == str(args.test_vt):
        raise RuntimeError("cannot safely identify original/temporary VT")
    sessions = run(["loginctl", "list-sessions", "--no-legend"], capture_output=True).stdout
    if f"tty{args.test_vt}" in sessions.split():
        raise RuntimeError("temporary VT already hosts a session")
    remote(args.host, ["mkdir", "-m", "700", remote_dir])
    remote(args.host, ["touch", remote_dir + "/source.jsonl"])
    (args.output / "run.json").write_text(json.dumps(dict(run_id=run_id, host=args.host,
        remote_bundle=bundle, source_hashes=hashes, original_kscreen=config,
        capture_command=capture_command(args, run_id, remote_dir)), indent=2) + "\n")
    clock = source = capture = None
    changed_mode = False
    source_path = args.output / "source.jsonl"
    clock_path = args.output / "clock-exchanges.jsonl"
    duration = min(3500, args.frames // 20 + 180)
    try:
        with (args.output / "clock.log").open("x") as log:
            clock = subprocess.Popen([sys.executable, str(ROOT / "tools/hws_clock_probe.py"),
                "--host", args.host, "--transport", "udp", "--hz", "100", "--seconds", str(duration),
                "--run-id", run_id, "--output", str(clock_path)], stdout=log, stderr=log)
        wait_for(lambda: clock_path.exists() and clock_path.stat().st_size > 4000, 20, [clock])
        cmd = capture_command(args, run_id, remote_dir)
        capture = subprocess.Popen(["ssh", "-tt", "-o", "BatchMode=yes", args.host,
                                    shlex.join(["python3", "-c", CAPTURE_BOOTSTRAP, remote_dir, *cmd])])
        def remote_exists(path):
            return subprocess.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", args.host,
                    shlex.join(["test", "-f", path])], timeout=10,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        wait_for(lambda: remote_exists(remote_dir + "/auth-ready"), 90, [clock, capture])
        changed_mode = True
        run(["kscreen-doctor", f"output.{output_id}.mode.{args.mode_id}"])
        with (args.output / "source.log").open("x") as log:
            source = subprocess.Popen(["sudo", "-n", "python3", "-u", "-c", SEAT_HELPER,
                str(ROOT / "tools/hws_frame_id_kms"), args.card, str(args.connector), str(args.crtc),
                str(duration), str(source_path), run_id, str(args.test_vt), old_vt],
                stdin=subprocess.PIPE, stdout=log, stderr=log)
        wait_for(lambda: source_path.exists() and source_path.stat().st_size > 4000, 20, [source, clock])
        with source_path.open() as stream: source_config = json.loads(stream.readline())
        expected = dict(run_id=run_id, width=1920, height=1080, clock_khz=148500, htotal=2200, vtotal=1125)
        if any(source_config.get(k) != v for k, v in expected.items()):
            raise RuntimeError("KMS source did not retain the required 1080p60 mode/run identity")
        remote(args.host, ["touch", remote_dir + "/source-ready"])
        def capture_complete():
            return remote_exists(bundle + "/capture-complete.json")
        wait_for(capture_complete, duration - 20, [source, clock, capture])
        time.sleep(.2)  # retain successor presentation and post-capture clock samples
        source.stdin.write(b"stop\n"); source.stdin.flush()
        source.wait(timeout=10)
        if source.returncode:
            raise RuntimeError("source failed or restoration failed; see source.log")
        time.sleep(.2)
        finished(clock)
        records = read_records(clock_path)
        c = records[0]
        try:
            mapping = ClockMap(records, c["source_boot_id"], c["capture_boot_id"], run_id)
            clock_report = mapping.report()
        except ClockError as exc:
            # Preserve completed raw evidence for the remote validator even
            # when calibration fails. It must report the failure, not lose the
            # source log and leave the capture runner waiting for a transfer.
            clock_report = dict(result="inconclusive", error=str(exc))
        (args.output / "clock-mapping.json").write_text(json.dumps(clock_report, indent=2) + "\n")
        upload(args.host, source_path, remote_dir + "/source.jsonl")
        upload(args.host, clock_path, remote_dir + "/clock.jsonl")
        ready = args.output / "ready"
        ready.write_text(run_id + "\n")
        upload(args.host, ready, remote_dir + "/ready")
        capture.wait(timeout=120)
        print(f"Remote evidence: {args.host}:{bundle}")
        print(f"Source/clock logs: {args.output}")
        return capture.returncode
    finally:
        if source:
            if source.poll() is None:
                try: source.stdin.write(b"stop\n"); source.stdin.flush(); source.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired): finished(source)
            source.stdin.close()
        finished(clock)
        if capture and capture.poll() is None:
            finished(capture)
        if changed_mode:
            run(["kscreen-doctor", f"output.{output_id}.mode.{old_mode}"])


def fetch_report(args, run_info):
    # Read only sealed evidence. The remote validator checks the full bundle,
    # including binary traces and anomaly dumps, before returning these reports.
    code = '''import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1]+"/tools")
from hws_vdone_evidence import verify_bundle_checksums
b=Path(sys.argv[2]); verify_bundle_checksums(b)
r={name:json.loads((b/(name+".json")).read_text()) for name in ("manifest","summary","diagnostics")}
r["stats"] = dict(line.split("=",1) for line in (b/"stats-after.txt").read_text().splitlines() if "=" in line)
print(json.dumps(r))
'''
    response = remote(args.host, ["python3", "-c", code, args.remote_root,
                                 run_info["remote_bundle"]], capture_output=True, timeout=60)
    return json.loads(response.stdout)


def assess_trial(args, run_info, report, returncode):
    m, s, d, stats = (report[name] for name in ("manifest", "summary", "diagnostics", "stats"))
    failures = []
    if not run_info.get("run_id") or any(r.get("run_id") != run_info["run_id"] for r in (m, s)):
        failures.append("run identity mismatch")
    if m.get("channel") != args.channel or s.get("channel") != args.channel:
        failures.append("capture channel mismatch")
    if (m.get("buffers_requested") != args.buffers or m.get("probe_mode") != "full"
            or m.get("queue_diagnostics") is not True or m.get("requeue_delay_ms") != 0):
        failures.append("capture profile mismatch")
    if args.require_vblank_off and m.get("nvidia_vblank") != "N":
        failures.append("NVIDIA vblank state changed")
    if not m.get("loaded_srcversion") or m.get("loaded_srcversion") != m.get("module_srcversion"):
        failures.append("loaded module identity mismatch")
    for key in ("kms_source_sha256", "pattern_sha256", "module_sha256", "capture_tool_sha256",
                "evidence_runner_sha256", "observer_validator_sha256", "boot_id"):
        if not m.get(key):
            failures.append("missing identity: " + key)
    for file, key in (("tools/hws_frame_id_kms.c", "kms_source_sha256"),
                      ("tools/hws_frame_pattern.h", "pattern_sha256")):
        if m.get(key) != run_info.get("source_hashes", {}).get(file):
            failures.append("source identity mismatch: " + key)
    for key in ("capture_checks", "independent_mapping", "source_presentation", "anomaly_observation"):
        if s.get(key, {}).get("result") != "pass":
            failures.append(key + " did not pass")
    presentation = s.get("source_presentation", {})
    if presentation.get("clock_mapping", {}).get("result") != "pass":
        failures.append("clock mapping did not pass")
    frames = s.get("frame_id_summary", {})
    if (s.get("captured_frames") != args.frames or frames.get("captured") != args.frames
            or frames.get("valid") != args.frames or frames.get("result") != "pass"):
        failures.append("incomplete or invalid frame capture")
    if d.get("evidence_status") != "complete" or d.get("failures") != []:
        failures.append("incomplete diagnostic evidence")
    late = d.get("late_toggle", {})
    if (late.get("enabled") != "Y" or late.get("evidence_status") not in ("complete", "not_observed")
            or late.get("failures") != []):
        failures.append("late-toggle evidence disabled, capped or incomplete")
    for key in ("diag_suppressed", "anomaly_suppressed", "late_toggle_suppressed",
                "vdone_fatal", "queue_failures", "guard_errors", "ring_corrupt"):
        if stats.get(key) != "0":
            failures.append("nonzero or missing " + key)
    allowed = {"driver evidence was captured from a dirty tracked tree",
               "evidence inputs were not committed at capture time"}
    strict_failures = s.get("failures", [])
    provenance = s.get("provenance", {})
    strict_pass = (s.get("result") == "pass" and not strict_failures
                   and provenance.get("result") == "pass" and not provenance.get("failures"))
    dirty_only = (args.allow_dirty and s.get("result") == "fail" and bool(strict_failures)
                  and set(strict_failures) <= allowed and provenance.get("result") == "fail"
                  and set(strict_failures) == set(provenance.get("failures", [])))
    if not (strict_pass or dirty_only) or returncode != (0 if strict_pass else 1):
        failures.append("unexpected validation or process failure")
    if s.get("presentation_failures") != [] or s.get("capture_checks", {}).get("failures") != []:
        failures.append("capture or presentation failures")
    if failures:
        raise RuntimeError("; ".join(failures))
    identity = {k: m.get(k) for k in ("loaded_srcversion", "module_sha256", "kms_source_sha256",
                "pattern_sha256", "capture_tool_sha256", "evidence_runner_sha256",
                "observer_validator_sha256", "boot_id", "kernel", "late_toggle_probe",
                "source_transition_checks", "nvidia_vblank")}
    return dict(run_id=s["run_id"], remote_bundle=run_info["remote_bundle"],
                # duplicate_recoveries is lifetime cumulative; duplicate_reports
                # is reset each stream and checked against this bundle's trace.
                frames=s["captured_frames"], duplicate_toggles=int(stats["duplicate_reports"]),
                recoveries=int(stats["vdone_recovered"]), no_buffer_frames=int(stats["frames_no_buffer"]),
                repeated_frame_ids=frames["repeated_ids"], strict_result=s["result"],
                diagnostic_result="pass", provenance_failures=provenance.get("failures", []),
                identity=identity)


def run_batch(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    batch = dict(result="running", requested_runs=args.runs, frames_per_run=args.frames,
                 requested_frames=args.runs * args.frames, completed_runs=0, captured_frames=0,
                 duplicate_toggles=0, recoveries=0, no_buffer_frames=0, trials=[],
                 note="Separate stream epochs; diagnostic completion does not waive strict provenance.")

    def save():
        temporary = output / "batch.json.partial"
        temporary.write_text(json.dumps(batch, indent=2) + "\n")
        temporary.replace(output / "batch.json")

    save()
    for index in range(1, args.runs + 1):
        trial_args = argparse.Namespace(**(vars(args) | {"output": output / f"run-{index:03d}", "runs": 1}))
        batch["active_run"] = str(trial_args.output)
        save()
        print(f"Batch capture {index}/{args.runs}: {args.frames} frames", flush=True)
        try:
            status = run_once(trial_args)
            run_info = json.loads((trial_args.output / "run.json").read_text())
            report = fetch_report(args, run_info)
            (trial_args.output / "review-inputs.json").write_text(json.dumps(report, indent=2) + "\n")
            row = assess_trial(args, run_info, report, status)
            if batch["trials"] and row["identity"] != batch["trials"][0]["identity"]:
                raise RuntimeError("source/capture build, boot or module parameters changed between trials")
            batch["trials"].append(row)
            batch["completed_runs"] += 1
            for key, field in (("captured_frames", "frames"), ("duplicate_toggles", "duplicate_toggles"),
                               ("recoveries", "recoveries"), ("no_buffer_frames", "no_buffer_frames")):
                batch[key] += row[field]
            save()
            print(f"Trial diagnostics PASS; duplicate toggles={row['duplicate_toggles']}; "
                  f"batch total={batch['duplicate_toggles']} across {batch['captured_frames']} frames; "
                  f"strict result={row['strict_result']}", flush=True)
        except (Exception, KeyboardInterrupt) as exc:
            batch["result"] = "interrupted" if isinstance(exc, KeyboardInterrupt) else "stopped"
            batch["error"] = str(exc) or type(exc).__name__
            save()
            print(f"Batch stopped; inspect {output / 'batch.json'}: {batch['error']}", file=sys.stderr)
            return 130 if isinstance(exc, KeyboardInterrupt) else 1
    batch.pop("active_run", None)
    batch["result"] = "diagnostic_complete"
    save()
    print(f"Batch complete: {batch['captured_frames']} frames, "
          f"{batch['duplicate_toggles']} duplicate toggles. Report: {output / 'batch.json'}")
    return 0


def main():
    parser = argument_parser()
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*", args.host):
        parser.error("invalid host")
    if not 1 <= args.frames <= 36000:
        parser.error("--frames must be 1..36000")
    if not args.run:
        parser.error("--run is required for the temporary source display takeover")
    if os.geteuid() == 0:
        parser.error("run as the desktop user; sudo is used only by the VT/source helper")
    if args.runs > 1 and (args.frames > 1000 or not args.queue_diagnostics or args.probe_mode != "full"):
        parser.error("batches require --frames <=1000, --queue-diagnostics and --probe-mode full")
    return run_batch(args) if args.runs > 1 else run_once(args)


if __name__ == "__main__":
    try: sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        print(f"Remote run incomplete: {exc}", file=sys.stderr)
        sys.exit(1)
