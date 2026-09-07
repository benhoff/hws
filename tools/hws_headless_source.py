#!/usr/bin/env python3
"""Run on the HWS capture host; explicitly take over a remote headless HDMI source.

One <=1000-frame full-evidence qualification. No KDE, reverse SSH, key copying,
module reload, root source process, or persistent network service is required.
Local sudo authenticates before the source display changes.
"""
import argparse
import fcntl
import hashlib
import ipaddress
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

from hws_clock_probe import UDP_PEER, LineReader
from hws_clock_mapping import read_records, ClockMap, ClockError
from hws_remote_source import assess_trial, capture_command, finished, remote, upload, wait_for
from hws_vdone_evidence import verify_bundle_checksums

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = ("tools/hws_frame_id_kms.c", "tools/hws_frame_pattern.h",
                "tools/hws_clock_probe.py", "tools/hws_clock_mapping.py")

# Each child receives SIGTERM and time to flush telemetry/restore scanout on
# stop, SSH EOF, hangup, or deadline. SIGKILL is a last resort and never a pass.
# The source binary owns the original CRTC/FB until restoration; no VT changes.
SUPERVISOR = '''import os,sys,time,signal,select,subprocess
stop=False
def interrupted(*unused):
 global stop
 stop=True
for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP): signal.signal(sig,interrupted)
child=None; requested=False; status=1
try:
 deadline=time.monotonic()+int(sys.argv[1])
 child=subprocess.Popen(sys.argv[2:],stdin=subprocess.DEVNULL,start_new_session=True)
 while not stop and time.monotonic()<deadline:
  if child.poll() is not None: break
  ready,_,_=select.select([sys.stdin],[],[],.1)
  if ready:
   requested=sys.stdin.readline().strip()=="stop"
   break
finally:
 if child:
  if child.poll() is None:
   child.terminate()
   try: child.wait(timeout=8)
   except subprocess.TimeoutExpired: child.kill(); child.wait(); requested=False
  status=child.returncode if requested else 1
sys.exit(status)
'''


def ssh_command(host, command):
    return ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
            shlex.join([str(a) for a in command])]


def supervised(host, seconds, command, log):
    return subprocess.Popen(ssh_command(host, ["python3", "-u", "-c", SUPERVISOR,
                                               str(seconds), *command]),
                            stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)


def stop_supervised(process):
    if process is None:
        return None
    if process.poll() is None:
        try:
            process.stdin.write(b"stop\n")
            process.stdin.flush()
        except (OSError, ValueError):
            pass
    try:
        return process.wait(timeout=12)
    except subprocess.TimeoutExpired:
        # Closing the SSH client triggers remote EOF/hangup cleanup; the
        # independent remote deadline remains if the network is broken.
        finished(process)
        return 1
    finally:
        try: process.stdin.close()
        except OSError: pass


def stop_capture(process):
    """Give the evidence runner/trace recorder their SIGINT cleanup path."""
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=12)
    except subprocess.TimeoutExpired:
        # Only this controller's newly created process group is targeted.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try: os.killpg(process.pid, sig)
            except ProcessLookupError: break
            try: process.wait(timeout=3); break
            except subprocess.TimeoutExpired: pass


def fetch(host, path, destination, limit=64*1024*1024):
    code = '''import sys
with open(sys.argv[1],"rb") as f: data=f.read(int(sys.argv[2])+1)
if len(data)>int(sys.argv[2]): raise SystemExit("remote evidence exceeds bound")
sys.stdout.buffer.write(data)
'''
    partial = destination.with_name(destination.name + ".partial")
    with partial.open("xb") as stream:
        remote(host, ["python3", "-c", code, path, str(limit)], stdout=stream, timeout=30)
    partial.replace(destination)


def check_source_config(config, args, run_id, hashes, source_boot):
    expected = dict(type="source_config", backend="drm-kms", run_id=run_id,
                    boot_id=source_boot, clock="CLOCK_MONOTONIC", async_flip=False,
                    connector_id=args.connector, crtc_id=args.crtc,
                    width=1920, height=1080, clock_khz=148500, htotal=2200, vtotal=1125,
                    source_sha256=hashes["tools/hws_frame_id_kms.c"],
                    pattern_sha256=hashes["tools/hws_frame_pattern.h"])
    if any(config.get(k) != v for k, v in expected.items()):
        raise RuntimeError("applied source mode, run, boot or executable identity mismatch")
    if config.get("vscan") not in (0, 1) or type(config.get("mode_flags")) is not int:
        raise RuntimeError("invalid source scan mode")
    if config["mode_flags"] & ((1 << 4) | (1 << 5) | (1 << 12) | (1 << 13)):
        raise RuntimeError("interlaced/doublescan/double-clock source refused")


def receiver_1080p60(text):
    fields = {k.strip(): v.strip() for k, v in re.findall(r"^\s*([^:\n]+):\s*([^\n]+)", text, re.M)}
    expected = {"Active width": "1920", "Active height": "1080", "Total width": "2200",
                "Total height": "1125", "Frame format": "progressive"}
    return (all(fields.get(k) == v for k, v in expected.items())
            and fields.get("Pixelclock", "").split()[:1] == ["148500000"])


def wait_receiver(args, source, clock, log):
    deadline, stable = time.monotonic() + 45, 0
    while time.monotonic() < deadline:
        if source.poll() is not None or clock.poll() is not None:
            raise RuntimeError("source/clock stopped during receiver lock")
        result = subprocess.run(["v4l2-ctl", "-d", f"/dev/video{args.channel}",
                                 "--query-dv-timings", "--verbose"],
                                text=True, capture_output=True, timeout=3)
        log.write(result.stdout + result.stderr); log.flush()
        stable = stable + 1 if result.returncode == 0 and receiver_1080p60(result.stdout) else 0
        if stable == 3:
            return
        time.sleep(.25)
    raise RuntimeError("receiver did not lock to exact 1080p60 within 45 seconds")


def report_bundle(bundle):
    verify_bundle_checksums(bundle)
    report = {name: json.loads((bundle / (name + ".json")).read_text())
              for name in ("manifest", "summary", "diagnostics")}
    report["stats"] = dict(line.split("=", 1) for line in (bundle / "stats-after.txt").read_text().splitlines()
                           if "=" in line)
    return report


def qualify(args):
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    run_id = str(uuid.uuid4())
    remote_dir = "/tmp/hws-headless-" + run_id
    source_path, clock_path = output / "source.jsonl", output / "clock.jsonl"
    source_path.touch(mode=0o600)
    args.remote_root = str(ROOT)  # reuse the existing full-evidence command builder locally
    args.probe_mode, args.queue_diagnostics = "full", True
    command = capture_command(args, run_id, str(output))
    info = dict(run_id=run_id, source_host=args.source_host, source_root=args.source_root,
                remote_source_directory=remote_dir, remote_bundle=str(output / "bundle"),
                capture_command=command, source_hashes={}, result="incomplete")
    def save():
        (output / "run.json").write_text(json.dumps(info, indent=2) + "\n")
    save()
    source = clock = peer = capture = None
    peer_reader = None
    logs = []
    try:
        subprocess.run(["make", "-C", str(ROOT / "tools"), "all", "hws_frame_id_kms"], check=True)
        # Password, module, channel, debugfs, trace-idle and provenance checks
        # all precede starting a remote source or changing a display mode.
        subprocess.run([*command, "--preflight-only"], check=True)
        hashes = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCE_FILES}
        response = remote(args.source_host, ["sha256sum", *[args.source_root + "/" + p for p in SOURCE_FILES]],
                          capture_output=True, timeout=15)
        if [line.split()[0] for line in response.stdout.splitlines()] != list(hashes.values()):
            raise RuntimeError("source/clock files differ between hosts; sync source first")
        remote(args.source_host, ["make", "-C", args.source_root + "/tools", "hws_frame_id_kms",
                                 "hws_drm_timing_probe", "DRM_CFLAGS=-I/usr/include/libdrm", "DRM_LIBS=-ldrm"],
               timeout=60)
        remote_info = json.loads(remote(args.source_host, ["python3", "-c",
            'import os,json; from pathlib import Path; print(json.dumps(dict(connection=os.environ["SSH_CONNECTION"].split(),boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip())))'],
            capture_output=True, timeout=15).stdout)
        capture_ip, _, source_ip, _ = remote_info["connection"]
        ipaddress.ip_address(capture_ip); ipaddress.ip_address(source_ip)
        info.update(source_hashes=hashes, source_boot_id=remote_info["boot"],
                    capture_ip=capture_ip, source_ip=source_ip)
        save()
        remote(args.source_host, ["mkdir", "-m", "700", remote_dir], timeout=15)
        before = remote(args.source_host, [args.source_root + "/tools/hws_drm_timing_probe", args.card, "--list"],
                        capture_output=True, timeout=15)
        (output / "source-display-before.txt").write_text(before.stdout)
        # UDP_PEER restricts the client IP and token, and dies on this pipe's
        # EOF. Supply the same endpoint roles that its SSH bootstrap supplies.
        peer = subprocess.Popen([sys.executable, "-u", "-c", UDP_PEER],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            env=dict(os.environ, SSH_CONNECTION=f"{source_ip} 0 {capture_ip} 0"))
        peer_reader = LineReader(peer.stdout)
        hello, _ = peer_reader.read(10)
        peer_file = output / "udp-peer.json"
        peer_file.write_text(json.dumps(hello) + "\n")
        upload(args.source_host, peer_file, remote_dir + "/udp-peer.json")
        def log(name):
            stream = (output / name).open("x")
            logs.append(stream)
            return stream
        duration = 180
        clock = supervised(args.source_host, duration + 10, ["python3", args.source_root + "/tools/hws_clock_probe.py",
            "--udp-peer-file", remote_dir + "/udp-peer.json", "--transport", "udp", "--hz", "100",
            "--seconds", str(duration), "--run-id", run_id, "--output", remote_dir + "/clock.jsonl"], log("clock.log"))
        def remote_started(path):
            code = 'import sys; from pathlib import Path; p=Path(sys.argv[1]); sys.exit(0 if p.exists() and p.stat().st_size>4000 else 1)'
            return subprocess.run(ssh_command(args.source_host, ["python3", "-c", code, path]),
                                  timeout=10).returncode == 0
        wait_for(lambda: remote_started(remote_dir + "/clock.jsonl"), 20, [clock, peer])
        source = supervised(args.source_host, duration + 10, ["env", "HWS_RUN_ID=" + run_id,
            args.source_root + "/tools/hws_frame_id_kms", args.card, str(args.connector), str(args.crtc),
            str(duration), remote_dir + "/source.jsonl", "--mode-1080p60"], log("source.log"))
        wait_for(lambda: remote_started(remote_dir + "/source.jsonl"), 20, [source, clock, peer])
        config = json.loads(remote(args.source_host, ["head", "-n", "1", remote_dir + "/source.jsonl"],
                                   capture_output=True, timeout=10).stdout)
        check_source_config(config, args, run_id, hashes, remote_info["boot"])
        wait_receiver(args, source, clock, log("receiver-ready.log"))
        capture = subprocess.Popen(command, stdout=log("capture.log"), stderr=subprocess.STDOUT,
                                   process_group=0)
        wait_for(lambda: (output / "bundle/capture-complete.json").exists(), 100, [capture, source, clock, peer])
        time.sleep(.25)  # successor presentations after the final capture
        source_status = stop_supervised(source)
        source = None
        time.sleep(.25)  # clock coverage extends past the last presentation
        clock_status = stop_supervised(clock)
        clock = None
        info["cleanup"] = dict(source=source_status, clock=clock_status)
        fetch(args.source_host, remote_dir + "/source.jsonl", source_path)
        fetch(args.source_host, remote_dir + "/clock.jsonl", clock_path)
        after = remote(args.source_host, [args.source_root + "/tools/hws_drm_timing_probe", args.card, "--list"],
                       capture_output=True, timeout=15)
        (output / "source-display-after.txt").write_text(after.stdout)
        rows = read_records(clock_path)
        try:
            mapping = ClockMap(rows, remote_info["boot"], hello["boot_id"], run_id).report()
        except ClockError as error:
            mapping = dict(result="inconclusive", error=str(error))
        (output / "clock-mapping.json").write_text(json.dumps(mapping, indent=2) + "\n")
        # Preserve completed evidence even when the source/clock gate failed.
        # The existing validator still sees raw records and does not waive it.
        ready = output / "ready.partial"
        ready.write_text(run_id + "\n"); ready.replace(output / "ready")
        status = capture.wait(timeout=120)
        report = report_bundle(output / "bundle")
        (output / "review-inputs.json").write_text(json.dumps(report, indent=2) + "\n")
        if source_status != 0 or clock_status != 0:
            raise RuntimeError(f"source/clock cleanup or qualification failed ({source_status}/{clock_status})")
        # Do not accept an older source binary that did not verify restoration.
        with source_path.open() as stream:
            final = json.loads(list(stream)[-1])
        if final.get("type") != "source_summary" or final.get("restored") is not True:
            raise RuntimeError("source did not verify original display restoration")
        row = assess_trial(args, info, report, status)
        info.update(result="diagnostic_complete", trial=row)
        save()
        print(f"Qualification diagnostics PASS: {row['frames']} frames; duplicates={row['duplicate_toggles']}; "
              f"no-buffer={row['no_buffer_frames']}; strict={row['strict_result']}")
        return 0
    except BaseException as error:
        info.update(result="incomplete", error=str(error) or type(error).__name__)
        save()
        raise
    finally:
        # Stop local DMA/capture before restoring the source on an error path.
        stop_capture(capture)
        for name, process in (("source", source), ("clock", clock)):
            if process is not None:
                status = stop_supervised(process)
                info.setdefault("cleanup", {})[name] = status
        if peer_reader: peer_reader.selector.close()
        if peer:
            peer.stdin.close()
            finished(peer)
            peer.stdout.close()
        for stream in logs: stream.close()
        save()
        print(f"Results: {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="authorize the remote HDMI takeover and local capture")
    parser.add_argument("--source-host", default="wulfuser@192.168.1.125")
    parser.add_argument("--source-root", default="/home/wulfuser/swdev/hws")
    parser.add_argument("--card", default="/dev/dri/card0")
    parser.add_argument("--connector", type=int, default=84)
    parser.add_argument("--crtc", type=int, default=81)
    parser.add_argument("--channel", type=int, choices=range(4), default=2)
    parser.add_argument("--frames", type=int, choices=range(1, 1001), default=1000, metavar="1..1000")
    parser.add_argument("--buffers", type=int, choices=range(2, 33), default=16)
    parser.add_argument("--require-vblank-off", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.run or os.geteuid() == 0:
        parser.error("run as the capture-host user with --run; sudo is used only by capture")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*", args.source_host):
        parser.error("invalid source SSH host")
    if args.connector <= 0 or args.crtc <= 0 or not Path(args.source_root).is_absolute():
        parser.error("positive connector/CRTC IDs and absolute source root required")
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *unused: (_ for _ in ()).throw(KeyboardInterrupt()))
    # Per-user exclusion for this controller; the capture preflight separately
    # refuses tracing already owned by another tool. Never steal DRM master.
    with open(f"/tmp/hws-headless-{os.getuid()}.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return qualify(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(f"Headless qualification incomplete: {error}", file=sys.stderr)
        sys.exit(1)
