#!/usr/bin/env python3
"""Collect bounded four-timestamp evidence over one persistent SSH connection."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import socket
import subprocess
import sys
import time
import uuid

from hws_clock_mapping import ClockMap, ClockError, METHOD, RATE_PPM, SLACK_NS, read_records

# Self-contained peer is sent as Python source; nothing is installed remotely.
PEER = '''import json,sys,time,socket
from pathlib import Path
def marker():
 a=time.monotonic_ns(); b=time.clock_gettime_ns(time.CLOCK_BOOTTIME); r=time.time_ns(); z=time.monotonic_ns()
 return dict(mono_before_ns=a,mono_after_ns=z,boottime_ns=b,realtime_ns=r)
print(json.dumps(dict(type="hello",boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),host=socket.gethostname())),flush=True)
for line in sys.stdin:
 f2=time.monotonic_ns()
 if len(line)>1024: raise ValueError("request too large")
 q=json.loads(line)
 if q.get("type")=="stop": break
 m=marker()
 f3=time.monotonic_ns()
 print(json.dumps(dict(type="reply",index=q["index"],run_id=q["run_id"],f2_ns=f2,f3_ns=f3,capture_clock=m)),flush=True)
'''

# An ephemeral UDP peer is scoped to the SSH client's IP and a random token.
# Closing SSH stdin stops it; it also has an independent one-hour deadline.
UDP_PEER = '''import json,sys,time,socket,os,secrets,select
from pathlib import Path
def marker():
 a=time.monotonic_ns(); b=time.clock_gettime_ns(time.CLOCK_BOOTTIME); r=time.time_ns(); z=time.monotonic_ns()
 return dict(mono_before_ns=a,mono_after_ns=z,boottime_ns=b,realtime_ns=r)
connection=os.environ["SSH_CONNECTION"].split()
address=connection[2]; allowed=connection[0]; token=secrets.token_hex(24)
s=socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET,socket.SOCK_DGRAM)
s.bind((address,0))
print(json.dumps(dict(type="hello",boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),host=socket.gethostname(),address=address,port=s.getsockname()[1],token=token)),flush=True)
deadline=time.monotonic()+3605
while time.monotonic()<deadline:
 ready,_,_=select.select([s,sys.stdin],[],[],1)
 if sys.stdin in ready: break
 if s not in ready: continue
 data,peer=s.recvfrom(2048); f2=time.monotonic_ns()
 if peer[0]!=allowed or len(data)>1024: continue
 try: q=json.loads(data)
 except ValueError: continue
 if not isinstance(q,dict) or q.get("token")!=token: continue
 if not isinstance(q.get("index"),int) or not isinstance(q.get("run_id"),str): continue
 m=marker(); f3=time.monotonic_ns()
 s.sendto(json.dumps(dict(type="reply",token=token,index=q["index"],run_id=q["run_id"],f2_ns=f2,f3_ns=f3,capture_clock=m)).encode(),peer)
s.close()
'''


def marker():
    a = time.monotonic_ns()
    boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    real = time.time_ns()
    z = time.monotonic_ns()
    return dict(mono_before_ns=a, mono_after_ns=z, boottime_ns=boot, realtime_ns=real)


class LineReader:
    def __init__(self, stream):
        self.stream = stream
        self.pending = b""
        self.selector = selectors.DefaultSelector()
        self.selector.register(stream, selectors.EVENT_READ)

    def read(self, timeout=3):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise ClockError("SSH clock exchange timed out")
            chunk = os.read(self.stream.fileno(), 4096)
            if not chunk:
                raise ClockError("SSH clock peer disconnected")
            self.pending += chunk
            if len(self.pending) > 16384:
                raise ClockError("SSH clock reply exceeds bound")
        line, self.pending = self.pending.split(b"\n", 1)
        received = time.monotonic_ns()
        return json.loads(line), received


def collect(args):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*", args.host):
        raise ClockError("invalid SSH host")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.run_id):
        raise ClockError("run ID must be 1..64 letters, digits, underscores or hyphens")
    stopped = False
    def stop(*unused):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", buffering=1) as out:
        process = reader = None
        if not getattr(args, "udp_peer_file", None):
            command = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", args.host,
                       "python3 -u -c " + shlex.quote(UDP_PEER if args.transport == "udp" else PEER)]
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            reader = LineReader(process.stdout)
        count, error, udp = 0, None, None
        try:
            hello = read_udp_peer(args.udp_peer_file) if getattr(args, "udp_peer_file", None) else reader.read(15)[0]
            if hello.get("type") != "hello" or not hello.get("boot_id"):
                raise ClockError("invalid clock peer greeting")
            if args.transport == "udp":
                address = hello["address"]
                udp = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_DGRAM)
                udp.connect((address, hello["port"]))
                udp.settimeout(3)
            config = dict(type="clock_config", schema=1, method=METHOD, clock="CLOCK_MONOTONIC",
                          rate_bound_ppm=RATE_PPM, timestamp_slack_ns=SLACK_NS, run_id=args.run_id,
                          source_host=socket.gethostname(), capture_host=hello["host"],
                          source_boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                          capture_boot_id=hello["boot_id"], requested_seconds=args.seconds, hz=args.hz,
                          transport=args.transport)
            out.write(json.dumps(config) + "\n")
            deadline = time.monotonic() + args.seconds
            while not stopped and time.monotonic() < deadline and count < 100_000:
                request = (json.dumps(dict(type="sample", index=count, run_id=args.run_id,
                                          token=hello.get("token"))) + "\n").encode()
                source_clock = marker()
                s1 = time.monotonic_ns()
                if udp:
                    udp.send(request)
                    payload = udp.recv(16384)
                    s4 = time.monotonic_ns()
                    reply = json.loads(payload)
                    if reply.get("token") != hello["token"]:
                        raise ClockError("UDP reply token mismatch")
                else:
                    process.stdin.write(request)
                    process.stdin.flush()
                    reply, s4 = reader.read()
                if reply.get("type") != "reply" or reply.get("index") != count or reply.get("run_id") != args.run_id:
                    raise ClockError("clock peer reply identity mismatch")
                row = dict(type="clock_sample", index=count, run_id=args.run_id, s1_ns=s1, s4_ns=s4,
                           f2_ns=reply["f2_ns"], f3_ns=reply["f3_ns"], source_clock=source_clock,
                           capture_clock=reply["capture_clock"])
                out.write(json.dumps(row) + "\n")
                count += 1
                time.sleep(max(0, 1 / args.hz - (time.monotonic_ns() - s1) / 1e9))
            if count >= 100_000 and time.monotonic() < deadline and not stopped:
                error = "clock sample budget exhausted before requested duration"
        except (OSError, ValueError, KeyError) as exc:
            error = str(exc)
        finally:
            if udp: udp.close()
            if process is not None and process.poll() is None:
                try:
                    process.stdin.write(b'{"type":"stop"}\n'); process.stdin.flush()
                    process.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    process.terminate()
                    try: process.wait(timeout=3)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
            if process is not None and process.returncode:
                error = error or f"SSH peer exited {process.returncode}"
            if reader is not None: reader.selector.close()
            if process is not None:
                process.stdin.close(); process.stdout.close()
            # SIGTERM is a deliberate graceful end to continuous acquisition;
            # complete records are usable only within their actual coverage.
            out.write(json.dumps(dict(type="clock_summary", run_id=args.run_id,
                                      result="fail" if error or count < 2 else "pass",
                                      samples=count, stopped=stopped, error=error)) + "\n")
    if error:
        raise ClockError(error)
    return analyze(args.output)


def read_udp_peer(path):
    """Endpoint launched/owned by the capture-side controller, not reverse SSH.

    The wire protocol and clock domains are unchanged: this process is still
    the source initiating s1/f2/f3/s4 exchanges. Endpoint files contain a
    short-lived token and must be kept inside a private run directory.
    """
    with Path(path).open("rb") as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ClockError("UDP peer metadata exceeds bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ClockError("invalid UDP peer metadata")
    ipaddress.ip_address(value.get("address", ""))
    if (value.get("type") != "hello" or type(value.get("port")) is not int
            or not 1 <= value["port"] <= 65535
            or not re.fullmatch(r"[0-9a-f]{48}", str(value.get("token", "")))
            or not isinstance(value.get("host"), str) or not value["host"]
            or not re.fullmatch(r"[0-9a-f-]{36}", str(value.get("boot_id", "")))):
        raise ClockError("invalid UDP peer metadata")
    return value


def analyze(path):
    rows = read_records(path)
    c = rows[0]
    mapping = ClockMap(rows, c.get("source_boot_id"), c.get("capture_boot_id"), c.get("run_id"))
    report = mapping.report()
    print(json.dumps(report, indent=2))
    return 0 if report["result"] == "pass" else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="father")
    p.add_argument("--transport", choices=("ssh", "udp"), default="udp",
                   help="UDP uses an ephemeral IP/token-restricted peer controlled by SSH")
    p.add_argument("--udp-peer-file", type=Path,
                   help="private endpoint metadata supplied by the capture controller; no reverse SSH")
    p.add_argument("--seconds", type=int, choices=range(1, 3601), default=60, metavar="1..3600")
    p.add_argument("--hz", type=int, choices=range(1, 101), default=20, metavar="1..100")
    p.add_argument("--run-id", default=str(uuid.uuid4()))
    p.add_argument("--output", type=Path)
    p.add_argument("--analyze", type=Path)
    args = p.parse_args()
    if args.udp_peer_file and (args.transport != "udp" or args.analyze):
        p.error("--udp-peer-file requires UDP collection")
    if args.analyze and not args.output:
        return analyze(args.analyze)
    if not args.output or args.analyze:
        p.error("provide either --output or --analyze")
    return collect(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ClockError, OSError, ValueError) as exc:
        print(f"Clock evidence unqualified: {exc}", file=sys.stderr)
        sys.exit(1)
