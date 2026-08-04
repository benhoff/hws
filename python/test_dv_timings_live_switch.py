#!/usr/bin/env python3
"""Probe HWS DV-timings behavior around /dev/video3.

This script focuses on Hans Verkuil's review questions:
1. Does S_DV_TIMINGS apply a same-geometry fps change?
2. Does anything observable change if S_DV_TIMINGS succeeds while streaming?
3. Does the receiver react to an external source timing change during capture?
4. Which observable state changes: QUERY_DV_TIMINGS, G_DV_TIMINGS, G_PARM,
   BAR0 registers, source-change events, and stream continuity?
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import mmap
import os
import re
import shlex
import select
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path


CVBS_IN_BASE = 0x4000
REG_STRIDE = 4
BAR0_SIZE = 64 * 1024
PCI_BDF_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
DQBUF_RE = re.compile(
    r"cap dqbuf:\s+\d+\s+seq:\s+(\d+).* ts: ([0-9.]+)",
)

IOC_NRBITS = 8
IOC_TYPEBITS = 8
IOC_SIZEBITS = 14
IOC_DIRBITS = 2
IOC_NRSHIFT = 0
IOC_TYPESHIFT = IOC_NRSHIFT + IOC_NRBITS
IOC_SIZESHIFT = IOC_TYPESHIFT + IOC_TYPEBITS
IOC_DIRSHIFT = IOC_SIZESHIFT + IOC_SIZEBITS
IOC_WRITE = 1
IOC_READ = 2
V4L2_EVENT_SOURCE_CHANGE = 5
V4L2_EVENT_SRC_CH_RESOLUTION = 1 << 0


def _ioc(direction: int, ioc_type: int, nr: int, size: int) -> int:
    return (
        (direction << IOC_DIRSHIFT)
        | (ioc_type << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT)
    )


def _iow(ioc_type: str, nr: int, ctype: type[ctypes.Structure]) -> int:
    return _ioc(IOC_WRITE, ord(ioc_type), nr, ctypes.sizeof(ctype))


def _ior(ioc_type: str, nr: int, ctype: type[ctypes.Structure]) -> int:
    return _ioc(IOC_READ, ord(ioc_type), nr, ctypes.sizeof(ctype))


class Timespec(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_long),
        ("tv_nsec", ctypes.c_long),
    ]


class V4L2EventSrcChange(ctypes.Structure):
    _fields_ = [("changes", ctypes.c_uint32)]


class V4L2EventUnion(ctypes.Union):
    _fields_ = [
        ("src_change", V4L2EventSrcChange),
        ("data", ctypes.c_uint8 * 64),
    ]


class V4L2Event(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("u", V4L2EventUnion),
        ("pending", ctypes.c_uint32),
        ("sequence", ctypes.c_uint32),
        ("timestamp", Timespec),
        ("id", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32 * 8),
    ]


class V4L2EventSubscription(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32 * 5),
    ]


VIDIOC_DQEVENT = _ior("V", 89, V4L2Event)
VIDIOC_SUBSCRIBE_EVENT = _iow("V", 90, V4L2EventSubscription)
VIDIOC_UNSUBSCRIBE_EVENT = _iow("V", 91, V4L2EventSubscription)


def reg_active_status() -> int:
    return CVBS_IN_BASE + 5 * REG_STRIDE


def reg_in_res(ch: int) -> int:
    return CVBS_IN_BASE + (90 + ch * 2) * REG_STRIDE


def reg_bchs(ch: int) -> int:
    return CVBS_IN_BASE + (91 + ch * 2) * REG_STRIDE


def reg_frame_rate(ch: int) -> int:
    return CVBS_IN_BASE + (110 + ch) * REG_STRIDE


def reg_out_res(ch: int) -> int:
    return CVBS_IN_BASE + (120 + ch) * REG_STRIDE


def reg_out_frame_rate(ch: int) -> int:
    return CVBS_IN_BASE + (130 + ch) * REG_STRIDE


class Probe:
    def __init__(self, args: argparse.Namespace) -> None:
        self.device = normalize_device(args.device)
        self.width = args.width
        self.height = args.height
        self.from_fps = args.from_fps
        self.to_fps = args.to_fps
        self.stream_secs = args.stream_secs
        self.observe_secs = args.observe_secs
        self.interval_secs = args.interval_secs
        self.external_ready_file = (
            Path(args.external_ready_file) if args.external_ready_file else None
        )
        self.video_sysfs = resolve_video_sysfs(self.device)
        self.channel_index = resolve_channel_index(self.video_sysfs)
        self.bar0_path = resolve_bar0_path(args.bar0_path, self.video_sysfs)
        self.outdir = Path(
            args.outdir
            or f"/tmp/hws-dv-live-switch-{time.strftime('%Y%m%d-%H%M%S')}"
        )
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.commands_log = self.outdir / "commands.log"
        self.summary_log = self.outdir / "summary.log"
        self.command_lock = threading.Lock()

    def append_summary(self, line: str) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.summary_log.open("a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] {line}\n")
        print(line)

    def log_command(self, argv: list[str], rc: int, outfile: Path) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        cmd = shlex.join(argv)
        with self.command_lock:
            with self.commands_log.open("a", encoding="utf-8") as fh:
                fh.write(f"[{stamp}] CMD {cmd}\n")
                fh.write(f"[{stamp}] RC  {rc} -> {outfile}\n")

    def run_command(self, stem: str, argv: list[str]) -> int:
        outfile = self.outdir / f"{stem}.txt"
        with outfile.open("w", encoding="utf-8") as fh:
            proc = subprocess.run(
                argv,
                stdout=fh,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
        rcfile = self.outdir / f"{stem}.rc"
        rcfile.write_text(f"{proc.returncode}\n", encoding="utf-8")
        self.log_command(argv, proc.returncode, outfile)
        return proc.returncode

    def write_text_file(self, stem: str, text: str) -> None:
        (self.outdir / f"{stem}.txt").write_text(text, encoding="utf-8")

    def capture_environment(self) -> None:
        lines = [
            f"device={self.device}",
            f"video_sysfs={self.video_sysfs or 'unavailable'}",
            f"channel_index={self.channel_index if self.channel_index is not None else 'unavailable'}",
            f"bar0_path={self.bar0_path or 'unavailable'}",
            f"requested_geometry={self.width}x{self.height}",
            f"requested_fps={self.from_fps}->{self.to_fps}",
            f"stream_secs={self.stream_secs}",
            f"observe_secs={self.observe_secs}",
            f"interval_secs={self.interval_secs}",
        ]
        if self.video_sysfs:
            for name in ("name", "index", "dev", "resolution"):
                path = self.video_sysfs / name
                if path.exists():
                    try:
                        lines.append(f"{name}={path.read_text(encoding='utf-8').strip()}")
                    except OSError as exc:
                        lines.append(f"{name}=error:{exc}")
        self.write_text_file("environment", "\n".join(lines) + "\n")
        self.run_command("device.info", ["v4l2-ctl", "-d", self.device, "--info"])
        self.run_command("device.all", ["v4l2-ctl", "-d", self.device, "--all"])
        self.run_command(
            "device.list_dv_timings",
            ["v4l2-ctl", "-d", self.device, "--list-dv-timings"],
        )
        self.run_command(
            "device.get_dv_timings_cap",
            ["v4l2-ctl", "-d", self.device, "--get-dv-timings-cap"],
        )

    def capture_snapshot(self, stem: str) -> None:
        self.run_command(
            f"{stem}.query_dv_timings",
            ["v4l2-ctl", "-d", self.device, "--query-dv-timings"],
        )
        self.run_command(
            f"{stem}.g_dv_timings",
            ["v4l2-ctl", "-d", self.device, "--get-dv-timings"],
        )
        self.run_command(
            f"{stem}.g_parm",
            ["v4l2-ctl", "-d", self.device, "--get-parm"],
        )
        self.capture_sysfs_resolution(f"{stem}.sysfs_resolution")
        self.capture_bar0_snapshot(f"{stem}.bar0")

    def capture_sysfs_resolution(self, stem: str) -> None:
        text = "unavailable\n"
        if self.video_sysfs:
            path = self.video_sysfs / "resolution"
            if path.exists():
                try:
                    text = path.read_text(encoding="utf-8")
                except OSError as exc:
                    text = f"error: {exc}\n"
        self.write_text_file(stem, text)

    def capture_bar0_snapshot(self, stem: str) -> None:
        out = self.outdir / f"{stem}.txt"
        if self.channel_index is None:
            out.write_text("channel index unavailable\n", encoding="utf-8")
            return
        if not self.bar0_path:
            out.write_text("BAR0 path unavailable\n", encoding="utf-8")
            return
        if is_driver_bar0_snapshot(self.bar0_path):
            try:
                out.write_text(
                    self.bar0_path.read_text(encoding="utf-8", errors="replace"),
                    encoding="utf-8",
                )
            except OSError as exc:
                out.write_text(f"BAR0 read failed: {exc}\n", encoding="utf-8")
            return

        lines = [
            f"device={self.device}",
            f"channel_index={self.channel_index}",
            f"bar0_path={self.bar0_path}",
        ]
        try:
            bar0 = read_bar0_bytes(self.bar0_path)
            active = read_u32_from_bytes(bar0, reg_active_status())
            in_res = read_u32_from_bytes(bar0, reg_in_res(self.channel_index))
            bchs = read_u32_from_bytes(bar0, reg_bchs(self.channel_index))
            in_fps = read_u32_from_bytes(bar0, reg_frame_rate(self.channel_index))
            out_res = read_u32_from_bytes(bar0, reg_out_res(self.channel_index))
            out_fps = read_u32_from_bytes(bar0, reg_out_frame_rate(self.channel_index))
        except OSError as exc:
            out.write_text(f"BAR0 read failed: {exc}\n", encoding="utf-8")
            return

        lines.extend(
            [
                format_active_status(self.channel_index, active),
                format_resolution_reg("IN_RES", reg_in_res(self.channel_index), in_res),
                format_bchs_reg(reg_bchs(self.channel_index), bchs),
                format_fps_reg("FRAME_RATE", reg_frame_rate(self.channel_index), in_fps),
                format_resolution_reg("OUT_RES", reg_out_res(self.channel_index), out_res),
                format_fps_reg(
                    "OUT_FRAME_RATE",
                    reg_out_frame_rate(self.channel_index),
                    out_fps,
                ),
            ]
        )
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def set_dv_timings(self, stem: str, fps: int) -> int:
        spec = (
            "cvt,"
            f"width={self.width},height={self.height},fps={fps},"
            "interlaced=0,reduced-blanking=0,reduced-fps=0"
        )
        return self.run_command(
            stem,
            ["v4l2-ctl", "-d", self.device, f"--set-dv-bt-timings={spec}"],
        )

    def start_stream(self, stem: str, duration_secs: int) -> tuple[subprocess.Popen[str], Path]:
        outfile = self.outdir / f"{stem}.txt"
        argv = [
            "timeout",
            f"{duration_secs}s",
            "v4l2-ctl",
            "-d",
            self.device,
            "--stream-mmap=4",
            "--stream-count=999999",
            "--stream-poll",
            "--stream-no-query",
            "--stream-to=/dev/null",
            "--verbose",
        ]
        fh = outfile.open("w", encoding="utf-8")
        proc = subprocess.Popen(
            argv,
            stdout=fh,
            stderr=subprocess.STDOUT,
            text=True,
        )
        setattr(proc, "_fh", fh)
        self.log_command(argv, -999, outfile)
        return proc, outfile

    def finish_stream(self, stem: str, proc: subprocess.Popen[str], outfile: Path) -> int:
        rc = proc.wait()
        fh = getattr(proc, "_fh")
        fh.close()
        (self.outdir / f"{stem}.rc").write_text(f"{rc}\n", encoding="utf-8")
        self.log_command(["wait", stem], rc, outfile)
        return rc

    def watch_source_change_events(self, stem: str, duration_secs: int) -> threading.Thread:
        thread = threading.Thread(
            target=self._watch_source_change_events,
            args=(stem, duration_secs),
            daemon=True,
        )
        thread.start()
        return thread

    def _watch_source_change_events(self, stem: str, duration_secs: int) -> None:
        outfile = self.outdir / f"{stem}.events.txt"
        countfile = self.outdir / f"{stem}.events.count"
        deadline = time.monotonic() + duration_secs
        count = 0

        fd: int | None = None
        subscription = V4L2EventSubscription(type=V4L2_EVENT_SOURCE_CHANGE, id=0, flags=0)

        with outfile.open("w", encoding="utf-8") as fh:
            try:
                fd = os.open(self.device, os.O_RDONLY | os.O_NONBLOCK)
                ioctl_struct(fd, VIDIOC_SUBSCRIBE_EVENT, subscription)
                fh.write(f"$ subscribe source_change=0 on {self.device}\n")

                poller = select.poll()
                poller.register(
                    fd,
                    select.POLLPRI
                    | getattr(select, "POLLIN", 0)
                    | getattr(select, "POLLERR", 0)
                    | getattr(select, "POLLHUP", 0),
                )

                while True:
                    remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
                    if remaining_ms == 0:
                        break
                    ready = poller.poll(remaining_ms)
                    if not ready:
                        continue
                    for _, mask in ready:
                        fh.write(f"[poll mask=0x{mask:x}]\n")
                        while True:
                            event = V4L2Event()
                            try:
                                ioctl_struct(fd, VIDIOC_DQEVENT, event)
                            except OSError as exc:
                                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                                    break
                                fh.write(f"[dqevent failed: {exc}]\n")
                                break

                            if event.type != V4L2_EVENT_SOURCE_CHANGE:
                                fh.write(
                                    f"type={event.type} sequence={event.sequence} pending={event.pending} id={event.id}\n"
                                )
                                continue

                            count += 1
                            changes = event.u.src_change.changes
                            labels: list[str] = []
                            if changes & V4L2_EVENT_SRC_CH_RESOLUTION:
                                labels.append("RESOLUTION")
                            label_text = ",".join(labels) if labels else "none"
                            fh.write(
                                "type=source_change "
                                f"sequence={event.sequence} pending={event.pending} "
                                f"id={event.id} changes=0x{changes:08x} ({label_text}) "
                                f"timestamp={event.timestamp.tv_sec}.{event.timestamp.tv_nsec:09d}\n"
                            )
                        fh.flush()
            except OSError as exc:
                fh.write(f"[event watch failed: {exc}]\n")
            finally:
                if fd is not None:
                    try:
                        ioctl_struct(fd, VIDIOC_UNSUBSCRIBE_EVENT, subscription)
                    except OSError:
                        pass
                    os.close(fd)

        countfile.write_text(f"{count}\n", encoding="utf-8")

    def capture_series(self, stem: str, duration_secs: int) -> None:
        deadline = time.monotonic() + duration_secs
        idx = 0
        while True:
            self.capture_snapshot(f"{stem}.tick{idx:03d}")
            idx += 1
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(float(self.interval_secs), remaining))

    def signal_external_ready(self) -> None:
        if not self.external_ready_file:
            return
        self.external_ready_file.parent.mkdir(parents=True, exist_ok=True)
        self.external_ready_file.write_text(
            f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n",
            encoding="utf-8",
        )

    def compare_pair(self, label: str, left_stem: str, right_stem: str) -> None:
        status = compare_text_files(
            self.outdir / f"{left_stem}.txt",
            self.outdir / f"{right_stem}.txt",
        )
        self.append_summary(f"{label}: {status}")

    def summarize_rc(self, label: str, stem: str) -> None:
        rc_path = self.outdir / f"{stem}.rc"
        rc_text = rc_path.read_text(encoding="utf-8").strip() if rc_path.exists() else "missing"
        output_path = self.outdir / f"{stem}.txt"
        output_text = (
            output_path.read_text(encoding="utf-8", errors="replace")
            if output_path.exists()
            else ""
        )
        self.append_summary(f"{label}: {describe_command_rc(rc_text, output_text)}")

    def summarize_event_count(self, label: str, stem: str) -> None:
        path = self.outdir / f"{stem}.events.count"
        count = path.read_text(encoding="utf-8").strip() if path.exists() else "missing"
        self.append_summary(f"{label}: count={count}")

    def summarize_stream_observation(self, label: str, stem: str) -> None:
        path = self.outdir / f"{stem}.txt"
        summary = summarize_stream_log(path)
        if not summary:
            self.append_summary(f"{label}: no dqbuf samples captured")
            return
        self.append_summary(
            f"{label}: buffers={summary['buffers']} seq={summary['first_seq']}->{summary['last_seq']} approx_fps={summary['fps']:.2f}"
        )

    def write_final_summary(self) -> None:
        self.append_summary(f"results_dir={self.outdir}")
        self.append_summary(f"device={self.device}")
        if self.video_sysfs:
            try:
                name = (self.video_sysfs / "name").read_text(encoding="utf-8").strip()
                self.append_summary(f"video_node_name={name}")
            except OSError:
                pass
        if self.channel_index is not None:
            self.append_summary(f"channel_index={self.channel_index}")
        if self.bar0_path:
            self.append_summary(f"bar0_path={self.bar0_path}")

        self.summarize_rc("idle S_DV_TIMINGS target", "idle.set_target")
        self.compare_pair(
            "idle G_DV_TIMINGS baseline->after_target",
            "baseline.g_dv_timings",
            "idle.after_target.g_dv_timings",
        )
        self.compare_pair(
            "idle QUERY_DV_TIMINGS baseline->after_target",
            "baseline.query_dv_timings",
            "idle.after_target.query_dv_timings",
        )
        self.compare_pair(
            "idle G_PARM baseline->after_target",
            "baseline.g_parm",
            "idle.after_target.g_parm",
        )
        self.compare_pair(
            "idle BAR0 baseline->after_target",
            "baseline.bar0",
            "idle.after_target.bar0",
        )

        self.summarize_rc("live S_DV_TIMINGS target", "live.set_target")
        self.summarize_rc("live stream", "live.stream")
        self.summarize_stream_observation("live observed stream", "live.stream")
        self.summarize_event_count("live source_change events", "live")
        self.compare_pair(
            "live G_DV_TIMINGS before->after_set",
            "live.before_set.g_dv_timings",
            "live.after_set.g_dv_timings",
        )
        self.compare_pair(
            "live QUERY_DV_TIMINGS before->after_set",
            "live.before_set.query_dv_timings",
            "live.after_set.query_dv_timings",
        )
        self.compare_pair(
            "live G_PARM before->after_set",
            "live.before_set.g_parm",
            "live.after_set.g_parm",
        )
        self.compare_pair(
            "live BAR0 before->after_set",
            "live.before_set.bar0",
            "live.after_set.bar0",
        )

        if self.observe_secs > 0:
            self.summarize_rc("external stream", "external.stream")
            self.summarize_stream_observation("external observed stream", "external.stream")
            self.summarize_event_count("external source_change events", "external")
            self.compare_pair(
                "external QUERY_DV_TIMINGS before->after",
                "external.before.query_dv_timings",
                "external.after.query_dv_timings",
            )
            self.compare_pair(
                "external G_DV_TIMINGS before->after",
                "external.before.g_dv_timings",
                "external.after.g_dv_timings",
            )
            self.compare_pair(
                "external G_PARM before->after",
                "external.before.g_parm",
                "external.after.g_parm",
            )
            self.compare_pair(
                "external BAR0 before->after",
                "external.before.bar0",
                "external.after.bar0",
            )

        self.append_summary(
            "Interpretation guide: live S_DV_TIMINGS returning EBUSY means a real input signal is present and the driver refuses live retiming."
        )
        self.append_summary(
            "Interpretation guide: external QUERY/G_DV/G_PARM/BAR0 changes show whether the receiver state tracks the real HDMI source timing."
        )
        self.append_summary(
            "Interpretation guide: external timing changes with zero source_change events indicate the driver still misses fps-only V4L2_EVENT_SOURCE_CHANGE notifications."
        )


def normalize_device(device: str) -> str:
    if device.isdigit():
        return f"/dev/video{device}"
    return device


def resolve_video_sysfs(device: str) -> Path | None:
    name = Path(device).name
    path = Path("/sys/class/video4linux") / name
    return path if path.exists() else None


def resolve_channel_index(video_sysfs: Path | None) -> int | None:
    if not video_sysfs:
        return None
    index_path = video_sysfs / "index"
    if not index_path.exists():
        return None
    try:
        return int(index_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def resolve_bar0_path(user_path: str | None, video_sysfs: Path | None) -> Path | None:
    if user_path:
        return Path(user_path)
    if not video_sysfs:
        return None
    debugfs_candidate = resolve_debugfs_bar0_path(video_sysfs)
    if debugfs_candidate:
        return debugfs_candidate
    candidate = video_sysfs / "device" / "resource0"
    if candidate.exists():
        return candidate.resolve()
    return None


def resolve_debugfs_bar0_path(video_sysfs: Path) -> Path | None:
    pci_bdf = resolve_pci_bdf(video_sysfs)
    if not pci_bdf:
        return None
    candidate = Path("/sys/kernel/debug/hws") / pci_bdf / "bar0_snapshot"
    return candidate if candidate.exists() else None


def resolve_pci_bdf(video_sysfs: Path) -> str | None:
    search_roots = [video_sysfs]
    device_link = video_sysfs / "device"
    if device_link.exists():
        search_roots.insert(0, device_link.resolve())

    for root in search_roots:
        for path in (root, *root.parents):
            name = path.name
            if PCI_BDF_RE.match(name):
                return name
    return None


def is_driver_bar0_snapshot(path: Path) -> bool:
    return path.name == "bar0_snapshot"


def read_bar0_bytes(path: Path) -> bytes:
    size = resolve_bar0_size(path)
    errors: list[str] = []

    for flags, label in (
        (os.O_RDONLY, "resource0 pread rdonly"),
        (os.O_RDONLY | getattr(os, "O_SYNC", 0), "resource0 pread rdonly+sync"),
        (os.O_RDWR, "resource0 pread rdwr"),
    ):
        try:
            return read_bar0_via_pread(path, size, flags)
        except OSError as exc:
            errors.append(f"{path} ({label}): {exc}")

    for mode, kwargs, label in (
        ("rb", {"access": mmap.ACCESS_READ}, "resource0 mmap access=READ"),
        ("rb", {"flags": mmap.MAP_SHARED, "prot": mmap.PROT_READ}, "resource0 mmap shared+prot"),
        ("r+b", {"access": mmap.ACCESS_READ}, "resource0 mmap rw access=READ"),
        (
            "r+b",
            {"flags": mmap.MAP_SHARED, "prot": mmap.PROT_READ | mmap.PROT_WRITE},
            "resource0 mmap rw shared+prot",
        ),
        ("rb", {"length": 0, "access": mmap.ACCESS_READ}, "resource0 mmap full-file access=READ"),
    ):
        try:
            with path.open(mode) as fh:
                mm = mmap.mmap(fh.fileno(), kwargs.pop("length", size), **kwargs)
                try:
                    return mm.read(size)
                finally:
                    mm.close()
        except OSError as exc:
            errors.append(f"{path} ({mode}, {label}): {exc}")

    dev_mem = Path("/dev/mem")
    resource_file = path.parent / "resource"
    if dev_mem.exists() and resource_file.exists():
        try:
            return read_bar0_via_dev_mem(dev_mem, resource_file, size)
        except OSError as exc:
            errors.append(f"{dev_mem} (BAR0 via resource file): {exc}")

    raise OSError("; ".join(errors))


def resolve_bar0_size(path: Path) -> int:
    sizes: list[int] = []
    try:
        stat_size = path.stat().st_size
        if stat_size > 0:
            sizes.append(stat_size)
    except OSError:
        pass

    resource_file = path.parent / "resource"
    if resource_file.exists():
        try:
            first = resource_file.read_text(encoding="utf-8").splitlines()[0].split()
            if len(first) >= 2:
                start = int(first[0], 16)
                end = int(first[1], 16)
                if end >= start:
                    sizes.append(end - start + 1)
        except (OSError, ValueError, IndexError):
            pass

    sizes.append(BAR0_SIZE)
    return min(size for size in sizes if size > 0)


def read_bar0_via_pread(path: Path, size: int, flags: int) -> bytes:
    fd = os.open(path, flags)
    try:
        chunks: list[bytes] = []
        offset = 0
        while offset < size:
            chunk = os.pread(fd, size - offset, offset)
            if not chunk:
                raise OSError(f"short pread at offset 0x{offset:04x}")
            chunks.append(chunk)
            offset += len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_bar0_via_dev_mem(dev_mem: Path, resource_file: Path, size: int) -> bytes:
    first = resource_file.read_text(encoding="utf-8").splitlines()[0].split()
    if len(first) < 2:
        raise OSError(f"could not parse BAR0 base from {resource_file}")

    bar_start = int(first[0], 16)
    page_size = mmap.PAGESIZE
    page_base = bar_start & ~(page_size - 1)
    page_off = bar_start - page_base
    map_size = page_off + size

    with dev_mem.open("r+b", buffering=0) as fh:
        mm = mmap.mmap(
            fh.fileno(),
            length=map_size,
            flags=mmap.MAP_SHARED,
            prot=mmap.PROT_READ,
            offset=page_base,
        )
        try:
            return mm[page_off : page_off + size]
        finally:
            mm.close()


def read_u32_from_bytes(data: bytes, offset: int) -> int:
    data = data[offset : offset + 4]
    if len(data) != 4:
        raise OSError(f"short read at offset 0x{offset:04x}")
    return struct.unpack("<I", data)[0]


def format_active_status(ch: int, value: int) -> str:
    active = 1 if value & (1 << ch) else 0
    interlaced = 1 if value & (1 << (8 + ch)) else 0
    return (
        f"ACTIVE_STATUS offset=0x{reg_active_status():04X} value=0x{value:08X} "
        f"active_ch{ch}={active} interlaced_ch{ch}={interlaced}"
    )


def format_resolution_reg(name: str, offset: int, value: int) -> str:
    width = value & 0xFFFF
    height = (value >> 16) & 0xFFFF
    return (
        f"{name} offset=0x{offset:04X} value=0x{value:08X} "
        f"width={width} height={height}"
    )


def format_bchs_reg(offset: int, value: int) -> str:
    brightness = value & 0xFF
    contrast = (value >> 8) & 0xFF
    hue = (value >> 16) & 0xFF
    saturation = (value >> 24) & 0xFF
    return (
        f"BCHS offset=0x{offset:04X} value=0x{value:08X} "
        f"brightness={brightness} contrast={contrast} hue={hue} saturation={saturation}"
    )


def format_fps_reg(name: str, offset: int, value: int) -> str:
    return f"{name} offset=0x{offset:04X} value=0x{value:08X} fps={value}"


def ioctl_struct(fd: int, request: int, cobj: ctypes.Structure) -> None:
    buf = bytearray(ctypes.string_at(ctypes.addressof(cobj), ctypes.sizeof(cobj)))
    fcntl.ioctl(fd, request, buf, True)
    ctypes.memmove(ctypes.addressof(cobj), bytes(buf), ctypes.sizeof(cobj))


def describe_command_rc(rc_text: str, output_text: str) -> str:
    try:
        rc = int(rc_text)
    except ValueError:
        return f"rc={rc_text}"

    if rc == 124:
        return "rc=124 (timeout)"

    for snippet, errno_name in (
        ("Device or resource busy", "EBUSY"),
        ("Invalid argument", "EINVAL"),
        ("No such device", "ENODEV"),
        ("No such file or directory", "ENOENT"),
        ("Link has been severed", "ENOLINK"),
        ("Operation not supported", "EOPNOTSUPP"),
        ("Operation not permitted", "EPERM"),
    ):
        if snippet in output_text:
            return f"rc={rc} ({errno_name})"

    return f"rc={rc}"


def compare_text_files(left: Path, right: Path) -> str:
    if not left.exists() or not right.exists():
        return "missing"
    left_text = left.read_text(encoding="utf-8", errors="replace")
    right_text = right.read_text(encoding="utf-8", errors="replace")
    if left_text == right_text:
        if is_error_snapshot(left_text):
            return "same-error"
        return "same"
    return "changed"


def is_error_snapshot(text: str) -> bool:
    first_line = text.lstrip().splitlines()[0] if text.strip() else ""
    return first_line.startswith(
        (
            "BAR0 read failed:",
            "error:",
            "channel index unavailable",
            "BAR0 path unavailable",
        )
    )


def summarize_stream_log(path: Path) -> dict[str, float | int] | None:
    if not path.exists():
        return None

    samples: list[tuple[int, float]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = DQBUF_RE.search(line)
        if not match:
            continue
        samples.append((int(match.group(1)), float(match.group(2))))

    if not samples:
        return None

    first_seq, first_ts = samples[0]
    last_seq, last_ts = samples[-1]
    fps = 0.0
    if len(samples) > 1 and last_ts > first_ts:
        fps = (len(samples) - 1) / (last_ts - first_ts)

    return {
        "buffers": len(samples),
        "first_seq": first_seq,
        "last_seq": last_seq,
        "fps": fps,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Probe HWS DV timings behavior on a live HDMI input.",
        add_help=False,
    )
    parser.add_argument("--help", action="help", help="show this help message and exit")
    parser.add_argument("-d", "--device", default="/dev/video3", help="capture device")
    parser.add_argument("-w", "--width", type=int, default=1920, help="timing width")
    parser.add_argument("-h", "--height", dest="height", type=int, default=1080, help="timing height")
    parser.add_argument("-f", "--from-fps", type=int, default=60, help="baseline fps")
    parser.add_argument("-t", "--to-fps", type=int, default=30, help="target fps for S_DV_TIMINGS")
    parser.add_argument("-s", "--stream-secs", type=int, default=15, help="stream duration for the live S_DV_TIMINGS phase")
    parser.add_argument("-m", "--observe-secs", type=int, default=0, help="manual external-source observation window")
    parser.add_argument("-i", "--interval-secs", type=int, default=1, help="poll interval for snapshots and event waits")
    parser.add_argument("-b", "--bar0-path", help="override BAR0 resource path")
    parser.add_argument("-o", "--outdir", help="override output directory")
    parser.add_argument("--external-ready-file", help="touch this file once the external observation stream is running")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    probe = Probe(args)

    probe.append_summary("Starting Hans DV timing probe")
    probe.capture_environment()
    probe.capture_snapshot("baseline")

    probe.append_summary(
        f"Idle phase: request {probe.width}x{probe.height}@{probe.to_fps} while not streaming (the HDMI signal may still be live)"
    )
    probe.set_dv_timings("idle.set_target", probe.to_fps)
    probe.capture_snapshot("idle.after_target")
    probe.append_summary(
        f"Idle restore phase: request {probe.width}x{probe.height}@{probe.from_fps}"
    )
    probe.set_dv_timings("idle.restore", probe.from_fps)
    probe.capture_snapshot("idle.after_restore")

    probe.append_summary("Live phase: stream, request S_DV_TIMINGS, then resample state")
    live_proc, live_out = probe.start_stream("live.stream", probe.stream_secs)
    live_events = probe.watch_source_change_events("live", probe.stream_secs)
    time.sleep(min(2, max(1, probe.stream_secs // 4)))
    probe.capture_snapshot("live.before_set")
    probe.set_dv_timings("live.set_target", probe.to_fps)
    probe.capture_snapshot("live.after_set")
    probe.finish_stream("live.stream", live_proc, live_out)
    live_events.join()
    probe.capture_snapshot("live.after_stream")
    probe.set_dv_timings("live.restore", probe.from_fps)
    probe.capture_snapshot("live.after_restore")

    if probe.observe_secs > 0:
        probe.append_summary(
            f"External observation phase: observe the Titan RTX HDMI source during the next {probe.observe_secs} seconds"
        )
        probe.capture_snapshot("external.before")
        ext_proc, ext_out = probe.start_stream("external.stream", probe.observe_secs)
        ext_events = probe.watch_source_change_events("external", probe.observe_secs)
        probe.signal_external_ready()
        probe.capture_series("external.series", probe.observe_secs)
        probe.finish_stream("external.stream", ext_proc, ext_out)
        ext_events.join()
        probe.capture_snapshot("external.after")

    probe.write_final_summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
