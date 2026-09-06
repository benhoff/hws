#!/usr/bin/env python3
"""Run and validate a bounded HWS VDONE evidence capture.

The kernel event stream is recorded through trace-cmd, never printk. The
script refuses to disturb an active tracefs session and stores full details in
an immutable bundle while printing only periodic capture progress and a final
verdict.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

from hws_vdone_observers import (
    measure_vdone, validate_anomalies, validate_content, validate_mapping, validate_source,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAPTURE = ROOT / "tools" / "hws_frame_id_capture"
DEFAULT_MODULE = ROOT / "src" / "HwsCapture.ko"
TRACE_EVENTS = (
    "hws:hws_vdone_stream",
    "hws:hws_vdone_irq",
    "hws:hws_vdone_copy",
    "hws:hws_vdone_frame",
    "hws:hws_vdone_recovery",
    "hws:hws_vdone_probe",
)
FAILURE_PATTERNS = (
    "VDONE ambiguity",
    "VDONE half-ring failure",
    "video queue failed",
    "DMA guard corruption",
    "VIDIOC_DQBUF: failed",
)
REPRODUCIBLE_INPUTS = (
    "src/hws_debugfs.c",
    "src/hws_debugfs.h",
    "src/hws_trace.c",
    "src/hws_trace.h",
    "src/hws_probe.h",
    "tools/hws_frame_id_capture.c",
    "tools/hws_frame_id_source.html",
    "tools/hws_vdone_evidence.py",
    "tools/hws_vdone_observers.py",
    "tools/hws_frame_id_kms.c",
    "tools/hws_frame_pattern.h",
)


class EvidenceError(RuntimeError):
    pass


def run(
    command: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def sudo(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return run(["sudo", "-n", *command], **kwargs)


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise EvidenceError(f"required command is missing: {name}")


def read_text(path: Path, *, privileged: bool = False) -> str:
    if privileged:
        return sudo(["cat", str(path)]).stdout
    return path.read_text(encoding="utf-8")


def write_text_exclusive(path: Path, text: str) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(text)


def tracked_status() -> list[str]:
    return run(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT
    ).stdout.splitlines()


def untracked_reproducible_inputs() -> list[str]:
    missing: list[str] = []

    for relative in REPRODUCIBLE_INPUTS:
        result = run(
            ["git", "ls-files", "--error-unmatch", relative],
            check=False,
            cwd=ROOT,
        )
        if result.returncode:
            missing.append(relative)
    return missing


def parse_kv(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            result[key.strip()] = value.strip()
    return result


def integer(mapping: dict[str, str], key: str) -> int:
    try:
        return int(mapping[key], 0)
    except (KeyError, ValueError) as error:
        raise EvidenceError(f"missing or invalid integer {key!r}") from error


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def bundle_payload_files(bundle: Path) -> list[Path]:
    files: list[Path] = []

    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise EvidenceError(f"evidence bundle contains a symlink: {path}")
        if path.is_file() and path.name != "SHA256SUMS":
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(bundle).as_posix())


def write_bundle_checksums(bundle: Path) -> None:
    checksums = [
        f"{sha256(path)}  {path.relative_to(bundle).as_posix()}"
        for path in bundle_payload_files(bundle)
    ]
    write_text_exclusive(bundle / "SHA256SUMS", "\n".join(checksums) + "\n")


def verify_bundle_checksums(bundle: Path) -> None:
    checksum_path = bundle / "SHA256SUMS"

    if not checksum_path.is_file():
        raise EvidenceError(f"evidence bundle has no SHA256SUMS: {bundle}")
    expected: dict[str, str] = {}
    for line_number, line in enumerate(
        checksum_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        digest, separator, relative = line.partition("  ")
        candidate = Path(relative)
        if (
            not separator
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not relative
            or candidate.is_absolute()
            or ".." in candidate.parts
            or relative in expected
        ):
            raise EvidenceError(f"invalid SHA256SUMS entry at line {line_number}")
        expected[relative] = digest

    actual_paths = {
        path.relative_to(bundle).as_posix(): path
        for path in bundle_payload_files(bundle)
    }
    missing = sorted(set(expected) - set(actual_paths))
    unlisted = sorted(set(actual_paths) - set(expected))
    if missing or unlisted:
        raise EvidenceError(
            f"bundle inventory mismatch: missing={missing} unlisted={unlisted}"
        )
    for relative, path in actual_paths.items():
        if sha256(path) != expected[relative]:
            raise EvidenceError(f"checksum mismatch: {relative}")


def seal_bundle(bundle: Path) -> None:
    for path in bundle_payload_files(bundle):
        path.chmod(0o444)
    (bundle / "SHA256SUMS").chmod(0o444)
    directories = sorted(
        (path for path in bundle.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for path in directories:
        path.chmod(0o555)
    bundle.chmod(0o555)


def find_pci_bdf(device: Path) -> str:
    video_node = device.resolve().name
    sysfs = (Path("/sys/class/video4linux") / video_node / "device").resolve()
    for candidate in (sysfs, *sysfs.parents):
        if (candidate / "vendor").exists() and (candidate / "device").exists():
            if re.fullmatch(
                r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]",
                candidate.name,
            ):
                return candidate.name
    raise EvidenceError(f"cannot resolve PCI BDF for {device}")


def find_video_channel(device: Path) -> tuple[int, str]:
    video_node = device.resolve().name
    name_path = Path("/sys/class/video4linux") / video_node / "name"
    try:
        name = name_path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise EvidenceError(f"cannot read V4L2 identity for {device}") from error
    match = re.search(r"-hdmi([0-9]+)$", name)
    if not match:
        raise EvidenceError(f"cannot resolve HWS channel from V4L2 name {name!r}")
    return int(match.group(1)), name


def tracefs_path() -> Path:
    for candidate in (Path("/sys/kernel/tracing"), Path("/sys/kernel/debug/tracing")):
        if candidate.exists():
            return candidate
    raise EvidenceError("tracefs is not mounted")


def ensure_trace_idle(tracefs: Path) -> None:
    current_tracer = read_text(tracefs / "current_tracer", privileged=True).strip()
    events_enabled = read_text(tracefs / "events" / "enable", privileged=True).strip()
    if current_tracer != "nop" or events_enabled not in ("0", ""):
        raise EvidenceError(
            f"tracefs is already in use (events={events_enabled!r}, tracer={current_tracer})"
        )


def parse_frame_file(
    path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    configs: list[dict[str, Any]] = []
    frames: list[dict[str, Any]] = []
    summary: dict[str, Any] | None = None
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise EvidenceError(f"invalid JSONL at {path}:{line_number}") from error
            if summary is not None:
                raise EvidenceError("capture JSONL contains records after its terminal summary")
            if record.get("type") == "config":
                if configs or frames:
                    raise EvidenceError("capture configuration must be the first record")
                configs.append(record)
            elif record.get("type") == "frame":
                if not configs:
                    raise EvidenceError("capture frame precedes configuration")
                frames.append(record)
            elif record.get("type") == "summary":
                summary = record
            else:
                raise EvidenceError("capture JSONL contains an unsupported record")
    if summary is None:
        raise EvidenceError("capture JSONL has no terminal summary")
    if len(configs) != 1:
        raise EvidenceError("capture JSONL must contain exactly one configuration")
    return configs[0], frames, summary


def trace_fields(line: str) -> dict[str, str]:
    return dict(re.findall(r"([a-zA-Z0-9_]+)=([^\s]+)", line))


def trace_records(trace_path: Path, channel: int, epoch: int, device: str) -> dict[str, list[dict[str, str]]]:
    records: dict[str, list[dict[str, str]]] = {
        "irq": [], "copy": [], "frame": [], "recovery": [], "stream": [],
        "loss": [], "probe": [],
    }
    process = subprocess.Popen(
        ["trace-cmd", "report", "-i", str(trace_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    for line in process.stdout:
        if re.search(r"\b(?:LOST|MISSED)\s+[0-9]+\s+EVENTS?\b", line, re.I):
            records["loss"].append({"line": line.strip()})
            continue
        event = None
        for name in ("irq", "copy", "frame", "recovery", "stream", "probe"):
            if f"hws_vdone_{name}:" in line:
                event = name
                break
        if event is None:
            continue
        fields = trace_fields(line)
        if fields.get("device") != device:
            continue
        try:
            if int(fields.get("ch", "-1"), 0) != channel:
                continue
            if int(fields.get("epoch", "-1"), 0) != epoch:
                continue
        except ValueError:
            continue
        records[event].append(fields)
    stderr = process.communicate()[1]
    if process.returncode:
        raise EvidenceError(f"trace-cmd report failed: {stderr.strip()}")
    return records


def trace_loss(trace_stat: str) -> list[str]:
    failures: list[str] = []
    counters = 0
    for line in trace_stat.splitlines():
        match = re.search(r"\b(overrun|dropped events|commit overrun):\s*([0-9]+)", line)
        if match:
            counters += 1
            if int(match.group(2)):
                failures.append(line.strip())
        if "no overrun found" in line.lower():
            failures.append(line.strip())
    if not counters:
        failures.append("trace statistics contain no overrun counters")
    return failures


def validate_bundle(
    bundle: Path,
    channel: int | None = None,
    *,
    write_summary: bool = False,
) -> dict[str, Any]:
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    selected_channel = manifest["channel"] if channel is None else channel
    before = parse_kv((bundle / "stats-before.txt").read_text(encoding="utf-8"))
    after = parse_kv((bundle / "stats-after.txt").read_text(encoding="utf-8"))
    config_before = parse_kv((bundle / "config-before.txt").read_text(encoding="utf-8"))
    config_after = parse_kv((bundle / "config-after.txt").read_text(encoding="utf-8"))
    capture_config, frames, frame_summary = parse_frame_file(
        bundle / "captured-frames.jsonl"
    )
    epoch = integer(after, "stream_epoch")
    trace = trace_records(bundle / "kernel-trace.dat", selected_channel, epoch, manifest["pci_bdf"])
    failures: list[str] = []

    if manifest.get("schema") != 3:
        failures.append("bundle predates full-frame content and queue/timing evidence")
    failures.extend(validate_content(frames, capture_config, frame_summary, manifest))

    if manifest.get("tracked_status"):
        failures.append("driver evidence was captured from a dirty tracked tree")
    if manifest.get("untracked_reproducible_inputs"):
        failures.append("evidence inputs were not committed at capture time")

    stable_config_keys = (
        "pci_bdf", "vendor", "device", "subsystem_vendor",
        "subsystem_device", "revision", "device_ver", "hw_ver", "sub_ver",
        "port_id", "irq", "irq_mode", "channel", "width", "height",
        "fourcc", "bytesperline", "sizeimage", "fps", "interlaced",
        "pixelclock", "htotal", "vtotal", "refresh_num", "refresh_den",
        "dma_extent", "split_bytes", "split16_cached", "split16_readback",
    )
    for key in stable_config_keys:
        if config_before.get(key) != config_after.get(key):
            failures.append(
                f"configuration changed for {key}: "
                f"{config_before.get(key)!r} -> {config_after.get(key)!r}"
            )
    if integer(config_after, "channel") != selected_channel:
        failures.append("debugfs channel does not match the requested channel")
    if config_after.get("pci_bdf") != manifest.get("pci_bdf"):
        failures.append("debugfs PCI BDF does not match the manifest")
    for capture_key, config_key in (
        ("width", "width"),
        ("height", "height"),
        ("fourcc", "fourcc"),
        ("bytesperline", "bytesperline"),
        ("sizeimage", "sizeimage"),
        ("split", "split_bytes"),
    ):
        if int(capture_config.get(capture_key, -1)) != integer(
            config_after, config_key
        ):
            failures.append(
                f"capture {capture_key} does not match debugfs {config_key}"
            )
    native_split = (integer(config_after, "sizeimage") // 2) & ~2047
    if integer(config_after, "split_bytes") != native_split:
        failures.append(
            f"programmed split is not native: expected={native_split} "
            f"actual={config_after.get('split_bytes')}"
        )
    refresh_den = integer(config_after, "refresh_den")
    if not refresh_den:
        failures.append("DV timing refresh denominator is zero")
    if integer(config_after, "refresh_num") != integer(
        config_after, "pixelclock"
    ):
        failures.append("DV timing refresh numerator does not match pixelclock")
    if refresh_den != (
        integer(config_after, "htotal") * integer(config_after, "vtotal")
    ):
        failures.append("DV timing refresh denominator does not match totals")

    stream_actions: dict[int, list[dict[str, str]]] = {0: [], 1: []}
    for record in trace["stream"]:
        action = int(record.get("action", "-1"), 0)
        if action in stream_actions:
            stream_actions[action].append(record)
    for action, name in ((1, "start"), (0, "stop")):
        if len(stream_actions[action]) != 1:
            failures.append(
                f"expected one stream {name} trace, found {len(stream_actions[action])}"
            )
            continue
        record = stream_actions[action][0]
        for trace_key, config_key in (
            ("width", "width"),
            ("height", "height"),
            ("fourcc", "fourcc"),
            ("fps", "fps"),
            ("sizeimage", "sizeimage"),
            ("extent", "dma_extent"),
            ("split", "split_bytes"),
            ("split16", "split16_cached"),
        ):
            if int(record.get(trace_key, "-1"), 0) != integer(
                config_after, config_key
            ):
                failures.append(
                    f"stream {name} {trace_key} does not match {config_key}"
                )

    before_epoch = integer(before, "stream_epoch")
    expected_epoch = 1 if before_epoch == (1 << 64) - 1 else before_epoch + 1
    if epoch != expected_epoch:
        failures.append(
            f"stream epoch did not advance exactly once: {before_epoch} -> {epoch}"
        )
    if integer(after, "streaming") or integer(after, "cap_active"):
        failures.append("capture channel remained active after STREAMOFF")

    observed = integer(after, "vdone_observed")
    dispositions = sum(
        integer(after, key)
        for key in (
            "vdone_ignored", "vdone_accepted", "vdone_deferred",
            "vdone_resynced", "vdone_recovered", "vdone_fatal",
        )
    )
    if observed != dispositions:
        failures.append(
            f"VDONE accounting mismatch: observed={observed} "
            f"dispositions={dispositions}"
        )
    if len(trace["irq"]) != observed:
        failures.append(f"trace IRQ count {len(trace['irq'])} != stats observed {observed}")
    result_keys = {
        0: "vdone_ignored",
        1: "vdone_accepted",
        2: "vdone_resynced",
        3: "vdone_recovered",
        4: "vdone_deferred",
        5: "vdone_fatal",
    }
    for result, key in result_keys.items():
        traced = sum(
            int(record.get("result", "-1"), 0) == result
            for record in trace["irq"]
        )
        if traced != integer(after, key):
            failures.append(
                f"trace/stat disposition mismatch for {key}: "
                f"trace={traced} stats={after.get(key)}"
            )
    for completed_half in (0, 1):
        traced = sum(
            int(record.get("result", "-1"), 0) == 1
            and int(record.get("completed_half", "-1"), 0) == completed_half
            for record in trace["irq"]
        )
        key = f"completed_half{completed_half}"
        if traced != integer(after, key):
            failures.append(
                f"trace/stat completed-half mismatch for {key}: "
                f"trace={traced} stats={after.get(key)}"
            )
    accepted_irqs: dict[int, list[dict[str, str]]] = {}
    for record in trace["irq"]:
        if int(record.get("result", "-1"), 0) == 1:
            generation = int(record["generation"], 0)
            accepted_irqs.setdefault(generation, []).append(record)
            if not int(record.get("stable", "0"), 0):
                failures.append(
                    f"accepted unstable toggle at generation {record.get('generation')}"
                )
            if int(record.get("reasserted", "0"), 0):
                failures.append(
                    f"accepted reasserted VDONE at generation {record.get('generation')}"
                )
            expected = int(record["after"], 0) ^ 1
            if int(record.get("completed_half", "-1"), 0) != expected:
                failures.append(
                    f"toggle mapping mismatch at generation {record.get('generation')}"
                )
    successful_copies: dict[int, list[dict[str, str]]] = {}
    for record in trace["copy"]:
        if int(record.get("completed_half", "-1"), 0) != (
            int(record["toggle"], 0) ^ 1
        ):
            failures.append(f"copy mapping mismatch at generation {record.get('generation')}")
        if int(record.get("result", "-1"), 0) == 0:
            generation = int(record["generation"], 0)
            successful_copies.setdefault(generation, []).append(record)
            toggle = int(record.get("toggle", "-1"), 0)
            if (
                int(record.get("toggle_before", "-2"), 0) != toggle
                or int(record.get("toggle_after", "-2"), 0) != toggle
            ):
                failures.append(
                    f"toggle changed during successful copy generation {generation}"
                )
            matching_irqs = [
                irq
                for irq in accepted_irqs.get(generation, [])
                if int(irq.get("after", "-1"), 0)
                == int(record.get("toggle", "-2"), 0)
                and int(irq.get("completed_half", "-1"), 0)
                == int(record.get("completed_half", "-2"), 0)
            ]
            if len(matching_irqs) != 1:
                failures.append(
                    f"successful copy generation {generation} has "
                    f"{len(matching_irqs)} matching accepted IRQ records"
                )
            if not int(record.get("guard_checked", "0"), 0):
                failures.append(f"missing guard check at generation {generation}")
            elif not int(record.get("guard_ok", "0"), 0):
                failures.append(f"guard failure at generation {generation}")

    delivered_sequences = {
        int(record["sequence"], 0)
        for record in trace["frame"]
        if int(record.get("delivered", "0"), 0)
    }
    delivered_records = [
        record
        for record in trace["frame"]
        if int(record.get("delivered", "0"), 0)
    ]
    no_buffer_records = [
        record
        for record in trace["frame"]
        if int(record.get("no_buffer", "0"), 0)
    ]
    for record in trace["frame"]:
        delivered = bool(int(record.get("delivered", "0"), 0))
        no_buffer = bool(int(record.get("no_buffer", "0"), 0))
        if delivered == no_buffer:
            failures.append(
                f"invalid delivery flags for sequence {record.get('sequence')}"
            )
    if len(delivered_sequences) != len(delivered_records):
        failures.append("duplicate delivered sequence in frame trace")
    for records, key in (
        (trace["frame"], "frames_completed"),
        (delivered_records, "frames_delivered"),
        (no_buffer_records, "frames_no_buffer"),
    ):
        if len(records) != integer(after, key):
            failures.append(
                f"trace/stat frame mismatch for {key}: "
                f"trace={len(records)} stats={after.get(key)}"
            )
    captured_sequences = {int(frame["v4l2_sequence"]) for frame in frames}
    untested_deliveries = sorted(delivered_sequences - captured_sequences)
    if untested_deliveries:
        preview = untested_deliveries[:8]
        failures.append(
            f"{len(untested_deliveries)} delivered sequences lack content tests: "
            f"{preview}"
        )
    for record in trace["frame"]:
        if int(record.get("delivered", "0"), 0):
            half0 = int(record["half0_generation"], 0)
            half1 = int(record["half1_generation"], 0)
            if not half0 or half1 != half0 + 1:
                failures.append(f"non-complementary delivered generations {half0}/{half1}")
                continue
            if int(record.get("dropped_partial", "0"), 0):
                failures.append(f"delivered sequence {record['sequence']} was marked partial")
            split = integer(config_after, "split_bytes")
            expected_copies = (
                (half0, 0, 0, split, 0),
                (
                    half1,
                    1,
                    split,
                    integer(config_after, "sizeimage") - split,
                    1,
                ),
            )
            for (
                generation,
                completed_half,
                offset,
                length,
                completes_frame,
            ) in expected_copies:
                matches = [
                    copy
                    for copy in successful_copies.get(generation, [])
                    if int(copy.get("completed_half", "-1"), 0) == completed_half
                    and int(copy.get("offset", "-1"), 0) == offset
                    and int(copy.get("length", "-1"), 0) == length
                    and int(copy.get("frame_complete", "-1"), 0) == completes_frame
                    and int(copy.get("guard_checked", "0"), 0)
                    and int(copy.get("guard_ok", "0"), 0)
                ]
                if len(matches) != 1:
                    failures.append(
                        "delivered sequence "
                        f"{record['sequence']} has {len(matches)} valid copy records "
                        f"for half {completed_half} generation {generation}"
                    )
    for frame in frames:
        if int(frame["v4l2_sequence"]) not in delivered_sequences:
            failures.append(f"captured sequence {frame['v4l2_sequence']} lacks a delivery trace")
        for required in (
            "upper_valid", "lower_valid", "ids_match", "monotonic",
            "sequence_ok", "payload_ok",
        ):
            if not frame.get(required):
                failures.append(f"frame {frame['capture_index']} failed {required}")
        if frame.get("poison_half0") or frame.get("poison_half1"):
            failures.append(f"frame {frame['capture_index']} retained poison")

    if frame_summary.get("result") != "pass":
        failures.append("frame-ID capture reported failure")
    if len(frames) != manifest.get("target_frames"):
        failures.append(
            f"captured frame count {len(frames)} != target "
            f"{manifest.get('target_frames')}"
        )
    if frame_summary.get("captured") != len(frames):
        failures.append("frame-ID summary count does not match its frame records")
    if integer(after, "vdone_fatal"):
        failures.append("fatal VDONE disposition observed")
    if integer(after, "queue_failures"):
        failures.append("video queue failure observed")
    if integer(after, "ring_corrupt"):
        failures.append("video ring marked corrupt")
    if integer(after, "guard_errors") != integer(before, "guard_errors"):
        failures.append("guard error counter changed")
    recovery_reports = sum(
        int(record.get("reports", "0"), 0) for record in trace["recovery"]
    )
    if recovery_reports != integer(after, "recovery_reports"):
        failures.append(
            "trace/stat recovery report mismatch: "
            f"trace={recovery_reports} stats={after.get('recovery_reports')}"
        )
    recovery_classes = {
        "duplicate_reports": lambda record: (
            int(record.get("steady", "0"), 0)
            and int(record.get("reason", "-1"), 0) == 2
        ),
        "overlap_reports": lambda record: (
            int(record.get("steady", "0"), 0)
            and int(record.get("reason", "-1"), 0) != 2
        ),
        "resync_reports": lambda record: not int(
            record.get("steady", "0"), 0
        ),
    }
    for key, predicate in recovery_classes.items():
        traced = sum(
            int(record.get("reports", "0"), 0)
            for record in trace["recovery"]
            if predicate(record)
        )
        if traced != integer(after, key):
            failures.append(
                f"trace/stat recovery mismatch for {key}: "
                f"trace={traced} stats={after.get(key)}"
            )
    traced_partials = sum(
        bool(int(record.get("dropped_partial", "0"), 0))
        for record in trace["recovery"]
    )
    if traced_partials != integer(after, "partial_recycles"):
        failures.append(
            "trace/stat partial recycle mismatch: "
            f"trace={traced_partials} stats={after.get('partial_recycles')}"
        )
    split = integer(config_after, "split_bytes")
    if integer(config_after, "split16_readback") * 16 != split:
        failures.append("split register readback does not match split bytes")

    stat_text = (bundle / "trace-stat.txt").read_text(encoding="utf-8")
    failures.extend(f"trace loss: {line}" for line in trace_loss(stat_text))
    failures.extend(
        f"trace loss marker: {record['line']}" for record in trace["loss"]
    )
    kernel_text = (bundle / "kernel.log").read_text(encoding="utf-8")
    failures.extend(
        f"kernel failure signature: {pattern}"
        for pattern in FAILURE_PATTERNS
        if pattern in kernel_text
    )
    if manifest.get("capture_exit_code"):
        failures.append(f"frame-ID capture exited with status {manifest['capture_exit_code']}")

    mapping, mapping_failures = validate_mapping(
        [p for p in trace["probe"] if int(p.get("window", "0"), 0) == 0],
        trace["irq"], trace["frame"], frames, config_after,
        int(after.get("probe_count", "0"), 0),
    )
    failures.extend(mapping_failures)
    source_path = bundle / "source-presentation.jsonl"
    source_records = (
        [json.loads(line) for line in source_path.read_text(encoding="utf-8").splitlines()]
        if source_path.exists() else []
    )
    presentation, presentation_failures = validate_source(
        source_records, frames, config_after, manifest.get("boot_id"),
    )
    source_configs = [r for r in source_records if r.get("type") == "source_config"]
    if source_configs and (
        source_configs[0].get("pattern") != capture_config.get("pattern")
        or source_configs[0].get("pattern_sha256") != manifest.get("pattern_sha256")
    ):
        presentation["result"] = "fail"
        presentation_failures.append("source and capture full-frame patterns differ")
    if source_configs and (
        not manifest.get("kms_source_sha256")
        or source_configs[0].get("source_sha256") != manifest["kms_source_sha256"]
    ):
        presentation["result"] = "fail"
        presentation["repeat_attribution"] = "unresolved"
        presentation_failures.append("source binary build digest differs from the recorded source code")
    failures.extend(presentation_failures)

    anomalies, anomaly_failures = validate_anomalies(
        trace["probe"], trace["irq"], config_after, after,
        source_records, presentation["result"] == "pass",
    )
    failures.extend(anomaly_failures)

    timing, timing_failures = measure_vdone(trace["irq"])
    failures.extend(timing_failures)

    summary = {
        "schema": 3,
        "result": "pass" if not failures else "fail",
        "run_id": manifest["run_id"],
        "channel": selected_channel,
        "stream_epoch": epoch,
        "vdone_observed": observed,
        "vdone_rate_hz": timing["rate_hz"],
        "vdone_timing": timing,
        "irq_trace_records": len(trace["irq"]),
        "copy_trace_records": len(trace["copy"]),
        "frame_trace_records": len(trace["frame"]),
        "recovery_trace_records": len(trace["recovery"]),
        "captured_frames": len(frames),
        "frame_id_summary": frame_summary,
        "independent_mapping": mapping,
        "source_presentation": presentation,
        "anomaly_observation": anomalies,
        "failures": failures,
    }
    if write_summary:
        write_text_exclusive(
            bundle / "summary.json", json.dumps(summary, indent=2) + "\n"
        )
    return summary


def capture_file(command: list[str], path: Path, *, privileged: bool = False) -> None:
    completed = sudo(command, check=False) if privileged else run(command, check=False)
    write_text_exclusive(path, completed.stdout + completed.stderr)
    if completed.returncode:
        raise EvidenceError(
            f"evidence command failed ({completed.returncode}): {' '.join(command)}"
        )


def build_manifest(args: argparse.Namespace, run_id: str, bdf: str) -> dict[str, Any]:
    module = args.module.resolve()
    return {
        "schema": 3,
        "run_id": run_id,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "device": str(args.device),
        "pci_bdf": bdf,
        "channel": args.channel,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "source_telemetry_path": str(args.source_telemetry) if args.source_telemetry else None,
        "kms_source_sha256": sha256(ROOT / "tools" / "hws_frame_id_kms.c"),
        "pattern_sha256": sha256(ROOT / "tools" / "hws_frame_pattern.h"),
        "observer_validator_sha256": sha256(ROOT / "tools" / "hws_vdone_observers.py"),
        "target_frames": args.frames,
        "label": args.label,
        "git_head": run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip(),
        "git_branch": run(["git", "branch", "--show-current"], cwd=ROOT).stdout.strip(),
        "git_status": run(["git", "status", "--porcelain"], cwd=ROOT).stdout.splitlines(),
        "tracked_status": tracked_status(),
        "untracked_reproducible_inputs": untracked_reproducible_inputs(),
        "module_path": str(module),
        "module_sha256": sha256(module),
        "module_srcversion": run(["modinfo", "-F", "srcversion", str(module)]).stdout.strip(),
        "loaded_srcversion": Path("/sys/module/HwsCapture/srcversion").read_text().strip(),
        "frame_source_sha256": sha256(ROOT / "tools" / "hws_frame_id_source.html"),
        "capture_tool_sha256": sha256(args.capture.resolve()),
        "capture_source_sha256": sha256(ROOT / "tools" / "hws_frame_id_capture.c"),
        "evidence_runner_sha256": sha256(Path(__file__).resolve()),
        "kernel": os.uname().release,
        "trace_events": list(TRACE_EVENTS),
    }


def run_capture(args: argparse.Namespace) -> int:
    for command in ("sudo", "trace-cmd", "modinfo", "v4l2-ctl", "journalctl", "lspci"):
        require_command(command)
    if os.geteuid() == 0:
        raise EvidenceError(
            "run as the desktop user; the harness invokes sudo only for tracing and logs"
        )
    if not args.device.exists():
        raise EvidenceError(f"video device does not exist: {args.device}")
    if not args.capture.is_file() or not os.access(args.capture, os.X_OK):
        raise EvidenceError(f"capture tool is missing or not executable: {args.capture}")
    if not args.module.is_file():
        raise EvidenceError(f"module is missing: {args.module}")
    if args.source_telemetry:
        if not args.source_telemetry.is_file():
            raise EvidenceError("--source-telemetry must name the running source's JSONL file")
        if args.source_telemetry.stat().st_size > 128 * 1024 * 1024:
            raise EvidenceError("source telemetry exceeds the 128 MiB evidence bound")
    if not Path("/sys/module/HwsCapture/srcversion").exists():
        raise EvidenceError("HwsCapture is not loaded")
    dirty_tracked = tracked_status()
    missing_inputs = untracked_reproducible_inputs()
    if not args.allow_dirty and (dirty_tracked or missing_inputs):
        raise EvidenceError(
            "tracked sources are dirty or evidence inputs are uncommitted; "
            "commit the instrumentation or pass --allow-dirty for a non-validating run"
        )

    run(["sudo", "-v"], check=True, capture=False)
    node_channel, video_name = find_video_channel(args.device)
    if node_channel != args.channel:
        raise EvidenceError(
            f"{args.device} is {video_name!r} (channel {node_channel}), "
            f"not requested channel {args.channel}"
        )
    bdf = find_pci_bdf(args.device)
    debug_dir = Path(f"/sys/kernel/debug/hws-{bdf}/video{args.channel}")
    config_path = debug_dir / "config"
    stats_path = debug_dir / "stats"
    if not config_path.exists() or not stats_path.exists():
        raise EvidenceError(f"driver evidence files are missing under {debug_dir}")
    tracefs = tracefs_path()
    ensure_trace_idle(tracefs)

    built_srcversion = run(["modinfo", "-F", "srcversion", str(args.module)]).stdout.strip()
    loaded_srcversion = Path("/sys/module/HwsCapture/srcversion").read_text().strip()
    if built_srcversion != loaded_srcversion:
        raise EvidenceError("loaded module does not match the in-tree module")

    run_id = args.run_id or dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    bundle = args.bundle or Path(f"/tmp/hws-vdone-{run_id}")
    if not args.keep_timings:
        configured = run(
            ["v4l2-ctl", "-d", str(args.device), "--set-dv-bt-timings=query"],
            check=False,
        )
        if configured.returncode:
            raise EvidenceError(
                "failed to configure the detected DV timings before the evidence snapshot: "
                + configured.stderr.strip()
            )
    bundle.mkdir(mode=0o755, parents=True, exist_ok=False)
    manifest = build_manifest(args, run_id, bdf)
    manifest["v4l2_name"] = video_name
    write_text_exclusive(bundle / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    write_text_exclusive(bundle / "config-before.txt", read_text(config_path, privileged=True))
    write_text_exclusive(bundle / "stats-before.txt", read_text(stats_path, privileged=True))
    capture_file(["v4l2-ctl", "-d", str(args.device), "--all"], bundle / "v4l2.txt")
    capture_file(["lspci", "-nnvv", "-s", bdf], bundle / "pci.txt")
    capture_file(["cat", "/proc/interrupts"], bundle / "interrupts-before.txt", privileged=True)

    anomaly_dir = bundle / "anomalies"
    anomaly_dir.mkdir()

    start_epoch = int(time.time())
    trace_fd, trace_name = tempfile.mkstemp(prefix="hws-vdone-trace-", suffix=".dat")
    os.close(trace_fd)
    trace_tmp = Path(trace_name)
    trace_tmp.unlink()
    capture_command = [
        str(args.capture), "--device", str(args.device),
        "--output", str(bundle / "captured-frames.jsonl"),
        "--frames", str(args.frames), "--split",
        parse_kv(read_text(config_path, privileged=True))["split_bytes"],
        "--anomaly-dir", str(anomaly_dir),
    ]
    if args.keep_timings:
        capture_command.append("--keep-timings")

    capture_result = 2
    started = time.monotonic()
    try:
        username = pwd.getpwuid(os.getuid()).pw_name
        trace_record = [
            "trace-cmd", "record", "-q", "--date", "--user", username,
            "-b", "8192", "-o", str(trace_tmp),
        ]
        for event in TRACE_EVENTS:
            trace_record.extend(["-e", event])
        trace_record.extend(capture_command)
        completed = sudo(trace_record, check=False, capture=False)
        capture_result = completed.returncode
    finally:
        if trace_tmp.exists():
            sudo(["chown", f"{os.getuid()}:{os.getgid()}", str(trace_tmp)], check=False)
            shutil.move(str(trace_tmp), bundle / "kernel-trace.dat")
        sudo(["trace-cmd", "reset"], check=False)

    manifest["elapsed_seconds"] = time.monotonic() - started
    manifest["capture_exit_code"] = capture_result
    (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    write_text_exclusive(bundle / "config-after.txt", read_text(config_path, privileged=True))
    write_text_exclusive(bundle / "stats-after.txt", read_text(stats_path, privileged=True))
    capture_file(["cat", "/proc/interrupts"], bundle / "interrupts-after.txt", privileged=True)
    capture_file(
        ["journalctl", "-k", "-b", "--since", f"@{start_epoch}", "--no-pager"],
        bundle / "kernel.log",
        privileged=True,
    )
    if not (bundle / "kernel-trace.dat").exists():
        raise EvidenceError(f"trace extraction failed; bundle={bundle}")
    capture_file(
        ["trace-cmd", "report", "--stat", "-i", str(bundle / "kernel-trace.dat")],
        bundle / "trace-stat.txt",
    )

    if args.source_telemetry:
        # A source may still be running. Preserve only a complete, bounded
        # JSONL prefix; never alter its file or include a torn final record.
        with args.source_telemetry.open("rb") as source:
            payload = source.read(128 * 1024 * 1024 + 1)
        if len(payload) > 128 * 1024 * 1024:
            raise EvidenceError("source telemetry exceeds the 128 MiB evidence bound")
        last_newline = payload.rfind(b"\n")
        if last_newline < 0:
            raise EvidenceError("source telemetry has no complete records")
        write_text_exclusive(
            bundle / "source-presentation.jsonl",
            payload[:last_newline + 1].decode("utf-8"),
        )

    summary = validate_bundle(bundle, args.channel, write_summary=True)
    write_bundle_checksums(bundle)
    seal_bundle(bundle)
    print(
        f"VDONE evidence result={summary['result'].upper()} "
        f"events={summary['vdone_observed']} frames={summary['captured_frames']} bundle={bundle}"
    )
    return 0 if summary["result"] == "pass" else 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--run", action="store_true", help="perform a hardware capture")
    result.add_argument("--validate", type=Path, help="validate an existing evidence bundle")
    result.add_argument("--device", type=Path, default=Path("/dev/video1"))
    result.add_argument("--channel", type=int, choices=range(4))
    result.add_argument("--frames", type=int, default=36000)
    result.add_argument("--bundle", type=Path)
    result.add_argument("--run-id")
    result.add_argument("--label", default="native-split-frame-id")
    result.add_argument("--capture", type=Path, default=DEFAULT_CAPTURE)
    result.add_argument("--module", type=Path, default=DEFAULT_MODULE)
    result.add_argument(
        "--source-telemetry", type=Path,
        help="KMS source JSONL on the same host/boot; absence makes mapping validation non-passing",
    )
    result.add_argument("--keep-timings", action="store_true")
    result.add_argument(
        "--allow-dirty",
        action="store_true",
        help="collect diagnostics from an unreproducible tree (validation will fail)",
    )
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.validate:
            verify_bundle_checksums(args.validate)
            summary = validate_bundle(args.validate, args.channel)
            print(json.dumps(summary, indent=2))
            return 0 if summary["result"] == "pass" else 1
        if not args.run:
            parser().print_help()
            return 2
        if args.channel is None:
            args.channel = 1
        if args.frames < 1:
            raise EvidenceError("--frames must be positive")
        return run_capture(args)
    except (
        EvidenceError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
