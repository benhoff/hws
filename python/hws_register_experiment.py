#!/usr/bin/env python3
"""Capture and compare allowlisted HWS register snapshots from debugfs.

This tool deliberately cannot mmap PCI resource0 and cannot write registers.
It accepts only snapshots emitted by the driver's register_snapshot interface,
which is generated from registers marked snapshot_safe in the register atlas.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
import time
from typing import Any


REGISTER_RE = re.compile(
    r"^register\s+id=(?P<id>\S+)\s+offset=0x(?P<offset>[0-9a-fA-F]+)\s+"
    r"value=0x(?P<value>[0-9a-fA-F]+)\s+channel=(?P<channel>-?\d+)\b"
)

EXPERIMENTS = {
    "cable": (
        "Disconnect the cable from the selected input and stop capture.",
        "Connect the cable to the same input without changing other settings.",
    ),
    "vcap": (
        "Leave the selected channel configured but not streaming.",
        "Start video capture on that channel with the same source and format.",
    ),
    "channel": (
        "Stream the chosen format on channel 0 only.",
        "Stop channel 0 and stream the same format on channel 1 only.",
    ),
    "resolution": (
        "Present a stable 1280x720 source on the selected channel.",
        "Change only that source to 1920x1080.",
    ),
    "queue-depth": (
        "Run the selected video channel with one queued VB2 buffer.",
        "Run the same workload with two queued VB2 buffers.",
    ),
    "audio": (
        "Leave the selected input connected with audio capture stopped.",
        "Start audio capture without changing the video source or format.",
    ),
    "custom": (
        "Establish and record the initial state.",
        "Change exactly one condition and record what changed.",
    ),
}


@dataclass(frozen=True)
class RegisterValue:
    reg_id: str
    offset: int
    value: int
    channel: int


@dataclass(frozen=True)
class Snapshot:
    metadata: dict[str, str]
    registers: dict[int, RegisterValue]
    raw: str


def root_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_number(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(value, 0)


def load_atlas(path: Path) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError(f"unsupported atlas schema in {path}")

    by_offset: dict[int, dict[str, Any]] = {}
    for reg in data["registers"]:
        base = parse_number(reg["offset"])
        channel = reg.get("channel")
        count = 1 if channel is None else parse_number(channel["count"])
        stride = 0 if channel is None else parse_number(channel["stride_bytes"])
        for instance in range(count):
            offset = base + instance * stride
            if offset in by_offset:
                raise ValueError(f"atlas has overlapping register offset 0x{offset:04x}")
            by_offset[offset] = {**reg, "instance": -1 if count == 1 else instance}
    return by_offset, data


def parse_metadata(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        result[key] = value
    return result


def parse_snapshot(text: str) -> Snapshot:
    metadata: dict[str, str] = {}
    registers: dict[int, RegisterValue] = {}

    for line in text.splitlines():
        if line.startswith("schema_version="):
            metadata.update(parse_metadata(line))
            continue
        match = REGISTER_RE.match(line)
        if not match:
            continue
        value = RegisterValue(
            reg_id=match.group("id"),
            offset=int(match.group("offset"), 16),
            value=int(match.group("value"), 16),
            channel=int(match.group("channel"), 10),
        )
        if value.offset in registers:
            raise ValueError(f"snapshot repeats offset 0x{value.offset:04x}")
        registers[value.offset] = value

    if metadata.get("allowlist_only") != "1":
        raise ValueError("refusing input that is not an allowlist-only driver snapshot")
    if metadata.get("schema_version") != "1":
        raise ValueError("unsupported or missing snapshot schema_version")
    if not registers:
        raise ValueError("snapshot contains no register values")
    return Snapshot(metadata=metadata, registers=registers, raw=text)


def read_snapshot(path: Path) -> Snapshot:
    if path.name not in {"register_snapshot", "bar0_snapshot"}:
        raise ValueError(
            f"refusing {path}: expected the driver's register_snapshot or bar0_snapshot"
        )
    return parse_snapshot(path.read_text(encoding="utf-8", errors="strict"))


def snapshot_to_json(snapshot: Snapshot, label: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "label": label,
        "captured_wall_time_ns": time.time_ns(),
        "driver_metadata": snapshot.metadata,
        "registers": [
            {
                "id": reg.reg_id,
                "offset": f"0x{reg.offset:04x}",
                "value": f"0x{reg.value:08x}",
                "channel": reg.channel,
            }
            for reg in sorted(snapshot.registers.values(), key=lambda item: item.offset)
        ],
    }


def write_snapshot(out_dir: Path, label: str, snapshot: Snapshot) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_") or "snapshot"
    text_path = out_dir / f"{safe_label}.snapshot.txt"
    json_path = out_dir / f"{safe_label}.snapshot.json"
    text_path.write_text(snapshot.raw, encoding="utf-8")
    json_path.write_text(
        json.dumps(snapshot_to_json(snapshot, label), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return text_path, json_path


def field_value(value: int, field: dict[str, Any]) -> int:
    lsb = parse_number(field["lsb"])
    msb = parse_number(field["msb"])
    mask = ((1 << (msb - lsb + 1)) - 1) << lsb
    return (value & mask) >> lsb


def diff_snapshots(
    before: Snapshot,
    after: Snapshot,
    atlas: dict[int, dict[str, Any]],
) -> list[str]:
    lines: list[str] = []
    offsets = sorted(set(before.registers) | set(after.registers))
    for offset in offsets:
        old = before.registers.get(offset)
        new = after.registers.get(offset)
        if old is None or new is None:
            lines.append(
                f"0x{offset:04x} presence changed: before={old is not None} after={new is not None}"
            )
            continue
        if old.value == new.value:
            continue

        desc = atlas.get(offset)
        reg_id = desc["id"] if desc else new.reg_id
        channel = new.channel
        xor = old.value ^ new.value
        lines.append(
            f"0x{offset:04x} {reg_id} ch={channel}: "
            f"0x{old.value:08x} -> 0x{new.value:08x} xor=0x{xor:08x}"
        )
        if desc:
            for field in desc.get("fields", []):
                if field.get("context") == "write":
                    continue
                old_field = field_value(old.value, field)
                new_field = field_value(new.value, field)
                if old_field != new_field:
                    lines.append(
                        f"  field {field['name']}[{field['msb']}:{field['lsb']}]: "
                        f"0x{old_field:x} -> 0x{new_field:x}"
                    )
    return lines


def load_saved_snapshot(path: Path) -> Snapshot:
    if path.suffix == ".txt":
        return parse_snapshot(path.read_text(encoding="utf-8"))
    data = json.loads(path.read_text(encoding="utf-8"))
    registers: dict[int, RegisterValue] = {}
    for item in data["registers"]:
        offset = parse_number(item["offset"])
        registers[offset] = RegisterValue(
            reg_id=item["id"],
            offset=offset,
            value=parse_number(item["value"]),
            channel=int(item["channel"]),
        )
    return Snapshot(
        metadata=data.get("driver_metadata", {}),
        registers=registers,
        raw="",
    )


def wait_for_user(prompt: str, delay_seconds: float | None) -> None:
    print(prompt)
    if delay_seconds is not None:
        if delay_seconds < 0:
            raise ValueError("delay must not be negative")
        print(f"Capturing in {delay_seconds:g} seconds...")
        time.sleep(delay_seconds)
        return
    if not sys.stdin.isatty():
        raise ValueError("interactive input unavailable; pass --delay-seconds")
    input("Press Enter to capture this state: ")


def default_snapshot_path(bdf: str) -> Path:
    return Path("/sys/kernel/debug/hws") / bdf / "register_snapshot"


def command_snapshot(args: argparse.Namespace, atlas: dict[int, dict[str, Any]]) -> int:
    snapshot = read_snapshot(args.snapshot_path)
    text_path, json_path = write_snapshot(args.output_dir, args.label, snapshot)
    print(f"captured {len(snapshot.registers)} allowlisted registers")
    print(text_path)
    print(json_path)
    return 0


def command_diff(args: argparse.Namespace, atlas: dict[int, dict[str, Any]]) -> int:
    before = load_saved_snapshot(args.before)
    after = load_saved_snapshot(args.after)
    lines = diff_snapshots(before, after, atlas)
    if not lines:
        print("no allowlisted register changes")
        return 0
    print("\n".join(lines))
    return 0


def command_pair(args: argparse.Namespace, atlas: dict[int, dict[str, Any]]) -> int:
    before_prompt, after_prompt = EXPERIMENTS[args.experiment]
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    out_dir = args.output_dir / f"{timestamp}-{args.experiment}"

    wait_for_user(f"Initial state: {before_prompt}", args.delay_seconds)
    before = read_snapshot(args.snapshot_path)
    write_snapshot(out_dir, "before", before)

    wait_for_user(f"Transition: {after_prompt}", args.delay_seconds)
    after = read_snapshot(args.snapshot_path)
    write_snapshot(out_dir, "after", after)

    lines = diff_snapshots(before, after, atlas)
    report = [
        f"experiment={args.experiment}",
        f"before_instruction={before_prompt}",
        f"after_instruction={after_prompt}",
        f"changed_lines={len(lines)}",
        "",
        *(lines or ["no allowlisted register changes"]),
    ]
    report_path = out_dir / "diff.txt"
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(lines or ["no allowlisted register changes"]))
    print(f"report: {report_path}")
    return 0


def command_monitor(args: argparse.Namespace, atlas: dict[int, dict[str, Any]]) -> int:
    previous = read_snapshot(args.snapshot_path)
    print(
        f"monitoring {len(previous.registers)} allowlisted registers every "
        f"{args.interval_seconds:g}s; Ctrl-C to stop"
    )
    try:
        while True:
            time.sleep(args.interval_seconds)
            current = read_snapshot(args.snapshot_path)
            lines = diff_snapshots(previous, current, atlas)
            if lines:
                print(f"--- {time.strftime('%Y-%m-%d %H:%M:%S')} ---")
                print("\n".join(lines), flush=True)
            previous = current
    except KeyboardInterrupt:
        return 0


def parse_args() -> argparse.Namespace:
    root = root_dir()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pci-bdf", default="0000:17:00.0")
    parser.add_argument(
        "--snapshot-path",
        type=Path,
        help="Driver debugfs register_snapshot path; resource0 is intentionally unsupported",
    )
    parser.add_argument(
        "--atlas",
        type=Path,
        default=root / "registers/hws_bar0_registers.json",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser("snapshot", help="capture one state")
    snapshot_parser.add_argument("--label", required=True)
    snapshot_parser.add_argument("--output-dir", type=Path, default=Path("/tmp/hws-registers"))

    diff_parser = subparsers.add_parser("diff", help="compare two saved snapshots")
    diff_parser.add_argument("before", type=Path)
    diff_parser.add_argument("after", type=Path)

    pair_parser = subparsers.add_parser("pair", help="guided controlled before/after experiment")
    pair_parser.add_argument("--experiment", choices=sorted(EXPERIMENTS), required=True)
    pair_parser.add_argument("--output-dir", type=Path, default=Path("/tmp/hws-register-experiments"))
    pair_parser.add_argument(
        "--delay-seconds",
        type=float,
        help="Non-interactive delay before each capture; otherwise wait for Enter",
    )

    monitor_parser = subparsers.add_parser("monitor", help="show changes between safe snapshots")
    monitor_parser.add_argument("--interval-seconds", type=float, default=1.0)

    args = parser.parse_args()
    if args.snapshot_path is None:
        args.snapshot_path = default_snapshot_path(args.pci_bdf)
    return args


def main() -> int:
    args = parse_args()
    try:
        atlas, _ = load_atlas(args.atlas)
        if args.command == "snapshot":
            return command_snapshot(args, atlas)
        if args.command == "diff":
            return command_diff(args, atlas)
        if args.command == "pair":
            return command_pair(args, atlas)
        if args.command == "monitor":
            if args.interval_seconds <= 0:
                raise ValueError("--interval-seconds must be positive")
            return command_monitor(args, atlas)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    raise AssertionError("unhandled command")


if __name__ == "__main__":
    raise SystemExit(main())
