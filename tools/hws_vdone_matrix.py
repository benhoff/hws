#!/usr/bin/env python3
"""Create a canonical VDONE matrix row from a validated evidence bundle."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
from fractions import Fraction
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from hws_vdone_evidence import (
    EvidenceError,
    validate_bundle,
    verify_bundle_checksums,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX = ROOT / "doc" / "evidence" / "vdone-matrix.csv"


def parse_kv(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            result[key.strip()] = value.strip()
    return result


def number(mapping: dict[str, str], key: str) -> int:
    return int(mapping[key], 0)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fourcc(value: int) -> str:
    raw = struct.pack("<I", value)
    return raw.decode("ascii", errors="replace")


def load_frame_summary(path: Path) -> dict[str, object]:
    with path.open(encoding="utf-8") as stream:
        summaries = [json.loads(line) for line in stream if '"type":"summary"' in line]
    if len(summaries) != 1:
        raise ValueError("captured-frames.jsonl must contain exactly one summary")
    return summaries[0]


def make_row(args: argparse.Namespace, header: list[str]) -> list[str]:
    bundle = args.bundle.resolve()
    verify_bundle_checksums(bundle)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    summary = validate_bundle(bundle, manifest["channel"])
    config = parse_kv(bundle / "config-after.txt")
    stats_before = parse_kv(bundle / "stats-before.txt")
    stats = parse_kv(bundle / "stats-after.txt")
    frame = load_frame_summary(bundle / "captured-frames.jsonl")
    if args.status == "validated" and summary.get("result") != "pass":
        raise ValueError("a failed bundle cannot be recorded as validated")

    created = dt.datetime.fromisoformat(manifest["created_utc"])
    refresh = Fraction(number(config, "refresh_num"), number(config, "refresh_den"))
    refresh_value = float(refresh)
    refresh_text = f"{refresh_value:.6f}".rstrip("0").rstrip(".")
    mode_rate = f"{refresh_value:.3f}".rstrip("0").rstrip(".")
    scan = "i" if number(config, "interlaced") else "p"
    values = {
        "evidence_id": args.evidence_id,
        "status": args.status,
        "test_date_utc": created.date().isoformat(),
        "pci_vendor": config["vendor"],
        "pci_device": config["device"],
        "subsystem_vendor": config["subsystem_vendor"],
        "subsystem_device": config["subsystem_device"],
        "revision": config["revision"],
        "device_ver": config["device_ver"],
        "hw_ver": config["hw_ver"],
        "channel": str(manifest["channel"]),
        "mode": f"{config['width']}x{config['height']}{scan}{mode_rate}",
        "refresh_hz": refresh_text,
        "format": fourcc(number(config, "fourcc")),
        "sizeimage": config["sizeimage"],
        "dma_extent": config["dma_extent"],
        "split_bytes": config["split_bytes"],
        "split_register_16": config["split16_cached"],
        "split_readback_16": config["split16_readback"],
        "irq_mode": config["irq_mode"],
        "vdone_count": str(summary["vdone_observed"]),
        "elapsed_seconds": f"{manifest['elapsed_seconds']:.6f}",
        "vdone_rate_hz": f"{summary['vdone_rate_hz']:.6f}",
        "toggle_mapping": "toggle_xor_1",
        "frame_id_frames": str(frame["captured"]),
        "frame_id_mismatches": str(frame["id_mismatches"]),
        "backwards_ids": str(frame["backwards_ids"]),
        "guard_errors": str(
            number(stats, "guard_errors") - number(stats_before, "guard_errors")
        ),
        "partial_deliveries": str(frame["poison_errors"]),
        "unrecovered_queue_failures": stats["queue_failures"],
        "driver_commit": manifest["git_head"],
        "source_commit": args.source_commit or manifest["git_head"],
        "artifact_uri": args.artifact_uri,
        "artifact_sha256": sha256(bundle / "SHA256SUMS"),
        "notes": args.notes,
    }
    missing = [field for field in header if field not in values]
    if missing:
        raise ValueError(f"matrix has unsupported columns: {', '.join(missing)}")
    return [values[field] for field in header]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--evidence-id", required=True)
    parser.add_argument(
        "--status", choices=("validated", "failed", "inconclusive"), default="validated"
    )
    parser.add_argument("--artifact-uri", required=True)
    parser.add_argument("--source-commit", default="")
    parser.add_argument("--notes", default="")
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--append", action="store_true")
    args = parser.parse_args()
    try:
        with args.matrix.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.reader(stream))
        if not rows:
            raise ValueError("matrix has no header")
        if any(row and row[0] == args.evidence_id for row in rows[1:]):
            raise ValueError(f"duplicate evidence ID: {args.evidence_id}")
        row = make_row(args, rows[0])
        rendered = io.StringIO()
        csv.writer(rendered, lineterminator="\n").writerow(row)
        if args.append:
            with args.matrix.open("a", newline="", encoding="utf-8") as stream:
                csv.writer(stream, lineterminator="\n").writerow(row)
        else:
            sys.stdout.write(rendered.getvalue())
        return 0
    except (
        EvidenceError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        ZeroDivisionError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
