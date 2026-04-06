#!/usr/bin/env python3
"""
Snapshot HWS audio debugfs state repeatedly and summarize where the DMA scratch
buffer changes. This is the reliable way to find live audio payload bytes on the
host: BAR0 gives register/remap state, while audio_scratch_chN exposes the
actual coherent DMA buffer the device is writing.
"""

from __future__ import annotations

import argparse
import itertools
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Probe HWS audio DMA scratch buffers")
    parser.add_argument("--pci-bdf", default="0000:17:00.0",
                        help="PCI BDF used under /sys/kernel/debug/hws")
    parser.add_argument("--channel", type=int, default=3,
                        help="Audio channel to inspect")
    parser.add_argument("--samples", type=int, default=12,
                        help="Number of snapshots to capture")
    parser.add_argument("--interval-ms", type=int, default=200,
                        help="Delay between snapshots in milliseconds")
    parser.add_argument("--output-dir", type=Path,
                        help="Directory for snapshots; default is /tmp timestamp dir")
    parser.add_argument("--include-bar0", action="store_true",
                        help="Save bar0_snapshot for each sample as well")
    return parser.parse_args()


def timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def changed_spans(prev: bytes, cur: bytes) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start = None
    for idx, (a, b) in enumerate(zip(prev, cur)):
        if a != b:
            if start is None:
                start = idx
        elif start is not None:
            spans.append((start, idx))
            start = None
    if start is not None:
        spans.append((start, min(len(prev), len(cur))))
    return spans


def compress_indices(indices: list[int]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for _, group in itertools.groupby(enumerate(indices), lambda x: x[1] - x[0]):
        block = list(group)
        spans.append((block[0][1], block[-1][1] + 1))
    return spans


def half_counts(spans: list[tuple[int, int]]) -> tuple[int, int, int]:
    first = 0
    second = 0
    other = 0
    for start, end in spans:
        first += max(0, min(end, 4096) - min(start, 4096))
        second += max(0, min(end, 8192) - max(start, 4096))
        if end > 8192:
            other += end - max(start, 8192)
    return first, second, other


def main() -> int:
    args = parse_args()

    root = Path("/sys/kernel/debug/hws") / args.pci_bdf
    state_path = root / "audio_state"
    scratch_path = root / f"audio_scratch_ch{args.channel}"
    bar0_path = root / "bar0_snapshot"

    if args.output_dir is None:
        out_dir = Path("/tmp") / f"hws-audio-dma-probe-{timestamp()}"
    else:
        out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    if not state_path.exists():
        raise SystemExit(f"missing debugfs file: {state_path}")
    if not scratch_path.exists():
        raise SystemExit(f"missing debugfs file: {scratch_path}")
    if args.include_bar0 and not bar0_path.exists():
        raise SystemExit(f"missing debugfs file: {bar0_path}")

    scratch_snapshots: list[bytes] = []
    summary_lines: list[str] = [
        f"pci_bdf={args.pci_bdf}",
        f"channel={args.channel}",
        f"samples={args.samples}",
        f"interval_ms={args.interval_ms}",
        f"output_dir={out_dir}",
    ]

    for index in range(args.samples):
        sample_prefix = out_dir / f"sample_{index:02d}"
        state_text = read_text(state_path)
        scratch = read_bytes(scratch_path)

        sample_prefix.with_suffix(".audio_state.txt").write_text(
            state_text, encoding="utf-8"
        )
        sample_prefix.with_suffix(".audio_scratch.bin").write_bytes(scratch)
        if args.include_bar0:
            sample_prefix.with_suffix(".bar0.bin").write_bytes(read_bytes(bar0_path))

        scratch_snapshots.append(scratch)
        time.sleep(args.interval_ms / 1000.0)

    changed_indices: list[int] = []
    pair_lines: list[str] = []

    for index in range(1, len(scratch_snapshots)):
        prev = scratch_snapshots[index - 1]
        cur = scratch_snapshots[index]
        spans = changed_spans(prev, cur)
        active = [idx for start, end in spans for idx in range(start, end)]
        changed_indices.extend(active)
        first, second, other = half_counts(spans)
        pair_lines.append(
            f"pair_{index - 1:02d}_{index:02d}: spans={len(spans)} "
            f"first_half={first} second_half={second} tail={other}"
        )

    unique_changed = sorted(set(changed_indices))
    active_spans = compress_indices(unique_changed) if unique_changed else []

    summary_lines.extend(pair_lines)
    summary_lines.append(f"scratch_size={len(scratch_snapshots[0]) if scratch_snapshots else 0}")
    summary_lines.append(f"active_byte_count={len(unique_changed)}")
    for idx, (start, end) in enumerate(active_spans):
        summary_lines.append(f"active_span_{idx}=0x{start:04x}-0x{end - 1:04x} ({end - start} bytes)")

    if unique_changed:
        first = sum(1 for idx in unique_changed if idx < 4096)
        second = sum(1 for idx in unique_changed if 4096 <= idx < 8192)
        other = sum(1 for idx in unique_changed if idx >= 8192)
        summary_lines.append(f"active_first_half={first}")
        summary_lines.append(f"active_second_half={second}")
        summary_lines.append(f"active_tail={other}")

    summary_path = out_dir / "summary.txt"
    summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
