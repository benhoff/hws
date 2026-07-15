#!/usr/bin/env python3
"""Compatibility entry point for the safe allowlisted register monitor."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pci-bdf", default="0000:17:00.0")
    parser.add_argument("--snapshot-path", type=Path)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument(
        "--all", action="store_true", help="deprecated; all reads are now allowlisted"
    )
    args = parser.parse_args()
    tool = Path(__file__).with_name("hws_register_experiment.py")
    print(
        "bar0_monitor.py no longer scans the complete BAR because unknown MMIO "
        "reads may have side effects; using the allowlisted debugfs monitor.",
        file=sys.stderr,
    )
    command = [sys.executable, str(tool), "--pci-bdf", args.pci_bdf]
    if args.snapshot_path:
        command.extend(["--snapshot-path", str(args.snapshot_path)])
    command.extend(["monitor", "--interval-seconds", str(args.interval_seconds)])
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
