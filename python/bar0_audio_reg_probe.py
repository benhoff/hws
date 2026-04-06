#!/usr/bin/env python3
"""
Probe HwsCapture BAR0 audio-related registers directly.

Use this as root on a development machine when the driver is loaded:

  sudo ./python/bar0_audio_reg_probe.py --write-probe

By default the script is read-only. With --write-probe it performs a reversible
stickiness test on:
  - INT_EN_REG_BASE
  - PCIEBR_EN_REG_BASE
  - PCIE_INT_DEC_REG_BASE
  - per-channel audio base registers at CVBS_IN_BUF_BASE + ((8 + ch) * 4)

The audio-base probe writes a harmless synthetic test pattern, reads it back
immediately, then restores the original value. Run the write probe only while
no capture streams are active.
"""

from __future__ import annotations

import argparse
import os
import struct
import time
from dataclasses import dataclass
from pathlib import Path


PCIE_BARADDROFSIZE = 4
PCI_BUS_ACCESS_BASE = 0x00000000
INT_EN_REG_BASE = PCI_BUS_ACCESS_BASE + 0x0134
PCIE_INT_DEC_REG_BASE = PCI_BUS_ACCESS_BASE + 0x0138
PCIEBR_EN_REG_BASE = PCI_BUS_ACCESS_BASE + 0x0148
CVBS_IN_BASE = 0x00004000
CVBS_IN_BUF_BASE = CVBS_IN_BASE + (16 * PCIE_BARADDROFSIZE)
PCI_ADDR_TABLE_BASE = 0x0
PCIEBAR_AXI_BASE = 0x20000000


@dataclass(frozen=True)
class ChannelRegs:
    channel: int
    audio_base_off: int
    shared_hi_off: int
    shared_lo_off: int
    audio_hi_off: int
    audio_lo_off: int
    abuf_toggle_off: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Probe HWS BAR0 audio registers")
    parser.add_argument("--pci-bdf", default="0000:17:00.0",
                        help="PCI device BDF under /sys/bus/pci/devices")
    parser.add_argument("--output-dir", type=Path,
                        help="Write a timestamped report directory under /tmp by default")
    parser.add_argument("--write-probe", action="store_true",
                        help="Perform reversible write/readback stickiness tests")
    parser.add_argument("--channels", default="0,1,2,3",
                        help="Comma-separated audio channels to probe")
    return parser.parse_args()


def timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def parse_channels(text: str) -> list[int]:
    channels: list[int] = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        ch = int(item, 10)
        if ch < 0 or ch > 3:
            raise ValueError(f"invalid channel: {item}")
        channels.append(ch)
    if not channels:
        raise ValueError("no channels requested")
    return channels


def channel_regs(ch: int) -> ChannelRegs:
    return ChannelRegs(
        channel=ch,
        audio_base_off=CVBS_IN_BUF_BASE + ((8 + ch) * PCIE_BARADDROFSIZE),
        shared_hi_off=PCI_ADDR_TABLE_BASE + 0x208 + ch * 8,
        shared_lo_off=PCI_ADDR_TABLE_BASE + 0x20C + ch * 8,
        audio_hi_off=PCI_ADDR_TABLE_BASE + 0x208 + (8 + ch) * 8,
        audio_lo_off=PCI_ADDR_TABLE_BASE + 0x20C + (8 + ch) * 8,
        abuf_toggle_off=CVBS_IN_BASE + (40 + ch) * PCIE_BARADDROFSIZE,
    )


class Bar0:
    def __init__(self, path: Path):
        self.path = path
        self.fd: int | None = None
        self.size: int = 0

    def __enter__(self) -> "Bar0":
        self.fd = os.open(self.path, os.O_RDWR | os.O_SYNC)
        self.size = os.fstat(self.fd).st_size
        if self.size <= 0:
            raise RuntimeError(f"invalid BAR size for {self.path}: {self.size}")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def read32(self, offset: int) -> int:
        assert self.fd is not None
        if offset < 0 or offset + 4 > self.size:
            raise ValueError(f"read offset out of range: 0x{offset:04x}")
        data = os.pread(self.fd, 4, offset)
        if len(data) != 4:
            raise RuntimeError(
                f"short read at 0x{offset:04x}: expected 4 bytes, got {len(data)}"
            )
        return struct.unpack("<I", data)[0]

    def write32(self, offset: int, value: int) -> None:
        assert self.fd is not None
        if offset < 0 or offset + 4 > self.size:
            raise ValueError(f"write offset out of range: 0x{offset:04x}")
        buf = struct.pack("<I", value & 0xFFFFFFFF)
        written = os.pwrite(self.fd, buf, offset)
        if written != 4:
            raise RuntimeError(
                f"short write at 0x{offset:04x}: expected 4 bytes, wrote {written}"
            )
        os.fsync(self.fd)


def read_snapshot(bar0: Bar0, channels: list[int]) -> list[str]:
    lines = [
        f"INT_EN=0x{bar0.read32(INT_EN_REG_BASE):08x}",
        f"PCIEBR_EN=0x{bar0.read32(PCIEBR_EN_REG_BASE):08x}",
        f"PCIE_INT_DEC=0x{bar0.read32(PCIE_INT_DEC_REG_BASE):08x}",
        f"ACTIVE_STATUS=0x{bar0.read32(CVBS_IN_BASE + 5 * PCIE_BARADDROFSIZE):08x}",
        f"ACAP_ENABLE=0x{bar0.read32(CVBS_IN_BASE + 3 * PCIE_BARADDROFSIZE):08x}",
        f"INT_STATUS=0x{bar0.read32(CVBS_IN_BASE + 1 * PCIE_BARADDROFSIZE):08x}",
    ]
    for ch in channels:
        regs = channel_regs(ch)
        lines.extend([
            f"ch{ch}.audio_base=0x{bar0.read32(regs.audio_base_off):08x}",
            f"ch{ch}.shared_hi=0x{bar0.read32(regs.shared_hi_off):08x}",
            f"ch{ch}.shared_lo=0x{bar0.read32(regs.shared_lo_off):08x}",
            f"ch{ch}.audio_hi=0x{bar0.read32(regs.audio_hi_off):08x}",
            f"ch{ch}.audio_lo=0x{bar0.read32(regs.audio_lo_off):08x}",
            f"ch{ch}.abuf_toggle=0x{bar0.read32(regs.abuf_toggle_off):08x}",
        ])
    return lines


def write_probe_reg(bar0: Bar0, offset: int, test_value: int) -> tuple[int, int]:
    orig = bar0.read32(offset)
    bar0.write32(offset, test_value)
    readback = bar0.read32(offset)
    bar0.write32(offset, orig)
    restored = bar0.read32(offset)
    if restored != orig:
        raise RuntimeError(
            f"restore mismatch at 0x{offset:04x}: orig=0x{orig:08x} restored=0x{restored:08x}"
        )
    return orig, readback


def synthetic_audio_base(ch: int) -> int:
    return ((ch + 1) * PCIEBAR_AXI_BASE + 0x00123000) & 0xFFFFFFFF


def run_write_probe(bar0: Bar0, channels: list[int]) -> list[str]:
    lines: list[str] = []

    control_regs = [
        ("INT_EN", INT_EN_REG_BASE, 0x0003FFFF),
        ("PCIEBR_EN", PCIEBR_EN_REG_BASE, 0x00000001),
        ("PCIE_INT_DEC", PCIE_INT_DEC_REG_BASE, 0x00000000),
    ]
    for name, offset, test_value in control_regs:
        orig, readback = write_probe_reg(bar0, offset, test_value)
        lines.append(
            f"{name}.probe offset=0x{offset:04x} orig=0x{orig:08x} "
            f"test=0x{test_value:08x} readback=0x{readback:08x}"
        )

    for ch in channels:
        regs = channel_regs(ch)
        test_value = synthetic_audio_base(ch)
        orig, readback = write_probe_reg(bar0, regs.audio_base_off, test_value)
        lines.append(
            f"ch{ch}.audio_base.probe offset=0x{regs.audio_base_off:04x} "
            f"orig=0x{orig:08x} test=0x{test_value:08x} readback=0x{readback:08x}"
        )

    return lines


def main() -> int:
    args = parse_args()
    channels = parse_channels(args.channels)
    bar0_path = Path("/sys/bus/pci/devices") / args.pci_bdf / "resource0"
    out_dir = args.output_dir or Path("/tmp") / f"hws-bar0-audio-probe-{timestamp()}"
    out_dir.mkdir(parents=True, exist_ok=True)

    if os.geteuid() != 0:
        raise SystemExit("run this script as root")
    if not bar0_path.exists():
        raise SystemExit(f"missing BAR0 resource: {bar0_path}")

    report_lines = [
        f"pci_bdf={args.pci_bdf}",
        f"bar0_path={bar0_path}",
        f"channels={','.join(str(ch) for ch in channels)}",
        f"write_probe={'1' if args.write_probe else '0'}",
    ]

    with Bar0(bar0_path) as bar0:
        report_lines.append("")
        report_lines.append("[snapshot.before]")
        report_lines.extend(read_snapshot(bar0, channels))

        if args.write_probe:
            report_lines.append("")
            report_lines.append("[write_probe]")
            report_lines.extend(run_write_probe(bar0, channels))
            report_lines.append("")
            report_lines.append("[snapshot.after]")
            report_lines.extend(read_snapshot(bar0, channels))

    summary_path = out_dir / "summary.txt"
    summary_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
