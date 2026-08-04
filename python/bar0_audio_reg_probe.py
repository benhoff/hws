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
import mmap
import os
import re
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
    video_base_off: int
    audio_base_off: int
    shared_hi_off: int
    shared_lo_off: int
    candidate8_hi_off: int
    candidate8_lo_off: int
    vbuf_toggle_off: int
    abuf_toggle_off: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Probe HWS BAR0 audio registers")
    parser.add_argument("--pci-bdf", default="0000:17:00.0",
                        help="PCI device BDF under /sys/bus/pci/devices")
    parser.add_argument("--bar0-path", type=Path,
                        help="Explicit BAR0 source. Defaults to debugfs bar0_snapshot for read-only probes, then sysfs resource0 with /dev/mem fallback")
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


def default_bar0_path(pci_bdf: str, write_probe: bool) -> Path:
    if not write_probe:
        debugfs = Path("/sys/kernel/debug/hws") / pci_bdf / "bar0_snapshot"
        if debugfs.exists():
            return debugfs
    return Path("/sys/bus/pci/devices") / pci_bdf / "resource0"


def channel_regs(ch: int) -> ChannelRegs:
    return ChannelRegs(
        channel=ch,
        video_base_off=CVBS_IN_BUF_BASE + (ch * PCIE_BARADDROFSIZE),
        audio_base_off=CVBS_IN_BUF_BASE + ((8 + ch) * PCIE_BARADDROFSIZE),
        shared_hi_off=PCI_ADDR_TABLE_BASE + 0x208 + ch * 8,
        shared_lo_off=PCI_ADDR_TABLE_BASE + 0x20C + ch * 8,
        candidate8_hi_off=PCI_ADDR_TABLE_BASE + 0x208 + (8 + ch) * 8,
        candidate8_lo_off=PCI_ADDR_TABLE_BASE + 0x20C + (8 + ch) * 8,
        vbuf_toggle_off=CVBS_IN_BASE + (32 + ch) * PCIE_BARADDROFSIZE,
        abuf_toggle_off=CVBS_IN_BASE + (40 + ch) * PCIE_BARADDROFSIZE,
    )


class Bar0:
    def __init__(self, path: Path):
        self.path = path
        self.fd: int | None = None
        self.mm: mmap.mmap | None = None
        self.mm_writable = False
        self.mmap_error: OSError | None = None
        self.snapshot_bytes: bytes | None = None
        self.snapshot_values: dict[int, int] | None = None
        self.devmem_error: OSError | None = None
        self.size: int = 0

    def __enter__(self) -> "Bar0":
        if self.path.name == "bar0_snapshot":
            raw = self.path.read_bytes()
            values = parse_snapshot_values(raw)
            self.snapshot_bytes = raw
            self.snapshot_values = values or None
            self.size = max(len(raw), max(values.keys(), default=0) + 4)
            return self

        self.fd = os.open(self.path, os.O_RDWR | os.O_SYNC)
        self.size = os.fstat(self.fd).st_size
        if self.size <= 0:
            raise RuntimeError(f"invalid BAR size for {self.path}: {self.size}")
        try:
            self.mm = mmap.mmap(
                self.fd,
                self.size,
                flags=mmap.MAP_SHARED,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
            self.mm_writable = True
        except OSError as exc:
            self.mmap_error = exc
            try:
                self.mm = mmap.mmap(
                    self.fd,
                    self.size,
                    flags=mmap.MAP_SHARED,
                    prot=mmap.PROT_READ,
                )
            except OSError:
                self.mm = None
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.mm is not None:
            self.mm.close()
            self.mm = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def read32(self, offset: int) -> int:
        if self.snapshot_values is not None:
            try:
                return self.snapshot_values[offset]
            except KeyError as exc:
                raise RuntimeError(
                    f"debugfs BAR0 snapshot does not contain offset 0x{offset:04x}"
                ) from exc

        if self.snapshot_bytes is not None:
            data = self.snapshot_bytes[offset : offset + 4]
            if len(data) != 4:
                raise RuntimeError(f"short snapshot read at 0x{offset:04x}")
            return struct.unpack("<I", data)[0]

        assert self.fd is not None
        if offset < 0 or offset + 4 > self.size:
            raise ValueError(f"read offset out of range: 0x{offset:04x}")
        if self.mm is not None:
            self.mm.seek(offset)
            data = self.mm.read(4)
        else:
            try:
                data = os.pread(self.fd, 4, offset)
            except OSError as exc:
                try:
                    self.snapshot_bytes = self.read_devmem_snapshot()
                    data = self.snapshot_bytes[offset : offset + 4]
                except OSError as devmem_exc:
                    self.devmem_error = devmem_exc
                    if self.mmap_error:
                        raise RuntimeError(
                            f"BAR0 read failed at 0x{offset:04x}; "
                            f"mmap failed first with {self.mmap_error}; "
                            f"/dev/mem fallback failed with {devmem_exc}"
                        ) from exc
                    raise RuntimeError(
                        f"BAR0 read failed at 0x{offset:04x}; "
                        f"/dev/mem fallback failed with {devmem_exc}"
                    ) from exc
        if len(data) != 4:
            raise RuntimeError(
                f"short read at 0x{offset:04x}: expected 4 bytes, got {len(data)}"
            )
        return struct.unpack("<I", data)[0]

    def read32_optional(self, offset: int) -> int | None:
        try:
            return self.read32(offset)
        except RuntimeError as exc:
            if self.snapshot_values is not None and "debugfs BAR0 snapshot" in str(exc):
                return None
            raise

    def read_devmem_snapshot(self) -> bytes:
        dev_mem = Path("/dev/mem")
        resource_file = self.path.parent / "resource"

        if not dev_mem.exists():
            raise OSError("missing /dev/mem")
        if not resource_file.exists():
            raise OSError(f"missing PCI resource file: {resource_file}")

        first = resource_file.read_text(encoding="utf-8").splitlines()[0].split()
        if len(first) < 2:
            raise OSError(f"could not parse BAR0 range from {resource_file}")

        bar_start = int(first[0], 16)
        bar_end = int(first[1], 16)
        if bar_end < bar_start:
            raise OSError(f"invalid BAR0 range in {resource_file}")

        resource_size = bar_end - bar_start + 1
        size = self.size if self.size > 0 else resource_size
        size = min(size, resource_size)

        page_size = mmap.PAGESIZE
        page_base = bar_start & ~(page_size - 1)
        page_off = bar_start - page_base
        map_size = page_off + size

        with dev_mem.open("rb", buffering=0) as fh:
            mm = mmap.mmap(
                fh.fileno(),
                length=map_size,
                flags=mmap.MAP_SHARED,
                prot=mmap.PROT_READ,
                offset=page_base,
            )
            try:
                return bytes(mm[page_off : page_off + size])
            finally:
                mm.close()

    def write32(self, offset: int, value: int) -> None:
        if self.snapshot_bytes is not None or self.snapshot_values is not None:
            raise RuntimeError("debugfs BAR0 snapshot is read-only")

        assert self.fd is not None
        if offset < 0 or offset + 4 > self.size:
            raise ValueError(f"write offset out of range: 0x{offset:04x}")
        buf = struct.pack("<I", value & 0xFFFFFFFF)
        if self.mm is not None:
            if not self.mm_writable:
                raise RuntimeError(f"BAR0 mapping is read-only; cannot write 0x{offset:04x}")
            self.mm.seek(offset)
            self.mm.write(buf)
            self.mm.flush()
            return

        written = os.pwrite(self.fd, buf, offset)
        if written != 4:
            raise RuntimeError(
                f"short write at 0x{offset:04x}: expected 4 bytes, wrote {written}"
            )
        os.fsync(self.fd)


def parse_snapshot_values(raw: bytes) -> dict[int, int]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {}

    values: dict[int, int] = {}
    for line in text.splitlines():
        offset_match = re.search(r"\boffset\s*=\s*0x([0-9a-fA-F]+)", line)
        value_match = re.search(r"\bvalue\s*=\s*0x([0-9a-fA-F]+)", line)
        if offset_match and value_match:
            values[int(offset_match.group(1), 16)] = int(value_match.group(1), 16)
            continue

        colon_match = re.search(
            r"^\s*(?:0x)?([0-9a-fA-F]{1,8})\s*[:=]\s*(?:0x)?([0-9a-fA-F]{1,8})\b",
            line,
        )
        if colon_match:
            values[int(colon_match.group(1), 16)] = int(colon_match.group(2), 16)
            continue

        words = re.findall(r"0x([0-9a-fA-F]{1,8})", line)
        if len(words) >= 2:
            values[int(words[0], 16)] = int(words[1], 16)

    return values


def read_snapshot(bar0: Bar0, channels: list[int]) -> list[str]:
    def fmt32_optional(offset: int) -> str:
        value = bar0.read32_optional(offset)
        if value is None:
            return "missing"
        return f"0x{value:08x}"

    lines = [
        f"INT_EN=0x{bar0.read32(INT_EN_REG_BASE):08x}",
        f"PCIEBR_EN=0x{bar0.read32(PCIEBR_EN_REG_BASE):08x}",
        f"PCIE_INT_DEC=0x{bar0.read32(PCIE_INT_DEC_REG_BASE):08x}",
        f"SYS_STATUS=0x{bar0.read32(CVBS_IN_BASE + 0 * PCIE_BARADDROFSIZE):08x}",
        f"ACTIVE_STATUS=0x{bar0.read32(CVBS_IN_BASE + 5 * PCIE_BARADDROFSIZE):08x}",
        f"VCAP_ENABLE=0x{bar0.read32(CVBS_IN_BASE + 2 * PCIE_BARADDROFSIZE):08x}",
        f"ACAP_ENABLE=0x{bar0.read32(CVBS_IN_BASE + 3 * PCIE_BARADDROFSIZE):08x}",
        f"INT_STATUS=0x{bar0.read32(CVBS_IN_BASE + 1 * PCIE_BARADDROFSIZE):08x}",
    ]
    for ch in channels:
        regs = channel_regs(ch)
        lines.extend([
            f"ch{ch}.video_base={fmt32_optional(regs.video_base_off)}",
            f"ch{ch}.audio_base=0x{bar0.read32(regs.audio_base_off):08x}",
            f"ch{ch}.shared_hi=0x{bar0.read32(regs.shared_hi_off):08x}",
            f"ch{ch}.shared_lo=0x{bar0.read32(regs.shared_lo_off):08x}",
            f"ch{ch}.candidate8_hi=0x{bar0.read32(regs.candidate8_hi_off):08x}",
            f"ch{ch}.candidate8_lo=0x{bar0.read32(regs.candidate8_lo_off):08x}",
            f"ch{ch}.vbuf_toggle={fmt32_optional(regs.vbuf_toggle_off)}",
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
    bar0_path = args.bar0_path or default_bar0_path(args.pci_bdf, args.write_probe)
    out_dir = args.output_dir or Path("/tmp") / f"hws-bar0-audio-probe-{timestamp()}"
    out_dir.mkdir(parents=True, exist_ok=True)

    if os.geteuid() != 0:
        raise SystemExit("run this script as root")
    if not bar0_path.exists():
        raise SystemExit(f"missing BAR0 source: {bar0_path}")

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
