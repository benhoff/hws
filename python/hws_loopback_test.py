#!/usr/bin/env python3
"""
hws_loopback_test.py
────────────────────
Automated “GPU → HDMI → capture-card” loop-back test for KDE/Wayland.

For every mode in MODES it will
  1. set the chosen GPU connector to that mode (via `modetest`);
  2. capture CAPTURE_SEC seconds from /dev/video0 with ffmpeg so the DMA runs;
  3. diff BAR0 against the baseline snapshot and show only *unknown* offsets
     (those not yet listed in KNOWN_OFFSETS).

Run as root:  sudo ./hws_loopback_test.py
"""

import mmap
import os
import subprocess
import sys
import time
from argparse import ArgumentParser
from pathlib import Path
from typing import List, Tuple

# ───── Site-specific paths ──────────────────────────────────────────────────
PCI_ADDR        = "0000:17:00.0"                       # <-- your capture card
BAR0_PATH       = f"/sys/bus/pci/devices/{PCI_ADDR}/resource0"
BAR0_SIZE       = 64 * 1024                            # 64 KiB BAR0

CAPTURE_DEV     = "/dev/video0"                        # V4L2 node
CAPTURE_SEC     = 1                                    # seconds per mode

# ----> Adjust for *your* GPU connector / CRTC (see `modetest -c`) <----
CONNECTOR_ID    = 110
CRTC_ID         = 109

MODES = [
    "1920x1080@60",
    "1280x720@60",
    "720x480@60",
]

# ───── Register constants ───────────────────────────────────────────────────
WORD        = 4
BAR_STRIDE  = 0x80            #  PCI_BARADDROFSIZE

# Offsets (bytes) that are already named in hws_reg.h ------------------------
KNOWN_OFFSETS = {
    # core / global
    0x0000,          # SYS_STATUS / DEC_MODE (same address)
    0x0080,          # INT_STATUS
    0x0100,          # VCAP_ENABLE
    0x0180,          # ACAP_ENABLE
    0x0200,          # INT_ENABLE
    0x0280,          # ACTIVE_STATUS
    0x0400,          # HDCP_STATUS
    0x0480,          # DMA_MAX_SIZE
    0x0C80,          # VBUF1_ADDR

    # VBUF_TOGGLE(0..3)
    0x1000, 0x1080, 0x1100, 0x1180,
    # ABUF_TOGGLE(0..3)
    0x1400, 0x1480, 0x1500, 0x1580,

    # DEVICE_INFO
    0x2B00,

    # IN_RES / BCHS (ch0-3)
    0x2D00, 0x2D80, 0x2E00, 0x2E80,
    0x2F00, 0x2F80, 0x3000, 0x3080,

    # FRAME_RATE (ch0-3)
    0x3680, 0x3700, 0x3780, 0x3800,

    # OUT_RES (ch0-3)
    0x3C00, 0x3C80, 0x3D00, 0x3D80,

    # INT_ACK
    0x4080,

    # OUT_FRAME_RATE (ch0-3)
    0x4100, 0x4180, 0x4200, 0x4280,
}
# additional “candidate” words whose *change* means “hot-plug happened”.
HOTPLUG_CANDIDATES = {
    5 * BAR_STRIDE,   # ACTIVE_STATUS   (signal present / interlace)
    8 * BAR_STRIDE,   # HDCP_STATUS     (HDCP auth often rises with 5 V)
    1 * BAR_STRIDE,   # INT_STATUS      (done flags often spike)
}
# ───── Helpers ──────────────────────────────────────────────────────────────
def read_bar0() -> bytes:
    with open(BAR0_PATH, "rb") as f:
        mm = mmap.mmap(f.fileno(), BAR0_SIZE, access=mmap.ACCESS_READ)
        try:
            data = mm.read(BAR0_SIZE)
        finally:
            mm.close()
    return data


def diff_words(base: bytes, cur: bytes) -> List[Tuple[int, int, int]]:
    """Return a list of differing 32-bit words (offset, old, new)."""
    diffs: List[Tuple[int, int, int]] = []
    for off in range(0, min(len(base), len(cur)), WORD):
        b = int.from_bytes(base[off:off + WORD], "little")
        c = int.from_bytes(cur [off:off + WORD], "little")
        if b != c:
            diffs.append((off, b, c))
    return diffs



def format_hex(val: int) -> str:
    return f"0x{val:08X}"


def mode_to_modetest_arg(mode: str) -> str:
    """‘1920x1080@60’ is already in the format modetest expects."""
    return mode


def set_mode(mode: str):
    subprocess.run(
        ["modetest", "-s", f"{CONNECTOR_ID}@{CRTC_ID}:{mode}"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def capture_one_second():
    subprocess.run(
        ["ffmpeg", "-loglevel", "quiet",
         "-f", "v4l2", "-i", CAPTURE_DEV,
         "-t", str(CAPTURE_SEC),
         "-f", "rawvideo", "-y", "/dev/null"],
        check=True,
    )


def hex32(val: int) -> str:
    return f"0x{val:08X}"


# ───── Hot-plug watch mode ────────────────────────────────────────────────
def hotplug_watch(poll_ms: int = 100):
    print("[hot-plug] Take baseline with **cable UN-plugged**, then insert the"
          " HDMI cable…")
    baseline = read_bar0()

    while True:
        cur   = read_bar0()
        diffs = diff_words(baseline, cur)
        print(diffs)

        # any candidate offset changed?
        trig = [d for d in diffs if d[0] in HOTPLUG_CANDIDATES]
        if trig:
            print("\n[hot-plug] Event detected!")
            for off, old, new in trig:
                print(f"  Offset {format_hex(off)}: {format_hex(old)} → "
                      f"{format_hex(new)}  ({'known' if off in KNOWN_OFFSETS else 'UNKNOWN!'})")
            print("\nDone.")
            return

        time.sleep(poll_ms / 1000)

# ───── Original mode-sweep loop-back test ─────────────────────────────────
def loopback_modes():
    print(f"[+] Reading baseline BAR0 ({BAR0_SIZE//1024} KiB)…")
    baseline = read_bar0()
    print("[+] Baseline captured, starting test loop\n")

    for i, mode in enumerate(MODES, 1):
        print(f"─── [{i}/{len(MODES)}] Mode {mode} ─────────────────────────")

        try:               set_mode(mode)
        except Exception as e:
            print(f"  !! modetest failed: {e}")
            continue

        time.sleep(0.5)
        try:               capture_one_second()
        except Exception:  pass

        cur     = read_bar0()
        unknown = [(o,b,c) for (o,b,c) in diff_words(baseline, cur)
                   if o not in KNOWN_OFFSETS]

        if not unknown:
            print("  No *unknown* register changes.\n")
        else:
            for off, old, new in unknown:
                print(f"  Offset {format_hex(off)}: {format_hex(old)} → "
                      f"{format_hex(new)}")
            print(f"  Changed *unknown* words: {len(unknown)}\n")

    print("== Test loop complete ==")

# ───── entry-point ────────────────────────────────────────────────────────
def main():
    if os.geteuid() != 0:
        sys.exit("Run as root please (BAR access & modetest)")

    ap = ArgumentParser()
    ap.add_argument("--hotplug", action="store_true",
                    help="wait for a 5-V hot-plug and report which registers changed")
    args = ap.parse_args()

    if args.hotplug:
        hotplug_watch()
    else:
        loopback_modes()

if __name__ == "__main__":
    main()

