#!/usr/bin/env python3
"""Unit tests for the allowlisted HWS register experiment parser."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).with_name("hws_register_experiment.py")
SPEC = importlib.util.spec_from_file_location("hws_register_experiment", MODULE_PATH)
assert SPEC and SPEC.loader
experiment = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = experiment
SPEC.loader.exec_module(experiment)


def snapshot(vcap: int, active: int) -> str:
    return "\n".join(
        [
            "schema_version=1 device=0000:17:00.0 bar=0 bar_size=0x10000 "
            "timestamp_start_ns=1 atomic=0 allowlist_only=1",
            f"register id=VIDEO_CAPTURE_ENABLE offset=0x4008 value=0x{vcap:08x} "
            "channel=-1 access=rw confidence=vendor-code",
            f"register id=ACTIVE_STATUS offset=0x4014 value=0x{active:08x} "
            "channel=-1 access=ro confidence=vendor-code",
            "timestamp_end_ns=2",
        ]
    )


class SnapshotTests(unittest.TestCase):
    def test_parse_allowlisted_snapshot(self) -> None:
        parsed = experiment.parse_snapshot(snapshot(0, 1))
        self.assertEqual(parsed.registers[0x4008].value, 0)
        self.assertEqual(parsed.registers[0x4014].value, 1)

    def test_rejects_unmarked_input(self) -> None:
        with self.assertRaisesRegex(ValueError, "allowlist-only"):
            experiment.parse_snapshot(
                "schema_version=1 allowlist_only=0\n"
                "register id=X offset=0x0000 value=0x00000000 channel=-1"
            )

    def test_rejects_resource0_path_without_reading_it(self) -> None:
        with self.assertRaisesRegex(ValueError, "register_snapshot"):
            experiment.read_snapshot(Path("/sys/bus/pci/devices/fake/resource0"))

    def test_diff_decodes_changed_field(self) -> None:
        atlas, _ = experiment.load_atlas(
            Path(__file__).resolve().parents[1]
            / "registers/hws_bar0_registers.json"
        )
        lines = experiment.diff_snapshots(
            experiment.parse_snapshot(snapshot(0, 1)),
            experiment.parse_snapshot(snapshot(1, 1)),
            atlas,
        )
        self.assertIn("VIDEO_CAPTURE_ENABLE", lines[0])
        self.assertTrue(any("field channel_enable" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
