#!/usr/bin/env python3
"""Validate the HWS BAR0 register atlas and generate its kernel table."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


ACCESS = {
    "ro": "HWS_REG_RO",
    "rw": "HWS_REG_RW",
    "w1c": "HWS_REG_W1C",
    "wo": "HWS_REG_WO",
    "r-status-w-control": "HWS_REG_R_STATUS_W_CONTROL",
}
CONFIDENCE = {
    "measured": "HWS_REG_MEASURED",
    "vendor-code": "HWS_REG_VENDOR_CODE",
    "inferred": "HWS_REG_INFERRED",
    "unknown": "HWS_REG_UNKNOWN",
}
FIELD_CONTEXT = {
    "both": "HWS_REG_FIELD_BOTH",
    "read": "HWS_REG_FIELD_READ",
    "write": "HWS_REG_FIELD_WRITE",
}


def number(value: object, context: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ValueError(f"{context}: invalid integer {value!r}") from exc
    raise ValueError(f"{context}: expected an integer, got {type(value).__name__}")


def c_string(value: str) -> str:
    return json.dumps(value)


def validate(atlas: dict) -> None:
    if atlas.get("schema_version") != 1:
        raise ValueError("unsupported or missing schema_version")
    bar_size = number(atlas.get("address_space_bytes"), "address_space_bytes")
    if bar_size <= 0:
        raise ValueError("address_space_bytes must be positive")

    ids: set[str] = set()
    covered: dict[int, str] = {}
    for index, reg in enumerate(atlas.get("registers", [])):
        context = f"registers[{index}]"
        reg_id = reg.get("id")
        if not isinstance(reg_id, str) or not reg_id:
            raise ValueError(f"{context}: missing id")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", reg_id):
            raise ValueError(f"{context}: id must be a C-style uppercase identifier")
        if reg_id in ids:
            raise ValueError(f"{context}: duplicate id {reg_id}")
        ids.add(reg_id)
        if reg.get("access") not in ACCESS:
            raise ValueError(f"{context}: unsupported access {reg.get('access')!r}")
        if not isinstance(reg.get("snapshot_safe"), bool):
            raise ValueError(f"{context}: snapshot_safe must be boolean")
        if reg.get("access") == "wo" and reg["snapshot_safe"]:
            raise ValueError(f"{context}: write-only registers cannot be snapshot-safe")
        confidence = reg.get("evidence", {}).get("confidence")
        if confidence not in CONFIDENCE:
            raise ValueError(f"{context}: unsupported confidence {confidence!r}")
        width = number(reg.get("width_bits"), f"{context}.width_bits")
        if width != 32:
            raise ValueError(f"{context}: kernel snapshot currently supports 32-bit registers only")
        offset = number(reg.get("offset"), f"{context}.offset")
        if offset % 4 or offset < 0 or offset + 4 > bar_size:
            raise ValueError(f"{context}: invalid/alignment-unsafe offset 0x{offset:x}")

        channel = reg.get("channel")
        count = 1 if channel is None else number(channel.get("count"), f"{context}.channel.count")
        stride = 0 if channel is None else number(channel.get("stride_bytes"), f"{context}.channel.stride_bytes")
        if count < 1 or count > 255 or (count > 1 and (stride < 4 or stride % 4)):
            raise ValueError(f"{context}: invalid channel count/stride")
        for instance in range(count):
            instance_offset = offset + instance * stride
            if instance_offset + 4 > bar_size:
                raise ValueError(f"{context}: channel instance exceeds BAR size")
            previous = covered.get(instance_offset)
            if previous:
                raise ValueError(
                    f"{context}: offset 0x{instance_offset:x} overlaps {previous}; "
                    "use one mixed-semantics entry for aliases"
                )
            covered[instance_offset] = reg_id

        for field_index, field in enumerate(reg.get("fields", [])):
            lsb = number(field.get("lsb"), f"{context}.fields[{field_index}].lsb")
            msb = number(field.get("msb"), f"{context}.fields[{field_index}].msb")
            if lsb < 0 or msb < lsb or msb >= width:
                raise ValueError(f"{context}.fields[{field_index}]: invalid bit range")
            if field.get("context", "both") not in FIELD_CONTEXT:
                raise ValueError(f"{context}.fields[{field_index}]: invalid context")

        reset = reg.get("reset_value")
        if reset is not None:
            number(reset, f"{context}.reset_value")
        for typical_index, typical in enumerate(reg.get("typical_values", [])):
            number(typical, f"{context}.typical_values[{typical_index}]")


def generate(atlas: dict, source: Path) -> str:
    fields: list[tuple[str, int, int, str]] = []
    typicals: list[int] = []
    register_rows: list[str] = []

    for reg in atlas["registers"]:
        field_first = len(fields)
        for field in reg.get("fields", []):
            fields.append(
                (
                    field["name"],
                    number(field["lsb"], "field lsb"),
                    number(field["msb"], "field msb"),
                    FIELD_CONTEXT[field.get("context", "both")],
                )
            )
        typical_first = len(typicals)
        typicals.extend(number(value, "typical value") for value in reg.get("typical_values", []))
        channel = reg.get("channel")
        count = 1 if channel is None else number(channel["count"], "channel count")
        stride = 0 if channel is None else number(channel["stride_bytes"], "channel stride")
        reset_known = reg.get("reset_value") is not None
        reset_value = 0 if not reset_known else number(reg["reset_value"], "reset value")
        evidence = reg["evidence"]
        register_rows.append(
            "\t{ "
            f".id = {c_string(reg['id'])}, .name = {c_string(reg['name'])}, "
            f".offset = 0x{number(reg['offset'], 'offset'):04x}, .width_bits = {number(reg['width_bits'], 'width')}, "
            f".access = {ACCESS[reg['access']]}, .count = {count}, .stride = {stride}, "
            f".snapshot_safe = {str(bool(reg['snapshot_safe'])).lower()}, "
            f".reset_known = {str(reset_known).lower()}, .reset_value = 0x{reset_value:08x}, "
            f".typical_first = {typical_first}, .typical_count = {len(reg.get('typical_values', []))}, "
            f".field_first = {field_first}, .field_count = {len(reg.get('fields', []))}, "
            f".confidence = {CONFIDENCE[evidence['confidence']]}, "
            f".evidence = {c_string(evidence['source'])} "
            "},"
        )

    lines = [
        "/* SPDX-License-Identifier: GPL-2.0-only */",
        "/* Generated by python/gen_hws_register_atlas.py; do not edit. */",
        f"/* Source: {source.as_posix()} */",
        "",
        "const struct hws_reg_field_desc hws_reg_fields[] = {",
    ]
    lines.extend(
        f"\t{{ .name = {c_string(name)}, .lsb = {lsb}, .msb = {msb}, .context = {context} }},"
        for name, lsb, msb, context in fields
    )
    lines.extend([
        "};",
        "const size_t hws_reg_field_count = ARRAY_SIZE(hws_reg_fields);",
        "",
        "const u32 hws_reg_typical_values[] = {",
    ])
    lines.extend(f"\t0x{value:08x}," for value in typicals)
    lines.extend([
        "};",
        "const size_t hws_reg_typical_value_count = ARRAY_SIZE(hws_reg_typical_values);",
        "",
        "const struct hws_reg_desc hws_reg_atlas[] = {",
    ])
    lines.extend(register_rows)
    lines.extend([
        "};",
        "const size_t hws_reg_atlas_count = ARRAY_SIZE(hws_reg_atlas);",
        "",
    ])
    return "\n".join(lines)


def generate_offsets(atlas: dict, source: Path) -> str:
    lines = [
        "/* SPDX-License-Identifier: GPL-2.0-only */",
        "/* Generated by python/gen_hws_register_atlas.py; do not edit. */",
        f"/* Source: {source.as_posix()} */",
        "#ifndef HWS_REG_ATLAS_OFFSETS_H",
        "#define HWS_REG_ATLAS_OFFSETS_H",
        "",
        f"#define HWS_ATLAS_BAR0_SIZE 0x{number(atlas['address_space_bytes'], 'address_space_bytes'):x}U",
        "",
    ]
    for reg in atlas["registers"]:
        channel = reg.get("channel")
        count = 1 if channel is None else number(channel["count"], "channel count")
        stride = 0 if channel is None else number(channel["stride_bytes"], "channel stride")
        prefix = f"HWS_ATLAS_{reg['id']}"
        lines.extend(
            [
                f"#define {prefix}_OFFSET 0x{number(reg['offset'], 'offset'):04x}U",
                f"#define {prefix}_COUNT {count}U",
                f"#define {prefix}_STRIDE {stride}U",
            ]
        )
    lines.extend(["", "#endif", ""])
    return "\n".join(lines)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--atlas", type=Path, default=root / "registers/hws_bar0_registers.json")
    parser.add_argument("--output", type=Path, default=root / "src/hws_reg_atlas_generated.inc")
    parser.add_argument("--offset-output", type=Path, default=root / "src/hws_reg_atlas_offsets.h")
    parser.add_argument("--check", action="store_true", help="validate and verify that generated output is current")
    args = parser.parse_args()

    try:
        atlas = json.loads(args.atlas.read_text(encoding="utf-8"))
        validate(atlas)
        generated = generate(atlas, args.atlas.relative_to(root))
        generated_offsets = generate_offsets(atlas, args.atlas.relative_to(root))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"atlas error: {exc}", file=sys.stderr)
        return 1

    if args.check:
        try:
            current = args.output.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"generated atlas missing: {exc}", file=sys.stderr)
            return 1
        if current != generated:
            print(f"generated atlas is stale: run {Path(__file__).name}", file=sys.stderr)
            return 1
        try:
            current_offsets = args.offset_output.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"generated offset header missing: {exc}", file=sys.stderr)
            return 1
        if current_offsets != generated_offsets:
            print(f"generated offset header is stale: run {Path(__file__).name}", file=sys.stderr)
            return 1
        print(f"atlas valid and generated output current: {len(atlas['registers'])} registers")
        return 0

    args.output.write_text(generated, encoding="utf-8")
    args.offset_output.write_text(generated_offsets, encoding="utf-8")
    print(f"wrote {args.output} and {args.offset_output} from {args.atlas}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
