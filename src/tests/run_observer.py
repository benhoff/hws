#!/usr/bin/env python3
"""Exercise the production observer with fake clocks/MMIO; never touch hardware."""
import os
from pathlib import Path
import subprocess
import tempfile

src = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="hws-observer-test-") as directory:
    output = Path(directory)
    header = output / "observer-under-test.h"
    # Keep production logic intact; replace only kernel includes with the shim.
    header.write_text("\n".join(
        line for name in ("hws_reg.h", "hws_observer.c")
        for line in (src / name).read_text().splitlines()
        if not line.startswith("#include ")) + "\n")
    binary = output / "test"
    subprocess.run([
        "cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        f'-DHWS_OBSERVER_UNDER_TEST="{header}"',
        str(src / "tests/test_observer.c"), "-o", str(binary)], check=True)
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS", "") + ":detect_leaks=0"
    subprocess.run([str(binary)], check=True, env=env)
