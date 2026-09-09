#!/usr/bin/env python3
"""Build the production IRQ tests in a temporary directory; no hardware access."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

src = Path(__file__).resolve().parents[1]
tools = src.parent / "tools"
env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
with tempfile.TemporaryDirectory(prefix="hws-irq-diagnostics-") as directory:
    output = Path(directory)
    header = output / "irq-under-test.h"
    subprocess.run([sys.executable, str(tools / "build_hws_irq_test.py"), str(header)],
                   env=env, check=True)
    command = ["cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               "-I", str(tools), f'-DHWS_IRQ_UNDER_TEST="{header}"',
               str(src / "tests/test_irq_diagnostics.c"), "-o", str(output / "test")]
    subprocess.run(command, env=env, check=True)
    # LeakSanitizer cannot inspect threads under the Codex ptrace sandbox.
    # Address and undefined-behavior checks remain enabled.
    env["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS", "") + ":detect_leaks=0"
    subprocess.run([str(output / "test")], env=env, check=True)
