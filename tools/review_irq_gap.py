#!/usr/bin/env python3
"""Review reproducer: DMA advances without IRQ observation in production code.

Uses the existing IRQ adapter, hardware model, and unchanged content oracle.
No driver source or regular test is modified. Exit 1 means the content assertion
found mixed-frame delivery; exit 2 means an unexpected test/build failure. This
does not establish that physical hardware produces the modeled interrupt gap.
"""

import hashlib
import json
from pathlib import Path
import resource
import signal
import subprocess
import tempfile

from build_hws_irq_test import generate


TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
HARNESS = r'''
#define main original_irq_test_main
#include "test_hws_irq.c"
#undef main

int main(int argc, char **argv)
{
    assert(argc == 3);
    unsigned hidden = (unsigned)strtoul(argv[1], NULL, 10);
    unsigned after_half = (unsigned)strtoul(argv[2], NULL, 10);
    assert(hidden <= 6 && !(hidden % 2) && after_half <= 1);
    test_case = "unobserved_dma_boundaries";
    initialize();
    synchronize_stream();
    step(true);
    assert(video()->active && video()->frame_half0_valid);
    if (after_half) step(true);
    for (unsigned i = 0; i < hidden; i++) {
        now += PERIOD_NS;
        hardware_boundary(); /* DMA and sticky status advance; no handler. */
    }
    step(true); /* Real handler/acknowledgement/worker/publication. */
    prove_forward_progress();
    check_ownership();
    return 0;
}
'''


def main():
    # Expected assertion failures should not create large core files.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    print(json.dumps({
        "source": str(ROOT / "src/hws_irq.c"),
        "sha256": hashlib.sha256((ROOT / "src/hws_irq.c").read_bytes()).hexdigest(),
        "scope": "production IRQ and worker; existing single-channel DMA model and content oracle",
        "mode": "640x480; 60 Hz; four queued buffers; diagnostics and audio disabled",
    }), flush=True)
    mixed = unexpected = 0
    with tempfile.TemporaryDirectory(prefix="hws-review-irq-gap-") as directory:
        tmp = Path(directory)
        (tmp / "irq.h").write_text(generate())
        (tmp / "gap.c").write_text(HARNESS)
        subprocess.run([
            "cc", "-std=c11", "-O2", "-g", "-I", str(TOOLS),
            '-DHWS_IRQ_UNDER_TEST="' + str(tmp / "irq.h") + '"',
            str(tmp / "gap.c"), "-o", str(tmp / "gap"),
        ], check=True, timeout=60)
        for hidden in (0, 2, 4, 6):
            for after_half in (0, 1):
                run = subprocess.run([str(tmp / "gap"), str(hidden), str(after_half)],
                                     capture_output=True, text=True, timeout=10)
                detected = (run.returncode == -signal.SIGABRT and
                            "Assertion `data[i] == id` failed" in run.stderr)
                bad = run.returncode != 0 and not detected
                mixed += detected
                unexpected += bad
                print(json.dumps({
                    "hidden_boundaries": hidden, "after_completed_half": after_half,
                    "content_check": "FAIL_MIXED_FRAME" if detected else
                                     "ERROR" if bad else "PASS",
                    "child_exit": run.returncode,
                    "assertion": run.stderr.strip() or None,
                }), flush=True)
    print(json.dumps({"mixed_frame_cases": mixed, "unexpected_errors": unexpected,
                      "hardware_occurrence_proven": False}))
    return 2 if unexpected else 1 if mixed else 0


if __name__ == "__main__":
    try:
        status = main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"runner_error": str(error)}), flush=True)
        status = 2
    raise SystemExit(status)
