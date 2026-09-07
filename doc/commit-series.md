# Remediation and diagnostic commit series

Prepared 2026-09-06 from the existing working tree on
`audio-upstream-v20-source-rewrite`, starting at `4706e64`.
This is a commit organization and software-verification record, not a new
hardware qualification.

## Commit boundaries

The series is dependency-ordered; later tooling consumes earlier diagnostics.
The shared full-IRQ test adapter spans the fixes and is introduced with the
diagnostic commit. Earlier fixes include their focused production-body tests.

| Order | Commit / subject | Scope |
| --- | --- | --- |
| 1 | `04dc82c` Reject ambiguous saved-half frame assembly | First-half continuity, rational-period helper, missed-boundary copy regression |
| 2 | `05c00f0` Synchronize audio teardown with worker and IRQ lifetimes | Work gating/drain, ALSA sync_stop, IRQ lifetime, paused-worker tests |
| 3 | `8b179e9` Coordinate fatal device failure and preserve DMA quarantine | Invalid MMIO, shared failure coordinator, consumer wakeup, isolation tests |
| 4 | `144bd84` Verify DMA configuration and report coherent rational frame periods | Mandatory readback, active-peer preservation, consistent timing API and tests |
| 5 | `df40fcd` Guard source transitions and restrict unsafe independent restarts | Opt-in source checks, retained notification, bounded non-forcing restart policy |
| 6 | `b083dc7` Add bounded queue and late-toggle diagnostics with IRQ regression models | Trace/debugfs instrumentation, observational late probe, full IRQ model and mutations |
| 7 | `6ac3555` Extend frame-ID tools with queue and DRM timing diagnostics | Userspace delay measurements/injection, exact raster, modeset/restore and timing tools |
| 8 | `93c051a` Add cross-host capture evidence and bounded diagnostic analysis | Clock mapping, remote/headless sources, bounded evidence interpretation and tests |
| 9 | `77a40e8` Add local capture validation runners and scoped result reporting | Quick/content/comparison modes, preflight and result-reporting tests |
| 10 | Review and qualification documentation | Historical reviews, remediation records, procedures, limitations and this index |

## Kernel logging policy

Removed the uncommitted additions for continuity-recovery notices, DMA-window
success output, DMA-configuration mismatch output, and the common failure
summary. Existing error reporting from the starting commit remains intact.
Error returns, readback checks, failure coordination and quarantine were not
removed with the messages. `dma_window_verify` remains a compatibility parameter;
mandatory verification does not depend on it.

Bounded tracepoints and debugfs counters are retained by request. Trace-event
format strings (`TP_printk`) are not new kernel printk messages. Late-toggle
probing remains opt-in and observational: it cannot acknowledge an interrupt,
rescue a duplicate or authorize a buffer delivery.

## Verification during the split

Each of the six driver snapshots was built with `make -C src W=1` against the
installed 7.1.9-arch1-2 headers. Focused tests accompanied the first five fixes;
the sixth snapshot also passed its complete tools suite and IRQ mutations.
The frame-ID/DRM snapshot passed its cumulative tools suite.

The integrated tools snapshot passes `make -C tools check`: 4,721 modeled IRQ
schedules plus targeted cases, audio/failure/configuration/transition models,
DRM/raster/decoder checks, 129 evidence tests and 16 clock tests. The local
runners pass all 30 hardware-free regressions, shell syntax checks and the DRM
preflight C syntax check. The final working-tree module also builds with `W=1`.

The sandbox refused the localhost UDP socket test; the complete suite passed
when rerun with socket access. This was an environment restriction, not a
waived test. The IRQ, audio, failure, configuration/timing and transition models
also pass AddressSanitizer/UndefinedBehaviorSanitizer checks. LeakSanitizer
required a rerun outside the sandbox's ptrace wrapper; sanitizer checks were
not disabled to obtain a pass.

No module was unloaded or loaded, no display was taken over, no remote host was
modified, and no commits were pushed during this work. Earlier hardware bundles
remain historical evidence for their recorded binaries, not hardware tests of
the logging-cleaned build. Rebuilding a module does not replace the loaded one.

## Preserved work and remaining limits

The original tracked diff and an explicit source-only archive were saved under
`/tmp/hws-commit-split.xWX4yV` before cleanup. No sealed test bundle was edited.
Credentials, local editor configuration, recordings/build outputs and unrelated
experimental harnesses were not committed. In particular, the unfinished
`src/hws_uapi.h` experiment remains untracked.

Passing these userspace models does not establish kernel concurrency safety,
private-ring post-stop DMA containment, shutdown/removal correctness, physical
source-transition safety, simultaneous A/V restart support, or color/audio
correctness. See [the remediation plan](driver-remediation-plan.md) for those
qualification gates. The physical cause of the NVIDIA-associated duplicate
toggles remains unresolved.

Dates, line references, hashes and statements about uncommitted or unloaded
code in earlier change records describe their original snapshots. This index
records the subsequent commit organization; it does not retroactively upgrade
those hardware or model results.
