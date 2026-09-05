# Linux inclusion gaps

Reviewed on September 5, 2026.

This file tracks the blockers found during a kernel-readiness review of
`src/`. The focus here is upstream inclusion, not just "builds as an
out-of-tree module".

## [high] Supported hardware matrix is still provisional

- Where:
  `src/hws_pci.c:45`, `src/hws_pci.c:47`, `src/hws_pci.c:51`,
  `src/hws_pci.c:66`, `src/hws_video.c:817`, `src/hws_video.c:828`
- What:
  The PCI ID table still contains comments such as "SKU unknown" and says the
  mapping needs vendor documentation or INF strings. The legacy hardware path
  is explicitly kept as a no-op.
- Why it matters:
  Upstream maintainers will expect a defensible statement of which boards are
  supported and what behavior is implemented for each hardware generation.
  A partially reverse-engineered table with incomplete runtime behavior is not
  ready for merge.
- Current status:
  Still present in current `master`.
- Baseline branch status:
  Partially pre-existing. `baseline` already carried the same raw PCI ID table
  without product-level identification (`baseline:src/hws_video.c:71`), so the
  documentation gap is old. However, `baseline` did still implement a legacy
  software frame-rate path for old hardware
  (`baseline:src/hws_video.c:5196`), whereas current `master` explicitly keeps
  the legacy path as a no-op. The "legacy support is incomplete" part is
  therefore newer.
- Fix direction:
  1. Identify each supported PCI/subsystem ID with an actual product name.
  2. Drop unsupported IDs from the table until they are validated.
  3. Either implement the legacy path or clearly stop claiming support for
     legacy hardware.
  4. Add the normal upstream collateral later: `Kconfig`, in-tree
     `Makefile`, `MAINTAINERS`, and user-visible documentation.
- How to test the current gap:
  There is no useful software-only test. This needs a per-SKU hardware test
  matrix.
- How to verify the fix:
  For each claimed board:
  1. Probe and remove cleanly.
  2. Stream video successfully.
  3. Handle no-signal, hotplug, and live mode changes.
  4. Survive suspend/resume and shutdown/reboot.
  5. Match the documented product identity and feature set.

## [high] Native-split VDONE content semantics matrix is incomplete

- Where:
  `doc/vdone-semantics.md`, `doc/evidence/vdone-matrix.csv`
- What:
  The driver consistently rounds the midpoint down to the native 2 KiB
  boundary and programs that value. Channel 1 has rate/toggle evidence at
  1920x1080p60, but not yet a preserved native-split content-proof artifact.
  The equivalent matrix is also incomplete for channels 0 and 2, supported
  modes, and the relevant PCI IDs.
- Why it matters:
  The implementation assumes that each accepted boundary identifies
  `toggle ^ 1` as complete and that two complementary segments form one source
  frame. Rate and toggle evidence alone cannot prove the latter.
- Current status:
  Instrumentation and a bounded evidence harness are present. The required
  hardware runs remain open and must be recorded in the canonical matrix.
- Baseline branch status:
  `baseline` also rounded the split to `16 * 128` bytes. Historical exact-
  midpoint and native-split tests produced different VDONE rates, which is why
  neither result may be generalized without its full configuration.
- Fix direction:
  Execute `doc/vdone-evidence-runbook.md`, retain each immutable evidence
  bundle, and add only validator-passing rows as `validated`.
- How to verify the fix:
  A passing run has matching independently decoded upper/lower IDs, stable
  `toggle ^ 1` mapping, consecutive complementary generations, complete
  poison replacement, unchanged guards, no fatal ambiguity, no unrecovered
  queue failure, and no trace loss.
