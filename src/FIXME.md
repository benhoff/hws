# Linux inclusion gaps

Reviewed on March 9, 2026.

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

## [medium] Build setup hides compiler diagnostics with `-w`

- Where:
  `src/Makefile:15`
- What:
  The out-of-tree module makefile adds `ccflags-y += -fno-ipa-icf -w`.
  `-w` suppresses warnings globally.
- Why it matters:
  Upstream will reject warning suppression instead of fixes, and it makes the
  local build result much less meaningful.
- Current status:
  Still present in current `master`.
- Baseline branch status:
  Already present in `baseline`, and worse there. The old makefile used `-w`
  as well, plus GCC dump flags (`baseline:src/Makefile:8`).
- Fix direction:
  Remove `-w` and make the code warning-clean with the compilers the kernel
  cares about.
- How to test the current bug:
  1. Remove `-w`.
  2. Rebuild with:
     `make -C /lib/modules/$(uname -r)/build M=$PWD/src W=1 modules`
  3. If available, also build with Clang:
     `make -C /lib/modules/$(uname -r)/build M=$PWD/src LLVM=1 W=1 modules`
  4. Run `scripts/checkpatch.pl --no-tree --file --strict` on the source
     files.
- How to verify the fix:
  1. GCC and Clang builds should be warning-clean, or have only narrowly
     justified warnings.
  2. `checkpatch.pl` should stay clean apart from any intentional exceptions.

## [low] Default half-size alignment still needs confirmation

- Where:
  `src/hws_video.c:377`, `src/hws_pci.c:324`, `src/hws_video.c:947`
- What:
  The default `pix.half_size` is derived from `sizeimage / 2`. If the
  hardware really requires a stricter half-buffer alignment than that, the
  seed and mode-change paths may still program an invalid value before userspace
  negotiates a format.
- Why it matters:
  This may be harmless if the hardware accepts the current programming, but if
  the alignment contract is real it can cause subtle DMA or frame-splitting
  errors.
- Current status:
  Still open. Current `master` still programs `pix.half_size / 16` from values
  derived as `sizeimage / 2`, so the alignment concern remains unresolved
  unless hardware evidence shows that is acceptable.
- Baseline branch status:
  Likely introduced later. `baseline` explicitly rounded `HLAF_SIZE` to a
  multiple of `16 * 128` bytes in `SetVideoFormteSize()`
  (`baseline:src/hws_video.c:3660`) and programmed that value in both
  `SetDMAAddress()` and `ChangeVideoSize()`
  (`baseline:src/hws_video.c:5058`, `baseline:src/hws_video.c:5106`).
- Fix direction:
  Confirm the hardware requirement and encode it in one helper used by every
  place that computes or programs half-size.
- How to test the current bug:
  1. Check vendor documentation or the known-good Windows driver behavior.
  2. If the requirement is known, log the programmed half-size during probe
     and mode changes and compare it against the expected alignment.
- How to verify the fix:
  1. All half-size programming should use the same aligned calculation.
  2. Probe, initial stream-on, and live mode changes should program identical
     values for the same format.

## [low] Interrupt mode is fixed to legacy INTx

- Where:
  `src/hws_pci.c:454`, `src/hws_pci.c:459`, `src/hws_pci.c:467`
- What:
  Probe forces legacy shared INTx and never attempts MSI or MSI-X.
- Why it matters:
  This is not always a hard blocker, but upstream reviewers often ask why a
  PCIe device does not use MSI when the hardware supports it.
- Current status:
  Still present in current `master`.
- Baseline branch status:
  Introduced later. `baseline` attempted to enable MSI in
  `probe_scan_for_msi()` (`baseline:src/hws_video.c:5385`) and used the result
  in `irq_setup()` (`baseline:src/hws_video.c:5428`). The old code still needs
  review, but it was not hard-wired to INTx only.
- Fix direction:
  Validate what the hardware supports. If MSI/MSI-X works, prefer it and keep
  INTx as fallback. If the hardware only supports INTx, document that clearly.
- How to test the current gap:
  1. Check the PCI capabilities for MSI/MSI-X support.
  2. If supported, add an MSI path and test interrupt delivery under load.
- How to verify the fix:
  1. The preferred interrupt mode should probe cleanly.
  2. Buffer completion and suspend/resume behavior should remain correct in
     both the preferred mode and fallback mode.
