# Linux inclusion gaps

Reviewed on March 9, 2026.

This file tracks the blockers found during a kernel-readiness review of
`src/`. The focus here is upstream inclusion, not just "builds as an
out-of-tree module".

## [high] Probe leaks coherent scratch DMA allocations

- Where:
  `src/hws_pci.c:435`, `src/hws_video.c:535`, `src/hws_pci.c:447`,
  `src/hws_pci.c:260`
- What:
  `hws_probe()` calls `hws_init_video_sys()` before the explicit scratch
  allocation path. `hws_init_video_sys()` seeds DMA windows, and
  `hws_seed_dma_windows()` allocates per-channel scratch buffers when
  `scratch_vid[ch].cpu` is `NULL`. Probe later calls
  `hws_alloc_seed_buffers()`, which allocates another set of coherent
  buffers and overwrites the stored pointers. The first set is then leaked.
- Why it matters:
  Every successful probe can leak coherent DMA memory. That is a real bug,
  not just an upstream style concern.
- Current status:
  Fixed in current `master`. Scratch allocation now has a single owner in
  probe via `hws_alloc_seed_buffers()`, and `hws_seed_dma_windows()` no
  longer allocates fallback coherent buffers when `scratch_vid[ch].cpu` is
  `NULL`.
- Baseline branch status:
  Not present in `baseline`. There, probe allocates DMA once in
  `DmaMemAllocPool()` before `InitVideoSys()` runs
  (`baseline:src/hws_video.c:5831`, `baseline:src/hws_video.c:5837`), and
  `SetDMAAddress()` only programs registers from already allocated buffers
  (`baseline:src/hws_video.c:4993`).
- Resolution:
  The driver now keeps a single allocation path: probe allocates scratch
  buffers exactly once, and the seed helper only programs registers from the
  already-owned buffers. A future cleanup could still switch this to
  `dmam_alloc_coherent()` to simplify lifetime management further.
- How to test the current bug:
  1. Load the driver with hardware present.
  2. Repeatedly unload and reload it.
  3. Use `CONFIG_DEBUG_KMEMLEAK` if available and scan
     `/sys/kernel/debug/kmemleak`.
  4. If coherent allocations are not visible to kmemleak on the target
     platform, add temporary counters or debug prints around the allocation
     and free paths and show that probe performs more allocations than remove
     frees.
- How to verify the fix:
  1. Each channel should allocate scratch memory only once per probe.
  2. Remove should free exactly what probe allocated.
  3. Repeated load/unload cycles should show no growth in leaked objects or
     allocation counters.

## [high] Partial probe unwind can double-free V4L2 control state

- Where:
  `src/hws_video.c:1521`, `src/hws_video.c:1529`, `src/hws_pci.c:491`,
  `src/hws_pci.c:521`, `src/hws_pci.c:525`, `src/hws_video.c:460`
- What:
  `hws_video_register()` has its own unwind path and frees per-channel
  control handlers on failure. Probe then falls back to
  `err_unwind_channels:` and calls `hws_video_cleanup_channel()` for already
  initialized channels, which frees the same handler again.
- Why it matters:
  A late registration failure can produce a double-free or use-after-free in
  probe cleanup.
- Current status:
  Fixed in current `master`. Registration-owned teardown is now separate from
  full channel teardown, so a failed `hws_video_register()` no longer frees
  control handlers that probe cleanup will free again.
- Baseline branch status:
  Not present in the same form in `baseline`. The old
  `hws_video_register()` owned its own unwind
  (`baseline:src/hws_video.c:3285`), and probe did not perform a second
  per-channel cleanup after a failed register path
  (`baseline:src/hws_video.c:5849`, `baseline:src/hws_video.c:5856`).
- Resolution:
  The driver now splits registration teardown from full channel teardown.
  `hws_video_register()` unwinds only registration-owned state, while
  `hws_video_cleanup_channel()` and normal unregister continue to own control
  handler teardown.
- How to test the current bug:
  1. Force a late failure inside `hws_video_register()`.
  2. The most practical way is a temporary debug knob that fails after N
     channels, or fault injection aimed at `video_register_device()` or
     `device_create_file()`.
  3. Run the failing probe path under `CONFIG_KASAN` or `SLUB_DEBUG`.
- How to verify the fix:
  1. The same injected failure should unwind cleanly with no allocator or
     KASAN reports.
  2. Re-probing after a failed attempt should still work.

## [high] Resolution-change path drains all buffers and cannot re-prime

- Where:
  `src/hws_video.c:848`, `src/hws_video.c:890`, `src/hws_video.c:895`,
  `src/hws_video.c:958`, `src/hws_video.c:969`
- What:
  `hws_video_apply_mode_change()` moves the active buffer and the entire
  capture queue to a local `done` list, completes them with errors, and then
  tries to restart capture by looking for a buffer in `capture_queue`. That
  queue is already empty, so the restart path cannot succeed.
- Why it matters:
  A live input mode change can stall streaming instead of recovering or
  failing in a controlled, documented way.
- Current status:
  Fixed in current `master`. Geometry changes now take the explicit
  renegotiation path: the driver emits `V4L2_EVENT_SOURCE_CHANGE`, marks the
  queue in error when buffers are present, drains in-flight buffers, and
  leaves restart to userspace instead of trying to re-prime from an empty
  queue.
- Baseline branch status:
  Not present in `baseline` as this exact bug. The old `ChangeVideoSize()`
  path only updated cached geometry and reprogrammed the half-size register
  (`baseline:src/hws_video.c:5091`) and did not drain the VB2 queue. The
  queueing model there was different and fed userspace from an internal
  hardware buffer pool via `video_data_process()`
  (`baseline:src/hws_video.c:2844`).
- Resolution:
  The driver now consistently uses explicit renegotiation for geometry
  changes. It no longer attempts a partial restart after draining the active
  queue state.
- How to test the current bug:
  1. Start streaming with at least two queued buffers.
  2. Change the live HDMI source resolution, for example from 1920x1080 to
     1280x720.
  3. Watch for a `V4L2_EVENT_SOURCE_CHANGE` followed by capture stalling or
     never re-arming.
  4. `v4l2-ctl` is enough for a manual test, for example:
     `v4l2-ctl -d /dev/videoX --stream-mmap=4 --stream-count=0 --stream-poll`
- How to verify the fix:
  1. After the same live mode change, streaming should either resume and keep
     delivering buffers, or fail in a predictable way that matches the
     documented userspace contract.
  2. The driver must not silently get stuck with an empty queue and no active
     DMA buffer.

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
