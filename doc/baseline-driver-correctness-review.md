# Baseline-to-Current Driver Correctness Review

## Purpose

This document records a correctness-focused comparison between the vendor-style
baseline driver and the transformed current driver. Architectural differences
are described where they affect the analysis, but they are not treated as
defects merely because they differ from the baseline.

The review concentrates on places where the transformation may have changed a
hardware contract, buffer-ownership rule, interrupt lifetime, or userspace API
guarantee.

## Review target

- Baseline: `origin/baseline` at `1af45c8`
- Original review snapshot: `audio-upstream-5patch-pulled-forward` at `10504a8`
- Current verified HEAD: `audio-upstream-5patch-pulled-forward` at `1eddd35`
- Common ancestor: `7497b18`
- Current working tree: included in the review
- Review date: 2026-07-14

The two branches diverged at the common ancestor. This is therefore not a
simple review of commits layered on top of `origin/baseline`: the current branch
contains a large driver reorganization, while `origin/baseline` has its own two
post-fork commits.

The current worktree already contains an important, uncommitted correction to
the device-information bit masks. That correction is discussed separately
below and is not counted as an open defect in the working tree.

## Severity and confidence

| Label | Meaning |
| --- | --- |
| High | Can corrupt captured data, violate DMA ownership, break another device, leave hardware live after teardown, or cause a kernel use-after-free. |
| Medium | Can cause intermittent multi-channel failures or resource leakage, but normally needs a narrower trigger. |
| Confirmed | The failure follows directly from software state and documented kernel API behavior. |
| Hardware validation required | The code relies on a hardware behavior that the baseline contradicts or does not establish. It should be treated as release-blocking until measured. |
| Validated | Target-hardware measurement has established the behavior and supersedes an inference made from the baseline. |

## Executive summary

| ID | Severity | Confidence | Finding |
| --- | --- | --- | --- |
| F1 | High | Confirmed | Queue starvation returns a V4L2 buffer while DMA remains enabled on it. |
| F2 | None; closed | Validated | Target-hardware measurement proved a 1:1 VDONE-to-frame relationship, so completing one full V4L2 buffer per VDONE is correct. |
| F3 | High | Hardware validation required | Pre-arming rewrites the channel's only live DMA remap/base registers. |
| F4 | None; closed | Verified in current code | IRQ vector cleanup now covers resolution failure, probe failure, and normal removal with correct devres ordering. |
| F5 | None; closed | Verified in current code | Suspend/remove now mask the device and synchronize the IRQ without disabling a shared Linux IRQ descriptor. |
| F6 | High | Confirmed | Probe opens the device interrupt fabric before installing a handler, and some failure paths do not quiesce the device. |
| F7 | High on affected modes/SKUs | Confirmed transformation omission; hardware layout details require validation | Raw-format capability, stride, and half-size rules from the baseline are not preserved. |
| F8 | High | Confirmed for ALSA; same lifetime defect is present in V4L2 | Open file handles can outlive the devm-allocated driver state. |
| F9 | Medium | Confirmed; carried over from baseline | Device-wide capture-enable registers use unlocked read/modify/write operations. |
| F10 | Medium | Confirmed | Inactive video-channel control handlers leak during normal removal. |

## Architectural changes that are not defects by themselves

The following changes are intentional design choices and are not findings on
their own:

- splitting the monolithic source into PCI, IRQ, video, V4L2 ioctl, and audio
  units;
- using videobuf2 DMA-contiguous buffers instead of the baseline's private
  video frame queue;
- supporting direct DMA into a V4L2 buffer when the address fits the device
  remap window;
- completing one full V4L2 frame for each VDONE, as validated by the measured
  1:1 VDONE-to-frame relationship;
- using a coherent bounce arena when video and audio must share a remap page;
- preferring MSI while retaining an INTx fallback;
- exposing one ALSA card with one capture PCM per active input;
- removing baseline-only scaling, rotation, and vendor queue machinery.

Those choices become correctness problems only where the implementation no
longer honors hardware completion, DMA ownership, or kernel object-lifetime
requirements.

## Detailed findings

### F1: Queue starvation returns a buffer while DMA remains enabled

Severity: **High**
Confidence: **Confirmed**

#### Current behavior

`hws_video_handle_vdone()` performs the following sequence:

1. Read `v->active` into `done`.
2. Remove or replace the active software pointer.
3. Call `vb2_buffer_done()` for `done`.
4. If no pre-armed buffer was promoted, call `hws_arm_next()`.
5. If the capture queue is empty, `hws_arm_next()` returns `-EAGAIN` and the
   handler returns without disabling capture.

Relevant current locations:

- `src/hws_irq.c:128-235`
- `src/hws_video.c:1267-1321`
- `src/hws_video.c:1627` (`min_queued_buffers = 1`)

The hardware VCAP bit and DMA base are unchanged when the queue is empty. The
last DMA target therefore still identifies the V4L2 buffer that has just been
returned to videobuf2 and userspace.

The no-signal synthesis path has the same ownership shape in
`src/hws_video.c:329-402`: it can complete the current buffer without disabling
capture when there is no replacement.

#### Why the baseline did not have this failure

The baseline hardware DMA target was a persistent private coherent buffer.
Userspace-facing buffers were filled by copying from that private buffer.
Running out of userspace buffers could drop a delivery, but it did not make the
hardware write into a buffer that had already been returned to userspace.

Direct DMA changes that ownership rule: hardware must be stopped or redirected
before the direct target is completed.

#### Failure sequence

The minimum reproducer is a valid one-buffer stream:

1. Queue one V4L2 buffer.
2. Start streaming.
3. Hardware completes the buffer and raises VDONE.
4. The threaded IRQ returns the buffer with `VB2_BUF_STATE_DONE`.
5. No second buffer is queued, so `hws_arm_next()` returns `-EAGAIN`.
6. VCAP remains enabled with the old DMA base.
7. Hardware can start the next capture into a buffer userspace now owns.

Even if a replacement buffer is queued shortly afterward, reprogramming its
DMA base occurs while capture is still enabled, leaving an unsafe interval.

#### Recommended correction

- Before completing `done`, establish one of two states:
  - a validated, already-latched replacement DMA target; or
  - VCAP disabled and its posted write flushed.
- When the queue starves, leave the VB2 queue streaming but the channel capture
  engine disabled.
- On a later QBUF, program the new target, acknowledge stale VDONE, publish the
  active software pointer, and only then re-enable capture.
- Apply the same ownership ordering to no-signal frame synthesis.

#### Validation

- Stream with exactly one buffer and delay requeueing it.
- Confirm VCAP is clear before DQBUF makes the buffer observable.
- Fill the dequeued buffer with a canary and verify the card does not modify it
  until the buffer is queued again.
- Repeat during signal loss and signal recovery.

### F2, closed: One VDONE per full frame is validated

Severity: **None; not a defect**
Confidence: **Validated on target hardware**

#### Measured result

Target-hardware measurement established a 1:1 relationship between VDONE
events and complete input frames. One VDONE therefore identifies one complete
frame, not one half-buffer completion.

This result closes the original concern raised from reading the baseline. The
current completion rule is correct:

```text
one VDONE -> one complete active V4L2 buffer
```

#### Baseline behavior

The baseline treats the video toggle as part of completion correctness:

- `origin/baseline:src/hws_video.c:4780-4800` reads the per-channel video
  toggle and schedules work only when the value changes.
- `origin/baseline:src/hws_video.c:4250-4274` selects the first or second DMA
  half from that toggle.
- `origin/baseline:src/hws_video.c:4291-4308` tracks whether the companion half
  has completed.
- `origin/baseline:src/hws_video.c:4338-4359` publishes a software frame only
  after the second half is copied.

The baseline's software frame-rate thresholds also use doubled counts, which
is consistent with two video completion events per frame.

#### Current implementation

`src/hws_irq.c:347-373` reads `HWS_REG_VBUF_TOGGLE(ch)` only when the optional
`toggle_debug` parameter is enabled. The value is recorded for logging but does
not control completion.

Every VDONE increments the pending count, and `src/hws_irq.c:128-196` completes
the entire current V4L2 buffer for each count. `half_seen` and
`last_buf_half_toggle` are diagnostic fields only.

The baseline's two-half copy pipeline is therefore an implementation detail of
the legacy private-buffer path, not evidence that the current driver must wait
for two VDONE events before completing a direct buffer.

No half-toggle gating should be added to the current completion path. Doing so
would combine two complete source frames into one V4L2 buffer and halve the
reported frame rate.

#### Remaining boundaries of this validation

The 1:1 measurement resolves only VDONE completion cadence. It does not by
itself prove:

- that programming `next_prepared` while capture is active is safely latched;
- that the symmetric half-size register value matches the hardware's internal
  buffer layout; or
- that queue starvation is safe when no new DMA target is available.

F1, F3, and the half-layout portion of F7 therefore remain open and independent
of this validated result.

#### Regression coverage

Retain the measured invariant as a hardware regression check:

- VDONE count should track complete input frames 1:1 over a sufficiently long
  capture;
- completed V4L2 sequence count should track VDONE count 1:1 when buffers are
  continuously available; and
- enabling toggle diagnostics must not change buffer-completion cadence.

### F3: Pre-arming rewrites the only live DMA mapping

Severity: **High**
Confidence: **Hardware validation required**

#### Current behavior

`hws_prime_next_locked()` in `src/hws_video.c:246-277` removes another queued
buffer and immediately calls `hws_program_dma_for_buffer()` while
`vid->active` still represents an in-flight frame.

`hws_program_dma_window()` in `src/hws_video.c:164-227` writes:

- the channel's single remap-table slot;
- the channel's single video base register; and
- the channel's half-size register when necessary.

There is no host descriptor ring, separate next-buffer register, or hardware
completion tag in the current implementation.

#### Baseline behavior

`origin/baseline:src/hws_video.c:4993-5064` programs one persistent private
video DMA base for each channel. Buffer rotation happens in software after the
card writes into that persistent buffer; the baseline does not rewrite the
channel base for every userspace buffer.

#### Risk

The current implementation assumes the card latches base/remap writes for the
next frame boundary rather than applying them to the active transfer.

If the registers are live:

- changing the base redirects the active transfer;
- changing the 512-MiB remap page changes address translation for the active
  transfer; and
- the software `active`/`next_prepared` ordering no longer describes where the
  hardware is writing.

The risk is highest when consecutive direct buffers occupy different remap
pages. The bounce path is also affected because it alternates between two
scratch offsets by rewriting the same base register.

#### Recommended correction

Choose one of the following only after hardware validation:

1. Use a persistent channel-owned DMA target and copy to VB2 buffers, matching
   the baseline's safe ownership model.
2. If the hardware has documented boundary latching, encode that contract in
   the driver and validate the exact write deadline and completion identity.
3. If there is an undiscovered descriptor or alternate-base mechanism, use it
   rather than treating a live base write as a software queue.

Do not keep `next_prepared` as a correctness mechanism based only on software
pointer tracking.

#### Validation

- Capture into buffers deliberately allocated in different remap pages.
- Record the base/remap registers and buffer canaries around every VDONE.
- Determine whether a base write during the first half changes the destination
  of the second half.
- Compare with a test mode that never rewrites the base while VCAP is enabled.

### F4, closed: IRQ vectors now have ordered cleanup

Severity: **None; fixed**
Confidence: **Verified in current code**

#### Original defect

The original review snapshot called:

```c
pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
```

without a matching `pci_free_irq_vectors()` path. That affected:

- failure after vector allocation;
- failure to resolve vector zero;
- later probe failure; and
- normal driver removal.

The Linux PCI documentation explicitly requires the driver to call
`pci_free_irq_vectors()` during cleanup:

<https://docs.kernel.org/6.18/PCI/msi-howto.html>

#### Current corrected behavior

Current `src/hws_pci.c:514-553` implements the required lifetime:

- `hws_free_irq_vectors()` calls `pci_free_irq_vectors()`.
- If `pci_irq_vector()` fails, the allocation is freed immediately.
- A `devm_add_action_or_reset()` cleanup action is registered after successful
  vector resolution.
- The cleanup action is registered before `devm_request_threaded_irq()`.
  Devres LIFO ordering therefore frees the IRQ action before freeing the
  vectors.
- If registering the cleanup action itself fails, the `_or_reset` variant
  immediately runs the vector cleanup.

Suspend/resume should keep the allocation; vector freeing belongs to probe
failure and final removal, not system sleep. The current implementation follows
that rule.

`doc/msi-interrupts.md` has also been corrected and no longer claims that
`pcim_enable_device()` manages vectors.

#### Regression validation

- Repeatedly bind and unbind in MSI mode and INTx fallback mode.
- Check `/sys/bus/pci/devices/.../msi_irqs`, `/proc/interrupts`, and PCI MSI
  enable state after each cycle.
- Fault-inject failures immediately after allocation, after IRQ request, and
  after V4L2/ALSA registration.

### F5, closed: Shared INTx teardown stays at the device

Severity: **None; fixed**
Confidence: **Verified in current code**

#### Original defect

When MSI/MSI-X is unavailable, `hws_alloc_irq()` requests the fallback with
`IRQF_SHARED`.

The original review snapshot's `hws_block_hotpaths()` nevertheless called:

```c
disable_irq(hws->irq);
```

This function is used by both suspend and remove. Resume balances the call with
`enable_irq()`, but normal remove does not.

That changed the Linux IRQ descriptor, not just this driver's registered
action. On a shared line it could stop every device using that line, and the
remove path left the disable depth unbalanced.

#### Current corrected behavior

Current `hws_block_hotpaths()` at `src/hws_pci.c:556-567` now:

1. publishes `suspended = true`;
2. masks the card at `INT_EN_REG_BASE`;
3. calls `synchronize_irq()` to drain any in-flight handler; and
4. clears pending device status.

There are no remaining `disable_irq()` or `enable_irq()` calls in the driver.
Resume restores hardware state and reopens the device gate before clearing the
suspended flag; it does not manipulate the shared Linux descriptor.

This is the correct common sequence for both MSI and shared INTx.

#### Regression validation

- Boot with MSI disabled so the card uses shared INTx.
- Identify another action on the same IRQ in `/proc/interrupts`.
- Suspend/resume and bind/unbind the HWS device while exercising the peer.
- Confirm the peer continues receiving interrupts and the descriptor depth is
  balanced.

### F6: Probe opens the interrupt fabric before a handler exists

Severity: **High**
Confidence: **Confirmed**

#### Current ordering

Probe performs this sequence:

1. `read_chip_id()`
2. `hws_init_video_sys(hws, false)` at `src/hws_pci.c:613`
3. initialize channels and allocate the audio workqueue
4. call `hws_init_video_sys(hws, false)` again; this is effectively a no-op
   because `start_run` is already true
5. allocate/request the IRQ at `src/hws_pci.c:646-666`

`hws_init_video_sys()` at `src/hws_video.c:778-806` starts the decoder and calls
`hws_open_irq_fabric()`, which writes the full interrupt-enable mask.

The baseline installs its IRQ at
`origin/baseline:src/hws_video.c:5736-5739` and only later calls
`InitVideoSys()` at line 5837.

#### Error-unwind problem

`err_unwind_channels` at `src/hws_pci.c:725-733` frees software resources but
does not mask the interrupt gate or stop the device.

Consequences include:

- an interrupt can arrive during channel initialization with no handler;
- an early initialization failure can return while the gate remains open;
- a later registration failure can allow devres to remove the IRQ action while
  the hardware remains started.

F4's vector-resource leak is now fixed, but that cleanup does not stop or mask
the device and therefore does not close this separate probe-ordering issue.

#### Recommended correction

- Keep the device interrupt gate masked during reset and capability discovery.
- Initialize software state and allocate the IRQ vector.
- Install the handler.
- Clear stale status.
- Only then start/unmask the device.
- Route every post-MMIO failure through a common device-quiesce path before
  software and devres teardown.

The common failure path must be safe both before and after IRQ registration.

#### Validation

Fault-inject every probe step and confirm after failure:

- VCAP and ACAP are disabled;
- the device interrupt gate is masked;
- sticky status is acknowledged;
- no IRQ action or vector remains; and
- repeated probe succeeds without a power cycle.

### F7: Hardware pixel-layout rules were lost during the direct-DMA transformation

Severity: **High on affected modes and device revisions**
Confidence: **Confirmed transformation omission; exact hardware layout still requires validation**

This finding contains three related layout mismatches.

#### F7.1: `support_yv12` is ignored

Current `read_chip_id()` stores and logs `support_yv12` at
`src/hws_pci.c:196-218`, but no capture path uses it. The driver always exposes
and sizes buffers as packed 16-bpp YUYV:

- `src/hws_video.c:1206-1224`
- `src/hws_v4l2_ioctl.c:708-715`
- `src/hws_v4l2_ioctl.c:744-818`

The baseline uses the capability as a real DMA-format selector:

- value 0: packed two bytes per pixel;
- value 1: 12-bpp source layout, converted through `FillYUU2()`;
- value 2: 10-bpp/5:4 source layout, converted through
  `FillNV12ToYUY2()`.

Relevant baseline locations are
`origin/baseline:src/hws_video.c:2873-2884,2962-3075,3660-3688`.

On a device reporting 1 or 2, the current driver can label raw planar data as
YUYV and program the wrong DMA length and half boundary.

#### F7.2: The V4L2 stride cannot be represented in hardware

The current code reports a 64-byte-aligned `bytesperline` and accepts a larger
userspace-requested stride. No per-line hardware stride register is programmed;
only base address and half length are written.

The baseline reports a tight YUYV pitch of `width * 2`. Examples:

| Width | Baseline pitch | Current minimum pitch |
| ---: | ---: | ---: |
| 720 | 1440 | 1472 |
| 1360 | 2720 | 2752 |
| 1680 | 3360 | 3392 |
| 1080 | 2160 | 2176 |

Unless the hardware independently inserts exactly that padding on every row,
the current `bytesperline` describes a layout that DMA does not produce.
Userspace will begin each row at the wrong offset.

Arbitrary width/height requests are also accepted by S_FMT even though the
current driver neither programs a hardware scaler nor performs the baseline's
software scaling.

#### F7.3: Half-size alignment changed

For packed YUYV, the baseline computes the first half by rounding `width *
height` down to a 2048-byte boundary, then assigns the remainder to the second
half.

The current driver uses symmetric `sizeimage / 2`. Commit `f8b50e3` explicitly
changed this for a ping-pong test, while `src/FIXME.md` still records the
alignment requirement as unresolved.

Even at 1920x1080, the two calculations differ. This matters if the hardware
uses the programmed half length as a packet or bank boundary rather than an
arbitrary split point.

#### Recommended correction

- Define the hardware DMA layout independently from the V4L2 output layout.
- For direct DMA, expose only a userspace format/stride that exactly matches
  what the card produces.
- If `support_yv12` requires conversion, use a persistent/bounce source buffer
  and convert before completing the YUYV destination.
- Reject arbitrary S_FMT dimensions if scaling is no longer supported.
- Restore the baseline half calculation unless hardware tests establish a new
  valid rule.
- Size bounce slots for every advertised mode or remove modes that cannot use
  the bounce path. In particular, aligned 1080x1920 is larger than the current
  `MAX_VIDEO_SCALER_SIZE` bounce slot even though it remains under the advertised
  4-MiB frame cap.

#### Validation

For every supported PCI ID and `support_yv12` value:

- capture a color-bar or pixel-coordinate pattern;
- verify row starts and plane ordering;
- compare bytes used with the programmed half length;
- test every advertised width that is not naturally 64-byte pitch-aligned;
- test portrait mode on both direct and bounce paths; and
- verify the first/second half boundary with canaries.

### F8: Open handles can outlive the driver state

Severity: **High**
Confidence: **Confirmed for ALSA; the same lifetime mismatch exists in V4L2**

#### Shared root cause

The top-level `struct hws_pcie_dev` is allocated with `devm_kzalloc()` at
`src/hws_pci.c:565-568`. Devres frees that allocation after the PCI remove
callback returns.

Both userspace interfaces keep pointers into that allocation beyond device
registration:

- ALSA: `pcm->private_data = &hws->audio[i]` at
  `src/hws_audio.c:1039`.
- V4L2: `video_set_drvdata(vdev, ch)`, `vdev->queue = &ch->buffer_queue`, and
  `q->drv_priv = ch` at `src/hws_video.c:1614-1631`.

#### ALSA failure

Remove calls `snd_card_free_when_closed()` at
`src/hws_audio.c:1123-1125`. That API disconnects the card but deliberately
returns before final release when files remain open:

<https://docs.kernel.org/sound/kernel-api/alsa-driver-api.html#c.snd_card_free_when_closed>

When the open PCM is eventually released, ALSA can invoke the driver's
`hw_free` and `close` callbacks. Those callbacks dereference `a`, `a->parent`,
and MMIO state at `src/hws_audio.c:873-931`. By then the devm allocation and PCI
resources can already be gone.

#### V4L2 failure

`video_unregister_device()` defers the final `video_device` release while an
fd remains open, but the V4L2 object's queue and driver data still point into
the devm allocation. A later VB2 file release can therefore access the freed
queue/channel.

`hws_video_release_registration()` at `src/hws_video.c:537-551` also calls
`vb2_queue_release()` before `vb2_video_unregister_device()`, reversing the
helper's intended unregister-then-release ordering and widening the teardown
race.

PCI sysfs unbind and hot unplug can trigger this even if normal module unload
is prevented by an open file's module reference.

#### Recommended correction

- Separate interface-visible state lifetime from PCI resource lifetime.
- Mark the device disconnected before tearing down MMIO/DMA.
- Keep channel/queue/private state alive until all ALSA and V4L2 references are
  gone, using an explicit reference-counted allocation or subsystem release
  callback.
- Ensure callbacks after disconnect do not touch MMIO or freed DMA state.
- Use `vb2_video_unregister_device()` in its intended order without manually
  releasing the queue first.

#### Validation

- Keep an ALSA capture fd open and unbind the PCI device.
- Close the fd after remove returns under KASAN.
- Repeat with an allocated/streaming V4L2 fd.
- Test concurrent close and unbind.
- Confirm callbacks return disconnected errors without accessing MMIO.

### F9: Capture-enable bitmaps use unlocked read/modify/write

Severity: **Medium**
Confidence: **Confirmed; carried over from baseline**

Video and audio enable all channels through device-wide bitmap registers:

- `src/hws_video.c:672-687`
- `src/hws_audio.c:815-834`

Each helper performs an MMIO read, modifies one bit, and writes the complete
word. The driver has per-channel locks but no device-wide lock covering these
registers.

Concurrent operations on different channels can lose an update:

```text
CPU 0 reads 0, plans to set channel 0
CPU 1 reads 0, plans to set channel 1
CPU 0 writes 0x1
CPU 1 writes 0x2
final value: 0x2 instead of 0x3
```

This existed in the baseline, so it is not solely a transformation regression.
The split multi-channel V4L2/ALSA interfaces make concurrent callers more
likely, however.

#### Recommended correction

- Add a device-level spinlock for capture-enable register updates, or maintain
  a protected software shadow and write the complete desired state.
- Use the same lock in start, stop, suspend, remove, and IRQ-fault containment.
- Avoid mixing unlocked direct zero writes with locked per-channel updates.

#### Validation

- Start and stop all video/audio channels concurrently in a loop.
- Read back VCAP/ACAP after every transition.
- Confirm the bitmap always matches the software active-channel set.

### F10: Control handlers for inactive channels leak

Severity: **Medium**
Confidence: **Confirmed**

Probe initializes video and audio state for all `max_channels` at
`src/hws_pci.c:615-628`. `hws_video_init_channel()` allocates a V4L2 control
handler and controls for each of those channels.

Normal unregister frees handlers only for `cur_max_video_ch` at
`src/hws_video.c:1667-1680`. On a one- or two-channel SKU, initialized handlers
for the remaining channels are never freed before the devm top-level structure
is released.

The ALSA-registration failure path also manually unregisters video while
leaving `v4l2_registered` true, causing the later channel unwind to skip video
cleanup.

#### Recommended correction

- Prefer initializing only active video channels; or
- track exactly which channel initializations succeeded and clean all of them
  independently from which devices were registered.
- Keep registration teardown and channel-state teardown as separate,
  idempotent operations.

#### Validation

- Repeatedly bind/unbind one-, two-, and four-channel device variants under
  kmemleak.
- Fault-inject V4L2 and ALSA registration failures.

## Working-tree correction that should be retained

Committed HEAD defined device version and subversion as bits `7:0` and `15:8`.
The baseline's `ReadChipId()` at
`origin/baseline:src/hws_video.c:5610-5619` instead uses:

- version: bits `15:8`;
- subversion: bits `23:16`;
- port ID: bits `25:24`; and
- YV12 capability: bits `31:28`.

The current uncommitted changes in `src/hws_reg.h` and `src/hws_pci.c` correct
those masks and centralize their use. They should be committed rather than
dropped. The correction can affect more than logging because `device_ver`
selects hardware-version behavior and DMA maximum-size programming.

The accompanying rename from `HWS_SYS_BUSY_BIT` to
`HWS_SYS_IRQ_PENDING_BIT` also removes a misleading collision with the actual
DMA-busy bit, which is bit 3.

## Build and static-check results

The current working tree built successfully against kernel `7.0.12-arch1-1`.

The ordinary `W=1` build does not expose warnings because `src/Makefile:16`
adds `-w`. The review therefore also built with the local `ccflags-y` override:

```sh
make -C src W=1 ccflags-y=-fno-ipa-icf
```

That build succeeded with one warning:

```text
src/hws_irq.c:216: label 'arm_next' defined but not used
```

`sparse`, `smatch`, and `cppcheck` were not available in the environment. The
review environment did not run hardware tests, but separately supplied target-
hardware measurement has closed F2. F3 and the half-layout portion of F7 remain
unresolved by static review.

The Makefile has two secondary tooling issues:

- `-w` suppresses warnings even when callers request `W=1`;
- `install` and `clean` use `M=$(PWD)` while `all` uses `M=$(CURDIR)`, so
  `make -C src clean` targets the wrong directory when invoked from the repo
  root.

## Recommended remediation order

### Phase 1: Establish the remaining DMA programming contract

1. Preserve the validated 1:1 VDONE-to-frame result as a regression test.
2. Determine whether base/remap writes latch at a safe boundary.
3. Confirm raw pixel layout and half-size alignment on every supported device
   revision.
4. Until these are known, use a persistent channel-owned DMA target rather
   than returning direct-DMA buffers on an assumed completion boundary.

### Phase 2: Fix the remaining unconditional DMA and probe lifecycle defects

1. Stop or redirect DMA before every `vb2_buffer_done()`.
2. Reorder probe so the IRQ handler exists before the device is unmasked.
3. Add a common hardware-quiesce error path.

Ordered vector cleanup and shared-INTx-safe masking are already implemented;
retain their bind/unbind and suspend/resume tests as regression coverage.

### Phase 3: Fix interface contracts and lifetime

1. Make V4L2 format, stride, and size exactly represent hardware output.
2. Restore conversion/bounce handling for non-YUYV hardware modes.
3. Tie ALSA/V4L2 private state lifetime to open handles rather than PCI devres.
4. Serialize device-wide capture-enable bitmap updates.
5. Complete channel-control cleanup.

## Suggested release acceptance criteria

The driver should not be considered ready for broad hardware testing until:

- no V4L2 buffer is visible to userspace while it remains a possible DMA
  target;
- the validated 1:1 VDONE-to-frame relationship remains covered by a hardware
  regression test;
- pre-armed DMA behavior is either documented by hardware or removed;
- every advertised format and stride matches captured memory;
- all probe failures leave capture and interrupt gates disabled;
- MSI/INTx bind, unbind, suspend, and resume leave IRQ state balanced;
- unbind with open ALSA/V4L2 handles passes under KASAN; and
- concurrent multi-channel start/stop preserves every VCAP/ACAP bit.

## Useful comparison commands

```sh
# Inspect a baseline range with stable line numbers.
git show origin/baseline:src/hws_video.c | nl -ba | sed -n '4250,4360p'

# Inspect baseline interrupt handling.
git show origin/baseline:src/hws_video.c | nl -ba | sed -n '4760,4835p'

# Inspect baseline DMA programming.
git show origin/baseline:src/hws_video.c | nl -ba | sed -n '4990,5070p'

# Show the current transformation size.
git diff --stat origin/baseline...HEAD

# Build without the Makefile's warning suppression.
make -C src W=1 ccflags-y=-fno-ipa-icf
```
