# Audio software lifetime remediation (R2)

2026-09-06: code and hardware-free regression slice of remediation batch 2.
**Kernel concurrency qualification remains open.** No driver reload, unbind,
PM cycle or audio hardware test was performed by the agent for this change.

## Reproduced failure

The selected production `hws_pcie_audio_hw_free()`/release bodies were run with
an audio worker paused after obtaining the ALSA runtime, or inside a period/XRUN
notification. Before the fix, suspended/lost/quiesced release could return while
the worker was paused: the independent `!released` assertion failed. A compile
error in the first test-adapter draft was corrected before recording that
assertion failure. This is a userspace model reproduction, not a kernel UAF.

## Implementation and lock contract

1. `hws_audio_publish_stopped()` closes `work_enabled` under `pending_lock`,
   then publishes stopped flags with `ring_lock` nested inside it. Delivery uses
   the same **pending -> ring** order. IRQ recording rechecks the gate under the
   lock; IRQ enqueue and device-fault enqueue are serialized with gate closure.
2. Sleepable quiesce publishes stop, optionally disables/acknowledges accessible
   hardware, synchronizes a still-registered IRQ, then always cancels/waits for
   delivery work. Suspended, PCI-lost and DMA-quiesced states forbid hardware
   access where appropriate; none substitutes for a software drain.
3. A device `irq_lifetime_lock` protects audio callback synchronization against
   IRQ release. IRQ acquisition uses `request_irq()` plus a managed cleanup
   action. That action frees the registered handler, clears registration and
   sets IRQ to -1 under the mutex, before managed vector/BAR release. Late audio
   close therefore cannot synchronize an unrelated reused IRQ or take the
   normal MMIO branch after resource release. Acquisition failure and cleanup
   action-registration failure retain normal unwind paths.
4. `cancel_work_sync()` is called with no pending/ring/scratch/IRQ-lifetime mutex
   or ALSA stream spinlock held. No worker or atomic trigger calls quiesce or
   cancellation. Existing global drain callers are process-context PCI/PM paths,
   not the audio delivery worker. The lifetime mutex is dropped before waiting
   for work; workers do not take it.
5. `.sync_stop` supplies the ALSA stop boundary. Prepare and hw_params also invoke
   it defensively before reconfiguration. Free/close drain before resetting
   runtime bookkeeping and releasing scratch ownership; close clears the ALSA
   pointer last. Sync-stop alone preserves ring geometry/position, because the
   driver advertises suspend/resume without a fresh prepare. Trigger-stop stays
   non-blocking. A fresh start opens the work gate only after setup.
6. Device-wide fault handling no longer caches a substream pointer and notifies
   it directly. It queues XRUN reporting on the same drainable delivery worker,
   under the work gate. A stream already stopping is not queued again. An
   in-flight old notification may finish while stop waits, but cannot survive
   the drain into runtime release or a newly prepared stream.

These boundaries concern **software lifetime**, not physical DMA quiescence.
Scratch quarantine, ownership and idle/isolation requirements remain unchanged.
This does not replace the separate coordinated MMIO-failure work in batch 3.

ALSA documents `sync_stop` before prepare/hw_params/hw_free and distinguishes
that sleepable synchronization from atomic trigger handling. The core source
was also inspected for synchronization outside its stream spinlock and managed
buffer release ordering. See [ALSA driver documentation](https://www.kernel.org/doc/html/latest/sound/kernel-api/writing-an-alsa-driver.html#sync-stop-callback)
and [PCM core implementation](https://github.com/torvalds/linux/blob/master/sound/core/pcm_native.c).
The build uses the installed 7.1.9-arch1-2 headers; the upstream source inspection
is not a substitute for tests of this host's running kernel.

## Repeatable tests

```sh
make -C tools check-audio
make -C tools check-audio-sanitize
make -C tools check
make -C src W=1
python3 -m unittest discover -s local-tests -p test_hws_test_runner.py
```

`check-audio` is included in `tools check`. The adapter extracts selected current
production function bodies and the actual audio state declarations, not a
rewritten lifecycle state machine. It inserts one explicit pause after runtime
acquisition; mocked ALSA notification calls provide two other pause points.
pthread mutexes/conditions implement bounded, repeatable thread handshakes. A
five-second wait timeout/30-second child timeout fails a stuck model.

Coverage:

- 60 cases: three worker pauses × free/close/sync-stop/prepare × healthy,
  suspended, PCI-lost, DMA-quiesced, and already-released IRQ/BAR states.
- Teardown must reach the worker drain and remain blocked until the worker is
  released. Notification/runtime use must precede release completion.
- Repeated free/close, delayed IRQ enqueue, fault enqueue after gate closure,
  and fault notification before a later stop.
- Production stop/prepare/start and suspend/sync-stop/resume bodies with mocked
  hardware/scratch reclaim; preserved resume geometry/position; no sleeping
  operation during modeled atomic trigger calls.
- Actual IRQ cleanup body, idempotent cleanup, late close, and cleanup racing
  with a callback paused inside IRQ synchronization.
- A temporary mutation deleting the worker drain compiles and fails the lifetime
  assertion. Callback wiring and the non-blocking trigger paths are also checked.

Results: audio suite PASS; userspace ASan/UBSan PASS; full tools suite PASS;
29 local-runner regressions PASS; warning-enabled module build PASS. The sandbox
blocks LeakSanitizer's tracing check and the clock suite's localhost UDP test;
their successful reruns outside the sandbox are the recorded passes.

Validated SHA-256 fingerprints (working tree, not a new commit):

```text
72c7c91707ada25ad920d76d2b907ad915d6009a1707967f3875fb57ea48cc86  src/hws_audio.c
c8101a408c9b748cb1fa4baf9753b91abee7037fcfd27479dd80d16210c2e226  src/hws_pci.c
f61ed2b7a500eec02b230effb5fe9fcccc74c3b45f2d8b6a6d64eeff77fb9afb  src/hws.h
f4d6e03420c1b63a234382bf845f994ce3042b11b57b8a0ae05f66f6e66b99d6  src/HwsCapture.ko
```

The test mocks MMIO, IRQ dispatch, workqueue scheduling/cancellation, ALSA locks,
runtime/scratch allocation and PCI management. It exercises selected function
bodies, not the entire audio IRQ/staging path. The simulated prepare in failed
device states tests the drain boundary, not hardware readiness. No ALSA runtime
is actually freed during an unsafe execution: the independent ordering assertion
catches premature release first. ASan/UBSan apply to the userspace executable.

## Required kernel/hardware follow-up

Batch 2 is **not fully qualified** until a test kernel runs synchronized worker
pauses against actual ALSA free/close/reprepare, runtime failure and removal.
Test runtime acquisition and both notification boundaries, repeated fault/stop,
open-FD disconnect, probe/unwind failures, and suspend/resume. Require no UAF,
old-stream notification after prepare, double cleanup, atomic sleep or deadlock.
Run KASAN/lockdep, then separately KCSAN; keep disruptive tests in a maintenance
window with a recovery path. Kernel pause hooks have not been added in this slice.

The user's video-only quick run `local-tests/all-tests.3jljjK` had successful
content checks and zero continuity gaps in its printed transport/lifecycle
summaries, but residual drops/recoveries and unqualified presentation timing.
Its saved module hash is
`45e9ebb5bb3502c1fcd848cb1c1f8c3d446508adb177fe734aef0918e12f4243`;
it differs from the audio remediation build. That run does not exercise this
audio lifetime race or qualify this patch. Batches 3–6 remain separate work.
