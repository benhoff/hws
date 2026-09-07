# Device/MMIO failure remediation (R3)

2026-09-06: remediation batch 3's **code and hardware-free test slice**.
Actual kernel concurrency, userspace wakeup latency and PCI/DMA containment
qualification remain open. No driver was reloaded, no device was unbound, and
no hardware fault, PM transition or display takeover was run for this change.

## Defect reproduced

The production IRQ implementation was tested with a single all-ones MMIO read
injected into an otherwise valid stream. Before the fix, the new assertion
`device.pci_lost && device.dma_failed && !delivered` failed. The old first-status
path silently returned IRQ_NONE; raw toggle reads could also mask U32_MAX into
valid toggle 1. A later valid read must not erase an observed device failure.

This is a software-model reproduction, not evidence that the historical
duplicate-toggle messages were caused by MMIO failure.

## Implementation and ownership contract

- `hws_device_lost()` is an IRQ-safe, idempotent latch. It records the first
  static reason string, sets fatal/lost state, publishes stopped stream flags,
  and queues one cleanup worker on the system long-work queue. It does not
  sleep, perform MMIO, drain a worker or return any buffers.
- The enqueue decision and lifecycle gate use one spinlock. Scheduling remains
  disabled during partial probe construction. Once interfaces are initialized,
  a fault already latched during registration is scheduled too. Probe unwind,
  remove, shutdown and suspend close the gate and cancel/wait before normal
  teardown. A pending canceled transaction is superseded by that teardown;
  a running transaction must finish before resources are destroyed. Late
  reporters cannot enqueue into destroyed private queues.
- Cleanup first finishes any overlapping capture-enable critical section and
  republishes stopped flags. It attempts independent PCI bus-master disable
  and pending-transaction verification under `dma_lock`. Only successful
  isolation sets `dma_quiesced`. The existing PCI helper's missing-function
  handling and hardware assumptions are unchanged.
- It then releases `dma_lock`, synchronizes the registered IRQ under its lifetime
  lock, waits for an old monitor pass, and drains video/audio work. No DMA,
  monitor, video-state or audio spinlock is held across the worker drains.
  This cleanup runs outside the private queues it drains.
- After copies finish, `hws_video_device_error()` takes each video state lock,
  errors the streaming vb2 queue, collects its active/queued buffers under the
  IRQ lock, and returns them once with ERROR. It shares the existing collection
  helper and state-lock serialization with STREAMOFF. These are **CPU-copy
  destinations**, not the fixed hardware DMA arenas.
- Audio faults use batch 2's gated, drainable XRUN notification worker. Cleanup
  flushes that notification; it does not cancel it immediately after enqueue.
  A stream already closing/stopping can have its gate shut and needs no new
  notification using a stale ALSA pointer.
- No arena is freed by this worker. Isolation failure still permits consumer
  errors after software drain, but keeps DMA arenas quarantined. Existing
  reclaim/teardown paths must establish their idle/isolation boundary. An
  all-ones idle poll latches failure and cannot be followed by a speculative
  healthy-looking BAR poll to authorize reclaim. Restart remains prohibited;
  resume checks the fatal latch, including at its final publication point.

`hws_read_toggle()` checks the raw register before extracting bit zero. Video
IRQ sampling, copy verification, recovery and optional probes, plus audio IRQ
sampling and copy verification, use it. First status, acknowledge readback,
receiver/status and capture-enable failure paths also reach the coordinator.
An unknown/shared interrupt cause is not claimed or acknowledged. No-cause IRQs
and source absence (`-ENOLINK`) are not device-loss events.

After the latch, ordinary IRQ and monitor entry and relevant audio diagnostic/
acknowledge paths avoid fresh MMIO. An already-running register sequence may
finish a bounded number of reads before noticing a concurrent failure; this is
not a global MMIO-access lock. Probe/PM containment operations retain their
separate lifecycle contract. Transactional verification of all programmable
registers is batch 4, not claimed complete here.

## Repeatable software checks

```sh
make -C tools check-failure
make -C tools check-irq
make -C tools check-failure-sanitize check-irq-sanitize check-audio-sanitize
make -C tools check check-irq-mutations
make -C src W=1
python3 -m unittest discover -s local-tests -p test_hws_test_runner.py -v
```

Results for this implementation:

- New IRQ fault cases: PASS at eight video read positions (first status,
  pre-ack toggle, ack readback, post-ack pair, copy/verify reads) and five audio
  IRQ read positions. Valid→all-ones→valid remains fatal with no later IRQ MMIO.
  Shared/unowned and zero-status controls pass.
- Production failure coordinator and video buffer-collection bodies compiled
  against pthread/mocked PCI/consumer operations: PASS for eight combinations
  of isolation success/failure, registered/absent IRQ and pre/post-enable fault.
  Concurrent repeated reporters schedule once; first reason is retained;
  cleanup and remove wait for a simulated active copy. Owned video buffers are
  returned once, audio notification ordering is checked, and later collection
  is empty. These are modeled consumers, not real blocked DQBUF/ALSA syscalls.
- Negative controls: removing the copy drain or falsely reporting PCI isolation
  success causes the new tests to fail. Lifecycle wiring checks pass.
- ASan/UBSan: new failure model, production IRQ model and audio lifetime model
  PASS. LeakSanitizer needed execution outside the ptrace sandbox; this is a
  userspace sanitizer run, **not kernel KASAN**.
- Full tools check PASS: IRQ/continuity model, audio lifetime, device failure,
  frame decoder/raster and timing probe, 95 VDONE and 16 clock tests. Existing
  IRQ mutation tests and 29 runner regressions PASS. Module build with `W=1`
  PASS against installed 7.1.9-arch1-2 headers. `git diff --check` PASS.

The model subprocess has a 30-second timeout to fail a stuck test. This is not
a promised driver response deadline. Workqueue scheduling, outstanding kernel
copies and PCI transactions must still be measured on a test kernel. Do not
add a timeout that frees memory while an old copy or DMA may still own it.

Build identity (dirty worktree based on commit
`4706e64bc4e6a60ed3e3049d287f79d12734d78c`): module srcversion
`FD9697A7586766793CF76EA`; `src/HwsCapture.ko` SHA-256
`b8b0c8ec997e49dc024395f7fe3756b9be00125a8edea50ff3dc33bf2cbdd9ea`.
These identify the on-disk build, not the loaded module or a hardware test run.

## Remaining qualification

On an isolated, recoverable test setup, load the exact reviewed build and add
controlled in-kernel MMIO fault injection and synchronized pause points. Test
first/middle/final reads during simultaneous video/audio; blocked DQBUF/ALSA
reads; failure versus STREAMOFF/close/remove; a queued versus running failure
worker; and suspend/resume/probe-unwind error paths. Verify bounded observable
errors, no duplicate completions, no restart, no deadlock/UAF, and no use of
released IRQ/BAR resources under KASAN/lockdep and separately KCSAN. Check shared
INTx behavior and interrupt containment as well as MSI/MSI-X where supported.

Independently fault PCI isolation and verify that hardware-targetable arenas
remain allocated/quarantined. Actual post-stop DMA requires the separate canary
test facilities; a software drain or passing content test cannot replace it.
The ordinary quick capture script is useful regression coverage after an
authorized reload, but does not inject device loss or establish these gates.

Historical duplicate toggles, source presentation timing, source-change policy
and batch 4 register/timing issues remain separate work. This change does not
claim to eliminate physical duplicate toggles or prove universal correctness.
