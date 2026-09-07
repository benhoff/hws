# Source transitions and peer-active restarts (R5, R7)

2026-09-06, batch 5: software checks, deterministic regressions and an explicit
restriction/recovery contract. **Hardware qualification remains open.** No
module was loaded/unloaded, source changed, stream interrupted or card unbound
as part of this work. This does not explain or eliminate historical duplicate
toggle recoveries.

## R5: opt-in worker checks, not DMA containment

`source_transition_checks=1` is a new read-only-at-runtime module parameter.
It defaults to **off** pending physical PCIe/worker-overhead qualification. The
existing one-second source monitor remains active with either setting. Merely
loading the new build with default parameters does not enable the faster checks.

When enabled, each normal completion worker checks receiver active/interlace,
native input dimensions and nominal integer FPS against the stream's configured
layout/rate before and after the half-copy. It uses paired samples: six reads
per check, no retries, no configuration writes. No new reads or polling are
added to the hard interrupt handler. The configuration remains immutable until
STREAMOFF has drained the worker; it is not replaced by detected metadata.

An observed mismatch/loss/unstable pair fails the target queue, clears saved-half
validity/continuity, disables its producer and leaves CPU destination ownership
attached for STREAMOFF to return after draining. Returning to the original
signal does not automatically resume the stream. All-ones reads use the existing
device-failure latch instead of masquerading as a source change. An ordinary
STREAMOFF/suspend cancellation does not generate a new source failure/event.

The worker never acquires `state_lock` or drains itself. It records a pending
source-change indication under `irq_lock`; the existing monitor consumes this
under `state_lock` and queues the V4L2 source-change event. The indication survives
a failed monitor trylock and a source that returns before the monitor samples
it. Delivery of that event depends on the monitor getting its lock; it is not
a hard one-second notification deadline. An old pending notification by itself
does not stop a new valid stream that the application already restarted.
Framework event coalescing and actual
kernel scheduling are not modeled by the tests.

### Cost and remaining restriction

The production-code model counts **5 → 5 IRQ reads** and **3 → 15 worker reads**
for a normal half: 12 extra worker reads, approximately 1,440 extra reads/second
at 60 frames/second. These are operation counts, **not measured PCIe latency**.
The model also injects read delay and verifies that the original copy deadline
still rejects late delivery; the additional checks cannot extend that deadline.

Per-video debugfs `stats` adds lifetime counters (take differences between runs):

- `source_check_count`: attempted snapshots, including canceled attempts.
- `source_check_ns`: cumulative elapsed snapshot time.
- `source_check_max_ns`: largest snapshot duration since channel initialization.
- `source_check_failures`: failed snapshots, excluding ordinary stop/suspend.

Average check time is delta ns / delta count, if the latter is nonzero. These
durations include any preemption during the snapshot and exclude the subsequent
counter lock. Maxima are lifetime values, not per-run percentiles. Preserve
deadline, recovery and queue counters alongside these timings.

**Stable-source operation remains the supported restriction.** Six sampled
register reads cannot prove coherent hardware latching or contain DMA:

- A change away and back between checks (including loss/return), a change after
  the final sample, or a receiver that reports an old state may be missed.
- 60↔59.94 changes are invisible if the hardware reports the same integer rate;
  porch/pixel-clock exactness is not provided by these registers.
- A larger source may already have written beyond the arena before software
  observes it. OUT_RES, guards and this check do not establish a DMA size limit.
- Loss with no further completion is still detected only by the monitor.

The oversize regression supplies a 3840×2160 **register report** and requires
the worker to stop. It does not execute a physical oversize DMA, emulate its
containment, or establish safety for that signal. Do not try unsupported larger
modes on the working host. Such tests need an isolated system, independent
containment evidence and a recovery plan.

### Application recovery

After a source error/event, stop the affected stream; do not treat an error
buffer as a valid image. STREAMOFF drains the old assembly. Release the old VB2
allocation (and mappings as required), query a stable supported source, set its
DV timings, obtain the new native format, allocate/requeue correctly sized
buffers and STREAMON. Configuration/start can fail while the source is unstable
or the old DMA arena is quarantined; preserve those errors. A matching source
alone does not revive the failed queue.

## R7: explicit restricted independent-restart contract

No global-idle requirement was relaxed and no automatic retry or peer shutdown
was added. The tests compile the actual video reclaim, audio reclaim,
non-forcing wait and idle-poll functions. Poll scheduling and PCI/framework
operations are modeled, not real kernel execution.

After disabling the target, reuse of its quarantined video/audio arena requires
observing the existing global DMA-busy bit clear (or an already established
global quiescence proof). A continuously busy peer can prevent that observation.

- The poll has a **100,000 microsecond budget**, with a 10 microsecond requested
  delay. This is not an end-to-end wall-clock bound: mutex contention and kernel
  scheduling can add time.
- A timeout maps to `EBUSY`, retains quarantine and performs no guard read/reuse,
  force-stop or PCI isolation. The caller gets one attempt, not an infinite retry.
- Once idle is observable, retry may verify guards and reclaim. Corruption is
  sticky (`EUCLEAN`); unavailable/fatal device state is not bypassed by a later
  apparently idle BAR value.
- Keep peers running if independent restart is needed. An application may use
  a finite retry budget (for example three attempts with backoff), then report
  restart unavailable. If all-stream interruption is acceptable, the application
  must explicitly coordinate stopping its video and audio peers before retrying.
  Do not solve this by forcing unbind, unloading the module or skipping idle.

This contract is for non-forcing per-stream reclaim. Fatal device failure and
whole-device teardown have separate global-stop policies. It is an availability
restriction, not proof of hardware memory safety or continuous A/V integrity.

## Permanent tests

Run without capture hardware or root:

```bash
make -C tools check-transitions
make -C tools check-irq-mutations
make -C tools check-transitions-sanitize
```

`make -C tools check` now includes the transition/restart tests. The existing
`hws-test-all.sh` therefore includes their software gate, but its ordinary
single-video quick hardware run is **not** a source-transition or concurrent-A/V
qualification test.

Coverage added:

- 48 source cases: 720p and 1080p, resolution changes (including both directions),
  integer-rate change, loss, interlace and oversize reports before/inside each
  half-copy. No affected successful delivery, retained ownership, sticky stop.
- All six source-snapshot read fault positions and pair-splitting transitions;
  peer status bits do not fail the target. Stop during copy causes no fabricated
  source event. A deliberately invisible loss/return demonstrates the limitation.
- Interrupt interleavings at all 15 worker MMIO positions for either half;
  ownership retained and subsequent forward progress required. MMIO budget and
  duration counters checked with deterministic read costs.
- Production notification/fail-queue functions: pending indication survives a
  busy monitor; once consumed it is not repeated on an unchanged sample; no
  automatic restart, configured-layout rewrite, self-drain or peer stop.
- Video and audio reclaim with opposite-direction same-slot peer, distinct-slot
  peers and all other channels active: three busy attempts retain identical
  device state, followed by idle success, guard corruption, missing-device and
  fatal-state cases. Model peer ticks are not content/audio validation.
- Mutation controls remove pre/post source checks, pending-event consumption,
  idle proof or error propagation, and substitute a forcing restart; assertions
  must reject them. Another control makes a delayed notification stop an already
  recovered stream and must also fail. Existing IRQ, audio-lifetime, device-failure and configuration
  tests remain required.

### Validation recorded for this change

- `make -C tools check check-irq-mutations`: PASS, including the new cases and
  existing 4,721 IRQ schedules, 95 evidence tests and 16 clock tests.
- `make -C tools check-transitions-sanitize`: PASS with ASan/UBSan, including
  the full IRQ model and production restart/notification functions.
- Runner regressions: 29 PASS.
- Kernel `W=1` module build against `7.1.9-arch1-2`: PASS, no emitted warnings.
- `git diff --check`: PASS.

The sandboxed full-suite attempt failed to start the local UDP clock peer;
the full unsandboxed rerun passed. Sanitizers also ran outside the sandbox.
These tests did not access capture hardware. Local, unsealed logs are in
`/tmp/hws-step5-validation.XzHAgl` (`software-final.log`, `sanitizers-final.log`,
`module-build-final.log`, `runner.log`).

Built module srcversion: `F32B3D4594E5B45A2B2BF67`.
SHA-256 of `src/HwsCapture.ko`:
`213d954b0988f5920550968e7e778ad789641824ccd134a261d7c99cbca0d5ad`.
SHA-256 of `src/hws_source.h`:
`067cba51558d677b237d85549e05ba36ad7ef01d8d6f989ead1531228f25676f`.
The build includes the pre-existing dirty worktree and earlier remediation
batches; this identity is not a new commit or evidence of a loaded module.

## Hardware qualification still to do

1. With all capture consumers stopped by their owners, deliberately load this
   exact build with `source_transition_checks=1`. This requires a manual module
   load/reboot decision; this change does not modify the boot configuration.
   Check `/sys/module/HwsCapture/parameters/source_transition_checks` is `Y` and
   that the loaded srcversion matches the build. Do not reload with live peers.
2. Start with a stable supported patterned source on the agreed input. Compare
   checks-off/on runs of the **same code**, full content checks and queue depth.
   Preserve stats, source evidence and kernel logs. Record mean/max snapshot
   cost, copy deadlines and drops/recoveries. Decide an acceptable worker budget
   from the fastest mode before enabling checks by default. No baseline branch
   comparison is needed.
3. On an appropriately contained test setup, coordinate supported 1080p↔720p,
   same-size rate and loss/return transitions. Record source commands/timing,
   DQEVENT, ioctl errors and captured content through reconfiguration. Ordinary
   mode commands cannot deterministically target a half-copy race; synchronized
   kernel hooks/hardware evidence are still needed for that claim.
4. For restart qualification, agree video-node/ALSA-device ownership and sources
   first. Hold a patterned video peer and checked 48 kHz stereo audio peer open
   continuously while restarting only the target. Begin with shared-slot A/V,
   then different channels, then all channels. Record every ioctl duration and
   errno, retry count, peer content/sequence losses, audio continuity/XRUNs, guards
   and source-check costs. Repeat with video and audio targets. End with a
   separately authorized coordinated-stop/retry case.

No automated physical transition/concurrent-audio harness was added: the active
source/node/ALSA mapping and disruptive test permission have not been established.
Those hardware tests, real kernel races and physical DMA containment remain open;
the software tests intentionally do not turn them into PASS results.

Separate follow-up: [bounded late-toggle diagnostic](late-toggle-diagnostic.md)
adds opt-in raw-register observations for the unresolved duplicate-toggle issue.
It does not change the recovery policy or close the hardware qualifications above.
