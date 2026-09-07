# Driver remediation plan

Commit organization: [series index and current verification](commit-series.md).
The updates below preserve their original implementation/qualification scope.

Proposed 2026-09-06, based on the
[end-to-end review](driver-end-to-end-review.md). Finding IDs R1–R8 refer to
that document. The initial plan is retained below.

2026-09-06 implementation update: batch 1's software remediation is implemented
and its permanent missed-boundary/model/build gates pass. See the
[continuity change record](vdone-continuity.md) for policy, test results and
limitations. No module was reloaded or hardware requalified. Batches 2–6 remain
open; arbitrary hardware/handler-timestamp ambiguity is not closed by batch 1.

Later 2026-09-06 update: batch 2's software-drain, stop/reprepare and IRQ-lifetime
changes plus paused-worker regressions are implemented. See
[audio lifetime remediation](audio-lifetime-remediation.md). Kernel synchronized
KASAN/lockdep/KCSAN qualification remains open, so batch 2 is not fully closed.

Batch 3 update (2026-09-06): coordinated device-failure latching, deferred
containment/drain/consumer errors and raw-toggle validation are implemented.
The production-code fault models, mutation controls, userspace sanitizers and
warning-enabled build pass. See [device-failure remediation](device-failure-remediation.md).
Real kernel fault/wakeup/race and physical DMA-isolation gates remain open;
batch 3 is software-remediated, not fully hardware-qualified.

Batch 4 update (2026-09-06): shared DMA-register verification and delayed cache
publication, active-peer remap protection, rational timing reporting/deadlines,
paired FPS detection and a serialized debugfs configuration snapshot are
implemented. See [configuration/timing remediation](configuration-timing-remediation.md)
for tests, error policy and precision limits. Software gates pass; hardware
register semantics, concurrent streams and PM qualification remain open.

Batch 5 update (2026-09-06): opt-in paired worker source checks, persistent
source-change notification and cost counters are implemented, with production
IRQ/notification/reclaim model tests. Non-forcing peer-active restart retains
its bounded poll/EBUSY/quarantine contract. See
[source-transition/restart remediation](source-transition-restart-remediation.md).
Extra source checks default off until real PCIe overhead is qualified; stable
source operation and independent-restart availability restrictions remain.
Physical source transitions, concurrent A/V and DMA containment are still open.

## Objectives and boundaries

1. Prevent the reproduced mixed-half delivery case.
2. Establish safe software/resource lifetime through stop, failure and removal.
3. Make programming failures and unavailable timing explicit.
4. Qualify the remaining hardware assumptions, or document restrictions where
   the hardware cannot support the desired guarantee.

Test current production code against independent assertions. No baseline/current
hardware comparison harness is required. Keep the current permanent DMA arena
architecture; do not combine this work with scaling, direct-DMA, multi-consumer,
or other architectural refactors.

Keep changes in small, separately reviewable patches, each with regression
coverage and updated evidence documentation. Preserve existing working-tree
changes and sealed evidence. No automatic commits, reloads, unbinds, PM cycles,
boot-option changes, or source takeovers are part of writing this plan.

## Work sequence

| Batch | Findings | Deliverable | Completion gate |
| --- | --- | --- | --- |
| 0 | All | Fixed review/test snapshot and explicit expected failures | Reproducers distinguish a defect from a runner error |
| 1 | R1 | Guard partial-frame continuity; permanent IRQ regression cases | No mixed delivery in expanded modeled schedules; existing controls pass |
| 2 | R2 | Audio software-drain/lifetime contract | Paused-worker teardown tests; kernel KASAN/lockdep follow-up |
| 3 | R3 | Coordinated runtime failure handling | Bounded consumer wakeup, no unsafe reclaim, race-safe repeated failure |
| 4 | R6, R4 | Transactional register verification and coherent timing API | Fault-injected programming and all-mode API tests pass |
| 5 | R5, R7 | Source-transition and concurrent-stream qualification | Reproduce risks, then fix or explicitly restrict unsupported behavior |
| 6 | R8, coverage gaps | Supported configuration matrix and lifecycle release gate | Per-configuration evidence, exclusions, and known limits recorded |

Batches 1–4 can begin with builds and software models on father alone. Kernel
concurrency validation is separate from a passing userspace model. Batch 5
depends on the safer lifecycle/failure paths from batches 2–3. Batch 6 starts
with documenting support now, but qualification closes only after the tests.

## Batch 0 — Preserve a trustworthy starting point

- Record HEAD, driver/tool hashes, kernel/build configuration and dirty inputs.
  Do not clean or reset the working tree to obtain this snapshot.
- Run existing IRQ tests, mutation checks, sanitizers and tool regressions.
- Retain the known failures from `review_irq_gap.py` and the numerical output
  from `review_timing_table.py`. They are negative evidence, not suite failures
  to hide. Test/build errors must remain distinguishable from mixed delivery.
- Keep content integrity, accounting, physical timing, provenance, concurrency
  and DMA lifetime as separate result categories. A pass in one does not clear
  failures in another.

## Batch 1 — Fix partial-frame pairing (R1)

Primary files: `src/hws.h`, `src/hws_irq.c`, stream-reset paths in
`src/hws_video.c`; `tools/test_hws_irq.c` and its adapter/shims.

### Tests first

Move the new DMA-only advance scenarios into the permanent production-code
suite: 0/2/4/6 withheld boundaries after either half, with the original independent
source-content oracle. Add odd gaps, startup, recovery, source holds, starvation,
pending/copying workers, exact time-boundary cases and timestamp anomalies.
Parameterize dimensions and native split so the suite includes unequal halves,
not just 640x480's symmetric split. Exercise all supported frame periods.

### Implementation

- Add saved first-half timing/stream-epoch state, distinct from the current
  completion's timestamp and observed generation.
- Define a mode-derived continuity bound and its rounding/tolerance in one
  helper. Use the configured timing's rational period where available; do not
  duplicate a hard-coded 60 Hz assumption. Internal use of that helper can
  precede the user-facing G_PARM change in batch 4.
- Check continuity before joining a second half and recheck relevant state
  before publication. Retain existing toggle, generation, copy-deadline and
  guard checks; a new age check supplements them.
- If continuity is uncertain, recycle/discard the partial destination and
  resynchronize. Do not publish a successful partial frame. If a worker owns
  the destination, defer ownership changes until that worker releases it.
- Reset saved continuity state on every recycle, stop, restart, fatal failure,
  source change and PM transition.
- Expose a distinct continuity-gap reason/counter in bounded diagnostics and
  update evidence consumers/tests. Count known discarded work; do not pretend
  to know the exact number of physical frames lost from IRQ parity alone.

Before choosing a numeric tolerance, document which assumptions make it safe
and test just-inside/at/just-outside limits for every rate. Do not tune the
threshold merely to pass one hardware log.

**Acceptance:** the three currently failing full-handler cases stop delivering
mixed frames; normal controls still deliver; ownership is exactly once; recovery
makes bounded progress under resumed normal events. A mutation removing the
continuity check must restore the failure.

**Residual limitation:** a software age/cadence check remediates the reproduced
case, not all possible delayed/coalesced hardware events. Add adversarial models
where handler timestamps conceal the true DMA cadence. If source identity cannot
be inferred from observable state, record the remaining guarantee as conditional
on timing assumptions. A universal guarantee would need stronger independently
validated hardware identity/completion information or a different justified
acquisition protocol—not interpretation of driver generations as hardware IDs.

## Batch 2 — Fix audio teardown synchronization (R2)

Primary files: `src/hws_audio.c`, `src/hws.h`, `src/hws_pci.c`; new audio
production-code and synchronized kernel lifetime tests.

First reproduce the identified interleaving with a worker paused after acquiring
runtime state and separately before XRUN/period notification. Race these points
against hw_free/close, removal publication and MMIO failure. Check STOP→PREPARE→
START, repeated cleanup, and close after BAR/IRQ resources are already gone.

Separate three facts in the lifecycle design:

- New work is prevented.
- Existing software work can no longer access stream/runtime resources.
- Hardware DMA has been quiesced or its arena remains quarantined.

Do not use `suspended` or `pci_lost` as proof of the second fact. Ensure every
resource-release/reprepare path reaches a software-drain boundary even when
MMIO is forbidden. Keep atomic trigger-stop limited to stopping/publication;
place blocking drain in an appropriate sleepable lifecycle callback. Evaluate
`.sync_stop` as the common ALSA entry point after checking actual PCM lock
contexts; do not simply add `cancel_work_sync()` everywhere.

Write and test the lock/order contract before implementation: no cancellation
while holding locks the worker/ALSA notification needs, no self-cancellation,
no synchronization against a freed/reused IRQ, and no old-stream notification
after a new stream epoch starts. Include failure work/removal interactions.

**Acceptance:** close/free cannot finish while a worker still has legal access
to the old runtime; no stale notification, UAF, double release, atomic sleep or
deadlock. Software-model tests are necessary but do not close this issue until
the synchronized kernel cases pass under KASAN and lockdep.

## Batch 3 — Coordinate device/MMIO failure (R3)

Primary files: PCI lifecycle, video/audio failure paths, IRQ raw-register reads.

- Define one idempotent device-failure transition. IRQ/monitor/callback callers
  latch the failure and stop new starts/work; a suitable process-context path
  coordinates hardware containment, software drain and consumer errors.
- Validate raw toggle reads before extracting bit zero, including U32_MAX.
  Preserve legitimate no-cause/shared-IRQ behavior and documented register
  semantics. Avoid uncontrolled retries against an inaccessible device.
- Wake blocked video/audio consumers with explicit errors. Return each owned
  buffer once through its defined cleanup path, after active copies drain.
- Preserve arenas until idle/isolation is independently established. If it
  cannot be established, retain quarantine and reject restart; never convert
  MMIO failure into success merely because a later read looks idle.
- Order failure-worker cancellation/lifetime with remove and probe unwind.
  Avoid draining a workqueue from a worker whose completion that drain awaits.

Fault-inject first/middle/final register reads, valid→all-ones→valid transitions,
repeated simultaneous failure reports, active copies and blocked reads. Include
remove racing with the new failure path.

**Acceptance:** bounded userspace error/wakeup, no work on freed resources, no
restart through a latched fatal state, and no free/reuse without a DMA boundary.
Specify software timeouts separately from guarantees hardware cannot provide.

## Batch 4 — Verify configuration and report coherent timings (R6, R4)

### R6: register programming as a transaction

Calculate expected remap/base/split values; program while capture is stopped;
flush and validate readable registers; publish cached state/window_valid only
after successful checks. On failure leave the cache invalid, refuse VCAP enable
and preserve quarantine as needed. Make correctness checks unconditional;
`dma_window_verify` may control extra logging, not whether an error is honored.

Share helpers with probe/resume where their register semantics really match.
Preserve known write-only/strobe readback exceptions. Inject failed/stale writes
to each field during initial start and mode-change restart, with diagnostics on
and off. Acceptance: bad programming never arms the affected stream or corrupts
a simultaneously active audio/video peer.

### R4: one timing representation

Use overflow-checked rational arithmetic for frame period from the accepted DV
timing state and a consistent snapshot across timing/format/debugfs consumers.
Repeat/check FPS along with receiver geometry/status samples. Decide and document
G_PARM behavior for absent, unstable and unsupported sources; do not silently
present a default rate as a measured one.

Test the complete enumerated table, reduced rational values, fractional/DMT
rates, invalid timing input, mode changes and busy queue behavior. Keep configured
timings distinct from detected timings. Where the receiver cannot distinguish
60 from 59.94 or alternative porch layouts, document inferred timing and reject
unsupported exactness claims rather than inventing precision.

**Acceptance:** timing APIs agree for the same valid state; negative cases have
documented results; changing metadata does not change native buffer layout,
enable unsafe scaling or make the independent physical timing test circular.

## Batch 5 — Characterize, then fix or restrict hardware-dependent behavior

### R5: source transitions

Add bounded source-state checks at suitable capture decision points, invalidating
assembly/queue state on a detected change. First measure the MMIO/IRQ overhead
and test races; do not add broad register polling to the hard handler by default.
This improves detection but is not a DMA-containment guarantee.

Use patterned 1080p↔720p, same-size refresh changes, loss/return, and sub-second
transitions in each assembly phase. Require no stale-layout successful delivery,
coherent source-change notification, and recovery only after valid configuration.
Model oversize DMA first. Larger unsupported physical modes require an isolated
system and suitable containment; do not test those casually on the working host.

If the device cannot constrain DMA during source transitions, retain a documented
stable-source restriction and mark this residual risk open. Faster polling or
larger guard pages alone cannot close it.

### R7: restart with other channels active

Keep the conservative global-idle check. Run repeated target-stream restarts
while peer channels continuously validate video and audio; measure idle-check
duration, EBUSY/retries, peer losses and guard state. Test shared-slot A/V first,
then different channels and all channels.

If restart stalls, prefer bounded, documented retry behavior or a coordinated
all-stream stop explicitly requested by the application. Use a per-channel idle
mechanism only after its hardware semantics are established. Do not force-stop
unrelated streams or skip idle verification to hide an availability failure.

**Acceptance:** either independent restarts meet a stated bounded contract with
intact peers, or their restriction/error/recovery procedure is documented and
tested. An availability restriction is not equivalent to a fixed memory-safety
defect, and a successful test on one load does not prove all possible loads.

## Batch 6 — Close support and release-test gaps (R8 and cross-cutting work)

- Document the current progressive native YUYV/MMAP and stereo 48 kHz/S16_LE
  scope, plus tested PCI ID/firmware/mode/channel combinations. Test clean
  rejection of unsupported requests.
- Make an explicit legacy-hardware decision: implement/test hw_ver==0 support,
  or gate it with a clear unsupported result. Recommended near-term approach
  is to avoid claiming untested legacy support. Removing IDs or breaking an
  existing user's supported setup requires a separate compatibility decision.
- Build bounded, test-only synchronized hooks for worker shutdown and DMA
  lifetime tests. Keep them off by default, restricted, self-expiring, and
  teardown-safe; do not expose arbitrary physical memory/register access.
- Split the old canary goal: (1) no software write into returned VB2 buffers;
  (2) no DMA into/reuse of the private arena after a claimed quiescence boundary.
  Restoring the old status ioctl alone is insufficient. Retain arenas while
  observing them; STREAMOFF may leave quarantined in-flight DMA by design.
- Fault-test probe unwind and every PM rollback stage; then exercise idle,
  video, audio, simultaneous A/V and open-FD removal on a test kernel. Use
  KASAN/lockdep and separately KCSAN. Review the existing unbind harness before
  allowing it to operate on the whole card.
- Give debugfs config a coherent snapshot/epoch and test readers across format
  change, suspend and removal. Test trace caps and instrumentation-on overhead.
- Validate colored patches/levels and known stereo samples; black/white IDs and
  silent audio do not establish colorimetry, sample continuity or A/V drift.

## Validation ladder and stopping rules

For each patch, run relevant reproducer/regressions, a warning-enabled module
build, and the expanded userspace sanitizer/mutation tests. Preserve a failing
counterexample before changing the assertion or recovery policy.

After software gates pass:

1. On an authorized reload, stop card consumers, load the exact reviewed build
   and verify loaded identity. Keep the previous known build available; no
   automatic rollback by unloading active channels.
2. Run short native capture and lifecycle/content tests on NVIDIA→video3 with
   unsupported vblank disabled. Use 16 buffers for low-starvation qualification
   and keep delayed 4-buffer trials as positive starvation controls.
3. Use laptop→video2 for independently qualified source timestamps and clock
   mapping. Verify distinct source IDs each refresh before claiming per-refresh
   loss accounting; source holds must remain explicit.
4. Run the targeted A/V, source-transition and kernel concurrency cases before
   a long soak. Disruptive tests require a separate maintenance window and an
   external recovery path.
5. Record which gates passed for which configuration. Expand the support matrix
   only from retained evidence; SKIP/INCONCLUSIVE stays unresolved.

Stop immediately on mixed content, guards changed, UAF/lockdep report, duplicate
buffer completion, unexplained memory writes or loss of DMA isolation. Preserve
artifacts and diagnose before increasing duration or weakening assertions.

Historical duplicate toggles remain a separate diagnosis track. Retain the
pre/post-toggle/status and nearby content evidence with timing/loss counters;
compare active audio/channels and instrumentation independently. Do not change
W1C ordering or suppress recovery merely to remove warnings. These fixes may
improve safe handling without eliminating the physical duplicate events.

## First implementation slice

Start with batch 1: permanent missed-boundary tests, explicit partial-frame
continuity state, safe discard/resynchronization, bounded reason accounting,
then all existing and new software checks. No laptop or module reload is needed
to implement/build/model-test that slice. Its hardware qualification and the
audio/lifecycle work remain separate gates.
