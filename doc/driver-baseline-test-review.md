# Driver/baseline review and targeted tests

Hardware result update (2026-09-06): the user selected laptop-to-**video2**.
Its 1,000-frame full-diagnostic calibration passed capture, independent mapping
and qualified presentation/clock checks with zero recoveries or reported drops.
The overall FAIL is solely dirty/uncommitted provenance. See the
[verified result](video2-laptop-calibration-20260906.md). This does not explain
NVIDIA-to-video3 duplicates because both source and capture input differ.

Latest follow-up (2026-09-06): father's remediation documents now record
software changes for continuity, audio lifetime, device failure, configuration/
timing and source transitions. The open/fix status below is historical; use
father's `doc/driver-remediation-plan.md` for implementation status. The newest
9,000-frame report still observes duplicate-toggle recovery with available
buffers and no change in four follow-up toggle reads. The next experiment is
the qualified laptop on the **same video3 input**, with the loaded driver
unchanged. See [external-source comparison](external-video3-source-test.md)
for the updated diagnosis, procedure and remaining execution prerequisites.

Follow-up: [end-to-end review, 2026-09-06](driver-end-to-end-review.md)
extends this historical snapshot with the complete driver lifecycle/audio review,
baseline feature comparison, prioritized tests and source fingerprints. It
reproduces finding 1 through the full production IRQ handler and worker, and
records a successful sanitizer run outside the ptrace-restricted sandbox.
It also explains why restoring the old VB2-canary ioctl alone cannot test DMA
into the current private ring. No production driver fix is claimed here.

Reviewed 2026-09-06. Comparison: repository `baseline` branch at `1af45c8`
against `4706e64` and father's current uncommitted driver instrumentation.
The baseline is the old monolithic `src/hws_video.c`; current capture logic is
split across video, IRQ, PCI and audio files. No baseline hardware run was made.
Baseline behavior is comparison evidence, not an independent correctness oracle.

The two reproducers below execute extracted, unchanged C functions with mocked
hardware. They were run against both the local driver and source snapshots from
father. They establish software behavior under the supplied conditions, not
the frequency or physical cause of those conditions on this card. No driver
changes, module reloads or disruptive hardware tests were made for this review.

## Updated scope and coverage from the linked session

Updated using the authenticated search API, including complete activity for
[turn 50](https://codex.home.benhoff.net/sessions/01a0742f-bb05-7e00-bce0-537209f77afb?view=audit&turn=50&focus=1)
and surrounding turns. The snapshot was created at 2026-09-06 17:44 UTC;
turn 50 was still in progress. The results below describe that captured state,
not a claim that its ongoing work has finished. Turn 47–50 content digests
were independently verified against the API's canonical evidence format.

The purpose is to test **current production IRQ code against correctness
requirements**: same-frame half assembly, safe handling of ambiguous events,
buffer ownership, and eventual recovery. In
[turn 48](https://codex.home.benhoff.net/sessions/01a0742f-bb05-7e00-bce0-537209f77afb?view=audit&turn=48&focus=1)
the user explicitly chose current-code tests. The baseline comparison above
remains historical review context; a baseline/current test harness is outside
the selected work.

Turn 50 adds `tools/build_hws_irq_test.py`, `hws_irq_test_shim.h`,
`hws_irq_test_api.h`, `test_hws_irq.c`, and `test_hws_irq_mutations.py` in the
linked workspace. The adapter compiles production `src/hws_irq.c` bodies with
mock MMIO, clocks, DMA memory, work scheduling and VB2 ownership. Delivered
contents are checked against simulated source IDs independently of driver
counters. This is broader than this review's extracted-copy reproducer.

| Work | Evidence in the captured turn | Remaining boundary |
| --- | --- | --- |
| Current-code IRQ tests | `make -C tools check-irq` passed: duplicates, starvation, pending/copy overlap, deadlines, guards, stop flags, timestamp boundaries, six MMIO injection points, and 4,096 short schedules | Scripted hardware model; not exhaustive hardware or kernel concurrency coverage |
| Test sensitivity | Three mutations were detected: wrong half selection, ignored duplicate, retained active buffer after recycling | Supports those assertions; does not establish completeness |
| Sanitizers | Address/undefined sanitizer executable built; `check-irq-sanitize` exited unsuccessfully because LeakSanitizer cannot run under ptrace | Successful sanitizer completion is not established in this snapshot; the reported failure is an environment limitation |
| Missing-boundary assembly, finding 1 | Still open: schedule actions are normal IRQ, duplicate IRQ, deferred worker, and worker drain | Add DMA-only advances with withheld IRQ delivery; worker deferral still invokes the handler |
| MMIO failure and shutdown | Valid-register interleavings and `stop_requested` behavior have modeled coverage | All-ones MMIO with a blocked DQBUF, real STREAMOFF synchronization and post-stop DMA remain separate tests |

The 4,096 schedules are all six-action combinations of four selected actions,
not every possible ordering. Their duplicate action reasserts status without
advancing DMA. The MMIO injection test inserts one boundary at a time on a
single video channel; it does not exercise active audio processing or bursts
of unobserved DMA boundaries.

Earlier results also matter:
[turn 42](https://codex.home.benhoff.net/sessions/01a0742f-bb05-7e00-bce0-537209f77afb?view=audit&turn=42&focus=1)
reports 18,000 content-checked frames across two comparison suites, reproduced
queue starvation with four buffers, and no starvation with sixteen under the
same application delays. Duplicate-toggle recoveries persisted with reduced
diagnostics, NVIDIA vblank disabled and sixteen buffers. Their physical cause
remains unresolved. Turn 46 reports no observed acknowledgement-toggle change,
copy deadline miss or completion overlap explaining those recoveries; it does
not establish a baseline regression.

No HDMI source or second host is required for the deterministic tests.
[Turn 49](https://codex.home.benhoff.net/sessions/01a0742f-bb05-7e00-bce0-537209f77afb?view=audit&turn=49&focus=1)
assigns NVIDIA loopback `/dev/video3` to content, starvation and recovery
follow-up, with its unsupported vblank option disabled. The laptop-to-video2
path supplies qualified source presentation timing and cross-host clock
mapping when those measurements are needed. Neither path directly measures
physical interrupt assertion before driver entry.

## What needs fixing, and what still needs diagnosis

These are implementation directions for consolidation, not completed driver
changes. The linked IRQ tests should provide regression cases for each applicable
change; their existing passes do not resolve every finding below.

1. **Missing-boundary assembly — reproduced in the extracted-copy model.**
   Track the age/identity of the saved first half, and reject/recycle partial
   assembly when the observed cadence cannot establish that the second half
   is adjacent. Use the supported mode's half-period with a justified timing
   tolerance; reset this state on recovery, source change and stream restart.
   Keep ownership changes coordinated with any active copy worker. Add the
   2/4/6 withheld-boundary scenarios to the production IRQ harness before
   selecting the final guard. Acceptance: no mixed frame is delivered, losses
   are accounted for, and capture resumes. Software IRQ timestamps are not
   hardware frame identities, so a cadence guard alone must not be presented
   as proof against every possible interrupt-delay pattern.
2. **Fractional timing metadata — reproduced API inconsistency.**
   Represent the reported frame period as a reduced rational derived from the
   same valid DV timing state used by the timing ioctls, instead of truncating
   it through integer `fps`. Handle invalid/stale detection explicitly rather
   than silently claiming a default measured rate. Check refresh stability
   across receiver samples as well as geometry. This fixes internal consistency;
   claiming accurate physical pixel clocks/porches still requires receiver
   evidence sufficient to distinguish the modes. Acceptance: timing APIs agree
   for fractional/DMT modes and remain coherent across rate changes.
3. **MMIO failure wakeup — code-path gap, physical failure not reproduced.**
   Route a detected PCI/MMIO loss into coordinated device-failure handling in
   an appropriate context. Fail affected active queues and return/wake pending
   buffers exactly once, respecting worker ownership. Retain DMA quarantine
   until quiescence is established independently; an all-ones read does not
   establish that DMA has stopped. Acceptance: a blocked DQBUF terminates with
   a bounded error without double completion or unsafe arena reclamation.
4. **Concurrent restart and source transitions — test before changing policy.**
   If sustained traffic prevents one channel from reclaiming its arena, the
   remedy requires a justified per-channel quiescence mechanism or explicit
   recoverable restart restrictions. Do not bypass the card-wide busy check
   without evidence. If brief mode changes permit stale-layout delivery, add
   reliable source-change invalidation and synchronize it with assembly/copy;
   faster polling alone does not prove containment of oversized DMA writes.
5. **Legacy support — unresolved support contract.**
   Either implement and validate mode/rate detection on `hw_ver == 0`, or
   explicitly gate unsupported operation and narrow the support claim. The
   modern-board test results do not choose or validate that implementation.
6. **Test infrastructure — concrete tooling work.**
   Complete the existing sanitizer run in an environment that supports it;
   if leak detection must be disabled, record that reduced coverage explicitly.
   Restore/rework synchronized shutdown-race hooks and the post-stop canary
   interface before counting those tests. Add active-audio MMIO interleavings
   and withheld-IRQ DMA advances to the current-code harness. Improve physical
   source throughput to distinct IDs every refresh where loss attribution
   requires it, and use a characterized color source for colorimetry.

The physical cause of duplicate-toggle recoveries remains a diagnosis task.
Do not remove recovery checks, change acknowledgement order, or suppress loss
accounting merely because a warning occurs. First establish a failing model
case or hardware evidence connecting the proposed change to the observed loss.

## Findings reproduced in software

### 1. High priority: an unobserved full-frame gap can evade half-pair checks

Current references: `src/hws_irq.c:224` (`hws_video_copy_completed_half`),
`:956` (generation increments per observed IRQ), `:978` (timestamp check),
`:598` (publication/sequence accounting). Audio contrast:
`src/hws_audio.c:891` and `:1209` enforce a bounded packet cadence.

The video IRQ path requires a stable toggle, monotonic timestamp and no active
copy conflict. It does not reject a long *forward* timestamp gap when the toggle
alternates. Its generation is a software count of observed interrupts, not a
hardware count of completed halves. The copy deadline starts at the latest IRQ
timestamp; it does not bound the age of the first half already in the destination.

Concrete scenario at 60 Hz:

1. Copy frame A's half 0, leaving the destination active.
2. Two boundaries are not observed by software: A's half 1 and B's half 0.
3. Observe B's half 1, 25 ms after the previous observed boundary. The toggle
   has changed and the software generation increments by one.
4. The current copy function accepts B's half 1 alongside A's saved half 0.

The reproducer returned success and a completed mixed-frame destination. A
normal adjacent pair passed; controls with a visible generation gap and an
expired worker deadline failed as intended. IRQ-path source review shows no
elapsed-gap rejection for the stable, alternating case. The reproducer does
not execute the whole IRQ handler or prove the hardware can suppress precisely
these boundaries with stable post-ack status.

```sh
python3 tools/review_completion_gap.py
```

| Injected copy scenario | Result |
| --- | --- |
| Adjacent halves, 8.333 ms gap | Complete, matching contents |
| Two unobserved boundaries, 25 ms gap, observed generation +1 | **Complete, mixed contents** |
| Same 25 ms gap, visible generation +3 | Rejected, `-EILSEQ` |
| Worker delayed to its 7.5 ms deadline | Rejected, `-ETIME` |

Baseline comparison: `baseline:src/hws_video.c:4783` and the repeated channel
handlers also rely on changed toggles; the copy path around `:4260–4307` uses
a half-done flag and a memory sentinel. This is not established as a newly
introduced regression: the old implementation also lacks a robust hardware
frame identity for pairing. The new generation checks do not eliminate this
inherited ambiguity.

**Required test:** after a verified half-0 copy, suppress/withhold observation of
two boundaries while DMA continues. Repeat with 2, 4 and 6 unobserved boundaries,
different modes, and both phases. Use a distinct source ID every refresh.
Require no successful buffer containing different source IDs in its halves;
recycling/resynchronization must be visible. Injecting worker delay alone is a
different test and already has a deadline defense. A likely fix is to invalidate
partial assembly when cadence cannot establish adjacency, with tolerances
justified for each supported timing rather than inferred from toggle alone.

**Updated implementation route:** add this scenario to the existing current-code
IRQ harness from turn 50, so the real handler, acknowledgement, worker and
publication paths execute together. The existing 4,096 schedules do not include
this action. Preserve the distinction between a reproduced model failure and
evidence that the physical card exhibits the modeled sequence.

### 2. Medium priority: G_PARM contradicts fractional DV timing entries

References: `src/hws_v4l2_ioctl.c:30` (table), `:125` (mode lookup), `:160`
(receiver detection), `:621` (`G_PARM`).

The table contains exact pixel clocks and totals, but associates each entry
with an integer `refresh_hz`. Detection uses dimensions, interlace and integer
FPS to choose that table entry. `G_PARM` returns `1 / fps`, so several modes
describe different periods through the two APIs.

The reproducer compiles the actual mode table and actual `G_PARM` function,
using local Linux UAPI constants and a receiver that supplies each entry's
declared integer rate:

```sh
python3 tools/review_timing_table.py
```

| Mode | Rate derived from DV timings | G_PARM rate |
| --- | ---: | ---: |
| 1920×1080p60 | 60.000000 Hz | 60 Hz |
| 720×480 | 59.940060 Hz | 60 Hz |
| 800×600 | 60.316541 Hz | 60 Hz |
| 1280×800 | 59.810326 Hz | 60 Hz |

`G_PARM` is intended to return the actual frame period. See the
[V4L2 streaming-parameter contract](https://www.kernel.org/doc/html/v6.8/userspace-api/media/v4l/vidioc-g-parm.html).
Baseline `G_PARM` (`baseline:src/hws_video.c:465`) also uses a nominal table
rate, so integer-rate reporting is inherited rather than a newly proven
regression. Current exact DV timings expose the contradiction more clearly.

Related coverage gap: two HDMI timings with the same active dimensions and
integer FPS but different pixel clocks/porches are indistinguishable to the
current detector. It reconstructs totals from the table rather than measuring
them. The paired receiver reads check resolution and active/interlace state,
but sample FPS only once. A same-resolution refresh transition can therefore
temporarily appear stable.

**Required tests:** compare `QUERY_DV_TIMINGS`, `G_DV_TIMINGS`, `G_PARM`, DRM
source mode and measured frame intervals for every enumerated mode, especially
59.94 variants and DMT modes. Exercise same-resolution rate changes and distinct
porch variants. Do not treat a table-derived receiver pixel clock as an
independent measurement of the physical source. This was not exposed by the
exact-60-Hz video2 calibration.

## Specific hardware-dependent tests still needed

### 3. Restart one channel while other video/audio streams continue

References: `src/hws_video.c:886`, `:1537`;
`src/hws_audio.c:584`; `src/hws_pci.c:1494`.

STREAMOFF retains a quarantined permanent DMA arena. A later restart/format
change must observe the *card-wide* busy bit clear before reclaiming it. The
code deliberately returns `-EBUSY` if other streams prevent that observation,
instead of stopping unrelated streams. Baseline did not implement this
quarantine/reclaim policy. Ordinary single-channel restart success does not
establish independent restart behavior under sustained card-wide traffic.

**Test:** run all available video and audio streams, repeatedly stop/restart or
retime one channel, and monitor untouched streams' content, sample continuity,
enable bits and errors. Record retry latency and whether idle can ever be
observed. Expected: no unrelated stream interruption or remap change; any
`EBUSY` is explicit and recoverable. This is an availability/independence risk,
not a confirmed memory-safety failure.

### 4. Live mode changes and brief signal outages between monitor polls

References: `src/hws_pci.c:305` (one-second monitor interval),
`src/hws_video.c:1130` (source-state change), `src/hws_pci.c:455`
(guard checks), `src/hws_reg.h:48` (1920×1080 allocation limit).

Current code stops capture and fails the queue after detecting a source-state
change, preserving userspace's configured layout. Baseline rewrote dimensions
from its monitor (`baseline:src/hws_video.c:5232`). This intentional change
needs transition tests. A transition and return between polls can go unseen;
the guard/copy path provides earlier checks only for conditions it can detect.
The code itself notes that OUT_RES is not a trusted DMA scaler.

**Test:** 1080p↔720p, 60↔30 Hz, short unplug/replug, and unsupported/interlaced
input. Check successful buffers around the transition for mixed content,
source-change events, dequeue error/wakeup, intact guards and explicit
userspace reconfiguration. For input larger than the arena, containment must
be established in an isolated fault-testing setup; a guard is detection, not
a bound on how far a device may write. No overflow was observed in our run.

### 5. MMIO failure must wake an already-blocked consumer

References: `src/hws_video.c:967–1009`, `src/hws_irq.c:1307`.

An all-ones ACTIVE_STATUS read marks `pci_lost` in the power-present poll.
Detection returns `-ENODEV`, and `check_video_format` skips the source-state
update for that result. The IRQ handler also returns without scheduling work
when interrupt status is all ones. These paths do not themselves fail an
already-active VB2 queue. Normal PCI removal has separate queue cleanup; the
case to test is a stalled/unresponsive function while still bound, with no
remove callback to wake userspace.

**Test:** inject all-ones reads while a blocking DQBUF is pending; require a
bounded wakeup/error and contained DMA. Test this separately from cable loss,
which returns `-ENOLINK`, and orderly PCI unbind. This is a code-path concern,
not a reproduced physical failure.

### 6. Advertised legacy hardware versus the removed fallback

References: `src/hws_video.c:1099`, `src/hws_v4l2_ioctl.c:160`,
`baseline:src/hws_video.c:5196`. Already tracked in `src/FIXME.md`.

Baseline used a software VDONE-rate accumulator on `hw_ver == 0`. Current code
leaves that path empty and requires the hardware FPS register for mode
detection/startup. Test an actual legacy revision before retaining its support
claim; modern-board results cannot cover it. This is a known support gap,
not a newly discovered failure on father.

## Test infrastructure and previous evidence

- Father's ten-minute channel-3 transport soak already received 36,000 buffers,
  with 79 recoveries and 40 no-buffer frames. Twenty ordinary start/stop cycles
  passed. The retained summary is
  `father:/home/hoff/swdev/hws/local-tests/transport-soak.5oZ9OA/README.md`.
  It is transport/lifecycle coverage, without full-frame content verification.
- The video2 run independently verified 1,000 frames and timing association at
  exact 1080p60. It had no recovery events and therefore did not exercise the
  partial-buffer recovery cases above. Its source updated at about 30 IDs/s.
- Existing `hws_streamoff_race_test.sh` on father expects
  `vdone_test_delay_us` and `vdone_test_delay_active`, absent from the current
  driver. Its post-stop canary tool expects a private SYS_STATUS ioctl; the
  untracked header exists but the current driver has no implementation. Those
  scripts do not currently supply coverage. Update hooks/harnesses before
  counting those tests, and distinguish requeue delay from worker/IRQ delay.
- The new deterministic harness does cover IRQ/worker overlap and stop-flag
  checks. It does not repair the missing real shutdown-race hooks or canary
  ioctl, so those hardware coverage gaps remain open.
- Black/white tile validation does not discriminate BT.601 from BT.709 chroma
  conversion. Existing colorimetry scripts need an independently characterized
  RGB/color source; the video2 run does not validate color metadata or controls.
- PM and unbind paths were read, but no suspend, unbind, sanitizer, legacy-board
  or simultaneous-audio run was performed during this review.

Updated remaining-work order:

1. Extend and finish the current-code deterministic tests already underway.
   Add withheld-IRQ/DMA-advance cases from finding 1, including 2/4/6 missed
   boundaries, and cover acknowledgement-to-toggle sampling with active audio.
   Retain content/ownership/forward-progress assertions and obtain a completed
   sanitizer result. Existing model passes do not close the missing-boundary
   finding.
2. Test fractional and alternate DV timing metadata and same-resolution rate
   changes (finding 2). The IRQ harness does not exercise the V4L2 ioctl table.
3. Validate channel independence during concurrent video/audio restart
   (finding 3), then live source transitions (finding 4).
4. Exercise all-ones MMIO with a blocked consumer (finding 5), real shutdown
   races, post-stop DMA, PM and reviewed unbind paths. Stop-flag unit tests do
   not establish DMA quiescence or userspace wakeup behavior.
5. Reproduce recovery on video3 with content checking and reconcile source-ID
   gaps with starvation/recovery counters. Use video2 when source presentation
   timing is required; improve to distinct IDs per refresh before using source
   identity to resolve every possible lost frame. Qualify any modeled failure
   mechanism against actual register/IRQ behavior.
6. Complete legacy-revision support (finding 6), colorimetry and remaining
   hardware/mode coverage before broad support claims.

Existing successful captures, content comparisons and transport soaks count as
coverage of their tested conditions. Repeating an ordinary transport soak alone
would not close the specific gaps above.
