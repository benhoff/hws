# End-to-end driver and baseline review

For the subsequent fixes and commit boundaries, see the
[series index](commit-series.md). Findings below describe the review snapshot.

Reviewed 2026-09-06 on father. This is a source review plus hardware-free
experiments, not a new hardware qualification or an exhaustive concurrency
proof. No production driver source, loaded module, boot option, or wiring was
changed during this review.

Follow-up: [staged remediation plan](driver-remediation-plan.md), with patch
boundaries, acceptance gates and hardware-dependent limitations.

2026-09-06 implementation update: R1's reproduced missed-boundary cases now pass
after a saved-half continuity guard was added. The original failure was first
reproduced in a permanent test, then the guard was implemented and tested; see
[change record and remaining limits](vdone-continuity.md). No loaded module or
hardware was changed. The findings, line references, hashes and failure table
below describe the **pre-remediation review snapshot**, not today's test verdict.

## Bottom line

Batch 5 follow-up: [R5/R7 software checks and remaining restrictions](source-transition-restart-remediation.md)
documents the opt-in worker source guard, deterministic regressions and retained
non-forcing restart policy. R5 physical containment and R7 concurrent A/V
qualification are not closed. The original findings below remain the review
snapshot, not claims about the later implementation.

The current implementation has substantially stronger ownership, DMA lifetime,
error accounting, and lifecycle defenses than the monolithic baseline. It still
has a **reproduced mixed-frame delivery case in the production IRQ/worker code**.
There is also a reproduced timing-metadata inconsistency, and a high-priority
audio teardown race candidate not covered by the video-only model.

The old duplicate-toggle messages are **not explained by this review**. The
baseline also detected identical consecutive toggles and discarded partial
frames, largely silently. More observable recovery does not establish a new
hardware failure or a regression in its frequency. Conversely, passing ordinary
capture does not resolve the concrete gaps below.

Recommended order: turn finding R1 into a permanent failing regression and fix
it; resolve/test R2 and R3's error/lifetime paths; then extend the qualified
content and simultaneous A/V tests. Repeating the existing short smoke suite
alone is less informative than these targeted tests.

## Scope and exact comparison

- Current: `audio-upstream-v20-source-rewrite`, HEAD
  `4706e64bc4e6a60ed3e3049d287f79d12734d78c`, **plus the existing working tree**.
- Baseline: `upstream/baseline`,
  `1af45c8022a201b157a65cccacfb02096981cd9e`. This is the available ref, not a
  local branch named `baseline`. No checkout or baseline hardware run was made.
- Followed probe/resource setup, receiver detection, V4L2 configuration and VB2
  ownership, register programming, IRQ acknowledgement, video assembly,
  recovery, ALSA delivery, monitor/controls, debugfs, STREAMOFF, remove, and PM.
- Reviewed `src/hws_pci.c`, `hws_video.c`, `hws_irq.c`, `hws_audio.c`,
  `hws_v4l2_ioctl.c`, `hws_debugfs.c`, relevant headers/trace instrumentation,
  and corresponding paths in baseline `src/hws_video.c`.
- Inspected the existing deterministic tests and local hardware runners. This
  was not a fresh end-to-end audit of every Python evidence/clock algorithm.
- Existing uncommitted driver changes add queue/IRQ diagnostics. Inspection of
  their diff found no change to half selection or recovery decisions. Enabled
  tracing can still change execution time; disabled tracing is not a substitute
  for testing the enabled path.

Related context: [earlier targeted review](driver-baseline-test-review.md),
[deterministic test scope](deterministic-vdone-tests.md),
[cross-host calibration](cross-host-timing.md), and
[hardware runner usage](../local-tests/README.md). Earlier hardware results are
historical evidence, not tests rerun for this review. Baseline is a comparison,
not a correctness oracle.

## Findings, in priority order

### R1 — High: missed DMA boundaries can produce a successful mixed frame

**Status: reproduced through the full production IRQ and worker, in the existing
hardware model. Physical occurrence is not established.**

References: `hws_irq_record_vdone()` in `src/hws_irq.c:934`, generation increment
at `:969`, timestamp check at `:993`; `hws_video_copy_completed_half()` at `:233`,
saved-half/generation checks at `:332`, final publication at `:607`.

The driver increments generation for observed IRQs. An alternating toggle and
generation +1 do not prove that only one hardware boundary elapsed. The copy
deadline bounds time since the latest handler timestamp, not the age of the
first half already copied into the destination.

At 60 Hz: copy A's first half; allow A's second half and B's first half to be
written without running the handler; then handle B's second half. The next
observed toggle alternates and the observed generation advances by one. The
driver publishes A-first-half + B-second-half as `VB2_BUF_STATE_DONE`.

New repeatable diagnostic:

```sh
python3 tools/review_irq_gap.py
```

It compiles the current production adapter and includes the existing test's
unchanged DMA model and independent content assertion. It adds **DMA-only
advances**, not delayed worker execution. No driver body is patched. Its
intentional exit 1 means mixed content was detected, not a setup failure.

| Unobserved boundaries | Gap after first-half copy | Gap after completed frame |
| --- | --- | --- |
| 0 | PASS | PASS |
| 2 | FAIL: mixed frame | PASS |
| 4 | FAIL: mixed frame | PASS |
| 6 | FAIL: mixed frame | PASS |

All three failures reached the existing `data[i] == id` assertion in
`tools/test_hws_irq.c:87`. The control cases retain forward-progress and ownership
checks. Model: 640x480, 60 Hz, four buffers, one video channel, audio/probes off.
The second column's gaps correspond to observed intervals of roughly 25,
41.67, and 58.33 ms. No source-timing clock synchronization is involved.

The previous extracted-copy reproducer also still fails this case:
`python3 tools/review_completion_gap.py`. The full-handler result supersedes
the earlier limitation that the IRQ acceptance path had only been inspected.
The normal 4,096 schedules do not include DMA-only advances, so their PASS
does not contradict this failure.

**Baseline:** changed-toggle and half-done/sentinel pairing at baseline
`:4260` and `:4783` also lacks a reliable source-frame identity. Not proven to
be a new regression. `2d48e17` added recovery behavior for already-detected
ambiguities; it did not establish physical adjacency for changed toggles.

**Required change/test:** preserve first-half age/identity and discard ambiguous
assembly; reset that state on recovery/restart/source change. Extend tests to
all advertised modes, both phases, multiple unobserved boundaries, late handler
entry, and distinct content each refresh. Require no mixed DONE buffers,
exactly-once ownership, explicit loss/uncertainty accounting and resumed capture.
A justified cadence bound is useful, but IRQ timestamps alone cannot identify
every physical DMA frame under arbitrary latency.

### R2 — High: audio close can bypass worker synchronization during failure/removal

Follow-up: the release-order failure was reproduced in a paused-worker userspace
model, and software synchronization was remediated. See
[audio change/test record](audio-lifetime-remediation.md). The original analysis
below is retained; actual kernel lifetime/concurrency qualification remains open.

**Status: concrete source-level race candidate; not reproduced in a kernel.**

References: `src/hws_audio.c:1633` (`hws_pcie_audio_release_stream`), `:99`
(normal quiesce), `:573` (worker cancellation), `:777` (substream/runtime reads),
`:548` (deferred XRUN notification); `src/hws_pci.c:997` (stop publication).

Normal audio release stops capture, synchronizes the IRQ, and cancels delivery
work. The alternate branch for `suspended`, `pci_lost`, or `dma_quiesced` only
publishes stopped state and resets runtime bookkeeping. Those conditions do
**not all mean that delivery work has already drained**. Removal publishes
`suspended` before its later `hws_audio_drain_work()`, and runtime MMIO failure
can set `pci_lost` without draining anything.

A relevant interleaving is: worker obtains `ss->runtime`; removal sets
`suspended` (or another path sets `pci_lost`); concurrent PCM close takes the
software-only branch; close returns and runtime lifetime ends; worker resumes
and dereferences the saved runtime. The later pending/ring-lock checks occur
after the initial runtime access. Similar scrutiny is needed for the saved
substream in XRUN/period notifications. Keeping the parent `hws` alive is not
the same as keeping the ALSA runtime alive.

There is no `.sync_stop` callback or `card->sync_irq` assignment supplying an
alternative synchronization here. ALSA documents synchronization before
prepare/hw_params/hw_free and automatic managed-buffer release after hw_free.
See [ALSA stop synchronization](https://www.kernel.org/doc/html/latest/sound/kernel-api/writing-an-alsa-driver.html#sync-stop-callback)
and [managed buffers](https://www.kernel.org/doc/html/latest/sound/kernel-api/writing-an-alsa-driver.html#managed-buffer-allocation).

**Baseline:** its close is a no-op and hw_free releases pages (`:3363` and
`:3376`); it is not a safe reference design. The current software-only release
branch is from `8c967c7`; the risk is in that lifecycle implementation, not in
the latest trace-only diff.

**Required test:** synchronize a paused audio worker at runtime acquisition and
just before notification with close/hw_free plus failure/removal publication.
Use a test kernel/KASAN and real ALSA lifetime transitions; run under lockdep
as well. Close must not free worker-reachable resources before software drain,
and drain must not deadlock with ALSA locks. Separate "MMIO must not be touched"
from "software work is drained"; do not fix this by blindly synchronizing a
released/reused IRQ number. Also cover STOP→PREPARE→START without close.

### R3 — High: runtime device loss is not a complete failure transaction

**Status update 2026-09-06:** coordinated latch/cleanup and raw-toggle checks
implemented; production-code fault models, negative controls and userspace
sanitizers pass. See [R3 remediation record](device-failure-remediation.md).
Actual kernel fault/wakeup/concurrency and PCI containment remain unqualified.
The original finding below describes the reviewed pre-remediation code.

References: `src/hws_video.c:965`, `:988`, `:854`; `src/hws_irq.c:1322`;
`src/hws_audio.c:1360`; contrast `src/hws_pci.c:1436`.

An all-ones ACTIVE_STATUS read sets `pci_lost`, but `check_video_format()` skips
source-state handling for `-ENODEV`. An all-ones interrupt-status read returns
IRQ_NONE. Neither action on its own fails/wakes every active queue or drains
audio/video work. A bound but unresponsive device can therefore leave blocking
capture without a bounded error, unless another lifecycle path intervenes.

Additionally, video/audio toggle reads immediately mask with `& 1`
(`hws_irq.c:1159`, `:1183`, `:1254`, and the copy paths). They cannot distinguish
a raw `U32_MAX` read from a valid toggle 1. Include partial register failures,
not only total BAR disappearance, in fault injection.

**Baseline:** also rejects missing/all-ones device status without a coordinated
modern queue-failure path. Not established as a new hardware regression.

**Required test:** mock each MMIO loss location with pending/active buffers and
blocked DQBUF/ALSA reads; require bounded wakeup/error and one ownership return.
Then test device failure in an isolated kernel. Keep fixed arenas quarantined
until separately verified DMA isolation; all-ones MMIO is not itself an idle
proof. Coordinate this work with R2.

### R4 — Medium: frame-period APIs disagree and detection is partly inferred

**Status update 2026-09-06:** rational period/API/deadline agreement and paired
FPS detection implemented; all-mode production-code tests pass. Receiver timing
is still table-inferred, not independently measured. See the
[R4/R6 remediation record](configuration-timing-remediation.md). The original
numerical finding below describes the pre-remediation implementation.

References: `src/hws_v4l2_ioctl.c:30`, `:160`, `:621`.

```sh
python3 tools/review_timing_table.py
```

| Mode | DV timing rate | G_PARM rate |
| --- | ---: | ---: |
| 1920x1080p60 | 60.000000 | 60 |
| 720x480p | 59.940060 | 60 |
| 800x600 | 60.316541 | 60 |
| 1280x800 | 59.810326 | 60 |

Detection reconstructs pixel clock/porches from width, height, interlace and
integer FPS. It does not independently measure those detailed timings. FPS is
sampled once between paired geometry/status reads, so same-size rate changes
are not covered by the paired-read consistency check. G_PARM also silently
falls back to configured/default FPS when detection fails. This is not the
cause of the R1 failure, which reproduces at an exact modeled 60 Hz.

**Baseline:** nominal integer G_PARM reporting at `:465` is inherited. The new
DV timing API makes the internal disagreement visible. The V4L2 contract
describes returning the actual period; not advertising a writable period is
appropriate for an HDMI receiver, but does not make a returned nominal value
an exact measurement. [V4L2 G_PARM documentation](https://www.kernel.org/doc/html/v6.8/userspace-api/media/v4l/vidioc-g-parm.html).

**Required test/change:** derive a coherent rational period from valid timing
state, handle unavailable detection explicitly, and sample refresh stability.
Test every enumerated mode and 60/59.94, 30/29.97, reduced-blanking and same-size
rate transitions. If the registers cannot distinguish variants, document that
limitation instead of claiming exact receiver timing.

### R5 — High-priority hardware test: source changes can outrun polling

**Status: safety/format hypothesis requiring controlled source transitions.**

References: `src/hws_pci.c:278` (one-second monitor), `src/hws_video.c:1133`
(source invalidation), `:923` (configured geometry), and
`src/hws_v4l2_ioctl.c:506` (native-only capture).

STREAMON checks the receiver twice and detected changes stop an active queue.
Between monitor passes, a short mode loss/change/return can escape detection.
The code itself states that OUT_RES is not a proven DMA scaler. Fixed arenas
and guard pages improve protection, but guard checking detects writes after
they occurred; it does not bound what an unsupported oversized source can DMA.

**Baseline:** monitor-driven geometry changes and software conversion existed
there too; current code intentionally avoids reprogramming a live ring. Do not
restore the old live-geometry behavior as a fix.

**Required test:** distinct patterned frames across 1080p60↔720p60, same-size
rate changes, unplug/replug, and sub-second loss/return, in each worker phase.
Require source-change/error behavior, no stale-layout DONE frames, and correct
reconfiguration/restart. First model oversize writes; only test unsupported
larger inputs on an isolated host with suitable DMA containment and recovery.
Faster polling alone cannot prove containment.

### R6 — Medium: video runtime programming does not enforce its readback

**Status update 2026-09-06:** fail-open behavior reproduced in a production-code
fault model, then remediated with mandatory verification, delayed cache commit
and active-peer protection. Model, mutation and sanitizer gates pass; no such
physical fault was injected or observed. See the
[R4/R6 remediation record](configuration-timing-remediation.md). The original
finding below describes the pre-remediation implementation.

References: `src/hws_video.c:83`, especially cached state at `:130`, `:147`,
`:155`, and the `dma_window_verify` branch at `:157`. Contrast probe/resume's
`hws_seed_dma_windows()` at `:642` and audio seed checks at
`src/hws_audio.c:216`.

Runtime video programming updates cached base/remap/split and marks the window
valid before verification. With verification enabled, mismatches are only
logged; otherwise a read flush is performed and ignored. A non-sticking split
write during a mode change can therefore return success and retain a cache
that disagrees with hardware. Probe/resume and audio have stronger checks.

**Baseline:** no evidence of a reliable write-readback failure contract there;
this is a current hardening inconsistency, not proof of the observed recoveries.
Most normal steady-state streams reuse already-established mappings.

**Required test/change:** inject stale/incorrect/all-ones readbacks for each
runtime register, including a geometry change after an initial successful
stream. Reject unverified programming before VCAP enable and keep the cache
invalid on failure. Test both values of `dma_window_verify`. Preserve documented
hardware exceptions for write-only/enable-strobe registers; do not indiscriminately
require equality for every register.

### R7 — Medium: independent restart depends on observing card-wide idle

**Status: availability risk, not evidence of unsafe arena reclamation.**

References: `src/hws_pci.c:1494`, `src/hws_video.c:889`,
`src/hws_audio.c:584`.

STREAMOFF retains the permanent arena; restart/reprepare tries to observe the
global BUSY bit clear, for up to 100 ms. Other active channels can prevent this
observation, producing EBUSY even though the target stream was stopped. The
conservative refusal is preferable to reusing memory without a quiescence
boundary; whether it harms real concurrent operation remains untested here.

**Baseline:** different global lifetime/busy handling; not an independence
guarantee. The per-stream quarantine design is newer.

**Required test:** continuously validate content on one or more channels while
another repeatedly performs STREAMOFF/ON and audio STOP/PREPARE/START. Include
audio and video on the same remap slot, then all channels. Record busy-poll
durations, bounded retry behavior, peer losses and guards. Do not remove the
idle requirement simply to make the restart succeed.

### R8 — Medium: the advertised hardware/feature contract needs narrowing or tests

**Status: observable support differences; hardware compatibility unresolved.**

References: `src/hws_pci.c:76`, `:125`, `src/hws_video.c:1102`, `:1693`,
`src/hws_v4l2_ioctl.c:30`, and `src/hws_audio.c:136`.

The PCI table still binds generations with `hw_ver == 0`, but their software
VDONE-rate accumulator from baseline `:5196` is now a no-op. Modern detection
requires a hardware FPS value. Native progressive YUYV/MMAP-only capture also
replaces baseline software scaling/conversion/interlace paths and READ/USERPTR
advertisement (`:2084`, `:2966`, `:3247`). ALSA is still stereo S16_LE/48 kHz,
but packet-sized period/buffer constraints replace the baseline's looser ones.

These restrictions can be deliberate correctness improvements, not accidental
regressions. They nevertheless need a documented support contract and tests
that unsupported operations are rejected cleanly. Current-mode success on one
0x8504 board does not qualify every PCI ID, legacy firmware, or input format.

## Baseline/current architectural differences worth testing

| Path | Baseline | Current | Main test implication |
| --- | --- | --- | --- |
| VDONE identity | Pre-ack toggle, half-done flag, in-ring sentinel | Stable post-ack samples, phase/generation/deadline checks | R1; separate acknowledgement-race tests |
| IRQ handling | Up to 100 drain iterations; busy tasklets skip events | One status snapshot/ack; independent channel workers | Test reassertion and pending causes with real MSI and INTx |
| Duplicate toggle | Clears partial-half state, no equivalent detailed accounting | Recycles destination, counts recovery, resumes | Compare semantics, not warning counts |
| Video memory | DMA ring plus staging/conversion queues | Permanent guarded DMA arena, CPU copy into VB2 | Target actual arena for DMA-lifetime tests |
| A/V remap | Per-channel register programming in monolith | Shared fixed per-channel arena and serialized remap | Simultaneous A/V start/stop and peer independence |
| Error/lifecycle | Ad hoc cleanup; no comparable PM transaction | Refcounted users, quarantined DMA, checked isolation and staged resume | R2/R3; injected failure at every transition stage |
| Receiver/API | Nominal rates, software transformations | Configured/detected timing split, native packed layout | R4/R5/R8; V4L2 compatibility and mode matrix |

The current IRQ handler records audio before video after acknowledgement
(`hws_irq.c:1339`). Active audio and other channels can widen the time between
the status snapshot and a particular video toggle sample. The existing harness
does not run this path with active audio. Test it with controlled boundaries;
do not infer it caused historical losses without matching evidence.

## What to test next, and how

### Hardware-free, highest immediate value

1. Make R1's new reproducer a permanent regression in the production-code suite
   when fixing pairing. Extend the hardware model with withheld/coalesced IRQs
   and parameterized native splits; do not replace the independent content
   oracle with driver counters.
2. Add an audio production-code adapter: packet content continuity, startup
   prime, duplicate/cadence/deadline/overlap failures, ring wrap and notification
   accounting. Add synchronized lifetime tests for R2, not just boolean stops.
3. Fault-inject MMIO/readback, DMA allocation, IRQ request, each node registration,
   and each resume step. Check error unwinding, stop/wakeup, no BME/VCAP/ACAP
   enable before setup, retained arenas when isolation fails, and balanced refs.
4. Test V4L2 table/TRY/G/S_FMT/G_PARM consistency for all 14 timing entries;
   malformed sizes/types, CREATE_BUFS, short planes, busy configuration,
   absent/unsupported signals. The current raster self-test covers 13 sizes,
   not the entire driver ioctl implementation.

No second host, NVIDIA setting, or driver reload is needed for these tests.

### Existing physical tests that remain useful

These commands are **instructions, not hardware tests run during this review**.
Verify device/channel mapping and loaded srcversion first. NVIDIA scripts are
specific to father's TITAN HDMI→video3 and temporarily take over the display.

```sh
bash local-tests/hws-test-all.sh --quick --with-pattern
bash local-tests/hws-test-all.sh --test-starvation --require-vblank-off
bash local-tests/hws-test-all.sh --compare-drops --require-vblank-off
```

Preserve full pixel/poison checks, queue evidence and each sealed comparison.
Use 16 buffers for low-starvation content runs; keep the 4-buffer injected-delay
case as a positive control. Distinguish queue starvation, orphan halves after
recovery, normal drain-tail behavior and source-held IDs. IRQ handler-entry
timestamps do not measure physical assertion-to-entry latency. The irqsoff
variant remains unavailable on the tested kernel and is not worth rerunning
unchanged just to obtain another SKIP.

Use the laptop/video2 procedure in [cross-host timing](cross-host-timing.md)
for timestamp association and independent presentation evidence. Its documented
1,000-frame run supports the tested half mapping; its approximately 30 distinct
IDs/s at a 60 Hz refresh is not a per-refresh loss oracle. Improve source update
throughput before making per-refresh loss claims, qualify the whole clock
interval, and keep dirty-provenance failures distinct from content passes.

For duplicates, retain raw pre/post toggle, status-after-ack, event intervals,
nearby copied IDs and IRQ/scheduler traces with loss counts. Compare audio
off/on, one/all channels, and minimal/full probes separately. MSI/INTx changes
require a separately authorized module reload and recorded loaded parameters;
do not silently change them in a test. Persistent stable duplicates with no
copy overlap/deadline miss still do not distinguish lost interrupts from
hardware-toggle behavior.

### Lifecycle/DMA tests need different instrumentation, not just longer capture

- **STREAMOFF and close:** pause the real worker at queue take, mid-copy, and
  just before publication; issue stop/close concurrently. Require exactly-once
  completion and no CPU writes into returned VB2 buffers. Test multiple FDs,
  poll/DQBUF waiters, exported buffers, and late close after disconnect.
- **Important canary correction:** `hws_dma_canary_test.c` poisons mapped V4L2
  buffers (`:960`), but current hardware DMA targets the private scratch arena,
  not those buffers. Restoring its missing SYS_STATUS ioctl alone will not
  prove that private-ring DMA stopped. A changed VB2 canary could also be a late
  software copy, not necessarily DMA. Test VB2 ownership separately from the
  actual DMA target.
- **Actual DMA lifetime:** keep the permanent arena allocated; record capture
  disable and the verified idle/isolation boundary; observe arena writes around
  that boundary with appropriate cache ordering and guard coverage. STREAMOFF
  deliberately permits quarantined in-flight arena DMA until later idle proof.
  The critical invariant is no reuse/free before quiescence, and no writes after
  the claimed quiescence boundary—not "all hardware writes cease instantly at
  STREAMOFF return."
- **Remove, unbind, suspend/resume, shutdown:** isolated host/card-wide consent,
  first idle, then video, audio, simultaneous A/V, and open FDs retained across
  removal. Inject mask/readback/idle failures and test resume rollback. Add
  KASAN, lockdep and separately KCSAN runs; inspect all kernel reports and
  external timeout/recovery behavior. The existing shell race hooks are absent
  and the unbind harness still needs review; do not count those SKIPs as passes.
- **Diagnostic interfaces:** read config/stats concurrently with format changes,
  suspend and unbind; retain an open debugfs FD across removal. Stats are locked,
  but config collects multiple READ_ONCE fields without a single state snapshot
  (`hws_debugfs.c:118`). It can describe mixed epochs; do not treat that alone
  as register corruption. Check trace caps/loss, no leaked addresses, and
  instrumentation-on overhead with multiple active channels.
- **Color and audio:** use characterized colored patches and levels, not only
  black/white IDs, to test the explicit full-range BT.601 matrix at SD and HD.
  Use known stereo sample sequences/tones at 48 kHz for channel order, exact
  packet continuity and A/V drift; silent or zero-filled audio is a weak oracle.

## Tests actually run for this review

| Command | Result and interpretation |
| --- | --- |
| `make -C src W=1` | PASS; all seven driver translation units rebuilt for 7.1.9-arch1-2, no emitted compiler warnings; no install/reload |
| `make -C tools check-irq` | PASS; existing modeled cases and 4,096 schedules |
| `make -C tools check-irq-mutations` | PASS; one unittest detects three deliberate temporary code mutations |
| `make -C tools check-irq-sanitize` | PASS outside sandbox with ASan/UBSan and leak detection; initial sandbox run stopped on LeakSanitizer/ptrace restriction |
| `make -C tools check` | IRQ, DRM-analysis, raster/decoder and 92 VDONE tests passed; localhost UDP clock test blocked in sandbox |
| `python3 -m unittest discover -s tools -p 'test_clock*.py' -v` | All 16 PASS outside sandbox, resolving the environment-only failure above |
| `python3 -m unittest discover -s local-tests -p 'test_hws_test_runner.py' -v` | 28 PASS |
| `python3 tools/review_completion_gap.py` | Reproduced mixed-frame acceptance; adjacent, visible-generation-gap and deadline controls behave as documented |
| `python3 tools/review_irq_gap.py` | Exit 1: three full-handler mixed-frame failures, five controls pass, zero unexpected errors |
| `python3 tools/review_timing_table.py` | Reproduced fractional/DMT rate disagreements using actual production functions/table |

No new hardware streams, source transitions, module reloads, unbind, suspend,
post-stop DMA test, physical IRQ-latency measurement, or baseline execution
were performed. Sanitizers here apply to the userspace IRQ model, not the
running kernel. The earlier review's in-progress sanitizer limitation is now
resolved; its other hardware/concurrency limits remain.

## Source fingerprint

Working-tree SHA-256 values at review time; line references above refer to these
files, not necessarily future edits:

```text
379a1b3830d4e0ca267e1ce1537fead8111322816d113e9f6880140d2d30cc9c  src/hws.h
1fbd1333bf98410a269eda758bc4762b65948a69bc45388dd3f0ef1901d97cdc  src/hws_pci.c
c0b148bf44e15bcc2386cb9fe9e9ade88802e7c281005a1ad931e6301314f07f  src/hws_irq.c
4d034d6f3ffac0829b8dd970482ebfb0329c245ff6a91080638ccfa0e1392c45  src/hws_video.c
efc4ece0b63a2fde2b0469d924a4b5b2565079d3e80a827b3e5a2984a6c7a1c3  src/hws_v4l2_ioctl.c
4adabf37daa6baf4e5aef8f10ca54719a4edbebab0c575d4fc604bdad52d2b2e  src/hws_audio.c
b3419faf9f058199f1e4e967cf192eec948f6de6cf7718c0a7aed90cfc9deebd  src/hws_reg.h
1dc86593b4110220838772037e71c88e743eb9b897938f2d881d94f608103b2f  src/hws_debugfs.c
3bf11fe198baa8f0d527f7a1caa22c330be765eb74ed9f9c118bccabc3eb8ebc  src/hws_trace.h
3c543c3e1c328f90bea33cc05ca5decfb0c1aa00c77b1228ceeeb9e368f4416b  src/hws_diag.h
```
