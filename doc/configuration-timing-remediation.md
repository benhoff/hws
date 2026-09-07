# DMA configuration and timing remediation (R6, R4)

2026-09-06: batch 4's code and hardware-free regression slice. No module reload,
display takeover, PM cycle, unbind or hardware fault injection was performed.
Normal hardware regression and concurrent-stream/PM qualification remain open.

## Before changing the code

The new test compiled the actual runtime video programming function, with
dropped writes and stale/corrupt/all-ones readbacks. The original implementation
failed the assertion that bad programming returns an error: it returned success.

`python3 tools/review_timing_table.py` independently exercised actual G_PARM
against the advertised DV table and a mocked receiver. Examples before the fix:
720x480 reported 60 instead of 59.940059940 Hz; 800x600 reported 60 instead of
60.316541208 Hz; 1280x800 reported 60 instead of 59.810326056 Hz.
These are software reproductions, not observed physical register faults or an
explanation of the historical duplicate-toggle recoveries.

## R6: verified programming before cache publication and capture

`src/hws_dma_config.h` supplies one transaction for the known-readable DMA
remap/base/split registers. Runtime video, probe/resume video seeding and audio
seeding use it. Channel IRQ lock serializes shared-slot users; capture lock
serializes the capture-status checks and programming against enable/disable.
Neither lock is held across a sleep or worker drain in this helper.

- The target producer must be off in hardware. Runtime video additionally
  requires stopped software state and its existing DMA-idle/reclaim boundary.
  A live producer is not reprogrammed. Probe/resume retains its globally
  quiesced lifecycle prerequisite.
- If the same channel's audio/video peer is active, read and verify the common
  remap slot without writing it. A conflict fails without rewriting that peer's
  mapping, even if the software cache says the page is right. Other channel
  base/split registers and capture bits are not rewritten by this transaction.
- When the peer is inactive, write and read back the remap. Then program and
  verify the target base and (video only) native split. Ordered reads flush
  writes. A mismatch returns `-EIO`; all-ones reads return `-ENODEV` through
  batch 3's device-failure latch. No retry, arena free or idle claim is added.
- Runtime video invalidates the old cache before a stopped transaction and
  publishes address/split/extent and `window_valid` only after all checks pass.
  Even an unchanged cached window is revalidated. VCAP enable also rejects an
  invalid window, and STREAMON propagates a failed programming result.
- `dma_window_verify` is retained as a compatibility option; both values
  enforce the same checks without successful-window logging. Known non-readable/
  strobe exceptions elsewhere are
  not converted into equality checks. In particular, idle audio DMA base may
  read zero during probe/resume; only that zero exception is accepted, and an
  audio stream start still requires the exact base. Unexpected nonzero idle
  audio readback is now rejected rather than accepted without comparison.

Readback proves the sampled register values, not permanent hardware behavior or
DMA containment. Capture-status reads, fixed-arena/shared-page assumptions and
peer behavior must still be validated on hardware. No relaxed global-idle or
scratch-quarantine rule was introduced to make peer restart more available.

## R4: coherent rational periods and explicit unavailable-source errors

`src/hws_timing.h` computes a reduced progressive frame-period fraction from
total horizontal pixels × total lines / pixel clock. Wide additions, bounded
totals, and reduced numerator/denominator range checks prevent overflow or
truncation into the V4L2 fraction. Invalid/interlaced/zero-clock inputs fail.

- G_PARM derives its period from the same inferred mode as QUERY_DV_TIMINGS.
  It no longer rounds fractional/DMT rates or returns configured/default 60 fps
  after detection fails. Its capability remains read-only.
- Receiver detection now brackets paired geometry/status samples with two FPS
  samples too. A same-size rate change between those samples is not stable.
- Configured G_DV_TIMINGS/S_DV_TIMINGS state stays separate from detected source
  state. Queries do not alter the capture geometry. Existing busy-queue timing
  restrictions and native packed YUYV split/layout are retained.
- IRQ copy deadlines and partial-frame continuity now derive their half-period
  from the same configured rational timings. The integer `current_fps` remains
  a nominal diagnostic label, not the deadline's timing authority. An invalid
  timing can therefore reject a copy at its deadline check before reaching the
  continuity check; the regression still requires no successful delivery.
- Debugfs config holds the video state mutex across its timing/layout snapshot.
  It retains the evidence ABI's `refresh_num=pixelclock` and
  `refresh_den=htotal*vtotal` fields, and adds reduced `frame_period_num/den`,
  `timing_status`, and a timing-basis label. This is configuration serialization,
  not a claim that all runtime counters/MMIO are one atomic hardware snapshot.

G_PARM source-result policy (no fallback period on error):

| Receiver state | Result |
| --- | --- |
| Stable supported mode | Reduced fraction of inferred table timing |
| No signal | `-ENOLINK` |
| Geometry/interlace/FPS changes between samples | `-ENOLCK` (or `-ENOLINK` if signal disappears) |
| Stable unsupported mode | `-ERANGE` |
| Device/MMIO lost | `-ENODEV` |
| Suspended | `-EBUSY` |

**Precision limitation:** the receiver exposes geometry/interlace and integer
FPS, not independently measured porches or pixel clock. 1080p60 versus 59.94,
30 versus 29.97, and alternative blanking with the same reported dimensions/rate
may be indistinguishable. The existing mode table remains an inference; this
patch makes APIs mathematically consistent with it, not exact source-clock
measurements. Unadvertised fractional/reduced-blanking variants are not added
to S_DV_TIMINGS. Independent presentation/clock qualification is still required.
Transitions that change and return between samples remain batch 5 work.

## Tests and results

```sh
make -C tools check-config
make -C tools check-config-sanitize
python3 tools/review_timing_table.py
make -C tools check check-irq-mutations
make -C tools check-irq-sanitize check-audio-sanitize check-failure-sanitize
make -C src W=1
python3 -m unittest discover -s local-tests -p test_hws_test_runner.py -v
```

`check-config` is included in `tools check`. Its adapters compile current
production functions and the real timing table/layout helpers; MMIO, locks,
device/queue containers and V4L2 matching are modeled. They do not execute real
kernel locking, VB2, ALSA, DMA or blocked userspace calls.

- 48 video register faults: four fields × three fault kinds × initial or
  1080p→720p reconfiguration × diagnostics on/off. Errors leave the cache
  uncommitted/invalid and cannot arm VCAP.
- Active-target rejection; no shared-slot writes in either direction with an
  active peer; conflict leaves peer mapping/capture untouched; all-ones capture
  status; documented idle-audio base exception versus strict stream start.
- All 14 advertised timing modes: exact cross-multiplied fractions, reduction,
  configured/detected separation, unchanged layout, busy-queue rejection and
  unchanged metadata on configuration error. Source loss, unsupported rate,
  paired FPS/geometry/interlace changes, irrelevant other-channel bits, MMIO
  loss, invalid clock/type/interlace and overflow cases are checked. Fractional
  arithmetic is tested separately from advertising an unsupported mode.
- Four negative controls remove readback equality, shared-peer protection,
  rational period reporting or paired-FPS checking. Each must fail its test.
  Caller wiring and debugfs state-lock placement are checked separately.
- Configuration ASan/UBSan, existing IRQ/audio/failure sanitizer suites, full
  tools regressions, IRQ mutations, 29 runner regressions, warning-enabled
  module build and whitespace check pass. LeakSanitizer requires running these
  userspace tests outside the ptrace sandbox; this is not kernel KASAN.
- The timing review now reports zero mathematical disagreement (within printed
  floating-point rounding) for every advertised mode. The tests use exact
  integer equality, not a floating-point tolerance.

Each model subprocess has a 30-second timeout; no kernel latency guarantee is
inferred from that timeout. Early adapter/build errors during implementation
were corrected before final validation; only final clean gates count as passes.

Final on-disk build (dirty worktree based on
`4706e64bc4e6a60ed3e3049d287f79d12734d78c`): module srcversion
`404708B32522E007470D448`; `src/HwsCapture.ko` SHA-256
`3ddedfb2ae98c2bd1cc193a99f1784b90e0fe578b7a6864049619526484ed246`.
This identifies a build, not the loaded module or a hardware qualification run.

## Remaining hardware gate

After an explicitly authorized reload and loaded-build identity check, run the
short native content/lifecycle test, then independently exercise audio and
video restarts with an active peer, and probe/PM restoration. Preserve register
readbacks and refuse to relax checks just because a hardware variant rejects
them. Any additional readback exception needs documented register semantics
and a safe stream-start proof. Test fractional/DMT sources and API error cases
with controlled input; use independent timing evidence where exactness matters.

The previous `all-tests.frCQWG` run predates these changes: it is useful batch-3
normal-operation evidence, not hardware validation of batch 4. Kernel races,
post-stop DMA, source-transition containment and the support matrix remain open.
