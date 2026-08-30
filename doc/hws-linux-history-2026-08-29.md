# HWS and Linux upstream history through v19, with v20 DMA-safety progress

Status date: 2026-08-30

This document reconstructs the HWS driver and Linux upstream work from the
Codex session history, the standalone HWS Git repository, and the Linux Git
repository. It distinguishes implementation, software validation, hardware
validation, submission preparation, actual submission, and reviewer feedback.

## Executive conclusion

Version 19 is a coherent, software-validated eight-patch series, but it is not
safe to submit in its current form. Hardware diagnostics performed on
2026-08-23 and 2026-08-24 disproved assumptions used by its video bounce-buffer
architecture:

- W1C VDONE status coalesces multiple capture phases and is not an event
  counter.
- A proposed fixed full-frame A/B bank arrangement did not alternate banks.
- DMA wrote 2,048 bytes beyond the nominal 1920x1080 YUYV `sizeimage`, through
  the page-rounded extent.
- The native half-ring was viable for channel 3 at 1920x1080p60, with a fixed
  DMA base and CPU copies of proved-complete halves. That architecture is now
  integrated on the `audio-upstream-v20-dma-safety` successor branch. Its
  targeted channel-3/1080p60 E2E matrix passed. At commit `fe6aabc`, the audio
  DMA boundary, interlaced-format, DV-timings API, and native-format findings
  below are code-resolved, with targeted hardware evidence where noted. The
  commit `e848e0e` also resolves the per-stream/global-idle coupling in code,
  with hardware validation pending. The working tree after `e848e0e` resolves
  the PCIe ordering and lifecycle-sequencing findings in code. The over-broad
  hardware scope and the remaining API, telemetry, and coverage findings below
  still prevent submission.

The August findings therefore require a production successor to v19. They are
not merely optional follow-on architecture work. The lifecycle, quiescing,
resume, IRQ, and audio changes in v19 remain useful foundations.

## Evidence and method

The history assessment used a fixed query matrix against three indexed project
identities:

- Main HWS history: 131 sessions
- Split/new-directory HWS history: 4 sessions
- Linux history: 28 sessions

The matrix contained 85 searches covering:

- Status intent: latest next step, unresolved issues, and resolved issues
- HWS evidence: VDONE, W1C, half ring, live DMA base, remap window, STREAMOFF,
  unbind, DMA idle, bounce, XRUN, colorimetry, sharpness, and frame drops
- Linux/submission evidence: v19, checkpatch, base-commit, mailbox,
  `git send-email`, Hans Verkuil, review, submitted, hardware validation, and
  media-next
- Repeated searches for `my-laptop` and `princess`, constrained to June through
  August 2026

Generic intent searches used relaxed lexical matching and included repeated or
resumed investigations. Conclusions were therefore based on technical-term
results, surrounding conversation turns, Git history, generated mailboxes, and
validation documents. Standalone HWS and Linux commits were matched by patch
subject and series order rather than SHA.

## Repository state on 2026-08-29

### Standalone HWS repository

`audio-upstream-v19` is at `8caff97d8dc1062bff3e23ce88d7d808036a5c56`
and matches `origin/audio-upstream-v19`.

The dangerous diagnostic branch is:

`test/DANGEROUS-dma-hardware-diagnostics-DO-NOT-USE-IN-PRODUCTION`

At the start of this assessment, its local tip was
`072aa15eaab39aa4794f7331155e89372ac37903`, five commits ahead of its
remote-tracking branch:

1. `5ad7521` - validate the half-ring DMA safety boundary
2. `d74bb52` - prove VDONE semantics across DMA splits
3. `5fa787a` - accept barcode proof of half mapping
4. `6658102` - distinguish source repetition from DMA gaps
5. `072aa15` - preserve the split-dependent VDONE evidence and findings

These diagnostic commits are evidence and experimental machinery. The branch
must not be used as a production driver. On 2026-08-29, the exact branch was
pushed to `origin`, preserving all five commits and their committed evidence.

### Linux repository

The Linux port is on branch `hws-v19` at
`c147bdcec325`, based on `06cb687a5132`. The currently checked-out Linux branch
was `next`, not `hws-v19`; its divergence from `origin/next` is unrelated to
the HWS series and should not be used to judge v19 state.

The generated v19 artifacts included:

- `/home/hoff/swdev/linux/hws-audio-upstream-19.patch`
- `/home/hoff/swdev/linux/hws-patch-series-changes.md`
- `/home/hoff/swdev/linux/hws-v19-description.txt`

The last two files and submission/dry-run helpers were untracked at assessment
time and must not be deleted without review.

## v19 patch mapping

The standalone and Linux SHAs differ because the repositories have different
paths and trees. The logical series is identical by subject and order.

| Order | Standalone HWS | Linux | Work |
| ---: | --- | --- | --- |
| 1 | `79b9a96` | `f7cd4fca922d` | Quiesce interrupts without disabling the shared IRQ |
| 2 | `41fba88` | `fc78537d4fd0` | Serialize video quiesce with queue state |
| 3 | `d3548ea` | `040f2b15cc32` | Wait for DMA idle before releasing buffers |
| 4 | `133c96c` | `0b6f22e44aa7` | Preserve software state across resume |
| 5 | `15a408d` | `d1495168ed66` | Program video DMA through remap windows |
| 6 | `2f9c0c` | `9733299d0285` | Add the shared scratch DMA arena |
| 7 | `3ced02f` | `00677830ee45` | Add the video bounce path |
| 8 | `8caff97` | `c147bdcec325` | Add embedded audio capture |

## Chronological history

### 2026-06-20 through 2026-06-26: core implementation

Work concentrated on video DMA and remap-window handling, scratch arenas,
bounce buffers, embedded audio, staged audio/video capture, VB2 ownership,
audio workqueue delivery, error unwinding, and device lifecycle paths. Repeated
readiness reviews found and corrected buffer-ownership, teardown, publication,
and failure-path problems.

### 2026-06-27 through 2026-06-29: first upstream attempt

A five-patch series, cover letter, validation notes, and send scripts were
prepared. The first send was malformed because the helper sent the combined
mailbox as one cover email. Hans Verkuil requested a repost. The helper was
changed to use `git mailsplit`, and media CI subsequently reported missing
Signed-off-by lines and style issues. Those issues were corrected in another
revision.

### 2026-07-16: confirmed human review

A corrected five-patch revision reached human review. Hans commented that the
`hws_seed_all_channels` helper was redundant or obsolete. The initialization
was subsequently centralized through `hws_init_video_sys` and incorporated
into the rewritten series. This proves that an earlier five-patch version was
submitted and reviewed; it does not prove that v19 was submitted.

### 2026-08-01: device-information patch

A separate device-information mask patch and send script were prepared and
dry-run. The reviewed evidence does not establish that the email was sent.

### 2026-08-03 through 2026-08-04: rewrite through v19

The series advanced rapidly through v4-v19. Material changes included:

- A read-only `enable_audio` control
- ALSA BATCH behavior and `snd_pcm_stop_xrun`
- Standalone resume lifecycle correction
- Stream-on buffer cleanup
- Atomic remap locking and recovery lock-order corrections
- Direct DMA limited to appropriate buffers, with MMAP bounce handling
- IRQ-side capture of buffer, cookie, slot, toggle, and timestamp state
- Fail-closed handling when completion ownership became unclear
- A single scratch allocation with boundary validation
- Shared-IRQ and PM queue serialization fixes
- DMA-idle and PCI-isolation prerequisites
- PCI-loss recovery
- Audio `IDLE`, `PENDING`, `COPYING`, and `XRUN` states
- Alternating embedded-audio DMA toggle handling

The resulting eight patches were synchronized into the standalone HWS branch
and Linux `hws-v19`. Final review identified a blocker: the two-slot video
bounce design relied on unproved DMA-base latching and reliable-enough VDONE
identity. Work moved to a deliberately dangerous hardware-diagnostic branch.

### 2026-08-06 through 2026-08-07: colorimetry

Hardware pixel measurements at 1080p indicated a BT.601 matrix and full range,
while the advertised metadata implied BT.709 defaults. A metadata correction
was implemented, built, checked, and prepared for sending. The reviewed
evidence does not establish an actual send. The apparent sharpness change was
a color-decoding perception, not a spatial-resolution change.

### 2026-08-09 through 2026-08-10: STREAMOFF/VDONE race

The first test appeared to pass because its log collection was broken. After
the collection was repaired, the pre-fix driver produced 47 ownership
warnings. With the targeted fix applied, 500 attempts using a widened 250 ms
race window produced no warnings. This validates the targeted race fix, not
the complete v19 DMA architecture.

### 2026-08-11: unbind testing

The minimal open-file-descriptor/no-buffer unbind case completed without
warnings. Attempts to exercise `REQBUFS`, mmap, QBUF, STREAMON, and active
unbind were undermined by correctness problems in the test harness and were
eventually canceled. Strong active-stream remove/unbind validation remains
outstanding.

### 2026-08-23 through 2026-08-24: decisive DMA diagnostics

Testing on device `8888:8504`, channel 3, at 1920x1080p60 established:

- One sticky W1C VDONE bit covered 38 subsequent observed toggle transitions.
- Clearing VCAP produced no later sampled memory changes. Busy first read clear
  approximately 16 us later, and the idle/stable proof completed after about
  50.163 ms.
- A fixed full-frame A/B layout failed across 32 events: bank A was rewritten,
  bank B remained untouched, and the toggle did not change.
- The native half-ring mapped toggle 0 to hardware writing half 0 and toggle 1
  to hardware writing half 1. The completed half is `toggle ^ 1`.
- All 29 immediate half copies verified. Minimum observed source reuse was
  about 7,950 us; maximum copy time was about 531 us.
- Injected loads through 5 ms were accepted. Loads of 7.2, 7.6, and 8.5 ms were
  suppressed, with no modeled bad delivery.
- VDONE cadence was split-dependent: a 2,072,576-byte native split produced one
  VDONE per half; the 2,073,600-byte production split produced one per full
  frame.
- At nominal `sizeimage` 4,147,200 bytes, DMA changed another 2,048 bytes,
  through page-aligned extent 4,149,248.

These results select a viable production direction for the tested scope but do
not validate the current v19 bounce path or establish the same behavior across
other channels and modes. The complete preserved evidence and requirements
are in `doc/dma-safety-findings.md` on the dangerous diagnostic branch.

## v20 DMA-safety implementation status

On 2026-08-29, the production successor work on
`audio-upstream-v20-dma-safety` replaced the v19 live-base/two-slot video path
with a permanent private native half-ring per channel. The implementation is
source-complete for this architectural step, passes software checks, and has
now received partial channel-3/1080p60 hardware validation as detailed below.
The fixed-ring architectural step is preserved as commit `f265440`.

The implemented invariants are:

- Every active channel receives one coherent arena at probe. Its video layout
  is a leading guard page, a `PAGE_ALIGN(MAX_VIDEO_SCALER_SIZE)` ring, and a
  trailing guard page; any audio scratch follows that protected region in the
  same remap page. The arena remains allocated until PCI teardown.
- A stream uses `PAGE_ALIGN(sizeimage)` as its hardware-owned extent, so the
  1920x1080 YUYV allocation includes the observed 2,048-byte DMA tail. Only
  `sizeimage` bytes are copied to userspace. A guard page beginning at the
  active extent is poisoned before capture and verified after each half copy
  and at STREAMOFF.
- The DMA base, remap entry, and native 2,048-byte-aligned split are programmed
  before VCAP is enabled. The programming helper rejects any live retargeting.
- Video DMA always targets the permanent ring. VB2 buffers are CPU-mapped MMAP
  buffers and their addresses are never written to the video DMA registers.
- The hard IRQ samples the video toggle before acknowledging W1C, acknowledges
  and reads back interrupt status, then requires two matching post-ACK toggle
  reads. The stable post-ACK value supplies the completion identity. A
  reasserted VDONE bit, unstable post-ACK sample, pending/copying event,
  duplicate toggle, non-monotonic timestamp, or event interval outside
  two-thirds through three-halves of the expected native-half period is
  classified as ambiguity and stops capture.
- The first eight clean boundaries after every start or recovery are
  synchronization events and are never copied. During that empty acquisition
  phase only, a duplicate or out-of-cadence boundary restarts synchronization;
  four consecutive restarts are allowed before the queue fails closed. Once
  synchronization completes, every ambiguity remains fatal. Steady-state
  processing explicitly expects half 0 and half 1 in order and requires
  consecutive event and frame generations.
- After W1C acknowledgment and stable identity selection, the hard handler
  records each channel's completion and queues an independent high-priority
  unbound worker per channel. Each worker treats `toggle ^ 1` as the completed
  half, checks the live toggle before, during, and after each copy, compares
  the destination with the stable source, and assembles half 0 and half 1 into
  one VB2 buffer. It detaches that buffer only after a final state, generation,
  and deadline check under the IRQ lock.
- The characterized IRQ-to-verified-copy limit is 7,500 us with 500 us reserved
  before nominal source reuse. Faster modes automatically receive a tighter
  deadline based on their half period.
- An orphan half 1 is dropped. A missing destination at half 0 drops the whole
  frame. A pending copy, duplicate toggle, half-order mismatch, destination
  mapping/size error, or guard failure stops capture and fails the queue
  instead of delivering an ambiguous buffer.
- STREAMOFF disables VCAP, synchronizes the hard IRQ, drains the channel worker,
  retains the permanent arena until teardown, and checks the active extent
  guard after the existing DMA-idle barrier. Remove and device-wide shutdown
  drain every channel worker before unregistering queues or freeing the shared
  workqueue. A persistent `dma_needs_idle` bit ensures an error path cannot
  avoid that proof by clearing `cap_active` early. Guard corruption is sticky
  and prevents a later STREAMON from reusing the channel arena.

The first complete v20 E2E run on channel 3 at 1080p60 passed normal capture,
packed-format negotiation, MMAP-only enforcement, rapid STREAMON/OFF, forced
INTx ambiguity injection, recovery, and the complete audio staging telemetry
check. CPU-stressed and concurrent video each failed closed after a correctly
timed VDONE sampled the previous toggle before W1C. Both incidents had zero
deadline misses, copy mismatches, and guard errors.

After stable post-W1C toggle selection was added, the 2026-08-29 21:59 E2E run
passed CPU-stressed capture and concurrent channel-3 video/audio capture. Its
only ordinary-path failure was rapid STREAMON/OFF iteration 8: generation 6
reported a stable duplicate toggle at an otherwise correct 8,662-us cadence,
about 50 ms into acquisition. No source resample, unstable toggle, deadline
miss, copy mismatch, or guard error occurred. The extended eight-event,
bounded startup resynchronization above addresses that acquisition-only case
and awaited an E2E rerun. Forced-INTx coalescing still failed closed with
`EIO`, and the module restored MSI capture successfully afterward. Evidence is
in `/tmp/hws-v20-e2e-20260829-215902` on the validation host.

The 2026-08-29 22:04 rerun passed all 20 checks with zero failures or skips.
It exercised normal 120-frame capture, packed-format and MMAP-only enforcement,
240 frames under eight CPU workers, 40 rapid STREAMON/OFF cycles, concurrent
channel-3 video and embedded audio with a live HDMI tone, forced-INTx W1C
coalescing with userspace `EIO`, and restoration to MSI with a successful
30-frame recovery capture. No ordinary-path kernel safety signature appeared.
The exact module had SHA-256
`7f601d78cceda9e071840aaf4ad42eafee71926e85cea5d526f8a4cf73f0e231`
and srcversion `89120688711938057BDF4E0`; evidence is in
`/tmp/hws-v20-e2e-20260829-220426`. No startup-resync message occurred, so the
eight-event quiet acquisition window was exercised but the bounded recovery
branch was not forced in this run.

The module builds against Arch kernel `7.1.9-arch1-2`, `git diff --check` is
clean, and Linux `checkpatch.pl` reports zero errors and zero warnings for the
change. The deadline, W1C ambiguity, phase, generation, and fail-closed step is
implemented and targeted hardware-checked. Broader hardware validation remains
outstanding, but the code-value assessment below identifies blockers that must
be resolved before broader testing alone could make v20 submission-ready.

## Validation matrix

| Area | Status | Evidence or gap |
| --- | --- | --- |
| Combined v19 mailbox application | Passed | Applies to its declared base in an isolated worktree and reproduces the expected tree |
| Per-commit software build | Passed | Every patch boundary built with `W=1` and relevant configurations |
| Checkpatch | Passed with one generic warning | Patches 1-7 clean; patch 8 has only the generic new-file/MAINTAINERS warning |
| Whitespace | Passed | `git diff --check` clean |
| Exact v19 hardware capture | Not performed | Earlier capture results cannot be attributed to the exact final v19 tree |
| STREAMOFF race | Passed for the targeted fix | 500 post-fix attempts with no ownership warning |
| Remove/unbind | Partial | Minimal open-FD case only; active streaming case remains unproved |
| Colorimetry | Measured correction passed; cache fix software-validated | Measurements support BT.601/full-range metadata. All configured geometry paths now refresh the four cached colorimetry fields; post-fix hardware regression remains pending |
| Native half-ring diagnostic | Passed for characterized scope | Strong channel 3/1080p60 diagnostic evidence; not generalized |
| v20 fixed half-ring implementation | Targeted hardware pass | The exact module passed normal, CPU-stressed, 40-cycle rapid STREAMON/OFF, concurrent A/V, forced ambiguity, and recovery checks on channel 3 at 1080p60 |
| v20 ambiguity/deadline gate | Targeted hardware pass | Stable post-W1C sampling and the eight-event startup window passed; forced-INTx ambiguity failed closed and recovered. The bounded startup-resync branch was not independently forced |
| v20 audio staging gate | Hardware passed for channel 3 | The final concurrent run reported 237 IRQs, one primed packet, 236 delivered packets, zero drops/errors, and 127 us maximum work latency |
| v20 audio W1C and DMA bounds | Targeted hardware pass; exact ack-window branches unforced | Channel 3 normal capture delivered 236 packets without a drop and observed no write beyond the 8 KiB ring. A 50 ms forced-INTx gate produced a duplicate-toggle XRUN, one dropped packet, userspace overrun, and an intact trailing guard. Ordered post-W1C ambiguity reasons remain implemented but need a deterministic acknowledge-window injector |
| v20 independent per-stream stop | Targeted hardware pass; full regression failed elsewhere | Video STREAMOFF left channel-3 audio running, audio stop left video running for 180 frames, both quarantined arenas were later reclaimed, and neither direction escalated to global DMA isolation. The same full run nevertheless failed on an earlier spontaneous VDONE duplicate-toggle event |
| v20 PCIe completion ordering | Probe/reload hardware pass; resume pending | Normal MSI and forced-INTx reloads verified Relaxed Ordering and No Snoop clear, and normal capture plus CPU stress passed with ordered completion reads. Suspend/resume verification remains pending |
| v20 lifecycle sequencing | Ordinary reload/remove hardware pass; focused lifecycle pending | Repeated normal/forced-INTx unloads completed coordinated removal in approximately 2.1..2.5 ms. Suspend failure propagation and active-handle video/ALSA removal still need focused tests |
| v20 EOF timestamps and sequence | Targeted hardware pass | On the exact in-tree module (`srcversion` `505CD68CDAF64B48D5734ED`), channel 3 at native 1080p60 delivered monotonic EOF timestamps 0.63..0.89 ms old at DQBUF with 16.62..16.72 ms cadence. Holding all three VB2 buffers for 250.174 ms advanced sequence 14 to 30; the 16-frame sequence delta matched the 266.673 ms EOF delta and exposed 15 dropped hardware frames |
| v20 DV/source-loss behavior | Targeted hardware pass; transition matrix pending | Hardware returned all 14 modes, bounded capabilities, preserved configured/detected independence, reported stable PCI `bus_info`, and rejected no-signal QUERY and STREAMON with `ENOLINK`. Mid-stream unplug/replug and deliberate mode changes remain untested |
| v20 packed YUYV layout | Hardware compliance pass for native channel-3 mode | Commit `fe6aabc` normalizes every request to configured native progressive geometry with exact packed stride and size. `v4l2-compliance` passed 49/49 and streamed native 1920x1080 YUYV; the unrelated power-present control warning was fixed afterward and needs a rerun |
| v19 submission readiness | Blocked | Production video DMA architecture must change and be revalidated |
| v20 latest full E2E regression | Failed, 29 passed / 3 failed | The current source passed load/order verification, normal and stressed capture, format/DV checks, rapid STREAMON/OFF, both independent stop directions, arena reclamation, and recovery. Concurrent capture then encountered an unforced VDONE duplicate-toggle at an 8,682 us interval; forced INTx encountered another at 8,613 us before deliberate gating, so fault injection could not start |
| v20 submission readiness | Blocked | Of the six original blockers, device scope remains unresolved in code. EOF timestamp/sequence semantics, audio bounds, progressive-only interlaced policy, DV-timings semantics, native packed format, and independent stop behavior have targeted proof for the characterized 8888:8504/channel-3 scope. The spontaneous VDONE duplicate-toggle failure is now an immediate blocker. Production telemetry, focused lifecycle testing, and cross-device validation also remain |

## 2026-08-29 v20 code-value submission assessment

The assessment at standalone commit `ac3c784` considered the implementation
itself rather than sign-off, patch formatting, checkpatch, or Git submission
mechanics. The result is **not ready for Linux submission yet**, although the
architecture has clear upstream value. The fixed private video ring, CPU-only
VB2 path, independent per-channel completion workers, audio staging,
generation/toggle/deadline validation, MSI preference, and fail-closed W1C
handling are substantial improvements over v19. The 20/20 hardware result is
strong evidence for the exact 8888:8504 channel-3/1080p60 path, but it does not
cover the following code-level problems.

### Original submission blockers and current status

1. **Per-stream stop still depends on a device-global DMA-idle observation.**
   The scratch arenas are deliberately allocated at probe and retained until
   PCI teardown, and neither video nor audio DMA targets userspace buffers.
   Nevertheless, video STREAMOFF, no-signal recovery, mode changes, and audio
   scratch release wait for a global busy bit. The code itself notes that
   another active channel can prevent the bit from clearing. A timeout in a
   forced caller sets `dma_failed` and `pci_lost`, disables every video and
   audio engine, fails all queues, and can clear PCI bus mastering. Stopping
   one stream while another remains active can therefore disable the entire
   card. Ordinary per-stream stop should disable that engine, synchronize its
   IRQ, drain its worker, return its VB2 or ALSA buffers, and leave permanent
   scratch quarantined. Global idle or PCI isolation should be reserved for
   remapping, freeing scratch, suspend/remove, or a real device-wide fault.

   The exceptional path in `hws_stop_streaming()` also returns without
   returning all driver-owned VB2 buffers when idle/isolation cannot be proved.
   That violates the VB2 stop contract even though the endpoint never targets
   those VB2 buffers.

   **Current status in the working tree after `fe6aabc`: code-resolved;
   hardware validation pending.** Video STREAMOFF disables only the selected
   engine, synchronizes the shared IRQ, drains that channel's worker, and
   returns every driver-owned VB2 buffer without waiting on the device-global
   busy bit. ALSA STOP publishes the stopped state and disables only its ACAP
   bit; the sleepable `hw_free`/close path drains deferred delivery before
   releasing its reference. Both paths leave any DMA-armed permanent arena
   quarantined.

   Before a quarantined video ring is reprogrammed, or a quarantined audio ring
   is prepared, the driver uses non-forcing `hws_try_wait_dma_idle()` and then
   verifies its guards. If another channel keeps the global busy bit asserted,
   the attempted reuse returns `-EBUSY`; it does not set `pci_lost`, disable
   unrelated engines, or clear bus mastering. Forced `hws_wait_dma_idle()` is
   now confined to channel destruction, scratch teardown, and coordinated
   device stop. The scratch-reference release API no longer accepts a
   misleading idle argument. The E2E harness includes both independent-stop
   directions and post-idle arena reuse, but this new matrix has not yet run on
   hardware.

2. **The audio DMA write extent is assumed rather than guarded and
   characterized.** Video has page-rounded capacity and guard pages, but audio
   receives only the inherited 10 KiB window and sits at the end of the
   coherent allocation without a trailing guard. CPU-side packet bounds do not
   detect or contain an endpoint write beyond that allocation. Because the
   video diagnostics already found an undocumented 2,048-byte write tail, the
   audio region needs a characterized page-rounded extent, a trailing guard or
   canary, verification after proved idle, and a failure policy equivalent to
   the video ring.

   **Current status at `fe6aabc`: code-resolved and targeted hardware-
   characterized; broader characterization pending.** The two 4 KiB packet
   halves retain an 8 KiB logical ring inside a 12 KiB page-rounded DMA
   capacity. The 8..12 KiB padding and a separate 4 KiB trailing guard use an
   offset-dependent canary. After DMA idle is proved, the driver reports the
   furthest modified byte and permanently refuses reuse if either the shared
   leading guard or trailing guard changed. The final 30/30 channel-3 run
   observed exactly 8,192 modified bytes during both normal capture and the
   forced-INTx XRUN, with the measurement area and trailing guard intact. This
   characterizes the tested 8888:8504 channel-3 path only; every other channel,
   mode, and retained PCI ID remains uncharacterized.

3. **The PCI match table is broader than the established implementation
   scope.** It binds unknown SKUs plus HDMI and SDI families, while the complete
   validation covers only the 8888:8504 HDMI card. Older device revisions enter
   a legacy path that explicitly leaves live geometry and FPS at defaults.
   Until per-model register behavior, channel counts, formats, and DMA extents
   are established, the table should be restricted to characterized devices or
   split into explicit per-model capabilities and operations.

   **Current status at `fe6aabc`: unresolved.** The match table still contains
   13 entries across vendor IDs 0x8888 and 0x1f33, including unknown, HDMI, and
   SDI SKUs. Capability selection is still keyed primarily by device ID, and
   old `device_ver` values still select the no-op legacy geometry/FPS path.
   Only 8888:8504 has the documented DMA-safety evidence.

4. **Interlaced geometry is internally inconsistent.** Detection bounds an
   interlaced register height using `height * 2`, implying the register reports
   a field height, but the driver then exposes that unmultiplied value as a
   `V4L2_FIELD_INTERLACED` frame and sizes the ring from it. This can reject a
   valid 1080i representation or expose and allocate only half a frame. The
   driver should reject detected interlaced input until support is defined, or
   establish the register semantics and consistently use full-frame geometry.

   **Current status at `fe6aabc`: code-resolved by explicit rejection; hardware
   rejection test pending.** The supported timing table now contains only
   complete progressive CEA/DMT modes, DV capabilities advertise progressive
   support only, detected interlaced input cannot match the supported table,
   `S_DV_TIMINGS` rejects interlaced timings, and `TRY_FMT` plus the shared
   layout validator reject interlaced state. An actual 1080i/other interlaced
   source has not yet proved the expected QUERY/STREAMON rejection on hardware.

5. **DV-timings behavior does not consistently represent the supported and
   configured state.** With a recognized live signal,
   `VIDIOC_ENUM_DV_TIMINGS` returns only the current timing rather than the
   supported list. `VIDIOC_G_DV_TIMINGS` substitutes detected live timing for
   configured timing. Several table entries contain only width and height with
   no usable clock or porch data, while a 1080x1920 portrait entry raises the
   advertised maximum height to 1920 even though capture formats are capped at
   1080. The timing table and query/get/set/enumerate/capability semantics must
   be made internally consistent.

   **Current status at `fe6aabc`: resolved and targeted API/hardware-
   validated.** The table contains 14 complete standard progressive timing
   definitions and no portrait entry. `ENUM_DV_TIMINGS` always returns that
   supported list, `G_DV_TIMINGS` returns configured state,
   `QUERY_DV_TIMINGS` performs stable live detection, and S/QUERY require an
   exact supported mode. Capability bounds, pixel clocks, and standards are
   derived from the same table and top out at 1920x1080. The 30/30 E2E run
   verified all 14 entries, configured/detected independence, and no-signal
   rejection; the subsequent native-only compliance run passed all 49 tests.

6. **Format negotiation accepts layouts that cannot reach STREAMON.** Packed
   YUYV negotiation permits odd widths and dimensions as small as 1x1. The
   native half split rounds down to a 2,048-byte boundary, so sufficiently
   small accepted formats produce a zero split and fail later during capture
   start. `TRY_FMT` must normalize every request to an actually streamable,
   even-width hardware geometry and maintain that invariant across live mode
   changes.

   **Current status at `fe6aabc`: resolved and hardware compliance-validated
   for native 1080p60.** Commit `9104861` first made every accepted layout
   strictly packed and streamable in software, but still exposed
   640x480..1920x1080 scaling. Compliance proved that a 640x480 output request
   on a live 1080p60 input does not constrain hardware DMA geometry. Commit
   `fe6aabc` therefore normalizes every request to configured native DV
   geometry, progressive field-none, exact `bytesperline = width * 2`, exact
   `sizeimage = bytesperline * height`, and a nonzero valid native split. The
   resulting run passed 49/49 compliance tests and native 1920x1080 streaming.
   A full post-change E2E regression and other native modes remain pending.

### Additional code issues

- PCIe Relaxed Ordering was enabled unconditionally even though the correctness
  design depends on DMA data being visible before completion toggle/IRQ
  observation. The working tree after `e848e0e` now clears and verifies both
  Relaxed Ordering and No Snoop at probe and resume; hardware validation is
  pending.
- A live SD/HD geometry change recalculates dimensions and buffer size without
  updating the cached colorimetry state.
- The synthetic no-signal YUYV frame fills every byte with `0x10`, including U
  and V. Neutral packed YUYV needs chroma values of 128 and a luma value chosen
  consistently with the advertised quantization.
- The permanent-ring design no longer needs coherent DMA allocators for VB2
  and ALSA userspace rings because the endpoint never targets them. CPU-oriented
  backing would better match ownership and avoid large unnecessary coherent
  allocations, although this is an architectural refinement rather than the
  primary safety blocker.

The two color-related bullets above describe the `ac3c784` assessment state.
They are resolved in the current branch, with hardware regression still
pending: live detection no longer mutates configured geometry; initialization,
`S_FMT`, and `S_DV_TIMINGS` all refresh colorspace, Y'CbCr encoding,
quantization, and transfer-function metadata; and source loss now stops and
fails the stream rather than manufacturing a synthetic YUYV frame.

### 2026-08-30 comprehensive follow-up findings

The follow-up review covered the full current driver at standalone commit
`ac3c784`, including IRQ ordering, video and audio completion publication,
V4L2 API behavior, format and signal transitions, probe/remove, power
management, and warning-enabled builds. It confirmed the six then-current
blockers above and found the following additional issues. The status paragraphs
above record which were subsequently resolved. These are code-value findings;
Git mechanics, sign-off, patch presentation, and checkpatch policy were
deliberately outside the assessment.

#### Completion and interrupt correctness

1. **The proof that endpoint data is visible at completion is incomplete.**
   `src/hws_pci.c` enables PCIe Relaxed Ordering unconditionally, while video
   and audio use relaxed MMIO reads to observe completion/toggle state. A
   `dma_rmb()` orders CPU observations but cannot turn a late endpoint DMA write
   into an ordered one. Likewise, copying a half and immediately comparing it
   with the source only detects a write that lands between those two CPU reads;
   two reads can agree on the same stale contents. Relaxed Ordering should be
   disabled unless the device's transaction ordering is documented and proved,
   and completion registers used as ordering points should use ordered MMIO
   access.

   **Resolution status (2026-08-30): implemented in the working tree after
   `e848e0e`, hardware validation pending.** Probe and resume now clear and
   read back both `PCI_EXP_DEVCTL_RELAX_EN` and
   `PCI_EXP_DEVCTL_NOSNOOP_EN`; failure to establish that conservative
   requester contract aborts initialization. Every VDONE/ADONE status and
   toggle read used as a DMA-completion ordering point now uses ordered
   `readl()`. The video path retains the pre-copy and post-copy toggle/deadline
   checks but removes the full-half `memcmp()`, which could detect only a narrow
   concurrent-write race and could not prove that a later endpoint write would
   not arrive. The E2E loader now reads PCIe Device Control after every module
   reload and refuses to continue if either unsafe requester attribute is set.

2. **Post-W1C ambiguity is handled for video but not for audio.** The IRQ
   handler reads `INT_STATUS` again after acknowledging the W1C bits, but only
   the video path receives that post-ack state. `hws_irq_record_audio()` sees
   only the pre-ack snapshot. An ADONE that reasserts or coalesces across the
   acknowledge can therefore be lost. Cadence and toggle checks may catch a
   later inconsistency, but cannot guarantee detection when an even number of
   toggles is lost or no later audio interrupt arrives. Post-ack audio bits must
   fail the affected PCM stream closed immediately, with a focused forced-INTx
   regression test analogous to the video ambiguity test.

   **Resolution status at `fe6aabc`: implemented and targeted hardware-
   validated.** ADONE now has a pre-ack toggle and two ordered post-ack samples.
   Status reassertion, unstable post-ack samples, or a toggle change across W1C
   disables ACAP in hard-IRQ context and reports a reason-specific ALSA XRUN.
   Forced INTx produced a duplicate-toggle XRUN, terminated userspace, and left
   the 8,192-byte observed DMA extent and guard clean. The three exact post-ack
   reassert/unstable/change branches still need deterministic injection.

3. **The enabled interrupt mask is broader than the sources the handler
   decodes.** `HWS_INT_EN_MASK` enables bits 0 through 17, while the current
   handler explicitly accounts for video channels 0 through 3 and audio
   channels 0 through 3. The value appears inherited from the vendor driver,
   so it is not proof of a live bug, but every remaining bit needs a documented
   source and disposition before the mask can be considered safe upstream.

   **Resolution status (2026-08-30): implemented in the working tree after
   `e848e0e`, hardware validation pending.** The inherited bits 0 through 17
   mask has been removed. The driver now constructs its gate from exactly one
   VDONE bit per configured video channel and one ADONE bit per configured
   audio channel, matching the handler's explicit demultiplexing scope.

#### Video API and signal-state correctness

4. **The measured colorimetry correction is absent from the current branch.**
   Hardware work established BT.601 coefficients and full-range quantization at
   1080p. Commit `6f24ceb` (`media: report measured HWS colorimetry`) preserves
   that correction on `audio-upstream-5patch-pulled-forward`, but it is not an
   ancestor of the current v20 branch. The current height-derived defaults
   report Rec.709 for HD, which misdescribes the measured image. Live geometry
   changes also resize the format without refreshing colorimetry. The measured
   metadata fix must be restored and applied consistently on every mode change.

5. **DV-timings discovery can report a plausible but false mode.**
   `hws_get_live_dv_geometry()` reads the resolution register without first
   requiring the channel's signal-present status. Query can consequently fall
   back to cached geometry and succeed with no link instead of returning
   `-ENOLINK`. When no exact width/height/frame-rate entry matches, the timing
   matcher falls back to width and height alone, so an unsupported refresh such
   as 1080p50 can be reported as a supported 1080p60 timing rather than
   `-ERANGE`. Detection must require a live, stable signal and an exact supported
   mode.

6. **Configured, detected, and enumerated timings remain conflated.**
   `VIDIOC_G_DV_TIMINGS` should return the configured timing, while
   `VIDIOC_QUERY_DV_TIMINGS` reports detected input and
   `VIDIOC_ENUM_DV_TIMINGS` enumerates the driver's supported set. The current
   implementation substitutes live state for configured state and filters
   enumeration around the current signal. `hws_set_current_dv_timings()` also
   caches only a partial timing structure. These operations need distinct,
   complete state and consistent capability bounds.

7. **The monitor changes capture geometry behind userspace's back.** On a live
   mode change it rewrites `pix`, buffer size, and output programming rather
   than reporting `V4L2_EVENT_SOURCE_CHANGE` and waiting for userspace to stop,
   renegotiate, and reallocate buffers. An FPS-only change can update cached
   state without sending a source-change event at all. In addition,
   `handle_hwv2_path()` reads format/control state and programs registers
   without the format state lock, racing ioctls and stream transitions.

8. **Buffer timestamps describe the wrong completion point.** The queue
   advertises monotonic EOF timestamps, but a completed frame inherits the
   timestamp recorded for its first half. That timestamp is roughly half a
   frame early and is neither a frame-start nor frame-end timestamp. For EOF
   semantics, publication should use the second-half completion timestamp.

   **Resolution status (2026-08-30): implemented and targeted hardware-
   validated in the working tree after `4468e93`.** A delivered buffer now receives
   the ordered VDONE timestamp belonging to its verified second-half event,
   after both halves pass generation, phase, toggle, deadline, and guard checks.
   The VB2 queue explicitly advertises monotonic EOF timestamp semantics. The
   obsolete first-half timestamp cache has been removed. With the exact
   in-tree module loaded, `hws_video_metadata_test.c` measured 12 normal
   channel-3/1080p60 EOF timestamps only 0.63..0.89 ms old at DQBUF, compared
   with approximately 9.34 ms from the deliberately observed stale module,
   and measured the expected 16.62..16.72 ms full-frame cadence.

9. **Sequence numbering excludes dropped complete frames.** The sequence
   counter advances only when a queued VB2 buffer is delivered. If no buffer is
   available when the first half arrives, a complete hardware frame is skipped
   without advancing the counter. V4L2 sequence numbers must expose dropped or
   repeated frames, so the driver needs a hardware-frame completion counter
   independent of userspace buffer availability.

   **Resolution status (2026-08-30): implemented and targeted hardware-
   validated in the working tree after `4468e93`.** Once startup synchronization has
   established the native half order, every verified second-half completion
   consumes exactly one sequence value. A delivered buffer receives that value;
   a frame skipped because no VB2 buffer was available still consumes it, so a
   later delivered buffer exposes the loss as a sequence gap. Phase-learning
   events are intentionally not counted because they cannot yet identify a
   trustworthy complete frame. The focused metadata test held every VB2 buffer
   for 250.174 ms: the next delivery advanced sequence 14 to 30, exposing 15
   skipped frames, while its 266.673 ms EOF timestamp delta agreed with exactly
   16 hardware frame periods.

10. **No-signal output is neither color-correct nor cadence-correct.** The
    monitor produces at most one synthetic frame per approximately one-second
    pass while stream parameters continue to advertise the normal 50/60 fps
    cadence. Filling every YUYV byte with `0x10` also makes both chroma
    components 16 instead of neutral 128. The driver should either report the
    signal loss and stop frame delivery, or generate correctly encoded neutral
    frames at a behavior and cadence that match its advertised API.

    **Resolution status (2026-08-30): implemented in `0626f47`, hardware
    validation pending.** The driver chose the V4L2 source-change model: it
    disables the channel producer, drains IRQ/copy work, marks the VB2 queue
    failed, and emits `V4L2_EVENT_SOURCE_CHANGE`. It delivers no synthetic
    frame. The working-tree harness additionally requires a no-signal
    STREAMON attempt to fail promptly instead of returning a frame.

11. **Capability metadata is incomplete.** `VIDIOC_QUERYCAP` does not populate
    a PCIe `bus_info` value, making otherwise identical multi-card devices hard
    for userspace to identify stably.

#### Probe, power-management, and removal lifetime

12. **Probe enables the core before all interrupt-facing resources exist.**
    Core initialization occurs before scratch arenas, workqueues, the final IRQ
    gate mask, and the installed handler. The later call described as starting
    the permanent arenas is currently a no-op because its enable-state guard
    returns early. This creates at least a sequencing/documentation error and
    may create a pre-handler interrupt window. The device should remain
    quiescent until all DMA targets, workers, locks, and IRQ handling are ready,
    then be enabled once in an explicit final step.

    **Resolution status (2026-08-30): implemented in the working tree after
    `e848e0e`, hardware validation pending.** Probe clears PCI bus mastering,
    masks the source gate, disables the core IRQ output, bridge, VCAP, ACAP,
    and decoder core, and clears pending status before discovery. It allocates
    all guarded arenas and workers and installs the IRQ handler before the one
    deterministic core initialization. Bus mastering is enabled only after the
    idle core and IRQ output have been configured, and the decoded source gate
    is opened last.

13. **Suspend hides quiesce failures.** The PM suspend path records video and
    audio stop errors but returns success unconditionally. The system can then
    enter a power transition even though queue ownership or DMA isolation was
    not established. A failed quiesce must abort suspend or transition through
    a proved device-wide isolation path.

    **Resolution status (2026-08-30): implemented in the working tree after
    `e848e0e`, hardware validation pending.** Device stop now returns its DMA
    idle/isolation result, coordinated quiesce preserves both device-stop and
    VB2 errors, and suspend returns the first audio or quiesce failure without
    saving state, disabling the function, or entering D3. When the failure did
    not mark DMA permanently unsafe, the idle core and retained arenas are
    restored before the failed suspend returns.

14. **Remove orders unregister before device-wide quiescence.** Video
    unregister initiates channel-by-channel streaming teardown before the
    coordinated device-wide stop. The working-tree per-stream change prevents
    one channel's stop from escalating through the global busy bit, but removal
    should still first block new opens, perform one coordinated device-wide
    stop/isolation, drain all workers, and only then unregister interfaces and
    release DMA memory. That lifecycle reordering remains unresolved.

    **Resolution status (2026-08-30): implemented in the working tree after
    `e848e0e`, hardware validation pending.** Remove first blocks IRQ and
    monitor hot paths, stops the monitor, disables all producers, synchronizes
    the IRQ, drains every completion worker, proves global DMA idle or isolates
    PCI DMA, and returns active VB2 buffers. ALSA and V4L2 interfaces are
    disconnected only after that coordinated boundary; arenas and workers are
    released afterward.

15. **ALSA removal can wait indefinitely for open files.**
    `hws_audio_unregister()` disconnects and then calls the synchronous
    `snd_card_free()`, which waits for all users to close. A sysfs unbind or
    physical hot-unplug with an open PCM/control descriptor can therefore block
    removal. A deferred-free design must retain the PCI parent and driver state
    until the final ALSA reference is gone. By contrast, the suspected analogous
    V4L2 late-close use-after-free was ruled out: VB2 video unregister releases
    the queue synchronously and the retained V4L2 parent reference protects the
    containing state during close.

    **Resolution status (2026-08-30): implemented in the working tree after
    `e848e0e`, hardware validation pending.** ALSA unregister disconnects the
    card and uses `snd_card_free_when_closed()` instead of the synchronous
    free. The parent driver allocation now has a shared `kref`: ALSA holds one
    through `snd_card.private_free`, V4L2 holds one through its release callback,
    and PCI devres holds the base reference. Disconnect replaces active ALSA
    operations with shutdown operations. Because the shutdown release still
    delegates final PCM cleanup to the original release path, the driver's
    `.hw_free` and `.close` explicitly switch to software-only ownership cleanup
    once removal has published the suspended/disconnected state. Removal can
    therefore release PCI resources while only the software parent remains
    until the final file close.

#### Build quality, performance, and validation scope

16. **The module Makefile suppresses compiler warnings with `-w`.** A
    warning-enabled `W=1` build and GCC analyzer build otherwise completed, but
    exposed a real format mismatch in the video diagnostics: a `size_t` split
    value is passed to `%08x`. It should use `%zx` or an explicitly sized cast,
    and warning suppression should be removed so ordinary kernel builds retain
    diagnostic value. The Clang attempt was not a valid driver result because
    the installed Arch kernel tree was configured with GCC-only flags.

17. **Every video half performs both a full copy and a full comparison inside
    the deadline.** The `memcpy()` followed by `memcmp()` doubles source-memory
    read traffic for each half and consumes a substantial share of the 7.5 ms
    safety window at 1080p60. The comparison is not a proof against a write that
    lands after both reads. It should be treated as diagnostic instrumentation
    unless a documented ordering contract makes it useful, and performance must
    be measured without weakening fail-closed behavior.

    **Resolution status (2026-08-30): implemented in the working tree after
    `e848e0e`, hardware validation pending.** The destination copy remains, but
    the second full source read and `copy_mismatches` accounting are removed.
    An ordered post-copy toggle observation plus the existing generation,
    phase, deadline, and guard checks remain the fail-closed acceptance gate.

18. **The successful hardware matrix is still narrow.** The 20/20 E2E pass
    proves the 8888:8504 card's channel-3 1080p60 path, including concurrent
    HDMI audio, CPU load, rapid STREAMON/OFF, and forced-INTx video ambiguity.
    It does not characterize four simultaneous channels, every accepted mode,
    slower or real-time workloads, audio post-W1C ambiguity, independent stream
    stop, suspend/resume, or active-handle removal. Deadline failures remain
    safely fail-closed, but could still become false EIOs outside the measured
    load.

19. **Start/stop telemetry is too heavy for the final production path.** Audio
    trigger emits information-level telemetry and reads several MMIO registers
    on every start and stop. This was useful for diagnosis but can add latency
    and log noise in an atomic-sensitive ALSA path. Keep detailed snapshots
    behind a debug mechanism or rate limit them once the audio investigation is
    complete.

The review did not find a new obvious buffer overrun or use-after-free in the
staged video/audio copy paths. The independent video workers are explicitly
drained, and the audio staging, generation, toggle, cadence, and deadline logic
is internally coherent for the tested path. Those positive results narrow the
remaining work, but do not offset the ordering, lifecycle, and public-API
blockers above.

### 2026-08-30 DV-timing remediation

Commit `0626f47` corrects the DV-timing and source-state cluster
identified in findings 4 through 7, 10, 11, and 16 above. These corrections
build successfully but have not yet passed the hardware E2E matrix or
`v4l2-compliance`, so their status is **implemented, hardware validation
pending**.

- The timing table uses complete kernel CEA-861 and DMT presets instead of
  width/height-only records. The unsupported 1080x1920 portrait entry was
  removed, and capability bounds now include the actual minimum/maximum pixel
  clocks and standards derived from the retained table.
- Live detection samples signal/interlace state and input resolution on both
  sides of the frame-rate read. No signal returns `-ENOLINK`, a changing or
  incomplete sample returns `-ENOLCK`, and a stable timing absent from the
  exact width/height/interlace/rate table returns `-ERANGE` with the partial
  detected geometry preserved. The old width/height-only refresh fallback is
  gone.
- `VIDIOC_QUERY_DV_TIMINGS` now reports detector state without changing driver
  configuration. `VIDIOC_G_DV_TIMINGS` returns only the configured timing,
  `VIDIOC_ENUM_DV_TIMINGS` always enumerates the full supported list, and
  `VIDIOC_S_DV_TIMINGS` accepts canonical complete modes, updates the default
  capture layout, and rejects a timing change while VB2 buffers exist.
- STREAMON requires the configured and detected timings to match exactly. It
  no longer changes `pix.interlaced` from a raw live bit or silently accepts a
  different refresh rate.
- The monitor keeps detected state separate from configured DV timing and
  pixel layout. Signal appearance/loss, lock-state changes, resolution changes,
  and FPS-only changes produce `V4L2_EVENT_SOURCE_CHANGE`. If streaming, the
  monitor disables that channel's producer, synchronizes its IRQ, drains its
  worker, and fails dequeues so userspace can STREAMOFF, query, set, free, and
  reallocate. It no longer resizes buffers, rewrites configured timing, or
  restarts DMA behind userspace's back.
- Synthetic one-frame-per-monitor-pass no-signal delivery was removed. A lost
  signal now follows the source-change/error path instead of advertising 50/60
  fps while returning incorrectly encoded `0x10`-filled frames.
- Monitor output/control programming now holds the per-channel state mutex.
  `VIDIOC_QUERYCAP` reports `PCI:<BDF>` in `bus_info`.
- The measured BT.601/full-range colorimetry correction was restored for both
  public format negotiation and internal pixel state, including timing-driven
  format changes.
- The module Makefile no longer suppresses all compiler warnings with `-w`.
  The hidden `size_t` diagnostic format mismatch was corrected. A clean `W=1`
  build and a `W=1 KCFLAGS=-fanalyzer` build both completed against Arch kernel
  `7.1.9-arch1-2`.
- `hws_v20_e2e_test.sh` now verifies multi-entry timing enumeration, bounded
  timing capabilities, independence of configured and detected timing state,
  no-signal query and STREAMON rejection, and PCI `bus_info`, then restores the
  live timing before the existing capture tests. Requiring no-signal STREAMON
  to fail promptly prevents regression to synthetic, incorrectly encoded
  YUYV frames.

The retained timing list still represents inherited claimed support rather
than complete per-mode hardware characterization. The next run must prove the
live 1080p60 path, the no-signal nodes, and at least one deliberate source mode
change. Every retained table entry must eventually be exercised or removed;
interlaced input remains deliberately unsupported and should return
`-ERANGE` rather than changing the capture layout.

### 2026-08-30 format-negotiation remediation

Commit `9104861` implemented the first correction for finding 6 above. Its
packed-layout portion passed the targeted 1080p60 hardware matrix, but the
scaler-range assumption was later disproved by `v4l2-compliance`.

- `TRY_FMT` clamps progressive YUYV requests to 640x480 through 1920x1080 and
  rounds odd widths up to the next complete two-pixel YUYV chroma pair.
- `bytesperline` is always exactly `width * 2`, and `sizeimage` is always
  exactly `bytesperline * height`; requested padding is not retained.
- The shared queue/start invariant now rejects out-of-range, odd-width,
  interlaced, padded, oversize, zero-split, and split-mismatched layouts.
  Consequently, a format accepted into driver state cannot later fail merely
  because the native 2 KiB-aligned half-ring split is zero.
- The E2E harness now checks the existing padded 720x576 request, a 1x1 request
  normalized to packed 640x480, and a 641x481 request normalized to packed
  642x481.

Those range semantics are historical. Current hardware evidence shows that
OUT_RES cannot be treated as a safe DMA scaler: a 640x480 request while the
input remained 1080p60 overwrote guards well beyond the nominal 640x480 DMA
extent. The working tree therefore exposes only the configured native DV
width/height. `TRY_FMT` still forces YUYV, progressive field-none, exact
`width * 2` stride, and exact `stride * height` `sizeimage`; arbitrary padded,
tiny, odd, or scaled requests all normalize to that same native packed layout.
The E2E probes now derive the configured native geometry and verify this
contract rather than expecting 640x480 or 642x481 scaler output.

### 2026-08-30 audio W1C and DMA-bound remediation

Commit `fe6aabc` contains both audio safety mechanisms. The characterized
8888:8504 channel-3 path has targeted normal and forced-INTx hardware evidence;
other channels, modes, and PCI IDs remain pending.

- The hard IRQ samples each asserted ADONE toggle before W1C, acknowledges the
  sticky status, then takes two ordered toggle samples and consumes the
  post-ack status. Reasserted ADONE, an unstable post-ack sample, or a toggle
  change across the acknowledge window is uncountable and therefore disables
  that channel's ACAP immediately. Deferred work reports a reason-specific
  ALSA XRUN rather than delivering a packet of uncertain identity.
- Each audio channel now places its 8 KiB two-packet ring in a 12 KiB
  page-rounded capacity followed by a 4 KiB patterned guard. The existing
  video suffix guard is also checked as the audio leading guard. Bytes from
  8..12 KiB are canary-filled to measure any contained hardware write tail.
- Guard and tail inspection happens only after the driver has disabled ACAP,
  synchronized IRQ/work ownership, and positively proved DMA idle. The driver
  logs the furthest observed modified byte. A leading or trailing guard change
  marks the scratch permanently corrupt and rejects reuse until module reload.
- `hws_audio_focus_test.sh` now requires a post-idle bounds record for a normal
  capture. When an audio source PCM is supplied, the E2E forced-INTx phase adds
  live embedded-audio capture and requires an ADONE W1C XRUN plus an intact DMA
  guard.

The 12 KiB capacity is containment based on page-rounding the inherited 10 KiB
window, not a claim that hardware writes all 12 KiB. Targeted channel-3 runs
observed exactly 8 KiB with intact canaries. Other channels, modes, and device
IDs must still record their observed extent before the capacity can be treated
as generally characterized.

### 2026-08-30 partial post-remediation hardware run

Evidence directory `/tmp/hws-v20-e2e-20260830-115159` records 24 passes and
four failures. The failures separate into one video behavior requiring a code
change and three harness/environment issues:

- The exact module loaded in MSI mode after manually loading
  `v4l2-dv-timings`. This proved the prior `Unknown symbol
  v4l2_match_dv_timings` error was raw `insmod` dependency resolution, not an
  ABI or implementation failure. Both harnesses now preload the module's ALSA,
  VB2, and DV-timings dependencies before every normal or cleanup `insmod`.
- DV enumeration returned all 14 modes, configured and detected timing state
  remained independent, `QUERYCAP` returned stable PCI `bus_info`, and
  no-signal `QUERY_DV_TIMINGS` failed as required. The capability ioctl also
  returned complete width, height, pixel-clock, standards, and progressive
  bounds; the reported failure was only a harness mismatch between the
  `v4l2-ctl` labels `PClock` and `Pixelclock`, now accepted by the parser.
- No-signal STREAMON did not fail promptly. The working tree now performs the
  live/matching timing gate in the `VIDIOC_STREAMON` wrapper before VB2 can
  enter a userspace dequeue loop, and repeats it in `start_streaming()` to
  close the setup race. It built with `W=1` and subsequently passed the direct
  no-signal ioctl test in the final run below.
- All three packed-YUYV probes passed, as did normal startup/capture, CPU-load
  capture, 40 rapid STREAMON/OFF cycles, forced video W1C failure, and recovery.
- The two audio-source failures did not exercise the new audio code: USB card
  enumeration moved NVIDIA HDMI from card 1 to card 2, making the supplied
  `hw:1,3` node nonexistent. The harness now accepts a stable ALSA card ID;
  subsequent runs should use `hw:NVidia,3`. Audio W1C ambiguity and DMA-bound
  characterization therefore remain pending.

A second run at `/tmp/hws-v20-e2e-20260830-115644` used the stable
`hw:NVidia,3` source and advanced the result to 28 passes and two failures:

- Normal concurrent channel-3 audio/video passed. Audio recorded 237 ADONE
  IRQs, one priming packet, 236 delivered packets, zero drops, and 294 us
  maximum worker latency. Post-idle inspection observed writes through byte
  8192 only; the 8..12 KiB measurement area and trailing guard remained intact.
- Gating forced legacy INTx for 50 ms during audio produced an ALSA XRUN with
  `reason=duplicate-toggle`, 45 delivered packets, one dropped packet, and a
  clean 8192-byte observed extent. This is a valid fail-closed result for
  completions coalesced before the W1C acknowledge window. The harness had
  incorrectly required only a `w1c-*` reason; it now accepts the bounded set of
  completion-loss detectors (`w1c-*`, duplicate toggle, or invalid cadence)
  while still requiring userspace termination and a clean DMA guard. The exact
  post-ack reassert/unstable/change branches remain unforced.
- The only driver-facing failure was again the no-signal STREAMON probe. Its
  empty `v4l2-ctl` log did not expose the ioctl result and the tool entered its
  streaming wait. The harness now invokes `VIDIOC_STREAMON` directly on a
  nonblocking descriptor and accepts only the driver's prompt link/timing
  errors; it cannot mistake a userspace dequeue wait for driver acceptance.

The final rerun at `/tmp/hws-v20-e2e-20260830-115945` passed the complete
targeted matrix: **30 passed, 0 failed, 0 skipped**. It tested module SHA-256
`5c47f9a810e4fe99f4d28027410ef9b40a35efe2f04833abdeca3b86372bc52e`
with source version `1863098A2C3F673A1986998` on Arch kernel
`7.1.9-arch1-2` and PCI function `0000:17:00.0`.

- The direct no-signal ioctl returned `ENOLINK` (`errno 67`) immediately.
- Normal channel-3 audio recorded 237 IRQs, one primed packet, 236 delivered
  packets, zero drops or validation errors, and 127 us maximum worker latency.
  DMA inspection observed exactly 8192 bytes inside the 12288-byte capacity;
  the trailing guard remained intact.
- Forced legacy-INTx audio loss again produced a duplicate-toggle XRUN after
  47 IRQs, with 45 delivered packets, one dropped packet, 115 us maximum worker
  latency, an 8192-byte observed extent, and an intact guard.
- The same exact module also passed complete-frame startup, 120-frame normal
  capture, all DV/format/API checks, 240-frame CPU-stressed capture, 40 rapid
  STREAMON/OFF cycles, concurrent video/audio, forced video W1C failure to
  userspace `EIO`, MSI-mode restoration, and a 30-frame recovery capture with
  no kernel safety failure.

This is a targeted channel-3/1080p60 hardware pass. It does not replace the
broader mode, channel, transition, independent-stop, lifecycle, or suspend
matrix listed below, and it did not deterministically enter the three narrow
post-W1C audio acknowledge-window branches.

### 2026-08-30 v4l2-compliance format-transition follow-up

Running `v4l2-compliance 1.32.0 -d /dev/video3 -f -v` after the 30/30 E2E
pass produced 53 tests: 49 succeeded, four failed, and one warning was
reported. Required ioctls, multiple opens, input/DV timing ioctls, controls,
format negotiation, buffer ioctls, blocking waits, and 640x480 MMAP streaming
all passed. The warning was the absence of the recommended read-only
`V4L2_CID_DV_RX_POWER_PRESENT` control.

The first substantive failure was 1920x1080 STREAMON immediately after the
successful 640x480 iteration. Kernel evidence showed four bounded startup
resynchronizations with alternating approximately 15 ms and 1 ms VDONE
intervals, followed by fail-closed ambiguity and a changed DMA guard. The
three subsequent Top/Bottom/Alternating failures occurred after that queue had
entered its error state and are treated as secondary until the first failure
is retested.

The first suspected cause was asynchronous output-scaler programming: `S_FMT`
changed software geometry, but the one-second monitor later wrote `OUT_RES`,
potentially while the next VCAP ownership interval was starting. The working
tree was changed to program and verify `OUT_RES` synchronously while idle from
`S_FMT`, `S_DV_TIMINGS`, and STREAMON, reject the write while VCAP or unresolved
DMA ownership is active, and stop the monitor changing it in either state.

A repeat compliance run at
`/tmp/hws-v4l2-compliance-20260830-120515.log` produced the identical four
failures and identical approximately 15.5 ms/1.15 ms VDONE pairing. The exact
module source version matched the rebuilt tree, so asynchronous `OUT_RES`
programming was real unsafe behavior but not the complete cause of this
failure. The remaining state difference is the engine's retained internal ring
position after the successful 640x480 stream: changing only its split before
the 1920x1080 stream did not re-arm the fixed base. The working tree now
invalidates the programming cache on idle geometry changes, forcing the same
permanent remap, base, and new split to be rewritten before VCAP is enabled.
It also reports the first changed byte in each guard page if the retest still
crosses a boundary. This second correction builds cleanly with `W=1` and strict
checkpatch.

The next run, `/tmp/hws-v4l2-compliance-20260830-120825.log`, again produced
the same surface result, but the new telemetry identified the root cause:
`video DMA guard mismatch ch=3 extent=614400 leading_off=-1 trailing_off=0`.
The guard was crossed by the successful 640x480 stream, not by the following
1920x1080 stream. The latter correctly failed closed because the channel had
already been marked corrupt, and the interlaced cases then inherited the VB2
queue error.

Packed 640x480 YUYV is exactly 614400 bytes and already page-aligned. The
working-tree extent formula used `PAGE_ALIGN(sizeimage)`, which therefore
reserved no space for the independently characterized 2048-byte hardware write
tail. At 1920x1080 the same formula happened to add 2048 bytes because
4147200 is half-page-aligned, masking the invariant error in all prior 1080p60
testing. The corrected invariant is now
`PAGE_ALIGN(sizeimage + HWS_VIDEO_DMA_TAIL_BYTES)`, with
`HWS_VIDEO_DMA_TAIL_BYTES = 2048`; maximum ring capacity uses the identical
formula. This gives 618496 bytes for the 614400-byte 640x480 frame and 4149248
bytes for the 4147200-byte 1080p frame. The correction builds cleanly with
`W=1` and strict checkpatch but remains hardware pending; both full compliance
and the 30-test E2E matrix must be rerun. The power-present control warning
remains a separate non-fatal API cleanup item.

The following run,
`/tmp/hws-v4l2-compliance-20260830-121005.log`, used the corrected tail formula
and moved the dynamic guard to extent 618496, but hardware again changed byte
zero of that guard and retained the same approximately 15.5 ms/1.15 ms VDONE
pairing. This disproves the interpretation as a fixed tail attached to a
640x480 DMA frame. The HDMI input remained 1080p60: the device continued native
DMA despite the smaller OUT_RES request. Treating arbitrary output dimensions
as a supported scaler is therefore unsafe. The working tree now binds capture
width/height to `cur_dv_timings`, while keeping the corrected `sizeimage + 2
KiB` extent invariant for actual native modes. This native-only negotiation
builds cleanly with `W=1` and strict checkpatch.

The native-only retest at
`/tmp/hws-v4l2-compliance-20260830-121259.log` passed all 49 tests with zero
failures. Compliance now reports scaling as unsupported and exercises only the
configured native 1920x1080 packed-YUYV mode; that stream passed. The sole
remaining warning was the missing `V4L2_CID_DV_RX_POWER_PRESENT` control. The
working tree now exposes that standard read-only single-input bitmask and
updates bit zero from the channel's hardware `ACTIVE_STATUS` source indication;
this final control addition is build-tested but still needs a compliance rerun.

### Required evidence after correction

The next hardware gate must stop video and audio independently while other
channels remain active, rather than stopping the only live streams together.
It must also exercise every retained PCI ID or prove that unsupported IDs have
been removed, record the post-idle audio write extent and intact guards on
every channel, force the new audio post-W1C ambiguity path, and test every
accepted progressive mode. It must explicitly
reject or validate interlaced input; test no-link, unsupported-refresh, and
source-change DV-timings behavior, including an actual mid-stream unplug,
prompt `EIO`/source-change notification, STREAMOFF cleanup, same-mode replug,
changed-mode reconfiguration, and restart; repeat the targeted EOF timestamp
and dropped-frame sequence proof on retained channels and modes; force the
bounded startup-resync branch; and
cover suspend/resume plus active-stream unbind/remove with open video and ALSA
file descriptors. Multi-channel load and ordering tests must verify after every
probe and resume that PCIe Device Control has Relaxed Ordering and No Snoop
clear. The active-handle unbind case must demonstrate that the unbind returns
promptly, existing ALSA operations fail as disconnected, the module remains
pinned until final close, and no callback reaches released PCI resources.
Passing the existing channel-3 matrix remains a required regression test, not
a substitute for these cases.

## Submission and review status

- An earlier five-patch series was submitted. Its first transmission was
  malformed, a repost reached media CI, and a later revision received Hans
  Verkuil's review.
- Reviewer feedback was incorporated into later rewrites.
- v19 was built, checked, ported, documented, and packaged as a mailbox.
- No reviewed evidence shows that v19 itself was sent.
- The history explicitly deferred submission until the bounce-buffer blocker
  was resolved; the August diagnostics confirmed the blocker.
- There is no evidence that v19 was accepted or merged.
- Actual sending of the device-information and colorimetry patches remains
  unconfirmed.

## Reconciled assumptions

- "One VDONE per frame" is true for the exact tested production split, not as
  a universal hardware property. The native split reports half cadence.
- Sticky W1C status cannot count completed segments or recover their identity.
- Fixed full-frame A/B banks were experimentally rejected for the tested mode.
- Prompt VCAP clearing does not replace a positive DMA-idle proof before the
  private DMA arena is remapped, freed, or reused after corruption. Because
  that arena is permanent and VB2/ALSA client buffers are CPU-only targets,
  ordinary per-stream stop can return client buffers while quarantining it.
- A two-slot allocation based only on `sizeimage` risks tail overlap because
  the tested hardware writes 2,048 bytes farther.
- The STREAMOFF result validates one fix but does not prove complete DMA safety.
- The colorimetry correction changes interpretation metadata, not sharpness or
  spatial resolution.

## Production successor requirements

The current evidence supports a permanent guarded private native half-ring per
channel, with CPU assembly into queued VB2 buffers:

1. Keep the hardware DMA base, remap entry, and split fixed while VCAP is
   enabled.
2. Allocate and separate the complete characterized hardware write extent,
   including guards and the observed 2,048-byte tail.
3. Never program affected direct-DMA paths with VB2 buffer addresses.
4. Copy only proved-complete halves into a destination VB2 buffer and deliver
   it only after both halves belong to the same verified generation.
5. Track phase, toggle, generation, source reuse, and a conservative copy
   deadline. Unexpected or ambiguous state must fail closed.
6. Centralize stop and quiescence. Per-stream stop must disable its engine,
   synchronize IRQ/work, return client buffers, and quarantine the permanent
   arena without requiring device-global idle. Suspend, remove, remapping,
   arena freeing, and real device-wide faults must prove global idle or isolate
   PCI DMA before memory can be released.

## Prioritized resume plan

1. Completed: the five diagnostic commits and evidence are preserved on the
   pushed dangerous branch. Its experimental driver was not merged.
2. Completed: `audio-upstream-v19` remains the immutable reference, and
   `audio-upstream-v20-dma-safety` was created from its exact tip.
3. Implemented and hardware-proved for the targeted channel-3/1080p60 matrix:
   the successor branch has the guarded fixed native half-ring, CPU two-half
   assembly, and extended startup synchronization. The bounded resync branch
   and broader channel/mode matrix remain to be forced.
4. Implemented and targeted hardware-proved: explicit W1C ambiguity, phase,
   generation, copy-deadline, copy verification, and fail-closed handling. The
   bounded startup-resync branch still needs a forced test.
5. Implemented and hardware-proved for channel 3: stable audio staging,
   cadence priming, completion generations, and post-copy
   toggle/generation/deadline validation with a live HDMI tone.
6. Packed YUYV and shared queue/STREAMON validation are targeted
   hardware-proved. Removing the disproved scaler range and normalizing all
   format requests to configured native DV geometry produced a 49/49
   `v4l2-compliance` pass. The subsequent DV receiver power-present control
   addition still needs its compliance rerun, as does the full E2E matrix.
7. Implemented in `0626f47` and targeted hardware-proved: geometry updates
   refresh the complete colorimetry cache, no-signal QUERY/STREAMON fail, and
   source loss does not generate synthetic frames. The full mid-stream
   unplug/replug and changed-mode recovery sequence remains pending.
8. Implemented and targeted hardware-proved in `fe6aabc`: post-W1C
   ADONE resampling fails ambiguous completion closed, and the page-rounded
   audio DMA capacity recorded an 8192-byte extent behind an intact trailing
   guard. Deterministic forcing of each narrow post-ack branch remains pending.
9. Implemented in `e848e0e`, hardware pending:
   independent per-stream stop no longer waits forcibly for device-global DMA
   idle, returns client buffers before releasing stream ownership, and
   quarantines permanent arenas until non-fatal idle proof and guard checking
   permit reuse. Run both new independent-stop directions and post-idle reuse.
10. Implemented in the working tree after `e848e0e`, hardware pending: probe,
   suspend, remove, and open-ALSA-handle teardown are sequenced around an
   explicit card-wide quiescence boundary and shared parent lifetime. PCIe
   Relaxed Ordering and No Snoop are disabled and verified, ordered completion
   reads are used, only decoded IRQ sources are unmasked, and the redundant
   full-half comparison is removed.
11. Targeted hardware-proved in the working tree after `4468e93`: EOF
   timestamps come from verified second-half completion, and hardware-frame
   sequences advance through VB2 starvation. Resolve the remaining code-value
   blockers, beginning with PCI device scope and production telemetry cleanup.
12. Validate every retained channel and mode, independent and concurrent
   audio/video stop, suspend/resume, active-stream unbind/remove, delayed
   copies, DMA isolation, allocation guards, and the public DV-timings API.
13. Port by patch subject and order to a fresh Linux branch based on current
   media-next. Generate the next revision, build each boundary, run checkpatch,
   apply the mailbox in isolation, and perform a send-email dry-run.
14. Confirm upstream status of the device-information and colorimetry patches
   before sending or duplicating them.
15. Inventory untracked test artifacts before cleanup; retain reproducers with
   the exact branch, commit, mode, channel, and expected result documented.

## History API operational note

The API retrieval engine was usable read-only, but the live HTTP service was
starved while synchronous session-tail parsing/indexing ran inside an async
request handler. The heavy work should be moved to a worker thread/process or
background job. Large initial backfills should begin after the server binds,
with a progress endpoint that does not depend on the busy event-loop path.
