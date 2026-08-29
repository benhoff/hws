# HWS and Linux upstream history through v19

Status date: 2026-08-29

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
  DMA base and CPU copies of proved-complete halves, but this has not yet been
  integrated into the production driver or validated across all supported
  channels and modes.

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
| Colorimetry | Passed for measured mode | Measurements support the metadata correction |
| Native half-ring diagnostic | Promising, diagnostic-only | Strong channel 3/1080p60 evidence; not integrated or generalized |
| v19 submission readiness | Blocked | Production video DMA architecture must change and be revalidated |

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
- Prompt VCAP clearing does not replace a positive DMA-idle proof before DMA
  memory is returned or released.
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
6. Centralize stop and quiescence so STREAMOFF, error recovery, suspend,
   remove, and probe unwind all prove DMA idle before releasing memory.

## Prioritized resume plan

1. Preserve the five local diagnostic commits and their evidence by pushing or
   backing up the dangerous branch. Do not merge its experimental driver into
   production.
2. Keep `audio-upstream-v19` immutable as the reference. Create a clearly
   named production DMA-safety successor branch from its exact tip.
3. Implement the guarded fixed native half-ring and CPU two-half assembly on
   the successor branch.
4. Add explicit W1C ambiguity, phase, generation, copy-deadline, and fail-closed
   handling.
5. Validate every supported channel and mode, concurrent audio/video,
   STREAMOFF, suspend/resume, active-stream unbind/remove, delayed copies, DMA
   idle, and allocation guards.
6. Port by patch subject and order to a fresh Linux branch based on current
   media-next. Generate the next revision, build each boundary, run checkpatch,
   apply the mailbox in isolation, and perform a send-email dry-run.
7. Confirm upstream status of the device-information and colorimetry patches
   before sending or duplicating them.
8. Inventory untracked test artifacts before cleanup; retain reproducers with
   the exact branch, commit, mode, channel, and expected result documented.

## History API operational note

The API retrieval engine was usable read-only, but the live HTTP service was
starved while synchronous session-tail parsing/indexing ran inside an async
request handler. The heavy work should be moved to a worker thread/process or
background job. Large initial backfills should begin after the server binds,
with a progress endpoint that does not depend on the busy event-loop path.
