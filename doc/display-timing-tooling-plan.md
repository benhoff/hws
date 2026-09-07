# HWS source and capture timing tooling

Implementation update: the clock collector, bounded-rate mapper, frame/anomaly
integration and remote launcher are now implemented. See
[cross-host timing usage and measured results](cross-host-timing.md).
The design discussion below records the investigation and its original staging.

Investigation: 2026-09-06. Implementation baseline: `4706e64` on princess and
father. Recommended existing-hardware route: Intel Darter HDMI output into an
HWS input on father, with continuous, independently measured clock mapping over
wired Ethernet. The required observation is GPU presentation of the encoded
source frame, followed by receiver/driver handling of that same frame.

## What the measurements must establish

The canonical requirements remain [VDONE semantics](vdone-semantics.md) and the
[evidence runbook](vdone-evidence-runbook.md). At 1080p60 the nominal frame is
16.667 ms; the native split has historically produced about 120 VDONE/s, or
8.333 ms between half completions. That cadence is a configuration-specific
observation, not a universal hardware contract.

| Question | Required evidence | Clock mapping needed? |
| --- | --- | --- |
| Was a complete, correctly paired frame delivered? | Full-frame pattern, both IDs, private-ring observation, copy/guard records | No, capture-local |
| How many refreshes did source ID X occupy? | Consecutive real flip sequences and source IDs, including the next presentation | No, source-local |
| Are repeated captures consistent with source occupancy? | Matching run/IDs and refresh counts; enough source log before/after capture | Counts can be compared without mapping, but temporal attribution still needs it |
| Was ID X captured within its presentation window? | Source presentation interval mapped into capture time, with uncertainty | Yes |
| What is source-to-capture latency? | Mapped source timestamp and matching capture timestamp; report a range | Yes |
| Where was time spent after the capture IRQ? | IRQ/ack, worker, copy, VB2 and dequeue/requeue timestamps | No, capture-local |
| Was an IRQ physically late or never asserted? | Independent hardware assertion/toggle observation | Software timestamps alone cannot decide |

`src/hws_irq.c` assigns the V4L2 timestamp from the recorded completion IRQ
timestamp. It is an EOF-associated software timestamp, not a hardware HDMI
arrival measurement. Existing diagnostics on father additionally distinguish
IRQ entry/ack, worker delay, processing wall/CPU time, and queue starvation.
Keep these endpoints explicit in any reported latency.

## Verified machine state

### Intel laptop (princess / Darter Pro)

- Comet Lake-U UHD, i915. Internal N156HCA-EAB eDP panel, 1920x1080 at
  approximately 60.008 Hz. `drmWaitVBlank`, get-sequence and queued-sequence
  events worked in a live test.
- Later inspection found HDMI-A-2 active at 2560x1440, 241700 kHz,
  totals 2720x1481. Connector 135, CRTC 84, card1 in this boot.
- The new probe collected 121 HDMI events / 120 intervals: mean
  16.6668948 ms, min 16.657337 ms, max 16.676935 ms, no sequence gaps.
- Internal CRTC 59 also passed: mean 16.6648158 ms, no sequence gaps.
- The reported timestamp followed userspace event receipt by approximately
  0.187–0.383 ms on HDMI and 0.492–0.702 ms on eDP. Preserve this signed
  difference; do not call it negative scheduling latency or clamp it to zero.
- KWin advertises `wp_presentation` v2 with `CLOCK_MONOTONIC`. Actual Wayland
  feedback flags and actual Intel KMS page-flip completions have not been tested.
- HDMI wiring into HWS and the target 1080p60 HDMI mode are not yet qualified.
  An internal-panel result does not qualify another connector; a 1440p HDMI
  result does not qualify the final 1080p60 receiver path.

The Linux [DRM API](https://www.kernel.org/doc/html/latest/gpu/drm-uapi.html)
defines the clock and event interfaces. Sequence-event timestamps refer to the
display engine's refresh epoch, not userspace callback receipt. Timestamp
resolution is not an accuracy guarantee or an optical measurement.

### Capture host (father)

- TITAN RTX using nvidia-drm; four HWS nodes. Current read-only queries found
  video0/video1 without signal, video2 at 720p60, video3 at 1080p60.
- Its local runbook identifies TITAN HDMI connector 827 / CRTC 200 as the
  loopback into video3. The HDMI EDID identifies an intermediary/display as
  `UHDMV360INS`; preserve the actual cable/switch route in future manifests.
- A fresh probe on CRTC 200 returned `DRM_CAP_TIMESTAMP_MONOTONIC=1` but
  `drmCrtcGetSequence=-1`, errno 95 (`EOPNOTSUPP`). A capability bit alone
  cannot qualify usable timing.
- Retained source logs from `local-tests/all-tests.a09lv6/pattern/source.jsonl`
  contain advancing timestamps but frozen page-flip sequence 0.
- The retained vblank-enabled experiment reports frozen sequence 2,
  presentation timestamps 498–515 ms before submission, and NVIDIA's
  unsupported-platform warning. Do not repeat boot-parameter changes as the
  solution to this tooling problem.
- Father's checkout contains substantial uncommitted queue/IRQ diagnostics and
  startup-validator fixes absent from princess. Build further capture-side work
  on that reviewed work, preserving its tests, rather than copying princess's
  older validator over it. This investigation did not modify father's checkout.

History: [Darter source discussion](https://codex.home.benhoff.net/sessions/01a07781-3891-7d83-b2a1-d0d61ae873d4?turn=1),
[clock mapping and proposed 0.5 ms target](https://codex.home.benhoff.net/sessions/01a07781-3891-7d83-b2a1-d0d61ae873d4?turn=2),
[recoveries with NVIDIA vblank disabled](https://codex.home.benhoff.net/sessions/01a0742f-bb05-7e00-bce0-537209f77afb?turn=40).
The history search had 89 indexed sessions / 1247 turns in the selected root,
no pending reindex, but reported import/empty-session caveats. Historical
claims are distinguished above from fresh measurements.

## Implemented first step: read-only DRM preflight

[hws_drm_timing_probe.c](../tools/hws_drm_timing_probe.c) enumerates connector
routes and records a bounded sequence-event sample as JSONL. It never calls
`drmSetMaster`, modesets, or submits a page flip. Run against an active output:

```sh
make -C tools hws_drm_timing_probe
tools/hws_drm_timing_probe /dev/dri/card1 --list
# Replace 84 with the CRTC associated with the intended HDMI connector.
tools/hws_drm_timing_probe /dev/dri/card1 84 121 /tmp/hdmi-timing.jsonl
```

The output must be a new file. Device access is required. Samples are bounded
to 2–3600, with a 120-second overall loop deadline and 2-second event waits.
The deadline does not preempt an ioctl blocked inside a broken driver.
Exit 0 means only that this sequence stream passed the preflight; exit 1 means
unqualified/failed and exit 2 indicates usage errors. Mode changes detected at
the final check invalidate the sample; a change away and back between checks
is not detectable by this probe. No page-flip or capture proof is implied.

It checks advancing counters/timestamps, interval agreement within 25% of one
nominal frame, and timestamp/receipt separation within one frame. These are
coarse sanity thresholds, not the clock-mapping accuracy target. Counter gaps
are recorded as unobserved sequences, not automatically blamed on hardware.
Both positive and negative receipt offsets are preserved. Interrupted, short,
stale, frozen, unsupported, or malformed observations cannot report usable.

Hardware-free analysis cases cover frozen NVIDIA counters, zero/stale timestamps,
sequence/time disagreement, valid gaps, and Intel's negative receipt offset.
`make -C tools check` passed all C checks and 46 Python tests.
Temporary live samples: `/tmp/hws-intel-crtc-timing.jsonl` and
`/tmp/hws-intel-hdmi-timing.jsonl` on princess; latest NVIDIA probe artifacts in
`/tmp/hws-drm-timing.tNFBUW/` on father. These are diagnostic artifacts, not
sealed VDONE evidence bundles.

## Remaining implementation, in order

### 1. Qualify the real Intel source path

Use the existing `hws_frame_id_kms` and `hws-bw-tiles-v1` pattern. Wire the laptop
to the chosen HWS input and select advertised 1920x1080p60 with 148500 kHz,
2200x1125 totals. Record connector/CRTC/EDID and receiver timings; reject clones,
scaling, overlays and unknown routing. Temporarily releasing KWin's DRM master
and restoring the desktop needs an explicit run action and cleanup/watchdog,
following father's existing local launcher design.

Collect actual page flips for at least 1000 captured frames before a soak.
Check non-frozen sequences, monotonic source timestamps, frame IDs, pattern
digests, and full-image capture. Log render-start/end and flip-ioctl entry/exit
alongside existing submitted/presented/callback fields so source rendering
misses can be distinguished from kernel-event delivery delay. Use ordinary
synchronous flips; targeted flips and async tearing are unnecessary.

Review the current validator's unconditional `presented_ns <= callback_ns`.
The sequence probe demonstrates that receipt and scanout timestamp epochs can
differ. It does not yet demonstrate the exact page-flip behavior. First collect
real flip evidence and inspect the driver semantics, then define a documented,
mode-dependent bound and regression tests if a correction is needed. Never
substitute callback time for presentation time or broadly accept stale events.

A Wayland backend is optional future work: it would need tested hardware-backed
presentation feedback, exact unscaled pattern output and output identity. Its
mere advertisement is insufficient for the existing strict KMS contract.

### 2. Add an independent clock mapper

Proposed tools: `tools/hws_clock_probe.py` for bounded timestamp exchanges and
`tools/hws_clock_mapping.py` for offline interval fitting/validation. Use a
persistent connection started over SSH first (no additional listening service),
with request IDs and a random shared run ID. Measure whether its uncertainty
meets the target; a dedicated UDP exchange is a later optimization if buffering
prevents it. SSH is transport/control, not a synchronized start-time guarantee.

For each exchange record source send/receive times s1/s4 and father receive/send
times f2/f3, all from that host's `CLOCK_MONOTONIC`. At locally constant offset
`father - source`, nonnegative one-way delays bound the offset by:

```text
f3 - s4 <= offset <= f2 - s1
```

The interval includes asymmetric network and userspace delays; do not assume
the midpoint is exact. For drift, fit a feasible affine map
`F(s) = a * (s - s0) + f0` constrained by `F(s1) <= f2` and `F(s4) >= f3`.
Preserve a feasible envelope rather than just a least-squares point estimate.
Define conservative clock-rate/curvature and sample-age bounds explicitly;
finite packet samples cannot rule out arbitrary rate changes between samples.
Inflate uncertainty for timestamp quantization and interpolation. Empty feasible
sets, excessive gaps or excursions must invalidate a calibration segment.

Sample continuously before/during/after capture (initial proposal: 10 exchanges/s,
60-second preflight, then throughout the 10-minute run). Record both boot IDs,
host identities, monotonic/boottime/realtime checks, run ID, sequence numbers,
timeouts, raw four-timestamp samples, fit method/version, drift envelope, validity
range and error bounds. A suspend/reboot or clock discontinuity splits/invalidates
the segment; never extrapolate indefinitely from a pre-run ping.

The initial target is **maximum mapping half-width <= 500 microseconds** over
the capture window. This follows the prior discussion, not a measured guarantee.
Even a qualifying global bound cannot decide every event near a boundary.
Do not estimate the clock offset from video latency: doing so would absorb the
latency under investigation into the calibration.

Father exposes wired PTP clocks; princess currently exposes only `iwlwifi-PTP`,
with no registered PTP clock on its r8169 wired NIC. This does not establish a
usable hardware-PTP path between them. Inspect NIC timestamp capabilities before
choosing a PTP implementation or buying hardware. A PTP/realtime clock still
requires a measured relation to each host's monotonic log timestamps. See the
[Linux PTP interface](https://www.kernel.org/doc/html/latest/driver-api/ptp.html).

### 3. Extend evidence and validators without weakening existing gates

Add an explicit schema version and optional `--clock-evidence` input to the
runner. Archive source log, both source-build/pattern identities, raw clock
exchanges and derived map before sealing the bundle. Bound file sizes and
verify the complete inventory. The capture host must archive the remote source
build identity; its local source hash is not evidence of what ran on princess.

Split source validation into source-local integrity/refresh occupancy and
cross-host temporal association. Preserve the same-host/boot path. A missing
map leaves cross-host timing inconclusive and the definitive overall gate
non-passing. Refactor `validate_anomalies` too: it currently compares source
times directly with capture-local probe timestamps when explaining held content.
Changing only `validate_source` would leave false cross-host attribution there.

Return an interval for every mapped presentation. For capture time c and mapped
source time [lo, hi], report latency [c-hi, c-lo]. Apply the existing EOF/source
window and two-frame receiver allowance to all admissible mapped times:
definitely inside, definitely outside, or ambiguous. Do not widen acceptance
windows until a run passes. Preserve source/capture-local evidence when temporal
association is ambiguous, while keeping the overall result non-passing.

Test asymmetric delay, drift, integer-nanosecond precision at long uptime,
outliers, missing samples, reboot/suspend, stale mappings, non-overlapping run
IDs, 32-bit flip-sequence wrap, frozen counters, and EOF exactly at uncertain
boundaries. Add synthetic full bundles covering both mapped success and
inconclusive failure. Preserve father's existing diagnostic/provenance split.

### 4. Orchestrate and report

A future `hws_remote_source.py` launcher should preflight both hosts, start clock
sampling, start the Intel pattern, verify receiver lock, capture 1000 calibration
frames, drain, and retain the next source presentation after the final captured
ID. Copy only complete source records, collect post-run clock samples, validate,
seal and restore displays even after disconnect/failure. Only then offer the
36000-frame run and channel/mode expansion. Do not silently choose a different
live input or stop another consumer.

Report source-held refreshes, capture-local cadence, mapped source-to-EOF latency
ranges, IRQ-to-worker/copy/dequeue timing, queue-starvation categories, and
ambiguous associations separately. A same-host supported GPU remains the simpler
alternative if suitable hardware becomes available, but the tested TITAN path
does not currently provide it.
