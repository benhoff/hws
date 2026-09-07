# VDONE frame-ID evidence runbook

This runbook collects complete, bounded evidence without using the kernel log
as an event stream. The detailed IRQ/copy/frame records go to tracefs, and the
capture tool writes JSONL without per-frame console output.

## Build and preflight

Build both the module and userspace tools:

```sh
make -C src
make -C tools
make -C tools hws_frame_id_kms
```

The optional KMS source target requires `pkg-config` and libdrm development
files. It embeds its source-file and pattern-header SHA-256 in the presentation
log; the runner compares these with the bundle and capture pattern identities.
The capture executable also embeds its C source hash, checked against the
manifest, so a stale binary cannot silently supply older validation behavior.
Hardware-free regression
checks are available with:

```sh
make -C tools check
```

Install `trace-cmd`, load the exact in-tree module, and verify that the working
tracked tree is clean and the evidence sources are committed. Unrelated
untracked working files are recorded but do not block a run. The runner rejects
a module `srcversion` mismatch, modified tracked inputs, uncommitted evidence
inputs, an already-active tracefs session, a missing debugfs evidence directory,
or an existing output directory. `--allow-dirty` permits diagnostic collection,
but the resulting bundle deliberately fails validation.

Both source implementations render the same 64-bit record at 20% and 80% of
frame height: preamble, 32-bit ID, complement, and CRC. For definitive evidence,
use [`tools/hws_frame_id_kms.c`](../tools/hws_frame_id_kms.c), which logs
synchronous DRM page-flip completions with their vblank sequences and monotonic
timestamps. The contract follows the kernel's
[DRM page-flip and timestamp API](https://www.kernel.org/doc/html/latest/gpu/drm-uapi.html).

Configure the source output to the mode under test first. Obtain the GPU card,
connector ID, and active CRTC ID with `modetest -c -p`. From a VT or SSH session
with DRM master available, start the source on the explicitly chosen output.
The following IDs are examples and must be replaced with the discovered IDs:

```sh
tools/hws_frame_id_kms /dev/dri/card0 95 72 1200 /var/tmp/ch1-source.jsonl
```

This takes over the selected CRTC using its existing mode, rejects cloned
outputs, and restores the saved framebuffer, viewport, and mode at exit. The
desktop compositor must release DRM master before it can run. Keep the source
running throughout capture and until the evidence runner finishes. The output
file must be readable by the capture user. A live file is allowed: the runner
archives a complete JSONL prefix, capped at 128 MiB, and requires the next
presentation after every captured ID to bound that ID's display interval.

The current source validator requires source and capture on the **same host
and boot**, connected by HDMI loopback. It records and checks the boot ID and
`CLOCK_MONOTONIC` domain. A separate source host requires a calibrated clock
mapping and is not automatically accepted. It also compares source dimensions,
pixelclock, and timing totals with the receiver's configuration.

[`tools/hws_frame_id_source.html`](../tools/hws_frame_id_source.html) remains
useful for decoder calibration. Press **E** to export its bounded rAF/draw
telemetry, visibility, and fullscreen state. Its 100,000-record limit and
discard count are explicit. This is application-render telemetry; it cannot
satisfy the physical-presentation or full-frame pattern gates. Its background
is deliberately not the definitive KMS pattern. A browser-only runner capture, or one
without `--source-telemetry`, is diagnostic and fails the definitive gates.

## Channel-1 native-split proof

The KMS source now fills every active pixel with the versioned
`hws-bw-tiles-v1` pattern: frame-ID/position-dependent 32x16 black/white tiles,
with the two barcode bands overlaid. Capture checks **every active YUYV byte**
against this pattern. No pixels, edges, or rows are masked. Black Y accepts
0–24, white Y 227–255 (full/limited range plus eight levels of tolerance), and
neutral U/V 120–136. Scaling, overlays, unexpected color processing, or stale
pattern binaries must fail calibration; do not widen the tolerances until the
test passes. Padded or non-YUYV layouts are rejected explicitly.

The pre-QBUF poison hashes remain supplementary diagnostics. A changed block
hash is **not** proof that the block was fully overwritten. The content gate
requires `content_checked_bytes == sizeimage` and `content_bad_bytes == 0`
on every frame. This verifies expected visible content within the stated
tolerances, not whether a hardware write occurred for every byte, nor detection
of changes that remain within those tolerances.

Start with a 1,000-frame decoder and whole-frame pattern calibration:

```sh
tools/hws_vdone_evidence.py --run \
  --device /dev/video1 --channel 1 --frames 1000 \
  --source-telemetry /var/tmp/ch1-source.jsonl \
  --label ch1-1080p60-native-calibration
```

Require a pass before the definitive run. Then collect at least ten minutes at
60 frames/s:

```sh
tools/hws_vdone_evidence.py --run \
  --device /dev/video1 --channel 1 --frames 36000 \
  --source-telemetry /var/tmp/ch1-source.jsonl \
  --bundle /var/tmp/hws-evidence/ch1-1080p60-native-001 \
  --label ch1-1080p60-native-definitive
```

The runner produces one immutable bundle containing configuration and counter
snapshots, PCI/V4L2 identity, the binary trace, kernel log for the bounded run,
per-frame content results, source presentation telemetry, a validator summary,
and SHA-256 checksums. Routine
recovery events do not enter `dmesg` after their first occurrence per class,
and per-IRQ/per-frame diagnostics exist only as explicitly enabled trace
events. The runner also rejects a device node whose advertised HDMI channel
does not match `--channel`.

The split cache may be zero in the snapshot before the first stream: it is
populated when the driver arms the DMA window. The validator permits this only
while both `streaming` and `cap_active` are zero. The final cache must equal the
native split divided by 16. Hardware split readbacks must still agree before
and after capture, and both STREAMON and STREAMOFF traces must report that same
native split. A nonzero incorrect cache or an actual register change still fails.

Capture budgets successful QBUF submissions, not just dequeues: it submits no
more than the requested frame count, stops replenishing early, drains all
submitted buffers, and then issues STREAMOFF. The summary must show
`submitted == captured == target_frames` and `outstanding == 0`. Interrupts,
timeouts, error buffers, or queue failures leave the run non-passing; no tail
deliveries are silently excluded. This also works for targets smaller than the
allocated buffer count.

`vdone_timing` uses first/last monotonic **active IRQ** timestamps. With N events
it reports N−1 intervals divided by that timestamp span, plus min/max/p50/p99
intervals and zero-interval count. Generation-zero ignored IRQs are excluded
from this rate but remain in disposition accounting. Matrix rows use this
event count and elapsed span and name the interval-count basis in their notes.
Manifest `elapsed_seconds` remains the separate end-to-end orchestration time,
including setup and trace finalization; it is not the VDONE rate denominator.

Validate a copied or archived bundle again with:

```sh
tools/hws_vdone_evidence.py --validate \
  /var/tmp/hws-evidence/ch1-1080p60-native-001 --channel 1
```

Never edit a bundle after `SHA256SUMS` is created. Preserve a failed or
inconclusive bundle before changing the driver. Revalidation checks the full
recursive file inventory, including bounded anomaly frames, before interpreting
the trace and does not rewrite the bundle. The runner seals every file
read-only and every directory non-writable after creating `SHA256SUMS`; archive
the directory on storage whose retention controls match the claim being made.

## Independent private-ring content observation

The runner enables `hws:hws_vdone_probe` before STREAMON. In the hard IRQ,
before the driver's completion decision or copy, the observer reads the upper
and lower barcode rows directly from the two physical private-ring regions.
Neither address is selected from `toggle` or `completed_half`.

Each observation reads 64 Y samples per row, then reads both rows again:
256 byte loads total. It records the four thresholded 64-bit records, contrast,
absolute row offsets, raw before/after toggles, status, generation, stream
epoch, PCI BDF, start time, and duration. The CPU only reads coherent DMA
memory. The observer allocates no memory, waits for nothing, and emits no
printk. It runs only while its tracepoint is enabled. The initial mapping
trace remains capped at **4,096 observations per channel per stream** (about
34 seconds at 120 VDONE/s). For later anomalies, one preceding observation is
retained in preallocated memory. A same-toggle read emits that preceding
sample, the triggering sample, and at most two following samples. At most
**16 windows / 64 additional records** are emitted. Overlapping or excess
triggers are counted, not emitted as another window.

Maintaining this preceding sample costs 256 byte loads per observed IRQ after
the initial window too. Total read observations are capped at **131,072 per
channel per stream** (about 18.2 minutes at 120 VDONE/s), after which reads stop.
Debugfs records `probe_reads`, `anomaly_windows`, `anomaly_records`,
`anomaly_triggers`, and `anomaly_suppressed`, alongside the caps. The summary
reports exhausted budgets and unobserved same-toggle IRQ pairs explicitly.
There is no allocation, polling loop, sleep, or printk in the IRQ observer.
IRQ/copy/frame tracing and full-frame content checks continue after the cap.

The validator independently decodes preamble/complement/CRC. For adjacent
stable observations spanning 0.65–1.35 nominal half-periods with alternating
toggles, it determines which physical region's decoded ID changed. Only then
does it compare that region to `toggle ^ 1`. It requires at least 32 supporting
changes for **each** region and zero opposing observations. Static/repeated
IDs are neutral; changes in both regions, gaps, changed toggles during a read,
low contrast, or invalid records cannot supply positive mapping evidence.
Observation latency must be below a quarter half-period and duration below an
eighth. Lost trace/probe records fail accounting.

At stream startup, an untouched ring region can still contain a valid barcode
from an earlier source run. Source IDs start randomly, so replacing that old
barcode can look like a backward ID. If the first stable generation-1 probe
contains an ID absent from the current source log, the validator tracks that
initial value per physical region. Its first observed replacement by a recorded
current-source ID is counted in `startup_replacements`, not as mapping support
or a backward-ID failure. `startup_out_of_source_regions` records the initial
number of such regions. This requires matching source boot, clock domain,
backend, source-build digest, and pattern identity. Without that provenance,
backward movement remains a failure.

This exception ends on any different stable value or an unstable observation;
it cannot be reused if old content reappears later. Backward movement between
current-source IDs still fails even at generation 2. All probe records and
delivery-to-ring links remain checked, and startup replacements cannot satisfy
the minimum mapping-transition counts. The source timing and presentation gates
remain separate requirements; recognizing retained content does not turn a
bundle with invalid presentation telemetry into a passing result.

Every delivered frame inside the probe window must also match the independent
upper and lower ring IDs recorded at its two generations; at least 16 such
deliveries are required. The report records the observed generation range and
all inconclusive counts. Sparse barcode reads do **not** prove that every byte
of a region remained stationary, nor does a 34-second observation establish
independent mapping throughout a ten-minute soak. Retain those limits in the
claim. The existing payload, copy, and guard gates remain required.

Source vblank-sequence gaps tell how many refresh intervals the preceding ID
occupied. Repeated captures within that occupancy are consistent with source
repetition; captures exceeding it fail with attribution unresolved. A source
record must precede the captured EOF and the EOF must fall no later than two
refresh periods after that ID was replaced (the explicit receiver/IRQ latency
allowance). KMS completion is evidence about GPU presentation, not a photodiode
measurement or proof of downstream display processing.

Version-3 summaries have separate `independent_mapping`, `source_presentation`,
`anomaly_observation`, and `vdone_timing` results. Older bundles lacking the
full-frame, queue-drain, or bounded anomaly evidence
cannot be promoted to `validated` by the current validator. The matrix writer
records `unproven` when the independent mapping gate fails, and puts probe
coverage and presentation status in the row's notes.

Newly generated summaries also expose `capture_checks`, `provenance`, and
`presentation_failures`. `capture_checks` contains all existing validation
failures except source-presentation checks and committed-input provenance.
It still requires content, copy/guard checks, queue accounting, native mapping,
trace completeness, and the applicable anomaly/IRQ checks. A passing diagnostic
scope does not certify source identity/timing, explain unresolved anomalies,
extend the bounded probe coverage, or establish universal memory safety.
The top-level `result` still combines **all** failures, including presentation
and provenance, so the matrix cannot promote a diagnostic-only run to validated.
These additive fields are optional when reading older version-3 summaries.

The local `local-tests/hws-test-all.sh --with-pattern` wrapper uses this scope
to collect a long content run despite unavailable NVIDIA timing. Its explicit
`--allow-dirty` collection preserves the strict provenance failure and saves
the working-tree patch. Sealed bundles are not edited. This is a diagnostic
workflow, not a replacement for the definitive proof above.

Anomaly windows do not expand the continuous mapping-proof window. Their
classifier reports `consistent_with_missed_or_coalesced_boundary` only for
stable, source-bounded, one-frame advances across a same-toggle interval with
appropriate post-event alternation. It does not distinguish where a boundary
was lost. Unchanged content with a source presentation spanning the interval
is `unchanged_content_source_held`, not proof of a spurious IRQ. Missing source
evidence, torn reads, insufficient following samples, and other ambiguous
cases remain unresolved. End-of-stream/read-budget-truncated windows are
explicitly inconclusive; missing records within an expected window fail
accounting. Compare observer-enabled and ordinary capture behavior when
measuring diagnostic overhead.

This production-path validator intentionally accepts only the native split.
Reproducing the historical exact-midpoint comparison requires a separate,
guarded diagnostic workflow and its own configuration/evidence row; do not
change the production split or bypass the native-split gate to obtain a pass.

## Optional BAR observation

For queue-starvation and recovery investigations, `--queue-diagnostics` adds
the bounded `hws_video_diag` trace and capture-side `queue-events.jsonl`.
The sealed `diagnostics.json` report separates recovery-orphan frames,
midstream empty queues, and deliberate budget draining. Missing/capped data
cannot provide positive attribution. `--buffers 4` and `--buffers 16` permit
controlled comparisons; `--probe-mode off` is explicitly non-validating for
independent mapping and does not weaken that gate. `--irq-latency` requests a
separate irqsoff measurement when supported, with additional observer overhead.
See `local-tests/README.md` for the local comparison runner, trace-field
semantics, caps, module-reload requirement, and interpretation limits.

Use the read-only BAR sampler in a separate diagnostic run. It records only
toggle/status transitions and scheduling gaps, so a 250 us polling interval
does not create a continuous log stream:

```sh
sudo tools/hws_vdone_sampler \
  --bdf 0000:05:00.0 --channel 1 --interval-us 250 --seconds 600 \
  --output /var/tmp/hws-evidence/ch1-toggle-sampler.jsonl
```

Run the ordinary frame-ID capture concurrently. This sampler is intentionally
not part of the primary proof: repeated BAR reads can perturb timing. Any
sampling gap spanning a possible half-period makes the affected interval
inconclusive. If the platform prohibits mapping a bound device's BAR through
sysfs, do not weaken resource protections; use an equivalent kernel trace
observer in a dedicated diagnostic build.

The BAR sampler alone does not observe DMA writes and therefore cannot replace
the private-ring content probe. Compare diagnostic overhead and ordinary
capture behavior when interpreting any new hardware result.

## Expansion order

After the channel-1 1080p60 native result passes:

1. Repeat the same proof on channels 0 and 2.
2. Rerun channel 3 with this harness so all channel evidence is comparable.
3. Run all exposed channels simultaneously, first without and then with
   embedded audio.
4. Test every mode returned by `VIDIOC_ENUM_DV_TIMINGS` on every channel.
5. Repeat on each supported physical PCI ID/revision before broadening the
   claim.

The currently enumerated YUYV modes are 1920x1080p60/p30, 1280x720p60,
720x480p59.94, 720x576p50, 640x480p60, 800x600p60, 1024x768p60,
1280x768p60, 1280x800p60, 1280x1024p60, 1360x768p60, 1440x900p60, and
1680x1050p60.

Every tuple gets its own evidence bundle and matrix row. The largest/fastest
mode, 30 Hz, 50 Hz, and splits nearest a scanline boundary also receive an
extended soak. A PCI ID for which physical hardware is unavailable remains
`unavailable`; it must not inherit another ID's result.

## Publishing a result

Copy one row per run into
[`doc/evidence/vdone-matrix.csv`](evidence/vdone-matrix.csv). Record the
artifact URI and `SHA256SUMS` digest. Use only the scoped wording defined in
[`doc/vdone-semantics.md`](vdone-semantics.md).

Generate a reviewed CSV row directly from a bundle to avoid transcription
errors:

```sh
tools/hws_vdone_matrix.py \
  /var/tmp/hws-evidence/ch1-1080p60-native-001 \
  --evidence-id HWS-8504-CH1-1080P60-NATIVE-001 \
  --artifact-uri https://artifacts.example/hws/ch1-1080p60-native-001
```

Inspect the printed row, then repeat with `--append`. The tool verifies every
bundle checksum, reruns the current validator, refuses to mark a failed result
as `validated`, and rejects duplicate evidence IDs.
