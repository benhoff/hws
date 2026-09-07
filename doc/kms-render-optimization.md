# Faster CPU rendering for the KMS frame-ID source

## Physical qualification result

The subsequent laptop-to-video2 run
`86a7c337-d6db-42a0-8bd6-7100cb078353` qualified the optimized source with
16 buffers and full diagnostics. All 20 sealed bundle checksum entries passed
on father at `/tmp/hws-remote-86a7c337-d6db-42a0-8bd6-7100cb078353/bundle`;
local logs are `/tmp/hws-video2-fast-source-calibration`.

- All 1,376 source presentations were valid. Each of the 1,375 successive
  presentation sequence increments was exactly one; intervals were
  16.659–16.688 ms (median 16.674 ms). No source-held refreshes occurred.
- Actual render times: median 1.093 ms, p95 1.628 ms, p99 1.976 ms,
  maximum 8.527 ms. The source met every observed refresh despite this
  larger real-run maximum than the memory-only benchmark.
- All 1,000 captured frames passed content checks, with zero repeated IDs.
  All 1,000 deliveries linked to independent DMA-region evidence, with zero
  mapping contradictions or ambiguous intervals.
- Zero duplicate-toggle recoveries, other recoveries, no-buffer frames,
  partial recycles, deadline misses or guard errors. Late-toggle observation
  was enabled but had no triggering events.
- Source timing and continuous clock mapping passed: maximum clock uncertainty
  314,532 ns, all 1,000 temporal associations inside valid intervals.
- The overall FAIL contains only dirty tracked-tree and uncommitted-input
  provenance failures. The sealed result was not modified.

Increasing image updates from about 30/s to one each refresh did not trigger
duplicates in this trial. That establishes a clean fast-source trial, not a
root cause for NVIDIA-to-video3 events. Source, capture input and capture-host
rendering workload still differ in that comparison.

## Implementation and pre-capture validation

Implemented 2026-09-06 to remove the laptop's measured 21–25 ms rendering
bottleneck at 1080p60. The source had usually presented a new ID every second
refresh. This change optimizes rendering; it does not inject duplicate toggles
or modify the capture driver.

`hws_frame_id_kms.c` now evaluates the existing pattern once per horizontal
color run. A scratch row in ordinary RAM is reused until a 16-pixel tile-row
boundary or barcode-band transition requires a new row. Each active row is
copied into the destination mapping, respecting framebuffer pitch. Scratch
storage is allocated once before presentation starts. No framebuffer reads,
per-frame allocations or full-frame precomputed image cache are needed.

The pixel pattern, CRC/ID encoding and barcode geometry are unchanged. The
source still uses two buffers, waits for each synchronous page flip before
reusing a buffer, and records actual render, submission, callback and presentation
times. Timing/clock validators are unchanged. The launcher requires matching
source/pattern hashes on both hosts, so both source builds must be updated.

## Measured CPU rendering performance

On princess, 100 samples of each renderer were alternated on a temporary
1920×1080 DRM dumb-buffer mapping, pitch 7,680 bytes. The benchmark allocates
an unattached framebuffer; it does not acquire DRM master, set a mode, flip a
display or start capture.

| Renderer | Median | 95th percentile | Maximum |
| --- | ---: | ---: | ---: |
| Original per-pixel reference | 19.660 ms | 24.362 ms | 27.837 ms |
| Row/run implementation | 1.043 ms | 1.215 ms | 1.410 ms |

Median CPU draw time improved about 19×. These are CPU render durations,
not presentation measurements or a scheduling guarantee. They provide ample
rendering headroom within a 16.67 ms refresh; actual per-refresh presentation
must be checked in the next source/capture telemetry.

Reproduce the equivalence test and optional memory-only benchmark:

```bash
make -C tools test_frame_id_render
tools/test_frame_id_render
tools/test_frame_id_render --bench /dev/dri/card1 100
```

`--bench heap 100` is an alternative CPU-memory benchmark; its performance is
not interchangeable with a DRM mapping. Neither benchmark requires a VT switch.

## Validation and next capture

- Exact XRGB comparison against the per-pixel specification passed for 13
  geometries and six IDs, including odd sizes, barcode rounding, high ID bits,
  framebuffer padding and scratch/allocation guards.
- The existing raster-to-YUYV capture-decoder test passed for 13 modes and
  three IDs each, retaining the content-corruption checks.
- AddressSanitizer/UndefinedBehaviorSanitizer exact-raster tests passed.
- The 26 local source-timing and observer regressions passed.

Before broader comparison, collect a fresh 1,000-frame video2 calibration using
the existing 16-buffer/full-diagnostic profile and a new output directory:

```bash
python3 /home/hoff/swdev/hws/tools/hws_remote_source.py --run --host father --channel 2 --frames 1000 --buffers 16 --queue-diagnostics --probe-mode full --require-vblank-off --allow-dirty --output /tmp/hws-video2-fast-source-calibration
```

Check render percentiles, advancing presentation sequences (normally +1),
approximately 16.67 ms presentation intervals, and remaining source holds.
Also check capture contents, independent DMA mapping, queue availability,
clock qualification and duplicate-toggle evidence. Keep dirty provenance
separate. This is a new source-workload profile: the prior slower-source
calibrations do not establish its physical capture behavior.
