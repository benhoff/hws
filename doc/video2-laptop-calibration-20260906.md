# Laptop-to-video2 calibration result

Run: `87baed29-8edd-4e81-9bf7-d59e71f27bc6`, captured
2026-09-06 23:50 UTC. The user selected video2 after the video3 attempt.

- Sealed evidence on father:
  `/tmp/hws-remote-87baed29-8edd-4e81-9bf7-d59e71f27bc6/bundle`.
- Source/clock logs on princess:
  `/tmp/hws-video2-laptop-calibration-20260906`.
- Reviewed `summary.json`, `diagnostics.json`, `stats-after.txt`,
  `config-after.txt`, `manifest.json`, and the local source/clock reports.
  All 20 entries in the bundle's `SHA256SUMS` passed verification on father.
  The sealed bundle was not edited or reclassified.

## Result

**All diagnostic capture and presentation gates passed.** Overall `result=fail`
has exactly two causes: the tracked driver tree was dirty, and evidence inputs
were uncommitted. There are no capture-check or presentation failures.

| Check | Observed result |
| --- | --- |
| Input/profile | video2, exact 1920×1080p60, 16 buffers, full probes, queue diagnostics, no injected delay |
| Content | 1,000 captured, 1,000 valid; zero decode/content/sequence/payload/poison/flagged errors |
| Independent half mapping | PASS, 2,009 raw probe records, all 1,000 deliveries linked, zero contradictions |
| Source presentation | PASS, 705 source presentations, all 1,000 capture associations inside their valid time intervals |
| Clock mapping | PASS, 2,968 samples, maximum uncertainty bound 301,446 ns, minimum exchange RTT 314,604 ns |
| VDONE | 2,009 events over 16.7337 seconds, 119.9974 events/s |
| Loss/recovery | Zero duplicate, overlap, continuity-gap or other recovery events; zero no-buffer frames or partial recycles |
| Failure counters | Zero fatal dispositions, queue failures, deadline misses, guard errors or ring corruption |
| Late-toggle observation | Enabled, zero windows, `not_observed` because no duplicate occurred |
| Evidence caps | 2,009/4,096 initial probes and 7,005/32,768 queue diagnostic records; zero diagnostic suppression |

One initial independent probe was unstable/undecodable; the independent validator
still linked all delivered frames and had 498/497 supporting transitions in the
two physical regions, exceeding its required support with zero contradictions.

The 504 repeated captured IDs are all consistent with source-held presentations.
There are zero repeats exceeding source occupancy. This is successful capture
of the presented content, not proof of a distinct source ID every refresh.

Recorded configuration matches the intended loaded build:

- Loaded and built module srcversion: `2872F13A805266B6EBE1D34`.
- Module SHA-256: `68d7e4e2963c0102e76ac296b6f65b9ca1970671d301f4a37b0bfd1e86996c17`.
- NVIDIA vblank `N`, late-toggle probe `Y`, source-transition checks `Y`.
- Driver, module parameters and source renderer were not changed for this run.

## Interpretation and next exposure

The laptop-to-video2 path is qualified for further diagnostic collection under
this configuration. This short run did not reproduce the duplicate-toggle
condition. It cannot establish that NVIDIA causes the video3 recoveries, because
the capture channel also differs, nor establish that the condition is fixed.

Continue on video2 as the user requested. Prefer repeated 1,000-frame runs with
16 buffers/full diagnostics and unique output directories, inspecting every
sealed result. A single 9,000-frame run would exceed the per-stream initial
probe and queue-diagnostic caps, reducing evidence for later events. Any
duplicate should be examined with queue availability, late raw register reads,
source/DMA IDs and delivered-frame content. Preserve the dirty provenance
failure separately; do not weaken the validator to obtain an overall PASS.

If a source-only comparison is later needed, both sources must be tested on
the same capture input under matched settings. No hardware IRQ-assertion
timestamp is available, so even recurrence with the laptop would not by itself
distinguish receiver/toggle behavior from interrupt delivery.
