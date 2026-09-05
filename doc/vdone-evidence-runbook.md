# VDONE frame-ID evidence runbook

This runbook collects complete, bounded evidence without using the kernel log
as an event stream. The detailed IRQ/copy/frame records go to tracefs, and the
capture tool writes JSONL without per-frame console output.

## Build and preflight

Build both the module and userspace tools:

```sh
make -C src
make -C tools
```

Install `trace-cmd`, load the exact in-tree module, and verify that the working
tracked tree is clean and the evidence sources are committed. Unrelated
untracked working files are recorded but do not block a run. The runner rejects
a module `srcversion` mismatch, modified tracked inputs, uncommitted evidence
inputs, an already-active tracefs session, a missing debugfs evidence directory,
or an existing output directory. `--allow-dirty` permits diagnostic collection,
but the resulting bundle deliberately fails validation.

Display [`tools/hws_frame_id_source.html`](../tools/hws_frame_id_source.html)
fullscreen on the HDMI source output. Set that output to the mode under test.
The page renders the same 64-bit record at 20% and 80% of frame height. Each
record contains a preamble, 32-bit frame ID, complement, and CRC.

## Channel-1 native-split proof

Start with a 1,000-frame decoder calibration:

```sh
tools/hws_vdone_evidence.py --run \
  --device /dev/video1 --channel 1 --frames 1000 \
  --label ch1-1080p60-native-calibration
```

Require a pass before the definitive run. Then collect at least ten minutes at
60 frames/s:

```sh
tools/hws_vdone_evidence.py --run \
  --device /dev/video1 --channel 1 --frames 36000 \
  --bundle /var/tmp/hws-evidence/ch1-1080p60-native-001 \
  --label ch1-1080p60-native-definitive
```

The runner produces one immutable bundle containing configuration and counter
snapshots, PCI/V4L2 identity, the binary trace, kernel log for the bounded run,
per-frame content results, a validator summary, and SHA-256 checksums. Routine
recovery events do not enter `dmesg` after their first occurrence per class,
and per-IRQ/per-frame diagnostics exist only as explicitly enabled trace
events. The runner also rejects a device node whose advertised HDMI channel
does not match `--channel`.

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

## Independent toggle observation

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
