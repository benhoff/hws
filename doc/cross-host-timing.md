# Cross-host HWS timing

The Intel laptop is the KMS source; father captures `/dev/video2`. Clock exchanges
use each machine's `CLOCK_MONOTONIC`. Frame IDs, source/pattern digests, both boot
IDs and the shared run ID bind the evidence together. No wall-clock subtraction
or network-symmetry assumption is used.

## Verified on 2026-09-06

- Wired route: princess `enp38s0f1` (192.168.1.202) to father (192.168.1.25).
- Selecting laptop HDMI-A-2 mode 12 produced matching 1080p60 on video2:
  148500 kHz, 2200x1125 totals. The original 1440p desktop mode was restored.
- Wi-Fi SSH clock exchanges: conservative uncertainty bound about 1.316 ms.
- Wired SSH: 0.704 ms at 20 Hz, 0.599 ms at 100 Hz; both inconclusive against
  the 0.5 ms target.
- Wired UDP at 100 Hz: 2918 samples over 30 seconds, minimum exchange RTT
  0.424 ms, maximum conservative uncertainty bound **0.357399 ms**: pass.
- The UDP peer is launched over authenticated SSH, bound to the SSH server's
  address on an ephemeral port, and accepts only the SSH client's IP and a
  random session token. SSH EOF/control input or its one-hour deadline stops it.
  There is no installed daemon or firewall change.

This qualifies the tested clock-exchange interval under the model below. A DRM
sequence test alone does not establish flip-event timestamps or optical timing.

### Video2 calibration: run 33ad5128-9d57-4d1f-86d5-ef8dcb2223c1

The 1000-frame diagnostic run completed with all frames valid, no decode/content
errors, no recovery events, and independent DMA-region mapping passing. VDONE
measured 119.998 Hz over 2017 events. Concurrent clock mapping passed at a maximum
conservative uncertainty of 0.330879 ms. All 1000 frame associations were inside
their source windows; none were ambiguous or outside.

The original sealed report failed presentation validation because the validator
incorrectly required callback receipt after the reported scanout timestamp. All
675 callbacks arrived 0.365–0.643 ms before scanout, within the mode's 0.667 ms
vertical blank. The corrected check below uses the DRM timestamp contract and
does not shift the raw timestamps. Reanalysis must be saved separately from the
original sealed bundle. Dirty/uncommitted-input provenance remains non-passing.

Rendering took a median 25.39 ms, so source updates usually occurred every two
refreshes (about 30 new IDs/s on a 60 Hz output). The 499 repeated capture IDs
were supported by recorded source holds. This run therefore does not qualify
60 distinct source patterns per second. The aggregate source-scanout-to-capture
completion bounds span 16.386–66.909 ms, including the age of held/repeated IDs;
they are not a measurement of receiver latency alone.

## Clock-only test

Run on the laptop; no sudo or display takeover is needed:

```sh
python3 tools/hws_clock_probe.py --host father --transport udp --hz 100 \
  --seconds 60 --output /tmp/hws-clock-check.jsonl
python3 tools/hws_clock_probe.py --analyze /tmp/hws-clock-check.jsonl
```

Output paths must be new. Exit 0 means the measured full-span conservative bound
is at most 500 us and the largest sample gap is at most 250 ms. Exit 1 means
inconclusive or failed; raw records remain available. `--transport ssh` provides
the persistent-pipe alternative. Both paths use the same mathematical checks.
Acquisition is capped at 100000 samples and the reader at 64 MiB. Requested
durations must be 1–3600 seconds. A deliberate SIGTERM gracefully finalizes the
actual covered interval; a transport error or exhausted budget is non-passing.

## Pattern calibration from the desktop terminal

Build and integrate the same source files on both hosts first. Run as the laptop's
desktop user, not as root. It authenticates local sudo and father's sudo before
switching the laptop's VT. Enter passwords only into the ordinary sudo prompts.
The remote capture preflight must pass before the display switch. It reads
debugfs and tracefs through sudo, including on root-only mounts, and checks the
loaded module and tracing state without configuring timings or starting capture.
To check father separately from its terminal:

```sh
python3 /home/hoff/swdev/hws/tools/hws_vdone_evidence.py --preflight-only --device /dev/video2 --channel 2 --allow-dirty
```

If retrying a failed calibration, choose a new output directory; old evidence
is retained. A failed clock qualification is transferred with the source log
and remains non-passing in the remote validator.

```sh
python3 tools/hws_remote_source.py --run --host father --channel 2 \
  --frames 1000 --allow-dirty --output /tmp/hws-video2-calibration
```

The current hardware defaults are card1, connector 135, CRTC 84, HDMI-A-2, KScreen
mode 12, temporary VT3. They are machine/boot-specific; use `--help` and
`hws_drm_timing_probe CARD --list` to update them after changes. The source checks
the connector/CRTC association and rejects clones; the launcher checks the KMS
source's actual mode before starting capture. It does not change driver modules
or NVIDIA parameters.

`--allow-dirty` is explicit because both checkouts contain development changes.
The strict provenance gate still fails on uncommitted inputs; this command is a
diagnostic calibration, not a way to publish a validated result. Father keeps its
existing capture-check/provenance/presentation reports. Review/commit evidence
inputs and remove `--allow-dirty` for definitive collection after calibration.
Do not proceed to `--frames 36000` until the relevant calibration gates pass.

The launcher starts continuous clock exchanges, selects 1080p60, starts the KMS
pattern with `HWS_RUN_ID`, and starts the remote evidence runner. After capture
and trace finalization, the runner writes `capture-complete.json` and waits up to
120 seconds for finalized source/clock transfer. The launcher retains successor
presentations, stops the source, takes post-source clock samples, transfers files
atomically, then publishes the readiness marker containing the run ID.

Local output includes `run.json`, source JSONL/log, raw clock JSONL/log and the
derived mapping report. The remote path is recorded in `run.json`; the sealed
bundle contains source presentations and `clock-exchanges.jsonl` in SHA256SUMS.
The bundle summary's `source_presentation` includes mapping metadata, temporal
association counts and source-to-completion-IRQ latency bounds.

The root source helper owns the source child and restores the original VT on
normal completion, parent-pipe closure, signals or its timeout. The launcher
restores the original KScreen mode on normal/error cleanup. Abrupt loss of the
launcher can leave the selected 1080p mode after the helper restores the VT;
the saved original KScreen configuration is in `run.json`. Failed transfers or
collection keep an incomplete bundle rather than presenting a successful seal.

## Model and validation

For source send/receive s1/s4 and capture receive/send f2/f3, constant offset is
bounded by `[f3-s4, f2-s1]`. The implementation generalizes this with a
**1000 ppm maximum relative rate difference** and **5000 ns timestamp slack**.
It intersects all sample constraints using forward/backward interval envelopes.
Unlike a single affine fit, it permits bounded time-varying drift. These are
declared assumptions, not physical accuracy established by software alone.

Integer nanoseconds avoid precision loss at long uptime. Clock-read brackets,
monotonic/boottime/realtime offsets, sample identity and order detect malformed
data and discontinuities. Missing summaries, excessive gaps, extrapolation,
inconsistent constraints or uncertainty above 500 us cannot qualify a timestamp.
No calibration is inferred from the video latency being measured.

For mapped source presentation `[lo, hi]` and capture time `c`, latency is
`[c-hi, c-lo]`. A frame passes temporal association only when **all** admissible
mapped times satisfy the existing source/EOF window. Definite violations fail;
overlapping uncertain boundaries are reported ambiguous and remain non-passing.
The same mapping is used by anomaly attribution, including source-held frames.
Same-host/boot evidence keeps the existing exact-domain path.

The V4L2 timestamp is associated with the driver's completion IRQ. Reported
latency includes HDMI/receiver/IRQ effects, and does not isolate physical HDMI
arrival or physical interrupt assertion. `callback_ns` remains a separate source
measurement. The [DRM timestamp contract](https://www.kernel.org/doc/html/v6.17/gpu/drm-kms.html#c.drm_crtc_funcs)
defines scanout start at the end of vblank, which may be in the future when the
callback arrives. For the recorded progressive mode, callbacks may lead scanout
by at most `(vtotal-height)*htotal/pixelclock`, rounded up to nanoseconds, plus
1 us for the legacy event timestamp representation. Submission must still
precede both callback and scanout. Sequence, cadence, mode and clock-identity
checks remain mandatory; frozen or stale timestamps cannot pass this change.
The report records signed callback-minus-scanout offsets and the mode-derived
limit. No correction is applied to source timestamps.

## Tests

```sh
make -C tools check
```

The new tests cover asymmetric delay, drift and long uptime, calibration gaps,
reboot/suspend, malformed/frozen counters, 32-bit sequence wrap, wrong run IDs,
uncertain frame boundaries, cross-host anomaly attribution, complete synthetic
bundles/checksums, UDP token rejection, peer shutdown and VT restoration with a
fake display/source. The UDP protocol test needs loopback networking. No hardware
display or capture is touched by the regression suite.
