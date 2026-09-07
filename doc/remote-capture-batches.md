# Longer exposure with bounded diagnostic captures

For the subsequently added Rockchip host `wulfuser@192.168.1.125`, use the
[father-controlled headless qualification](rockchip-source-setup.md) first.
The laptop/KDE command below does not apply unchanged to that host. The new
launcher is implemented and software-tested; its physical qualification is
pending an interactive sudo prompt on father.

## First hardware batch: stopped after one completed trial

The requested 20,000-frame batch started, but only **1/20 trials completed**.
Trial 2 stopped before source/capture startup because the remote authentication
barrier timed out. While it was waiting, father's preflight subprocess was
observed blocked in `sudo -v`; it had not produced `auth-ready`. Each trial
opens a fresh SSH PTY, so sudo can require authentication again. This is a
limitation for unattended batches, not a capture-driver failure. Keeping one
authenticated remote session across trials is future tooling work; it has not
been implemented here.

Completed trial: `2fd2db82-3415-458d-963a-ae500c5cded6`, sealed evidence at
`father:/tmp/hws-remote-2fd2db82-3415-458d-963a-ae500c5cded6/bundle`.
Princess's aggregate is `/tmp/hws-video2-fast-source-20k/batch.json`, and the
verified reports are retained in `run-001/review-inputs.json` alongside it.

| Measurement | Completed trial result |
| --- | --- |
| Delivered frames | 1,000 captured, 1,000 valid, zero repeated IDs |
| Content, independent mapping and source/clock checks | PASS |
| Duplicate toggles / recoveries | 0 / 0 |
| No-buffer drops | 11: ten midstream, one while the final queue budget drained |
| VDONE events | 2,031; the extra events account for the no-buffer losses |
| Late-toggle windows | 0; enabled, but no duplicate triggered a window |
| Strict result | FAIL solely for dirty tracked sources and uncommitted evidence inputs |

The batch result is `stopped`, with error `timed out waiting for run phase`.
The 1,000-frame trial is valid diagnostic evidence with explicitly accounted
queue starvation. It is not a completed 20,000-frame experiment. No files in
the sealed bundle were changed. The separate fast-source calibration and its
performance/cadence results are in [the rendering report](kms-render-optimization.md).

## Batch procedure and validation

The laptop source launcher accepts `--runs N`. Use repeated 1,000-frame trials
to search for intermittent duplicate toggles while retaining fresh per-stream
probe and queue-diagnostic budgets. This is repeated startup/capture exposure,
not one uninterrupted stream or a long-duration lifecycle qualification.

For 20,000 frames on the qualified fast laptop source and video2:

```bash
python3 /home/hoff/swdev/hws/tools/hws_remote_source.py --run --host father --channel 2 --frames 1000 --runs 20 --buffers 16 --queue-diagnostics --probe-mode full --require-vblank-off --allow-dirty --output /tmp/hws-video2-fast-source-20k
```

Run from princess's desktop terminal using the usual sudo prompts. Each trial
uses its own source/capture run ID, clock measurement and sealed remote bundle;
the launcher restores the desktop between trials. The loaded capture driver
is not reloaded. Twenty trials contain about 5.6 minutes of active video, plus
authentication, mode switching, clock collection and validation overhead.

Output contains `run-001` through `run-020`, each with the existing source/clock
logs and `run.json` recording the remote bundle. `review-inputs.json` preserves
the reports fetched after checking the complete sealed bundle's checksums.
`batch.json` is updated after each trial and records accepted frame counts,
duplicate-toggle counts, recovery/no-buffer counts, strict provenance results,
build identities and any stopping error. Console updates show cumulative
duplicate toggles separately from repeated source frame IDs.

The batch proceeds only if capture contents, independent mapping, source timing,
clock mapping, anomaly checks and diagnostic completeness pass. Late-toggle
observation must be enabled and complete or explicitly not observed; cap
exhaustion, suppressed diagnostics and fatal/guard/queue failures stop the batch.
Observed recoveries with passing checks are counted and do not themselves stop
collection. A changed source/capture build, capture boot or recorded module
parameter profile stops aggregation across trials.

With `--allow-dirty`, only these exact strict failures may be carried forward:

- `driver evidence was captured from a dirty tracked tree`
- `evidence inputs were not committed at capture time`

They remain FAIL in the sealed results and in the per-trial strict result. A
completed batch reports `diagnostic_complete`, not universal driver correctness.
Unknown failures, failed collection, checksum errors or incomplete reports stop
before the next trial. Totals include only accepted trials; the stopped trial's
path/error and available evidence remain for inspection. Ctrl-C records an
interruption and uses the existing source/VT restoration path.

Batch mode requires `--frames <=1000`, `--queue-diagnostics` and full probes;
single-run operation retains its existing options. Increasing a single run to
20,000 frames would exhaust the initial 4,096-probe and 32,768-queue-record caps.
It would therefore offer less diagnostic coverage for later events.

Validation: 18 launcher/batch/preflight tests passed locally, including injected
recoveries, dirty-only acceptance, unknown failure rejection, missing/invalid
evidence, cap exhaustion, changed builds, checksum-read failures and interruption.
The gate also accepted the existing real sealed fast-source calibration
`86a7c337-d6db-42a0-8bd6-7100cb078353` with zero duplicates and its strict
provenance failures intact. The first partial hardware batch is recorded above.
