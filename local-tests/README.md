# Local NVIDIA HDMI validation

See the [commit-series record](../doc/commit-series.md) for the committed driver
changes, logging policy, software verification and remaining hardware limits.

For hardware-free tests of the current driver's IRQ/completion logic, run
`make -C tools check-irq` from the repository root. The all-tests runner includes
these through `tools-check`; no module reload or HDMI signal is required for
this software test. See [deterministic VDONE tests](../doc/deterministic-vdone-tests.md)
for modeled coverage, sanitizer/mutation commands, and limits.

## Queue-starvation and vblank-disabled comparisons

These additions change userspace tools/runners only: no further HwsCapture reload
is needed if the existing diagnostic module already passes `module-identity`.
The runner rebuilds the tools before testing. Each comparison takes roughly
4–6 minutes, temporarily takes over TITAN HDMI, and restores the desktop.

Measure normal versus deliberately delayed requeueing:

```bash
bash /home/hoff/swdev/hws/local-tests/hws-test-all.sh --test-starvation
```

This captures 1,000 frames per trial with 4 and 16 buffers, using 0 and 80 ms
delays every 60 frames, with two repeats in reversed order. Delays occur only
before replenishment, never after the submission budget is exhausted. All full
image, barcode, poison, and mapping checks remain enabled in every trial. This
tests sensitivity to application delay; it does not optimize away any checks.
Missing/capped diagnostics or missing/short injections fail the comparison's
collection checks. No observed queue starvation is also a useful result, not
proof that starvation can never occur.

`pattern/comparison.jsonl` records each trial and its `diagnostic` object:

- `timing.userspace_processing_before_requeue`: wall time holding a dequeued
  buffer before poison preparation, including injected delay.
- `timing.userspace_processing_cpu`: thread CPU time over that processing window.
- `timing.userspace_processing_non_cpu`: wall minus CPU time; includes sleep,
  blocking I/O and descheduling, **not a direct scheduler-latency measurement**.
- `timing.poison_preparation` and `timing.qbuf_ioctl`: separately measured wall time.
- `injected_delay`: requested delay, observed durations/count, and kernel EMPTY
  generations occurring during the injection. Overlap is correlation, not a
  physical interrupt-cause finding.
- `drops` and `drop_counts`: distinguish midstream empty queues, budget draining,
  post-final-delivery losses, and orphan halves after recovery.

For the NVIDIA comparison, first remove the previously added unsupported
`nvidia_drm.vblank=1` option and reboot manually (see the vblank section below).
Then run the **same** minimal/full diagnostics comparison:

```bash
bash /home/hoff/swdev/hws/local-tests/hws-test-all.sh --compare-drops --require-vblank-off
```

The guard reads the loaded sysfs parameter and accepts only `N`; missing,
unreadable, or enabled state prevents hardware testing before receiver setup or
display switching. Each pattern trial rechecks the guard and archives the loaded
value, kernel and boot ID in its sealed manifest and comparison row. Compare
these results with `all-tests.j9QpyJ/pattern/comparison.jsonl`; that older run did
not put the vblank value in each row, so use its enclosing archived state.
The pre/post-reboot comparison is exploratory, not a controlled causal proof.

If duplicate stable toggles persist, full-diagnostics rows retain each recovery's
reason, interval, toggle, stable/reasserted observations, neighboring IRQs, and
IRQ/worker timing windows. For a separate IRQ-disabled-latency diagnostic:

```bash
bash /home/hoff/swdev/hws/local-tests/hws-test-all.sh --irq-latency --require-vblank-off
```

This requires the kernel's `irqsoff` tracer; unsupported kernels are reported as
unavailable. Its maximum is system-wide, not proof of HwsCapture IRQ latency.
There is still no physical IRQ-assertion timestamp to distinguish a late IRQ
from hardware-toggle behavior conclusively. Do not combine `--irq-latency`,
`--compare-drops`, and `--test-starvation`; their workloads must remain separate.
The vblank guard can also be combined with `--test-starvation`.

All these remain diagnostic runs: source-presentation timing is unqualified,
strict failures are retained, and exit 2 for incomplete coverage is expected.

## Drop/recovery diagnostics (requires the newly built module)

The instrumentation changes the module, so **load the new build before running
hardware tests**. The runner still refuses a srcversion mismatch and never
reloads the card itself. Stop all HwsCapture video/audio consumers first; a
reload affects every channel, including Windows-fed inputs:

```sh
sudo modprobe -r HwsCapture && sudo insmod /home/hoff/swdev/hws/src/HwsCapture.ko
bash /home/hoff/swdev/hws/local-tests/hws-test-all.sh --quick --with-pattern
```

The short pattern run now includes bounded queue/IRQ diagnostics. Each bundle
contains `queue-events.jsonl` (userspace QBUF/DQBUF and shutdown timing) and
`diagnostics.json` (loss categories, nearby IRQ/queue records, and latency
distributions). A kernel `hws_video_diag` trace records buffer indices, queue
depth, active-buffer identity, acquisition/empty/recycle/pre-completion events,
IRQ entry/ack timestamps, worker dispatch, and stream start/stop. No kernel
pointers are exposed. It adds no MMIO reads, allocations or printk, and does
not change queueing, recovery, DMA selection, or completion decisions.

The kernel trace is enabled only when requested and capped at 32,768 records
per channel/stream; debugfs exposes `diag_records`, `diag_suppressed`, and
`diag_limit`. Initial QBUF callbacks precede the new stream epoch; the START
snapshot supplies its initial queue depth. Userspace logging is optional,
buffered, and capped at 8,192 records plus config/summary. Poison preparation,
QBUF ioctl time, and processing between DQBUF and requeue are separated.
Caps/loss/malformed evidence make attribution inconclusive. Long soaks will
exhaust these diagnostic limits; use the short runs for causal investigation.

Loss categories distinguish recovery-orphan halves, midstream queue emptiness,
submission-budget draining, and an empty queue after the final userspace dequeue.
IRQ timings start at **CPU handler entry**, not physical interrupt assertion;
they cannot establish hardware-to-CPU interrupt latency. The completion event
is recorded just before releasing the buffer to VB2, not at userspace dequeue.
No diagnostic report bypasses the strict content/mapping/source gates.

For controlled short comparisons (typically 4–6 minutes):

```sh
bash /home/hoff/swdev/hws/local-tests/hws-test-all.sh --compare-drops
```

After full calibration, it collects 1,000 frames in each of four conditions:
4/16 buffers × minimal/full extra diagnostics, repeated twice in reversed
order. Minimal retains the normal IRQ/copy/frame/recovery traces and pixel
checks, but disables the ring probe and new queue diagnostics; it is therefore
explicitly non-validating for independent mapping. Full enables both. Results
are in `pattern/comparison.jsonl`, including per-run duration and recovery rate.
This compares total diagnostic overhead; it does not isolate the cost of each
individual observer. Two repeats are exploratory, not statistical proof.

Optional interrupt-disabled latency investigation is a **separate** run:

```sh
bash /home/hoff/swdev/hws/local-tests/hws-test-all.sh --irq-latency
```

It requires the `irqsoff` tracer; if unavailable, setup is reported incomplete.
The run resets the latency maximum, disables function-call tracing to reduce
overhead, records the maximum in `irqsoff-max-us.txt`, and restores the previous
function-trace option during cleanup. The maximum is system-wide, not proof
that HwsCapture caused the latency or that it coincided with a drop. This mode
cannot be combined with `--compare-drops` because it changes the measurement.
Existing tracing sessions remain protected by the idle-tracefs preflight.

The runner never changes `nvidia_drm.vblank`. To investigate its effect, repeat
the same comparison on a boot without the unsupported `vblank=1` option and
retain both result directories. Neither NVIDIA timing failures nor changed
drop rates alone establish causality.

## One-command current-setup test suite

Run as `hoff` from a terminal (do not prefix the script with `sudo`):

```sh
bash /home/hoff/swdev/hws/local-tests/hws-test-all.sh --with-pattern
```

Allow about 25 minutes. The script builds the kernel module without installing
or reloading it, runs the tool regressions, checks the loaded module identity,
captures 36,000 ordinary desktop frames on video3, and exercises 20 ordinary
start/stop cycles (2/4/8/16 requested buffers; 1/2/4/60/120 frames each). It
records debugfs snapshots around each stream, delivery/loss/recovery accounting,
and fresh kernel messages. It refuses to stop an existing consumer.

`--with-pattern` additionally authorizes temporarily switching away from KDE
and taking over the TITAN HDMI output for 1,000 calibration and 36,000 content
frames. The existing VT/ACL restoration and independent display watchdog are
retained. The source is fixed to this machine's card1, connector 827, CRTC 200,
1080p60 HDMI loopback into video3; it is not a general GPU discovery tool.
Do not use it after changing GPU wiring/IDs without rechecking that setup.

The pattern run captures full-frame checks, bounded private-ring observations,
copy/guard traces, buffer accounting, and anomaly evidence. Broken NVIDIA
presentation timing and dirty-input provenance remain explicitly failed in
each strict bundle summary, but do not prevent progressing from a passing
`capture_checks` calibration to the long content run. The script does not
enable vblank or edit boot settings; the known unsupported vblank=1 boot may
still emit NVIDIA warnings. Returning to the default vblank=0 remains advisable,
but valid vblank telemetry is not required for this diagnostic-only mode.

Without `--with-pattern`, the display is not switched. Other options:

```sh
bash local-tests/hws-test-all.sh --quick          # 600-frame ordinary smoke
bash local-tests/hws-test-all.sh --quick --with-pattern # also 1,000 pattern frames
bash local-tests/hws-test-all.sh --software-only # no capture or sudo
bash local-tests/hws-test-all.sh --no-sudo       # privileged checks unavailable
```

`--quick --with-pattern` usually takes about 2–3 minutes with an incremental
build. It runs 600 ordinary frames, all 20 restart cycles, and the 1,000-frame
pattern calibration with the same content, trace, guard, and accounting checks.
It skips both ten-minute soaks and explicitly records that lost duration
coverage. Build time and receiver readiness can make it take longer. The
display is still temporarily taken over for the pattern calibration.

`--output DIR` selects a
new output directory; existing directories are never reused. The default is
a unique `local-tests/all-tests.*` directory. `results.tsv` reports PASS, FAIL,
WARN, INCONCLUSIVE, and SKIP per check. Drops/recoveries are WARN, not hidden
inside a clean pass. Missing stats/logs are not interpreted as zero errors.
An ordinary transport pass does not certify pixels or DMA guards; its stats
only establish the recorded counter checks. Exit 1 means a failed test;
exit 2 means incomplete coverage/warnings/skips (expected with the current
known limitations); exit 0 is reserved for all checks covered and passing.

Explicitly excluded: synchronized shutdown races (missing driver hooks),
post-stop DMA canary test (missing status ioctl), card unbind (disruptive and
the existing harness needs review), other channels/modes, simultaneous audio,
sanitizer-kernel testing, and before/after commit comparisons. No capture-driver
source or hardware registers are patched by this suite, and no driver is
installed/reloaded. The strict NVIDIA launcher remains strict unless its
explicit `--content-only` option is supplied by this wrapper.

Tested checkout: `4706e64bc4e6a60ed3e3049d287f79d12734d78c`, including
`d9df61d800f5bc47de6e49da0b4a67a12fc6d059`.

The loopback is the Linux TITAN RTX HDMI output to `/dev/video3` (channel 3).
The launcher uses `/dev/dri/card1`, connector 827, CRTC 200. These identifiers
were verified during this boot; verify them again after GPU changes or reboot.
The launcher checks the connector/CRTC relationship before setting the mode.
VT1 hosts KDE, VT2 hosts SDDM. It selects another unused VT, sets 1080p60,
waits for receiver readiness, and restores KDE on exit.

## Results

- Forced kernel-module rebuild and userspace builds passed.
- All 46 Python tests passed; decoder and KMS raster checks passed in 13 modes.
- Channels 0 and 3 each completed a 600-frame streaming smoke test at 60 fps.
- The saved channel-3 calibration captured and drained all 1,000 submissions.
- All 1,000 frames passed barcode and full-frame content validation, with no
  payload, sequence, poison, or flagged-buffer errors.
- Independent mapping passed: 879 and 878 supporting transitions for the two
  regions, zero contradictions, and all 1,000 deliveries linked to observations.
- Five recovery events occurred without fatal errors or queue failures. Anomaly
  evidence accounting passed; cause attribution remains unresolved.
- Overall validation failed: all 1,117 archived NVIDIA page-flip sequence
  numbers were zero, preventing source refresh and repetition validation.
  The run recorded `nvidia_drm` parameter `vblank=N`.
- The ten-minute strict pattern/evidence run has not run; it requires a passing
  calibration first. A separate transport-only soak is recorded below.

The complete retained run is `calibration-20260905-ch3/`. Its sealed evidence
bundle is the `calibration/` subdirectory. Its checksum inventory was verified
before and after copying from `/tmp`; do not modify the sealed bundle.

A second retained run, `calibration-20260905-ch3-repeat/`, also passed all
1,000 captured frames but failed independent mapping at generation 2. Its
generation-1 lower ring sample decoded to ID 472622230, which appears in the
previous run's presentation log. At generation 2 this was replaced with the
current source's ID 306156297. The validator flags that startup replacement
as a backward ID. This is separate from the disabled-vblank failures and needs
follow-up on handling retained ring content at stream startup. The new source
chooses a random starting ID, so ID ordering between runs is not meaningful.
The sealed evidence has not been modified to suppress the failure.

## Vblank-enabled test and current blocker

The user booted with `nvidia_drm.vblank=1`. The retained run
`calibration-20260905-ch3-vblank/` recorded `vblank=Y`, passed all 1,000 captured
frames, and passed independent mapping with 880/878 supporting transitions,
zero contradictions, and 1,000 linked deliveries. It had three recovery events,
no fatal events, and no queue failures.

However, every one of the 1,210 source presentations had sequence 2. Reported
presentation times preceded submission by 498–515 ms. A separate CRTC query
also returned sequence 2 and timestamp zero. The kernel explicitly reported
`RG semaphore vblank interrupt not supported on this platform`, accompanied by
DRM vblank-wait timeouts. This NVIDIA 610.57.04/TITAN configuration cannot
supply the required vblank evidence through the tested path. Do not infer a
capture-driver failure from the NVIDIA DRM warning or promote this run to pass.

The driver includes a fallback timestamp path when no real vblank callback has
fired, consistent with the unusable presentation telemetry observed here:
https://github.com/NVIDIA/open-gpu-kernel-modules/blob/610.57.04/kernel-open/nvidia-drm/nvidia-drm-modeset.c#L546

The first stream after module load also exposed a separate validator issue:
`split16_cached` initialized from 0 to 129536. The actual hardware readback was
129536 both before and after capture, and `split_bytes` stayed at 2072576. The
validator treated that software-cache initialization as a configuration change.
Both startup issues are now fixed in the working-tree validator. Read-only
revalidation of all three retained bundles removed exactly the backward-ID
startup failure and the split-cache initialization failure. All three now pass
independent mapping; their original source-presentation failures remain. The
sealed bundles and their recorded summaries were not rewritten, and their
checksum inventories still verify. The 59-test regression suite and the C
decoder/KMS raster checks passed with the fixes. Details of the narrowly scoped
startup exceptions are in `doc/vdone-evidence-runbook.md`.

Return to the default `vblank=0` on the next boot. If the option was added only
through a one-time GRUB edit, a normal reboot without adding it again suffices.
If it was made persistent, remove that specific addition from its configuration.
The launcher has not edited boot settings or reloaded NVIDIA.

The launcher now refuses to switch displays when the current boot reports this
unsupported-platform warning, or when vblank is disabled. Repeating the same
strict test cannot establish a pass on this configuration. Basic streaming,
buffer, and recovery tests on Windows-fed video0/video1 remain possible without
KMS vblank evidence. A definitive presentation test needs a supported source
configuration, plus resolution of the validator startup issues. The ten-minute
definitive run remains pending.

## Transport-only soak and lifecycle follow-up

`transport-soak.5oZ9OA/` records a ten-minute channel-3 1080p60 YUYV streaming
test, with the existing desktop signal and no display changes. It completed
36,000 requested buffers, with 40 reported drops. Driver counters recorded
79 recoveries, 40 no-buffer frames, zero fatal errors, and zero queue failures.
Twenty subsequent ordinary start/stop cycles completed without driver-reported
recoveries, no-buffer frames, fatal errors, or queue failures. The device was
released afterward. The software regression suite passed again (59 tests).

This is evidence of sustained delivery and successful ordinary restarts only.
It does not test image contents, DMA guards, independent mapping, or source
presentation timing, and does not explain the drops. The strict evidence run
remains blocked as described above. The follow-up lifecycle script is
`hws-transport-lifecycle.sh`; it requires a new output-directory argument and
an idle `/dev/video3`.
