# Bounded late-toggle diagnostic

Implemented 2026-09-06. Diagnostic only: this does **not** fix duplicate-toggle
loss or authorize delivering a frame previously rejected as ambiguous. No
module reload, HDMI change, stream takeover or hardware experiment was performed
while implementing it. Existing dirty-worktree remediation changes are retained.

## Question and observation

The user-supplied `local-tests/all-tests.nZCtk6` bundle contained three
same-toggle recoveries, separated from their preceding observations by about
8.1–8.7 ms, and two orphan-half drops. Sparse DMA-region barcode content advanced
around the anomaly windows. Those facts do not establish a harmless repeated
interrupt, a missed physical boundary, or a stale toggle register.

This diagnostic asks: **does the raw toggle value change shortly after the
driver has already classified a duplicate, and what is interrupt status then?**

## Kernel behavior and limits

- New `late_toggle_probe=1` module parameter; default **off**, runtime read-only.
  Sampling requires the `hws:hws_vdone_late_toggle` trace event to be enabled too.
  Either gate off means no extra register reads and no window consumption.
- Only duplicate dispositions trigger it, including startup resynchronization.
  It runs after the normal phase/recovery decision and IRQ trace, outside the
  channel spinlock but still in hard-IRQ context. Counters use the existing lock.
- At most **four back-to-back pairs** of raw VBUF_TOGGLE and INT_STATUS reads per
  window. No sleep, intentional delay, retry-until-change, DMA-memory scan, W1C
  write or configuration write. It does not stop early merely because a toggle
  changed: subsequent samples can expose another change or status reassertion.
- A **50 µs soft elapsed budget** prevents starting another pair. One pair,
  an NMI or a stalled bus read can overrun that budget. The actual start/end
  timestamps and budget flag are retained; trace emission/counter locking after
  the recorded finish can add overhead too. This is not a hard latency guarantee.
- At most **16 windows per channel per stream epoch**: at most 128 extra MMIO
  reads and 16 new trace records. Further duplicates increment a saturating
  suppression counter. The actual STREAMON evidence-reset function resets this
  budget, and is exercised by the deterministic test.
- The result never updates the selected half, generation, saved-buffer state or
  completion disposition. A changed late value cannot rescue a frame or change
  the expected phase. Existing content/guard/deadline/recovery checks stay intact.
- Stop/suspend/lost-device gates terminate or skip observation. **Exception to
  purely observational behavior:** an all-ones register read invokes the existing
  fatal device-loss path, just like other MMIO accessors; it is never converted
  into a valid toggle. No further reads follow that fault.

Because this runs in the IRQ handler, it can perturb hardware/interrupt timing
even though it cannot authorize a different completion. Keep it diagnostic-only
and compare with it disabled when investigating an apparent timing change.
There is no deliberate spacing between samples: the four pairs need not span
50 µs and cannot rule out a toggle change later than the actual observed window.

## Evidence

`hws_vdone_late_toggle` records device/channel/epoch/generation, window index,
the already-chosen baseline toggle, original IRQ-observation timestamp, window
start/finish, count, flags and four raw-value/time slots. Only the first `count`
pairs are complete. Register values are unmasked in the trace. Flag bits:
`1` budget, `2` stop/suspend, `4` device fault, `8` nonmonotonic clock.

Per-channel debugfs `stats` adds per-stream:
`late_toggle_windows`, `late_toggle_samples`, `late_toggle_suppressed`,
`late_toggle_budget_exits`, `late_toggle_max_ns`.
The duration is the whole sampled window, not per-read cost or end-to-end IRQ time.

The existing evidence collector now enables this trace event and records both
`late_toggle_probe` and `source_transition_checks` module settings in its
manifest. Queue-diagnostic runs put the report in `diagnostics.json` under
`late_toggle`; the quick pattern summary also prints `late_toggle` and
`late_classes`. Other capture/timing gates are unchanged.

Observation labels:

- `toggle_changed_without_sampled_vdone`: at least one raw low-bit value differs
  from the duplicate decision, and no pair sampled this channel's VDONE bit set.
  This is **not** proof of late hardware publication: status can change between
  reads, and physical DMA/interrupt assertion time is not measured.
- `status_reasserted_in_window`: at least one status sample has this channel's
  VDONE bit. A further boundary is possible; do not interpret a changed toggle
  as belonging to the original completion.
- `no_toggle_change_observed`: unchanged in this short sample window only.
- `incomplete_window`: stop, budget, fault or clock flags prevent a complete
  four-pair observation. Raw samples are still retained.

Evidence status `complete` means inventory and linkage agree, not driver safety
or physical cause. `capped` means later duplicates were not observed. Zero
windows is `not_observed`, never a success claim; an old bundle without this
instrumentation is `unavailable`. Missing records, trace loss, contradictory
counters, malformed timing or wrong device/epoch/generation linkage produce
`inconclusive`, not a causal classification. The changed-sample time interval is
the interval containing that **read**, relative to the original software IRQ
observation; it is not the instant of the underlying hardware transition.

## Tests and running

Hardware-free:

```bash
make -C tools check-irq
make -C tools check-irq-mutations
make -C tools check-irq-sanitize
make -C tools check
python3 -m unittest discover -s local-tests -p test_hws_test_runner.py -v
```

The production IRQ adapter now also extracts the actual per-stream evidence
reset. Tests cover parameter/trace gates, late changes at all eight MMIO read
positions, full raw values, reasserted status without acknowledging it, unchanged
ownership/phase, the 16-window cap/reset, slow reads and budget overrun,
stop/suspend, mismatched epoch, all-ones faults at all eight reads, clock rollback
and normal duplicate recovery/forward progress with tracing enabled. Mutation
controls make the diagnostic change the chosen half or exceed its cap; both
must fail. Python fixtures check classifications, provenance/linkage, missing
events/caps/loss, time bounds, trace-text parsing and preservation of the separate
capture/presentation verdicts.

Final validation (2026-09-06): full `make -C tools check check-irq-mutations`
PASS (including 105 evidence tests, 16 clock tests and the existing production
models); ASan/UBSan IRQ model PASS; 30 runner regressions PASS; kernel `W=1`
module build against `7.1.9-arch1-2` PASS with no emitted warnings;
`git diff --check` PASS. The full suite and sanitizer ran outside the sandbox
for localhost socket/LeakSanitizer support. No capture hardware was exercised.
Local unsealed logs: `/tmp/hws-late-toggle-validation.67CRDD/software-final.log`,
`sanitizers.log`, `runner.log`, `module-build.log` in that directory.

Built srcversion: `2872F13A805266B6EBE1D34`.
`src/HwsCapture.ko` SHA-256:
`68d7e4e2963c0102e76ac296b6f65b9ca1970671d301f4a37b0bfd1e86996c17`.
`src/hws_late_toggle.h` SHA-256:
`82e9cf66254df1d53269de06ea8237e2528e17d7ed0dd28caff536691deda694`.
This identifies the dirty-worktree build, not a new commit or loaded-module proof.

For the next **user-controlled** stable-source hardware run, first have the
owners stop applications using all four card inputs and any capture-card audio.
Do not force module removal or change NVIDIA parameters. The configuration last
used in this session had capture audio disabled and source checks enabled; to
preserve that configuration while adding this diagnostic:

```bash
cd /home/hoff/swdev/hws
sudo fuser -v /dev/video0 /dev/video1 /dev/video2 /dev/video3
```

Proceed only after all listed users have exited (and audio users, if enabled).
Build first, so a build failure cannot leave the device unloaded:

```bash
make -C /lib/modules/"$(uname -r)"/build M="$PWD/src" W=1 modules
```

After a successful build:

```bash
sudo rmmod HwsCapture &&
sudo insmod ./src/HwsCapture.ko enable_audio=0 source_transition_checks=1 late_toggle_probe=1
cat /sys/module/HwsCapture/parameters/late_toggle_probe
bash local-tests/hws-test-all.sh --quick --with-pattern
```

If `HwsCapture` is already unloaded, skip `rmmod` and run the `insmod` line
directly; trying to remove a missing module would stop the `&&` chain.

Expect `Y` from the parameter check. If reload fails, stop and report the error;
do not force it or proceed as though the new module were loaded. Confirm that
`video3` still denotes the intended HDMI input if node numbering changed.
The quick runner will temporarily take over the NVIDIA HDMI display, as before.
Keep the same HDMI cable/input/mode and application workload for this first run.
No second host is needed to collect these observations. Transport/lifecycle
stages normally have this trace event disabled; **pattern capture** collects the
late windows. Zero windows can simply mean no duplicate occurred during capture.

Return the result directory. Inspect its `pattern/calibration/diagnostics.json`
and raw trace alongside the existing DMA-region anomaly windows. A later
qualified laptop run on the same capture input can help separate source effects
from capture behavior, but is a separate coordinated experiment. Do not implement
a completion-rescue policy from one late-toggle observation.
