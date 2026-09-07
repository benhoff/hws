# Saved-half continuity remediation (R1)

Historical change record; see [the commit series](commit-series.md) for the
later logging cleanup, commits and integrated software checks.

Implemented 2026-09-06 in the working tree on father, following batch 1 of
[the remediation plan](driver-remediation-plan.md). No module reload, hardware
test, boot-option change, baseline execution or commit was performed.

## Defect and changed behavior

The original production IRQ/worker model could publish A's first half together
with B's second half after two unobserved DMA boundaries. Observed generation
increments and alternating toggles alone did not detect this. The new permanent
content assertion failed before the guard was implemented.

`src/hws_irq.c` now saves the first half's IRQ timestamp, configured half-period
and stream epoch. Before copying its partner, and again before publication, it
requires continuity with that saved state. Rejection uses `-ESTALE`, recycles the
driver-owned partial destination, and resynchronizes through the existing phase
recovery. Both halves must be overwritten before that destination is delivered.
Concurrent worker overlap retains its existing recovery/ownership precedence.
Toggle, observed-generation, copy-deadline and guard checks remain in force.

Saved state clears on delivery, recycling, phase reset, initialization/cleanup,
fatal failure and aborted work. Stop/source-change/PM paths clear it after worker
drain when stopped or suspended. These lifecycle paths were inspected and built;
the userspace IRQ model does not execute actual kernel stop/PM concurrency.

## Timing policy and assumptions

For progressive configured timings, let:

`T = floor(floor(htotal * vtotal * 1e9 / pixelclock) / 2)` nanoseconds.

The helper checks arithmetic overflow, geometry agreement and a 1–240 Hz frame
rate range. Invalid/unavailable timing returns zero and cannot authorize a pair.
It uses configured DV timings, not rounded integer `current_fps`. It does not
repair the separate G_PARM/detected-timing finding R4.

The second IRQ must be strictly newer than the first and no later than
`T + floor(T/2)` after it. Saved epoch and period must still match. At each check,
the current time must not precede the second IRQ; the first half's age must be
at most that continuity limit plus the second event's existing copy budget.
The separate copy deadline still rejects at its own exact expiry boundary.

Why 1.5T: normal adjacent halves separated by T tolerate up to +0.5T differential
IRQ-entry jitter. Two hidden boundaries produce a 3T separation with prompt
handlers, which is rejected. Under an assumed absolute differential timestamp
error of at most 0.5T, that 3T separation also cannot fit the accepted window.
This is a **conservative software policy, not a measured hardware latency bound**.
Large scheduling jitter may now cause safe additional drops. Do not widen this
threshold merely to remove warnings.

The model uses a shared monotonic clock and regular simulated DMA cadence. It
does not validate arbitrary discrepancies between physical DMA, register
visibility and handler timestamps. Independent hardware timing/identity evidence
and adversarial delayed-observation modeling remain necessary for any stronger
claim. Successful pairing tests do not prove zero loss or universal correctness.

## Diagnostics and compatibility

- Recovery trace reason **6** means saved first-half continuity lost. Existing
  numeric reasons are unchanged.
- Per-stream debugfs `continuity_gaps` and `continuity_reports` count these
  worker-level rejections. They agree after the stream is drained.
- IRQ disposition counter `vdone_recovered` is unchanged: do not add a worker
  rejection to it and break IRQ accounting. Inspect the new counters separately.
- Continuity rejections are counted in debugfs/trace without a new kernel log
  message. The traced interval is the observed second-minus-first IRQ
  interval, not a measurement of IRQ latency or physical loss.
- The evidence validator checks reason-6 accounting separately from overlap and
  requires both counters when either is advertised or reason 6 is present.
  Older bundles without this reason/counter pair remain supported.
- The local transport reporter warns on nonzero continuity gaps; comparison rows
  expose their count and rate separately. Missing or inconsistent counters do
  not silently pass. Diagnostics leave the physical cause/loss count unresolved.

## Verification

Software checks performed on this implementation:

| Check | Result / scope |
| --- | --- |
| Permanent regression before guard | Failed the independent mixed-content assertion, as expected |
| `make -C tools check-irq` | PASS; 4,721 schedules plus targeted cases |
| `python3 tools/review_irq_gap.py` | PASS; all 8 cases, 0 mixed deliveries, 0 runner errors |
| `python3 tools/review_completion_gap.py` | Adjacent pair accepted; hidden-boundary pair rejected with -ESTALE; generation/deadline controls still reject |
| `make -C tools check-irq-mutations` | PASS; all four mutations compile then fail assertions, including removing continuity |
| `make -C tools check-irq-sanitize` | PASS outside sandbox; AddressSanitizer/UndefinedBehaviorSanitizer userspace model |
| `make -C tools check` | PASS; IRQ, raster/decoder, DRM analysis, 95 VDONE and 16 clock tests |
| Local runner regressions | PASS; 29 tests, including continuity warning/malformed accounting |
| `make -C src W=1` | PASS against 7.1.9-arch1-2 headers; no warnings |

The clock suite's local UDP test required running outside the sandbox, as did
LeakSanitizer (which rejects the sandbox's ptrace wrapper). Both reruns passed;
the sandbox failures themselves were not counted as passes.

Validated source/build SHA-256 fingerprints (the original failing snapshot's
fingerprints remain in the end-to-end review):

```text
6dbce8a57852b4aae0410ca3d9b9dc32787cd116ac0c2157fa04bf53ec3719de  src/hws.h
a7af5814f9c0643d140b464e8e6c26c3b46af8617d636ed93807ab83e2a74ff0  src/hws_irq.c
84fa0029b71385ab9879860202c89e27dfd57cfe6239104e82ec22e0f62c0163  src/hws_video.c
a9106bce5a1cff227e7e28d6b385141c462ea4d52345624860d060fe06a7bc20  src/hws_debugfs.c
5dea1e62ce0224052ef45bff73a56d93abd5dfe1446cb57aae5febce07d1af21  src/HwsCapture.ko
```

The permanent tests cover 0–6 hidden boundaries after each half, all 14 timing
table entries including fractional/DMT rates and asymmetric splits, exact
continuity boundaries, invalid timing, age/epoch invalidation, held source IDs,
startup, duplicate recovery, queue starvation, missed events during copying and
pending workers. Every delivered word must match the independent source ID;
exclusive ownership and bounded recovery under resumed normal events are checked.

## Remaining qualification

The loaded driver is unchanged. To test this code on hardware, arrange a safe
reload of the newly built module with all card consumers stopped, verify its
loaded identity, then retain fresh content/trace evidence and both continuity
counters. Use the existing short content run first; the laptop's qualified
timing path is needed for stronger physical timing/loss claims.

This does not resolve why real duplicate toggles occur. R2–R8, actual kernel
concurrency, source-transition safety and post-stop DMA remain separate work.
