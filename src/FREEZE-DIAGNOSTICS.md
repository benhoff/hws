# Capture freeze diagnostics

Build this branch with `make -j4`, then load the resulting `HwsCapture.ko` during
your normal driver reload. Rebuilding alone does not instrument the loaded
module. The default settings work with `enable_audio=0`; no tracing command is
required. This change does not restart capture, acknowledge interrupts, change
frame validation, or read DMA image memory.

The existing monitor samples each channel's CPU counters approximately once a
second. IRQ diagnostics retain values already read by the normal handler in
fixed-size storage. They do not perform extra register reads or print from the
IRQ/copy path.

- `stall_timeout_ms=2000`: report a lack of frame delivery after approximately
  2–3 seconds. Values are clamped to 1000–60000; zero disables automatic reports.
- `stall_heartbeat_ms=30000`: healthy progress summary every 30 seconds; zero
  disables healthy summaries. Nonzero values below 1000 are treated as 1000.
- `completion_diagnostics=1`: retain two IRQ observations before a duplicate,
  the duplicate itself, and two subsequent observations. `VDONE context` and
  `VDONE sample` journal lines publish at most one window per ten seconds per
  channel, even when frames continue arriving. All duplicates remain counted;
  `suppressed` counts duplicate triggers that did not open another window.
  Set this parameter to zero at module load to disable IRQ context collection.
  `stall_timeout_ms=0` also disables publication of these windows.
- A stall produces `capture-diag STALL`, software `state`, and raw `registers`
  lines in the kernel journal. Persistent stalls repeat every ten seconds.
  `RESUMED` records subsequent progress. `STREAMOFF` records software state
  before queued and partial buffers are removed, even for a short-lived stream.

Watch with:

```sh
journalctl -kf -g 'capture-diag|VDONE|HwsCapture'
```

When a screen freezes, collect evidence **before unloading**:

```sh
sudo bash ./capture-freeze.sh
```

The script prints a private `/tmp/hws-freeze.*` directory containing kernel
logs, loaded module parameters and source version, device node names, task wait
states, and two debugfs/interrupt snapshots. Reads have individual timeouts.
Missing files or permissions are recorded rather than silently omitted. The
script does not mount debugfs, change trace settings, or touch capture controls.
Source revision/diff describe the checkout; they are not proof of which binary
is loaded. Save the bundle elsewhere if it must survive a reboot.

Each `/sys/kernel/debug/hws-<PCI-address>/videoN/stall` file provides a live CPU
snapshot without requiring the channel's ioctl mutex or reading hardware.
`stats` contains the full existing recovery counters. The right-hand screen in
the recorder's current arrangement uses channel 1 (`video1`).

Interpretation:

| Evidence | What it narrows down |
| --- | --- |
| `no-recent-vdone`, increasing `irq_age_ms` | Channel completion notifications stopped; inspect raw signal, capture-enable, interrupt status and gate values. |
| `completion-pending`, old `pending_age_ms` | A completion is pending/copying while the IRQ path can still be active; inspect task wait states and overlap counts. |
| Increasing `queue_empty` / `starved` | A first-half buffer acquisition found the actual capture queue empty / a subsequently completed half pair was lost for that reason. |
| Increasing `orphaned` | A second half arrived without a retained first half, e.g. following duplicate recovery, even if application buffers are queued. |
| `recovering-without-delivery`, increasing duplicate/overlap/continuity totals | Frame validation repeatedly discards work. |
| Increasing `delivered` behind a frozen picture | The driver is completing buffers; investigate the application's dequeue/render path or frozen source content. This does not prove pixels are changing. |
| `capture-disabled`, `queue_failures` or source-change state | Capture was stopped/failed; correlate preceding driver messages. |

`delta_*` covers the last monitor sampling interval (`sample_ms`), not the entire
heartbeat period. Cumulative counts allow comparisons across heartbeat lines.
`delivery_idle_ms`/`stalled_ms` are based on when progress was last observed by
the monitor, not an exact last-frame timestamp. `irq_age_ms` is measured from
the driver's last recorded completion timestamp (or stream start if none).
`active=4294967295` means no partial buffer. `completion` is 0=idle, 1=pending,
2=copying, 3=overrun; `phase` is 0=sync, 1=expect half 0, 2=expect half 1.
`deadlines`/`guards` are existing channel counters, not necessarily per-stream.
`no_buffer = starved + orphaned`; the historical counter alone is not proof of
application starvation. `queue_empty` can exceed `starved` if recovery discards
that half pair before completion. These new counters reset at STREAMON.
The `stall` file's raw timestamps are monotonic nanoseconds. Its `sample` field
reveals whether the monitor itself stopped running.

The hint is an observation, not a proven root cause. Register reads are a
separate, non-atomic sample taken only for stall reports. A sampled toggle
cannot establish whether DMA is stationary. If STREAMOFF/restart overlaps a
report, use the epoch and surrounding lifecycle messages to interpret it.
The monitor cannot report while the whole kernel, its own thread, or an IRQ
spinlock is stuck. A successful driver completion also precedes the existing
`vb2_buffer_done()` call and does not prove userspace dequeued/rendered it.

For duplicate context, `offset=0` identifies the trigger; -2/-1 and +1/+2 are
preceding/following channel completions. `ns` and `pending_ns` are monotonic
nanoseconds. `interval_ns` compares adjacent stored observations (zero if the
predecessor is unavailable). `expected_half_ns` comes from configured rational
timing. The states/queue depths are sampled **before** that IRQ's recovery or
acceptance decision; `result` and `ambiguity` describe the decision afterward.
`before`/`after` straddle W1C acknowledgment; `status`/`ack_status` retain the
shared interrupt status words. `stable` and `reasserted` describe the normal
post-acknowledgment sampling checks. No image pixels are recorded.

Result values: 0=ignored, 1=queued, 2=resynced, 3=recovered, 4=deferred,
5=overrun. Ambiguity: 0=none, 1=inflight, 2=duplicate, 3=backward timestamp,
4=unstable toggle, 5=status reasserted, 6=continuity. A missing post-trigger
observation produces a partial window after two seconds or at STREAMOFF.
An interrupted startup can lack preceding observations, which are omitted.

A duplicate with roughly twice the configured half period, stable toggle,
idle completion worker and available buffers supports a gap in observed
completion transitions. It does not uniquely distinguish hardware failing to
transition from software missing a notification: both can expose identical
one-bit toggle and sticky-status observations. The regression test explicitly
demonstrates that limit instead of treating the hint as a hardware diagnosis.

## Opt-in observation between interrupts

The observer independently reads interrupt status, channel toggle, then
interrupt status again from the monitor thread. It requests approximately 1 ms
between samples while armed; scheduling, kernel tick resolution and normal
format monitoring can make gaps longer. It never acknowledges an interrupt or
accesses image memory. **These extra PCIe reads and wakeups can affect timing**;
compare against the normal diagnostics with the observer disabled.

After loading the rebuilt module and starting capture, arm a run on channel 1
(the right screen in the current recorder arrangement):

```sh
echo 1 | sudo tee /sys/module/HwsCapture/parameters/irq_observer_run
journalctl -k --since '1 minute ago' -g 'IRQ observer|VDONE'
```

Allow up to one second for the monitor to notice the request. It saves the
latest 64 samples and stops eight samples after it detects a new duplicate,
or after 15 seconds without one. The journal contains `IRQ observer begin`,
`end`, and chronologically ordered `sample` rows. A timeout still publishes
the last samples, but may not contain any failure. Each row's `trigger=1`
marks the first sample that noticed the driver's duplicate counter increase;
it is not the exact instant of the hardware event.

Write a different nonzero run number (2, then 3, etc.) for another attempt.
Write zero to cancel. Finished runs do not automatically restart. If capture
is stopped when armed, the request is skipped; start capture and use a new run
number. Runs also stop on an observed stream epoch change, device loss,
suspend, invalid register read or backward clock. Parameters are module-wide;
with multiple cards, each monitor observes its selected channel independently.

The load-time parameters `irq_observer_channel=1` and `irq_observer_ms=15000`
select channel and timeout; the timeout is clamped to 100–30000 ms. The default
`irq_observer_run=0` causes no observer register reads. This feature operates
independently of `completion_diagnostics` and `stall_timeout_ms`.

| Observer evidence | What it establishes |
| --- | --- |
| `pending_pairs_no_record` greater than zero | The channel's pending bit was set in all four status reads across two nearby samples, while the driver's completion generation remained unchanged. The card exposed a pending completion that had not yet been recorded by the driver. This does **not** prove the card sent an MSI: device interrupt generation, host delivery and handler delay remain possible. |
| `toggle_changes_no_record` greater than zero | The card's toggle changed between nearby samples with no recorded channel completion in between. The hardware indicator advanced; its notification or handling needs investigation. It does not prove the image DMA completed correctly. |
| Both counts zero | Inconclusive. The observer may have missed the transition or pending interval, or the card may not have produced it. Zero is not evidence that the card is faulty. |

These counts use pairs spanning at most 4 ms, with no generation change
during or between the two samples and no observed lifecycle/MMIO invalidity.
`generation_before`/`generation_after` bracket each sample's reads.
`raced` in the end summary counts invalid samples and samples overlapping a
generation change; the row's `raced` flag marks lifecycle/MMIO/clock invalidity,
so also compare its generation fields. `max_pair_span_ns` exposes the largest
span across adjacent samples, including pairs excluded from these counts.

The hardware reads and CPU metadata are not atomic together. In particular,
the handler acknowledges status before updating its completion generation;
a sample can land in that interval. A generation is a recorded channel
completion, **not** a count of CPU interrupt entries or transmitted MSI
messages. The bit is a latch, not an event counter; neither it nor the one-bit
toggle identifies every transition. Correlate the rows with the `VDONE`
window and repeat the run. Proving whether the card actually transmitted a
missing MSI would require additional device-side counters/trace or a PCIe
analyzer; this software observer cannot make that final distinction.

Host regression test (no capture hardware needed):

```sh
cc -std=c11 -Wall -Wextra -Werror -o /tmp/hws-stall-test tests/test_stall_policy.c
/tmp/hws-stall-test
python3 tests/run_observer.py
python3 tests/run_irq_diagnostics.py
```
