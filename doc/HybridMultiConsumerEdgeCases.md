# Hybrid Multi-Consumer Edge Cases

This document describes edge cases for the hybrid capture implementation:

- `DIRECT` mode: one streaming consumer, DMA writes directly into that consumer's queued buffers.
- `FANOUT` mode: two or more streaming consumers, DMA writes into an internal staging buffer and a threaded IRQ handler copies to each consumer buffer.
- Per-file queues remain authoritative. The channel engine borrows a direct owner's buffers for DMA, but queued buffers stay attached to their stream context instead of being migrated into a channel-global software queue.
- `FANOUT` is currently `MMAP`-only. `DMABUF` capture remains supported for `DIRECT` mode, but the branch rejects entering `FANOUT` until multi-consumer destination mapping rules are implemented explicitly.
- The hard IRQ now only acknowledges fanout completions and wakes the threaded handler. Fanout memcpy work no longer runs in hard IRQ context.

The companion test script is:

- `./test_hybrid_multi_consumer.sh`
- It now validates capture progress using `sizeimage` from `VIDIOC_G_FMT` rather than treating any non-empty output file as success.

## Test Coverage Matrix

1. Single consumer baseline (`DIRECT`)
- Test: `Test 1` in `test_hybrid_multi_consumer.sh`
- Expected:
  - stream succeeds
  - output file is non-empty

2. Two overlapping consumers (`FANOUT`)
- Test: `Test 2`
- Expected:
  - both streams run concurrently
  - both outputs are non-empty

3. Mode transition `FANOUT -> DIRECT`
- Test: `Test 3`
- Scenario:
  - consumer A long-running
  - consumer B short-running exits first
- Expected:
  - B completes
  - A continues and completes

4. Original direct owner exits first
- Test: `Test 4`
- Scenario:
  - consumer A starts first in `DIRECT`
  - consumer B joins, pushing the channel into `FANOUT`
  - consumer A is terminated first
- Expected:
  - A has already produced some frame payloads
  - B continues and completes

5. Abrupt close of one consumer
- Test: `Test 5`
- Scenario:
  - two consumers streaming
  - one process is terminated
- Expected:
  - remaining consumer continues successfully

6. Format change while queue(s) busy
- Test: `Test 6`
- Expected:
  - `VIDIOC_S_FMT` size change fails while another stream is active
  - active stream continues

7. Rapid stream on/off loops plus repeated `1 <-> 2` oscillation
- Test: `Test 7`
- Expected:
  - repeated single-open cycles succeed
  - a long-lived primary stream survives repeated short-lived secondary consumers joining and exiting
  - no hangs/timeouts

## Edge Cases and Expected Behavior

1. Stream mode transitions are deferred to frame boundaries
- Path: internal recompute when streamer count changes (`1 <-> 2+`).
- Expected:
  - queued buffers stay on their owning file handle and are not drained just because the mode changed.
  - normal `DIRECT -> FANOUT` and `FANOUT -> DIRECT` transitions are deferred until a safe frame boundary.
  - all consumers that receive a fanout-delivered frame should still see identical sequence/timestamp metadata for that frame.
  - special case: if the current direct owner is the handle being stopped or closed, the branch still forces an immediate direct-path restart so that streamoff/release does not leave that handle holding in-flight DMA buffers.

2. Slow or stalled consumer in fan-out mode
- Expected:
  - stalled consumer may miss frames if it does not keep its queue fed.
  - other consumers can continue receiving frames.

3. Single consumer with no queued buffers
- Expected:
  - capture engine may be active but cannot produce dequeuable frames until user queues buffers.
  - once buffers are queued, direct mode should be kicked and streaming resumes.

4. Consumer process exits without clean streamoff
- Expected:
  - per-file release path removes that consumer context.
  - mode recompute should keep the channel running for surviving consumers.

5. `VIDIOC_S_FMT` semantics with multiple open handles
- Expected:
  - size-changing `S_FMT` should fail if any queue is busy.
  - once all queues are idle, format change is allowed.

6. Live input resolution change while buffers stay large enough
- Expected:
  - the engine is reprogrammed without draining or erroring active queues when the new `sizeimage` still fits existing allocations.
  - direct mode may temporarily stop pre-arming the next buffer while the channel is being reconfigured, but queued buffers remain owned by their original file handle.
  - if the new `sizeimage` exceeds `alloc_sizeimage`, the queues are marked in error and userspace must recover with `STREAMOFF/REQBUFS/STREAMON`.

7. Suspend/resume during active capture
- Expected:
  - suspend path stops engine and marks queues in error.
  - user space should restart streaming after resume.

8. No-signal input source
- Expected:
  - behavior depends on existing no-signal handling path.
  - frame content validity is not guaranteed by this test suite; only stream liveness/non-empty output is checked.

## Known Limits Not Fully Covered by the Script

1. Exact frame integrity between consumers
- Current script checks non-empty outputs and process success, not per-frame byte equality.

2. Performance saturation thresholds
- Bandwidth saturation depends on resolution/fps/CPU and number of consumers.
- For high-rate validation, run longer captures and monitor dropped frames and CPU usage.

3. Long-duration stability
- Script targets functional and transition correctness.
- Run multi-hour soak tests separately for leak and recovery validation.

## Suggested Manual Follow-Ups

1. Long soak:
- Run 2 consumers for 30+ minutes and track:
  - dropped/late frames
  - CPU load
  - kernel warnings

2. Mixed user-space clients:
- Run one stream via `v4l2-ctl` and another via VLC/ffmpeg concurrently.

3. Resolution transition stress:
- Alternate valid resolutions only while all queues are idle.
- Confirm that `S_FMT` fails while busy and succeeds when idle.

## Future Test Cases

These are common scenarios not fully covered by the current scripted suite and should be added as dedicated tests.

1. Abrupt `FANOUT -> DIRECT` boundary exit
- Scenario:
  - two consumers active in `FANOUT`
  - one consumer exits exactly during IRQ/completion and mode recompute
- Goal:
  - verify no deadlock, no use-after-free, and surviving consumer keeps streaming

2. `FANOUT -> DIRECT` with temporary queue starvation
- Scenario:
  - two consumers active
  - one exits
  - remaining consumer briefly has no queued buffers
- Goal:
  - verify direct path re-arms correctly once QBUF resumes

3. Mixed memory/backing modes per consumer
- Scenario:
  - one consumer uses `MMAP`, second uses `DMABUF` (and different queue depths)
- Goal:
  - currently unsupported for `FANOUT`
  - future work: verify mixed queue types and sizes do not break fan-out transitions once that policy is implemented

4. Sequence/timestamp monotonicity across transitions
- Scenario:
  - capture through repeated `DIRECT <-> FANOUT` mode flips
- Goal:
  - verify sequence and timestamp progression remains monotonic and sane

5. Queue error recovery across consumers
- Scenario:
  - trigger queue errors (e.g., busy `S_FMT`, suspend/resume)
  - recover with `STREAMOFF/REQBUFS/STREAMON`
- Goal:
  - verify all consumer handles recover predictably without reboot/reload

6. Signal-loss and re-lock in fan-out mode
- Scenario:
  - run two consumers, force input loss/reconnect
- Goal:
  - verify both streams recover and mode state remains correct
