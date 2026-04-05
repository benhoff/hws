# Hybrid Multi-Consumer Kernel-Grade Assessment

## Summary

This branch is a meaningful architectural improvement over `master`, but it is not yet "Linux kernel grade".

The main positive change is the move from a channel-global vb2 queue to per-file-handle queues plus a channel-level capture state machine. That is a better model for multi-consumer streaming and is much closer to what a robust V4L2 implementation needs.

Recent work also closed several concrete correctness gaps that were previously called out in this document:

- fanout completion no longer walks the consumer list across unlock/relock windows
- `release()` and `stop_streaming()` now wait for in-flight fanout completions before queue teardown
- live mode changes are now deferred through worker state instead of being silently dropped on `mutex_trylock()`
- registration/unwind now uses single-owner `video_device` teardown and cancels pending mode-change work
- the dead `VIDIOC_S_PARM` implementation was removed

That said, the branch is still not ready to be described as production-quality kernel code or an upstream-ready Linux V4L2 implementation.

Latest practical status:

- on `2026-04-05`, the scripted hybrid multi-consumer runtime scenarios passed cleanly on a normal-rate live signal
- on `2026-04-05`, the same script still timed out in Tests 3 and 7 on a very low-rate input of about `1.14 fps`
- `v4l2-compliance` remains at one warning and one failure in representative host runs
- the old buffer-metadata issues (`Field: Any`, first-buffer sequence starting at `1`) are no longer the active blockers
- the remaining compliance failure is the second-opener `REQBUFS`/`EBUSY` mismatch, which is tied to the branch's intentional per-file multi-consumer queue model rather than a simple metadata bug
- the remaining `V4L2_CID_DV_RX_POWER_PRESENT` warning is inherited from `master` and is not a branch-specific regression

## What Improved Versus `master`

1. Per-file queues replace the old channel-global queue.
Each open file handle now owns its own `vb2_queue` and buffer list through `struct hws_vfh_ctx`, instead of all users sharing one channel queue.

2. The capture engine has an explicit mode model.
The branch introduces `HWS_CAPTURE_MODE_NONE`, `HWS_CAPTURE_MODE_DIRECT`, and `HWS_CAPTURE_MODE_FANOUT`, with deferred transitions and ownership tracking in `struct hws_capture_engine`.

3. Fanout copy work moved out of hard IRQ context.
The branch uses a threaded IRQ path for fanout completions instead of doing memcpy-style work in hard IRQ context. This is the right direction for kernel behavior.

4. Live resolution changes are handled more intentionally.
The branch now tries to preserve active queues when the new frame still fits existing allocations, and only forces queue error recovery when the new size exceeds the negotiated allocation.

5. Completed-buffer field metadata is now exported more consistently.
Successful direct, fanout, and no-signal completions now stamp the active negotiated `field` into the returned `vb2_v4l2_buffer`, which removes the earlier `Field: Any` style `v4l2-compliance` regression.

6. First-buffer sequence numbering is now aligned with userspace expectations.
The capture completion paths now start each stream at sequence `0`, so the earlier `got sequence number 1, expected 0` warning class is no longer the active compliance issue.

7. Fanout completion and release ordering are materially safer.
The fanout threaded IRQ path now snapshots per-consumer work under `consumers_lock`, and release/streamoff wait for in-flight fanout completions before queue teardown. That removes the earlier unstable list-walk pattern that was the most concrete lifetime bug in previous revisions of this branch.

8. Live mode changes are now durable instead of best-effort.
Detected mode changes are now coalesced into worker-owned pending state and applied under `state_lock`, rather than being silently skipped when the lock is busy.

9. Failure-path teardown is more coherent.
The registration and unregister paths now use a single `video_device` teardown helper and cancel pending mode-change work before dismantling channel state, which removes the earlier double-teardown risk in the sysfs-registration unwind path.

10. The `G_PARM` / `S_PARM` surface is more honest.
The dead `hws_vidioc_s_parm()` implementation was removed instead of leaving the source tree implying support that the ioctl table did not actually expose.

These are all real improvements. They make the branch more coherent and easier to reason about than `master`.

## Why It Is Not Yet Kernel Grade

### 1. The remaining `REQBUFS` failure is an API-model mismatch, not a small bug

The only remaining `v4l2-compliance` failure is that a second opener can still allocate buffers instead of receiving `-EBUSY`.

That is not an accident in the current branch design. The branch intentionally gives each open handle its own `vb2_queue`, and multi-consumer streaming depends on that same-node, per-file queue model.

So the unresolved question is architectural:

- keep the current same-node multi-consumer behavior and accept that this compliance check fails
- add an explicit opt-in path for fanout semantics while keeping the default node conventional
- redesign the userspace-facing topology around separate nodes or another explicit fanout layer

Until that policy is settled, the branch is not upstream-ready.

### 2. Validation is still branch-grade rather than kernel-grade

The branch now has a much better test story than earlier revisions:

- the scripted direct/fanout scenarios pass on a normal-rate live signal
- the script adapts to low-rate inputs instead of blindly assuming a high frame cadence
- the post-run validation subset now extracts known `v4l2-compliance` signatures into a dedicated findings report

But the validation bar is still below what "kernel grade" should imply.

Missing or incomplete coverage still includes:

- lock-focused stress under `lockdep`
- memory/race validation under `KASAN` and `KCSAN`
- long-duration soak
- exact frame-integrity checks across consumers
- failure-injection coverage for registration and teardown paths
- deeper suspend/resume and signal-loss stress

### 3. Very low-rate live inputs still expose behavioral gaps

On `2026-04-05`, the full scripted suite passed on a normal-rate input around `36.70 fps`, but the same suite still timed out in Tests 3 and 7 on a low-rate input around `1.14 fps`.

That does not prove a kernel race by itself, because the current tests intentionally rely on short-lived peer consumers and a live source that may not deliver enough frames during those windows. But it does mean the current branch is not yet robust enough to claim clean behavior across the low-cadence cases that real hardware may present.

At minimum, this area still needs either:

- stronger low-rate handling in the driver or userspace interaction model
- or a more explicit test and API contract for what should happen when a peer joins and exits while the source cadence is extremely low

### 4. The lock and ownership model is improved but still needs upstream-grade validation

The current implementation is materially safer than before, but it still relies on several interacting synchronization domains:

- `state_lock`
- `irq_lock`
- `consumers_lock`
- per-context `qlock`
- deferred mode-change work

That can be correct, but upstream-quality confidence normally comes from both code review and dedicated stress tooling. Until the branch has been exercised under lockdep/sanitizer coverage and the invariants are documented more explicitly, the locking story should still be treated as improved rather than fully closed.

### 5. The remaining `DV_RX_POWER_PRESENT` warning is inherited, but still part of the observed surface

The missing `V4L2_CID_DV_RX_POWER_PRESENT` warning is not a regression introduced by this branch. `master` does not expose it either, and this branch intentionally no longer tries to add it independently.

That warning is not the reason this branch is considered not kernel grade. The `REQBUFS` behavior and the validation gaps above are the real blockers. But the warning should still be documented honestly in the current validation snapshot.

## Must-Fix Items Before Calling It Kernel Grade

### 1. Decide the public API story for multi-consumer queue ownership

This is now the top remaining blocker.

The branch needs one explicit policy:

1. accept and document the current same-node multi-consumer behavior, understanding that it diverges from a conventional `REQBUFS` ownership model
2. introduce an opt-in fanout path while keeping the default node conventional
3. redesign the topology so the capture node and the fanout/distribution path are separated

Until that choice is made, the remaining compliance failure is expected but unresolved.

### 2. Strengthen low-rate and long-duration validation

The branch now behaves well on a normal-rate source, but low-rate live inputs still show timeouts in transition-heavy tests.

Before calling the branch kernel grade, validate:

- normal-rate and very low-rate live signals
- long soak under repeated `1 <-> 2` consumer oscillation
- abrupt join/exit near frame boundaries
- queue starvation and refill recovery

### 3. Document and validate lock ordering and invariants

The code should explicitly describe the intended ownership and lock ordering for:

- `engine.active`
- `engine.next_prepared`
- `engine.direct_owner`
- the consumer registry
- per-context queue ownership
- deferred mode-change state

That documentation should then be backed by stress testing and assertions where practical.

### 4. Strengthen observable state and diagnostics

Before calling this branch robust, add better observability for:

- `DIRECT -> FANOUT` transitions
- `FANOUT -> DIRECT` transitions
- dropped frames
- queue starvation
- queue errors
- mode-change retries or coalescing

Tracepoints, debug counters, or at least strongly structured debug logs would make review and stress testing far easier.

### 5. Run upstream-grade tooling, not just functional scripts

Before describing the branch as kernel grade, it should be exercised under:

- `lockdep`
- `KASAN`
- `KCSAN`
- failure injection for registration and teardown paths
- `v4l2-compliance` against the final intended userspace API

## Validation Bar for "Kernel Grade"

At a minimum, the branch should clear the following bar before being described that way.

### Build and static sanity

- clean builds across supported kernels
- `W=1` or equivalent warning review
- no obvious lockdep complaints under stress

### Concurrency and memory safety

- repeated open/close while streaming
- repeated `1 <-> 2` consumer oscillation
- abrupt consumer death during fanout completion
- validation under `lockdep`
- validation under `KASAN`
- validation under `KCSAN`

### Functional stress

- long soak with two or more consumers
- frame integrity checks across consumers, not just non-empty output
- queue starvation and refill recovery
- repeated `STREAMOFF/REQBUFS/STREAMON` recovery
- suspend/resume during active capture
- signal loss and relock while in fanout mode

### API behavior

- predictable `S_FMT` behavior with multiple open handles
- predictable `S_DV_TIMINGS` behavior while queues are active
- explicit and tested `G_PARM` / `S_PARM` policy
- consistent rejection or policy enforcement for unsupported mixed memory modes
- `v4l2-compliance` coverage for the advertised ioctl surface
- failure-injection coverage for registration and sysfs-creation unwind paths

## Practical Bottom Line

If the question is "is this branch closer to a kernel-quality design than `master`?", the answer is yes.

If the question is "would I call this production-quality or upstream-quality Linux kernel code today?", the answer is still no.

The branch has the right architectural direction:

- per-file queues
- explicit direct vs fanout capture modes
- deferred mode transitions
- threaded fanout completion work

But the remaining same-node `REQBUFS` semantics question and the still-shallow validation story are enough to keep it out of the "kernel grade" bucket.

## Suggested Next Steps

1. Decide whether the current same-node multi-consumer queue model is the intended userspace API, or whether it needs a more conventional capture/fanout split.
2. Add targeted low-rate transition coverage and decide whether the observed low-fps timeouts are driver issues or test-contract issues.
3. Document lock ordering and engine invariants in code and review material.
4. Add stress tests that specifically target abrupt join/exit and queue-starvation windows.
5. Re-evaluate after lockdep/KASAN/KCSAN, `v4l2-compliance`, failure-injection, and soak coverage.

Until those are done, this branch should be treated as a strong refactor/prototype branch, not a finished kernel-grade implementation.
