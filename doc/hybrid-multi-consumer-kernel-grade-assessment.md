# Hybrid Multi-Consumer Kernel-Grade Assessment

## Summary

This branch is a meaningful architectural improvement over `master`, but it is not yet "Linux kernel grade".

The main positive change is the move from a channel-global vb2 queue to per-file-handle queues plus a channel-level capture state machine. That is a better model for multi-consumer streaming and is much closer to what a robust V4L2 implementation needs.

However, the current implementation still has concurrency, lifetime, and validation gaps that are too significant for production-quality kernel code or upstream submission.

Latest practical status:

- the scripted hybrid multi-consumer runtime scenarios can now pass cleanly on a normal-rate live signal
- `v4l2-compliance` is down to one warning and one failure in a representative host run
- the old buffer-metadata issues (`Field: Any`, first-buffer sequence starting at `1`) are no longer the active blockers
- the remaining compliance failure is the second-opener `REQBUFS`/`EBUSY` mismatch, which is tied to the branch's intentional per-file multi-consumer queue model rather than a simple metadata bug

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

These are all real improvements. They make the branch more coherent and easier to reason about than `master`.

## Why It Is Not Yet Kernel Grade

### 1. Consumer lifetime is not safe enough in the fanout path

The most serious issue is the interaction between the fanout IRQ thread and `release()`.

In the fanout completion path, the code iterates `v->consumers`, drops `consumers_lock`, processes a consumer buffer, then reacquires the lock and continues the same list walk:

- `src/hws_irq.c`: `hws_video_handle_vdone_fanout()`

At the same time, `release()` can remove that same `ctx` from the list and free it:

- `src/hws_video.c`: `hws_release()`

That pattern is not safe for kernel code. It creates a real risk of:

- use-after-free
- invalid iterator state after relock
- list corruption or stale pointer reuse during close or stream shutdown

This is the main blocker to calling the branch kernel grade.

### 2. Live mode changes can be dropped silently

`hws_video_apply_mode_change()` uses `mutex_trylock()` and simply returns if the lock is busy.

That means a detected input mode change can be skipped with no deferred retry and no durable "pending mode change" record. In practice, the next polling cycle may notice again, but that is still best-effort behavior rather than a correctness guarantee.

For kernel-grade code, mode detection and reconfiguration should not depend on a transient lock race.

### 3. Teardown and quiesce behavior are not fully deterministic

The branch has improved teardown paths, but they still do not provide the kind of strict shutdown guarantees expected from production kernel code.

Examples:

- engine stop primarily handles direct-path in-flight buffers
- per-consumer queued buffers are not always drained under one unified teardown model
- unregister/quiesce paths rely heavily on queue error signaling rather than explicit completion and synchronization
- the release path does not make a strong enough guarantee that no threaded IRQ path can still observe a soon-to-be-freed consumer context

For remove, suspend, error recovery, and hot-unplug scenarios, kernel code should be more explicit and more deterministic than this.

### 4. The lock and ownership model is still too fragile

The implementation now uses several separate synchronization domains:

- `state_lock`
- `irq_lock`
- `consumers_lock`
- per-context `qlock`

That can be correct, but only if the invariants and lock ordering are extremely clear. Right now the code does not yet establish a sufficiently crisp, documented lock hierarchy or ownership contract for:

- `engine.active`
- `engine.next_prepared`
- `engine.direct_owner`
- the `consumers` list
- each context's private queued buffers

Kernel-grade code needs those rules to be obvious and defensible, because future maintenance otherwise tends to reintroduce races quickly.

### 5. Validation is still branch-grade rather than kernel-grade

The branch includes useful design notes and a companion test script, but the validation bar is still limited.

The current script is better than it was before:

- it covers the core direct/fanout runtime transitions
- it runs a post-test `v4l2-compliance` pass when the tool is available
- it now calls out known buffer-metadata signatures such as `V4L2_FIELD_ANY` and `buf.check(q, last_seq)` in a dedicated findings report
- it adapts its functional frame/time budget to low-rate live inputs so a ~`1 fps` source does not trivially invalidate every transition test

That closes one concrete regression class, but it does not change the broader conclusion below.

The current material explicitly acknowledges missing coverage for:

- abrupt `FANOUT -> DIRECT` exit races
- exact frame integrity between consumers
- long-duration stability
- queue error recovery scenarios
- signal-loss and relock behavior in fanout mode

At the current branch state, a representative `v4l2-compliance` run is much closer to clean than before, but it still shows at least one remaining behavioral mismatch around second-opener `REQBUFS`/`EBUSY` semantics, plus a warning about `V4L2_CID_DV_RX_POWER_PRESENT`.

That is good engineering honesty, but it also means the branch is not yet validated to the level implied by "kernel grade".

### 6. Registration error unwind still has an object lifetime bug

The `hws_video_register()` failure path is not safe enough around `video_device` ownership.

On the `hws_resolution_create()` failure path, the code does:

- `video_unregister_device(vdev)`
- then falls into `err_unwind`
- then reuses `ch->video_device` during the unwind loop

Those steps are not interchangeable. Once `video_unregister_device()` runs, the `video_device` may already have been released through its `->release` callback. Continuing to inspect or free that same pointer in generic unwind code creates a real risk of:

- use-after-free in the unwind loop
- double release or double unregister style teardown
- failure-path-only crashes that are easy to miss in normal testing

Kernel-grade code needs the registration path to have single-owner, single-release semantics even under partial initialization failure.

### 7. The userspace API surface is internally inconsistent

The branch still carries an implementation of `hws_vidioc_s_parm()`, but the ioctl table no longer exposes `.vidioc_s_parm`.

That leaves the driver in an awkward state:

- the source implies `VIDIOC_S_PARM` support exists
- userspace receives unsupported-ioctl behavior instead
- `VIDIOC_G_PARM` and `VIDIOC_S_PARM` no longer form a coherent pair

This is not the worst defect in the branch, but it is still below kernel-grade polish. At best it is dead code and an avoidable compatibility regression. At worst it causes confusing behavior in userspace and `v4l2-compliance`.

## Must-Fix Items Before Calling It Kernel Grade

### 1. Fix consumer lifetime and list-walk safety

This is the first hard blocker.

Acceptable directions include:

1. Add reference counting to `struct hws_vfh_ctx`
- take a ref while selecting work under `consumers_lock`
- drop the lock
- process the consumer safely
- put the ref after use

2. Use an RCU-style consumer list and deferred free
- if the list really needs lockless or relock-heavy traversal
- still pair this with explicit ownership rules for queued buffers

3. Snapshot work items under the lock
- build a temporary stable list or array of consumer work targets under `consumers_lock`
- drop the lock
- process those items without continuing an unstable kernel list iteration

Any of these can be made correct. The current pattern should not remain.

### 2. Replace dropped mode changes with deferred work

The mode-change path should not just give up on `mutex_trylock()` failure.

The better pattern is:

1. record the newly detected mode in stable channel state
2. queue a worker
3. let the worker take `state_lock`
4. coalesce repeated changes and apply only the latest valid state

This gives deterministic behavior under load and makes the detection path auditable.

### 3. Make teardown and release synchronization explicit

Before freeing a consumer context, the code should make it impossible for either the hard IRQ path or the threaded IRQ path to still reference that context.

That generally means:

1. mark the context dead and remove it from selection under the appropriate lock
2. synchronize any pending threaded work or IRQ visibility for that channel
3. only then release the vb2 queue and free the context

Similarly, suspend, unregister, and error paths should:

- stop the engine
- prevent further consumer selection
- complete or error all affected buffers in a deterministic way
- only then release higher-level objects

### 4. Document and enforce lock ordering

The code should define and follow a single lock ordering scheme. For example:

1. `state_lock` as the outer state transition lock
2. `consumers_lock` for the consumer registry and channel-level ownership pointers
3. per-context `qlock` for a specific context queue
4. `irq_lock` only for the engine's in-flight pointer state

The exact order may differ, but it needs to be deliberate, documented, and backed by assertions where practical.

### 5. Strengthen observable state and diagnostics

Before calling this branch robust, add better observability for:

- `DIRECT -> FANOUT` transitions
- `FANOUT -> DIRECT` transitions
- dropped frames
- queue starvation
- queue errors
- mode-change retries or coalescing

Tracepoints, debug counters, or at least strongly structured debug logs would make review and stress testing far easier.

### 6. Fix registration unwind ownership after `video_unregister_device()`

The registration path should never continue to treat a `video_device *` as live after handing it to `video_unregister_device()`.

The simplest acceptable fix is:

1. make the failure path choose exactly one teardown primitive per object
2. clear `ch->video_device` immediately after unregistering or releasing it
3. structure `err_unwind` so it never re-visits an already released node

Failure paths are part of the correctness story in kernel code, not cleanup afterthoughts.

### 7. Make `G_PARM` / `S_PARM` policy consistent

The driver should make one explicit choice and implement it cleanly:

1. either expose both `VIDIOC_G_PARM` and `VIDIOC_S_PARM` with a defensible policy
2. or reject `S_PARM` intentionally and remove the dead handler

Half-implemented ioctl support is the wrong middle ground for production kernel code.

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

But the concurrency and teardown details are not yet strong enough, and the validation story is not yet deep enough, to justify calling it kernel grade.

## Suggested Next Steps

1. Fix the fanout consumer lifetime race first.
2. Replace best-effort live mode changes with deferred work.
3. Harden release, quiesce, suspend, and unregister ordering.
4. Document lock ordering and engine invariants.
5. Fix the registration unwind path so `video_device` lifetime is single-owner and single-release.
6. Decide whether `VIDIOC_S_PARM` is supported, then wire it or remove it consistently.
7. Add stress tests that specifically target the known race windows.
8. Re-evaluate after lockdep/KASAN/KCSAN, `v4l2-compliance`, failure-injection, and soak coverage.

Until those are done, this branch should be treated as a strong refactor/prototype branch, not a finished kernel-grade implementation.
