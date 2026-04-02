# Hybrid Multi-Consumer Refactor Plan

## Goal

Land multi-consumer capture on top of current `master` without importing the vendor Acasis architecture wholesale.

The target behavior is:

- keep the current split `master` layout and standard V4L2/VB2 structure;
- preserve the zero-copy direct-DMA fast path for one streaming consumer;
- provide true same-frame fanout when two or more consumers stream at once;
- avoid Acasis-style internal vendor buffering, CPU-only copy pipelines, and monolithic driver structure.

## Summary Recommendation

The current `feat/hybrid-multi-consumer` branch is the right direction, but not the cleanest final shape.

What should be kept:

- explicit `NONE` / `DIRECT` / `FANOUT` capture modes;
- one per-open streaming context with its own `vb2_queue`;
- direct DMA into user buffers for the single-consumer case;
- a real fanout path that gives multiple consumers the same frame.

What should be changed:

- stop treating the channel-global queue as a temporary owner of per-file buffers;
- stop doing fanout copies in the hard IRQ path;
- stop treating `DMABUF` fanout support as solved until the mapping rules are explicit;
- keep vendor processing features such as scaling and rotation out of the core capture path.

## Concrete Architectural Recommendation

Use a strict producer/consumer split:

- one hardware-facing capture engine per channel owns hardware state and DMA programming;
- each open file handle keeps its own queue and never transfers queue ownership to the channel object;
- a small dispatcher layer decides whether the engine is in direct or fanout mode;
- mode switches happen at frame boundaries and should not invalidate queued buffers unless the format changes or the engine hits a real error.

In practice, this means `master` should evolve toward three distinct responsibilities:

1. `struct hws_video`

- channel-level V4L2 object;
- format state, controls, and stream list;
- lock domain for policy decisions such as mode changes, suspend/resume, and format changes.

2. `struct hws_capture_engine`

- hardware-facing per-channel state;
- current capture mode;
- active DMA target and optional pre-armed DMA target;
- sequence counter and frame metadata for the current completed frame;
- fanout staging buffer and related DMA mapping.

3. `struct hws_vfh_ctx`

- one instance per open file handle;
- per-file `vb2_queue`;
- queued buffers owned only by that file handle;
- streaming flag and memory-mode constraints for that stream.

## Data Ownership Rules

These rules should drive the refactor:

- A buffer queued by a file handle stays owned by that file handle until it is completed or cancelled.
- The engine may borrow a buffer from the direct owner for hardware DMA, but it should not permanently move buffers into a channel-global software queue.
- Fanout mode uses a staging buffer owned by the engine, not another consumer's buffer.
- A consumer with no queued buffer drops that frame only for itself. It must not block other consumers or stall the engine.

## Mode Rules

The mode machine should be simple and explicit:

1. `NONE`

- no streaming contexts;
- engine stopped;
- no active DMA target.

2. `DIRECT`

- exactly one streaming context;
- engine DMA targets come directly from that context's queued buffers;
- pre-arming the next direct buffer is allowed.

3. `FANOUT`

- two or more streaming contexts;
- engine DMA always targets a channel-owned staging buffer;
- each completed staged frame is copied or otherwise delivered to each consumer with a queued destination buffer.

Mode transitions:

- `NONE -> DIRECT`: arm first queued buffer from the sole streaming context.
- `DIRECT -> FANOUT`: finish or cancel only the in-flight direct DMA buffer as needed, then start using the staging buffer. Remaining queued buffers stay on the original stream context and become normal consumer buffers.
- `FANOUT -> DIRECT`: when only one streaming context remains, stop using the staging buffer and resume programming that context's queued buffers directly.
- `* -> NONE`: stop hardware and return all pending buffers with error or queue state consistent with normal streamoff semantics.

## Delivery Policy

### Direct mode

- Pop the next buffer only from the owning stream context.
- Program hardware DMA directly to that buffer.
- Complete buffers from the normal completion path with the current sequence and timestamp.

### Fanout mode

- Program hardware DMA to a coherent staging buffer owned by the channel engine.
- On frame completion, package the frame metadata once: sequence number, timestamp, payload length, and any no-signal marker.
- Deliver that same frame to all streaming contexts that have a queued destination buffer.
- Every consumer that receives the same source frame must get the same sequence and timestamp.

## IRQ and Worker Recommendation

Fanout copies should not run in the hard IRQ path.

Recommended split:

- hard IRQ:
  - acknowledge the hardware interrupt;
  - capture minimal completion metadata;
  - queue direct completion or fanout work;
  - program the next DMA target if the engine state already allows it.

- threaded IRQ or ordered workqueue:
  - perform fanout memcpy work;
  - touch consumer queues and call `vb2_buffer_done()` for fanout completions;
  - handle optional no-signal frame synthesis if that remains part of the design.

This keeps interrupt latency bounded and avoids scaling the top-half cost with consumer count.

## Memory-Mode Recommendation

The first implementation should make memory-mode behavior explicit rather than optimistic.

Recommended version 1 policy:

- `DIRECT` mode may support `MMAP` and `DMABUF`.
- `FANOUT` mode should support `MMAP` first.
- `DMABUF` in `FANOUT` should be rejected or disabled until the driver has explicit and validated CPU mapping semantics for every destination buffer type used in fanout delivery.

Do not advertise full multi-consumer `DMABUF` support until this policy is implemented and tested.

## Recommended File Responsibilities

Keep the current split-file direction in `master` and add one new capture-engine unit.

- `src/hws_video.c`
  - video-device registration;
  - file open/release;
  - stream-context lifetime;
  - queue-switch wrappers if they remain necessary.

- `src/hws_v4l2_ioctl.c`
  - ioctl operations;
  - format changes;
  - streamon/streamoff policy hooks into the engine.

- `src/hws_irq.c`
  - interrupt acknowledgement;
  - direct completion path;
  - scheduling fanout completion work, not performing fanout copies inline.

- `src/hws_capture.c` and `src/hws_capture.h`
  - engine mode machine;
  - direct-owner selection;
  - fanout staging-buffer allocation and teardown;
  - next-buffer programming helpers;
  - suspend/resume capture-engine transitions.

## Concrete Refactor Steps

### Phase 1: Isolate responsibilities without changing behavior

- Introduce an engine helper unit and move the hybrid mode-transition code there.
- Move `capture_mode`, `direct_owner`, active DMA pointers, sequence counter, and fanout staging-buffer fields under an engine-specific sub-structure.
- Keep the existing per-file `hws_vfh_ctx` shape.

### Phase 2: Remove channel-global queue ownership

- Stop migrating queued buffers from a stream context into a channel-global queue.
- Replace that logic with helpers that pop direct-mode buffers from the owning stream context only.
- Keep per-stream queues authoritative in all modes.

### Phase 3: Move fanout work out of IRQ context

- Replace inline fanout buffer copies with a deferred completion path.
- Preserve same-frame metadata across all consumers.
- Keep the direct single-consumer completion path fast and simple.

### Phase 4: Make memory-mode policy explicit

- Gate fanout support on a supported destination memory type.
- Reject unsupported combinations early in `REQBUFS` or `STREAMON`.
- Document the policy in code comments and V4L2 capability behavior.

### Phase 5: Stabilize mode transitions

- Ensure `DIRECT -> FANOUT` and `FANOUT -> DIRECT` transitions do not require userspace to close and reopen the device.
- Avoid draining or erroring queued buffers during a normal consumer-count transition.
- Reserve queue errors for real faults, suspend, format changes requiring reallocation, or hardware-stop paths.

### Phase 6: Optional cleanup

- Revisit whether the temporary `video_device->queue` swapping wrappers should remain or be replaced with more explicit per-file queue dispatch.
- Add broader `DMABUF` fanout support only after there is a tested mapping model.

## Acceptance Criteria

The refactor is complete only when all of the following are true:

- One streaming file handle still uses direct DMA into its queued buffers.
- Two or more streaming file handles receive the same frame contents, sequence, and timestamp.
- Starting a second consumer does not force the first consumer to restart streaming.
- Stopping one of multiple consumers does not disturb the others.
- Format changes only invalidate buffers when the required buffer size actually changes.
- Fanout memcpy work no longer happens in hard IRQ context.
- Suspend/resume returns all affected queues to a well-defined error state and can recover cleanly on the next stream start.

## Out of Scope

These items should not be folded into the refactor:

- Acasis scaling, rotation, and other CPU-heavy transform paths;
- ALSA/audio work;
- ProCapture-style private event devices;
- broad `USERPTR` support unless there is a separate, explicit design for it.
