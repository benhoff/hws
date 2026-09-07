# Deterministic tests of the current VDONE implementation

Run on this host without a GPU, capture card, sudo, driver reload, or another
machine:

```sh
make -C tools check-irq
make -C tools check-irq-mutations
make -C tools check-irq-sanitize
```

`make -C tools check` also runs `check-irq`. The normal suite typically takes
seconds; sanitizer execution is slower. A failed assertion or sanitizer report
fails the command. Assertions cannot be disabled with `NDEBUG`.
Assertion failures identify the case, schedule number, and MMIO injection point
and half so the same deterministic sequence can be located and reproduced.

## Code under test

`build_hws_irq_test.py` generates a disposable translation unit from the current
`src/hws_irq.c`. It replaces include directives, not function bodies. Video
state declarations, enums and inline layout checks come directly from
`src/hws.h`; register definitions and probe declarations also come from their
production headers. Make dependencies regenerate it when these sources change.
There is no baseline implementation or independently rewritten completion state
machine. Kernel module builds do not include or use this adapter.

The test supplies a single-channel environment: sticky write-one-to-clear status,
an alternating active-half toggle, a simulated private DMA ring, deterministic
time, queued work and application-owned buffers. MMIO hooks inject another
hardware completion after each of the six status/toggle read or acknowledge
write operations of the handler, for both assembly halves. Copy hooks interrupt
the simulated memcpy halfway through either half. These are explicit model
assumptions, not measurements of the physical card.

## Checks performed

- Normal startup synchronization and full frame delivery.
- Duplicate while a partial frame is active; that buffer must be recycled and
  both halves overwritten before delivery.
- Duplicate after delivery, and a 300-event startup duplicate burst including
  saturation of the streak counter, followed by forward progress.
- Empty destination queue, then replenishment and resumed delivery.
- Completion arriving with a pending worker or during either half's copy.
- Deadline expiry, its exact boundary, invalid configured rates, equal and
  backward timestamps, guard failure and a stop request before/during copying.
- All 4,096 length-six schedules over normal completions, repeated toggles,
  completions with deferred work, and worker execution. Each nonfatal schedule
  must resume delivery within twelve subsequent ordinary half completions.
- Another 625 length-four schedules add two DMA advances with no handler.
- Zero through six withheld DMA boundaries after either half, including all
  14 enumerated progressive timing entries and unequal native half sizes.
- Just below, at and above the 1.5-half-period continuity limit for each mode;
  saved-half age, epoch changes during copy, invalid timing, source holds,
  and missed boundaries during startup and copying.
- Queue accounting and exclusive buffer ownership after each simulated step.
  Completion requires driver ownership; a buffer cannot be completed twice
  without being requeued.

Every delivered byte is checked against the independent simulated source frame
ID. Both halves must contain one matching ID, and delivered IDs must increase
except in the explicit source-hold test, which permits repeated complete IDs.
Skipped source IDs are permitted by the recovery contract. This is not a
zero-loss assertion, and a passing run does not explain physical duplicate IRQs.

Mutation tests deliberately alter **temporary generated copies only**: wrong
half selection, disabled duplicate detection, failure to clear the active
pointer after recycling, and disabled saved-half continuity. All four must
compile and then fail assertions. This
checks that the suite notices these defects; it does not establish exhaustive
fault detection. Production files are never mutated by these tests.

## Limits

The [2026-09-06 end-to-end review](driver-end-to-end-review.md) found DMA advances
without observed IRQ boundaries missing from the original suite. These cases
are now permanent regressions. `python3 tools/review_irq_gap.py` also remains
available: after the [continuity fix](vdone-continuity.md), all eight cases pass,
with no mixed delivery. This does not establish that hardware generated the
original counterexample or that arbitrary DMA/handler timing is safe. The guard
is conditional on the configured cadence and observed timestamps; stronger
hardware identity and adversarial delayed-observation qualification remain open.

This is not a kernel/lockdep/KCSAN test. Locks enforce modeled ownership but do
not reproduce multicore memory ordering, actual workqueue internals, CPU IRQ
masking or PCIe/DMA ordering. Audio, simultaneous channels, STREAMOFF teardown,
device removal and DMA after stop are outside this suite. The stop-request test
does not release buffers or claim to prove DMA quiescence. Guard and VB2
framework operations are simulated; their production implementations are not
covered here. Optional ring-probe/trace instrumentation is disabled in the model.

AddressSanitizer and UndefinedBehaviorSanitizer check the userspace executable,
not the loaded kernel module. Passing establishes the checked properties for
these deterministic modeled scenarios only. Hardware content/timing tests and
the outstanding shutdown/post-stop-DMA tests remain necessary.
