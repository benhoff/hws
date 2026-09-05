# HWS VDONE semantics and evidence register

This is the canonical statement of VDONE behavior. Historical notes are useful
for chronology, but they do not broaden the claims recorded here.

## Rule for every claim

VDONE semantics are configuration-dependent. A claim is valid only for the
evidence row that names the PCI identity, hardware revision, channel, mode,
format, frame size, programmed split, register readback, IRQ mode, driver
commit, content result, and preserved artifact.

Use this form:

> For configuration `<evidence-id>`, the programmed split produced
> `<observed semantics>`.

Do not write an unqualified statement that VDONE is per-frame or per-half.

The machine-readable register is
[`doc/evidence/vdone-matrix.csv`](evidence/vdone-matrix.csv). A row is
`validated` only when its artifact passes the validator in
[`tools/hws_vdone_evidence.py`](../tools/hws_vdone_evidence.py). A narrative
recovered from session history without its raw artifact is
`historical-summary`, not `validated`.

Use `unknown`, `not-run`, or `unavailable` explicitly when an older record
lacks a required value. Such a row documents the limit of the surviving
evidence and can never be promoted to `validated`.

## Current implementation contract

The driver programs the native split:

```text
split = round_down(sizeimage / 2, 2048)
split_register = split / 16
```

It treats the stable post-W1C toggle as the half currently being filled, so the
completed half is `toggle ^ 1`. It copies complementary halves from a permanent
guarded ring and publishes a V4L2 buffer only after both halves have been
assembled. A stable duplicate or copy overlap recycles any incomplete,
driver-owned destination and resumes synchronization; it never publishes the
partial destination.

This is an implementation contract, not proof that every listed device,
channel, and mode exhibits the same hardware behavior.

## Existing evidence

The surviving historical record reports the following on PCI `8888:8504`,
YUYV 1920x1080p60:

| Evidence ID | Channel | Split | Result | Evidence status |
| --- | ---: | ---: | --- | --- |
| `HWS-8504-CH3-1080P60-NATIVE-20260824` | 3 | 2,072,576 | Approximately 120 VDONE/s; content pairing and `toggle ^ 1` mapping passed | Historical summary; raw artifact no longer reachable |
| `HWS-8504-CH3-1080P60-EXACT-20260824` | 3 | 2,073,600 | Approximately 60 VDONE/s; every decoded event contained matching upper/lower IDs | Historical summary; raw artifact no longer reachable |
| `HWS-8504-CH1-1080P60-NATIVE-20260904` | 1 | 2,072,576 | 119.4 VDONE/s and alternating accepted toggles with isolated same-toggle recoveries | Rate/toggle evidence only; frame-content proof pending |

The first new validation target is channel 1 at the native split. Until it
passes, the strongest permissible statement is:

> On `8888:8504` channel 1 at YUYV 1920x1080p60 with split 2,072,576,
> IRQ rate and toggle behavior strongly support per-segment VDONE, but
> same-source-frame pairing has not yet been content-proven.

## Validation gates

A run passes only when all of the following hold:

- The trace contains no lost records and the configured split remains stable.
- Every observed VDONE has exactly one recorded disposition.
- Every accepted VDONE records `completed_half == stable_toggle ^ 1`.
- Every successful copy links to exactly one accepted IRQ with the same stable
  toggle and completed half.
- Every delivered frame links to consecutive half-0 and half-1 generations,
  and both generations link to exactly one guarded copy with the configured
  offset and length.
- Every trace-delivered sequence has a corresponding captured content record.
- Both independently decoded frame IDs are valid and equal.
- Captured IDs never move backward.
- No delivered buffer retains its pre-QBUF poison or has a short/error payload.
- Guard errors, fatal VDONE dispositions, and unrecovered queue failures are
  zero.
- Final configuration and guard evidence is preserved with the run.
- The device/channel identity and all capture-layout fields agree, the native
  split formula holds, and the complete artifact inventory passes SHA-256
  verification.

Repeated source IDs are measurements, not failures. They must not be described
as DMA repetition unless source-side evidence rules out display repetition.

## Claim levels

- **Configuration-specific:** one PCI identity, revision, channel, mode,
  format, split, driver build, and IRQ mode passed.
- **Board-specific:** every exposed channel and every advertised mode passed on
  that physical board, followed by simultaneous-channel coverage.
- **Device-ID-specific:** the board-specific result was repeated on appropriate
  revisions/firmware for that PCI ID.
- **Family-wide:** every claimed PCI ID is validated or explicitly excluded.

No narrower claim automatically promotes to the next level.
