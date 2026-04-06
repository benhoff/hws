# Audio Capture Investigation Summary

This document summarizes the current HWS HDMI audio investigation for the
`0x8504` board and records what has been confirmed, disproven, and still needs
to be isolated.

It is intended to prevent the same dead ends from being retried and to keep the
next debugging steps tied to hard evidence instead of assumptions.

## Scope

The problem started as:

- only one HWS ALSA capture endpoint was visible
- expected behavior for this board was one userspace-visible audio endpoint per
  video input

After fixing the visible endpoint count, the problem became:

- `hw:5,0..3` all exist
- direct ALSA capture still fails with:

```text
arecord: pcm_read:2285: read error: Input/output error
```

That failure is different from the earlier sound-server contention issue:

- contention failure: `Device or resource busy`
- current failure: stream opens, then read path fails after start

## Current Repo Instrumentation

The following investigation helpers were added during this work:

- [`test_audio_capture.sh`](../test_audio_capture.sh)
- [`test_hdmi_output_loop.sh`](../test_hdmi_output_loop.sh)
- [`test_audio_trace_matrix.sh`](../test_audio_trace_matrix.sh)
- [`test_bar0_snapshot_diff.sh`](../test_bar0_snapshot_diff.sh)

Kernel-side probes and trace support were added in:

- [`src/hws_pci.c`](../src/hws_pci.c)
- [`src/hws_audio.c`](../src/hws_audio.c)
- [`src/hws_irq.c`](../src/hws_irq.c)

The most important live probe interfaces are:

- `/sys/bus/pci/devices/0000:17:00.0/audio_reg_probe`
- `/sys/bus/pci/devices/0000:17:00.0/audio_reg_probe_run`
- `/sys/bus/pci/devices/0000:17:00.0/audio_reg_probe_slots`
- `/sys/bus/pci/devices/0000:17:00.0/audio_reg_probe_remap`

## What Has Been Confirmed

### 1. ALSA topology was under-enumerated, and that part was fixed

For device `0x8504`, the current branch originally exposed only one ALSA capture
endpoint because [`src/hws_pci.c`](../src/hws_pci.c) classified it as
`cur_max_linein_ch = 1`.

That was changed to expose four ALSA devices, matching the baseline branch's
userspace-visible behavior:

- `hw:5,0`
- `hw:5,1`
- `hw:5,2`
- `hw:5,3`

### 2. Sound-server contention was real earlier, but is not the current failure

Earlier in the investigation, PipeWire auto-opened the HWS PCM devices and
caused `Device or resource busy`.

That was real, but the current failure mode is different:

- the device opens
- capture starts
- `pcm_read()` fails with `Input/output error`

That points at the driver/hardware path after stream start, not at userspace
device contention.

### 3. Video is present during the failing loop tests

The HDMI loop tests drive audio through a real HDMI output while also opening
the matching V4L2 node.

The kernel BAR snapshots show matching active video bits during the runs:

- input 0 test: `active=00000001`, `vcap=00000001`
- input 3 test: `active=00000008`, `vcap=00000008`

So these failures are not simply "audio-only source" mistakes.

### 4. At least one earlier build had a working channel 0 audio path

At an earlier point in the investigation, with live HDMI audio on physical
input 0, channel 0 produced:

- `audio-trace:irq`
- `audio-trace:deliver`

That proves the basic ADONE -> DMA -> ALSA delivery pipeline can work on this
hardware family in some build/state.

## What Has Been Disproven

### 1. Not just an enumeration problem

Fixing the userspace-visible ALSA device count from 1 to 4 did not solve the
actual capture failure.

### 2. Not just PipeWire or PulseAudio holding the PCM devices open

When the current failure occurs, `arecord` does not fail at open. It fails after
stream start with `pcm_read()`.

That does not match the usual "server already owns the PCM device" symptom.

### 3. Not just "no audio source attached"

The failing loop tests had a live HDMI path with matching video activity on the
same input. The failing runs still showed:

- channel selected
- audio base register seeded
- capture enable bit set
- no DMA
- no ADONE

### 4. Not fixed by the obvious buffer-layout and startup-order experiments

The following experiments were tried and did not solve the issue:

- separate audio scratch buffer vs video-tail audio buffer
- 10 KiB audio window restoration
- full baseline-sized 4 MiB video DMA backing buffer
- init-time audio seeding
- start-time audio seeding
- IRQ ordering changes
- decoder start-run ordering changes
- attempted IRQ-fabric restore / reopen logic

### 5. Not explained by an obvious baseline-only init write

The baseline branch was searched for:

- `INT_EN_REG_BASE`
- `PCIEBR_EN_REG_BASE`
- `PCIE_INT_DEC_REG_BASE`
- `SetDMAAddress`
- `InitVideoSys`
- `ReadChipId`
- audio start/stop logic

No clear baseline-only "unlock" sequence was found that would explain the dead
audio paths in the current branch.

## Strongest Low-Level Evidence

### 1. The live MMIO decode is sparse

The in-kernel probe output from:

- `/sys/bus/pci/devices/0000:17:00.0/audio_reg_probe`

showed the following stable behavior:

- `INT_EN` is clamped to `0x00030100`
- `PCIEBR_EN` is clamped to `0x00000000`
- `PCIE_INT_DEC` reads as `0x00000000`
- `ch0.audio_base` latches writes
- `ch3.audio_base` latches writes
- `ch1.audio_base` does not latch writes
- `ch2.audio_base` does not latch writes

Representative probe result:

```text
INT_EN.probe orig=0x00030100 test=0x0003ffff readback=0x00030100
PCIEBR_EN.probe orig=0x00000000 test=0x00000001 readback=0x00000000
ch0.audio_base.probe reg=0x4060 ... readback=0x20123000
ch1.audio_base.probe reg=0x4064 ... readback=0x00000000
ch2.audio_base.probe reg=0x4068 ... readback=0x00000000
ch3.audio_base.probe reg=0x406c ... readback=0x80123000
```

### 2. Slot probe proved that slots 9 and 10 are dead

Triggering:

```bash
echo run | sudo tee /sys/bus/pci/devices/0000:17:00.0/audio_reg_probe >/dev/null
cat /sys/bus/pci/devices/0000:17:00.0/audio_reg_probe
```

showed:

- writable slots: `0`, `1`, `2`, `3`, `8`, `11`
- dead slots: `4`, `5`, `6`, `7`, `9`, `10`, `12`, `13`, `14`, `15`

That is the strongest evidence collected so far. The current and baseline audio
path both assume the high-bank mapping is:

- channel 0 -> slot 8
- channel 1 -> slot 9
- channel 2 -> slot 10
- channel 3 -> slot 11

But on the live hardware state:

- slot 8 works
- slot 11 works
- slot 9 does not
- slot 10 does not

### 3. BAR snapshots prove channel 3 is armed but never starts DMA

The live `hw:5,3` loop run in `/tmp/hws-bar0-snapshot-ch3-live` showed:

- `audio.prestart`
- `audio.seed`
- `audio.start`
- no `audio.first_irq`

Important values during that run:

- `int_en=00030100`
- `br=00000000`
- `dec=00000000`
- `active=00000008`
- `acap=00000008` after start
- `slot11 base` updated to the seeded audio buffer
- delayed probe CRC stayed `00000000->00000000`

Interpretation:

- channel 3 base programming sticks
- capture-enable bit turns on
- hardware still never writes audio into the DMA target
- hardware still never raises ADONE

## Baseline Branch Findings

The baseline branch was important, but it did not prove what was initially
assumed.

### 1. Baseline exposes 4 ALSA devices by looping over video channels

In baseline:

- `origin/baseline:src/hws_video.c` audio registration loops
  `m_nCurreMaxVideoChl`
- that means baseline exposes one ALSA capture device per video input

### 2. Baseline's capability table still says `0x8504` has one line-in channel

Baseline `SetHardWareInfo()` classifies `0x8504` as:

- `m_nCurreMaxVideoChl = 4`
- `m_nCurreMaxLineInChl = 1`

So baseline is internally inconsistent:

- hardware table says "1 line-in"
- userspace-visible audio registration behaves like "4 inputs"

### 3. Baseline still uses the same `8 + ch` audio slot mapping

Baseline `SetDMAAddress()` writes audio DMA base to:

- `CBVS_IN_BUF_BASE + ((8 + i) * 4)`

That is the same slot family we probed on the current branch. There was no
discovered alternate baseline mapping for channels 1 and 2.

### 4. Baseline does not show an obvious extra IRQ bridge/decode enable

Baseline writes:

- `INT_EN_REG_BASE = 0x3ffff`

but does not clearly enable:

- `PCIEBR_EN_REG_BASE`
- `PCIE_INT_DEC_REG_BASE`

The only visible `PCIEBR_EN_REG_BASE` write in baseline was commented out.

### 5. An instrumented baseline branch reproduced the same low-level shape

An instrumented `baseline-instrumented` worktree was created from
`origin/baseline` with:

- `audio_trace=1`
- BAR snapshot logging
- split summary/slot/remap sysfs MMIO probes

That baseline pass showed the same idle MMIO behavior as the current branch:

- `INT_EN = 0x00030100`
- `PCIEBR_EN = 0x00000000`
- `PCIE_INT_DEC = 0x00000000`
- audio base slots `8` and `11` writable
- audio base slots `9` and `10` dead
- remap slots `8..11` writable

So baseline does **not** provide evidence of a hidden low-level enable sequence
that unlocks channels 1 and 2.

### 6. Baseline ALSA runtime also failed after stream start

On the instrumented baseline branch, the driver registered four separate ALSA
cards:

- `HAudio 1`
- `HAudio 2`
- `HAudio 3`
- `HAudio 4`

Direct capture on all four baseline ALSA devices failed with the same runtime
symptom:

```text
arecord: pcm_read:2285: read error: Input/output error
```

The baseline audio trace showed:

- `audio-trace:start ch0` with a valid base register
- `audio-trace:start ch3` with a valid base register
- `audio-trace:start ch1` with `base=00000000`
- `audio-trace:start ch2` with `base=00000000`
- no `audio-trace:irq`
- no `audio-trace:deliver`
- no `bar0-snap:audio.first_irq`

That means baseline, on this host and hardware state, is not a known-good
functional capture reference.

## Current Interpretation

The strongest current interpretation is:

1. The current failure is below ALSA.
2. It is also below the current DMA-buffer layout choice.
3. The live hardware/MMIO state only exposes a sparse subset of the expected
   slot bank.
4. Baseline's "4 audio inputs" behavior was at least partly a userspace
   registration choice, not proof of 4 independent working hardware audio DMA
   engines.
5. Channels 1 and 2 are currently blocked at the visible MMIO base-register
   layer, independently of ALSA.

Two realistic possibilities remain:

1. There is an undocumented hardware enable or mux sequence that makes the
   missing slots and interrupt bits come alive.
2. `0x8504` in this operating mode does not actually expose 4 independent audio
   DMA paths, and both baseline and current were over-exposing audio endpoints.

## Why The Current BAR Diff Attempt Was Not Conclusive

A good-vs-bad BAR snapshot diff was attempted using:

- `hw:5,0` on `/dev/video0`
- `hw:5,3` on `/dev/video3`

That comparison did **not** isolate a missing sequence because the current build
failed both runs in the same way:

- `seed_count=1`
- `start_count=1`
- `irq_count=0`
- `deliver_count=0`

That means the current build no longer has a working control case.

Without one same-build success case and one same-build failure case, the BAR
snapshot diff cannot isolate the delta that matters.

## Recommended Next Step

The next step should be:

1. Use a build with `audio_trace=1` and a confirmed HDMI source that carries
   real embedded audio on physical input 0.
2. Treat channel 0 as the only honest functional control path until another
   physical input is fed with real audio.
3. Re-run channel 0 end-to-end and require evidence of:
   - `audio-trace:start`
   - `audio-trace:irq`
   - `audio-trace:deliver`
4. Only after channel 0 is a proven control case, test channel 3 with a real
   audio-bearing source on physical input 3.
5. Do not treat channel 1 or 2 functional failures as meaningful until there is
   contrary MMIO evidence, because their audio base registers currently do not
   latch writes at all.

If channel 0 still cannot be made to produce `irq`/`deliver` with confirmed
embedded HDMI audio, then the investigation should stop assuming a channel-mux
issue and instead treat the current hardware/driver state as failing even the
single valid audio slot.

## Practical Rule Going Forward

Do not treat:

- "baseline shows four ALSA devices"

as equivalent to:

- "baseline proved four independent hardware audio DMA channels worked"

The collected evidence does not support that conclusion.
