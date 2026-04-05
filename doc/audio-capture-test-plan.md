# Audio Capture Test Plan

This document turns the current audio risks into a concrete validation plan.

The goal is to verify that the repaired audio path works on real hardware without regressing the existing video path.

## Questions To Answer

1. Does audio capture start and stop cleanly on boards that expose line-in channels?
2. Does the driver deliver stable PCM data across a range of ALSA period and buffer sizes?
3. Does audio capture remain correct while video is streaming on the same card?
4. Do repeated lifecycle operations behave correctly:
   - open / close
   - start / stop
   - suspend / resume
   - disconnect / unload
5. Does the driver handle signal-loss and source-change conditions without stuck interrupts, bad pointers, or broken period timing?

## Why These Observations Matter

- The current audio design uses fixed hardware packets and software delivery into the ALSA ring.
- That means correctness depends on more than "audio exists":
  - packet accounting must be correct
  - ALSA pointer movement must be correct
  - `snd_pcm_period_elapsed()` cadence must be correct
  - audio must not disturb the working video DMA path
- A build-only result is not enough to prove that the design is safe.

## Prerequisites

1. A board and input setup that actually exposes HWS audio capture devices.
2. The current driver built and loaded.
3. A known-good HDMI source with embedded audio or another supported audio source for the board.
4. `arecord`, `aplay`, and `speaker-test` or equivalent ALSA tools.
5. `dmesg` access for kernel log review.
6. If mixed audio/video testing is desired, `v4l2-ctl` or another capture tool.

## Basic Device Discovery

Confirm:

- the expected ALSA capture device appears
- the expected video node appears
- the card reports the right number of audio-capable inputs

Useful commands:

```bash
arecord -l
cat /proc/asound/cards
v4l2-ctl --list-devices
```

## Test 0: Audio Remap Slot Validation

Goal: determine whether audio DMA uses the per-channel remap slot `ch` or the
second-bank remap slot `8 + ch`.

Why this matters:

- The current audio path uses scratch DMA buffers instead of the legacy
  "audio carved out of video DMA" layout.
- Baseline definitely programmed the audio BAR window at `8 + ch`, but it did
  not clearly program a separate remap-table entry for audio.
- The current code assumes the remap table is indexed by BAR window slot:
  - video slot `ch`     -> table entry `0x208 + ch * 8`
  - audio slot `8 + ch` -> table entry `0x208 + (8 + ch) * 8`

This test is intended to validate that assumption on real hardware.

### Register Layout To Watch

For channel `ch`:

- candidate shared remap slot:
  - high word: `0x208 + ch * 8`
  - low word:  `0x20c + ch * 8`
- candidate audio-only remap slot:
  - high word: `0x208 + (8 + ch) * 8`
  - low word:  `0x20c + (8 + ch) * 8`
- audio BAR window register:
  - `CVBS_IN_BUF_BASE + ((8 + ch) * 4)`

For `ch = 0`, that means:

- shared slot: `0x208` / `0x20c`
- audio slot: `0x248` / `0x24c`
- audio BAR window: `0x4060`

### Safety Notes

- This is an intrusive hardware test.
- Run it only on a development machine.
- Keep captures short.
- Do not stream video on the same channel while doing the discriminator step.
- Expect to stop/start the audio stream between trials.
- If a trial wedges the engine, unload and reload the module before continuing.

### Phase 1: Passive Observation

First verify what the driver currently programs without perturbing anything.

Steps:

1. Start a short audio capture on one channel with a steady source.
2. While the capture is running, read BAR0 and record:
   - shared remap slot `ch`
   - audio remap slot `8 + ch`
   - audio BAR window register
3. Stop capture.

Expected observation on the current branch:

- the audio BAR window register changes
- the audio remap slot `8 + ch` is programmed by the driver
- the shared remap slot `ch` may or may not already contain unrelated video
  state

This phase only tells you what software wrote. It does not prove what the
hardware actually consumes.

### Phase 2: Discriminator Test

This phase determines which remap slot the hardware really uses for audio.

Use one channel, audio only, no concurrent video stream.

Preparation:

1. Start a 10-15 second capture:

```bash
arecord -D hw:0,0 -f S16_LE -r 48000 -c 2 -d 15 /tmp/hws-audio-remap.wav
```

2. After the stream starts, snapshot the four remap words:
   - shared slot high/low
   - audio slot high/low

3. Keep a copy of those original values so they can be restored immediately.

Trial A: poison only the audio-slot remap entry `8 + ch`.

1. While audio capture is running, overwrite only the audio candidate slot
   high/low words with a clearly wrong value, for example all zeroes.
2. Do not touch the shared slot `ch`.
3. Observe the recording and kernel log.
4. Restore the original audio-slot remap values.

Interpretation:

- If audio immediately goes silent, corrupts, stalls, or starts IRQ/log noise:
  the hardware is using slot `8 + ch`.
- If audio continues normally:
  slot `8 + ch` is probably not the consumed remap entry.

Trial B: poison only the shared remap entry `ch`.

1. Restart the short capture.
2. Overwrite only the shared candidate slot high/low words with a wrong value.
3. Do not touch the audio slot `8 + ch`.
4. Observe the recording and kernel log.
5. Restore the original shared-slot remap values.

Interpretation:

- If audio fails in Trial B but not Trial A:
  the hardware is using the shared slot `ch`.
- If audio fails in Trial A but not Trial B:
  the hardware is using the audio slot `8 + ch`.
- If both fail:
  the engine may depend on both, or the test disturbed a shared transport path.
- If neither fails:
  the writes may not have landed where expected, or the engine may have cached
  the mapping before the overwrite.

### Practical Read/Write Method

Any BAR0 mmap tool is fine. One simple approach is a short Python snippet that
mmaps `resource0`, reads 32-bit little-endian words, and optionally writes them
back.

Pseudocode:

```text
open /sys/bus/pci/devices/0000:17:00.0/resource0 as read-write
mmap BAR0
read32(offset)
write32(offset, value)
save original values before every overwrite
restore original values before stopping the stream
```

Use exact BAR0 byte offsets, not "word indices".

### Strongest Expected Outcomes

The most likely outcomes are:

1. Audio depends on slot `8 + ch`.
   - This validates the current `HWS_AUDIO_REMAP_SLOT_OFF(ch)` assumption.

2. Audio actually depends on slot `ch`.
   - This means the current driver is programming the wrong remap-table entry,
     even though the audio BAR window register itself is correct.

3. Audio works with either because both slots resolve to the same effective
   page in the current test setup.
   - This can happen if the scratch buffer lands in the same upper address/page
     as video or if stale remap state masks the bug.
   - In that case, repeat after a fresh module reload and with video left idle.

### Minimum Evidence To Save

For each remap-slot trial, save:

1. the exact BAR0 offsets written
2. the original and poisoned values
3. `dmesg` before and after
4. the recorded WAV or a checksum of it
5. whether the stream stalled, went silent, repeated old data, or stayed clean
6. whether a module reload was needed to recover

If this test proves that slot `8 + ch` is required, the current audio remap
logic is validated. If it proves that slot `ch` is required, the current audio
start path needs to be corrected before treating ALSA capture as hardware-ready.

## Test 1: Basic Audio Smoke Test

Goal: prove the device can capture usable audio at all.

Steps:

1. Connect a source with steady audio content.
2. Record a short sample with a conservative format such as `48000 Hz`, `S16_LE`, `2 channels`.
3. Play the result back and confirm it contains valid audio instead of silence, repeated fragments, or obvious corruption.
4. Review `dmesg` for warnings, DMA faults, or IRQ storms.

Example:

```bash
arecord -D hw:0,0 -f S16_LE -r 48000 -c 2 -d 10 /tmp/hws-audio-smoke.wav
aplay /tmp/hws-audio-smoke.wav
```

## Test 2: Start / Stop / Reopen Stability

Goal: make sure normal user operations do not leave the channel in a bad state.

Run repeated cycles of:

1. open capture
2. record for a few seconds
3. stop
4. close
5. reopen and repeat

Include:

- short recordings
- long-enough recordings to cross many periods
- back-to-back runs without unloading the module

Success criteria:

- every run starts promptly
- no stale audio from a previous run
- no kernel warnings
- no stuck busy state after stop

## Test 3: ALSA Period / Buffer Matrix

Goal: validate the fixed-packet to ALSA-period adaptation layer.

Vary:

- period size
- period count
- sample rate
- channel count, if the hardware supports the format

Recommended matrix:

- small period / small buffer
- small period / large buffer
- medium period / medium buffer
- large period / large buffer

For each case, verify:

- capture starts
- pointer advances monotonically with wraparound
- no immediate XRUN
- no obvious audio repetition or dropout
- period wakeups are neither too fast nor too slow

Useful command shape:

```bash
arecord -D hw:0,0 -f S16_LE -r 48000 -c 2 --period-size=1024 --buffer-size=8192 -d 15 /tmp/test.wav
```

## Test 4: Long-Run Stability

Goal: catch drift, counter bugs, and interrupt issues that short runs miss.

Run at least one sustained capture long enough to exercise:

- many ring wraps
- many period notifications
- normal scheduler noise

Recommended duration:

- 30 minutes minimum for a first pass
- longer if this branch is being considered for upstreaming

Success criteria:

- no growing pointer error
- no late corruption in the recording
- no interrupt storm or log spam
- no progressive A/V disturbance if video is also active

## Test 5: Mixed Audio / Video Operation

Goal: prove audio does not regress the working video path.

Run video-only first and capture the baseline behavior.
Then run video and audio together on the same hardware and compare.

Check:

- video still streams correctly when audio starts
- audio still captures correctly while video is active
- starting or stopping audio does not disturb video timing, format, or stream continuity
- starting or stopping video does not break audio capture

This is the most important integration test for the current branch.

## Test 6: Source Change and Signal-Loss Handling

Goal: verify that audio behaves sanely across live input changes.

Test:

1. steady signal with audio
2. signal removed
3. signal restored
4. source switched to a different mode or sample source

Watch for:

- clean recovery after signal returns
- no stale DMA data being replayed
- no stuck pointer or repeated period callbacks during no-signal
- no hard requirement to unload and reload the driver

## Test 7: Suspend / Resume and Driver Lifecycle

Goal: prove the audio state machine survives power-management and teardown events.

Scenarios:

1. suspend / resume while audio is idle
2. suspend / resume while audio capture is active
3. unload / reload the module after audio capture
4. system shutdown / reboot with the driver loaded

Success criteria:

- no callbacks after teardown
- no use-after-free style symptoms
- audio can be started again after resume or reload
- no persistent IRQ activity after stop

## Test 8: Multi-Input Coverage

Goal: make sure channel-specific assumptions are not only correct for one input.

If the board exposes more than one audio-capable input, repeat the smoke and mixed-operation tests on each supported input.

This is especially important for boards where the driver reports multiple line-in channels.

## Minimum Evidence To Keep

For each major test run, save:

1. exact command line
2. kernel version and branch/commit id
3. `dmesg` excerpt before and after the run
4. the recorded WAV or a checksum of it
5. whether video was active at the same time
6. whether the result was pass, fail, or ambiguous

## Exit Criteria For "Hardware-Validated"

This audio branch is in good shape only when all of the following are true:

- basic capture works reliably
- the period/buffer matrix does not show systematic glitches
- long-run capture is stable
- mixed audio/video operation is stable
- suspend/resume and stop/start cycles are clean
- no unexplained kernel warnings remain

If any of those fail, the branch should still be treated as experimental.
