# DMA and interrupt data flow

This document describes the DMA and interrupt behavior implemented by the
current driver. It focuses on video capture, the V4L2/videobuf2 handoff, and
the important difference between the current video completion path and the
older vendor implementation.

## Short answer

The current video path does **not** check which half completed before returning
a V4L2 buffer.

- One videobuf2 buffer represents one complete packed-YUYV frame.
- The hardware DMA window is configured as two adjacent halves inside that
  frame with `HWS_HALF_SZ_OFF(ch)`.
- A `VDONE` status bit causes the driver to treat the current full V4L2 buffer
  as complete.
- `HWS_REG_VBUF_TOGGLE(ch)` is read only when the `toggle_debug` module
  parameter is enabled. Its value is recorded for logging and does not control
  buffer completion.
- The buffer is returned to userspace with `vb2_buffer_done()`.

Video capture is zero-copy only when the card can DMA directly into the
videobuf2 allocation. When the buffer cannot be represented by the card's
shared 512 MiB remap window, the card writes to a coherent scratch slot and the
driver copies the completed frame into the V4L2 buffer before returning it.

Audio is different: its interrupt path always reads the audio half-toggle,
selects the opposite (completed) half, and copies that packet from coherent
scratch DMA memory into the ALSA ring.

## Objects and ownership

The V4L2 queue uses `vb2_dma_contig_memops` and currently advertises only
`VB2_MMAP`. Each `struct hwsvideo_buffer` contains one `vb2_v4l2_buffer` and a
`slot` value that records where the card wrote the frame.

| Driver state | Meaning |
| --- | --- |
| `capture_queue` | Buffers queued by videobuf2 and waiting for the driver. |
| `active` | Buffer that software associates with the next `VDONE`. |
| `next_prepared` | Following buffer whose DMA window has already been programmed. |
| `slot == HWS_VIDEO_DIRECT_SLOT` (`-1`) | The card writes directly into the V4L2 buffer. |
| `slot == 0` or `1` | The card writes into that scratch-arena bounce slot. |

`irq_lock` protects `capture_queue`, `active`, `next_prepared`, and their
ownership transitions. A buffer must leave those driver-owned states before
`vb2_buffer_done()` gives it back to videobuf2 and, eventually, userspace.

There is no host descriptor ring in this driver. Buffer selection consists of
writing BAR remap and capture-window MMIO registers, then tracking the expected
completion in software.

## DMA address programming

The card does not consume an unrestricted host `dma_addr_t` directly. Each
channel uses a BAR remap-table entry plus a device-side address within a
512 MiB page.

The important values are:

| Value | Purpose |
| --- | --- |
| `HWS_VIDEO_REMAP_SLOT_OFF(ch)` | High 32 bits and 512 MiB page bits of the host DMA address. |
| `HWS_BUF_BASE_OFF(ch)` | Device-side video base, including the low 29 address bits. |
| `HWS_HALF_SZ_OFF(ch)` | Half-frame length in 16-byte units. |
| `HWS_REG_AUD_DMA_ADDR(ch)` | Device-side audio capture base. |

`hws_program_dma_window()` splits a host DMA address as follows:

```text
host DMA address
  high 32 bits --------------------> remap slot high word
  low bits [31:29] ----------------> remap slot 512 MiB page word
  low bits [28:0] -----------------> per-channel device buffer offset

device video base = (channel + 1) * 0x20000000 + low_29_bits
```

The entire frame must remain within the selected 512 MiB page. Video and audio
for the same channel use the same remap-table slot, even though their base
registers are different. Consequently, concurrent-capable video and audio DMA
addresses must also belong to the same remap page.

The half-size register is programmed with `sizeimage / 2 / 16`. This describes
the hardware's split-buffer layout; by itself it does not establish whether a
`VDONE` interrupt means "one half completed" or "the complete frame
completed."

MMIO writes are read back where necessary to flush posted PCI writes before
capture is enabled.

## Direct video DMA versus the bounce path

`hws_select_video_dma()` makes the decision for every buffer.

### Direct path

The V4L2 plane address from `vb2_dma_contig_plane_dma_addr()` is selected when:

1. the entire frame fits within one remap page; and
2. if the channel has an audio window, the video address is in the same remap
   page as the channel's audio scratch address.

The selected buffer receives `slot = HWS_VIDEO_DIRECT_SLOT`. The device then
writes the frame directly into the videobuf2 allocation:

```text
capture device -> PCIe DMA -> vb2 dma-contig buffer -> userspace DQBUF
```

No payload `memcpy()` occurs on completion. `hws_video_prepare_done_buffer()`
executes `dma_rmb()`, fills in payload size, field, sequence, and timestamp,
then the interrupt thread calls `vb2_buffer_done()`.

This is zero-copy with respect to the capture driver's data path. Userspace can
`mmap()` the same V4L2 buffer. The queue does not currently advertise
`VB2_DMABUF`, so importing an arbitrary userspace-provided DMA-BUF as a capture
buffer is not supported by this implementation.

### Bounce path

For an audio-capable channel whose V4L2 allocation is outside the shared remap
page, the driver chooses one of two coherent video scratch slots:

```text
capture device -> PCIe DMA -> coherent scratch slot
                              -> memcpy -> vb2 buffer -> userspace DQBUF
```

`hws_video_prepare_done_buffer()` performs the copy after `dma_rmb()` and before
`vb2_buffer_done()`. This path is not zero-copy.

The driver refuses unsupported cases rather than silently copying when:

- the frame or scratch arena cannot fit the hardware window;
- scratch memory is unavailable; or
- a `VB2_MEMORY_DMABUF` buffer would require bouncing.

The last check is defensive today because the queue advertises only MMAP mode.

## Video queue and DMA sequence

At `STREAMON`, `hws_start_streaming()` performs these transitions:

1. Acquire the per-channel scratch arena when the channel also has an audio
   DMA window.
2. Remove the first queued V4L2 buffer and make it `active`.
3. Select its direct or bounce DMA address and program the remap, base, and
   half-size registers.
4. Clear a stale `VDONE`, issue the required write barrier, and enable capture
   for the channel.
5. If another V4L2 buffer is queued, program it and record it as
   `next_prepared`.

The code assumes the hardware latches the programmed DMA base at the required
capture boundary. This assumption matters because `hws_prime_next_locked()`
programs `next_prepared` while `active` still represents the in-flight frame.
There is no software-visible descriptor or completion tag with which to match a
`VDONE` to a particular DMA address.

When a buffer is queued after streaming has started, `hws_buffer_queue()` uses
the same logic: it starts capture immediately if no buffer is active, otherwise
it tries to populate `next_prepared`.

## Interrupt demultiplexing

The device has one PCI interrupt vector. Probe requests one vector with
`PCI_IRQ_ALL_TYPES`; the PCI core can select MSI-X, MSI, or shared legacy INTx.
All channel causes are demultiplexed through `HWS_REG_INT_STATUS`:

| Status bits | Meaning |
| --- | --- |
| bits 0-3 | Video `VDONE` for channels 0-3. |
| bits 8-11 | Audio `ADONE` for channels 0-3. |

The register uses write-one-to-clear semantics.

### Hard interrupt handler

`hws_irq_handler()` is deliberately short:

1. Read an `INT_STATUS` snapshot.
2. For each active video bit, increment `irq_pending_vdone[ch]` and request the
   threaded handler. It also sets `half_seen = true`. With `toggle_debug=1`, it
   reads and records `VBUF_TOGGLE`; otherwise it does not read the video toggle.
3. For each active audio bit, read `ABUF_TOGGLE` immediately and queue the
   toggle value for deferred audio work.
4. Acknowledge exactly the processed snapshot by writing it back to
   `INT_STATUS`.
5. Re-read and repeat until no causes remain, with `MAX_INT_LOOPS` as a guard
   against stuck hardware.

Draining is important for MSI, where software cannot rely on a still-asserted
level to invoke the handler again. A zero status returns `IRQ_NONE`, which is
also required for a shared INTx line.

Video uses a per-channel pending count rather than a Boolean so multiple
`VDONE` observations are not collapsed before the IRQ thread runs. The count
contains no hardware buffer identity and no half-toggle history.

### Threaded video handler

`hws_irq_thread()` consumes pending video counts and calls
`hws_video_handle_vdone()` for each one. The completion path is:

```text
VDONE status
  -> hard IRQ increments irq_pending_vdone[ch] and acknowledges status
  -> IRQ thread removes one pending count
  -> current active buffer is treated as a complete frame
  -> next_prepared is promoted to active, if present
  -> dma_rmb()
  -> optional scratch-to-V4L2 memcpy
  -> set bytesused, field, sequence, and timestamp
  -> vb2_buffer_done(VB2_BUF_STATE_DONE)
  -> userspace poll()/DQBUF can observe the buffer
  -> program another queued buffer as next_prepared
```

If preparing or programming a buffer fails, the completed buffer is returned
with an error or the entire videobuf2 queue is put into an error state,
depending on where the failure occurs.

## What "half done" means in this code

There are two distinct implementations in the repository's history.

### Current driver

The current video path assumes one `VDONE` completes one full `sizeimage`
buffer. It does not use `VBUF_TOGGLE` for correctness. `half_seen` is only a
diagnostic flag; despite its name, it is set on `VDONE` and is not used to gate
completion. `last_buf_half_toggle` is also diagnostic and changes only when
`toggle_debug=1`.

Therefore, the current logic is not:

```text
determine completed half -> mark half complete -> publish after both halves
```

It is:

```text
observe VDONE -> publish the entire software-active V4L2 buffer
```

### Vendor baseline

The older vendor path did follow the half-completion model:

1. Read the video toggle on each video interrupt.
2. Ignore a repeated toggle and schedule work when it changes.
3. Copy the indicated half from a persistent hardware DMA buffer into the
   corresponding half of a software frame buffer.
4. Mark the software frame ready only after the second half.

That path was always a copy path: the device wrote into a private DMA buffer,
then the driver copied each half into its userspace-facing frame queue.

The current rewrite changed both the destination model and the completion
model. Direct DMA makes a zero-copy V4L2 path possible, but it does not remove
the need to honor half-completion semantics if the hardware actually raises
`VDONE` once per half.

## Hardware contract that still needs validation

The register layout proves that the DMA target is split into halves, but the
current source does not establish the interrupt cadence conclusively. Two
questions should be validated on hardware:

1. Does `VDONE` occur once per half or once per complete frame?
2. When the base register is rewritten for `next_prepared`, when does the
   device latch that address?

The first question is safety-critical for zero-copy. If `VDONE` is a half-done
event, the current driver can expose a V4L2 buffer while the device is still
writing its other half, and it can advance software ownership one interrupt too
early. In that case the driver needs per-active-buffer half state, must sample
`VBUF_TOGGLE` on every edge in the hard handler, and must call
`vb2_buffer_done()` only after both halves of the same V4L2 buffer are complete.

A practical validation is to capture a stable source while counting `VDONE`
events and sampling the toggle:

- approximately one `VDONE` per input frame supports the current full-frame
  interpretation;
- approximately two `VDONE` events per frame with an alternating toggle
  supports the vendor half-completion interpretation;
- repeated or skipped toggle values indicate an overrun, lost edge, or a
  different register contract and must not be treated as a valid full frame.

The driver implements this validation behind the writable `toggle_debug`
module parameter. Enable it before starting capture or while a stable capture
is running:

```sh
echo 1 | sudo tee /sys/module/HwsCapture/parameters/toggle_debug
sudo dmesg -w | grep DMA-VALIDATION
```

It samples `VBUF_TOGGLE` in the hard interrupt handler so the value belongs to
the interrupt edge being counted. Every active channel emits a summary after
approximately two seconds. Disable it after the test because validation mode
adds one MMIO read per video interrupt and periodically logs from hard IRQ
context:

```sh
echo 0 | sudo tee /sys/module/HwsCapture/parameters/toggle_debug
```

Each line contains an interpretation in both `verdict` and plain text:

| Verdict | Interpretation |
| --- | --- |
| `OK_FULL_FRAME` | About 1.00 `VDONE` per input frame. This supports the current full-V4L2-buffer completion model. |
| `BUG_HALF_DONE` | About 2.00 `VDONE`s per frame and the toggle alternates on at least 90% of edges. The current driver is returning each V4L2 buffer one half too early. |
| `BUG_TOGGLE_SEQUENCE` | About 2.00 `VDONE`s per frame, but the toggle does not alternate reliably. Suspect missed/coalesced edges or a different hardware contract; do not trust completed frames. |
| `WARN_INCONCLUSIVE` | The cadence is neither approximately one nor two events per frame. Confirm the source and detected FPS are stable, then investigate interrupt delivery. |
| `WAIT_NO_FPS` | The driver has no nonzero input FPS with which to interpret the interrupt rate. |

For example, this is direct evidence that the current completion path is
wrong for the tested hardware:

```text
DMA-VALIDATION ch=0 verdict=BUG_HALF_DONE vdone_events=241 window_ms=2000 input_fps=60 vdone_per_frame=2.00 toggle_flips=240 same_toggle=0 interpretation="two alternating VDONEs per frame; current driver completes each V4L2 buffer one half too early"
```

`same_toggle` counts adjacent interrupts which reported the same one-bit
toggle. A repeated value can also mean that an even number of toggle edges was
missed, so the counter identifies an anomaly but cannot distinguish repeated
hardware state from lost interrupts by itself.

Also verify that `slot=-1` buffers contain a stable pattern in both halves at
the moment they are dequeued. A successful bounce-path test alone does not
prove direct-DMA ownership is correct because the completion-time copy changes
the timing seen by userspace.

## Audio comparison

The audio path retains explicit ping-pong semantics:

1. `ADONE` is observed in the hard handler.
2. `ABUF_TOGGLE` reports the half the device is filling now.
3. The completed packet is therefore in the opposite half:
   `toggle == 1` selects offset 0, and `toggle == 0` selects one packet offset.
4. Deferred work executes `dma_rmb()` and copies the packet into the ALSA DMA
   ring.
5. `snd_pcm_period_elapsed()` notifies ALSA as period boundaries are crossed.

Audio is intentionally not zero-copy in the current design. Its coherent
hardware scratch buffer and ALSA runtime ring are separate allocations.

## Source map

| Area | Main definitions and functions |
| --- | --- |
| Register layout | `hws_reg.h` |
| Buffer/channel state | `struct hwsvideo_buffer`, `struct hws_video`, and `struct hws_pcie_dev` in `hws.h` |
| Direct/bounce selection | `hws_select_video_dma()` in `hws_video.c` |
| Remap programming | `hws_program_dma_window()` in `hws_video.c` |
| V4L2 completion preparation | `hws_video_prepare_done_buffer()` in `hws_video.c` |
| Queue start and buffer ownership | `hws_start_streaming()`, `hws_buffer_queue()`, and `hws_prime_next_locked()` in `hws_video.c` |
| IRQ demultiplexing and video completion | `hws_irq_handler()`, `hws_irq_thread()`, and `hws_video_handle_vdone()` in `hws_irq.c` |
| Audio half selection and delivery | `hws_audio_packet_offset()`, `hws_audio_queue_interrupt()`, and `hws_audio_deliver_one_packet()` in `hws_audio.c` |
| IRQ transport selection | `hws_alloc_irq()` in `hws_pci.c` and `doc/msi-interrupts.md` |
