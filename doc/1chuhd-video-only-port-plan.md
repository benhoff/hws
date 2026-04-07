# 1CHUHD Video-Only Port Plan

This branch scopes the `../HWS-HDMI-1CHUHD-CaptureCard` port to:

- video capture only
- no ALSA/audio support
- no software scaling or rotation support
- no attempt to preserve the vendor's monolithic driver structure

## Goal

Bring the current split driver in `src/` up to the point where the
`1CHUHD` board can probe, expose a V4L2 capture node, detect live input
geometry, and stream frames at native input size for supported modes.

## Explicit Non-Goals

- Porting the vendor ALSA path
- Porting the vendor workqueues dedicated to audio
- Porting the vendor software scaler functions
- Porting vendor rotation or format-conversion helper buffers that only
  exist to support software scaling
- Preserving feature parity with the vendor module name or DKMS package name

## Required Work

1. Add the `1CHUHD` PCI IDs to the modern PCI table in `src/hws_pci.c`.

2. Map those IDs to the correct runtime capability profile:
   - single active video channel
   - UHD geometry limits
   - correct hardware-generation behavior for DMA programming

3. Expand the current geometry and DV-timings limits:
   - raise max width and height
   - add the missing UHD/VESA timings needed by the board
   - ensure `TRY_FMT`, `S_FMT`, and live mode-change handling all accept
     native UHD timings

4. Port the minimum DMA path needed for UHD capture:
   - understand the vendor's four-slice frame layout
   - reproduce the required BAR table and half-size programming in the
     split driver
   - deliver a single V4L2 frame buffer to userspace without relying on
     the removed software scaler

5. Decide whether the board's live DMA format is always directly consumable
   as YUYV:
   - if yes, keep the current YUYV-only userspace contract
   - if no, port only the minimum format-conversion path required for
     native capture and leave all scaling code out

## Likely Files To Change

- `src/hws_pci.c`
- `src/hws_reg.h`
- `src/hws.h`
- `src/hws_video.c`
- `src/hws_v4l2_ioctl.c`

## First Implementation Milestone

The first useful milestone is not "full vendor parity". It is:

- board probes on the new PCI IDs
- one capture node registers
- UHD live geometry is visible through DV timings
- native-size streaming works for at least one known-good UHD mode

## Notes

The vendor `1CHUHD` driver still assumes a monolithic design and includes
audio registration and software scaling paths. Those should be treated as
reference material only. This branch is intentionally narrowing scope to
the smallest defensible port into the current split architecture.

The remaining hard blocker after the first implementation pass is the UHD
DMA layout itself. The vendor code does not behave like the current
single-window vb2 DMA path:

- it programs four BAR remap slots for the UHD board
- it updates four half-size registers during mode changes
- it appears to alternate between buffer banks and only mark a full frame
  ready after the required halves have completed

That means UHD streaming is not expected to work correctly on this branch
until the current `src/hws_video.c` and `src/hws_irq.c` path is taught the
vendor board's multi-slice completion model.
