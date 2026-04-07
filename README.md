# HWS 1CHUHD Feature Branch

This branch contains an in-progress video-only port for the
`HWS-HDMI-1CHUHD-CaptureCard` family.

Branch:

```sh
feat/1chuhd-video-only-port
```

Scope:

- same-driver support for the `1CHUHD` PCI IDs
- video capture only
- no audio support
- no software scaling requirement

## Current Status

Implemented in this branch:

- `1CHUHD` PCI ID detection and single-channel capability selection
- UHD geometry and DV timings exposure
- board-specific sliced DMA setup for `1CHUHD`
- CPU-side frame assembly from the sliced DMA banks
- structured trace logging for probe, slice layout, bank completion, and
  frame completion
- a log collection script for hardware validation handoff

Not finished yet:

- real hardware validation
- confirming bank ordering on the actual board
- confirming whether slices are simple contiguous YUYV chunks
- confirming whether interlaced input needs different reconstruction
- confirming whether the `support_yv12` bit requires a missing format path
- deciding whether `MMAP` is enough or whether `DMABUF` must be restored for
  this board

## What You Need

If you do not have the hardware yourself, hand this branch to someone who
does and ask them to:

1. Build the module from this branch.
2. Run the collector script.
3. Send back the generated result directory and a short note about image
   correctness for each tested mode.

The main evidence needed is:

- whether `1920x1080`, `3840x2160`, and `4096x2160` stream correctly
- whether any mode shows reordered quadrants, duplicated halves, or other
  slice assembly errors
- whether interlaced input behaves differently

## Build

```sh
make -C /lib/modules/$(uname -r)/build M=$PWD/src modules
```

## Hardware Validation

Run:

```sh
./collect_1chuhd_logs.sh
```

If the source cannot generate every default mode, pass only the supported
modes:

```sh
./collect_1chuhd_logs.sh 1920x1080 3840x2160
```

The script will:

- reload the module with `trace_1chuhd=1`
- run the key `v4l2-ctl` capability and DV timing queries
- stream test the requested modes with `MMAP`
- capture `dmesg` and per-mode command output into a timestamped directory
  under `/tmp`

Send that whole result directory back.

## Important Files

- `collect_1chuhd_logs.sh`
- `doc/1chuhd-hardware-validation.md`
- `doc/1chuhd-video-only-port-plan.md`

## Branch Safety

This work is on the feature branch only. It is not intended to be pushed to
`master` until hardware validation answers the remaining board-specific
questions.
