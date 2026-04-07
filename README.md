# HWS 1CHUHD Feature Branch

This branch contains an in-progress video-only port for the
`HWS-HDMI-1CHUHD-CaptureCard` family.

Branch:

```sh
feat/1chuhd-video-only-port
```

Target hardware:

- `8888:8581`
- `1f33:8581`
- `8888:85a1`
- `8888:8591`

Scope:

- same-driver support for the `1CHUHD` PCI IDs
- video capture only
- no audio support
- no software scaling requirement

## Quick Start For A Hardware Tester

If you have one of the boards above and a live HDMI source connected, this is
the fastest path:

```sh
git checkout feat/1chuhd-video-only-port
./collect_1chuhd_logs.sh
```

That script builds the module, reloads it with extra tracing, runs the main
capture tests, and creates a timestamped log directory under `/tmp` plus a
`.tar.gz` archive you can send back.

Please send back:

- the generated `.tar.gz` file
- a short note saying which tested modes showed a correct image
- any visible failures such as reordered quadrants, duplicated halves,
  corrupted stripes, no signal, or interlace artifacts

## Tester Prerequisites

The tester should have:

- one of the target `1CHUHD` boards installed
- a live HDMI source available for testing
- Linux kernel headers for the running kernel
- `make`
- `sudo`
- `v4l2-ctl`
- `lspci`

If `v4l2-ctl` is missing, it is usually provided by the `v4l-utils` package.

## What The Script Does

`./collect_1chuhd_logs.sh` will:

- detect whether a matching target PCI ID is present
- build `src/HwsCapture.ko` unless `--no-build` is given
- reload the module with `trace_1chuhd=1`
- auto-detect the HWS video node when possible
- run `v4l2-ctl` capability, format, and DV timing queries
- run MMAP streaming tests for `1920x1080`, `3840x2160`, and `4096x2160` by default
- capture `dmesg` and all command output
- package the results into a `.tar.gz` archive for easy return

If the test source cannot produce every default mode, pass only the supported
modes:

```sh
./collect_1chuhd_logs.sh 1920x1080 3840x2160
```

Useful options:

```sh
./collect_1chuhd_logs.sh --help
./collect_1chuhd_logs.sh -d /dev/video2
./collect_1chuhd_logs.sh --no-build
```

## Current Status

Implemented in this branch:

- `1CHUHD` PCI ID detection and single-channel capability selection
- UHD geometry and DV timings exposure
- board-specific sliced DMA setup for `1CHUHD`
- CPU-side frame assembly from the sliced DMA banks
- structured trace logging for probe, slice layout, bank completion, and
  frame completion
- a hardware-validation collector script for external testers

Still open:

- real hardware validation
- confirming bank ordering on the actual board
- confirming whether slices are simple contiguous YUYV chunks
- confirming whether interlaced input needs different reconstruction
- confirming whether the `support_yv12` bit requires a missing format path
- deciding whether `MMAP` is enough or whether `DMABUF` must be restored for
  this board

## Important Files

- `collect_1chuhd_logs.sh`
- `doc/1chuhd-hardware-validation.md`
- `doc/1chuhd-video-only-port-plan.md`

## Branch Safety

This work is on the feature branch only. It is not intended to be pushed to
`master` until hardware validation answers the remaining board-specific
questions.
