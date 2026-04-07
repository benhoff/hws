# 1CHUHD Hardware Validation

This branch adds a same-driver `1CHUHD` path that uses sliced DMA and
CPU-side frame assembly. It builds, but it has not been validated on real
hardware.

## What The Hardware Owner Should Test

1. Build and load the module from this branch.

2. Confirm probe succeeds:
   - the PCI device binds to `HwsCapture`
   - exactly one video node is registered for the `1CHUHD` board

3. Confirm reported timings and formats:
   - `v4l2-ctl --all`
   - `v4l2-ctl --list-dv-timings`
   - `v4l2-ctl --query-dv-timings`

4. Test native progressive modes with `mmap` buffers:
   - `1920x1080p60`
   - `3840x2160p30`
   - `3840x2160p60`
   - `4096x2160p30`
   - `4096x2160p60`

5. For each mode, verify:
   - stream starts
   - no corrupted stripes or reordered quadrants
   - no repeating top/bottom half
   - frames remain stable across at least 30 seconds

6. Test live mode changes while streaming:
   - `1080p -> 2160p`
   - `2160p -> 1080p`
   - no-signal -> valid signal
   - valid signal -> no-signal

7. If the board supports interlaced input, test at least one interlaced mode.

## Preferred Log Collection

Run the collector script after building the module:

```sh
make -C /lib/modules/$(uname -r)/build M=$PWD/src modules
chmod +x ./collect_1chuhd_logs.sh
./collect_1chuhd_logs.sh
```

The script reloads the module with `trace_1chuhd=1`, captures probe and
streaming logs, runs the key `v4l2-ctl` queries, and writes everything to a
timestamped directory under `/tmp`.

If the source cannot generate every default mode, pass only the supported
modes, for example:

```sh
./collect_1chuhd_logs.sh 1920x1080 3840x2160
```

## Manual Commands

Build:

```sh
make -C /lib/modules/$(uname -r)/build M=$PWD/src modules
```

Load with tracing:

```sh
sudo insmod src/HwsCapture.ko trace_1chuhd=1
```

Inspect:

```sh
v4l2-ctl -d /dev/video0 --all
v4l2-ctl -d /dev/video0 --list-dv-timings
v4l2-ctl -d /dev/video0 --query-dv-timings
```

Stream test:

```sh
v4l2-ctl -d /dev/video0 \
  --set-fmt-video=width=3840,height=2160,pixelformat=YUYV \
  --stream-mmap=4 --stream-count=120 --stream-to=/dev/null
```

Relevant trace lines in `dmesg` are prefixed with `1chuhd:` and should show:

- board capability selection and scratch DMA allocation
- per-slot sliced DMA layout programming
- per-VDONE bank/toggle handling
- logical frame completion after both banks arrive

## Questions The Hardware Owner Needs To Answer

1. Does the bank ordering match the current assumption?
   Current code assumes toggle `1` fills slices `0` and `1`, and toggle `0`
   fills slices `2` and `3`.

2. Are the four slices laid out as simple contiguous chunks of one
   progressive YUYV frame?

3. Does interlaced input require different frame reconstruction than the
   current progressive-style assembly?

4. Is `MMAP` sufficient for expected userspace, or is `DMABUF` required for
   the real deployment?

5. Does the board always deliver data in a form that can be exposed as YUYV,
   or is the `support_yv12` bit signaling a format path that still needs
   conversion?

## What To Send Back

- the result directory from `./collect_1chuhd_logs.sh`
- whether each tested mode produced a correct image
- whether any mode showed slice ordering issues, duplicated halves, or
  interlace artifacts

With those answers, the remaining driver changes should be limited to
runtime corrections rather than more structural refactoring.
