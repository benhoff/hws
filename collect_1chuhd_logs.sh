#!/usr/bin/env bash

set -euo pipefail

DEVICE="/dev/video0"
MODULE_PATH="src/HwsCapture.ko"
RESULT_DIR=""
STREAM_COUNT=120
MMAP_BUFS=4
MODES=()

usage() {
	printf '%s\n' \
		"Usage: $0 [-d /dev/videoX] [-m path/to/HwsCapture.ko] [-o result_dir] [-c stream_count] [-b mmap_buffers] [WIDTHxHEIGHT ...]" \
		"" \
		"Build the module first, then run this as a user with sudo access." \
		"Default modes: 1920x1080 3840x2160 4096x2160"
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	-d|--device)
		DEVICE="$2"
		shift 2
		;;
	-m|--module)
		MODULE_PATH="$2"
		shift 2
		;;
	-o|--output)
		RESULT_DIR="$2"
		shift 2
		;;
	-c|--stream-count)
		STREAM_COUNT="$2"
		shift 2
		;;
	-b|--buffers)
		MMAP_BUFS="$2"
		shift 2
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		MODES+=("$1")
		shift
		;;
	esac
done

need_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'Missing required command: %s\n' "$1" >&2
		exit 2
	fi
}

need_cmd date
need_cmd dmesg
need_cmd insmod
need_cmd lspci
need_cmd modinfo
need_cmd modprobe
need_cmd sleep
need_cmd sudo
need_cmd tee
need_cmd timeout
need_cmd uname
need_cmd v4l2-ctl

if [ ! -f "$MODULE_PATH" ]; then
	printf 'Module not found: %s\n' "$MODULE_PATH" >&2
	exit 1
fi

if [ "${#MODES[@]}" -eq 0 ]; then
	MODES=("1920x1080" "3840x2160" "4096x2160")
fi

if [ -z "$RESULT_DIR" ]; then
	RESULT_DIR="/tmp/1chuhd-logs-$(date +%Y%m%d-%H%M%S)"
fi

mkdir -p "$RESULT_DIR"
SUMMARY="$RESULT_DIR/summary.log"
COMMANDS="$RESULT_DIR/commands.log"

log() {
	printf '%s\n' "$*" | tee -a "$SUMMARY"
}

run_capture() {
	local name="$1"
	shift

	log "== $name =="
	printf '$ %s\n' "$*" | tee -a "$COMMANDS"
	"$@" 2>&1 | tee "$RESULT_DIR/$name.txt"
}

run_capture_allow_fail() {
	local name="$1"
	shift
	local rc

	log "== $name =="
	printf '$ %s\n' "$*" | tee -a "$COMMANDS"
	set +e
	"$@" 2>&1 | tee "$RESULT_DIR/$name.txt"
	rc=${PIPESTATUS[0]}
	set -e
	printf 'exit_code=%d\n' "$rc" | tee -a "$RESULT_DIR/$name.txt"
}

capture_dmesg() {
	local name="$1"

	log "== $name =="
	printf '$ sudo dmesg --time-format=iso\n' | tee -a "$COMMANDS"
	sudo dmesg --time-format=iso | tee "$RESULT_DIR/$name.txt"
}

log "Collecting 1CHUHD validation logs in $RESULT_DIR"
run_capture host_uname uname -a
run_capture module_info modinfo "$MODULE_PATH"
run_capture pci_devices lspci -nn

log "Reloading HwsCapture with trace_1chuhd=1"
printf '$ sudo modprobe -r HwsCapture\n' | tee -a "$COMMANDS"
sudo modprobe -r HwsCapture >/dev/null 2>&1 || true
printf '$ sudo dmesg -C\n' | tee -a "$COMMANDS"
sudo dmesg -C
printf '$ sudo insmod %s trace_1chuhd=1\n' "$MODULE_PATH" | tee -a "$COMMANDS"
sudo insmod "$MODULE_PATH" trace_1chuhd=1
sleep 1

if [ ! -e "$DEVICE" ]; then
	log "Device not found after module load: $DEVICE"
	capture_dmesg dmesg_after_load
	exit 1
fi

run_capture v4l2_all v4l2-ctl -d "$DEVICE" --all
run_capture dv_timings_list v4l2-ctl -d "$DEVICE" --list-dv-timings
run_capture dv_timings_query v4l2-ctl -d "$DEVICE" --query-dv-timings

for mode in "${MODES[@]}"; do
	width="${mode%x*}"
	height="${mode#*x}"
	prefix="mode_${width}x${height}"

	run_capture_allow_fail "${prefix}_set_fmt" \
		v4l2-ctl -d "$DEVICE" \
		--set-fmt-video="width=${width},height=${height},pixelformat=YUYV"
	run_capture_allow_fail "${prefix}_query_dv_timings" \
		v4l2-ctl -d "$DEVICE" --query-dv-timings
	run_capture_allow_fail "${prefix}_stream" \
		timeout 30s v4l2-ctl -d "$DEVICE" \
		--stream-mmap="$MMAP_BUFS" \
		--stream-count="$STREAM_COUNT" \
		--stream-to=/dev/null
done

capture_dmesg dmesg_final

cat > "$RESULT_DIR/README.txt" <<EOF
Send this whole directory back, along with a short note answering:

1. Which tested modes displayed a correct image?
2. Which modes showed reordered quadrants, duplicated halves, or interlace artifacts?
3. If a mode failed, did the failure happen at format set, query-dv-timings, or during streaming?
EOF

log "Done. Send $RESULT_DIR back with the short observation notes from README.txt."
