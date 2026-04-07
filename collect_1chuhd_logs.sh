#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
BUILD_MODULE=1
PACKAGE_RESULTS=1
DEVICE=""
MODULE_NAME="HwsCapture"
MODULE_PATH="$REPO_ROOT/src/HwsCapture.ko"
RESULT_DIR=""
STREAM_COUNT=120
STREAM_TIMEOUT=30
MMAP_BUFS=4
MODES=()
PCI_MATCH=""
ARCHIVE_PATH=""

usage() {
	printf '%s\n' \
		"Usage: $0 [options] [WIDTHxHEIGHT ...]" \
		"" \
		"Collect logs for the HWS HDMI 1CHUHD feature branch." \
		"" \
		"Target boards:" \
		"  PCI IDs: 8888:8581, 1f33:8581, 8888:85a1, 8888:8591" \
		"" \
		"Options:" \
		"  -d, --device /dev/videoX   Use a specific video node" \
		"  -m, --module PATH          Use a specific HwsCapture.ko path" \
		"  -o, --output DIR           Write logs to DIR" \
		"  -c, --stream-count N       Frames per mode (default: 120)" \
		"  -t, --stream-timeout N     Timeout seconds per mode (default: 30)" \
		"  -b, --buffers N            MMAP buffers (default: 4)" \
		"      --no-build             Skip building the module" \
		"      --no-package           Skip creating the final .tar.gz archive" \
		"  -h, --help                 Show this help" \
		"" \
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
	-t|--stream-timeout)
		STREAM_TIMEOUT="$2"
		shift 2
		;;
	-b|--buffers)
		MMAP_BUFS="$2"
		shift 2
		;;
	--no-build)
		BUILD_MODULE=0
		shift
		;;
	--no-package)
		PACKAGE_RESULTS=0
		shift
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

find_matching_pci() {
	lspci -Dn | awk '
		$3 ~ /^(8888:8581|1f33:8581|8888:85a1|8888:8591)$/ { print; found=1 }
		END { if (!found) exit 1 }
	'
}

auto_detect_device() {
	local sysnode
	local name
	local devname

	for sysnode in /sys/class/video4linux/video*; do
		[ -e "$sysnode/name" ] || continue
		name="$(cat "$sysnode/name" 2>/dev/null || true)"
		devname="/dev/$(basename "$sysnode")"
		case "$name" in
		hws-*|HwsCapture*|*hws*)
			printf '%s\n' "$devname"
			return 0
			;;
		esac
	done

	return 1
}

build_module() {
	log "Building module"
	printf '$ make -C /lib/modules/%s/build M=%s/src modules\n' \
		"$(uname -r)" "$REPO_ROOT" | tee -a "$COMMANDS"
	make -C "/lib/modules/$(uname -r)/build" M="$REPO_ROOT/src" modules \
		2>&1 | tee "$RESULT_DIR/build.txt"
}

write_result_readme() {
	if [ "$PACKAGE_RESULTS" -eq 1 ]; then
		cat > "$RESULT_DIR/README.txt" <<EOF
Send back either:

- the archive: $(basename "$ARCHIVE_PATH")
- or this whole directory: $RESULT_DIR

Please include a short note answering:

1. Which tested modes displayed a correct image?
2. Which modes showed reordered quadrants, duplicated halves, corrupted stripes,
   no signal, or interlace artifacts?
3. If a mode failed, did the failure happen at format set, query-dv-timings,
   or during streaming?
4. If you tested a live mode switch or interlaced source manually, what happened?
EOF
	else
		cat > "$RESULT_DIR/README.txt" <<EOF
Send back this whole directory:

- $RESULT_DIR

Please include a short note answering:

1. Which tested modes displayed a correct image?
2. Which modes showed reordered quadrants, duplicated halves, corrupted stripes,
   no signal, or interlace artifacts?
3. If a mode failed, did the failure happen at format set, query-dv-timings,
   or during streaming?
4. If you tested a live mode switch or interlaced source manually, what happened?
EOF
	fi
}

package_results() {
	local parent_dir
	local base_dir

	parent_dir="$(dirname "$RESULT_DIR")"
	base_dir="$(basename "$RESULT_DIR")"
	ARCHIVE_PATH="$RESULT_DIR.tar.gz"
	tar -C "$parent_dir" -czf "$ARCHIVE_PATH" "$base_dir"
}

need_cmd awk
need_cmd cat
need_cmd date
need_cmd dmesg
need_cmd grep
need_cmd insmod
need_cmd lspci
need_cmd ls
need_cmd make
need_cmd mkdir
need_cmd modinfo
need_cmd modprobe
need_cmd sleep
need_cmd sudo
need_cmd tar
need_cmd tee
need_cmd timeout
need_cmd uname
need_cmd v4l2-ctl

if [ "${#MODES[@]}" -eq 0 ]; then
	MODES=("1920x1080" "3840x2160" "4096x2160")
fi

if [ -z "$RESULT_DIR" ]; then
	RESULT_DIR="/tmp/1chuhd-logs-$(date +%Y%m%d-%H%M%S)"
fi

mkdir -p "$RESULT_DIR"
SUMMARY="$RESULT_DIR/summary.log"
COMMANDS="$RESULT_DIR/commands.log"

log "Collecting HWS 1CHUHD validation logs"
log "Repo root: $REPO_ROOT"
log "Result dir: $RESULT_DIR"
log "Modes: ${MODES[*]}"

if ! PCI_MATCH="$(find_matching_pci)"; then
	log "WARNING: no matching 1CHUHD PCI ID was found."
	log "Expected one of: 8888:8581, 1f33:8581, 8888:85a1, 8888:8591"
	log "Continuing anyway in case lspci output is unusual."
else
	log "Detected target board:"
	printf '%s\n' "$PCI_MATCH" | tee -a "$SUMMARY"
fi

run_capture host_uname uname -a
run_capture pci_devices lspci -Dnn

if [ "$BUILD_MODULE" -eq 1 ]; then
	build_module
fi

if [ ! -f "$MODULE_PATH" ]; then
	log "Module not found: $MODULE_PATH"
	exit 1
fi

run_capture module_info modinfo "$MODULE_PATH"

log "Checking sudo access"
printf '$ sudo -v\n' | tee -a "$COMMANDS"
sudo -v

log "Reloading $MODULE_NAME with trace_1chuhd=1"
printf '$ sudo modprobe -r %s\n' "$MODULE_NAME" | tee -a "$COMMANDS"
sudo modprobe -r "$MODULE_NAME" >/dev/null 2>&1 || true
printf '$ sudo dmesg -C\n' | tee -a "$COMMANDS"
sudo dmesg -C
printf '$ sudo insmod %s trace_1chuhd=1\n' "$MODULE_PATH" | tee -a "$COMMANDS"
sudo insmod "$MODULE_PATH" trace_1chuhd=1
sleep 1

run_capture_allow_fail v4l2_list_devices v4l2-ctl --list-devices

if [ -z "$DEVICE" ]; then
	if DEVICE="$(auto_detect_device)"; then
		log "Auto-detected video node: $DEVICE"
	else
		DEVICE="/dev/video0"
		log "Could not auto-detect an HWS video node; falling back to $DEVICE"
	fi
fi

if [ ! -e "$DEVICE" ]; then
	log "Device not found after module load: $DEVICE"
	capture_dmesg dmesg_after_load
	exit 1
fi

log "Using video node: $DEVICE"
run_capture_allow_fail video_nodes ls -l /dev/video*
run_capture v4l2_all v4l2-ctl -d "$DEVICE" --all
run_capture_allow_fail v4l2_formats v4l2-ctl -d "$DEVICE" --list-formats-ext
run_capture dv_timings_list v4l2-ctl -d "$DEVICE" --list-dv-timings
run_capture_allow_fail dv_timings_query_initial v4l2-ctl -d "$DEVICE" --query-dv-timings

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
		timeout "${STREAM_TIMEOUT}s" v4l2-ctl -d "$DEVICE" \
		--stream-mmap="$MMAP_BUFS" \
		--stream-count="$STREAM_COUNT" \
		--stream-to=/dev/null
done

capture_dmesg dmesg_final

ARCHIVE_PATH="$RESULT_DIR.tar.gz"
write_result_readme
if [ "$PACKAGE_RESULTS" -eq 1 ]; then
	package_results
fi

if [ "$PACKAGE_RESULTS" -eq 1 ]; then
	log "Archive ready: $ARCHIVE_PATH"
else
	log "Packaging disabled; send directory: $RESULT_DIR"
fi
log "Please send back the archive or directory plus the short note from README.txt."
