#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Focused HWS embedded-audio diagnostic. Reloads the in-tree module in normal
# MSI mode, captures one PCM, and correlates ALSA, IRQ, and driver telemetry.

set -Eeuo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
MODULE_PATH="$SCRIPT_DIR/src/HwsCapture.ko"
MODULE_NAME=HwsCapture
BDF=0000:17:00.0
PCM=hw:4,3
VIDEO_NODE=
DURATION=5
OUTPUT_DIR=
RUN=0
MODULE_TOUCHED=0
KLOG_BASELINE_LINES=0
CAPTURE_PID=
VIDEO_PID=
VIDEO_RC=

usage() {
	cat <<'EOF'
Usage: ./hws_audio_focus_test.sh [options]

Reload HwsCapture in MSI-preferred mode and diagnose one embedded-audio PCM.
Without --run, print the resolved targets without changing hardware.

Options:
  --run             Reload the module and run the focused capture
  --pcm PCM         ALSA PCM. Default: hw:4,3
  --video NODE      Stream NODE concurrently, for example /dev/video3
  --seconds N       Capture duration. Default: 5
  --bdf BDF         HWS PCI function. Default: 0000:17:00.0
  --module PATH     Module under test. Default: src/HwsCapture.ko
  --output-dir DIR  Evidence directory. Default: /tmp timestamp directory
  -h, --help        Show this help

Stop WirePlumber before using --run. The script refuses to unload the module
when an HWS video or sound node is open. It leaves the tested module loaded in
normal MSI-preferred mode.
EOF
}

die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 2
}

print_command() {
	printf '+'
	printf ' %q' "$@"
	printf '\n'
}

parse_args() {
	while (($#)); do
		case "$1" in
		--run)
			RUN=1
			shift
			;;
		--pcm)
			PCM=${2:?missing value for --pcm}
			shift 2
			;;
		--video)
			VIDEO_NODE=${2:?missing value for --video}
			shift 2
			;;
		--seconds)
			DURATION=${2:?missing value for --seconds}
			shift 2
			;;
		--bdf)
			BDF=${2:?missing value for --bdf}
			shift 2
			;;
		--module)
			MODULE_PATH=${2:?missing value for --module}
			shift 2
			;;
		--output-dir)
			OUTPUT_DIR=${2:?missing value for --output-dir}
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			die "unknown option: $1"
			;;
		esac
	done
}

validate_args() {
	[[ "$DURATION" =~ ^[0-9]+$ ]] && ((DURATION > 0)) ||
		die "--seconds must be a positive integer"
	if [[ "$BDF" =~ ^[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]$ ]]; then
		BDF="0000:$BDF"
	fi
	[[ "$BDF" =~ ^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]$ ]] ||
		die "invalid PCI BDF: $BDF"
	[[ "$PCM" =~ ^hw:([0-9]+),([0-9]+)$ ]] ||
		die "--pcm must use hw:CARD,DEVICE syntax"
	if [[ -n "$VIDEO_NODE" ]]; then
		[[ "$VIDEO_NODE" =~ ^/dev/video[0-9]+$ ]] ||
			die "--video must use /dev/videoN syntax"
	fi
	[[ -f "$MODULE_PATH" ]] || die "module not found: $MODULE_PATH"
	MODULE_PATH=$(realpath "$MODULE_PATH")
	[[ -d "/sys/bus/pci/devices/$BDF" ]] || die "PCI function not found: $BDF"
}

require_commands() {
	local command
	local -a commands=(arecord dmesg fuser insmod modinfo realpath rg rmmod
		sha256sum strace timeout udevadm v4l2-ctl)

	for command in "${commands[@]}"; do
		command -v "$command" >/dev/null 2>&1 ||
			die "required command not found: $command"
	done
}

path_belongs_to_bdf() {
	local path=$1
	local resolved

	resolved=$(realpath -e "$path" 2>/dev/null || true)
	[[ "$resolved" == *"/$BDF/"* || "$resolved" == *"/$BDF" ]]
}

discover_owned_device_files() {
	local class node

	shopt -s nullglob
	for class in /sys/class/video4linux/video*; do
		path_belongs_to_bdf "$class/device" || continue
		node="/dev/${class##*/}"
		[[ -e "$node" ]] && printf '%s\n' "$node"
	done
	for class in /sys/class/sound/*; do
		path_belongs_to_bdf "$class/device" || continue
		node="/dev/snd/${class##*/}"
		[[ -e "$node" ]] && printf '%s\n' "$node"
	done
	shopt -u nullglob
}

refuse_open_devices() {
	local node users pid process
	local busy=0

	while IFS= read -r node; do
		[[ -n "$node" ]] || continue
		users=$(fuser "$node" 2>/dev/null || true)
		if [[ -n "$users" ]]; then
			for pid in $users; do
				process=$(ps -p "$pid" -o comm= 2>/dev/null || true)
				printf 'BUSY: %s is open by PID %s (%s)\n' \
					"$node" "$pid" "${process:-unknown}" >&2
			done
			busy=1
		fi
	done < <(discover_owned_device_files)
	((busy == 0)) || die "close the listed HWS users before module reload"
}

pcm_node() {
	local card device

	[[ "$PCM" =~ ^hw:([0-9]+),([0-9]+)$ ]] || return 1
	card=${BASH_REMATCH[1]}
	device=${BASH_REMATCH[2]}
	printf '/dev/snd/pcmC%sD%sc\n' "$card" "$device"
}

pcm_channel() {
	[[ "$PCM" =~ ^hw:[0-9]+,([0-9]+)$ ]] || return 1
	printf '%s\n' "${BASH_REMATCH[1]}"
}

verify_pcm() {
	local node class

	node=$(pcm_node)
	class="/sys/class/sound/${node##*/}"
	[[ -e "$node" && -e "$class/device" ]] ||
		die "$PCM is not present after module load (expected $node)"
	path_belongs_to_bdf "$class/device" ||
		die "$PCM does not belong to PCI function $BDF"
}

verify_video() {
	local class

	[[ -n "$VIDEO_NODE" ]] || return 0
	class="/sys/class/video4linux/${VIDEO_NODE##*/}"
	[[ -e "$VIDEO_NODE" && -e "$class/device" ]] ||
		die "$VIDEO_NODE is not present after module load"
	path_belongs_to_bdf "$class/device" ||
		die "$VIDEO_NODE does not belong to PCI function $BDF"
}

wait_for_pcm() {
	local attempt
	local node

	node=$(pcm_node)
	for ((attempt = 0; attempt < 100; attempt++)); do
		[[ -e "$node" ]] && return 0
		sleep 0.1
	done
	return 1
}

verify_loaded_module() {
	local expected loaded force_intx
	local msi_dir="/sys/bus/pci/devices/$BDF/msi_irqs"

	expected=$(modinfo -F srcversion "$MODULE_PATH")
	loaded=$(<"/sys/module/$MODULE_NAME/srcversion")
	[[ "$loaded" == "$expected" ]] ||
		die "loaded srcversion $loaded does not match test module $expected"
	force_intx=$(<"/sys/module/$MODULE_NAME/parameters/force_intx")
	[[ "$force_intx" == N ]] || die "focused test requires force_intx=N"
	[[ -d "$msi_dir" ]] && compgen -G "$msi_dir/*" >/dev/null ||
		die "$BDF did not enable MSI/MSI-X"
}

reload_test_module() {
	MODULE_TOUCHED=1
	if [[ -d "/sys/module/$MODULE_NAME" ]]; then
		refuse_open_devices
		print_command rmmod "$MODULE_NAME"
		rmmod "$MODULE_NAME"
	fi
	print_command insmod "$MODULE_PATH" enable_audio=Y force_intx=N
	insmod "$MODULE_PATH" enable_audio=Y force_intx=N
	udevadm settle --timeout=10 || true
	wait_for_pcm || die "$PCM did not appear after module load"
	verify_loaded_module
	verify_pcm
	verify_video
}

irq_vector() {
	local path

	for path in "/sys/bus/pci/devices/$BDF/msi_irqs/"*; do
		[[ -e "$path" ]] || continue
		printf '%s\n' "${path##*/}"
		return 0
	done
	return 1
}

irq_total() {
	local vector=$1

	awk -v wanted="$vector:" '
		$1 == wanted {
			for (i = 2; i <= NF && $i ~ /^[0-9]+$/; i++)
				total += $i
		}
		END { print total + 0 }
	' /proc/interrupts
}

collect_kernel_delta() {
	local current="$OUTPUT_DIR/dmesg-current.log"
	local first=$((KLOG_BASELINE_LINES + 1))

	dmesg >"$current"
	tail -n "+$first" "$current" >"$OUTPUT_DIR/kernel-delta.log"
}

cleanup() {
	local exit_code=$?

	trap - EXIT INT TERM
	if [[ -n "$CAPTURE_PID" ]] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
		kill -TERM "$CAPTURE_PID" 2>/dev/null || true
		wait "$CAPTURE_PID" 2>/dev/null || true
	fi
	if [[ -n "$VIDEO_PID" ]] && kill -0 "$VIDEO_PID" 2>/dev/null; then
		kill -TERM "$VIDEO_PID" 2>/dev/null || true
		wait "$VIDEO_PID" 2>/dev/null || true
	fi
	if ((RUN && MODULE_TOUCHED)) && [[ ! -d "/sys/module/$MODULE_NAME" ]]; then
		printf 'Cleanup: restoring %s in MSI-preferred mode\n' "$MODULE_NAME" >&2
		insmod "$MODULE_PATH" enable_audio=Y force_intx=N || exit_code=1
	fi
	exit "$exit_code"
}

write_metadata() {
	{
		printf 'date=%s\n' "$(date --iso-8601=seconds)"
		printf 'bdf=%s\n' "$BDF"
		printf 'pcm=%s\n' "$PCM"
		printf 'video=%s\n' "${VIDEO_NODE:-none}"
		printf 'duration_seconds=%s\n' "$DURATION"
		printf 'module=%s\n' "$MODULE_PATH"
		printf 'module_sha256=%s\n' "$(sha256sum "$MODULE_PATH" | awk '{print $1}')"
		printf 'module_srcversion=%s\n' "$(modinfo -F srcversion "$MODULE_PATH")"
		printf 'git_head=%s\n' "$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || printf unknown)"
		printf 'git_status=%s\n' "$(git -C "$SCRIPT_DIR" status --short 2>/dev/null | tr '\n' ';')"
	} >"$OUTPUT_DIR/metadata.txt"
}

start_video_capture() {
	[[ -n "$VIDEO_NODE" ]] || return 0

	printf 'Starting concurrent capture on %s\n' "$VIDEO_NODE"
	timeout --signal=TERM --kill-after=2s "$((DURATION + 5))s" \
		v4l2-ctl --device "$VIDEO_NODE" --stream-mmap=4 \
		--stream-poll --stream-to=/dev/null \
		>"$OUTPUT_DIR/video-capture.log" 2>&1 &
	VIDEO_PID=$!
	sleep 0.5
	if ! kill -0 "$VIDEO_PID" 2>/dev/null; then
		set +e
		wait "$VIDEO_PID"
		VIDEO_RC=$?
		set -e
		VIDEO_PID=
		die "concurrent capture on $VIDEO_NODE exited early (exit $VIDEO_RC; see $OUTPUT_DIR/video-capture.log)"
	fi
}

stop_video_capture() {
	[[ -n "$VIDEO_PID" ]] || return 0

	kill -TERM "$VIDEO_PID" 2>/dev/null || true
	set +e
	wait "$VIDEO_PID"
	VIDEO_RC=$?
	set -e
	VIDEO_PID=
}

run_capture() {
	local channel vector irq_before irq_after irq_delta rc

	channel=$(pcm_channel)
	vector=$(irq_vector) || die "could not resolve the active MSI vector"
	irq_before=$(irq_total "$vector")
	printf '%s\n' "$irq_before" >"$OUTPUT_DIR/irq-before.txt"
	cp "/proc/interrupts" "$OUTPUT_DIR/proc-interrupts-before.txt"

	printf 'Capturing %s for %s seconds on MSI vector %s\n' \
		"$PCM" "$DURATION" "$vector"
	start_video_capture
	set +e
	timeout --signal=TERM --kill-after=2s "$((DURATION + 5))s" \
		strace -tt -T -yy -o "$OUTPUT_DIR/arecord.strace" \
		arecord -q --fatal-errors -D "$PCM" -t raw -f S16_LE \
		-r 48000 -c 2 -d "$DURATION" /dev/null \
		>"$OUTPUT_DIR/arecord.log" 2>&1
	rc=$?
	set -e
	stop_video_capture
	sleep 0.2

	irq_after=$(irq_total "$vector")
	irq_delta=$((irq_after - irq_before))
	printf '%s\n' "$irq_after" >"$OUTPUT_DIR/irq-after.txt"
	cp "/proc/interrupts" "$OUTPUT_DIR/proc-interrupts-after.txt"
	collect_kernel_delta
	rg "audio telemetry .*ch=$channel([[:space:]]|$)" \
		"$OUTPUT_DIR/kernel-delta.log" >"$OUTPUT_DIR/audio-telemetry.log" || true

	{
		printf 'pcm=%s\n' "$PCM"
		printf 'channel=%s\n' "$channel"
		printf 'video=%s\n' "${VIDEO_NODE:-none}"
		if [[ -n "$VIDEO_NODE" ]]; then
			printf 'video_rc=%s\n' "$VIDEO_RC"
		fi
		printf 'arecord_rc=%s\n' "$rc"
		printf 'msi_vector=%s\n' "$vector"
		printf 'irq_before=%s\n' "$irq_before"
		printf 'irq_after=%s\n' "$irq_after"
		printf 'irq_delta=%s\n' "$irq_delta"
		printf 'telemetry_events=%s\n' \
			"$(wc -l <"$OUTPUT_DIR/audio-telemetry.log")"
		if ((rc == 0)); then
			printf 'result=PASS\n'
		elif rg -q 'event=xrun' "$OUTPUT_DIR/audio-telemetry.log"; then
			printf 'result=XRUN_DIAGNOSED\n'
		elif rg -q 'event=stop .*irq=0 .*delivered=0' \
			"$OUTPUT_DIR/audio-telemetry.log"; then
			printf 'result=FAIL_NO_ADONE\n'
		else
			printf 'result=FAIL_NO_XRUN_TELEMETRY\n'
		fi
	} >"$OUTPUT_DIR/summary.txt"

	cat "$OUTPUT_DIR/summary.txt"
	printf '\nAudio telemetry:\n'
	cat "$OUTPUT_DIR/audio-telemetry.log"
	printf '\nEvidence: %s\n' "$OUTPUT_DIR"
	return "$rc"
}

main() {
	parse_args "$@"
	validate_args
	require_commands

	if ((!RUN)); then
		printf 'Focused audio preflight:\n'
		printf '  PCI function: %s\n' "$BDF"
		printf '  PCM:          %s\n' "$PCM"
		printf '  Video:        %s\n' "${VIDEO_NODE:-none}"
		printf '  Duration:     %s seconds\n' "$DURATION"
		printf '  Module:       %s\n' "$MODULE_PATH"
		printf '\nNo state changed. Add --run as root after stopping WirePlumber.\n'
		return 0
	fi

	((EUID == 0)) || die "--run requires root"
	if [[ -z "$OUTPUT_DIR" ]]; then
		OUTPUT_DIR="/tmp/hws-audio-focus-$(date +%Y%m%d-%H%M%S)"
	fi
	mkdir -p -- "$OUTPUT_DIR"
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	dmesg >"$OUTPUT_DIR/dmesg-baseline.log"
	KLOG_BASELINE_LINES=$(wc -l <"$OUTPUT_DIR/dmesg-baseline.log")
	write_metadata
	reload_test_module
	run_capture
}

main "$@"
