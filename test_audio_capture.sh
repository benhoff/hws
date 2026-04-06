#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: ./test_audio_capture.sh [options]

Automate as much of doc/audio-capture-test-plan.md as is practical from bash.
The script writes all evidence under a timestamped output directory and keeps a
summary TSV that marks each phase PASS/FAIL/WARN/SKIP/INFO.

Defaults:
  - autodetect the first HWS ALSA capture device, then loop over all detected
    HWS PCM capture devices for smoke coverage
  - use PipeWire by default for recording so the desktop audio session can own
    the HWS devices without blocking the test harness
  - use 48 kHz, S16_LE, 2 channels
  - run deeper matrix/long-run testing only on the first selected device
  - skip intrusive BAR remap mutation, module reload, and interactive
    source-change testing unless explicitly requested

Options:
  --audio-device hw:CARD,DEV   Restrict testing to one ALSA capture device.
  --backend NAME               Recording backend: pipewire or alsa.
  --video-device /dev/videoN   V4L2 node to use for mixed A/V testing.
  --pci-device 0000:17:00.0    PCI BDF for BAR0 remap validation.
  --module-name NAME           Kernel module name for reload testing.
  --module-ko PATH             Module .ko to insmod during reload testing.
  --output-dir DIR             Output directory. Default: /tmp timestamp dir.
  --smoke-seconds N            Seconds for smoke captures. Default: 10
  --short-seconds N            Seconds per reopen cycle. Default: 4
  --matrix-seconds N           Seconds per period/buffer case. Default: 12
  --long-run-seconds N         Sustained capture duration. Default: 300
  --mixed-seconds N            Audio duration for mixed A/V test. Default: 15
  --reopen-cycles N            Reopen iterations. Default: 5
  --playback                   Play smoke captures back with aplay.
  --skip-mixed-video           Skip video baseline + mixed A/V phases.
  --run-remap-validation       Run intrusive Test 0 BAR remap collection/trials.
  --run-module-reload          Unload/reload the module, then rerun smoke.
  --interactive-source-change  Prompt for manual signal-loss/source-change steps.
  --help                       Show this help.

Examples:
  ./test_audio_capture.sh
  ./test_audio_capture.sh --backend pipewire
  ./test_audio_capture.sh --audio-device hw:5,0 --video-device /dev/video0
  sudo ./test_audio_capture.sh --audio-device hw:5,0 --pci-device 0000:17:00.0 \
      --run-remap-validation --run-module-reload
EOF
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

OUTPUT_DIR=""
AUDIO_DEVICE=""
VIDEO_DEVICE=""
PCI_DEVICE="0000:17:00.0"
MODULE_NAME="HwsCapture"
MODULE_KO="$SCRIPT_DIR/src/HwsCapture.ko"
AUDIO_BACKEND="pipewire"

SMOKE_SECONDS=10
SHORT_SECONDS=4
MATRIX_SECONDS=12
LONG_RUN_SECONDS=300
MIXED_SECONDS=15
REOPEN_CYCLES=5

RATE=48000
CHANNELS=2
FORMAT="S16_LE"
SAMPLE_BYTES=2

PLAYBACK=0
SKIP_MIXED_VIDEO=0
RUN_REMAP_VALIDATION=0
RUN_MODULE_RELOAD=0
RUN_INTERACTIVE_SOURCE_CHANGE=0

RUN_LOG=""
SUMMARY_TSV=""
SUMMARY_TXT=""
MANUAL_FOLLOWUPS=""
LAST_BG_PID=""
LAST_CAPTURE_TARGET=""

declare -a AUDIO_DEVICES=()
declare -a BACKGROUND_PIDS=()
declare -a RESTORE_OFFSETS=()
declare -a RESTORE_VALUES=()

timestamp() {
	date '+%Y%m%d-%H%M%S'
}

log() {
	local msg=$1
	printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$msg" | tee -a "$RUN_LOG"
}

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

note_cmd_missing() {
	local cmd=$1
	record_result "prereq.$cmd" "SKIP" "command not found"
}

sanitize_name() {
	printf '%s' "$1" | tr '/:,' '_'
}

audio_channel_index() {
	local dev=$1
	local idx=${dev##*,}
	printf '%s\n' "$((10#$idx))"
}

audio_card_index() {
	local dev=$1
	local card=${dev#hw:}
	card=${card%%,*}
	printf '%s\n' "$((10#$card))"
}

audio_card_id() {
	local dev=$1
	local card

	card=$(audio_card_index "$dev")
	cat "/proc/asound/card${card}/id" 2>/dev/null || true
}

audio_card_bdf() {
	local dev=$1
	local card
	local path

	card=$(audio_card_index "$dev")
	path=$(readlink -f "/sys/class/sound/card${card}/device" 2>/dev/null || true)
	if [ -n "$path" ]; then
		basename "$path"
	fi
}

pipewire_target_guess() {
	local dev=$1
	local bdf
	local ch

	bdf=$(audio_card_bdf "$dev")
	ch=$(audio_channel_index "$dev")
	if [ -n "$bdf" ]; then
		printf 'alsa_input.pci-%s.pro-input-%s\n' "${bdf//:/_}" "$ch"
	fi
}

pipewire_target_for_audio_device() {
	local dev=$1
	local expected=""
	local ch
	local resolved=""

	ch=$(audio_channel_index "$dev")
	expected=$(pipewire_target_guess "$dev")

	if have_cmd pactl; then
		set +e
		resolved=$(
			pactl list short sources 2>/dev/null | awk -v expected="$expected" -v ch="$ch" '
				$2 == expected { print $2; exit }
				index($2, ".pro-input-" ch) { print $2; exit }
			'
		)
		set -e
	fi

	if [ -n "$resolved" ]; then
		printf '%s\n' "$resolved"
	elif [ -n "$expected" ]; then
		printf '%s\n' "$expected"
	fi
}

begin_dmesg_capture() {
	local before_path=$1
	if dmesg -T >"$before_path" 2>/dev/null; then
		wc -l <"$before_path"
	else
		printf 'dmesg unavailable before test\n' >"$before_path"
		printf '0\n'
	fi
}

finish_dmesg_capture() {
	local start_lines=$1
	local after_path=$2
	local delta_path=$3

	if dmesg -T >"$after_path" 2>/dev/null; then
		tail -n "+$((start_lines + 1))" "$after_path" >"$delta_path" || :
	else
		printf 'dmesg unavailable after test\n' >"$after_path"
		printf 'dmesg delta unavailable\n' >"$delta_path"
	fi
}

record_result() {
	local name=$1
	local status=$2
	local detail=$3

	printf '%s\t%s\t%s\n' "$status" "$name" "$detail" >>"$SUMMARY_TSV"
	printf '%-5s  %-32s %s\n' "$status" "$name" "$detail" | tee -a "$SUMMARY_TXT" "$RUN_LOG" >/dev/null
}

kill_background_pids() {
	local pid
	for pid in "${BACKGROUND_PIDS[@]:-}"; do
		if kill -0 "$pid" >/dev/null 2>&1; then
			kill "$pid" >/dev/null 2>&1 || true
			wait "$pid" >/dev/null 2>&1 || true
		fi
	done
	BACKGROUND_PIDS=()
}

bar0_path() {
	printf '/sys/bus/pci/devices/%s/resource0\n' "$PCI_DEVICE"
}

queue_bar0_restore() {
	RESTORE_OFFSETS+=("$1")
	RESTORE_VALUES+=("$2")
}

clear_bar0_restore() {
	RESTORE_OFFSETS=()
	RESTORE_VALUES=()
}

bar0_read32() {
	local path=$1
	local offset=$2

	python3 - "$path" "$offset" <<'PY'
import mmap
import struct
import sys

path = sys.argv[1]
offset = int(sys.argv[2], 0)

with open(path, "rb", buffering=0) as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        if offset < 0 or offset + 4 > len(mm):
            raise SystemExit("offset out of range")
        value = struct.unpack_from("<I", mm, offset)[0]
        print(f"0x{value:08x}")
    finally:
        mm.close()
PY
}

bar0_write32() {
	local path=$1
	local offset=$2
	local value=$3

	python3 - "$path" "$offset" "$value" <<'PY'
import mmap
import struct
import sys

path = sys.argv[1]
offset = int(sys.argv[2], 0)
value = int(sys.argv[3], 0)

with open(path, "r+b", buffering=0) as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)
    try:
        if offset < 0 or offset + 4 > len(mm):
            raise SystemExit("offset out of range")
        struct.pack_into("<I", mm, offset, value)
        mm.flush()
    finally:
        mm.close()
PY
}

restore_bar0_registers() {
	local path
	local i

	path=$(bar0_path)
	if [ "${#RESTORE_OFFSETS[@]}" -eq 0 ] || [ ! -e "$path" ]; then
		return 0
	fi

	for i in "${!RESTORE_OFFSETS[@]}"; do
		bar0_write32 "$path" "${RESTORE_OFFSETS[$i]}" "${RESTORE_VALUES[$i]}" || true
	done
	clear_bar0_restore
}

cleanup() {
	local rc=$?
	trap - EXIT INT TERM
	restore_bar0_registers || true
	kill_background_pids || true
	exit "$rc"
}

trap cleanup EXIT INT TERM

analyze_wav() {
	local wav=$1
	local duration=$2
	local analysis_path=$3
	local size=0
	local sha=""
	local expected_min=0
	local status="missing"

	if [ -f "$wav" ]; then
		size=$(stat -c %s "$wav" 2>/dev/null || printf '0')
		sha=$(sha256sum "$wav" | awk '{print $1}')
	fi

	expected_min=$((44 + (duration * RATE * CHANNELS * SAMPLE_BYTES * 3 / 4)))

	{
		printf 'path=%s\n' "$wav"
		printf 'size_bytes=%s\n' "$size"
		printf 'expected_min_bytes=%s\n' "$expected_min"
		printf 'sha256=%s\n' "$sha"
	} >"$analysis_path"

	if [ ! -f "$wav" ] || [ "$size" -eq 0 ]; then
		status="missing"
	elif [ "$size" -le 44 ]; then
		status="empty"
	elif [ "$size" -lt "$expected_min" ]; then
		status="truncated"
	else
		status="ok"
	fi

	if have_cmd ffmpeg && [ -f "$wav" ]; then
		local volume_log="$analysis_path.volumedetect.log"
		local mean_volume=""
		local max_volume=""
		local ffmpeg_rc=0

		set +e
		ffmpeg -nostdin -hide_banner -i "$wav" -af volumedetect -f null - >/dev/null 2>"$volume_log"
		ffmpeg_rc=$?
		set -e

		mean_volume=$(awk -F': ' '/mean_volume/ {print $2}' "$volume_log" | tail -n 1)
		max_volume=$(awk -F': ' '/max_volume/ {print $2}' "$volume_log" | tail -n 1)

		{
			printf 'ffmpeg_rc=%s\n' "$ffmpeg_rc"
			printf 'mean_volume=%s\n' "${mean_volume:-unknown}"
			printf 'max_volume=%s\n' "${max_volume:-unknown}"
		} >>"$analysis_path"

		if [ "$status" = "ok" ] && [ "${max_volume:-}" = "-inf dB" ]; then
			status="silent"
		fi
	fi

	printf 'status=%s\n' "$status" >>"$analysis_path"
	printf '%s\n' "$status"
}

run_arecord_capture() {
	local dev=$1
	local duration=$2
	local wav_path=$3
	local log_path=$4
	shift 4

	set +e
	arecord -D "$dev" -f "$FORMAT" -r "$RATE" -c "$CHANNELS" "$@" -d "$duration" "$wav_path" >"$log_path" 2>&1
	local rc=$?
	set -e
	printf 'exit_code=%s\n' "$rc" >>"$log_path"
	return "$rc"
}

run_pw_record_capture() {
	local dev=$1
	local duration=$2
	local wav_path=$3
	local log_path=$4
	local target=""
	shift 4

	target=$(pipewire_target_for_audio_device "$dev")
	LAST_CAPTURE_TARGET=$target
	if [ -z "$target" ]; then
		printf 'pipewire target resolution failed for %s\n' "$dev" >"$log_path"
		printf 'exit_code=1\n' >>"$log_path"
		return 1
	fi

	set +e
	timeout --signal=INT --kill-after=3s "${duration}s" \
		pw-record \
			--target "$target" \
			--rate "$RATE" \
			--channels "$CHANNELS" \
			--format s16 \
			"$wav_path" >"$log_path" 2>&1
	local rc=$?
	set -e
	if [ "$rc" -eq 124 ] || [ "$rc" -eq 130 ]; then
		rc=0
	fi
	printf 'target=%s\n' "$target" >>"$log_path"
	printf 'exit_code=%s\n' "$rc" >>"$log_path"
	return "$rc"
}

run_audio_capture() {
	local dev=$1
	local duration=$2
	local wav_path=$3
	local log_path=$4
	shift 4

	LAST_CAPTURE_TARGET=$dev
	case "$AUDIO_BACKEND" in
		alsa)
			run_arecord_capture "$dev" "$duration" "$wav_path" "$log_path" "$@"
			;;
		pipewire)
			run_pw_record_capture "$dev" "$duration" "$wav_path" "$log_path" "$@"
			;;
		*)
			printf 'unsupported backend: %s\n' "$AUDIO_BACKEND" >"$log_path"
			printf 'exit_code=1\n' >>"$log_path"
			return 1
			;;
	esac
}

run_audio_case() {
	local name=$1
	local dev=$2
	local duration=$3
	local out_dir=$4
	shift 4

	local prefix="$out_dir/$name"
	local wav_path="$prefix.wav"
	local arecord_log="$prefix.arecord.log"
	local before_log="$prefix.dmesg.before.log"
	local after_log="$prefix.dmesg.after.log"
	local delta_log="$prefix.dmesg.delta.log"
	local analysis_path="$prefix.analysis.txt"
	local dmesg_start=0
	local rc=0
	local wav_status=""
	local status="PASS"
	local detail=""

	log "Running $name on $dev for ${duration}s"
	dmesg_start=$(begin_dmesg_capture "$before_log")
	if run_audio_capture "$dev" "$duration" "$wav_path" "$arecord_log" "$@"; then
		rc=0
	else
		rc=$?
	fi
	finish_dmesg_capture "$dmesg_start" "$after_log" "$delta_log"

	wav_status=$(analyze_wav "$wav_path" "$duration" "$analysis_path")
	detail="backend=$AUDIO_BACKEND device=$dev target=$LAST_CAPTURE_TARGET rc=$rc wav_status=$wav_status file=$(basename "$wav_path")"

	if [ "$rc" -ne 0 ] || [ "$wav_status" = "missing" ] || [ "$wav_status" = "empty" ] || [ "$wav_status" = "truncated" ]; then
		status="FAIL"
	elif [ "$wav_status" = "silent" ]; then
		status="WARN"
	fi

	record_result "$name" "$status" "$detail"
	[ "$status" != "FAIL" ]
}

play_back_capture() {
	local wav=$1
	local log_path=$2

	if ! have_cmd aplay; then
		note_cmd_missing aplay
		return 0
	fi

	set +e
	aplay "$wav" >"$log_path" 2>&1
	local rc=$?
	set -e

	if [ "$rc" -eq 0 ]; then
		record_result "smoke.playback" "PASS" "aplay completed for $(basename "$wav")"
	else
		record_result "smoke.playback" "WARN" "aplay rc=$rc for $(basename "$wav")"
	fi
}

run_reopen_test() {
	local dev=$1
	local out_dir=$2
	local i=0
	local failures=0
	local duplicate_shas=0
	local last_sha=""

	log "Running reopen stability test on $dev ($REOPEN_CYCLES cycles)"

	for ((i = 1; i <= REOPEN_CYCLES; i++)); do
		local name
		local analysis_path
		local current_sha=""

		printf -v name 'reopen.cycle_%02d' "$i"
		if ! run_audio_case "$name" "$dev" "$SHORT_SECONDS" "$out_dir"; then
			failures=$((failures + 1))
		fi

		analysis_path="$out_dir/$name.analysis.txt"
		if [ -f "$analysis_path" ]; then
			current_sha=$(awk -F= '/^sha256=/ {print $2}' "$analysis_path")
			if [ -n "$last_sha" ] && [ -n "$current_sha" ] && [ "$last_sha" = "$current_sha" ]; then
				duplicate_shas=$((duplicate_shas + 1))
			fi
			last_sha=$current_sha
		fi
	done

	if [ "$failures" -gt 0 ]; then
		record_result "reopen.summary" "FAIL" "failures=$failures duplicate_shas=$duplicate_shas"
	elif [ "$duplicate_shas" -gt 0 ]; then
		record_result "reopen.summary" "WARN" "all cycles completed; duplicate_shas=$duplicate_shas"
	else
		record_result "reopen.summary" "PASS" "all cycles completed cleanly"
	fi
}

run_matrix_test() {
	local dev=$1
	local out_dir=$2
	local failures=0
	local matrix_cases=(
		"512:2048"
		"512:8192"
		"1024:4096"
		"2048:16384"
		"4096:32768"
	)
	local entry=""

	if [ "$AUDIO_BACKEND" != "alsa" ]; then
		record_result "matrix.summary" "SKIP" "period/buffer matrix requires --backend alsa"
		return 0
	fi

	log "Running ALSA period/buffer matrix on $dev"

	for entry in "${matrix_cases[@]}"; do
		local period=${entry%%:*}
		local buffer=${entry##*:}
		local name="matrix.p${period}.b${buffer}"
		if ! run_audio_case "$name" "$dev" "$MATRIX_SECONDS" "$out_dir" "--period-size=$period" "--buffer-size=$buffer" -v; then
			failures=$((failures + 1))
		fi
	done

	if [ "$failures" -gt 0 ]; then
		record_result "matrix.summary" "FAIL" "failed_cases=$failures"
	else
		record_result "matrix.summary" "PASS" "all period/buffer cases completed"
	fi
}

run_long_run_test() {
	local dev=$1
	local out_dir=$2

	log "Running long capture on $dev for ${LONG_RUN_SECONDS}s"
	if run_audio_case "longrun.capture" "$dev" "$LONG_RUN_SECONDS" "$out_dir"; then
		if [ "$LONG_RUN_SECONDS" -lt 1800 ]; then
			record_result "longrun.note" "INFO" "captured ${LONG_RUN_SECONDS}s; rerun with --long-run-seconds 1800 for the plan's 30 minute recommendation"
		fi
	else
		record_result "longrun.note" "WARN" "long-run capture failed before reaching ${LONG_RUN_SECONDS}s"
	fi
}

autodetect_video_device() {
	if have_cmd v4l2-ctl; then
		v4l2-ctl --list-devices 2>/dev/null | awk '
			BEGIN { IGNORECASE = 1; fallback = "" }
			/^[^ \t].*:$/ { name = $0; next }
			/^[ \t]+\/dev\/video[0-9]+/ {
				gsub(/^[ \t]+/, "", $0)
				if (name ~ /(hws|hwscapture|avmatrix)/) {
					print $0
					exit
				}
				if (fallback == "")
					fallback = $0
			}
			END {
				if (fallback != "")
					print fallback
			}
		' | head -n 1
		return
	fi

	if compgen -G '/dev/video*' >/dev/null; then
		ls /dev/video* 2>/dev/null | head -n 1
	fi
}

run_video_capture() {
	local duration=$1
	local log_path=$2

	set +e
	ffmpeg -nostdin -hide_banner -loglevel info -f v4l2 -i "$VIDEO_DEVICE" -t "$duration" -f null - >"$log_path" 2>&1
	local rc=$?
	set -e
	printf 'exit_code=%s\n' "$rc" >>"$log_path"
	return "$rc"
}

run_video_capture_bg() {
	local duration=$1
	local log_path=$2

	(
		ffmpeg -nostdin -hide_banner -loglevel info -f v4l2 -i "$VIDEO_DEVICE" -t "$duration" -f null -
	) >"$log_path" 2>&1 &

	local pid=$!
	BACKGROUND_PIDS+=("$pid")
	LAST_BG_PID=$pid
}

run_mixed_video_test() {
	local dev=$1
	local out_dir=$2
	local before_log=""
	local after_log=""
	local delta_log=""
	local dmesg_start=0
	local rc_video=0
	local rc_audio=0
	local wav_status=""
	local audio_wav=""
	local audio_analysis=""
	local video_pid=""
	local video_duration=$((MIXED_SECONDS + 4))
	local -a background_remaining=()
	local pid=""

	if [ "$SKIP_MIXED_VIDEO" -eq 1 ]; then
		record_result "mixed.summary" "SKIP" "audio_device=$dev mixed A/V explicitly disabled"
		return 0
	fi

	if [ -z "$VIDEO_DEVICE" ]; then
		record_result "mixed.summary" "SKIP" "audio_device=$dev no V4L2 video node available"
		return 0
	fi

	if ! have_cmd ffmpeg; then
		record_result "mixed.summary" "SKIP" "audio_device=$dev ffmpeg not installed"
		return 0
	fi

	log "Running video-only baseline on $VIDEO_DEVICE"
	if run_video_capture "$MIXED_SECONDS" "$out_dir/mixed.video_only.ffmpeg.log"; then
		record_result "mixed.video_only" "PASS" "audio_device=$dev video_device=$VIDEO_DEVICE baseline completed"
	else
		record_result "mixed.video_only" "WARN" "audio_device=$dev video_device=$VIDEO_DEVICE baseline failed"
	fi

	log "Running concurrent audio/video test: audio=$dev video=$VIDEO_DEVICE"

	before_log="$out_dir/mixed.concurrent.dmesg.before.log"
	after_log="$out_dir/mixed.concurrent.dmesg.after.log"
	delta_log="$out_dir/mixed.concurrent.dmesg.delta.log"
	dmesg_start=$(begin_dmesg_capture "$before_log")

	run_video_capture_bg "$video_duration" "$out_dir/mixed.concurrent.video.ffmpeg.log"
	video_pid=$LAST_BG_PID
	sleep 2

	audio_wav="$out_dir/mixed.concurrent.audio.wav"
	if run_audio_capture "$dev" "$MIXED_SECONDS" "$audio_wav" "$out_dir/mixed.concurrent.audio.arecord.log"; then
		rc_audio=0
	else
		rc_audio=$?
	fi
	set +e
	wait "$video_pid"
	rc_video=$?
	set -e

	for pid in "${BACKGROUND_PIDS[@]}"; do
		if [ "$pid" != "$video_pid" ]; then
			background_remaining+=("$pid")
		fi
	done
	BACKGROUND_PIDS=("${background_remaining[@]}")

	printf 'exit_code=%s\n' "$rc_audio" >>"$out_dir/mixed.concurrent.audio.arecord.log"
	finish_dmesg_capture "$dmesg_start" "$after_log" "$delta_log"

	audio_analysis="$out_dir/mixed.concurrent.audio.analysis.txt"
	wav_status=$(analyze_wav "$audio_wav" "$MIXED_SECONDS" "$audio_analysis")

	if [ "$rc_audio" -ne 0 ] || [ "$rc_video" -ne 0 ] || [ "$wav_status" = "missing" ] || [ "$wav_status" = "empty" ] || [ "$wav_status" = "truncated" ]; then
		record_result "mixed.concurrent" "FAIL" "backend=$AUDIO_BACKEND audio_device=$dev audio_target=$LAST_CAPTURE_TARGET video_device=$VIDEO_DEVICE audio_rc=$rc_audio video_rc=$rc_video wav_status=$wav_status"
	elif [ "$wav_status" = "silent" ]; then
		record_result "mixed.concurrent" "WARN" "backend=$AUDIO_BACKEND audio_device=$dev audio_target=$LAST_CAPTURE_TARGET video_device=$VIDEO_DEVICE audio_rc=$rc_audio video_rc=$rc_video wav_status=$wav_status"
	else
		record_result "mixed.concurrent" "PASS" "backend=$AUDIO_BACKEND audio_device=$dev audio_target=$LAST_CAPTURE_TARGET video_device=$VIDEO_DEVICE audio_rc=$rc_audio video_rc=$rc_video wav_status=$wav_status"
	fi
}

discover_hws_card_indices() {
	awk '/^[[:space:]]*[0-9]+ \[[^]]+\]: .*HWS HDMI Audio/ { print $1 }' /proc/asound/cards 2>/dev/null
}

discover_hws_audio_devices() {
	local card_idx=$1
	local card_prefix

	printf -v card_prefix '%02d-' "$card_idx"
	awk -v prefix="$card_prefix" '
		index($1, prefix) == 1 && /capture/ {
			split($1, parts, "-")
			printf "hw:%d,%d\n", parts[1] + 0, parts[2] + 0
		}
	' /proc/asound/pcm 2>/dev/null
}

record_discovery() {
	local discover_dir=$1
	local card_idx=""

	mkdir -p "$discover_dir"
	log "Collecting discovery data"

	if have_cmd arecord; then
		set +e
		arecord -l >"$discover_dir/arecord-l.txt" 2>&1
		local arecord_rc=$?
		set -e
		record_result "discovery.arecord" "INFO" "saved arecord -l output rc=$arecord_rc"
	else
		note_cmd_missing arecord
	fi

	if have_cmd aplay; then
		set +e
		aplay -l >"$discover_dir/aplay-l.txt" 2>&1
		local aplay_rc=$?
		set -e
		record_result "discovery.aplay" "INFO" "saved aplay -l output rc=$aplay_rc"
	fi

	cat /proc/asound/cards >"$discover_dir/proc-asound-cards.txt" 2>/dev/null || printf 'unavailable\n' >"$discover_dir/proc-asound-cards.txt"
	cat /proc/asound/pcm >"$discover_dir/proc-asound-pcm.txt" 2>/dev/null || printf 'unavailable\n' >"$discover_dir/proc-asound-pcm.txt"

	if have_cmd v4l2-ctl; then
		set +e
		v4l2-ctl --list-devices >"$discover_dir/v4l2-list-devices.txt" 2>&1
		local v4l2_rc=$?
		set -e
		record_result "discovery.v4l2" "INFO" "saved v4l2-ctl --list-devices rc=$v4l2_rc"
	else
		note_cmd_missing v4l2-ctl
	fi

	if have_cmd pactl; then
		set +e
		pactl list short sources >"$discover_dir/pactl-sources.txt" 2>&1
		local pactl_rc=$?
		set -e
		record_result "discovery.pactl" "INFO" "saved pactl list short sources rc=$pactl_rc"
	fi

	set +e
	lsmod >"$discover_dir/lsmod.txt" 2>&1
	grep -n "$MODULE_NAME" "$discover_dir/lsmod.txt" >"$discover_dir/lsmod-module.txt" 2>&1
	grep_rc=$?
	set -e

	if [ "$grep_rc" -eq 0 ]; then
		record_result "discovery.module" "INFO" "module $MODULE_NAME present in lsmod"
	else
		record_result "discovery.module" "WARN" "module $MODULE_NAME not found in lsmod snapshot"
	fi

	for card_idx in $(discover_hws_card_indices); do
		record_result "discovery.hws_card_$card_idx" "INFO" "found HWS audio card index $card_idx"
	done
}

ensure_output_dir() {
	if [ -z "$OUTPUT_DIR" ]; then
		OUTPUT_DIR="/tmp/hws-audio-capture-$(timestamp)"
	fi

	mkdir -p "$OUTPUT_DIR"
	RUN_LOG="$OUTPUT_DIR/run.log"
	SUMMARY_TSV="$OUTPUT_DIR/summary.tsv"
	SUMMARY_TXT="$OUTPUT_DIR/summary.txt"
	MANUAL_FOLLOWUPS="$OUTPUT_DIR/manual-followups.txt"
	: >"$RUN_LOG"
	printf 'status\tname\tdetail\n' >"$SUMMARY_TSV"
	: >"$SUMMARY_TXT"
}

write_run_metadata() {
	local meta_dir="$OUTPUT_DIR/meta"
	mkdir -p "$meta_dir"

	uname -a >"$meta_dir/uname.txt"
	date -Iseconds >"$meta_dir/started-at.txt"
	printf 'cwd=%s\n' "$SCRIPT_DIR" >"$meta_dir/context.txt"
	printf 'output_dir=%s\n' "$OUTPUT_DIR" >>"$meta_dir/context.txt"
	printf 'module_name=%s\n' "$MODULE_NAME" >>"$meta_dir/context.txt"
	printf 'module_ko=%s\n' "$MODULE_KO" >>"$meta_dir/context.txt"
	printf 'audio_backend=%s\n' "$AUDIO_BACKEND" >>"$meta_dir/context.txt"
	printf 'pci_device=%s\n' "$PCI_DEVICE" >>"$meta_dir/context.txt"
	printf 'audio_device_override=%s\n' "${AUDIO_DEVICE:-auto}" >>"$meta_dir/context.txt"
	printf 'video_device=%s\n' "${VIDEO_DEVICE:-auto}" >>"$meta_dir/context.txt"
	printf 'smoke_seconds=%s\n' "$SMOKE_SECONDS" >>"$meta_dir/context.txt"
	printf 'short_seconds=%s\n' "$SHORT_SECONDS" >>"$meta_dir/context.txt"
	printf 'matrix_seconds=%s\n' "$MATRIX_SECONDS" >>"$meta_dir/context.txt"
	printf 'long_run_seconds=%s\n' "$LONG_RUN_SECONDS" >>"$meta_dir/context.txt"
	printf 'mixed_seconds=%s\n' "$MIXED_SECONDS" >>"$meta_dir/context.txt"
	printf 'reopen_cycles=%s\n' "$REOPEN_CYCLES" >>"$meta_dir/context.txt"
	printf 'playback=%s\n' "$PLAYBACK" >>"$meta_dir/context.txt"
	printf 'skip_mixed_video=%s\n' "$SKIP_MIXED_VIDEO" >>"$meta_dir/context.txt"
	printf 'run_remap_validation=%s\n' "$RUN_REMAP_VALIDATION" >>"$meta_dir/context.txt"
	printf 'run_module_reload=%s\n' "$RUN_MODULE_RELOAD" >>"$meta_dir/context.txt"
	printf 'interactive_source_change=%s\n' "$RUN_INTERACTIVE_SOURCE_CHANGE" >>"$meta_dir/context.txt"

	if have_cmd git; then
		set +e
		git rev-parse HEAD >"$meta_dir/git-head.txt" 2>"$meta_dir/git-head.err"
		git status --short >"$meta_dir/git-status.txt" 2>"$meta_dir/git-status.err"
		set -e
	fi
}

maybe_autodetect_video_device() {
	if [ -n "$VIDEO_DEVICE" ]; then
		return 0
	fi

	VIDEO_DEVICE=$(autodetect_video_device || true)
}

discover_audio_devices() {
	local card_idx=""

	if [ -n "$AUDIO_DEVICE" ]; then
		AUDIO_DEVICES=("$AUDIO_DEVICE")
		return 0
	fi

	for card_idx in $(discover_hws_card_indices); do
		while IFS= read -r dev; do
			[ -n "$dev" ] && AUDIO_DEVICES+=("$dev")
		done < <(discover_hws_audio_devices "$card_idx")
	done
}

run_module_reload_test() {
	local dev=$1
	local out_dir=$2
	local reload_dir="$out_dir/module_reload"
	local unload_log="$reload_dir/modprobe-r.log"
	local load_log="$reload_dir/insmod.log"
	local was_loaded=0

	if [ "$RUN_MODULE_RELOAD" -ne 1 ]; then
		record_result "lifecycle.module_reload" "SKIP" "module reload test not requested"
		return 0
	fi

	if [ "$AUDIO_BACKEND" != "alsa" ]; then
		record_result "lifecycle.module_reload" "SKIP" "module reload validation currently requires --backend alsa"
		return 0
	fi

	if [ "$EUID" -ne 0 ]; then
		record_result "lifecycle.module_reload" "SKIP" "root required"
		return 0
	fi

	if [ ! -f "$MODULE_KO" ]; then
		record_result "lifecycle.module_reload" "SKIP" "module .ko not found at $MODULE_KO"
		return 0
	fi

	mkdir -p "$reload_dir"
	if lsmod | awk -v module="$MODULE_NAME" '$1 == module { found = 1 } END { exit found ? 0 : 1 }'; then
		was_loaded=1
	fi

	log "Running module reload test with $MODULE_NAME"
	if [ "$was_loaded" -eq 1 ]; then
		set +e
		modprobe -r "$MODULE_NAME" >"$unload_log" 2>&1
		local unload_rc=$?
		set -e
		if [ "$unload_rc" -ne 0 ]; then
			record_result "lifecycle.module_reload" "FAIL" "modprobe -r rc=$unload_rc"
			return 1
		fi
	else
		printf 'module %s was not loaded before test\n' "$MODULE_NAME" >"$unload_log"
	fi

	set +e
	insmod "$MODULE_KO" >"$load_log" 2>&1
	local load_rc=$?
	set -e

	if [ "$load_rc" -ne 0 ]; then
		record_result "lifecycle.module_reload" "FAIL" "insmod rc=$load_rc"
		return 1
	fi

	sleep 2
	record_result "lifecycle.module_reload" "PASS" "module reloaded via $(basename "$MODULE_KO")"
	run_audio_case "lifecycle.reload_smoke" "$dev" "$SMOKE_SECONDS" "$reload_dir" || true
}

run_interactive_source_change_test() {
	local dev=$1
	local out_dir=$2
	local prefix="$out_dir/source_change.interactive"
	local audio_log="$prefix.arecord.log"
	local wav="$prefix.wav"
	local before_log="$prefix.dmesg.before.log"
	local after_log="$prefix.dmesg.after.log"
	local delta_log="$prefix.dmesg.delta.log"
	local analysis="$prefix.analysis.txt"
	local dmesg_start=0
	local total_duration=30
	local pid=0
	local rc=0
	local wav_status=""
	local -a remaining=()
	local old_pid=""

	if [ "$RUN_INTERACTIVE_SOURCE_CHANGE" -ne 1 ]; then
		record_result "source_change.interactive" "SKIP" "interactive source-change test not requested"
		return 0
	fi

	if [ ! -t 0 ]; then
		record_result "source_change.interactive" "SKIP" "stdin is not interactive"
		return 0
	fi

	log "Preparing interactive source-change test on $dev"
	printf '\nInteractive source-change test on %s\n' "$dev"
	printf '  1. Make sure steady audio is present.\n'
	printf '  2. Press Enter to start capture.\n'
	printf '  3. After 8 seconds, remove signal.\n'
	printf '  4. After another 8 seconds, restore signal.\n'
	printf '  5. After another 8 seconds, optionally switch source/mode.\n\n'
	read -r

	dmesg_start=$(begin_dmesg_capture "$before_log")
	set +e
	arecord -D "$dev" -f "$FORMAT" -r "$RATE" -c "$CHANNELS" -d "$total_duration" "$wav" >"$audio_log" 2>&1 &
	pid=$!
	set -e
	BACKGROUND_PIDS+=("$pid")

	sleep 8
	printf 'Remove signal now.\n'
	sleep 8
	printf 'Restore signal now.\n'
	sleep 8
	printf 'Switch source or mode now if desired.\n'

	set +e
	wait "$pid"
	rc=$?
	set -e

	for old_pid in "${BACKGROUND_PIDS[@]}"; do
		if [ "$old_pid" != "$pid" ]; then
			remaining+=("$old_pid")
		fi
	done
	BACKGROUND_PIDS=("${remaining[@]}")

	printf 'exit_code=%s\n' "$rc" >>"$audio_log"
	finish_dmesg_capture "$dmesg_start" "$after_log" "$delta_log"
	wav_status=$(analyze_wav "$wav" "$total_duration" "$analysis")

	if [ "$rc" -ne 0 ]; then
		record_result "source_change.interactive" "FAIL" "arecord rc=$rc wav_status=$wav_status manual inspection required"
	else
		record_result "source_change.interactive" "INFO" "capture completed wav_status=$wav_status inspect audio + dmesg for signal-loss handling"
	fi
}

capture_remap_registers() {
	local ch=$1
	local out_path=$2
	local path
	local shared_hi_off shared_lo_off audio_hi_off audio_lo_off window_off
	local shared_hi shared_lo audio_hi audio_lo window

	path=$(bar0_path)
	shared_hi_off=$((0x208 + ch * 8))
	shared_lo_off=$((0x20c + ch * 8))
	audio_hi_off=$((0x208 + (8 + ch) * 8))
	audio_lo_off=$((0x20c + (8 + ch) * 8))
	window_off=$((0x4060 + ch * 4))

	shared_hi=$(bar0_read32 "$path" "$shared_hi_off")
	shared_lo=$(bar0_read32 "$path" "$shared_lo_off")
	audio_hi=$(bar0_read32 "$path" "$audio_hi_off")
	audio_lo=$(bar0_read32 "$path" "$audio_lo_off")
	window=$(bar0_read32 "$path" "$window_off")

	{
		printf 'channel=%s\n' "$ch"
		printf 'shared_hi_offset=0x%03x value=%s\n' "$shared_hi_off" "$shared_hi"
		printf 'shared_lo_offset=0x%03x value=%s\n' "$shared_lo_off" "$shared_lo"
		printf 'audio_hi_offset=0x%03x value=%s\n' "$audio_hi_off" "$audio_hi"
		printf 'audio_lo_offset=0x%03x value=%s\n' "$audio_lo_off" "$audio_lo"
		printf 'window_offset=0x%03x value=%s\n' "$window_off" "$window"
	} >"$out_path"
}

run_remap_trial() {
	local label=$1
	local dev=$2
	local ch=$3
	local poison_hi_off=$4
	local poison_lo_off=$5
	local out_dir=$6
	local path
	local prefix="$out_dir/$label"
	local before_log="$prefix.dmesg.before.log"
	local after_log="$prefix.dmesg.after.log"
	local delta_log="$prefix.dmesg.delta.log"
	local audio_log="$prefix.arecord.log"
	local wav="$prefix.wav"
	local analysis="$prefix.analysis.txt"
	local pid=0
	local dmesg_start=0
	local orig_hi=""
	local orig_lo=""
	local rc=0
	local wav_status=""
	local symptom="none"
	local -a remaining=()
	local old_pid=""

	path=$(bar0_path)
	dmesg_start=$(begin_dmesg_capture "$before_log")

	set +e
	arecord -D "$dev" -f "$FORMAT" -r "$RATE" -c "$CHANNELS" -d "$MIXED_SECONDS" "$wav" >"$audio_log" 2>&1 &
	pid=$!
	set -e
	BACKGROUND_PIDS+=("$pid")

	sleep 2
	orig_hi=$(bar0_read32 "$path" "$poison_hi_off")
	orig_lo=$(bar0_read32 "$path" "$poison_lo_off")
	queue_bar0_restore "$poison_hi_off" "$orig_hi"
	queue_bar0_restore "$poison_lo_off" "$orig_lo"

	capture_remap_registers "$ch" "$prefix.registers.before.txt"
	bar0_write32 "$path" "$poison_hi_off" 0x0
	bar0_write32 "$path" "$poison_lo_off" 0x0
	capture_remap_registers "$ch" "$prefix.registers.poisoned.txt"
	sleep 2
	restore_bar0_registers
	capture_remap_registers "$ch" "$prefix.registers.restored.txt"

	set +e
	wait "$pid"
	rc=$?
	set -e

	for old_pid in "${BACKGROUND_PIDS[@]}"; do
		if [ "$old_pid" != "$pid" ]; then
			remaining+=("$old_pid")
		fi
	done
	BACKGROUND_PIDS=("${remaining[@]}")

	printf 'poison_hi_offset=0x%03x\n' "$poison_hi_off" >"$prefix.mutation.txt"
	printf 'poison_lo_offset=0x%03x\n' "$poison_lo_off" >>"$prefix.mutation.txt"
	printf 'original_hi=%s\n' "$orig_hi" >>"$prefix.mutation.txt"
	printf 'original_lo=%s\n' "$orig_lo" >>"$prefix.mutation.txt"
	printf 'poison_value=0x00000000\n' >>"$prefix.mutation.txt"
	printf 'exit_code=%s\n' "$rc" >>"$audio_log"

	finish_dmesg_capture "$dmesg_start" "$after_log" "$delta_log"
	wav_status=$(analyze_wav "$wav" "$MIXED_SECONDS" "$analysis")

	if [ "$rc" -ne 0 ] || [ "$wav_status" = "missing" ] || [ "$wav_status" = "empty" ] || [ "$wav_status" = "truncated" ]; then
		symptom="capture_failed_or_truncated"
		record_result "$label" "WARN" "rc=$rc wav_status=$wav_status symptom=$symptom manual review required"
	else
		record_result "$label" "INFO" "rc=$rc wav_status=$wav_status symptom=$symptom inspect artifacts for slot dependency"
	fi
}

run_remap_validation() {
	local dev=$1
	local out_dir=$2
	local ch=0
	local path
	local passive_log="$out_dir/remap.passive.arecord.log"
	local passive_wav="$out_dir/remap.passive.wav"
	local passive_analysis="$out_dir/remap.passive.analysis.txt"
	local passive_before="$out_dir/remap.passive.dmesg.before.log"
	local passive_after="$out_dir/remap.passive.dmesg.after.log"
	local passive_delta="$out_dir/remap.passive.dmesg.delta.log"
	local dmesg_start=0
	local pid=0
	local rc=0
	local wav_status=""
	local -a remaining=()
	local old_pid=""

	if [ "$RUN_REMAP_VALIDATION" -ne 1 ]; then
		record_result "remap.summary" "SKIP" "BAR remap validation not requested"
		return 0
	fi

	if [ "$AUDIO_BACKEND" != "alsa" ]; then
		record_result "remap.summary" "SKIP" "BAR remap validation currently requires --backend alsa"
		return 0
	fi

	if [ "$EUID" -ne 0 ]; then
		record_result "remap.summary" "SKIP" "root required for BAR0 mmap access"
		return 0
	fi

	if ! have_cmd python3; then
		record_result "remap.summary" "SKIP" "python3 required for BAR0 read/write helper"
		return 0
	fi

	path=$(bar0_path)
	if [ ! -w "$path" ]; then
		record_result "remap.summary" "SKIP" "BAR0 path is not writable: $path"
		return 0
	fi

	ch=$(audio_channel_index "$dev")
	log "Running intrusive remap validation on $dev (channel $ch)"

	dmesg_start=$(begin_dmesg_capture "$passive_before")
	set +e
	arecord -D "$dev" -f "$FORMAT" -r "$RATE" -c "$CHANNELS" -d "$MIXED_SECONDS" "$passive_wav" >"$passive_log" 2>&1 &
	pid=$!
	set -e
	BACKGROUND_PIDS+=("$pid")
	sleep 2
	capture_remap_registers "$ch" "$out_dir/remap.passive.registers.txt"
	set +e
	wait "$pid"
	rc=$?
	set -e

	for old_pid in "${BACKGROUND_PIDS[@]}"; do
		if [ "$old_pid" != "$pid" ]; then
			remaining+=("$old_pid")
		fi
	done
	BACKGROUND_PIDS=("${remaining[@]}")

	printf 'exit_code=%s\n' "$rc" >>"$passive_log"
	finish_dmesg_capture "$dmesg_start" "$passive_after" "$passive_delta"
	wav_status=$(analyze_wav "$passive_wav" "$MIXED_SECONDS" "$passive_analysis")

	if [ "$rc" -ne 0 ]; then
		record_result "remap.passive" "FAIL" "rc=$rc wav_status=$wav_status"
		record_result "remap.summary" "WARN" "passive remap observation failed; discriminator trials skipped"
		return 1
	fi

	record_result "remap.passive" "INFO" "captured register snapshot + wav_status=$wav_status"
	run_remap_trial "remap.trial_a_audio_slot" "$dev" "$ch" "$((0x208 + (8 + ch) * 8))" "$((0x20c + (8 + ch) * 8))" "$out_dir"
	run_remap_trial "remap.trial_b_shared_slot" "$dev" "$ch" "$((0x208 + ch * 8))" "$((0x20c + ch * 8))" "$out_dir"
	record_result "remap.summary" "INFO" "manual interpretation required; inspect remap artifacts"
}

write_manual_followups() {
	cat >"$MANUAL_FOLLOWUPS" <<EOF
Remaining coverage from doc/audio-capture-test-plan.md that this harness cannot
fully prove on its own:

Backend note:
  audio_backend=$AUDIO_BACKEND
  PipeWire mode is useful for functional smoke testing but it does not validate
  direct ALSA period/buffer behavior. Use --backend alsa for those phases.

1. Manual listening review:
   - Listen to the smoke, long-run, and mixed A/V WAV files.
   - Confirm there is real program audio rather than silence, stale fragments,
     or obvious corruption.

2. Physical source change / signal loss:
   - Rerun with --interactive-source-change to collect an assisted capture.
   - Inspect the WAV and dmesg delta for stale DMA data, stuck callbacks, or
     broken recovery when signal is removed and restored.

3. Suspend / resume:
   - Test idle suspend/resume and active-capture suspend/resume manually.
   - Confirm audio can be started again afterwards and that no callbacks arrive
     after teardown.

4. Intrusive BAR remap validation:
   - Rerun with --run-remap-validation as root on a development machine only.
   - Inspect the passive snapshot plus both discriminator trials to determine
     whether audio depends on slot ch or slot 8+ch.

5. Module lifecycle:
   - Rerun with --run-module-reload as root if you want the script to unload
     and reload the locally built module before repeating smoke capture.

6. Long-run duration:
   - The test plan recommends 30 minutes minimum.
   - If this run used less than 1800 seconds, rerun with:
       --long-run-seconds 1800

Artifacts for this run:
  output_dir=$OUTPUT_DIR
  summary_tsv=$SUMMARY_TSV
  summary_txt=$SUMMARY_TXT
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--audio-device)
			AUDIO_DEVICE=${2:?missing value for --audio-device}
			shift 2
			;;
		--backend)
			AUDIO_BACKEND=${2:?missing value for --backend}
			shift 2
			;;
		--video-device)
			VIDEO_DEVICE=${2:?missing value for --video-device}
			shift 2
			;;
		--pci-device)
			PCI_DEVICE=${2:?missing value for --pci-device}
			shift 2
			;;
		--module-name)
			MODULE_NAME=${2:?missing value for --module-name}
			shift 2
			;;
		--module-ko)
			MODULE_KO=${2:?missing value for --module-ko}
			shift 2
			;;
		--output-dir)
			OUTPUT_DIR=${2:?missing value for --output-dir}
			shift 2
			;;
		--smoke-seconds)
			SMOKE_SECONDS=${2:?missing value for --smoke-seconds}
			shift 2
			;;
		--short-seconds)
			SHORT_SECONDS=${2:?missing value for --short-seconds}
			shift 2
			;;
		--matrix-seconds)
			MATRIX_SECONDS=${2:?missing value for --matrix-seconds}
			shift 2
			;;
		--long-run-seconds)
			LONG_RUN_SECONDS=${2:?missing value for --long-run-seconds}
			shift 2
			;;
		--mixed-seconds)
			MIXED_SECONDS=${2:?missing value for --mixed-seconds}
			shift 2
			;;
		--reopen-cycles)
			REOPEN_CYCLES=${2:?missing value for --reopen-cycles}
			shift 2
			;;
		--playback)
			PLAYBACK=1
			shift
			;;
		--skip-mixed-video)
			SKIP_MIXED_VIDEO=1
			shift
			;;
		--run-remap-validation)
			RUN_REMAP_VALIDATION=1
			shift
			;;
		--run-module-reload)
			RUN_MODULE_RELOAD=1
			shift
			;;
		--interactive-source-change)
			RUN_INTERACTIVE_SOURCE_CHANGE=1
			shift
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			printf 'Unknown option: %s\n\n' "$1" >&2
			usage >&2
			exit 1
			;;
	esac
done

ensure_output_dir
write_run_metadata
log "Audio capture test run started"

case "$AUDIO_BACKEND" in
	alsa)
		if ! have_cmd arecord; then
			log "arecord is required for --backend alsa"
			record_result "prereq.arecord" "FAIL" "arecord not installed"
			write_manual_followups
			exit 1
		fi
		;;
	pipewire)
		if ! have_cmd pw-record; then
			log "pw-record is required for --backend pipewire"
			record_result "prereq.pw-record" "FAIL" "pw-record not installed"
			write_manual_followups
			exit 1
		fi
		;;
	*)
		log "unsupported backend: $AUDIO_BACKEND"
		record_result "prereq.backend" "FAIL" "unsupported backend $AUDIO_BACKEND"
		write_manual_followups
		exit 1
		;;
esac

discover_audio_devices
maybe_autodetect_video_device
record_discovery "$OUTPUT_DIR/discovery"

if [ "${#AUDIO_DEVICES[@]}" -eq 0 ]; then
	record_result "discovery.audio_devices" "FAIL" "no HWS ALSA capture devices detected"
	write_manual_followups
	exit 1
fi

record_result "discovery.audio_devices" "INFO" "selected devices: ${AUDIO_DEVICES[*]}"
record_result "discovery.backend" "INFO" "audio backend $AUDIO_BACKEND"
if [ -n "$VIDEO_DEVICE" ]; then
	record_result "discovery.video_device" "INFO" "using video device $VIDEO_DEVICE"
else
	record_result "discovery.video_device" "WARN" "no video device selected; mixed A/V will be skipped"
fi

for idx in "${!AUDIO_DEVICES[@]}"; do
	dev=${AUDIO_DEVICES[$idx]}
	dev_tag=$(sanitize_name "$dev")
	dev_dir="$OUTPUT_DIR/$dev_tag"
	mkdir -p "$dev_dir"

	run_audio_case "smoke.capture" "$dev" "$SMOKE_SECONDS" "$dev_dir" || true
	if [ "$PLAYBACK" -eq 1 ] && [ -f "$dev_dir/smoke.capture.wav" ]; then
		play_back_capture "$dev_dir/smoke.capture.wav" "$dev_dir/smoke.playback.log"
	fi

	run_reopen_test "$dev" "$dev_dir"

	if [ "$idx" -eq 0 ]; then
		run_matrix_test "$dev" "$dev_dir"
		run_long_run_test "$dev" "$dev_dir"
		run_mixed_video_test "$dev" "$dev_dir"
		run_interactive_source_change_test "$dev" "$dev_dir"
		run_module_reload_test "$dev" "$dev_dir" || true
		run_remap_validation "$dev" "$dev_dir" || true
	else
		record_result "matrix.summary.$dev_tag" "SKIP" "deep matrix reserved for first device"
		record_result "longrun.note.$dev_tag" "SKIP" "long-run capture reserved for first device"
		run_mixed_video_test "$dev" "$dev_dir"
	fi
done

write_manual_followups
log "Audio capture test run finished"
log "Summary written to $SUMMARY_TSV"
