#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: ./hws_mixed_audio_video_test.sh [options]

Run a focused mixed audio/video capture test:
  - start V4L2 MMAP streaming on a video node
  - capture ALSA audio from the matching HWS PCM device while video is active
  - collect audio/video logs, WAV analysis, and kernel log deltas

Options:
  --audio-device DEV     ALSA capture device. Default: hw:4,3
  --video-device DEV     V4L2 video device. Default: /dev/video3
  --duration SEC         Audio capture duration. Default: 60
  --video-extra SEC      Keep video running this much longer than audio. Default: 4
  --warmup SEC           Delay after video starts before audio capture. Default: 2
  --video-buffers N      V4L2 mmap buffer count. Default: 8
  --rate HZ              Audio sample rate. Default: 48000
  --format FORMAT        ALSA sample format. Default: S16_LE
  --channels N           Audio channel count. Default: 2
  --output-dir DIR       Evidence directory. Default: /tmp timestamp dir
  --allow-silence        Do not fail if volumedetect reports digital silence.
  --help                 Show this help.

Example:
  ./hws_mixed_audio_video_test.sh --audio-device hw:4,3 --video-device /dev/video3 --duration 300
EOF
}

AUDIO_DEVICE="hw:4,3"
VIDEO_DEVICE="/dev/video3"
OUTPUT_DIR=""
DURATION=60
VIDEO_EXTRA=4
WARMUP=2
VIDEO_BUFFERS=8
RATE=48000
FORMAT="S16_LE"
CHANNELS=2
ALLOW_SILENCE=0

RUN_LOG=""
SUMMARY=""
VIDEO_PID=""
VIDEO_STARTED_AT=0

timestamp() {
	date '+%Y%m%d-%H%M%S'
}

log() {
	printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$RUN_LOG"
}

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

require_cmd() {
	local cmd=$1

	if ! have_cmd "$cmd"; then
		printf 'missing required command: %s\n' "$cmd" >&2
		exit 127
	fi
}

sample_bytes() {
	case "$FORMAT" in
	S8|U8)
		printf '1\n'
		;;
	S16_*|U16_*)
		printf '2\n'
		;;
	S24_*|U24_*)
		printf '3\n'
		;;
	S32_*|U32_*|FLOAT_*)
		printf '4\n'
		;;
	*)
		printf '2\n'
		;;
	esac
}

record_summary() {
	local key=$1
	local value=$2

	printf '%s=%s\n' "$key" "$value" >>"$SUMMARY"
}

cleanup() {
	local rc=$?

	trap - EXIT INT TERM
	stop_video_stream >/dev/null 2>&1 || true
	exit "$rc"
}

trap cleanup EXIT INT TERM

stop_video_stream() {
	local rc=0

	if [ -z "$VIDEO_PID" ]; then
		return 0
	fi

	if kill -0 "$VIDEO_PID" >/dev/null 2>&1; then
		if have_cmd pkill; then
			pkill -INT -P "$VIDEO_PID" >/dev/null 2>&1 || true
		fi
		kill -INT "$VIDEO_PID" >/dev/null 2>&1 || true
		sleep 1
		if kill -0 "$VIDEO_PID" >/dev/null 2>&1; then
			if have_cmd pkill; then
				pkill -TERM -P "$VIDEO_PID" >/dev/null 2>&1 || true
			fi
			kill -TERM "$VIDEO_PID" >/dev/null 2>&1 || true
		fi
	fi

	if wait "$VIDEO_PID"; then
		rc=0
	else
		rc=$?
	fi
	VIDEO_PID=""
	return "$rc"
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

snapshot_context() {
	local dir=$1

	mkdir -p "$dir"
	{
		date
		uname -a
	} >"$dir/system.txt" 2>&1 || true

	arecord -l >"$dir/arecord-list.txt" 2>&1 || true
	arecord -L >"$dir/arecord-pcms.txt" 2>&1 || true
	v4l2-ctl --list-devices >"$dir/v4l2-list-devices.txt" 2>&1 || true
	v4l2-ctl -d "$VIDEO_DEVICE" --all >"$dir/video-all.txt" 2>&1 || true
	cat /proc/asound/cards >"$dir/proc-asound-cards.txt" 2>/dev/null || true
	cat /proc/asound/pcm >"$dir/proc-asound-pcm.txt" 2>/dev/null || true
}

analyze_wav() {
	local wav=$1
	local analysis=$2
	local bytes_per_sample
	local expected_min
	local size=0
	local sha=""
	local status="missing"

	bytes_per_sample=$(sample_bytes)
	expected_min=$((44 + DURATION * RATE * CHANNELS * bytes_per_sample * 3 / 4))

	if [ -f "$wav" ]; then
		size=$(stat -c %s "$wav" 2>/dev/null || printf '0')
		sha=$(sha256sum "$wav" | awk '{ print $1 }')
	fi

	{
		printf 'path=%s\n' "$wav"
		printf 'size_bytes=%s\n' "$size"
		printf 'expected_min_bytes=%s\n' "$expected_min"
		printf 'sha256=%s\n' "$sha"
	} >"$analysis"

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
		local volume_log="$analysis.volumedetect.log"
		local mean_volume=""
		local max_volume=""
		local ffmpeg_rc=0

		set +e
		ffmpeg -nostdin -hide_banner -i "$wav" -af volumedetect -f null - \
			>/dev/null 2>"$volume_log"
		ffmpeg_rc=$?
		set -e

		mean_volume=$(awk -F': ' '/mean_volume/ { print $2 }' "$volume_log" | tail -n 1)
		max_volume=$(awk -F': ' '/max_volume/ { print $2 }' "$volume_log" | tail -n 1)

		{
			printf 'ffmpeg_rc=%s\n' "$ffmpeg_rc"
			printf 'mean_volume=%s\n' "${mean_volume:-unknown}"
			printf 'max_volume=%s\n' "${max_volume:-unknown}"
		} >>"$analysis"

		if [ "$status" = "ok" ] && [ "${max_volume:-}" = "-inf dB" ]; then
			status="silent"
		fi
	fi

	printf 'status=%s\n' "$status" >>"$analysis"
	printf '%s\n' "$status"
}

kernel_delta_has_issues() {
	local delta=$1

	grep -Eiq \
		'(BUG:|WARNING:|WARN_ON|Oops|Call Trace|DMA fault|IOMMU|xrun|overrun|underrun|HwsCapture.*(error|failed|timeout|stalled))' \
		"$delta"
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--audio-device)
			AUDIO_DEVICE=${2:?missing value for --audio-device}
			shift 2
			;;
		--video-device)
			VIDEO_DEVICE=${2:?missing value for --video-device}
			shift 2
			;;
		--duration)
			DURATION=${2:?missing value for --duration}
			shift 2
			;;
		--video-extra)
			VIDEO_EXTRA=${2:?missing value for --video-extra}
			shift 2
			;;
		--warmup)
			WARMUP=${2:?missing value for --warmup}
			shift 2
			;;
		--video-buffers)
			VIDEO_BUFFERS=${2:?missing value for --video-buffers}
			shift 2
			;;
		--rate)
			RATE=${2:?missing value for --rate}
			shift 2
			;;
		--format)
			FORMAT=${2:?missing value for --format}
			shift 2
			;;
		--channels)
			CHANNELS=${2:?missing value for --channels}
			shift 2
			;;
		--output-dir)
			OUTPUT_DIR=${2:?missing value for --output-dir}
			shift 2
			;;
		--allow-silence)
			ALLOW_SILENCE=1
			shift
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			printf 'unknown option: %s\n' "$1" >&2
			usage >&2
			exit 2
			;;
		esac
	done
}

main() {
	local video_duration
	local video_log
	local audio_log
	local audio_wav
	local audio_analysis
	local before_log
	local after_log
	local delta_log
	local dmesg_start
	local audio_rc=0
	local audio_started_at=0
	local audio_elapsed=0
	local video_rc=0
	local video_ok=0
	local wav_status
	local kernel_status="ok"
	local result="PASS"

	parse_args "$@"

	require_cmd arecord
	require_cmd awk
	require_cmd date
	require_cmd grep
	require_cmd mkdir
	require_cmd sha256sum
	require_cmd stat
	require_cmd tail
	require_cmd tee
	require_cmd timeout
	require_cmd v4l2-ctl

	if [ ! -e "$VIDEO_DEVICE" ]; then
		printf 'video device not found: %s\n' "$VIDEO_DEVICE" >&2
		exit 1
	fi

	if [ -z "$OUTPUT_DIR" ]; then
		OUTPUT_DIR="/tmp/hws-mixed-av-$(timestamp)"
	fi
	mkdir -p "$OUTPUT_DIR"
	RUN_LOG="$OUTPUT_DIR/run.log"
	SUMMARY="$OUTPUT_DIR/summary.txt"
	: >"$RUN_LOG"
	: >"$SUMMARY"

	video_duration=$((DURATION + WARMUP + VIDEO_EXTRA))
	video_log="$OUTPUT_DIR/video.v4l2-ctl.log"
	audio_log="$OUTPUT_DIR/audio.arecord.log"
	audio_wav="$OUTPUT_DIR/audio.wav"
	audio_analysis="$OUTPUT_DIR/audio.analysis.txt"
	before_log="$OUTPUT_DIR/dmesg.before.log"
	after_log="$OUTPUT_DIR/dmesg.after.log"
	delta_log="$OUTPUT_DIR/dmesg.delta.log"

	log "output_dir=$OUTPUT_DIR"
	log "audio_device=$AUDIO_DEVICE"
	log "video_device=$VIDEO_DEVICE"
	log "duration=${DURATION}s warmup=${WARMUP}s video_duration=${video_duration}s"

	snapshot_context "$OUTPUT_DIR/context"

	record_summary "audio_device" "$AUDIO_DEVICE"
	record_summary "video_device" "$VIDEO_DEVICE"
	record_summary "duration_seconds" "$DURATION"
	record_summary "video_duration_seconds" "$video_duration"
	record_summary "rate" "$RATE"
	record_summary "format" "$FORMAT"
	record_summary "channels" "$CHANNELS"

	dmesg_start=$(begin_dmesg_capture "$before_log")

	log "starting video stream"
	set +e
	timeout --signal=INT --kill-after=5s "${video_duration}s" \
		v4l2-ctl -d "$VIDEO_DEVICE" \
			--stream-mmap="$VIDEO_BUFFERS" \
			--stream-to=/dev/null \
			>"$video_log" 2>&1 &
	VIDEO_PID=$!
	VIDEO_STARTED_AT=$(date +%s)
	set -e

	sleep "$WARMUP"

	log "starting audio capture"
	audio_started_at=$(date +%s)
	set +e
	arecord --fatal-errors -D "$AUDIO_DEVICE" -f "$FORMAT" -r "$RATE" \
		-c "$CHANNELS" -d "$DURATION" "$audio_wav" >"$audio_log" 2>&1
	audio_rc=$?
	set -e
	audio_elapsed=$(($(date +%s) - audio_started_at))
	printf 'exit_code=%s\n' "$audio_rc" >>"$audio_log"

	if [ "$audio_rc" -ne 0 ]; then
		log "audio capture failed after ${audio_elapsed}s; stopping video stream"
		set +e
		stop_video_stream
		video_rc=$?
		set -e
	else
		log "waiting for video stream"
		set +e
		wait "$VIDEO_PID"
		video_rc=$?
		set -e
		VIDEO_PID=""
	fi
	printf 'exit_code=%s\n' "$video_rc" >>"$video_log"

	finish_dmesg_capture "$dmesg_start" "$after_log" "$delta_log"

	case "$video_rc" in
	0|124|130)
		video_ok=1
		;;
	*)
		video_ok=0
		;;
	esac

	wav_status=$(analyze_wav "$audio_wav" "$audio_analysis")
	if kernel_delta_has_issues "$delta_log"; then
		kernel_status="issues"
	fi

	record_summary "audio_rc" "$audio_rc"
	record_summary "audio_elapsed_seconds" "$audio_elapsed"
	record_summary "video_rc" "$video_rc"
	record_summary "video_ok" "$video_ok"
	record_summary "video_elapsed_seconds" "$(($(date +%s) - VIDEO_STARTED_AT))"
	record_summary "wav_status" "$wav_status"
	record_summary "kernel_status" "$kernel_status"

	if [ "$audio_rc" -ne 0 ]; then
		result="FAIL"
	elif [ "$video_ok" -ne 1 ]; then
		result="FAIL"
	elif [ "$wav_status" = "missing" ] || [ "$wav_status" = "empty" ] ||
		[ "$wav_status" = "truncated" ]; then
		result="FAIL"
	elif [ "$wav_status" = "silent" ] && [ "$ALLOW_SILENCE" -ne 1 ]; then
		result="FAIL"
	elif [ "$kernel_status" != "ok" ]; then
		result="FAIL"
	fi

	record_summary "result" "$result"

	log "result=$result audio_rc=$audio_rc video_rc=$video_rc wav_status=$wav_status kernel_status=$kernel_status"
	log "summary=$SUMMARY"

	if [ "$result" != "PASS" ]; then
		exit 1
	fi
}

main "$@"
