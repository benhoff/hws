#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: ./test_hdmi_output_loop.sh [options]

Drive a host HDMI playback sink with a generated tone while capturing the
matching HwsCapture audio/video inputs. This does not "feed audio into
/dev/video3" directly; it sends audio to the upstream GPU HDMI output that is
physically cabled into the capture card.

Defaults:
  --audio-device hw:5,3
  --video-device /dev/video3
  --playback-target auto-detect first HDMI sink
  --xrandr-output HDMI-A-1
  --duration 8
  --tone-frequency 1000

Options:
  --audio-device hw:CARD,DEV   ALSA capture device to record from.
  --video-device /dev/videoN   V4L2 capture node to sample in parallel.
  --playback-target NAME       PipeWire sink node name for pw-play --target.
  --xrandr-output NAME         Display output wired into the capture card.
  --duration N                Seconds of capture/playback. Default: 8
  --tone-frequency HZ         Tone frequency. Default: 1000
  --rate HZ                   Sample rate. Default: 48000
  --channels N                Channels. Default: 2
  --output-dir DIR            Evidence directory. Default: /tmp timestamp dir.
  --skip-video                Skip the parallel /dev/videoN ffmpeg capture.
  --list-targets              Print candidate HDMI sinks and exit.
  --help                      Show this help.
EOF
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

AUDIO_DEVICE="hw:5,3"
VIDEO_DEVICE="/dev/video3"
PLAYBACK_TARGET=""
XRANDR_OUTPUT="HDMI-A-1"
OUTPUT_DIR=""

DURATION=8
TONE_FREQUENCY=1000
RATE=48000
CHANNELS=2
SKIP_VIDEO=0
LIST_TARGETS=0

RUN_LOG=""
SUMMARY_TXT=""
LAST_BG_PID=""
declare -a BACKGROUND_PIDS=()

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

ensure_output_dir() {
	if [ -z "$OUTPUT_DIR" ]; then
		OUTPUT_DIR="/tmp/hws-hdmi-loop-$(timestamp)"
	fi

	mkdir -p "$OUTPUT_DIR"
	RUN_LOG="$OUTPUT_DIR/run.log"
	SUMMARY_TXT="$OUTPUT_DIR/summary.txt"
	: >"$RUN_LOG"
	: >"$SUMMARY_TXT"
}

record_summary() {
	local key=$1
	local value=$2
	printf '%s=%s\n' "$key" "$value" | tee -a "$SUMMARY_TXT" "$RUN_LOG" >/dev/null
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

cleanup() {
	trap - EXIT INT TERM
	kill_background_pids || true
}

trap cleanup EXIT INT TERM

candidate_hdmi_sinks() {
	if have_cmd pactl; then
		pactl list short sinks 2>/dev/null | awk '
			index(tolower($2), "hdmi") { print $2 }
		'
	fi
}

detect_playback_target() {
	local sink=""

	if [ -n "$PLAYBACK_TARGET" ]; then
		printf '%s\n' "$PLAYBACK_TARGET"
		return 0
	fi

	if have_cmd pactl; then
		sink=$(pactl list short sinks 2>/dev/null | awk '
			$2 ~ /pci-0000_65_00\.1\.hdmi-stereo/ { print $2; exit }
			index(tolower($2), "hdmi") { print $2; exit }
		')
	fi

	printf '%s\n' "$sink"
}

audio_channel_index() {
	local dev=$1
	local idx=${dev##*,}
	printf '%s\n' "$((10#$idx))"
}

begin_kernel_capture() {
	date '+%Y-%m-%d %H:%M:%S'
}

finish_kernel_capture() {
	local since=$1
	local log_path=$2

	if have_cmd journalctl; then
		journalctl --no-pager -k --since "$since" >"$log_path" 2>&1 || true
	else
		printf 'journalctl unavailable\n' >"$log_path"
	fi
}

generate_tone() {
	local tone_path=$1
	local tone_duration=$2

	ffmpeg -nostdin -hide_banner -loglevel error -y \
		-f lavfi -i "sine=frequency=${TONE_FREQUENCY}:sample_rate=${RATE}:duration=${tone_duration}" \
		-af "volume=0.8" \
		-ac "$CHANNELS" \
		-c:a pcm_s16le "$tone_path"
}

run_video_capture_bg() {
	local duration=$1
	local log_path=$2

	(
		ffmpeg -nostdin -hide_banner -loglevel info \
			-f v4l2 -i "$VIDEO_DEVICE" -t "$duration" -f null -
	) >"$log_path" 2>&1 &

	LAST_BG_PID=$!
	BACKGROUND_PIDS+=("$LAST_BG_PID")
}

run_playback_bg() {
	local target=$1
	local tone_path=$2
	local log_path=$3

	(
		pw-play --target "$target" "$tone_path"
	) >"$log_path" 2>&1 &

	LAST_BG_PID=$!
	BACKGROUND_PIDS+=("$LAST_BG_PID")
}

run_arecord_capture() {
	local wav_path=$1
	local log_path=$2
	local rc=0

	set +e
	arecord -D "$AUDIO_DEVICE" -f S16_LE -r "$RATE" -c "$CHANNELS" \
		-d "$DURATION" "$wav_path" >"$log_path" 2>&1
	rc=$?
	set -e
	printf 'exit_code=%s\n' "$rc" >>"$log_path"
	return "$rc"
}

analyze_wav() {
	local wav_path=$1
	local analysis_path=$2
	local status="missing"
	local size=0
	local expected_min=0
	local mean_volume=""
	local max_volume=""

	if [ -f "$wav_path" ]; then
		size=$(stat -c %s "$wav_path" 2>/dev/null || printf '0')
	fi
	expected_min=$((44 + (DURATION * RATE * CHANNELS * 2 * 3 / 4)))

	{
		printf 'path=%s\n' "$wav_path"
		printf 'size_bytes=%s\n' "$size"
		printf 'expected_min_bytes=%s\n' "$expected_min"
	} >"$analysis_path"

	if [ ! -f "$wav_path" ] || [ "$size" -eq 0 ]; then
		status="missing"
	elif [ "$size" -le 44 ]; then
		status="empty"
	elif [ "$size" -lt "$expected_min" ]; then
		status="truncated"
	else
		status="ok"
	fi

	if have_cmd ffmpeg && [ -f "$wav_path" ]; then
		local volume_log="$analysis_path.volumedetect.log"
		ffmpeg -nostdin -hide_banner -i "$wav_path" -af volumedetect -f null - \
			>/dev/null 2>"$volume_log" || true
		mean_volume=$(awk -F': ' '/mean_volume/ {print $2}' "$volume_log" | tail -n 1)
		max_volume=$(awk -F': ' '/max_volume/ {print $2}' "$volume_log" | tail -n 1)
		printf 'mean_volume=%s\n' "${mean_volume:-unknown}" >>"$analysis_path"
		printf 'max_volume=%s\n' "${max_volume:-unknown}" >>"$analysis_path"
		if [ "$status" = "ok" ] && [ "${max_volume:-}" = "-inf dB" ]; then
			status="silent"
		fi
	fi

	printf 'status=%s\n' "$status" >>"$analysis_path"
	printf '%s\n' "$status"
}

trace_channel_summary() {
	local kernel_log=$1
	local ch=$2
	local trace_log=$3
	local seed_count=0
	local start_count=0
	local irq_count=0
	local deliver_count=0
	local zero_base=0
	local trace_available=0

	rg "audio-trace:.*ch${ch}\\b" "$kernel_log" >"$trace_log" || true

	if [ -s "$trace_log" ]; then
		trace_available=1
	fi
	seed_count=$(grep -c 'audio-trace:seed' "$trace_log" 2>/dev/null || true)
	start_count=$(grep -c 'audio-trace:start' "$trace_log" 2>/dev/null || true)
	irq_count=$(grep -c 'audio-trace:irq ' "$trace_log" 2>/dev/null || true)
	deliver_count=$(grep -c 'audio-trace:deliver' "$trace_log" 2>/dev/null || true)
	if rg -q 'base=00000000' "$trace_log"; then
		zero_base=1
	fi

	{
		printf 'trace_available=%s\n' "$trace_available"
		printf 'seed_count=%s\n' "$seed_count"
		printf 'start_count=%s\n' "$start_count"
		printf 'irq_count=%s\n' "$irq_count"
		printf 'deliver_count=%s\n' "$deliver_count"
		printf 'zero_base=%s\n' "$zero_base"
	}
}

snapshot_environment() {
	if have_cmd pactl; then
		pactl list short sinks >"$OUTPUT_DIR/pactl-sinks.txt" 2>&1 || true
	fi
	if have_cmd xrandr; then
		xrandr --query >"$OUTPUT_DIR/xrandr.txt" 2>&1 || true
	fi
	if have_cmd v4l2-ctl; then
		v4l2-ctl --list-devices >"$OUTPUT_DIR/v4l2-list-devices.txt" 2>&1 || true
	fi
	cat /proc/asound/pcm >"$OUTPUT_DIR/proc-asound-pcm.txt" 2>/dev/null || true
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--audio-device)
				AUDIO_DEVICE=$2
				shift 2
				;;
			--video-device)
				VIDEO_DEVICE=$2
				shift 2
				;;
			--playback-target)
				PLAYBACK_TARGET=$2
				shift 2
				;;
			--xrandr-output)
				XRANDR_OUTPUT=$2
				shift 2
				;;
			--duration)
				DURATION=$2
				shift 2
				;;
			--tone-frequency)
				TONE_FREQUENCY=$2
				shift 2
				;;
			--rate)
				RATE=$2
				shift 2
				;;
			--channels)
				CHANNELS=$2
				shift 2
				;;
			--output-dir)
				OUTPUT_DIR=$2
				shift 2
				;;
			--skip-video)
				SKIP_VIDEO=1
				shift
				;;
			--list-targets)
				LIST_TARGETS=1
				shift
				;;
			--help|-h)
				usage
				exit 0
				;;
			*)
				printf 'Unknown option: %s\n' "$1" >&2
				usage >&2
				exit 1
				;;
		esac
	done
}

main() {
	local playback_target=""
	local tone_path=""
	local playback_log=""
	local capture_log=""
	local capture_wav=""
	local capture_analysis=""
	local kernel_log=""
	local kernel_since=""
	local video_log=""
	local trace_log=""
	local trace_summary=""
	local capture_rc=0
	local playback_rc=0
	local playback_pid=""
	local video_pid=""
	local tone_duration=0
	local wav_status=""
	local ch=0

	parse_args "$@"

	if [ "$LIST_TARGETS" -eq 1 ]; then
		candidate_hdmi_sinks
		exit 0
	fi

	for cmd in ffmpeg pw-play arecord journalctl; do
		if ! have_cmd "$cmd"; then
			printf 'missing required command: %s\n' "$cmd" >&2
			exit 1
		fi
	done

	if [ "$SKIP_VIDEO" -ne 1 ] && [ ! -e "$VIDEO_DEVICE" ]; then
		printf 'video device not found: %s\n' "$VIDEO_DEVICE" >&2
		exit 1
	fi

	playback_target=$(detect_playback_target)
	if [ -z "$playback_target" ]; then
		printf 'could not auto-detect an HDMI playback target; use --playback-target\n' >&2
		exit 1
	fi

	ensure_output_dir
	snapshot_environment

	record_summary "audio_device" "$AUDIO_DEVICE"
	record_summary "video_device" "$VIDEO_DEVICE"
	record_summary "playback_target" "$playback_target"
	record_summary "xrandr_output" "$XRANDR_OUTPUT"
	record_summary "duration_seconds" "$DURATION"
	record_summary "tone_frequency_hz" "$TONE_FREQUENCY"

	tone_duration=$((DURATION + 2))
	tone_path="$OUTPUT_DIR/tone.wav"
	playback_log="$OUTPUT_DIR/playback.log"
	capture_log="$OUTPUT_DIR/capture.arecord.log"
	capture_wav="$OUTPUT_DIR/capture.wav"
	capture_analysis="$OUTPUT_DIR/capture.analysis.txt"
	kernel_log="$OUTPUT_DIR/kernel.log"
	video_log="$OUTPUT_DIR/video.ffmpeg.log"
	trace_log="$OUTPUT_DIR/audio-trace.log"
	trace_summary="$OUTPUT_DIR/audio-trace-summary.txt"
	ch=$(audio_channel_index "$AUDIO_DEVICE")

	log "Generating ${tone_duration}s tone at ${TONE_FREQUENCY} Hz"
	generate_tone "$tone_path" "$tone_duration"

	kernel_since=$(begin_kernel_capture)

	if [ "$SKIP_VIDEO" -ne 1 ]; then
		log "Starting parallel video capture on $VIDEO_DEVICE"
		run_video_capture_bg "$tone_duration" "$video_log"
		video_pid=$LAST_BG_PID
	fi

	log "Starting playback on $playback_target"
	run_playback_bg "$playback_target" "$tone_path" "$playback_log"
	playback_pid=$LAST_BG_PID

	sleep 1

	log "Capturing $AUDIO_DEVICE for ${DURATION}s"
	if run_arecord_capture "$capture_wav" "$capture_log"; then
		capture_rc=0
	else
		capture_rc=$?
	fi

	set +e
	wait "$playback_pid"
	playback_rc=$?
	set -e

	if [ -n "$video_pid" ]; then
		set +e
		wait "$video_pid"
		set -e
	fi

	finish_kernel_capture "$kernel_since" "$kernel_log"
	wav_status=$(analyze_wav "$capture_wav" "$capture_analysis")
	trace_channel_summary "$kernel_log" "$ch" "$trace_log" >"$trace_summary"

	record_summary "capture_rc" "$capture_rc"
	record_summary "playback_rc" "$playback_rc"
	record_summary "wav_status" "$wav_status"
	cat "$trace_summary" >>"$SUMMARY_TXT"

	if [ "$playback_rc" -ne 0 ]; then
		log "Playback failed; inspect $playback_log"
	elif [ "$capture_rc" -eq 0 ] && [ "$wav_status" != "missing" ] && \
		[ "$wav_status" != "empty" ] && [ "$wav_status" != "truncated" ]; then
		log "Capture produced audio evidence: wav_status=$wav_status"
	elif rg -q '^irq_count=[1-9]' "$trace_summary" && rg -q '^deliver_count=[1-9]' "$trace_summary"; then
		log "Driver delivered packets, but the ALSA capture still ended poorly; inspect $capture_log and $trace_log"
	else
		log "No successful capture. Inspect $capture_log and $trace_log"
	fi

	log "Evidence written to $OUTPUT_DIR"
}

main "$@"
