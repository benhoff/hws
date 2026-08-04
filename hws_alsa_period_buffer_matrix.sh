#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./hws_audio_lib.sh
. "$SCRIPT_DIR/hws_audio_lib.sh"

usage() {
	cat <<'EOF'
Usage: ./hws_alsa_period_buffer_matrix.sh [options]

Run a focused ALSA period/buffer matrix against one HWS HDMI audio capture
device. Period and buffer sizes are ALSA frame counts.

Options:
  --audio-device DEV       HWS ALSA capture device. Default: auto:3.
                           Accepts hw:C,D, plughw:C,D, auto, or auto:D.
  --target NAME            PipeWire/Pulse playback sink. Default: auto NVIDIA HDMI.
  --card NAME              PipeWire/Pulse card for --profile. Default: auto NVIDIA.
  --profile NAME           Set NVIDIA card profile before target detection.
  --cases LIST             Matrix cases as period:buffer pairs.
                           Default: 256:1024,256:4096,1024:4096,4096:16384.
  --duration N             Seconds per capture. Default: 15.
  --rate HZ                Capture rate. Default: 48000.
  --format FORMAT          ALSA sample format. Default: S16_LE.
  --channels N             Channel count. Default: 2.
  --tone-frequency HZ      Generated playback tone frequency. Default: 1000.
  --output-dir DIR         Evidence directory. Default: /tmp timestamp dir.
  --allow-silence          Do not fail if captured samples are all digital silence.
  --no-playback            Do not generate an HDMI playback tone.
  --no-kernel-log          Skip per-case kernel warning/error collection.
  --help                   Show this help.

Examples:
  ./hws_alsa_period_buffer_matrix.sh --audio-device hw:4,3
  ./hws_alsa_period_buffer_matrix.sh --audio-device hw:4,3 --cases 128:512,512:2048
  ./hws_alsa_period_buffer_matrix.sh --no-playback --allow-silence
EOF
}

AUDIO_DEVICE="auto:3"
TARGET="auto"
CARD="auto"
PROFILE=""
CASES="256:1024 256:4096 1024:4096 4096:16384"
OUTPUT_DIR=""

DURATION=15
RATE=48000
FORMAT="S16_LE"
CHANNELS=2
TONE_FREQUENCY=1000
SIZE_TOLERANCE_PERCENT=5
HW_PARAMS_TIMEOUT=5
CAPTURE_TIMEOUT_PADDING=10

ALLOW_SILENCE=0
NO_PLAYBACK=0
COLLECT_KERNEL_LOG=1

RUN_LOG=""
SUMMARY_TSV=""
PLAYBACK_TONE=""
PLAYBACK_PID=""
FAILURES=0
PASSES=0

log() {
	printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$RUN_LOG"
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

safe_name() {
	printf '%s' "$1" | tr -c 'A-Za-z0-9_.=-' '_'
}

normalize_list() {
	printf '%s\n' "$1" | tr ',;' '  ' | awk '
		{
			for (i = 1; i <= NF; i++)
				if ($i != "")
					print $i
		}
	'
}

format_bits() {
	case "$1" in
	S8|U8) printf '8\n' ;;
	S16_LE|U16_LE|S16_BE|U16_BE) printf '16\n' ;;
	S24_LE|U24_LE|S24_BE|U24_BE|S24_3LE|S24_3BE) printf '24\n' ;;
	S32_LE|U32_LE|S32_BE|U32_BE|FLOAT_LE|FLOAT_BE) printf '32\n' ;;
	S64_LE|U64_LE|S64_BE|U64_BE|FLOAT64_LE|FLOAT64_BE) printf '64\n' ;;
	*) printf '16\n' ;;
	esac
}

format_codec() {
	case "$1" in
	S16_LE) printf 'pcm_s16le\n' ;;
	S16_BE) printf 'pcm_s16be\n' ;;
	S24_LE|S24_3LE) printf 'pcm_s24le\n' ;;
	S24_BE|S24_3BE) printf 'pcm_s24be\n' ;;
	S32_LE) printf 'pcm_s32le\n' ;;
	S32_BE) printf 'pcm_s32be\n' ;;
	*) printf '%s\n' "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" ;;
	esac
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--audio-device)
			AUDIO_DEVICE=$2
			shift 2
			;;
		--target)
			TARGET=$2
			shift 2
			;;
		--card)
			CARD=$2
			shift 2
			;;
		--profile)
			PROFILE=$2
			shift 2
			;;
		--cases)
			CASES=$(normalize_list "$2" | tr '\n' ' ')
			shift 2
			;;
		--duration)
			DURATION=$2
			shift 2
			;;
		--rate)
			RATE=$2
			shift 2
			;;
		--format)
			FORMAT=$2
			shift 2
			;;
		--channels)
			CHANNELS=$2
			shift 2
			;;
		--tone-frequency)
			TONE_FREQUENCY=$2
			shift 2
			;;
		--output-dir)
			OUTPUT_DIR=$2
			shift 2
			;;
		--allow-silence)
			ALLOW_SILENCE=1
			shift
			;;
		--no-playback)
			NO_PLAYBACK=1
			shift
			;;
		--no-kernel-log)
			COLLECT_KERNEL_LOG=0
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

validate_number() {
	local name=$1
	local value=$2

	[[ "$value" =~ ^[0-9]+$ ]] || die "$name must be an integer: $value"
	[ "$value" -gt 0 ] || die "$name must be greater than zero"
}

validate_cases() {
	local pair
	local period
	local buffer
	local valid=""

	for pair in $CASES; do
		[[ "$pair" =~ ^[0-9]+:[0-9]+$ ]] || die "invalid case '$pair'; expected period:buffer"
		period=${pair%%:*}
		buffer=${pair##*:}
		validate_number "period size" "$period"
		validate_number "buffer size" "$buffer"
		[ "$buffer" -gt "$period" ] || die "buffer must be larger than period in case '$pair'"
		valid="${valid:+$valid }$pair"
	done

	[ -n "$valid" ] || die "no matrix cases configured"
	CASES=$valid
}

resolve_audio_device() {
	local requested=$1
	local preferred
	local resolved

	case "$requested" in
	auto)
		resolved=$(hws_detect_hws_audio_device "" || true)
		;;
	auto:*)
		preferred=${requested#auto:}
		resolved=$(hws_detect_hws_audio_device "$preferred" || true)
		;;
	*)
		resolved=$requested
		;;
	esac

	[ -n "$resolved" ] || die "could not auto-detect HWS ALSA capture device for '$requested'"
	if ! hws_alsa_capture_device_exists "$resolved"; then
		die "ALSA capture device not found in /proc/asound/pcm: $resolved"
	fi
	printf '%s\n' "$resolved"
}

init_output() {
	if [ -z "$OUTPUT_DIR" ]; then
		OUTPUT_DIR="/tmp/hws-alsa-period-buffer-matrix-$(hws_timestamp)"
	fi

	mkdir -p "$OUTPUT_DIR/tests" "$OUTPUT_DIR/context"
	RUN_LOG="$OUTPUT_DIR/run.log"
	SUMMARY_TSV="$OUTPUT_DIR/summary.tsv"
	PLAYBACK_TONE="$OUTPUT_DIR/playback-tone.wav"
	: >"$RUN_LOG"
	printf 'case\tstatus\tperiod_size\tbuffer_size\tactual_period_size\tactual_buffer_size\tcapture_rc\theader_ok\tsize_ok\tnonzero_ok\trate_ok\tchannels_ok\tformat_ok\txrun_ok\tperiod_ok\tbuffer_ok\tkernel_warning_ok\tkernel_error_ok\tdetail\tartifact_dir\n' >"$SUMMARY_TSV"
}

write_context() {
	local hw_params_rc

	{
		printf 'audio_device=%s\n' "$AUDIO_DEVICE"
		printf 'target=%s\n' "$TARGET"
		printf 'cases=%s\n' "$CASES"
		printf 'duration=%s\n' "$DURATION"
		printf 'rate=%s\n' "$RATE"
		printf 'format=%s\n' "$FORMAT"
		printf 'channels=%s\n' "$CHANNELS"
		printf 'allow_silence=%s\n' "$ALLOW_SILENCE"
		printf 'playback_enabled=%s\n' "$((1 - NO_PLAYBACK))"
		printf 'kernel_log_enabled=%s\n' "$COLLECT_KERNEL_LOG"
		if git -C "$SCRIPT_DIR" rev-parse --short HEAD >/dev/null 2>&1; then
			printf 'git_head=%s\n' "$(git -C "$SCRIPT_DIR" rev-parse --short HEAD)"
			printf 'git_branch=%s\n' "$(git -C "$SCRIPT_DIR" branch --show-current 2>/dev/null || true)"
		fi
	} >"$OUTPUT_DIR/context/test-config.txt"

	hws_write_audio_context "$OUTPUT_DIR/context/audio" || true

	if timeout --kill-after=2s "${HW_PARAMS_TIMEOUT}s" \
		arecord --fatal-errors -D "$AUDIO_DEVICE" --dump-hw-params \
		-f "$FORMAT" -r "$RATE" -c "$CHANNELS" \
		-d 1 -t raw /dev/null >"$OUTPUT_DIR/context/hw-params.txt" 2>&1; then
		hw_params_rc=0
	else
		hw_params_rc=$?
	fi
	if [ "$hw_params_rc" -eq 124 ]; then
		printf 'timeout_after_s=%s\n' "$HW_PARAMS_TIMEOUT" >>"$OUTPUT_DIR/context/hw-params.txt"
	fi
	printf 'exit_code=%s\n' "$hw_params_rc" >>"$OUTPUT_DIR/context/hw-params.txt"
}

ensure_playback_tone() {
	if [ -f "$PLAYBACK_TONE" ]; then
		return 0
	fi

	ffmpeg -nostdin -hide_banner -loglevel error -y \
		-f lavfi -i "sine=frequency=${TONE_FREQUENCY}:sample_rate=${RATE}:duration=5" \
		-af "volume=0.8" \
		-ac "$CHANNELS" \
		-c:a pcm_s16le "$PLAYBACK_TONE"
}

start_playback_loop() {
	local playback_log="$OUTPUT_DIR/playback.log"

	if [ "$NO_PLAYBACK" -eq 1 ]; then
		log "playback disabled"
		return 0
	fi

	ensure_playback_tone
	log "starting playback loop target=$TARGET"
	(
		while :; do
			pw-play --target "$TARGET" "$PLAYBACK_TONE" || exit $?
		done
	) >"$playback_log" 2>&1 &
	PLAYBACK_PID=$!
	sleep 0.5
}

cleanup() {
	trap - EXIT INT TERM
	if [ -n "$PLAYBACK_PID" ] && kill -0 "$PLAYBACK_PID" >/dev/null 2>&1; then
		kill "$PLAYBACK_PID" >/dev/null 2>&1 || true
		wait "$PLAYBACK_PID" >/dev/null 2>&1 || true
	fi
}

capture_kernel_log() {
	local since=$1
	local priority=$2
	local out=$3

	if [ "$COLLECT_KERNEL_LOG" -ne 1 ]; then
		printf 'kernel log collection disabled\n' >"$out"
		return 77
	fi
	if ! hws_have_cmd journalctl; then
		printf 'journalctl unavailable\n' >"$out"
		return 77
	fi

	if ! journalctl --no-pager -k -p "$priority" --since "$since" >"$out" 2>&1; then
		return 77
	fi
	if grep -qx -- '-- No entries --' "$out" 2>/dev/null; then
		: >"$out"
	fi
	return 0
}

extract_arecord_setup_value() {
	local log_path=$1
	local key=$2

	awk -v key="$key" '
		$0 ~ "^[[:space:]]*" key "[[:space:]]*:" {
			line = $0
			sub(".*:[[:space:]]*", "", line)
			sub("[[:space:]].*", "", line)
			print line
			exit
		}
	' "$log_path"
}

run_arecord_case() {
	local period=$1
	local buffer=$2
	local wav_path=$3
	local log_path=$4
	local capture_timeout=$((DURATION + CAPTURE_TIMEOUT_PADDING))
	local rc

	if timeout --kill-after=2s "${capture_timeout}s" \
		arecord --fatal-errors -v -D "$AUDIO_DEVICE" -f "$FORMAT" -r "$RATE" -c "$CHANNELS" \
		--period-size="$period" --buffer-size="$buffer" \
		-d "$DURATION" "$wav_path" >"$log_path" 2>&1; then
		rc=0
	else
		rc=$?
	fi
	if [ "$rc" -eq 124 ]; then
		printf 'timeout_after_s=%s\n' "$capture_timeout" >>"$log_path"
	fi
	printf 'exit_code=%s\n' "$rc" >>"$log_path"
	return "$rc"
}

run_hw_params_case() {
	local period=$1
	local buffer=$2
	local out=$3
	local rc

	if timeout --kill-after=2s "${HW_PARAMS_TIMEOUT}s" \
		arecord --fatal-errors -D "$AUDIO_DEVICE" --dump-hw-params \
		-f "$FORMAT" -r "$RATE" -c "$CHANNELS" \
		--period-size="$period" --buffer-size="$buffer" \
		-d 1 -t raw /dev/null >"$out" 2>&1; then
		rc=0
	else
		rc=$?
	fi
	if [ "$rc" -eq 124 ]; then
		printf 'timeout_after_s=%s\n' "$HW_PARAMS_TIMEOUT" >>"$out"
	fi
	printf 'exit_code=%s\n' "$rc" >>"$out"
	return "$rc"
}

analyze_case() {
	local period=$1
	local buffer=$2
	local wav_path=$3
	local capture_log=$4
	local warning_log=$5
	local error_log=$6
	local warning_rc=$7
	local error_rc=$8
	local capture_rc=$9
	local out=${10}
	local size=0
	local data_bytes=0
	local bits
	local bytes_per_sample
	local expected_data_bytes
	local min_data_bytes
	local codec=""
	local sample_rate=""
	local file_channels=""
	local max_volume=""
	local actual_period=""
	local actual_buffer=""
	local expected_codec
	local header_ok=0
	local size_ok=0
	local nonzero_ok=0
	local rate_ok=0
	local channels_ok=0
	local format_ok=0
	local xrun_ok=1
	local period_ok=1
	local buffer_ok=1
	local warning_ok="unknown"
	local error_ok="unknown"
	local status="FAIL"
	local detail="ok"

	if [ -f "$wav_path" ]; then
		size=$(stat -c %s "$wav_path" 2>/dev/null || printf '0')
	fi
	if [ "$size" -gt 44 ]; then
		data_bytes=$((size - 44))
	fi

	bits=$(format_bits "$FORMAT")
	bytes_per_sample=$(((bits + 7) / 8))
	expected_data_bytes=$((DURATION * RATE * CHANNELS * bytes_per_sample))
	min_data_bytes=$((expected_data_bytes * (100 - SIZE_TOLERANCE_PERCENT) / 100))
	if [ "$data_bytes" -ge "$min_data_bytes" ]; then
		size_ok=1
	fi

	if ffprobe -v error -select_streams a:0 -show_entries stream=codec_name \
		-of default=noprint_wrappers=1:nokey=1 "$wav_path" >/dev/null 2>&1; then
		header_ok=1
		codec=$(ffprobe -v error -select_streams a:0 -show_entries stream=codec_name \
			-of default=noprint_wrappers=1:nokey=1 "$wav_path" 2>/dev/null | head -n 1)
		sample_rate=$(ffprobe -v error -select_streams a:0 -show_entries stream=sample_rate \
			-of default=noprint_wrappers=1:nokey=1 "$wav_path" 2>/dev/null | head -n 1)
		file_channels=$(ffprobe -v error -select_streams a:0 -show_entries stream=channels \
			-of default=noprint_wrappers=1:nokey=1 "$wav_path" 2>/dev/null | head -n 1)
	fi

	expected_codec=$(format_codec "$FORMAT")
	[ "$codec" = "$expected_codec" ] && format_ok=1
	[ "$sample_rate" = "$RATE" ] && rate_ok=1
	[ "$file_channels" = "$CHANNELS" ] && channels_ok=1

	if [ -f "$wav_path" ]; then
		ffmpeg -nostdin -hide_banner -i "$wav_path" -af volumedetect -f null - \
			>/dev/null 2>"$out.volumedetect.log" || true
		max_volume=$(awk -F': ' '/max_volume/ { print $2 }' "$out.volumedetect.log" | tail -n 1)
		if [ "$ALLOW_SILENCE" -eq 1 ] ||
		   { [ -n "$max_volume" ] && [ "$max_volume" != "-inf dB" ]; }; then
			nonzero_ok=1
		fi
	fi

	if grep -Eiq '(^|[^a-z])(xrun|overrun|underrun)([^a-z]|$)' "$capture_log"; then
		xrun_ok=0
	fi

	actual_period=$(extract_arecord_setup_value "$capture_log" period_size || true)
	actual_buffer=$(extract_arecord_setup_value "$capture_log" buffer_size || true)
	if [ -n "$actual_period" ] && [ "$actual_period" != "$period" ]; then
		period_ok=0
	fi
	if [ -n "$actual_buffer" ] && [ "$actual_buffer" != "$buffer" ]; then
		buffer_ok=0
	fi

	if [ "$warning_rc" -eq 0 ]; then
		if [ -s "$warning_log" ]; then
			warning_ok=0
		else
			warning_ok=1
		fi
	fi
	if [ "$error_rc" -eq 0 ]; then
		if [ -s "$error_log" ]; then
			error_ok=0
		else
			error_ok=1
		fi
	fi

	if [ "$capture_rc" -eq 124 ]; then
		detail="arecord_timeout"
	elif [ "$xrun_ok" -ne 1 ]; then
		detail="xrun_reported"
	elif [ "$capture_rc" -ne 0 ]; then
		detail="arecord_rc=$capture_rc"
	elif [ "$header_ok" -ne 1 ]; then
		detail="invalid_wav_header"
	elif [ "$size_ok" -ne 1 ]; then
		detail="payload_too_small"
	elif [ "$rate_ok" -ne 1 ] || [ "$channels_ok" -ne 1 ] || [ "$format_ok" -ne 1 ]; then
		detail="format_mismatch"
	elif [ "$nonzero_ok" -ne 1 ]; then
		detail="silent_capture"
	elif [ "$period_ok" -ne 1 ]; then
		detail="actual_period_size=$actual_period"
	elif [ "$buffer_ok" -ne 1 ]; then
		detail="actual_buffer_size=$actual_buffer"
	elif [ "$warning_ok" = "0" ]; then
		detail="kernel_warning"
	elif [ "$error_ok" = "0" ]; then
		detail="kernel_error"
	else
		status="PASS"
	fi

	{
		printf 'status=%s\n' "$status"
		printf 'detail=%s\n' "$detail"
		printf 'period_size=%s\n' "$period"
		printf 'buffer_size=%s\n' "$buffer"
		printf 'actual_period_size=%s\n' "${actual_period:-unknown}"
		printf 'actual_buffer_size=%s\n' "${actual_buffer:-unknown}"
		printf 'capture_rc=%s\n' "$capture_rc"
		printf 'size_bytes=%s\n' "$size"
		printf 'actual_data_bytes=%s\n' "$data_bytes"
		printf 'expected_data_bytes=%s\n' "$expected_data_bytes"
		printf 'min_data_bytes=%s\n' "$min_data_bytes"
		printf 'codec=%s\n' "${codec:-unknown}"
		printf 'sample_rate=%s\n' "${sample_rate:-unknown}"
		printf 'channels=%s\n' "${file_channels:-unknown}"
		printf 'max_volume=%s\n' "${max_volume:-unknown}"
		printf 'header_ok=%s\n' "$header_ok"
		printf 'size_ok=%s\n' "$size_ok"
		printf 'nonzero_ok=%s\n' "$nonzero_ok"
		printf 'rate_ok=%s\n' "$rate_ok"
		printf 'channels_ok=%s\n' "$channels_ok"
		printf 'format_ok=%s\n' "$format_ok"
		printf 'xrun_ok=%s\n' "$xrun_ok"
		printf 'period_ok=%s\n' "$period_ok"
		printf 'buffer_ok=%s\n' "$buffer_ok"
		printf 'kernel_warning_ok=%s\n' "$warning_ok"
		printf 'kernel_error_ok=%s\n' "$error_ok"
	} >"$out"
}

analysis_value() {
	local path=$1
	local key=$2

	awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$path" 2>/dev/null || true
}

run_case() {
	local pair=$1
	local period=${pair%%:*}
	local buffer=${pair##*:}
	local case_id="period_${period}_buffer_${buffer}"
	local artifact_dir="$OUTPUT_DIR/tests/$(safe_name "$case_id")"
	local capture_rc=0
	local warning_rc=77
	local error_rc=77
	local since
	local status
	local detail
	local analysis

	mkdir -p "$artifact_dir"
	log "RUN $case_id (${DURATION}s ${RATE}Hz $FORMAT ${CHANNELS}ch)"

	run_hw_params_case "$period" "$buffer" "$artifact_dir/hw-params.log" || true

	since=$(date '+%Y-%m-%d %H:%M:%S')
	if run_arecord_case "$period" "$buffer" "$artifact_dir/capture.wav" "$artifact_dir/arecord.log"; then
		capture_rc=0
	else
		capture_rc=$?
	fi

	if capture_kernel_log "$since" warning "$artifact_dir/kernel-warnings.log"; then
		warning_rc=0
	else
		warning_rc=$?
	fi
	if capture_kernel_log "$since" err "$artifact_dir/kernel-errors.log"; then
		error_rc=0
	else
		error_rc=$?
	fi

	analysis="$artifact_dir/analysis.txt"
	analyze_case "$period" "$buffer" "$artifact_dir/capture.wav" \
		"$artifact_dir/arecord.log" "$artifact_dir/kernel-warnings.log" \
		"$artifact_dir/kernel-errors.log" "$warning_rc" "$error_rc" \
		"$capture_rc" "$analysis"

	status=$(analysis_value "$analysis" status)
	detail=$(analysis_value "$analysis" detail)
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$case_id" "$status" "$period" "$buffer" \
		"$(analysis_value "$analysis" actual_period_size)" \
		"$(analysis_value "$analysis" actual_buffer_size)" \
		"$capture_rc" \
		"$(analysis_value "$analysis" header_ok)" \
		"$(analysis_value "$analysis" size_ok)" \
		"$(analysis_value "$analysis" nonzero_ok)" \
		"$(analysis_value "$analysis" rate_ok)" \
		"$(analysis_value "$analysis" channels_ok)" \
		"$(analysis_value "$analysis" format_ok)" \
		"$(analysis_value "$analysis" xrun_ok)" \
		"$(analysis_value "$analysis" period_ok)" \
		"$(analysis_value "$analysis" buffer_ok)" \
		"$(analysis_value "$analysis" kernel_warning_ok)" \
		"$(analysis_value "$analysis" kernel_error_ok)" \
		"$detail" "$artifact_dir" >>"$SUMMARY_TSV"

	if [ "$status" = "PASS" ]; then
		PASSES=$((PASSES + 1))
		log "PASS $case_id"
	else
		FAILURES=$((FAILURES + 1))
		log "FAIL $case_id - $detail (see $analysis)"
	fi
}

main() {
	local pair

	parse_args "$@"
	validate_number "duration" "$DURATION"
	validate_number "rate" "$RATE"
	validate_number "channels" "$CHANNELS"
	validate_number "tone frequency" "$TONE_FREQUENCY"
	validate_cases

	hws_require_cmds arecord awk date ffmpeg ffprobe mkdir stat tee timeout || exit 127
	if [ "$NO_PLAYBACK" -ne 1 ]; then
		hws_require_cmds pactl pw-play || exit 127
	fi

	if [ -n "$PROFILE" ]; then
		hws_set_nvidia_profile "$CARD" "$PROFILE"
		sleep 1
	fi

	AUDIO_DEVICE=$(resolve_audio_device "$AUDIO_DEVICE")
	if [ "$NO_PLAYBACK" -ne 1 ]; then
		TARGET=$(hws_resolve_playback_target "$TARGET")
	fi

	init_output
	trap cleanup EXIT INT TERM
	write_context

	log "output_dir=$OUTPUT_DIR"
	log "audio_device=$AUDIO_DEVICE"
	log "cases=$CASES"
	if [ "$NO_PLAYBACK" -ne 1 ]; then
		log "target=$TARGET"
	fi

	start_playback_loop
	for pair in $CASES; do
		run_case "$pair"
	done

	log "summary=$SUMMARY_TSV"
	log "passes=$PASSES failures=$FAILURES"
	if [ "$FAILURES" -ne 0 ]; then
		exit 1
	fi
}

main "$@"
