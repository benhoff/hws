#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: ./test_audio_trace_matrix.sh [options]

Drive one live HDMI playback source into a selected HwsCapture video input and
probe multiple ALSA audio devices using the existing audio_trace logs. This is
the fastest way to answer:

1. Did the channel arm?
2. Did the audio DMA base register stick?
3. Did the hardware write any bytes?
4. Did ADONE IRQs ever arrive?

Defaults:
  --video-device /dev/video3
  --audio-devices hw:5,0,hw:5,1,hw:5,2,hw:5,3
  --duration 4
  --skip-video

The loaded module should have audio_trace enabled:
  sudo insmod src/HwsCapture.ko audio_trace=1
EOF
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

VIDEO_DEVICE="/dev/video3"
DURATION=4
OUTPUT_DIR=""
PLAYBACK_TARGET=""
XRANDR_OUTPUT="HDMI-A-1"
TONE_FREQUENCY=1000
RATE=48000
CHANNELS=2
SKIP_VIDEO=1
declare -a AUDIO_DEVICES=("hw:5,0" "hw:5,1" "hw:5,2" "hw:5,3")

timestamp() {
	date '+%Y%m%d-%H%M%S'
}

log() {
	printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$1"
}

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

summary_value() {
	local path=$1
	local key=$2
	awk -F= -v k="$key" '$1 == k { print substr($0, index($0, "=") + 1); exit }' "$path"
}

trace_start_line() {
	local path=$1
	awk '/audio-trace:start/ { print; exit }' "$path"
}

trace_probe_line() {
	local path=$1
	awk '/audio-trace:probe/ { print; exit }' "$path"
}

extract_field() {
	local line=$1
	local key=$2
	local value=""

	value=$(printf '%s\n' "$line" | sed -n "s/.*${key}=\\([^ ]*\\).*/\\1/p")
	printf '%s\n' "$value"
}

extract_pair_field() {
	local line=$1
	local key=$2
	local value=""

	value=$(printf '%s\n' "$line" | sed -n "s/.*${key}=\\[\\([^]]*\\)\\].*/\\1/p")
	printf '%s\n' "$value"
}

probe_crc_pair() {
	local line=$1
	printf '%s\n' "$line" | sed -n 's/.*crc=\([0-9a-fA-F]\+\)->\([0-9a-fA-F]\+\).*/\1 \2/p'
}

classify_channel() {
	local capture_rc=$1
	local wav_status=$2
	local irq_count=$3
	local deliver_count=$4
	local base=$5
	local crc_before=$6
	local crc_after=$7

	if [ "$irq_count" -gt 0 ] || [ "$deliver_count" -gt 0 ]; then
		printf 'dma_active\n'
		return 0
	fi

	if [ -n "$crc_before" ] && [ -n "$crc_after" ] && [ "$crc_before" != "$crc_after" ]; then
		printf 'dma_without_irq\n'
		return 0
	fi

	if [ "$base" = "00000000" ]; then
		printf 'armed_base_zero\n'
		return 0
	fi

	if [ "$capture_rc" != "0" ] && [ "$wav_status" = "empty" ]; then
		printf 'armed_no_dma\n'
		return 0
	fi

	printf 'unknown\n'
}

ensure_output_dir() {
	if [ -z "$OUTPUT_DIR" ]; then
		OUTPUT_DIR="/tmp/hws-audio-trace-matrix-$(timestamp)"
	fi

	mkdir -p "$OUTPUT_DIR"
}

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
		--video-device)
			VIDEO_DEVICE=$2
			shift 2
			;;
		--audio-devices)
			IFS=',' read -r -a AUDIO_DEVICES <<<"$2"
			shift 2
			;;
		--duration)
			DURATION=$2
			shift 2
			;;
		--output-dir)
			OUTPUT_DIR=$2
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
		--with-video)
			SKIP_VIDEO=0
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

check_prereqs() {
	local trace_param="/sys/module/HwsCapture/parameters/audio_trace"

	if [ ! -e "$trace_param" ]; then
		printf 'missing module parameter: %s\n' "$trace_param" >&2
		exit 1
	fi

	if [ "$(cat "$trace_param")" != "Y" ]; then
		printf 'audio_trace is not enabled: %s\n' "$trace_param" >&2
		exit 1
	fi

	if [ ! -x "$SCRIPT_DIR/test_hdmi_output_loop.sh" ]; then
		printf 'missing helper: %s/test_hdmi_output_loop.sh\n' "$SCRIPT_DIR" >&2
		exit 1
	fi
}

run_probe() {
	local dev=$1
	local ch=${dev##*,}
	local run_dir="$OUTPUT_DIR/ch${ch}"
	local cmd=(
		"$SCRIPT_DIR/test_hdmi_output_loop.sh"
		--audio-device "$dev"
		--video-device "$VIDEO_DEVICE"
		--duration "$DURATION"
		--output-dir "$run_dir"
		--xrandr-output "$XRANDR_OUTPUT"
		--tone-frequency "$TONE_FREQUENCY"
		--rate "$RATE"
		--channels "$CHANNELS"
	)

	if [ -n "$PLAYBACK_TARGET" ]; then
		cmd+=(--playback-target "$PLAYBACK_TARGET")
	fi
	if [ "$SKIP_VIDEO" -eq 1 ]; then
		cmd+=(--skip-video)
	fi

	log "Running live trace probe on $dev with source on $VIDEO_DEVICE"
	"${cmd[@]}" >/dev/null
}

emit_matrix() {
	local matrix_tsv="$OUTPUT_DIR/matrix.tsv"
	local matrix_txt="$OUTPUT_DIR/matrix.txt"
	local dev

	{
		printf 'audio_device\tchannel\tcapture_rc\twav_status\tseed_count\tstart_count\tirq_count\tdeliver_count\tinput\tbase\tsrc\tdma\tshared\taudio\tgate\tbr\tdec\tprobe_crc_before\tprobe_crc_after\tclassification\tartifacts\n'
		for dev in "${AUDIO_DEVICES[@]}"; do
			local ch=${dev##*,}
			local run_dir="$OUTPUT_DIR/ch${ch}"
			local summary="$run_dir/summary.txt"
			local trace="$run_dir/audio-trace.log"
			local start_line=""
			local probe_line=""
			local capture_rc=""
			local wav_status=""
			local seed_count=""
			local start_count=""
			local irq_count=""
			local deliver_count=""
			local input=""
			local base=""
			local src=""
			local dma=""
			local shared=""
			local audio=""
			local gate=""
			local br=""
			local dec=""
			local crc_before=""
			local crc_after=""
			local classification=""
			local crc_pair=""

			capture_rc=$(summary_value "$summary" "capture_rc")
			wav_status=$(summary_value "$summary" "wav_status")
			seed_count=$(summary_value "$summary" "seed_count")
			start_count=$(summary_value "$summary" "start_count")
			irq_count=$(summary_value "$summary" "irq_count")
			deliver_count=$(summary_value "$summary" "deliver_count")
			start_line=$(trace_start_line "$trace")
			probe_line=$(trace_probe_line "$trace")

			if [ -n "$start_line" ]; then
				input=$(extract_field "$start_line" "input")
				base=$(extract_field "$start_line" "base")
				src=$(extract_field "$start_line" "src")
				dma=$(extract_field "$start_line" "dma")
				shared=$(extract_pair_field "$start_line" "shared")
				audio=$(extract_pair_field "$start_line" "audio")
				gate=$(extract_field "$start_line" "gate")
				br=$(extract_field "$start_line" "br")
				dec=$(extract_field "$start_line" "dec")
			fi

			if [ -n "$probe_line" ]; then
				crc_pair=$(probe_crc_pair "$probe_line")
				crc_before=${crc_pair%% *}
				crc_after=${crc_pair##* }
				if [ "$crc_before" = "$crc_pair" ]; then
					crc_before=""
					crc_after=""
				fi
			fi

			classification=$(classify_channel "${capture_rc:-1}" "${wav_status:-missing}" \
				"${irq_count:-0}" "${deliver_count:-0}" "${base:-}" \
				"${crc_before:-}" "${crc_after:-}")

			printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
				"$dev" "$ch" "${capture_rc:-}" "${wav_status:-}" \
				"${seed_count:-}" "${start_count:-}" "${irq_count:-}" "${deliver_count:-}" \
				"${input:-}" "${base:-}" "${src:-}" "${dma:-}" \
				"${shared:-}" "${audio:-}" "${gate:-}" "${br:-}" "${dec:-}" \
				"${crc_before:-}" "${crc_after:-}" "$classification" "$run_dir"
		done
	} >"$matrix_tsv"

	{
		printf 'Live HWS audio trace matrix\n'
		printf 'video_device=%s\n' "$VIDEO_DEVICE"
		printf 'duration_seconds=%s\n' "$DURATION"
		printf 'output_dir=%s\n' "$OUTPUT_DIR"
		printf '\n'
		column -s $'\t' -t "$matrix_tsv"
	} >"$matrix_txt"

	printf '%s\n' "$matrix_txt"
}

main() {
	local dev

	parse_args "$@"
	ensure_output_dir
	check_prereqs

	for dev in "${AUDIO_DEVICES[@]}"; do
		run_probe "$dev"
	done

	emit_matrix
}

main "$@"
