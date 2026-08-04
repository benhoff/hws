#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./hws_audio_lib.sh
. "$SCRIPT_DIR/hws_audio_lib.sh"

usage() {
	cat <<'EOF'
Usage: ./hws_nvidia_hdmi_audio_matrix.sh [options]

Sweep NVIDIA HDMI/DP playback sinks against HWS ALSA capture inputs. This is
intended to map pro-output-N sinks to physical capture channels and collect
non-listening audio evidence for each pair.

Options:
  --targets LIST          Comma-separated PipeWire sink targets. Default: all NVIDIA HDMI sinks.
  --audio-devices LIST    HWS capture devices. Accepts quoted spaces or hw:5,0,hw:5,1 form.
  --profile NAME          Set NVIDIA card profile before target detection, for example pro-audio.
  --capture-backend NAME  Capture backend: pipewire or alsa. Default: pipewire.
  --card NAME             Pulse/PipeWire card for --profile. Default: auto NVIDIA.
  --duration N            Seconds per pair. Default: 6.
  --tone-frequency HZ     Base tone frequency. Default: 1000.
  --vary-tone             Add 100 Hz per target index to make runs visually distinct.
  --video-device /dev/videoN
  --with-video            Also run the parallel V4L2 smoke capture.
  --output-dir DIR        Matrix evidence directory. Default: /tmp timestamp dir.
  --help                  Show this help.
EOF
}

TARGETS_CSV=""
AUDIO_DEVICES_SPEC="hw:5,0 hw:5,1 hw:5,2 hw:5,3"
PROFILE=""
CAPTURE_BACKEND="pipewire"
CARD="auto"
DURATION=6
TONE_FREQUENCY=1000
VARY_TONE=0
VIDEO_DEVICE="/dev/video3"
WITH_VIDEO=0
OUTPUT_DIR=""

while [ $# -gt 0 ]; do
	case "$1" in
	--targets)
		TARGETS_CSV=$2
		shift 2
		;;
	--audio-devices)
		AUDIO_DEVICES_SPEC=$2
		shift 2
		;;
	--profile)
		PROFILE=$2
		shift 2
		;;
	--capture-backend|--backend)
		CAPTURE_BACKEND=$2
		shift 2
		;;
	--card)
		CARD=$2
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
	--vary-tone)
		VARY_TONE=1
		shift
		;;
	--video-device)
		VIDEO_DEVICE=$2
		shift 2
		;;
	--with-video)
		WITH_VIDEO=1
		shift
		;;
	--output-dir)
		OUTPUT_DIR=$2
		shift 2
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

hws_require_cmds pactl pw-play ffmpeg arecord journalctl

if [ -n "$PROFILE" ]; then
	hws_set_nvidia_profile "$CARD" "$PROFILE"
	sleep 1
fi

if [ -z "$OUTPUT_DIR" ]; then
	OUTPUT_DIR="/tmp/hws-nvidia-hdmi-audio-matrix-$(hws_timestamp)"
fi
mkdir -p "$OUTPUT_DIR"
hws_write_audio_context "$OUTPUT_DIR/context"

declare -a TARGETS=()
declare -a AUDIO_DEVICES=()

if [ -n "$TARGETS_CSV" ]; then
	IFS=',' read -r -a TARGETS <<<"$TARGETS_CSV"
else
	while IFS= read -r target; do
		[ -n "$target" ] && TARGETS+=("$target")
	done < <(hws_list_hdmi_sinks | awk 'NR > 1 && $2 == "nvidia-hdmi" { print $1 }')
fi
while IFS= read -r audio_device; do
	[ -n "$audio_device" ] && AUDIO_DEVICES+=("$audio_device")
done < <(hws_expand_alsa_device_list "$AUDIO_DEVICES_SPEC")

if [ "${#TARGETS[@]}" -eq 0 ]; then
	printf 'no NVIDIA HDMI targets found; run ./hws_hdmi_audio_targets.sh\n' >&2
	exit 1
fi

MATRIX_TSV="$OUTPUT_DIR/matrix.tsv"
MATRIX_TXT="$OUTPUT_DIR/matrix.txt"

{
	printf 'playback_target\taudio_device\ttone_hz\tcapture_rc\tplayback_rc\twav_status\tmean_volume\tmax_volume\ttrace_available\tirq_count\tdeliver_count\tzero_base\trun_dir\n'
} >"$MATRIX_TSV"

summary_value() {
	local path=$1
	local key=$2

	awk -F= -v k="$key" '$1 == k { print substr($0, index($0, "=") + 1); exit }' "$path" 2>/dev/null || true
}

trace_value() {
	local path=$1
	local key=$2

	awk -F= -v k="$key" '$1 == k { print $2; exit }' "$path" 2>/dev/null || true
}

printf 'output_dir=%s\n' "$OUTPUT_DIR"
printf 'targets=%s\n' "${TARGETS[*]}"
printf 'audio_devices=%s\n' "${AUDIO_DEVICES[*]}"

target_index=0
for target in "${TARGETS[@]}"; do
	tone=$TONE_FREQUENCY
	if [ "$VARY_TONE" -eq 1 ]; then
		tone=$((TONE_FREQUENCY + target_index * 100))
	fi

	for audio_device in "${AUDIO_DEVICES[@]}"; do
		safe_target=$(printf '%s' "$target" | tr '/:,' '___')
		safe_audio=$(printf '%s' "$audio_device" | tr '/:,' '___')
		run_dir="$OUTPUT_DIR/${safe_target}/${safe_audio}"
		mkdir -p "$run_dir"

		cmd=(
			"$SCRIPT_DIR/test_hdmi_output_loop.sh"
			--audio-device "$audio_device"
			--playback-target "$target"
			--capture-backend "$CAPTURE_BACKEND"
			--duration "$DURATION"
			--tone-frequency "$tone"
			--output-dir "$run_dir"
		)
		if [ "$WITH_VIDEO" -eq 1 ]; then
			cmd+=(--video-device "$VIDEO_DEVICE")
		else
			cmd+=(--skip-video)
		fi

		printf 'running target=%s audio=%s tone=%s\n' "$target" "$audio_device" "$tone"
		set +e
		"${cmd[@]}"
		run_rc=$?
		set -e

		summary="$run_dir/summary.txt"
		analysis="$run_dir/capture.analysis.txt"
		trace="$run_dir/audio-trace-summary.txt"

		capture_rc=$(summary_value "$summary" capture_rc)
		playback_rc=$(summary_value "$summary" playback_rc)
		wav_status=$(summary_value "$summary" wav_status)
		mean_volume=$(summary_value "$analysis" mean_volume)
		max_volume=$(summary_value "$analysis" max_volume)
		trace_available=$(trace_value "$trace" trace_available)
		irq_count=$(trace_value "$trace" irq_count)
		deliver_count=$(trace_value "$trace" deliver_count)
		zero_base=$(trace_value "$trace" zero_base)

		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$target" "$audio_device" "$tone" \
			"${capture_rc:-unknown}" "${playback_rc:-unknown}" \
			"${wav_status:-unknown}" "${mean_volume:-unknown}" "${max_volume:-unknown}" \
			"${trace_available:-0}" "${irq_count:-0}" "${deliver_count:-0}" \
			"${zero_base:-unknown}" "$run_dir" >>"$MATRIX_TSV"

		if [ "$run_rc" -ne 0 ]; then
			printf 'pair returned rc=%s; keeping artifacts in %s\n' "$run_rc" "$run_dir" >&2
		fi
	done

	target_index=$((target_index + 1))
done

{
	printf 'HWS NVIDIA HDMI Audio Matrix\n'
	printf 'Output: %s\n\n' "$OUTPUT_DIR"
	column -t -s $'\t' "$MATRIX_TSV" 2>/dev/null || cat "$MATRIX_TSV"
	printf '\nLikely active pairs:\n'
	tail -n +2 "$MATRIX_TSV" | while IFS=$'\t' read -r \
		playback_target audio_device tone_hz capture_rc playback_rc \
		wav_status mean_volume max_volume trace_available irq_count \
		deliver_count zero_base run_dir; do
		if [ "${irq_count:-0}" -gt 0 ] || [ "${deliver_count:-0}" -gt 0 ] ||
		   [ "$wav_status" = "ok" ]; then
			printf '%s\n' \
				"- target=$playback_target audio=$audio_device tone=$tone_hz wav=$wav_status irq=$irq_count delivered=$deliver_count max=$max_volume dir=$run_dir"
		fi
	done
} | tee "$MATRIX_TXT"

printf 'matrix_tsv=%s\n' "$MATRIX_TSV"
printf 'matrix_txt=%s\n' "$MATRIX_TXT"
