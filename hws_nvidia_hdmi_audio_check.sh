#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./hws_audio_lib.sh
. "$SCRIPT_DIR/hws_audio_lib.sh"

usage() {
	cat <<'EOF'
Usage: ./hws_nvidia_hdmi_audio_check.sh [options]

Drive a generated tone out of the NVIDIA HDMI/DP audio sink, capture it from an
HWS ALSA input, and write analysis artifacts for the captured WAV.

Options:
  --target NAME             PipeWire/Pulse sink target. Default: auto NVIDIA HDMI.
  --card NAME               Pulse/PipeWire card for --profile. Default: auto NVIDIA.
  --profile NAME            Set NVIDIA card profile before target detection.
  --capture-backend NAME    Capture backend: pipewire or alsa. Default: pipewire.
  --audio-device hw:C,D     HWS ALSA capture device. Default: hw:5,3.
  --video-device /dev/videoN  V4L2 node for parallel video smoke. Default: /dev/video3.
  --skip-video              Do not run the parallel V4L2 capture.
  --duration N              Capture/playback seconds. Default: 10.
  --tone-frequency HZ       Generated tone frequency. Default: 1000.
  --rate HZ                 Sample rate. Default: 48000.
  --channels N              Channel count. Default: 2.
  --set-default             Also set the target as the default sink.
  --output-dir DIR          Evidence directory. Default: /tmp timestamp dir.
  --list-targets            List candidate targets and exit.
  --help                    Show this help.
EOF
}

TARGET="auto"
CARD="auto"
PROFILE=""
CAPTURE_BACKEND="pipewire"
AUDIO_DEVICE="hw:5,3"
VIDEO_DEVICE="/dev/video3"
OUTPUT_DIR=""
DURATION=10
TONE_FREQUENCY=1000
RATE=48000
CHANNELS=2
SKIP_VIDEO=0
SET_DEFAULT=0
LIST_TARGETS=0

while [ $# -gt 0 ]; do
	case "$1" in
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
	--capture-backend|--backend)
		CAPTURE_BACKEND=$2
		shift 2
		;;
	--audio-device)
		AUDIO_DEVICE=$2
		shift 2
		;;
	--video-device)
		VIDEO_DEVICE=$2
		shift 2
		;;
	--skip-video)
		SKIP_VIDEO=1
		shift
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
	--set-default)
		SET_DEFAULT=1
		shift
		;;
	--output-dir)
		OUTPUT_DIR=$2
		shift 2
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

if [ "$LIST_TARGETS" -eq 1 ]; then
	hws_list_hdmi_sinks
	exit 0
fi

hws_require_cmds pactl pw-play ffmpeg ffprobe arecord journalctl

if [ -n "$PROFILE" ]; then
	hws_set_nvidia_profile "$CARD" "$PROFILE"
	sleep 1
fi

TARGET=$(hws_resolve_playback_target "$TARGET")
if [ -z "$OUTPUT_DIR" ]; then
	OUTPUT_DIR="/tmp/hws-nvidia-hdmi-audio-check-$(hws_timestamp)"
fi
mkdir -p "$OUTPUT_DIR"
hws_write_audio_context "$OUTPUT_DIR/context"

if [ "$SET_DEFAULT" -eq 1 ]; then
	pactl set-default-sink "$TARGET"
fi

{
	printf 'target=%s\n' "$TARGET"
	printf 'card=%s\n' "$CARD"
	printf 'profile=%s\n' "$PROFILE"
	printf 'capture_backend=%s\n' "$CAPTURE_BACKEND"
	printf 'audio_device=%s\n' "$AUDIO_DEVICE"
	printf 'video_device=%s\n' "$VIDEO_DEVICE"
	printf 'skip_video=%s\n' "$SKIP_VIDEO"
	printf 'duration_seconds=%s\n' "$DURATION"
	printf 'tone_frequency_hz=%s\n' "$TONE_FREQUENCY"
	printf 'rate_hz=%s\n' "$RATE"
	printf 'channels=%s\n' "$CHANNELS"
	printf 'set_default=%s\n' "$SET_DEFAULT"
} >"$OUTPUT_DIR/wrapper-summary.txt"

cmd=(
	"$SCRIPT_DIR/test_hdmi_output_loop.sh"
	--audio-device "$AUDIO_DEVICE"
	--playback-target "$TARGET"
	--capture-backend "$CAPTURE_BACKEND"
	--duration "$DURATION"
	--tone-frequency "$TONE_FREQUENCY"
	--rate "$RATE"
	--channels "$CHANNELS"
	--output-dir "$OUTPUT_DIR"
)

if [ "$SKIP_VIDEO" -eq 1 ]; then
	cmd+=(--skip-video)
else
	cmd+=(--video-device "$VIDEO_DEVICE")
fi

printf 'target=%s\n' "$TARGET"
printf 'output_dir=%s\n' "$OUTPUT_DIR"
printf 'running=%q' "${cmd[0]}"
for arg in "${cmd[@]:1}"; do
	printf ' %q' "$arg"
done
printf '\n'

set +e
"${cmd[@]}"
LOOP_RC=$?
set -e
printf 'loop_rc=%s\n' "$LOOP_RC" >>"$OUTPUT_DIR/wrapper-summary.txt"

if [ -f "$OUTPUT_DIR/capture.wav" ]; then
	"$SCRIPT_DIR/hws_audio_analyze.sh" \
		--wav "$OUTPUT_DIR/capture.wav" \
		--output-dir "$OUTPUT_DIR/analysis" \
		--expected-tone "$TONE_FREQUENCY"
else
	printf 'capture.wav was not produced; inspect %s/capture.arecord.log\n' "$OUTPUT_DIR" >&2
fi

exit "$LOOP_RC"
