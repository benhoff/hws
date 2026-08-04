#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./hws_audio_lib.sh
. "$SCRIPT_DIR/hws_audio_lib.sh"

usage() {
	cat <<'EOF'
Usage: ./hws_hdmi_audio_play.sh [options]

Push a known audio signal, or a supplied WAV/media file, out through an
NVIDIA/HDMI PipeWire playback sink.

Options:
  --target NAME          PipeWire/Pulse sink target. Default: auto NVIDIA HDMI.
  --card NAME            Pulse/PipeWire card for --profile. Default: auto NVIDIA.
  --profile NAME         Set NVIDIA card profile before target detection.
  --file PATH            Play an existing audio file instead of generating tone.wav.
  --duration N           Generated tone duration in seconds. Default: 10.
  --tone-frequency HZ    Generated tone frequency. Default: 1000.
  --rate HZ              Generated sample rate. Default: 48000.
  --channels N           Generated channels. Default: 2.
  --volume N             Generated tone volume multiplier. Default: 0.8.
  --loop                 Repeat playback until interrupted.
  --set-default          Also set the detected target as the default sink.
  --output-dir DIR       Evidence/output directory. Default: /tmp timestamp dir.
  --list-targets         List candidate targets and exit.
  --help                 Show this help.
EOF
}

TARGET="auto"
CARD="auto"
PROFILE=""
INPUT_FILE=""
OUTPUT_DIR=""
DURATION=10
TONE_FREQUENCY=1000
RATE=48000
CHANNELS=2
VOLUME="0.8"
LOOP=0
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
	--file)
		INPUT_FILE=$2
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
	--volume)
		VOLUME=$2
		shift 2
		;;
	--loop)
		LOOP=1
		shift
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

hws_require_cmds pw-play pactl
if [ -z "$INPUT_FILE" ]; then
	hws_require_cmds ffmpeg
fi

if [ -n "$PROFILE" ]; then
	hws_set_nvidia_profile "$CARD" "$PROFILE"
	sleep 1
fi

TARGET=$(hws_resolve_playback_target "$TARGET")

if [ -z "$OUTPUT_DIR" ]; then
	OUTPUT_DIR="/tmp/hws-hdmi-audio-play-$(hws_timestamp)"
fi
mkdir -p "$OUTPUT_DIR"
hws_write_audio_context "$OUTPUT_DIR/context"

if [ "$SET_DEFAULT" -eq 1 ]; then
	pactl set-default-sink "$TARGET"
fi

SOURCE_FILE=$INPUT_FILE
if [ -z "$SOURCE_FILE" ]; then
	SOURCE_FILE="$OUTPUT_DIR/tone.wav"
	ffmpeg -nostdin -hide_banner -loglevel error -y \
		-f lavfi -i "sine=frequency=${TONE_FREQUENCY}:sample_rate=${RATE}:duration=${DURATION}" \
		-af "volume=${VOLUME}" \
		-ac "$CHANNELS" \
		-c:a pcm_s16le "$SOURCE_FILE"
fi

{
	printf 'target=%s\n' "$TARGET"
	printf 'card=%s\n' "$CARD"
	printf 'profile=%s\n' "$PROFILE"
	printf 'source_file=%s\n' "$SOURCE_FILE"
	printf 'duration_seconds=%s\n' "$DURATION"
	printf 'tone_frequency_hz=%s\n' "$TONE_FREQUENCY"
	printf 'rate_hz=%s\n' "$RATE"
	printf 'channels=%s\n' "$CHANNELS"
	printf 'loop=%s\n' "$LOOP"
	printf 'set_default=%s\n' "$SET_DEFAULT"
} >"$OUTPUT_DIR/summary.txt"

printf 'target=%s\n' "$TARGET"
printf 'source_file=%s\n' "$SOURCE_FILE"
printf 'output_dir=%s\n' "$OUTPUT_DIR"

if [ "$LOOP" -eq 1 ]; then
	while :; do
		pw-play --target "$TARGET" "$SOURCE_FILE" >>"$OUTPUT_DIR/playback.log" 2>&1
	done
else
	pw-play --target "$TARGET" "$SOURCE_FILE" >>"$OUTPUT_DIR/playback.log" 2>&1
fi
