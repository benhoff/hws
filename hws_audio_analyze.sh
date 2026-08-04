#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./hws_audio_lib.sh
. "$SCRIPT_DIR/hws_audio_lib.sh"

usage() {
	cat <<'EOF'
Usage: ./hws_audio_analyze.sh [options] [capture.wav|capture-dir]

Analyze a captured WAV without sending it through a playback device.

Options:
  --wav PATH              WAV file to analyze.
  --dir DIR               Directory containing capture.wav or another WAV.
  --output-dir DIR        Analysis output directory. Default: next to the WAV.
  --expected-tone HZ      Also compute a narrow-band volume check around HZ.
  --no-images             Skip waveform/spectrum PNG generation.
  --help                  Show this help.
EOF
}

WAV_PATH=""
INPUT_DIR=""
OUTPUT_DIR=""
EXPECTED_TONE=""
MAKE_IMAGES=1

while [ $# -gt 0 ]; do
	case "$1" in
	--wav)
		WAV_PATH=$2
		shift 2
		;;
	--dir)
		INPUT_DIR=$2
		shift 2
		;;
	--output-dir)
		OUTPUT_DIR=$2
		shift 2
		;;
	--expected-tone)
		EXPECTED_TONE=$2
		shift 2
		;;
	--no-images)
		MAKE_IMAGES=0
		shift
		;;
	--help|-h)
		usage
		exit 0
		;;
	-*)
		printf 'Unknown option: %s\n' "$1" >&2
		usage >&2
		exit 1
		;;
	*)
		if [ -d "$1" ]; then
			INPUT_DIR=$1
		else
			WAV_PATH=$1
		fi
		shift
		;;
	esac
done

hws_require_cmds ffmpeg ffprobe

if [ -n "$INPUT_DIR" ] && [ -z "$WAV_PATH" ]; then
	if [ -f "$INPUT_DIR/capture.wav" ]; then
		WAV_PATH="$INPUT_DIR/capture.wav"
	else
		for candidate in "$INPUT_DIR"/*.wav; do
			if [ -f "$candidate" ]; then
				WAV_PATH=$candidate
				break
			fi
		done
	fi
fi

if [ -z "$WAV_PATH" ]; then
	printf 'no WAV file supplied\n' >&2
	usage >&2
	exit 1
fi
if [ ! -f "$WAV_PATH" ]; then
	printf 'WAV file not found: %s\n' "$WAV_PATH" >&2
	exit 1
fi

if [ -z "$OUTPUT_DIR" ]; then
	OUTPUT_DIR="$(dirname -- "$WAV_PATH")/analysis-$(hws_timestamp)"
fi
mkdir -p "$OUTPUT_DIR"

FFPROBE_LOG="$OUTPUT_DIR/ffprobe.txt"
VOLUME_LOG="$OUTPUT_DIR/volumedetect.log"
ASTATS_LOG="$OUTPUT_DIR/astats.log"
SUMMARY="$OUTPUT_DIR/summary.txt"

ffprobe -hide_banner "$WAV_PATH" >"$FFPROBE_LOG" 2>&1 || true
ffmpeg -nostdin -hide_banner -i "$WAV_PATH" \
	-af volumedetect -f null - > /dev/null 2>"$VOLUME_LOG" || true
ffmpeg -nostdin -hide_banner -i "$WAV_PATH" \
	-af astats=metadata=1:reset=1 -f null - > /dev/null 2>"$ASTATS_LOG" || true

if [ "$MAKE_IMAGES" -eq 1 ]; then
	ffmpeg -nostdin -hide_banner -loglevel error -y -i "$WAV_PATH" \
		-lavfi "showwavespic=s=1600x360" "$OUTPUT_DIR/waveform.png" || true
	ffmpeg -nostdin -hide_banner -loglevel error -y -i "$WAV_PATH" \
		-lavfi "showspectrum=s=1600x720:scale=log:legend=1" \
		"$OUTPUT_DIR/spectrum.png" || true
fi

if [ -n "$EXPECTED_TONE" ]; then
	LOW=$((EXPECTED_TONE * 95 / 100))
	HIGH=$((EXPECTED_TONE * 105 / 100))
	if [ "$LOW" -lt 20 ]; then
		LOW=20
	fi
	ffmpeg -nostdin -hide_banner -i "$WAV_PATH" \
		-af "highpass=f=${LOW},lowpass=f=${HIGH},volumedetect" \
		-f null - > /dev/null 2>"$OUTPUT_DIR/tone-band-volumedetect.log" || true
fi

SIZE_BYTES=$(stat -c %s "$WAV_PATH" 2>/dev/null || printf '0')
DURATION=$(ffprobe -v error -show_entries format=duration \
	-of default=noprint_wrappers=1:nokey=1 "$WAV_PATH" 2>/dev/null || true)
STREAMS=$(ffprobe -v error -select_streams a:0 \
	-show_entries stream=codec_name,sample_rate,channels,bits_per_sample \
	-of default=noprint_wrappers=1 "$WAV_PATH" 2>/dev/null || true)

{
	printf 'wav=%s\n' "$WAV_PATH"
	printf 'size_bytes=%s\n' "$SIZE_BYTES"
	printf 'duration_seconds=%s\n' "${DURATION:-unknown}"
	printf '%s\n' "$STREAMS"
	printf '\n[volumedetect]\n'
	awk -F': ' '/mean_volume|max_volume/ { print $2 ? $1 "=" $2 : $0 }' "$VOLUME_LOG" |
		sed 's/.*] //'
	printf '\n[astats-overall]\n'
	awk '
		/Overall/ { overall = 1; next }
		overall && /DC offset|Min level|Max level|Peak level dB|RMS level dB|Crest factor|Flat factor|Peak count|Number of samples|Zero crossings rate/ {
			line = $0
			sub(/^.*] /, "", line)
			print line
		}
	' "$ASTATS_LOG"
	if [ -n "$EXPECTED_TONE" ]; then
		printf '\n[tone-band]\n'
		printf 'expected_tone_hz=%s\n' "$EXPECTED_TONE"
		printf 'band_hz=%s-%s\n' "$LOW" "$HIGH"
		awk -F': ' '/mean_volume|max_volume/ { print $2 ? $1 "=" $2 : $0 }' \
			"$OUTPUT_DIR/tone-band-volumedetect.log" | sed 's/.*] //'
	fi
	if [ "$MAKE_IMAGES" -eq 1 ]; then
		printf '\n[images]\n'
		printf 'waveform=%s\n' "$OUTPUT_DIR/waveform.png"
		printf 'spectrum=%s\n' "$OUTPUT_DIR/spectrum.png"
	fi
} >"$SUMMARY"

printf 'analysis_dir=%s\n' "$OUTPUT_DIR"
printf 'summary=%s\n' "$SUMMARY"
cat "$SUMMARY"
