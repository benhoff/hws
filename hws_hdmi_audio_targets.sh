#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./hws_audio_lib.sh
. "$SCRIPT_DIR/hws_audio_lib.sh"

usage() {
	cat <<'EOF'
Usage: ./hws_hdmi_audio_targets.sh [options]

List HDMI/NVIDIA playback sinks and HWS capture devices.

Options:
  --target-only   Print only the auto-selected playback target.
  --help          Show this help.
EOF
}

TARGET_ONLY=0

while [ $# -gt 0 ]; do
	case "$1" in
	--target-only)
		TARGET_ONLY=1
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

if [ "$TARGET_ONLY" -eq 1 ]; then
	hws_resolve_playback_target auto
	exit 0
fi

printf 'Default playback sink\n'
if hws_have_cmd pactl; then
	pactl get-default-sink 2>/dev/null || true
else
	printf 'pactl not found\n'
fi

printf '\nAuto-selected NVIDIA/HDMI target\n'
TARGET=$(hws_detect_hdmi_sink nvidia || true)
if [ -n "$TARGET" ]; then
	printf '%s\n' "$TARGET"
else
	printf '(none; enable an NVIDIA card profile such as pro-audio or pass --target manually)\n'
fi

printf '\nHDMI/NVIDIA playback candidates\n'
hws_list_hdmi_sinks || true

printf '\nNVIDIA card profiles\n'
hws_list_nvidia_card_profiles || true

printf '\nAll playback sinks\n'
if hws_have_cmd pactl; then
	pactl list short sinks 2>/dev/null || true
fi

printf '\nHWS capture devices\n'
if [ -r /proc/asound/pcm ]; then
	awk 'tolower($0) ~ /hws|hdmi in|capture/ { print }' /proc/asound/pcm
else
	printf '/proc/asound/pcm is not readable\n'
fi

printf '\nALSA capture cards\n'
if hws_have_cmd arecord; then
	arecord -l 2>/dev/null || true
else
	printf 'arecord not found\n'
fi
