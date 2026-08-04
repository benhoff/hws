#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./hws_audio_lib.sh
. "$SCRIPT_DIR/hws_audio_lib.sh"

usage() {
	cat <<'EOF'
Usage: ./hws_hdmi_audio_profile.sh [options]

List or change the NVIDIA HDMI audio card profile.

Options:
  --card NAME         Pulse/PipeWire card name. Default: auto NVIDIA card.
  --profile NAME      Set this profile, for example pro-audio.
  --list              List NVIDIA card profiles. Default action.
  --help              Show this help.

Examples:
  ./hws_hdmi_audio_profile.sh --list
  ./hws_hdmi_audio_profile.sh --profile pro-audio
  ./hws_hdmi_audio_profile.sh --profile output:hdmi-stereo-extra3
EOF
}

CARD="auto"
PROFILE=""
LIST=1

while [ $# -gt 0 ]; do
	case "$1" in
	--card)
		CARD=$2
		shift 2
		;;
	--profile)
		PROFILE=$2
		LIST=0
		shift 2
		;;
	--list)
		LIST=1
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

hws_require_cmds pactl

if [ "$LIST" -eq 1 ]; then
	hws_list_nvidia_card_profiles
	exit 0
fi

if [ -z "$PROFILE" ]; then
	printf 'no profile supplied\n' >&2
	usage >&2
	exit 1
fi

if [ "$CARD" = "auto" ]; then
	CARD=$(hws_detect_nvidia_card || true)
fi
if [ -z "$CARD" ]; then
	printf 'could not auto-detect an NVIDIA audio card\n' >&2
	exit 1
fi

hws_set_nvidia_profile "$CARD" "$PROFILE"
printf 'card=%s\n' "$CARD"
printf 'profile=%s\n' "$PROFILE"
printf '\nPlayback targets after profile change\n'
hws_list_hdmi_sinks || true
