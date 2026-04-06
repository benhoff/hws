#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: ./test_bar0_snapshot_diff.sh [options]

Run one known-good capture case and one failing capture case, then diff the
kernel-emitted `bar0-snap:` checkpoints between them.

The loaded HwsCapture module must have `audio_trace=1`.

Defaults:
  --good-audio-device hw:5,0
  --good-video-device /dev/video0
  --bad-audio-device  hw:5,3
  --bad-video-device  /dev/video3
  --duration 4

Options:
  --good-audio-device DEV   Known-good ALSA device.
  --good-video-device DEV   Matching known-good V4L2 device.
  --bad-audio-device DEV    Failing ALSA device.
  --bad-video-device DEV    Matching failing V4L2 device.
  --playback-target NAME    PipeWire sink target for both runs.
  --duration N              Seconds per capture. Default: 4
  --tone-frequency HZ       Tone frequency. Default: 1000
  --rate HZ                 Sample rate. Default: 48000
  --channels N              Channel count. Default: 2
  --output-dir DIR          Evidence directory. Default: /tmp timestamp dir.
  --with-video              Capture video in parallel during both runs.
  --help                    Show this help.
EOF
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

GOOD_AUDIO_DEVICE="hw:5,0"
GOOD_VIDEO_DEVICE="/dev/video0"
BAD_AUDIO_DEVICE="hw:5,3"
BAD_VIDEO_DEVICE="/dev/video3"
PLAYBACK_TARGET=""
OUTPUT_DIR=""
DURATION=4
TONE_FREQUENCY=1000
RATE=48000
CHANNELS=2
SKIP_VIDEO=1

timestamp() {
	date '+%Y%m%d-%H%M%S'
}

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

log() {
	printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$1"
}

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
		--good-audio-device)
			GOOD_AUDIO_DEVICE=$2
			shift 2
			;;
		--good-video-device)
			GOOD_VIDEO_DEVICE=$2
			shift 2
			;;
		--bad-audio-device)
			BAD_AUDIO_DEVICE=$2
			shift 2
			;;
		--bad-video-device)
			BAD_VIDEO_DEVICE=$2
			shift 2
			;;
		--playback-target)
			PLAYBACK_TARGET=$2
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

ensure_output_dir() {
	if [ -z "$OUTPUT_DIR" ]; then
		OUTPUT_DIR="/tmp/hws-bar0-diff-$(timestamp)"
	fi
	mkdir -p "$OUTPUT_DIR"
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

	for cmd in awk diff find sed sort; do
		if ! have_cmd "$cmd"; then
			printf 'missing required command: %s\n' "$cmd" >&2
			exit 1
		fi
	done
}

run_case() {
	local label=$1
	local audio_device=$2
	local video_device=$3
	local run_dir="$OUTPUT_DIR/$label"
	local -a cmd=(
		"$SCRIPT_DIR/test_hdmi_output_loop.sh"
		--audio-device "$audio_device"
		--video-device "$video_device"
		--duration "$DURATION"
		--tone-frequency "$TONE_FREQUENCY"
		--rate "$RATE"
		--channels "$CHANNELS"
		--output-dir "$run_dir"
	)

	if [ -n "$PLAYBACK_TARGET" ]; then
		cmd+=(--playback-target "$PLAYBACK_TARGET")
	fi
	if [ "$SKIP_VIDEO" -eq 1 ]; then
		cmd+=(--skip-video)
	fi

	log "Running $label case: audio=$audio_device video=$video_device"
	"${cmd[@]}"
}

extract_snapshots() {
	local kernel_log=$1
	local dest=$2

	mkdir -p "$dest"
	awk -v dest="$dest" '
	{
		pos = index($0, "bar0-snap:");
		if (!pos)
			next;
		line = substr($0, pos);
		rest = substr(line, length("bar0-snap:") + 1);
		split(rest, parts, " ");
		tag = parts[1];
		gsub(/[^A-Za-z0-9_.-]/, "_", tag);
		file = dest "/" tag ".txt";
		print line >> file;
	}
	' "$kernel_log"

	find "$dest" -type f -name '*.txt' -print0 | while IFS= read -r -d '' file; do
		sed -i -E 's/^.*bar0-snap:[^ ]+ //' "$file"
	done
}

require_snapshots() {
	local dir=$1
	local label=$2

	if ! find "$dir" -maxdepth 1 -type f -name '*.txt' | grep -q .; then
		printf 'no bar0 snapshots found for %s in %s; reload the rebuilt module with audio_trace=1\n' \
			"$label" "$dir" >&2
		exit 1
	fi
}

write_diff_report() {
	local good_dir=$1
	local bad_dir=$2
	local out_dir=$3
	local summary="$out_dir/diff-summary.txt"
	local tags_file="$out_dir/common-tags.txt"

	mkdir -p "$out_dir"
	find "$good_dir" -maxdepth 1 -type f -name '*.txt' -printf '%f\n' | sort >"$out_dir/good-tags.txt"
	find "$bad_dir" -maxdepth 1 -type f -name '*.txt' -printf '%f\n' | sort >"$out_dir/bad-tags.txt"
	comm -12 "$out_dir/good-tags.txt" "$out_dir/bad-tags.txt" >"$tags_file"

	{
		printf 'good_case=%s\n' "$good_dir"
		printf 'bad_case=%s\n' "$bad_dir"
		printf '\n[common_tags]\n'
		cat "$tags_file"
		printf '\n[tag_status]\n'
	} >"$summary"

	while IFS= read -r tag; do
		[ -n "$tag" ] || continue
		local diff_path="$out_dir/${tag%.txt}.diff"
		if diff -u "$good_dir/$tag" "$bad_dir/$tag" >"$diff_path"; then
			printf '%s=same\n' "${tag%.txt}" >>"$summary"
			rm -f "$diff_path"
		else
			printf '%s=differs\n' "${tag%.txt}" >>"$summary"
		fi
	done <"$tags_file"
}

main() {
	local good_snap_dir=""
	local bad_snap_dir=""

	parse_args "$@"
	check_prereqs
	ensure_output_dir

	run_case good "$GOOD_AUDIO_DEVICE" "$GOOD_VIDEO_DEVICE"
	run_case bad "$BAD_AUDIO_DEVICE" "$BAD_VIDEO_DEVICE"

	good_snap_dir="$OUTPUT_DIR/good/bar0-snaps"
	bad_snap_dir="$OUTPUT_DIR/bad/bar0-snaps"
	extract_snapshots "$OUTPUT_DIR/good/kernel.log" "$good_snap_dir"
	extract_snapshots "$OUTPUT_DIR/bad/kernel.log" "$bad_snap_dir"
	require_snapshots "$good_snap_dir" "good case"
	require_snapshots "$bad_snap_dir" "bad case"
	write_diff_report "$good_snap_dir" "$bad_snap_dir" "$OUTPUT_DIR/diffs"

	log "BAR0 snapshot diff summary: $OUTPUT_DIR/diffs/diff-summary.txt"
	log "Evidence directory: $OUTPUT_DIR"
}

main "$@"
