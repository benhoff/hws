#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROBE_SCRIPT="$SCRIPT_DIR/python/bar0_audio_reg_probe.py"

usage() {
	cat <<'EOF'
Usage: ./hws_audio_video_reg_snapshot_test.sh [options]

Run a non-invasive BAR0 register snapshot test around audio capture and video
capture startup. The test records:

  1. idle register state
  2. register state while ALSA audio capture is running
  3. register state shortly after V4L2 video capture starts
  4. register state after video exits

Options:
  --pci-bdf BDF          PCI device BDF. Default: 0000:17:00.0
  --channel N            Target audio channel for the slot verdict. Default: 3
  --snapshot-channels L  Comma-separated channels to snapshot. Default: 0,1,2,3
  --audio-device DEV     ALSA capture device. Default: hw:5,3
  --video-device DEV     V4L2 video device. Default: /dev/video3
  --video-buffers N      V4L2 mmap buffer count. Default: v4l2-ctl default
  --audio-duration SEC   arecord duration. Default: 60
  --video-count N        v4l2-ctl stream frame count. Default: 300
  --audio-warmup SEC     Delay before audio-running snapshot. Default: 2
  --video-warmup SEC     Delay after video start before snapshot. Default: 2
  --bar0-path PATH       Explicit BAR0 source for snapshots
  --output-dir DIR       Evidence directory. Default: /tmp timestamp dir
  --help                 Show this help.
EOF
}

timestamp() {
	date '+%Y%m%d-%H%M%S'
}

require_cmd() {
	local cmd=$1

	if ! command -v "$cmd" >/dev/null 2>&1; then
		printf 'missing required command: %s\n' "$cmd" >&2
		exit 127
	fi
}

PCI_BDF="0000:17:00.0"
CHANNEL=3
SNAPSHOT_CHANNELS="0,1,2,3"
AUDIO_DEVICE="hw:5,3"
VIDEO_DEVICE="/dev/video3"
VIDEO_BUFFERS=""
AUDIO_DURATION=60
VIDEO_COUNT=300
AUDIO_WARMUP=2
VIDEO_WARMUP=2
BAR0_PATH=""
OUTPUT_DIR=""

while [ $# -gt 0 ]; do
	case "$1" in
	--pci-bdf)
		PCI_BDF=$2
		shift 2
		;;
	--channel)
		CHANNEL=$2
		shift 2
		;;
	--snapshot-channels)
		SNAPSHOT_CHANNELS=$2
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
	--video-buffers)
		VIDEO_BUFFERS=$2
		shift 2
		;;
	--audio-duration)
		AUDIO_DURATION=$2
		shift 2
		;;
	--video-count)
		VIDEO_COUNT=$2
		shift 2
		;;
	--audio-warmup)
		AUDIO_WARMUP=$2
		shift 2
		;;
	--video-warmup)
		VIDEO_WARMUP=$2
		shift 2
		;;
	--bar0-path)
		BAR0_PATH=$2
		shift 2
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
		printf 'unknown option: %s\n' "$1" >&2
		usage >&2
		exit 2
		;;
	esac
done

if [ -z "$OUTPUT_DIR" ]; then
	OUTPUT_DIR="/tmp/hws-audio-video-reg-snapshot-$(timestamp)"
fi

require_cmd arecord
require_cmd awk
require_cmd date
require_cmd mkdir
require_cmd python3
require_cmd tee
require_cmd v4l2-ctl

if [ ! -f "$PROBE_SCRIPT" ]; then
	printf 'missing BAR0 probe script: %s\n' "$PROBE_SCRIPT" >&2
	exit 1
fi

mkdir -p "$OUTPUT_DIR"

if [ "$(id -u)" -eq 0 ]; then
	PROBE_CMD=(python3 "$PROBE_SCRIPT")
else
	require_cmd sudo
	PROBE_CMD=(sudo python3 "$PROBE_SCRIPT")
fi

AUDIO_PID=""
VIDEO_PID=""

cleanup() {
	local pid

	for pid in "$VIDEO_PID" "$AUDIO_PID"; do
		if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
			kill "$pid" >/dev/null 2>&1 || true
			wait "$pid" >/dev/null 2>&1 || true
		fi
	done
}
trap cleanup EXIT

run_probe() {
	local label=$1
	local dir="$OUTPUT_DIR/$label"
	local path_file="$dir/probe-path.txt"
	local args=(
		--pci-bdf "$PCI_BDF"
		--channels "$SNAPSHOT_CHANNELS"
		--output-dir "$dir"
	)

	mkdir -p "$dir"
	printf '[%s] snapshot %s\n' "$(date '+%H:%M:%S')" "$label" | tee -a "$OUTPUT_DIR/test.log"
	if [ -n "$BAR0_PATH" ]; then
		args+=(--bar0-path "$BAR0_PATH")
	fi
	"${PROBE_CMD[@]}" "${args[@]}" | tee "$path_file"
}

extract_field() {
	local summary=$1
	local field=$2

	awk -F= -v key="$field" '$1 == key { print $2; exit }' "$summary"
}

channel_list() {
	printf '%s\n' "$SNAPSHOT_CHANNELS" | tr ',' ' '
}

slot_pair() {
	local summary=$1
	local ch=$2
	local prefix=$3
	local hi lo

	hi=$(extract_field "$summary" "ch${ch}.${prefix}_hi")
	lo=$(extract_field "$summary" "ch${ch}.${prefix}_lo")
	printf '%s:%s' "$hi" "$lo"
}

bool_text() {
	if [ "$1" = "$2" ]; then
		printf 'no'
	else
		printf 'yes'
	fi
}

hex_bit_set() {
	local value=$1
	local bit=$2

	if [ -z "$value" ]; then
		printf 'unknown'
		return
	fi

	if (( (value & (1 << bit)) != 0 )); then
		printf 'yes'
	else
		printf 'no'
	fi
}

write_comparison() {
	local report="$OUTPUT_DIR/register-comparison.tsv"
	local verdict="$OUTPUT_DIR/remap-slot-verdict.tsv"
	local idle="$OUTPUT_DIR/idle/summary.txt"
	local audio="$OUTPUT_DIR/audio_running/summary.txt"
	local video="$OUTPUT_DIR/video_running/summary.txt"
	local after="$OUTPUT_DIR/after_video/summary.txt"
	local field idle_v audio_v video_v after_v changed
	local ch ch_prefix
	local global_fields=(
		"SYS_STATUS"
		"ACTIVE_STATUS"
		"VCAP_ENABLE"
		"ACAP_ENABLE"
		"INT_STATUS"
	)

	printf 'field\tidle\taudio_running\tvideo_running\tafter_video\tchanged_audio_to_video\n' >"$report"
	for field in "${global_fields[@]}"; do
		idle_v=$(extract_field "$idle" "$field")
		audio_v=$(extract_field "$audio" "$field")
		video_v=$(extract_field "$video" "$field")
		after_v=$(extract_field "$after" "$field")
		if [ "$audio_v" != "$video_v" ]; then
			changed=yes
		else
			changed=no
		fi
		printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$field" "$idle_v" "$audio_v" "$video_v" "$after_v" "$changed" >>"$report"
	done

	for ch in $(channel_list); do
		ch_prefix="ch${ch}"
		for field in \
			"${ch_prefix}.video_base" \
			"${ch_prefix}.audio_base" \
			"${ch_prefix}.shared_hi" \
			"${ch_prefix}.shared_lo" \
			"${ch_prefix}.candidate8_hi" \
			"${ch_prefix}.candidate8_lo" \
			"${ch_prefix}.vbuf_toggle" \
			"${ch_prefix}.abuf_toggle"; do
			idle_v=$(extract_field "$idle" "$field")
			audio_v=$(extract_field "$audio" "$field")
			video_v=$(extract_field "$video" "$field")
			after_v=$(extract_field "$after" "$field")
			if [ "$audio_v" != "$video_v" ]; then
				changed=yes
			else
				changed=no
			fi
			printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
				"$field" "$idle_v" "$audio_v" "$video_v" "$after_v" "$changed" >>"$report"
		done
	done

	write_slot_verdict "$verdict" "$audio" "$video" "$after"
}

write_slot_verdict() {
	local verdict=$1
	local audio=$2
	local video=$3
	local after=$4
	local ch shared_audio shared_video shared_after candidate8_audio candidate8_video
	local candidate8_after audio_base_audio audio_base_video video_base_audio
	local video_base_video acap_video vcap_video slot_diff_video
	local shared_changed candidate8_changed audio_base_changed video_base_changed
	local acap_enabled vcap_enabled result

	printf 'channel\tshared_audio\tshared_video\tshared_after\tcandidate8_audio\tcandidate8_video\tcandidate8_after\tvideo_base_audio\tvideo_base_video\taudio_base_audio\taudio_base_video\tshared_changed_audio_to_video\tcandidate8_changed_audio_to_video\tslots_differ_at_video\tvideo_base_changed_audio_to_video\taudio_base_changed_audio_to_video\tacap_enabled_at_video\tvcap_enabled_at_video\tresult\n' >"$verdict"

	for ch in $(channel_list); do
		shared_audio=$(slot_pair "$audio" "$ch" shared)
		shared_video=$(slot_pair "$video" "$ch" shared)
		shared_after=$(slot_pair "$after" "$ch" shared)
		candidate8_audio=$(slot_pair "$audio" "$ch" candidate8)
		candidate8_video=$(slot_pair "$video" "$ch" candidate8)
		candidate8_after=$(slot_pair "$after" "$ch" candidate8)
		video_base_audio=$(extract_field "$audio" "ch${ch}.video_base")
		video_base_video=$(extract_field "$video" "ch${ch}.video_base")
		audio_base_audio=$(extract_field "$audio" "ch${ch}.audio_base")
		audio_base_video=$(extract_field "$video" "ch${ch}.audio_base")
		acap_video=$(extract_field "$video" "ACAP_ENABLE")
		vcap_video=$(extract_field "$video" "VCAP_ENABLE")

		shared_changed=$(bool_text "$shared_audio" "$shared_video")
		candidate8_changed=$(bool_text "$candidate8_audio" "$candidate8_video")
		slot_diff_video=$(bool_text "$shared_video" "$candidate8_video")
		video_base_changed=$(bool_text "$video_base_audio" "$video_base_video")
		audio_base_changed=$(bool_text "$audio_base_audio" "$audio_base_video")
		acap_enabled=$(hex_bit_set "$acap_video" "$ch")
		vcap_enabled=$(hex_bit_set "$vcap_video" "$ch")

		if [ "$ch" = "$CHANNEL" ] &&
		   [ "$shared_changed" = "yes" ] &&
		   [ "$slot_diff_video" = "yes" ] &&
		   [ "$candidate8_changed" = "no" ] &&
		   [ "$audio_base_changed" = "no" ] &&
		   [ "$acap_enabled" = "yes" ] &&
		   [ "${AUDIO_RC:-}" = "0" ]; then
			result="supports_independent_candidate8_bank"
		elif [ "$ch" = "$CHANNEL" ] &&
		     [ "$shared_changed" = "yes" ] &&
		     [ "$slot_diff_video" = "yes" ] &&
		     [ "${AUDIO_RC:-}" != "0" ]; then
			result="supports_or_suspects_audio_slot_ch"
		elif [ "$ch" = "$CHANNEL" ] &&
		     [ "$shared_changed" = "no" ] &&
		     [ "$video_base_changed" = "yes" ]; then
			result="inconclusive_video_base_changed_same_remap_page"
		elif [ "$ch" = "$CHANNEL" ] &&
		     [ "$shared_changed" = "no" ]; then
			result="inconclusive_target_shared_slot_not_reprogrammed"
		elif [ "$ch" = "$CHANNEL" ] &&
		     [ "$slot_diff_video" = "no" ]; then
			result="inconclusive_target_slots_same_at_video"
		else
			result="-"
		fi

		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$ch" "$shared_audio" "$shared_video" "$shared_after" \
			"$candidate8_audio" "$candidate8_video" "$candidate8_after" \
			"$video_base_audio" "$video_base_video" \
			"$audio_base_audio" "$audio_base_video" \
			"$shared_changed" "$candidate8_changed" "$slot_diff_video" \
			"$video_base_changed" "$audio_base_changed" \
			"$acap_enabled" "$vcap_enabled" "$result" >>"$verdict"
	done
}

{
	printf 'pci_bdf=%s\n' "$PCI_BDF"
	printf 'channel=%s\n' "$CHANNEL"
	printf 'snapshot_channels=%s\n' "$SNAPSHOT_CHANNELS"
	printf 'audio_device=%s\n' "$AUDIO_DEVICE"
	printf 'video_device=%s\n' "$VIDEO_DEVICE"
	printf 'video_buffers=%s\n' "$VIDEO_BUFFERS"
	printf 'audio_duration=%s\n' "$AUDIO_DURATION"
	printf 'video_count=%s\n' "$VIDEO_COUNT"
	printf 'audio_warmup=%s\n' "$AUDIO_WARMUP"
	printf 'video_warmup=%s\n' "$VIDEO_WARMUP"
	printf 'bar0_path=%s\n' "$BAR0_PATH"
	printf 'output_dir=%s\n' "$OUTPUT_DIR"
} >"$OUTPUT_DIR/test-summary.txt"

printf 'output_dir=%s\n' "$OUTPUT_DIR"

run_probe idle

printf '[%s] starting audio capture\n' "$(date '+%H:%M:%S')" | tee -a "$OUTPUT_DIR/test.log"
arecord -D "$AUDIO_DEVICE" -f S16_LE -r 48000 -c 2 -d "$AUDIO_DURATION" \
	"$OUTPUT_DIR/audio.wav" >"$OUTPUT_DIR/audio.arecord.log" 2>&1 &
AUDIO_PID=$!

sleep "$AUDIO_WARMUP"

AUDIO_EARLY_RC=""
if ! kill -0 "$AUDIO_PID" >/dev/null 2>&1; then
	set +e
	wait "$AUDIO_PID"
	AUDIO_EARLY_RC=$?
	set -e
	AUDIO_PID=""
	printf 'audio exited before video start, rc=%s\n' "$AUDIO_EARLY_RC" | tee -a "$OUTPUT_DIR/test.log"
fi

run_probe audio_running

printf '[%s] starting video capture\n' "$(date '+%H:%M:%S')" | tee -a "$OUTPUT_DIR/test.log"
VIDEO_ARGS=(-d "$VIDEO_DEVICE" --stream-count="$VIDEO_COUNT" --stream-to=/dev/null)
if [ -n "$VIDEO_BUFFERS" ]; then
	VIDEO_ARGS+=(--stream-mmap="$VIDEO_BUFFERS")
else
	VIDEO_ARGS+=(--stream-mmap)
fi
v4l2-ctl "${VIDEO_ARGS[@]}" \
	>"$OUTPUT_DIR/video.v4l2.log" 2>&1 &
VIDEO_PID=$!

sleep "$VIDEO_WARMUP"
run_probe video_running

set +e
wait "$VIDEO_PID"
VIDEO_RC=$?
VIDEO_PID=""
set -e
printf 'video_rc=%s\n' "$VIDEO_RC" | tee -a "$OUTPUT_DIR/test.log"

run_probe after_video

if [ -n "$AUDIO_PID" ]; then
	set +e
	wait "$AUDIO_PID"
	AUDIO_RC=$?
	AUDIO_PID=""
	set -e
else
	AUDIO_RC=$AUDIO_EARLY_RC
fi
printf 'audio_rc=%s\n' "$AUDIO_RC" | tee -a "$OUTPUT_DIR/test.log"

{
	printf 'audio_rc=%s\n' "$AUDIO_RC"
	printf 'video_rc=%s\n' "$VIDEO_RC"
} >>"$OUTPUT_DIR/test-summary.txt"

write_comparison

printf 'comparison=%s/register-comparison.tsv\n' "$OUTPUT_DIR"
printf 'verdict=%s/remap-slot-verdict.tsv\n' "$OUTPUT_DIR"
printf 'summary=%s/test-summary.txt\n' "$OUTPUT_DIR"

if [ "$AUDIO_RC" != "0" ] || [ "$VIDEO_RC" != "0" ]; then
	exit 1
fi
