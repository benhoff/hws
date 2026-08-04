#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./hws_audio_lib.sh
. "$SCRIPT_DIR/hws_audio_lib.sh"

usage() {
	cat <<'EOF'
Usage: ./hws_audio_suspend_before_after_test.sh [options]

Run one supported HWS ALSA capture before suspend and one after resume, then
print a clear PASS/FAIL verdict. Evidence is saved under a timestamped output
directory.

Options:
  --audio-device hw:C,D       ALSA capture device. Default: hw:5,3.
  --pci-device BDF            PCI device for audio_reg_probe snapshots. Default: auto from ALSA card.
  --output-dir DIR            Evidence directory. Default: /tmp/hws-audio-before-after-<timestamp>.
  --duration N                Seconds per capture. Default: 5.
  --rate HZ                   Capture rate. Default: 48000.
  --format FORMAT             ALSA sample format. Default: S16_LE.
  --channels N                Channel count. Default: 2.
  --playback-target NAME      PipeWire/Pulse sink to play a test tone during each capture.
                              Use auto to detect NVIDIA HDMI. Default: disabled.
  --tone-frequency HZ         Generated playback tone frequency. Default: 1000.
  --playback-lead-seconds N   Start playback this many seconds before capture. Default: 2.
  --playback-extra-seconds N  Keep generated tone longer than capture by this many seconds. Default: 3.
  --min-percent N             Minimum expected payload percentage. Default: 90.
  --settle-seconds N          Delay after resume before after-capture. Default: 5.
  --resume-timeout N          Seconds to wait for PM suspend exit. Default: 180.
  --suspend-cmd CMD           Suspend command. Default: systemctl suspend.
  --auto-suspend              Run suspend command without prompting.
  --manual-suspend            Prompt, then run suspend command. Default.
  --skip-suspend              Do not suspend; run before and after captures back-to-back.
  --allow-silence             Do not fail if captured samples are all digital silence.
  --no-journal                Skip kernel journal collection.
  --help                      Show this help.

Examples:
  ./hws_audio_suspend_before_after_test.sh --audio-device hw:5,3
  ./hws_audio_suspend_before_after_test.sh --playback-target auto --audio-device hw:5,3
  ./hws_audio_suspend_before_after_test.sh --auto-suspend
  ./hws_audio_suspend_before_after_test.sh --skip-suspend --output-dir /tmp/hws-audio-check
EOF
}

AUDIO_DEVICE="hw:5,3"
PCI_DEVICE="auto"
OUTPUT_DIR=""
DURATION=5
RATE=48000
FORMAT="S16_LE"
CHANNELS=2
PLAYBACK_TARGET=""
TONE_FREQUENCY=1000
PLAYBACK_LEAD_SECONDS=2
PLAYBACK_EXTRA_SECONDS=3
MIN_PERCENT=90
SETTLE_SECONDS=5
RESUME_TIMEOUT=180
SUSPEND_CMD="systemctl suspend"
SUSPEND_MODE="manual"
ALLOW_SILENCE=0
COLLECT_JOURNAL=1

RUN_LOG=""
SUMMARY_TSV=""
JOURNAL_SINCE=""
PCM_INDEX=""
IDLE_INHIBITOR_PID=""
PLAYBACK_PID=""

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

log() {
	local msg=$*

	printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$msg" | tee -a "$RUN_LOG"
}

cleanup() {
	if [ -n "$PLAYBACK_PID" ]; then
		kill "$PLAYBACK_PID" >/dev/null 2>&1 || true
		wait "$PLAYBACK_PID" >/dev/null 2>&1 || true
	fi
	if [ -n "$IDLE_INHIBITOR_PID" ]; then
		kill "$IDLE_INHIBITOR_PID" >/dev/null 2>&1 || true
		wait "$IDLE_INHIBITOR_PID" >/dev/null 2>&1 || true
	fi
}

playback_tone_duration() {
	printf '%s\n' "$((DURATION + PLAYBACK_LEAD_SECONDS + PLAYBACK_EXTRA_SECONDS))"
}

stop_playback_source() {
	local playback_log=$1
	local rc

	if [ -z "$PLAYBACK_PID" ]; then
		return 0
	fi

	if kill -0 "$PLAYBACK_PID" >/dev/null 2>&1; then
		kill "$PLAYBACK_PID" >/dev/null 2>&1 || true
	fi
	set +e
	wait "$PLAYBACK_PID"
	rc=$?
	set -e
	printf 'exit_code=%s\n' "$rc" >>"$playback_log"
	PLAYBACK_PID=""
}

start_playback_source() {
	local phase=$1
	local phase_dir=$2
	local tone_wav="$phase_dir/playback-tone.wav"
	local ffmpeg_log="$phase_dir/playback-tone.ffmpeg.log"
	local playback_log="$phase_dir/playback.log"
	local tone_seconds

	if [ -z "$PLAYBACK_TARGET" ]; then
		return 0
	fi

	tone_seconds=$(playback_tone_duration)
	log "$phase: generating ${tone_seconds}s ${TONE_FREQUENCY}Hz tone for $PLAYBACK_TARGET"
	ffmpeg -nostdin -hide_banner -loglevel error \
		-f lavfi -i "sine=frequency=${TONE_FREQUENCY}:sample_rate=${RATE}:duration=${tone_seconds}" \
		-ac "$CHANNELS" -c:a pcm_s16le "$tone_wav" >"$ffmpeg_log" 2>&1

	log "$phase: pw-play --target $PLAYBACK_TARGET $tone_wav"
	pw-play --target "$PLAYBACK_TARGET" "$tone_wav" >"$playback_log" 2>&1 &
	PLAYBACK_PID=$!
	if [ "$PLAYBACK_LEAD_SECONDS" -gt 0 ]; then
		sleep "$PLAYBACK_LEAD_SECONDS"
	fi
}

start_idle_inhibitor() {
	if ! hws_have_cmd systemd-inhibit || ! hws_have_cmd sleep; then
		return 0
	fi

	systemd-inhibit --what=idle --mode=block --who=hws-audio-test \
		--why="HWS audio before/after suspend test" sleep infinity &
	IDLE_INHIBITOR_PID=$!
}

record_result() {
	local phase=$1
	local status=$2
	local detail=$3
	local artifact=$4

	printf '%s\t%s\t%s\t%s\n' "$phase" "$status" "$detail" "$artifact" >>"$SUMMARY_TSV"
	printf '%-8s %-5s %s\n' "$phase" "$status" "$detail" | tee -a "$RUN_LOG"
}

alsa_card_index() {
	local dev=$1
	local card

	card=${dev#*:}
	card=${card%%,*}
	[[ "$card" =~ ^[0-9]+$ ]] || return 1
	printf '%s\n' "$((10#$card))"
}

alsa_pcm_index() {
	local dev=$1
	local pcm

	pcm=${dev##*,}
	pcm=${pcm%%:*}
	[[ "$pcm" =~ ^[0-9]+$ ]] || return 1
	printf '%s\n' "$((10#$pcm))"
}

detect_pci_device() {
	local card
	local path

	if [ "$PCI_DEVICE" != "auto" ]; then
		printf '%s\n' "$PCI_DEVICE"
		return 0
	fi

	card=$(alsa_card_index "$AUDIO_DEVICE") || return 1
	path=$(readlink -f "/sys/class/sound/card${card}/device" 2>/dev/null || true)
	if [ -z "$path" ]; then
		return 1
	fi
	basename "$path"
}

format_bits() {
	case "$1" in
	S8|U8) printf '8\n' ;;
	S16_LE|S16_BE|U16_LE|U16_BE) printf '16\n' ;;
	S24_LE|S24_BE|U24_LE|U24_BE) printf '24\n' ;;
	S32_LE|S32_BE|U32_LE|U32_BE|FLOAT_LE|FLOAT_BE) printf '32\n' ;;
	*) printf '16\n' ;;
	esac
}

format_codec() {
	case "$1" in
	S16_LE) printf 'pcm_s16le\n' ;;
	S16_BE) printf 'pcm_s16be\n' ;;
	S24_LE) printf 'pcm_s24le\n' ;;
	S24_BE) printf 'pcm_s24be\n' ;;
	S32_LE) printf 'pcm_s32le\n' ;;
	S32_BE) printf 'pcm_s32be\n' ;;
	*) printf 'unknown\n' ;;
	esac
}

capture_audio_context() {
	local dir=$1

	mkdir -p "$dir"
	hws_write_audio_context "$dir" || true
	if [ "$PCI_DEVICE" != "auto" ] && [ -n "$PCI_DEVICE" ]; then
		printf '%s\n' "$PCI_DEVICE" >"$dir/pci-device.txt"
	fi
}

snapshot_audio_regs() {
	local phase_dir=$1
	local pci=$2
	local sysfs="/sys/bus/pci/devices/$pci"
	local attr

	mkdir -p "$phase_dir"
	if [ -z "$pci" ] || [ ! -d "$sysfs" ]; then
		printf 'pci sysfs path unavailable: %s\n' "${sysfs:-unknown}" >"$phase_dir/audio_reg_probe.missing"
		return 0
	fi

	for attr in audio_reg_probe audio_reg_probe_run audio_reg_probe_slots audio_reg_probe_remap; do
		if [ -r "$sysfs/$attr" ]; then
			cat "$sysfs/$attr" >"$phase_dir/$attr.txt" 2>"$phase_dir/$attr.err" || true
		else
			printf 'missing or unreadable: %s/%s\n' "$sysfs" "$attr" >"$phase_dir/$attr.missing"
		fi
	done
}

extract_counter() {
	local file=$1
	local key=$2
	local line

	[ -n "$PCM_INDEX" ] || return 1
	[ -f "$file" ] || return 1
	line=$(grep -E "^ch${PCM_INDEX}[.]audio_base=" "$file" | tail -n 1 || true)
	[ -n "$line" ] || return 1
	printf '%s\n' "$line" | sed -n "s/.* ${key}=\\([0-9][0-9]*\\).*/\\1/p"
}

analyze_wav() {
	local wav=$1
	local arecord_log=$2
	local out=$3
	local capture_rc=$4
	local size=0
	local data_bytes=0
	local bits
	local expected_bytes
	local min_bytes
	local codec=""
	local sample_rate=""
	local file_channels=""
	local expected_codec
	local max_volume=""
	local header_ok=0
	local format_ok=0
	local rate_ok=0
	local channels_ok=0
	local payload_ok=0
	local nonzero_ok=0
	local xrun_ok=1
	local status="FAIL"
	local reason=""

	bits=$(format_bits "$FORMAT")
	expected_bytes=$((DURATION * RATE * CHANNELS * bits / 8))
	min_bytes=$((expected_bytes * MIN_PERCENT / 100))

	if [ -f "$wav" ]; then
		size=$(stat -c %s "$wav" 2>/dev/null || printf '0')
	fi
	if [ "$size" -gt 44 ]; then
		data_bytes=$((size - 44))
	fi
	if [ "$data_bytes" -ge "$min_bytes" ]; then
		payload_ok=1
	fi

	if ffprobe -v error -select_streams a:0 -show_entries stream=codec_name \
		-of default=noprint_wrappers=1:nokey=1 "$wav" >/dev/null 2>&1; then
		header_ok=1
		codec=$(ffprobe -v error -select_streams a:0 -show_entries stream=codec_name \
			-of default=noprint_wrappers=1:nokey=1 "$wav" 2>/dev/null | head -n 1)
		sample_rate=$(ffprobe -v error -select_streams a:0 -show_entries stream=sample_rate \
			-of default=noprint_wrappers=1:nokey=1 "$wav" 2>/dev/null | head -n 1)
		file_channels=$(ffprobe -v error -select_streams a:0 -show_entries stream=channels \
			-of default=noprint_wrappers=1:nokey=1 "$wav" 2>/dev/null | head -n 1)
	fi

	expected_codec=$(format_codec "$FORMAT")
	[ "$codec" = "$expected_codec" ] && format_ok=1
	[ "$sample_rate" = "$RATE" ] && rate_ok=1
	[ "$file_channels" = "$CHANNELS" ] && channels_ok=1

	if [ -f "$wav" ]; then
		ffmpeg -nostdin -hide_banner -i "$wav" -af volumedetect -f null - \
			>/dev/null 2>"$out.volumedetect.log" || true
		max_volume=$(awk -F': ' '/max_volume/ { print $2 }' "$out.volumedetect.log" | tail -n 1)
		if [ -n "$max_volume" ] && [ "$max_volume" != "-inf dB" ]; then
			nonzero_ok=1
		fi
	fi

	if grep -Eiq '(^|[^a-z])(xrun|overrun|underrun)([^a-z]|$)' "$arecord_log"; then
		xrun_ok=0
	fi

	if [ "$capture_rc" -ne 0 ]; then
		reason="arecord_rc=$capture_rc"
	elif [ "$header_ok" -ne 1 ]; then
		reason="missing_or_invalid_wav_header"
	elif [ "$payload_ok" -ne 1 ]; then
		reason="payload_too_small"
	elif [ "$rate_ok" -ne 1 ] || [ "$channels_ok" -ne 1 ] || [ "$format_ok" -ne 1 ]; then
		reason="format_mismatch"
	elif [ "$xrun_ok" -ne 1 ]; then
		reason="xrun_reported"
	elif [ "$ALLOW_SILENCE" -ne 1 ] && [ "$nonzero_ok" -ne 1 ]; then
		reason="silent_capture"
	else
		status="PASS"
		reason="ok"
	fi

	{
		printf 'status=%s\n' "$status"
		printf 'reason=%s\n' "$reason"
		printf 'capture_rc=%s\n' "$capture_rc"
		printf 'size_bytes=%s\n' "$size"
		printf 'actual_data_bytes=%s\n' "$data_bytes"
		printf 'expected_data_bytes=%s\n' "$expected_bytes"
		printf 'minimum_data_bytes=%s\n' "$min_bytes"
		printf 'codec=%s\n' "$codec"
		printf 'sample_rate=%s\n' "$sample_rate"
		printf 'channels=%s\n' "$file_channels"
		printf 'max_volume=%s\n' "$max_volume"
		printf 'header_ok=%s\n' "$header_ok"
		printf 'payload_ok=%s\n' "$payload_ok"
		printf 'rate_ok=%s\n' "$rate_ok"
		printf 'channels_ok=%s\n' "$channels_ok"
		printf 'format_ok=%s\n' "$format_ok"
		printf 'nonzero_ok=%s\n' "$nonzero_ok"
		printf 'xrun_ok=%s\n' "$xrun_ok"
	} >"$out"

	printf '%s\n' "$status"
}

run_capture_phase() {
	local phase=$1
	local pci=$2
	local phase_dir="$OUTPUT_DIR/$phase"
	local wav="$phase_dir/capture.wav"
	local arecord_log="$phase_dir/arecord.log"
	local analysis="$phase_dir/analysis.txt"
	local before_regs="$phase_dir/regs-before"
	local after_regs="$phase_dir/regs-after"
	local rc=0
	local status
	local reason
	local data_bytes
	local max_volume
	local irq_count=""
	local delivered_count=""
	local counter_detail=""

	mkdir -p "$phase_dir"
	start_playback_source "$phase" "$phase_dir"
	snapshot_audio_regs "$before_regs" "$pci"

	log "$phase: arecord -D $AUDIO_DEVICE -f $FORMAT -r $RATE -c $CHANNELS -d $DURATION"
	set +e
	arecord -D "$AUDIO_DEVICE" -f "$FORMAT" -r "$RATE" -c "$CHANNELS" \
		-d "$DURATION" "$wav" >"$arecord_log" 2>&1
	rc=$?
	set -e
	printf 'exit_code=%s\n' "$rc" >>"$arecord_log"
	stop_playback_source "$phase_dir/playback.log"

	status=$(analyze_wav "$wav" "$arecord_log" "$analysis" "$rc")
	snapshot_audio_regs "$after_regs" "$pci"

	reason=$(sed -n 's/^reason=//p' "$analysis" | tail -n 1)
	data_bytes=$(sed -n 's/^actual_data_bytes=//p' "$analysis" | tail -n 1)
	max_volume=$(sed -n 's/^max_volume=//p' "$analysis" | tail -n 1)

	irq_count=$(extract_counter "$after_regs/audio_reg_probe.txt" irq || true)
	delivered_count=$(extract_counter "$after_regs/audio_reg_probe.txt" delivered || true)
	if [ -n "$irq_count" ] || [ -n "$delivered_count" ]; then
		counter_detail=" irq=${irq_count:-unknown} delivered=${delivered_count:-unknown}"
		if [ "$status" = "PASS" ] && [ "${delivered_count:-1}" = "0" ]; then
			status="FAIL"
			reason="no_audio_delivery_counter"
			printf 'status=%s\nreason=%s\n' "$status" "$reason" >>"$analysis"
		fi
	fi

	record_result "$phase" "$status" \
		"reason=$reason data=$data_bytes max_volume=${max_volume:-unknown}${counter_detail}" \
		"$phase_dir"
	printf '%s\n' "$status" >"$phase_dir/status"
	printf '%s\n' "$status"
}

collect_journal() {
	local out=$1

	if [ "$COLLECT_JOURNAL" -ne 1 ]; then
		return 0
	fi
	if ! hws_have_cmd journalctl; then
		printf 'journalctl unavailable\n' >"$out"
		return 0
	fi
	journalctl --no-pager -k --since "$JOURNAL_SINCE" >"$out" 2>&1 || true
	grep -E 'HwsCapture|hws|global-irq|audio-trace|audio-snap|irq-fabric|arecord|ALSA' \
		"$out" >"${out%.log}.filtered.log" 2>/dev/null || true
}

pm_suspend_exit_count() {
	if ! hws_have_cmd journalctl; then
		return 1
	fi

	journalctl --no-pager -k -b 0 2>/dev/null | grep -c 'PM: suspend exit' || true
}

wait_for_suspend_exit() {
	local before_count=$1
	local deadline
	local count

	deadline=$(($(date +%s) + RESUME_TIMEOUT))
	log "waiting up to ${RESUME_TIMEOUT}s for kernel PM: suspend exit"
	while [ "$(date +%s)" -le "$deadline" ]; do
		count=$(pm_suspend_exit_count || true)
		if [ -n "$count" ] && [ "$count" -gt "$before_count" ]; then
			log "kernel PM suspend exit observed"
			return 0
		fi
		sleep 1
	done

	return 1
}

run_suspend_command() {
	local before_count=""

	before_count=$(pm_suspend_exit_count || true)
	log "running suspend command: $SUSPEND_CMD"
	$SUSPEND_CMD

	if [ -z "$before_count" ]; then
		log "suspend command returned; journal wait unavailable"
		return 0
	fi
	if ! wait_for_suspend_exit "$before_count"; then
		die "timed out waiting for kernel PM: suspend exit"
	fi
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--audio-device)
			AUDIO_DEVICE=$2
			shift 2
			;;
		--pci-device)
			PCI_DEVICE=$2
			shift 2
			;;
		--output-dir)
			OUTPUT_DIR=$2
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
		--playback-target)
			PLAYBACK_TARGET=$2
			shift 2
			;;
		--tone-frequency)
			TONE_FREQUENCY=$2
			shift 2
			;;
		--playback-lead-seconds)
			PLAYBACK_LEAD_SECONDS=$2
			shift 2
			;;
		--playback-extra-seconds)
			PLAYBACK_EXTRA_SECONDS=$2
			shift 2
			;;
		--min-percent)
			MIN_PERCENT=$2
			shift 2
			;;
		--settle-seconds)
			SETTLE_SECONDS=$2
			shift 2
			;;
		--resume-timeout)
			RESUME_TIMEOUT=$2
			shift 2
			;;
		--suspend-cmd)
			SUSPEND_CMD=$2
			shift 2
			;;
		--auto-suspend)
			SUSPEND_MODE="auto"
			shift
			;;
		--manual-suspend)
			SUSPEND_MODE="manual"
			shift
			;;
		--skip-suspend)
			SUSPEND_MODE="skip"
			shift
			;;
		--allow-silence)
			ALLOW_SILENCE=1
			shift
			;;
		--no-journal)
			COLLECT_JOURNAL=0
			shift
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			die "unknown option: $1"
			;;
		esac
	done
}

main() {
	local pci=""
	local before_status
	local after_status
	local overall="FAIL"
	local timestamp

	parse_args "$@"
	hws_require_cmds arecord ffprobe ffmpeg awk sed grep stat date || exit 1

	[[ "$DURATION" =~ ^[0-9]+$ ]] || die "--duration must be an integer"
	[[ "$RATE" =~ ^[0-9]+$ ]] || die "--rate must be an integer"
	[[ "$CHANNELS" =~ ^[0-9]+$ ]] || die "--channels must be an integer"
	[[ "$TONE_FREQUENCY" =~ ^[0-9]+$ ]] || die "--tone-frequency must be an integer"
	[[ "$PLAYBACK_LEAD_SECONDS" =~ ^[0-9]+$ ]] || die "--playback-lead-seconds must be an integer"
	[[ "$PLAYBACK_EXTRA_SECONDS" =~ ^[0-9]+$ ]] || die "--playback-extra-seconds must be an integer"
	[[ "$MIN_PERCENT" =~ ^[0-9]+$ ]] || die "--min-percent must be an integer"
	[[ "$SETTLE_SECONDS" =~ ^[0-9]+$ ]] || die "--settle-seconds must be an integer"
	[[ "$RESUME_TIMEOUT" =~ ^[0-9]+$ ]] || die "--resume-timeout must be an integer"
	if [ -n "$PLAYBACK_TARGET" ]; then
		hws_require_cmds pw-play pactl || exit 1
		PLAYBACK_TARGET=$(hws_resolve_playback_target "$PLAYBACK_TARGET")
	fi

	timestamp=$(hws_timestamp)
	if [ -z "$OUTPUT_DIR" ]; then
		OUTPUT_DIR="/tmp/hws-audio-before-after-$timestamp"
	fi
	mkdir -p "$OUTPUT_DIR"
	RUN_LOG="$OUTPUT_DIR/run.log"
	SUMMARY_TSV="$OUTPUT_DIR/summary.tsv"
	printf 'phase\tstatus\tdetail\tartifact\n' >"$SUMMARY_TSV"
	JOURNAL_SINCE=$(date '+%Y-%m-%d %H:%M:%S')
	PCM_INDEX=$(alsa_pcm_index "$AUDIO_DEVICE" || true)

	pci=$(detect_pci_device || true)
	if [ -n "$pci" ]; then
		PCI_DEVICE=$pci
	else
		PCI_DEVICE=""
		log "warning: could not detect PCI device for $AUDIO_DEVICE; sysfs snapshots will be skipped"
	fi

	log "output_dir=$OUTPUT_DIR"
	log "audio_device=$AUDIO_DEVICE pci_device=${PCI_DEVICE:-unknown} pcm_index=${PCM_INDEX:-unknown}"
	log "format=$FORMAT rate=$RATE channels=$CHANNELS duration=${DURATION}s"
	if [ -n "$PLAYBACK_TARGET" ]; then
		log "playback_target=$PLAYBACK_TARGET tone=${TONE_FREQUENCY}Hz lead=${PLAYBACK_LEAD_SECONDS}s extra=${PLAYBACK_EXTRA_SECONDS}s"
	else
		log "playback_target=disabled; capture depends on an external HDMI audio source"
	fi
	trap cleanup EXIT
	start_idle_inhibitor
	capture_audio_context "$OUTPUT_DIR/context"

	before_status=$(run_capture_phase "before" "$PCI_DEVICE" | tail -n 1)
	if [ "$before_status" != "PASS" ] && [ "$SUSPEND_MODE" != "skip" ]; then
		log "before capture failed; skipping suspend command"
		SUSPEND_MODE="skip"
	fi

	case "$SUSPEND_MODE" in
	auto)
		run_suspend_command
		;;
	manual)
		if [ -t 0 ]; then
			printf '\nBefore capture is complete. Press Enter to run: %s\n' "$SUSPEND_CMD"
			printf 'After the machine resumes, the script will wait %ss and run the after capture.\n' "$SETTLE_SECONDS"
			read -r _
			run_suspend_command
		else
			die "manual suspend requires a TTY; use --auto-suspend or --skip-suspend"
		fi
		;;
	skip)
		log "skipping suspend step"
		;;
	*)
		die "invalid suspend mode: $SUSPEND_MODE"
		;;
	esac

	if [ "$SUSPEND_MODE" != "skip" ] && [ "$SETTLE_SECONDS" -gt 0 ]; then
		log "resumed; waiting ${SETTLE_SECONDS}s before after capture"
		sleep "$SETTLE_SECONDS"
	fi

	after_status=$(run_capture_phase "after" "$PCI_DEVICE" | tail -n 1)
	collect_journal "$OUTPUT_DIR/kernel-journal.log"

	if [ "$before_status" = "PASS" ] && [ "$after_status" = "PASS" ]; then
		overall="PASS"
	elif [ "$before_status" != "PASS" ]; then
		overall="FAIL_BEFORE"
	else
		overall="FAIL_AFTER"
	fi

	{
		printf 'overall=%s\n' "$overall"
		printf 'before=%s\n' "$before_status"
		printf 'after=%s\n' "$after_status"
		printf 'output_dir=%s\n' "$OUTPUT_DIR"
		printf 'summary_tsv=%s\n' "$SUMMARY_TSV"
	} >"$OUTPUT_DIR/final-verdict.txt"

	printf '\n'
	printf 'OVERALL: %s\n' "$overall" | tee -a "$RUN_LOG"
	printf 'before:  %s\n' "$before_status" | tee -a "$RUN_LOG"
	printf 'after:   %s\n' "$after_status" | tee -a "$RUN_LOG"
	printf 'evidence: %s\n' "$OUTPUT_DIR" | tee -a "$RUN_LOG"

	if [ "$overall" = "PASS" ]; then
		printf 'Result: capture worked before and after the suspend boundary.\n'
		exit 0
	fi

	if [ "$overall" = "FAIL_BEFORE" ]; then
		printf 'Result: before capture failed, so suspend/resume is not the first problem to debug.\n'
	else
		printf 'Result: before capture passed but after capture failed; this reproduces the resume bug.\n'
	fi
	exit 1
}

main "$@"
