#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: ./test_hdmi_output_loop.sh [options]

Drive a host HDMI playback sink with a generated tone while capturing the
matching HwsCapture audio/video inputs. This does not "feed audio into
/dev/video3" directly; it sends audio to the upstream GPU HDMI output that is
physically cabled into the capture card.

Defaults:
  --audio-device hw:5,3
  --video-device /dev/video3
  --playback-target auto-detect first HDMI sink
  --xrandr-output HDMI-A-1
  --duration 8
  --tone-frequency 1000

Options:
  --audio-device hw:CARD,DEV   ALSA capture device to record from.
  --capture-backend NAME       Capture backend: alsa, pipewire, or sample-bank. Default: alsa.
  --debugfs-dir DIR            HWS debugfs dir for sample-bank backend. Default: auto.
  --sample-limit N             sample-bank packet limit. Default: 100.
  --sample-threshold N         sample-bank peak threshold. Default: 256.
  --dump-sample-bank           Also dump raw sample-bank PCM into output dir.
  --video-device /dev/videoN   V4L2 capture node to sample in parallel.
  --playback-target NAME       PipeWire sink node name for pw-play --target.
  --xrandr-output NAME         Display output wired into the capture card.
  --duration N                Seconds of capture/playback. Default: 8
  --tone-frequency HZ         Tone frequency. Default: 1000
  --rate HZ                   Sample rate. Default: 48000
  --channels N                Channels. Default: 2
  --output-dir DIR            Evidence directory. Default: /tmp timestamp dir.
  --skip-video                Skip the parallel /dev/videoN ffmpeg capture.
  --list-targets              Print candidate HDMI sinks and exit.
  --help                      Show this help.
EOF
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

AUDIO_DEVICE="hw:5,3"
CAPTURE_BACKEND="alsa"
DEBUGFS_DIR=""
SAMPLE_LIMIT=100
SAMPLE_THRESHOLD=256
SAMPLE_DUMP_RAW=0
VIDEO_DEVICE="/dev/video3"
PLAYBACK_TARGET=""
XRANDR_OUTPUT="HDMI-A-1"
OUTPUT_DIR=""

DURATION=8
TONE_FREQUENCY=1000
RATE=48000
CHANNELS=2
SKIP_VIDEO=0
LIST_TARGETS=0

RUN_LOG=""
SUMMARY_TXT=""
LAST_BG_PID=""
declare -a BACKGROUND_PIDS=()

timestamp() {
	date '+%Y%m%d-%H%M%S'
}

log() {
	local msg=$1
	printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$msg" | tee -a "$RUN_LOG"
}

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

ensure_output_dir() {
	if [ -z "$OUTPUT_DIR" ]; then
		OUTPUT_DIR="/tmp/hws-hdmi-loop-$(timestamp)"
	fi

	mkdir -p "$OUTPUT_DIR"
	RUN_LOG="$OUTPUT_DIR/run.log"
	SUMMARY_TXT="$OUTPUT_DIR/summary.txt"
	: >"$RUN_LOG"
	: >"$SUMMARY_TXT"
}

record_summary() {
	local key=$1
	local value=$2
	printf '%s=%s\n' "$key" "$value" | tee -a "$SUMMARY_TXT" "$RUN_LOG" >/dev/null
}

kill_background_pids() {
	local pid
	for pid in "${BACKGROUND_PIDS[@]:-}"; do
		if kill -0 "$pid" >/dev/null 2>&1; then
			kill "$pid" >/dev/null 2>&1 || true
			wait "$pid" >/dev/null 2>&1 || true
		fi
	done
	BACKGROUND_PIDS=()
}

cleanup() {
	trap - EXIT INT TERM
	kill_background_pids || true
}

trap cleanup EXIT INT TERM

candidate_hdmi_sinks() {
	if have_cmd pactl; then
		pactl list short sinks 2>/dev/null | awk '
			index(tolower($2), "hdmi") { print $2 }
		'
	fi
}

detect_playback_target() {
	local sink=""

	if [ -n "$PLAYBACK_TARGET" ]; then
		printf '%s\n' "$PLAYBACK_TARGET"
		return 0
	fi

	if have_cmd pactl; then
		sink=$(pactl list short sinks 2>/dev/null | awk '
			$2 ~ /pci-0000_65_00\.1\.hdmi-stereo/ { print $2; exit }
			index(tolower($2), "hdmi") { print $2; exit }
		')
	fi

	printf '%s\n' "$sink"
}

audio_channel_index() {
	local dev=$1
	local idx

	case "$dev" in
	hw:*,*|plughw:*,*)
		idx=${dev##*,}
		;;
	*)
		printf 'invalid --audio-device %q; expected hw:CARD,DEV such as hw:5,3\n' "$dev" >&2
		return 2
		;;
	esac

	if ! [[ "$idx" =~ ^[0-9]+$ ]]; then
		printf 'invalid --audio-device %q; device index must be numeric\n' "$dev" >&2
		return 2
	fi

	printf '%s\n' "$((10#$idx))"
}

audio_card_index() {
	local dev=$1
	local card

	case "$dev" in
	hw:*,*|plughw:*,*)
		card=${dev#*:}
		card=${card%%,*}
		;;
	*)
		printf 'invalid --audio-device %q; expected hw:CARD,DEV such as hw:5,3\n' "$dev" >&2
		return 2
		;;
	esac

	if ! [[ "$card" =~ ^[0-9]+$ ]]; then
		printf 'invalid --audio-device %q; card index must be numeric\n' "$dev" >&2
		return 2
	fi

	printf '%s\n' "$((10#$card))"
}

audio_card_bdf() {
	local dev=$1
	local card
	local path

	card=$(audio_card_index "$dev")
	path=$(readlink -f "/sys/class/sound/card${card}/device" 2>/dev/null || true)
	if [ -n "$path" ]; then
		basename "$path"
	fi
}

pipewire_target_for_audio_device() {
	local dev=$1
	local bdf
	local ch
	local expected=""
	local resolved=""

	bdf=$(audio_card_bdf "$dev")
	ch=$(audio_channel_index "$dev")
	if [ -n "$bdf" ]; then
		expected="alsa_input.pci-${bdf//:/_}.pro-input-${ch}"
	fi

	if have_cmd pactl; then
		set +e
		resolved=$(
			pactl list short sources 2>/dev/null | awk -v expected="$expected" -v ch="$ch" '
				$2 == expected { print $2; exit }
				index($2, ".pro-input-" ch) { print $2; exit }
			'
		)
		set -e
	fi

	if [ -n "$resolved" ]; then
		printf '%s\n' "$resolved"
	elif [ -n "$expected" ]; then
		printf '%s\n' "$expected"
	fi
}

summary_value() {
	local path=$1
	local key=$2

	awk -F= -v k="$key" '$1 == k { print substr($0, index($0, "=") + 1); exit }' "$path" 2>/dev/null || true
}

is_sample_bank_backend() {
	case "$CAPTURE_BACKEND" in
	sample-bank|sample_bank|memory|debugfs)
		return 0
		;;
	esac
	return 1
}

debugfs_path_exists() {
	local path=$1

	if [ -e "$path" ]; then
		return 0
	fi
	if have_cmd sudo; then
		sudo test -e "$path"
		return $?
	fi
	return 1
}

debugfs_dir_exists() {
	local path=$1

	if [ -d "$path" ]; then
		return 0
	fi
	if have_cmd sudo; then
		sudo test -d "$path"
		return $?
	fi
	return 1
}

detect_sample_debugfs_dir() {
	local bdf
	local dir
	local dirs=()

	if [ -n "$DEBUGFS_DIR" ]; then
		printf '%s\n' "$DEBUGFS_DIR"
		return 0
	fi

	bdf=$(audio_card_bdf "$AUDIO_DEVICE" || true)
	if [ -n "$bdf" ] && debugfs_dir_exists "/sys/kernel/debug/hws/$bdf"; then
		printf '/sys/kernel/debug/hws/%s\n' "$bdf"
		return 0
	fi

	while IFS= read -r dir; do
		[ -n "$dir" ] && dirs+=("$dir")
	done < <(
		if [ -r /sys/kernel/debug/hws ] && [ -x /sys/kernel/debug/hws ]; then
			find /sys/kernel/debug/hws -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true
		elif have_cmd sudo; then
			sudo find /sys/kernel/debug/hws -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true
		fi
	)

	if [ "${#dirs[@]}" -eq 1 ]; then
		printf '%s\n' "${dirs[0]}"
		return 0
	fi
	if [ "${#dirs[@]}" -gt 1 ]; then
		printf 'multiple HWS debugfs dirs found; pass --debugfs-dir\n' >&2
		return 1
	fi

	printf 'no HWS debugfs dir found under /sys/kernel/debug/hws\n' >&2
	return 1
}

write_debugfs_value() {
	local path=$1
	local value=$2

	if [ -w "$path" ]; then
		printf '%s\n' "$value" >"$path"
	elif have_cmd sudo; then
		printf '%s\n' "$value" | sudo tee "$path" >/dev/null
	else
		printf 'cannot write %s; run as root or install sudo\n' "$path" >&2
		return 1
	fi
}

read_debugfs_to_file() {
	local path=$1
	local output=$2

	if [ -r "$path" ]; then
		cat "$path" >"$output"
	elif have_cmd sudo; then
		sudo cat "$path" >"$output"
	else
		printf 'cannot read %s; run as root or install sudo\n' "$path" >&2
		return 1
	fi
}

begin_kernel_capture() {
	date '+%Y-%m-%d %H:%M:%S'
}

finish_kernel_capture() {
	local since=$1
	local log_path=$2

	if have_cmd journalctl; then
		journalctl --no-pager -k --since "$since" >"$log_path" 2>&1 || true
	else
		printf 'journalctl unavailable\n' >"$log_path"
	fi
}

generate_tone() {
	local tone_path=$1
	local tone_duration=$2

	ffmpeg -nostdin -hide_banner -loglevel error -y \
		-f lavfi -i "sine=frequency=${TONE_FREQUENCY}:sample_rate=${RATE}:duration=${tone_duration}" \
		-af "volume=0.8" \
		-ac "$CHANNELS" \
		-c:a pcm_s16le "$tone_path"
}

run_video_capture_bg() {
	local duration=$1
	local log_path=$2

	(
		ffmpeg -nostdin -hide_banner -loglevel info \
			-f v4l2 -i "$VIDEO_DEVICE" -t "$duration" -f null -
	) >"$log_path" 2>&1 &

	LAST_BG_PID=$!
	BACKGROUND_PIDS+=("$LAST_BG_PID")
}

run_playback_bg() {
	local target=$1
	local tone_path=$2
	local log_path=$3

	(
		pw-play --target "$target" "$tone_path"
	) >"$log_path" 2>&1 &

	LAST_BG_PID=$!
	BACKGROUND_PIDS+=("$LAST_BG_PID")
}

run_arecord_capture() {
	local wav_path=$1
	local log_path=$2
	local rc=0

	set +e
	arecord -D "$AUDIO_DEVICE" -f S16_LE -r "$RATE" -c "$CHANNELS" \
		-d "$DURATION" "$wav_path" >"$log_path" 2>&1
	rc=$?
	set -e
	printf 'exit_code=%s\n' "$rc" >>"$log_path"
	return "$rc"
}

run_pw_record_capture() {
	local wav_path=$1
	local log_path=$2
	local rc=0
	local target

	target=$(pipewire_target_for_audio_device "$AUDIO_DEVICE")
	if [ -z "$target" ]; then
		printf 'pipewire target resolution failed for %s\n' "$AUDIO_DEVICE" >"$log_path"
		printf 'exit_code=1\n' >>"$log_path"
		return 1
	fi

	set +e
	timeout --signal=INT --kill-after=3s "${DURATION}s" \
		pw-record \
			--target "$target" \
			--rate "$RATE" \
			--channels "$CHANNELS" \
			--format s16 \
			"$wav_path" >"$log_path" 2>&1
	rc=$?
	set -e
	if [ "$rc" -eq 124 ] || [ "$rc" -eq 130 ]; then
		rc=0
	fi
	printf 'target=%s\n' "$target" >>"$log_path"
	printf 'exit_code=%s\n' "$rc" >>"$log_path"
	return "$rc"
}

run_sample_bank_capture() {
	local wav_path=$1
	local log_path=$2
	local rc=0
	local ch
	local debugfs_dir
	local ctl_path
	local meta_path
	local samples_path
	local ctl_before="$OUTPUT_DIR/audio-sample-ctl.before.txt"
	local ctl_after="$OUTPUT_DIR/audio-sample-ctl.txt"
	local meta_out="$OUTPUT_DIR/audio-sample-meta.txt"
	local raw_out="$OUTPUT_DIR/audio-samples.raw"

	: "$wav_path"
	ch=$(audio_channel_index "$AUDIO_DEVICE")
	debugfs_dir=$(detect_sample_debugfs_dir) || {
		printf 'debugfs_dir=unavailable\n' >"$log_path"
		printf 'exit_code=1\n' >>"$log_path"
		return 1
	}
	ctl_path="$debugfs_dir/audio_sample_ctl_ch${ch}"
	meta_path="$debugfs_dir/audio_sample_meta_ch${ch}"
	samples_path="$debugfs_dir/audio_samples_ch${ch}"

	{
		printf 'debugfs_dir=%s\n' "$debugfs_dir"
		printf 'channel=%s\n' "$ch"
		printf 'ctl_path=%s\n' "$ctl_path"
		printf 'meta_path=%s\n' "$meta_path"
		printf 'samples_path=%s\n' "$samples_path"
		printf 'sample_limit=%s\n' "$SAMPLE_LIMIT"
		printf 'sample_threshold=%s\n' "$SAMPLE_THRESHOLD"
		printf 'dump_raw=%s\n' "$SAMPLE_DUMP_RAW"
	} >"$log_path"

	if ! debugfs_path_exists "$ctl_path" || ! debugfs_path_exists "$meta_path"; then
		printf 'missing sample-bank debugfs files for channel %s\n' "$ch" >>"$log_path"
		printf 'exit_code=1\n' >>"$log_path"
		return 1
	fi

	read_debugfs_to_file "$ctl_path" "$ctl_before" || rc=1
	if [ "$rc" -eq 0 ]; then
		if ! write_debugfs_value "$ctl_path" "arm $SAMPLE_LIMIT $SAMPLE_THRESHOLD"; then
			rc=1
		fi
	fi

	if [ "$rc" -eq 0 ]; then
		sleep "$DURATION"
		if ! write_debugfs_value "$ctl_path" "flush"; then
			rc=1
		fi
	fi

	if [ "$rc" -eq 0 ]; then
		read_debugfs_to_file "$ctl_path" "$ctl_after" || rc=1
		read_debugfs_to_file "$meta_path" "$meta_out" || rc=1
	fi
	if [ "$rc" -eq 0 ] && [ "$SAMPLE_DUMP_RAW" -eq 1 ]; then
		read_debugfs_to_file "$samples_path" "$raw_out" || rc=1
	fi

	printf 'ctl_before=%s\n' "$ctl_before" >>"$log_path"
	printf 'ctl_after=%s\n' "$ctl_after" >>"$log_path"
	printf 'meta=%s\n' "$meta_out" >>"$log_path"
	if [ "$SAMPLE_DUMP_RAW" -eq 1 ]; then
		printf 'raw=%s\n' "$raw_out" >>"$log_path"
	fi
	printf 'exit_code=%s\n' "$rc" >>"$log_path"
	return "$rc"
}

run_audio_capture() {
	local wav_path=$1
	local log_path=$2

	case "$CAPTURE_BACKEND" in
	alsa)
		run_arecord_capture "$wav_path" "$log_path"
		;;
	pipewire)
		run_pw_record_capture "$wav_path" "$log_path"
		;;
	sample-bank|sample_bank|memory|debugfs)
		run_sample_bank_capture "$wav_path" "$log_path"
		;;
	*)
		printf 'unsupported capture backend: %s\n' "$CAPTURE_BACKEND" >"$log_path"
		printf 'exit_code=1\n' >>"$log_path"
		return 1
		;;
	esac
}

analyze_wav() {
	local wav_path=$1
	local analysis_path=$2
	local status="missing"
	local size=0
	local expected_min=0
	local mean_volume=""
	local max_volume=""
	local tone_status=""

	if [ -f "$wav_path" ]; then
		size=$(stat -c %s "$wav_path" 2>/dev/null || printf '0')
	fi
	expected_min=$((44 + (DURATION * RATE * CHANNELS * 2 * 3 / 4)))

	{
		printf 'path=%s\n' "$wav_path"
		printf 'size_bytes=%s\n' "$size"
		printf 'expected_min_bytes=%s\n' "$expected_min"
	} >"$analysis_path"

	if [ ! -f "$wav_path" ] || [ "$size" -eq 0 ]; then
		status="missing"
	elif [ "$size" -le 44 ]; then
		status="empty"
	elif [ "$size" -lt "$expected_min" ]; then
		status="truncated"
	else
		status="ok"
	fi

	if have_cmd ffmpeg && [ -f "$wav_path" ]; then
		local volume_log="$analysis_path.volumedetect.log"
		ffmpeg -nostdin -hide_banner -i "$wav_path" -af volumedetect -f null - \
			>/dev/null 2>"$volume_log" || true
		mean_volume=$(awk -F': ' '/mean_volume/ {print $2}' "$volume_log" | tail -n 1)
		max_volume=$(awk -F': ' '/max_volume/ {print $2}' "$volume_log" | tail -n 1)
		printf 'mean_volume=%s\n' "${mean_volume:-unknown}" >>"$analysis_path"
		printf 'max_volume=%s\n' "${max_volume:-unknown}" >>"$analysis_path"
		if [ "$status" = "ok" ] && [ "${max_volume:-}" = "-inf dB" ]; then
			status="silent"
		fi
	fi

	if have_cmd python3 && [ -f "$wav_path" ] && [ "$size" -gt 44 ]; then
		python3 - "$wav_path" "$analysis_path" "$RATE" "$CHANNELS" \
			"$TONE_FREQUENCY" "$DURATION" <<'PY'
import array
import math
import sys
import wave

wav_path, analysis_path = sys.argv[1], sys.argv[2]
expected_rate = int(sys.argv[3])
expected_channels = int(sys.argv[4])
expected_freq = float(sys.argv[5])
expected_duration = float(sys.argv[6])

def emit(values):
    with open(analysis_path, "a", encoding="utf-8") as out:
        for key, value in values:
            out.write(f"{key}={value}\n")

def channel_stats(samples, rate, freq):
    n = len(samples)
    if n == 0:
        return {
            "mean": 0.0,
            "peak": 0,
            "rms": 0.0,
            "freq": float("nan"),
            "fit_peak": 0.0,
            "residual_rms": 0.0,
            "residual_ratio": float("inf"),
        }

    mean = sum(samples) / n
    centered = [x - mean for x in samples]
    peak = max(abs(x) for x in samples)
    rms = math.sqrt(sum(x * x for x in centered) / n)

    crossings = []
    prev = centered[0]
    for i in range(1, n):
        cur = centered[i]
        if prev < 0 <= cur:
            denom = cur - prev
            frac = (-prev / denom) if denom else 0.0
            crossings.append((i - 1 + frac) / rate)
        prev = cur
    if len(crossings) >= 2:
        zc_freq = (len(crossings) - 1) / (crossings[-1] - crossings[0])
    else:
        zc_freq = float("nan")

    ss = cc = sc = xs_s = xs_c = 0.0
    for i, y in enumerate(centered):
        angle = 2.0 * math.pi * freq * i / rate
        s = math.sin(angle)
        c = math.cos(angle)
        ss += s * s
        cc += c * c
        sc += s * c
        xs_s += y * s
        xs_c += y * c

    det = ss * cc - sc * sc
    if det:
        b_s = (xs_s * cc - xs_c * sc) / det
        b_c = (xs_c * ss - xs_s * sc) / det
        fit_peak = math.sqrt(b_s * b_s + b_c * b_c)
        residual = 0.0
        for i, y in enumerate(centered):
            angle = 2.0 * math.pi * freq * i / rate
            fit = b_s * math.sin(angle) + b_c * math.cos(angle)
            err = y - fit
            residual += err * err
        residual_rms = math.sqrt(residual / n)
    else:
        fit_peak = 0.0
        residual_rms = rms

    residual_ratio = residual_rms / rms if rms else float("inf")
    return {
        "mean": mean,
        "peak": peak,
        "rms": rms,
        "freq": zc_freq,
        "fit_peak": fit_peak,
        "residual_rms": residual_rms,
        "residual_ratio": residual_ratio,
    }

try:
    with wave.open(wav_path, "rb") as wav:
        channels = wav.getnchannels()
        sample_width = wav.getsampwidth()
        rate = wav.getframerate()
        frames = wav.getnframes()
        raw = wav.readframes(frames)
except Exception as exc:
    emit([("tone_status", "wav_parse_error"), ("tone_error", str(exc))])
    sys.exit(0)

values = [
    ("wav_rate", rate),
    ("wav_channels", channels),
    ("wav_sample_width", sample_width),
    ("wav_frames", frames),
    ("wav_duration_s", f"{(frames / rate) if rate else 0.0:.6f}"),
    ("expected_tone_hz", f"{expected_freq:.3f}"),
]

if sample_width != 2:
    values.append(("tone_status", "unsupported_sample_width"))
    emit(values)
    sys.exit(0)

samples = array.array("h")
samples.frombytes(raw)
if sys.byteorder != "little":
    samples.byteswap()

if channels <= 0:
    values.append(("tone_status", "invalid_channels"))
    emit(values)
    sys.exit(0)

channel_data = [samples[ch::channels] for ch in range(channels)]
stats = channel_stats(channel_data[0], rate, expected_freq)

values.extend([
    ("tone_channel", 0),
    ("tone_mean", f"{stats['mean']:.3f}"),
    ("tone_peak", stats["peak"]),
    ("tone_rms", f"{stats['rms']:.3f}"),
    ("tone_zero_cross_freq_hz", f"{stats['freq']:.3f}" if math.isfinite(stats["freq"]) else "nan"),
    ("tone_fit_peak", f"{stats['fit_peak']:.3f}"),
    ("tone_fit_residual_rms", f"{stats['residual_rms']:.3f}"),
    ("tone_fit_residual_ratio", f"{stats['residual_ratio']:.6f}" if math.isfinite(stats["residual_ratio"]) else "inf"),
])

if channels >= 2:
    right = channel_data[1]
    left = channel_data[0]
    count = min(len(left), len(right))
    if count:
        diff_peak = max(abs(left[i] - right[i]) for i in range(count))
        diff_rms = math.sqrt(sum((left[i] - right[i]) ** 2 for i in range(count)) / count)
    else:
        diff_peak = 0
        diff_rms = 0.0
    values.extend([
        ("tone_lr_diff_peak", diff_peak),
        ("tone_lr_diff_rms", f"{diff_rms:.6f}"),
    ])

freq_tol = max(2.0, expected_freq * 0.01)
duration = frames / rate if rate else 0.0
freq = stats["freq"]
freq_ok = math.isfinite(freq) and abs(freq - expected_freq) <= freq_tol
format_ok = rate == expected_rate and channels == expected_channels
duration_ok = duration >= expected_duration * 0.75
peak_ok = stats["peak"] >= 256
residual_ok = math.isfinite(stats["residual_ratio"]) and stats["residual_ratio"] <= 0.15

if not peak_ok:
    tone_status = "silent"
elif not format_ok:
    tone_status = "format_mismatch"
elif not duration_ok:
    tone_status = "truncated"
elif not math.isfinite(freq):
    tone_status = "no_tone"
elif not freq_ok:
    tone_status = "wrong_tone"
elif not residual_ok:
    tone_status = "noisy_tone"
else:
    tone_status = "tone_ok"

values.append(("tone_status", tone_status))
emit(values)
PY
		tone_status=$(summary_value "$analysis_path" tone_status)
		if [ "$status" = "ok" ] && [ -n "$tone_status" ]; then
			status="$tone_status"
		fi
	elif [ ! -f "$wav_path" ] || [ "$size" -le 44 ]; then
		:
	else
		printf 'tone_status=python3_unavailable\n' >>"$analysis_path"
	fi

	printf 'status=%s\n' "$status" >>"$analysis_path"
	printf '%s\n' "$status"
}

analyze_sample_bank() {
	local analysis_path=$1
	local ctl_path="$OUTPUT_DIR/audio-sample-ctl.txt"
	local meta_path="$OUTPUT_DIR/audio-sample-meta.txt"
	local status="missing"
	local captured=""
	local total_packets=""
	local quiet_packets=""
	local dropped_full=""
	local max_peak=""
	local last_peak=""
	local debug_auto_arm=""
	local debug_autostart=""
	local threshold=""
	local slot_count=0

	if [ -f "$ctl_path" ]; then
		captured=$(summary_value "$ctl_path" captured)
		total_packets=$(summary_value "$ctl_path" total_packets)
		quiet_packets=$(summary_value "$ctl_path" quiet_packets)
		dropped_full=$(summary_value "$ctl_path" dropped_full)
		max_peak=$(summary_value "$ctl_path" max_peak)
		last_peak=$(summary_value "$ctl_path" last_peak)
		debug_auto_arm=$(summary_value "$ctl_path" debug_auto_arm)
		debug_autostart=$(summary_value "$ctl_path" debug_autostart)
		threshold=$(summary_value "$ctl_path" threshold)
	fi
	if [ -f "$meta_path" ]; then
		slot_count=$(awk 'BEGIN { n = 0 } /^[0-9]+\t/ { n++ } END { print n }' "$meta_path")
	fi

	captured=${captured:-0}
	total_packets=${total_packets:-0}
	quiet_packets=${quiet_packets:-0}
	dropped_full=${dropped_full:-0}
	max_peak=${max_peak:-0}
	last_peak=${last_peak:-0}

	if [ ! -f "$ctl_path" ]; then
		status="missing"
	elif [ "$captured" -gt 0 ]; then
		status="ok"
	elif [ "$total_packets" -gt 0 ]; then
		status="quiet"
	else
		status="no_packets"
	fi

	{
		printf 'status=%s\n' "$status"
		printf 'ctl=%s\n' "$ctl_path"
		printf 'meta=%s\n' "$meta_path"
		printf 'debug_auto_arm=%s\n' "${debug_auto_arm:-unknown}"
		printf 'debug_autostart=%s\n' "${debug_autostart:-unknown}"
		printf 'captured=%s\n' "$captured"
		printf 'meta_slots=%s\n' "$slot_count"
		printf 'total_packets=%s\n' "$total_packets"
		printf 'quiet_packets=%s\n' "$quiet_packets"
		printf 'dropped_full=%s\n' "$dropped_full"
		printf 'threshold=%s\n' "${threshold:-unknown}"
		printf 'last_peak=%s\n' "$last_peak"
		printf 'max_peak=%s\n' "$max_peak"
	} >"$analysis_path"

	printf '%s\n' "$status"
}

trace_channel_summary() {
	local kernel_log=$1
	local ch=$2
	local trace_log=$3
	local seed_count=0
	local start_count=0
	local irq_count=0
	local deliver_count=0
	local zero_base=0
	local trace_available=0

	rg "audio-trace:.*ch${ch}\\b" "$kernel_log" >"$trace_log" || true

	if [ -s "$trace_log" ]; then
		trace_available=1
	fi
	seed_count=$(grep -c 'audio-trace:seed' "$trace_log" 2>/dev/null || true)
	start_count=$(grep -c 'audio-trace:start' "$trace_log" 2>/dev/null || true)
	irq_count=$(grep -c 'audio-trace:irq ' "$trace_log" 2>/dev/null || true)
	deliver_count=$(grep -c 'audio-trace:deliver' "$trace_log" 2>/dev/null || true)
	if rg -q 'base=00000000' "$trace_log"; then
		zero_base=1
	fi

	{
		printf 'trace_available=%s\n' "$trace_available"
		printf 'seed_count=%s\n' "$seed_count"
		printf 'start_count=%s\n' "$start_count"
		printf 'irq_count=%s\n' "$irq_count"
		printf 'deliver_count=%s\n' "$deliver_count"
		printf 'zero_base=%s\n' "$zero_base"
	}
}

snapshot_environment() {
	if have_cmd pactl; then
		pactl list short sinks >"$OUTPUT_DIR/pactl-sinks.txt" 2>&1 || true
	fi
	if have_cmd xrandr; then
		xrandr --query >"$OUTPUT_DIR/xrandr.txt" 2>&1 || true
	fi
	if have_cmd v4l2-ctl; then
		v4l2-ctl --list-devices >"$OUTPUT_DIR/v4l2-list-devices.txt" 2>&1 || true
	fi
	cat /proc/asound/pcm >"$OUTPUT_DIR/proc-asound-pcm.txt" 2>/dev/null || true
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--audio-device)
				AUDIO_DEVICE=$2
				shift 2
				;;
			--capture-backend|--backend)
				CAPTURE_BACKEND=$2
				shift 2
				;;
			--debugfs-dir)
				DEBUGFS_DIR=$2
				shift 2
				;;
			--sample-limit)
				SAMPLE_LIMIT=$2
				shift 2
				;;
			--sample-threshold)
				SAMPLE_THRESHOLD=$2
				shift 2
				;;
			--dump-sample-bank)
				SAMPLE_DUMP_RAW=1
				shift
				;;
			--video-device)
				VIDEO_DEVICE=$2
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
			--skip-video)
				SKIP_VIDEO=1
				shift
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
}

main() {
	local playback_target=""
	local tone_path=""
	local playback_log=""
	local capture_log=""
	local capture_wav=""
	local capture_analysis=""
	local kernel_log=""
	local kernel_since=""
	local video_log=""
	local trace_log=""
	local trace_summary=""
	local capture_rc=0
	local playback_rc=0
	local playback_pid=""
	local video_pid=""
	local tone_duration=0
	local wav_status=""
	local sample_status=""
	local ch=0

	parse_args "$@"

	if [ "$LIST_TARGETS" -eq 1 ]; then
		candidate_hdmi_sinks
		exit 0
	fi

	for cmd in ffmpeg pw-play journalctl; do
		if ! have_cmd "$cmd"; then
			printf 'missing required command: %s\n' "$cmd" >&2
			exit 1
		fi
	done
	case "$CAPTURE_BACKEND" in
	alsa)
		if ! have_cmd arecord; then
			printf 'missing required command: arecord\n' >&2
			exit 1
		fi
		;;
	pipewire)
		for cmd in pw-record timeout pactl; do
			if ! have_cmd "$cmd"; then
				printf 'missing required command for pipewire capture: %s\n' "$cmd" >&2
				exit 1
			fi
		done
		;;
	sample-bank|sample_bank|memory|debugfs)
		;;
	*)
		printf 'unsupported capture backend: %s\n' "$CAPTURE_BACKEND" >&2
		exit 1
		;;
	esac

	if [ "$SKIP_VIDEO" -ne 1 ] && [ ! -e "$VIDEO_DEVICE" ]; then
		printf 'video device not found: %s\n' "$VIDEO_DEVICE" >&2
		exit 1
	fi

	playback_target=$(detect_playback_target)
	if [ -z "$playback_target" ]; then
		printf 'could not auto-detect an HDMI playback target; use --playback-target\n' >&2
		exit 1
	fi

	ensure_output_dir
	snapshot_environment

	record_summary "audio_device" "$AUDIO_DEVICE"
	record_summary "capture_backend" "$CAPTURE_BACKEND"
	record_summary "video_device" "$VIDEO_DEVICE"
	record_summary "playback_target" "$playback_target"
	record_summary "xrandr_output" "$XRANDR_OUTPUT"
	record_summary "duration_seconds" "$DURATION"
	record_summary "tone_frequency_hz" "$TONE_FREQUENCY"
	if is_sample_bank_backend; then
		record_summary "sample_limit" "$SAMPLE_LIMIT"
		record_summary "sample_threshold" "$SAMPLE_THRESHOLD"
		record_summary "sample_dump_raw" "$SAMPLE_DUMP_RAW"
	fi

	tone_duration=$((DURATION + 2))
	tone_path="$OUTPUT_DIR/tone.wav"
	playback_log="$OUTPUT_DIR/playback.log"
	capture_log="$OUTPUT_DIR/capture.${CAPTURE_BACKEND}.log"
	capture_wav="$OUTPUT_DIR/capture.wav"
	capture_analysis="$OUTPUT_DIR/capture.analysis.txt"
	kernel_log="$OUTPUT_DIR/kernel.log"
	video_log="$OUTPUT_DIR/video.ffmpeg.log"
	trace_log="$OUTPUT_DIR/audio-trace.log"
	trace_summary="$OUTPUT_DIR/audio-trace-summary.txt"
	ch=$(audio_channel_index "$AUDIO_DEVICE")

	if is_sample_bank_backend && [ ! -x /sys/kernel/debug ]; then
		if have_cmd sudo; then
			log "Requesting sudo for debugfs access before playback starts"
			sudo -v
		else
			printf 'sample-bank backend needs debugfs access; run as root or install sudo\n' >&2
			exit 1
		fi
	fi

	log "Generating ${tone_duration}s tone at ${TONE_FREQUENCY} Hz"
	generate_tone "$tone_path" "$tone_duration"

	kernel_since=$(begin_kernel_capture)

	if [ "$SKIP_VIDEO" -ne 1 ]; then
		log "Starting parallel video capture on $VIDEO_DEVICE"
		run_video_capture_bg "$tone_duration" "$video_log"
		video_pid=$LAST_BG_PID
	fi

	log "Starting playback on $playback_target"
	run_playback_bg "$playback_target" "$tone_path" "$playback_log"
	playback_pid=$LAST_BG_PID

	sleep 1

	log "Capturing $AUDIO_DEVICE for ${DURATION}s via $CAPTURE_BACKEND"
	if run_audio_capture "$capture_wav" "$capture_log"; then
		capture_rc=0
	else
		capture_rc=$?
	fi

	set +e
	wait "$playback_pid"
	playback_rc=$?
	set -e

	if [ -n "$video_pid" ]; then
		set +e
		wait "$video_pid"
		set -e
	fi

	finish_kernel_capture "$kernel_since" "$kernel_log"
	if is_sample_bank_backend; then
		sample_status=$(analyze_sample_bank "$capture_analysis")
		wav_status="$sample_status"
	else
		wav_status=$(analyze_wav "$capture_wav" "$capture_analysis")
	fi
	trace_channel_summary "$kernel_log" "$ch" "$trace_log" >"$trace_summary"

	record_summary "capture_rc" "$capture_rc"
	record_summary "playback_rc" "$playback_rc"
	record_summary "wav_status" "$wav_status"
	if is_sample_bank_backend; then
		record_summary "sample_status" "$sample_status"
		record_summary "sample_captured" "$(summary_value "$capture_analysis" captured)"
		record_summary "sample_total_packets" "$(summary_value "$capture_analysis" total_packets)"
		record_summary "sample_quiet_packets" "$(summary_value "$capture_analysis" quiet_packets)"
		record_summary "sample_max_peak" "$(summary_value "$capture_analysis" max_peak)"
		record_summary "sample_debug_autostart" "$(summary_value "$capture_analysis" debug_autostart)"
	else
		record_summary "tone_status" "$(summary_value "$capture_analysis" tone_status)"
		record_summary "tone_zero_cross_freq_hz" "$(summary_value "$capture_analysis" tone_zero_cross_freq_hz)"
		record_summary "tone_peak" "$(summary_value "$capture_analysis" tone_peak)"
		record_summary "tone_rms" "$(summary_value "$capture_analysis" tone_rms)"
		record_summary "tone_fit_residual_ratio" "$(summary_value "$capture_analysis" tone_fit_residual_ratio)"
	fi
	cat "$trace_summary" >>"$SUMMARY_TXT"

	if [ "$playback_rc" -ne 0 ]; then
		log "Playback failed; inspect $playback_log"
	elif [ "$capture_rc" -eq 0 ] && [ "$wav_status" = "tone_ok" ]; then
		log "Capture matches generated tone: freq=$(summary_value "$capture_analysis" tone_zero_cross_freq_hz)Hz peak=$(summary_value "$capture_analysis" tone_peak)"
	elif is_sample_bank_backend && \
		[ "$sample_status" = "ok" ]; then
		log "Sample bank captured non-empty packets: captured=$(summary_value "$capture_analysis" captured) max_peak=$(summary_value "$capture_analysis" max_peak)"
	elif is_sample_bank_backend && \
		[ "$sample_status" = "quiet" ]; then
		log "Sample bank saw packets but none above threshold; inspect $capture_analysis"
	elif is_sample_bank_backend; then
		log "Sample bank did not capture packets; inspect $capture_log, $capture_analysis, and $trace_log"
	elif [ "$capture_rc" -eq 0 ] && [ "$wav_status" != "missing" ] && \
		[ "$wav_status" != "empty" ] && [ "$wav_status" != "truncated" ]; then
		log "Capture produced audio evidence but did not pass tone check: wav_status=$wav_status; inspect $capture_analysis"
	elif rg -q '^irq_count=[1-9]' "$trace_summary" && rg -q '^deliver_count=[1-9]' "$trace_summary"; then
		log "Driver delivered packets, but the ALSA capture still ended poorly; inspect $capture_log and $trace_log"
	else
		log "No successful capture. Inspect $capture_log and $trace_log"
	fi

	log "Evidence written to $OUTPUT_DIR"
}

main "$@"
