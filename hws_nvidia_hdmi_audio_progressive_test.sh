#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./hws_audio_lib.sh
. "$SCRIPT_DIR/hws_audio_lib.sh"

usage() {
	cat <<'EOF'
Usage: ./hws_nvidia_hdmi_audio_progressive_test.sh [options]

Run progressive NVIDIA HDMI -> HWS ALSA capture validation. Tests that have
already passed are recorded in a state file and skipped on later runs.

Options:
  --target NAME              PipeWire/Pulse sink target. Default: auto NVIDIA HDMI.
  --card NAME                Pulse/PipeWire card for --profile. Default: auto NVIDIA.
  --profile NAME             Set NVIDIA card profile before target detection.
  --audio-device DEV         HWS ALSA capture device. Default: auto:3.
                             Accepts hw:C,D, plughw:C,D, auto, or auto:D.
  --output-dir DIR           Evidence directory. Default: /tmp timestamp dir.
  --state-dir DIR            Persistent resume directory. Default: XDG state dir.
  --required-rates LIST      Required rates. Default: 48000.
  --optional-rates LIST      Optional rates to test only if advertised. Default: empty.
  --required-formats LIST    Required ALSA formats. Default: S16_LE.
  --optional-formats LIST    Optional formats to test only if advertised. Default: empty.
  --required-channels LIST   Required channel counts. Default: 2.
  --optional-channels LIST   Optional channel counts to test if advertised. Default: empty.
  --default-rate HZ          Baseline rate for non-rate tests. Default: 48000.
  --default-format FORMAT    Baseline format for non-format tests. Default: S16_LE.
  --default-channels N       Baseline channel count for non-channel tests. Default: 2.
  --smoke-duration N         Seconds for ordinary capture tests. Default: 5.
  --short-duration N         Seconds for repeated short captures. Default: 1.
  --repeat-cycles N          Repeated start/stop cycles. Default: 10.
  --short-cycles N           Consecutive short captures. Default: 100.
  --open-close-cycles N      Consecutive device node open/close cycles. Default: 1000.
  --long-1m-duration N       1-minute test duration override. Default: 60.
  --long-10m-duration N      10-minute test duration override. Default: 600.
  --long-1h-duration N       1-hour test duration override. Default: 3600.
  --skip-long                Skip 1-minute, 10-minute, and 1-hour capture tests.
  --strict-advertised        Fail advertised-capability checks on extra values too.
  --rerun-passed             Ignore previous PASS state and run tests again.
  --list-targets             List candidate HDMI/NVIDIA sinks and exit.
  --help                     Show this help.

No sudo, module load/unload, debugfs writes, or other escalated operations are
performed by this script.
EOF
}

TARGET="auto"
CARD="auto"
PROFILE=""
AUDIO_DEVICE="auto:3"
AUDIO_DEVICE_REQUESTED=""
OUTPUT_DIR=""
STATE_DIR=""

REQUIRED_RATES="48000"
OPTIONAL_RATES=""
REQUIRED_FORMATS="S16_LE"
OPTIONAL_FORMATS=""
REQUIRED_CHANNELS="2"
OPTIONAL_CHANNELS=""

DEFAULT_RATE=48000
DEFAULT_FORMAT="S16_LE"
DEFAULT_CHANNELS=2
SMOKE_DURATION=5
SHORT_DURATION=1
REPEAT_CYCLES=10
SHORT_CYCLES=100
OPEN_CLOSE_CYCLES=1000
LONG_1M_DURATION=60
LONG_10M_DURATION=600
LONG_1H_DURATION=3600
TONE_FREQUENCY=1000
SIZE_TOLERANCE_PERCENT=3

SKIP_LONG=0
STRICT_ADVERTISED=0
RERUN_PASSED=0
LIST_TARGETS=0

STATE_FILE=""
SESSION_FILE=""
CAPABILITY_DIR=""
HW_PARAMS_FILE=""
CAP_RATE_LINE=""
CAP_FORMAT_LINE=""
CAP_CHANNEL_LINE=""
PLAYBACK_TONE=""
LAST_BG_PID=""

declare -a BACKGROUND_PIDS=()

csv_to_words() {
	local value=$1

	value=${value//,/ }
	value=${value//;/ }
	printf '%s\n' "$value" | awk '
		{
			for (i = 1; i <= NF; i++)
				if ($i != "")
					print $i
		}
	'
}

normalize_list() {
	csv_to_words "$1" | awk '!seen[$0]++ { printf "%s%s", sep, $0; sep = " " } END { print "" }'
}

safe_name() {
	printf '%s' "$1" | tr -c 'A-Za-z0-9_.=-' '_'
}

timestamp() {
	date '+%Y%m%d-%H%M%S'
}

log() {
	printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

die() {
	printf '%s\n' "$*" >&2
	exit 1
}

parse_args() {
	while [ "$#" -gt 0 ]; do
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
		--audio-device)
			AUDIO_DEVICE=$2
			shift 2
			;;
		--output-dir)
			OUTPUT_DIR=$2
			shift 2
			;;
		--state-dir)
			STATE_DIR=$2
			shift 2
			;;
		--required-rates)
			REQUIRED_RATES=$(normalize_list "$2")
			shift 2
			;;
		--optional-rates)
			OPTIONAL_RATES=$(normalize_list "$2")
			shift 2
			;;
		--required-formats)
			REQUIRED_FORMATS=$(normalize_list "$2")
			shift 2
			;;
		--optional-formats)
			OPTIONAL_FORMATS=$(normalize_list "$2")
			shift 2
			;;
		--required-channels)
			REQUIRED_CHANNELS=$(normalize_list "$2")
			shift 2
			;;
		--optional-channels)
			OPTIONAL_CHANNELS=$(normalize_list "$2")
			shift 2
			;;
		--default-rate)
			DEFAULT_RATE=$2
			shift 2
			;;
		--default-format)
			DEFAULT_FORMAT=$2
			shift 2
			;;
		--default-channels)
			DEFAULT_CHANNELS=$2
			shift 2
			;;
		--smoke-duration)
			SMOKE_DURATION=$2
			shift 2
			;;
		--short-duration)
			SHORT_DURATION=$2
			shift 2
			;;
		--repeat-cycles)
			REPEAT_CYCLES=$2
			shift 2
			;;
		--short-cycles)
			SHORT_CYCLES=$2
			shift 2
			;;
		--open-close-cycles)
			OPEN_CLOSE_CYCLES=$2
			shift 2
			;;
		--long-1m-duration)
			LONG_1M_DURATION=$2
			shift 2
			;;
		--long-10m-duration)
			LONG_10M_DURATION=$2
			shift 2
			;;
		--long-1h-duration)
			LONG_1H_DURATION=$2
			shift 2
			;;
		--skip-long)
			SKIP_LONG=1
			shift
			;;
		--strict-advertised)
			STRICT_ADVERTISED=1
			shift
			;;
		--rerun-passed)
			RERUN_PASSED=1
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

cleanup() {
	local pid

	trap - EXIT INT TERM
	for pid in "${BACKGROUND_PIDS[@]:-}"; do
		if kill -0 "$pid" >/dev/null 2>&1; then
			kill "$pid" >/dev/null 2>&1 || true
			wait "$pid" >/dev/null 2>&1 || true
		fi
	done
	BACKGROUND_PIDS=()
}

trap cleanup EXIT INT TERM

state_has_pass() {
	local test_id=$1

	[ "$RERUN_PASSED" -eq 0 ] || return 1
	[ -f "$STATE_FILE" ] || return 1
	awk -F '\t' -v id="$test_id" '$1 == id && $2 == "PASS" { found = 1 } END { exit found ? 0 : 1 }' "$STATE_FILE"
}

append_session_result() {
	local test_id=$1
	local status=$2
	local name=$3
	local detail=${4:-}
	local artifact=${5:-}

	printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$test_id" "$status" "$(date -Is)" "$name" "$detail" "$artifact" >>"$SESSION_FILE"
}

record_result() {
	local test_id=$1
	local status=$2
	local name=$3
	local detail=${4:-}
	local artifact=${5:-}

	printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$test_id" "$status" "$(date -Is)" "$name" "$detail" "$artifact" >>"$STATE_FILE"
	append_session_result "$test_id" "$status" "$name" "$detail" "$artifact"
}

skip_previous_pass() {
	local test_id=$1
	local name=$2

	log "SKIP $test_id - already passed"
	append_session_result "$test_id" "SKIP_PASS" "$name" "previous PASS in $STATE_FILE" ""
}

mark_skip() {
	local test_id=$1
	local name=$2
	local detail=$3

	log "SKIP $test_id - $detail"
	record_result "$test_id" "SKIP" "$name" "$detail" ""
}

test_name() {
	local test_id=$1

	case "$test_id" in
	alsa_enumerates) printf 'Verify device enumerates in ALSA' ;;
	alsa_open) printf 'Verify ALSA device can be opened' ;;
	alsa_close) printf 'Verify ALSA device can be closed' ;;
	advertised_rates_expected) printf 'Verify advertised sample rates match expected values' ;;
	advertised_formats_expected) printf 'Verify advertised sample formats match expected values' ;;
	advertised_channels_expected) printf 'Verify advertised channel counts match expected values' ;;
	capture_rate_*) printf 'Verify successful capture at requested sample rate' ;;
	capture_format_*) printf 'Verify successful capture at requested sample format' ;;
	capture_channels_*) printf 'Verify successful capture at requested channel count' ;;
	capture_all_advertised_rates) printf 'Verify successful capture at every advertised sample rate' ;;
	capture_all_advertised_formats) printf 'Verify successful capture at every advertised sample format' ;;
	capture_all_advertised_channels) printf 'Verify successful capture at every advertised channel count' ;;
	wav_size_duration_*) printf 'Verify output WAV file size matches expected duration' ;;
	wav_nonzero_samples_*) printf 'Verify output WAV file contains non-zero samples' ;;
	wav_valid_headers_*) printf 'Verify output WAV file contains valid headers' ;;
	captured_sample_rate_matches_*) printf 'Verify captured sample rate matches requested sample rate' ;;
	captured_channel_count_matches_*) printf 'Verify captured channel count matches requested channel count' ;;
	captured_sample_format_matches_*) printf 'Verify captured sample format matches requested sample format' ;;
	no_xruns_reported_*) printf 'Verify no XRUNs reported during capture' ;;
	no_kernel_warnings_*) printf 'Verify no kernel warnings during capture' ;;
	no_kernel_errors_*) printf 'Verify no kernel errors during capture' ;;
	capture_start_succeeds_*) printf 'Verify capture start succeeds' ;;
	capture_stop_succeeds_*) printf 'Verify capture stop succeeds' ;;
	repeated_start_stop_cycles) printf 'Verify repeated start/stop capture cycles' ;;
	short_capture_100_cycles) printf 'Verify 100 consecutive short captures succeed' ;;
	open_close_1000_cycles) printf 'Verify 1000 consecutive device open/close cycles succeed' ;;
	long_capture_60s) printf 'Verify 1-minute capture succeeds' ;;
	long_capture_600s) printf 'Verify 10-minute capture succeeds' ;;
	long_capture_3600s) printf 'Verify 1-hour capture succeeds' ;;
	no_data_truncation_long_capture) printf 'Verify no data truncation during long capture' ;;
	*) printf '%s' "$test_id" ;;
	esac
}

run_simple_test() {
	local test_id=$1
	local func=$2
	local name
	local artifact_dir
	local detail_file
	local rc
	local detail
	local status

	name=$(test_name "$test_id")
	if state_has_pass "$test_id"; then
		skip_previous_pass "$test_id" "$name"
		return 0
	fi

	artifact_dir="$OUTPUT_DIR/tests/$(safe_name "$test_id")"
	detail_file="$artifact_dir/detail.txt"
	mkdir -p "$artifact_dir"

	set +e
	"$func" "$artifact_dir" >"$detail_file" 2>&1
	rc=$?
	set -e

	detail=$(tr '\n' ';' <"$detail_file" | sed 's/;*$//')
	case "$rc" in
	0)
		status="PASS"
		log "PASS $test_id"
		;;
	77)
		status="SKIP"
		log "SKIP $test_id - ${detail:-not supported}"
		;;
	*)
		status="FAIL"
		log "FAIL $test_id - see $detail_file"
		;;
	esac

	record_result "$test_id" "$status" "$name" "$detail" "$artifact_dir"
	return 0
}

audio_device_parts() {
	local dev=$1

	hws_alsa_device_parts "$dev"
}

audio_devnode() {
	local card
	local pcm

	if read -r card pcm < <(audio_device_parts "$AUDIO_DEVICE"); then
		printf '/dev/snd/pcmC%sD%sc\n' "$card" "$pcm"
		return 0
	fi

	return 1
}

proc_asound_key() {
	local card=$1
	local pcm=$2

	printf '%02d-%02d' "$card" "$pcm"
}

resolve_audio_device() {
	local requested=$AUDIO_DEVICE
	local resolved=""
	local pcm

	AUDIO_DEVICE_REQUESTED=$requested
	case "$requested" in
	""|auto)
		resolved=$(hws_detect_hws_audio_device || true)
		if [ -z "$resolved" ]; then
			die "could not auto-detect an HWS ALSA capture device; run ./hws_hdmi_audio_targets.sh and pass --audio-device"
		fi
		AUDIO_DEVICE=$resolved
		return 0
		;;
	auto:*)
		pcm=${requested#auto:}
		if ! [[ "$pcm" =~ ^[0-9]+$ ]]; then
			die "invalid --audio-device $requested; expected auto or auto:D with numeric D"
		fi
		resolved=$(hws_detect_hws_audio_device "$((10#$pcm))" || true)
		if [ -z "$resolved" ]; then
			die "could not auto-detect HWS ALSA capture PCM $pcm; run ./hws_hdmi_audio_targets.sh and pass --audio-device"
		fi
		AUDIO_DEVICE=$resolved
		return 0
		;;
	esac

	if hws_alsa_capture_device_exists "$requested"; then
		return 0
	fi

	if read -r _ pcm < <(audio_device_parts "$requested"); then
		resolved=$(hws_detect_hws_audio_device "$pcm" || true)
		if [ -n "$resolved" ]; then
			log "WARN: requested audio_device=$requested is not present; using detected HWS capture device $resolved for PCM $pcm"
			AUDIO_DEVICE=$resolved
			return 0
		fi
	fi
}

test_alsa_enumerates() {
	local card
	local pcm
	local key

	arecord -l >"$1/arecord-list.txt" 2>&1 || true
	arecord -L >"$1/arecord-pcms.txt" 2>&1 || true
	cp /proc/asound/pcm "$1/proc-asound-pcm.txt" 2>/dev/null || true

	if read -r card pcm < <(audio_device_parts "$AUDIO_DEVICE"); then
		key=$(proc_asound_key "$card" "$pcm")
		if [ -r /proc/asound/pcm ] &&
		   awk -v key="$key" '$0 ~ "^" key ":" && tolower($0) ~ /capture/ { found = 1 } END { exit found ? 0 : 1 }' /proc/asound/pcm; then
			printf 'device=%s proc_asound_key=%s\n' "$AUDIO_DEVICE" "$key"
			return 0
		fi
		printf 'device=%s was not found as a capture PCM in /proc/asound/pcm\n' "$AUDIO_DEVICE"
		printf 'detected_hws_devices=%s\n' "$(hws_discover_hws_audio_devices | tr '\n' ' ')"
		return 1
	fi

	if arecord -L 2>/dev/null | awk -v dev="$AUDIO_DEVICE" '$0 == dev { found = 1 } END { exit found ? 0 : 1 }'; then
		printf 'device=%s found in arecord -L\n' "$AUDIO_DEVICE"
		return 0
	fi

	printf 'device=%s is not a numeric hw/plughw device and was not found exactly in arecord -L\n' "$AUDIO_DEVICE"
	return 1
}

open_close_devnode_once() {
	local node

	node=$(audio_devnode) || return 1
	[ -e "$node" ] || {
		printf 'node missing: %s\n' "$node"
		return 1
	}
	( exec 9<"$node" )
}

test_alsa_open_once() {
	local node

	node=$(audio_devnode) || {
		printf 'cannot derive /dev/snd node from %s\n' "$AUDIO_DEVICE"
		return 77
	}
	printf 'node=%s\n' "$node"
	open_close_devnode_once
}

test_alsa_close_once() {
	local node

	node=$(audio_devnode) || {
		printf 'cannot derive /dev/snd node from %s\n' "$AUDIO_DEVICE"
		return 77
	}
	printf 'node=%s\n' "$node"
	open_close_devnode_once
}

test_open_close_cycles() {
	local node
	local i

	node=$(audio_devnode) || {
		printf 'cannot derive /dev/snd node from %s\n' "$AUDIO_DEVICE"
		return 77
	}
	[ -e "$node" ] || {
		printf 'node missing: %s\n' "$node"
		return 1
	}

	for ((i = 1; i <= OPEN_CLOSE_CYCLES; i++)); do
		if ! ( exec 9<"$node" ); then
			printf 'open/close failed at cycle=%s node=%s\n' "$i" "$node"
			return 1
		fi
	done

	printf 'cycles=%s node=%s\n' "$OPEN_CLOSE_CYCLES" "$node"
}

dump_hw_params() {
	local out=$1
	local rc

	if arecord -D "$AUDIO_DEVICE" --dump-hw-params \
		-f "$DEFAULT_FORMAT" -r "$DEFAULT_RATE" -c "$DEFAULT_CHANNELS" \
		-d 1 -t raw /dev/null >"$out" 2>&1; then
		rc=0
	else
		rc=$?
	fi
	printf 'exit_code=%s\n' "$rc" >>"$out"
	if awk '
		/^[[:space:]]*FORMAT:/ { format = 1 }
		/^[[:space:]]*CHANNELS:/ { channels = 1 }
		/^[[:space:]]*RATE:/ { rate = 1 }
		END { exit format && channels && rate ? 0 : 1 }
	' "$out"; then
		return 0
	fi
	return "$rc"
}

hw_param_line() {
	local key=$1

	awk -v key="$key" '
		$0 ~ "^[[:space:]]*" key ":" {
			line = $0
			sub("^[[:space:]]*" key ":[[:space:]]*", "", line)
			print line
			exit
		}
	' "$HW_PARAMS_FILE"
}

numbers_from_line() {
	printf '%s\n' "$1" | awk '
		{
			line = $0
			gsub(/[^0-9]+/, " ", line)
			for (i = 1; i <= split(line, a, /[[:space:]]+/); i++)
				if (a[i] != "")
					print a[i]
		}
	'
}

unique_words() {
	printf '%s\n' "$*" | awk '
		{
			for (i = 1; i <= NF; i++)
				if (!seen[$i]++) {
					printf "%s%s", sep, $i
					sep = " "
				}
		}
		END { print "" }
	'
}

line_supports_number() {
	local line=$1
	local value=$2

	[ -n "$line" ] || return 1
	printf '%s\n' "$line" | awk -v value="$value" '
		BEGIN { supported = 0 }
		{
			lower = tolower($0)
			if (index(lower, "continuous") || index(lower, "knot")) {
				supported = 1
				exit
			}
			line = $0
			gsub(/[^0-9]+/, " ", line)
			n = split(line, nums, /[[:space:]]+/)
			count = 0
			for (i = 1; i <= n; i++)
				if (nums[i] != "")
					values[++count] = nums[i] + 0
			if ($0 ~ /\[/ && count >= 2 && value >= values[1] && value <= values[2])
				supported = 1
			for (i = 1; i <= count; i++)
				if (values[i] == value)
					supported = 1
		}
		END { exit supported ? 0 : 1 }
	'
}

line_supports_format() {
	local line=$1
	local format=$2

	[ -n "$line" ] || return 1
	printf '%s\n' "$line" | awk -v format="$format" '
		{
			for (i = 1; i <= NF; i++)
				if ($i == format)
					found = 1
		}
		END { exit found ? 0 : 1 }
	'
}

rate_supported() {
	line_supports_number "$CAP_RATE_LINE" "$1"
}

format_supported() {
	line_supports_format "$CAP_FORMAT_LINE" "$1"
}

channels_supported() {
	line_supports_number "$CAP_CHANNEL_LINE" "$1"
}

advertised_rates() {
	local values

	values=$(unique_words "$REQUIRED_RATES $OPTIONAL_RATES $(numbers_from_line "$CAP_RATE_LINE" | tr '\n' ' ')")
	for value in $values; do
		if rate_supported "$value"; then
			printf '%s\n' "$value"
		fi
	done
}

advertised_formats() {
	local values

	values=$(unique_words "$REQUIRED_FORMATS $OPTIONAL_FORMATS $CAP_FORMAT_LINE")
	for value in $values; do
		if format_supported "$value"; then
			printf '%s\n' "$value"
		fi
	done
}

advertised_channels() {
	local values

	values=$(unique_words "$REQUIRED_CHANNELS $OPTIONAL_CHANNELS $(numbers_from_line "$CAP_CHANNEL_LINE" | tr '\n' ' ')")
	for value in $values; do
		if channels_supported "$value"; then
			printf '%s\n' "$value"
		fi
	done
}

test_advertised_rates_expected() {
	local missing=0
	local extra=0
	local rate
	local expected
	local advertised

	printf 'rate_line=%s\n' "$CAP_RATE_LINE"
	for rate in $REQUIRED_RATES; do
		if ! rate_supported "$rate"; then
			printf 'missing_required_rate=%s\n' "$rate"
			missing=1
		fi
	done

	if [ "$STRICT_ADVERTISED" -eq 1 ]; then
		expected=$(unique_words "$REQUIRED_RATES $OPTIONAL_RATES")
		advertised=$(advertised_rates | tr '\n' ' ')
		for rate in $advertised; do
			if ! printf ' %s ' "$expected" | grep -F " $rate " >/dev/null 2>&1; then
				printf 'extra_advertised_rate=%s\n' "$rate"
				extra=1
			fi
		done
	fi

	[ "$missing" -eq 0 ] && [ "$extra" -eq 0 ]
}

test_advertised_formats_expected() {
	local missing=0
	local extra=0
	local format
	local expected
	local advertised

	printf 'format_line=%s\n' "$CAP_FORMAT_LINE"
	for format in $REQUIRED_FORMATS; do
		if ! format_supported "$format"; then
			printf 'missing_required_format=%s\n' "$format"
			missing=1
		fi
	done

	if [ "$STRICT_ADVERTISED" -eq 1 ]; then
		expected=$(unique_words "$REQUIRED_FORMATS $OPTIONAL_FORMATS")
		advertised=$(advertised_formats | tr '\n' ' ')
		for format in $advertised; do
			if ! printf ' %s ' "$expected" | grep -F " $format " >/dev/null 2>&1; then
				printf 'extra_advertised_format=%s\n' "$format"
				extra=1
			fi
		done
	fi

	[ "$missing" -eq 0 ] && [ "$extra" -eq 0 ]
}

test_advertised_channels_expected() {
	local missing=0
	local extra=0
	local channels
	local expected
	local advertised

	printf 'channels_line=%s\n' "$CAP_CHANNEL_LINE"
	for channels in $REQUIRED_CHANNELS; do
		if ! channels_supported "$channels"; then
			printf 'missing_required_channels=%s\n' "$channels"
			missing=1
		fi
	done

	if [ "$STRICT_ADVERTISED" -eq 1 ]; then
		expected=$(unique_words "$REQUIRED_CHANNELS $OPTIONAL_CHANNELS")
		advertised=$(advertised_channels | tr '\n' ' ')
		for channels in $advertised; do
			if ! printf ' %s ' "$expected" | grep -F " $channels " >/dev/null 2>&1; then
				printf 'extra_advertised_channels=%s\n' "$channels"
				extra=1
			fi
		done
	fi

	[ "$missing" -eq 0 ] && [ "$extra" -eq 0 ]
}

format_codec() {
	case "$1" in
	S16_LE) printf 'pcm_s16le\n' ;;
	S24_LE) printf 'pcm_s24le\n' ;;
	S32_LE) printf 'pcm_s32le\n' ;;
	*) printf '%s\n' "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" ;;
	esac
}

format_bits() {
	case "$1" in
	S8|U8) printf '8\n' ;;
	S16_LE|U16_LE|S16_BE|U16_BE) printf '16\n' ;;
	S24_LE|U24_LE|S24_BE|U24_BE|S24_3LE|S24_3BE) printf '24\n' ;;
	S32_LE|U32_LE|S32_BE|U32_BE|FLOAT_LE|FLOAT_BE) printf '32\n' ;;
	S64_LE|U64_LE|S64_BE|U64_BE|FLOAT64_LE|FLOAT64_BE) printf '64\n' ;;
	*) printf '16\n' ;;
	esac
}

analysis_value() {
	local path=$1
	local key=$2

	awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$path" 2>/dev/null || true
}

ensure_playback_tone() {
	if [ -f "$PLAYBACK_TONE" ]; then
		return 0
	fi

	ffmpeg -nostdin -hide_banner -loglevel error -y \
		-f lavfi -i "sine=frequency=${TONE_FREQUENCY}:sample_rate=48000:duration=5" \
		-af "volume=0.8" \
		-ac 2 \
		-c:a pcm_s16le "$PLAYBACK_TONE"
}

start_playback_loop() {
	local log_path=$1

	ensure_playback_tone
	(
		while :; do
			pw-play --target "$TARGET" "$PLAYBACK_TONE" || exit $?
		done
	) >"$log_path" 2>&1 &

	LAST_BG_PID=$!
	BACKGROUND_PIDS+=("$LAST_BG_PID")
}

stop_pid() {
	local pid=$1

	if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" >/dev/null 2>&1 || true
	fi
}

capture_kernel_log() {
	local since=$1
	local priority=$2
	local out=$3

	if ! hws_have_cmd journalctl; then
		printf 'journalctl unavailable\n' >"$out"
		return 77
	fi

	local rc

	if journalctl --no-pager -k -p "$priority" --since "$since" >"$out" 2>&1; then
		rc=0
	else
		rc=$?
	fi

	if [ "$rc" -ne 0 ]; then
		return 77
	fi
	if grep -qx -- '-- No entries --' "$out" 2>/dev/null; then
		: >"$out"
	fi
	return 0
}

run_arecord_once() {
	local rate=$1
	local format=$2
	local channels=$3
	local duration=$4
	local wav_path=$5
	local log_path=$6
	local rc

	if arecord -D "$AUDIO_DEVICE" -f "$format" -r "$rate" -c "$channels" \
		-d "$duration" "$wav_path" >"$log_path" 2>&1; then
		rc=0
	else
		rc=$?
	fi
	printf 'exit_code=%s\n' "$rc" >>"$log_path"
	return "$rc"
}

validate_capture() {
	local wav_path=$1
	local capture_log=$2
	local warning_log=$3
	local error_log=$4
	local warning_rc=$5
	local error_rc=$6
	local rate=$7
	local format=$8
	local channels=$9
	local duration=${10}
	local out=${11}
	local capture_rc=${12}
	local size=0
	local codec=""
	local sample_rate=""
	local file_channels=""
	local bits_per_sample=""
	local stream_duration=""
	local max_volume=""
	local expected_codec
	local bits
	local bytes_per_sample
	local expected_data_bytes
	local min_data_bytes
	local actual_data_bytes=0
	local header_ok=0
	local size_ok=0
	local nonzero_ok=0
	local rate_ok=0
	local channels_ok=0
	local format_ok=0
	local xrun_ok=0
	local warning_ok="unknown"
	local error_ok="unknown"
	local start_ok=0
	local stop_ok=0
	local capture_ok=0
	local no_truncation_ok=0

	if [ -f "$wav_path" ]; then
		size=$(stat -c %s "$wav_path" 2>/dev/null || printf '0')
	fi

	if [ "$size" -gt 0 ] &&
	   ffprobe -v error -select_streams a:0 -show_entries stream=codec_name \
		   -of default=noprint_wrappers=1:nokey=1 "$wav_path" >/dev/null 2>&1; then
		header_ok=1
		codec=$(ffprobe -v error -select_streams a:0 -show_entries stream=codec_name \
			-of default=noprint_wrappers=1:nokey=1 "$wav_path" 2>/dev/null | head -n 1)
		sample_rate=$(ffprobe -v error -select_streams a:0 -show_entries stream=sample_rate \
			-of default=noprint_wrappers=1:nokey=1 "$wav_path" 2>/dev/null | head -n 1)
		file_channels=$(ffprobe -v error -select_streams a:0 -show_entries stream=channels \
			-of default=noprint_wrappers=1:nokey=1 "$wav_path" 2>/dev/null | head -n 1)
		bits_per_sample=$(ffprobe -v error -select_streams a:0 -show_entries stream=bits_per_sample \
			-of default=noprint_wrappers=1:nokey=1 "$wav_path" 2>/dev/null | head -n 1)
		stream_duration=$(ffprobe -v error -show_entries format=duration \
			-of default=noprint_wrappers=1:nokey=1 "$wav_path" 2>/dev/null | head -n 1)
	fi

	bits=${bits_per_sample:-}
	if ! [[ "$bits" =~ ^[0-9]+$ ]] || [ "$bits" -eq 0 ]; then
		bits=$(format_bits "$format")
	fi
	bytes_per_sample=$(((bits + 7) / 8))
	expected_data_bytes=$((duration * rate * channels * bytes_per_sample))
	min_data_bytes=$((expected_data_bytes * (100 - SIZE_TOLERANCE_PERCENT) / 100))
	if [ "$size" -gt 44 ]; then
		actual_data_bytes=$((size - 44))
	fi
	if [ "$actual_data_bytes" -ge "$min_data_bytes" ]; then
		size_ok=1
		no_truncation_ok=1
	fi

	if [ "$header_ok" -eq 1 ]; then
		if [ "$sample_rate" = "$rate" ]; then
			rate_ok=1
		fi
		if [ "$file_channels" = "$channels" ]; then
			channels_ok=1
		fi
		expected_codec=$(format_codec "$format")
		if [ "$codec" = "$expected_codec" ]; then
			format_ok=1
		fi
	fi

	if [ "$header_ok" -eq 1 ]; then
		ffmpeg -nostdin -hide_banner -i "$wav_path" \
			-af volumedetect -f null - >/dev/null 2>"$out.volumedetect.log" || true
		max_volume=$(awk -F': ' '/max_volume/ { print $2 }' "$out.volumedetect.log" | tail -n 1)
		if [ -n "$max_volume" ] && [ "$max_volume" != "-inf dB" ]; then
			nonzero_ok=1
		fi
	fi

	if ! grep -Eiq '(^|[^a-z])(xrun|overrun|underrun)([^a-z]|$)' "$capture_log"; then
		xrun_ok=1
	fi

	if [ "$warning_rc" -eq 0 ]; then
		if [ ! -s "$warning_log" ]; then
			warning_ok=1
		else
			warning_ok=0
		fi
	fi
	if [ "$error_rc" -eq 0 ]; then
		if [ ! -s "$error_log" ]; then
			error_ok=1
		else
			error_ok=0
		fi
	fi

	if [ "$capture_rc" -eq 0 ] || [ "$size" -gt 44 ]; then
		start_ok=1
	fi
	if [ "$capture_rc" -eq 0 ]; then
		stop_ok=1
	fi

	if [ "$capture_rc" -eq 0 ] &&
	   [ "$header_ok" -eq 1 ] &&
	   [ "$size_ok" -eq 1 ] &&
	   [ "$nonzero_ok" -eq 1 ] &&
	   [ "$rate_ok" -eq 1 ] &&
	   [ "$channels_ok" -eq 1 ] &&
	   [ "$format_ok" -eq 1 ] &&
	   [ "$xrun_ok" -eq 1 ]; then
		capture_ok=1
	fi

	{
		printf 'wav=%s\n' "$wav_path"
		printf 'capture_log=%s\n' "$capture_log"
		printf 'capture_rc=%s\n' "$capture_rc"
		printf 'size_bytes=%s\n' "$size"
		printf 'actual_data_bytes=%s\n' "$actual_data_bytes"
		printf 'expected_data_bytes=%s\n' "$expected_data_bytes"
		printf 'min_data_bytes=%s\n' "$min_data_bytes"
		printf 'requested_rate=%s\n' "$rate"
		printf 'requested_format=%s\n' "$format"
		printf 'requested_channels=%s\n' "$channels"
		printf 'requested_duration=%s\n' "$duration"
		printf 'codec=%s\n' "${codec:-unknown}"
		printf 'sample_rate=%s\n' "${sample_rate:-unknown}"
		printf 'channels=%s\n' "${file_channels:-unknown}"
		printf 'bits_per_sample=%s\n' "${bits_per_sample:-unknown}"
		printf 'duration_seconds=%s\n' "${stream_duration:-unknown}"
		printf 'max_volume=%s\n' "${max_volume:-unknown}"
		printf 'header_ok=%s\n' "$header_ok"
		printf 'size_ok=%s\n' "$size_ok"
		printf 'nonzero_ok=%s\n' "$nonzero_ok"
		printf 'rate_ok=%s\n' "$rate_ok"
		printf 'channels_ok=%s\n' "$channels_ok"
		printf 'format_ok=%s\n' "$format_ok"
		printf 'xrun_ok=%s\n' "$xrun_ok"
		printf 'kernel_warning_ok=%s\n' "$warning_ok"
		printf 'kernel_error_ok=%s\n' "$error_ok"
		printf 'start_ok=%s\n' "$start_ok"
		printf 'stop_ok=%s\n' "$stop_ok"
		printf 'no_truncation_ok=%s\n' "$no_truncation_ok"
		printf 'capture_ok=%s\n' "$capture_ok"
	} >"$out"
}

capture_id_status() {
	local test_id=$1
	local analysis=$2
	local key
	local value

	case "$test_id" in
	capture_rate_*|capture_format_*|capture_channels_*|long_capture_*)
		key="capture_ok"
		;;
	wav_size_duration_*)
		key="size_ok"
		;;
	wav_nonzero_samples_*)
		key="nonzero_ok"
		;;
	wav_valid_headers_*)
		key="header_ok"
		;;
	captured_sample_rate_matches_*)
		key="rate_ok"
		;;
	captured_channel_count_matches_*)
		key="channels_ok"
		;;
	captured_sample_format_matches_*)
		key="format_ok"
		;;
	no_xruns_reported_*)
		key="xrun_ok"
		;;
	no_kernel_warnings_*)
		key="kernel_warning_ok"
		;;
	no_kernel_errors_*)
		key="kernel_error_ok"
		;;
	capture_start_succeeds_*)
		key="start_ok"
		;;
	capture_stop_succeeds_*)
		key="stop_ok"
		;;
	no_data_truncation_long_capture)
		key="no_truncation_ok"
		;;
	*)
		key="capture_ok"
		;;
	esac

	value=$(analysis_value "$analysis" "$key")
	case "$value" in
	1)
		printf 'PASS\n'
		;;
	0)
		printf 'FAIL\n'
		;;
	unknown)
		printf 'SKIP\n'
		;;
	*)
		printf 'FAIL\n'
		;;
	esac
}

capture_detail_for_id() {
	local test_id=$1
	local analysis=$2
	local status=$3

	case "$test_id" in
	capture_rate_*|captured_sample_rate_matches_*)
		printf 'requested_rate=%s sample_rate=%s capture_ok=%s' \
			"$(analysis_value "$analysis" requested_rate)" \
			"$(analysis_value "$analysis" sample_rate)" \
			"$(analysis_value "$analysis" capture_ok)"
		;;
	capture_format_*|captured_sample_format_matches_*)
		printf 'requested_format=%s codec=%s capture_ok=%s' \
			"$(analysis_value "$analysis" requested_format)" \
			"$(analysis_value "$analysis" codec)" \
			"$(analysis_value "$analysis" capture_ok)"
		;;
	capture_channels_*|captured_channel_count_matches_*)
		printf 'requested_channels=%s channels=%s capture_ok=%s' \
			"$(analysis_value "$analysis" requested_channels)" \
			"$(analysis_value "$analysis" channels)" \
			"$(analysis_value "$analysis" capture_ok)"
		;;
	no_kernel_warnings_*)
		if [ "$status" = "SKIP" ]; then
			printf 'journalctl unavailable or not readable without escalation'
		else
			printf 'kernel_warning_ok=%s' "$(analysis_value "$analysis" kernel_warning_ok)"
		fi
		;;
	no_kernel_errors_*)
		if [ "$status" = "SKIP" ]; then
			printf 'journalctl unavailable or not readable without escalation'
		else
			printf 'kernel_error_ok=%s' "$(analysis_value "$analysis" kernel_error_ok)"
		fi
		;;
	*)
		printf 'capture_rc=%s capture_ok=%s header_ok=%s size_ok=%s nonzero_ok=%s xrun_ok=%s' \
			"$(analysis_value "$analysis" capture_rc)" \
			"$(analysis_value "$analysis" capture_ok)" \
			"$(analysis_value "$analysis" header_ok)" \
			"$(analysis_value "$analysis" size_ok)" \
			"$(analysis_value "$analysis" nonzero_ok)" \
			"$(analysis_value "$analysis" xrun_ok)"
		;;
	esac
}

all_ids_passed() {
	local ids=$1
	local id

	for id in $ids; do
		state_has_pass "$id" || return 1
	done
	return 0
}

run_capture_case() {
	local case_id=$1
	local label=$2
	local rate=$3
	local format=$4
	local channels=$5
	local duration=$6
	local ids=$7
	local id
	local artifact_dir
	local playback_pid
	local capture_rc
	local warning_rc
	local error_rc
	local since
	local analysis
	local status
	local detail
	local name

	if all_ids_passed "$ids"; then
		for id in $ids; do
			skip_previous_pass "$id" "$(test_name "$id")"
		done
		return 0
	fi

	for id in $ids; do
		if state_has_pass "$id"; then
			skip_previous_pass "$id" "$(test_name "$id")"
		fi
	done

	artifact_dir="$OUTPUT_DIR/tests/$(safe_name "$case_id")"
	mkdir -p "$artifact_dir"
	log "RUN $case_id - $label (${rate}Hz $format ${channels}ch ${duration}s)"

	since=$(date '+%Y-%m-%d %H:%M:%S')
	start_playback_loop "$artifact_dir/playback.log"
	playback_pid=$LAST_BG_PID
	sleep 0.5

	if run_arecord_once "$rate" "$format" "$channels" "$duration" \
		"$artifact_dir/capture.wav" "$artifact_dir/arecord.log"; then
		capture_rc=0
	else
		capture_rc=$?
	fi

	stop_pid "$playback_pid"

	if capture_kernel_log "$since" warning "$artifact_dir/kernel-warnings.log"; then
		warning_rc=0
	else
		warning_rc=$?
	fi
	if capture_kernel_log "$since" err "$artifact_dir/kernel-errors.log"; then
		error_rc=0
	else
		error_rc=$?
	fi

	analysis="$artifact_dir/analysis.txt"
	validate_capture "$artifact_dir/capture.wav" "$artifact_dir/arecord.log" \
		"$artifact_dir/kernel-warnings.log" "$artifact_dir/kernel-errors.log" \
		"$warning_rc" "$error_rc" "$rate" "$format" "$channels" "$duration" \
		"$analysis" "$capture_rc"

	for id in $ids; do
		if state_has_pass "$id"; then
			continue
		fi
		status=$(capture_id_status "$id" "$analysis")
		detail=$(capture_detail_for_id "$id" "$analysis" "$status")
		name=$(test_name "$id")
		case "$status" in
		PASS)
			log "PASS $id"
			;;
		SKIP)
			log "SKIP $id - $detail"
			;;
		*)
			status="FAIL"
			log "FAIL $id - see $analysis"
			;;
		esac
		record_result "$id" "$status" "$name" "$detail" "$artifact_dir"
	done
}

rate_capture_id() {
	printf 'capture_rate_%s_fmt_%s_ch_%s\n' "$1" "$DEFAULT_FORMAT" "$DEFAULT_CHANNELS"
}

format_capture_id() {
	printf 'capture_format_%s_rate_%s_ch_%s\n' "$1" "$DEFAULT_RATE" "$DEFAULT_CHANNELS"
}

channels_capture_id() {
	printf 'capture_channels_%s_rate_%s_fmt_%s\n' "$1" "$DEFAULT_RATE" "$DEFAULT_FORMAT"
}

baseline_suffix() {
	printf 'rate_%s_fmt_%s_ch_%s\n' "$DEFAULT_RATE" "$DEFAULT_FORMAT" "$DEFAULT_CHANNELS"
}

record_aggregate() {
	local test_id=$1
	local ids=$2
	local name
	local missing=""
	local failed=""
	local id

	name=$(test_name "$test_id")
	if state_has_pass "$test_id"; then
		skip_previous_pass "$test_id" "$name"
		return 0
	fi

	for id in $ids; do
		if state_has_pass "$id"; then
			continue
		fi
		if [ -f "$STATE_FILE" ] &&
		   awk -F '\t' -v id="$id" '$1 == id && $2 == "FAIL" { found = 1 } END { exit found ? 0 : 1 }' "$STATE_FILE"; then
			failed="${failed:+$failed }$id"
		else
			missing="${missing:+$missing }$id"
		fi
	done

	if [ -z "$missing" ] && [ -z "$failed" ]; then
		log "PASS $test_id"
		record_result "$test_id" "PASS" "$name" "all advertised capture cases passed" ""
	else
		log "FAIL $test_id - failed=${failed:-none} missing=${missing:-none}"
		record_result "$test_id" "FAIL" "$name" "failed=${failed:-none} missing=${missing:-none}" ""
	fi
}

run_repeated_captures() {
	local test_id=$1
	local cycles=$2
	local duration=$3
	local artifact_dir
	local playback_pid
	local i
	local rc=0
	local capture_rc=0
	local name

	name=$(test_name "$test_id")
	if state_has_pass "$test_id"; then
		skip_previous_pass "$test_id" "$name"
		return 0
	fi

	artifact_dir="$OUTPUT_DIR/tests/$(safe_name "$test_id")"
	mkdir -p "$artifact_dir"
	log "RUN $test_id - cycles=$cycles duration=${duration}s"

	start_playback_loop "$artifact_dir/playback.log"
	playback_pid=$LAST_BG_PID
	sleep 0.5

	for ((i = 1; i <= cycles; i++)); do
		set +e
		run_arecord_once "$DEFAULT_RATE" "$DEFAULT_FORMAT" "$DEFAULT_CHANNELS" "$duration" \
			"$artifact_dir/capture-${i}.wav" "$artifact_dir/arecord-${i}.log"
		capture_rc=$?
		set -e
		if [ "$capture_rc" -ne 0 ]; then
			rc=$capture_rc
			printf 'failed_cycle=%s rc=%s\n' "$i" "$rc" >"$artifact_dir/failure.txt"
			break
		fi
		if grep -Eiq '(^|[^a-z])(xrun|overrun|underrun)([^a-z]|$)' "$artifact_dir/arecord-${i}.log"; then
			rc=1
			printf 'xrun_cycle=%s\n' "$i" >"$artifact_dir/failure.txt"
			break
		fi
	done

	stop_pid "$playback_pid"

	if [ "$rc" -eq 0 ]; then
		log "PASS $test_id"
		record_result "$test_id" "PASS" "$name" "cycles=$cycles duration=$duration" "$artifact_dir"
	else
		log "FAIL $test_id - see $artifact_dir"
		record_result "$test_id" "FAIL" "$name" "cycles=$cycles failed_cycle=${i}" "$artifact_dir"
	fi
}

run_rate_tests() {
	local rate
	local ids=""
	local id

	for rate in $REQUIRED_RATES; do
		id=$(rate_capture_id "$rate")
		run_capture_case "rate-$rate" "required rate $rate" \
			"$rate" "$DEFAULT_FORMAT" "$DEFAULT_CHANNELS" "$SMOKE_DURATION" "$id"
	done

	for rate in $OPTIONAL_RATES; do
		id=$(rate_capture_id "$rate")
		if rate_supported "$rate"; then
			run_capture_case "rate-$rate" "optional advertised rate $rate" \
				"$rate" "$DEFAULT_FORMAT" "$DEFAULT_CHANNELS" "$SMOKE_DURATION" "$id"
		elif state_has_pass "$id"; then
			skip_previous_pass "$id" "$(test_name "$id")"
		else
			mark_skip "$id" "$(test_name "$id")" "rate $rate is not advertised"
		fi
	done

	for rate in $(advertised_rates); do
		id=$(rate_capture_id "$rate")
		ids="${ids:+$ids }$id"
		run_capture_case "rate-$rate" "advertised rate $rate" \
			"$rate" "$DEFAULT_FORMAT" "$DEFAULT_CHANNELS" "$SMOKE_DURATION" "$id"
	done

	[ -n "$ids" ] && record_aggregate "capture_all_advertised_rates" "$ids"
	return 0
}

run_format_tests() {
	local format
	local ids=""
	local id

	for format in $REQUIRED_FORMATS; do
		id=$(format_capture_id "$format")
		run_capture_case "format-$format" "required format $format" \
			"$DEFAULT_RATE" "$format" "$DEFAULT_CHANNELS" "$SMOKE_DURATION" "$id"
	done

	for format in $OPTIONAL_FORMATS; do
		id=$(format_capture_id "$format")
		if format_supported "$format"; then
			run_capture_case "format-$format" "optional advertised format $format" \
				"$DEFAULT_RATE" "$format" "$DEFAULT_CHANNELS" "$SMOKE_DURATION" "$id"
		elif state_has_pass "$id"; then
			skip_previous_pass "$id" "$(test_name "$id")"
		else
			mark_skip "$id" "$(test_name "$id")" "format $format is not advertised"
		fi
	done

	for format in $(advertised_formats); do
		id=$(format_capture_id "$format")
		ids="${ids:+$ids }$id"
		run_capture_case "format-$format" "advertised format $format" \
			"$DEFAULT_RATE" "$format" "$DEFAULT_CHANNELS" "$SMOKE_DURATION" "$id"
	done

	[ -n "$ids" ] && record_aggregate "capture_all_advertised_formats" "$ids"
	return 0
}

run_channel_tests() {
	local channels
	local ids=""
	local id

	for channels in $REQUIRED_CHANNELS; do
		id=$(channels_capture_id "$channels")
		run_capture_case "channels-$channels" "required channel count $channels" \
			"$DEFAULT_RATE" "$DEFAULT_FORMAT" "$channels" "$SMOKE_DURATION" "$id"
	done

	for channels in $OPTIONAL_CHANNELS; do
		id=$(channels_capture_id "$channels")
		if channels_supported "$channels"; then
			run_capture_case "channels-$channels" "optional advertised channel count $channels" \
				"$DEFAULT_RATE" "$DEFAULT_FORMAT" "$channels" "$SMOKE_DURATION" "$id"
		elif state_has_pass "$id"; then
			skip_previous_pass "$id" "$(test_name "$id")"
		else
			mark_skip "$id" "$(test_name "$id")" "channel count $channels is not advertised"
		fi
	done

	for channels in $(advertised_channels); do
		id=$(channels_capture_id "$channels")
		ids="${ids:+$ids }$id"
		run_capture_case "channels-$channels" "advertised channel count $channels" \
			"$DEFAULT_RATE" "$DEFAULT_FORMAT" "$channels" "$SMOKE_DURATION" "$id"
	done

	[ -n "$ids" ] && record_aggregate "capture_all_advertised_channels" "$ids"
	return 0
}

run_baseline_capture_checks() {
	local suffix
	local ids

	suffix=$(baseline_suffix)
	ids="$(rate_capture_id "$DEFAULT_RATE")"
	ids="$ids $(format_capture_id "$DEFAULT_FORMAT")"
	ids="$ids $(channels_capture_id "$DEFAULT_CHANNELS")"
	ids="$ids wav_size_duration_$suffix"
	ids="$ids wav_nonzero_samples_$suffix"
	ids="$ids wav_valid_headers_$suffix"
	ids="$ids captured_sample_rate_matches_$suffix"
	ids="$ids captured_channel_count_matches_$suffix"
	ids="$ids captured_sample_format_matches_$suffix"
	ids="$ids no_xruns_reported_$suffix"
	ids="$ids no_kernel_warnings_$suffix"
	ids="$ids no_kernel_errors_$suffix"
	ids="$ids capture_start_succeeds_$suffix"
	ids="$ids capture_stop_succeeds_$suffix"

	run_capture_case "baseline-$suffix" "baseline capture and artifact checks" \
		"$DEFAULT_RATE" "$DEFAULT_FORMAT" "$DEFAULT_CHANNELS" "$SMOKE_DURATION" "$ids"
}

run_long_tests() {
	local suffix
	local ids

	if [ "$SKIP_LONG" -eq 1 ]; then
		mark_skip "long_capture_60s" "$(test_name long_capture_60s)" "--skip-long"
		mark_skip "long_capture_600s" "$(test_name long_capture_600s)" "--skip-long"
		mark_skip "long_capture_3600s" "$(test_name long_capture_3600s)" "--skip-long"
		mark_skip "no_data_truncation_long_capture" "$(test_name no_data_truncation_long_capture)" "--skip-long"
		return 0
	fi

	suffix=$(baseline_suffix)
	run_capture_case "long-60s-$suffix" "1-minute capture" \
		"$DEFAULT_RATE" "$DEFAULT_FORMAT" "$DEFAULT_CHANNELS" "$LONG_1M_DURATION" "long_capture_60s"
	run_capture_case "long-600s-$suffix" "10-minute capture" \
		"$DEFAULT_RATE" "$DEFAULT_FORMAT" "$DEFAULT_CHANNELS" "$LONG_10M_DURATION" "long_capture_600s"

	ids="long_capture_3600s no_data_truncation_long_capture"
	run_capture_case "long-3600s-$suffix" "1-hour capture and truncation check" \
		"$DEFAULT_RATE" "$DEFAULT_FORMAT" "$DEFAULT_CHANNELS" "$LONG_1H_DURATION" "$ids"
}

init_dirs() {
	local safe_device
	local state_root

	safe_device=$(safe_name "$AUDIO_DEVICE")
	if [ -z "$OUTPUT_DIR" ]; then
		OUTPUT_DIR="/tmp/hws-nvidia-hdmi-audio-progressive-$(timestamp)"
	fi
	if [ -z "$STATE_DIR" ]; then
		if [ -n "${XDG_STATE_HOME:-}" ]; then
			state_root=$XDG_STATE_HOME
		elif [ -n "${HOME:-}" ]; then
			state_root="$HOME/.local/state"
		else
			state_root="/tmp"
		fi
		STATE_DIR="$state_root/hws-nvidia-hdmi-audio-progressive/$safe_device"
	fi

	mkdir -p "$OUTPUT_DIR" "$STATE_DIR"
	STATE_FILE="$STATE_DIR/state.tsv"
	SESSION_FILE="$OUTPUT_DIR/session-results.tsv"
	CAPABILITY_DIR="$OUTPUT_DIR/capabilities"
	HW_PARAMS_FILE="$CAPABILITY_DIR/hw-params.txt"
	PLAYBACK_TONE="$OUTPUT_DIR/playback-tone.wav"
	mkdir -p "$CAPABILITY_DIR"
	: >"$SESSION_FILE"
	touch "$STATE_FILE"
}

write_run_summary() {
	{
		printf 'target=%s\n' "$TARGET"
		printf 'card=%s\n' "$CARD"
		printf 'profile=%s\n' "$PROFILE"
		printf 'audio_device_requested=%s\n' "$AUDIO_DEVICE_REQUESTED"
		printf 'audio_device=%s\n' "$AUDIO_DEVICE"
		printf 'output_dir=%s\n' "$OUTPUT_DIR"
		printf 'state_dir=%s\n' "$STATE_DIR"
		printf 'state_file=%s\n' "$STATE_FILE"
		printf 'required_rates=%s\n' "$REQUIRED_RATES"
		printf 'optional_rates=%s\n' "$OPTIONAL_RATES"
		printf 'required_formats=%s\n' "$REQUIRED_FORMATS"
		printf 'optional_formats=%s\n' "$OPTIONAL_FORMATS"
		printf 'required_channels=%s\n' "$REQUIRED_CHANNELS"
		printf 'optional_channels=%s\n' "$OPTIONAL_CHANNELS"
		printf 'default_rate=%s\n' "$DEFAULT_RATE"
		printf 'default_format=%s\n' "$DEFAULT_FORMAT"
		printf 'default_channels=%s\n' "$DEFAULT_CHANNELS"
		printf 'smoke_duration=%s\n' "$SMOKE_DURATION"
		printf 'short_duration=%s\n' "$SHORT_DURATION"
		printf 'repeat_cycles=%s\n' "$REPEAT_CYCLES"
		printf 'short_cycles=%s\n' "$SHORT_CYCLES"
		printf 'open_close_cycles=%s\n' "$OPEN_CLOSE_CYCLES"
		printf 'skip_long=%s\n' "$SKIP_LONG"
		printf 'strict_advertised=%s\n' "$STRICT_ADVERTISED"
		printf 'rerun_passed=%s\n' "$RERUN_PASSED"
		printf 'cap_rate_line=%s\n' "$CAP_RATE_LINE"
		printf 'cap_format_line=%s\n' "$CAP_FORMAT_LINE"
		printf 'cap_channel_line=%s\n' "$CAP_CHANNEL_LINE"
	} >"$OUTPUT_DIR/run-summary.txt"
}

print_session_summary() {
	local pass
	local fail
	local skip
	local skip_pass

	pass=$(awk -F '\t' '$2 == "PASS" { n++ } END { print n + 0 }' "$SESSION_FILE")
	fail=$(awk -F '\t' '$2 == "FAIL" { n++ } END { print n + 0 }' "$SESSION_FILE")
	skip=$(awk -F '\t' '$2 == "SKIP" { n++ } END { print n + 0 }' "$SESSION_FILE")
	skip_pass=$(awk -F '\t' '$2 == "SKIP_PASS" { n++ } END { print n + 0 }' "$SESSION_FILE")

	{
		printf 'pass=%s\n' "$pass"
		printf 'fail=%s\n' "$fail"
		printf 'skip=%s\n' "$skip"
		printf 'skip_previous_pass=%s\n' "$skip_pass"
		printf 'session_results=%s\n' "$SESSION_FILE"
		printf 'state_file=%s\n' "$STATE_FILE"
		printf 'output_dir=%s\n' "$OUTPUT_DIR"
	} | tee "$OUTPUT_DIR/summary.txt"

	if [ "$fail" -gt 0 ]; then
		return 1
	fi
	return 0
}

main() {
	parse_args "$@"

	if [ "$LIST_TARGETS" -eq 1 ]; then
		hws_list_hdmi_sinks
		exit 0
	fi

	hws_require_cmds arecord ffmpeg ffprobe pw-play pactl awk sed grep stat date

	if [ -n "$PROFILE" ]; then
		hws_set_nvidia_profile "$CARD" "$PROFILE"
		sleep 1
		fi
		TARGET=$(hws_resolve_playback_target "$TARGET")
		resolve_audio_device

		init_dirs
	hws_write_audio_context "$OUTPUT_DIR/context"

	if ! dump_hw_params "$HW_PARAMS_FILE"; then
		log "WARN: --dump-hw-params returned non-zero; capability checks may fail. See $HW_PARAMS_FILE"
	fi
	CAP_RATE_LINE=$(hw_param_line RATE || true)
	CAP_FORMAT_LINE=$(hw_param_line FORMAT || true)
	CAP_CHANNEL_LINE=$(hw_param_line CHANNELS || true)
	write_run_summary

	log "output_dir=$OUTPUT_DIR"
	log "state_file=$STATE_FILE"
	log "target=$TARGET"
	log "audio_device=$AUDIO_DEVICE"

	run_simple_test "alsa_enumerates" test_alsa_enumerates
	run_simple_test "alsa_open" test_alsa_open_once
	run_simple_test "alsa_close" test_alsa_close_once

	run_simple_test "advertised_rates_expected" test_advertised_rates_expected
	run_simple_test "advertised_formats_expected" test_advertised_formats_expected
	run_simple_test "advertised_channels_expected" test_advertised_channels_expected

	run_baseline_capture_checks
	run_rate_tests
	run_format_tests
	run_channel_tests

	run_repeated_captures "repeated_start_stop_cycles" "$REPEAT_CYCLES" "$SHORT_DURATION"
	run_repeated_captures "short_capture_100_cycles" "$SHORT_CYCLES" "$SHORT_DURATION"
	run_simple_test "open_close_1000_cycles" test_open_close_cycles
	run_long_tests

	print_session_summary
}

main "$@"
