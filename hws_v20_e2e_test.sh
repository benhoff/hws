#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# End-to-end hardware validation for the guarded native half-ring video path.
# The default invocation is a read-only preflight. Pass --run to reload the
# in-tree module and exercise real capture hardware.

set -Eeuo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
MODULE_PATH="$SCRIPT_DIR/src/HwsCapture.ko"
BDF=auto
DEVICE=auto
OUTPUT_DIR=
RUN=0
FAULT_INJECTION=0
SKIP_AUDIO=0
SKIP_CPU_STRESS=0
SKIP_MODULE_RELOAD=0
ALLOW_STALE_MODULE=0
FRAMES=120
STRESS_FRAMES=240
RAPID_LOOPS=40
AUDIO_SECONDS=5
AUDIO_SOURCE_PCM=
CPU_WORKERS=auto

MODULE_NAME=HwsCapture
MODULE_TOUCHED=0
ORIGINAL_AUDIO_PARAMETER=Y
TEST_AUDIO_PARAMETER=Y
AUDIO_PARAMETER_OVERRIDE=auto
CURRENT_FORCE_INTX=N
PCI_INTX_GATED=0
KLOG_MODE=
KLOG_START=
KLOG_BASELINE_LINES=0
KLOG_FILE=
PHASE_KLOG_LINES=0
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
CURRENT_STEP=0
TOTAL_STEPS=8
SUMMARY_FILE=
PRIMARY_DEVICE=
PRIMARY_NAME=
AUDIO_SOURCE_PID=

declare -a VIDEO_NODES=()
declare -a LIVE_VIDEO_NODES=()
declare -a AUDIO_PCMS=()
declare -a CHILD_PIDS=()
declare -a STRESS_PIDS=()

usage() {
	cat <<'EOF'
Usage: ./hws_v20_e2e_test.sh [options]

Validate the production HwsCapture guarded native half-ring path end to end.
Without --run the script performs a read-only preflight and prints the target.

Normal execution:
  1. Verify HwsCapture.ko matches the running kernel and is not stale.
  2. Refuse to proceed if an HWS video/audio device is open.
  3. Reload the in-tree module in normal MSI-preferred mode and verify it.
  4. Discover HWS video and ALSA nodes through the selected PCI function.
  5. Capture complete MMAP frames after startup synchronization.
  6. Verify packed YUYV, reject USERPTR, stress copies, and repeat STREAMON/OFF.
  7. Capture all live video inputs concurrently with embedded audio.
  8. Optionally reload with forced INTx and inject W1C coalescing.
  9. Reload in normal MSI-preferred mode and prove capture recovers.

Options:
  --run                    Perform hardware-changing tests (root required)
  --module PATH            Module to test. Default: src/HwsCapture.ko
  --bdf BDF                PCI function. Default: auto-detect exactly one HWS card
  --device DEV             Primary V4L2 node. Default: first live HWS input
  --frames N               Normal capture frames. Default: 120
  --stress-frames N        Frames captured under CPU load. Default: 240
  --rapid-loops N          Short STREAMON/OFF iterations. Default: 40
  --audio-seconds N        Concurrent ALSA capture duration. Default: 5
  --audio-source-pcm PCM   Play a 48 kHz stereo test tone through PCM while
                           validating embedded audio, for example hw:1,3
  --cpu-workers N          CPU load workers. Default: min(nproc, 8)
  --output-dir DIR         Evidence directory. Default: /tmp timestamp directory
  --enable-audio           Load the test module with enable_audio=Y
  --disable-audio          Load the test module with enable_audio=N
                           Default: preserve the currently loaded setting
  --skip-audio             Do not exercise embedded audio PCMs
  --skip-cpu-stress        Do not run the CPU-contention phase
  --skip-module-reload     Test the already-loaded module; require srcversion match
  --allow-stale-module     Permit a module older than a driver source/header file
  --fault-injection        Reload with force_intx=Y, gate INTx for 50 ms,
                           and require W1C ambiguity to fail the queue closed
  -h, --help               Show this help

Build and run:
  make -C src
  sudo ./hws_v20_e2e_test.sh --run

The test requires a live signal on at least one HWS input. The fault-injection
phase is opt-in because it deliberately interrupts delivery from the PCI card.
The script always restores the PCI INTx-disable bit, even when interrupted.
It leaves the tested in-tree module loaded in normal MSI-preferred mode.
EOF
}

log() {
	printf '%s\n' "$*"
	if [[ -n "$SUMMARY_FILE" ]]; then
		printf '%s\n' "$*" >>"$SUMMARY_FILE"
	fi
}

die() {
	log "ERROR: $*"
	exit 2
}

is_uint() {
	[[ "$1" =~ ^[0-9]+$ ]]
}

print_command() {
	printf '+'
	printf ' %q' "$@"
	printf '\n'
}

pass() {
	PASS_COUNT=$((PASS_COUNT + 1))
	log "PASS: $*"
}

fail() {
	FAIL_COUNT=$((FAIL_COUNT + 1))
	log "FAIL: $*"
}

skip() {
	SKIP_COUNT=$((SKIP_COUNT + 1))
	log "SKIP: $*"
}

step() {
	CURRENT_STEP=$((CURRENT_STEP + 1))
	log ""
	log "[$CURRENT_STEP/$TOTAL_STEPS] $*"
}

parse_args() {
	while (($#)); do
		case "$1" in
		--run)
			RUN=1
			shift
			;;
		--module)
			MODULE_PATH=${2:?missing value for --module}
			shift 2
			;;
		--bdf)
			BDF=${2:?missing value for --bdf}
			shift 2
			;;
		--device)
			DEVICE=${2:?missing value for --device}
			shift 2
			;;
		--frames)
			FRAMES=${2:?missing value for --frames}
			shift 2
			;;
		--stress-frames)
			STRESS_FRAMES=${2:?missing value for --stress-frames}
			shift 2
			;;
		--rapid-loops)
			RAPID_LOOPS=${2:?missing value for --rapid-loops}
			shift 2
			;;
		--audio-seconds)
			AUDIO_SECONDS=${2:?missing value for --audio-seconds}
			shift 2
			;;
		--audio-source-pcm)
			AUDIO_SOURCE_PCM=${2:?missing value for --audio-source-pcm}
			shift 2
			;;
		--cpu-workers)
			CPU_WORKERS=${2:?missing value for --cpu-workers}
			shift 2
			;;
		--output-dir)
			OUTPUT_DIR=${2:?missing value for --output-dir}
			shift 2
			;;
		--enable-audio)
			AUDIO_PARAMETER_OVERRIDE=Y
			shift
			;;
		--disable-audio)
			AUDIO_PARAMETER_OVERRIDE=N
			shift
			;;
		--skip-audio)
			SKIP_AUDIO=1
			shift
			;;
		--skip-cpu-stress)
			SKIP_CPU_STRESS=1
			shift
			;;
		--skip-module-reload)
			SKIP_MODULE_RELOAD=1
			shift
			;;
		--allow-stale-module)
			ALLOW_STALE_MODULE=1
			shift
			;;
		--fault-injection)
			FAULT_INJECTION=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			printf 'Unknown option: %s\n\n' "$1" >&2
			usage >&2
			exit 2
			;;
		esac
	done
}

validate_args() {
	local value

	for value in "$FRAMES" "$STRESS_FRAMES" "$RAPID_LOOPS" \
		"$AUDIO_SECONDS"; do
		is_uint "$value" || die "numeric options must be unsigned integers"
		((value > 0)) || die "frame, loop, and duration counts must be nonzero"
	done
	if [[ "$CPU_WORKERS" != auto ]]; then
		is_uint "$CPU_WORKERS" || die "--cpu-workers must be a positive integer"
		((CPU_WORKERS > 0)) || die "--cpu-workers must be nonzero"
	fi
	if [[ -n "$AUDIO_SOURCE_PCM" ]]; then
		[[ "$AUDIO_SOURCE_PCM" =~ ^hw:[0-9]+,[0-9]+$ ]] ||
			die "--audio-source-pcm must use hw:CARD,DEVICE syntax"
		((SKIP_AUDIO == 0)) ||
			die "--audio-source-pcm cannot be combined with --skip-audio"
		[[ "$AUDIO_PARAMETER_OVERRIDE" != N ]] ||
			die "--audio-source-pcm cannot be combined with --disable-audio"
	fi
	if ((FAULT_INJECTION && SKIP_MODULE_RELOAD)); then
		die "--fault-injection cannot be combined with --skip-module-reload; recovery must be tested"
	fi
	if ((SKIP_MODULE_RELOAD)) && [[ "$AUDIO_PARAMETER_OVERRIDE" != auto ]]; then
		die "audio load overrides cannot be combined with --skip-module-reload"
	fi
	if [[ "$BDF" != auto && "$BDF" =~ ^[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]$ ]]; then
		BDF="0000:$BDF"
	fi
}

require_commands() {
	local command
	local -a commands=(modinfo sha256sum realpath v4l2-ctl timeout)

	if ((RUN)); then
		commands+=(insmod rmmod udevadm fuser journalctl)
		((SKIP_AUDIO)) || commands+=(arecord)
		[[ -n "$AUDIO_SOURCE_PCM" ]] && commands+=(speaker-test)
		((FAULT_INJECTION)) && commands+=(setpci)
	fi
	for command in "${commands[@]}"; do
		command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
	done
}

is_supported_hws_bdf() {
	local bdf=$1
	local sysfs="/sys/bus/pci/devices/$bdf"
	local vendor device subvendor subdevice

	[[ -r "$sysfs/vendor" && -r "$sysfs/device" && \
		-r "$sysfs/subsystem_vendor" && -r "$sysfs/subsystem_device" ]] ||
		return 1
	vendor=$(<"$sysfs/vendor")
	device=$(<"$sysfs/device")
	subvendor=$(<"$sysfs/subsystem_vendor")
	subdevice=$(<"$sysfs/subsystem_device")
	vendor=${vendor,,}
	device=${device,,}
	subvendor=${subvendor,,}
	subdevice=${subdevice,,}
	[[ "$subvendor:$subdevice" == "0x8888:0x0007" ]] || return 1
	case "$vendor:$device" in
	0x8888:0x9534|0x1f33:0x8534|0x1f33:0x8554|\
	0x8888:0x8524|0x1f33:0x6524|0x8888:0x8504|\
	0x8888:0x6504|0x8888:0x8532|0x8888:0x8512|\
	0x8888:0x8501|0x1f33:0x6502|0x1f33:0x8504|\
	0x1f33:0x8524)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

resolve_bdf() {
	local path candidate
	local -a candidates=()

	if [[ "$BDF" != auto ]]; then
		BDF=${BDF,,}
		is_supported_hws_bdf "$BDF" ||
			die "$BDF is not a supported HWS PCI function with subsystem 8888:0007"
		return
	fi

	shopt -s nullglob
	for path in /sys/bus/pci/devices/*; do
		candidate=${path##*/}
		if is_supported_hws_bdf "$candidate"; then
			candidates+=("$candidate")
		fi
	done
	shopt -u nullglob
	((${#candidates[@]} > 0)) || die "no supported HWS PCI function was found"
	if ((${#candidates[@]} != 1)); then
		die "found ${#candidates[@]} HWS functions (${candidates[*]}); select one with --bdf"
	fi
	BDF=${candidates[0]}
}

validate_module() {
	local module_name vermagic srcversion source stale=0

	MODULE_PATH=$(realpath -e -- "$MODULE_PATH" 2>/dev/null) ||
		die "module does not exist: $MODULE_PATH"
	module_name=$(modinfo -F name "$MODULE_PATH" 2>/dev/null || true)
	[[ "$module_name" == "$MODULE_NAME" ]] ||
		die "$MODULE_PATH identifies as '$module_name', not $MODULE_NAME"
	vermagic=$(modinfo -F vermagic "$MODULE_PATH" 2>/dev/null || true)
	[[ "$vermagic" == "$(uname -r) "* ]] ||
		die "module vermagic '$vermagic' does not match running kernel $(uname -r)"
	srcversion=$(modinfo -F srcversion "$MODULE_PATH" 2>/dev/null || true)
	[[ -n "$srcversion" ]] || die "module has no srcversion"

	shopt -s nullglob
	for source in "$SCRIPT_DIR"/src/*.c "$SCRIPT_DIR"/src/*.h \
		"$SCRIPT_DIR"/src/Makefile; do
		if [[ "$source" -nt "$MODULE_PATH" ]]; then
			log "STALE: ${source##*/} is newer than ${MODULE_PATH##*/}"
			stale=1
		fi
	done
	shopt -u nullglob
	if ((stale && !ALLOW_STALE_MODULE)); then
		die "rebuild with 'make -C src', or explicitly pass --allow-stale-module"
	fi
}

path_belongs_to_bdf() {
	local path=$1
	local resolved

	resolved=$(realpath -e -- "$path" 2>/dev/null || true)
	[[ "$resolved" == *"/$BDF/"* || "$resolved" == *"/$BDF" ]]
}

discover_video_nodes() {
	local class node

	VIDEO_NODES=()
	shopt -s nullglob
	for class in /sys/class/video4linux/video*; do
		if path_belongs_to_bdf "$class/device"; then
			node="/dev/${class##*/}"
			[[ -c "$node" ]] && VIDEO_NODES+=("$node")
		fi
	done
	shopt -u nullglob
	if ((${#VIDEO_NODES[@]})); then
		mapfile -t VIDEO_NODES < <(printf '%s\n' "${VIDEO_NODES[@]}" | sort -V)
	fi
}

discover_audio_pcms() {
	local class base rest card device

	AUDIO_PCMS=()
	shopt -s nullglob
	for class in /sys/class/sound/pcmC*D*c; do
		path_belongs_to_bdf "$class/device" || continue
		base=${class##*/}
		rest=${base#pcmC}
		card=${rest%%D*}
		rest=${rest#*D}
		device=${rest%c}
		[[ "$card" =~ ^[0-9]+$ && "$device" =~ ^[0-9]+$ ]] || continue
		AUDIO_PCMS+=("hw:$card,$device")
	done
	shopt -u nullglob
}

discover_owned_device_files() {
	local class node

	discover_video_nodes
	printf '%s\n' "${VIDEO_NODES[@]}"
	shopt -s nullglob
	for class in /sys/class/sound/*; do
		path_belongs_to_bdf "$class/device" || continue
		node="/dev/snd/${class##*/}"
		[[ -e "$node" ]] && printf '%s\n' "$node"
	done
	shopt -u nullglob
}

refuse_open_devices() {
	local node users pid process
	local busy=0

	while IFS= read -r node; do
		[[ -n "$node" ]] || continue
		users=$(fuser "$node" 2>/dev/null || true)
		if [[ -n "$users" ]]; then
			for pid in $users; do
				process=$(ps -p "$pid" -o comm= 2>/dev/null || true)
				[[ -n "$process" ]] || process=unknown
				log "BUSY: $node is open by PID $pid ($process)"
			done
			busy=1
		fi
	done < <(discover_owned_device_files)
	((busy == 0)) || die "close the listed HWS users before module reload; no processes were killed"
}

unload_test_module() {
	local refcount holder

	refuse_open_devices
	print_command rmmod "$MODULE_NAME"
	if rmmod "$MODULE_NAME"; then
		return 0
	fi
	refcount=
	if [[ -r "/sys/module/$MODULE_NAME/refcnt" ]]; then
		refcount=$(<"/sys/module/$MODULE_NAME/refcnt")
	fi
	[[ -n "$refcount" ]] && log "Module reference count after failed unload: $refcount"
	shopt -s nullglob
	for holder in "/sys/module/$MODULE_NAME/holders/"*; do
		log "Module holder: ${holder##*/}"
	done
	shopt -u nullglob
	# Catch an application that raced the first device check.
	refuse_open_devices
	die "$MODULE_NAME could not be unloaded; inspect module holders and open descriptors"
}

wait_for_nodes() {
	local attempt

	for ((attempt = 0; attempt < 100; attempt++)); do
		discover_video_nodes
		((${#VIDEO_NODES[@]} > 0)) && return 0
		sleep 0.1
	done
	return 1
}

verify_loaded_module() {
	local expected loaded

	[[ -d "/sys/module/$MODULE_NAME" ]] || die "$MODULE_NAME did not load"
	expected=$(modinfo -F srcversion "$MODULE_PATH")
	loaded=
	if [[ -r "/sys/module/$MODULE_NAME/srcversion" ]]; then
		loaded=$(<"/sys/module/$MODULE_NAME/srcversion")
	fi
	[[ -n "$loaded" ]] || die "loaded module does not expose a srcversion"
	[[ "$loaded" == "$expected" ]] ||
		die "loaded srcversion $loaded does not match test module $expected"
}

msi_is_active() {
	local msi_dir="/sys/bus/pci/devices/$BDF/msi_irqs"

	[[ -d "$msi_dir" ]] && compgen -G "$msi_dir/*" >/dev/null
}

verify_irq_mode() {
	local expected_force_intx=$1
	local loaded_force_intx=

	if [[ -r "/sys/module/$MODULE_NAME/parameters/force_intx" ]]; then
		loaded_force_intx=$(<"/sys/module/$MODULE_NAME/parameters/force_intx")
	fi
	[[ "$loaded_force_intx" == "$expected_force_intx" ]] ||
		die "loaded force_intx=$loaded_force_intx; expected $expected_force_intx"

	if [[ "$expected_force_intx" == Y ]]; then
		msi_is_active && die "force_intx=Y was requested, but $BDF still has active MSI IRQs"
		log "IRQ mode verified: forced legacy INTx"
	else
		msi_is_active || die "normal validation requires MSI/MSI-X, but $BDF fell back to legacy INTx"
		log "IRQ mode verified: MSI/MSI-X"
	fi
}

load_test_module() {
	local audio_parameter=$TEST_AUDIO_PARAMETER
	local force_intx=${1:-N}

	MODULE_TOUCHED=1
	if [[ -d "/sys/module/$MODULE_NAME" ]]; then
		unload_test_module
	fi
	print_command insmod "$MODULE_PATH" "enable_audio=$audio_parameter" \
		"force_intx=$force_intx"
	insmod "$MODULE_PATH" "enable_audio=$audio_parameter" \
		"force_intx=$force_intx"
	CURRENT_FORCE_INTX=$force_intx
	udevadm settle --timeout=10 || true
	wait_for_nodes || die "no HWS video nodes appeared for $BDF after module load"
	verify_loaded_module
	verify_irq_mode "$force_intx"
}

stop_children() {
	local pid

	for pid in "${CHILD_PIDS[@]}" "${STRESS_PIDS[@]}"; do
		[[ -n "$pid" ]] || continue
		if kill -0 "$pid" 2>/dev/null; then
			kill -TERM "$pid" 2>/dev/null || true
		fi
	done
	for pid in "${CHILD_PIDS[@]}" "${STRESS_PIDS[@]}"; do
		[[ -n "$pid" ]] || continue
		wait "$pid" 2>/dev/null || true
	done
	CHILD_PIDS=()
	STRESS_PIDS=()
}

restore_intx() {
	if ((PCI_INTX_GATED)); then
		setpci -s "$BDF" COMMAND=0000:0400 2>/dev/null || {
			printf 'CRITICAL: failed to restore PCI INTx delivery on %s\n' "$BDF" >&2
			return 1
		}
		PCI_INTX_GATED=0
	fi
}

cleanup() {
	local exit_code=$?
	local loaded_force_intx=
	local restore_normal=0

	trap - EXIT INT TERM
	if ! restore_intx; then
		exit_code=1
	fi
	stop_audio_source
	stop_children
	if ((RUN && MODULE_TOUCHED)); then
		if [[ ! -d "/sys/module/$MODULE_NAME" ]]; then
			restore_normal=1
		elif [[ -r "/sys/module/$MODULE_NAME/parameters/force_intx" ]]; then
			loaded_force_intx=$(<"/sys/module/$MODULE_NAME/parameters/force_intx")
			[[ "$loaded_force_intx" == Y ]] && restore_normal=1
		fi
		if ((restore_normal)); then
			printf 'Cleanup: restoring tested module in MSI-preferred mode\n' >&2
			if [[ -d "/sys/module/$MODULE_NAME" ]] && ! rmmod "$MODULE_NAME"; then
				printf 'CRITICAL: could not unload forced-INTx module; manual reload is required\n' >&2
				exit_code=1
			elif ! insmod "$MODULE_PATH" "enable_audio=$TEST_AUDIO_PARAMETER" \
				"force_intx=N"; then
				printf 'CRITICAL: could not restore HWS service; manual module load is required\n' >&2
				exit_code=1
			fi
		fi
	fi
	exit "$exit_code"
}

init_klog() {
	KLOG_FILE="$OUTPUT_DIR/kernel.log"
	KLOG_START=$(date '+%Y-%m-%d %H:%M:%S')
	# The kernel ring is immediate; journald can attribute a late-ingested
	# message to the phase after the one that actually triggered it.
	if dmesg >/dev/null 2>&1; then
		KLOG_MODE=dmesg
		dmesg >"$OUTPUT_DIR/dmesg-baseline.log"
		KLOG_BASELINE_LINES=$(wc -l <"$OUTPUT_DIR/dmesg-baseline.log")
		: >"$KLOG_FILE"
	elif journalctl -k -n 0 --no-pager >/dev/null 2>&1; then
		KLOG_MODE=journal
		: >"$KLOG_FILE"
	else
		die "kernel log is unreadable; fail-closed behavior cannot be assessed"
	fi
}

collect_klog() {
	local all_log="$OUTPUT_DIR/dmesg-current.log"

	if [[ "$KLOG_MODE" == journal ]]; then
		journalctl -k --since "$KLOG_START" -o short-iso-precise --no-pager \
			| sed '/^-- No entries --$/d' >"$KLOG_FILE"
	else
		dmesg >"$all_log"
		tail -n "+$((KLOG_BASELINE_LINES + 1))" "$all_log" >"$KLOG_FILE"
	fi
}

phase_begin() {
	collect_klog
	PHASE_KLOG_LINES=$(wc -l <"$KLOG_FILE")
}

phase_log_delta() {
	local tag=$1
	local delta="$OUTPUT_DIR/klog-$tag.log"

	collect_klog
	tail -n "+$((PHASE_KLOG_LINES + 1))" "$KLOG_FILE" >"$delta"
	printf '%s\n' "$delta"
}

kernel_delta_is_clean() {
	local delta=$1
	local universal='BUG:|WARNING:|Oops:|KASAN:|KFENCE:|general protection fault|kernel panic|use-after-free'
	local hws_fatal='VDONE ambiguity|VDONE half-ring failure|video queue failed|DMA guard corruption|retained DMA-owned|failed to restart guarded ring|threaded IRQ processing many VDONE events|audio ch[0-9]+ packet overrun|audio start refused|shared-window conflict'

	if grep -EinE "$universal" "$delta" >"$delta.failures"; then
		return 1
	fi
	if grep -EinE "$hws_fatal" "$delta" >>"$delta.failures"; then
		return 1
	fi
	rm -f -- "$delta.failures"
	return 0
}

finish_clean_phase() {
	local tag=$1
	local description=$2
	local delta

	delta=$(phase_log_delta "$tag")
	if kernel_delta_is_clean "$delta"; then
		pass "$description produced no kernel safety failure"
	else
		fail "$description produced a kernel safety failure (see $delta.failures)"
	fi
}

video_has_live_signal() {
	local node=$1
	local output

	output=$(timeout 3 v4l2-ctl -d "$node" --list-inputs 2>&1) || return 1
	[[ ! "$output" =~ \([Nn]o[[:space:]][Ss]ignal\) ]]
}

select_video_nodes() {
	local node class name

	discover_video_nodes
	((${#VIDEO_NODES[@]} > 0)) || die "no video nodes belong to $BDF"
	LIVE_VIDEO_NODES=()
	PRIMARY_DEVICE=
	for node in "${VIDEO_NODES[@]}"; do
		class="/sys/class/video4linux/${node##*/}"
		name=$(<"$class/name")
		v4l2-ctl -d "$node" --all >"$OUTPUT_DIR/${node##*/}-all.txt" 2>&1 || true
		v4l2-ctl -d "$node" --query-dv-timings \
			>"$OUTPUT_DIR/${node##*/}-timings.txt" 2>&1 || true
		if video_has_live_signal "$node"; then
			LIVE_VIDEO_NODES+=("$node")
			log "LIVE: $node ($name)"
		else
			log "NO SIGNAL: $node ($name)"
		fi
	done
	((${#LIVE_VIDEO_NODES[@]} > 0)) ||
		die "no HWS input reports a live signal; connect a source and rerun"

	if [[ "$DEVICE" != auto ]]; then
		[[ -c "$DEVICE" ]] || die "$DEVICE is not a character device"
		for node in "${LIVE_VIDEO_NODES[@]}"; do
			[[ "$node" == "$DEVICE" ]] && PRIMARY_DEVICE=$node
		done
		[[ -n "$PRIMARY_DEVICE" ]] ||
			die "$DEVICE is not a live HWS input belonging to $BDF"
	else
		PRIMARY_DEVICE=${LIVE_VIDEO_NODES[0]}
	fi
	PRIMARY_NAME=$(<"/sys/class/video4linux/${PRIMARY_DEVICE##*/}/name")
	log "Primary capture node: $PRIMARY_DEVICE ($PRIMARY_NAME)"
}

set_live_timings() {
	local node=$1
	local logfile=$2

	if ! timeout 5 v4l2-ctl -d "$node" --set-dv-bt-timings=query \
		>"$logfile" 2>&1; then
		return 1
	fi
	v4l2-ctl -d "$node" --get-fmt-video >>"$logfile" 2>&1
}

format_sizeimage() {
	local node=$1

	v4l2-ctl -d "$node" --get-fmt-video 2>/dev/null |
		awk -F: '/Size Image/ {gsub(/[[:space:]]/, "", $2); print $2; exit}'
}

run_video_capture() {
	local node=$1
	local frames=$2
	local logfile=$3
	local output=${4:-/dev/null}
	local seconds=$((frames / 10 + 15))

	if ! timeout --signal=TERM --kill-after=2s "${seconds}s" \
		v4l2-ctl --silent -d "$node" --set-dv-bt-timings=query \
		--stream-mmap=4 --stream-poll --stream-count="$frames" \
		--stream-to="$output" >"$logfile" 2>&1; then
		return 1
	fi
	# v4l2-ctl 1.32 reports streaming ioctl failures but exits zero.
	if grep -Eiq 'VIDIOC_[A-Z0-9_]+: failed|(^|[[:space:]])(read|stream|select)[^:]*error:' \
		"$logfile"; then
		return 1
	fi
	return 0
}

test_startup_and_normal_capture() {
	local frames_file="$OUTPUT_DIR/startup-frames.yuyv"
	local sizeimage actual expected

	set_live_timings "$PRIMARY_DEVICE" "$OUTPUT_DIR/set-live-timings.log" || {
		fail "could not apply detected timings on $PRIMARY_DEVICE"
		return
	}
	sizeimage=$(format_sizeimage "$PRIMARY_DEVICE")
	if ! is_uint "$sizeimage" || ((sizeimage == 0)); then
		fail "could not determine sizeimage for $PRIMARY_DEVICE"
		return
	fi
	if run_video_capture "$PRIMARY_DEVICE" 3 "$OUTPUT_DIR/startup-capture.log" \
		"$frames_file"; then
		actual=$(stat -c '%s' "$frames_file")
		expected=$((sizeimage * 3))
		if ((actual == expected)); then
			pass "startup synchronization delivered 3 complete frames ($actual bytes)"
		else
			fail "startup capture size $actual did not equal 3 * sizeimage ($expected)"
		fi
	else
		fail "startup capture failed on $PRIMARY_DEVICE"
	fi
	if run_video_capture "$PRIMARY_DEVICE" "$FRAMES" \
		"$OUTPUT_DIR/normal-capture.log"; then
		pass "normal MMAP capture completed $FRAMES frames"
	else
		fail "normal MMAP capture did not complete $FRAMES frames"
	fi
}

test_memory_model() {
	local rc

	set +e
	timeout --signal=TERM --kill-after=1s 8s v4l2-ctl --verbose \
		-d "$PRIMARY_DEVICE" --set-dv-bt-timings=query \
		--stream-user=2 --stream-count=1 \
		>"$OUTPUT_DIR/userptr-rejection.log" 2>&1
	rc=$?
	set -e
	if ((rc == 124)); then
		fail "USERPTR rejection probe timed out"
	elif grep -Eq 'VIDIOC_REQBUFS returned -1 \(Invalid argument\)' \
		"$OUTPUT_DIR/userptr-rejection.log"; then
		pass "USERPTR capture was rejected (MMAP is the only VB2 I/O mode)"
	else
		fail "USERPTR probe did not observe VIDIOC_REQBUFS/EINVAL (exit $rc)"
	fi
}

test_packed_yuyv() {
	local logfile="$OUTPUT_DIR/packed-yuyv.log"
	local bytesperline sizeimage

	if ! timeout 5s v4l2-ctl -d "$PRIMARY_DEVICE" \
		--try-fmt-video=width=720,height=576,pixelformat=YUYV,bytesperline=4096,sizeimage=4194304 \
		>"$logfile" 2>&1; then
		fail "packed YUYV TRY_FMT probe failed"
		return
	fi
	bytesperline=$(awk -F: '/Bytes per Line/ {
		gsub(/[[:space:]]/, "", $2); print $2; exit
	}' "$logfile")
	sizeimage=$(awk -F: '/Size Image/ {
		gsub(/[[:space:]]/, "", $2); print $2; exit
	}' "$logfile")
	if [[ "$bytesperline" == 1440 && "$sizeimage" == 829440 ]]; then
		pass "padded TRY_FMT request was normalized to packed 720x576 YUYV"
	else
		fail "TRY_FMT returned bpl=${bytesperline:-missing} size=${sizeimage:-missing}; expected 1440/829440"
	fi
}

dv_timing_signature() {
	awk -F: '/Active width|Active height|Pixelclock/ {
		gsub(/^[[:space:]]+/, "", $2)
		split($2, value, /[[:space:]]+/)
		printf "%s/", value[1]
	}' "$1"
}

test_dv_timing_api() {
	local list_log="$OUTPUT_DIR/dv-list.log"
	local cap_log="$OUTPUT_DIR/dv-cap.log"
	local query_log="$OUTPUT_DIR/dv-query.log"
	local query_after_log="$OUTPUT_DIR/dv-query-after-set.log"
	local get_log="$OUTPUT_DIR/dv-get.log"
	local info_log="$OUTPUT_DIR/dv-info.log"
	local no_signal_log="$OUTPUT_DIR/dv-no-signal.log"
	local query_sig candidate_sig query_after_sig
	local candidate_found=0 modes=0 no_signal_tested=0
	local node idx

	if timeout 5s v4l2-ctl -d "$PRIMARY_DEVICE" --list-dv-timings \
		>"$list_log" 2>&1; then
		modes=$(grep -Ec '^[[:space:]]*Index[[:space:]]*:' "$list_log" || true)
		if ((modes > 1)); then
			pass "DV enumeration returned the full supported list ($modes modes)"
		else
			fail "DV enumeration returned only $modes mode(s)"
		fi
	else
		fail "DV timing enumeration failed"
	fi

	if timeout 5s v4l2-ctl -d "$PRIMARY_DEVICE" --get-dv-timings-cap \
		>"$cap_log" 2>&1 && grep -q 'Pixelclock' "$cap_log"; then
		pass "DV capabilities include bounded pixel-clock metadata"
	else
		fail "DV timing capabilities were incomplete"
	fi

	if ! timeout 5s v4l2-ctl -d "$PRIMARY_DEVICE" --query-dv-timings \
		>"$query_log" 2>&1; then
		fail "QUERY_DV_TIMINGS failed on the live input"
		return
	fi
	query_sig=$(dv_timing_signature "$query_log")
	if [[ -z "$query_sig" ]]; then
		fail "could not parse detected DV timings"
		return
	fi

	for idx in 0 1; do
		if ! timeout 5s v4l2-ctl -d "$PRIMARY_DEVICE" \
			--set-dv-bt-timings="index=$idx" \
			>"$OUTPUT_DIR/dv-set-index-$idx.log" 2>&1; then
			continue
		fi
		if ! timeout 5s v4l2-ctl -d "$PRIMARY_DEVICE" --get-dv-timings \
			>"$get_log" 2>&1; then
			continue
		fi
		candidate_sig=$(dv_timing_signature "$get_log")
		if [[ -n "$candidate_sig" && "$candidate_sig" != "$query_sig" ]]; then
			candidate_found=1
			break
		fi
	done

	if ((candidate_found)) &&
		timeout 5s v4l2-ctl -d "$PRIMARY_DEVICE" --query-dv-timings \
			>"$query_after_log" 2>&1; then
		query_after_sig=$(dv_timing_signature "$query_after_log")
		if [[ "$query_after_sig" == "$query_sig" ]]; then
			pass "configured and detected DV timing state remained independent"
		else
			fail "QUERY_DV_TIMINGS changed after configuring a different mode"
		fi
	else
		fail "could not exercise independent configured/detected DV state"
	fi

	if ! timeout 5s v4l2-ctl -d "$PRIMARY_DEVICE" \
		--set-dv-bt-timings=query \
		>"$OUTPUT_DIR/dv-restore-live.log" 2>&1; then
		fail "could not restore the detected DV timing after API checks"
		return
	fi

	if timeout 5s v4l2-ctl -d "$PRIMARY_DEVICE" --info >"$info_log" 2>&1 &&
		grep -Eq 'Bus info[[:space:]]*:[[:space:]]*PCI:' "$info_log"; then
		pass "QUERYCAP reports stable PCI bus_info"
	else
		fail "QUERYCAP did not report PCI bus_info"
	fi

	for node in "${VIDEO_NODES[@]}"; do
		if video_has_live_signal "$node"; then
			continue
		fi
		no_signal_tested=1
		if timeout 5s v4l2-ctl -d "$node" --query-dv-timings \
			>"$no_signal_log" 2>&1; then
			fail "QUERY_DV_TIMINGS succeeded without a signal on $node"
		else
			pass "QUERY_DV_TIMINGS rejected no-signal input on $node"
		fi
		break
	done
	if ((!no_signal_tested)); then
		skip "no inactive video node was available for the ENOLINK check"
	fi
}

start_cpu_stress() {
	local workers=$CPU_WORKERS
	local available worker

	available=$(nproc)
	if [[ "$workers" == auto ]]; then
		workers=$available
		((workers > 8)) && workers=8
	fi
	log "Starting $workers CPU workers (available CPUs: $available)"
	if command -v stress-ng >/dev/null 2>&1; then
		stress-ng --cpu "$workers" --cpu-method all --metrics-brief \
			>"$OUTPUT_DIR/cpu-stress.log" 2>&1 &
		STRESS_PIDS+=("$!")
	else
		for ((worker = 0; worker < workers; worker++)); do
			sha256sum /dev/zero >/dev/null 2>>"$OUTPUT_DIR/cpu-stress.log" &
			STRESS_PIDS+=("$!")
		done
	fi
	sleep 1
}

stop_cpu_stress() {
	local pid

	for pid in "${STRESS_PIDS[@]}"; do
		kill -TERM "$pid" 2>/dev/null || true
	done
	for pid in "${STRESS_PIDS[@]}"; do
		wait "$pid" 2>/dev/null || true
	done
	STRESS_PIDS=()
}

test_cpu_stress() {
	if ((SKIP_CPU_STRESS)); then
		skip "CPU-contention capture disabled by --skip-cpu-stress"
		return
	fi
	start_cpu_stress
	if run_video_capture "$PRIMARY_DEVICE" "$STRESS_FRAMES" \
		"$OUTPUT_DIR/stressed-capture.log"; then
		pass "MMAP capture completed $STRESS_FRAMES frames under CPU load"
	else
		fail "capture failed under CPU load"
	fi
	stop_cpu_stress
}

test_rapid_stream_cycles() {
	local iteration rc=0
	local logfile="$OUTPUT_DIR/rapid-stream-cycles.log"

	: >"$logfile"
	for ((iteration = 1; iteration <= RAPID_LOOPS; iteration++)); do
		printf '\niteration=%u\n' "$iteration" >>"$logfile"
		if ! run_video_capture "$PRIMARY_DEVICE" 4 "$logfile.iteration"; then
			rc=1
			printf 'capture failed at iteration %u\n' "$iteration" >>"$logfile"
			cat "$logfile.iteration" >>"$logfile"
			break
		fi
		cat "$logfile.iteration" >>"$logfile"
		if ((iteration % 10 == 0 || iteration == RAPID_LOOPS)); then
			log "  rapid STREAMON/OFF: $iteration/$RAPID_LOOPS"
		fi
	done
	rm -f -- "$logfile.iteration"
	if ((rc == 0)); then
		pass "$RAPID_LOOPS rapid STREAMON/OFF cycles completed"
	else
		fail "rapid STREAMON/OFF failed at iteration $iteration"
	fi
}

run_audio_capture() {
	local pcm=$1
	local logfile=$2

	timeout --signal=TERM --kill-after=2s "$((AUDIO_SECONDS + 8))s" \
		arecord -q --fatal-errors -D "$pcm" -t raw -f S16_LE -r 48000 \
		-c 2 -d "$AUDIO_SECONDS" /dev/null >"$logfile" 2>&1
}

audio_source_paths() {
	local spec=${AUDIO_SOURCE_PCM#hw:}
	local card=${spec%%,*}
	local device=${spec##*,}

	printf '%s\n' "/dev/snd/pcmC${card}D${device}p"
	printf '%s\n' "/proc/asound/card${card}/pcm${device}p/info"
	printf '%s\n' "/proc/asound/card${card}/pcm${device}p/sub0/status"
}

start_audio_source() {
	local spec=${AUDIO_SOURCE_PCM#hw:}
	local card=${spec%%,*}
	local node info status attempt rc eld
	local -a paths=()

	[[ -n "$AUDIO_SOURCE_PCM" ]] || return 0
	mapfile -t paths < <(audio_source_paths)
	node=${paths[0]}
	info=${paths[1]}
	status=${paths[2]}
	[[ -c "$node" ]] || {
		log "Audio source playback node is missing: $node"
		return 1
	}
	[[ -r "$info" ]] && grep -qx 'stream: PLAYBACK' "$info" || {
		log "Audio source is not a playback PCM: $AUDIO_SOURCE_PCM"
		return 1
	}
	cp "$info" "$OUTPUT_DIR/audio-source-pcm-info.txt"
	{
		shopt -s nullglob
		for eld in "/proc/asound/card${card}"/eld*; do
			printf '[%s]\n' "$eld"
			cat "$eld"
		done
		shopt -u nullglob
	} >"$OUTPUT_DIR/audio-source-eld.txt"

	log "Starting 48 kHz stereo HDMI tone on $AUDIO_SOURCE_PCM"
	speaker-test -D "$AUDIO_SOURCE_PCM" -r 48000 -c 2 -F S16_LE \
		-t sine -f 1000 -l 0 >"$OUTPUT_DIR/audio-source.log" 2>&1 &
	AUDIO_SOURCE_PID=$!
	for ((attempt = 0; attempt < 50; attempt++)); do
		if ! kill -0 "$AUDIO_SOURCE_PID" 2>/dev/null; then
			set +e
			wait "$AUDIO_SOURCE_PID"
			rc=$?
			set -e
			AUDIO_SOURCE_PID=
			log "Audio source exited before reaching RUNNING (exit $rc)"
			log "Audio source log: $OUTPUT_DIR/audio-source.log"
			return 1
		fi
		if [[ -r "$status" ]] && grep -qx 'state: RUNNING' "$status"; then
			cp "$status" "$OUTPUT_DIR/audio-source-running.txt"
			return 0
		fi
		sleep 0.1
	done
	log "Audio source did not reach RUNNING (see $OUTPUT_DIR/audio-source.log)"
	return 1
}

stop_audio_source() {
	local rc

	[[ -n "$AUDIO_SOURCE_PID" ]] || return 0
	kill -TERM "$AUDIO_SOURCE_PID" 2>/dev/null || true
	set +e
	wait "$AUDIO_SOURCE_PID"
	rc=$?
	set -e
	printf '%s\n' "$rc" >"$OUTPUT_DIR/audio-source-stop-rc.txt"
	AUDIO_SOURCE_PID=
}

video_node_channel() {
	local node=$1
	local name

	name=$(<"/sys/class/video4linux/${node##*/}/name")
	if [[ "$name" =~ ([0-9]+)$ ]]; then
		printf '%s\n' "${BASH_REMATCH[1]}"
		return 0
	fi
	return 1
}

audio_pcm_matches_live_video() {
	local pcm=$1
	local pcm_channel=${pcm##*,}
	local node video_channel

	for node in "${LIVE_VIDEO_NODES[@]}"; do
		video_channel=$(video_node_channel "$node" 2>/dev/null || true)
		[[ -n "$video_channel" && "$pcm_channel" == "$video_channel" ]] &&
			return 0
	done
	return 1
}

test_concurrent_capture() {
	local node pcm pid rc
	local failures=0
	local audio_started=0
	local index=0
	local -a labels=()
	local -a pids=()

	discover_audio_pcms
	if ((!SKIP_AUDIO)) && [[ -n "$AUDIO_SOURCE_PCM" ]]; then
		if start_audio_source; then
			pass "audio source $AUDIO_SOURCE_PCM reached RUNNING"
		else
			stop_audio_source
			fail "could not establish a verified HDMI audio source on $AUDIO_SOURCE_PCM"
			return
		fi
	elif ((!SKIP_AUDIO)); then
		log "Audio source is externally managed and was not verified by the harness"
	fi
	for node in "${LIVE_VIDEO_NODES[@]}"; do
		run_video_capture "$node" "$FRAMES" \
			"$OUTPUT_DIR/concurrent-${node##*/}.log" &
		pid=$!
		pids+=("$pid")
		CHILD_PIDS+=("$pid")
		labels+=("video:$node")
	done
	if ((SKIP_AUDIO)); then
		skip "embedded-audio concurrency disabled by --skip-audio"
	elif ((${#AUDIO_PCMS[@]} == 0)); then
		skip "selected card exposes no embedded-audio capture PCMs"
	else
		for pcm in "${AUDIO_PCMS[@]}"; do
			audio_pcm_matches_live_video "$pcm" || continue
			run_audio_capture "$pcm" \
				"$OUTPUT_DIR/concurrent-audio-${pcm//[:,]/-}.log" &
			pid=$!
			pids+=("$pid")
			CHILD_PIDS+=("$pid")
			labels+=("audio:$pcm")
			audio_started=$((audio_started + 1))
		done
		if ((audio_started == 0)); then
			skip "no embedded-audio PCM corresponds to a live video input"
		fi
	fi

	set +e
	for pid in "${pids[@]}"; do
		wait "$pid"
		rc=$?
		if ((rc != 0)); then
			log "  concurrent failure: ${labels[index]} exited $rc"
			failures=$((failures + 1))
		fi
		index=$((index + 1))
	done
	set -e
	CHILD_PIDS=()
	stop_audio_source
	if ((failures == 0)); then
		pass "concurrent capture completed (${#LIVE_VIDEO_NODES[@]} video, $audio_started audio)"
	else
		fail "$failures concurrent video/audio capture process(es) failed"
	fi
}

test_fault_injection() {
	local original_command rc delta
	local capture_pid

	if ((!FAULT_INJECTION)); then
		skip "W1C/INTx coalescing injection not requested"
		return
	fi

	phase_begin
	log "Reloading the test module with force_intx=Y for fault injection"
	load_test_module Y
	reselect_primary_after_reload
	finish_clean_phase forced-intx-load "forced-INTx diagnostic reload"

	original_command=$(setpci -s "$BDF" COMMAND)
	if ((((16#$original_command) & 0x0400) != 0)); then
		fail "PCI COMMAND already has INTx disabled; refusing fault injection"
		return
	fi

	phase_begin
	timeout --signal=TERM --kill-after=2s 15s v4l2-ctl --silent \
		-d "$PRIMARY_DEVICE" --set-dv-bt-timings=query \
		--stream-mmap=4 --stream-poll --stream-count=100000 \
		--stream-to=/dev/null >"$OUTPUT_DIR/fault-capture.log" 2>&1 &
	capture_pid=$!
	CHILD_PIDS+=("$capture_pid")
	sleep 1
	if ! kill -0 "$capture_pid" 2>/dev/null; then
		fail "capture exited before INTx fault could be injected"
		wait "$capture_pid" 2>/dev/null || true
		CHILD_PIDS=()
		return
	fi
	log "Gating legacy INTx on $BDF for 50 ms"
	PCI_INTX_GATED=1
	setpci -s "$BDF" COMMAND=0400:0400
	sleep 0.050
	restore_intx || die "could not restore INTx after fault injection"

	set +e
	wait "$capture_pid"
	rc=$?
	set -e
	CHILD_PIDS=()
	delta=$(phase_log_delta fault-injection)
	if grep -EinE 'BUG:|WARNING:|Oops:|KASAN:|KFENCE:|general protection fault|kernel panic|use-after-free' \
		"$delta" >"$delta.failures"; then
		fail "fault injection caused a kernel fault (see $delta.failures)"
	elif ((rc != 124)) && grep -Eq 'VDONE ambiguity' "$delta" &&
		grep -Eq 'VDONE half-ring failure' "$delta" &&
		grep -Eq 'video queue failed' "$delta" &&
		grep -Eq 'VIDIOC_DQBUF: failed: Input/output error' \
			"$OUTPUT_DIR/fault-capture.log"; then
		pass "coalesced W1C event failed the queue closed and userspace observed EIO"
	elif ((rc == 124)); then
		fail "capture hung after ambiguity and had to be timed out"
	else
		fail "fault did not produce the complete kernel-to-userspace fail-closed sequence (see $delta)"
	fi
}

reselect_primary_after_reload() {
	local node name
	local requested_device=$DEVICE
	local wanted_name=$PRIMARY_NAME

	DEVICE=auto
	select_video_nodes
	DEVICE=$requested_device
	for node in "${LIVE_VIDEO_NODES[@]}"; do
		name=$(<"/sys/class/video4linux/${node##*/}/name")
		if [[ "$name" == "$wanted_name" ]]; then
			PRIMARY_DEVICE=$node
			PRIMARY_NAME=$wanted_name
			return
		fi
	done
	die "the original live input $wanted_name did not return after module reload"
}

test_module_recovery() {
	if ((SKIP_MODULE_RELOAD)); then
		skip "module teardown/reload disabled by --skip-module-reload"
		return
	fi
	load_test_module N
	reselect_primary_after_reload
	if run_video_capture "$PRIMARY_DEVICE" 30 "$OUTPUT_DIR/recovery-capture.log"; then
		pass "tested module unloaded, reloaded, and recovered a 30-frame capture"
	else
		fail "capture did not recover after module teardown/reload"
	fi
}

write_metadata() {
	{
		printf 'date=%s\n' "$(date --iso-8601=seconds)"
		printf 'uname=%s\n' "$(uname -srvm)"
		printf 'bdf=%s\n' "$BDF"
		printf 'module=%s\n' "$MODULE_PATH"
		printf 'module_sha256=%s\n' "$(sha256sum "$MODULE_PATH" | awk '{print $1}')"
		printf 'module_srcversion=%s\n' "$(modinfo -F srcversion "$MODULE_PATH")"
		printf 'module_vermagic=%s\n' "$(modinfo -F vermagic "$MODULE_PATH")"
		printf 'test_enable_audio=%s\n' "$TEST_AUDIO_PARAMETER"
		printf 'audio_source_pcm=%s\n' "${AUDIO_SOURCE_PCM:-external-unverified}"
		printf 'normal_force_intx=N\n'
		printf 'fault_force_intx=%s\n' "$FAULT_INJECTION"
		printf 'git_head=%s\n' "$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || printf unknown)"
		printf 'git_branch=%s\n' "$(git -C "$SCRIPT_DIR" branch --show-current 2>/dev/null || printf unknown)"
		printf 'fault_injection=%s\n' "$FAULT_INJECTION"
	} >"$OUTPUT_DIR/metadata.txt"
	lspci -Dnnks "$BDF" >"$OUTPUT_DIR/lspci.txt" 2>&1 || true
}

dry_run_summary() {
	local loaded=No

	[[ -d "/sys/module/$MODULE_NAME" ]] && loaded=Yes
	printf 'Read-only preflight passed.\n'
	printf '  PCI function: %s\n' "$BDF"
	printf '  Test module:  %s\n' "$MODULE_PATH"
	printf '  SHA-256:      %s\n' "$(sha256sum "$MODULE_PATH" | awk '{print $1}')"
	printf '  srcversion:   %s\n' "$(modinfo -F srcversion "$MODULE_PATH")"
	printf '  loaded now:   %s\n' "$loaded"
	printf '  Audio source: %s\n' "${AUDIO_SOURCE_PCM:-external/unverified}"
	printf '\nNo module, device, or PCI state was changed. Run with sudo and --run to test hardware.\n'
}

main() {
	local delta

	parse_args "$@"
	validate_args
	require_commands
	resolve_bdf
	validate_module
	if ((!RUN)); then
		dry_run_summary
		return 0
	fi
	((EUID == 0)) || die "--run requires root; use sudo"
	if [[ -r "/sys/module/$MODULE_NAME/parameters/enable_audio" ]]; then
		ORIGINAL_AUDIO_PARAMETER=$(<"/sys/module/$MODULE_NAME/parameters/enable_audio")
	fi
	[[ "$ORIGINAL_AUDIO_PARAMETER" =~ ^([Yy1]|[Nn0])$ ]] ||
		ORIGINAL_AUDIO_PARAMETER=Y
	TEST_AUDIO_PARAMETER=$ORIGINAL_AUDIO_PARAMETER
	if [[ "$AUDIO_PARAMETER_OVERRIDE" != auto ]]; then
		TEST_AUDIO_PARAMETER=$AUDIO_PARAMETER_OVERRIDE
	fi
	if [[ -n "$AUDIO_SOURCE_PCM" && "$TEST_AUDIO_PARAMETER" == N ]]; then
		die "--audio-source-pcm requires audio capture; add --enable-audio"
	fi
	if ((FAULT_INJECTION)); then
		TOTAL_STEPS=9
	fi
	if [[ -z "$OUTPUT_DIR" ]]; then
		OUTPUT_DIR="/tmp/hws-v20-e2e-$(date +%Y%m%d-%H%M%S)"
	fi
	mkdir -p -- "$OUTPUT_DIR"
	SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
	: >"$SUMMARY_FILE"
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	init_klog
	write_metadata

	step "Load and identify the exact test module"
	phase_begin
	if ((SKIP_MODULE_RELOAD)); then
		verify_loaded_module
		verify_irq_mode N
		wait_for_nodes || die "no HWS video nodes exist for the already-loaded module"
		pass "already-loaded module srcversion matches the test module"
	else
		load_test_module N
		pass "loaded the in-tree module and matched srcversion"
	fi
	finish_clean_phase module-load "module load"

	step "Discover nodes and require a live input"
	select_video_nodes
	discover_audio_pcms
	pass "discovered ${#VIDEO_NODES[@]} video node(s), ${#LIVE_VIDEO_NODES[@]} live"

	step "Exercise startup synchronization and complete-frame assembly"
	phase_begin
	test_startup_and_normal_capture
	finish_clean_phase normal-capture "startup and normal capture"

	step "Verify DV timings, packed YUYV, and MMAP-only VB2 capture"
	phase_begin
	test_dv_timing_api
	test_packed_yuyv
	test_memory_model
	finish_clean_phase memory-model "DV timing, packed format, and memory-model checks"

	step "Exercise copy deadlines under CPU contention"
	phase_begin
	test_cpu_stress
	finish_clean_phase cpu-stress "CPU-contention capture"

	step "Repeat STREAMON/STREAMOFF against fixed-base ring ownership"
	phase_begin
	test_rapid_stream_cycles
	finish_clean_phase rapid-stream "rapid STREAMON/OFF"

	step "Capture live channels and embedded audio concurrently"
	phase_begin
	test_concurrent_capture
	finish_clean_phase concurrent "concurrent video/audio capture"

	if ((FAULT_INJECTION)); then
		step "Reload with forced INTx, inject W1C coalescing, and require fail-closed handling"
		test_fault_injection
	fi

	step "Restore MSI-preferred mode and prove capture recovery"
	phase_begin
	test_module_recovery
	finish_clean_phase module-recovery "module teardown/recovery"

	collect_klog
	delta="$OUTPUT_DIR/kernel.log"
	log ""
	log "Evidence: $OUTPUT_DIR"
	log "Results: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"
	log "Tested module remains loaded: $MODULE_PATH"
	if ((FAIL_COUNT)); then
		log "RESULT: FAIL"
		return 1
	fi
	log "RESULT: PASS"
}

main "$@"
