#!/usr/bin/env bash
# Hybrid multi-consumer validation for HWS V4L2 driver.
# Covers direct mode (single consumer) and fan-out mode (2+ consumers).

set -u
set -o pipefail

DEVICE="/dev/video0"
WIDTH=1920
HEIGHT=1080
PIXFMT="YUYV"
MMAP_BUFS=6
OUTDIR="/tmp/hws_hybrid_test_$(date +%Y%m%d_%H%M%S)_$$"
KEEP_ARTIFACTS=0
SIZEIMAGE=0

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

usage() {
	cat <<EOF
Usage: $0 [options]

Options:
  --device /dev/videoN      Video node to test (default: ${DEVICE})
  --width N                 Capture width (default: ${WIDTH})
  --height N                Capture height (default: ${HEIGHT})
  --pixfmt FOURCC           Pixel format (default: ${PIXFMT})
  --mmap-bufs N             MMAP buffer count per stream (default: ${MMAP_BUFS})
  --outdir PATH             Directory for logs/artifacts
  --keep-artifacts          Keep logs and raw files even when all tests pass
  -h, --help                Show this help
EOF
}

log() {
	printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"
}

pass() {
	PASS_COUNT=$((PASS_COUNT + 1))
	log "PASS: $*"
}

fail() {
	FAIL_COUNT=$((FAIL_COUNT + 1))
	log "FAIL: $*"
}

warn() {
	WARN_COUNT=$((WARN_COUNT + 1))
	log "WARN: $*"
}

tail_log() {
	local f="$1"

	if [[ -f "${f}" ]]; then
		log "---- ${f} (tail) ----"
		tail -n 40 "${f}" || true
		log "---- end tail ----"
	fi
}

require_cmd() {
	local cmd="$1"

	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "Missing required command: ${cmd}" >&2
		exit 2
	fi
}

file_size() {
	local f="$1"

	if [[ ! -f "${f}" ]]; then
		echo 0
		return
	fi
	if stat -c%s "${f}" >/dev/null 2>&1; then
		stat -c%s "${f}"
	else
		stat -f%z "${f}"
	fi
}

assert_nonempty_file() {
	local f="$1"
	local s

	s="$(file_size "${f}")"
	if [[ "${s}" -gt 0 ]]; then
		return 0
	fi
	return 1
}

min_frames_for_capture() {
	local frames="$1"
	local min_frames

	min_frames=$((frames / 4))
	if [[ "${min_frames}" -lt 8 ]]; then
		min_frames=8
	fi
	if [[ "${min_frames}" -gt "${frames}" ]]; then
		min_frames="${frames}"
	fi
	if [[ "${min_frames}" -lt 1 ]]; then
		min_frames=1
	fi
	echo "${min_frames}"
}

query_sizeimage() {
	local logf="$1"
	local size

	if ! v4l2-ctl -d "${DEVICE}" --get-fmt-video >"${logf}" 2>&1; then
		return 1
	fi

	size="$(
		awk -F: '/Size Image/ {
			gsub(/[[:space:]]/, "", $2)
			print $2
			exit
		}' "${logf}"
	)"
	if [[ ! "${size}" =~ ^[0-9]+$ || "${size}" -le 0 ]]; then
		return 1
	fi
	echo "${size}"
}

assert_capture_progress() {
	local f="$1"
	local frames="$2"
	local name="$3"
	local logf="$4"
	local min_frames="${5:-}"
	local size
	local captured_frames
	local remainder

	if [[ -z "${min_frames}" ]]; then
		min_frames="$(min_frames_for_capture "${frames}")"
	fi

	size="$(file_size "${f}")"
	if [[ "${size}" -le 0 ]]; then
		fail "${name} produced empty output"
		tail_log "${logf}"
		return 1
	fi
	if [[ "${SIZEIMAGE}" -le 0 ]]; then
		fail "${name} cannot be validated because sizeimage is unset"
		return 1
	fi

	captured_frames=$((size / SIZEIMAGE))
	remainder=$((size % SIZEIMAGE))
	if [[ "${captured_frames}" -lt "${min_frames}" ]]; then
		fail "${name} captured too few frame-sized payloads: ${captured_frames}/${frames} (min ${min_frames})"
		tail_log "${logf}"
		return 1
	fi
	if [[ "${remainder}" -ne 0 ]]; then
		warn "${name} output size ${size} is not a whole-number multiple of sizeimage ${SIZEIMAGE}"
	fi
	return 0
}

set_base_format() {
	local logf="$1"

	v4l2-ctl -d "${DEVICE}" \
		--set-fmt-video=width="${WIDTH}",height="${HEIGHT}",pixelformat="${PIXFMT}" \
		>"${logf}" 2>&1
}

capture_fg() {
	local out_file="$1"
	local frames="$2"
	local timeout_s="$3"
	local logf="$4"

	timeout --signal=TERM "${timeout_s}" \
		v4l2-ctl -d "${DEVICE}" \
			--stream-mmap="${MMAP_BUFS}" \
			--stream-count="${frames}" \
			--stream-to="${out_file}" \
		>"${logf}" 2>&1
}

capture_bg() {
	local out_file="$1"
	local frames="$2"
	local timeout_s="$3"
	local logf="$4"

	timeout --signal=TERM "${timeout_s}" \
		v4l2-ctl -d "${DEVICE}" \
			--stream-mmap="${MMAP_BUFS}" \
			--stream-count="${frames}" \
			--stream-to="${out_file}" \
		>"${logf}" 2>&1 &
	echo $!
}

wait_ok() {
	local pid="$1"
	local name="$2"
	local logf="$3"

	wait "${pid}"
	local rc=$?

	if [[ "${rc}" -ne 0 ]]; then
		fail "${name} exited with code ${rc}"
		tail_log "${logf}"
		return 1
	fi
	return 0
}

stop_bg() {
	local pid="$1"

	if kill -0 "${pid}" >/dev/null 2>&1; then
		kill -TERM "${pid}" >/dev/null 2>&1 || true
		wait "${pid}" >/dev/null 2>&1 || true
	fi
}

cleanup() {
	local job_pids

	job_pids="$(jobs -pr || true)"
	if [[ -n "${job_pids}" ]]; then
		kill ${job_pids} >/dev/null 2>&1 || true
		wait ${job_pids} >/dev/null 2>&1 || true
	fi

	if [[ "${KEEP_ARTIFACTS}" -eq 1 || "${FAIL_COUNT}" -ne 0 ]]; then
		log "Artifacts kept at ${OUTDIR}"
	else
		rm -rf "${OUTDIR}"
	fi
}

test_single_baseline() {
	local raw="${OUTDIR}/t1_single.raw"
	local logf="${OUTDIR}/t1_single.log"
	local frames=90

	log "Test 1: single consumer baseline (direct path)"
	if ! capture_fg "${raw}" "${frames}" 12s "${logf}"; then
		fail "single baseline capture failed"
		tail_log "${logf}"
		return
	fi
	if ! assert_capture_progress "${raw}" "${frames}" "single baseline" "${logf}"; then
		return
	fi
	pass "single consumer baseline"
}

test_dual_overlap() {
	local raw_a="${OUTDIR}/t2_dual_a.raw"
	local raw_b="${OUTDIR}/t2_dual_b.raw"
	local log_a="${OUTDIR}/t2_dual_a.log"
	local log_b="${OUTDIR}/t2_dual_b.log"
	local pid_a pid_b
	local frames=220

	log "Test 2: dual overlapping streams (fan-out path)"
	pid_a="$(capture_bg "${raw_a}" "${frames}" 20s "${log_a}")"
	sleep 1
	pid_b="$(capture_bg "${raw_b}" "${frames}" 20s "${log_b}")"

	if ! wait_ok "${pid_a}" "dual stream A" "${log_a}"; then
		return
	fi
	if ! wait_ok "${pid_b}" "dual stream B" "${log_b}"; then
		return
	fi
	if ! assert_capture_progress "${raw_a}" "${frames}" "dual overlap stream A" "${log_a}"; then
		return
	fi
	if ! assert_capture_progress "${raw_b}" "${frames}" "dual overlap stream B" "${log_b}"; then
		return
	fi
	pass "dual overlapping streams"
}

test_fanout_to_direct_transition() {
	local raw_a="${OUTDIR}/t3_trans_a.raw"
	local raw_b="${OUTDIR}/t3_trans_b.raw"
	local log_a="${OUTDIR}/t3_trans_a.log"
	local log_b="${OUTDIR}/t3_trans_b.log"
	local pid_a pid_b
	local frames_a=260
	local frames_b=70

	log "Test 3: fan-out to direct transition (second consumer exits first)"
	pid_a="$(capture_bg "${raw_a}" "${frames_a}" 24s "${log_a}")"
	sleep 1
	pid_b="$(capture_bg "${raw_b}" "${frames_b}" 12s "${log_b}")"

	if ! wait_ok "${pid_b}" "transition stream B" "${log_b}"; then
		stop_bg "${pid_a}"
		return
	fi
	if ! wait_ok "${pid_a}" "transition stream A" "${log_a}"; then
		return
	fi
	if ! assert_capture_progress "${raw_a}" "${frames_a}" "fanout-to-direct stream A" "${log_a}"; then
		return
	fi
	if ! assert_capture_progress "${raw_b}" "${frames_b}" "fanout-to-direct stream B" "${log_b}"; then
		return
	fi
	pass "fan-out to direct transition"
}

test_direct_owner_exit() {
	local raw_a="${OUTDIR}/t4_owner_exit_a.raw"
	local raw_b="${OUTDIR}/t4_owner_exit_b.raw"
	local log_a="${OUTDIR}/t4_owner_exit_a.log"
	local log_b="${OUTDIR}/t4_owner_exit_b.log"
	local pid_a pid_b rc_a
	local frames_a=260
	local frames_b=260

	log "Test 4: original direct owner exits first while peer continues"
	pid_a="$(capture_bg "${raw_a}" "${frames_a}" 24s "${log_a}")"
	sleep 1
	pid_b="$(capture_bg "${raw_b}" "${frames_b}" 24s "${log_b}")"
	sleep 2

	kill -TERM "${pid_a}" >/dev/null 2>&1 || true
	wait "${pid_a}" >/dev/null 2>&1
	rc_a=$?
	if [[ "${rc_a}" -eq 0 ]]; then
		warn "owner-exit stream A exited cleanly before/after TERM"
	fi

	if ! wait_ok "${pid_b}" "owner-exit stream B" "${log_b}"; then
		return
	fi
	if ! assert_capture_progress "${raw_a}" "${frames_a}" "owner-exit stream A" "${log_a}" 8; then
		return
	fi
	if ! assert_capture_progress "${raw_b}" "${frames_b}" "owner-exit stream B" "${log_b}"; then
		return
	fi
	pass "direct owner exits, peer continues"
}

test_kill_one_consumer() {
	local raw_a="${OUTDIR}/t5_kill_a.raw"
	local raw_b="${OUTDIR}/t5_kill_b.raw"
	local log_a="${OUTDIR}/t5_kill_a.log"
	local log_b="${OUTDIR}/t5_kill_b.log"
	local pid_a pid_b rc_b
	local frames_a=260
	local frames_b=260

	log "Test 5: abrupt close of one consumer while another continues"
	pid_a="$(capture_bg "${raw_a}" "${frames_a}" 24s "${log_a}")"
	sleep 1
	pid_b="$(capture_bg "${raw_b}" "${frames_b}" 24s "${log_b}")"
	sleep 2

	kill -TERM "${pid_b}" >/dev/null 2>&1 || true
	wait "${pid_b}" >/dev/null 2>&1
	rc_b=$?
	if [[ "${rc_b}" -eq 0 ]]; then
		warn "stream B exited cleanly before/after TERM in kill-one-consumer test"
	fi

	if ! wait_ok "${pid_a}" "kill-one stream A" "${log_a}"; then
		return
	fi
	if ! assert_capture_progress "${raw_a}" "${frames_a}" "kill-one primary stream A" "${log_a}"; then
		return
	fi
	pass "kill one consumer, other continues"
}

test_s_fmt_while_busy() {
	local raw="${OUTDIR}/t6_busy_fmt.raw"
	local cap_log="${OUTDIR}/t6_busy_fmt_capture.log"
	local fmt_log="${OUTDIR}/t6_busy_fmt_ioctl.log"
	local pid alt_w alt_h rc
	local frames=220

	log "Test 6: S_FMT size change while streaming should fail"
	pid="$(capture_bg "${raw}" "${frames}" 20s "${cap_log}")"
	sleep 1

	alt_w=1280
	alt_h=720
	if [[ "${WIDTH}" -eq 1280 && "${HEIGHT}" -eq 720 ]]; then
		alt_w=640
		alt_h=480
	fi

	v4l2-ctl -d "${DEVICE}" \
		--set-fmt-video=width="${alt_w}",height="${alt_h}",pixelformat="${PIXFMT}" \
		>"${fmt_log}" 2>&1
	rc=$?
	if [[ "${rc}" -eq 0 ]]; then
		fail "S_FMT unexpectedly succeeded while queue was busy"
		tail_log "${fmt_log}"
		kill -TERM "${pid}" >/dev/null 2>&1 || true
		wait "${pid}" >/dev/null 2>&1 || true
		return
	fi

	if ! wait_ok "${pid}" "busy S_FMT stream" "${cap_log}"; then
		return
	fi
	if ! assert_capture_progress "${raw}" "${frames}" "busy S_FMT capture" "${cap_log}"; then
		return
	fi
	pass "S_FMT blocked while active streaming"
}

test_rapid_restarts() {
	local i
	local raw logf
	local raw_a raw_b log_a log_b pid_a pid_b
	local single_frames=40
	local primary_frames=360
	local secondary_frames=45

	log "Test 7: rapid stream start/stop and 1<->2 oscillation stress"
	for i in 1 2 3; do
		raw="${OUTDIR}/t7_single_${i}.raw"
		logf="${OUTDIR}/t7_single_${i}.log"
		if ! capture_fg "${raw}" "${single_frames}" 10s "${logf}"; then
			fail "rapid single iteration ${i} failed"
			tail_log "${logf}"
			return
		fi
		if ! assert_capture_progress "${raw}" "${single_frames}" "rapid single iteration ${i}" "${logf}"; then
			return
		fi
	done

	raw_a="${OUTDIR}/t7_osc_a.raw"
	log_a="${OUTDIR}/t7_osc_a.log"
	pid_a="$(capture_bg "${raw_a}" "${primary_frames}" 30s "${log_a}")"
	sleep 1

	for i in 1 2 3 4; do
		raw_b="${OUTDIR}/t7_osc_${i}_b.raw"
		log_b="${OUTDIR}/t7_osc_${i}_b.log"
		pid_b="$(capture_bg "${raw_b}" "${secondary_frames}" 10s "${log_b}")"
		if ! wait_ok "${pid_b}" "oscillation peer iter ${i}" "${log_b}"; then
			stop_bg "${pid_a}"
			return
		fi
		if ! assert_capture_progress "${raw_b}" "${secondary_frames}" "oscillation peer iter ${i}" "${log_b}"; then
			stop_bg "${pid_a}"
			return
		fi
		sleep 1
	done

	if ! wait_ok "${pid_a}" "oscillation primary stream A" "${log_a}"; then
		return
	fi
	if ! assert_capture_progress "${raw_a}" "${primary_frames}" "oscillation primary stream A" "${log_a}"; then
		return
	fi

	pass "rapid restart and mode oscillation stress"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--device)
		DEVICE="$2"
		shift 2
		;;
	--width)
		WIDTH="$2"
		shift 2
		;;
	--height)
		HEIGHT="$2"
		shift 2
		;;
	--pixfmt)
		PIXFMT="$2"
		shift 2
		;;
	--mmap-bufs)
		MMAP_BUFS="$2"
		shift 2
		;;
	--outdir)
		OUTDIR="$2"
		shift 2
		;;
	--keep-artifacts)
		KEEP_ARTIFACTS=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "Unknown option: $1" >&2
		usage
		exit 2
		;;
	esac
done

trap cleanup EXIT INT TERM

require_cmd timeout
require_cmd v4l2-ctl
require_cmd stat
require_cmd awk

mkdir -p "${OUTDIR}"
log "Hybrid multi-consumer test output: ${OUTDIR}"

if [[ ! -e "${DEVICE}" ]]; then
	echo "Device ${DEVICE} not found." >&2
	exit 2
fi

if ! v4l2-ctl -d "${DEVICE}" --all >"${OUTDIR}/device_all.log" 2>&1; then
	echo "Unable to query ${DEVICE}. Check permissions and driver load." >&2
	tail_log "${OUTDIR}/device_all.log"
	exit 2
fi

if ! set_base_format "${OUTDIR}/set_base_fmt.log"; then
	echo "Failed to set base format on ${DEVICE}" >&2
	tail_log "${OUTDIR}/set_base_fmt.log"
	exit 2
fi

if ! SIZEIMAGE="$(query_sizeimage "${OUTDIR}/get_fmt.log")"; then
	echo "Failed to query sizeimage from ${DEVICE}" >&2
	tail_log "${OUTDIR}/get_fmt.log"
	exit 2
fi
log "Base format sizeimage: ${SIZEIMAGE} bytes"

test_single_baseline
test_dual_overlap
test_fanout_to_direct_transition
test_direct_owner_exit
test_kill_one_consumer
test_s_fmt_while_busy
test_rapid_restarts

# Best-effort restore to requested baseline format.
set_base_format "${OUTDIR}/set_base_fmt_end.log" || true

log "Summary: pass=${PASS_COUNT} fail=${FAIL_COUNT} warn=${WARN_COUNT}"
if [[ "${FAIL_COUNT}" -ne 0 ]]; then
	exit 1
fi
exit 0
