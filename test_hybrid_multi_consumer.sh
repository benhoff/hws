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

	log "Test 1: single consumer baseline (direct path)"
	if ! capture_fg "${raw}" 90 12s "${logf}"; then
		fail "single baseline capture failed"
		tail_log "${logf}"
		return
	fi
	if ! assert_nonempty_file "${raw}"; then
		fail "single baseline produced empty output"
		tail_log "${logf}"
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

	log "Test 2: dual overlapping streams (fan-out path)"
	pid_a="$(capture_bg "${raw_a}" 220 20s "${log_a}")"
	sleep 1
	pid_b="$(capture_bg "${raw_b}" 220 20s "${log_b}")"

	if ! wait_ok "${pid_a}" "dual stream A" "${log_a}"; then
		return
	fi
	if ! wait_ok "${pid_b}" "dual stream B" "${log_b}"; then
		return
	fi
	if ! assert_nonempty_file "${raw_a}" || ! assert_nonempty_file "${raw_b}"; then
		fail "dual overlap produced empty output"
		tail_log "${log_a}"
		tail_log "${log_b}"
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

	log "Test 3: fan-out to direct transition (second consumer exits first)"
	pid_a="$(capture_bg "${raw_a}" 260 24s "${log_a}")"
	sleep 1
	pid_b="$(capture_bg "${raw_b}" 70 12s "${log_b}")"

	if ! wait_ok "${pid_b}" "transition stream B" "${log_b}"; then
		return
	fi
	if ! wait_ok "${pid_a}" "transition stream A" "${log_a}"; then
		return
	fi
	if ! assert_nonempty_file "${raw_a}" || ! assert_nonempty_file "${raw_b}"; then
		fail "transition test produced empty output"
		tail_log "${log_a}"
		tail_log "${log_b}"
		return
	fi
	pass "fan-out to direct transition"
}

test_kill_one_consumer() {
	local raw_a="${OUTDIR}/t4_kill_a.raw"
	local raw_b="${OUTDIR}/t4_kill_b.raw"
	local log_a="${OUTDIR}/t4_kill_a.log"
	local log_b="${OUTDIR}/t4_kill_b.log"
	local pid_a pid_b rc_b

	log "Test 4: abrupt close of one consumer while another continues"
	pid_a="$(capture_bg "${raw_a}" 260 24s "${log_a}")"
	sleep 1
	pid_b="$(capture_bg "${raw_b}" 260 24s "${log_b}")"
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
	if ! assert_nonempty_file "${raw_a}"; then
		fail "kill-one-consumer left primary stream empty"
		tail_log "${log_a}"
		return
	fi
	pass "kill one consumer, other continues"
}

test_s_fmt_while_busy() {
	local raw="${OUTDIR}/t5_busy_fmt.raw"
	local cap_log="${OUTDIR}/t5_busy_fmt_capture.log"
	local fmt_log="${OUTDIR}/t5_busy_fmt_ioctl.log"
	local pid alt_w alt_h rc

	log "Test 5: S_FMT size change while streaming should fail"
	pid="$(capture_bg "${raw}" 220 20s "${cap_log}")"
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
	if ! assert_nonempty_file "${raw}"; then
		fail "busy S_FMT capture produced empty output"
		tail_log "${cap_log}"
		return
	fi
	pass "S_FMT blocked while active streaming"
}

test_rapid_restarts() {
	local i
	local raw logf
	local raw_a raw_b log_a log_b pid_a pid_b

	log "Test 6: rapid stream start/stop stress"
	for i in 1 2 3 4 5; do
		raw="${OUTDIR}/t6_single_${i}.raw"
		logf="${OUTDIR}/t6_single_${i}.log"
		if ! capture_fg "${raw}" 40 10s "${logf}"; then
			fail "rapid single iteration ${i} failed"
			tail_log "${logf}"
			return
		fi
		if ! assert_nonempty_file "${raw}"; then
			fail "rapid single iteration ${i} produced empty output"
			tail_log "${logf}"
			return
		fi
	done

	for i in 1 2 3; do
		raw_a="${OUTDIR}/t6_dual_${i}_a.raw"
		raw_b="${OUTDIR}/t6_dual_${i}_b.raw"
		log_a="${OUTDIR}/t6_dual_${i}_a.log"
		log_b="${OUTDIR}/t6_dual_${i}_b.log"
		pid_a="$(capture_bg "${raw_a}" 80 12s "${log_a}")"
		sleep 1
		pid_b="$(capture_bg "${raw_b}" 80 12s "${log_b}")"
		if ! wait_ok "${pid_a}" "rapid dual A iter ${i}" "${log_a}"; then
			return
		fi
		if ! wait_ok "${pid_b}" "rapid dual B iter ${i}" "${log_b}"; then
			return
		fi
		if ! assert_nonempty_file "${raw_a}" || ! assert_nonempty_file "${raw_b}"; then
			fail "rapid dual iteration ${i} produced empty output"
			tail_log "${log_a}"
			tail_log "${log_b}"
			return
		fi
	done
	pass "rapid restart stress"
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

test_single_baseline
test_dual_overlap
test_fanout_to_direct_transition
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
