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
RUN_KERNEL_GRADE=1
COMPLIANCE_TIMEOUT="600s"
RUN_START_TS="$(date '+%Y-%m-%d %H:%M:%S')"
MEASURED_FPS="0.00"
LOW_RATE_MODE=0

T1_FRAMES=90
T2_FRAMES=220
T3_FRAMES_A=260
T3_FRAMES_B=70
T4_FRAMES_A=260
T4_FRAMES_B=260
T5_FRAMES_A=260
T5_FRAMES_B=260
T6_FRAMES=220
T7_SINGLE_FRAMES=40
T7_PRIMARY_FRAMES=360
T7_SECONDARY_FRAMES=45
OWNER_EXIT_MIN_FRAMES=8

T1_TIMEOUT=""
T2_TIMEOUT=""
T3_TIMEOUT_A=""
T3_TIMEOUT_B=""
T4_TIMEOUT_A=""
T4_TIMEOUT_B=""
T5_TIMEOUT_A=""
T5_TIMEOUT_B=""
T6_TIMEOUT=""
T7_SINGLE_TIMEOUT=""
T7_PRIMARY_TIMEOUT=""
T7_SECONDARY_TIMEOUT=""

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
  --compliance-timeout DUR  Timeout for v4l2-compliance (default: ${COMPLIANCE_TIMEOUT})
  --skip-kernel-grade       Skip post-run compliance/log checks
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
	local __pidvar="$1"
	local out_file="$2"
	local frames="$3"
	local timeout_s="$4"
	local logf="$5"

	timeout --signal=TERM "${timeout_s}" \
		v4l2-ctl -d "${DEVICE}" \
			--stream-mmap="${MMAP_BUFS}" \
			--stream-count="${frames}" \
			--stream-to="${out_file}" \
		>"${logf}" 2>&1 &
	printf -v "${__pidvar}" '%s' "$!"
}

timeout_for_frames() {
	local frames="$1"

	awk -v frames="${frames}" -v fps="${MEASURED_FPS}" '
		BEGIN {
			if (fps + 0 < 0.10)
				fps = 1.0
			secs = (frames / fps) * 2.2 + 8.0
			if (secs < 10.0)
				secs = 10.0
			printf "%ds\n", int(secs + 0.999)
		}
	'
}

probe_capture_rate() {
	local raw="${OUTDIR}/probe_rate.raw"
	local logf="${OUTDIR}/probe_rate.log"
	local start_ns end_ns elapsed_ns captured_frames

	log "Probing live capture rate"
	start_ns="$(date +%s%N)"
	timeout --signal=TERM 20s \
		v4l2-ctl -d "${DEVICE}" \
			--stream-mmap="${MMAP_BUFS}" \
			--stream-count=4 \
			--stream-to="${raw}" \
		>"${logf}" 2>&1 || true
	end_ns="$(date +%s%N)"

	captured_frames=$(( $(file_size "${raw}") / SIZEIMAGE ))
	elapsed_ns=$((end_ns - start_ns))
	if [[ "${captured_frames}" -lt 1 || "${elapsed_ns}" -le 0 ]]; then
		warn "unable to estimate fps from probe capture, assuming 1.00 fps"
		tail_log "${logf}"
		MEASURED_FPS="1.00"
		return
	fi

	MEASURED_FPS="$(
		awk -v frames="${captured_frames}" -v ns="${elapsed_ns}" '
			BEGIN {
				printf "%.2f\n", (frames * 1000000000.0) / ns
			}
		'
	)"
	log "Measured capture rate: ${MEASURED_FPS} fps (${captured_frames} frames in probe)"
}

configure_test_profile() {
	T1_FRAMES=90
	T2_FRAMES=220
	T3_FRAMES_A=260
	T3_FRAMES_B=70
	T4_FRAMES_A=260
	T4_FRAMES_B=260
	T5_FRAMES_A=260
	T5_FRAMES_B=260
	T6_FRAMES=220
	T7_SINGLE_FRAMES=40
	T7_PRIMARY_FRAMES=360
	T7_SECONDARY_FRAMES=45
	OWNER_EXIT_MIN_FRAMES=8
	LOW_RATE_MODE=0

	if awk -v fps="${MEASURED_FPS}" 'BEGIN { exit !(fps < 5.0) }'; then
		LOW_RATE_MODE=1
		T1_FRAMES=6
		T2_FRAMES=10
		T3_FRAMES_A=14
		T3_FRAMES_B=4
		T4_FRAMES_A=14
		T4_FRAMES_B=14
		T5_FRAMES_A=14
		T5_FRAMES_B=14
		T6_FRAMES=10
		T7_SINGLE_FRAMES=3
		T7_PRIMARY_FRAMES=16
		T7_SECONDARY_FRAMES=3
		OWNER_EXIT_MIN_FRAMES=2
		log "Using low-rate test profile for measured ${MEASURED_FPS} fps input"
	fi

	T1_TIMEOUT="$(timeout_for_frames "${T1_FRAMES}")"
	T2_TIMEOUT="$(timeout_for_frames "${T2_FRAMES}")"
	T3_TIMEOUT_A="$(timeout_for_frames "${T3_FRAMES_A}")"
	T3_TIMEOUT_B="$(timeout_for_frames "${T3_FRAMES_B}")"
	T4_TIMEOUT_A="$(timeout_for_frames "${T4_FRAMES_A}")"
	T4_TIMEOUT_B="$(timeout_for_frames "${T4_FRAMES_B}")"
	T5_TIMEOUT_A="$(timeout_for_frames "${T5_FRAMES_A}")"
	T5_TIMEOUT_B="$(timeout_for_frames "${T5_FRAMES_B}")"
	T6_TIMEOUT="$(timeout_for_frames "${T6_FRAMES}")"
	T7_SINGLE_TIMEOUT="$(timeout_for_frames "${T7_SINGLE_FRAMES}")"
	T7_PRIMARY_TIMEOUT="$(timeout_for_frames "${T7_PRIMARY_FRAMES}")"
	T7_SECONDARY_TIMEOUT="$(timeout_for_frames "${T7_SECONDARY_FRAMES}")"
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

	if [[ "${KEEP_ARTIFACTS}" -eq 1 || "${FAIL_COUNT}" -ne 0 || "${WARN_COUNT}" -ne 0 ]]; then
		log "Artifacts kept at ${OUTDIR}"
	else
		rm -rf "${OUTDIR}"
	fi
}

test_single_baseline() {
	local raw="${OUTDIR}/t1_single.raw"
	local logf="${OUTDIR}/t1_single.log"
	local frames="${T1_FRAMES}"

	log "Test 1: single consumer baseline (direct path)"
	if ! capture_fg "${raw}" "${frames}" "${T1_TIMEOUT}" "${logf}"; then
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
	local frames="${T2_FRAMES}"

	log "Test 2: dual overlapping streams (fan-out path)"
	capture_bg pid_a "${raw_a}" "${frames}" "${T2_TIMEOUT}" "${log_a}"
	sleep 1
	capture_bg pid_b "${raw_b}" "${frames}" "${T2_TIMEOUT}" "${log_b}"

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
	local frames_a="${T3_FRAMES_A}"
	local frames_b="${T3_FRAMES_B}"

	log "Test 3: fan-out to direct transition (second consumer exits first)"
	capture_bg pid_a "${raw_a}" "${frames_a}" "${T3_TIMEOUT_A}" "${log_a}"
	sleep 1
	capture_bg pid_b "${raw_b}" "${frames_b}" "${T3_TIMEOUT_B}" "${log_b}"

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
	local frames_a="${T4_FRAMES_A}"
	local frames_b="${T4_FRAMES_B}"

	log "Test 4: original direct owner exits first while peer continues"
	capture_bg pid_a "${raw_a}" "${frames_a}" "${T4_TIMEOUT_A}" "${log_a}"
	sleep 1
	capture_bg pid_b "${raw_b}" "${frames_b}" "${T4_TIMEOUT_B}" "${log_b}"
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
	if ! assert_capture_progress "${raw_a}" "${frames_a}" "owner-exit stream A" "${log_a}" "${OWNER_EXIT_MIN_FRAMES}"; then
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
	local frames_a="${T5_FRAMES_A}"
	local frames_b="${T5_FRAMES_B}"

	log "Test 5: abrupt close of one consumer while another continues"
	capture_bg pid_a "${raw_a}" "${frames_a}" "${T5_TIMEOUT_A}" "${log_a}"
	sleep 1
	capture_bg pid_b "${raw_b}" "${frames_b}" "${T5_TIMEOUT_B}" "${log_b}"
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
	local fmt_idle_log="${OUTDIR}/t6_busy_fmt_idle_ioctl.log"
	local fmt_restore_log="${OUTDIR}/t6_busy_fmt_restore.log"
	local pid alt_w alt_h rc
	local frames="${T6_FRAMES}"

	log "Test 6: S_FMT size change should fail while busy and succeed once idle"
	capture_bg pid "${raw}" "${frames}" "${T6_TIMEOUT}" "${cap_log}"
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

	if ! v4l2-ctl -d "${DEVICE}" \
		--set-fmt-video=width="${alt_w}",height="${alt_h}",pixelformat="${PIXFMT}" \
		>"${fmt_idle_log}" 2>&1; then
		fail "S_FMT still failed after queues went idle"
		tail_log "${fmt_idle_log}"
		return
	fi
	if ! set_base_format "${fmt_restore_log}"; then
		fail "failed to restore baseline format after idle S_FMT test"
		tail_log "${fmt_restore_log}"
		return
	fi

	pass "S_FMT blocked while active streaming and succeeded once idle"
}

test_rapid_restarts() {
	local i
	local raw logf
	local raw_a raw_b log_a log_b pid_a pid_b
	local single_frames="${T7_SINGLE_FRAMES}"
	local primary_frames="${T7_PRIMARY_FRAMES}"
	local secondary_frames="${T7_SECONDARY_FRAMES}"

	log "Test 7: rapid stream start/stop and 1<->2 oscillation stress"
	for i in 1 2 3; do
		raw="${OUTDIR}/t7_single_${i}.raw"
		logf="${OUTDIR}/t7_single_${i}.log"
		if ! capture_fg "${raw}" "${single_frames}" "${T7_SINGLE_TIMEOUT}" "${logf}"; then
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
	capture_bg pid_a "${raw_a}" "${primary_frames}" "${T7_PRIMARY_TIMEOUT}" "${log_a}"
	sleep 1

	for i in 1 2 3 4; do
		raw_b="${OUTDIR}/t7_osc_${i}_b.raw"
		log_b="${OUTDIR}/t7_osc_${i}_b.log"
		capture_bg pid_b "${raw_b}" "${secondary_frames}" "${T7_SECONDARY_TIMEOUT}" "${log_b}"
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

run_v4l2_compliance_assessment() {
	local logf="${OUTDIR}/kernel_grade_v4l2_compliance.log"
	local findingsf="${OUTDIR}/kernel_grade_v4l2_findings.txt"
	local summary failed warnings rc
	local field_any seq_check seq_start_warning timed_out
	local reqbufs_busy_fail dv_power_present_warn

	if ! command -v v4l2-compliance >/dev/null 2>&1; then
		warn "kernel-grade validation subset: v4l2-compliance not found, skipping compliance portion"
		return 0
	fi

	log "Kernel-grade validation subset: running v4l2-compliance (timeout ${COMPLIANCE_TIMEOUT})"
	if timeout --signal=TERM "${COMPLIANCE_TIMEOUT}" \
		v4l2-compliance -d "${DEVICE}" -s -v >"${logf}" 2>&1; then
		rc=0
	else
		rc=$?
	fi

	summary="$(
		grep -E '([0-9]+ tests succeeded, [0-9]+ failed(, [0-9]+ warning(s)?)?)|(Total for .* Succeeded: [0-9]+, Failed: [0-9]+(, Warnings: [0-9]+)?)' "${logf}" |
			tail -n 1 || true
	)"
	failed=0
	warnings=0
	timed_out=0
	if [[ -n "${summary}" ]]; then
		log "Kernel-grade validation subset compliance summary: ${summary}"
		if [[ "${summary}" == Total\ for* ]]; then
			failed="$(printf '%s\n' "${summary}" | sed -nE 's/.* Failed: ([0-9]+).*/\1/p')"
			warnings="$(printf '%s\n' "${summary}" | sed -nE 's/.* Warnings: ([0-9]+).*/\1/p')"
		else
			failed="$(printf '%s\n' "${summary}" | sed -nE 's/.* ([0-9]+) failed.*/\1/p')"
			warnings="$(printf '%s\n' "${summary}" | sed -nE 's/.* failed, ([0-9]+) warning(s)?.*/\1/p')"
		fi
		[[ -n "${failed}" ]] || failed=0
		[[ -n "${warnings}" ]] || warnings=0
	fi
	if [[ "${rc}" -eq 124 ]]; then
		timed_out=1
		if [[ -z "${summary}" ]]; then
			summary="Timed out after ${COMPLIANCE_TIMEOUT}"
		fi
	fi

	field_any=0
	seq_check=0
	seq_start_warning=0
	reqbufs_busy_fail=0
	dv_power_present_warn=0
	if grep -Fq 'g_field() == V4L2_FIELD_ANY' "${logf}"; then
		field_any=1
	fi
	if grep -Fq 'buf.check(q, last_seq)' "${logf}"; then
		seq_check=1
	fi
	if grep -Eq 'got sequence number [0-9]+, expected 0' "${logf}"; then
		seq_start_warning=1
	fi
	if grep -Fq 'q2.reqbufs(node->node2, 1) != EBUSY' "${logf}"; then
		reqbufs_busy_fail=1
	fi
	if grep -Fq 'V4L2_CID_DV_RX_POWER_PRESENT not found' "${logf}"; then
		dv_power_present_warn=1
	fi

	cat >"${findingsf}" <<EOF
Known v4l2-compliance findings
==============================

Summary:
${summary:-No summary line found}

Known signature checks:
- V4L2_FIELD_ANY on completed buffers: $([[ "${field_any}" -eq 1 ]] && echo detected || echo not detected)
- first-buffer sequence expected 0 warning: $([[ "${seq_start_warning}" -eq 1 ]] && echo detected || echo not detected)
- buf.check(q, last_seq) failures: $([[ "${seq_check}" -eq 1 ]] && echo detected || echo not detected)
- REQBUFS second-opener EBUSY failure: $([[ "${reqbufs_busy_fail}" -eq 1 ]] && echo detected || echo not detected)
- DV_RX_POWER_PRESENT missing warning: $([[ "${dv_power_present_warn}" -eq 1 ]] && echo detected || echo not detected)
- timed out before completion: $([[ "${timed_out}" -eq 1 ]] && echo yes || echo no)

Interpretation:
- A V4L2_FIELD_ANY hit usually means the driver did not stamp completed capture
  buffers with the negotiated field value.
- A first-buffer sequence warning means the stream still appears to start at a
  non-zero sequence number from userspace's point of view.
- A buf.check(q, last_seq) hit usually means buffer metadata or sequence
  progression is still inconsistent from userspace's point of view.
- A REQBUFS EBUSY hit means the multi-opener queue-busy semantics still do not
  match what v4l2-compliance expects for a second handle.
- A DV_RX_POWER_PRESENT warning means the expected power-present control is not
  exposed for the input under test.
- A timeout means the compliance pass hung or stalled and the log should be
  inspected to see which subtest stopped making progress.
EOF

	if [[ "${field_any}" -eq 1 ]]; then
		log "Compliance finding: completed buffers still report V4L2_FIELD_ANY"
	else
		log "Compliance finding: no V4L2_FIELD_ANY buffer-field regressions detected"
	fi
	if [[ "${seq_start_warning}" -eq 1 ]]; then
		log "Compliance finding: first-buffer sequence did not start at 0"
	fi
	if [[ "${seq_check}" -eq 1 ]]; then
		log "Compliance finding: buf.check(q, last_seq) failures detected"
	fi
	if [[ "${reqbufs_busy_fail}" -eq 1 ]]; then
		log "Compliance finding: second-opener REQBUFS did not return EBUSY"
	fi
	if [[ "${dv_power_present_warn}" -eq 1 ]]; then
		log "Compliance finding: V4L2_CID_DV_RX_POWER_PRESENT missing"
	fi
	if [[ "${timed_out}" -eq 1 ]]; then
		log "Compliance finding: v4l2-compliance timed out after ${COMPLIANCE_TIMEOUT}"
	fi
	log "Wrote v4l2-compliance findings report: ${findingsf}"

	if [[ "${timed_out}" -eq 1 ]]; then
		fail "kernel-grade validation subset: v4l2-compliance timed out"
		tail_log "${logf}"
		return 1
	fi
	if [[ "${rc}" -ne 0 || "${failed}" -ne 0 ]]; then
		fail "kernel-grade validation subset: v4l2-compliance reported failures"
		tail_log "${logf}"
		return 1
	fi
	if [[ "${warnings}" -ne 0 ]]; then
		warn "kernel-grade validation subset: v4l2-compliance reported ${warnings} warning(s)"
		return 0
	fi

	pass "kernel-grade validation subset: v4l2-compliance clean"
	return 0
}

collect_kernel_log_since_start() {
	local logf="$1"
	local tmp="${logf}.tmp"

	rm -f "${tmp}"

	if command -v journalctl >/dev/null 2>&1; then
		if journalctl -k --since "${RUN_START_TS}" --no-pager >"${tmp}" 2>&1; then
			mv "${tmp}" "${logf}"
			return 0
		fi
	fi

	if command -v dmesg >/dev/null 2>&1; then
		if dmesg --since "${RUN_START_TS}" >"${tmp}" 2>&1; then
			mv "${tmp}" "${logf}"
			return 0
		fi
		if dmesg >"${tmp}" 2>&1; then
			mv "${tmp}" "${logf}"
			return 0
		fi
	fi

	rm -f "${tmp}"
	return 1
}

run_kernel_log_assessment() {
	local logf="${OUTDIR}/kernel_grade_kernel.log"
	local hws_log="${OUTDIR}/kernel_grade_hws.log"

	if ! collect_kernel_log_since_start "${logf}"; then
		warn "kernel-grade validation subset: unable to collect kernel logs, skipping log review"
		return 0
	fi

	grep -Ei 'hws|hwscapture' "${logf}" >"${hws_log}" || true

	if grep -Eiq 'BUG:|WARNING:|Oops:|Call Trace:|general protection fault|kernel panic|KASAN:|UBSAN:' "${logf}"; then
		fail "kernel-grade validation subset: severe kernel diagnostics detected during run"
		tail_log "${logf}"
		return 1
	fi

	if [[ ! -s "${hws_log}" ]]; then
		pass "kernel-grade validation subset: no new HWS kernel log entries"
		return 0
	fi

	if grep -Eiq '(^|[^[:alpha:]])(error|failed|fail|warning|warn|timeout|hung|stuck|oops|bug)([^[:alpha:]]|$)' "${hws_log}"; then
		warn "kernel-grade validation subset: HWS kernel log contains warning/error text"
		tail_log "${hws_log}"
		return 0
	fi

	pass "kernel-grade validation subset: HWS kernel log clean"
	return 0
}

run_kernel_grade_assessment() {
	local rc=0

	log "Kernel-grade validation subset: reviewing compliance and kernel logs"
	if ! run_v4l2_compliance_assessment; then
		rc=1
	fi
	if ! run_kernel_log_assessment; then
		rc=1
	fi
	return "${rc}"
}

write_kernel_grade_scope() {
	local scope_file="${OUTDIR}/kernel_grade_scope.txt"

	cat >"${scope_file}" <<EOF
Hybrid multi-consumer validation scope
=====================================

This script exercises a lightweight runtime subset of the validation bar
documented in:
  doc/hybrid-multi-consumer-kernel-grade-assessment.md

Automated by this script:
- single-consumer DIRECT capture
- overlapping multi-consumer FANOUT capture
- FANOUT -> DIRECT transition when one consumer exits
- direct-owner exit while another consumer continues
- abrupt close of one consumer while another keeps streaming
- S_FMT reject-while-busy and accept-once-idle behavior
- rapid 1 <-> 2 consumer oscillation stress
- optional v4l2-compliance run when the tool is installed, with a bounded timeout
- extraction of known v4l2-compliance signatures such as V4L2_FIELD_ANY and
  first-buffer sequence warnings and buf.check(q, last_seq) failures
- post-run kernel log scan for severe diagnostics and HWS warning/error text

Not automated here:
- lockdep, KASAN, or KCSAN validation
- exact frame-integrity comparison between consumers
- long soak / multi-hour stability
- STREAMOFF / REQBUFS / STREAMON recovery loops
- suspend / resume during active capture
- signal-loss and relock behavior
- active-queue S_DV_TIMINGS policy checks
- G_PARM / S_PARM policy validation
- mixed MMAP / DMABUF multi-consumer coverage
- failure-injection and registration-unwind coverage

Passing this script does not mean the branch is already kernel grade.
It only covers the runtime items above.
EOF

	log "Wrote kernel-grade scope report: ${scope_file}"
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
	--compliance-timeout)
		COMPLIANCE_TIMEOUT="$2"
		shift 2
		;;
	--skip-kernel-grade)
		RUN_KERNEL_GRADE=0
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
write_kernel_grade_scope

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

probe_capture_rate
configure_test_profile
log "Configured test profile: t1=${T1_FRAMES}/${T1_TIMEOUT} t2=${T2_FRAMES}/${T2_TIMEOUT} t3=${T3_FRAMES_A}+${T3_FRAMES_B} t4=${T4_FRAMES_A}+${T4_FRAMES_B} t5=${T5_FRAMES_A}+${T5_FRAMES_B} t6=${T6_FRAMES}/${T6_TIMEOUT} t7=${T7_SINGLE_FRAMES},${T7_PRIMARY_FRAMES},${T7_SECONDARY_FRAMES}"

test_single_baseline
test_dual_overlap
test_fanout_to_direct_transition
test_direct_owner_exit
test_kill_one_consumer
test_s_fmt_while_busy
test_rapid_restarts

# Best-effort restore to requested baseline format.
set_base_format "${OUTDIR}/set_base_fmt_end.log" || true

if [[ "${RUN_KERNEL_GRADE}" -eq 1 ]]; then
	run_kernel_grade_assessment || true
	set_base_format "${OUTDIR}/set_base_fmt_post_assess.log" || true
fi

log "Summary: pass=${PASS_COUNT} fail=${FAIL_COUNT} warn=${WARN_COUNT}"
if [[ "${FAIL_COUNT}" -ne 0 ]]; then
	exit 1
fi
exit 0
