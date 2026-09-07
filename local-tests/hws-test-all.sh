#!/usr/bin/env bash
# Bounded, channel-3 diagnostics for the current Linux TITAN HDMI loopback.
set -Eeuo pipefail
export LC_ALL=C
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$script_dir/.." && pwd)
cd "$repo"
with_pattern=0
quick=0
compare_drops=0
test_starvation=0
require_vblank_off=0
irq_latency=0
software_only=0
use_sudo=1
frames=36000
stream_timeout=720
output=
usage() {
    printf '%s\n' \
      'Usage: bash local-tests/hws-test-all.sh [options]' \
      '  --with-pattern    Also take over TITAN HDMI/VT for 1,000 + 36,000 pattern frames.' \
      '                    Restores the desktop; requires sudo. Allow about 25 minutes total.' \
      '  --quick           600 transport frames; pattern calibration only (1,000 frames).' \
      '                    Keeps all 20 restart cycles; typically about 2-3 minutes with pattern.' \
      '  --compare-drops   Quick + pattern; two repeats of 4/16 buffers, minimal/full diagnostics.' \
      '                    About 4-6 minutes; does not establish causality by itself.' \
      '  --irq-latency     Separate quick pattern run with irqsoff, if supported by the kernel.' \
      '  --test-starvation Quick + pattern; 0/80 ms requeue delay every 60 frames, 4/16 buffers.' \
      '                    Two reversed repeats; all content checks retained (about 4-6 minutes).' \
      '  --require-vblank-off  Refuse hardware tests unless loaded NVIDIA vblank=N.' \
      '  --software-only   Build/check only; no capture, sudo, or display changes.' \
      '  --no-sudo         Run unprivileged tests; privileged evidence is marked unavailable.' \
      '  --output DIR      New results directory (default: unique directory in local-tests).' \
      '  --help            Show this help.' \
      'Default: builds, regressions, transport soak, 20 lifecycle cycles, stats/kernel checks.' \
      'Only video3 is exercised. No driver reload, boot edits, unbind, or audio changes.' \
      'Exit: 0 all checks covered/passed; 1 failure; 2 incomplete/skipped/warnings.' \
      'An incomplete result is expected while timing/race/matrix coverage is unavailable.'
}
while (($#)); do
    case $1 in
        --with-pattern) with_pattern=1; shift ;;
        --quick) quick=1; frames=600; stream_timeout=60; shift ;;
        --compare-drops) compare_drops=1; quick=1; with_pattern=1; frames=600; stream_timeout=60; shift ;;
        --test-starvation) test_starvation=1; quick=1; with_pattern=1; frames=600; stream_timeout=60; shift ;;
        --require-vblank-off) require_vblank_off=1; shift ;;
        --irq-latency) irq_latency=1; quick=1; with_pattern=1; frames=600; stream_timeout=60; shift ;;
        --software-only) software_only=1; use_sudo=0; shift ;;
        --no-sudo) use_sudo=0; shift ;;
        --output) output=${2:?Missing output directory}; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done
if (( compare_drops + test_starvation + irq_latency > 1 )); then
    echo 'Run --irq-latency, --compare-drops and --test-starvation separately.' >&2; exit 2
fi
if (( require_vblank_off && (software_only || ! use_sudo) )); then
    echo '--require-vblank-off requires hardware testing and sudo.' >&2; exit 2
fi
if (( with_pattern && (software_only || ! use_sudo) )); then
    echo '--with-pattern requires hardware testing and sudo.' >&2; exit 2
fi
[[ $EUID != 0 ]] || { echo 'Run as the desktop user, not sudo bash.' >&2; exit 2; }
for tool in python3 timeout flock rg; do command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 2; }; done
# Avoid overlapping runner builds/capture sessions. Device occupancy is also checked below.
exec 9> "$script_dir/.hws-test-all.lock"
flock -n 9 || { echo 'Another all-tests runner is active.' >&2; exit 2; }
if [[ -n $output ]]; then mkdir -- "$output"; else output=$(mktemp -d "$script_dir/all-tests.XXXXXX"); fi
output=$(cd -- "$output" && pwd)
printf 'test\tstatus\tdetails\n' > "$output/results.tsv"
failed=0; incomplete=0; privileged=0; keepalive_pid=; stage_pid=; heartbeat_pid=
record() {
    local name=$1 status=$2 detail=$3
    detail=${detail//$'\n'/; }; detail=${detail//$'\t'/ }
    printf '%s\t%s\t%s\n' "$name" "$status" "$detail" | tee -a "$output/results.tsv"
    [[ $status != FAIL ]] || failed=1
    [[ $status != SKIP && $status != INCONCLUSIVE && $status != WARN ]] || incomplete=1
}
finish() {
    local status=$?
    trap - EXIT
    if [[ -n $stage_pid ]]; then
        kill -TERM "$stage_pid" 2>/dev/null || true
        wait "$stage_pid" 2>/dev/null || true
    fi
    [[ -z $heartbeat_pid ]] || kill "$heartbeat_pid" 2>/dev/null || true
    [[ -z $keepalive_pid ]] || kill "$keepalive_pid" 2>/dev/null || true
    date --iso-8601=seconds > "$output/end.txt"
    if (( status != 0 && status != 1 && status != 2 )); then
        record interrupted INCONCLUSIVE "Runner interrupted/unexpected exit=$status"
    fi
    local verdict
    case $status in 0) verdict='ALL CHECKS PASSED';; 1) verdict='FAILED TEST OR RUNNER ERROR';; *) verdict='INCOMPLETE COVERAGE';; esac
    printf '%s (exit=%s)\n' "$verdict" "$status" > "$output/overall.txt"
    printf '\n%s (exit=%s)\nResults: %s\nNo universal driver-correctness claim is made.\n' "$verdict" "$status" "$output"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
date --iso-8601=seconds > "$output/start.txt"
printf 'Results: %s\n' "$output"
git rev-parse HEAD > "$output/git-head.txt"
git status --short > "$output/git-status.txt"
git diff --binary HEAD > "$output/working-tree.patch"
uname -a > "$output/kernel-version.txt"
cp -- /proc/cmdline "$output/kernel-command-line.txt"
cp -- "$script_dir/hws-test-all.sh" "$script_dir/hws-test-report.py" \
    "$script_dir/hws-nvidia-validation.sh" "$script_dir/hws-drm-preflight.c" "$output/"
run_stage() {
    local name=$1 budget=$2 status=0
    shift 2
    echo "Running $name (log: $output/$name.log)"
    (exec 9>&-; while sleep 30; do echo "Still running $name ..."; done) & heartbeat_pid=$!
    timeout --signal=INT --kill-after=15s "$budget" "$@" > "$output/$name.log" 2>&1 & stage_pid=$!
    wait "$stage_pid" || status=$?
    stage_pid=
    kill "$heartbeat_pid" 2>/dev/null || true
    wait "$heartbeat_pid" 2>/dev/null || true
    heartbeat_pid=
    if (( status )); then
        record "$name" FAIL "exit=$status; see $name.log"
        tail -15 "$output/$name.log"
        return 1
    fi
    record "$name" PASS "see $name.log"
}
build_ok=1
if [[ -d /lib/modules/$(uname -r)/build ]] && command -v make >/dev/null; then
    run_stage module-build 600 make -C src -j4 || build_ok=0
else
    record module-build SKIP 'Matching kernel headers or make unavailable'; build_ok=0
fi
if command -v make >/dev/null && command -v pkg-config >/dev/null && pkg-config --exists libdrm; then
    run_stage tools-check 180 make -C tools check || build_ok=0
else
    record tools-check SKIP 'make/pkg-config/libdrm development files unavailable'; build_ok=0
fi
run_stage runner-regressions 60 python3 -m unittest discover -s local-tests -p 'test_hws_test_runner.py' -v || build_ok=0
if (( software_only )); then
    record hardware SKIP '--software-only selected'
elif (( ! build_ok )); then
    record hardware SKIP 'Build/regression prerequisites did not pass'
else
    hardware_ready=1
    for tool in v4l2-ctl modinfo fuser; do
        if ! command -v "$tool" >/dev/null; then
            record preflight INCONCLUSIVE "Missing $tool"; hardware_ready=0
        fi
    done
    if (( use_sudo )) && command -v sudo >/dev/null && sudo -v; then
        privileged=1
        (exec 9>&-; while sleep 45; do sudo -n -v || exit; done) & keepalive_pid=$!
    else
        record privileged-evidence SKIP 'sudo unavailable/declined/disabled; no password is stored'
    fi
    if (( require_vblank_off )); then
        if (( privileged )) && sudo -n cat /sys/module/nvidia_drm/parameters/vblank > "$output/nvidia-vblank.txt" && \
            note=$(python3 "$script_dir/hws-test-report.py" vblank-off "$(< "$output/nvidia-vblank.txt")"); then
            record vblank-off PASS "$note"
        else
            record vblank-off INCONCLUSIVE 'Loaded NVIDIA vblank=N required; no hardware tests started. Remove vblank=1 and reboot manually.'
            hardware_ready=0
        fi
    fi
    if [[ ! -c /dev/video3 || $(readlink -f /sys/class/video4linux/video3/device/driver/module) != /sys/module/HwsCapture ]]; then
        record preflight INCONCLUSIVE 'video3 is not an available HwsCapture node'; hardware_ready=0
    fi
    if (( hardware_ready )); then
        if [[ ! -r /sys/module/HwsCapture/srcversion ]] || \
            [[ $(modinfo -F srcversion src/HwsCapture.ko) != $(< /sys/module/HwsCapture/srcversion) ]]; then
            record module-identity INCONCLUSIVE 'Load the matching build manually; runner will not reload it'
            hardware_ready=0
        else
            cp -- /sys/module/HwsCapture/srcversion "$output/module-srcversion.txt"
            sha256sum src/HwsCapture.ko > "$output/module-sha256.txt"
            record module-identity PASS 'Loaded srcversion matches in-tree build'
        fi
    fi
    is_busy() {
        if (( privileged )); then sudo -n fuser /dev/video3; else fuser /dev/video3; fi
    }
    if (( hardware_ready )) && is_busy > "$output/device-users.txt" 2>&1; then
        record device-available INCONCLUSIVE 'video3 is occupied; no consumer will be stopped'; hardware_ready=0
    fi
    if (( hardware_ready )); then
        bdf=$(basename -- "$(readlink -f /sys/class/video4linux/video3/device)")
        debug_channel="/sys/kernel/debug/hws-$bdf/video3"
        snapshot() {
            local stage=$1 position=$2
            (( privileged )) || return 0
            sudo -n cat "$debug_channel/stats" > "$output/$stage-$position.txt" 2> "$output/$stage-$position.err" || true
        }
        log_cursor=
        if (( privileged )); then
            log_cursor=$(sudo -n journalctl -k -b -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
        fi
        if run_stage receiver 15 v4l2-ctl -d /dev/video3 --set-dv-bt-timings=query --get-fmt-video --query-dv-timings; then
            capture_status=0
            snapshot transport before
            run_stage transport "$stream_timeout" v4l2-ctl -d /dev/video3 --stream-mmap=4 \
                --stream-count="$frames" --stream-to=/dev/null || capture_status=1
            snapshot transport after
            assess_transport() {
                local name=$1 count=$2 status=$3 verdict=0 note label
                note=$(python3 "$script_dir/hws-test-report.py" transport "$output/$name.log" "$count" \
                    "$output/$name-before.txt" "$output/$name-after.txt" "$status") || verdict=$?
                case $verdict in 0) label=PASS;; 1) label=FAIL;; 3) label=WARN;; *) label=INCONCLUSIVE;; esac
                record "$name-accounting" "$label" "$note"
                [[ $label != FAIL ]]
            }
            if assess_transport transport "$frames" "$capture_status" && (( capture_status == 0 )); then
                for buffers in 2 4 8 16; do
                    for count in 1 2 4 60 120; do
                        name="lifecycle-$buffers-$count"; status=0
                        snapshot "$name" before
                        run_stage "$name" 30 v4l2-ctl -d /dev/video3 --stream-mmap="$buffers" \
                            --stream-count="$count" --stream-to=/dev/null || status=1
                        snapshot "$name" after
                        assess_transport "$name" "$count" "$status" || break 2
                        (( status == 0 )) || break 2
                    done
                done
            else
                record lifecycle SKIP 'Transport failed; no further stream attempts'
            fi
            if (( with_pattern && privileged && ! failed )); then
                pattern_status=0
                pattern_options=()
                (( ! compare_drops )) || pattern_options+=(--compare-drops)
                (( ! test_starvation )) || pattern_options+=(--test-starvation)
                (( ! require_vblank_off )) || pattern_options+=(--require-vblank-off)
                (( ! irq_latency )) || pattern_options+=(--irq-latency)
                pattern_phases=(calibration definitive)
                if (( quick )); then
                    pattern_options+=(--quick)
                    pattern_phases=(calibration)
                fi
                echo 'Starting pattern test: the HDMI display will be taken over temporarily.'
                # Launcher owns its watchdog/cleanup. Do not wrap its display restoration in timeout.
                bash "$script_dir/hws-nvidia-validation.sh" --content-only "${pattern_options[@]}" --output "$output/pattern" \
                    > "$output/pattern-launcher.log" 2>&1 9>&- & stage_pid=$!
                wait "$stage_pid" || pattern_status=$?
                stage_pid=
                if (( pattern_status )); then
                    if (( pattern_status == 2 )); then
                        record pattern-run INCONCLUSIVE 'Pattern/evidence setup unavailable; see pattern-launcher.log'
                    else
                        record pattern-run FAIL "exit=$pattern_status; see pattern-launcher.log"
                    fi
                    tail -25 "$output/pattern-launcher.log"
                else
                    for phase in "${pattern_phases[@]}"; do
                        if note=$(python3 "$script_dir/hws-test-report.py" pattern-gate "$output/pattern/$phase"); then
                            record "pattern-$phase-capture" PASS "$note"
                        else
                            record "pattern-$phase-capture" FAIL "$note"
                        fi
                    done
                    if (( compare_drops )); then
                        record drop-comparison WARN 'Collected diagnostic comparisons; inspect pattern/comparison.jsonl, no causal claim'
                    fi
                    if (( test_starvation )); then
                        record starvation-comparison WARN 'Collected full-check delay comparisons; inspect pattern/comparison.jsonl for CPU/wall timing and delay/EMPTY overlap; no causal claim'
                    fi
                fi
            else
                record pattern SKIP 'Requires --with-pattern, sudo, and passing transport checks'
            fi
        else
            record capture SKIP 'Receiver configuration failed'
        fi
        if [[ -n $log_cursor ]] && sudo -n journalctl --no-pager -k -b --after-cursor="$log_cursor" -o short-iso > "$output/kernel.log"; then
            if rg -i 'BUG:|WARNING:|Oops:|Call Trace:|hung task|soft lockup|DMA guard corruption|video queue failed|IOMMU.*(fault|error)' "$output/kernel.log" > "$output/kernel-alerts.log"; then
                record kernel-alerts WARN 'Fresh kernel alerts need attribution; see kernel-alerts.log'
            else
                record kernel-alerts PASS 'No matched fault signatures; this is not proof of memory safety'
            fi
        else
            record kernel-alerts INCONCLUSIVE 'Kernel journal unavailable; cannot check fresh faults'
        fi
    fi
fi
if (( quick )); then
    record long-soak SKIP '--quick selected: short transport and optional pattern calibration only'
fi
record presentation-timing SKIP 'NVIDIA timing path is unqualified; inspect separate pattern summary when available'
record shutdown-race SKIP 'Current driver lacks the synchronized race-test hooks'
record post-stop-dma SKIP 'Current driver lacks the canary test status ioctl; not replaced by streaming guard checks'
record unbind SKIP 'Disrupts all card channels; existing unbind harness requires review before use'
record coverage-matrix SKIP 'Other inputs/modes, simultaneous A/V, sanitizer kernels, and baseline comparison not exercised'
if (( failed )); then exit 1; fi
if (( incomplete )); then exit 2; fi
exit 0
