#!/usr/bin/env bash
# Run from a terminal as hoff; sudo prompts before the display changes.
set -Eeuo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$script_dir/.."
content_only=0
quick=0
compare_drops=0
test_starvation=0
require_vblank_off=0
irq_latency=0
requested_output=
select_test_vt() {
    local candidate process_table
    process_table=$(ps -eo tty=,comm=,args=)
    # Avoid KDE on VT1, SDDM's detached Xorg on VT2, and any other terminal
    # with a getty, login, application, or explicitly assigned Xorg server.
    for candidate in {3..12}; do
        if awk -v terminal="tty$candidate" -v xvt="vt$candidate" '
            $1 == terminal { busy = 1 }
            $2 == "Xorg" {
                for (i = 3; i <= NF; i++) if ($i == xvt) busy = 1
            }
            END { exit busy ? 0 : 1 }
        ' <<< "$process_table"; then
            continue
        fi
        printf '%s\n' "$candidate"
        return 0
    done
    echo 'No available test VT between VT3 and VT12.' >&2
    return 1
}
wait_receiver() {
    local attempt output stable=0
    # Each ioctl command has a one-second timeout; 30 attempts bound this
    # readiness phase to about 45 seconds, even if the device stops replying.
    for attempt in {1..30}; do
        printf 'Receiver readiness attempt %s\n' "$attempt"
        if output=$(timeout --kill-after=0.25s 1s v4l2-ctl -d /dev/video3 \
            --set-dv-bt-timings=query --verbose 2>&1); then
            printf '%s\n' "$output"
            if awk '
                /Active width:/ { w = $3 }
                /Active height:/ { h = $3 }
                /Total width:/ { tw = $3 }
                /Total height:/ { th = $3 }
                /Pixelclock:/ { clock = $2 }
                /Frame format:/ { progressive = ($3 == "progressive") }
                END { exit !(w == 1920 && h == 1080 && tw == 2200 &&
                             th == 1125 && clock == 148500000 && progressive) }
            ' <<< "$output"; then
                stable=$((stable + 1))
                if (( stable == 3 )); then
                    echo 'Receiver ready: three consecutive 1920x1080p60 timing checks passed.'
                    return 0
                fi
            else
                stable=0
            fi
        else
            printf '%s\n' "$output"
            stable=0
        fi
        sleep 0.25
    done
    echo 'Receiver failed to lock and accept 1920x1080p60 timings within the readiness budget.' >&2
    return 1
}
# Read-only selection check: no authentication, switching, or capture.
if [[ ${1:-} == --select-vt ]]; then
    select_test_vt
    exit
fi
# Configures the detected receiver timing, without switching VTs or streaming.
if [[ ${1:-} == --check-receiver ]]; then
    wait_receiver
    exit
fi
while (($#)); do
    case $1 in
        --content-only) content_only=1; shift ;;
        --quick) quick=1; shift ;;
        --compare-drops) compare_drops=1; quick=1; shift ;;
        --test-starvation) test_starvation=1; quick=1; shift ;;
        --require-vblank-off) require_vblank_off=1; shift ;;
        --irq-latency) irq_latency=1; quick=1; shift ;;
        --output) requested_output=${2:?Missing output directory}; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done
if (( quick && ! content_only )); then
    echo '--quick requires --content-only; the strict validation run cannot be shortened.' >&2
    exit 2
fi
if (( compare_drops + test_starvation + irq_latency > 1 )); then
    echo 'Run --irq-latency, --compare-drops and --test-starvation separately.' >&2; exit 2
fi
[[ $(id -un) == hoff ]] || { echo 'Run as hoff, without sudo.' >&2; exit 2; }
sudo -v
if (( irq_latency )) && ! sudo -n cat /sys/kernel/tracing/available_tracers | grep -qw irqsoff; then
    echo 'irqsoff tracer unavailable on this kernel.' >&2; exit 2
fi
nvidia_vblank_errors=$(sudo -n journalctl --no-pager -k -b -o cat \
    --grep='RG semaphore vblank interrupt not supported on this platform' -n 5) || {
    journal_status=$?
    # journalctl returns 1 for a search with no matching entries.
    (( journal_status == 1 )) || exit "$journal_status"
}
if (( ! content_only )) && [[ $nvidia_vblank_errors == *'RG semaphore vblank interrupt not supported on this platform'* ]]; then
    echo 'Cannot validate: NVIDIA reports that vblank interrupts are unsupported on this platform.' >&2
    echo 'No display switch or capture was started. Return to vblank=0 on the next boot; see local-tests/README.md.' >&2
    exit 2
fi
nvidia_vblank=$(sudo -n cat /sys/module/nvidia_drm/parameters/vblank)
if (( require_vblank_off )); then
    python3 "$script_dir/hws-test-report.py" vblank-off "$nvidia_vblank"
fi
if (( ! content_only )) && [[ $nvidia_vblank != Y ]]; then
    echo 'Cannot validate: NVIDIA DRM vblank is disabled. No display switch or capture was started.' >&2
    echo 'This TITAN platform failed the vblank=1 test; do not enable it again just to rerun this harness. See local-tests/README.md.' >&2
    exit 2
fi
if (( content_only )); then
    echo 'Diagnostic content mode: source timing and provenance remain separate, non-waived gates.'
    echo "NVIDIA vblank=$nvidia_vblank; no module parameter is being changed."
    [[ -z $nvidia_vblank_errors ]] || echo 'Known NVIDIA vblank warnings exist; timing cannot be certified.'
fi
for cmd in trace-cmd modetest chvt setfacl getfacl timeout systemd-run cc pkg-config; do
    command -v "$cmd" >/dev/null
done
(( content_only )) || [[ -z $(git status --porcelain --untracked-files=no) ]] || {
    echo 'Tracked files changed; refusing a definitive evidence run.' >&2; exit 2;
}
if [[ ! -r /sys/module/HwsCapture/srcversion ]]; then
    echo 'HwsCapture is not loaded. Load the matching in-tree module before capture.' >&2
    exit 2
fi
[[ $(modinfo -F srcversion src/HwsCapture.ko) == $(cat /sys/module/HwsCapture/srcversion) ]]
if fuser /dev/video3 >/dev/null 2>&1; then
    echo 'Channel 3 is occupied; stop its consumer before retrying.' >&2
    exit 2
fi
[[ $(sudo -n cat /sys/kernel/tracing/current_tracer) == nop ]]
[[ $(sudo -n cat /sys/kernel/tracing/events/enable) == 0 ]]
debug_root=/sys/kernel/debug
debug_channel=/sys/kernel/debug/hws-0000:17:00.0/video3
sudo -n test -f "$debug_channel/config"
sudo -n test -f "$debug_channel/stats"
original_vt=$(sudo -n fgconsole)
[[ $original_vt == 1 ]] || { echo 'Expected the KDE session on VT1.' >&2; exit 2; }
test_vt=$(select_test_vt)
if [[ -n $requested_output ]]; then
    mkdir -- "$requested_output"
    run_dir=$(cd -- "$requested_output" && pwd)
else
    run_dir=$(mktemp -d /tmp/hws-nvidia-validation.XXXXXX)
fi
chmod 755 "$run_dir"
git diff --binary HEAD > "$run_dir/working-tree.patch"
cc -std=c11 -Wall -Wextra -Werror $(pkg-config --cflags libdrm) \
    "$script_dir/hws-drm-preflight.c" -o "$run_dir/drm-preflight" $(pkg-config --libs libdrm)
getfacl -p /dev/video3 > "$run_dir/video3.acl"
printf '%s\n' "$nvidia_vblank" > "$run_dir/nvidia-vblank.txt"
debug_mode=$(sudo -n stat -c %a "$debug_root")
source_pid=
keepalive_pid=
switched=0
watchdog=hws-validation-restore-$$
cleanup() {
    result=$?
    trap - EXIT INT TERM HUP
    set +e
    if [[ -n $source_pid ]]; then
        kill -TERM "$source_pid" 2>/dev/null
        wait "$source_pid"
    fi
    sudo -n setfacl -P --restore="$run_dir/video3.acl" || result=2
    sudo -n chmod "$debug_mode" "$debug_root" || result=2
    restored=0
    if (( switched )); then
        sudo -n chvt "$original_vt" && restored=1
    else
        restored=1
    fi
    if (( restored )); then
        sudo -n systemctl stop "$watchdog.timer" 2>/dev/null
    else
        echo 'ERROR: display restoration failed; independent watchdog remains active.' >&2
        result=2
    fi
    [[ -z $keepalive_pid ]] || kill "$keepalive_pid" 2>/dev/null
    if (( result )); then
        for log in drm-preflight.log source.log receiver-ready.log calibration.log definitive.log; do
            if [[ -f $run_dir/$log ]]; then
                echo "$log:"
                tail -30 "$run_dir/$log"
            fi
        done
    fi
    echo "Test exit status: $result; results: $run_dir"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
(while sleep 45; do sudo -n -v || exit; done) &
keepalive_pid=$!
# Restore VT1 independently if the launcher terminates unexpectedly.
sudo -n systemd-run --quiet --unit="$watchdog" --on-active=18m /usr/bin/chvt "$original_vt"
# The current harness stats debugfs paths as the user before privileged reads.
# Temporarily permit directory traversal, and restore its exact mode on exit.
sudo -n chmod o+x "$debug_root"
[[ -e $debug_channel/config && -e $debug_channel/stats ]]
# Recheck immediately before switching in case a session started meanwhile.
test_vt=$(select_test_vt)
echo "Results: $run_dir. Switching from KDE to unused VT$test_vt for calibration."
switched=1
sudo -n chvt "$test_vt"
sleep 2
sudo -n fgconsole > "$run_dir/active-vt.txt"
if [[ $(< "$run_dir/active-vt.txt") != "$test_vt" ]]; then
    echo "VT$test_vt did not remain active." >&2
    exit 1
fi
if ! sudo -n "$run_dir/drm-preflight" /dev/dri/card1 --1080p60 > "$run_dir/drm-preflight.log" 2>&1; then
    sudo -n cat /sys/kernel/debug/dri/1/clients > "$run_dir/drm-clients.txt" 2>&1 || true
    exit 1
fi
# logind may revoke the active-seat ACL on a VT switch; retain only this
# capture user's access during the test and restore the saved ACL afterward.
sudo -n setfacl -m u:hoff:rw /dev/video3
sudo -n timeout --signal=TERM --kill-after=5s 1020 \
    tools/hws_frame_id_kms /dev/dri/card1 827 200 1000 "$run_dir/source.jsonl" \
    > "$run_dir/source.log" 2>&1 &
source_pid=$!
for ((attempt=0; attempt<50; attempt++)); do
    [[ ! -s $run_dir/source.jsonl ]] || break
    kill -0 "$source_pid" 2>/dev/null || { cat "$run_dir/source.log"; exit 1; }
    sleep 0.1
done
[[ -s $run_dir/source.jsonl ]] || { cat "$run_dir/source.log"; exit 1; }
sudo -n chmod 644 "$run_dir/source.jsonl"
python3 - "$run_dir/source.jsonl" <<'PY'
import json, sys
with open(sys.argv[1]) as stream:
    config = json.loads(stream.readline())
expected = {"width": 1920, "height": 1080, "clock_khz": 148500,
            "htotal": 2200, "vtotal": 1125}
if any(config.get(key) != value for key, value in expected.items()):
    raise SystemExit("Source did not retain the required 1080p60 timing: " + str(config))
PY
if ! wait_receiver > "$run_dir/receiver-ready.log" 2>&1; then
    exit 2
fi
extra=()
(( ! content_only )) || extra+=(--allow-dirty)
phases=(calibration definitive)
if (( quick )); then
    phases=(calibration)
    echo 'Quick diagnostic: 1,000 pattern frames only; ten-minute content soak skipped.'
fi
if (( compare_drops )); then
    # Reverse the second block to reduce simple ordering/warm-up confounding.
    phases+=(compare-r1-b4-minimal compare-r1-b4-full compare-r1-b16-minimal compare-r1-b16-full
             compare-r2-b16-full compare-r2-b16-minimal compare-r2-b4-full compare-r2-b4-minimal)
fi
if (( test_starvation )); then
    # All profiles retain full content, poison, mapping and queue diagnostics.
    phases+=(starve-r1-b4-d0 starve-r1-b4-d80 starve-r1-b16-d0 starve-r1-b16-d80
             starve-r2-b16-d80 starve-r2-b16-d0 starve-r2-b4-d80 starve-r2-b4-d0)
fi
for phase in "${phases[@]}"; do
    frames=1000; budget=120
    [[ $phase != definitive ]] || { frames=36000; budget=850; }
    run_options=(--buffers 4 --queue-diagnostics)
    if [[ $phase == compare-* ]]; then
        IFS=- read -r _ repeat buffer profile <<< "$phase"
        run_options=(--buffers "${buffer#b}")
        budget=90
        if [[ $profile == minimal ]]; then
            run_options+=(--probe-mode off)
        else
            run_options+=(--queue-diagnostics)
        fi
    fi
    if [[ $phase == starve-* ]]; then
        IFS=- read -r _ repeat buffer delay <<< "$phase"
        run_options=(--buffers "${buffer#b}" --queue-diagnostics --requeue-delay-ms "${delay#d}")
        budget=90
    fi
    (( ! require_vblank_off )) || run_options+=(--require-vblank-off)
    (( ! irq_latency )) || run_options+=(--irq-latency)
    status=0
    timeout --signal=INT --kill-after=15s "$budget" tools/hws_vdone_evidence.py --run \
        --device /dev/video3 --channel 3 --frames "$frames" --keep-timings \
        --source-telemetry "$run_dir/source.jsonl" "${extra[@]}" "${run_options[@]}" \
        --bundle "$run_dir/$phase" --label "ch3-1080p60-native-$phase" \
        > "$run_dir/$phase.log" 2>&1 || status=$?
    if (( ! content_only )); then
        (( status == 0 )) || exit "$status"
    else
        # Exit 1 is an expected strict failure only if the sealed bundle proves
        # that all non-presentation/non-provenance checks actually passed.
        (( status <= 1 )) || exit "$status"
        if [[ $phase == compare-* || $phase == starve-* ]]; then
            python3 "$script_dir/hws-test-report.py" comparison-row "$run_dir/$phase" >> "$run_dir/comparison.jsonl"
        else
            python3 "$script_dir/hws-test-report.py" pattern-gate "$run_dir/$phase"
        fi
    fi
done
if (( content_only )); then
    echo 'Content diagnostics completed. This is NOT a definitive presentation-validation pass.'
fi
