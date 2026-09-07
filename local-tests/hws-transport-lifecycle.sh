#!/usr/bin/env bash
# Transport-only lifecycle smoke test. No pixel, DMA-guard, or timing proof.
set -Eeuo pipefail
device=/dev/video3
output=${1:?Usage: bash local-tests/hws-transport-lifecycle.sh NEW_OUTPUT_DIRECTORY}
command -v v4l2-ctl >/dev/null
command -v fuser >/dev/null
[[ -c $device ]] || { echo "$device is unavailable" >&2; exit 2; }
[[ $(readlink -f /sys/class/video4linux/video3/device/driver/module) == /sys/module/HwsCapture ]] || {
    echo 'video3 is not bound to HwsCapture' >&2; exit 2;
}
if fuser "$device" >/dev/null 2>&1; then
    echo "$device is occupied; refusing concurrent capture" >&2
    exit 2
fi
mkdir -- "$output"
date --iso-8601=seconds > "$output/start.txt"
v4l2-ctl -d "$device" --get-fmt-video --query-dv-timings > "$output/format.txt" 2>&1
printf 'buffers\trequested\texit_status\tcompletion_markers\n' > "$output/cycles.tsv"
for buffers in 2 4 8 16; do
    for frames in 1 2 4 60 120; do
        log="$output/buffers-$buffers-frames-$frames.log"
        status=0
        timeout --signal=INT --kill-after=5s 30 v4l2-ctl -d "$device" \
            --stream-mmap="$buffers" --stream-count="$frames" --stream-to=/dev/null \
            > "$log" 2>&1 || status=$?
        markers=$(LC_ALL=C tr -cd '<' < "$log" | wc -c)
        printf '%s\t%s\t%s\t%s\n' "$buffers" "$frames" "$status" "$markers" >> "$output/cycles.tsv"
        if (( status != 0 || markers != frames )); then
            echo "Transport cycle failed: buffers=$buffers frames=$frames status=$status markers=$markers"
            date --iso-8601=seconds > "$output/end.txt"
            exit 1
        fi
        echo "Completed transport cycle: buffers=$buffers frames=$frames"
    done
done
date --iso-8601=seconds > "$output/end.txt"
echo '20 transport start/stop cycles completed; pixels and DMA guards were not examined.'
