#!/usr/bin/env bash
# Read-only evidence collection. Run while frozen, before unloading the driver.
set -euo pipefail
umask 077

if (( $# > 1 )); then
    echo "Usage: sudo bash $0 [new-output-directory]" >&2
    exit 2
fi
if (( $# )); then
    out=$1
    mkdir -- "$out"
else
    out=$(mktemp -d /tmp/hws-freeze.XXXXXXXX)
fi

collect() {
    local destination=$1
    shift
    local status=0
    timeout --kill-after=1s 5s "$@" > "$out/$destination" 2>&1 || status=$?
    if (( status )); then
        printf '\nCollection exit status: %s (124 means timeout)\n' "$status" >> "$out/$destination"
    fi
}

collect date.txt date --iso-8601=seconds
collect uname.txt uname -a
collect kernel.log journalctl --no-pager -k --since '2 hours ago' -o short-precise
collect modules.txt cat /proc/modules
collect tasks.txt ps -eLo pid,tid,comm,stat,wchan:40
collect source-commit.txt git -C "$(dirname -- "$0")" rev-parse HEAD
collect source-diff.patch git -C "$(dirname -- "$0")" diff -- .
collect checkout-module-sha256.txt sha256sum "$(dirname -- "$0")/HwsCapture.ko"

shopt -s nullglob
mkdir "$out/module" "$out/nodes"
for path in /sys/module/HwsCapture/parameters/* /sys/module/HwsCapture/srcversion /sys/module/HwsCapture/taint; do
    collect "module/$(basename -- "$path")" cat "$path"
done
for path in /sys/class/video4linux/video*/name; do
    node=$(basename -- "$(dirname -- "$path")")
    collect "nodes/$node.txt" cat "$path"
done

# Two CPU-state snapshots show whether progress continues behind a frozen view.
# Each read is bounded; a busy ioctl must not block the rest of the bundle.
for sample in 1 2; do
    mkdir "$out/sample-$sample"
    collect "sample-$sample/date.txt" date --iso-8601=ns
    collect "sample-$sample/interrupts.txt" cat /proc/interrupts
    found=0
    for channel in /sys/kernel/debug/hws-*/video*; do
        found=1
        device=$(basename -- "$(dirname -- "$channel")")
        node=$(basename -- "$channel")
        for name in stats stall config; do
            collect "sample-$sample/$device-$node-$name.txt" cat "$channel/$name"
        done
    done
    if (( !found )); then
        echo 'No readable HWS debugfs channels. Run with sudo; debugfs must be mounted and the instrumented driver loaded.' > "$out/sample-$sample/debugfs-unavailable.txt"
    fi
    if (( sample == 1 )); then sleep 2; fi
done
collect kernel-after.log journalctl --no-pager -k --since '5 minutes ago' -o short-precise
printf 'Saved freeze evidence to %s\n' "$out"
