#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MODULE_PATH="$SCRIPT_DIR/src/HwsCapture.ko"
MODULE_NAME=HwsCapture
DEVICE=/dev/video3
SECONDS_TO_RUN=300
RUN=0

usage() {
	cat <<EOF
Usage: $(basename "$0") --run [--device DEV] [--seconds N]

Reload the exact in-tree HwsCapture module and require uninterrupted capture
through at least one recoverable duplicate VDONE event.

The soak reports elapsed time, IRQ progress, and the number of recovered
duplicate events every five seconds. A quiet capture is therefore visibly
distinguishable from a stalled one.

Run this as the desktop user, not through sudo. The script uses sudo only for
module, capture, and kernel-log operations so it can stop/restore WirePlumber
in the correct user session.
EOF
}

while (($#)); do
	case "$1" in
	--run)
		RUN=1
		shift
		;;
	--device)
		(($# >= 2)) || { echo "ERROR: --device needs a value" >&2; exit 2; }
		DEVICE=$2
		shift 2
		;;
	--seconds)
		(($# >= 2)) || { echo "ERROR: --seconds needs a value" >&2; exit 2; }
		seconds_value=$2
		[[ "$seconds_value" =~ ^[0-9]+$ ]] &&
			((seconds_value >= 1 && seconds_value <= 3600)) || {
			echo "ERROR: --seconds must be 1..3600" >&2
			exit 2
		}
		SECONDS_TO_RUN=$seconds_value
		shift 2
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		echo "ERROR: unknown option: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

((RUN)) || { usage; exit 2; }
((EUID != 0)) || {
	echo "ERROR: run as the desktop user; do not prefix the script with sudo" >&2
	exit 2
}
[[ -r "$MODULE_PATH" ]] || {
	echo "ERROR: missing module: $MODULE_PATH" >&2
	exit 2
}
[[ -e "$DEVICE" ]] || {
	echo "ERROR: missing capture node: $DEVICE" >&2
	exit 2
}

for required in sudo systemctl modinfo v4l2-ctl journalctl timeout; do
	command -v "$required" >/dev/null || {
		echo "ERROR: missing command: $required" >&2
		exit 2
	}
done

# Authenticate before stopping desktop services. Every later privileged call is
# non-interactive; progress polling refreshes this credential during the soak.
sudo -v

wp_was_active=$(systemctl --user is-active wireplumber.service || true)
progress_pid=
cleanup() {
	if [[ -n "$progress_pid" ]]; then
		kill "$progress_pid" 2>/dev/null || true
		wait "$progress_pid" 2>/dev/null || true
	fi
	if [[ "$wp_was_active" == active ]]; then
		systemctl --user start wireplumber.service
	fi
}
trap cleanup EXIT

if [[ "$wp_was_active" == active ]]; then
	systemctl --user stop wireplumber.service
fi

sudo -n rmmod "$MODULE_NAME" 2>/dev/null || true
sudo -n modprobe -a snd-pcm videobuf2-dma-contig videobuf2-v4l2 \
	v4l2-dv-timings
sudo -n insmod "$MODULE_PATH" enable_audio=Y force_intx=N

built=$(modinfo -F srcversion "$MODULE_PATH")
loaded=$(<"/sys/module/$MODULE_NAME/srcversion")
echo "built:  $built"
echo "loaded: $loaded"
[[ "$built" == "$loaded" ]] || {
	echo "FAIL: loaded module does not match the in-tree module" >&2
	exit 1
}

stamp=$(date +%Y%m%d-%H%M%S)
output_dir="/tmp/hws-vdone-recovery-$stamp"
mkdir -p "$output_dir"
capture_log="$output_dir/capture.log"
kernel_log="$output_dir/kernel.log"
recovery_log="$output_dir/recovery.log"
started_epoch=$(date +%s)
started_monotonic=$SECONDS
pci_bdf=$(basename "$(readlink -f "/sys/class/video4linux/$(basename "$DEVICE")/device")")

read_irq_total() {
	sudo -n awk -v bdf="$pci_bdf" '
		index($0, bdf) {
			for (i = 2; i <= NF && $i ~ /^[0-9]+$/; i++)
				total += $i
		}
		END { print total + 0 }
	' /proc/interrupts
}

count_recoveries() {
	sudo -n journalctl -k -b --since "@$started_epoch" --no-pager \
		2>/dev/null |
		awk '/VDONE duplicate recovered/ { count++ }
			END { print count + 0 }'
}

irq_before=$(read_irq_total)
progress_monitor() {
	while sleep 5; do
		progress_elapsed=$((SECONDS - started_monotonic))
		if irq_now=$(read_irq_total 2>/dev/null); then
			irq_delta=$((irq_now - irq_before))
		else
			irq_delta='unavailable'
		fi
		if ! recovery_count=$(count_recoveries); then
			recovery_count='unavailable'
		fi
		printf '\rSoak progress: %4ds/%ds | IRQ delta: %-11s | recoveries: %-11s' \
			"$progress_elapsed" "$SECONDS_TO_RUN" \
			"$irq_delta" "$recovery_count" >&2
	done
}

progress_monitor &
progress_pid=$!
set +e
sudo -n timeout --signal=TERM --kill-after=2s "${SECONDS_TO_RUN}s" \
	v4l2-ctl --silent -d "$DEVICE" \
		--set-dv-bt-timings=query \
		--stream-mmap=4 --stream-poll \
		--stream-count=100000 --stream-to=/dev/null \
		>"$capture_log" 2>&1
capture_rc=$?
set -e
elapsed=$((SECONDS - started_monotonic))
kill "$progress_pid" 2>/dev/null || true
wait "$progress_pid" 2>/dev/null || true
progress_pid=
irq_after=$(read_irq_total)
recovery_count=$(count_recoveries)
printf '\rSoak complete: %4ds/%ds | IRQ delta: %-11d | recoveries: %-11d\n' \
	"$elapsed" "$SECONDS_TO_RUN" "$((irq_after - irq_before))" \
	"$recovery_count" >&2

if ! sudo -n journalctl -k -b --since "@$started_epoch" --no-pager \
	>"$kernel_log"; then
	cat "$capture_log"
	echo "capture_rc=$capture_rc elapsed=${elapsed}s evidence=$output_dir"
	echo "RESULT: FAIL (privileged kernel evidence was unavailable)"
	exit 1
fi
grep -E \
	-e 'VDONE duplicate recovered' \
	-e 'VDONE phase resync' \
	-e 'VDONE ambiguity' \
	-e 'VDONE half-ring failure' \
	-e 'video queue failed' \
	"$kernel_log" >"$recovery_log" || true

cat "$capture_log"
cat "$recovery_log"
echo "capture_rc=$capture_rc elapsed=${elapsed}s evidence=$output_dir"

if ((capture_rc != 124)); then
	echo "RESULT: FAIL (capture command returned $capture_rc; expected timeout status 124)"
	exit 1
fi

if grep -q 'VIDIOC_DQBUF: failed: Input/output error' "$capture_log" ||
	grep -Eq 'VDONE ambiguity|VDONE half-ring failure|video queue failed' \
		"$recovery_log"; then
	echo "RESULT: FAIL (capture or kernel queue failure)"
	exit 1
fi

minimum_elapsed=$((SECONDS_TO_RUN > 2 ? SECONDS_TO_RUN - 2 : SECONDS_TO_RUN))
if ((elapsed < minimum_elapsed)); then
	echo "RESULT: FAIL (capture exited before the requested soak duration)"
	exit 1
fi

if grep -q 'VDONE duplicate recovered' "$recovery_log"; then
	echo "RESULT: PASS (duplicate VDONE recovered and capture continued)"
	exit 0
fi

echo "RESULT: INCONCLUSIVE (capture survived, but no duplicate was observed)"
exit 2
