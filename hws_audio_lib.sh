#!/usr/bin/env bash
# Common helpers for the local HWS HDMI audio scripts. Source this file.

hws_have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

hws_timestamp() {
	date '+%Y%m%d-%H%M%S'
}

hws_detect_hdmi_sink() {
	local prefer=${1:-nvidia}

	if ! hws_have_cmd pactl; then
		return 1
	fi

	pactl list sinks 2>/dev/null | awk -v prefer="$prefer" '
		BEGIN {
			RS = "Sink #"
			FS = "\n"
		}
		NR > 1 {
			name = ""
			block = tolower($0)
			for (i = 1; i <= NF; i++) {
				line = $i
				if (line ~ /^[ \t]*Name: /) {
					name = line
					sub(/^[ \t]*Name: /, "", name)
				}
			}
			if (name == "")
				next

			is_nvidia = index(block, "nvidia") > 0
			is_hdmi = index(block, "hdmi") > 0 || index(block, "displayport") > 0

			if (is_nvidia && is_hdmi && primary == "")
				primary = name
			else if (is_nvidia && nvidia_only == "")
				nvidia_only = name
			else if (is_hdmi && hdmi_only == "")
				hdmi_only = name
		}
		END {
			if (prefer == "nvidia") {
				if (primary != "")
					print primary
				else if (nvidia_only != "")
					print nvidia_only
				else if (hdmi_only != "")
					print hdmi_only
			} else {
				if (primary != "")
					print primary
				else if (hdmi_only != "")
					print hdmi_only
				else if (nvidia_only != "")
					print nvidia_only
			}
		}
	'
}

hws_list_hdmi_sinks() {
	if ! hws_have_cmd pactl; then
		printf 'pactl not found; cannot list PipeWire/Pulse sinks\n' >&2
		return 1
	fi

	pactl list sinks 2>/dev/null | awk '
		BEGIN {
			RS = "Sink #"
			FS = "\n"
			OFS = "\t"
			print "target", "class", "description"
		}
		NR > 1 {
			name = ""
			desc = ""
			block = tolower($0)
			for (i = 1; i <= NF; i++) {
				line = $i
				if (line ~ /^[ \t]*Name: /) {
					name = line
					sub(/^[ \t]*Name: /, "", name)
				}
				if (line ~ /^[ \t]*Description: /) {
					desc = line
					sub(/^[ \t]*Description: /, "", desc)
				}
			}
			if (name == "")
				next

			is_nvidia = index(block, "nvidia") > 0
			is_hdmi = index(block, "hdmi") > 0 || index(block, "displayport") > 0
			if (!is_nvidia && !is_hdmi)
				next

			if (is_nvidia && is_hdmi)
				class = "nvidia-hdmi"
			else if (is_nvidia)
				class = "nvidia"
			else
				class = "hdmi"

			print name, class, desc
		}
	'
}

hws_detect_nvidia_card() {
	if ! hws_have_cmd pactl; then
		return 1
	fi

	pactl list cards 2>/dev/null | awk '
		BEGIN {
			RS = "Card #"
			FS = "\n"
		}
		NR > 1 {
			name = ""
			block = tolower($0)
			for (i = 1; i <= NF; i++) {
				line = $i
				if (line ~ /^[ \t]*Name: /) {
					name = line
					sub(/^[ \t]*Name: /, "", name)
				}
			}
			if (name != "" && index(block, "nvidia") > 0) {
				print name
				exit
			}
		}
	'
}

hws_list_nvidia_card_profiles() {
	if ! hws_have_cmd pactl; then
		printf 'pactl not found; cannot list card profiles\n' >&2
		return 1
	fi

	pactl list cards 2>/dev/null | awk '
		BEGIN {
			RS = "Card #"
			FS = "\n"
			OFS = "\t"
			print "card", "active_profile", "profile", "available"
		}
		NR > 1 {
			name = ""
			active = ""
			count = 0
			in_profiles = 0
			block = tolower($0)
			for (i = 1; i <= NF; i++) {
				line = $i
				if (line ~ /^[ \t]*Name: /) {
					name = line
					sub(/^[ \t]*Name: /, "", name)
				}
				if (line ~ /^[ \t]*Profiles:/) {
					in_profiles = 1
					continue
				}
				if (line ~ /^[ \t]*Active Profile: /) {
					active = line
					sub(/^[ \t]*Active Profile: /, "", active)
					in_profiles = 0
				}
				if (in_profiles && line ~ /^[ \t]+[^ \t].*: /) {
					profile = line
					sub(/^[ \t]+/, "", profile)
					sub(/: .*/, "", profile)
					available = (line ~ /available: yes/) ? "yes" : "no"
					profiles[++count] = profile "\t" available
				}
			}
			if (name == "" || index(block, "nvidia") == 0)
				next
			for (i = 1; i <= count; i++) {
				split(profiles[i], fields, "\t")
				print name, active, fields[1], fields[2]
			}
		}
	'
}

hws_set_nvidia_profile() {
	local card=${1:-auto}
	local profile=${2:-}

	if [ -z "$profile" ]; then
		printf 'no profile supplied\n' >&2
		return 1
	fi
	if [ -z "$card" ] || [ "$card" = "auto" ]; then
		card=$(hws_detect_nvidia_card || true)
	fi
	if [ -z "$card" ]; then
		printf 'could not auto-detect an NVIDIA audio card\n' >&2
		return 1
	fi

	pactl set-card-profile "$card" "$profile"
}

hws_resolve_playback_target() {
	local target=${1:-auto}

	if [ -z "$target" ] || [ "$target" = "auto" ]; then
		target=$(hws_detect_hdmi_sink nvidia || true)
	fi

	if [ -z "$target" ]; then
		printf 'could not auto-detect an NVIDIA/HDMI playback sink; run ./hws_hdmi_audio_targets.sh and pass --target, or enable a card profile with --profile pro-audio\n' >&2
		return 1
	fi

	printf '%s\n' "$target"
}

hws_require_cmds() {
	local missing=0
	local cmd

	for cmd in "$@"; do
		if ! hws_have_cmd "$cmd"; then
			printf 'missing required command: %s\n' "$cmd" >&2
			missing=1
		fi
	done

	return "$missing"
}

hws_expand_alsa_device_list() {
	local spec=$1
	local token

	spec=${spec//,hw:/ hw:}
	spec=${spec//,plughw:/ plughw:}
	spec=${spec//;/ }

	for token in $spec; do
		[ -n "$token" ] && printf '%s\n' "$token"
	done
}

hws_discover_hws_card_indices() {
	awk '/^[[:space:]]*[0-9]+ \[[^]]+\]: .*HWS HDMI Audio/ { print $1 }' /proc/asound/cards 2>/dev/null
}

hws_discover_hws_audio_devices() {
	local card_idx=${1:-}
	local discovered_card
	local card_prefix

	if [ -n "$card_idx" ]; then
		printf -v card_prefix '%02d-' "$card_idx"
		awk -v prefix="$card_prefix" '
			index($1, prefix) == 1 && /capture/ {
				split($1, parts, "-")
				printf "hw:%d,%d\n", parts[1] + 0, parts[2] + 0
			}
		' /proc/asound/pcm 2>/dev/null
		return 0
	fi

	for discovered_card in $(hws_discover_hws_card_indices); do
		hws_discover_hws_audio_devices "$discovered_card"
	done
}

hws_alsa_device_parts() {
	local dev=$1
	local rest
	local card
	local pcm

	case "$dev" in
	hw:*|plughw:*)
		rest=${dev#*:}
		card=${rest%%,*}
		pcm=${rest#*,}
		pcm=${pcm%%,*}
		if [[ "$card" =~ ^[0-9]+$ ]] && [[ "$pcm" =~ ^[0-9]+$ ]]; then
			printf '%s %s\n' "$((10#$card))" "$((10#$pcm))"
			return 0
		fi
		;;
	esac

	return 1
}

hws_alsa_capture_device_exists() {
	local dev=$1
	local card
	local pcm
	local key

	if read -r card pcm < <(hws_alsa_device_parts "$dev"); then
		printf -v key '%02d-%02d' "$card" "$pcm"
		[ -r /proc/asound/pcm ] &&
			awk -v key="$key" '$0 ~ "^" key ":" && tolower($0) ~ /capture/ { found = 1 } END { exit found ? 0 : 1 }' /proc/asound/pcm
		return $?
	fi

	return 1
}

hws_detect_hws_audio_device() {
	local preferred_pcm=${1:-}
	local dev
	local first=""
	local pcm

	while IFS= read -r dev; do
		[ -n "$dev" ] || continue
		[ -n "$first" ] || first=$dev
		pcm=${dev##*,}
		if [ -n "$preferred_pcm" ] && [ "$pcm" = "$preferred_pcm" ]; then
			printf '%s\n' "$dev"
			return 0
		fi
	done < <(hws_discover_hws_audio_devices)

	if [ -z "$preferred_pcm" ] && [ -n "$first" ]; then
		printf '%s\n' "$first"
		return 0
	fi

	return 1
}

hws_write_audio_context() {
	local output_dir=$1

	mkdir -p "$output_dir"
	{
		date
		uname -a
	} >"$output_dir/system.txt" 2>&1 || true

	if hws_have_cmd pactl; then
		pactl info >"$output_dir/pactl-info.txt" 2>&1 || true
		pactl list short sinks >"$output_dir/pactl-sinks-short.txt" 2>&1 || true
		pactl list sinks >"$output_dir/pactl-sinks.txt" 2>&1 || true
		pactl list cards >"$output_dir/pactl-cards.txt" 2>&1 || true
	fi
	if hws_have_cmd wpctl; then
		wpctl status >"$output_dir/wpctl-status.txt" 2>&1 || true
	fi
	if hws_have_cmd pw-cli; then
		pw-cli ls Node >"$output_dir/pw-cli-nodes.txt" 2>&1 || true
	fi
	if hws_have_cmd arecord; then
		arecord -l >"$output_dir/arecord-list.txt" 2>&1 || true
		arecord -L >"$output_dir/arecord-pcms.txt" 2>&1 || true
	fi
	cat /proc/asound/cards >"$output_dir/proc-asound-cards.txt" 2>/dev/null || true
	cat /proc/asound/pcm >"$output_dir/proc-asound-pcm.txt" 2>/dev/null || true
}
