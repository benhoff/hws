# Rockchip source host setup

Prepared 2026-09-06. The user identified the source as
`wulfuser@192.168.1.125` and confirmed its HDMI cable feeds **father's video2**.
The source host's own `/dev/video*` nodes are not the HWS capture target.

## Headless launcher implemented

`tools/hws_headless_source.py` now runs on **father**, controlling the source
over the already-working outbound SSH connection. It does not need KDE or a
reverse login, and it does not reload the capture driver. The earlier setup
notes below describe the initial import, before this implementation.

Run from father's normal terminal in `/home/hoff/swdev/hws`:

```bash
python3 tools/hws_headless_source.py --run --allow-dirty --require-vblank-off \
  --output /tmp/hws-rockchip-video2-qualification-1
```

Enter father's sudo password only in the normal terminal prompt. Run as `hoff`,
not `sudo python3`. Choose a new output path for each attempt. Defaults select
`wulfuser@192.168.1.125`, `/home/wulfuser/swdev/hws`, card0/connector84/CRTC81,
father's video2, 1,000 frames, 16 buffers, full mapping probes and queue evidence.
The current driver must already have `late_toggle_probe=1`; no parameter is
changed automatically. Stop other consumers of the selected capture input first.

The first agent-run attempt at
`/tmp/hws-rockchip-first-qualification-20260906` stopped during local capture
preflight because sudo required a terminal/password. **No remote source,
HDMI modeset or capture started.** The live qualification remains pending;
passing software tests is not a physical Rockchip timing/capture result.

Implemented safeguards:

- Capture preflight (including authentication) precedes source startup.
- File hashes must match between hosts. Native source builds use overridable
  `DRM_CFLAGS`/`DRM_LIBS`; the Rockchip profile uses the installed headers/library
  without installing packages or requiring `pkg-config`.
- `hws_frame_id_kms ... --mode-1080p60` selects only advertised exact CTA
  1920x1080p60 timing: 148500 kHz, totals 2200x1125. It saves the original CRTC,
  framebuffer and viewport, verifies the applied scanout before announcing
  readiness, and restores/read-verifies the original configuration afterward.
  The old positional invocation still uses the current mode.
- The remote process runs as `wulfuser`, using existing DRM permissions. A
  busy/unavailable DRM master is an error; no compositor is stopped or master
  forcibly taken. No source-side sudo policy is changed.
- A supervised source/clock child receives graceful termination on stop,
  SSH EOF/hangup or its deadline. Forced termination is never a successful run.
  SIGKILL, a machine crash or a hung kernel can still prevent restoration;
  software cleanup is not a guarantee against those failures.
- The source initiates the existing four-timestamp clock exchanges against
  an ephemeral IP/token-restricted UDP endpoint on father. Endpoint metadata
  travels over outbound SSH into a private directory. There is no reverse SSH,
  installed daemon, firewall change, or change to the clock-bound model. The new
  `hws_clock_probe.py --udp-peer-file` option uses that endpoint directly.
- Three consecutive exact receiver timing queries precede capture. The
  existing collector configures the detected timings and seals raw source,
  clock, trace and content evidence. Source/clock transfer failures cannot
  release the validation-ready marker with missing evidence.
- Error cleanup interrupts the local capture process group before stopping
  the source, giving the evidence runner/trace recorder their cleanup path.
- The existing strict gates remain. Only the two explicitly allowed dirty
  provenance failures permit diagnostic completion; timing/content failures
  remain failures. The launcher also requires confirmed source restoration.

A related reporting correction now uses the per-stream `duplicate_reports`
counter in `assess_trial`, not lifetime `duplicate_recoveries`, so prior-stream
recoveries cannot inflate a subsequent batch trial. The sealed counters and
prior reports were not edited.

Software verification: full `make -C tools check` passed, including the new
headless/UDP cleanup tests and exact-mode/restoration modeled-DRM test; the
30 local runner regressions also passed. Native ARM64 builds, exact raster and
decoder tests, modeled mode restoration and headless regressions passed on the
Rockchip. Its read-only display query still showed the original 4096x2160 mode.

The updated source file SHA-256 is
`c3be4756a1543a1663e05f630b6428d0ddae4a2dacbd1c4106c7c02e5b19e15e`;
the pattern hash is unchanged. Both hosts have the same source implementation,
but this new source build must be physically qualified before extending exposure.
The launcher is deliberately limited to one <=1,000-frame run with fresh evidence
budgets; it does not yet perform an unattended 20-run batch.

## Copied checkout

- Host: `nanopct6-lts`, ARM64 Rockchip, Armbian/Ubuntu 24.04.
- Checkout: `/home/wulfuser/swdev/hws`.
- Branch: `audio-upstream-v20-source-rewrite`; HEAD `4706e64`.
- Git history was transferred as a bundle and cloned into a new directory.
  The current working-tree source/documentation files were then overlaid,
  preserving the uncommitted implementation rather than testing HEAD alone.
- The initial overlay contains 126 files; a checksum-based rsync dry run found
  no differences. This setup note is transferred separately afterward.
- `.env`, `.codex`, SSH credentials, local Git configuration/hooks, compiled
  binaries, generated headers, and historical test recordings were not copied
  from the working tree. No pre-existing checkout was overwritten: setup
  required that the checkout path did not exist.
- Import materials remain at `/home/wulfuser/hws-import-zLAlsD` on the source;
  local staging remains at `/tmp/hws-wulf-transfer.zLAlsD` on father.

Source identities match father:

```
tools/hws_frame_id_kms.c
22948ffba6d3f46c34d72641bd24f19621037aa516a389fc1a024c843c6138b5
tools/hws_frame_pattern.h
b39bddb09865bf4d8201fe59dea932017271d296808dcf719852b14e6ab89272
```

## Native build and checks

The installed DRM headers/library were sufficient, but `pkg-config` was absent.
No packages were installed. Source and probe tools were built directly with
`cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic -I/usr/include/libdrm`, linking
`-ldrm` (and `-lm` for the timing probe). The source build included
`HWS_SOURCE_SHA256` and `HWS_PATTERN_SHA256` definitions matching the hashes
above. The resulting source executable is native ARM64, not father's x86 build.

Checks completed on the new host:

- Exact raster equivalence: 13 geometries and six frame IDs, PASS.
- Raster/capture decoder: 13 modes and three IDs each, PASS.
- Clock-mapping, remote-source/batch, and capture-preflight unit tests: 30 PASS.
  Their simulated capture/failure messages are not physical capture results.
- Read-only DRM CRTC sequence check: 120 samples, zero invalid, usable.
  This tested the **existing 4096x2160 mode**, not the intended capture mode.
  Raw output: `/home/wulfuser/hws-import-zLAlsD/checks/drm-sequence.jsonl`.
- Unattached 1080p DRM-buffer rendering benchmark, 30 samples: optimized
  renderer median 0.794 ms, p95 1.889 ms, max 1.912 ms. This is CPU rendering
  time only, not page-flip/presentation qualification.

## Initial hardware configuration and remaining work at import

Read-only enumeration found:

| Field | Value |
| --- | --- |
| DRM card | `/dev/dri/card0` |
| Connected output | HDMI-A-1 |
| Connector ID | 84 |
| CRTC ID | 81 |
| Current active size | 4096x2160 |
| HDMI-A-2 | Disconnected |
| Network to father | `end1`, 192.168.1.125 to 192.168.1.25 |

These IDs must be rechecked after hardware/boot changes. No HDMI mode, VT,
module, sudo policy, SSH key, or receiver configuration was changed, and no
physical capture was started.

The laptop-oriented `hws_remote_source.py` assumes a source-side KDE session and
`kscreen-doctor`. This host lacks that tool. Its active 4096x2160 mode is also
outside the intended native 1080p HWS test. At import the KMS source only used the
active mode rather than selecting 1080p itself. Do not run the laptop command
unchanged or treat successful sequence checks as qualified page flips.

These findings motivated the headless launcher documented above. Its pending
physical test is one fully instrumented 1,000-frame qualification before a batch.

`sudo -n` on the source requires authentication. Reverse SSH from the source
to `hoff@192.168.1.25` stopped at unknown host-key verification; subsequent
user authentication was not tested. Do not copy private keys or weaken host-key
checking to work around this. A father-controlled SSH orchestration design
could avoid needing a source-to-father login and repeated per-trial sudo PTYs.
