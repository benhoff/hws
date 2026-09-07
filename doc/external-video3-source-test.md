# Qualified laptop source on father's video3 input

Prepared 2026-09-06 in response to father's latest nine-capture report.

## Execution update: use video2

The user subsequently specified **video2**. The video3 attempt captured 1,000
frames with zero valid decodes and does not qualify the laptop source on that
input. The corrected laptop-to-video2 run passed all capture, independent
mapping and presentation/clock gates with zero recoveries. Only dirty/uncommitted
provenance failed. See [the verified video2 result](video2-laptop-calibration-20260906.md).
The video3 procedure below records the originally planned experiment; continue
on video2 as instructed. The input difference remains a confound relative to
NVIDIA-to-video3, so the present comparison cannot isolate the source alone.

## Evidence and decision

The user-provided report records nine duplicate-toggle recoveries across 9,000
content-checked frames, with NVIDIA vblank disabled, 4/16 buffers and reduced/full
instrumentation. Fully instrumented 16-buffer cases had 13–14 buffers available
at the duplicate. Those particular events were not queue starvation. All nine
late-toggle windows retained four unchanged toggle reads with no sampled status
reassertion. This provides no supporting evidence for a brief reread-and-rescue
policy; changes outside the sampled windows remain possible. Independent capture
checks passed for fully instrumented runs; reduced runs lack that proof.

The next experiment changes the source to the qualified Intel laptop while
holding the capture input at `/dev/video3`, the mode at exact 1080p60 and the
loaded driver fixed. Do not use the NVIDIA source launcher for this run.
Do not interpret older review entries as instructions to reapply fixes already
implemented on father. Its remediation plan records the newer software changes.

Read-only readiness checks found loaded HwsCapture srcversion
`2872F13A805266B6EBE1D34`, `late_toggle_probe=Y`, and
`source_transition_checks=Y`, matching the build identified in father's late
diagnostic document. No module or module parameter was changed here.

## Tooling update

`tools/hws_remote_source.py` now accepts `--buffers`, `--queue-diagnostics`,
`--probe-mode` and `--require-vblank-off`. The exact capture command is saved
in local `run.json` and used for both remote preflight and capture. The profile
below requests 16 buffers, full DMA probes and queue diagnostics with no injected
requeue delay. Father's current evidence runner already supports these options
and collects the enabled late-toggle event. Source and pattern hashes match
between the two hosts; source rendering behavior is unchanged for this test.

The existing four-buffer default remains available for prior workflows. New
regressions verify the video3 profile through both bootstrap phases, preserve
defaults and require explicit selection of reduced probes. They passed with
the existing preflight tests (8 tests total) on the laptop.

## Readiness and execution

The laptop initially routed to father through Wi-Fi. Its 30-second clock check
was inconclusive at a maximum uncertainty bound of 874,449 ns. After the wired
link was reconnected, the route became `enp38s0f1`, source `192.168.1.202`, to
father `192.168.1.25`. The second check passed: 2,921 samples, maximum uncertainty
325,259 ns, minimum exchange RTT 357,035 ns, maximum sample gap 11,878,123 ns.
Raw records are on princess at `/tmp/hws-video3-clock-wired-20260906.jsonl`.
The capture still collects and validates its own continuous clock evidence.

The HDMI cable must connect the laptop to the **physical input previously used
by NVIDIA as video3**. A change from the earlier video2 setup is required;
network reconnection alone does not establish HDMI routing. A receiver's current
1080p timing does not identify which source is connected.

Both hosts' noninteractive sudo checks currently require passwords. Run the
following in the laptop's desktop terminal so local and remote sudo can use their
ordinary interactive prompts. The launcher authenticates/preflights before
switching VT, restores the display, and does not reload the driver. Do not put
passwords in chat or command arguments.

First qualify the new channel/source combination with 1,000 frames:

```bash
python3 /home/hoff/swdev/hws/tools/hws_remote_source.py --run --host father --channel 3 --frames 1000 --buffers 16 --queue-diagnostics --probe-mode full --require-vblank-off --allow-dirty --output /tmp/hws-video3-laptop-calibration-20260906
```

Inspect the completed bundle before extending exposure. Required diagnostic
gates are valid decoded contents, independent capture checks, qualified source
presentation/clock mapping, correct run/module identity, and complete late-toggle
evidence for any duplicates (or an explicit `not_observed` result). The overall
strict result may fail solely for dirty provenance; inspect each gate separately
and do not waive other failures. Preserve every sealed bundle.

For further fully instrumented exposure, prefer repeated 1,000-frame captures
on the user-selected video2 with a fresh output directory for each. The observed
driver has a 4,096-record initial independent-probe cap and a 32,768-record queue
diagnostic cap per stream. This calibration used 2,009 and 7,005 respectively.
Simply extending one run to 9,000 frames would exhaust these caps and reduce
coverage later in the run. This supersedes the earlier single-9,000-frame
suggestion. Each repeated capture must be checked independently; the expected
dirty-provenance exit code is not a reason to ignore other failures.
Match individual NVIDIA profiles when comparing rates; nine heterogeneous
captures are not one controlled rate estimate. Repeated startup epochs also
differ from one continuous long run.

For each duplicate, inspect queue availability, pre/post-ack and follow-up
toggle/status samples, source holds, DMA-region IDs, discarded partials and
delivered content. Keep content, independent mapping, timing and provenance
verdicts separate. The source can hold IDs over multiple refreshes; this setup
does not yet provide distinct-per-refresh loss identity in every case.

Duplicates with the Intel source would weaken a NVIDIA-specific explanation,
but would not distinguish receiver behavior from interrupt delivery. Absence
in a short trial would not establish that changing the source fixes the issue.
No physical video3 laptop capture has been completed by this preparation.
