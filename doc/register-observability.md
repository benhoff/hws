# HWS register atlas, snapshots, and MMIO tracing

This observability layer is intentionally allowlist-first. BAR0 is an MMIO
address decoder, not ordinary RAM: an unknown read can acknowledge status or
advance hardware state, and an unknown write can start DMA or corrupt address
translation. No tool in this layer scans unknown BAR offsets or writes a
register.

## Register atlas

`registers/hws_bar0_registers.json` is the source of truth. Each register has:

- BAR offset and width;
- access semantics (`ro`, `rw`, `w1c`, `wo`, or mixed read/write meaning);
- channel instance count and stride;
- named bitfields;
- known reset and typical values, with unknown values represented explicitly;
- evidence source and confidence (`measured`, `vendor-code`, `inferred`, or
  `unknown`); and
- an explicit `snapshot_safe` decision.

The kernel table in `src/hws_reg_atlas_generated.inc` and the driver offset
macros in `src/hws_reg_atlas_offsets.h` are generated from the JSON atlas.
`hws_reg.h` aliases its established register names to those generated offsets,
so the driver and observability tools cannot carry different numeric maps. Do
not edit either generated file directly:

```sh
make -C src atlas
make -C src atlas-check
```

The generator rejects unaligned and out-of-range offsets, overlapping register
instances, invalid bitfields, unsupported semantics, and stale generated
output.

## Read-only debugfs interfaces

With debugfs mounted and the driver loaded, each device exposes:

```text
/sys/kernel/debug/hws/<PCI-BDF>/register_atlas
/sys/kernel/debug/hws/<PCI-BDF>/register_snapshot
/sys/kernel/debug/hws/<PCI-BDF>/bar0_snapshot
```

`register_atlas` contains metadata and performs no MMIO. `register_snapshot`
reads only 32-bit registers marked `snapshot_safe=true`. `bar0_snapshot` is a
compatibility alias for existing scripts.

The snapshot header contains `allowlist_only=1` and `atomic=0`. The latter is
important: hardware continues running while the registers are read, so values
from the beginning and end of a snapshot can belong to slightly different
instants. Start and end monotonic timestamps bound that interval.

Snapshots refuse MMIO while the device is suspended or known to be lost. Each
offset is also bounds-checked against the actual BAR0 resource length reported
by PCI rather than a hardcoded size.

## MMIO trace event

All BAR0 reads and writes made by the driver use the tracing wrapper. The trace
event records the trace timestamp plus:

- PCI device;
- read/write operation and ordered/relaxed variant;
- offset and value;
- atlas register name and inferred channel; and
- calling function.

Tracing is disabled by default. A short capture can be collected with:

```sh
sudo sh -c 'echo 0 > /sys/kernel/tracing/tracing_on'
sudo sh -c 'echo > /sys/kernel/tracing/trace'
sudo sh -c 'echo 1 > /sys/kernel/tracing/events/hws/hws_mmio/enable'
sudo sh -c 'echo 1 > /sys/kernel/tracing/tracing_on'

# Perform one controlled action here.

sudo sh -c 'echo 0 > /sys/kernel/tracing/tracing_on'
sudo sh -c 'echo 0 > /sys/kernel/tracing/events/hws/hws_mmio/enable'
sudo cat /sys/kernel/tracing/trace
```

Keep trace windows short. IRQ status and toggle reads can generate substantial
volume during active capture. Tracing observes existing driver accesses; it
does not introduce reads of unknown offsets.

## Controlled differential experiments

`python/hws_register_experiment.py` reads only the driver debugfs snapshot. It
will reject `resource0`, arbitrary binary dumps, or a snapshot missing the
`allowlist_only=1` marker.

Capture one labeled state:

```sh
sudo python3 python/hws_register_experiment.py \
  --pci-bdf 0000:17:00.0 snapshot --label idle
```

Run a guided before/after experiment:

```sh
sudo python3 python/hws_register_experiment.py \
  --pci-bdf 0000:17:00.0 pair --experiment cable
```

Available experiment prompts are `cable`, `vcap`, `channel`, `resolution`,
`queue-depth`, `audio`, and `custom`. The tool does not manipulate the source,
stream, queue, or hardware. It waits for the operator to establish each state,
which keeps the exact transition visible and reviewable.

Compare previously saved text or JSON snapshots:

```sh
python3 python/hws_register_experiment.py diff before.snapshot.json after.snapshot.json
```

Monitor only allowlisted changes:

```sh
sudo python3 python/hws_register_experiment.py \
  --pci-bdf 0000:17:00.0 monitor --interval-seconds 1
```

The legacy `python/bar0_monitor.py` entry point now delegates to this safe
monitor. It no longer maps and polls the complete 64 KiB BAR.

For each experiment, keep the source, channel, format, process, and timing
constant except for the one condition under test. Repeat the pair several times
and treat a field as understood only when its changes correlate consistently.
BAR readback can establish the visible register value, but it cannot by itself
prove hidden internal state such as when a DMA target is latched.
