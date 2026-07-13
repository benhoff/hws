# MSI and INTx interrupt operation

## Hardware capability

The validated AVMatrix VC42 (`8888:8504`, subsystem `8888:0007`) advertises:

```text
Capabilities: [48] MSI: Enable- Count=1/1 Maskable- 64bit+
```

The card therefore supports one 64-bit MSI vector. It does not advertise an
MSI-X capability. One vector means that MSI changes how the PCI function
notifies the host, but does not give each capture channel a separate interrupt.
The driver must continue to demultiplex all video and audio causes through
`HWS_REG_INT_STATUS`.

## Selection policy

At probe, `hws_alloc_irq()` requests exactly one vector in this order:

1. Request one vector with `PCI_IRQ_ALL_TYPES`.
2. Let the PCI core prefer MSI-X, then MSI, and finally legacy INTx.
3. If no interrupt type is available, fail probe; the device cannot operate
   without completion interrupts.

The validated card does not expose MSI-X, but allowing it avoids imposing that
hardware-specific limitation on other supported devices. PCI core handles
message-signaled interrupt availability and platform quirks before selecting
legacy INTx as the fallback.

The resulting `request_threaded_irq()` flags differ by mode:

| Mode | IRQ flags | Reason |
| --- | --- | --- |
| MSI-X | `0` | An MSI-X vector is dedicated and must not use `IRQF_SHARED`. |
| MSI | `0` | An MSI vector is dedicated and must not use `IRQF_SHARED`. |
| INTx | `IRQF_SHARED` | A legacy interrupt pin may be shared with other PCI devices. |

Always use `pci_irq_vector(pdev, 0)` after vector allocation. Do not assume
`pdev->irq` is the Linux IRQ assigned to MSI.

## Automatic fallback conditions

The PCI core can reject MSI for several reasons, including:

- MSI disabled globally by the kernel or boot parameters.
- MSI disabled for the device or an upstream PCI bus.
- Interrupt-remapping or architecture policy rejecting the allocation.
- No free host interrupt vector.
- A different supported card revision not advertising MSI.

PCI core attempts shared INTx if message-signaled allocation is unavailable. A
successful fallback is not a probe error. The driver reports the installed
Linux IRQ number:

```text
irq handler installed on irq=N
```

## Fallback validation and recovery

Use the applicable PCI or platform test mechanism to disable MSI when the INTx
fallback needs explicit validation. For example, the `pci=nomsi` kernel command
line option disables MSI system-wide and therefore requires a reboot:

```sh
pci=nomsi
```

Do not use a system-wide MSI override as the normal configuration after MSI has
passed the streaming and power-management tests below. INTx fallback testing is
useful for:

- Comparing MSI behavior against the previous driver configuration.
- Isolating a platform-specific MSI routing problem.
- Recovering capture while an MSI regression is investigated.

## Handler behavior

INTx is level-triggered: an unacknowledged device cause keeps the line asserted.
MSI is message-based: software cannot depend on an asserted line to invoke the
handler again. The hard handler consequently reads, handles, acknowledges, and
re-reads `HWS_REG_INT_STATUS` until no causes remain.

The loop is bounded by `MAX_INT_LOOPS`. Reaching the bound produces a ratelimited
warning and indicates a stuck status bit, unexpected acknowledgment semantics,
or an interrupt source arriving faster than it can be drained. Video completion
is still deferred to the threaded handler, and audio completion is still queued
to the existing audio work path.

For shared INTx, a zero status returns `IRQ_NONE`, allowing the kernel to treat
the interrupt as belonging to another device. For MSI, zero status is unexpected
but the same return remains useful for detecting broken device signaling.

## Lifetime and power management

`pci_alloc_irq_vectors()` state must outlive the registered IRQ action. Because
`pcim_enable_device()` does not manage vector allocations, the driver registers
a devres action that calls `pci_free_irq_vectors()`. The cleanup action is
registered before `devm_request_threaded_irq()`, so devres LIFO ordering frees
the IRQ action before it frees the vectors.

Vectors remain allocated across system suspend. The suspend sequence marks the
device suspended, masks its interrupt gate, synchronizes any in-flight handler,
and clears stale status before entering D3. Resume restores the device and PCI
state, reopens the device interrupt gate, and then clears the suspended state.
It never disables the Linux IRQ descriptor, because the INTx fallback may share
that descriptor with unrelated devices. Do not free and reallocate the vector
in suspend/resume callbacks.

## Validation

After loading in the default mode, verify all three views agree:

```sh
lspci -s 17:00.0 -vv
ls /sys/bus/pci/devices/0000:17:00.0/msi_irqs/
grep -E 'HwsCapture|17:00.0' /proc/interrupts
```

Expected MSI evidence:

- `lspci` reports `MSI: Enable+` and `DisINTx+`.
- `msi_irqs` contains exactly one entry.
- `/proc/interrupts` identifies a PCI MSI interrupt rather than IO-APIC INTx.

Run the same functional workload in default MSI mode and, in a controlled test
environment, with MSI disabled so PCI core selects INTx:

1. Capture one video channel, then all available video channels.
2. Capture all audio channels alone and concurrently with video.
3. Check frame drops, ALSA XRUNs, and interrupt counts under CPU and PCIe load.
4. Stop and restart streams repeatedly.
5. Suspend and resume with streams closed, then reopen them.
6. Unload and reload the module repeatedly in both modes.
7. Confirm there are no `IRQ status did not drain`, `nobody cared`, or probe
   fallback messages unless the condition is being tested intentionally.

If MSI fails while INTx remains stable, preserve the full kernel log, the
`lspci -vv` output for the endpoint and its upstream bridge, `/proc/interrupts`,
and the IOMMU/interrupt-remapping boot configuration before forcing fallback.
