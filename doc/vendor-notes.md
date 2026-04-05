# Vendor Branch Notes

## Acasis Import

- Source archive: `/home/hoff/Downloads/1080P_PCIe_capture_card_drivers_for_Linux.zip`
- Imported branch: `acasis`
- Baseline compared against: current `master`

### Structural differences

- The baseline driver is split across PCI, IRQ, V4L2 ioctl, and video files.
- The Acasis drop collapses most driver logic into a single large `src/hws_video.c`.
- The Acasis branch removes `src/hws_irq.c`, `src/hws_irq.h`, `src/hws_pci.c`, `src/hws_v4l2_ioctl.c`, `src/hws_v4l2_ioctl.h`, and `src/hws_video.h`.
- The Acasis branch adds `src/hws_compat.h` and `src/load.sh`.

### Likely useful items to port to master

- Add PCI ID `0x8888:0x8521` to the device table and classify it as a 1-channel board.
- Consider carrying over the V4L2 file-handle compatibility shim from `src/hws_compat.h` for future kernel API changes.
- Consider the ALSA capture path only if HDMI audio capture is a real goal. The Acasis code registers PCM devices and has a separate audio DMA/workqueue path.

### Optional ideas worth studying, not copying blindly

- Per-open VB2 queues and refcounted capture start/stop. The Acasis code supports multiple opens, but it is not a true broadcast fan-out design.
- Software scaling and rotation driven by `S_FMT`. This enables fixed output sizes, including portrait-style output, but it adds a large amount of CPU-heavy copy/transform code.

### Items that should not be ported as-is

- The Acasis ext-control handlers return `-ERANGE` immediately on newer kernels, so that control path is incomplete.
- The old Acasis `s_ctrl` range check uses `>= min || <= max`, which is incorrect.
- The Acasis code does not implement the DV timings API that `master` already supports.

### Recommendation order

1. Port `0x8521` support if the Acasis board enumerates with that device ID.
2. Port the small V4L2 compatibility shim if we want to stay ahead of upstream API churn.
3. Treat ALSA capture as a separate feature project.
4. Treat scaling, rotation, and multi-open behavior as deliberate design work, not vendor-sync work.

## ProCapture 1.3.4420

- Source archive: `/home/hoff/Downloads/ProCaptureForLinux_1.3.4420.tar.gz`
- Imported branch: `procapture-1.3.4420`
- Baseline compared against: current `master`

### Architectural shape

- The visible driver structure is split into a low-level capture core with separate V4L2 and ALSA frontends layered on top.
- The V4L2 frontend uses per-open stream objects instead of one purely channel-global capture state.
- DMA memory handling is abstracted behind vendor helpers rather than going straight from hardware state into the V4L2 queue layer.

### Likely useful ideas to port to master

- If HDMI audio capture matters, add ALSA as a sibling frontend to the existing core rather than mixing audio handling into the current V4L2 path.
- If future features need per-client processing state, consider a per-open stream object model for crop, OSD, and similar stream-local settings.
- If `USERPTR` or broader scatter-gather support becomes a goal, consider a small DMA abstraction layer around buffer mapping and ownership.

### Feature areas worth studying, not copying wholesale

- The ProCapture stack exposes a much broader in-kernel processing pipeline, including crop, OSD composition, deinterlace, aspect/color processing, and SDI ANC handling.
- These features are useful as design references if `master` grows beyond straightforward capture, but they should be treated as independent projects rather than vendor-sync work.

### Items that should not be ported as-is

- Do not replace the current standard VB2/V4L2 flow with the ProCapture custom queue, timer, notification, and kthread-driven frame pump.
- Do not copy the separate `/dev/mw-event` control plane. Standard V4L2 events and ioctls are a better fit for `master`.
- Do not assume the visible vendor code is complete. The package links against a prebuilt `ProCaptureLib.o`, so a large part of the real behavior is opaque in this source drop.

### Recommendation order

1. Keep the existing `master` V4L2/VB2 architecture as the base.
2. Add a separate ALSA frontend only if audio capture is a real requirement.
3. Consider a DMA abstraction only if there is a concrete need for new buffer types such as `USERPTR` or richer SG handling.
4. Treat crop, OSD, ANC, and other processing features as deliberate feature work, not direct vendor imports.
