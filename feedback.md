drivers/media/pci/hws/
├── Kconfig
├── Makefile
├── hws-core.c          # probe glue, device lifecycle, common structs, logging, pm hooks
├── hws-pci.c           # PCI IDs, enable device, BARs, DMA masks, MSI/MSI-X wiring
├── hws-irq.c           # ISR/ threaded handler, status/ack, work handling
├── hws-video.c         # V4L2 device/node, vb2 queue, formats, controls, ioctls
├── hws-queue.c         # (optional) vb2 ops and DMA engine helpers if large
├── hws-regs.h          # register definitions, bitfields, masks (SPDX header!)
├── hws.h               # shared driver structs, enums, helpers
