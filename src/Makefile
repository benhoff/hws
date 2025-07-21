HwsCapture-objs := hws_video.o

obj-m = HwsCapture.o

EXTRA_CFLAGS += -I$(src)
# strip debug symbols
EXTRA_LDFLAGS += -S
ccflags-y += -fdump-ipa-cgraph -fno-ipa-icf -w
ccflags-y += -I$(src)


ifneq ($(KERNELRELEASE),)
KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
endif

PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

