obj-m = HwsCapture.o

HwsCapture-objs := \
	 hws_pci.o \
	 hws_irq.o \
	 hws_video.o \
	 hws_v4l2_ioctl.o 

src := $(CURDIR)

EXTRA_CFLAGS += -I$(src)
EXTRA_LDFLAGS += -S

# -------- Extra compile flags for every obj in this makefile ----------
ccflags-y += -fno-ipa-icf -w
ccflags-y += -I$(src)

ifneq ($(KERNELRELEASE),)
KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
endif

all:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) modules

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

# --------------------------------------------------------------------
# clang-tidy setup (optional)
CLANG_TIDY    := clang-tidy
HAVE_CLANG_TIDY := $(shell which $(CLANG_TIDY) 2>/dev/null)
ifndef HAVE_CLANG_TIDY
$(warning "$(CLANG_TIDY) not found! Skipping clang-tidy checks.")
endif

TIDY_CFLAGS   := $(EXTRA_CFLAGS)
TIDY_INCLUDES := -I$(src) \
                 -I$(KERNELDIR)/include \
                 -I$(KERNELDIR)/include/uapi \
                 -I$(KERNELDIR)/arch/$(shell uname -m)/include
TIDY_DEFINES  := -D__KERNEL__ -D__KERNEL_STRICT_NAMES

C_SOURCES     := $(wildcard *.c)

.PHONY: tidy
tidy:
ifdef HAVE_CLANG_TIDY
	@echo ">> Running clang-tidy on: $(C_SOURCES)"
	@for f in $(C_SOURCES); do \
	  echo "   - $$f"; \
	  $(CLANG_TIDY) -p . $$f -- $(TIDY_CFLAGS) $(TIDY_INCLUDES) $(TIDY_DEFINES); \
	done
else
	@echo ">> clang-tidy not available, skipping tidy checks"
endif
