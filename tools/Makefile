CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
CFLAGS += -DHWS_PATTERN_SHA256='"$(shell sha256sum hws_frame_pattern.h | cut -c1-64)"'

.PHONY: all clean check

# Optional physical presentation source (requires libdrm development files).
hws_frame_id_kms: hws_frame_id_kms.c hws_frame_pattern.h Makefile
	$(CC) $(CFLAGS) $(shell pkg-config --cflags libdrm) -DHWS_SOURCE_SHA256='"$(shell sha256sum hws_frame_id_kms.c | cut -c1-64)"' -o $@ $< $(shell pkg-config --libs libdrm)

.DEFAULT_GOAL := all

test_frame_id_kms: test_frame_id_kms.c hws_frame_id_kms.c hws_frame_id_capture.c hws_frame_pattern.h Makefile
	$(CC) $(CFLAGS) $(shell pkg-config --cflags libdrm) -o $@ $< $(shell pkg-config --libs libdrm)

check: all hws_frame_id_kms test_frame_id_kms
	./hws_frame_id_capture --self-test
	./test_frame_id_kms
	python3 -m unittest discover -s . -p 'test_vdone*.py' -v

all: hws_frame_id_capture hws_vdone_sampler

hws_frame_id_capture: hws_frame_id_capture.c hws_frame_pattern.h Makefile
	$(CC) $(CFLAGS) -DHWS_CAPTURE_SHA256='"$(shell sha256sum hws_frame_id_capture.c | cut -c1-64)"' -o $@ $<

hws_vdone_sampler: hws_vdone_sampler.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f hws_frame_id_capture hws_vdone_sampler hws_frame_id_kms test_frame_id_kms
