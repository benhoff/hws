CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic

.PHONY: all clean

all: hws_frame_id_capture hws_vdone_sampler

hws_frame_id_capture: hws_frame_id_capture.c
	$(CC) $(CFLAGS) -o $@ $<

hws_vdone_sampler: hws_vdone_sampler.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f hws_frame_id_capture hws_vdone_sampler
