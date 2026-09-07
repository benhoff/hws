CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
CFLAGS += -DHWS_PATTERN_SHA256='"$(shell sha256sum hws_frame_pattern.h | cut -c1-64)"'

.PHONY: all clean check

.PHONY: check-audio check-audio-sanitize
check-audio:
	python3 -m unittest test_audio_lifetime -v

check-audio-sanitize:
	HWS_AUDIO_SANITIZE=1 python3 -m unittest test_audio_lifetime.AudioLifetimeTests.test_paused_worker_lifetime -v

# Optional physical presentation source (requires libdrm development files).
hws_frame_id_kms: hws_frame_id_kms.c hws_frame_pattern.h Makefile
	$(CC) $(CFLAGS) $(shell pkg-config --cflags libdrm) -DHWS_SOURCE_SHA256='"$(shell sha256sum hws_frame_id_kms.c | cut -c1-64)"' -o $@ $< $(shell pkg-config --libs libdrm)

.DEFAULT_GOAL := all

test_frame_id_kms: test_frame_id_kms.c hws_frame_id_kms.c hws_frame_id_capture.c hws_frame_pattern.h Makefile
	$(CC) $(CFLAGS) $(shell pkg-config --cflags libdrm) -o $@ $< $(shell pkg-config --libs libdrm)

.PHONY: check-failure check-failure-sanitize
check-failure:
	python3 -m unittest test_device_failure -v

check-failure-sanitize:
	HWS_FAILURE_SANITIZE=1 python3 -m unittest test_device_failure.DeviceFailureTests.test_production_failure_transaction -v

.PHONY: check-config check-config-sanitize
check-config:
	python3 -m unittest test_configuration -v

check-config-sanitize:
	HWS_CONFIG_SANITIZE=1 python3 -m unittest test_configuration.ConfigurationTests.test_dma_transaction test_configuration.ConfigurationTests.test_timing_contract -v

check: check-config check-failure check-audio all hws_frame_id_kms test_frame_id_kms
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
