CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
CFLAGS += -DHWS_PATTERN_SHA256='"$(shell sha256sum hws_frame_pattern.h | cut -c1-64)"'
DRM_CFLAGS ?= $(shell pkg-config --cflags libdrm)
DRM_LIBS ?= $(shell pkg-config --libs libdrm)

.PHONY: all clean check check-irq check-irq-sanitize check-irq-mutations check-audio check-audio-sanitize

check-audio:
	python3 -m unittest test_audio_lifetime -v

.PHONY: check-config check-config-sanitize
check-config:
	python3 -m unittest test_configuration -v

check-config-sanitize:
	HWS_CONFIG_SANITIZE=1 python3 -m unittest test_configuration.ConfigurationTests.test_dma_transaction test_configuration.ConfigurationTests.test_timing_contract -v

.PHONY: check-transitions check-transitions-sanitize
check-transitions: check-irq
	python3 -m unittest test_transitions -v

check-transitions-sanitize: check-irq-sanitize
	HWS_TRANSITION_SANITIZE=1 python3 -m unittest test_transitions.TransitionTests.test_restart_and_notification_contract -v

.PHONY: check-failure check-failure-sanitize
check-failure:
	python3 -m unittest test_device_failure -v

check-failure-sanitize:
	HWS_FAILURE_SANITIZE=1 python3 -m unittest test_device_failure.DeviceFailureTests.test_production_failure_transaction -v

check-audio-sanitize:
	HWS_AUDIO_SANITIZE=1 python3 -m unittest test_audio_lifetime.AudioLifetimeTests.test_paused_worker_lifetime -v

.hws_irq_under_test.h: build_hws_irq_test.py test_audio_lifetime.py ../src/hws_irq.c ../src/hws_video.c ../src/hws.h ../src/hws_reg.h ../src/hws_probe.h ../src/hws_fault.h ../src/hws_timing.h ../src/hws_source.h ../src/hws_late_toggle.h
	python3 build_hws_irq_test.py $@

test_hws_irq: test_hws_irq.c hws_irq_test_shim.h hws_irq_test_api.h .hws_irq_under_test.h Makefile
	$(CC) $(CFLAGS) -o $@ $<

check-irq: test_hws_irq
	./test_hws_irq

test_hws_irq_sanitize: test_hws_irq.c hws_irq_test_shim.h hws_irq_test_api.h .hws_irq_under_test.h Makefile
	$(CC) $(CFLAGS) -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -o $@ $<

check-irq-sanitize: test_hws_irq_sanitize
	./test_hws_irq_sanitize

check-irq-mutations:
	python3 -m unittest test_hws_irq_mutations -v

# Optional physical presentation source (requires libdrm development files).
hws_frame_id_kms: hws_frame_id_kms.c hws_frame_pattern.h Makefile
	$(CC) $(CFLAGS) $(DRM_CFLAGS) -DHWS_SOURCE_SHA256='"$(shell sha256sum hws_frame_id_kms.c | cut -c1-64)"' -o $@ $< $(DRM_LIBS)

.DEFAULT_GOAL := all

hws_drm_timing_probe: hws_drm_timing_probe.c Makefile
	$(CC) $(CFLAGS) $(DRM_CFLAGS) -o $@ $< $(DRM_LIBS) -lm

test_drm_timing_probe: test_drm_timing_probe.c hws_drm_timing_probe.c Makefile
	$(CC) $(CFLAGS) $(DRM_CFLAGS) -o $@ $< $(DRM_LIBS) -lm

test_frame_id_kms: test_frame_id_kms.c hws_frame_id_kms.c hws_frame_id_capture.c hws_frame_pattern.h Makefile
	$(CC) $(CFLAGS) $(DRM_CFLAGS) -o $@ $< $(DRM_LIBS)

test_frame_id_render: test_frame_id_render.c hws_frame_id_kms.c hws_frame_pattern.h Makefile
	$(CC) $(CFLAGS) $(DRM_CFLAGS) -o $@ $< $(DRM_LIBS)

test_kms_modes: test_kms_modes.c hws_frame_id_kms.c hws_frame_pattern.h Makefile
	$(CC) $(CFLAGS) $(DRM_CFLAGS) -o $@ $< $(DRM_LIBS)

check: test_kms_modes test_frame_id_render check-irq check-audio check-failure check-config check-transitions all hws_frame_id_kms test_frame_id_kms hws_drm_timing_probe test_drm_timing_probe
	./test_kms_modes
	./test_drm_timing_probe
	./hws_frame_id_capture --self-test
	./test_frame_id_kms
	./test_frame_id_render
	python3 -m unittest discover -s . -p 'test_vdone*.py' -v
	python3 -m unittest discover -s . -p 'test_clock*.py' -v

all: hws_frame_id_capture hws_vdone_sampler

hws_frame_id_capture: hws_frame_id_capture.c hws_frame_pattern.h Makefile
	$(CC) $(CFLAGS) -DHWS_CAPTURE_SHA256='"$(shell sha256sum hws_frame_id_capture.c | cut -c1-64)"' -o $@ $<

hws_vdone_sampler: hws_vdone_sampler.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f test_kms_modes
	rm -f test_frame_id_render
	rm -f hws_frame_id_capture hws_vdone_sampler hws_frame_id_kms test_frame_id_kms hws_drm_timing_probe test_drm_timing_probe
	rm -f test_hws_irq test_hws_irq_sanitize .hws_irq_under_test.h
