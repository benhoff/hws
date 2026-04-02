/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_CAPTURE_H
#define HWS_CAPTURE_H

#include <linux/types.h>

struct hws_video;
struct hws_vfh_ctx;
struct hwsvideo_buffer;

void hws_capture_engine_init(struct hws_video *vid);
void hws_capture_engine_cleanup(struct hws_video *vid);
void hws_capture_engine_stop_locked(struct hws_video *vid);

int hws_capture_recompute_stream_mode_locked(struct hws_video *vid,
					     struct hws_vfh_ctx *ctx,
					     bool stopping);
void hws_capture_kick_direct_locked(struct hws_video *vid);
bool hws_capture_has_pending(const struct hws_video *vid);
int hws_capture_apply_pending_locked(struct hws_video *vid);

void hws_capture_prepare_reconfigure_locked(struct hws_video *vid);
int hws_capture_restart_after_reconfigure_locked(struct hws_video *vid);

void hws_prime_next_locked(struct hws_video *vid);
struct hwsvideo_buffer *hws_take_direct_buffer_locked(struct hws_video *vid);

#endif /* HWS_CAPTURE_H */
