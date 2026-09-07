#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <xf86drm.h>
#include <xf86drmMode.h>

/* This launcher's verified TITAN HDMI route: connector 827, CRTC 200.
 * Keep the existing console framebuffer alive and select an advertised mode.
 * The KMS source restores this mode, and returning to VT1 restores KDE.
 */
static int set_1080p60(int fd)
{
    uint32_t connector_id = 827;
    const uint32_t crtc_id = 200;
    drmModeConnector *connector = drmModeGetConnector(fd, connector_id);
    drmModeCrtc *crtc = drmModeGetCrtc(fd, crtc_id);
    drmModeEncoder *encoder = connector ? drmModeGetEncoder(fd, connector->encoder_id) : NULL;
    drmModeRes *resources = drmModeGetResources(fd);
    drmModeModeInfo *mode = NULL;
    int attached = 0, result = -1;
    if (!connector || !crtc || !encoder || !resources || !crtc->mode_valid ||
        !crtc->buffer_id || connector->connection != DRM_MODE_CONNECTED ||
        encoder->crtc_id != crtc_id)
        goto out;
    for (int i = 0; i < resources->count_connectors; ++i) {
        drmModeConnector *other = drmModeGetConnector(fd, resources->connectors[i]);
        drmModeEncoder *e = other ? drmModeGetEncoder(fd, other->encoder_id) : NULL;
        if (e && e->crtc_id == crtc_id)
            ++attached;
        if (e) drmModeFreeEncoder(e);
        if (other) drmModeFreeConnector(other);
    }
    if (attached != 1)
        goto out;
    for (int i = 0; i < connector->count_modes; ++i) {
        drmModeModeInfo *m = &connector->modes[i];
        if (m->hdisplay == 1920 && m->vdisplay == 1080 &&
            m->clock == 148500 && m->htotal == 2200 && m->vtotal == 1125 &&
            !(m->flags & (DRM_MODE_FLAG_INTERLACE | DRM_MODE_FLAG_DBLSCAN))) {
            mode = m;
            break;
        }
    }
    if (!mode)
        goto out;
    fprintf(stderr, "HDMI mode before setup: %ux%u clock=%u kHz\n",
            crtc->mode.hdisplay, crtc->mode.vdisplay, crtc->mode.clock);
    result = drmModeSetCrtc(fd, crtc_id, crtc->buffer_id, 0, 0,
                          &connector_id, 1, mode);
    if (result)
        fprintf(stderr, "Set HDMI 1920x1080p60: %s\n", strerror(errno));
    else
        fprintf(stderr, "HDMI mode set to 1920x1080p60, 148500 kHz\n");
out:
    if (result)
        fprintf(stderr, "Cannot establish the verified, uncloned HDMI 1080p60 mode\n");
    if (resources) drmModeFreeResources(resources);
    if (encoder) drmModeFreeEncoder(encoder);
    if (crtc) drmModeFreeCrtc(crtc);
    if (connector) drmModeFreeConnector(connector);
    return result;
}

int main(int argc, char **argv)
{
    uint64_t cap = 0;
    const struct timespec delay = { .tv_nsec = 100000000 };
    int fd, result, saved_errno = 0;
    if (argc != 2 && !(argc == 3 && !strcmp(argv[2], "--1080p60")))
        return 2;
    fd = open(argv[1], O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", argv[1], strerror(errno));
        return 1;
    }
    errno = 0;
    result = drmGetCap(fd, DRM_CAP_TIMESTAMP_MONOTONIC, &cap);
    fprintf(stderr, "timestamp capability: return=%d value=%" PRIu64 " errno=%d (%s)\n",
            result, cap, errno, strerror(errno));
    if (result || cap != 1) {
        close(fd);
        return 1;
    }
    for (int attempt = 0; attempt < 50; ++attempt) {
        errno = 0;
        result = drmSetMaster(fd);
        saved_errno = errno;
        if (!result)
            break;
        if (attempt == 0)
            fprintf(stderr, "first drmSetMaster: return=%d errno=%d (%s)\n",
                    result, saved_errno, strerror(saved_errno));
        nanosleep(&delay, NULL);
    }
    fprintf(stderr, "drmSetMaster: return=%d errno=%d (%s); drmIsMaster=%d\n",
            result, saved_errno, strerror(saved_errno), drmIsMaster(fd));
    if (!result) {
        if (argc == 3)
            result = set_1080p60(fd);
        drmDropMaster(fd);
    }
    close(fd);
    return result ? 1 : 0;
}
