/* SPDX-License-Identifier: GPL-2.0-only */
/* Framework boundaries only; no completion/recovery decisions live here. */
struct hws_audio { bool cap_active, stream_running, stop_requested; };
struct pci_dev { int dev; };
#define pci_name(p) "0000:00:00.0"
struct hws_pcie_dev {
    struct pci_dev *pdev;
    struct hws_video video[MAX_VID_CHANNELS];
    struct hws_audio audio[MAX_VID_CHANNELS];
    u8 *bar0_base;
    struct workqueue_struct *video_wq;
    unsigned cur_max_video_ch, cur_max_audio_ch;
    bool suspended, pci_lost, dma_failed;
};
enum { HWS_DIAG_QBUF=1, HWS_DIAG_TAKE, HWS_DIAG_EMPTY, HWS_DIAG_RECYCLE,
       HWS_DIAG_COMPLETE, HWS_DIAG_STOP, HWS_DIAG_IRQ, HWS_DIAG_WORK, HWS_DIAG_START };
#define hws_diag_locked(...) ((void)0)
static void *hws_video_ring_cpu(struct hws_pcie_dev *, unsigned);
static bool hws_video_ring_guards_ok(struct hws_pcie_dev *, unsigned, size_t);
static void hws_enable_video_capture(struct hws_pcie_dev *, unsigned, bool);
static void hws_video_fail_queue(struct hws_video *, const char *);
static bool late_trace_enabled;
static bool trace_hws_vdone_late_toggle_enabled(void) { return late_trace_enabled; }
static void trace_hws_vdone_late_toggle(const char *, u32, u64, u64,
                                       const struct hws_late_toggle_observation *);
static void hws_device_lost(struct hws_pcie_dev *d, const char *reason)
{
    assert(reason); d->pci_lost=d->dma_failed=true;
    for(unsigned ch=0;ch<d->cur_max_video_ch;ch++) {
        d->video[ch].cap_active=false; d->video[ch].stop_requested=true;
    }
}
static bool hws_audio_record_interrupt(struct hws_pcie_dev *d, unsigned ch,
                                      u8 t, u64 ns, enum hws_audio_xrun_reason a)
{ (void)d; (void)ch; (void)t; (void)ns; (void)a; assert(!"audio is outside this test's scope"); return false; }
static void hws_audio_queue_work(struct hws_pcie_dev *d, unsigned ch)
{ (void)d; (void)ch; assert(!"audio is outside this test's scope"); }
