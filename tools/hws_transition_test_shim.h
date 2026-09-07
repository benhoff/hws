/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <linux/videodev2.h>
typedef uint32_t u32;
#define U32_MAX UINT32_MAX
#define BIT(n) (1U << (n))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define __iomem
#define HWS_REG_SYS_STATUS 0
#define HWS_REG_INT_STATUS 4
#define HWS_SYS_DMA_BUSY_BIT BIT(3)
#define MAX_DMA_AUDIO_PK_SIZE 4096
#define HWS_AUDIO_XRUN_DMA_GUARD 1
#define might_sleep() ((void)0)
#define smp_wmb() ((void)0)
#define dev_dbg(...) ((void)0)
#define dev_crit(...) ((void)0)
#define dev_info(...) ((void)0)
#define dev_warn_ratelimited(...) ((void)0)
#define lockdep_assert_held(p) assert(*(p))
#define spin_lock_irqsave(p,f) do { (f)=0; assert(!*(p)); *(p)=1; } while(0)
#define spin_unlock_irqrestore(p,f) do { (void)(f); assert(*(p)); *(p)=0; } while(0)
static void mutex_lock(int *p) { assert(!*p); *p=1; }
static void mutex_unlock(int *p) { assert(*p); *p=0; }
static bool mutex_trylock(int *p) { if (*p) return false; *p=1; return true; }
struct hws_pcie_dev;
struct hws_video {
    struct hws_pcie_dev *parent; unsigned channel_index;
    bool dma_needs_idle, ring_corrupt, cap_active, stop_requested;
    unsigned guard_errors; size_t ring_extent;
    unsigned evidence_queue_failures;
    int state_lock, irq_lock, buffer_queue;
    bool source_state_initialized, source_change_pending;
    int detected_dv_status; u32 detected_fps;
    struct v4l2_dv_timings detected_dv_timings, cur_dv_timings;
    void *video_device;
};
struct hws_audio {
    struct hws_pcie_dev *parent; unsigned channel_index;
    bool dma_armed, scratch_corrupt, cap_active, stream_running;
    int scratch_state_lock, pending_lock, xrun_reason;
    size_t observed_dma_extent;
};
struct hws_pcie_dev {
    unsigned char *bar0_base; int dma_lock, irq;
    bool dma_quiesced, dma_failed, pci_lost;
    unsigned max_channels;
    struct hws_video video[4]; struct hws_audio audio[4];
};
static unsigned char regs[8];
static unsigned reads, idle_at, fault_at, elapsed_us, poll_calls;
static unsigned forced, isolated, guards, notices, disables, drains, errors, syncs;
static bool good_guards, saw_idle;
static unsigned peer_ticks[4];
static struct hws_pcie_dev device;
static u32 readl(void *addr)
{
    if (addr == regs+HWS_REG_INT_STATUS) return 0;
    assert(addr == regs+HWS_REG_SYS_STATUS);
    ++reads;
    for (unsigned ch=0;ch<4;ch++)
        if (device.video[ch].cap_active || device.audio[ch].cap_active) peer_ticks[ch]++;
    if (reads == fault_at) return U32_MAX;
    if (idle_at && reads >= idle_at) { saw_idle=true; return 0; }
    return HWS_SYS_DMA_BUSY_BIT;
}
/* Poll scheduling/time are modeled. The production loop's predicate, delay
 * and timeout arguments are used; real kernel sleep/mutex scheduling is not.
 */
#define readl_poll_timeout(addr,val,cond,delay,timeout) ({ \
    int result=-ETIMEDOUT; poll_calls++; elapsed_us=0; \
    assert((delay)==10 && (timeout)==100000); \
    for (;;) { (val)=readl(addr); if (cond) { result=0; break; } \
        if (elapsed_us >= (timeout)) { break; } elapsed_us+=(delay); } result; })
static void hws_device_lost(struct hws_pcie_dev *d,const char *reason)
{ assert(reason); d->pci_lost=true; }
static int hws_isolate_pci_dma(struct hws_pcie_dev *d,const char *o,int ch)
{ isolated++; return 0; }
static int hws_force_dma_quiesce_locked(struct hws_pcie_dev *d,const char *o,int ch)
{ forced++; return 0; }
static bool hws_video_ring_guards_ok(struct hws_pcie_dev *d,unsigned ch,size_t n)
{ assert(saw_idle || d->dma_quiesced); guards++; return good_guards; }
static int hws_audio_scratch_verify(struct hws_pcie_dev *d,unsigned ch,size_t *observed)
{ assert(saw_idle || d->dma_quiesced); guards++; *observed=8192; return good_guards?0:-EUCLEAN; }
static void hws_audio_count_failure_locked(struct hws_audio *a,int reason)
{ assert(a->pending_lock && reason==HWS_AUDIO_XRUN_DMA_GUARD); }
static void hws_enable_video_capture(struct hws_pcie_dev *d,unsigned ch,bool on)
{ assert(!on && ch==0); disables++; }
static void synchronize_irq(int irq) { assert(irq>=0); syncs++; }
static void hws_video_drain_channel_work(struct hws_video *v)
{ assert(v->state_lock && v->stop_requested && !v->cap_active); drains++; }
static void vb2_queue_error(int *q) { *q=1; errors++; }
static bool video_is_registered(void *v) { return v != NULL; }
static void v4l2_event_queue(void *v,struct v4l2_event *e)
{ assert(v && e->type==V4L2_EVENT_SOURCE_CHANGE &&
    e->u.src_change.changes==V4L2_EVENT_SRC_CH_RESOLUTION); notices++; }
