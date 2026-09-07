/* SPDX-License-Identifier: GPL-2.0-only */
/* Compile the actual production IRQ implementation; shim only its environment. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wpedantic"
#ifndef HWS_IRQ_UNDER_TEST
#define HWS_IRQ_UNDER_TEST ".hws_irq_under_test.h"
#endif
#include HWS_IRQ_UNDER_TEST
#pragma GCC diagnostic pop
#undef memcpy
#include <linux/v4l2-dv-timings.h>

#ifdef NDEBUG
#error "Deterministic driver tests require assertions enabled"
#endif
#define MAX_FRAME_BYTES (1920U * 1080U * 2U)
static unsigned mode_width=640, mode_height=480, mode_fps=60;
static u64 mode_period_ns=8333333;
static struct v4l2_dv_timings mode_timings;
#define FRAME_BYTES (mode_width * mode_height * 2U)
#define HALF_BYTES hws_video_native_split(FRAME_BYTES)
#define PERIOD_NS mode_period_ns
#define BUFFER_COUNT 4
static struct hws_pcie_dev device;
static struct workqueue_struct workqueue;
static u8 registers[0x5000];
static u32 ring[MAX_FRAME_BYTES / 4], destinations[BUFFER_COUNT][MAX_FRAME_BYTES / 4];
static struct hwsvideo_buffer buffers[BUFFER_COUNT];
static u64 now;
static unsigned delivered, last_id, source_id, copies, failures;
static bool guards_ok;
static bool source_hold;
static unsigned mmio_count, inject_mmio;
static unsigned fault_read_at, read_count;
static unsigned late_records;
static unsigned ack_writes;
static struct hws_late_toggle_observation late_record;
static u64 read_cost_ns;
static void (*mmio_hook)(void), (*copy_hook)(void);
static const char *test_case;
static unsigned schedule_id, injection_point, injection_half;
static _Noreturn void test_assert_fail(const char *expression, const char *file, int line)
{
    fprintf(stderr, "%s:%d: Assertion `%s` failed; case=%s schedule=%u MMIO=%u half=%u\n",
            file,line,expression,test_case,schedule_id,injection_point,injection_half);
    abort();
}
static struct hws_video *video(void) { return &device.video[0]; }
static void trace_hws_vdone_late_toggle(const char *dev, u32 ch, u64 epoch, u64 gen,
                                       const struct hws_late_toggle_observation *p)
{
    (void)dev; assert(ch==0 && epoch==video()->evidence_stream_epoch && gen>0);
    late_records++; late_record=*p;
}

static u32 reg_get(unsigned offset) { u32 value; memcpy(&value, registers+offset, 4); return value; }
static void reg_set(unsigned offset, u32 value) { memcpy(registers+offset, &value, 4); }
static void mmio_boundary(void)
{
    mmio_count++;
    if (mmio_hook && mmio_count == inject_mmio) {
        void (*hook)(void)=mmio_hook;
        mmio_hook=NULL;
        hook();
    }
}
static u32 readl(const void *address)
{
    ptrdiff_t offset=(const u8 *)address-registers;
    assert(offset >= 0 && offset+4 <= (ptrdiff_t)sizeof(registers));
    u32 value=reg_get((unsigned)offset);
    if (++read_count == fault_read_at) value=U32_MAX;
    now+=read_cost_ns;
    mmio_boundary();
    return value;
}
static void writel(u32 value, void *address)
{
    ptrdiff_t offset=(u8 *)address-registers;
    assert(offset == HWS_REG_INT_STATUS);
    ack_writes++;
    /* Scripted sticky status: writing one clears that pending bit. */
    reg_set((unsigned)offset, reg_get((unsigned)offset) & ~value);
    mmio_boundary();
}
static u64 ktime_get_mono_fast_ns(void) { return now; }
static void *hws_video_ring_cpu(struct hws_pcie_dev *d, unsigned ch)
{ assert(d == &device && ch == 0); return ring; }
static bool hws_video_ring_guards_ok(struct hws_pcie_dev *d, unsigned ch, size_t extent)
{ assert(d == &device && !ch && extent == FRAME_BYTES); return guards_ok; }
static void hws_enable_video_capture(struct hws_pcie_dev *d, unsigned ch, bool enable)
{ assert(d == &device && !ch); d->video[ch].cap_active=enable; }
static void hws_video_fail_queue(struct hws_video *v, const char *reason)
{ assert(v == video() && reason); failures++; v->stop_requested=true; v->cap_active=false; }

static void vb2_buffer_done(struct vb2_buffer *b, int state)
{
    assert(state == VB2_BUF_STATE_DONE && b->owned);
    assert(b->payload == FRAME_BYTES && b->data == destinations[b->index]);
    u32 *data=b->data, id=data[0];
    /* Oracle uses source content, never the driver's selected toggle/half. */
    assert((source_hold ? id >= last_id : id > last_id) && id <= source_id);
    for (unsigned i=0; i<FRAME_BYTES/4; i++) assert(data[i] == id);
    assert(buffers[b->index].vb.sequence + 1 == video()->sequence_number);
    last_id=id;
    delivered++;
    b->owned=false;
}
static void *test_memcpy(void *dst, const void *src, size_t length)
{
    assert(src == (void *)ring || src == (void *)((u8 *)ring+HALF_BYTES));
    assert(length == (src == (void *)ring ? HALF_BYTES : FRAME_BYTES-HALF_BYTES) && video()->active);
    struct vb2_buffer *b=&video()->active->vb.vb2_buf;
    assert(b->owned && !video()->stop_requested);
    assert(dst == b->data || dst == (u8 *)b->data+HALF_BYTES);
    /* Allow a deterministic IRQ in the middle of the actual driver's copy. */
    memcpy(dst, src, length/2);
    if (copy_hook) { void (*hook)(void)=copy_hook; copy_hook=NULL; hook(); }
    memcpy((u8 *)dst+length/2, (const u8 *)src+length/2, length-length/2);
    copies++;
    return dst;
}
static void enqueue(unsigned index)
{
    struct vb2_buffer *b=&buffers[index].vb.vb2_buf;
    assert(!b->owned && list_empty(&buffers[index].list));
    memset(destinations[index], 0xa5, FRAME_BYTES);
    b->owned=true;
    list_add(&buffers[index].list, &video()->capture_queue);
    video()->queued_count++;
}
static void run_work(void)
{
    struct work_struct *w=&video()->vdone_work;
    if (w->pending) { w->pending=false; w->fn(w); }
}
static void check_ownership(void)
{
    unsigned queued=0;
    for (struct list_head *p=video()->capture_queue.next; p!=&video()->capture_queue; p=p->next) {
        assert(++queued <= BUFFER_COUNT);
        struct hwsvideo_buffer *b=container_of(p,struct hwsvideo_buffer,list);
        assert(b->vb.vb2_buf.owned && b != video()->active);
    }
    assert(queued == video()->queued_count);
    for (unsigned i=0;i<BUFFER_COUNT;i++) {
        bool attached=!list_empty(&buffers[i].list) || video()->active == &buffers[i];
        assert(buffers[i].vb.vb2_buf.owned == attached);
    }
}
static void replenish(void)
{ for (unsigned i=0;i<BUFFER_COUNT;i++) if (!buffers[i].vb.vb2_buf.owned) enqueue(i); }
static void hardware_boundary(void)
{
    u32 toggle=reg_get(HWS_REG_VBUF_TOGGLE(0)) ^ 1;
    if (toggle && !source_hold) source_id++;
    unsigned offset=toggle ? 0 : HALF_BYTES/4;
    unsigned length=toggle ? HALF_BYTES : FRAME_BYTES-HALF_BYTES;
    for (unsigned i=0;i<length/4;i++) ring[offset+i]=source_id;
    reg_set(HWS_REG_VBUF_TOGGLE(0),toggle);
    reg_set(HWS_REG_INT_STATUS,reg_get(HWS_REG_INT_STATUS) | 1);
}
static void interrupt_only(void)
{ assert(hws_irq_handler(0,&device) == IRQ_HANDLED); }
static void step(bool worker)
{
    now+=PERIOD_NS;
    hardware_boundary();
    interrupt_only();
    if (worker) run_work();
    check_ownership();
}
static void duplicate(void)
{ now+=PERIOD_NS; reg_set(HWS_REG_INT_STATUS,1); interrupt_only(); run_work(); check_ownership(); }
static void initialize(void)
{
    memset(&device,0,sizeof(device)); memset(registers,0,sizeof(registers));
    memset(buffers,0,sizeof(buffers)); memset(ring,0,FRAME_BYTES);
    delivered=last_id=source_id=copies=failures=mmio_count=inject_mmio=0;
    mmio_hook=copy_hook=NULL; now=NSEC_PER_SEC; guards_ok=true; source_hold=false;
    fault_read_at=read_count=0;
    read_cost_ns=0;
    source_transition_checks=false;
    late_toggle_probe=late_trace_enabled=false; late_records=0;
    ack_writes=0;
    memset(&late_record,0,sizeof(late_record));
    reg_set(HWS_REG_ACTIVE_STATUS, 1);
    reg_set(HWS_REG_IN_RES(0), mode_width | (mode_height << 16));
    reg_set(HWS_REG_FRAME_RATE(0), mode_fps);
    device.bar0_base=registers; device.video_wq=&workqueue; device.cur_max_video_ch=1;
    struct hws_video *v=video();
    v->parent=&device; v->cap_active=true; v->current_fps=mode_fps;
    v->pix=(struct hws_pix_state){.width=mode_width,.height=mode_height,.fourcc=V4L2_PIX_FMT_YUYV,
        .bytesperline=mode_width*2,.sizeimage=FRAME_BYTES,.half_size=HALF_BYTES,.field=V4L2_FIELD_NONE};
    v->cur_dv_timings=(struct v4l2_dv_timings){.type=V4L2_DV_BT_656_1120,
        .bt={.width=640,.height=480,.pixelclock=25200000,.hfrontporch=16,
             .hsync=96,.hbackporch=48,.vfrontporch=10,.vsync=2,.vbackporch=33}};
    if (mode_timings.bt.pixelclock) v->cur_dv_timings=mode_timings;
    v->ring_extent=FRAME_BYTES; v->ring_split=HALF_BYTES;
    INIT_LIST_HEAD(&v->capture_queue); hws_irq_init_video_work(v);
    for (unsigned i=0;i<BUFFER_COUNT;i++) {
        buffers[i].vb.vb2_buf=(struct vb2_buffer){.index=i,.data=destinations[i],.size=FRAME_BYTES};
        INIT_LIST_HEAD(&buffers[i].list); enqueue(i);
    }
    assert(hws_yuyv_layout_valid(&v->pix));
}
static void synchronize_stream(void)
{ for (unsigned i=0;i<HWS_VIDEO_SYNC_EVENTS;i++) step(true); assert(!delivered); }
static void prove_forward_progress(void)
{
    unsigned before=delivered;
    for (unsigned i=0;i<12;i++) { replenish(); step(true); }
    assert(delivered > before && !failures && !video()->evidence_vdone_fatal);
}
static void test_normal_and_duplicate(void)
{
    initialize(); synchronize_stream();
    step(true); assert(video()->active && video()->frame_half0_valid);
    unsigned before=copies;
    duplicate(); assert(copies == before && !delivered && !video()->active);
    assert(video()->duplicate_recoveries == 1 && video()->evidence_partial_recycles == 1);
    prove_forward_progress();
}
static void test_starvation(void)
{
    initialize(); synchronize_stream();
    for (unsigned i=0;i<16;i++) step(true);
    assert(delivered == BUFFER_COUNT && video()->evidence_frames_no_buffer == 4);
    prove_forward_progress();
}
static void interrupt_during_copy(void) { now+=PERIOD_NS; hardware_boundary(); interrupt_only(); }
static void stop_during_copy(void) { video()->stop_requested=true; }
static void test_copy_and_pending_overlap(void)
{
    initialize(); synchronize_stream(); step(false); step(false); run_work();
    assert(video()->overlap_recoveries && !delivered); check_ownership(); prove_forward_progress();
    initialize(); synchronize_stream(); copy_hook=interrupt_during_copy; step(true);
    assert(video()->overlap_recoveries && !delivered); check_ownership(); prove_forward_progress();
    initialize(); synchronize_stream(); step(true); copy_hook=interrupt_during_copy; step(true);
    assert(video()->overlap_recoveries && !delivered); check_ownership(); prove_forward_progress();
    initialize(); synchronize_stream(); copy_hook=stop_during_copy; step(true);
    assert(!delivered); unsigned before=copies; run_work(); assert(copies == before);
    /* This tests stop_requested only, NOT actual STREAMOFF/DMA quiescence. */
}
static void test_deadline_and_guard(void)
{
    initialize(); synchronize_stream(); step(false); now+=HWS_VIDEO_COPY_DEADLINE_NS; run_work();
    assert(video()->deadline_misses == 1 && !delivered); prove_forward_progress();
    initialize(); synchronize_stream(); guards_ok=false; step(true);
    assert(failures == 1 && video()->ring_corrupt && !delivered);
}
static void test_clock_boundaries_and_stop(void)
{
    initialize();
    assert(hws_video_copy_deadline_ns(video()) == HWS_VIDEO_COPY_DEADLINE_NS);
    video()->cur_dv_timings.bt.pixelclock=800ULL*525*240;
    assert(hws_video_copy_deadline_ns(video()) == NSEC_PER_SEC/480-500000);
    video()->current_fps=0; /* nominal label cannot override configured timing */
    assert(hws_video_copy_deadline_ns(video()) == NSEC_PER_SEC/480-500000);
    video()->cur_dv_timings.bt.pixelclock=0; assert(!hws_video_copy_deadline_ns(video()));
    video()->cur_dv_timings.bt.pixelclock=800ULL*525*241;
    assert(!hws_video_copy_deadline_ns(video()));
    assert(!hws_video_deadline_expired(100,1000,1099));
    assert(hws_video_deadline_expired(100,1000,1100));
    assert(hws_video_deadline_expired(100,1000,999));
    assert(hws_video_deadline_expired(0,1000,1001));
    initialize(); synchronize_stream(); step(false);
    video()->stop_requested=true; run_work();
    assert(!copies && !delivered);
    step(true); assert(!copies && video()->evidence_vdone_ignored == 1);
    initialize(); synchronize_stream();
    now=video()->last_vdone_timestamp_ns; hardware_boundary(); interrupt_only(); run_work();
    assert(!video()->evidence_vdone_fatal); /* equal timestamps are allowed */
    now=video()->last_vdone_timestamp_ns-1; hardware_boundary(); interrupt_only(); run_work();
    assert(video()->evidence_vdone_fatal == 1 && video()->stop_requested);
}
static void test_duplicate_bursts_and_after_delivery(void)
{
    initialize();
    for (unsigned i=0;i<300;i++) duplicate();
    assert(!delivered && !video()->evidence_vdone_fatal && video()->sync_restart_streak == U8_MAX);
    prove_forward_progress();
    initialize(); synchronize_stream(); step(true); step(true);
    assert(delivered == 1 && !video()->active);
    unsigned before=video()->evidence_partial_recycles;
    duplicate();
    assert(delivered == 1 && video()->evidence_partial_recycles == before);
    prove_forward_progress();
}
static void test_mmio_interleavings(void)
{
    /* Arrive after each status/toggle read or W1C write in the real handler. */
    for (unsigned half=0;half<2;half++) for (unsigned point=1;point<=6;point++) {
        injection_point=point; injection_half=half;
        initialize(); synchronize_stream(); if (half) step(true);
        mmio_count=0; inject_mmio=point; mmio_hook=hardware_boundary;
        step(false); assert(!mmio_hook); run_work();
        if (reg_get(HWS_REG_INT_STATUS) && video()->cap_active) { interrupt_only(); run_work(); }
        check_ownership();
        if (video()->cap_active) prove_forward_progress();
        else assert(video()->stop_requested && video()->evidence_vdone_fatal);
    }
}
static void test_exhaustive_short_schedules(void)
{
    /* 4^6 schedules: normal completion, same toggle, deferred worker, worker drain. */
    for (unsigned schedule=0;schedule<4096;schedule++) {
        schedule_id=schedule;
        initialize(); synchronize_stream();
        unsigned choices=schedule;
        for (unsigned i=0;i<6;i++,choices>>=2) {
            replenish();
            switch (choices & 3) {
            case 0: step(true); break;
            case 1: duplicate(); break;
            case 2: step(false); break;
            case 3: run_work(); check_ownership(); break;
            }
        }
        run_work(); check_ownership(); prove_forward_progress();
    }
}
static void test_unobserved_boundaries(void)
{
    for (unsigned hidden=0;hidden<=6;hidden++) for (unsigned half=0;half<2;half++) {
        initialize(); synchronize_stream(); step(true);
        if (half) step(true);
        for (unsigned i=0;i<hidden;i++) { now+=PERIOD_NS; hardware_boundary(); }
        unsigned before=delivered;
        step(true);
        if (hidden && !(hidden%2) && !half) {
            assert(delivered == before && video()->continuity_gaps == 1);
            assert(video()->evidence_continuity_reports == 1);
            assert(video()->evidence_partial_recycles == 1 && !video()->active);
            assert(!video()->frame_timestamp_ns && !video()->frame_half_period_ns);
            assert(!video()->overlap_recoveries && !video()->duplicate_recoveries);
        }
        check_ownership(); prove_forward_progress();
    }
}
static void test_all_mode_gaps(void)
{
    static const struct { struct v4l2_dv_timings timing; unsigned fps; } modes[]={
        {V4L2_DV_BT_CEA_1920X1080P60,60}, {V4L2_DV_BT_CEA_1920X1080P30,30},
        {V4L2_DV_BT_CEA_1280X720P60,60}, {V4L2_DV_BT_CEA_720X480P59_94,60},
        {V4L2_DV_BT_CEA_720X576P50,50}, {V4L2_DV_BT_DMT_800X600P60,60},
        {V4L2_DV_BT_DMT_640X480P60,60}, {V4L2_DV_BT_DMT_1024X768P60,60},
        {V4L2_DV_BT_DMT_1280X768P60,60}, {V4L2_DV_BT_DMT_1280X800P60,60},
        {V4L2_DV_BT_DMT_1280X1024P60,60}, {V4L2_DV_BT_DMT_1360X768P60,60},
        {V4L2_DV_BT_DMT_1440X900P60,60}, {V4L2_DV_BT_DMT_1680X1050P60,60},
    };
    for (unsigned m=0;m<sizeof(modes)/sizeof(modes[0]);m++) {
        mode_timings=modes[m].timing; mode_fps=modes[m].fps;
        mode_width=mode_timings.bt.width; mode_height=mode_timings.bt.height;
        struct v4l2_bt_timings *bt=&mode_timings.bt;
        u64 ht=bt->width+bt->hfrontporch+bt->hsync+bt->hbackporch;
        u64 vt=bt->height+bt->vfrontporch+bt->vsync+bt->vbackporch;
        mode_period_ns=ht*vt*NSEC_PER_SEC/bt->pixelclock/2;
        test_unobserved_boundaries();
        /* Exact continuity threshold, at every rational mode period. */
        for (int delta=-1;delta<=1;delta++) {
            initialize(); synchronize_stream(); step(true);
            now+=PERIOD_NS+PERIOD_NS/2+delta;
            hardware_boundary(); interrupt_only(); run_work();
            assert(delivered == (delta<=0 ? 1U : 0U));
            assert(video()->continuity_gaps == (delta>0 ? 1U : 0U));
            prove_forward_progress();
        }
    }
    memset(&mode_timings,0,sizeof(mode_timings));
    mode_width=640; mode_height=480; mode_fps=60; mode_period_ns=8333333;
}
static void invalidate_epoch_during_copy(void) { video()->evidence_stream_epoch++; }
static void hidden_boundaries_during_copy(void)
{ for (unsigned i=0;i<2;i++) { now+=PERIOD_NS; hardware_boundary(); } }
static void test_gap_interleavings(void)
{
    for (unsigned half=0;half<2;half++) {
        initialize(); synchronize_stream(); if (half) step(true);
        copy_hook=hidden_boundaries_during_copy; step(true);
        assert(!delivered && video()->deadline_misses);
        assert(!video()->frame_timestamp_ns && !video()->frame_epoch);
        if (reg_get(HWS_REG_INT_STATUS)) { interrupt_only(); run_work(); }
        check_ownership(); prove_forward_progress();
    }
    /* DMA-only advances during startup, before either half can be retained. */
    initialize(); step(true); hidden_boundaries_during_copy(); step(true);
    check_ownership(); prove_forward_progress();
    /* 5^4 schedules also include two unobserved hardware boundaries. */
    for (unsigned schedule=0;schedule<625;schedule++) {
        schedule_id=schedule; initialize(); synchronize_stream();
        unsigned choices=schedule;
        for (unsigned i=0;i<4;i++,choices/=5) {
            replenish();
            switch (choices%5) {
            case 0: step(true); break;
            case 1: duplicate(); break;
            case 2: step(false); break;
            case 3: run_work(); check_ownership(); break;
            case 4: hidden_boundaries_during_copy(); step(true); break;
            }
        }
        run_work(); check_ownership(); prove_forward_progress();
    }
}
static void test_continuity_state(void)
{
    initialize(); synchronize_stream(); step(true);
    struct hws_vdone_event event={.timestamp_ns=now+PERIOD_NS,
        .deadline_ns=HWS_VIDEO_COPY_DEADLINE_NS};
    assert(hws_video_frame_contiguous(video(),&event,event.timestamp_ns));
    u64 end=now+PERIOD_NS+PERIOD_NS/2+event.deadline_ns;
    assert(hws_video_frame_contiguous(video(),&event,end));
    assert(!hws_video_frame_contiguous(video(),&event,end+1));
    assert(!hws_video_frame_contiguous(video(),&event,event.timestamp_ns-1));
    event.timestamp_ns=now;
    assert(!hws_video_frame_contiguous(video(),&event,now));
    /* Final publication must recheck the epoch even after a successful copy. */
    copy_hook=invalidate_epoch_during_copy; step(true);
    assert(!delivered && video()->continuity_gaps == 1);
    prove_forward_progress();
    initialize(); synchronize_stream(); step(true);
    video()->cur_dv_timings.bt.pixelclock=0; step(true);
    /* Invalid timing now rejects the IRQ deadline before a copy can begin. */
    assert(!delivered && (video()->continuity_gaps || video()->deadline_misses || failures));
    initialize();
    video()->cur_dv_timings.bt.hfrontporch=U32_MAX;
    assert(!hws_video_continuity_period_ns(video()));
    initialize(); synchronize_stream(); step(true); step(true);
    source_hold=true;
    for (unsigned i=0;i<6;i++) { replenish(); step(true); }
    assert(delivered == 4 && !video()->continuity_gaps);
    source_hold=false; prove_forward_progress();
    initialize(); synchronize_stream(); step(true); duplicate();
    assert(!video()->frame_timestamp_ns && !video()->frame_epoch);
    prove_forward_progress();
}
static void test_mmio_failure(void)
{
    /* First status, pre-ack, ack, post-ack pair, and three copy/verify reads. */
    for(unsigned point=1;point<=8;point++) {
        initialize(); synchronize_stream(); step(true);
        read_count=0; fault_read_at=point;
        now+=PERIOD_NS; hardware_boundary();
        (void)hws_irq_handler(0,&device); run_work();
        assert(device.pci_lost && device.dma_failed && !delivered);
        assert(video()->stop_requested); check_ownership();
        unsigned reads=read_count;
        fault_read_at=0; /* valid again must not revive the stream */
        assert(hws_irq_handler(0,&device)==IRQ_NONE);
        assert(read_count==reads && !delivered);
    }
    for(unsigned point=1;point<=5;point++) {
        initialize(); device.cur_max_audio_ch=1;
        device.audio[0].cap_active=device.audio[0].stream_running=true;
        reg_set(HWS_REG_INT_STATUS,HWS_INT_ADONE_BIT(0));
        read_count=0; fault_read_at=point;
        (void)hws_irq_handler(0,&device);
        assert(device.pci_lost && device.dma_failed);
    }
    initialize(); reg_set(HWS_REG_INT_STATUS,0);
    assert(hws_irq_handler(0,&device)==IRQ_NONE && !device.pci_lost);
    reg_set(HWS_REG_INT_STATUS,BIT(31)); /* shared/unowned cause, no W1C */
    assert(hws_irq_handler(0,&device)==IRQ_NONE && !device.pci_lost);
    assert(reg_get(HWS_REG_INT_STATUS)==BIT(31));
}

static unsigned transition_kind;
static void change_source(void)
{
    switch (transition_kind) {
    case 0: reg_set(HWS_REG_IN_RES(0), mode_width==1920 ?
                   1280 | (720U << 16) : 1920 | (1080U << 16)); break;
    case 1: reg_set(HWS_REG_IN_RES(0), 640 | (480U << 16)); break;
    case 2: reg_set(HWS_REG_FRAME_RATE(0), mode_fps == 60 ? 50 : 60); break;
    case 3: reg_set(HWS_REG_ACTIVE_STATUS, 0); break;
    case 4: reg_set(HWS_REG_ACTIVE_STATUS, 1 | BIT(8)); break;
    case 5: reg_set(HWS_REG_IN_RES(0), 3840 | (2160U << 16)); break;
    }
}
static void restore_source(void)
{
    reg_set(HWS_REG_ACTIVE_STATUS, 1);
    reg_set(HWS_REG_IN_RES(0), mode_width | (mode_height << 16));
    reg_set(HWS_REG_FRAME_RATE(0), mode_fps);
}
static void test_source_transitions(void)
{
    /* Before and inside each half, including an unsupported oversize register
     * report. We do NOT write beyond the model ring to simulate real DMA.
     */
    for (unsigned base=0;base<2;base++) {
    mode_width=base?1920:1280; mode_height=base?1080:720;
    mode_fps=60; mode_period_ns=8333333;
    mode_timings=base ? (struct v4l2_dv_timings)V4L2_DV_BT_CEA_1920X1080P60 :
                       (struct v4l2_dv_timings)V4L2_DV_BT_CEA_1280X720P60;
    for (transition_kind=0;transition_kind<6;transition_kind++) {
        for (unsigned phase=0;phase<4;phase++) {
            initialize(); source_transition_checks=true; synchronize_stream();
            if (phase >= 2) step(true);
            if (phase & 1) copy_hook=change_source;
            else change_source();
            unsigned before=copies;
            step(true);
            if (!(phase & 1)) assert(copies == before);
            assert(failures == 1 && !delivered && video()->stop_requested);
            assert(video()->source_change_pending && !video()->frame_half0_valid);
            assert(video()->source_check_failures == 1);
            check_ownership();
            restore_source();
            for (unsigned i=0;i<4;i++) { now+=PERIOD_NS; hardware_boundary();
                (void)hws_irq_handler(0,&device); run_work(); }
            assert(!delivered && !video()->cap_active && video()->source_change_pending);
            check_ownership();
        }
    }
    }
    /* Every snapshot read may fail, or a transition may split the pair. */
    for (unsigned point=1;point<=6;point++) {
        initialize(); source_transition_checks=true;
        read_count=0; fault_read_at=point;
        assert(!hws_video_check_source(video()));
        assert(device.pci_lost && !video()->source_change_pending);
        initialize(); source_transition_checks=true;
        transition_kind=2; mmio_count=0; inject_mmio=point; mmio_hook=change_source;
        bool first=hws_video_check_source(video());
        /* A change AFTER the last sampled value cannot be seen until next check. */
        if (first) assert(!hws_video_check_source(video()));
        assert(video()->source_change_pending);
    }
    initialize(); source_transition_checks=true; synchronize_stream();
    reg_set(HWS_REG_ACTIVE_STATUS, 1 | BIT(1) | BIT(9)); /* peer status irrelevant */
    step(true); step(true); assert(delivered == 1 && !failures);
    /* Deterministic MMIO budget: added reads are worker-only, 12/half. */
    unsigned worker_reads[2], irq_reads[2];
    for (unsigned enabled=0;enabled<2;enabled++) {
        initialize(); source_transition_checks=enabled; synchronize_stream();
        read_count=0; step(false); irq_reads[enabled]=read_count;
        read_count=0; run_work(); worker_reads[enabled]=read_count;
    }
    assert(irq_reads[0] == irq_reads[1]);
    assert(worker_reads[1] == worker_reads[0]+12);
    printf("Source-check MMIO budget: IRQ %u -> %u, worker %u -> %u reads/half (not PCIe latency)\n",
           irq_reads[0],irq_reads[1],worker_reads[0],worker_reads[1]);
    /* Real handler interleaved at every added/old worker MMIO boundary. */
    for (unsigned half=0;half<2;half++) {
        for (unsigned point=1;point<=worker_reads[1];point++) {
            initialize(); source_transition_checks=true; synchronize_stream();
            if (half) step(true);
            step(false); mmio_count=0; inject_mmio=point;
            mmio_hook=interrupt_during_copy; run_work();
            check_ownership(); assert(!delivered);
            prove_forward_progress();
        }
    }
    /* Stop while copying: no successful return and no fabricated source event. */
    initialize(); source_transition_checks=true; synchronize_stream();
    step(true); copy_hook=stop_during_copy; step(true);
    assert(!delivered && !video()->source_change_pending); check_ownership();
    assert(!failures && !video()->source_check_failures);
    initialize(); source_transition_checks=true; read_cost_ns=1000;
    assert(hws_video_check_source(video()));
    assert(video()->source_check_count==1 && video()->source_check_ns==6000 &&
           video()->source_check_max_ns==6000);
    initialize(); source_transition_checks=true; synchronize_stream(); step(true);
    read_cost_ns=1000000; step(true);
    assert(!delivered); check_ownership(); /* added MMIO cannot bypass deadline */
    /* Explicit blind-spot control: unobserved loss/return is NOT detected. */
    initialize(); source_transition_checks=true; synchronize_stream(); step(true);
    transition_kind=3; change_source(); restore_source(); step(true);
    assert(delivered == 1 && !video()->source_change_pending);
    puts("Source transitions PASS: 48 phase cases (720p/1080p), paired reads/faults, stop, peer bits, sticky stop and MMIO cost; hidden ABA remains unobservable.");
}

static void late_toggle_changes(void) { reg_set(HWS_REG_VBUF_TOGGLE(0),0x80); }
static void late_clock_backwards(void) { now-=100000; }
static void assert_late_observation_only(struct hws_video before)
{
    before.late_toggle_windows=video()->late_toggle_windows;
    before.late_toggle_samples=video()->late_toggle_samples;
    before.late_toggle_suppressed=video()->late_toggle_suppressed;
    before.late_toggle_budget_exits=video()->late_toggle_budget_exits;
    before.late_toggle_max_ns=video()->late_toggle_max_ns;
    assert(!memcmp(&before,video(),sizeof(before)));
}
static void probe_late(void)
{ hws_irq_probe_late_toggle(video(),video()->evidence_stream_epoch,1,now,1); }
static void test_late_toggle_diagnostic(void)
{
    for (unsigned option=0;option<2;option++) for (unsigned tracing=0;tracing<2;tracing++) {
        initialize(); late_toggle_probe=option; late_trace_enabled=tracing;
        struct hws_video before=*video();
        probe_late();
        assert(read_count==(option && tracing ? 8U : 0U));
        assert(late_records==(option && tracing ? 1U : 0U));
        assert(!ack_writes && !delivered); assert_late_observation_only(before);
    }
    for (unsigned position=1;position<=8;position++) {
        initialize(); late_toggle_probe=late_trace_enabled=true; read_cost_ns=1000;
        reg_set(HWS_REG_VBUF_TOGGLE(0),0x81); /* preserve all raw register bits */
        mmio_count=0; inject_mmio=position; mmio_hook=late_toggle_changes;
        struct hws_video before=*video(); probe_late();
        assert(late_records==1 && late_record.count==4 && !late_record.flags);
        assert(late_record.toggle[0]==0x81 && late_record.baseline==1);
        if (position<=6) assert(late_record.toggle[3]==0x80);
        assert(video()->late_toggle_max_ns==8000 && !ack_writes);
        assert_late_observation_only(before); check_ownership();
    }
    initialize(); late_toggle_probe=late_trace_enabled=true;
    reg_set(HWS_REG_INT_STATUS,1); probe_late();
    for (unsigned i=0;i<4;i++) assert(late_record.status[i]==1);
    assert(reg_get(HWS_REG_INT_STATUS)==1 && !ack_writes); /* never ack diagnostic data */
    initialize(); late_toggle_probe=late_trace_enabled=true;
    for (unsigned i=0;i<18;i++) probe_late();
    assert(read_count==128 && late_records==16 && video()->late_toggle_suppressed==2);
    unsigned long flags;
    spin_lock_irqsave(&video()->irq_lock,flags);
    hws_video_reset_evidence_locked(video());
    spin_unlock_irqrestore(&video()->irq_lock,flags);
    assert(!video()->late_toggle_windows && !video()->late_toggle_samples &&
           !video()->late_toggle_suppressed && !video()->late_toggle_budget_exits &&
           !video()->late_toggle_max_ns);
    probe_late(); assert(read_count==136 && late_record.window==1 && late_records==17);
    initialize(); late_toggle_probe=late_trace_enabled=true; read_cost_ns=20000;
    probe_late(); assert(read_count==4 && late_record.count==2);
    assert(late_record.flags==HWS_LATE_TOGGLE_BUDGET && video()->late_toggle_max_ns==80000);
    assert(video()->late_toggle_budget_exits==1); /* last MMIO can overrun soft budget */
    initialize(); late_toggle_probe=late_trace_enabled=true;
    video()->stop_requested=true; probe_late(); assert(!read_count && !late_records);
    video()->stop_requested=false; device.suspended=true; probe_late(); assert(!read_count);
    device.suspended=false; hws_irq_probe_late_toggle(video(),99,1,now,1); assert(!read_count);
    hws_irq_probe_late_toggle(video(),0,1,now+1,1);
    assert(!read_count && late_record.flags==HWS_LATE_TOGGLE_CLOCK);
    for (unsigned position=1;position<=8;position++) {
        initialize(); late_toggle_probe=late_trace_enabled=true;
        fault_read_at=position; probe_late();
        assert(device.pci_lost && device.dma_failed && read_count==position);
        assert(late_record.flags & HWS_LATE_TOGGLE_FAULT);
        unsigned reads=read_count; fault_read_at=0; probe_late();
        assert(read_count==reads && hws_irq_handler(0,&device)==IRQ_NONE);
    }
    initialize(); late_toggle_probe=late_trace_enabled=true;
    inject_mmio=1; mmio_hook=stop_during_copy; probe_late();
    assert(read_count<=2 && late_record.flags==HWS_LATE_TOGGLE_STOPPED);
    initialize(); late_toggle_probe=late_trace_enabled=true;
    inject_mmio=1; mmio_hook=late_clock_backwards; probe_late();
    assert(read_count==2 && late_record.flags==HWS_LATE_TOGGLE_CLOCK);
    /* Handler integration: diagnostic late value cannot replace disposition. */
    initialize(); synchronize_stream(); step(true);
    late_toggle_probe=late_trace_enabled=true;
    mmio_count=0; inject_mmio=7; mmio_hook=late_toggle_changes;
    unsigned writes=ack_writes; duplicate();
    assert(late_records==1 && late_record.toggle[3]==0x80);
    assert(video()->duplicate_recoveries==1 && !video()->active && !delivered);
    assert(video()->last_buf_half_toggle==1 && ack_writes==writes+1);
    check_ownership(); reg_set(HWS_REG_VBUF_TOGGLE(0),1); prove_forward_progress();
    /* Original state/content cases also run with the diagnostic armed. */
    initialize(); synchronize_stream(); late_toggle_probe=late_trace_enabled=true;
    step(true); duplicate(); prove_forward_progress();
    assert(late_records==1 && !failures);
    puts("Late-toggle diagnostic PASS: opt-in/trace gates, raw samples, all read positions, no W1C/rescue, 16-window cap, soft time budget, stop/fault/clock exits and unchanged duplicate recovery.");
}

int main(void)
{
#define RUN_TEST(fn) do { test_case=#fn; schedule_id=injection_point=injection_half=0; fn(); } while (0)
    RUN_TEST(test_normal_and_duplicate); RUN_TEST(test_starvation);
    RUN_TEST(test_copy_and_pending_overlap); RUN_TEST(test_deadline_and_guard);
    RUN_TEST(test_clock_boundaries_and_stop); RUN_TEST(test_duplicate_bursts_and_after_delivery);
    RUN_TEST(test_unobserved_boundaries);
    RUN_TEST(test_all_mode_gaps); RUN_TEST(test_continuity_state); RUN_TEST(test_gap_interleavings);
    RUN_TEST(test_mmio_interleavings); RUN_TEST(test_exhaustive_short_schedules);
    RUN_TEST(test_mmio_failure);
    RUN_TEST(test_source_transitions);
    RUN_TEST(test_late_toggle_diagnostic);
    puts("Production VDONE code PASS: continuity gaps in 14 modes, boundaries/epoch/holds, duplicate/starvation/overlap/deadline/guard/MMIO and 4721 schedules");
    puts("Scope: deterministic modeled hardware; not kernel concurrency, real IRQ timing, or post-stop DMA proof.");
    puts("MMIO fault cases PASS: 8 video and 5 audio read positions; transient recovery rejected; shared/no-cause IRQ preserved.");
    return 0;
}
