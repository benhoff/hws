
static void init(void)
{
    memset(&device,0,sizeof(device)); memset(peer_ticks,0,sizeof(peer_ticks));
    reads=idle_at=fault_at=elapsed_us=poll_calls=0;
    forced=isolated=guards=notices=disables=drains=errors=syncs=0;
    good_guards=true; saw_idle=false;
    device.bar0_base=regs; device.max_channels=4; device.irq=12;
    for (unsigned ch=0;ch<4;ch++) {
        device.video[ch].parent=&device; device.video[ch].channel_index=ch;
        device.audio[ch].parent=&device; device.audio[ch].channel_index=ch;
        device.video[ch].ring_extent=4096;
    }
    device.video[0].dma_needs_idle=true;
    device.audio[0].dma_armed=true;
    device.audio[0].scratch_state_lock=1;
}
static int reclaim(bool audio)
{
    return audio ? hws_audio_reclaim_scratch_locked(&device.audio[0],false,"test") :
        hws_video_reclaim_ring(&device.video[0],"test");
}
static void restart_tests(void)
{
    for (unsigned audio=0;audio<2;audio++) {
        for (unsigned peers=0;peers<3;peers++) {
            init();
            /* Same slot opposite direction; then distinct slot; then all. */
            if (!peers) {
                if (audio) device.video[0].cap_active=true;
                else device.audio[0].cap_active=true;
            } else {
                for (unsigned ch=1;ch<(peers==1?2:4);ch++) {
                    device.video[ch].cap_active=true;
                    device.audio[ch].cap_active=true;
                }
            }
            struct hws_pcie_dev before=device;
            for (unsigned attempt=0;attempt<3;attempt++) {
                reads=0;
                assert(reclaim(audio)==-EBUSY);
                assert(elapsed_us==100000 && reads==10001 && !guards);
                assert(!memcmp(&before,&device,sizeof(device)));
                assert(!forced && !isolated);
            }
            assert(peer_ticks[peers?1:0]>0);
            /* No automatic retry/peer stop: caller retries once idle observable. */
            reads=0; idle_at=500;
            assert(reclaim(audio)==0 && elapsed_us==4990 && guards==1);
            assert(!forced && !isolated);
            if (audio) assert(!device.audio[0].dma_armed);
            else assert(!device.video[0].dma_needs_idle);
            for (unsigned ch=0;ch<4;ch++) {
                assert(device.video[ch].cap_active==before.video[ch].cap_active);
                assert(device.audio[ch].cap_active==before.audio[ch].cap_active);
            }
        }
        init(); idle_at=1; good_guards=false;
        assert(reclaim(audio)==-EUCLEAN);
        assert(audio?device.audio[0].scratch_corrupt:device.video[0].ring_corrupt);
        good_guards=true; assert(reclaim(audio)==-EUCLEAN); /* sticky corruption */
        init(); fault_at=3;
        assert(reclaim(audio)==-ENODEV && device.pci_lost && !guards);
        unsigned n=reads; idle_at=1;
        assert(reclaim(audio)==-ENODEV && reads==n && !guards);
        assert(audio?device.audio[0].dma_armed:device.video[0].dma_needs_idle);
        init(); device.dma_failed=true;
        assert(reclaim(audio)==-EIO && !reads && !guards);
        init(); device.dma_quiesced=true;
        assert(reclaim(audio)==0 && !reads && guards==1);
    }
    puts("Restart contract PASS: video/audio x shared/distinct/all peers, 3 bounded busy retries, idle success, guards, fatal latch; no forced peer stop.");
}
static void notification_tests(void)
{
    init(); struct hws_video *v=&device.video[0];
    v->video_device=v; v->source_state_initialized=true; v->detected_fps=60;
    struct v4l2_dv_timings t={.type=V4L2_DV_BT_656_1120,
        .bt={.width=1920,.height=1080}};
    v->detected_dv_timings=v->cur_dv_timings=t;
    /* Fast transient caught by worker, now returned to old geometry. */
    v->source_change_pending=true; v->stop_requested=true;
    v->state_lock=1; hws_video_update_source_state(&device,0,0,&t,60);
    assert(!notices && v->source_change_pending); /* busy monitor loses nothing */
    v->state_lock=0; hws_video_update_source_state(&device,0,0,&t,60);
    assert(notices==1 && !v->source_change_pending && !drains);
    hws_video_update_source_state(&device,0,0,&t,60);
    assert(notices==1 && v->stop_requested && !v->cap_active);
    /* Application recovered before monitor consumed the old indication. */
    v->source_change_pending=true; v->cap_active=true; v->stop_requested=false;
    hws_video_update_source_state(&device,0,0,&t,60);
    assert(notices==2 && !disables && v->cap_active && !v->stop_requested);
    /* Monitor-detected change stops only target, never rewrites configured mode. */
    v->cap_active=true; v->stop_requested=false;
    device.video[1].cap_active=device.audio[0].cap_active=true;
    t.bt.width=1280; t.bt.height=720;
    hws_video_update_source_state(&device,0,0,&t,60);
    assert(notices==3 && disables==1 && drains==1 && syncs==1 && errors==1);
    assert(v->stop_requested && !v->cap_active && v->buffer_queue);
    assert(v->cur_dv_timings.bt.width==1920 && v->cur_dv_timings.bt.height==1080);
    assert(device.video[1].cap_active && device.audio[0].cap_active);
    /* Actual worker-safe fail path cannot acquire state_lock (stop can own it)
     * or drain its own worker. Notification is still monitor-owned.
     */
    v->state_lock=1; v->cap_active=true; v->stop_requested=false;
    unsigned prior_drains=drains, prior_notices=notices;
    hws_video_fail_queue(v,"source snapshot");
    assert(v->state_lock && !v->irq_lock && v->evidence_queue_failures==1);
    assert(v->stop_requested && !v->cap_active && drains==prior_drains && notices==prior_notices);
    assert(device.video[1].cap_active && device.audio[0].cap_active);
    puts("Source notification PASS: transient retained through busy monitor, one consumption, no auto-restart/layout rewrite or peer stop.");
}
int main(void)
{
    struct rlimit limit={0,0}; setrlimit(RLIMIT_CORE,&limit);
    restart_tests(); notification_tests();
    puts("Scope: production decisions with modeled polling/framework; no hardware DMA containment or actual concurrent A/V qualification.");
    return 0;
}
