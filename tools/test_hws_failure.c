
static atomic_bool cancel_done;
static void *report_failure(void *arg)
{ hws_device_lost(arg,"repeated concurrent report"); return NULL; }
static void *cancel_failure(void *arg)
{ hws_failure_cancel(arg); cancel_done=true; return NULL; }

static void test_transaction(int pci_result, bool irq_registered, bool early_failure)
{
    struct hws_pcie_dev h={0};
    struct hwsvideo_buffer buffers[3]={0};
    pthread_t reporters[8], cancel;
    pthread_mutex_t *locks[]={&h.failure_lock,&h.capture_lock,&h.dma_lock,
        &h.irq_lifetime_lock,&h.monitor_lock,&h.video[0].state_lock,&h.video[0].irq_lock};
    for(unsigned i=0;i<sizeof(locks)/sizeof(*locks);i++) assert(!pthread_mutex_init(locks[i],NULL));
    h.cur_max_video_ch=h.cur_max_audio_ch=1; h.irq=7; h.irq_registered=irq_registered;
    h.start_run=true; h.video[0].cap_active=true;
    h.video[0].queue_initialized=h.video[0].buffer_queue.streaming=true;
    h.audio[0].stream_running=h.audio[0].cap_active=true;
    h.failure_work.fn=hws_failure_work;
    INIT_LIST_HEAD(&h.video[0].capture_queue);
    for(unsigned i=0;i<3;i++) INIT_LIST_HEAD(&buffers[i].list);
    h.video[0].active=&buffers[0];
    for(unsigned i=1;i<3;i++) list_add_tail(&buffers[i].list,&h.video[0].capture_queue);
    h.video[0].queued_count=2;
    enqueues=isolations=irq_drains=audio_drains=audio_errors=audio_flushes=0;
    at_copy_drain=release_copy=false; cancel_done=false; isolation_result=pci_result;
    if (early_failure) {
        hws_device_lost(&h,"first failure");
        assert(h.failure_latched && enqueues==0);
    }
    hws_failure_enable(&h);
    if (!early_failure) hws_device_lost(&h,"first failure");
    mutex_lock(&pause_lock);
    while (!at_copy_drain) pthread_cond_wait(&pause_cond,&pause_lock);
    mutex_unlock(&pause_lock);
    assert(h.pci_lost && h.dma_failed && !h.start_run);
    assert(!h.video[0].buffer_queue.errors && !buffers[0].vb.vb2_buf.returned);
    for(unsigned i=0;i<8;i++) assert(!pthread_create(&reporters[i],NULL,report_failure,&h));
    for(unsigned i=0;i<8;i++) assert(!pthread_join(reporters[i],NULL));
    assert(enqueues==1 && !strcmp(h.failure_reason,"first failure"));
    assert(!pthread_create(&cancel,NULL,cancel_failure,&h));
    /* Observe the gate closing: cancel must still wait for the active copy. */
    for (;;) {
        bool enabled; mutex_lock(&h.failure_lock); enabled=h.failure_enabled; mutex_unlock(&h.failure_lock);
        if (!enabled) break;
        sched_yield();
    }
    assert(!cancel_done);
    hws_device_lost(&h,"report during remove"); assert(enqueues==1);
    mutex_lock(&pause_lock); release_copy=true; pthread_cond_broadcast(&pause_cond); mutex_unlock(&pause_lock);
    assert(!pthread_join(cancel,NULL));
    assert(cancel_done && isolations==1 && irq_drains==(unsigned)irq_registered);
    assert(h.dma_quiesced==!pci_result && h.pci_lost && h.dma_failed);
    assert(h.video[0].buffer_queue.errors==1 && !h.video[0].active && !h.video[0].queued_count);
    for(unsigned i=0;i<3;i++) assert(buffers[i].vb.vb2_buf.returned==1);
    assert(audio_errors==1 && audio_flushes==1);
    /* A subsequent STREAMOFF collection is empty, never a second completion. */
    LIST_HEAD(done); hws_video_collect_done_locked(&h.video[0],&done); assert(list_empty(&done));
    hws_device_lost(&h,"report after remove gate"); assert(enqueues==1);
    hws_failure_cancel(&h);
    for(unsigned i=0;i<sizeof(locks)/sizeof(*locks);i++) assert(!pthread_mutex_destroy(locks[i]));
}
int main(void)
{
    for(unsigned mode=0;mode<8;mode++) test_transaction(mode&1 ? -EIO : 0,mode&2,mode&4);
    puts("Production device-failure transaction PASS: 8 isolation/IRQ/probe combinations, concurrent reporters, paused copy, remove cancellation, exact-once video return, audio notification ordering.");
    puts("Scope: pthread/mocked PCI and consumers, not kernel races or physical DMA containment.");
    return 0;
}
