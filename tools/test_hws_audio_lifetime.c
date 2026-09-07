static struct hws_pcie_dev device;
static struct snd_pcm_substream stream;
static struct snd_pcm_runtime runtime;
static char destination[64], packet[16];
static int operation;
static void *irq_release_thread(void *unused)
{
    (void)unused;
    spin_lock(&control); irq_release_started=true; pthread_cond_broadcast(&changed);
    spin_unlock(&control);
    hws_release_irq(&device);
    return NULL;
}

static void *worker_thread(void *unused)
{
    struct hws_audio *a=&device.audio[0];
    enum hws_audio_xrun_reason failure;
    (void)unused;
    if (pause_point==2) hws_audio_report_xrun(a);
    else hws_audio_deliver_packet(a,packet,1,&failure);
    spin_lock(&control);
    a->deliver_work.running=false; pthread_cond_broadcast(&changed);
    spin_unlock(&control);
    return NULL;
}
static void *release_thread(void *unused)
{
    (void)unused;
    if (operation==3) assert(!hws_pcie_audio_prepare(&stream));
    else if (operation==2) hws_pcie_audio_sync_stop(&stream);
    else if (operation) hws_pcie_audio_close(&stream);
    else hws_pcie_audio_hw_free(&stream);
    spin_lock(&control);
    released=true; pthread_cond_broadcast(&changed);
    spin_unlock(&control);
    return NULL;
}
static void scenario(int state, int point, int op)
{
    memset(&device,0,sizeof(device));
    struct hws_audio *a=&device.audio[0];
    device.cur_max_audio_ch=1; device.irq=7;
    device.audio_wq=(void *)&device; device.snd_card=&device;
    device.irq_registered=true; device.bar0_base=&device;
    assert(!pthread_mutex_init(&device.irq_lifetime_lock.lock,NULL));
    assert(!pthread_mutex_init(&a->ring_lock,NULL));
    assert(!pthread_mutex_init(&a->pending_lock,NULL));
    a->parent=&device; a->pcm_substream=&stream;
    a->stream_running=a->cap_active=true;
    a->work_enabled=true;
    a->packet_state=HWS_AUDIO_PACKET_COPYING; a->pending_generation=1;
    a->frame_bytes=4; a->hw_packet_bytes=16;
    a->ring_size_byframes=16; a->period_size_byframes=4;
    runtime=(struct snd_pcm_runtime){.dma_area=destination,.channels=2,
        .buffer_size=16,.period_size=4};
    stream.runtime=&runtime; stream.private_data=a;
    paused=resume_worker=drain_entered=released=false;
    notifications=mmio_calls=irq_syncs=0; pause_point=point; operation=op;
    a->deliver_work.running=true;
    pthread_t worker, teardown;
    assert(!pthread_create(&worker,NULL,worker_thread,NULL));
    spin_lock(&control);
    while(!paused) await_change();
    if(state==1) device.suspended=true;
    if(state==2) device.pci_lost=true;
    if(state==3) device.dma_quiesced=true;
    if(state==4) { device.suspended=true; device.irq=-1;
        device.irq_registered=false; device.bar0_base=NULL; }
    assert(!pthread_create(&teardown,NULL,release_thread,NULL));
    while(!drain_entered && !released) await_change();
    assert(!released); /* Pre-fix suspended/lost branch fails here. */
    resume_worker=true; pthread_cond_broadcast(&changed);
    spin_unlock(&control);
    assert(!pthread_join(worker,NULL)); assert(!pthread_join(teardown,NULL));
    assert(released && !a->deliver_work.running);
    assert(!a->work_enabled);
    assert(a->ring_size_byframes==(op>=2 ? 16UL : 0UL));
    assert(a->packet_state==HWS_AUDIO_PACKET_IDLE);
    if(state) assert(mmio_calls==(point==2 ? 1 : 0));
    if(state==4) assert(!irq_syncs);
    if(!state) {
        /* Real prepare/start/stop bodies; mocked hardware and scratch reclaim. */
        assert(!hws_pcie_audio_prepare(&stream));
        a->pcm_substream=&stream; a->scratch_acquired=true;
        atomic_context=true;
        assert(!hws_pcie_audio_trigger(&stream,SNDRV_PCM_TRIGGER_START));
        assert(a->work_enabled && a->stream_running);
        assert(!hws_pcie_audio_trigger(&stream,SNDRV_PCM_TRIGGER_STOP));
        assert(!a->work_enabled && !a->stream_running);
        atomic_context=false;
        assert(!hws_pcie_audio_prepare(&stream));
        atomic_context=true;
        assert(!hws_pcie_audio_trigger(&stream,SNDRV_PCM_TRIGGER_START));
        atomic_context=false;
        /* sync_stop must not erase state required by advertised PCM RESUME. */
        a->ring_wpos_byframes=7; a->period_used_byframes=2;
        atomic_context=true;
        assert(!hws_pcie_audio_trigger(&stream,SNDRV_PCM_TRIGGER_SUSPEND));
        atomic_context=false;
        hws_pcie_audio_sync_stop(&stream);
        assert(a->ring_size_byframes==16 && a->ring_wpos_byframes==7);
        assert(a->period_used_byframes==2);
        a->dma_armed=false; /* Model the separate successful PM reclaim. */
        atomic_context=true;
        assert(!hws_pcie_audio_trigger(&stream,SNDRV_PCM_TRIGGER_RESUME));
        atomic_context=false;
        assert(a->stream_running && a->ring_wpos_byframes==7);
    }
    /* Repeated free/close must be harmless. */
    hws_pcie_audio_hw_free(&stream); hws_pcie_audio_close(&stream);
    assert(!a->pcm_substream);
    /* Neither a delayed IRQ enqueue nor a later device fault may reopen work. */
    queued=0; hws_audio_queue_work(&device,0); hws_audio_dma_fault_all(&device);
    assert(!queued);
    /* Model a fresh prepared/start epoch; fault notifications are drainable. */
    a->pcm_substream=&stream; a->work_enabled=true;
    hws_audio_dma_fault_all(&device);
    assert(queued==1 && a->packet_state==HWS_AUDIO_PACKET_XRUN);
    hws_pcie_audio_sync_stop(&stream);
    assert(!a->work_enabled && a->packet_state==HWS_AUDIO_PACKET_IDLE);
    /* Managed IRQ release is idempotent, and late close never syncs it. */
    if(!state && !point && !op) {
        /* IRQ release must serialize with a callback already synchronizing it. */
        pause_irq_sync=true; irq_sync_paused=resume_irq_sync=irq_release_started=false;
        operation=2;
        pthread_t syncer, freer;
        assert(!pthread_create(&syncer,NULL,release_thread,NULL));
        spin_lock(&control);
        while(!irq_sync_paused) await_change();
        assert(!pthread_create(&freer,NULL,irq_release_thread,NULL));
        while(!irq_release_started) await_change();
        assert(pthread_mutex_trylock(&device.irq_lifetime_lock.lock)==EBUSY);
        resume_irq_sync=true; pthread_cond_broadcast(&changed);
        spin_unlock(&control);
        assert(!pthread_join(syncer,NULL)); assert(!pthread_join(freer,NULL));
        pause_irq_sync=false;
    } else hws_release_irq(&device);
    assert(!device.irq_registered && device.irq==-1);
    int sync_before=irq_syncs, frees_before=freed_irqs;
    hws_release_irq(&device); hws_pcie_audio_close(&stream);
    assert(irq_syncs==sync_before && freed_irqs==frees_before);
    pthread_mutex_destroy(&a->ring_lock); pthread_mutex_destroy(&a->pending_lock);
    pthread_mutex_destroy(&device.irq_lifetime_lock.lock);
}
int main(void)
{
    for(int state=0;state<5;state++) for(int point=0;point<3;point++)
        for(int op=0;op<4;op++) scenario(state,point,op);
    puts("Audio lifetime PASS: 60 paused worker/lifecycle cases; stop/prepare/start, enqueue gate, fault notification, IRQ lifetime and late cleanup");
    puts("Scope: production function bodies, modeled ALSA/workqueue/IRQ; not kernel concurrency or DMA proof.");
}
