struct hws_pcie_dev {
    struct hws_audio audio[1];
    unsigned cur_max_audio_ch;
    bool suspended, pci_lost, dma_quiesced, dma_failed, irq_registered;
    void *bar0_base;
    int irq;
    struct mutex irq_lifetime_lock;
    struct workqueue_struct *audio_wq;
    void *snd_card;
};
static pthread_mutex_t control = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool paused, resume_worker, drain_entered, released;
static int pause_point, notifications, mmio_calls, irq_syncs;
static int queued, freed_irqs;
static bool pause_irq_sync, irq_sync_paused, resume_irq_sync, irq_release_started;
static void await_change(void)
{
    struct timespec deadline;
    assert(!clock_gettime(CLOCK_REALTIME, &deadline));
    deadline.tv_sec += 5;
    assert(!pthread_cond_timedwait(&changed, &control, &deadline));
}
static void pause_worker(int point)
{
    if (point != pause_point) return;
    spin_lock(&control);
    paused=true; pthread_cond_broadcast(&changed);
    while (!resume_worker) await_change();
    assert(!released); /* Runtime/notification must still belong to the stream. */
    spin_unlock(&control);
}
static void cancel_work_sync(struct work_struct *w)
{
    assert(!atomic_context);
    spin_lock(&control);
    drain_entered=true; pthread_cond_broadcast(&changed);
    while (w->running) await_change();
    spin_unlock(&control);
}
static void synchronize_irq(int irq)
{
    assert(!atomic_context && irq==7); irq_syncs++;
    spin_lock(&control);
    if(pause_irq_sync) {
        irq_sync_paused=true; pthread_cond_broadcast(&changed);
        while(!resume_irq_sync) await_change();
    }
    spin_unlock(&control);
}
static void free_irq(int irq, void *hws) { assert(irq==7 && hws); freed_irqs++; }
static void queue_work(struct workqueue_struct *wq, struct work_struct *work)
{ assert(wq && work); queued++; }
static void hws_enable_audio_capture(struct hws_pcie_dev *h, unsigned ch, bool enable)
{ assert(h && !ch); h->audio[ch].cap_active=enable; }
static bool hws_check_audio_capture(struct hws_pcie_dev *h, unsigned ch)
{ return h->audio[ch].cap_active; }
static int hws_audio_hw_ready(struct hws_pcie_dev *h)
{ return h->pci_lost ? -ENODEV : 0; }
static int hws_audio_guard_and_seed_capture_buffer(struct hws_pcie_dev *h, unsigned ch)
{ assert(h && !ch); return 0; }
static void hws_audio_ack_pending(struct hws_pcie_dev *h, unsigned ch)
{ assert(h && !ch); }
static int hws_audio_prepare_scratch(struct hws_audio *a, const char *owner)
{
    assert(owner && !a->deliver_work.running && !a->work_enabled);
    a->dma_armed=false; return 0;
}
static int snd_pcm_format_physical_width(unsigned format) { (void)format; return 16; }
static void hws_audio_disable_capture_and_ack(struct hws_pcie_dev *h, unsigned ch)
{ assert(!ch && h->bar0_base && !h->suspended && !h->pci_lost); mmio_calls++; }
static void hws_audio_release_scratch(struct hws_audio *a, bool idle)
{ (void)a; (void)idle; }
static void hws_audio_log_telemetry(struct hws_audio *a, const char *event, bool force)
{ (void)a; (void)event; (void)force; }
static void snd_pcm_period_elapsed(struct snd_pcm_substream *ss)
{ pause_worker(1); assert(ss->runtime); notifications++; }
static void snd_pcm_stop_xrun(struct snd_pcm_substream *ss)
{ pause_worker(2); assert(ss->runtime); notifications++; }
