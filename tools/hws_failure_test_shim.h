/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <errno.h>
#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_SEQ_CST)
#define WRITE_ONCE(x,v) __atomic_store_n(&(x),(v),__ATOMIC_SEQ_CST)
#define smp_wmb() atomic_thread_fence(memory_order_release)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define spin_lock_irqsave(p,f) do { (f)=0; assert(!pthread_mutex_lock(p)); } while (0)
#define spin_unlock_irqrestore(p,f) do { (void)(f); assert(!pthread_mutex_unlock(p)); } while (0)
#define mutex_lock(p) assert(!pthread_mutex_lock(p))
#define mutex_unlock(p) assert(!pthread_mutex_unlock(p))
#define dev_err(...) ((void)0)
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
#define list_first_entry(h,t,m) container_of((h)->next,t,m)
#define list_for_each_entry_safe(p,n,h,m) \
    for ((p)=list_first_entry(h,__typeof__(*(p)),m), \
         (n)=list_first_entry(&(p)->m,__typeof__(*(p)),m); \
         &(p)->m!=(h); (p)=(n),(n)=list_first_entry(&(n)->m,__typeof__(*(n)),m))
static void INIT_LIST_HEAD(struct list_head *h) { h->next=h->prev=h; }
static bool list_empty(struct list_head *h) { return h->next==h; }
static bool list_node_unlinked(struct list_head *h) { return list_empty(h); }
static void list_del_init(struct list_head *n)
{ n->prev->next=n->next; n->next->prev=n->prev; INIT_LIST_HEAD(n); }
static void list_add_tail(struct list_head *n,struct list_head *h)
{ n->prev=h->prev; n->next=h; h->prev->next=n; h->prev=n; }
static void list_move_tail(struct list_head *n,struct list_head *h)
{ list_del_init(n); list_add_tail(n,h); }
struct vb2_buffer { unsigned returned; };
struct hwsvideo_buffer { struct list_head list; struct { struct vb2_buffer vb2_buf; } vb; };
struct vb2_queue { bool streaming; unsigned errors; };
struct work_struct { pthread_t thread; void (*fn)(struct work_struct *); bool queued; };
struct hws_video {
    pthread_mutex_t state_lock, irq_lock;
    bool cap_active, stop_requested, queue_initialized;
    struct vb2_queue buffer_queue;
    struct hwsvideo_buffer *active;
    struct list_head capture_queue;
    unsigned queued_count;
};
struct hws_audio { bool stream_running, cap_active, stop_requested; struct work_struct deliver_work; };
struct hws_pcie_dev {
    pthread_mutex_t failure_lock, capture_lock, dma_lock, irq_lifetime_lock, monitor_lock;
    bool failure_latched, failure_enabled, failure_scheduled, pci_lost, dma_failed;
    bool start_run, dma_quiesced, irq_registered;
    const char *failure_reason;
    struct work_struct failure_work;
    unsigned cur_max_video_ch, cur_max_audio_ch;
    struct hws_video video[1]; struct hws_audio audio[1];
    int irq;
};
static void *system_long_wq=(void *)1;
static atomic_uint enqueues, isolations, irq_drains, audio_drains, audio_errors, audio_flushes;
static int isolation_result;
static pthread_mutex_t pause_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pause_cond=PTHREAD_COND_INITIALIZER;
static bool at_copy_drain, release_copy;
static void *worker_thread(void *arg)
{ struct work_struct *w=arg; w->fn(w); return NULL; }
static bool queue_work(void *q,struct work_struct *w)
{
    assert(q==system_long_wq && !w->queued);
    w->queued=true; enqueues++;
    assert(!pthread_create(&w->thread,NULL,worker_thread,w)); return true;
}
static void cancel_work_sync(struct work_struct *w)
{ if (w->queued) { assert(!pthread_join(w->thread,NULL)); w->queued=false; } }
static int hws_disable_pci_dma_checked(struct hws_pcie_dev *h,const char *owner,int ch,bool wait)
{ assert(h->pci_lost && h->dma_failed && owner && ch==-1 && wait); isolations++; return isolation_result; }
static void synchronize_irq(int irq) { assert(irq==7); irq_drains++; }
static void hws_video_drain_work(struct hws_pcie_dev *h)
{
    assert(h->video[0].stop_requested && !h->video[0].cap_active);
    /* Copies must finish before returning ownership to vb2. */
    mutex_lock(&pause_lock); at_copy_drain=true; pthread_cond_broadcast(&pause_cond);
    while (!release_copy) pthread_cond_wait(&pause_cond,&pause_lock);
    mutex_unlock(&pause_lock);
}
static void hws_audio_drain_work(struct hws_pcie_dev *h)
{ assert(h->audio[0].stop_requested); audio_drains++; }
static void hws_audio_dma_fault_all(struct hws_pcie_dev *h)
{ assert(h->dma_failed && audio_drains==1); audio_errors++; }
static void flush_work(struct work_struct *w)
{ (void)w; assert(audio_errors==1); audio_flushes++; }
static bool vb2_is_streaming(struct vb2_queue *q) { return q->streaming; }
static void vb2_queue_error(struct vb2_queue *q)
{ assert(release_copy && audio_drains==1); q->errors++; }
#define VB2_BUF_STATE_ERROR 1
static void vb2_buffer_done(struct vb2_buffer *b,int state)
{ assert(release_copy && state==VB2_BUF_STATE_ERROR && !b->returned); b->returned++; }
static void hws_video_reset_stream_phase_locked(struct hws_video *v) { (void)v; }
