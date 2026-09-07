/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HWS_IRQ_TEST_SHIM_H
#define HWS_IRQ_TEST_SHIM_H
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <linux/videodev2.h>
static _Noreturn void test_assert_fail(const char *, const char *, int);
#undef assert
#define assert(expr) ((expr) ? (void)0 : test_assert_fail(#expr, __FILE__, __LINE__))
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define U8_MAX UINT8_MAX
#define U32_MAX UINT32_MAX
#define U64_MAX UINT64_MAX
#define NSEC_PER_SEC UINT64_C(1000000000)
#define NSEC_PER_USEC UINT64_C(1000)
#define SZ_2K 2048U
#define SZ_2M (2U * 1024U * 1024U)
#define BIT(n) (1U << (n))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))
#define min_t(t,a,b) min((t)(a),(t)(b))
#define max_t(t,a,b) max((t)(a),(t)(b))
#define round_down(x,a) ((x) / (a) * (a))
#define IS_ALIGNED(x,a) (!((x) % (a)))
#define div_u64(x,y) ((u64)(x) / (y))
#define div64_u64(x,y) ((u64)(x) / (u64)(y))
#define container_of(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
struct list_head { struct list_head *next, *prev; };
static void INIT_LIST_HEAD(struct list_head *h) { h->next = h->prev = h; }
static bool list_empty(const struct list_head *h) { return h->next == h; }
static void list_add(struct list_head *n, struct list_head *h)
{ n->next = h->next; n->prev = h; h->next->prev = n; h->next = n; }
static void list_del_init(struct list_head *n)
{ n->prev->next = n->next; n->next->prev = n->prev; INIT_LIST_HEAD(n); }
#define list_first_entry(h,t,m) container_of((h)->next,t,m)
typedef int spinlock_t;
#define spin_lock_irqsave(p,f) do { (f)=0; assert(!*(p)); *(p)=1; } while (0)
#define spin_unlock_irqrestore(p,f) do { (void)(f); assert(*(p)); *(p)=0; } while (0)
#define lockdep_assert_held(p) assert(*(p))
typedef unsigned int atomic_t;
#define atomic_fetch_inc(p) ((*(p))++)
struct mutex { int unused; };
struct vb2_queue { int unused; };
struct v4l2_ctrl_handler { int unused; };
struct vb2_buffer { unsigned index; u64 timestamp; void *data; size_t size, payload; bool owned; };
struct vb2_v4l2_buffer { struct vb2_buffer vb2_buf; u32 sequence; enum v4l2_field field; };
static size_t vb2_plane_size(struct vb2_buffer *b, unsigned p) { assert(!p); return b->size; }
static void *vb2_plane_vaddr(struct vb2_buffer *b, unsigned p) { assert(!p && b->owned); return b->data; }
static void vb2_set_plane_payload(struct vb2_buffer *b, unsigned p, size_t s)
{ assert(!p && s <= b->size); b->payload=s; }
#define VB2_BUF_STATE_DONE 0
static void vb2_buffer_done(struct vb2_buffer *, int);
struct work_struct { void (*fn)(struct work_struct *); bool pending; };
struct workqueue_struct { int unused; };
#define INIT_WORK(w,f) do { (w)->fn=(f); (w)->pending=false; } while (0)
static bool queue_work(struct workqueue_struct *q, struct work_struct *w)
{ assert(q); bool fresh=!w->pending; w->pending=true; return fresh; }
static bool schedule_work(struct work_struct *w) { bool fresh=!w->pending; w->pending=true; return fresh; }
typedef int irqreturn_t;
#define IRQ_NONE 0
#define IRQ_HANDLED 1
static u32 readl(const void *);
static void writel(u32, void *);
static u64 ktime_get_mono_fast_ns(void);
static void *test_memcpy(void *, const void *, size_t);
#define memcpy test_memcpy
#define dma_rmb() ((void)0)
#define WARN_ON_ONCE(x) (x)
#define dev_warn(...) ((void)0)
#define dev_info(...) ((void)0)
#define dev_err_ratelimited(...) ((void)0)
#define trace_hws_vdone_probe_enabled() false
#define trace_hws_video_diag_enabled() false
#define trace_hws_vdone_probe(...) ((void)0)
#define trace_hws_vdone_copy(...) ((void)0)
#define trace_hws_vdone_recovery(...) ((void)0)
#define trace_hws_vdone_frame(...) ((void)0)
#define trace_hws_vdone_irq(...) ((void)0)
#define module_param(...)
#define MODULE_PARM_DESC(...)
#endif
