/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <linux/videodev2.h>
#include <linux/v4l2-dv-timings.h>
typedef uint32_t u32; typedef uint64_t u64; typedef uint64_t dma_addr_t;
#define U32_MAX UINT32_MAX
#define U64_MAX UINT64_MAX
#define div64_u64(a,b) ((u64)(a)/(u64)(b))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BIT(n) (1U<<(n))
#define SZ_2K 2048U
#define PAGE_SIZE 4096U
#define PAGE_ALIGN(n) (((n)+4095U)&~4095U)
#define round_down(n,a) ((n)/(a)*(a))
#define IS_ALIGNED(n,a) (!((n)% (a)))
#define lower_32_bits(n) ((u32)(n))
#define upper_32_bits(n) ((u32)((u64)(n)>>32))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define lockdep_assert_held(p) assert(*(p))
#define spin_lock_irqsave(p,f) do { (f)=0; assert(!*(p)); *(p)=1; } while(0)
#define spin_unlock_irqrestore(p,f) do { (void)(f); assert(*(p)); *(p)=0; } while(0)
#define dev_dbg(...) ((void)0)
#define dev_err(...) ((void)0)
#define __iomem
/* DEVICE */
struct hws_pcie_dev;
struct vb2_queue { bool busy; };
struct hws_video {
    struct hws_pcie_dev *parent; int channel_index;
    struct hws_pix_state pix;
    int irq_lock;
    bool cap_active, stop_requested, dma_needs_idle, window_valid;
    u32 last_dma_hi,last_dma_page,last_pci_addr,last_half16;
    size_t ring_extent,ring_split;
    struct v4l2_dv_timings cur_dv_timings;
    u32 current_fps;
    int state_lock;
    struct vb2_queue buffer_queue;
};
struct hws_pcie_dev {
    unsigned char *bar0_base;
    unsigned max_channels,cur_max_video_ch,cur_max_audio_ch;
    int capture_lock;
    bool pci_lost,dma_failed,dma_quiesced,suspended;
    struct hws_video video[4];
};
#define HWS_BUF_BASE_OFF(ch) HWS_REG_VIDEO_DMA_ADDR(ch)
#define HWS_HALF_SZ_OFF(ch) HWS_REG_VIDEO_HALF_SIZE(ch)
static bool dma_window_verify;
static dma_addr_t ring_dma=0x1234002000ULL;
static dma_addr_t hws_video_ring_dma(struct hws_pcie_dev *h,unsigned ch)
{ (void)h;(void)ch;return ring_dma; }
static size_t hws_video_dma_extent(u32 size) {return PAGE_ALIGN(size+SZ_2K);}
static size_t hws_video_ring_capacity(void) {return MAX_VIDEO_SCALER_SIZE+8192;}
static bool hws_dma_fits_remap_window(dma_addr_t d,size_t s)
{return s && upper_32_bits(d)==upper_32_bits(d+s-1) &&
    (lower_32_bits(d)&PCI_E_BAR_ADD_MASK)==(lower_32_bits(d+s-1)&PCI_E_BAR_ADD_MASK);}
static void hws_device_lost(struct hws_pcie_dev *h,const char *reason)
{assert(reason);h->pci_lost=h->dma_failed=true;}
static unsigned char regs[0x5000];
static unsigned fault_offset=UINT32_MAX,write_count,shared_writes;
static unsigned fault_kind; /* 1: dropped write, 2: wrong readback, 3: all ones */
static unsigned fault_nth, fault_reads;
static u32 fault_xor=16;
static u32 get_reg(unsigned off) {u32 r;memcpy(&r,regs+off,4);return r;}
static void set_reg(unsigned off,u32 v) {memcpy(regs+off,&v,4);}
static u32 readl(void *addr)
{
    unsigned off=(unsigned char *)addr-regs;
    assert(off+4<=sizeof(regs));
    bool inject=off==fault_offset && (!fault_nth || ++fault_reads==fault_nth);
    if(inject && fault_kind==2) return get_reg(off)^fault_xor;
    if(inject && fault_kind==3) return U32_MAX;
    return get_reg(off);
}
static void writel(u32 v,void *addr)
{
    unsigned off=(unsigned char *)addr-regs;
    assert(off+4<=sizeof(regs)); write_count++;
    if(off==PCI_ADDR_TABLE_BASE+HWS_VIDEO_REMAP_SLOT_OFF(0) ||
       off==PCI_ADDR_TABLE_BASE+HWS_VIDEO_REMAP_SLOT_OFF(0)+PCIE_BARADDROFSIZE) shared_writes++;
    if(off!=fault_offset || fault_kind!=1) set_reg(off,v);
}
#define writel_relaxed writel
#define readl_relaxed readl
