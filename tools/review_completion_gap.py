#!/usr/bin/env python3
"""Exercise the real half-copy function with mocked DMA/MMIO and accepted events.

This is a review reproducer, not hardware validation or a replacement for IRQ
fault injection. It extracts the current C function unchanged, supplies the
states created by the IRQ path, and reports whether mixed-frame halves pass.
Exit zero means the experiment ran; inspect accepted_mixed_frame in its output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def function(source, name):
    end_name = source.index(name + '(')
    start = source.rfind('\nstatic ', 0, end_name) + 1
    start_body = source.index('{', end_name)
    depth = 1
    end = start_body + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


SHIM = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <linux/videodev2.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
#define U32_MAX UINT32_MAX
#define U64_MAX UINT64_MAX
#define NSEC_PER_SEC 1000000000ULL
#define div_u64(x,y) ((x)/(y))
#define div64_u64(x,y) ((x)/(y))
#define spin_lock_irqsave(lock, flags) ((void)(lock), (flags)=0)
#define spin_unlock_irqrestore(lock, flags) ((void)(lock), (void)(flags))
#define dma_rmb() ((void)0)
#define HWS_REG_VBUF_TOGGLE(ch) (0U * (ch))
#define HWS_VIDEO_SYNC_EVENTS 8
enum { HWS_VIDEO_COMPLETION_COPYING=2 };
enum { HWS_VIDEO_PHASE_SYNC, HWS_VIDEO_PHASE_EXPECT_HALF0, HWS_VIDEO_PHASE_EXPECT_HALF1 };
struct vb2_buffer { unsigned char *data; size_t size; };
struct vb2_v4l2_buffer { struct vb2_buffer vb2_buf; };
struct hwsvideo_buffer { struct vb2_v4l2_buffer vb; };
struct hws_pcie_dev { unsigned char *bar0_base; unsigned char ring[16]; };
struct hws_video {
 struct hws_pcie_dev *parent; unsigned int channel_index; int irq_lock;
 struct { size_t sizeimage; unsigned int width,height; } pix;
 struct v4l2_dv_timings cur_dv_timings;
 size_t ring_split,ring_extent; int completion_state,half_phase;
 u64 completion_generation,phase_generation,frame_generation;
 u64 frame_timestamp_ns,frame_half_period_ns,frame_epoch,evidence_stream_epoch;
 unsigned int sync_events,sync_restart_streak; bool frame_half0_valid;
 struct hwsvideo_buffer *active,*queued;
};
struct hws_vdone_event { u64 timestamp_ns,deadline_ns,generation; u8 toggle; };
struct hws_vdone_copy_observation {
 u64 started_ns,offset,length; u8 toggle_before,toggle_after;
 bool toggle_before_valid,toggle_after_valid,guard_checked,guard_ok;
};
static u64 mock_now;
static u64 ktime_get_mono_fast_ns(void) { return mock_now; }
static u32 readl(void *p) { return *(u32 *)p; }
static void *hws_video_ring_cpu(struct hws_pcie_dev *h, unsigned int ch) { (void)ch; return h->ring; }
static bool hws_video_ring_guards_ok(struct hws_pcie_dev *h, unsigned int ch,size_t extent) { (void)h;(void)ch;(void)extent; return true; }
static size_t vb2_plane_size(struct vb2_buffer *b,unsigned int plane) { (void)plane; return b->size; }
static void *vb2_plane_vaddr(struct vb2_buffer *b,unsigned int plane) { (void)plane; return b->data; }
static struct hwsvideo_buffer *hws_irq_take_queued_buffer_locked(struct hws_video *v) {
 struct hwsvideo_buffer *b=v->queued; v->queued=NULL; return b;
}
'''

MAIN = r'''
static void scenario(const char *name,u64 gap,u64 generation_step,u64 worker_delay,bool new_frame) {
 unsigned char destination[16]={0}; u32 toggle=1;
 struct hws_pcie_dev hw={.bar0_base=(void *)&toggle};
 struct hwsvideo_buffer buffer={.vb.vb2_buf={.data=destination,.size=sizeof(destination)}};
 struct hws_video v={.parent=&hw,.pix.sizeimage=16,.ring_split=8,.ring_extent=16,
  .completion_state=HWS_VIDEO_COMPLETION_COPYING,.completion_generation=10,
  .half_phase=HWS_VIDEO_PHASE_EXPECT_HALF0,.phase_generation=9,.queued=&buffer};
 v.pix.width=640; v.pix.height=480;
 v.cur_dv_timings.type=V4L2_DV_BT_656_1120;
 v.cur_dv_timings.bt=(struct v4l2_bt_timings){.width=640,.height=480,
  .hfrontporch=16,.hsync=96,.hbackporch=48,.vfrontporch=10,.vsync=2,
  .vbackporch=33,.pixelclock=25200000};
 struct hws_vdone_event e={.timestamp_ns=1000000000,.deadline_ns=7500000,.generation=10,.toggle=1};
 struct hws_vdone_copy_observation observation;
 struct hwsvideo_buffer *done; bool complete;
 memset(hw.ring,0xa0,sizeof(hw.ring)); mock_now=e.timestamp_ns+1000;
 int ret=hws_video_copy_completed_half(&v,&e,&done,&complete,&observation);
 assert(ret==0 && !done && !complete && v.frame_half0_valid);
 if(new_frame) memset(hw.ring,0xb0,sizeof(hw.ring));
 toggle=0; e.toggle=0; e.timestamp_ns+=gap; e.generation+=generation_step;
 v.completion_generation=e.generation; mock_now=e.timestamp_ns+worker_delay;
 ret=hws_video_copy_completed_half(&v,&e,&done,&complete,&observation);
 bool mixed=ret==0 && done==&buffer && complete && destination[0]!=destination[8];
 printf("{\"case\":\"%s\",\"irq_gap_ns\":%llu,\"generation_step\":%llu,\"result\":%d,\"frame_complete\":%s,\"accepted_mixed_frame\":%s}\n",
  name,(unsigned long long)gap,(unsigned long long)generation_step,ret,complete?"true":"false",mixed?"true":"false");
}
int main(void) {
 scenario("normal_adjacent_halves",8333333,1,1000,false);
 scenario("two_unobserved_boundaries",25000000,1,1000,true);
 scenario("visible_generation_gap_control",25000000,3,1000,true);
 scenario("late_worker_control",8333333,1,7500000,false);
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] / 'src/hws_irq.c')
    args = parser.parse_args()
    source = args.source.read_text()
    source_dir = args.source.resolve().parent
    helpers = ''
    if 'hws_video_frame_contiguous(' in source:
        header = (source_dir / 'hws.h').read_text()
        helpers = '\n'.join(((source_dir / 'hws_timing.h').read_text(),
                             function(header, 'hws_video_clear_frame_continuity'),
                             function(source, 'hws_video_continuity_period_ns'),
                             function(source, 'hws_video_frame_contiguous')))
    if 'hws_read_toggle(' in source:
        helpers += '''
static u8 hws_read_toggle(struct hws_pcie_dev *h, unsigned int reg)
{ return readl(h->bar0_base + reg) & 1; }
'''
    code = SHIM + '\n' + helpers + '\n' + function(source, 'hws_video_deadline_expired') + '\n' + function(source, 'hws_video_copy_completed_half') + MAIN
    with tempfile.TemporaryDirectory(prefix='hws-completion-review-') as tmp:
        path = Path(tmp)
        (path / 'review.c').write_text(code)
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', str(path / 'review.c'), '-o', str(path / 'review')], check=True)
        print(json.dumps(dict(source=str(args.source), sha256=hashlib.sha256(source.encode()).hexdigest(), scope='actual copy function; mocked hardware and accepted IRQ events')), flush=True)
        subprocess.run([str(path / 'review')], check=True)


if __name__ == '__main__': main()
