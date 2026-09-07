#!/usr/bin/env python3
"""Compare actual G_PARM code with the DV timings table, using a mock receiver.

No devices are opened. The receiver returns each table entry's integer hardware
rate in turn. Both the mode table and G_PARM implementation are extracted from
the checked-out C source, rather than reimplemented in Python.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


SHIM = r'''
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/videodev2.h>
#include <linux/v4l2-dv-timings.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define U32_MAX UINT32_MAX
#define div64_u64(a,b) ((u64)(a)/(u64)(b))
struct hws_dv_mode { struct v4l2_dv_timings timings; u32 refresh_hz; };
struct hws_video { u32 current_fps; struct v4l2_dv_timings timings; };
struct file { struct hws_video *video; };
#define video_drvdata(f) ((f)->video)
static int hws_detect_dv_timings(struct hws_video *v,struct v4l2_dv_timings *t,u32 *fps) {
 *t=v->timings; if(fps) *fps=v->current_fps; return 0;
}
'''

MAIN = r'''
int main(void) {
 puts("width,height,pixelclock,htotal,vtotal,dv_refresh_hz,g_parm_refresh_hz,difference_ppm");
 for(size_t i=0;i<sizeof(hws_dv_modes)/sizeof(hws_dv_modes[0]);i++) {
  const struct hws_dv_mode *m=&hws_dv_modes[i];
  const struct v4l2_bt_timings *b=&m->timings.bt;
  unsigned int ht=b->width+b->hfrontporch+b->hsync+b->hbackporch;
  unsigned int vt=b->height+b->vfrontporch+b->vsync+b->vbackporch;
  struct hws_video v={.current_fps=m->refresh_hz,.timings=m->timings}; struct file f={.video=&v};
  struct v4l2_streamparm p={.type=V4L2_BUF_TYPE_VIDEO_CAPTURE};
  if(hws_vidioc_g_parm(&f,NULL,&p)) return 1;
  double actual=(double)b->pixelclock/ht/vt;
  double reported=(double)p.parm.capture.timeperframe.denominator/p.parm.capture.timeperframe.numerator;
  printf("%u,%u,%llu,%u,%u,%.9f,%.9f,%.3f\n",b->width,b->height,
   (unsigned long long)b->pixelclock,ht,vt,actual,reported,(reported/actual-1)*1000000);
 }
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] / 'src/hws_v4l2_ioctl.c')
    args = parser.parse_args()
    source = args.source.read_text()
    start = source.index('static const struct hws_dv_mode hws_dv_modes[]')
    table = source[start:source.index('\n};', start) + 3]
    start = source.index('int hws_vidioc_g_parm(')
    code = source[start:source.index('\nint hws_vidioc_enum_input(', start)]
    with tempfile.TemporaryDirectory(prefix='hws-timing-review-') as tmp:
        path = Path(tmp)
        helper = args.source.parent / 'hws_timing.h'
        timing = helper.read_text() if 'hws_dv_frame_period(' in code else ''
        (path / 'review.c').write_text(SHIM + timing + table + '\n' + code + MAIN)
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Wno-unused-parameter', '-Werror', str(path / 'review.c'), '-o', str(path / 'review')], check=True)
        print(json.dumps(dict(source=str(args.source), sha256=hashlib.sha256(source.encode()).hexdigest(), scope='actual mode table and G_PARM; mock receiver')), flush=True)
        subprocess.run([str(path / 'review')], check=True)


if __name__ == '__main__': main()
