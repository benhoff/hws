#!/usr/bin/env python3
"""Build-only adapter: compile production IRQ bodies, never a copied state machine.

Only kernel includes are replaced. The video's actual declarations and inline
layout helpers are extracted from hws.h; unrelated PCI/ALSA types are shimmed.
Generated output is disposable and must not be edited or used by a kernel build.
"""
from pathlib import Path
import re
import sys
from test_audio_lifetime import function

ROOT = Path(__file__).resolve().parents[1]


def segment(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError(f"production declaration boundaries changed: {start!r}, {end!r}")
    first = text.index(start)
    return text[first:text.index(end, first)]


def without_includes(text):
    return re.sub(r'^#include[^\n]*$', '', text, flags=re.M)


def generate():
    h = (ROOT / 'src/hws.h').read_text()
    parts = ['/* Generated from current production sources. DO NOT EDIT. */',
             '#include "hws_irq_test_shim.h"']
    for name in ('hws_reg.h', 'hws_probe.h', 'hws_late_toggle.h'):
        parts += [f'#line 1 "../src/{name}"', without_includes((ROOT / 'src' / name).read_text())]
    start = 'struct hws_pix_state {'
    parts += [f'#line {h[:h.index(start)].count(chr(10))+1} "../src/hws.h"',
              segment(h, start, 'enum hws_audio_packet_state {'),
              segment(h, 'enum hws_audio_xrun_reason {', 'struct hws_audio {'),
              '#include "hws_irq_test_api.h"',
              without_includes((ROOT / 'src/hws_fault.h').read_text()),
              without_includes((ROOT / 'src/hws_timing.h').read_text()),
              without_includes((ROOT / 'src/hws_source.h').read_text()),
              '#line 1 "../src/hws_irq.c"',
              without_includes((ROOT / 'src/hws_irq.c').read_text()),
              function((ROOT / 'src/hws_video.c').read_text(), 'hws_video_reset_evidence_locked')]
    return '\n'.join(parts)


if __name__ == '__main__':
    Path(sys.argv[1]).write_text(generate())
