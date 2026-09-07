"""Selected production restart/monitor bodies; modeled MMIO, not kernel races."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest
from test_audio_lifetime import function

ROOT = Path(__file__).resolve().parents[1]


def generate():
    pci = (ROOT/'src/hws_pci.c').read_text()
    video = (ROOT/'src/hws_video.c').read_text()
    audio = (ROOT/'src/hws_audio.c').read_text()
    code = (ROOT/'tools/hws_transition_test_shim.h').read_text()
    for name in ('HWS_BUSY_POLL_DELAY_US', 'HWS_DMA_IDLE_GRACE_US'):
        code += '\n' + re.search(r'^#define '+name+r' .*$', pci, re.M)[0]
    for src, names in ((pci, ('hws_poll_dma_idle', '__hws_wait_dma_idle', 'hws_try_wait_dma_idle')),
                       (video, ('hws_video_reclaim_ring', 'hws_video_update_source_state', 'hws_video_fail_queue')),
                       (audio, ('hws_audio_reclaim_scratch_locked',))):
        code += '\n' + '\n'.join(function(src, n) for n in names)
    return code + (ROOT/'tools/test_hws_transitions.c').read_text()


class TransitionTests(unittest.TestCase):
    def compile_run(self, code, mutation=False):
        with tempfile.TemporaryDirectory(prefix='hws-transitions-') as tmp:
            path = Path(tmp)
            (path/'test.c').write_text(code)
            flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                     '-Wno-unused-parameter', '-Wno-unused-variable', '-Wno-unused-function']
            if os.environ.get('HWS_TRANSITION_SANITIZE') == '1':
                flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            subprocess.run(['cc', *flags, str(path/'test.c'), '-o', str(path/'test')], check=True)
            result = subprocess.run([str(path/'test')], capture_output=mutation, timeout=30)
            if mutation:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'Assertion', result.stderr)
            else:
                self.assertEqual(result.returncode, 0)

    def test_restart_and_notification_contract(self):
        self.compile_run(generate())

    def test_negative_controls(self):
        code = generate()
        for old, new in (
            ('__hws_wait_dma_idle(hws, owner, ch, false)', '__hws_wait_dma_idle(hws, owner, ch, true)'),
            ('ret = hws_poll_dma_idle(hws, HWS_DMA_IDLE_GRACE_US, &status);', 'ret = 0;'),
            ('notify = changed || v->source_change_pending;', 'notify = changed;'),
            ('if (changed && READ_ONCE(v->cap_active)) {', 'if (READ_ONCE(v->cap_active)) {'),
            ('return ret == -ETIMEDOUT ? -EBUSY : ret;', 'return 0;'),
        ):
            with self.subTest(mutation=old):
                self.assertIn(old, code)
                self.compile_run(code.replace(old,new), mutation=True)


if __name__ == '__main__':
    unittest.main()
