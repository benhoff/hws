"""Compile selected production audio lifecycle bodies against a pthread model.

Only explicit pause hooks are inserted into delivery; hardware/ALSA/workqueue
operations are mocks. No claim about actual kernel concurrency or DMA safety.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    import re
    match = re.search(r'^(?:static\s+)?(?:inline\s+)?(?:void|bool|int)\s*\n?'+name+r'\([^;{}]*\)\s*\{', source, re.M)
    if not match:
        raise ValueError(f'missing production function {name}')
    start = source.index('{', match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def generate():
    source = (ROOT/'src/hws_audio.c').read_text()
    names = ['hws_audio_reset_ring_state', 'hws_audio_reset_counters',
             'hws_audio_clear_pending', 'hws_audio_reset_runtime_state',
             'hws_audio_publish_stopped', 'hws_audio_drain_channel_work',
             'hws_audio_quiesce_capture', 'hws_audio_report_xrun',
             'hws_audio_deliver_packet', 'hws_pcie_audio_release_stream',
             'hws_pcie_audio_close', 'hws_pcie_audio_hw_free',
             'hws_audio_queue_work', 'hws_audio_dma_fault_all']
    names += ['hws_audio_discard_stale_done', 'hws_start_audio_capture',
              'hws_stop_audio_capture', 'hws_pcie_audio_prepare', 'hws_pcie_audio_trigger']
    # sync_stop must precede prepare in this selected-function translation unit.
    if 'static int hws_pcie_audio_sync_stop(' in source:
        names.insert(names.index('hws_pcie_audio_prepare'), 'hws_pcie_audio_sync_stop')
    header = (ROOT/'src/hws.h').read_text()
    decl = header[header.index('enum hws_audio_packet_state {'):header.index('struct hws_scratch_dma {')]
    bodies = '\n'.join(function(source, name) for name in names)
    bodies += '\n' + function((ROOT/'src/hws_pci.c').read_text(), 'hws_release_irq')
    anchor = '\trt = ss->runtime;'
    assert bodies.count(anchor) == 1
    bodies = bodies.replace(anchor, anchor+'\n\tpause_worker(0);')
    return (ROOT/'tools/hws_audio_lifetime_shim.h').read_text() + decl + '\n' + \
        (ROOT/'tools/hws_audio_lifetime_mocks.h').read_text() + bodies + '\n' + \
        (ROOT/'tools/test_hws_audio_lifetime.c').read_text()


class AudioLifetimeTests(unittest.TestCase):
    def test_paused_worker_lifetime(self):
        with tempfile.TemporaryDirectory(prefix='hws-audio-lifetime-') as tmp:
            path = Path(tmp)
            (path/'test.c').write_text(generate())
            flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread', '-g', '-O1']
            if os.environ.get('HWS_AUDIO_SANITIZE') == '1':
                flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            subprocess.run(['cc', *flags, str(path/'test.c'), '-o', str(path/'test')], check=True)
            subprocess.run([str(path/'test')], check=True, timeout=30)

    def test_missing_drain_is_detected(self):
        code = generate()
        anchor = 'cancel_work_sync(&a->deliver_work);'
        self.assertEqual(code.count(anchor), 1)
        with tempfile.TemporaryDirectory(prefix='hws-audio-mutation-') as tmp:
            path = Path(tmp)
            (path/'test.c').write_text(code.replace(anchor, '(void)a; /* mutation */'))
            subprocess.run(['cc', '-std=gnu11', '-pthread', '-O1', str(path/'test.c'),
                            '-o', str(path/'test')], check=True)
            result = subprocess.run([str(path/'test')], capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'!released', result.stderr)

    def test_callback_wiring_and_nonblocking_trigger(self):
        source = (ROOT/'src/hws_audio.c').read_text()
        self.assertIn('.sync_stop = hws_pcie_audio_sync_stop,', source)
        for name in ('hws_pcie_audio_prepare', 'hws_pcie_audio_hw_params'):
            self.assertIn('hws_pcie_audio_sync_stop(substream);', function(source, name))
        for name in ('hws_pcie_audio_trigger', 'hws_stop_audio_capture', 'hws_audio_report_xrun'):
            body = function(source, name)
            for blocking in ('cancel_work_sync(', 'synchronize_irq(', 'mutex_lock(',
                             'hws_pcie_audio_sync_stop(', 'hws_audio_quiesce_capture('):
                self.assertNotIn(blocking, body)


if __name__ == '__main__':
    unittest.main()
