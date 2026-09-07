"""Compile production failure/ownership functions against a pthread model.

Tests scheduling, cancellation and ordering, not Linux scheduling or PCI physics.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from test_audio_lifetime import function

ROOT = Path(__file__).resolve().parents[1]


def generate():
    pci = (ROOT / 'src/hws_pci.c').read_text()
    video = (ROOT / 'src/hws_video.c').read_text()
    bodies = function(pci, 'hws_publish_stop_flags')
    for name in ('hws_video_collect_done_locked', 'hws_video_device_error'):
        bodies += '\n' + function(video, name)
    for name in ('hws_failure_work', 'hws_device_lost',
                 'hws_failure_enable', 'hws_failure_cancel'):
        bodies += '\n' + function(pci, name)
    return (ROOT / 'tools/hws_failure_test_shim.h').read_text() + bodies + \
        (ROOT / 'tools/test_hws_failure.c').read_text()


class DeviceFailureTests(unittest.TestCase):
    def test_production_failure_transaction(self):
        with tempfile.TemporaryDirectory(prefix='hws-device-failure-') as tmp:
            path = Path(tmp)
            (path / 'test.c').write_text(generate())
            flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread', '-O1', '-g']
            if os.environ.get('HWS_FAILURE_SANITIZE') == '1':
                flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            subprocess.run(['cc', *flags, str(path/'test.c'), '-o', str(path/'test')], check=True)
            subprocess.run([str(path/'test')], check=True, timeout=30)

    def test_lifecycle_wiring(self):
        pci = (ROOT / 'src/hws_pci.c').read_text()
        probe = function(pci, 'hws_probe')
        self.assertLess(probe.index('hws_video_register(hws)'), probe.index('hws_failure_enable(hws)'))
        for label in ('err_stop_private:', 'err_unwind_channels:'):
            tail = probe.split(label)[1]
            self.assertLess(tail.index('hws_failure_cancel(hws)'), tail.index('hws_free_seed_buffers(hws)'))
        transition = function(pci, 'hws_quiesce_for_transition')
        self.assertLess(transition.index('hws_failure_cancel(hws)'), transition.index('hws_block_hotpaths(hws)'))
        for name in ('hws_remove', 'hws_pm_suspend', 'hws_shutdown'):
            self.assertIn('hws_quiesce_for_transition(', function(pci, name))
        restart = function(pci, 'hws_restart_quiesced_core')
        self.assertIn('if (hws->failure_latched)', restart)
        self.assertLess(restart.index('if (hws->failure_latched)'), restart.index('WRITE_ONCE(hws->pci_lost, false)'))
        worker = function(pci, 'hws_failure_work')
        for forbidden in ('hws_poll_dma_idle', 'dma_free', 'hws_failure_cancel', 'hws_quiesce_for_transition'):
            self.assertNotIn(forbidden, worker)

    def test_missing_drain_and_false_isolation_are_detected(self):
        original = generate()
        mutations = {
            'missing-copy-drain': ('hws_video_drain_work(hws);', '(void)hws;'),
            'false-isolation': ('WRITE_ONCE(hws->dma_quiesced, !ret);',
                                'WRITE_ONCE(hws->dma_quiesced, true);'),
        }
        for name, (before, after) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='hws-failure-mutation-') as tmp:
                self.assertEqual(original.count(before), 1)
                path = Path(tmp)
                (path/'test.c').write_text(original.replace(before, after))
                subprocess.run(['cc', '-std=gnu11', '-pthread', '-O1', str(path/'test.c'),
                                '-o', str(path/'test')], check=True)
                result = subprocess.run([str(path/'test')], capture_output=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'Assertion', result.stderr)


if __name__ == '__main__':
    unittest.main()
