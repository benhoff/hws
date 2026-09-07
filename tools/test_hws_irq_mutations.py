"""Oracle sensitivity checks: mutations affect only disposable generated code."""
import os
from pathlib import Path
import resource
import shlex
import subprocess
import tempfile
import unittest

from build_hws_irq_test import generate

TOOLS = Path(__file__).resolve().parent


def no_core_dump():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class MutationTests(unittest.TestCase):
    def test_assertions_detect_half_duplicate_ownership_and_continuity_faults(self):
        original = generate()
        mutations = [
            ('late diagnostic mutates selected half',
             'p.count++;', 'p.count++; v->last_buf_half_toggle = p.toggle[i] & 1;'),
            ('late diagnostic exceeds window budget',
             'if (v->late_toggle_windows >= HWS_LATE_TOGGLE_WINDOWS) {', 'if (false) {'),
            ('removed source precheck',
             'if (!hws_video_check_source(v))\n\t\treturn;\n\tret = hws_video_copy_completed_half',
             'ret = hws_video_copy_completed_half'),
            ('removed source postcheck',
             'if (!hws_video_check_source(v))\n\t\treturn;\n\tspin_lock_irqsave',
             'spin_lock_irqsave'),
            ('removed continuity guard', 'return first && period && v->frame_epoch',
             'return true; /* MUTATION */ return first && period && v->frame_epoch'),
            ('wrong half', 'u8 completed_half = event->toggle ^ 1;',
             'u8 completed_half = event->toggle;'),
            ('ignored duplicate', 'toggle == v->last_buf_half_toggle)', 'false)'),
            ('double-owned buffer', 'v->active = NULL;\n\tv->frame_generation = 0;',
             '/* MUTATION: retained active pointer after recycling */\n\tv->frame_generation = 0;'),
        ]
        for name, old, new in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='hws-irq-mutation.') as tmp:
                self.assertEqual(original.count(old), 1, 'production code changed; update explicit mutation anchor')
                header = Path(tmp) / 'mutated.h'
                header.write_text(original.replace(old, new))
                binary = Path(tmp) / 'test'
                compile_run = subprocess.run([
                    *shlex.split(os.environ.get('CC', 'cc')), '-std=c11', '-O1', '-I', str(TOOLS),
                    f'-DHWS_IRQ_UNDER_TEST="{header}"', str(TOOLS / 'test_hws_irq.c'), '-o', str(binary)],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(compile_run.returncode, 0, compile_run.stderr)
                run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30,
                                     preexec_fn=no_core_dump)
                self.assertEqual(run.returncode, -6, run.stdout + run.stderr)
                self.assertIn('Assertion', run.stderr)


if __name__ == '__main__':
    unittest.main()
