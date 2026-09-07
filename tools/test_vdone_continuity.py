"""Permanent copy-level regression; hardware and accepted IRQ events are mocked."""
import errno
import json
from pathlib import Path
import subprocess
import sys
import unittest


class ContinuityTests(unittest.TestCase):
    def test_saved_half_rejects_missed_boundaries(self):
        script = Path(__file__).with_name('review_completion_gap.py')
        result = subprocess.run([sys.executable, str(script)], check=True,
                                capture_output=True, text=True, timeout=30)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        cases = {row['case']: row for row in rows if 'case' in row}
        expected = {'normal_adjacent_halves': 0,
                    'two_unobserved_boundaries': -errno.ESTALE,
                    'visible_generation_gap_control': -errno.EILSEQ,
                    'late_worker_control': -errno.ETIME}
        self.assertEqual(set(cases), set(expected))
        for name, code in expected.items():
            with self.subTest(case=name):
                self.assertEqual(cases[name]['result'], code)
                self.assertFalse(cases[name]['accepted_mixed_frame'])
                self.assertEqual(cases[name]['frame_complete'], code == 0)


if __name__ == '__main__':
    unittest.main()
