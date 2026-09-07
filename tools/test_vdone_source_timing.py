"""DRM callback receipt and scanout timestamps have distinct epochs."""
import unittest

from hws_vdone_observers import validate_source
from test_vdone_observers import source_fixture, CONFIG


class SourceTimestampTests(unittest.TestCase):
    def test_callbacks_within_vblank_can_precede_scanout(self):
        records, frames = source_fixture()
        for r in records[1:]: r['callback_ns'] = r['presented_ns'] - 642587
        result, failures = validate_source(records, frames, CONFIG, 'boot')
        self.assertEqual(failures, [])
        self.assertEqual(result['callback_timing']['blanking_ns'], 666667)
        self.assertEqual(result['callback_timing']['before_scanout_count'], len(records)-1)
        self.assertEqual(result['callback_timing']['minimum_callback_minus_scanout_ns'], -642587)

    def test_mode_derived_limit_is_enforced_at_boundary(self):
        for early, passes in ((667667, True), (667668, False), (16666667, False)):
            with self.subTest(early=early):
                records, frames = source_fixture()
                records[1]['submitted_ns'] = records[1]['presented_ns'] - 20000000
                records[1]['callback_ns'] = records[1]['presented_ns'] - early
                result, failures = validate_source(records, frames, CONFIG, 'boot')
                self.assertEqual(result['result'] == 'pass', passes)
                self.assertEqual(bool(failures), not passes)

    def test_limit_comes_from_mode_not_a_fixed_one_ms_allowance(self):
        records, frames = source_fixture()
        config = dict(CONFIG, vtotal='1090')
        records[0]['vtotal'] = 1090
        records[1]['callback_ns'] = records[1]['presented_ns'] - 200000
        result, failures = validate_source(records, frames, config, 'boot')
        self.assertEqual(result['callback_timing']['blanking_ns'], 148149)
        self.assertEqual(result['callback_timing']['invalid_records'], 1)
        self.assertIn('invalid source submission/presentation/callback timestamps', failures)

    def test_submission_must_precede_both_callback_and_scanout(self):
        for key in ('callback_ns', 'presented_ns'):
            with self.subTest(key=key):
                records, frames = source_fixture()
                records[1][key] = records[1]['submitted_ns'] - 1
                result, failures = validate_source(records, frames, CONFIG, 'boot')
                self.assertEqual(result['callback_timing']['invalid_records'], 1)
                self.assertIn('invalid source submission/presentation/callback timestamps', failures)

    def test_frozen_counter_still_fails_with_valid_early_callbacks(self):
        records, frames = source_fixture()
        for r in records[1:]:
            r['callback_ns'] = r['presented_ns'] - 500000
            r['sequence'] = 0
        result, failures = validate_source(records, frames, CONFIG, 'boot')
        self.assertEqual(result['callback_timing']['invalid_records'], 0)
        self.assertEqual(result['result'], 'fail')
        self.assertIn('source presentation IDs, sequences, or timestamps are not ordered', failures)


if __name__ == '__main__': unittest.main()
