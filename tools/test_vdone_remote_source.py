"""External-source options must reach both remote preflight and capture."""
import json
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import hws_remote_source as source
from hws_remote_source import argument_parser, capture_command, CAPTURE_BOOTSTRAP


class RemoteSourceTests(unittest.TestCase):
    def test_video3_comparison_options_reach_both_capture_phases(self):
        args = argument_parser().parse_args([
            '--run', '--channel', '3', '--frames', '1000', '--buffers', '16',
            '--queue-diagnostics', '--probe-mode', 'full', '--require-vblank-off',
            '--allow-dirty', '--output', '/unused'])
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            runner = directory / 'runner.py'
            runner.write_text(
                'import json,sys\nfrom pathlib import Path\n'
                'd=Path(sys.argv[1]); phase="preflight" if "--preflight-only" in sys.argv else "capture"\n'
                '(d/(phase+".json")).write_text(json.dumps(sys.argv[2:]))\n')
            command = capture_command(args, 'test-run', tmp)
            (directory / 'source-ready').touch()
            subprocess.run([sys.executable, '-c', CAPTURE_BOOTSTRAP, tmp,
                            sys.executable, str(runner), tmp, *command[2:]],
                           check=True, capture_output=True, timeout=5)
            for phase in ('preflight', 'capture'):
                recorded = json.loads((directory / (phase + '.json')).read_text())
                for flag, value in (('--device', '/dev/video3'), ('--channel', '3'),
                                    ('--frames', '1000'), ('--buffers', '16'),
                                    ('--probe-mode', 'full'), ('--run-id', 'test-run'),
                                    ('--clock-evidence', tmp + '/clock.jsonl'),
                                    ('--source-telemetry', tmp + '/source.jsonl')):
                    self.assertEqual(recorded[recorded.index(flag) + 1], value)
                for flag in ('--queue-diagnostics', '--require-vblank-off', '--allow-dirty'):
                    self.assertIn(flag, recorded)
                self.assertEqual('--preflight-only' in recorded, phase == 'preflight')
                self.assertNotIn('--requeue-delay-ms', recorded)

    def test_existing_default_profile_is_preserved(self):
        args = argument_parser().parse_args(['--output', '/unused'])
        command = capture_command(args, 'run', '/remote')
        for flag, value in (('--device', '/dev/video2'), ('--buffers', '4'), ('--probe-mode', 'full')):
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertNotIn('--queue-diagnostics', command)
        self.assertNotIn('--require-vblank-off', command)
        self.assertNotIn('--allow-dirty', command)

    def test_reduced_probe_profile_requires_explicit_option(self):
        args = argument_parser().parse_args(['--probe-mode', 'off', '--output', '/unused'])
        command = capture_command(args, 'run', '/remote')
        self.assertEqual(command[command.index('--probe-mode') + 1], 'off')


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.args = argument_parser().parse_args([
            '--run', '--runs', '2', '--channel', '2', '--frames', '1000', '--buffers', '16',
            '--queue-diagnostics', '--require-vblank-off', '--allow-dirty', '--output', '/unused'])
        self.info = dict(run_id='trial', remote_bundle='/bundle', source_hashes={
            'tools/hws_frame_id_kms.c': 'source', 'tools/hws_frame_pattern.h': 'pattern'})
        provenance = ['driver evidence was captured from a dirty tracked tree',
                      'evidence inputs were not committed at capture time']
        self.report = dict(
            manifest=dict(run_id='trial', channel=2, buffers_requested=16, probe_mode='full',
                          queue_diagnostics=True, requeue_delay_ms=0, nvidia_vblank='N',
                          loaded_srcversion='module', module_srcversion='module',
                          kms_source_sha256='source', pattern_sha256='pattern', module_sha256='binary',
                          capture_tool_sha256='capture', evidence_runner_sha256='runner',
                          observer_validator_sha256='observer', boot_id='boot'),
            summary=dict(run_id='trial', channel=2, captured_frames=1000, result='fail',
                         capture_checks=dict(result='pass', failures=[]),
                         independent_mapping=dict(result='pass'),
                         source_presentation=dict(result='pass', clock_mapping=dict(result='pass')),
                         anomaly_observation=dict(result='pass'), presentation_failures=[],
                         frame_id_summary=dict(captured=1000, valid=1000, result='pass', repeated_ids=0),
                         provenance=dict(result='fail', failures=provenance), failures=provenance[:]),
            diagnostics=dict(evidence_status='complete', failures=[],
                             late_toggle=dict(enabled='Y', evidence_status='not_observed', failures=[])),
            stats={k: '0' for k in ('diag_suppressed', 'anomaly_suppressed', 'late_toggle_suppressed',
                                   'vdone_fatal', 'queue_failures', 'guard_errors', 'ring_corrupt',
                                   'duplicate_recoveries', 'duplicate_reports', 'vdone_recovered', 'frames_no_buffer')})

    def assess(self, report=None, code=1):
        return source.assess_trial(self.args, self.info, report or self.report, code)

    def test_dirty_only_is_diagnostic_pass_and_preserves_strict_failure(self):
        row = self.assess()
        self.assertEqual(row['strict_result'], 'fail')
        self.assertEqual(row['diagnostic_result'], 'pass')
        self.assertEqual(len(row['provenance_failures']), 2)
        self.args.allow_dirty = False
        with self.assertRaises(RuntimeError):
            self.assess()

    def test_unknown_failure_never_gets_treated_as_dirty_provenance(self):
        self.report['summary']['failures'].append('frame content mismatch')
        with self.assertRaises(RuntimeError):
            self.assess()

    def test_strict_pass_requires_successful_process(self):
        self.report['summary'].update(result='pass', failures=[], provenance=dict(result='pass', failures=[]))
        self.assertEqual(self.assess(code=0)['strict_result'], 'pass')
        with self.assertRaises(RuntimeError):
            self.assess(code=1)

    def test_incomplete_identity_counts_timing_or_diagnostics_stop(self):
        changes = [
            ('manifest', 'run_id', 'other'), ('manifest', 'loaded_srcversion', 'other'),
            ('manifest', 'buffers_requested', 4), ('manifest', 'kms_source_sha256', 'other'),
            ('manifest', 'nvidia_vblank', 'Y'), ('summary', 'captured_frames', 999),
            ('summary', 'capture_checks', dict(result='fail', failures=['bad data'])),
            ('summary', 'source_presentation', dict(result='pass', clock_mapping=dict(result='inconclusive'))),
            ('diagnostics', 'evidence_status', 'inconclusive'),
            ('diagnostics', 'late_toggle', dict(enabled='Y', evidence_status='capped', failures=[])),
            ('stats', 'diag_suppressed', '1'), ('stats', 'vdone_fatal', '1'),
        ]
        for section, key, value in changes:
            with self.subTest(section=section, key=key):
                report = copy.deepcopy(self.report)
                report[section][key] = value
                with self.assertRaises(RuntimeError):
                    self.assess(report)

    def test_observed_duplicate_with_complete_evidence_is_counted(self):
        self.report['stats'].update(duplicate_recoveries='12', duplicate_reports='2', vdone_recovered='2')
        self.report['diagnostics']['late_toggle']['evidence_status'] = 'complete'
        row = self.assess()
        self.assertEqual(row['duplicate_toggles'], 2)

    def batch(self, reports=None, run_error=None):
        with tempfile.TemporaryDirectory() as tmp:
            self.args.output = Path(tmp) / 'batch'
            def run(args):
                args.output.mkdir()
                (args.output / 'run.json').write_text(json.dumps(self.info))
                if run_error:
                    raise run_error
                return 1
            with patch.object(source, 'run_once', side_effect=run) as run_mock, \
                    patch.object(source, 'fetch_report', side_effect=reports or [self.report, self.report]):
                code = source.run_batch(self.args)
            return code, json.loads((self.args.output / 'batch.json').read_text()), run_mock.call_count

    def test_batch_counts_duplicates_across_separate_trials(self):
        self.report['stats'].update(duplicate_recoveries='12', duplicate_reports='2', vdone_recovered='2')
        self.report['diagnostics']['late_toggle']['evidence_status'] = 'complete'
        code, batch, calls = self.batch()
        self.assertEqual((code, calls, batch['captured_frames'], batch['duplicate_toggles']), (0, 2, 2000, 4))
        self.assertEqual(batch['result'], 'diagnostic_complete')
        self.assertTrue(all(t['strict_result'] == 'fail' for t in batch['trials']))

    def test_failed_validation_never_starts_next_trial(self):
        self.report['summary']['frame_id_summary']['valid'] = 999
        code, batch, calls = self.batch()
        self.assertEqual((code, calls, batch['completed_runs']), (1, 1, 0))
        self.assertEqual(batch['result'], 'stopped')

    def test_report_read_failure_stops_batch(self):
        code, batch, calls = self.batch(reports=[RuntimeError('checksum mismatch')])
        self.assertEqual((code, calls), (1, 1))
        self.assertIn('checksum mismatch', batch['error'])

    def test_changed_module_is_not_combined_with_previous_trial(self):
        second = copy.deepcopy(self.report)
        second['manifest']['module_sha256'] = 'changed'
        code, batch, calls = self.batch(reports=[self.report, second])
        self.assertEqual((code, calls, batch['completed_runs']), (1, 2, 1))
        self.assertIn('changed between trials', batch['error'])

    def test_interruption_is_recorded_without_starting_next_trial(self):
        code, batch, calls = self.batch(run_error=KeyboardInterrupt())
        self.assertEqual((code, calls), (130, 1))
        self.assertEqual(batch['result'], 'interrupted')


if __name__ == '__main__':
    unittest.main()
