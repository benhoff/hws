"""Permission-aware preflight and the remote display-takeover barrier."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import hws_vdone_evidence as evidence
from hws_remote_source import CAPTURE_BOOTSTRAP


class PreflightTests(unittest.TestCase):
    def test_root_only_debugfs_uses_privileged_reads(self):
        paths = [Path('/root-only/config'), Path('/root-only/stats')]
        with patch.object(Path, 'exists', side_effect=PermissionError), patch.object(
                evidence, 'sudo', return_value=subprocess.CompletedProcess([], 0, 'ok', '')) as sudo:
            evidence.check_driver_evidence(*paths)
        self.assertEqual([c.args[0] for c in sudo.call_args_list],
                         [['cat', str(p)] for p in paths])

    def test_debugfs_read_error_retains_actual_reason(self):
        for reason in ('No such file or directory', 'sudo: a password is required', 'Input/output error'):
            with self.subTest(reason=reason), patch.object(evidence, 'sudo', return_value=
                    subprocess.CompletedProcess([], 1, '', reason)):
                with self.assertRaisesRegex(evidence.EvidenceError, reason):
                    evidence.check_driver_evidence(Path('/config'), Path('/stats'))

    def test_tracefs_fallback_checks_interface_with_sudo(self):
        replies = [subprocess.CompletedProcess([], 1, '', 'absent'),
                   subprocess.CompletedProcess([], 0, 'nop', '')]
        with patch.object(Path, 'exists', side_effect=PermissionError), patch.object(
                evidence, 'sudo', side_effect=replies):
            self.assertEqual(evidence.tracefs_path(), Path('/sys/kernel/debug/tracing'))
        with patch.object(evidence, 'sudo', return_value=replies[0]):
            with self.assertRaises(evidence.EvidenceError): evidence.tracefs_path()

    def test_preflight_returns_before_capture_or_timing_changes(self):
        args = evidence.parser().parse_args(['--preflight-only', '--allow-dirty', '--channel', '2'])
        def command(argv, **kwargs):
            self.assertIn(argv[0], ('sudo', 'modinfo'))
            return subprocess.CompletedProcess(argv, 0, 'test-srcversion', '')
        with patch.object(evidence, 'require_command'), patch.object(evidence.os, 'geteuid', return_value=1000), \
                patch.object(evidence.os, 'access', return_value=True), \
                patch.object(Path, 'exists', return_value=True), patch.object(Path, 'is_file', return_value=True), \
                patch.object(Path, 'read_text', return_value='test-srcversion'), \
                patch.object(Path, 'mkdir', side_effect=AssertionError('must not create a bundle')), \
                patch.object(evidence, 'tracked_status', return_value=[]), \
                patch.object(evidence, 'untracked_reproducible_inputs', return_value=[]), \
                patch.object(evidence, 'find_video_channel', return_value=(2, 'video2')), \
                patch.object(evidence, 'find_pci_bdf', return_value='0000:17:00.0'), \
                patch.object(evidence, 'check_driver_evidence'), \
                patch.object(evidence, 'tracefs_path', return_value=Path('/tracefs')), \
                patch.object(evidence, 'ensure_trace_idle'), patch.object(evidence, 'run', side_effect=command):
            self.assertEqual(evidence.run_capture(args), 0)

    def test_remote_preflight_failure_never_releases_display_barrier(self):
        for succeeds in (False, True):
            with self.subTest(succeeds=succeeds), tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                runner = d / 'runner.py'
                runner.write_text('import sys\nfrom pathlib import Path\n'
                    'd=Path(sys.argv[1]); preflight="--preflight-only" in sys.argv\n'
                    '(d/("checked" if preflight else "captured")).touch()\n'
                    f'sys.exit(0 if {succeeds!r} or not preflight else 2)\n')
                (d / 'source-ready').touch()
                result = subprocess.run([sys.executable, '-c', CAPTURE_BOOTSTRAP, tmp,
                                         sys.executable, str(runner), tmp], capture_output=True, timeout=5)
                self.assertTrue((d / 'checked').exists())
                self.assertEqual((d / 'auth-ready').exists(), succeeds)
                self.assertEqual((d / 'captured').exists(), succeeds)
                self.assertEqual(result.returncode == 0, succeeds)


if __name__ == '__main__': unittest.main()
