"""Headless controller safety barriers and real subprocess/UDP cleanup tests."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import hws_headless_source as headless
from hws_clock_probe import UDP_PEER, LineReader, read_udp_peer
from hws_clock_mapping import read_records, ClockMap


class HeadlessTests(unittest.TestCase):
    def args(self, output):
        return argparse.Namespace(output=Path(output), source_host='user@source',
            source_root='/source', connector=84, crtc=81, card='/dev/dri/card0',
            channel=2, frames=1000, buffers=16, allow_dirty=True, require_vblank_off=True)

    def test_failed_preflight_never_contacts_or_changes_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(Path(tmp)/'run')
            error=subprocess.CalledProcessError(1, ['preflight'])
            with patch.object(headless.subprocess,'run', side_effect=[None,error]) as run, \
                    patch.object(headless,'remote') as remote, patch.object(headless,'supervised') as source:
                with self.assertRaises(subprocess.CalledProcessError): headless.qualify(args)
            remote.assert_not_called(); source.assert_not_called()
            command=run.call_args_list[-1].args[0]
            self.assertIn('--preflight-only',command)
            self.assertIn('--queue-diagnostics',command)
            self.assertEqual(command[command.index('--device')+1],'/dev/video2')
            self.assertEqual(json.loads((args.output/'run.json').read_text())['result'],'incomplete')

    def test_changed_source_hash_never_starts_remote_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(headless.subprocess,'run'), \
                    patch.object(headless,'remote',return_value=argparse.Namespace(stdout='wrong hash\n')), \
                    patch.object(headless,'supervised') as source:
                with self.assertRaisesRegex(RuntimeError,'files differ'):
                    headless.qualify(self.args(Path(tmp)/'run'))
            source.assert_not_called()

    def test_source_identity_and_applied_mode_gate(self):
        args=self.args('/unused')
        hashes={'tools/hws_frame_id_kms.c':'source','tools/hws_frame_pattern.h':'pattern'}
        config=dict(type='source_config',backend='drm-kms',run_id='run',boot_id='boot',
            clock='CLOCK_MONOTONIC',async_flip=False,connector_id=84,crtc_id=81,
            width=1920,height=1080,clock_khz=148500,htotal=2200,vtotal=1125,
            mode_flags=5,vscan=0,source_sha256='source',pattern_sha256='pattern')
        headless.check_source_config(config,args,'run',hashes,'boot')
        for key,value in [('width',4096),('clock_khz',148352),('run_id','other'),
                ('boot_id','other'),('source_sha256','stale'),('pattern_sha256','stale'),
                ('async_flip',True),('connector_id',87),('crtc_id',82),('mode_flags',16),
                ('vscan',2),('mode_flags',1<<12)]:
            with self.subTest(key=key,value=value):
                with self.assertRaises(RuntimeError):
                    headless.check_source_config(dict(config,**{key:value}),args,'run',hashes,'boot')

    def test_receiver_requires_exact_totals_and_clock(self):
        text='Active width: 1920\nActive height: 1080\nTotal width: 2200\nTotal height: 1125\nFrame format: progressive\nPixelclock: 148500000 Hz (60.00 frames per second)\n'
        self.assertTrue(headless.receiver_1080p60(text))
        for old,new in [('1920','4096'),('148500000','148351648'),('2200','2201'),('progressive','interlaced')]:
            self.assertFalse(headless.receiver_1080p60(text.replace(old,new)))

    def test_ssh_command_preserves_argument_boundaries(self):
        import shlex
        command=['python3','/path with space/test.py',"a'b",'$HOME']
        self.assertEqual(shlex.split(headless.ssh_command('host',command)[-1]),command)

    def supervise(self, action):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            child=d/'child.py'
            child.write_text('import signal,time,sys\nfrom pathlib import Path\n'
                'd=Path(sys.argv[1])\n'
                'def stop(*a):\n (d/"restored").touch(); sys.exit(0)\n'
                'signal.signal(signal.SIGTERM,stop)\n(d/"ready").touch()\n'
                'while True: time.sleep(.02)\n')
            p=subprocess.Popen([sys.executable,'-u','-c',headless.SUPERVISOR,
                '1' if action=='deadline' else '15',sys.executable,str(child),str(d)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+3
                while not (d/'ready').exists() and time.monotonic()<deadline: time.sleep(.01)
                self.assertTrue((d/'ready').exists())
                if action=='stop': p.stdin.write(b'stop\n'); p.stdin.flush()
                if action=='eof': p.stdin.close(); p.stdin=None
                if action=='signal': p.terminate()
                status=p.wait(timeout=5)
                self.assertTrue((d/'restored').exists())
                self.assertEqual(status,0 if action=='stop' else 1)
            finally:
                if p.poll() is None: p.terminate()
                p.communicate(timeout=10)

    def test_supervisor_stop_and_connection_loss_restore(self):
        for action in ('stop','eof','signal','deadline'):
            with self.subTest(action=action): self.supervise(action)

    def test_supervisor_early_child_exit_is_not_success(self):
        p=subprocess.run([sys.executable,'-c',headless.SUPERVISOR,'3',sys.executable,'-c','pass'],
                         input=b'',capture_output=True,timeout=5)
        self.assertEqual(p.returncode,1)

    def test_capture_interrupt_uses_cleanup_handler(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker=Path(tmp)/'cleanup'
            code=('import signal,time,sys\nfrom pathlib import Path\n'
                  'def stop(*a):\n Path(sys.argv[1]).touch(); sys.exit(0)\n'
                  'signal.signal(signal.SIGINT,stop)\nprint("ready",flush=True)\n'
                  'while True: time.sleep(.01)\n')
            p=subprocess.Popen([sys.executable,'-u','-c',code,str(marker)],
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,process_group=0)
            try:
                self.assertEqual(p.stdout.readline(),b'ready\n')
                headless.stop_capture(p)
                self.assertTrue(marker.exists())
                self.assertEqual(p.returncode,0)
            finally:
                if p.poll() is None: p.terminate()
                p.communicate(timeout=3)

    def test_udp_peer_file_rejects_malformed_and_oversized(self):
        good=dict(type='hello',address='127.0.0.1',port=12345,token='a'*48,
                  host='capture',boot_id='a'*8+'-'+ 'b'*4+'-'+ 'c'*4+'-'+ 'd'*4+'-'+ 'e'*12)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'peer.json'; p.write_text(json.dumps(good))
            self.assertEqual(read_udp_peer(p),good)
            for changes in ({'port':True},{'port':65536},{'token':'bad'}, {'address':'not-an-ip'}, {'boot_id':''}):
                p.write_text(json.dumps(dict(good,**changes)))
                with self.assertRaises(ValueError): read_udp_peer(p)
            p.write_text(' '*16385)
            with self.assertRaises(ValueError): read_udp_peer(p)

    def test_external_udp_peer_preserves_clock_domains_without_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            peer=subprocess.Popen([sys.executable,'-u','-c',UDP_PEER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                env=dict(os.environ,SSH_CONNECTION='127.0.0.1 1 127.0.0.1 2'))
            reader=LineReader(peer.stdout)
            try:
                hello,_=reader.read(3)
                (d/'peer.json').write_text(json.dumps(hello))
                # No ssh executable on PATH: only the provided UDP endpoint.
                result=subprocess.run([sys.executable,str(headless.ROOT/'tools/hws_clock_probe.py'),
                    '--udp-peer-file',str(d/'peer.json'),'--seconds','1','--hz','30',
                    '--run-id','test','--output',str(d/'clock.jsonl')],
                    env=dict(os.environ,PATH=tmp),capture_output=True,text=True,timeout=8)
                self.assertEqual(result.returncode,0,result.stderr+result.stdout)
                records=read_records(d/'clock.jsonl'); config=records[0]
                mapping=ClockMap(records,config['source_boot_id'],hello['boot_id'],'test')
                self.assertEqual(mapping.report()['result'],'pass')
                for row in records[1:-1]:
                    self.assertLess(row['s1_ns'],row['f2_ns'])
                    self.assertLess(row['f3_ns'],row['s4_ns'])
            finally:
                peer.stdin.close(); peer.stdin=None
                peer.communicate(timeout=5)
                reader.selector.close()


if __name__=='__main__': unittest.main()
