#!/usr/bin/env python3
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

from hws_clock_probe import PEER, UDP_PEER, LineReader
from hws_remote_source import configured_output, SEAT_HELPER


class PeerTests(unittest.TestCase):
    def peer(self, code):
        env = dict(os.environ, SSH_CONNECTION="127.0.0.1 1234 127.0.0.1 22")
        p = subprocess.Popen([sys.executable, "-u", "-c", code], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.addCleanup(self.finish, p)
        reader = LineReader(p.stdout)
        self.addCleanup(reader.selector.close)
        return p, reader

    def finish(self, p):
        if p.poll() is None: p.terminate()
        p.communicate(timeout=3)

    def test_ssh_protocol_and_eof_shutdown(self):
        p, reader = self.peer(PEER)
        self.assertEqual(reader.read()[0]["type"], "hello")
        p.stdin.write(b'{"index":0,"run_id":"test"}\n'); p.stdin.flush()
        reply, received = reader.read()
        self.assertEqual(reply["run_id"], "test")
        self.assertLessEqual(reply["f2_ns"], reply["f3_ns"])
        self.assertLessEqual(reply["f3_ns"], received)
        p.stdin.write(b'{"type":"stop"}\n'); p.stdin.flush()
        self.assertEqual(p.wait(timeout=3), 0)

    def test_udp_rejects_wrong_token_and_stops_on_control_eof(self):
        p, reader = self.peer(UDP_PEER)
        hello, _ = reader.read()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((hello["address"], hello["port"]))
            sock.settimeout(.1)
            q = dict(index=0, run_id="test", token="wrong")
            sock.send(json.dumps(q).encode())
            with self.assertRaises(socket.timeout): sock.recv(4096)
            q["token"] = hello["token"]
            sock.send(json.dumps(q).encode()); sock.settimeout(2)
            reply = json.loads(sock.recv(4096))
            self.assertEqual(reply["index"], 0)
            self.assertEqual(reply["token"], hello["token"])
        p.stdin.close(); p.stdin = None
        self.assertEqual(p.wait(timeout=3), 0)

    def test_output_mode_refuses_replication_and_wrong_size(self):
        output = dict(name="HDMI-A-2", connected=True, enabled=True, id=1, currentModeId="11",
                      scale=1, modes=[dict(id="12", size=dict(width=1920, height=1080), refreshRate=60)])
        self.assertEqual(configured_output(dict(outputs=[output]), "HDMI-A-2", "12"), ("1", "11"))
        for changes in (dict(scale=2), dict(replicationSource=2), dict(enabled=False)):
            bad = dict(output, **changes)
            with self.assertRaises(RuntimeError): configured_output(dict(outputs=[bad]), "HDMI-A-2", "12")

    def test_seat_helper_restores_vt_on_parent_pipe_closure(self):
        # Real process/pipe cleanup, with fake chvt and source; no root or DRM.
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "chvt").write_text('#!/bin/sh\necho "$1" >> "$HWS_TEST_VT_LOG"\n')
            (d / "source").write_text('#!/usr/bin/env python3\nimport signal,time,sys\nsignal.signal(signal.SIGTERM,lambda *a:sys.exit(0))\nwhile True: time.sleep(.1)\n')
            (d / "chvt").chmod(0o755); (d / "source").chmod(0o755)
            env = dict(os.environ, PATH=tmp+":"+os.environ["PATH"], HWS_TEST_VT_LOG=str(d / "vts"))
            p = subprocess.Popen([sys.executable, "-u", "-c", SEAT_HELPER,
                str(d / "source"), "card", "1", "2", "10", "out", "run", "3", "1"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            self.addCleanup(self.finish, p)
            p.stdin.close(); p.stdin = None
            p.wait(timeout=4)
            self.assertEqual((d / "vts").read_text().splitlines(), ["3", "1"])


if __name__ == "__main__": unittest.main()
