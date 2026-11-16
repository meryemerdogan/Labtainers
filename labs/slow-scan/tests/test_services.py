#!/usr/bin/env python3
"""
Functional tests for the Step 3 victim services, run as real processes on
127.0.0.1 with free ports. No Docker, no root, works on Windows and Linux.

    python3 -m unittest discover -s labs/slow-scan/tests -v

  testsvc.py       banner is sent, connection is closed, bad arguments rejected
  MyHTTPServer.py  serves index.html, 404 for missing files, and every request
                   becomes one Apache-style log line that Labtainers' own
                   getTS (ResultParser.py) turns into a timestamp
"""
import os
import re
import shutil
import socket
import subprocess
import sys
sys.dont_write_bytecode = True  # no __pycache__ next to lab scripts: it would end up in the image
import tempfile
import time
import types
import unittest
import urllib.error
import urllib.request
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
TOP = os.path.dirname(os.path.dirname(LAB))
BIN = os.path.join(LAB, 'victim', '_system', 'usr', 'bin')
WWW = os.path.join(LAB, 'victim', '_system', 'var', 'www', 'html')
TESTSVC = os.path.join(BIN, 'testsvc.py')
HTTPD = os.path.join(BIN, 'MyHTTPServer.py')


def start(argv, port_re):
    """Start a server, wait for its 'port N' line, return (proc, port)."""
    proc = subprocess.Popen([sys.executable, '-u'] + argv, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    assert proc.stdout is not None
    line = proc.stdout.readline()
    m = re.search(port_re, line)
    if not m:
        proc.kill()
        raise AssertionError('server did not start: %r %s' % (line, proc.stdout.read()))
    return proc, int(m.group(1))


def stop(proc):
    proc.kill()
    proc.wait(timeout=10)
    proc.stdout.close()


def labtainers_getTS():
    """The real getTS from ResultParser.py, or None if it cannot be imported here."""
    paths = [os.path.join(TOP, 'scripts', 'labtainer-instructor', 'assess_bin'),
             os.path.join(TOP, 'scripts', 'labtainer-student', 'lab_bin')]
    saved_path = list(sys.path)
    sys.path[:0] = paths
    stubbed = []
    try:
        for mod in ('parse',):  # pip package on the Labtainers host, not needed by getTS
            try:
                __import__(mod)
            except ImportError:
                sys.modules[mod] = types.ModuleType(mod)
                stubbed.append(mod)
        with warnings.catch_warnings():  # ResultParser.py has old-style regex escapes
            warnings.simplefilter('ignore', SyntaxWarning)
            import ResultParser  # type: ignore
        return ResultParser.getTS
    except Exception:
        return None
    finally:
        sys.path[:] = saved_path
        for mod in stubbed:
            sys.modules.pop(mod, None)


class TestSvc(unittest.TestCase):
    def setUp(self):
        self.proc, self.port = start([TESTSVC, '0', 'inventory'], r'listening on port (\d+)')

    def tearDown(self):
        stop(self.proc)

    def connect(self):
        return socket.create_connection(('127.0.0.1', self.port), timeout=5)

    def test_banner_then_close(self):
        with self.connect() as s:
            data = b''
            while True:
                chunk = s.recv(1024)
                if not chunk:  # server closed the connection
                    break
                data += chunk
        self.assertEqual(data, b'220 slow-scan inventory service ready\r\n')

    def test_connect_scan_style_probe(self):
        # like scan.py / nmap -sT: connect and close at once; the service must survive it
        for _ in range(20):
            self.connect().close()
        with self.connect() as s:
            self.assertTrue(s.recv(1024).startswith(b'220 slow-scan inventory'))

    def test_connections_are_logged(self):
        with self.connect() as s:
            s.recv(1024)
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        self.assertRegex(line, r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d inventory connection from 127\.0\.0\.1:\d+$')


class TestSvcArgs(unittest.TestCase):
    def run_bad(self, *args):
        r = subprocess.run([sys.executable, TESTSVC] + list(args), capture_output=True,
                           text=True, timeout=20)
        self.assertNotEqual(r.returncode, 0)
        return r.stderr

    def test_usage(self):
        self.assertIn('usage', self.run_bad())

    def test_port_not_a_number(self):
        self.assertIn('port must be a number', self.run_bad('http', 'x'))

    def test_port_out_of_range(self):
        self.assertIn('out of range', self.run_bad('70000', 'x'))


class HttpServer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='slowscan-http-')
        self.log = os.path.join(self.tmp, 'myhttplogfile.txt')
        self.proc, self.port = start([HTTPD, '--port', '0', '--bind', '127.0.0.1',
                                      '--root', WWW, '--log', self.log], r'on port (\d+)')

    def tearDown(self):
        stop(self.proc)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def get(self, path):
        return urllib.request.urlopen('http://127.0.0.1:%d%s' % (self.port, path), timeout=5)

    def log_lines(self, n):
        deadline = time.time() + 5
        while time.time() < deadline:
            if os.path.exists(self.log):
                with open(self.log) as fh:
                    lines = fh.read().splitlines()
                if len(lines) >= n:
                    return lines
            time.sleep(0.05)
        self.fail('expected %d log lines in %s' % (n, self.log))

    def test_serves_index(self):
        with self.get('/') as r:
            self.assertEqual(r.status, 200)
            self.assertIn(b'slow-scan victim', r.read())

    def test_missing_file_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get('/nope.html')
        self.assertEqual(cm.exception.code, 404)

    def test_log_format(self):
        self.get('/').close()
        line = self.log_lines(1)[0]
        self.assertRegex(line, r'^127\.0\.0\.1 - - \[\d\d/[A-Z][a-z]{2}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4}\] '
                               r'"GET / HTTP/1\.1" 200 -$')

    def test_log_parsed_by_labtainers_getTS(self):
        getTS = labtainers_getTS()
        if getTS is None:
            self.skipTest('ResultParser.py not importable here')
        self.get('/').close()
        ts = getTS(self.log_lines(1)[0], None)
        self.assertIsNotNone(ts)
        self.assertEqual(ts[:8], time.strftime('%Y%m%d'))

    def test_log_appends_across_restarts(self):
        self.get('/').close()
        self.log_lines(1)
        stop(self.proc)
        self.proc, self.port = start([HTTPD, '--port', '0', '--bind', '127.0.0.1',
                                      '--root', WWW, '--log', self.log], r'on port (\d+)')
        self.get('/').close()
        self.assertEqual(len(self.log_lines(2)), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
