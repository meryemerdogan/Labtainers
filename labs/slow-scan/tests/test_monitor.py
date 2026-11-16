#!/usr/bin/env python3
"""
Tests for victim/_system/usr/bin/monitor.py (Milestone 2, Step 4).

    python3 -m unittest discover -s labs/slow-scan/tests -v

  * ConnTracker: SYN -> SYN-ACK / RST / nothing, retransmissions counted once,
    ECN SYNs, packets that must be ignored, output format = detector input
  * tcpdump backend: real tcpdump -n -tt lines, command line (tcpdump faked)
  * end to end, if scapy is installed: a crafted pcap of a slow scan plus a
    benign client goes through monitor.py --pcap (scapy backend) into conn.log,
    then detector.py --replay: proposed alerts after 110 s, baseline stays silent
"""
import io
import os
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True  # no __pycache__ next to lab scripts: it would end up in the image
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
BIN = os.path.join(LAB, 'victim', '_system', 'usr', 'bin')
MONITOR = os.path.join(BIN, 'monitor.py')
DETECTOR = os.path.join(BIN, 'detector.py')
sys.path[:0] = [HERE, BIN]
import detector  # type: ignore  # noqa: E402
import monitor  # type: ignore  # noqa: E402
from monitor import ACK, FIN, RST, SYN  # type: ignore  # noqa: E402

V, A, C = '172.20.0.30', '172.20.0.10', '172.20.0.20'
ECE, CWR, PSH = 0x40, 0x80, 0x08
T = 1795000000.0  # arbitrary epoch seconds

try:
    import scapy.all  # type: ignore  # noqa: F401
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False


class Tracker(unittest.TestCase):
    def setUp(self):
        self.tr = monitor.ConnTracker(V, timeout=3.0, retrans_memory=30.0)
        self.lines = []

    def pkt(self, dt, src, sport, dst, dport, flags):
        self.lines += self.tr.packet(T + dt, src, sport, dst, dport, flags)

    def syn(self, dt, port, sport=40000, src=A, flags=SYN):
        self.pkt(dt, src, sport, V, port, flags)

    def reply(self, dt, port, flags, sport=40000, dst=A):
        self.pkt(dt, V, port, dst, sport, flags)

    def results(self):
        return [detector.parse_line(l).result for l in self.lines]

    def test_open_port(self):
        self.syn(0, 22)
        self.reply(0.001, 22, SYN | ACK)
        self.assertEqual(self.lines, ['%s src=%s sport=40000 dst=%s dport=22 result=OK' % (monitor.fmt_ts(T), A, V)])

    def test_closed_port(self):
        self.syn(0, 23)
        self.reply(0.001, 23, RST | ACK)
        self.assertEqual(self.results(), ['FAIL'])

    def test_bare_rst_also_fails(self):
        self.syn(0, 23)
        self.reply(0.001, 23, RST)
        self.assertEqual(self.results(), ['FAIL'])

    def test_timeout(self):
        self.syn(0, 24)
        self.lines += self.tr.expire(T + 2.9)
        self.assertEqual(self.lines, [])
        self.lines += self.tr.expire(T + 3.0)
        self.assertEqual(self.results(), ['TIMEOUT'])
        self.assertTrue(self.lines[0].startswith(monitor.fmt_ts(T) + ' '))  # stamped with the SYN time

    def test_timeout_triggered_by_later_packet(self):
        self.syn(0, 24)
        self.syn(5, 25, sport=40001)  # any later packet also expires old attempts
        self.assertEqual(self.results(), ['TIMEOUT'])

    def test_retransmission_counted_once(self):
        self.syn(0, 22)
        self.syn(1, 22)
        self.reply(1.001, 22, SYN | ACK)
        self.assertEqual(self.results(), ['OK'])
        self.assertEqual(self.tr.counts['retransmissions'], 1)

    def test_retransmission_after_timeout_ignored(self):
        self.syn(0, 24)
        self.lines += self.tr.expire(T + 3)
        self.syn(7, 24)     # Linux retransmits at 1, 3, 7, 15 s
        self.syn(15, 24)
        self.lines += self.tr.expire(T + 30)
        self.assertEqual(self.results(), ['TIMEOUT'])
        self.syn(100, 24)   # long after: a new attempt that reuses the port
        self.reply(100.001, 24, RST | ACK)
        self.assertEqual(self.results(), ['TIMEOUT', 'FAIL'])

    def test_ecn_syn_counts(self):
        self.syn(0, 22, flags=SYN | ECE | CWR)
        self.reply(0.001, 22, SYN | ACK | ECE)
        self.assertEqual(self.results(), ['OK'])

    def test_ignored_packets(self):
        self.pkt(0, V, 50000, A, 80, SYN)            # victim's own outbound connection
        self.pkt(0, A, 40000, C, 22, SYN)            # not for the victim
        self.reply(0, 22, SYN | ACK)                 # SYN-ACK without a SYN
        self.reply(0, 23, RST | ACK)                 # RST without a SYN
        self.syn(1, 22)
        self.pkt(1.001, A, 40000, V, 22, ACK)        # handshake ACK, data, FIN: not attempts
        self.pkt(1.002, A, 40000, V, 22, PSH | ACK)
        self.pkt(1.003, A, 40000, V, 22, FIN | ACK)
        self.pkt(1.004, A, 40000, V, 22, SYN | FIN)  # odd flag combination: not a plain SYN
        self.reply(1.005, 22, SYN | ACK)
        self.assertEqual(self.results(), ['OK'])
        self.lines += self.tr.expire(T + 100)
        self.assertEqual(self.results(), ['OK'])

    def test_rst_after_established_ignored(self):
        self.syn(0, 22)
        self.reply(0.001, 22, SYN | ACK)
        self.reply(5, 22, RST | ACK)  # connection reset later: still one OK attempt
        self.assertEqual(self.results(), ['OK'])

    def test_parallel_attempts_and_sources(self):
        for i, port in enumerate((22, 23, 24)):
            self.syn(0, port, sport=40000 + i)
            self.syn(0, port, sport=50000 + i, src=C)
        self.reply(0.01, 22, SYN | ACK, sport=40000)
        self.reply(0.01, 23, RST | ACK, sport=50001, dst=C)
        self.lines += self.tr.expire(T + 3)
        evs = sorted((detector.parse_line(l).src, detector.parse_line(l).dport, detector.parse_line(l).result)
                     for l in self.lines)
        self.assertEqual(evs, [(A, 22, 'OK'), (A, 23, 'TIMEOUT'), (A, 24, 'TIMEOUT'),
                               (C, 22, 'TIMEOUT'), (C, 23, 'FAIL'), (C, 24, 'TIMEOUT')])

    def test_flush(self):
        self.syn(0, 24)
        self.lines += self.tr.flush()
        self.assertEqual(self.results(), ['TIMEOUT'])
        self.assertEqual(self.tr.pending, {})

    def test_every_line_is_valid_detector_input(self):
        for i in range(50):
            self.syn(i, 1000 + i, sport=30000 + i)
            if i % 3 == 0:
                self.reply(i + 0.01, 1000 + i, SYN | ACK, sport=30000 + i)
            elif i % 3 == 1:
                self.reply(i + 0.01, 1000 + i, RST | ACK, sport=30000 + i)
        self.lines += self.tr.flush()
        self.assertEqual(len(self.lines), 50)
        for l in self.lines:
            self.assertIsNotNone(detector.parse_line(l), l)
            self.assertNotIn('[', l)


class Tcpdump(unittest.TestCase):
    SAMPLE = [
        '1795000000.000100 IP 172.20.0.10.40312 > 172.20.0.30.22: Flags [S], seq 1, win 64240, '
        'options [mss 1460,sackOK,TS val 1 ecr 0,nop,wscale 7], length 0',
        '1795000000.000200 IP 172.20.0.30.22 > 172.20.0.10.40312: Flags [S.], seq 9, ack 2, win 65160, length 0',
        '1795000010.000100 IP 172.20.0.10.40313 > 172.20.0.30.23: Flags [SEW], seq 1, win 64240, length 0',
        '1795000010.000200 IP 172.20.0.30.23 > 172.20.0.10.40313: Flags [R.], seq 0, ack 2, win 0, length 0',
        'tcpdump: verbose output suppressed, use -v[v]... for full protocol decode',
        '1795000020.0 IP6 fe80::1.40000 > fe80::2.22: Flags [S], seq 1, length 0',
    ]

    def test_parse(self):
        got = [monitor.parse_tcpdump_line(l) for l in self.SAMPLE]
        self.assertEqual(got[0], (1795000000.0001, A, 40312, V, 22, SYN))
        self.assertEqual(got[1][5], SYN | ACK)
        self.assertEqual(got[2][5], SYN | ECE | CWR)
        self.assertEqual(got[3][5], RST | ACK)
        self.assertEqual(got[4:], [None, None])

    def test_backend_with_fake_tcpdump(self):
        sample = self.SAMPLE
        seen = {}

        class FakePopen:
            def __init__(self, cmd, **kw):
                seen['cmd'] = cmd
                self.stdout = io.StringIO('\n'.join(sample) + '\n')

            def wait(self):
                return 0

        real = monitor.subprocess.Popen
        monitor.subprocess.Popen = FakePopen
        try:
            tr = monitor.ConnTracker(V)
            lines = []
            args = type('Args', (), dict(pcap=None, iface='eth0', victim=V))()
            monitor.run_tcpdump(args, lambda *p: lines.extend(tr.packet(*p)))
        finally:
            monitor.subprocess.Popen = real
        self.assertEqual(seen['cmd'][:6], ['tcpdump', '-l', '-n', '-tt', '-i', 'eth0'])
        self.assertEqual(seen['cmd'][-1], monitor.bpf_filter(V))
        self.assertIn('tcp-syn|tcp-rst', seen['cmd'][-1])
        self.assertEqual([detector.parse_line(l).result for l in lines], ['OK', 'FAIL'])


class Cli(unittest.TestCase):
    def test_bad_backend_fails_cleanly(self):
        tmp = tempfile.mkdtemp(prefix='slowscan-mon-')
        try:
            r = subprocess.run([sys.executable, MONITOR, '--victim', V, '--backend', 'tcpdump',
                                '--pcap', os.path.join(tmp, 'missing.pcap'), '--out', '-'],
                               capture_output=True, text=True, timeout=60,
                               env=dict(os.environ, PATH=tmp))  # no tcpdump on this PATH
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('backend tcpdump failed', r.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(HAVE_SCAPY, 'scapy not installed (it is in the victim image)')
class EndToEnd(unittest.TestCase):
    """pcap -> monitor.py (scapy backend) -> conn.log -> detector.py --replay"""

    OPEN = {22, 80, 8081, 9090}
    PORTS = list(range(15, 41)) + list(range(8079, 8084)) + list(range(9088, 9093))

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='slowscan-e2e-')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def build_pcap(self):
        from scapy.all import IP, TCP, Ether, wrpcap  # type: ignore
        pkts = []

        def add(t, src, sport, dst, dport, flags):
            p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
            p.time = t
            pkts.append(p)

        for i, port in enumerate(self.PORTS):  # slow scan, 10 s between probes
            t = T + 10 * i
            add(t, A, 41000 + i, V, port, 'S')
            add(t + 0.0005, V, port, A, 41000 + i, 'SA' if port in self.OPEN else 'RA')
            if port in self.OPEN:
                add(t + 0.001, A, 41000 + i, V, port, 'A')
                add(t + 0.002, A, 41000 + i, V, port, 'R')
        for i in range(0, 400, 5):  # client browsing every 5 s
            t = T + i + 1
            add(t, C, 50000 + i, V, 80, 'S')
            add(t + 0.0005, V, 80, C, 50000 + i, 'SA')
            add(t + 0.001, C, 50000 + i, V, 80, 'A')
            add(t + 0.01, C, 50000 + i, V, 80, 'FA')
        # one filtered port: SYN + retransmission, never answered
        add(T + 2, C, 59999, V, 7, 'S')
        add(T + 3, C, 59999, V, 7, 'S')
        pkts.sort(key=lambda p: p.time)
        path = os.path.join(self.tmp, 'slow.pcap')
        wrpcap(path, pkts)
        return path

    def test_pipeline(self):
        pcap = self.build_pcap()
        conn = os.path.join(self.tmp, 'conn.log')
        r = subprocess.run([sys.executable, MONITOR, '--victim', V, '--backend', 'scapy', '--pcap', pcap,
                            '--out', conn], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('backend=scapy', r.stderr)
        with open(conn) as fh:
            lines = fh.read().splitlines()
        evs = [detector.parse_line(l) for l in lines]
        self.assertTrue(all(evs), lines)
        scan = [e for e in evs if e.src == A]
        self.assertEqual(len(scan), 36)
        self.assertEqual({e.dport for e in scan if e.result == 'OK'}, {22, 8081, 9090})
        self.assertEqual(sum(e.result == 'FAIL' for e in scan), 33)
        self.assertEqual({e.result for e in evs if e.src == C and e.dport == 80}, {'OK'})
        self.assertEqual([e.result for e in evs if e.dport == 7], ['TIMEOUT'])  # retransmission counted once
        self.assertIn('retransmissions=1', r.stderr)

        out = {}
        for mode in ('baseline', 'proposed'):
            d = subprocess.run([sys.executable, DETECTOR, '--mode', mode, '--replay', conn],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(d.returncode, 0, d.stderr)
            out[mode] = d.stdout.splitlines()
        self.assertEqual(out['baseline'], [])
        self.assertEqual(len(out['proposed']), 1)
        self.assertRegex(out['proposed'][0], r'ALERT mode=proposed src=172\.20\.0\.10 dst=172\.20\.0\.30 '
                                             r'ports=12 attempts=12 fail=0\.92 first_seen=\S+ delay=110$')


if __name__ == '__main__':
    unittest.main(verbosity=2)
