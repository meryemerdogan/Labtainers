#!/usr/bin/env python3
"""
Tests for victim/_system/usr/bin/detector.py (Milestone 2, Step 5).

Runs anywhere with Python 3 (no containers):

    python3 -m unittest discover -s labs/slow-scan/tests -v

  * decision logic `update()` on the scenarios of MILESTONE2_PLAN.md 7.3/7.4
  * window edges, failure-ratio edge, cooldown, out-of-order TIMEOUT lines
  * --replay on tests/fixtures/*.log, fixtures in sync with scenarios.py
  * --follow as a real process: tail from the end, file created later,
    partial lines, truncation, heartbeats
"""
import os
import re
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True  # no __pycache__ next to lab scripts: it would end up in the image
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
BIN = os.path.join(LAB, 'victim', '_system', 'usr', 'bin')
DETECTOR = os.path.join(BIN, 'detector.py')
FIXTURES = os.path.join(HERE, 'fixtures')
sys.path[:0] = [HERE, BIN]
import detector  # type: ignore  # noqa: E402
import scenarios  # type: ignore  # noqa: E402
from scenarios import ATTACKER, CLIENT, VICTIM  # type: ignore  # noqa: E402


def ev(t, port, result='FAIL', src=ATTACKER):
    return detector.Event(float(t), src, 40000 + int(t * 10) % 20000, VICTIM, port, result)


def run(mode, events, **kw):
    st = detector.new_state(mode, **kw)
    return [a for a in (detector.update(st, e) for e in events) if a]


def run_lines(mode, lines, **kw):
    return run(mode, [detector.parse_line(l) for l in lines], **kw)


class ParseLine(unittest.TestCase):
    def test_valid(self):
        e = detector.parse_line('2026-11-20T10:15:03 src=172.20.0.10 sport=40312 dst=172.20.0.30 dport=22 result=OK\n')
        self.assertEqual((e.src, e.sport, e.dst, e.dport, e.result, e.failed),
                         ('172.20.0.10', 40312, '172.20.0.30', 22, 'OK', False))
        self.assertEqual(detector.fmt_ts(e.t), '2026-11-20T10:15:03')

    def test_timeout_is_failure(self):
        e = detector.parse_line('2026-11-20T10:15:03 src=a sport=1 dst=b dport=2 result=TIMEOUT')
        self.assertTrue(e.failed)

    def test_crlf_tolerated(self):
        self.assertIsNotNone(detector.parse_line('2026-11-20T10:15:03 src=a sport=1 dst=b dport=2 result=FAIL\r\n'))

    def test_rejects_garbage(self):
        for bad in ['', 'hello', '2026-11-20T10:15:03 HEARTBEAT mode=baseline window=60 threshold=12',
                    '2026-13-20T10:15:03 src=a sport=1 dst=b dport=2 result=OK',      # month 13
                    '2026-11-20T10:15:03 src=a sport=1 dst=b dport=2 result=MAYBE',
                    '2026-11-20T10:15:03 src=a sport=1 dst=b dport=2',                 # partial line
                    '2026-11-20 10:15:03 src=a sport=1 dst=b dport=2 result=OK']:
            self.assertIsNone(detector.parse_line(bad), bad)


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        b, p = detector.Config('baseline'), detector.Config('proposed')
        self.assertEqual((b.threshold, b.window, b.fail_ratio, b.cooldown), (12, 60, None, 60))
        self.assertEqual((p.threshold, p.window, p.fail_ratio, p.cooldown), (12, 600, 0.70, 600))

    def test_baseline_has_no_fail_ratio(self):
        with self.assertRaises(ValueError):
            detector.Config('baseline', fail_ratio=0.5)

    def test_invalid(self):
        for kw in [dict(threshold=0), dict(window=0), dict(fail_ratio=1.5), dict(cooldown=-1)]:
            with self.assertRaises(ValueError, msg=kw):
                detector.Config('proposed', **kw)
        with self.assertRaises(ValueError):
            detector.Config('fancy')


class Scenarios(unittest.TestCase):
    """MILESTONE2_PLAN.md 7.4, first alert per source."""

    def check(self, name):
        _, want_base, want_prop = scenarios.SCENARIOS[name]
        for mode, want in (('baseline', want_base), ('proposed', want_prop)):
            alerts = run_lines(mode, scenarios.lines(name))
            first = {}
            for a in alerts:
                first.setdefault(a.src, a)
            got = sorted((s, round(a.delay)) for s, a in first.items())
            self.assertEqual(got, sorted(want), '%s/%s: %s' % (name, mode, alerts))

    def test_fast_scan(self):
        self.check('fast_scan')

    def test_slow_scan_10s(self):
        self.check('slow_scan_10s')

    def test_slow_scan_30s(self):
        self.check('slow_scan_30s')

    def test_slow_scan_50s(self):
        self.check('slow_scan_50s')

    def test_slow_scan_60s_missed_by_design(self):
        self.check('slow_scan_60s')

    def test_health_check(self):
        self.check('health_check')

    def test_web_browsing(self):
        self.check('web_browsing')

    def test_outage_retries(self):
        self.check('outage_retries')

    def test_mixed(self):
        self.check('mixed_benign_and_slow_scan')

    def test_random_order_and_jitter(self):
        for seed in range(5):
            evs = sorted(scenarios.random_slow_scan(seed=seed), key=lambda e: e[0])
            lines = [l for _, l in evs]
            self.assertEqual(run_lines('baseline', lines), [], seed)
            p = run_lines('proposed', lines)
            self.assertTrue(p, seed)
            self.assertTrue(80 <= p[0].delay <= 150, (seed, p[0].delay))  # 11 gaps of 10 s +-30 %

    def test_fast_scan_alert_fields(self):
        a = run_lines('baseline', scenarios.lines('fast_scan'))[0]
        self.assertEqual((a.src, a.dst, a.ports, a.attempts, a.failed, a.mode),
                         (ATTACKER, VICTIM, 12, 12, 12, 'baseline'))
        self.assertRegex(a.line(), r'^2026-11-20T10:00:00 ALERT mode=baseline src=172\.20\.0\.10 dst=172\.20\.0\.30 '
                                   r'ports=12 attempts=12 fail=1\.00 first_seen=2026-11-20T10:00:00 delay=0$')
        self.assertNotIn('[', a.line())  # getTS: brackets would switch it to the httpd branch


class Edges(unittest.TestCase):
    def test_threshold_is_inclusive(self):
        self.assertEqual(len(run('baseline', [ev(i, 100 + i) for i in range(11)])), 0)
        self.assertEqual(len(run('baseline', [ev(i, 100 + i) for i in range(12)])), 1)

    def test_window_is_half_open(self):
        # 12 probes spanning exactly 60 s: the first falls out at t=60 -> (0, 60] holds 11
        evs = [ev(i * 60 / 11, 100 + i) for i in range(12)]
        self.assertEqual(run('baseline', evs), [])
        evs = [ev(i * 59 / 11, 100 + i) for i in range(12)]
        self.assertEqual(len(run('baseline', evs)), 1)

    def test_repeated_port_counts_once(self):
        evs = [ev(i, 100 + i % 11) for i in range(40)]  # 40 attempts, 11 distinct ports
        self.assertEqual(run('baseline', evs), [])
        self.assertEqual(len(run('baseline', evs + [ev(40, 999)])), 1)

    def test_fail_ratio_edge(self):
        # 19 attempts on 11 ports, then a 12th port: the ratio is decided at attempt 20.
        # 14/20 = 0.70 exactly must alert; 13/20 = 0.65 must not.
        def evs(failed):
            out = [ev(i, 100 + i % 11, 'FAIL' if i < failed else 'OK') for i in range(19)]
            return out + [ev(19, 999, 'OK')]
        self.assertEqual(len(run('proposed', evs(14))), 1)
        self.assertEqual(run('proposed', evs(13)), [])
        for attempts in range(10, 101):  # float edge: k/n == 0.70 exactly must always alert
            if attempts * 7 % 10 == 0:
                k = attempts * 7 // 10
                st = detector.new_state('proposed', threshold=attempts)  # decided at the last event
                alerts = [detector.update(st, ev(0, i, 'FAIL' if i < k else 'OK')) for i in range(attempts)]
                self.assertIsNotNone(alerts[-1], '%d/%d' % (k, attempts))

    def test_fail_ratio_zero_is_window_only(self):
        evs = [ev(i * 30, 100 + i, 'OK') for i in range(12)]  # all open, 30 s apart
        self.assertEqual(run('proposed', evs), [])
        self.assertEqual(len(run('proposed', evs, fail_ratio=0.0)), 1)

    def test_cooldown(self):
        evs = [ev(i, 100 + i) for i in range(200)]  # 200 s of 1 port/s
        b = run('baseline', evs)
        self.assertEqual([round(a.t) for a in b], [11, 71, 131, 191])  # one alert per 60 s
        self.assertEqual(len(run('baseline', evs, cooldown=1e9)), 1)

    def test_sources_are_independent(self):
        evs = []
        for i in range(12):
            evs += [ev(i, 100 + i, src=ATTACKER), ev(i, 100 + i, src=CLIENT)]
        self.assertEqual(sorted(a.src for a in run('baseline', evs)), [ATTACKER, CLIENT])

    def test_out_of_order_timeout_lines(self):
        # monitor writes TIMEOUT lines 3 s late: they arrive after newer FAIL lines
        evs = []
        for i in range(12):
            r = 'TIMEOUT' if i % 3 == 0 else 'FAIL'
            evs.append((i * 10 + (3 if r == 'TIMEOUT' else 0), ev(i * 10, 100 + i, r)))
        in_arrival_order = [e for _, e in sorted(evs, key=lambda x: x[0])]
        in_time_order = [e for _, e in sorted(evs, key=lambda x: x[1].t)]
        a, b = run('proposed', in_arrival_order), run('proposed', in_time_order)
        self.assertEqual(len(a), 1)
        self.assertEqual((a[0].first_seen, a[0].ports), (b[0].first_seen, b[0].ports))
        self.assertEqual(a[0].first_seen, 0)

    def test_first_seen_is_oldest_in_window(self):
        # a source that browsed an hour ago and then scans: delay is measured from the scan
        evs = [ev(0, 80, 'OK')] + [ev(3600 + i * 10, 100 + i) for i in range(12)]
        a = run('proposed', evs)[0]
        self.assertEqual((a.first_seen, round(a.delay)), (3600, 110))

    def test_idle_sources_are_forgotten(self):
        st = detector.new_state('baseline')
        for i in range(detector.GC_EVERY * 2):
            detector.update(st, ev(i, 80, 'OK', src='10.0.%d.%d' % (i // 250, i % 250)))
        self.assertLess(len(st.sources), 100)


class Replay(unittest.TestCase):
    def test_fixtures_match_generator(self):
        for name in scenarios.SCENARIOS:
            with open(os.path.join(FIXTURES, name + '.log'), newline='') as fh:
                self.assertEqual(fh.read(), '\n'.join(scenarios.lines(name)) + '\n',
                                 'fixtures/%s.log is stale: run python3 tests/scenarios.py' % name)

    def replay(self, mode, name, *extra):
        r = subprocess.run([sys.executable, DETECTOR, '--mode', mode, '--replay',
                            os.path.join(FIXTURES, name + '.log')] + list(extra),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.splitlines(), r.stderr

    def test_replay_cli(self):
        out, err = self.replay('proposed', 'slow_scan_10s')
        self.assertEqual(out, ['2026-11-20T10:01:50 ALERT mode=proposed src=172.20.0.10 dst=172.20.0.30 '
                               'ports=12 attempts=12 fail=0.92 first_seen=2026-11-20T10:00:00 delay=110'])
        self.assertIn('36 events, 0 unparsed lines, 1 alerts', err)
        out, _ = self.replay('baseline', 'slow_scan_10s')
        self.assertEqual(out, [])

    def test_replay_cli_threshold(self):
        out, _ = self.replay('proposed', 'slow_scan_10s', '--threshold', '14')
        self.assertIn('delay=130', out[0])

    def test_cli_rejects_fail_ratio_in_baseline(self):
        r = subprocess.run([sys.executable, DETECTOR, '--mode', 'baseline', '--fail-ratio', '0.5',
                            '--replay', os.path.join(FIXTURES, 'fast_scan.log')],
                           capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('no failure-rate condition', r.stderr)


class Follow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='slowscan-follow-')
        self.log = os.path.join(self.tmp, 'conn.log')
        self.out = os.path.join(self.tmp, 'proposed.log')
        self.proc = None

    def tearDown(self):
        if self.proc:
            self.proc.kill()
            self.proc.wait(timeout=10)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def start(self, mode='proposed', heartbeat='0'):
        self.proc = subprocess.Popen([sys.executable, DETECTOR, '--mode', mode, '--follow', self.log,
                                      '--out', self.out, '--heartbeat', heartbeat, '--poll', '0.05'])

    def append(self, lines, newline=True):
        with open(self.log, 'a', newline='\n') as fh:
            fh.write('\n'.join(lines) + ('\n' if newline else ''))

    def output(self, pattern, n=1, timeout=10):
        deadline = time.time() + timeout
        hits = []
        while time.time() < deadline:
            if os.path.exists(self.out):
                with open(self.out) as fh:
                    hits = [l for l in fh.read().splitlines() if re.search(pattern, l)]
                if len(hits) >= n:
                    return hits
            time.sleep(0.05)
        self.fail('expected %d lines matching %r, got %r' % (n, pattern, hits))

    def settle(self):
        time.sleep(0.6)  # > a few poll intervals

    def test_tails_from_end(self):
        self.append(scenarios.lines('slow_scan_10s'))  # history from a previous session: ignored
        self.start()
        self.settle()
        self.append(scenarios.lines('fast_scan'))
        alerts = self.output('ALERT')
        self.assertIn('delay=0', alerts[0])  # the fast scan, not the old slow scan

    def test_file_created_later_and_partial_lines(self):
        self.start()
        self.settle()
        lines = scenarios.lines('slow_scan_10s')
        self.append(lines[:11])
        self.append([lines[11][:30]], newline=False)  # half a line: must wait for the rest
        self.settle()
        self.assertFalse(os.path.exists(self.out) and 'ALERT' in open(self.out).read())
        with open(self.log, 'a', newline='\n') as fh:
            fh.write(lines[11][30:] + '\n')
        self.assertIn('delay=110', self.output('ALERT')[0])

    def test_truncation(self):
        self.append(['x'])
        self.start()
        self.settle()
        self.append(scenarios.lines('outage_retries')[:50])
        self.settle()
        with open(self.log, 'w', newline='\n'):
            pass  # truncated, e.g. by logrotate copytruncate
        self.settle()
        self.append(scenarios.lines('fast_scan'))
        self.output('ALERT')

    def test_heartbeat(self):
        self.start(mode='baseline', heartbeat='0.2')
        hb = self.output('HEARTBEAT', n=3)
        self.assertRegex(hb[0], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d HEARTBEAT mode=baseline window=60 threshold=12 events=0$')
        self.append(scenarios.lines('health_check')[:8])
        self.output(r'HEARTBEAT .* events=8$')


if __name__ == '__main__':
    unittest.main(verbosity=2)
