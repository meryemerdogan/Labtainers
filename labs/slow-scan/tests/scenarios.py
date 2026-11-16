#!/usr/bin/env python3
"""
Synthetic conn.log traffic for the detector tests (MILESTONE2_PLAN.md 7.3/7.4).

Every scenario returns conn.log lines exactly as monitor.py writes them
(whole-second ISO timestamps). EXPECTED says what each detector mode must do.
`python3 scenarios.py` (or make_fixtures) rewrites tests/fixtures/*.log, which
can be replayed by hand:

    python3 victim/_system/usr/bin/detector.py --mode proposed --replay tests/fixtures/slow_scan_10s.log
"""
import datetime
import os
import random

ATTACKER, CLIENT, VICTIM = '172.20.0.10', '172.20.0.20', '172.20.0.30'
OPEN_PORTS = {22, 80, 8081, 9090}
T0 = datetime.datetime(2026, 11, 20, 10, 0, 0)
SLOW_PORTS = list(range(15, 41)) + list(range(8079, 8084)) + list(range(9088, 9093))  # 36 ports, plan 8


def line(t, src, sport, dport, result):
    ts = (T0 + datetime.timedelta(seconds=int(t))).strftime('%Y-%m-%dT%H:%M:%S')
    return '%s src=%s sport=%d dst=%s dport=%d result=%s' % (ts, src, sport, VICTIM, dport, result)


def probe(t, src, sport, port):
    return (t, line(t, src, sport, port, 'OK' if port in OPEN_PORTS else 'FAIL'))


def scan(ports, delay, start=0.0, src=ATTACKER, sport=40000):
    return [probe(start + i * delay, src, sport + i, p) for i, p in enumerate(ports)]


def web(start=0.0, every=5, duration=1800, src=CLIENT, sport=50000):
    return [probe(start + i * every, src, sport + i, 80) for i in range(int(duration // every))]


def health_check(start=0.0, every=60, duration=1800, src=CLIENT, sport=52000):
    out, n = [], 0
    for i in range(int(duration // every)):
        for p in (22, 80, 8081, 9090):
            out.append(probe(start + i * every, src, sport + n, p))
            n += 1
    return out


def outage(start=0.0, every=2, duration=300, port=8081, src=CLIENT, sport=54000):
    """A client retrying one stopped service: every attempt fails, but always the same port."""
    return [(start + i * every, line(start + i * every, src, sport + i, port, 'FAIL'))
            for i in range(int(duration // every))]


def mixed():
    """30 min of benign client traffic with a 10 s slow scan starting at minute 5."""
    return web() + health_check() + scan(SLOW_PORTS, 10, start=300)


def random_slow_scan(seed=7, delay=10, jitter=0.3):
    """Shuffled ports, delay +-30 %: the 'random delay' variant from the proposal."""
    rnd = random.Random(seed)
    ports = SLOW_PORTS[:]
    rnd.shuffle(ports)
    out, t = [], 0.0
    for i, p in enumerate(ports):
        out.append(probe(t, ATTACKER, 41000 + i, p))
        t += delay * (1 + rnd.uniform(-jitter, jitter))
    return out


SCENARIOS = {
    # name: (events, baseline alerts, proposed alerts) - alerts as [(src, delay)]
    'fast_scan':       (lambda: scan(range(1, 201), 0.05), [(ATTACKER, 0)], [(ATTACKER, 0)]),
    'slow_scan_10s':   (lambda: scan(SLOW_PORTS, 10), [], [(ATTACKER, 110)]),
    'slow_scan_30s':   (lambda: scan(SLOW_PORTS, 30), [], [(ATTACKER, 330)]),
    'slow_scan_50s':   (lambda: scan(SLOW_PORTS, 50), [], [(ATTACKER, 550)]),   # last delay that fits 600 s
    'slow_scan_60s':   (lambda: scan(SLOW_PORTS, 60), [], []),                  # missed by design
    'health_check':    (health_check, [], []),
    'web_browsing':    (web, [], []),
    'outage_retries':  (outage, [], []),
    'mixed_benign_and_slow_scan': (mixed, [], [(ATTACKER, 110)]),
}


def lines(name):
    events = SCENARIOS[name][0]()
    return [l for _, l in sorted(events, key=lambda e: e[0])]


def write_fixtures(directory):
    os.makedirs(directory, exist_ok=True)
    for name in SCENARIOS:
        with open(os.path.join(directory, name + '.log'), 'w', newline='\n') as fh:
            fh.write('\n'.join(lines(name)) + '\n')


if __name__ == '__main__':
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
    write_fixtures(d)
    print('wrote %d fixtures to %s' % (len(SCENARIOS), d))
