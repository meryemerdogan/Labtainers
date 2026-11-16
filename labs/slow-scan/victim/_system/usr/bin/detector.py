#!/usr/bin/env python3
"""
slow-scan port-scan detector (Milestone 2, Step 5).

Reads conn.log lines written by monitor.py and raises one ALERT per scanning
source. Two modes, same code:

  baseline  alert when a source touches >= THRESHOLD distinct ports within
            WINDOW seconds (default 12 ports / 60 s): the classic detector
  proposed  same, but over a long window (default 600 s) AND only if at least
            FAIL_RATIO of the source's attempts in the window failed
            (RST or TIMEOUT; default 0.70)

    detector.py --mode baseline|proposed [--threshold 12] [--window S] [--fail-ratio R]
                (--follow /var/log/slowscan/conn.log | --replay recorded_conn.log)
                [--out FILE] [--heartbeat 30] [--cooldown S]

Clock: the timestamps in conn.log are the clock in both modes. The window,
the alert time and `delay` are computed from them, never from the wall clock,
so following a live log and replaying the same log give identical alerts.
Only HEARTBEAT lines (follow mode) use the wall clock.

Output (one line each, ISO timestamp first, no square brackets, for getTS):
    2026-11-20T10:15:00 HEARTBEAT mode=proposed window=600 threshold=12 fail_ratio=0.70 events=42
    2026-11-20T10:17:05 ALERT mode=proposed src=172.20.0.10 dst=172.20.0.30 ports=12 attempts=13 fail=0.92 first_seen=2026-11-20T10:15:03 delay=122

  first_seen  oldest attempt of that source still inside the window when the
              alert fired, i.e. the first probe of the scan
  delay       alert time - first_seen (the detection delay in proposal section 6)
"""
import argparse
import bisect
import datetime
import os
import re
import sys
import time

TS_FORMAT = '%Y-%m-%dT%H:%M:%S'
EPOCH = datetime.datetime(1970, 1, 1)
LINE_RE = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d) src=(\S+) sport=(\d+) dst=(\S+) dport=(\d+) '
                     r'result=(OK|FAIL|TIMEOUT)\s*$')
DEFAULTS = {
    'baseline': dict(threshold=12, window=60, fail_ratio=None),
    'proposed': dict(threshold=12, window=600, fail_ratio=0.70),
}
GC_EVERY = 1000  # events between sweeps that forget idle sources


def parse_ts(s):
    """'2026-11-20T10:15:03' -> seconds. Naive on purpose: monitor and detector share one clock."""
    return (datetime.datetime.strptime(s, TS_FORMAT) - EPOCH).total_seconds()


def fmt_ts(t):
    return (EPOCH + datetime.timedelta(seconds=t)).strftime(TS_FORMAT)


class Event:
    __slots__ = ('t', 'src', 'sport', 'dst', 'dport', 'result')

    def __init__(self, t, src, sport, dst, dport, result):
        self.t, self.src, self.sport, self.dst, self.dport, self.result = t, src, sport, dst, dport, result

    @property
    def failed(self):
        return self.result != 'OK'  # FAIL and TIMEOUT both count as failures


def parse_line(line):
    """conn.log line -> Event, or None for anything else (blank, partial, foreign)."""
    m = LINE_RE.match(line)
    if not m:
        return None
    try:
        t = parse_ts(m.group(1))
    except ValueError:  # e.g. month 13
        return None
    return Event(t, m.group(2), int(m.group(3)), m.group(4), int(m.group(5)), m.group(6))


class Config:
    def __init__(self, mode, threshold=None, window=None, fail_ratio=None, cooldown=None):
        if mode not in DEFAULTS:
            raise ValueError('mode must be baseline or proposed')
        d = DEFAULTS[mode]
        self.mode = mode
        self.threshold = d['threshold'] if threshold is None else threshold
        self.window = d['window'] if window is None else window
        if mode == 'baseline' and fail_ratio is not None:
            raise ValueError('baseline mode has no failure-rate condition')
        self.fail_ratio = d['fail_ratio'] if fail_ratio is None else fail_ratio
        self.cooldown = self.window if cooldown is None else cooldown
        if self.threshold < 1 or self.window <= 0 or self.cooldown < 0:
            raise ValueError('threshold >= 1, window > 0 and cooldown >= 0 required')
        if self.fail_ratio is not None and not 0 <= self.fail_ratio <= 1:
            raise ValueError('fail-ratio must be between 0 and 1')

    def describe(self):
        s = 'mode=%s window=%g threshold=%d' % (self.mode, self.window, self.threshold)
        if self.fail_ratio is not None:
            s += ' fail_ratio=%.2f' % self.fail_ratio
        return s


class Alert:
    def __init__(self, t, mode, src, dst, ports, attempts, failed, first_seen):
        self.t, self.mode, self.src, self.dst = t, mode, src, dst
        self.ports, self.attempts, self.failed, self.first_seen = ports, attempts, failed, first_seen

    @property
    def fail(self):
        return self.failed / self.attempts

    @property
    def delay(self):
        return self.t - self.first_seen

    def line(self):
        return '%s ALERT mode=%s src=%s dst=%s ports=%d attempts=%d fail=%.2f first_seen=%s delay=%d' % (
            fmt_ts(self.t), self.mode, self.src, self.dst, self.ports, self.attempts, self.fail,
            fmt_ts(self.first_seen), round(self.delay))

    def __repr__(self):
        return '<%s>' % self.line()


class State:
    def __init__(self, config):
        self.config = config
        self.now = float('-inf')  # latest event time seen: the detector's clock
        self.sources = {}         # src -> sorted list of (t, dport, failed) inside the window
        self.last_alert = {}      # src -> time of its last alert (cooldown)
        self.events = 0


def new_state(mode, **kw):
    return State(Config(mode, **kw))


def _prune(evs, cutoff):
    """Drop entries with t <= cutoff: the window is (now - window, now]."""
    i = bisect.bisect_right(evs, (cutoff, float('inf'), True))
    if i:
        del evs[:i]


def update(state, event):
    """Feed one conn.log event; return an Alert or None. No I/O and no wall clock."""
    cfg = state.config
    state.events += 1
    state.now = max(state.now, event.t)
    cutoff = state.now - cfg.window

    evs = state.sources.setdefault(event.src, [])
    bisect.insort(evs, (event.t, event.dport, event.failed))  # monitor writes TIMEOUTs up to 3 s late
    _prune(evs, cutoff)
    if state.events % GC_EVERY == 0:
        for src in [s for s, e in state.sources.items() if not e or e[-1][0] <= cutoff]:
            del state.sources[src]
    if not evs:
        return None

    ports = len({d for _, d, _ in evs})
    if ports < cfg.threshold:
        return None
    attempts = len(evs)
    failed = sum(1 for _, _, f in evs if f)
    if cfg.fail_ratio is not None and failed / attempts < cfg.fail_ratio - 1e-9:  # 1e-9: 0.7 is not exact in binary
        return None
    last = state.last_alert.get(event.src)
    if last is not None and state.now - last < cfg.cooldown:
        return None
    state.last_alert[event.src] = state.now
    return Alert(state.now, cfg.mode, event.src, event.dst, ports, attempts, failed, evs[0][0])


# ---- input ----------------------------------------------------------------
class Follower:
    """`tail -F` for one file: starts at the end (or the beginning), survives the
    file appearing later, being truncated, or being replaced."""

    def __init__(self, path, from_start=False):
        self.path = path
        self.fh = None
        self.ino = None
        self.buf = ''
        # Skip only what is already there at startup (an earlier session's history).
        # If the file does not exist yet, it will be read from its first line.
        self.first_open_at_end = not from_start
        self._open()
        self.first_open_at_end = False

    def _open(self):
        try:
            fh = open(self.path, 'r', encoding='utf-8', errors='replace', newline='')
        except FileNotFoundError:
            return
        if self.first_open_at_end:
            fh.seek(0, os.SEEK_END)
        self.fh, self.ino, self.buf = fh, os.fstat(fh.fileno()).st_ino, ''

    def lines(self):
        if self.fh is None:
            self._open()
            if self.fh is None:
                return []
        self.buf += self.fh.read()
        try:
            st = os.stat(self.path)
            if st.st_ino != self.ino or st.st_size < self.fh.tell():  # replaced or truncated
                self.fh.close()
                self.fh = None  # reopened from the start on the next call
        except FileNotFoundError:
            pass  # deleted: keep reading the old handle until a new file appears
        *done, self.buf = self.buf.split('\n')
        return done


def run_replay(state, path, out):
    bad = alerts = 0
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for line in fh:
            ev = parse_line(line)
            if ev is None:
                bad += bool(line.strip())
                continue
            alert = update(state, ev)
            if alert:
                alerts += 1
                out.write(alert.line() + '\n')
    out.flush()
    print('detector: replay %s: %d events, %d unparsed lines, %d alerts (%s)'
          % (path, state.events, bad, alerts, state.config.describe()), file=sys.stderr)
    return 0


def run_follow(state, path, out, heartbeat, poll, from_start):
    fol = Follower(path, from_start=from_start)
    next_hb = time.time()
    while True:
        for line in fol.lines():
            ev = parse_line(line)
            if ev is not None:
                alert = update(state, ev)
                if alert:
                    out.write(alert.line() + '\n')
                    out.flush()
        now = time.time()
        if heartbeat > 0 and now >= next_hb:
            out.write('%s HEARTBEAT %s events=%d\n'
                      % (time.strftime(TS_FORMAT, time.localtime(now)), state.config.describe(), state.events))
            out.flush()
            next_hb = now + heartbeat
        time.sleep(poll)


def main(argv=None):
    ap = argparse.ArgumentParser(description='slow-scan port-scan detector')
    ap.add_argument('--mode', choices=sorted(DEFAULTS), required=True)
    ap.add_argument('--threshold', type=int, help='distinct ports (default 12)')
    ap.add_argument('--window', type=float, help='seconds (default 60 baseline, 600 proposed)')
    ap.add_argument('--fail-ratio', type=float, help='proposed only (default 0.70; 0 disables)')
    ap.add_argument('--cooldown', type=float, help='seconds before the same source can alert again (default: window)')
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--follow', metavar='FILE', help='tail a live conn.log (starts at its end)')
    src.add_argument('--replay', metavar='FILE', help='read a recorded conn.log from the start and exit')
    ap.add_argument('--from-start', action='store_true', help='--follow: read existing lines first')
    ap.add_argument('--out', default='-', help="output file (appended), '-' for stdout")
    ap.add_argument('--heartbeat', type=float, default=30, help='--follow: seconds between HEARTBEAT lines, 0 = off')
    ap.add_argument('--poll', type=float, default=0.5, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    try:
        state = State(Config(args.mode, args.threshold, args.window, args.fail_ratio, args.cooldown))
    except ValueError as e:
        ap.error(str(e))
    out = sys.stdout if args.out == '-' else open(args.out, 'a', buffering=1)
    try:
        if args.replay:
            return run_replay(state, args.replay, out)
        return run_follow(state, args.follow, out, args.heartbeat, args.poll, args.from_start)
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    sys.exit(main())
