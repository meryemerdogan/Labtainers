#!/usr/bin/env python3
"""
slow-scan connection monitor (Milestone 2, Step 4).

Watches TCP traffic to the victim and writes one line per inbound connection
attempt to /var/log/slowscan/conn.log (format frozen in MILESTONE2_PLAN.md 7.1):

    2026-11-20T10:15:03 src=172.20.0.10 sport=40312 dst=172.20.0.30 dport=22 result=OK

  OK       the victim answered the SYN with SYN-ACK (port open)
  FAIL     the victim answered with RST (port closed)
  TIMEOUT  no answer within --timeout seconds (counts as a failure)

The timestamp is the time of the attempt's first SYN. OK and FAIL lines are
written as soon as the answer is seen, while TIMEOUT lines are written
--timeout seconds later, so the log can be out of order by up to that much.
The detector handles this.

A SYN for a (src, sport, dport) that is still pending is a retransmission and
is not counted again. The same holds for a few seconds after a timeout.

Backends:
  scapy    scapy.sniff with a BPF filter (default, python3-scapy in the image)
  tcpdump  parses `tcpdump -l -n -tt` output (fallback, same results)
  auto     scapy, falling back to tcpdump if scapy cannot start

    monitor.py --iface eth0 --victim 172.20.0.30 --out /var/log/slowscan/conn.log
    monitor.py --victim 172.20.0.30 --pcap capture.pcap --out -     # offline
"""
import argparse
import re
import subprocess
import sys
import threading
import time

FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10
TS_FORMAT = '%Y-%m-%dT%H:%M:%S'


def fmt_ts(t):
    return time.strftime(TS_FORMAT, time.localtime(t))


def format_line(t, src, sport, dst, dport, result):
    return '%s src=%s sport=%d dst=%s dport=%d result=%s' % (fmt_ts(t), src, sport, dst, dport, result)


class ConnTracker:
    """Turns packets into conn.log lines. No I/O and no clock, so it is testable without scapy.

    packet() and expire() return the lines that became final, in first-SYN order.
    """

    def __init__(self, victim, timeout=3.0, retrans_memory=30.0):
        self.victim = victim
        self.timeout = timeout
        self.retrans_memory = retrans_memory
        self.pending = {}    # (src, sport, dport) -> time of first SYN
        self.timed_out = {}  # (src, sport, dport) -> time it timed out
        self.counts = {'OK': 0, 'FAIL': 0, 'TIMEOUT': 0, 'retransmissions': 0}

    def _resolve(self, key, result):
        first = self.pending.pop(key, None)
        if first is None:
            return None
        self.counts[result] += 1
        src, sport, dport = key
        return format_line(first, src, sport, self.victim, dport, result)

    def packet(self, t, src, sport, dst, dport, flags):
        out = self.expire(t)
        f = flags & (FIN | SYN | RST | ACK)  # ignore ECN/PSH/URG bits: Linux may send SYN|ECE|CWR
        if dst == self.victim and f == SYN:
            key = (src, sport, dport)
            if key in self.pending or key in self.timed_out:
                self.counts['retransmissions'] += 1
            else:
                self.pending[key] = t
        elif src == self.victim and f == SYN | ACK:
            line = self._resolve((dst, dport, sport), 'OK')
            if line:
                out.append(line)
        elif src == self.victim and f & RST:
            line = self._resolve((dst, dport, sport), 'FAIL')
            if line:
                out.append(line)
        return out

    def expire(self, now):
        out = []
        for key, first in sorted(self.pending.items(), key=lambda kv: kv[1]):
            if now - first >= self.timeout:
                out.append(self._resolve(key, 'TIMEOUT'))
                self.timed_out[key] = now
        for key, when in list(self.timed_out.items()):
            if now - when > self.retrans_memory:
                del self.timed_out[key]
        return out

    def flush(self):
        """End of an offline capture: whatever is still pending never got an answer."""
        return self.expire(float('inf'))


# ---- tcpdump backend ------------------------------------------------------
TCPDUMP_RE = re.compile(r'^(\d+\.\d+) IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): '
                        r'Flags \[([^\]]*)\]')
TCPDUMP_FLAGS = {'F': FIN, 'S': SYN, 'R': RST, '.': ACK, 'P': 0x08, 'U': 0x20, 'E': 0x40, 'W': 0x80}


def parse_tcpdump_line(line):
    """'1763633703.123456 IP a.b.c.d.p > e.f.g.h.q: Flags [S.], ...' -> packet tuple or None."""
    m = TCPDUMP_RE.match(line)
    if not m:
        return None
    flags = 0
    for ch in m.group(6):
        flags |= TCPDUMP_FLAGS.get(ch, 0)
    return (float(m.group(1)), m.group(2), int(m.group(3)), m.group(4), int(m.group(5)), flags)


def bpf_filter(victim):
    return 'tcp and host %s and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)' % victim


def run_tcpdump(args, on_packet):
    cmd = ['tcpdump', '-l', '-n', '-tt']
    cmd += ['-r', args.pcap] if args.pcap else ['-i', args.iface]
    cmd.append(bpf_filter(args.victim))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    assert proc.stdout is not None
    for line in proc.stdout:
        pkt = parse_tcpdump_line(line)
        if pkt:
            on_packet(*pkt)
    return proc.wait()


# ---- scapy backend --------------------------------------------------------
def run_scapy(args, on_packet):
    from scapy.all import IP, TCP, sniff  # type: ignore  # imported here so the rest works without scapy

    def cb(pkt):
        if IP in pkt and TCP in pkt:
            ip, tcp = pkt[IP], pkt[TCP]
            on_packet(float(pkt.time), ip.src, int(tcp.sport), ip.dst, int(tcp.dport), int(tcp.flags))

    if args.pcap:
        # no BPF offline (it would need tcpdump); ConnTracker ignores unrelated packets anyway
        sniff(offline=args.pcap, store=False, prn=cb)
    else:
        sniff(iface=args.iface, filter=bpf_filter(args.victim), store=False, prn=cb)
    return 0


# ---- main -----------------------------------------------------------------
class Monitor:
    def __init__(self, tracker, out):
        self.tracker = tracker
        self.out = out
        self.lock = threading.Lock()

    def write(self, lines):
        for line in lines:
            self.out.write(line + '\n')
        if lines:
            self.out.flush()

    def on_packet(self, t, src, sport, dst, dport, flags):
        with self.lock:
            self.write(self.tracker.packet(t, src, sport, dst, dport, flags))

    def expire_loop(self, interval=0.5):
        while True:
            time.sleep(interval)
            with self.lock:
                self.write(self.tracker.expire(time.time()))


def main(argv=None):
    ap = argparse.ArgumentParser(description='slow-scan connection monitor')
    ap.add_argument('--iface', default='eth0')
    ap.add_argument('--victim', required=True, help='IP address of the monitored host')
    ap.add_argument('--out', default='/var/log/slowscan/conn.log', help="log file, '-' for stdout")
    ap.add_argument('--timeout', type=float, default=3.0, help='seconds without an answer = TIMEOUT')
    ap.add_argument('--backend', choices=['auto', 'scapy', 'tcpdump'], default='auto')
    ap.add_argument('--pcap', help='read packets from a capture file instead of --iface')
    args = ap.parse_args(argv)

    out = sys.stdout if args.out == '-' else open(args.out, 'a', buffering=1)
    mon = Monitor(ConnTracker(args.victim, timeout=args.timeout), out)
    if not args.pcap:
        threading.Thread(target=mon.expire_loop, daemon=True).start()

    backends = {'scapy': [run_scapy], 'tcpdump': [run_tcpdump], 'auto': [run_scapy, run_tcpdump]}
    rc = 1
    for backend in backends[args.backend]:
        name = backend.__name__[4:]
        print('monitor: backend=%s %s victim=%s out=%s' % (
            name, 'pcap=' + args.pcap if args.pcap else 'iface=' + args.iface, args.victim, args.out),
            file=sys.stderr, flush=True)
        try:
            rc = backend(args, mon.on_packet)
            break
        except KeyboardInterrupt:
            rc = 0
            break
        except Exception as e:  # e.g. scapy missing or failing to open the interface
            print('monitor: backend %s failed: %s: %s' % (name, type(e).__name__, e), file=sys.stderr, flush=True)
    if args.pcap:
        with mon.lock:
            mon.write(mon.tracker.flush())
    print('monitor: %s' % ' '.join('%s=%d' % kv for kv in mon.tracker.counts.items()),
          file=sys.stderr, flush=True)
    return rc


if __name__ == '__main__':
    sys.exit(main())
