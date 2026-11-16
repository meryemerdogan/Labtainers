# Steps 4–5: Monitor and detectors, implementation notes

Companion to [MILESTONE2_PLAN.md §7](MILESTONE2_PLAN.md) and [STEP3_VICTIM_SERVICES.md](STEP3_VICTIM_SERVICES.md). Step 3 left the victim with services on 22/80/8081/9090. This step adds:
- the connection monitor (Step 4),
- the baseline and proposed detectors (Step 5).

All three run as systemd services on the victim and start with no manual commands.

---

## 1. Result

```text
                 victim 172.20.0.30
  eth0 ──► slowscan-monitor (monitor.py, root, scapy | tcpdump)
                 │ one line per inbound connection attempt
                 ▼
           /var/log/slowscan/conn.log
                 │ tail -F                    │ tail -F
                 ▼                            ▼
  slowscan-baseline (detector.py)   slowscan-proposed (detector.py)
  12 ports / 60 s                   12 ports / 600 s and >= 70 % failed
                 ▼                            ▼
  /var/log/slowscan/baseline.log    /var/log/slowscan/proposed.log
```

Measured on the replay fixtures (§7). These are the numbers of plan §7.4:

| Traffic | Baseline | Proposed |
|---|---|---|
| Fast scan, 0.05 s, ports 1–200 | ALERT, delay 0 s | ALERT, delay 0 s |
| Slow scan, 10 s | silent | ALERT, delay **110 s** |
| Slow scan, 30 s | silent | ALERT, delay 330 s |
| Slow scan, 50 s | silent | ALERT, delay 550 s (last delay that fits in 600 s) |
| Slow scan, 60 s | silent | silent (missed by design) |
| Slow scan, 10 s ± 30 % jitter, random order, 5 seeds | silent | ALERT, delay 80–150 s |
| Health check: 4 services/min, all OK | silent | silent |
| Web browsing every 5 s | silent | silent |
| Outage retries: 1 port, all FAIL | silent | silent |
| 30 min benign traffic + 10 s slow scan | silent | ALERT on the attacker only, delay 110 s |

## 2. Files

```text
labs/slow-scan/
├── victim/
│   ├── _bin/fixlocal.sh                               unchanged: already lists the three new units
│   └── _system/
│       ├── usr/bin/monitor.py                         new (Step 4)
│       ├── usr/bin/detector.py                        new (Step 5)
│       └── etc/systemd/system/
│           ├── slowscan-monitor.service               new
│           ├── slowscan-baseline.service              new
│           └── slowscan-proposed.service              new
├── tests/
│   ├── scenarios.py                                   new: synthetic traffic + expected alerts
│   ├── fixtures/*.log                                 new: 9 recorded conn.log files (generated)
│   ├── test_monitor.py                                new: 17 tests (1 needs scapy)
│   ├── test_detector.py                               new: 36 tests
│   ├── check_lab.py                                   + "detection" group, Python 3.8 syntax, bytecode check
│   ├── test_check_lab.py                              + 12 mutation tests
│   └── runtime_check.sh                               + Steps 4–5 checks, --no-scan, --slow
└── README.md                                          + monitoring/detection section
```

## 3. Log formats (plan §7.1, unchanged)

```text
conn.log      2026-11-20T10:15:03 src=172.20.0.10 sport=40312 dst=172.20.0.30 dport=22 result=OK
baseline.log  2026-11-20T10:15:00 HEARTBEAT mode=baseline window=60 threshold=12 events=42
proposed.log  2026-11-20T10:17:05 ALERT mode=proposed src=172.20.0.10 dst=172.20.0.30 ports=12 attempts=13 fail=0.92 first_seen=2026-11-20T10:15:03 delay=122
```

- Every line starts with `YYYY-MM-DDTHH:MM:SS` and has no square brackets. That is the ISO branch of Labtainers' `getTS`, needed for the M3 assessment.
- HEARTBEAT lines got two extra fields:
  - `fail_ratio=0.70` in proposed mode,
  - `events=N`, the number of conn.log lines processed so far. In a demo this shows the detector is alive and reading.
- `check_lab.py` loads the real `monitor.py` and `detector.py` and checks that every line the monitor can write is parsed by the detector. If either side changes the format, the check fails.

## 4. Step 4: `monitor.py`

### 4.1 Classifying packets
The decision logic is a small class, `ConnTracker`. It does no I/O and reads no clock: packets go in, finished conn.log lines come out. That makes it testable without scapy or root.

| Packet | Action |
|---|---|
| inbound **SYN**: dst = victim, SYN set, no ACK/RST/FIN | new key `(src, sport, dport)` → pending, remember its time. If the key is already pending, it is a **retransmission**: not counted again. |
| outbound **SYN-ACK** for a pending key | write `result=OK` |
| outbound **RST** (`R` or `RA`) for a pending key | write `result=FAIL` |
| pending for ≥ 3 s | write `result=TIMEOUT`. For 30 s afterwards, further SYNs on that key are treated as retransmissions (Linux retries at 1, 3, 7, 15 s) |
| anything else | ignored: the victim's own outbound connections, traffic to other hosts, handshake ACKs, data, FIN, a RST on an already established connection, SYN-ACK/RST without a SYN |

Details that matter:
- **ECN.** Linux may send a SYN with `ECE|CWR` set. Only the SYN/ACK/RST/FIN bits are compared, so these still count. Comparing "flags exactly `S`", as the plan says, would have silently missed them.
- **Timestamp = time of the first SYN.** OK and FAIL lines are written immediately. TIMEOUT lines are written 3 s later with the earlier time, so conn.log can be **out of order by up to 3 s**. The detector is built for that (§5.3).
- **Line buffering.** Each line is flushed at once, so the detectors see it immediately.

### 4.2 Capture backends
- `--backend scapy`: `sniff(iface="eth0", filter=BPF, store=False, prn=...)`, as in the plan.
- `--backend tcpdump`: runs `tcpdump -l -n -tt -i eth0 BPF` and parses lines like `1795000000.000100 IP 172.20.0.10.40312 > 172.20.0.30.22: Flags [S.] ...`. This is the plan's fallback, built in.
- `--backend auto` (used by the unit): scapy first. If scapy can't be imported or fails to open the interface, it falls back to tcpdump and logs `backend scapy failed: ...` to the journal.
- BPF filter for both: `tcp and host 172.20.0.30 and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)`. Only SYN, SYN-ACK and RST packets reach Python, so a busy web server doesn't load the monitor.
- `--pcap FILE --out -` replays a capture offline (scapy or tcpdump `-r`). At the end, anything still pending is reported as TIMEOUT. The monitor's counters go to stderr, e.g. `OK=3 FAIL=33 TIMEOUT=1 retransmissions=1`.

## 5. Step 5: `detector.py`

```text
detector.py --mode baseline|proposed [--threshold 12] [--window S] [--fail-ratio R] [--cooldown S]
            (--follow FILE [--from-start] [--heartbeat 30] | --replay FILE) [--out FILE]
```

| | baseline | proposed |
|---|---|---|
| window | 60 s | 600 s |
| rule | `distinct ports >= 12` | `distinct ports >= 12` **and** `failed / attempts >= 0.70` |
| cooldown | 60 s (= window) | 600 s (= window) |

### 5.1 Decision logic: `update(state, event) -> Alert | None`
This has no I/O and reads no wall clock, so the same function runs live, in replay and in the tests.
1. The detector's clock is `state.now`, the **latest timestamp seen in conn.log**.
2. Per source, keep a sorted list of `(t, dport, failed)`. Insert the event, then drop entries with `t <= now - window`. The window is `(now - W, now]`.
3. `ports` is the number of distinct `dport` values. `fail` is `failed / attempts`, where FAIL and TIMEOUT both count as failed.
4. Rule from the table above. If it holds and the source is not in cooldown, raise an alert at time `now`:
   - `first_seen` = the oldest attempt of that source still in the window, i.e. the scan's first probe.
   - `delay = now - first_seen`: the detection delay of proposal §6.
5. Every 1000 events, sources whose newest entry has left the window are forgotten, so memory stays bounded.

### 5.2 Why the log's timestamps are the clock
The plan wants replay mode to drive the M3 evaluation. Window, alert time and `delay` all come from conn.log timestamps, in follow mode too. So following a live log and later replaying the same file produce **byte-identical ALERT lines**. Only HEARTBEAT lines use the wall clock.

### 5.3 Out-of-order lines
TIMEOUT lines arrive up to 3 s late (§4.1). Events are inserted in sorted position (`bisect.insort`), and `now` only moves forward. A test feeds the same events in arrival order and in time order and checks that the alerts are the same.

### 5.4 Follow mode (`tail -F`)
- On start it skips the lines already in conn.log (an earlier session's history) and reads only new ones. If conn.log doesn't exist yet (the monitor hasn't started), the detector waits and then reads the new file from its first line.
- Half-written lines are buffered until their newline arrives.
- A truncated or replaced file (logrotate) is reopened from the start.
- HEARTBEAT every 30 s, plus one right at start, so `baseline.log` is never empty during a slow scan.

### 5.5 Replay mode
`--replay FILE` reads the whole file, prints ALERT lines, and writes a summary to stderr:
`detector: replay slow_scan_10s.log: 36 events, 0 unparsed lines, 1 alerts (mode=proposed window=600 threshold=12 fail_ratio=0.70)`

## 6. Units and startup

```ini
slowscan-monitor.service   After=waitparam.service network.target              root (capture)
  ExecStart=/usr/bin/python3 /usr/bin/monitor.py --iface eth0 --victim 172.20.0.30 --out /var/log/slowscan/conn.log --backend auto
slowscan-baseline.service  After=waitparam.service slowscan-monitor.service
  ExecStart=/usr/bin/python3 /usr/bin/detector.py --mode baseline --threshold 12 --window 60 --follow /var/log/slowscan/conn.log --out /var/log/slowscan/baseline.log --heartbeat 30
slowscan-proposed.service  After=waitparam.service slowscan-monitor.service
  ExecStart=/usr/bin/python3 /usr/bin/detector.py --mode proposed --threshold 12 --window 600 --fail-ratio 0.70 --follow ... --out /var/log/slowscan/proposed.log --heartbeat 30
```

- All three have `Restart=on-failure` and `WantedBy=multi-user.target`.
- Same conventions as Step 3: the interpreter is named in `ExecStart`, and the units are ordered after `waitparam`. In M3, `THRESHOLD` (and the test ports) will be substituted into these unit files during parameterization, which finishes before waitparam releases them.
- `fixlocal.sh` already had these unit names in its list (Step 3), so it now enables and starts them. `/tmp/fixlocal.output` no longer shows "skipping" lines.

## 7. Deviations from plan §7 (for the report)

| Plan | Implemented | Reason |
|---|---|---|
| inbound SYN = flags exactly `S` | SYN/ACK/RST/FIN bits compared, ECN bits ignored | Linux SYNs can carry `ECE|CWR` |
| scapy, with tcpdump as a manual fallback | `--backend auto`: scapy, tcpdump automatically if scapy fails | no manual step if scapy misbehaves in the image |
| TIMEOUT after 3 s | same, plus 30 s retransmission memory | a SYN retransmitted at 7 s or 15 s is not counted as a new attempt |
| `deque` per source | sorted list per source | TIMEOUT lines arrive up to 3 s out of order |
| `first_seen` = source's first attempt | oldest attempt **in the window** | same value for a scan. Not skewed by a host that browsed an hour earlier and scans now (tested) |
| follow mode uses wall clock | wall clock only for HEARTBEAT; log time for everything else | follow and replay give identical alerts |
| HEARTBEAT `mode window threshold` | + `fail_ratio`, `events` | shows the detector is reading |
| alert once per source, then a cooldown | cooldown = window (configurable) | a scan longer than the window alerts again ("still scanning"). The evaluation uses the first alert per source |
| units run the scripts directly | `/usr/bin/python3 <script>` | works even if the exec bit is lost from a Windows commit |

## 8. Verification

### 8.1 Already run (Windows, Python 3.12, no Docker)

```text
python labs/slow-scan/tests/check_lab.py               205 passed, 6 warnings, 0 failed
python -m unittest discover -s labs/slow-scan/tests    Ran 120 tests ... OK (skipped=1: needs scapy)
<venv with scapy 2.5.0> -m unittest discover ...       Ran 120 tests ... OK (end-to-end test included)
bash -n tests/runtime_check.sh                         OK
```

- **`test_monitor.py`:**
  - every row of the §4.1 table, plus ECN, parallel attempts from two sources, and offline flush
  - every line it writes is valid detector input with no brackets
  - real tcpdump lines (`[S]`, `[S.]`, `[SEW]`, `[R.]`, IPv6 ignored) and the exact tcpdump command, with tcpdump faked
  - **End to end:** a crafted pcap goes through `monitor.py --backend scapy --pcap`, then `detector.py --replay`. The pcap holds a 36-port slow scan at 10 s, a client browsing every 5 s, and a filtered port with a retransmission. The monitor reports OK for 22/8081/9090, FAIL for the other 33 ports, OK for all client traffic, and TIMEOUT counted once for the filtered port. Baseline stays silent; proposed alerts with `fail=0.92 delay=110`.
- **`test_detector.py`:**
  - all fixtures in both modes (§1 table)
  - edges: the threshold counts as reached at exactly 12 ports; the window `(now-60, now]` is half-open; a repeated port counts once; a ratio of exactly 0.70 alerts and 0.65 doesn't, checked for every n up to 100; `--fail-ratio 0` gives a window-only detector
  - cooldown timing; independent sources; out-of-order TIMEOUT lines; first_seen after old benign traffic; memory cleanup
  - `--replay` output, byte for byte
  - `--follow` as a real process: skips old history, reads a file created later, waits for the rest of a half-written line, survives truncation, writes heartbeats
- **`check_lab.py`, new `detection` group:**
  - each unit's options: interface, victim IP, log paths, mode, window, threshold, ratio
  - the monitor runs as root; the detectors run after the monitor; baseline has no `--fail-ratio`; no detector writes into conn.log
  - the detector accepts each unit's settings
  - monitor and detector agree on the log format
  - two more checks in other groups: every victim script parses as **Python 3.8** (Ubuntu 20.04 in the image), and there are no `__pycache__`/`.pyc` files in container directories, since Labtainers would build them into the image. The tests now set `sys.dont_write_bytecode` so they don't create any.
- **Warnings:**
  - the usual subnet note
  - five exec-bit notes for untracked scripts (see §9)

### 8.2 To run in the Linux VM (not run yet: needs Docker)

```bash
cdlab
rebuild slow-scan -f
bash $LABTAINER_DIR/labs/slow-scan/tests/runtime_check.sh --slow
```

The new part of `runtime_check.sh` checks:
- the three units are active and enabled, and the journal shows which backend the monitor uses
- conn.log exists, and both logs contain HEARTBEAT lines
- a client `curl` produces a new `src=172.20.0.20 ... dport=80 result=OK` line, and an attacker probe of port 24 a `result=FAIL` line
- the last conn.log line matches the frozen format
- the client's normal traffic raises no alert
- **fast scan** (`nmap -sT -Pn -T4 -p 1-200` from the attacker): both detectors alert within 10 s
- **`--slow`** (about 2.5 min): the client probes 13 closed ports 10 s apart; proposed alerts, baseline stays silent

The client is used for the slow scan because the attacker is still in cooldown from the fast scan. `--no-scan` skips the fast scan. After running the script, restart with `labtainer -r slow-scan` before a demo or evidence collection, so the detectors start clean.

Demo (plan §10), by hand:

```bash
# victim
sudo tail -f /var/log/slowscan/*.log
# attacker: fast
nmap -sT -Pn -T5 172.20.0.30                       # both ALERT, delay=0
# stoplab; labtainer -r slow-scan, then attacker: slow (scan.py comes in Step 6)
nmap -sT -Pn -T1 -p 1-30 172.20.0.30               # T1 = 15 s between probes: baseline HEARTBEAT only, proposed ALERT ~165 s
```

Debugging: `journalctl -u slowscan-monitor -u slowscan-baseline -u slowscan-proposed`, `/tmp/fixlocal.output`.

## 9. Before committing

Add the five victim scripts with the executable bit:

```bash
git add --chmod=+x labs/slow-scan/victim/_system/etc/rc.local \
                   labs/slow-scan/victim/_system/usr/bin/MyHTTPServer.py \
                   labs/slow-scan/victim/_system/usr/bin/testsvc.py \
                   labs/slow-scan/victim/_system/usr/bin/monitor.py \
                   labs/slow-scan/victim/_system/usr/bin/detector.py
git add labs/slow-scan
python labs/slow-scan/tests/check_lab.py -q   # exec-bit warnings become PASS
```

- Commit `tests/fixtures/*.log`. They are the replay inputs, and `test_detector.py` fails if they drift from `scenarios.py`. To regenerate them: `python labs/slow-scan/tests/scenarios.py`.
- Don't commit `tests/__pycache__/` (already git-ignored).

## 10. Hooks for the next steps

- **Step 6 (`scan.py`):** any connect scan works with the monitor. `nmap -sT` is already verified by `runtime_check.sh`. Once `scan.py` exists, its presets (`--delay 0.05`, `--delay 10`) should reproduce the 0 s / 110 s delays of §1.
- **Milestone 3 evaluation:**
  - record conn.log from real runs (with benign traffic), then run `detector.py --replay` in both modes with any `--threshold`, `--window` or `--fail-ratio`. Recording happens once, and the parameter sweeps run offline.
  - `scenarios.py` already generates labelled traffic (attacker = scan, client = benign) to prototype the metrics.
- **Milestone 3 assessment:**
  - add `victim:/var/log/slowscan/conn.log`, `baseline.log` and `proposed.log` to `results.config`, or they aren't collected at `stoplab`
  - ALERT lines carry `src=`, `delay=` and an ISO timestamp for `getTS`
- **Parameterization:** `--threshold 12` appears once in each detector unit, so it is the place for `THRESHOLD`.
