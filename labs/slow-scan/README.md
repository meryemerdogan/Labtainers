# slow-scan

Labtainers lab for CENG 519: detecting low-and-slow TCP port scans with a
long-window, failure-rate detector, compared against a classic 60 s threshold
detector.

## Topology

```text
   attacker 172.20.0.10          client 172.20.0.20
   (network2: python3, nmap, nc) (network2 + curl, sshpass)
            |                             |
   =========+=== SLOWSCAN_LAN 172.20.0.0/24 ===+=========
                          |
               victim 172.20.0.30
               (network.ssh2: sshd via xinetd, + python3-scapy)
```

One flat L2 segment, so no router and no static routes are needed.
`GATEWAY 172.20.0.100` is only Docker's link to the host.
Other labs use 172.20.0.0/24 too (denyhost, httplab, sshlab, ...). Only one of
them can run at a time.

## Victim services

All start automatically: `victim/_bin/fixlocal.sh` enables them on the first
start, so they also come back after `stoplab` / `labtainer slow-scan`.

| Port | Service | Files (under `victim/_system/`) |
|---|---|---|
| 22 | sshd, started per connection by xinetd (`network.ssh2` base) | `etc/rc.local`, `etc/tmpfiles.d/sshd.conf` (create `/run/sshd`) |
| 80 | `MyHTTPServer.py` (Python 3), logs to `/var/log/myhttplogfile.txt` | `usr/bin/MyHTTPServer.py`, `etc/systemd/system/httpserver.service`, `var/www/html/index.html` |
| 8081 | `testsvc.py 8081 inventory`, banner service | `usr/bin/testsvc.py`, `etc/systemd/system/testsvc1.service` |
| 9090 | `testsvc.py 9090 backup`, banner service | `usr/bin/testsvc.py`, `etc/systemd/system/testsvc2.service` |

Inside the victim: `sudo systemctl status httpserver testsvc1 testsvc2 --no-pager` and `ss -tln`.

## Monitoring and detection

| Unit | Command | Output |
|---|---|---|
| `slowscan-monitor` | `monitor.py --iface eth0 --victim 172.20.0.30` (scapy, tcpdump fallback) | `/var/log/slowscan/conn.log`: one line per connection attempt, `result=OK/FAIL/TIMEOUT` |
| `slowscan-baseline` | `detector.py --mode baseline --threshold 12 --window 60 --follow conn.log` | `/var/log/slowscan/baseline.log` |
| `slowscan-proposed` | `detector.py --mode proposed --threshold 12 --window 600 --fail-ratio 0.70 --follow conn.log` | `/var/log/slowscan/proposed.log` |

```text
2026-11-20T10:15:03 src=172.20.0.10 sport=40312 dst=172.20.0.30 dport=22 result=OK
2026-11-20T10:15:00 HEARTBEAT mode=proposed window=600 threshold=12 fail_ratio=0.70 events=42
2026-11-20T10:17:05 ALERT mode=proposed src=172.20.0.10 dst=172.20.0.30 ports=12 attempts=13 fail=0.92 first_seen=2026-11-20T10:15:03 delay=122
```

Watch them live in the victim: `sudo tail -f /var/log/slowscan/*.log`.
Replay a recorded log (both modes see identical input):
`python3 victim/_system/usr/bin/detector.py --mode proposed --replay tests/fixtures/slow_scan_10s.log`.

## Build and run (Linux host with Labtainers)

```bash
export LABTAINER_DIR=~/Labtainers
cd $LABTAINER_DIR/scripts/labtainer-student
rebuild slow-scan          # add -f after deleting/renaming files
```

## Checks

| Script | Where | What |
|---|---|---|
| `tests/check_lab.py` | anywhere with Python 3 | static checks: layout, start.config (through Labtainers' own parser), topology, Dockerfiles, base-image assumptions, victim services, monitor/detector units, monitor-to-detector log format, Python 3.8 syntax, LF line endings, no bytecode in images |
| `tests/test_check_lab.py` | anywhere with Python 3 | mutation tests that prove `check_lab.py` catches real mistakes |
| `tests/test_services.py` | anywhere with Python 3 | runs `testsvc.py` and `MyHTTPServer.py` on localhost: banners, HTTP 200/404, log format parsed by Labtainers' `getTS` |
| `tests/test_monitor.py` | anywhere with Python 3 (+ scapy for the end-to-end test) | SYN/SYN-ACK/RST/timeout logic, retransmissions, tcpdump parsing; pcap -> `monitor.py` -> `detector.py` |
| `tests/test_detector.py` | anywhere with Python 3 | plan 7.4 scenarios in both modes, window/ratio/cooldown edges, out-of-order lines, `--replay`, `--follow` as a real process |
| `tests/scenarios.py` | anywhere with Python 3 | generates `tests/fixtures/*.log` (fast scan, slow scans at 10/30/50/60 s, health check, web, outage, mixed) |
| `tests/runtime_check.sh` | Labtainers host, lab running | images, containers, IPs, packages, users, services, ports, RST on closed ports, monitor/detector units, conn.log lines, fast-scan alerts (`--slow`: slow scan, baseline silent, proposed alerts) |

```bash
python3 labs/slow-scan/tests/check_lab.py
python3 -m unittest discover -s labs/slow-scan/tests -v
bash labs/slow-scan/tests/runtime_check.sh          # --rebuild to build first, --slow for the 2.5 min slow scan
```

`tests/` lives outside the container directories, so it never ends up in an image.
