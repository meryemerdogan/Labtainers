# CENG 519 — Milestone 2 Plan: `slow-scan` First Version

Companion document: [LABTAINERS_GUIDE.md](LABTAINERS_GUIDE.md) explains how Labtainers works.
Proposal: [CENG519_Low_and_Slow_Scan_Detection_Proposal.md](CENG519_Low_and_Slow_Scan_Detection_Proposal.md)

---

## 1. What Milestone 2 asks for, and how we meet it

| Requirement (Week 8) | How we satisfy it | Section |
|---|---|---|
| New lab under `labs/<lab-name>/` in branch `project/<student-number>-<lab-name>` | `labs/slow-scan/` on `project/2736403-slow-scan` | §3, §4 |
| Main containers, virtual networks, IP addressing and routing implemented | 3 containers (attacker, client, victim) on one LAN `172.20.0.0/24`. Single LAN, so no router is needed | §4 |
| `rebuild slow-scan` gives a working environment with no undocumented manual steps | All services start from systemd units enabled in `fixlocal.sh`. Nothing has to be typed after `rebuild` | §5, §6 |
| A reproducible attack runs inside the lab | `scan.py` on the attacker: fast (`--delay 0.05`) and slow (`--delay 10`) TCP connect scans | §8 |
| A basic detection mechanism is demonstrated | `monitor.py` logs each connection attempt. `detector.py` runs in baseline mode (60 s window) and proposed mode (10 min window + failure rate) | §6, §7 |
| Submit: URL + branch + commit hash, 2–4 page PDF report, optional video | Checklist in §11, report outline in §12 | §11, §12 |

**Scope for this milestone.** Environment + attack + monitor + both detector modes + a minimal client.
**Later (Milestone 3):** full benign traffic generator, `results.config`/`goals.config`, `parameter.config`, the evaluation runs, and the guides.

---

## 2. Current state (checked on 2026-11-14)

- `labs/slow-scan/` contains only an empty `README.md`, from commit `d561e916` ("Lab folder created").
- The local checkout is on **`master`**. The working branch `origin/project/2736403-slow-scan` already exists.
- `origin` = `https://github.com/meryemerdogan/Labtainers.git`.
- On the Windows machine `core.autocrlf=true`. Shell and Python scripts **must** end up with LF line endings (see §3.4).
- Labtainers needs Linux + Docker. **All building and testing happens in a Linux VM.**

---

## 3. Step 0 — Development environment (both members, first day)

### 3.1 VM
Use one of:
- The **Labtainers VM appliance** (VirtualBox or VMware) from https://nps.edu/web/c3o/virtual-machine-images. Docker and Labtainers are pre-installed. Recommended.
- An Ubuntu 20.04/22.04 VM. Install Docker, then follow `setup_scripts/install-docker-ubuntu.sh`.

Give the VM at least 4 GB RAM and 30 GB disk.

### 3.2 Clone our fork in the VM and point Labtainers at it
```bash
git clone https://github.com/meryemerdogan/Labtainers.git ~/Labtainers
cd ~/Labtainers
git checkout project/2736403-slow-scan

# The appliance's ~/.bashrc points LABTAINER_DIR at ~/labtainer/trunk. Override it:
cat >> ~/.bashrc <<'EOF'
export LABTAINER_DIR=$HOME/Labtainers
export PATH=$LABTAINER_DIR/scripts/designer/bin:$PATH
alias cdlab="cd $LABTAINER_DIR/scripts/labtainer-student"
EOF
source ~/.bashrc
```
- `rebuild.py` reads `LABTAINER_DIR` (`scripts/labtainer-student/bin/rebuild.py:542`).
- `rebuild`, `labtainer`, `stoplab` and `checkwork` are found through the `./bin` entry in PATH, so they only work when you are in `scripts/labtainer-student`.

### 3.3 Sanity check that the toolchain works
```bash
cdlab
rebuild iptables2      # an existing lab built on the same base images (network2 / network.ssh2)
stoplab
```
The first run pulls the base images (`labtainer.base2`, `labtainer.network2`, ...) from Docker Hub and takes a while.

### 3.4 Line endings and Git workflow
- Create `labs/slow-scan/.gitattributes` with:
  ```
  * text=auto eol=lf
  ```
- If you edit on Windows, check scripts with `file victim/_system/usr/bin/*.py` in the VM. CRLF breaks `#!/usr/bin/env python3`.
- `labs/iptables2/server/server` in the repo has CRLF endings. **Don't copy it byte for byte.**
- On Windows, leave `master`:
  ```
  git fetch origin
  git checkout -b project/2736403-slow-scan origin/project/2736403-slow-scan
  ```
- Each member works on a short feature branch (`m1/env`, `m2/detector`) and merges into `project/2736403-slow-scan`. Or both commit directly with frequent `git pull --rebase`.
- `rebuild` uses **git modification dates** to decide whether an image is stale. After deleting files, or if something looks cached, run `rebuild slow-scan -f`.

---

## 4. Step 1 — Lab skeleton and topology (Member 1)

### 4.1 Generate the skeleton (in the VM)
```bash
cd $LABTAINER_DIR/labs/slow-scan
new_lab_setup.py -b network2                     # creates config/, dockerfiles/, docs/, instr_config/, slow-scan/
new_lab_setup.py -r slow-scan attacker           # rename the default container
new_lab_setup.py -a client -b network2
new_lab_setup.py -a victim -b network.ssh2       # network2 + sshd started by xinetd
```
- `new_lab_setup.py` lives in `scripts/designer/bin/new_lab_setup.py`. Its flags are `-a -A -C -r -m -d -c -b`.
- It maps `network` to `network2` automatically.
- Add these by hand (`new_lab_setup.py` does not create them):
  - `config/about.txt`: one line, e.g. "Detect low-and-slow TCP port scans with a long-window, failure-rate detector."
  - `config/keywords.txt`: one per line, e.g. `scan detection`, `intrusion detection`, `ids`, `nmap`, `network monitoring`.
  - `docs/read_first.txt`: points to the lab manual, as in `labs/tcpip/docs/read_first.txt`.

### 4.2 Topology

```text
   +------------------+         +-------------------+
   |  attacker        |         |  client           |
   |  172.20.0.10     |         |  172.20.0.20      |
   |  scan.py, nmap   |         |  benign_traffic.py|
   +--------+---------+         +---------+---------+
            |                             |
   =========+======= LAN 172.20.0.0/24 ===+=========
                          |
               +----------+-----------+
               |  victim  172.20.0.30 |
               |  :80 http  :22 ssh   |
               |  :8081 :9090 test    |
               |  monitor.py          |
               |  detector.py x2      |
               +----------------------+
```

### 4.3 `config/start.config`
```
GLOBAL_SETTINGS
	LAB_MASTER_SEED slow-scan_2736403_master_seed

NETWORK SLOWSCAN_LAN
	MASK 172.20.0.0/24
	GATEWAY 172.20.0.100

CONTAINER attacker
	USER ubuntu
	TERMINALS 1
	SLOWSCAN_LAN 172.20.0.10

CONTAINER client
	USER ubuntu
	TERMINALS 1
	SLOWSCAN_LAN 172.20.0.20

CONTAINER victim
	USER ubuntu
	TERMINALS 1
	SLOWSCAN_LAN 172.20.0.30
```
- `GATEWAY` is Docker's link to the host. It must be inside `MASK` and must not be a container IP. `.100` follows `labs/denyhost`.
- **Network name:** the NETWORK name becomes the Docker network name (lower-cased). Seven other labs (centos-log2, cgc, dhcp-test, dns, ghidra, kali-test, ldap) call theirs `LAN` on other subnets. Labtainers reuses an existing network with the same name instead of creating one, so a leftover `lan` network would break our addresses. Hence `SLOWSCAN_LAN`.
- **Routing:** all hosts share one L2 segment, so no routes are needed. Say this explicitly in the report.
- 172.20.0.0/24 is also used by 11 other labs (denyhost, httplab, liveforensics, pcapanalysis, plc-traffic, ssh-agent, sshlab, telnetlab, vpnlab, vpnlab2, wireshark-intro). Only one of them can run at a time; stop the other lab first.
- If you want the client terminal hidden later (pure bot), use `TERMINALS 0`.

---

## 5. Step 2 — Dockerfiles (Member 1)

`new_lab_setup.py` generates `dockerfiles/Dockerfile.slow-scan.<container>.student` from `scripts/designer/templates/dockerfiles/Dockerfile.template.base2.student`. Change only the `FROM` line and add packages **before** `USER $user_name`.

**victim:** `dockerfiles/Dockerfile.slow-scan.victim.student`
```dockerfile
FROM $registry/labtainer.network.ssh2
...
RUN /usr/bin/apt-source.sh
RUN apt-get update && apt-get install -y --no-install-recommends python3-scapy
...
```
**attacker:** `FROM $registry/labtainer.network2`. No extra packages; `python3`, `nmap` and `nc` are already there.

**client:** `FROM $registry/labtainer.network2`. Add `curl` and `sshpass` (needed later for scripted SSH logins):
```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends curl sshpass
```

What the base images already contain (see [LABTAINERS_GUIDE.md §4](LABTAINERS_GUIDE.md)):
- `network2` has `python3`, `pip3`, `openssh-server`, `tcpdump`, `nmap`, `netcat-openbsd`, `xinetd`, `iptables`, `wget`.
- **No base image has scapy.**

---

## 6. Step 3 — Victim services (Member 1)

Everything below lives in `labs/slow-scan/victim/`. Files under `_system/` are copied to `/` in the container. Files under `_bin/` go to `~/.local/bin/`.

| File | Purpose | Copy from |
|---|---|---|
| `_system/usr/bin/MyHTTPServer.py` | Web server on port 80. **Port it to Python 3** (`http.server`). Log in httpd format to `/var/log/myhttplogfile.txt` | `scripts/designer/services/web-server.tar` (Python 2 version) |
| `_system/etc/systemd/system/httpserver.service` | runs it as root | same tar |
| `_system/var/www/html/index.html` | page | same tar |
| `_system/usr/bin/testsvc.py` | tiny TCP banner service: `testsvc.py <port> <name>`; accepts, sends a banner, closes | new (idea: `labs/iptables2/server/server`) |
| `_system/etc/systemd/system/testsvc1.service` | `ExecStart=/usr/bin/testsvc.py 8081 inventory` | new |
| `_system/etc/systemd/system/testsvc2.service` | `ExecStart=/usr/bin/testsvc.py 9090 backup` | new |
| `_system/etc/rc.local` | `#!/bin/bash` + `mkdir -p /run/sshd` + `exit 0` (sshd on base2 needs it) | `labs/tcpip/server/_system/etc/rc.local` |
| SSH on port 22 | already provided by `network.ssh2` (xinetd + `/etc/xinetd.d/ssh`) | — |
| `_bin/fixlocal.sh` | enables and starts all services (see below) | `labs/plc-app/monitor/_bin/fixlocal.sh` |

Ports 8081 and 9090 are fixed for now. They become the parameters `TEST_PORT1`/`TEST_PORT2` in Milestone 3.

**systemd unit template** (pattern from `labs/plc-app/monitor/_system/lib/systemd/system/heartbeat.service`). With no `User=`, the unit runs as root, which packet capture needs.
```ini
[Unit]
Description=slow-scan connection monitor
After=waitparam.service network.target

[Service]
Type=simple
ExecStart=/usr/bin/monitor.py --iface eth0 --victim 172.20.0.30 --out /var/log/slowscan/conn.log
Restart=on-failure
StandardOutput=null

[Install]
WantedBy=multi-user.target
```

**`victim/_bin/fixlocal.sh`.** This runs once, as user `ubuntu` with passwordless sudo, after parameterization.
```bash
#!/bin/bash
sudo mkdir -p /var/log/slowscan
for s in httpserver testsvc1 testsvc2 slowscan-monitor slowscan-baseline slowscan-proposed; do
    sudo systemctl enable $s
done
# unblock waitparam.service (prerequisite of our units)
sudo mkdir -p /var/labtainer/did_param
for s in httpserver testsvc1 testsvc2 slowscan-monitor slowscan-baseline slowscan-proposed; do
    sudo systemctl start $s
done
sudo /etc/init.d/xinetd restart
```
Because the units are enabled, they also come back after `stoplab` followed by `labtainer slow-scan`.

**Check inside the victim:**
- `sudo systemctl status httpserver testsvc1 slowscan-*`
- `ss -tlnp` should list 22, 80, 8081 and 9090.

---

## 7. Steps 4–5 — Monitoring and detection

### 7.1 The agreed log format. Freeze this on day 1 so both members can work in parallel.

`/var/log/slowscan/conn.log`, one line per connection attempt:
```
2026-11-20T10:15:03 src=172.20.0.10 sport=40312 dst=172.20.0.30 dport=22 result=OK
2026-11-20T10:15:13 src=172.20.0.10 sport=40318 dst=172.20.0.30 dport=23 result=FAIL
2026-11-20T10:15:23 src=172.20.0.10 sport=40322 dst=172.20.0.30 dport=24 result=TIMEOUT
```
- The timestamp **must** start the line as `YYYY-MM-DDTHH:MM:SS`.
  - Labtainers' assessment parser (`getTS` in `scripts/labtainer-instructor/assess_bin/ResultParser.py:369`) understands this ISO form.
  - It only tries ISO if the line has **no `[` … `]`**, so never use square brackets in our logs.
  - Python `logging`'s default `2026-11-20 10:15:03,123` does **not** parse.
- `result` is one of:
  - `OK` = the victim replied SYN-ACK
  - `FAIL` = the victim replied RST
  - `TIMEOUT` = no reply within 3 s (counts as a failure)

`/var/log/slowscan/baseline.log` and `/var/log/slowscan/proposed.log`:
```
2026-11-20T10:15:00 HEARTBEAT mode=baseline window=60 threshold=12
2026-11-20T10:17:05 ALERT mode=proposed src=172.20.0.10 dst=172.20.0.30 ports=12 attempts=13 fail=0.92 first_seen=2026-11-20T10:15:03 delay=122
```

### 7.2 `monitor.py` (Member 1): `victim/_system/usr/bin/monitor.py`
- Unit `slowscan-monitor.service`, run as root.
- `scapy.sniff(iface="eth0", filter="tcp and host 172.20.0.30", store=False, prn=handle)`.
- **Inbound SYN** (flags exactly `S`, dst = victim):
  - Key `(src, sport, dport)`.
  - If the key is already pending, it is a retransmission. **Count it once.**
  - Otherwise store it as pending with its first-seen time.
- **Outbound SYN-ACK** (`SA`) for a pending key: write `result=OK`.
- **Outbound RST** (`R`/`RA`) for a pending key: write `result=FAIL`.
- A background thread writes `result=TIMEOUT` for keys pending more than 3 s.
- Flush after every line (`line_buffering=True`) so the detectors see lines immediately.
- **Fallback** if scapy gives trouble: run `tcpdump -l -n -i eth0 'tcp and host 172.20.0.30 and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)'` as a subprocess and parse its lines into the same format.
- Unit test without containers: feed a pcap with `sniff(offline="x.pcap")`.

### 7.3 `detector.py` (Member 2): `victim/_system/usr/bin/detector.py`
```
detector.py --mode baseline|proposed
            [--threshold 12] [--window SECONDS] [--fail-ratio 0.70]
            (--follow /var/log/slowscan/conn.log | --replay recorded_conn.log)
            [--out FILE] [--heartbeat 30]
```
- Defaults:
  - baseline: `window=60`, no failure-rate condition
  - proposed: `window=600`, `fail-ratio=0.70`
- Per source keep a `deque` of `(t, dport, failed)`. Drop entries older than `t_now - window`.
  - `distinct = len({dport})`
  - `fail = failed_count / attempts`
- Rules:
  - **Baseline:** `distinct >= threshold`.
  - **Proposed:** `distinct >= threshold and fail >= fail_ratio`.
- Alert **once per source**, then a cooldown (e.g. no new alert for the same source for one window).
  - Include `first_seen`, the time of the source's first attempt, and `delay = alert_time - first_seen`. Section 6 of the proposal uses this as the detection delay.
- **Follow mode:** tail the file like `tail -F`, starting at the end. Use wall-clock time for heartbeats.
- **Replay mode:** read the whole file and use the timestamps in the log as the clock. Both modes then see identical input, which is the core of the Milestone 3 evaluation.
- Two units:
  - `slowscan-baseline.service`: `--mode baseline --follow ... --out /var/log/slowscan/baseline.log`
  - `slowscan-proposed.service`: `--mode proposed --follow ... --out /var/log/slowscan/proposed.log`
- Keep the decision logic in a pure function, `update(state, event) -> alert|None`, so Member 2 can test it on a laptop with hand-written `conn.log` files before the containers are ready:
  - fast scan
  - slow scan at 10 s
  - health check (4 ports, all OK)
  - outage retries (1 port, all FAIL)

### 7.4 Expected behaviour (sanity numbers)

| Traffic | Baseline (12 ports / 60 s) | Proposed (12 ports / 600 s, ≥70 % fail) |
|---|---|---|
| Fast scan, 0.05 s delay, 100 ports | alert in under 1 s | alert in under 1 s |
| Slow scan, 10 s delay | max 6 ports/min, **no alert** | 12 ports after ~110–120 s, **alert** |
| Slow scan, 30 s delay | no alert | 12 ports after ~330 s, alert |
| Slow scan, >50 s delay | no alert | **missed by design** (fewer than 12 ports in 600 s) |
| Health check: 4 services, all OK | no alert | no alert (4 ports, 0 % fail) |
| Outage retries: 1 port, all FAIL | no alert | no alert (1 port) |

---

## 8. Step 6 — Attack: `attacker/scan.py` (Member 1)

The file sits in `labs/slow-scan/attacker/scan.py` and lands in `/home/ubuntu/scan.py`.
```
python3 scan.py 172.20.0.30 --ports 20-40,79-81,8080-8082,9089-9091 --delay 10
        [--jitter 0.3] [--random-order] [--seed 7] [--timeout 1]
```
- Ports accept a list or ranges. Run a TCP connect scan with `socket.connect_ex`, with timeout 1 s.
- `--delay` sets the sleep between probes. `--jitter` gives a uniformly random ±fraction of it (the "random delay" in the proposal). `--random-order` shuffles the ports, using `--seed` for reproducibility.
- Print one line per probe (`2026-11-20T10:15:03 port 22 open`) and a summary of the open ports.
- Stdout is captured by Labtainers' stdin/stdout mirroring, which is useful for assessment later.
- Reference presets for the demo:
  - fast: `--delay 0.05 --ports 1-200`
  - slow: `--delay 10 --ports 15-40,8079-8083,9088-9092` (36 ports, ~6 min)
- Comparison with real tools: `nmap -sT -T5 172.20.0.30` (fast) and `nmap -sT -T1 -p 1-30 172.20.0.30` (T1 waits 15 s between probes). nmap is already in the image.

## 9. Step 7 — Minimal client (Member 1; optional for M2)

`labs/slow-scan/client/benign_traffic.py` (lands in `$HOME`). For now it only has to show that legitimate traffic is logged as `OK`:
- Every 5 s, `curl -s http://172.20.0.30/`.
- Every 60 s, a "health check" that connects to 22, 80, 8081 and 9090.

The full generator (SSH logins with `sshpass`, the outage scenario, seeds) is Milestone 3 work.

---

## 10. Step 8 — Demo run and evidence collection (both; Member 2 collects the evidence)

```bash
cdlab
rebuild slow-scan            # use -f after deleting files
```
1. **victim terminal:**
   - `sudo systemctl status slowscan-monitor slowscan-baseline slowscan-proposed --no-pager`
   - `ss -tlnp`
   - `sudo tail -f /var/log/slowscan/*.log`
2. **client terminal:** `curl 172.20.0.30` several times. Each request appears in `conn.log` as `result=OK`, with no alerts.
3. **attacker terminal:** `python3 scan.py 172.20.0.30 --ports 1-200 --delay 0.05`. Both baseline and proposed raise an ALERT.
4. `stoplab`, then `labtainer -r slow-scan` for a clean state.
   - attacker: the slow scan preset (`--delay 10`).
   - Expected: baseline shows only HEARTBEAT lines; proposed alerts about 2 min after the first probe.
5. Optional packet evidence on the victim:
   - capture: `sudo tcpdump -n -i eth0 -c 30 'host 172.20.0.10' -w /tmp/slow.pcap`
   - read: `tcpdump -n -r /tmp/slow.pcap | head`
   - This shows the SYN → RST pairs.
6. Take screenshots of all three terminals for each scenario. Copy the log excerpts (`docker cp slow-scan.victim.student:/var/log/slowscan ./evidence` or `cat` + copy). Optionally record a 2–3 minute video.
7. **Final gate (mandatory before submitting).** In a *different* directory or VM user:
   ```bash
   git clone https://github.com/meryemerdogan/Labtainers.git /tmp/fresh && cd /tmp/fresh
   git checkout <commit-hash>
   export LABTAINER_DIR=/tmp/fresh && cd scripts/labtainer-student
   rebuild slow-scan -f
   ```
   Repeat steps 1–4. Only this commit hash goes into the submission.

**Debugging:**
- `scripts/labtainer-student/labtainer.log`
- `$LABTAINER_DIR/logs/docker_build.log`
- in the container: `/tmp/parameterize.sh.log`, `/tmp/fixlocal.output`, `journalctl -u slowscan-monitor`

---

## 11. Step 9 — Commit and submit

- Lab files go only under `labs/slow-scan/`. Keep this plan, the guide and the proposal outside the lab directory. They can stay uncommitted, or go in a `project-docs/` folder if the team wants them versioned.
- Delete the empty `labs/slow-scan/README.md`, or put a short description in it.
- Commit, then `git push origin project/2736403-slow-scan`. Check on GitHub that the branch shows the files.
- **Online text:**
  ```
  Repository: https://github.com/meryemerdogan/Labtainers
  Branch:     project/2736403-slow-scan
  Commit:     <40-char hash from: git rev-parse HEAD>
  Demo video: <link, optional>
  ```

---

## 12. Step 10 — Progress report (PDF, 2–4 pages)

1. **Implemented topology:** the diagram from §4.2, plus a table of containers, IPs, base images, services/ports and scripts.
2. **Build and run instructions:** clone, `LABTAINER_DIR`, `cdlab`, `rebuild slow-scan`, and the demo commands from §10. State that no manual steps are needed.
3. **Attack scenario:** `scan.py` options, fast vs slow presets, and why the slow one evades a 60 s window.
4. **Basic detection, with evidence:**
   - a `conn.log` excerpt (OK/FAIL lines)
   - a baseline ALERT on the fast scan
   - baseline HEARTBEAT-only output during the slow scan, next to the proposed ALERT with its `delay`
   - a 5–10 line tcpdump excerpt showing SYN/RST
   - one screenshot
5. **Deviations from the proposal.** Fill in honestly. Likely items:
   - the monitor uses scapy in a systemd service
   - the detector runs as two services that tail a shared log
   - the proposed mode was already implemented in M2
   - fixed test-service ports (8081/9090) until parameterization
   - TIMEOUT counted as a failure
   - log timestamps in ISO format for Labtainers' parser
6. **Plan for remaining work**, with owners and dates:
   - **Benign traffic** (M1): web + SSH logins, health check every minute, outage retries on one stopped service, seeds.
   - **Automated assessment** (M1: objectives 1, 4; M2: objectives 2, 3): results.config entries on `victim:/var/log/slowscan/*.log` and `/var/log/myhttplogfile.txt`; goals using `time_during` / `boolean ... and_not` / `count_greater` (draft in [LABTAINERS_GUIDE.md §9](LABTAINERS_GUIDE.md)).
   - **Parameterization:** `RAND_REPLACE` for `TEST_PORT1`/`TEST_PORT2` (disjoint ranges) in the unit files and the client script, plus `THRESHOLD` (10–14) in the detector unit files.
   - **Evaluation** (M1: recording and labels; M2: replay and metrics): delays 1/10/30 s × 5 seeds with benign traffic. Metrics: detection rate, false-positive rate, detection delay.
   - **Student guide and instructor guide** (`labs/slow-scan/docs/`).

Write the report in LaTeX or Word, with the topology figure drawn in draw.io.

---

## 13. Work split for Milestone 2

| Area | Member 1 | Member 2 |
|---|---|---|
| Environment | §3 VM check, §4 skeleton + start.config, §5 Dockerfiles, §6 victim services + fixlocal | §3 VM check |
| Attack / traffic | §8 `scan.py`, §9 minimal client | — |
| Detection | §7.2 `monitor.py` + its unit | §7.3 `detector.py` (both modes, follow + replay) + 2 units + offline tests |
| Verification | §10 demo run | §10 evidence collection, final fresh-clone gate |
| Report | Sections 1–3 | Sections 4–6, assembly into PDF |

Shared: agree on §7.1 first, review each other's code, and both run the final gate.

### Suggested timeline (adjust to the real deadline)
| Day | Milestone |
|---|---|
| 1 | VMs ready, `rebuild iptables2` works, log format frozen |
| 2–3 | Skeleton builds; victim services up; detector passes offline tests |
| 4 | monitor.py writes conn.log; detectors running as services |
| 5 | scan.py + full demo works end-to-end |
| 6 | Fresh-clone gate, evidence, screenshots, video |
| 7 | Report finished, push, submit commit hash |

---

## 14. Done checklist

- [ ] Branch `project/2736403-slow-scan` contains `labs/slow-scan/{config,dockerfiles,docs,instr_config,attacker,client,victim}`
- [ ] `config/about.txt`, `config/keywords.txt`, `docs/read_first.txt` present
- [ ] All scripts have LF endings and are executable (`_bin` files are made executable automatically; for `_system/usr/bin/*.py` run `git update-index --chmod=+x` or `chmod +x` in the VM before committing)
- [ ] `rebuild slow-scan -f` from a fresh clone succeeds and opens 3 terminals
- [ ] Ports 22/80/8081/9090 are open on the victim with no manual commands
- [ ] `conn.log` gets lines for client traffic (OK) and scans (FAIL)
- [ ] Fast scan: baseline and proposed alert
- [ ] Slow scan: baseline silent, proposed alerts about 2 min after the first probe
- [ ] Evidence (logs, tcpdump excerpt, screenshots) saved
- [ ] Report PDF 2–4 pages, includes deviations and the remaining-work plan
- [ ] Commit hash and URL submitted

---

## 15. Gotchas found in the codebase

- **sshd**: `network2` removes `ssh.service` from autostart. Use `network.ssh2`, which runs sshd through xinetd, and `mkdir -p /run/sshd` in `rc.local`.
- **Python 2 templates**: `MyHTTPServer.py` (web-server.tar) and `labs/nmap-ssh/client/webbot.py` are Python 2. Port them to Python 3.
- **Timestamps**: ISO lines must have no square brackets. Otherwise the httpd branch of `getTS` is tried instead.
- **Artifact collection**: at `stoplab` only absolute paths **named in `results.config`** are copied (`GatherOtherArtifacts`, `scripts/labtainer-student/bin/labutils.py:2148`). Add `victim:/var/log/slowscan/...` entries in M3, or the logs won't reach the grader.
- **Startup order**:
  1. systemd boots
  2. parameterization
  3. `fixlocal.sh` (first start only)
  4. `/var/labtainer/did_param` is created, which releases `waitparam.service`
  5. `rc.local` and our units (`After=waitparam.service`) start

  Anything that reads parameterized files must wait for `waitparam`.
- **Stale images**: `rebuild` compares git modification dates. Use `-f` after deleting or renaming files.
- **Subnet clash**: 11 other labs use 172.20.0.0/24 (see §4.3). Only one of these labs can run at a time.
- **`new_lab_setup.py` on a Windows checkout**: it copies `_bin/`, `_system/` and `instr_config/` templates byte for byte, so they come out with CRLF. Normalize to LF afterwards (`tests/check_lab.py` flags any CRLF).
- **Missing `LAB_MASTER_SEED`** makes Labtainers' `ParseStartConfig` crash with a `TypeError` instead of printing its "Missing lab_master_seed" error.
