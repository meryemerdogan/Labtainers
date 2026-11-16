# CENG 519 — Term Project Proposal

**Topic:** Low-and-slow scan detection  
**Title:** Detecting Low-and-Slow TCP Port Scans with Long-Window Connection Tracking  
**Lab name:** `slow-scan`  
**Team:** `<Member 1 name, student number>`, `<Member 2 name, student number>` (pair approved by the instructor)  
**Fork URL:** `https://github.com/meryemerdogan/Labtainers`  
**Branch:** `project/2736403-slow-scan`  
**Lab path:** `labs/slow-scan/`

## 1. Topic and Motivation

A port scan reveals which services a host exposes and is usually the first step of an attack. Fast scans are easy to detect because many ports are probed within seconds. A **low-and-slow** scan spreads the same probes over minutes, so a detector that counts ports over a short window never sees enough evidence. Simply making the window longer is not a complete fix: legitimate clients that use several services also accumulate "distinct ports" over time and cause false alarms.

This lab aims to make students see this tradeoff directly. They run a fast and a slow scan, watch a short-window detector miss the slow one, and then use a detector that combines a long window with the **failure rate** of connection attempts (scans mostly hit closed ports; normal clients mostly succeed).

Zeek's scan policy already describes the window-length tradeoff [1]. The contribution here is a reproducible, automatically graded teaching lab with a controlled comparison, not a new detection algorithm.

## 2. Novelty Check

| Existing lab | What it covers | How `slow-scan` differs |
|---|---|---|
| `nmap-discovery` | Using Nmap to find a host and port | Attacker side only; no detection |
| `nmap-ssh` | Nmap and traffic analysis of an SSH weakness | No detector, no timing analysis |
| `snort` | Snort rules; fast Nmap scan triggers the `ICMP PING NMAP` alert | Rule-based, fast scans only; no slow scans, no false-positive or delay measurement |
| `netflow` | Flow records with the SiLK tools | Traffic records only; no scan detection |

No existing lab studies how detection window length affects slow-scan detection and false alarms, and none has students implement and measure their own scan detector.

## 3. Threat Model

| Element | Description |
|---|---|
| Protected system | A victim server running a web server, SSH, and two extra test services |
| Attacker | A user on the attacker container with normal network access to the victim |
| Capabilities | Open TCP connections to any port; choose port order and delay between probes |
| Objective | Find the victim's open ports without being detected |
| Defender | Observes the victim's traffic, correlates connection attempts per source over time, and raises alerts |
| Assumptions | One scanning source, no IP spoofing, attacker cannot access the victim's monitor. Closed ports reply with TCP RST (Linux default). UDP and distributed scans are out of scope |
| Violated property | Confidentiality of the network's service inventory (unauthorized reconnaissance) |

## 4. Topology

Three containers on one isolated Labtainers network. The detector runs on the victim, so no routing setup is needed.

```text
   +------------------+         +-------------------+
   |  attacker        |         |  client           |
   |  172.20.0.10     |         |  172.20.0.20      |
   |  scan.py         |         |  benign_traffic.py|
   +--------+---------+         +---------+---------+
            |                             |
   =========+======= LAN 172.20.0.0/24 ===+=========
                          |
               +----------+-----------+
               |  victim  172.20.0.30 |
               |  web, SSH, 2 test    |
               |  services            |
               |  monitor.py +        |
               |  detector.py         |
               +----------------------+
```

| Container | Role |
|---|---|
| `attacker` | Runs the student scan generator |
| `client` | Runs benign traffic (legitimate user and health checks) |
| `victim` | Runs services; `monitor.py` records connection attempts, `detector.py` raises alerts |

## 5. Attack, Benign Traffic, and Detection

**Attack.** `scan.py` makes TCP connection attempts to a list of ports. Options: delay between probes (e.g. 1 s or 10 s), fixed or random delay, and port order.

**Benign traffic.** `benign_traffic.py` on the client produces:
- normal web requests and SSH logins;
- a health check that contacts all four running services every minute (many distinct ports, all successful);
- a short "service outage" where the client retries one stopped service (many failures, one port).

**Monitoring.** `monitor.py` captures SYN packets to the victim and the victim's reply (SYN-ACK = success, RST = failure). It writes one line per connection attempt: time, source, port, result. Retransmitted SYNs are counted once.

**Detectors.** One script, `detector.py`, with two modes, both reading the monitor's log:

| Mode | Rule (starting values) |
|---|---|
| Baseline | Alert if a source contacts ≥ 12 distinct ports within **60 s** |
| Proposed | Alert if a source contacts ≥ 12 distinct ports within **10 min** **and** ≥ 70 % of its attempts in that window failed |

Example: a scan with a 10 s delay touches only 6 ports per minute, so the baseline never alerts. In a 10-minute window it reaches 12 ports after about 2 minutes, almost all failed, so the proposed detector alerts. The health check reaches 4 ports with 0 % failures, and the outage retries hit 1 port, so neither should trigger it.

Each alert prints the time, source, victim, port count, and failure rate.

## 6. Experimental Evaluation

**Questions.**
1. Does a longer window detect slow scans that the baseline misses?
2. Does the failure-rate condition prevent false alarms from benign traffic?
3. How long after the first probe is a scan detected?

**Setup.** Scan delays of 1 s, 10 s, and 30 s, each run with benign traffic present and repeated with 5 random seeds. To keep experiments short, the monitor's log is recorded once per run and then replayed into both detector modes, so both see identical input.

**Metrics.**

| Metric | Definition |
|---|---|
| Detection rate | Fraction of scan runs that raised an alert |
| False-positive rate | Fraction of benign runs where the client was flagged |
| Detection delay | Time from the first probe to the alert |

Known limitation to document: a scan slower than about 50 s between probes cannot reach 12 ports in 10 minutes and will be missed by design.

## 7. Automatically Assessable Objectives

The monitor and detector write log files on the victim. `results.config` checks them with Labtainers' timestamped regex matching.

| # | Objective | Evidence checked |
|---|---|---|
| 1 | Student performed a slow scan | Monitor log shows ≥ 12 distinct ports from the attacker with an average gap ≥ 8 s |
| 2 | Baseline missed the slow scan | Baseline was running during the scan (heartbeat lines in its log) **and** has no alert for the attacker |
| 3 | Proposed detector caught the slow scan | Alert naming the attacker and victim within 3 minutes of the first probe |
| 4 | Benign traffic not flagged | Web server log shows successful client requests **and** no alert names the client |

## 8. Parameterization

Using Labtainers' `parameter.config`, each student gets:
- different port numbers for the two test services (so students must actually scan);
- a different port-count threshold (10–14) for the detectors.

Assessment checks use the same parameters, so every student's lab is gradable.

## 9. Student Tasks (Summary)

1. Generate benign traffic and look at the monitor log.
2. Run a fast scan; see the baseline detect it.
3. Run a slow scan; see the baseline miss it.
4. Run the proposed detector on the same traffic; explain why it alerts and the benign client does not.
5. Run the experiments in Section 6 and report the metrics.

## 10. Division of Work

The scope above stays the same; the work is split evenly between the two members.

| Area | Member 1 | Member 2 |
|---|---|---|
| Environment | Containers, network, victim services | — |
| Traffic | `scan.py`, `benign_traffic.py` | — |
| Detection | `monitor.py` | `detector.py` (both modes) |
| Evaluation | Recording runs and ground-truth labels | Replay, metrics, result analysis |
| Assessment | Objectives 1 and 4 | Objectives 2 and 3 |
| Documentation | Student guide | Instructor guide |

The members agree on the monitor's log format first, so both sides can be developed in parallel. Both review each other's code, verify a clean `rebuild slow-scan`, and prepare the report and demo together.

## References

1. Zeek documentation, *TCP scan detection policy*. https://docs.zeek.org/en/v6.0.9/scripts/policy/misc/scan.zeek.html
2. Course Labtainers repository. https://github.com/cengwins/Labtainers
