# Labtainers Guide for the `slow-scan` Team

This guide covers what Labtainers is, what it gives us, and how to use it to build, run and grade our lab.
Everything here was checked against this repository (v1.4.4n). Paths are relative to the repo root.
For the step-by-step Milestone 2 work, see [MILESTONE2_PLAN.md](MILESTONE2_PLAN.md).

The official manual is the **Lab Designer Guide**: `docs/labdesigner/labdesigner.pdf` (LaTeX source `docs/labdesigner/labdesigner.tex`). §12 below maps its sections to line numbers.

---

## 1. What Labtainers is and why it suits our project

Labtainers is a framework from the Naval Postgraduate School for cyber-security labs that run in **Docker containers**.

| Feature | What it means | How we use it |
|---|---|---|
| Containerised lab computers | Each "computer" is a Docker container built from a lab Dockerfile on top of a Labtainers base image | attacker, client and victim are three containers |
| Virtual networks | `start.config` defines Docker networks with fixed IPs | LAN `172.20.0.0/24` with .10 / .20 / .30 |
| One-command build and run | `rebuild <lab>` (developer) and `labtainer <lab>` (student) build images, create networks, start containers and open terminals | the instructor runs `rebuild slow-scan` |
| systemd inside containers | Services start at boot like on a real Linux server | web, test services, monitor and detectors start automatically |
| Startup hooks | `fixlocal.sh`, `rc.local`, systemd units | enable our services with no manual steps |
| **Parameterization** | Values are randomised per student from a seed (`parameter.config`) | different test-service ports and threshold per student |
| **Automatic artifact collection** | `stoplab` zips the student's command history, stdin/stdout of programs, and chosen log files | collects `conn.log`, `baseline.log`, `proposed.log` and the web log |
| **Automated assessment** | `results.config` turns artifacts into values; `goals.config` turns values into pass/fail goals; `checkwork` / `gradelab` evaluate them | our 4 objectives |
| Lab manuals | `docs/` folder; `read_first.txt` shown at start | student guide |

So the framework already handles build, network, startup, randomisation, evidence collection and grading. We only write the lab-specific parts: Dockerfile additions, scripts, configs and documents.

---

## 2. Installing and the everyday commands

### 2.1 Where to run it
Labtainers needs **Linux + Docker**. Use the Labtainers VM appliance (https://nps.edu/web/c3o/virtual-machine-images) or an Ubuntu VM with Docker (`setup_scripts/install-docker-ubuntu.sh`).

Point the tools at **our fork**:
```bash
git clone https://github.com/meryemerdogan/Labtainers.git ~/Labtainers
cd ~/Labtainers && git checkout project/2736403-slow-scan
echo 'export LABTAINER_DIR=$HOME/Labtainers' >> ~/.bashrc
echo 'export PATH=$LABTAINER_DIR/scripts/designer/bin:$PATH' >> ~/.bashrc
echo 'alias cdlab="cd $LABTAINER_DIR/scripts/labtainer-student"' >> ~/.bashrc
source ~/.bashrc
```
The appliance's `.bashrc` adds `./bin` to `PATH`, so the student commands work **from `scripts/labtainer-student`** (`cdlab`).

### 2.2 Student-side commands (`scripts/labtainer-student/bin/`)

| Command | What it does | Useful flags |
|---|---|---|
| `rebuild <lab>` | **Developer command.** Rebuilds changed images, recreates containers and starts the lab | `-f` force rebuild of all images (needed after deleting files), `-C <ctr>` rebuild one container, `-N` no Docker cache, `-b` build only, `-L` local build without pulling |
| `labtainer <lab>` | Student start (pulls published images; for our unpublished lab use `rebuild`) | `-r` redo from scratch, `-k` list keywords, `-f <kw>` find labs by keyword, `-d` diagnose |
| `stoplab [lab]` | Stops the lab, gathers artifacts and prints the path of the results zip | |
| `checkwork [lab]` | Runs the automated assessment on the current artifacts (student self-check) | |
| `moreterm.py <lab> <ctr>` | Opens another terminal on a container | |

Logs: `scripts/labtainer-student/labtainer.log` (run `tail -f labtainer.log` while developing) and `$LABTAINER_DIR/logs/docker_build.log`.

### 2.3 Instructor-side (`scripts/labtainer-instructor/`)
- `gradelab <lab>` grades the student zips in `~/labtainer_xfer/<lab>`.
- `gradelab -d <lab>` opens a debug shell in the grader. Run `instructor.py` there; its log is `/tmp/instructor.log`.
- `gradelab -w` serves a web UI on port 8008.

### 2.4 Designer tools (`scripts/designer/bin/`)
`new_lab_setup.py` (§5), `labedit` (Java GUI editor; optional), `hash-goals.py`, `create_image.sh`.

---

## 3. Anatomy of a lab directory

```
labs/slow-scan/
├── config/
│   ├── start.config          containers, users, networks, IPs, terminals
│   ├── parameter.config      per-student randomisation
│   ├── about.txt             one-line description shown in lab listings
│   └── keywords.txt          search keywords (labtainer -k / -f)
├── dockerfiles/
│   └── Dockerfile.slow-scan.<container>.student
├── docs/
│   ├── read_first.txt        shown when the lab starts
│   └── slow-scan.pdf (+ .tex/.docx, Makefile)
├── instr_config/
│   ├── results.config        artifact → named result values
│   ├── goals.config          results → goals (grades)
│   └── pregrade.sh           optional preprocessing of artifacts before grading
└── <container>/              one directory per container
    ├── <any file>            → copied to $HOME (/home/ubuntu)
    ├── _bin/                 → $HOME/.local/bin (made executable): fixlocal.sh, prestop, treataslocal, ...
    ├── _system/              → copied to / (e.g. _system/etc/rc.local → /etc/rc.local), owned by root
    ├── home_tar/, sys_tar/   big/static files (created automatically by rebuild)
```
- The copy rules are in `scripts/labtainer-student/bin/buildImage.sh` (about lines 92–122).
- The Dockerfile `ADD`s the `sys_*.tar.gz` and `*.tar.gz` that `rebuild` creates from these folders.

---

## 4. Base images (`scripts/designer/base_dockerfiles/`)

| Image | Built on | Contains | Notes |
|---|---|---|---|
| `labtainer.base2` | Ubuntu 20.04 + systemd | python, **python3 + pip3**, rsyslog, sudo, `waitparam.service` | modern minimal base |
| **`labtainer.network2`** | base2 | openssh-server, **tcpdump**, **nmap**, netcat-openbsd, xinetd, iptables, wget, dnsutils, openvpn | removes `ssh.service` from autostart. **Our attacker and client** |
| **`labtainer.network.ssh2`** | network2 | `/etc/xinetd.d/ssh` + `/etc/services` → sshd started by xinetd | **Our victim** |
| `labtainer.wireshark2` | network2 | Wireshark GUI | for students who want GUI packet view |
| `labtainer.tap` / `netmon` | network / wireshark2 | traffic mirroring to `/taps` pcaps | alternative design for a separate monitor host |
| `labtainer.lamp` | CentOS | Apache httpd, MySQL, PHP | (snort / dmz labs) |
| `labtainer.kali` | Kali | metasploit, hydra, ... | |
| `labtainer.base`, `labtainer.network` | old Ubuntu, python2 | | legacy; `new_lab_setup.py` maps them to the `2` versions |
| `base3` / `network3` | Ubuntu 24.04 + venv | | not used by any lab yet |

**Not included anywhere:** scapy, apache2 on Ubuntu, curl, sshpass. Install them in our Dockerfiles, before `USER $user_name`:
```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends python3-scapy
```

---

## 5. Creating and changing labs: `new_lab_setup.py`

Run it from inside `labs/<lab>/`. It needs `LABTAINER_DIR` set.

| Command | Effect |
|---|---|
| `new_lab_setup.py -b network2` | create a new lab whose first container is named after the lab |
| `new_lab_setup.py -a victim -b network.ssh2` | add a container |
| `new_lab_setup.py -r old new` | rename a container |
| `new_lab_setup.py -A from new` | copy a container within this lab |
| `new_lab_setup.py -C otherlab from new` | copy a container from another lab (e.g. `-C iptables2 server victim`) |
| `new_lab_setup.py -d ctr` | delete a container |
| `new_lab_setup.py -c newlab` / `-m newlab` | clone or rename the lab |

The generated Dockerfile comes from `scripts/designer/templates/dockerfiles/Dockerfile.template.base2.student`:
```dockerfile
ARG registry
FROM $registry/labtainer.network2
ARG lab
ARG labdir
ARG imagedir
ARG user_name
ARG password
ARG apt_source
ARG version
LABEL version=$version
ENV APT_SOURCE $apt_source
RUN /usr/bin/apt-source.sh
#  >>> put package installation here (runs as root) <<<
ADD $labdir/$imagedir/sys_tar/sys.tar /
ADD $labdir/sys_$lab.tar.gz /
RUN useradd -ms /bin/bash $user_name
RUN echo "$user_name:$password" | chpasswd
RUN adduser $user_name sudo
USER $user_name
ENV HOME /home/$user_name
ADD $labdir/$imagedir/home_tar/home.tar $HOME
RUN rm -f $HOME/home.tar
ADD $labdir/$lab.tar.gz $HOME
USER root
CMD ["/bin/bash", "-c", "exec /sbin/init --log-target=journal 3>&1"]
```

---

## 6. `config/start.config`

The parser is `scripts/labtainer-student/bin/ParseStartConfig.py`. The keywords below are the ones we use; the full list is in labdesigner.tex lines 486–643.
```
GLOBAL_SETTINGS
	LAB_MASTER_SEED slow-scan_2736403_master_seed   # seed for parameterization & hashing

NETWORK LAN                     # any name of letters, '-' or '_'
	MASK 172.20.0.0/24
	GATEWAY 172.20.0.100        # Docker's host link: inside MASK, not a container IP

CONTAINER victim
	USER ubuntu                 # account created in the container
	TERMINALS 1                 # 0 = no terminal opened, -1 = student cannot attach
	LAN 172.20.0.30             # <network name> <ip>  (optionally :MAC)
```
Other keys:
- `X11 YES`: GUI apps.
- `ADD-HOST name:ip`: adds an `/etc/hosts` entry.
- `NO_GW YES`.
- `LAB_GATEWAY ip`: default route through another container. Used for routed topologies; we don't need it.
- `WAIT_FOR <ctr>`.
- `TERMINAL_GROUP`.
- `XTERM <title> <script>`: run a `_bin` script in a titled terminal, e.g. to show `tail -f` of the alert log on start.

Subnet note: `labs/denyhost` and `labs/httplab` also use `172.20.0.0/24`, so they cannot run at the same time as ours.

---

## 7. What happens when a container starts

Order, from `scripts/labtainer-student/lab_bin/parameterize.sh` and `waitparam.service`:

1. Container boots `/sbin/init` (systemd). Enabled units that do **not** wait start now.
2. **Parameterization**: `ParameterParser.py` substitutes the `parameter.config` symbols in the listed files. Log: `/tmp/parameterize.sh.log`.
3. **`~/.local/bin/fixlocal.sh <password> <user>`** runs as the lab user, **on the first start only**, with passwordless sudo. Errors go to `/tmp/fixlocal.output`.
4. `/var/labtainer/did_param` is created. This releases **`waitparam.service`**.
5. Units with `After=waitparam.service` start, then `rc-local.service` (`/etc/rc.local`, every boot).

**Running our daemons** (pattern from `labs/plc-app/monitor`, `labs/iptables2/server`):

`victim/_system/etc/systemd/system/slowscan-monitor.service`
```ini
[Unit]
Description=slow-scan monitor
After=waitparam.service network.target
[Service]
Type=simple
ExecStart=/usr/bin/monitor.py --out /var/log/slowscan/conn.log
Restart=on-failure
StandardOutput=null
[Install]
WantedBy=multi-user.target
```
With no `User=` line the unit runs as root, which packet capture needs.

`victim/_bin/fixlocal.sh`
```bash
#!/bin/bash
sudo systemctl enable slowscan-monitor
sudo mkdir -p /var/labtainer/did_param      # unblock waitparam
sudo systemctl start slowscan-monitor
```

**Ready-made pieces in the repo:**
- `scripts/designer/services/web-server.tar` contains `MyHTTPServer.py` (Python 2; port it to Python 3), `httpserver.service` and `index.html`. Extract it inside the container directory: `tar -xf $LABTAINER_DIR/scripts/designer/services/web-server.tar`. It logs to `/var/log/myhttplogfile.txt` in httpd format.
- **sshd**: `network.ssh2` (xinetd), plus `mkdir -p /run/sshd` in `_system/etc/rc.local` (see `labs/tcpip/server/_system/etc/rc.local`).
- **Extra TCP services**: a Python listener plus a systemd unit (`labs/iptables2/server/server` + `wizbang.service`), or an xinetd entry (`labs/iptables2/server/_system/etc/xinetd.d/telnetx`).
- **Background bots**: `labs/nmap-ssh/client/webbot.py` + init scripts (an example of benign client traffic).

**Other `_bin` hooks:**

| File | Purpose |
|---|---|
| `fixlocal.sh` | first-boot setup (above) |
| `student_startup.sh` | runs when each student terminal opens |
| `prestop` | runs at `stoplab`/`checkwork` (30 s limit); its output becomes `prestop.stdout` and can be graded (e.g. `labs/iptables2/client/_bin/prestop`) |
| `treataslocal` | list of system programs (e.g. `/usr/bin/nmap`) whose stdin/stdout should be recorded like student programs |
| `notify` | file-access events (e.g. `labs/iptables2`) |

---

## 8. Parameterization: `config/parameter.config`

Syntax: `<id> : <OP> : <ctr>:<file>[;<ctr>:<file>...] : <SYMBOL> : <args>`. Relative file paths are under `$HOME`; `_bin` files are reachable as `.local/bin/<file>`.

| Operation | Args | Example in repo |
|---|---|---|
| `RAND_REPLACE` | `low : high [: step]` | `labs/iptables2/config/parameter.config`: `WIZ_PORT : RAND_REPLACE : server:server;client:wizbang;client:.local/bin/prestop : WIZ_PORT : 10003 : 10090` |
| `RAND_REPLACE` on system files | | `labs/nmap-discovery/config/parameter.config`: `randport : RAND_REPLACE : friedshrimp:/etc/xinetd.d/ssh;friedshrimp:/etc/services : RANDOM_PORT : 2000 : 3000` |
| `RAND_REPLACE_UNIQUE` | values never repeat | `labs/dmz-example` |
| `HASH_CREATE` / `HASH_REPLACE` | seed-based hash string | `labs/sshlab`: `FSTRING : HASH_REPLACE : server:filetoview.txt : SSH_STRING : mysshfilestirng` |

Values are applied on the first start, before `fixlocal.sh`. Units that read parameterized files must use `After=waitparam.service`.

**Planned for slow-scan (Milestone 3):**
```
TEST_PORT1 : RAND_REPLACE : victim:/etc/systemd/system/testsvc1.service;client:benign_traffic.py : TEST_PORT1 : 8000 : 8499
TEST_PORT2 : RAND_REPLACE : victim:/etc/systemd/system/testsvc2.service;client:benign_traffic.py : TEST_PORT2 : 9000 : 9499
THRESHOLD  : RAND_REPLACE : victim:/etc/systemd/system/slowscan-baseline.service;victim:/etc/systemd/system/slowscan-proposed.service : THRESHOLD : 10 : 14
```
The ranges are disjoint, so the two ports can never collide. In goals, refer to the values as `parameter.THRESHOLD`.

---

## 9. Automated assessment

### 9.1 Pipeline
1. `stoplab` / `checkwork` collect artifacts into `~/.local/result`: bash history, stdin/stdout of programs, `prestop.stdout`, and **every absolute-path file named in `results.config`**. The copy is `sudo cp --parents <path>` in `GatherOtherArtifacts`, `scripts/labtainer-student/bin/labutils.py:2148`.
2. `instr_config/pregrade.sh` (optional) can preprocess them.
3. `results.config` extracts named values from the artifacts, timestamped.
4. `goals.config` evaluates the goals and produces the grade report.

### 9.2 `results.config`
```
<result> = <ctr>:<file> : <field_type> : <field_id> [: <line_type> : <line_id>]
```
- `<file>` can be:
  - an absolute system path (`victim:/var/log/slowscan/proposed.log`)
  - a `$HOME`-relative path
  - `<prog>.stdout` / `<prog>.stdin`
  - `*.stdout`
- Common types:
  - `CONTAINS`, `FILE_REGEX`, `FILE_REGEX_TS` (timestamped by the log line)
  - `LOG_TS`, `LOG_RANGE`, `STRING_COUNT`, `LINE_COUNT`
  - `TOKEN <n> : LINE|STARTSWITH|SEARCH`, `GROUP <n> : REGEX : <re>`
  - `COMMAND_COUNT`, `TIME_DELIM`, `PARAM`
- Names starting with `_` are hidden from the report. `cw_` names plus `#CHECK_TRUE:` give checkwork-only checks.

Real examples:
```
getindexhtml     = server:/var/log/myhttplogfile.txt : CONTAINS : GET /index.html            # labs/httplab
_log_plan_local  = web_server:/var/log/httpd/access_log : FILE_REGEX_TS : 192.168.2.1.*plan.html.*   # labs/snort
deny_2           = server:/var/log/auth.log : STRING_COUNT : Connection closed by 172.20.0.2  # labs/denyhost
_ssh_open        = client:nmap.stdout : FILE_REGEX : 22/tcp.*open                            # labs/iptables2
```

**Timestamps the parser understands** (`getTS`, `scripts/labtainer-instructor/assess_bin/ResultParser.py:369`):
- syslog `Nov 20 10:15:03`
- snort `11/20-10:15:03`
- mariadb `261120 10:15:03`
- httpd `[20/Nov/2026:10:15:03 +0000]`
- ISO `2026-11-20T10:15:03`. This one is tried only if the line has no `[...]`.

Lines with no recognisable timestamp take the previous line's timestamp. **Our logs use ISO and no square brackets.**

### 9.3 `goals.config`
```
<goal> = matchany|matchlast : <operator> : <result> : answer=<lit>|result.<x>|parameter.<x>
<goal> = boolean : ( g1 and g2 and_not g3 )        # operators: and, or, and_not, or_not, not
<goal> = time_before | time_during | time_not_during : <goal1> : <goal2>
<goal> = count_greater : <n> : ( g1, g2, ... )    # summed across timestamps
<goal> = count : <result>        |   <goal> = value : <result>
<goal> = execute : <script> : <result> : <answer>
```
- Operators: `string_equal`, `string_contains`, `string_start`, `string_end`, `string_diff`, `integer_equal`, `integer_greater`, `integer_lessthan`, `hash_equal`.
- `boolean` is evaluated **within one timestamped set**. To combine evidence from different times, use `count_greater`.

Real examples:
```
snort_remote_fire = time_during : _log_plan_remote : snort_remote_conf               # labs/snort
proper_config     = boolean : (snort_remote_fire and_not snort_local_fire and snort_local_nmap)
first_ports_ok    = boolean : ( _ssh and _http and_not _telnet )                     # labs/iptables2
sshview           = matchany : string_equal : sshfileview : parameter.FSTRING        # labs/sshlab
```

### 9.4 Draft mapping of our four objectives (Milestone 3 work)

"Average gap ≥ 8 s" and "no alert for X" are awkward to express with regexes alone. The most robust approach is a small **`victim/_bin/prestop`** script (Python, runs at `stoplab`/`checkwork`). It reads our logs and prints one summary line per fact. Those lines are then graded simply:

`prestop` output (example):
```
SLOWSCAN src=172.20.0.10 ports=24 avg_gap=10.1
BASELINE_HEARTBEATS 22
BASELINE_ALERTS_ATTACKER 0
PROPOSED_ALERT_ATTACKER delay=118
CLIENT_WEB_OK 37
ALERTS_CLIENT 0
```
`results.config` (draft):
```
# Keep the logs themselves in the artifacts:
_conn       = victim:/var/log/slowscan/conn.log : LINE_COUNT
_base       = victim:/var/log/slowscan/baseline.log : LINE_COUNT
_prop       = victim:/var/log/slowscan/proposed.log : LINE_COUNT
_web        = victim:/var/log/myhttplogfile.txt : LINE_COUNT
# Summary facts:
scan_gap    = victim:prestop.stdout : TOKEN : 4 : STARTSWITH : SLOWSCAN
base_hb     = victim:prestop.stdout : TOKEN : 2 : STARTSWITH : BASELINE_HEARTBEATS
base_att    = victim:prestop.stdout : TOKEN : 2 : STARTSWITH : BASELINE_ALERTS_ATTACKER
prop_att    = victim:prestop.stdout : TOKEN : 2 : STARTSWITH : PROPOSED_ALERT_ATTACKER
client_ok   = victim:prestop.stdout : TOKEN : 2 : STARTSWITH : CLIENT_WEB_OK
client_alrt = victim:prestop.stdout : TOKEN : 2 : STARTSWITH : ALERTS_CLIENT
```
`goals.config` (draft):
```
_slow        = matchany : string_contains : scan_gap   : answer=avg_gap
_base_ran    = matchany : integer_greater : base_hb    : answer=0
_base_quiet  = matchany : integer_equal   : base_att   : answer=0
_prop_fired  = matchany : string_start    : prop_att   : answer=delay=
_web_ok      = matchany : integer_greater : client_ok  : answer=0
_no_fp       = matchany : integer_equal   : client_alrt: answer=0
slow_scan_performed      = boolean : _slow
baseline_missed_slowscan = boolean : (_base_ran and _base_quiet)
proposed_caught_slowscan = boolean : _prop_fired
benign_not_flagged       = boolean : (_web_ok and _no_fp)
```
- **Check the operator direction before relying on it.** For `integer_greater` the guide says "answertag is greater than resulttag". Simplest is to let `prestop` print `yes`/`no` for each objective, including the 8 s gap check and the 3-minute delay check, and use `string_equal : answer=yes`.
- Test with `checkwork` and `gradelab -d`.

Because the logs are also listed (the `_conn`, `_base`, ... lines), the instructor's grader gets the raw evidence too. A tamper-resistant alternative is to do the same computation in `instr_config/pregrade.sh`, which runs on the grader side over the collected logs.

---

## 10. Existing labs worth copying from

| Lab | What to take from it |
|---|---|
| `labs/iptables2` | Ubuntu 20.04 server with Python TCP services as systemd units, `fixlocal.sh` that enables them, xinetd ssh, `prestop` + nmap-based grading, parameterized port (`WIZ_PORT`) |
| `labs/plc-app` (monitor) | systemd daemon with `After=waitparam.service` plus the `did_param` unlock in `fixlocal.sh` |
| `labs/snort` | IDS lab: detector output graded with `time_during` and `boolean ... and_not` (closest to our "detector fired / didn't fire" objectives); LaTeX student manual layout |
| `labs/nmap-ssh`, `labs/nmap-discovery` | scanning-lab conventions, randomised SSH port via `RAND_REPLACE` on `/etc/xinetd.d/ssh`, benign web bot (`webbot.py`) |
| `labs/denyhost`, `labs/httplab` | same 172.20.0.0/24 network; grading from `/var/log/...` with `STRING_COUNT`/`CONTAINS` |
| `labs/sys-log`, `labs/centos-log` | `LOG_TS`, `LOG_RANGE`, `time_not_during` |
| `labs/tcpip` | attacker/client/server on one LAN; `rc.local` with `/run/sshd`; DOCX manual + report template |

---

## 11. Debugging and gotchas

- **Build fails**: read `scripts/labtainer-student/labtainer.log` and `$LABTAINER_DIR/logs/docker_build.log`.
- **Service not running**: `systemctl status <unit>`, `journalctl -u <unit>`, `/tmp/fixlocal.output`, `/tmp/parameterize.sh.log`.
- **Changes not picked up**: `rebuild` compares git modification dates. After deleting or renaming files, or if in doubt, run `rebuild slow-scan -f`.
- **Windows line endings**: CRLF breaks shebangs. Put `* text=auto eol=lf` in `labs/slow-scan/.gitattributes` and test from a VM clone.
- **Executable bits**: `_bin/*` is made executable automatically. For `_system/usr/bin/*.py`, set `chmod +x` in git (`git update-index --chmod=+x <file>`) or call them as `python3 /usr/bin/x.py` in `ExecStart`.
- **sshd** does not autostart on `network2`. Use `network.ssh2` + `/run/sshd`.
- **Python 2 leftovers** in the repo (`MyHTTPServer.py`, `webbot.py`): port them to Python 3.
- **Root**: users are in `sudo` with NOPASSWD. Daemons that sniff packets should be root systemd units.
- **Logs to grade** must be named with their absolute path in `results.config`, or they are not collected.
- **One lab per subnet**: stop other labs that use 172.20.0.0/24.
- **Grading test loop**: `stoplab` → `checkwork slow-scan`. For deeper debugging: `gradelab -d slow-scan` → `instructor.py` → `/tmp/instructor.log`.

---

## 12. Lab Designer Guide index (`docs/labdesigner/labdesigner.tex`)

| Line | Section |
|---|---|
| 208 / 287 | Creating new labs / Command line lab creation (incl. testing, multiple containers) |
| 433 | Docker files (base image list ~458) |
| 486 | Container definitions in start.config |
| 644 / 695 | Files in the student's home directory / Lab-specific system files |
| 725 | System services |
| 754 | Lab instructions for students |
| 782 | Running programs in virtual terminals (`XTERM`) |
| 811 | Final lab environment fixup (`fixlocal.sh`) |
| 851 / 876 / 964 | Parameterizing a lab / syntax / synchronising startup with parameterization |
| 1009 / 1030 | Automated assessment / artifact files (stdin/stdout, logs, prestop) |
| 1238 / 1418 / 1465 | Artifact result values / evaluating results / goal definitions |
| 1682 / 1718 | Student self-assessment (`checkwork`) / current-state artifacts |
| 1743 / 1916 | Assessment examples (LOG_RANGE, TIME_DELIM) / debugging assessment |
| 2013 / 2036 / 2111 | Networking / network taps / interface assignments |
| 2886 / 2953 / 3007 | Networking notes (SSH, network2) / user management & sudo / container isolation |
