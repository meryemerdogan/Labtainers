# Step 3: Victim services, implementation notes

Companion to [MILESTONE2_PLAN.md §6](MILESTONE2_PLAN.md). Steps 1 and 2 (skeleton, topology, Dockerfiles) were already done. This step makes the victim (172.20.0.30) offer its four TCP services with no manual commands after `rebuild slow-scan`.

---

## 1. Result

| Port | Service | How it starts | Runs as |
|---|---|---|---|
| 22 | sshd | xinetd starts `sshd -i` per connection (from the `network.ssh2` base) | root |
| 80 | `MyHTTPServer.py`, serves `/var/www/html`, logs to `/var/log/myhttplogfile.txt` | `httpserver.service` | root (port 80 is privileged) |
| 8081 | `testsvc.py 8081 inventory`, banner service | `testsvc1.service` | nobody |
| 9090 | `testsvc.py 9090 backup`, banner service | `testsvc2.service` | nobody |

Any other port is closed, so the kernel answers a SYN with RST. Step 4's monitor will turn that RST into `result=FAIL`.

## 2. Files

```text
labs/slow-scan/
├── victim/
│   ├── _bin/fixlocal.sh                         rewritten: enable + start all services
│   └── _system/                                 copied to / in the container
│       ├── etc/rc.local                         mkdir -p /run/sshd on every boot
│       ├── etc/tmpfiles.d/sshd.conf             same, without needing an exec bit
│       ├── etc/systemd/system/httpserver.service
│       ├── etc/systemd/system/testsvc1.service
│       ├── etc/systemd/system/testsvc2.service
│       ├── usr/bin/MyHTTPServer.py              Python 3 port of web-server.tar
│       ├── usr/bin/testsvc.py                   new
│       └── var/www/html/index.html
├── tests/
│   ├── check_lab.py                             + "services" check group
│   ├── test_check_lab.py                        + 15 mutation tests for it
│   ├── test_services.py                         new: runs both servers on localhost
│   └── runtime_check.sh                         + Step 3 runtime checks (in the VM)
└── README.md                                    + services table, new tests
```

## 3. How each piece works

### 3.1 Web server: `MyHTTPServer.py`
The template in `scripts/designer/services/web-server.tar` is Python 2 (`SimpleHTTPServer`, `SocketServer`, `print "..."`). The port:

- Uses `http.server.ThreadingHTTPServer` and `SimpleHTTPRequestHandler(directory=/var/www/html)`. Being threaded, a slow client or a half-open scan connection cannot block other requests.
- Overrides `log_message` to write one line per request in Apache common log format:
  ```
  172.20.0.20 - - [20/Nov/2026:10:15:03 +0000] "GET / HTTP/1.1" 200 -
  ```
  The bracketed `dd/Mon/YYYY:HH:MM:SS` is what the httpd branch of Labtainers' `getTS` (`scripts/labtainer-instructor/assess_bin/ResultParser.py`) parses. We need that for the Milestone 3 assessment. (The "no square brackets" rule in plan §7.1 is only for our own `/var/log/slowscan/*.log` files, which use the ISO branch.)
- Opens the log in **append** mode. The template used `'w'`, which would wipe the history on every service restart.
- Takes `--port`, `--bind`, `--root` and `--log`. The defaults are the in-lab values, so the unit file just restates them. The options let the server run in tests without root.

### 3.2 Banner service: `testsvc.py <port> <name>`
A `socketserver.ThreadingTCPServer` (with `allow_reuse_address`) that, for each connection:
1. completes the handshake, so a scanner sees the port as **open** and the monitor sees a SYN-ACK,
2. sends `220 slow-scan <name> service ready\r\n`,
3. closes the connection.

It logs `2026-11-20T10:15:03 inventory connection from 172.20.0.20:40312` to stdout, so `journalctl -u testsvc1` shows who connected. It tolerates clients that disconnect before the banner is sent, which is what a connect scan does. It validates its arguments (port number in range, printable ASCII name). Port `0` means "pick a free port" and is used only by the tests.

The idea comes from `labs/iptables2/server/server`, but that file is Python 2 with CRLF line endings and a parameterized port, so it was rewritten rather than copied.

### 3.3 systemd units
All three follow the `labs/plc-app/monitor/.../heartbeat.service` pattern:

```ini
[Unit]
After=waitparam.service network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/bin/testsvc.py 8081 inventory
User=nobody                 # httpserver.service has no User= (root, for port 80)
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
```

- `After=waitparam.service`: Labtainers' `waitparam.service` stays "activating" until `/var/labtainer/did_param` exists, which marks the end of parameterization. Ordering after it means that in Milestone 3, when the ports become parameters (`TEST_PORT1`/`TEST_PORT2`), the services read the already-parameterized unit files.
- `ExecStart=/usr/bin/python3 <script>` instead of running the script directly. Executable bits only reach the image through git, and these files are written on Windows. Naming the interpreter makes the units work even if the `+x` bit is lost (see §6).
- `Restart=on-failure`: a crashed service comes back by itself during a long slow-scan run.
- The test services run as `nobody`. They don't need root (ports > 1024), and it is a better example in a security lab. The HTTP server stays root because of port 80, and `check_lab.py` checks this rule.

### 3.4 SSH on port 22
The `network.ssh2` base already has `/etc/xinetd.d/ssh`, which runs `sshd -i` for each connection. The catch: sshd refuses to start without its privilege-separation directory `/run/sshd`. Labtainers creates containers with `--tmpfs /run` (`labutils.py:597/608`), so the directory **disappears on every boot**, and `network2` disables `ssh.service`, which would normally create it. We create it in three places:

| Where | When | Why |
|---|---|---|
| `fixlocal.sh` (`mkdir -p /run/sshd`) | first boot | covers the first start right away |
| `/etc/tmpfiles.d/sshd.conf` (`d /run/sshd 0755 root root -`) | every boot, `systemd-tmpfiles-setup` | does not depend on any exec bit |
| `/etc/rc.local` | every boot, `rc-local.service` | the Labtainers convention (`labs/tcpip`) asked for by the plan |

`rc.local` only runs if it is executable. That is why `tmpfiles.d` was added as a fallback that can't fail for that reason.

### 3.5 `fixlocal.sh`
Labtainers runs it once, as `ubuntu`, after parameterization (`scripts/labtainer-student/lab_bin/parameterize.sh:123-131`). `ubuntu` is in the `sudo` group, which is `NOPASSWD` in the base2 sudoers, so plain `sudo` works. In order, it:

1. builds the list of units **that exist** out of `httpserver testsvc1 testsvc2 slowscan-monitor slowscan-baseline slowscan-proposed`. Steps 4–5 only have to drop their unit files in, with no edit here. Missing ones are reported in `/tmp/fixlocal.output`.
2. `mkdir -p /var/log/slowscan /run/sshd`
3. `systemctl daemon-reload`, `enable` the units and `enable xinetd`. Enabled units start on their own on every later `labtainer slow-scan`. `fixlocal.sh` itself never runs again.
4. `mkdir -p /var/labtainer/did_param`. **This must come before `start`.** Our units are `After=waitparam.service`, and waitparam only finishes when this directory exists, so `systemctl start` would block until then. parameterize.sh creates the directory later anyway; creating it early is the same trick `labs/plc-app` uses.
5. `systemctl start` the units and `systemctl restart xinetd`.
6. writes `fixlocal: <unit> failed to start` to `/tmp/fixlocal.output` for any unit that isn't active.

### 3.6 Boot sequence

```text
first start (rebuild / labtainer -r)         later starts (labtainer slow-scan)
-------------------------------------        ----------------------------------
systemd boots                                systemd boots
  tmpfiles.d  -> /run/sshd                     tmpfiles.d -> /run/sshd
  waitparam.service waits ...                  waitparam: did_param exists -> ready
parameterize.sh                                rc.local -> /run/sshd
  ParameterParser.py                           httpserver, testsvc1, testsvc2 (enabled)
  fixlocal.sh                                  xinetd (enabled) -> sshd on demand
    enable units, mkdir did_param
    start units, restart xinetd
  waitparam ready -> rc.local
```

## 4. Deviations from plan §6

| Plan | Implemented | Reason |
|---|---|---|
| `ExecStart=/usr/bin/<script>.py` | `ExecStart=/usr/bin/python3 /usr/bin/<script>.py` | works even if the exec bit is lost in a Windows commit |
| `rc.local` creates `/run/sshd` | `rc.local` **and** `tmpfiles.d/sshd.conf` (+ `fixlocal.sh` on first boot) | `/run` is a tmpfs, and `rc.local` silently does nothing without `+x` |
| units run as root | test services run as `nobody`; HTTP stays root | least privilege; root isn't needed above port 1024 |
| `fixlocal.sh` enables a fixed list of six units | enables only the units that exist | the monitor/detector units don't exist yet; no edit needed when they arrive |
| `/etc/init.d/xinetd restart` | `systemctl enable xinetd` + `systemctl restart xinetd` | same effect, and xinetd is guaranteed to be enabled for restarts |
| HTTP log opened with `'w'` | append mode, full Apache timestamp `[dd/Mon/YYYY:HH:MM:SS +zzzz]` | keeps history across restarts; parsed by `getTS` |

These can go into the "Deviations from the proposal" section of the progress report.

## 5. Verification

### 5.1 Already run (Windows, Python 3.12, no Docker)

```text
python labs/slow-scan/tests/check_lab.py
  151 passed, 4 warnings, 0 failed
python -m unittest discover -s labs/slow-scan/tests
  Ran 55 tests ... OK
bash -n victim/_bin/fixlocal.sh victim/_system/etc/rc.local tests/runtime_check.sh   -> OK
```

- **`check_lab.py`, `services` group:** checks that all files exist, that both scripts compile as Python 3 with no Python 2 idioms, the log path and timestamp format, and each unit file:
  - `After=waitparam`, `WantedBy=multi-user.target`, `Restart=`
  - `ExecStart` goes through `python3`
  - the expected port
  - root only for port < 1024
  - no port clashes, including with 22

  It also checks that `fixlocal.sh` lists every shipped unit, enables them, and creates `did_param` before `start`. Finally it checks the `/run/sshd` entries in `rc.local` and `tmpfiles.d`, and the git exec bits.
- **The 4 warnings:**
  - the usual subnet-sharing note
  - three "not tracked yet" exec-bit notes, which go away after the commit in §6
- **`test_check_lab.py`:** 15 new mutation tests. Each one breaks one rule and confirms `check_lab.py` reports it, for example:
  - a wrong port
  - the HTTP server running as `nobody`
  - a unit missing from `fixlocal.sh`
  - `start` before `did_param`
  - `rc.local` without `mkdir`
- **`test_services.py`:** starts the real scripts on 127.0.0.1 and checks:
  - the exact banner, followed by the server closing the connection
  - 20 connect-and-close probes don't kill the service
  - connection log lines are written
  - bad arguments are rejected
  - `GET /` returns 200 with our page, and a missing file returns 404
  - the log line has the exact format and is parsed by **Labtainers' own `getTS`** to today's date
  - the log is appended across restarts

### 5.2 To run in the Linux VM (not run yet: needs Docker)

```bash
cdlab
rebuild slow-scan -f
bash $LABTAINER_DIR/labs/slow-scan/tests/runtime_check.sh
```

The new Step 3 part of `runtime_check.sh` checks:
- `httpserver`, `testsvc1` and `testsvc2` are active **and enabled**, and xinetd is active
- `/run/sshd`, `/var/log/slowscan` and `did_param` exist
- the victim listens on 22, 80, 8081 and 9090, and `fixlocal.sh` reported no failed unit
- from the client, `curl http://172.20.0.30/` returns 200, and the request appears in `/var/log/myhttplogfile.txt`
- from the attacker, the banners on 8081 (`inventory`) and 9090 (`backup`) are correct, and port 22 answers `SSH-2.0-...`
- a closed port (23) is **refused**, i.e. answered with RST (`connect_ex` = 111) rather than dropped

Manual checks, plus restart persistence (the script doesn't automate this one):

```bash
# victim terminal
sudo systemctl status httpserver testsvc1 testsvc2 --no-pager
ss -tln                                    # 22, 80, 8081, 9090
cat /tmp/fixlocal.output                   # only "not installed yet, skipping" lines for steps 4-5
# attacker terminal
nmap -sT -p 20-25,79-81,8080-8082,9089-9091 172.20.0.30   # open: 22 80 8081 9090
# persistence
stoplab; labtainer slow-scan               # then rerun runtime_check.sh: services must be up again
```

## 6. Before committing (important)

Executable bits only reach the image through git, and on Windows git doesn't record them for new files. Add the three scripts with the bit set:

```bash
git add --chmod=+x labs/slow-scan/victim/_system/etc/rc.local \
                   labs/slow-scan/victim/_system/usr/bin/MyHTTPServer.py \
                   labs/slow-scan/victim/_system/usr/bin/testsvc.py
git add labs/slow-scan
python labs/slow-scan/tests/check_lab.py -q    # the 3 exec-bit warnings should now be PASS
```

(`_bin/fixlocal.sh` is made executable by Labtainers itself.) All new files are LF; `.gitattributes` keeps them that way.

## 7. Hooks for the next steps

- **Steps 4–5 (monitor, detectors):**
  - put `slowscan-monitor.service`, `slowscan-baseline.service` and `slowscan-proposed.service` in `victim/_system/etc/systemd/system/`
  - `fixlocal.sh` already enables and starts them, and `check_lab.py` fails if a unit file is added whose name is not in the `UNITS` list
  - `/var/log/slowscan/` already exists
- **Milestone 3 parameterization:** ports 8081/9090 appear only in `testsvc1.service` and `testsvc2.service` (plus the test expectations), so `RAND_REPLACE` for `TEST_PORT1`/`TEST_PORT2` only has to touch those two lines. The units already start after `waitparam`.
- **Milestone 3 assessment:** `/var/log/myhttplogfile.txt` is parseable by `getTS`. Add it to `results.config` so it is collected at `stoplab`.
