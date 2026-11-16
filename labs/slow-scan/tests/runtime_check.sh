#!/bin/bash
#
# Runtime checks for the slow-scan lab: Milestone 2, Step 1 (topology),
# Step 2 (images), Step 3 (victim services) and Steps 4-5 (monitor and
# detectors). Run on the Labtainers host (Linux VM with Docker).
#
#   labs/slow-scan/tests/runtime_check.sh [--rebuild] [--no-scan] [--slow]
#
#   --rebuild   run `rebuild slow-scan -f` first
#   --no-scan   skip the fast scan (attacker, nmap 1-200): both detectors must alert
#   --slow      also run a ~2.5 min slow scan from the CLIENT (13 closed ports,
#               10 s apart): baseline must stay silent, proposed must alert
#
# The scans leave the detectors with state (one alert per source, then a
# cooldown of one window). Restart with `labtainer -r slow-scan` before a demo.
#
# Exit status 0 = no FAIL.
#
set -u
LAB=slow-scan
NET=slowscan_lan                    # Docker network = lower-cased NETWORK name in start.config
SUBNET=172.20.0.0/24
GATEWAY=172.20.0.100
declare -A IP=([attacker]=172.20.0.10 [client]=172.20.0.20 [victim]=172.20.0.30)
CONTAINERS=(attacker client victim)

pass=0; fail=0
ok()   { printf 'PASS  %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf 'FAIL  %s\n' "$*"; fail=$((fail+1)); }
info() { printf 'INFO  %s\n' "$*"; }
check() { local msg=$1; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else bad "$msg"; fi; }
cname() { echo "$LAB.$1.student"; }
dx()    { local c; c=$(cname "$1"); shift; docker exec "$c" "$@"; }

here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../../.." && pwd)

do_rebuild=0; do_scan=1; do_slow=0
for a in "$@"; do
    case $a in
        --rebuild) do_rebuild=1 ;;
        --no-scan) do_scan=0 ;;
        --slow)    do_slow=1 ;;
        *) echo "usage: $0 [--rebuild] [--no-scan] [--slow]"; exit 2 ;;
    esac
done

if [ $do_rebuild = 1 ]; then
    echo "== rebuild $LAB -f (from $top/scripts/labtainer-student)"
    export LABTAINER_DIR="${LABTAINER_DIR:-$top}"
    (cd "$LABTAINER_DIR/scripts/labtainer-student" && ./bin/rebuild "$LAB" -f) \
        || { echo "FAIL  rebuild $LAB -f returned non-zero (see scripts/labtainer-student/labtainer.log, logs/docker_build.log)"; exit 1; }
fi

command -v docker >/dev/null || { echo "FAIL  docker not found"; exit 1; }

echo "== images and containers"
for c in "${CONTAINERS[@]}"; do
    check "image $(cname "$c") exists" docker image inspect "$(cname "$c")"
    running=$(docker inspect -f '{{.State.Running}}' "$(cname "$c")" 2>/dev/null)
    if [ "$running" = "true" ]; then ok "container $(cname "$c") is running"
    else bad "container $(cname "$c") is running (got: ${running:-absent}); start it with: rebuild $LAB"; fi
done
[ $fail -gt 0 ] && { echo; echo "$pass passed, $fail failed (containers missing, skipping the rest)"; exit 1; }

echo "== network"
cfg=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{.Gateway}}{{end}}' "$NET" 2>/dev/null)
[ "$cfg" = "$SUBNET $GATEWAY" ] && ok "docker network $NET is $SUBNET gw $GATEWAY" \
                                 || bad "docker network $NET is $SUBNET gw $GATEWAY (got: ${cfg:-absent})"
for c in "${CONTAINERS[@]}"; do
    got=$(docker inspect -f "{{with index .NetworkSettings.Networks \"$NET\"}}{{.IPAddress}}{{end}}" "$(cname "$c")" 2>/dev/null)
    [ "$got" = "${IP[$c]}" ] && ok "$c has ${IP[$c]} on $NET" || bad "$c has ${IP[$c]} on $NET (got: ${got:-none})"
    nnets=$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$(cname "$c")" 2>/dev/null)
    [ "$nnets" = "1" ] && ok "$c is attached to exactly one network" || bad "$c is attached to exactly one network (got $nnets)"
    h=$(dx "$c" hostname 2>/dev/null)
    [ "$h" = "$c" ] && ok "$c hostname is $c" || bad "$c hostname is $c (got: ${h:-?})"
    dx "$c" hostname -I 2>/dev/null | tr ' ' '\n' | grep -qx "${IP[$c]}" \
        && ok "$c sees ${IP[$c]} on its own interface" || bad "$c sees ${IP[$c]} on its own interface"
done

echo "== reachability on the shared L2 segment (no router)"
for pair in attacker:victim client:victim attacker:client victim:attacker victim:client; do
    src=${pair%%:*}; dst=${pair##*:}
    check "$src -> $dst (${IP[$dst]}) ping" dx "$src" ping -c 1 -W 2 "${IP[$dst]}"
done
for c in attacker client; do
    r=$(dx "$c" ip route get "${IP[victim]}" 2>/dev/null)
    if [ -z "$r" ]; then info "$c: 'ip route' unavailable, skipped direct-route check"
    elif echo "$r" | grep -q ' via '; then bad "$c reaches victim directly, no gateway hop (got: $r)"
    else ok "$c reaches victim directly, no gateway hop"; fi
done

echo "== packages (Step 2)"
check "attacker: python3"            dx attacker python3 --version
check "attacker: nmap"               dx attacker nmap --version
check "attacker: nc (netcat)"        dx attacker sh -c 'command -v nc'
check "client: curl"                 dx client curl --version
check "client: sshpass"              dx client sh -c 'command -v sshpass'
check "client: python3"              dx client python3 --version
check "victim: python3 imports scapy" dx victim python3 -c 'import scapy.all'
check "victim: tcpdump"              dx victim sh -c 'command -v tcpdump'
check "victim: xinetd"               dx victim sh -c 'command -v xinetd'
check "victim: sshd binary"          dx victim test -x /usr/sbin/sshd
check "victim: xinetd ssh service"   dx victim test -f /etc/xinetd.d/ssh
v=$(dx victim python3 -c 'import scapy; print(scapy.VERSION)' 2>/dev/null) && info "victim scapy version: $v"

echo "== users"
for c in "${CONTAINERS[@]}"; do
    check "$c: user ubuntu exists with /home/ubuntu" dx "$c" sh -c 'id ubuntu && test -d /home/ubuntu'
    check "$c: ubuntu is in the sudo group"           dx "$c" sh -c 'id -nG ubuntu | grep -qw sudo'
done

echo "== victim services (Step 3)"
V=${IP[victim]}
for s in httpserver testsvc1 testsvc2; do
    check "victim: $s.service is active"  dx victim systemctl is-active --quiet "$s"
    check "victim: $s.service is enabled (survives a lab restart)" dx victim systemctl is-enabled --quiet "$s"
done
check "victim: xinetd is active (sshd on 22)" dx victim systemctl is-active --quiet xinetd
check "victim: /run/sshd exists"              dx victim test -d /run/sshd
check "victim: /var/log/slowscan exists"      dx victim test -d /var/log/slowscan
check "victim: did_param flag exists (waitparam released)" dx victim test -d /var/labtainer/did_param
listening=$(dx victim sh -c "ss -tln 2>/dev/null | awk 'NR>1{print \$4}' | sed 's/.*://' | sort -un | tr '\n' ' '")
for p in 22 80 8081 9090; do
    case " $listening " in *" $p "*) ok "victim listens on TCP $p" ;;
                           *) bad "victim listens on TCP $p (listening: ${listening:-none})" ;; esac
done
info "victim listening TCP ports: ${listening:-none}"
if dx victim test -s /tmp/fixlocal.output 2>/dev/null; then
    info "victim /tmp/fixlocal.output: $(dx victim sh -c 'tr "\n" "|" < /tmp/fixlocal.output' 2>/dev/null)"
fi
dx victim grep -q 'failed to start' /tmp/fixlocal.output 2>/dev/null \
    && bad "victim: fixlocal.sh reported a unit that failed to start (see /tmp/fixlocal.output)" \
    || ok "victim: fixlocal.sh reported no failed units"

echo "== services seen from the LAN (Step 3)"
# banner <container> <port>: first bytes the victim sends on connect (python3: same on every base)
banner() { dx "$1" python3 -c "import socket,sys
s=socket.create_connection(('$V',$2),timeout=3); print(s.recv(128).decode(errors='replace').strip())" 2>/dev/null; }
code=$(dx client curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$V/" 2>/dev/null)
[ "$code" = "200" ] && ok "client: GET http://$V/ returns 200" || bad "client: GET http://$V/ returns 200 (got: ${code:-no answer})"
sleep 1
dx victim grep -q "^${IP[client]} - - \[.*\] \"GET / HTTP/1.1\" 200" /var/log/myhttplogfile.txt 2>/dev/null \
    && ok "victim: /var/log/myhttplogfile.txt logged the client request" \
    || bad "victim: /var/log/myhttplogfile.txt logged the client request"
b=$(banner attacker 8081); [[ "$b" == "220 slow-scan inventory service ready" ]] \
    && ok "attacker: 8081 banner is 'inventory'" || bad "attacker: 8081 banner is 'inventory' (got: ${b:-none})"
b=$(banner attacker 9090); [[ "$b" == "220 slow-scan backup service ready" ]] \
    && ok "attacker: 9090 banner is 'backup'" || bad "attacker: 9090 banner is 'backup' (got: ${b:-none})"
b=$(banner client 22); [[ "$b" == SSH-2.0-* ]] \
    && ok "client: port 22 answers with an SSH banner" || bad "client: port 22 answers with an SSH banner (got: ${b:-none})"
# A closed port must answer RST (ECONNREFUSED = 111), not stay silent: the monitor
# turns RST into result=FAIL. Port 23 is not used by any service.
rc=$(dx attacker python3 -c "import socket
s=socket.socket(); s.settimeout(3); print(s.connect_ex(('$V',23)))" 2>/dev/null)
[ "$rc" = "111" ] && ok "attacker: closed port 23 is refused (RST)" || bad "attacker: closed port 23 is refused (RST) (connect_ex: ${rc:-?})"

echo "== monitor and detectors (Steps 4-5)"
LOGDIR=/var/log/slowscan
CONN=$LOGDIR/conn.log
for s in slowscan-monitor slowscan-baseline slowscan-proposed; do
    check "victim: $s.service is active"  dx victim systemctl is-active --quiet "$s"
    check "victim: $s.service is enabled" dx victim systemctl is-enabled --quiet "$s"
done
b=$(dx victim journalctl -u slowscan-monitor --no-pager -o cat 2>/dev/null | grep 'monitor: backend=' | tail -1)
info "monitor: ${b:-no start line in the journal}"
dx victim journalctl -u slowscan-monitor --no-pager -o cat 2>/dev/null | grep -q 'backend scapy failed' \
    && info "monitor: scapy failed and the tcpdump fallback is in use (journalctl -u slowscan-monitor)"
check "victim: $CONN exists" dx victim test -f "$CONN"
for m in baseline proposed; do
    dx victim grep -q "HEARTBEAT mode=$m " "$LOGDIR/$m.log" 2>/dev/null \
        && ok "victim: $m.log has HEARTBEAT lines" || bad "victim: $m.log has HEARTBEAT lines"
done

# wait_for <seconds> <file> <ERE>: poll the victim until a line matches
wait_for() {
    local i
    for ((i = 0; i < $1 * 2; i++)); do
        dx victim grep -Eq "$3" "$2" 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}
# count <file> <ERE>
count() { local c; c=$(dx victim grep -Ec "$2" "$1" 2>/dev/null); echo "${c:-0}"; }
probe() {  # probe <container> <port>: one TCP connect, like a connect scan
    dx "$1" python3 -c "import socket
s=socket.socket(); s.settimeout(3); s.connect_ex(('$V',$2)); s.close()" >/dev/null 2>&1
}

C=${IP[client]}; A=${IP[attacker]}
n=$(count "$CONN" "src=$C .* dport=80 result=OK")
dx client curl -s -o /dev/null --max-time 5 "http://$V/" >/dev/null 2>&1
if wait_for 5 "$CONN" "src=$C .* dport=80 result=OK"; then
    m=$(count "$CONN" "src=$C .* dport=80 result=OK")
    [ "$m" -gt "$n" ] && ok "conn.log: client web request logged as result=OK" \
                      || bad "conn.log: client web request logged as result=OK (no new line)"
else bad "conn.log: client web request logged as result=OK"; fi
n=$(count "$CONN" "src=$A .* dport=24 result=FAIL")
probe attacker 24
sleep 1
m=$(count "$CONN" "src=$A .* dport=24 result=FAIL")
[ "$m" -gt "$n" ] && ok "conn.log: attacker probe of closed port 24 logged as result=FAIL" \
                  || bad "conn.log: attacker probe of closed port 24 logged as result=FAIL"
line=$(dx victim tail -n 1 "$CONN" 2>/dev/null)
[[ "$line" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\ src=[0-9.]+\ sport=[0-9]+\ dst=$V\ dport=[0-9]+\ result=(OK|FAIL|TIMEOUT)$ ]] \
    && ok "conn.log: lines follow the frozen format" || bad "conn.log: lines follow the frozen format (last: ${line:-none})"
for m in baseline proposed; do
    dx victim grep -q "ALERT mode=$m src=$C " "$LOGDIR/$m.log" 2>/dev/null \
        && bad "$m: no alert for the client's normal traffic" || ok "$m: no alert for the client's normal traffic"
done

if [ $do_scan = 1 ]; then
    echo "== fast scan: attacker nmap -sT -Pn -T4 -p 1-200 (Steps 4-5)"
    declare -A before
    for m in baseline proposed; do before[$m]=$(count "$LOGDIR/$m.log" "ALERT mode=$m src=$A "); done
    dx attacker nmap -sT -Pn -T4 -p 1-200 "$V" >/dev/null 2>&1
    for m in baseline proposed; do
        if wait_for 10 "$LOGDIR/$m.log" "ALERT mode=$m src=$A " && \
           [ "$(count "$LOGDIR/$m.log" "ALERT mode=$m src=$A ")" -gt "${before[$m]}" ]; then
            ok "$m: ALERT for the fast scan"
            info "$(dx victim grep "ALERT mode=$m src=$A " "$LOGDIR/$m.log" | tail -1)"
        elif [ "${before[$m]}" -gt 0 ]; then
            bad "$m: ALERT for the fast scan (attacker already alerted earlier and is in cooldown: run labtainer -r $LAB)"
        else
            bad "$m: ALERT for the fast scan"
        fi
    done
fi

if [ $do_slow = 1 ]; then
    echo "== slow scan: client, 13 closed ports 10 s apart (~2.5 min) (Steps 4-5)"
    dx client python3 -c "import socket, time
for i, p in enumerate(range(1001, 1014)):
    if i: time.sleep(10)
    s = socket.socket(); s.settimeout(1); s.connect_ex(('$V', p)); s.close()" >/dev/null 2>&1
    if wait_for 10 "$LOGDIR/proposed.log" "ALERT mode=proposed src=$C "; then
        ok "proposed: ALERT for the slow scan"
        info "$(dx victim grep "ALERT mode=proposed src=$C " "$LOGDIR/proposed.log" | tail -1)"
    else bad "proposed: ALERT for the slow scan"; fi
    dx victim grep -q "ALERT mode=baseline src=$C " "$LOGDIR/baseline.log" 2>/dev/null \
        && bad "baseline: silent during the slow scan" || ok "baseline: silent during the slow scan"
fi

echo
echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
