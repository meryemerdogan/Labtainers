#!/usr/bin/env python3
"""
Static checks for the slow-scan lab: Milestone 2, Step 1 (skeleton and
topology), Step 2 (Dockerfiles), Step 3 (victim services) and Steps 4-5
(monitor and detectors).

Needs only Python 3 (no Docker, no Linux), so it runs on a Windows checkout,
in the VM, or in CI.

    python3 labs/slow-scan/tests/check_lab.py            # from the repo root
    python3 check_lab.py --lab-dir X --labtainer-dir Y   # explicit paths

Exit status 0 = no FAIL. WARN lines are informational.

What is checked:
  layout      required dirs/files, no generator leftovers, one Dockerfile per container
  startconfig parsed by Labtainers' own ParseStartConfig with network validation on
  topology    expected containers/IPs/user/terminals, subnet + gateway rules,
              network-name and subnet collisions with other labs
  dockerfile  FROM line and base, template invariants, apt packages (exact set,
              before USER, with update / -y / --no-install-recommends)
  bases       the base image chain really provides what our containers rely on
  services    victim files, unit files (ordering, ports, root only where needed),
              fixlocal.sh enable/start order, /run/sshd on every boot, exec bits,
              every victim script parses as Python 3.8 (Ubuntu 20.04)
  detection   monitor/detector units (options, ordering, root for capture),
              monitor.py output parsed by detector.py, unit settings accepted
  hygiene     LF line endings, no BOM, shebangs, .gitattributes
"""
import argparse
import ast
import importlib.util
import ipaddress
import os
import re
import subprocess
import sys
sys.dont_write_bytecode = True  # no __pycache__ next to lab scripts: it would end up in the image
import types

LAB_NAME = 'slow-scan'

# ---- The spec from MILESTONE2_PLAN.md sections 4 and 5 ----------------------
NETWORK = 'SLOWSCAN_LAN'
SUBNET = '172.20.0.0/24'
GATEWAY = '172.20.0.100'
EXPECTED = {
    # container: IP, base image, packages we apt-get install, packages the
    #            base chain must already provide for this container
    'attacker': dict(ip='172.20.0.10', base='network2', install=set(),
                     from_base={'nmap', 'netcat-openbsd', 'python3-pip'}),
    'client':   dict(ip='172.20.0.20', base='network2', install={'curl', 'sshpass'},
                     from_base={'python3-pip'}),
    'victim':   dict(ip='172.20.0.30', base='network.ssh2', install={'python3-scapy'},
                     from_base={'python3-pip', 'tcpdump', 'xinetd', 'openssh-server'}),
}
REQUIRED_DIRS = ['config', 'dockerfiles', 'docs', 'instr_config']
REQUIRED_FILES = [
    'config/start.config', 'config/parameter.config', 'config/about.txt',
    'config/keywords.txt', 'docs/read_first.txt',
    'instr_config/results.config', 'instr_config/goals.config',
    '.gitattributes',
]
TEMPLATE_ARGS = ['lab', 'labdir', 'imagedir', 'user_name', 'password', 'apt_source', 'version']
TEMPLATE_LINES = [
    'ADD $labdir/$imagedir/sys_tar/sys.tar /',
    'ADD $labdir/sys_$lab.tar.gz /',
    'RUN useradd -ms /bin/bash $user_name',
    'ADD $labdir/$imagedir/home_tar/home.tar $HOME',
    'ADD $labdir/$lab.tar.gz $HOME',
]
INIT_CMD = 'CMD ["/bin/bash", "-c", "exec /sbin/init --log-target=journal 3>&1"]'

# ---- Step 3: victim services (MILESTONE2_PLAN.md section 6) ----------------
VICTIM_SYS = 'victim/_system'
UNIT_DIR = 'etc/systemd/system'
SERVICES = {
    # unit: (script it runs, TCP port it must listen on)
    'httpserver': ('/usr/bin/MyHTTPServer.py', 80),
    'testsvc1':   ('/usr/bin/testsvc.py', 8081),
    'testsvc2':   ('/usr/bin/testsvc.py', 9090),
}
SSH_PORT = 22                       # sshd via xinetd, from the network.ssh2 base
HTTP_LOG = '/var/log/myhttplogfile.txt'
VICTIM_FILES = ['usr/bin/MyHTTPServer.py', 'usr/bin/testsvc.py', 'var/www/html/index.html',
                'etc/rc.local', 'etc/tmpfiles.d/sshd.conf']
PY2_IDIOMS = [r'^\s*print\s+["\']', r'import\s+SimpleHTTPServer', r'import\s+SocketServer\b',
              r'\bexcept\s+\w+\s*,\s*\w+\s*:']
MIN_PYTHON = (3, 8)                 # python3 on Ubuntu 20.04 (base2)

# ---- Steps 4-5: monitor and detectors (MILESTONE2_PLAN.md section 7) ------
VICTIM_IP = EXPECTED['victim']['ip']
CONN_LOG = '/var/log/slowscan/conn.log'
DETECTION_UNITS = {
    # unit: (script, options its ExecStart must pass)
    'slowscan-monitor': ('/usr/bin/monitor.py',
                         {'--iface': 'eth0', '--victim': VICTIM_IP, '--out': CONN_LOG}),
    'slowscan-baseline': ('/usr/bin/detector.py',
                          {'--mode': 'baseline', '--threshold': '12', '--window': '60',
                           '--follow': CONN_LOG, '--out': '/var/log/slowscan/baseline.log'}),
    'slowscan-proposed': ('/usr/bin/detector.py',
                          {'--mode': 'proposed', '--threshold': '12', '--window': '600', '--fail-ratio': '0.70',
                           '--follow': CONN_LOG, '--out': '/var/log/slowscan/proposed.log'}),
}
BINARY_EXT = {'.pdf', '.docx', '.png', '.jpg', '.jpeg', '.gif', '.pcap', '.tar', '.gz', '.zip'}


class Report:
    def __init__(self, quiet=False):
        self.items = []
        self.quiet = quiet

    def add(self, status, group, msg):
        self.items.append((status, group, msg))
        if not self.quiet:
            print('%-4s  %-11s %s' % (status, group, msg))

    def ok(self, g, m):
        self.add('PASS', g, m)

    def fail(self, g, m):
        self.add('FAIL', g, m)

    def warn(self, g, m):
        self.add('WARN', g, m)

    def check(self, cond, g, m):
        (self.ok if cond else self.fail)(g, m)
        return cond

    @property
    def failures(self):
        return [i for i in self.items if i[0] == 'FAIL']


def read(path):
    with open(path, 'rb') as fh:
        return fh.read().decode('utf-8')


# ---- start.config ---------------------------------------------------------
class _Logger:
    def __init__(self):
        self.errors = []

    def error(self, msg, *_):
        self.errors.append(str(msg).strip())

    def debug(self, *a, **k):
        pass

    info = warning = debug


def parse_with_labtainers(start_config, labtainer_dir):
    """Run the real Labtainers parser (skip_networks=False => full validation).

    labutils imports Unix-only modules (fcntl) and is only used by the parser
    for MACVLAN networks, so a stub is enough. Returns (parsed, errors).
    """
    bin_dir = os.path.join(labtainer_dir, 'scripts', 'labtainer-student', 'bin')
    if bin_dir not in sys.path:
        sys.path.insert(0, bin_dir)
    saved = sys.modules.get('labutils')
    stub = types.ModuleType('labutils')
    setattr(stub, 'getFirstUnassignedIface', lambda n=1: None)
    sys.modules['labutils'] = stub
    try:
        sys.modules.pop('ParseStartConfig', None)
        import ParseStartConfig  # type: ignore  # from Labtainers' student bin dir
        cfg = types.SimpleNamespace(default_registry='labtainers', test_registry='testregistry:5000')
        logger = _Logger()
        try:
            parsed = ParseStartConfig.ParseStartConfig(start_config, LAB_NAME, cfg, logger,
                                                       skip_networks=False)
        except SystemExit:
            return None, logger.errors or ['parser exited without a message']
        except Exception as e:  # e.g. TypeError in finalize() when LAB_MASTER_SEED is missing
            return None, logger.errors + ['parser crashed: %s: %s (missing lab_master_seed?)'
                                          % (type(e).__name__, e)]
        return parsed, logger.errors
    finally:
        if saved is None:
            sys.modules.pop('labutils', None)
        else:
            sys.modules['labutils'] = saved


def other_lab_networks(labtainer_dir):
    """{lab: [(netname_lower, mask)]} for every other lab's start.config."""
    out = {}
    labs = os.path.join(labtainer_dir, 'labs')
    for lab in sorted(os.listdir(labs)):
        if lab == LAB_NAME:
            continue
        sc = os.path.join(labs, lab, 'config', 'start.config')
        if not os.path.isfile(sc):
            continue
        nets, cur = [], None
        try:
            text = read(sc)
        except (UnicodeDecodeError, OSError):
            continue
        for line in text.splitlines():
            parts = line.strip().split()
            if not parts or parts[0].startswith('#'):
                continue
            key = parts[0].lower()
            if key == 'network' and len(parts) > 1:
                cur = [parts[1].lower(), None]
                nets.append(cur)
            elif key == 'mask' and cur is not None and len(parts) > 1:
                cur[1] = parts[1]
            elif key in ('container', 'global_settings'):
                cur = None
        out[lab] = [tuple(n) for n in nets]
    return out


# ---- checks ---------------------------------------------------------------
def check_layout(lab, rep):
    g = 'layout'
    for d in REQUIRED_DIRS + list(EXPECTED):
        rep.check(os.path.isdir(os.path.join(lab, d)), g, 'directory %s/ exists' % d)
    for f in REQUIRED_FILES:
        rep.check(os.path.isfile(os.path.join(lab, f)), g, 'file %s exists' % f)
    for c in EXPECTED:
        rep.check(os.path.isfile(os.path.join(lab, c, '_bin', 'fixlocal.sh')), g,
                  '%s/_bin/fixlocal.sh exists' % c)
    # leftovers from new_lab_setup.py (default container is named after the lab)
    rep.check(not os.path.exists(os.path.join(lab, LAB_NAME)), g,
              'no leftover default container dir %s/' % LAB_NAME)
    ddir = os.path.join(lab, 'dockerfiles')
    if os.path.isdir(ddir):
        want = {'Dockerfile.%s.%s.student' % (LAB_NAME, c) for c in EXPECTED}
        have = set(os.listdir(ddir))
        rep.check(want <= have, g, 'one Dockerfile per container (%s)' % ', '.join(sorted(EXPECTED)))
        extra = have - want
        rep.check(not extra, g, 'no stray Dockerfiles' + (': %s' % sorted(extra) if extra else ''))

    about = os.path.join(lab, 'config', 'about.txt')
    if os.path.isfile(about):
        lines = [l for l in read(about).splitlines() if l.strip()]
        rep.check(len(lines) == 1, g, 'about.txt is one non-empty line')
    kw = os.path.join(lab, 'config', 'keywords.txt')
    if os.path.isfile(kw):
        lines = [l for l in read(kw).splitlines() if l.strip()]
        rep.check(len(lines) >= 3, g, 'keywords.txt has %d keywords (one per line)' % len(lines))
    rf = os.path.join(lab, 'docs', 'read_first.txt')
    if os.path.isfile(rf):
        t = read(rf)
        rep.check('LAB_DOCS/%s.pdf' % LAB_NAME in t and 'LABNAME' not in t, g,
                  'read_first.txt points at LAB_DOCS/%s.pdf' % LAB_NAME)


def check_start_config(lab, labtainer_dir, rep):
    g = 'startconfig'
    sc = os.path.join(lab, 'config', 'start.config')
    if not os.path.isfile(sc):
        rep.fail(g, 'start.config missing, skipping')
        return
    parsed, errors = parse_with_labtainers(sc, labtainer_dir)
    if not rep.check(parsed is not None and not errors, g,
                     'Labtainers ParseStartConfig accepts it (network validation on)'
                     + ('' if not errors else ': ' + ' | '.join(errors))):
        return
    assert parsed is not None

    g = 'topology'
    net = NETWORK.lower()
    rep.check(set(parsed.subnets) == {net}, g,
              'exactly one network, %s (got %s)' % (NETWORK, sorted(parsed.subnets)))
    sub = parsed.subnets.get(net)
    if sub is not None:
        rep.check(sub.mask == SUBNET, g, 'network mask is %s' % SUBNET)
        rep.check(sub.gateway == GATEWAY, g, 'gateway is %s' % GATEWAY)
    network = ipaddress.ip_network(SUBNET)
    gw = ipaddress.ip_address(GATEWAY)
    rep.check(gw in network and gw not in (network.network_address, network.broadcast_address),
              g, 'gateway is a usable host address inside the subnet')

    rep.check(list(parsed.containers) == list(EXPECTED), g,
              'containers are %s, in that order' % ', '.join(EXPECTED))
    seen = {}
    for name, spec in EXPECTED.items():
        c = parsed.containers.get(name)
        if c is None:
            rep.fail(g, 'container %s missing' % name)
            continue
        rep.check(c.user == 'ubuntu', g, '%s: USER ubuntu' % name)
        rep.check(int(c.terminals) == 1, g, '%s: TERMINALS 1' % name)
        rep.check(list(c.container_nets) == [net], g, '%s: attached only to %s' % (name, NETWORK))
        addr = c.container_nets.get(net, '')
        rep.check(addr == spec['ip'], g, '%s: address %s (got %s)' % (name, spec['ip'], addr or '-'))
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        rep.check(ip in network and ip not in (network.network_address, network.broadcast_address),
                  g, '%s: %s is a usable host in %s' % (name, ip, SUBNET))
        rep.check(ip != gw, g, '%s: address is not the Docker gateway' % name)
        if ip in seen:
            rep.fail(g, '%s: address %s duplicates %s' % (name, ip, seen[ip]))
        seen[ip] = name
    rep.check(len(seen) == len(EXPECTED), g, 'container addresses are unique')
    rep.check(bool(parsed.lab_master_seed) and LAB_NAME in parsed.lab_master_seed, g,
              'LAB_MASTER_SEED is set')

    # collisions with other labs
    others = other_lab_networks(labtainer_dir)
    for pnet in parsed.subnets:
        same_name = sorted(l for l, nets in others.items() if any(n == pnet for n, _ in nets))
        rep.check(not same_name, g, 'Docker network name "%s" is unique across labs%s'
                  % (pnet, '' if not same_name else ' (also in: %s)' % ', '.join(same_name)))
    overlap = []
    for l, nets in others.items():
        for _, mask in nets:
            try:
                if mask and ipaddress.ip_network(mask, strict=False).overlaps(network):
                    overlap.append(l)
            except ValueError:
                pass
    overlap = sorted(set(overlap))
    if overlap:
        # Normal in Labtainers (one lab at a time); labutils refuses to start
        # and names the lab to stop. Informational only.
        rep.warn(g, 'subnet %s is also used by %d labs (%s): only one of them can run at a time'
                 % (SUBNET, len(overlap), ', '.join(overlap)))


def apt_installs(text):
    """[(line_index, full_RUN_text, {packages})] for every apt-get install RUN."""
    lines = text.splitlines()
    out, i = [], 0
    while i < len(lines):
        start, cmd = i, lines[i]
        while cmd.rstrip().endswith('\\') and i + 1 < len(lines):
            i += 1
            cmd = cmd.rstrip()[:-1] + ' ' + lines[i]
        i += 1
        s = cmd.strip()
        if s.startswith('#') or not re.match(r'(RUN\s+)?.*apt-get\s+.*install', s):
            continue
        pkgs = set()
        for seg in re.split(r'&&|;', s):
            toks = seg.split()
            if 'apt-get' in toks and 'install' in toks:
                for t in toks[toks.index('install') + 1:]:
                    if not t.startswith('-') and t != '\\':
                        pkgs.add(t)
        out.append((start, s, pkgs))
    return out


def base_chain(labtainer_dir, base):
    """Walk Dockerfile.labtainer.<base> -> parent ... ; return (chain, packages)."""
    bdir = os.path.join(labtainer_dir, 'scripts', 'designer', 'base_dockerfiles')
    chain, pkgs, cur = [], set(), base
    while cur and cur not in chain:
        path = os.path.join(bdir, 'Dockerfile.labtainer.%s' % cur)
        if not os.path.isfile(path):
            break
        chain.append(cur)
        text = read(path)
        for _, _, p in apt_installs(text):
            pkgs |= p
        m = re.search(r'^FROM\s+\$registry/labtainer\.(\S+)', text, re.M)
        cur = m.group(1) if m else None
    return chain, pkgs, bdir


def check_dockerfiles(lab, labtainer_dir, rep):
    g = 'dockerfile'
    for name, spec in EXPECTED.items():
        path = os.path.join(lab, 'dockerfiles', 'Dockerfile.%s.%s.student' % (LAB_NAME, name))
        if not os.path.isfile(path):
            rep.fail(g, '%s: Dockerfile missing' % name)
            continue
        text = read(path)
        lines = [l.rstrip() for l in text.splitlines()]
        instr = [(i, l.strip()) for i, l in enumerate(lines) if l.strip() and not l.strip().startswith('#')]
        froms = [(i, l) for i, l in instr if l.startswith('FROM')]
        want_from = 'FROM $registry/labtainer.%s' % spec['base']
        rep.check(len(froms) == 1 and froms[0][1] == want_from, g,
                  '%s: single FROM line "%s"' % (name, want_from))
        if froms:
            before = [l for i, l in instr if i < froms[0][0]]
            rep.check(before == ['ARG registry'], g, '%s: only "ARG registry" precedes FROM' % name)
        bfile = os.path.join(labtainer_dir, 'scripts', 'designer', 'base_dockerfiles',
                             'Dockerfile.labtainer.%s' % spec['base'])
        rep.check(os.path.isfile(bfile), g, '%s: base Dockerfile.labtainer.%s exists' % (name, spec['base']))
        stripped = [l for _, l in instr]
        missing = [a for a in TEMPLATE_ARGS if 'ARG %s' % a not in stripped]
        rep.check(not missing, g, '%s: template ARGs present%s' % (name, '' if not missing else ' (missing %s)' % missing))
        missing = [l for l in TEMPLATE_LINES if l not in stripped]
        rep.check(not missing, g, '%s: template ADD/useradd lines present%s'
                  % (name, '' if not missing else ' (missing %s)' % missing))
        rep.check(bool(instr) and instr[-1][1] == INIT_CMD, g, '%s: last instruction starts systemd init' % name)
        users = [(i, l) for i, l in instr if l.startswith('USER ')]
        rep.check([l for _, l in users] == ['USER $user_name', 'USER root'], g,
                  '%s: USER $user_name ... USER root sequence intact' % name)
        user_idx = next((i for i, l in users if l == 'USER $user_name'), len(lines))

        installs = apt_installs(text)
        got = set().union(*[p for _, _, p in installs]) if installs else set()
        rep.check(got == spec['install'], g, '%s: installs exactly %s (got %s)'
                  % (name, sorted(spec['install']) or 'nothing', sorted(got) or 'nothing'))
        for idx, cmd, pkgs in installs:
            label = '%s: install of %s' % (name, ' '.join(sorted(pkgs)))
            rep.check(idx < user_idx, g, label + ' runs as root, before USER $user_name')
            rep.check(re.search(r'apt-get\s+update\s*&&', cmd) is not None, g, label + ' is chained after apt-get update')
            rep.check(re.search(r'\s-y\b', cmd) is not None and '--no-install-recommends' in cmd, g,
                      label + ' uses -y --no-install-recommends')
        apt_src = next((i for i, l in instr if l == 'RUN /usr/bin/apt-source.sh'), None)
        if installs:
            rep.check(apt_src is not None and apt_src < installs[0][0], g,
                      '%s: apt-source.sh runs before package installs' % name)


def check_bases(labtainer_dir, rep):
    g = 'bases'
    for name, spec in EXPECTED.items():
        chain, pkgs, bdir = base_chain(labtainer_dir, spec['base'])
        rep.check(bool(chain) and chain[-1] == 'base2', g,
                  '%s: base chain %s ends at base2 (Ubuntu 20.04)' % (name, ' -> '.join(chain) or '?'))
        missing = sorted(spec['from_base'] - pkgs)
        rep.check(not missing, g, '%s: base provides %s%s'
                  % (name, ', '.join(sorted(spec['from_base'])), '' if not missing else ' (missing %s)' % missing))
        overlap = sorted(spec['install'] & pkgs)
        rep.check(not overlap, g, '%s: no package installed twice (base already has %s)' % (name, overlap)
                  if overlap else '%s: lab packages are not already in the base' % name)
    # sshd via xinetd is what network.ssh2 adds on top of network2
    ssh2 = os.path.join(labtainer_dir, 'scripts', 'designer', 'base_dockerfiles', 'Dockerfile.labtainer.network.ssh2')
    if os.path.isfile(ssh2):
        rep.check('/etc/xinetd.d/ssh' in read(ssh2), g, 'victim: network.ssh2 installs the xinetd ssh service')
    # no base ships scapy (why the victim installs it)
    allp = set()
    for b in ('network2', 'network.ssh2'):
        allp |= base_chain(labtainer_dir, b)[1]
    rep.check(not any('scapy' in p for p in allp), g, 'scapy is not in any base we use (victim must install it)')


def parse_unit(text):
    """systemd unit file -> {section: {key: [values]}} (good enough for our units)."""
    out, sec = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in '#;':
            continue
        if line.startswith('[') and line.endswith(']'):
            sec = out.setdefault(line[1:-1], {})
        elif '=' in line and sec is not None:
            k, v = line.split('=', 1)
            sec.setdefault(k.strip(), []).append(v.strip())
    return out


def unit_port(unit, args):
    """TCP port a service unit's ExecStart arguments make it listen on."""
    if unit == 'httpserver':
        if '--port' in args and args.index('--port') + 1 < len(args):
            return args[args.index('--port') + 1]
        return '80'  # MyHTTPServer.py default
    return args[0] if args else None


def git_mode(repo_root, path):
    """'100755' / '100644' from the git index, None if untracked, False if git is unusable."""
    rel = os.path.relpath(path, repo_root).replace(os.sep, '/')
    try:
        out = subprocess.run(['git', '-C', repo_root, 'ls-files', '-s', '--', rel],
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    if out.returncode != 0:
        return False
    return out.stdout.split()[0] if out.stdout.strip() else None


def check_unit_common(rep, g, sysdir, unit, script):
    """Checks every slow-scan unit shares. Returns (unit, [Service], ExecStart argv) or None."""
    p = os.path.join(sysdir, *UNIT_DIR.split('/'), unit + '.service')
    if not os.path.isfile(p):
        return None
    u = parse_unit(read(p))
    label = '%s.service' % unit
    rep.check({'Unit', 'Service', 'Install'} <= set(u), g, label + ': has [Unit], [Service], [Install]')
    after = ' '.join(u.get('Unit', {}).get('After', [])).split()
    rep.check('waitparam.service' in after, g, label + ': After=waitparam.service')
    rep.check('multi-user.target' in u.get('Install', {}).get('WantedBy', []), g,
              label + ': WantedBy=multi-user.target')
    svc = u.get('Service', {})
    rep.check(bool(svc.get('Restart')), g, label + ': Restart= is set')
    execs = svc.get('ExecStart', [])
    if not rep.check(len(execs) == 1, g, label + ': exactly one ExecStart'):
        return None
    argv = execs[0].split()
    rep.check(argv[:2] == ['/usr/bin/python3', script], g,
              label + ': ExecStart runs "/usr/bin/python3 %s" (independent of the exec bit)' % script)
    rep.check(os.path.isfile(os.path.join(sysdir, *script.strip('/').split('/'))), g,
              label + ': %s is shipped in %s' % (script, VICTIM_SYS))
    return u, svc, argv


def load_script(path, name):
    """Import a lab script (e.g. detector.py) from its file without touching sys.path."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load %s' % path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def option_map(args):
    """['--a', 'x', '--flag', '--b', 'y'] -> {'--a': 'x', '--flag': None, '--b': 'y'}"""
    out, i = {}, 0
    while i < len(args):
        if args[i].startswith('--'):
            val = args[i + 1] if i + 1 < len(args) and not args[i + 1].startswith('--') else None
            out[args[i]] = val
            i += 2 if val is not None else 1
        else:
            i += 1
    return out


def check_detection(lab, rep):
    g = 'detection'
    sysdir = os.path.join(lab, *VICTIM_SYS.split('/'))
    for unit, (script, want) in DETECTION_UNITS.items():
        rep.check(os.path.isfile(os.path.join(sysdir, *UNIT_DIR.split('/'), unit + '.service')), g,
                  '%s/%s/%s.service exists' % (VICTIM_SYS, UNIT_DIR, unit))
        res = check_unit_common(rep, g, sysdir, unit, script)
        if res is None:
            continue
        u, svc, argv = res
        label = '%s.service' % unit
        opts = option_map(argv[2:])
        for k, v in want.items():
            rep.check(opts.get(k) == v, g, '%s: %s %s (got %s)' % (label, k, v, opts.get(k, 'nothing')))
        if unit == 'slowscan-monitor':
            user = (svc.get('User') or ['root'])[-1]
            rep.check(user == 'root', g, label + ': runs as root (packet capture)')
        else:
            after = ' '.join(u.get('Unit', {}).get('After', [])).split()
            rep.check('slowscan-monitor.service' in after, g, label + ': After=slowscan-monitor.service')
            if want['--mode'] == 'baseline':
                rep.check('--fail-ratio' not in opts, g, label + ': baseline has no --fail-ratio')
            rep.check(opts.get('--out') not in (None, CONN_LOG), g, label + ': does not write into conn.log')

    # monitor and detectors must agree on the frozen conn.log format (plan 7.1)
    mon_p = os.path.join(sysdir, 'usr', 'bin', 'monitor.py')
    det_p = os.path.join(sysdir, 'usr', 'bin', 'detector.py')
    if not (os.path.isfile(mon_p) and os.path.isfile(det_p)):
        rep.fail(g, 'monitor.py and detector.py are shipped')
        return
    try:
        mon = load_script(mon_p, '_slowscan_monitor')
        det = load_script(det_p, '_slowscan_detector')
    except Exception as e:  # syntax errors are reported by check_services
        rep.fail(g, 'monitor.py and detector.py import cleanly (%s: %s)' % (type(e).__name__, e))
        return
    ok = True
    for result in ('OK', 'FAIL', 'TIMEOUT'):
        line = mon.format_line(1795000000.0, '172.20.0.10', 40312, VICTIM_IP, 22, result)
        e = det.parse_line(line)
        ok &= bool(re.match(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d ', line)) and '[' not in line and \
            e is not None and (e.src, e.sport, e.dst, e.dport, e.result) == \
            ('172.20.0.10', 40312, VICTIM_IP, 22, result)
    rep.check(ok, g, 'detector.py parses every line format monitor.py writes (ISO first, no brackets)')
    for unit, (_, want) in DETECTION_UNITS.items():
        if '--mode' not in want:
            continue
        p = os.path.join(sysdir, *UNIT_DIR.split('/'), unit + '.service')
        if not os.path.isfile(p):
            continue
        execs = parse_unit(read(p)).get('Service', {}).get('ExecStart', [''])
        opts = option_map(execs[0].split()[2:])
        try:
            num = lambda k, f: None if opts.get(k) is None else f(opts[k])  # noqa: E731
            cfg = det.Config(opts.get('--mode'), num('--threshold', int), num('--window', float),
                             num('--fail-ratio', float), num('--cooldown', float))
            rep.ok(g, '%s.service: detector accepts its settings (%s)' % (unit, cfg.describe()))
        except (ValueError, TypeError) as e:
            rep.fail(g, '%s.service: detector accepts its settings (%s)' % (unit, e))


def check_services(lab, rep, repo_root=None):
    g = 'services'
    sysdir = os.path.join(lab, *VICTIM_SYS.split('/'))
    unit_dir = os.path.join(sysdir, *UNIT_DIR.split('/'))
    for f in VICTIM_FILES + ['%s/%s.service' % (UNIT_DIR, u) for u in SERVICES]:
        rep.check(os.path.isfile(os.path.join(sysdir, *f.split('/'))), g, '%s/%s exists' % (VICTIM_SYS, f))

    # Python scripts: valid Python 3 for the image's interpreter, no Python 2 leftovers
    bindir = os.path.join(sysdir, 'usr', 'bin')
    scripts = sorted(f for f in os.listdir(bindir) if f.endswith('.py')) if os.path.isdir(bindir) else []
    for rel in ['usr/bin/' + f for f in scripts]:
        p = os.path.join(sysdir, *rel.split('/'))
        src = read(p)
        try:
            compile(src, p, 'exec')
            ast.parse(src, p, feature_version=MIN_PYTHON)
            rep.ok(g, '%s compiles as Python %d.%d (Ubuntu 20.04 in the image)' % ((rel,) + MIN_PYTHON))
        except SyntaxError as e:
            rep.fail(g, '%s compiles as Python %d.%d (%s line %s)' % ((rel,) + MIN_PYTHON + (e.msg, e.lineno)))
        py2 = [pat for pat in PY2_IDIOMS if re.search(pat, src, re.M)]
        rep.check(not py2, g, '%s has no Python 2 idioms%s' % (rel, '' if not py2 else ' (%s)' % py2))
        rep.check(src.startswith('#!/usr/bin/env python3\n'), g, '%s shebang is python3' % rel)
    p = os.path.join(sysdir, 'usr', 'bin', 'MyHTTPServer.py')
    if os.path.isfile(p):
        src = read(p)
        rep.check("'%s'" % HTTP_LOG in src, g, 'MyHTTPServer.py logs to %s by default' % HTTP_LOG)
        rep.check("'%d/%b/%Y:%H:%M:%S" in src, g,
                  'MyHTTPServer.py writes httpd-style [dd/Mon/YYYY:HH:MM:SS] timestamps (getTS)')
    p = os.path.join(sysdir, 'var', 'www', 'html', 'index.html')
    if os.path.isfile(p):
        rep.check('<html' in read(p).lower(), g, 'index.html is an HTML page')

    # unit files
    ports = {}
    for unit, (script, port) in SERVICES.items():
        res = check_unit_common(rep, g, sysdir, unit, script)
        if res is None:
            continue
        _, svc, argv = res
        label = '%s.service' % unit
        got = unit_port(unit, argv[2:])
        rep.check(got == str(port), g, label + ': listens on port %d (got %s)' % (port, got))
        if unit.startswith('testsvc'):
            rep.check(len(argv) == 4 and argv[3].isprintable() and argv[3].isascii(), g,
                      label + ': ExecStart passes <port> <name>')
        user = (svc.get('User') or ['root'])[-1]
        if port < 1024:
            rep.check(user == 'root', g, label + ': runs as root (port %d is privileged)' % port)
        if got and got.isdigit():
            ports.setdefault(int(got), []).append(unit)
    taken = {SSH_PORT: ['xinetd ssh']}
    clash = {pt: units for pt, units in ports.items() if len(units) > 1 or pt in taken}
    rep.check(not clash, g, 'service ports are unique and do not clash with ssh/22'
              + ('' if not clash else ' (%s)' % clash))

    # fixlocal.sh enables and starts everything, in the right order
    fl = os.path.join(lab, 'victim', '_bin', 'fixlocal.sh')
    if os.path.isfile(fl):
        text = read(fl)
        m = re.search(r'^UNITS="([^"]*)"', text, re.M)
        listed = m.group(1).split() if m else []
        shipped = sorted(f[:-len('.service')] for f in os.listdir(unit_dir)
                         if f.endswith('.service')) if os.path.isdir(unit_dir) else []
        missing = [s for s in shipped if s not in listed]
        rep.check(m is not None and not missing, g, 'fixlocal.sh UNITS lists every shipped unit'
                  + ('' if not missing else ' (missing %s)' % missing))
        rep.check(re.search(r'systemctl\s+enable\s+\$present', text) is not None, g,
                  'fixlocal.sh enables the units (they survive a lab restart)')
        lock = re.search(r'mkdir\s+-p\s+"?\$PERMLOCKDIR"?', text)
        start = re.search(r'systemctl\s+start\s+\$present', text)
        rep.check('PERMLOCKDIR=/var/labtainer/did_param' in text and lock is not None
                  and start is not None and lock.start() < start.start(), g,
                  'fixlocal.sh creates /var/labtainer/did_param before starting units')
        rep.check(re.search(r'mkdir\s+-p\s+[^\n]*/var/log/slowscan', text) is not None, g,
                  'fixlocal.sh creates /var/log/slowscan')
        rep.check(re.search(r'systemctl\s+restart\s+xinetd', text) is not None, g,
                  'fixlocal.sh restarts xinetd (sshd on port 22)')

    # sshd needs /run/sshd, and /run is a tmpfs: recreate it on every boot
    p = os.path.join(sysdir, 'etc', 'rc.local')
    if os.path.isfile(p):
        t = read(p)
        rep.check(t.startswith('#!/bin/bash\n') and 'mkdir -p /run/sshd' in t, g,
                  'rc.local is a bash script that creates /run/sshd')
    p = os.path.join(sysdir, 'etc', 'tmpfiles.d', 'sshd.conf')
    if os.path.isfile(p):
        rep.check(re.search(r'^d\s+/run/sshd\s', read(p), re.M) is not None, g,
                  'tmpfiles.d/sshd.conf creates /run/sshd on every boot')

    # Executable bits travel through git only. ExecStart names python3 and
    # tmpfiles.d covers /run/sshd, so a missing bit is a warning, not a failure.
    if repo_root:
        for rel in ['etc/rc.local'] + ['usr/bin/' + f for f in scripts]:
            p = os.path.join(sysdir, *rel.split('/'))
            if not os.path.isfile(p):
                continue
            mode = git_mode(repo_root, p)
            if mode is False:
                rep.warn(g, 'git not available; skipped exec-bit check of %s' % rel)
            elif mode is None:
                rep.warn(g, '%s is not tracked yet; add it with: git add --chmod=+x %s'
                         % (rel, os.path.relpath(p, repo_root).replace(os.sep, '/')))
            else:
                rep.check(mode == '100755', g, '%s is executable in git (mode %s)' % (rel, mode))


def lab_files(lab):
    for root, dirs, files in os.walk(lab):
        dirs[:] = [d for d in dirs if d not in ('__pycache__', 'home_tar', 'sys_tar')]
        for f in files:
            if f.endswith('.pyc') or os.path.splitext(f)[1].lower() in BINARY_EXT:
                continue
            yield os.path.join(root, f)


def check_hygiene(lab, rep, repo_root=None):
    g = 'hygiene'
    crlf, bom, bad_shebang = [], [], []
    for path in lab_files(lab):
        with open(path, 'rb') as fh:
            data = fh.read()
        rel = os.path.relpath(path, lab).replace(os.sep, '/')
        if b'\r' in data:
            crlf.append(rel)
        if data.startswith(b'\xef\xbb\xbf'):
            bom.append(rel)
        if (rel.endswith('.sh') or rel.endswith('.py')) and data and not data.startswith(b'#!'):
            if rel.endswith('.sh') or b'__main__' in data:
                bad_shebang.append(rel)
    rep.check(not crlf, g, 'all text files use LF line endings' + ('' if not crlf else ' (CRLF: %s)' % crlf))
    rep.check(not bom, g, 'no UTF-8 BOMs' + ('' if not bom else ' (%s)' % bom))
    rep.check(not bad_shebang, g, 'scripts start with #!' + ('' if not bad_shebang else ' (%s)' % bad_shebang))
    # Labtainers tars everything under a container dir into the image (CheckTars.py: `ls -A`),
    # git-ignored or not, so bytecode left by running tests would ship.
    junk = []
    for c in EXPECTED:
        for root, dirs, files in os.walk(os.path.join(lab, c)):
            junk += [os.path.relpath(os.path.join(root, d), lab).replace(os.sep, '/') for d in dirs if d == '__pycache__']
            junk += [os.path.relpath(os.path.join(root, f), lab).replace(os.sep, '/') for f in files if f.endswith('.pyc')]
    rep.check(not junk, g, 'no __pycache__/.pyc in container dirs (they would be built into the image)'
              + ('' if not junk else ' (%s)' % junk))
    ga = os.path.join(lab, '.gitattributes')
    if os.path.isfile(ga):
        rep.check('* text=auto eol=lf' in read(ga).splitlines(), g, '.gitattributes forces eol=lf')
    # Ask git itself, when available, that the attribute applies.
    if repo_root:
        probe = os.path.relpath(os.path.join(lab, 'config', 'start.config'), repo_root).replace(os.sep, '/')
        try:
            out = subprocess.run(['git', '-C', repo_root, 'check-attr', 'eol', '--', probe],
                                 capture_output=True, text=True, timeout=20)
            if out.returncode == 0:
                rep.check(out.stdout.strip().endswith('eol: lf'), g, 'git applies eol=lf to lab files')
        except (OSError, subprocess.SubprocessError):
            rep.warn(g, 'git not available; skipped git check-attr')


def run_all(lab_dir, labtainer_dir, quiet=False, repo_root=None):
    rep = Report(quiet=quiet)
    check_layout(lab_dir, rep)
    check_start_config(lab_dir, labtainer_dir, rep)
    check_dockerfiles(lab_dir, labtainer_dir, rep)
    check_bases(labtainer_dir, rep)
    check_services(lab_dir, rep, repo_root=repo_root)
    check_detection(lab_dir, rep)
    check_hygiene(lab_dir, rep, repo_root=repo_root)
    return rep


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_lab = os.path.dirname(here)
    default_top = os.path.dirname(os.path.dirname(default_lab))
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--lab-dir', default=default_lab)
    ap.add_argument('--labtainer-dir', default=os.environ.get('LABTAINER_DIR') or default_top)
    ap.add_argument('-q', '--quiet', action='store_true', help='print only FAIL/WARN lines and the summary')
    args = ap.parse_args()
    if not os.path.isdir(os.path.join(args.labtainer_dir, 'scripts', 'labtainer-student', 'bin')):
        # LABTAINER_DIR may point at another checkout (e.g. the appliance's trunk)
        args.labtainer_dir = default_top
    rep = run_all(args.lab_dir, args.labtainer_dir, quiet=args.quiet, repo_root=default_top)
    if args.quiet:
        for s, g, m in rep.items:
            if s != 'PASS':
                print('%-4s  %-11s %s' % (s, g, m))
    n = {s: sum(1 for i in rep.items if i[0] == s) for s in ('PASS', 'WARN', 'FAIL')}
    print('\n%d passed, %d warnings, %d failed' % (n['PASS'], n['WARN'], n['FAIL']))
    return 1 if n['FAIL'] else 0


if __name__ == '__main__':
    sys.exit(main())
