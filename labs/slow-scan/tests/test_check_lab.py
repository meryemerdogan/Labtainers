#!/usr/bin/env python3
"""
Self-tests for check_lab.py: proves the validator catches real mistakes.

Each test copies the lab into a temp dir, injects one fault, and asserts that
check_lab reports a FAIL in the expected group. The unmodified copy must pass.

    python3 -m unittest discover -s labs/slow-scan/tests -v
"""
import os
import shutil
import sys
sys.dont_write_bytecode = True  # no __pycache__ next to lab scripts: it would end up in the image
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
TOP = os.path.dirname(os.path.dirname(LAB))
sys.path.insert(0, HERE)
import check_lab  # noqa: E402


class MutationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='slowscan-test-')
        self.lab = os.path.join(self.tmp, 'labs', 'slow-scan')
        shutil.copytree(LAB, self.lab, ignore=shutil.ignore_patterns('tests', '__pycache__'))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers
    def path(self, rel):
        return os.path.join(self.lab, *rel.split('/'))

    def edit(self, rel, old, new, count=1):
        p = self.path(rel)
        with open(p, 'rb') as fh:
            s = fh.read().decode('utf-8')
        self.assertIn(old, s, 'fixture text not found in %s' % rel)
        with open(p, 'wb') as fh:
            fh.write(s.replace(old, new, count).encode('utf-8'))

    def run_checks(self):
        return check_lab.run_all(self.lab, TOP, quiet=True)

    def assertFails(self, group, needle=''):
        rep = self.run_checks()
        hits = [m for _, g, m in rep.failures if g == group and needle in m]
        self.assertTrue(hits, 'expected a FAIL in %r containing %r; failures were: %s'
                        % (group, needle, rep.failures))

    # baseline
    def test_clean_copy_passes(self):
        rep = self.run_checks()
        self.assertEqual(rep.failures, [])

    # start.config / topology
    def test_ip_outside_subnet(self):
        self.edit('config/start.config', 'SLOWSCAN_LAN 172.20.0.30', 'SLOWSCAN_LAN 172.21.0.30')
        self.assertFails('topology', 'usable host')

    def test_duplicate_ip(self):
        self.edit('config/start.config', 'SLOWSCAN_LAN 172.20.0.20', 'SLOWSCAN_LAN 172.20.0.10')
        self.assertFails('topology', 'duplicates')

    def test_container_on_gateway_address(self):
        self.edit('config/start.config', 'SLOWSCAN_LAN 172.20.0.30', 'SLOWSCAN_LAN 172.20.0.100')
        self.assertFails('topology', 'not the Docker gateway')

    def test_broadcast_address(self):
        self.edit('config/start.config', 'SLOWSCAN_LAN 172.20.0.30', 'SLOWSCAN_LAN 172.20.0.255')
        self.assertFails('topology', 'usable host')

    def test_gateway_outside_subnet_rejected_by_labtainers_parser(self):
        self.edit('config/start.config', 'GATEWAY 172.20.0.100', 'GATEWAY 172.30.0.100')
        self.assertFails('startconfig', 'Gateway IP')

    def test_undefined_network_rejected_by_labtainers_parser(self):
        # Labtainers rejects this as "Can't understand config setting: LAN ..."
        self.edit('config/start.config', '\tSLOWSCAN_LAN 172.20.0.20', '\tLAN 172.20.0.20')
        self.assertFails('startconfig', 'LAN 172.20.0.20')

    def test_bad_ip_rejected_by_labtainers_parser(self):
        self.edit('config/start.config', 'SLOWSCAN_LAN 172.20.0.20', 'SLOWSCAN_LAN 172.20.0.300')
        self.assertFails('startconfig', 'bad ip')

    def test_missing_master_seed(self):
        self.edit('config/start.config', '\tLAB_MASTER_SEED slow-scan_2736403_master_seed\n', '')
        self.assertFails('startconfig', 'lab_master_seed')

    def test_network_name_shared_with_other_labs(self):
        self.edit('config/start.config', 'SLOWSCAN_LAN', 'LAN', count=-1)
        self.assertFails('topology', 'unique across labs')

    def test_missing_container(self):
        self.edit('config/start.config', 'CONTAINER client\n\tUSER ubuntu\n\tTERMINALS 1\n\tSLOWSCAN_LAN 172.20.0.20\n', '')
        self.assertFails('topology', 'containers are')

    def test_wrong_terminal_count(self):
        self.edit('config/start.config', 'CONTAINER victim\n\tUSER ubuntu\n\tTERMINALS 1',
                  'CONTAINER victim\n\tUSER ubuntu\n\tTERMINALS 0')
        self.assertFails('topology', 'victim: TERMINALS 1')

    # layout
    def test_missing_dockerfile(self):
        os.remove(self.path('dockerfiles/Dockerfile.slow-scan.client.student'))
        self.assertFails('layout', 'one Dockerfile per container')

    def test_generator_leftover_dir(self):
        os.makedirs(self.path('slow-scan/_bin'))
        self.assertFails('layout', 'leftover')

    def test_stray_dockerfile(self):
        shutil.copy(self.path('dockerfiles/Dockerfile.slow-scan.client.student'),
                    self.path('dockerfiles/Dockerfile.slow-scan.slow-scan.student'))
        self.assertFails('layout', 'stray')

    def test_missing_about(self):
        os.remove(self.path('config/about.txt'))
        self.assertFails('layout', 'about.txt')

    # dockerfiles
    def test_wrong_base_image(self):
        self.edit('dockerfiles/Dockerfile.slow-scan.victim.student',
                  'FROM $registry/labtainer.network.ssh2', 'FROM $registry/labtainer.network2')
        self.assertFails('dockerfile', 'single FROM')

    def test_missing_package(self):
        self.edit('dockerfiles/Dockerfile.slow-scan.client.student', ' curl sshpass', ' curl')
        self.assertFails('dockerfile', 'installs exactly')

    def test_extra_package_on_attacker(self):
        self.edit('dockerfiles/Dockerfile.slow-scan.attacker.student', 'USER $user_name\n',
                  'RUN apt-get update && apt-get install -y --no-install-recommends hping3\nUSER $user_name\n')
        self.assertFails('dockerfile', 'installs exactly')

    def test_install_after_user(self):
        p = 'dockerfiles/Dockerfile.slow-scan.victim.student'
        line = 'RUN apt-get update && apt-get install -y --no-install-recommends python3-scapy\n'
        self.edit(p, line, '')
        self.edit(p, 'ENV HOME /home/$user_name\n', 'ENV HOME /home/$user_name\n' + line)
        self.assertFails('dockerfile', 'before USER')

    def test_install_without_update(self):
        self.edit('dockerfiles/Dockerfile.slow-scan.victim.student',
                  'RUN apt-get update && apt-get install', 'RUN apt-get install')
        self.assertFails('dockerfile', 'apt-get update')

    def test_install_without_y(self):
        self.edit('dockerfiles/Dockerfile.slow-scan.client.student', 'install -y --no-install-recommends', 'install --no-install-recommends')
        self.assertFails('dockerfile', '-y --no-install-recommends')

    def test_multiline_install_is_parsed(self):
        # continuation lines must still be understood (and the set compared exactly)
        self.edit('dockerfiles/Dockerfile.slow-scan.client.student',
                  '--no-install-recommends curl sshpass', '--no-install-recommends \\\n    curl \\\n    sshpass')
        rep = self.run_checks()
        self.assertEqual(rep.failures, [])

    def test_template_line_removed(self):
        self.edit('dockerfiles/Dockerfile.slow-scan.attacker.student', 'ADD $labdir/$lab.tar.gz $HOME\n', '')
        self.assertFails('dockerfile', 'template ADD')

    def test_user_root_removed(self):
        self.edit('dockerfiles/Dockerfile.slow-scan.attacker.student', 'USER root\n', '')
        self.assertFails('dockerfile', 'USER $user_name ... USER root')

    # services (Step 3)
    def test_missing_unit_file(self):
        os.remove(self.path('victim/_system/etc/systemd/system/testsvc2.service'))
        self.assertFails('services', 'testsvc2.service exists')

    def test_unit_without_waitparam_ordering(self):
        self.edit('victim/_system/etc/systemd/system/httpserver.service',
                  'After=waitparam.service network.target', 'After=network.target')
        self.assertFails('services', 'httpserver.service: After=waitparam.service')

    def test_unit_not_wanted_by_multi_user(self):
        self.edit('victim/_system/etc/systemd/system/testsvc1.service',
                  'WantedBy=multi-user.target', 'WantedBy=graphical.target')
        self.assertFails('services', 'WantedBy=multi-user.target')

    def test_wrong_test_port(self):
        self.edit('victim/_system/etc/systemd/system/testsvc1.service', 'testsvc.py 8081', 'testsvc.py 8082')
        self.assertFails('services', 'listens on port 8081')

    def test_port_clash_between_services(self):
        self.edit('victim/_system/etc/systemd/system/testsvc2.service', 'testsvc.py 9090', 'testsvc.py 8081')
        self.assertFails('services', 'unique')

    def test_http_server_dropped_root(self):
        self.edit('victim/_system/etc/systemd/system/httpserver.service',
                  'Restart=on-failure', 'User=nobody\nRestart=on-failure')
        self.assertFails('services', 'runs as root')

    def test_execstart_relies_on_exec_bit(self):
        self.edit('victim/_system/etc/systemd/system/testsvc1.service',
                  'ExecStart=/usr/bin/python3 /usr/bin/testsvc.py', 'ExecStart=/usr/bin/testsvc.py')
        self.assertFails('services', 'independent of the exec bit')

    def test_python2_leftover(self):
        self.edit('victim/_system/usr/bin/MyHTTPServer.py', 'import argparse\n',
                  'import argparse\nimport SimpleHTTPServer\n')
        self.assertFails('services', 'Python 2 idioms')

    def test_python_syntax_error(self):
        self.edit('victim/_system/usr/bin/testsvc.py', 'def main(argv=None):', 'def main(argv=None)')
        self.assertFails('services', 'compiles as Python 3')

    def test_unit_not_listed_in_fixlocal(self):
        self.edit('victim/_bin/fixlocal.sh', 'UNITS="httpserver testsvc1 testsvc2 ', 'UNITS="httpserver testsvc1 ')
        self.assertFails('services', 'missing [\'testsvc2\']')

    def test_new_unit_must_be_listed_in_fixlocal(self):
        shutil.copy(self.path('victim/_system/etc/systemd/system/testsvc1.service'),
                    self.path('victim/_system/etc/systemd/system/extra.service'))
        self.assertFails('services', "missing ['extra']")

    def test_start_before_did_param(self):
        p = 'victim/_bin/fixlocal.sh'
        self.edit(p, 'sudo mkdir -p "$PERMLOCKDIR"\n', '')
        self.edit(p, 'sudo systemctl start $present\n', 'sudo systemctl start $present\nsudo mkdir -p "$PERMLOCKDIR"\n')
        self.assertFails('services', 'did_param before starting')

    def test_units_not_enabled(self):
        self.edit('victim/_bin/fixlocal.sh', 'sudo systemctl enable $present\n', '')
        self.assertFails('services', 'enables the units')

    def test_rc_local_without_run_sshd(self):
        self.edit('victim/_system/etc/rc.local', 'mkdir -p /run/sshd\n', '')
        self.assertFails('services', 'rc.local')

    def test_missing_tmpfiles_entry(self):
        os.remove(self.path('victim/_system/etc/tmpfiles.d/sshd.conf'))
        self.assertFails('services', 'tmpfiles.d/sshd.conf exists')

    def test_python_newer_than_image(self):
        # match needs Python 3.10; the image has 3.8
        self.edit('victim/_system/usr/bin/testsvc.py', 'def main(argv=None):',
                  'def _f(x):\n    match x:\n        case _:\n            pass\n\n\ndef main(argv=None):')
        self.assertFails('services', 'compiles as Python 3.8')

    # detection (Steps 4-5)
    def test_missing_detector_unit(self):
        os.remove(self.path('victim/_system/etc/systemd/system/slowscan-proposed.service'))
        self.assertFails('detection', 'slowscan-proposed.service exists')

    def test_monitor_wrong_victim(self):
        self.edit('victim/_system/etc/systemd/system/slowscan-monitor.service',
                  '--victim 172.20.0.30', '--victim 172.20.0.20')
        self.assertFails('detection', '--victim 172.20.0.30')

    def test_monitor_not_root(self):
        self.edit('victim/_system/etc/systemd/system/slowscan-monitor.service',
                  'Restart=on-failure', 'User=nobody\nRestart=on-failure')
        self.assertFails('detection', 'runs as root (packet capture)')

    def test_detector_follows_wrong_file(self):
        self.edit('victim/_system/etc/systemd/system/slowscan-baseline.service',
                  '--follow /var/log/slowscan/conn.log', '--follow /var/log/slowscan/con.log')
        self.assertFails('detection', '--follow /var/log/slowscan/conn.log')

    def test_detector_writes_into_conn_log(self):
        self.edit('victim/_system/etc/systemd/system/slowscan-proposed.service',
                  '--out /var/log/slowscan/proposed.log', '--out /var/log/slowscan/conn.log')
        self.assertFails('detection', 'does not write into conn.log')

    def test_baseline_with_fail_ratio(self):
        self.edit('victim/_system/etc/systemd/system/slowscan-baseline.service',
                  '--window 60', '--window 60 --fail-ratio 0.70')
        self.assertFails('detection', 'baseline has no --fail-ratio')

    def test_detector_rejects_unit_settings(self):
        self.edit('victim/_system/etc/systemd/system/slowscan-proposed.service',
                  '--heartbeat 30', '--heartbeat 30 --cooldown -5')
        self.assertFails('detection', 'detector accepts its settings')

    def test_detector_not_after_monitor(self):
        self.edit('victim/_system/etc/systemd/system/slowscan-proposed.service',
                  'After=waitparam.service slowscan-monitor.service', 'After=waitparam.service')
        self.assertFails('detection', 'After=slowscan-monitor.service')

    def test_log_format_drift(self):
        # monitor changes its output: the detector would silently see nothing
        self.edit('victim/_system/usr/bin/monitor.py', "'%s src=%s sport=%d dst=%s dport=%d result=%s'",
                  "'%s src=%s sport=%d dst=%s dport=%d res=%s'")
        self.assertFails('detection', 'parses every line format')

    def test_log_with_brackets(self):
        self.edit('victim/_system/usr/bin/monitor.py', "TS_FORMAT = '%Y-%m-%dT%H:%M:%S'",
                  "TS_FORMAT = '[%Y-%m-%dT%H:%M:%S]'")
        self.assertFails('detection', 'no brackets')

    # hygiene
    def test_crlf_detected(self):
        p = self.path('victim/_bin/fixlocal.sh')
        with open(p, 'rb') as fh:
            data = fh.read()
        with open(p, 'wb') as fh:
            fh.write(data.replace(b'\n', b'\r\n'))
        self.assertFails('hygiene', 'victim/_bin/fixlocal.sh')

    def test_bom_detected(self):
        p = self.path('config/start.config')
        with open(p, 'rb') as fh:
            data = fh.read()
        with open(p, 'wb') as fh:
            fh.write(b'\xef\xbb\xbf' + data)
        self.assertFails('hygiene', 'BOM')

    def test_shell_script_without_shebang(self):
        self.edit('client/_bin/fixlocal.sh', '#!/bin/bash\n', '')
        self.assertFails('hygiene', '#!')

    def test_bytecode_in_container_dir(self):
        os.makedirs(self.path('victim/_system/usr/bin/__pycache__'))
        self.assertFails('hygiene', '__pycache__')

    def test_gitattributes_weakened(self):
        with open(self.path('.gitattributes'), 'w', newline='\n') as fh:
            fh.write('* text=auto\n')
        self.assertFails('hygiene', 'eol=lf')


if __name__ == '__main__':
    unittest.main(verbosity=2)
