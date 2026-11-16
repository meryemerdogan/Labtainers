#!/bin/bash
#
#  slow-scan victim: run once by parameterize.sh, as user ubuntu, after
#  parameterization (first start only). Arguments: $1 = password, $2 = user.
#  The ubuntu user is in the sudo group, which is NOPASSWD in Labtainers'
#  base2 sudoers, so plain sudo works. stderr goes to /tmp/fixlocal.output.
#
#  Enables every slow-scan service so it starts now and on every later
#  `labtainer slow-scan` restart, without manual steps.
#
UNITS="httpserver testsvc1 testsvc2 slowscan-monitor slowscan-baseline slowscan-proposed"
UNIT_DIR=/etc/systemd/system
PERMLOCKDIR=/var/labtainer/did_param

# Units of later steps (monitor, detectors) are skipped until their files exist,
# so this script does not need editing when they are added.
present=""
for s in $UNITS; do
    if [ -f "$UNIT_DIR/$s.service" ]; then
        present="$present $s"
    else
        echo "fixlocal: $s.service not installed yet, skipping" >&2
    fi
done

# Directories the services need. /run/sshd is also created on every boot by
# /etc/tmpfiles.d/sshd.conf and /etc/rc.local; this covers the first boot.
sudo mkdir -p /var/log/slowscan /run/sshd

sudo systemctl daemon-reload
sudo systemctl enable $present
sudo systemctl enable xinetd

# Our units are ordered After=waitparam.service, which blocks until this
# directory exists. Create it first, or `systemctl start` would wait forever.
sudo mkdir -p "$PERMLOCKDIR"

sudo systemctl start $present
# sshd on port 22 is started per connection by xinetd (network.ssh2 base).
sudo systemctl restart xinetd

for s in $present xinetd; do
    systemctl is-active --quiet "$s" || echo "fixlocal: $s failed to start" >&2
done
exit 0
