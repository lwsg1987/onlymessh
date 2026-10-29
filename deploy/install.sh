#!/bin/sh
# Install onlymessh as a systemd service on a Debian/Ubuntu host.
set -eu

PREFIX=${PREFIX:-/usr/local}
CONFDIR=/etc/onlymessh

command -v ufw >/dev/null || { echo "ufw is not installed" >&2; exit 1; }

python3 -m venv /opt/onlymessh
/opt/onlymessh/bin/pip install --quiet --upgrade pip
/opt/onlymessh/bin/pip install --quiet .

ln -sf /opt/onlymessh/bin/onlymessh "$PREFIX/bin/onlymessh"

mkdir -p "$CONFDIR"
[ -f "$CONFDIR/config.toml" ] || cp deploy/onlymessh.toml "$CONFDIR/config.toml"

install -m 0644 deploy/onlymessh.service /etc/systemd/system/onlymessh.service
systemctl daemon-reload
systemctl enable --now onlymessh.service
systemctl --no-pager --lines=20 status onlymessh.service || true

echo
echo "Edit $CONFDIR/config.toml, then: systemctl restart onlymessh"
