"""Lockout guards: never let a sync pass cut the operator's own SSH access.

onlymessh deletes every pure-IP ALLOW rule that is not in the resolved set.
If the operator's SSH session is permitted by such a rule (rather than by a
port rule like ``22/tcp ALLOW Anywhere``), a normal sync would remove it and
lock them out of the machine.

These helpers find the addresses that currently hold an SSH session, so the
sync pass can treat them as implicit ``keep`` entries.

Two output quirks of the real ``ss`` on Ubuntu 24.04 drove the parsing here:

* the listen line carries several processes, e.g.
  ``users:(("sshd",pid=847,fd=3),("systemd",pid=1,fd=89))`` — matching on
  ``("sshd"`` alone is reliable, matching up to the closing paren is not;
* established peers of a v4 connection are printed as **IPv4-mapped IPv6**
  (``[::ffff:2.31.193.187]:45888``).  UFW wants the plain v4 form, so the
  mapped prefix has to be stripped or the address would never match a rule.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import subprocess

log = logging.getLogger("onlymessh")

_ENDPOINT = re.compile(r"^(?P<host>.+?):(?P<port>\d+)$")
_SSHD_MARKER = '("sshd"'


def _ss(args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ["ss", *args], capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout or ""


def _split_endpoint(text: str) -> tuple[str, int] | None:
    """Split ``[::ffff:1.2.3.4]:22`` / ``*:22`` / ``1.2.3.4:22`` into (host, port)."""
    m = _ENDPOINT.match(text.strip())
    if not m:
        return None
    try:
        port = int(m.group("port"))
    except ValueError:
        return None
    host = m.group("host").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.split("%", 1)[0]
    return host, port


def _normalise(host: str) -> str | None:
    """Turn whatever ``ss`` printed into a plain IPv4/IPv6 literal."""
    if not host:
        return None
    # IPv4-mapped IPv6 (``::ffff:1.2.3.4``) → plain IPv4, which is what the
    # ufw rule holds.
    if host.lower().startswith("::ffff:") and "." in host:
        host = host.rsplit(":", 1)[-1]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _listen_ports() -> set[int]:
    """TCP ports sshd is listening on."""
    ports: set[int] = set()
    for line in _ss(["-Hlnp"]).splitlines():
        if _SSHD_MARKER not in line:
            continue
        # `ss -Hlnp` columns: netid state recv-q send-q local peer users:(...)
        # → the local address is the 4th field (index 4), not index 3.
        parts = line.split()
        if len(parts) < 5:
            continue
        ep = _split_endpoint(parts[4])
        if ep:
            ports.add(ep[1])
    return ports


def _established_peers(ports: set[int]) -> set[str]:
    """Peer addresses of established connections whose *local* port is in ``ports``."""
    if not ports:
        return set()
    peers: set[str] = set()
    for line in _ss(["-Htn", "state", "established"]).splitlines():
        cols = line.split()
        if len(cols) < 4:
            continue
        local = _split_endpoint(cols[2])
        if not local or local[1] not in ports:
            continue
        peer = _split_endpoint(cols[3])
        if not peer:
            continue
        ip = _normalise(peer[0])
        if ip:
            peers.add(ip)
    return peers


def current_ssh_sources() -> list[str]:
    """Addresses that are talking SSH to this machine right now.

    Two independent sources are combined:

    1. ``$SSH_CONNECTION`` (``<client> <clientport> <server> <serverport>``) —
       set when onlymessh runs from an interactive SSH session.
    2. ``ss`` — works under systemd, where the variable is absent.

    Returns an empty list when neither can be determined; that is a safe
    answer (the guard simply adds nothing) and is logged.
    """
    found: list[str] = []

    env = os.environ.get("SSH_CONNECTION", "")
    if env:
        parts = env.split()
        if parts:
            ip = _normalise(parts[0])
            if ip:
                found.append(ip)

    for ip in sorted(_established_peers(_listen_ports())):
        if ip not in found:
            found.append(ip)

    if not found:
        log.debug("could not determine the current SSH source address")
    return found