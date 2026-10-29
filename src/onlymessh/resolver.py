"""Domain resolution."""

from __future__ import annotations

import ipaddress
import socket

IPVersion = int  # 4, 6, or 0 for both


def resolve(domain: str, ip_version: IPVersion = 0, timeout: float | None = None) -> list[str]:
    """Resolve ``domain`` to a sorted, de-duplicated list of addresses.

    The system resolver is used on purpose so that ``/etc/hosts`` and local
    caching resolvers behave exactly as the rest of the machine expects.
    """
    families = []
    if ip_version in (0, 4):
        families.append(socket.AF_INET)
    if ip_version in (0, 6):
        families.append(socket.AF_INET6)

    old_timeout = socket.getdefaulttimeout()
    if timeout is not None:
        socket.setdefaulttimeout(timeout)
    try:
        found: set[str | ipaddress._BaseAddress] = set()
        for family in families:
            try:
                infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            except socket.gaierror:
                continue
            for info in infos:
                addr = info[4][0].split("%", 1)[0]
                try:
                    found.add(ipaddress.ip_address(addr))
                except ValueError:
                    continue
    finally:
        if timeout is not None:
            socket.setdefaulttimeout(old_timeout)

    return sorted(str(a) for a in found)
