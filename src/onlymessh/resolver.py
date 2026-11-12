"""Domain resolution."""

from __future__ import annotations

import ipaddress
import socket

IPVersion = int  # 4, 6, or 0 for both


def resolve(domain: str, ip_version: IPVersion = 0, timeout: float | None = None) -> list[str]:
    """Resolve ``domain`` to a sorted, de-duplicated list of addresses.

    The system resolver is used on purpose so that ``/etc/hosts`` and local
    caching resolvers behave exactly as the rest of the machine expects.

    ``timeout`` bounds the lookup.  ``socket.setdefaulttimeout()`` does *not*
    affect ``getaddrinfo()`` — it only applies to socket operations — so the
    resolver call is dispatched to a worker thread and abandoned if it
    overruns.  The thread is a daemon: a stuck NSS lookup cannot hold the
    process open.
    """
    if timeout is None or timeout <= 0:
        return _resolve_now(domain, ip_version)

    result: list[list[str]] = []

    def _worker() -> None:
        result.append(_resolve_now(domain, ip_version))

    import threading

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        # getaddrinfo is still blocked in C; we cannot cancel it, but the
        # caller must not wait.  Returning [] makes the sync pass leave the
        # firewall untouched, which is the safe direction.
        return []
    return result[0] if result else []


def _resolve_now(domain: str, ip_version: IPVersion = 0) -> list[str]:
    families = []
    if ip_version in (0, 4):
        families.append(socket.AF_INET)
    if ip_version in (0, 6):
        families.append(socket.AF_INET6)

    found: set[str] = set()
    for family in families:
        try:
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
        except socket.gaierror:
            continue
        for info in infos:
            sockaddr = info[4]
            if not isinstance(sockaddr, tuple) or not sockaddr:
                continue
            addr = str(sockaddr[0]).split("%", 1)[0]
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                continue
            found.add(addr)

    return sorted(found)
