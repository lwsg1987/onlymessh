"""The DNS timeout must actually bound the lookup.

``socket.setdefaulttimeout()`` does not apply to ``getaddrinfo()`` — the
lookup happens in C and ignores it.  onlymessh therefore runs the resolver
on a worker thread and gives up after the deadline, returning [] so the sync
pass leaves the firewall untouched.
"""

import socket
import time

from onlymessh import resolver


def test_timeout_returns_empty_quickly(monkeypatch):
    def slow(*a, **kw):
        time.sleep(10)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0))]

    monkeypatch.setattr(resolver.socket, "getaddrinfo", slow)

    start = time.time()
    result = resolver.resolve("slow.example", 4, 0.3)
    elapsed = time.time() - start

    assert result == []
    assert elapsed < 1.0


def test_no_timeout_waits_for_result():
    assert resolver.resolve("localhost", 4) == ["127.0.0.1"]


def test_unknown_domain_returns_empty():
    assert resolver.resolve("no-such-host.invalid", 4, 2.0) == []


def test_ipv6_addresses_are_filtered_by_version():
    result = resolver.resolve("ip6-localhost", 4, 2.0)
    assert all(":" not in a for a in result)