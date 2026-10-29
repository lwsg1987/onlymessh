from onlymessh.resolver import resolve


def test_localhost_resolves():
    assert resolve("localhost", 4) == ["127.0.0.1"]


def test_unknown_domain_returns_empty():
    assert resolve("no-such-host.invalid", timeout=2) == []
