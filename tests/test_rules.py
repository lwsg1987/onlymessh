import ipaddress

from onlymessh.rules import Rule, parse_status, plan

STATUS = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                  ALLOW       Anywhere                   # app
22/tcp (v6)             ALLOW       Anywhere (v6)              # app
Anywhere                   ALLOW       203.0.113.4
Anywhere (v6)              ALLOW       2001:db8::1
Anywhere                   ALLOW       10.0.0.0/8
22/tcp                     ALLOW       198.51.100.8
Anywhere                   DENY        192.0.2.9
Anywhere                   LIMIT       192.0.2.8
"""


def test_parse_status_shape():
    active, rules = parse_status(STATUS)
    assert active is True
    assert len(rules) == 8
    assert rules[2] == Rule("Anywhere", "ALLOW", "203.0.113.4")
    assert rules[0].comment == "app"


def test_ip_only_classification():
    _, rules = parse_status(STATUS)
    ip_only = [(r.to, r.source) for r in rules if r.is_ip_only]
    assert ip_only == [
        ("Anywhere", "203.0.113.4"),
        ("Anywhere (v6)", "2001:db8::1"),
        ("Anywhere", "10.0.0.0/8"),
    ]


def test_inactive_and_empty_tables():
    active, rules = parse_status("Status: inactive\n")
    assert active is False and rules == []


def test_plan_adds_missing_and_drops_stale():
    _, rules = parse_status(STATUS)
    change = plan(["203.0.113.4", "192.0.2.8"], rules)
    assert change.to_add == ["192.0.2.8"]
    assert [r.source for r in change.to_remove] == ["2001:db8::1", "10.0.0.0/8"]


def test_plan_never_touches_port_or_deny_rules():
    _, rules = parse_status(STATUS)
    change = plan(["203.0.113.4"], rules)
    sources = {r.source for r in change.to_remove}
    assert "198.51.100.8" not in sources   # port-scoped rule
    assert "192.0.2.9" not in sources   # DENY
    assert "192.0.2.8" not in sources   # LIMIT
    assert "Anywhere" not in sources  # allow-all port rules


def test_plan_keeps_configured_addresses():
    _, rules = parse_status(STATUS)
    change = plan(["203.0.113.4"], rules, keep=["10.0.0.0/8"])
    assert [r.source for r in change.to_remove] == ["2001:db8::1"]


def test_plan_is_idempotent():
    _, rules = parse_status(STATUS)
    plan(["203.0.113.4"], rules, keep=["10.0.0.0/8"])
    change = plan(["203.0.113.4"], rules, keep=["10.0.0.0/8", "2001:db8::1"])
    assert change.empty


def test_plan_filters_by_ip_version():
    _, rules = parse_status(STATUS)
    change = plan(["203.0.113.4"], rules, ip_version=4)
    assert all(ipaddress.ip_network(r.source).version == 4 for r in change.to_remove)
    assert [r.source for r in change.to_remove] == ["10.0.0.0/8"]
