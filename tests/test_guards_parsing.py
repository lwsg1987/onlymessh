"""``ss`` output parsing — the part that silently failed on a real host.

These tests use the exact lines Ubuntu 24.04 produces:

* listen: ``users:(("sshd",pid=847,fd=3),("systemd",pid=1,fd=89))``
* established: ``[::ffff:66.63.177.75]:22 [::ffff:2.31.193.187]:36692``

The old regex could not match the listen line (it required the closing paren
right after the sshd pid), so ``_listen_ports()`` returned an empty set and the
whole guard silently degraded to "no protection" whenever ``SSH_CONNECTION``
was absent — i.e. under systemd, which is how it actually runs.
"""

from onlymessh import guards


def test_split_endpoint_plain():
    assert guards._split_endpoint("1.2.3.4:22") == ("1.2.3.4", 22)


def test_split_endpoint_ipv6_bracketed():
    assert guards._split_endpoint("[2001:db8::1]:22") == ("2001:db8::1", 22)


def test_split_endpoint_mapped_ipv6():
    assert guards._split_endpoint("[::ffff:2.31.193.187]:45888") == (
        "::ffff:2.31.193.187",
        45888,
    )


def test_split_endpoint_wildcard():
    assert guards._split_endpoint("*:22") == ("*", 22)


def test_normalise_strips_mapped_prefix():
    assert guards._normalise("::ffff:2.31.193.187") == "2.31.193.187"


def test_normalise_keeps_plain_v4():
    assert guards._normalise("2.31.193.187") == "2.31.193.187"


def test_normalise_keeps_v6():
    assert guards._normalise("2001:db8::1") == "2001:db8::1"


def test_listen_ports_real_line():
    lines = (
        'tcp   LISTEN 0      4096   *:22   *:* '
        'users:(("sshd",pid=847,fd=3),("systemd",pid=1,fd=89))'
    )
    assert guards._SSHD_MARKER in lines
    # `ss -Hlnp`: netid state recv-q send-q local peer users:(...)
    cols = lines.split()
    assert cols[4] == "*:22"
    assert guards._split_endpoint(cols[4]) == ("*", 22)


def test_listen_ports_parses(monkeypatch):
    sample = (
        'tcp   LISTEN 0      4096   *:22   *:* '
        'users:(("sshd",pid=847,fd=3),("systemd",pid=1,fd=89))\n'
        'tcp   LISTEN 0      4096   127.0.0.1:53   0.0.0.0:* '
        'users:(("systemd-resolve",pid=1,fd=9))\n'
    )
    monkeypatch.setattr(guards, "_ss", lambda args: sample)
    assert guards._listen_ports() == {22}


def test_established_peers_parses_mapped_ipv4(monkeypatch):
    sample = "0      72     [::ffff:66.63.177.75]:22 [::ffff:2.31.193.187]:45888\n"
    monkeypatch.setattr(guards, "_ss", lambda args: sample)
    assert guards._established_peers({22}) == {"2.31.193.187"}


def test_established_peers_ignores_other_ports(monkeypatch):
    sample = "0      0      1.2.3.4:443      5.6.7.8:5000\n"
    monkeypatch.setattr(guards, "_ss", lambda args: sample)
    assert guards._established_peers({22}) == set()


def test_current_ssh_sources_combines_env_and_ss(monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "9.9.9.9 4444 10.0.0.1 22")
    monkeypatch.setattr(guards, "_ss", lambda args: (
        'tcp LISTEN 0 4096 *:22 *:* users:(("sshd",pid=1,fd=3))\n'
        "0 0 [::ffff:10.0.0.1]:22 [::ffff:8.8.8.8]:1234\n"
    ))
    sources = guards.current_ssh_sources()
    assert "9.9.9.9" in sources
    assert "8.8.8.8" in sources


def test_current_ssh_sources_empty_is_safe(monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr(guards, "_ss", lambda args: "")
    assert guards.current_ssh_sources() == []