"""UFW wrapper hardening: timeouts and error surfacing."""

import subprocess

import pytest

from onlymessh.ufw import Ufw, UfwError

STATUS = """Status: active

To                         Action      From
--                         ------      ----
Anywhere                   ALLOW       192.0.2.1
"""


def test_timeout_raises_ufw_error():
    """A hung ufw must not freeze the sync loop forever."""

    def runner(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="ufw", timeout=1.0)

    ufw = Ufw("/usr/sbin/ufw", runner=runner, timeout=1.0)
    with pytest.raises(UfwError) as exc:
        ufw.status()
    assert "timed out" in str(exc.value)


def test_timeout_is_passed_to_runner():
    seen = {}

    def runner(cmd, **kw):
        seen.update(kw)
        return subprocess.CompletedProcess(cmd, 0, STATUS, "")

    ufw = Ufw("/usr/sbin/ufw", runner=runner, timeout=7.5)
    ufw.status()
    assert seen["timeout"] == 7.5


def test_nonzero_exit_surfaces_stderr():
    def runner(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, "", "ERROR: broken\n")

    ufw = Ufw("/usr/sbin/ufw", runner=runner)
    with pytest.raises(UfwError) as exc:
        ufw.allow_from("192.0.2.9")
    assert "broken" in str(exc.value)


def test_status_parses():
    ufw = Ufw(
        "/usr/sbin/ufw",
        runner=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, STATUS, ""),
    )
    active, rules = ufw.status()
    assert active is True
    assert [r.source for r in rules] == ["192.0.2.1"]