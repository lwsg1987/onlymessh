"""Lockout-guard tests: the SSH session must survive every sync pass."""

import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from onlymessh import sync as sync_mod
from onlymessh.config import Config
from onlymessh.ufw import Ufw

FAKE = Path(__file__).parent / "fakeufw" / "ufw"


@pytest.fixture
def fake_ufw(tmp_path):
    script = tmp_path / "ufw"
    shutil.copy(FAKE, script)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({
        "active": True,
        "rules": [
            ["22/tcp", "ALLOW", "Anywhere"],
            ["Anywhere", "ALLOW", "198.51.100.1"],
        ],
    }), encoding="utf-8")
    os.environ["FAKE_UFW_STATE"] = str(state)
    ufw = Ufw(str(script))
    yield ufw, state
    os.environ.pop("FAKE_UFW_STATE", None)


def read_state(state: Path):
    return json.loads(state.read_text(encoding="utf-8"))


def test_ssh_source_is_never_removed(fake_ufw, monkeypatch):
    """The operator's own IP stays allowed even when DNS no longer lists it."""
    ufw, state = fake_ufw
    monkeypatch.setattr(sync_mod, "resolve", lambda *a, **k: ["203.0.113.4"])
    monkeypatch.setattr(sync_mod, "current_ssh_sources", lambda: ["198.51.100.1"])

    res = sync_mod.sync_once(Config(domain="example.com"), ufw)

    assert res.kept_for_ssh == ["198.51.100.1"]
    assert "198.51.100.1" not in res.removed
    sources = [r[2] for r in read_state(state)["rules"]]
    assert "198.51.100.1" in sources
    assert "203.0.113.4" in sources


def test_ssh_source_inside_dns_answer_is_not_flagged(fake_ufw, monkeypatch):
    """A session whose IP is in the resolved set needs no special keep."""
    ufw, _ = fake_ufw
    monkeypatch.setattr(sync_mod, "resolve", lambda *a, **k: ["198.51.100.1"])
    monkeypatch.setattr(sync_mod, "current_ssh_sources", lambda: ["198.51.100.1"])

    res = sync_mod.sync_once(Config(domain="example.com"), ufw)

    assert res.kept_for_ssh == []
    assert res.removed == []


def test_ssh_source_already_inside_keep_cidr_is_not_duplicated(fake_ufw, monkeypatch):
    """An SSH source covered by a keep CIDR must not be re-added as a host."""
    ufw, _ = fake_ufw
    monkeypatch.setattr(sync_mod, "resolve", lambda *a, **k: ["203.0.113.4"])
    monkeypatch.setattr(sync_mod, "current_ssh_sources", lambda: ["198.51.100.1"])

    res = sync_mod.sync_once(
        Config(domain="example.com", keep=["198.51.100.0/24"]), ufw
    )

    assert res.kept_for_ssh == []


def test_no_ssh_sources_behaves_like_before(fake_ufw, monkeypatch):
    """When the source cannot be determined, the pass is unchanged."""
    ufw, _ = fake_ufw
    monkeypatch.setattr(sync_mod, "resolve", lambda *a, **k: ["203.0.113.4"])
    monkeypatch.setattr(sync_mod, "current_ssh_sources", list)

    res = sync_mod.sync_once(Config(domain="example.com"), ufw)

    assert res.kept_for_ssh == []
    assert res.removed == ["198.51.100.1"]