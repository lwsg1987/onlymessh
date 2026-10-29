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
            ["Anywhere", "ALLOW", "192.0.2.9"],
            ["Anywhere", "ALLOW", "192.0.2.1"],
            ["22/tcp", "ALLOW", "198.51.100.8"],
        ],
    }), encoding="utf-8")
    os.environ["FAKE_UFW_STATE"] = str(state)
    ufw = Ufw(str(script))
    yield ufw, state
    os.environ.pop("FAKE_UFW_STATE", None)


def read_state(state: Path):
    return json.loads(state.read_text(encoding="utf-8"))


def test_sync_replaces_ips_and_keeps_port_rules(fake_ufw, monkeypatch):
    ufw, state = fake_ufw
    monkeypatch.setattr(sync_mod, "resolve", lambda *a, **k: ["203.0.113.4"])
    res = sync_mod.sync_once(Config(domain="example.com"), ufw)

    assert res.added == ["203.0.113.4"]
    assert sorted(res.removed) == ["192.0.2.1", "192.0.2.9"]
    rules = read_state(state)["rules"]
    assert ["22/tcp", "ALLOW", "Anywhere"] in rules
    assert ["22/tcp", "ALLOW", "198.51.100.8"] in rules
    assert ["Anywhere", "ALLOW", "203.0.113.4"] in rules
    assert not any(r[2] in ("192.0.2.9", "192.0.2.1") for r in rules)


def test_sync_is_idempotent(fake_ufw, monkeypatch):
    ufw, state = fake_ufw
    monkeypatch.setattr(sync_mod, "resolve", lambda *a, **k: ["203.0.113.4"])
    sync_mod.sync_once(Config(domain="example.com"), ufw)
    snapshot = read_state(state)
    res = sync_mod.sync_once(Config(domain="example.com"), ufw)
    assert (res.added, res.removed) == ([], [])
    assert read_state(state) == snapshot


def test_dns_failure_leaves_firewall_untouched(fake_ufw, monkeypatch):
    ufw, state = fake_ufw
    before = read_state(state)
    monkeypatch.setattr(sync_mod, "resolve", lambda *a, **k: [])
    res = sync_mod.sync_once(Config(domain="example.com"), ufw)
    assert res.skipped == "DNS returned no addresses"
    assert read_state(state) == before


def test_dry_run_changes_nothing(fake_ufw, monkeypatch):
    ufw, state = fake_ufw
    before = read_state(state)
    monkeypatch.setattr(sync_mod, "resolve", lambda *a, **k: ["203.0.113.4"])
    res = sync_mod.sync_once(Config(domain="example.com", dry_run=True), ufw)
    assert res.added == ["203.0.113.4"]
    assert read_state(state) == before


def test_keep_list_survives(fake_ufw, monkeypatch):
    ufw, state = fake_ufw
    monkeypatch.setattr(sync_mod, "resolve", lambda *a, **k: ["203.0.113.4"])
    sync_mod.sync_once(Config(domain="example.com", keep=["192.0.2.9"]), ufw)
    rules = read_state(state)["rules"]
    assert ["Anywhere", "ALLOW", "192.0.2.9"] in rules
    assert ["Anywhere", "ALLOW", "192.0.2.1"] not in rules


def test_inactive_ufw_is_a_noop(fake_ufw, monkeypatch):
    ufw, state = fake_ufw
    data = read_state(state)
    data["active"] = False
    state.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(sync_mod, "resolve", lambda *a, **k: ["203.0.113.4"])
    res = sync_mod.sync_once(Config(domain="example.com"), ufw)
    assert res.skipped == "ufw is inactive"
