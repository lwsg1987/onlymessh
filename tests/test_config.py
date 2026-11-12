"""Config-loading edge cases: a shared config file must not break the daemon."""

import pytest

from onlymessh.config import Config, from_args, load


def test_unknown_section_is_dropped(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(
        'domain = "example.com"\n'
        "\n"
        "[logging]\n"
        'level = "info"\n',
        encoding="utf-8",
    )
    values = load(p)
    assert values["domain"] == "example.com"
    assert "logging" not in values


def test_unknown_scalar_key_is_dropped(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(
        'domain = "example.com"\n'
        "future_option = 42\n",
        encoding="utf-8",
    )
    values = load(p)
    assert values == {"domain": "example.com"}


def test_config_with_extra_section_still_loads(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(
        'domain = "example.com"\n'
        "\n"
        "[logging]\n"
        'level = "debug"\n',
        encoding="utf-8",
    )
    cfg = from_args(["--config", str(p)])
    assert cfg.domain == "example.com"


def test_onlymessh_section_is_flattened(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(
        "[onlymessh]\n"
        'domain = "example.com"\n'
        "interval = 900\n",
        encoding="utf-8",
    )
    cfg = from_args(["--config", str(p)])
    assert cfg.domain == "example.com"
    assert cfg.interval == 900


def test_missing_file_is_empty():
    assert load("/nonexistent/path/config.toml") == {}


def test_ufw_timeout_is_configurable():
    cfg = Config(domain="example.com", ufw_timeout=12.5)
    assert cfg.ufw_timeout == 12.5


def test_bad_interval_still_rejected():
    with pytest.raises(ValueError):
        Config(domain="example.com", interval=5)