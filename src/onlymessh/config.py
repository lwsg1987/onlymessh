"""Configuration: TOML file plus command line overrides."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path

import tomllib

from . import __version__

DEFAULT_CONFIG_PATH = "/etc/onlymessh/config.toml"


@dataclass
class Config:
    domain: str
    interval: int = 600
    keep: list[str] = field(default_factory=list)
    ip_version: int = 0
    dns_timeout: float = 10.0
    ufw_cmd: str = "ufw"
    dry_run: bool = False
    once: bool = False
    log_file: str | None = None

    def __post_init__(self) -> None:
        self.domain = self.domain.strip().rstrip(".")
        if not self.domain:
            raise ValueError("domain must not be empty")
        if self.interval < 10:
            raise ValueError("interval must be at least 10 seconds")
        if self.ip_version not in (0, 4, 6):
            raise ValueError("ip_version must be 0, 4 or 6")


def load(path: str | Path = DEFAULT_CONFIG_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("rb") as fh:
        data = tomllib.load(fh)
    flat = dict(data)
    flat.update(data.get("onlymessh", {}))
    flat.pop("onlymessh", None)
    return flat


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="onlymessh",
        description="Keep the UFW IP allow-list in sync with a domain's DNS records.",
    )
    p.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="TOML config file")
    p.add_argument("--domain", help="domain to resolve (required unless set in config)")
    p.add_argument("--interval", type=int, help="seconds between checks (default 600)")
    p.add_argument("--keep", action="append", metavar="IP",
                   help="extra address/CIDR that is never removed (repeatable)")
    p.add_argument("--ip-version", type=int, choices=(0, 4, 6), help="0 = both")
    p.add_argument("--dns-timeout", type=float, help="resolver timeout in seconds")
    p.add_argument("--ufw-cmd", default=None, help="path to the ufw binary")
    p.add_argument("--log-file", default=None, help="append logs here")
    p.add_argument("--dry-run", action="store_true", help="print the plan, change nothing")
    p.add_argument("--once", action="store_true", help="run one check and exit")
    p.add_argument("--version", action="version", version=f"onlymessh {__version__}")
    return p


def from_args(argv: list[str] | None = None) -> Config:
    args = build_parser().parse_args(argv)
    raw = {
        "domain": args.domain,
        "interval": args.interval,
        "keep": args.keep,
        "ip_version": args.ip_version,
        "dns_timeout": args.dns_timeout,
        "ufw_cmd": args.ufw_cmd,
        "dry_run": args.dry_run if args.dry_run else None,
        "once": args.once if args.once else None,
        "log_file": args.log_file,
    }
    merged = {k: v for k, v in raw.items() if v is not None}
    try:
        file_values = load(args.config)
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"invalid config {args.config}: {exc}")
    values = {**file_values, **merged}

    if not values.get("domain"):
        raise SystemExit("missing --domain (or `domain` in the config file)")
    if isinstance(values.get("keep"), str):
        values["keep"] = [values["keep"]]

    try:
        return Config(**values)
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"bad configuration: {exc}")


def write_example(path: str | Path) -> None:
    Path(path).write_text(
        'domain = "example.com"\n'
        "interval = 600\n"
        "ip_version = 0\n"
        "keep = []\n"
        'dns_timeout = 10.0\n',
        encoding="utf-8",
    )
