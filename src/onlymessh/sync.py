"""One reconciliation pass: resolve the domain, then patch UFW."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .config import Config
from .resolver import resolve
from .rules import ChangePlan, plan
from .ufw import Ufw

log = logging.getLogger("onlymessh")


@dataclass
class Result:
    domain: str
    desired: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    skipped: str | None = None


def sync_once(cfg: Config, ufw: Ufw) -> Result:
    res = Result(domain=cfg.domain)

    desired = resolve(cfg.domain, cfg.ip_version, cfg.dns_timeout)
    if not desired:
        # Never let a DNS hiccup wipe the allow-list and lock the operator out.
        res.skipped = "DNS returned no addresses"
        log.error("%s resolved to nothing - leaving the firewall untouched", cfg.domain)
        return res
    res.desired = desired
    log.info("%s -> %s", cfg.domain, ", ".join(desired))

    active, rules = ufw.status()
    if not active:
        res.skipped = "ufw is inactive"
        log.warning("ufw is inactive - nothing to do")
        return res

    change: ChangePlan = plan(desired, rules, keep=cfg.keep, ip_version=cfg.ip_version)

    for rule in change.to_remove:
        log.info("remove allow from %s", rule.source)
        if not cfg.dry_run:
            ufw.delete_allow_from(rule.source)
        res.removed.append(rule.source)

    for net in change.to_add:
        log.info("add allow from %s", net)
        if not cfg.dry_run:
            ufw.allow_from(net)
        res.added.append(net)

    if change.empty:
        log.info("allow-list already in sync")
    return res
