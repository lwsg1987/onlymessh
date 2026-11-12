"""One reconciliation pass: resolve the domain, then patch UFW."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .config import Config
from .guards import current_ssh_sources
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
    kept_for_ssh: list[str] = field(default_factory=list)
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

    # The operator's own SSH session must survive this pass.  If it is held
    # open by a pure-IP ALLOW rule that is not in the resolved set, a normal
    # sync would delete it and cut the session.
    keep = list(cfg.keep)
    for ip in current_ssh_sources():
        if ip in desired or any(_covers_existing(ip, k) for k in keep):
            continue
        if any(_covers_existing(ip, d) for d in desired):
            continue
        keep.append(ip + "/32")
        res.kept_for_ssh.append(ip)
        log.warning("keeping %s: current SSH session source (not in DNS answer)", ip)

    change: ChangePlan = plan(desired, rules, keep=keep, ip_version=cfg.ip_version)

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


def _covers_existing(addr: str, cidr: str) -> bool:
    """True when ``addr`` already falls inside ``cidr``."""
    import ipaddress

    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
