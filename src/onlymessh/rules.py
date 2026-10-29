"""Parsing and diffing UFW ``status`` output.

A rule is modelled as the (to, action, source) triple that ``ufw status``
prints.  onlymessh only ever touches *pure IP* ALLOW rules: rules whose
destination is ``Anywhere`` (or ``Anywhere (v6)``) and whose source is an
address or CIDR block.  Everything else - port rules (``22/tcp``), rules that
allow from ``Anywhere``, DENY / LIMIT / REJECT rules - is read-only for us.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

_COLUMNS = re.compile(r"\s{2,}")
_NUMBERED = re.compile(r"^\[\s*\d+\]\s+")
_NON_IP_SOURCES = {"anywhere", "any", "anywhere (v6)"}


class ParseError(RuntimeError):
    pass


def _norm_target(value: str) -> str:
    return value.strip().lower().replace(" (v6)", "")


def fmt(net: ipaddress._BaseNetwork) -> str:
    """Print a network the way UFW does: bare address for host routes."""
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


@dataclass(frozen=True)
class Rule:
    """One row of ``ufw status``."""

    to: str
    action: str
    source: str
    comment: str | None = None

    @property
    def is_v6(self) -> bool:
        return "(v6)" in self.to.lower()

    @property
    def is_allow(self) -> bool:
        return self.action.upper().startswith("ALLOW")

    @property
    def is_ip_only(self) -> bool:
        """``Anywhere  ALLOW  <address>`` - the only kind we manage."""
        return self.is_allow and _norm_target(self.to) == "anywhere" and self.parse_source() is not None

    def parse_source(self) -> ipaddress._BaseNetwork | None:
        raw = self.source.strip()
        if not raw or raw.lower() in _NON_IP_SOURCES:
            return None
        raw = raw.split()[0]
        try:
            return ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return None


def _split_comment(line: str) -> tuple[str, str | None]:
    if " # " in line:
        body, _, comment = line.partition(" # ")
        return body, comment.strip() or None
    return line, None


def parse_status(output: str) -> tuple[bool, list[Rule]]:
    """Parse ``ufw status`` output into ``(active, rules)``."""
    active = False
    rules: list[Rule] = []
    saw_table = False

    for raw in output.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("Status:"):
            active = "inactive" not in stripped.lower()
            continue
        if stripped.startswith("To") and "Action" in stripped:
            saw_table = True
            continue
        if set(stripped) <= set("- "):
            continue
        if not saw_table:
            continue

        body, comment = _split_comment(stripped)
        body = _NUMBERED.sub("", body).strip()
        body = re.sub(r"^ALLOW IN\b", "ALLOW", body)
        cells = [c for c in _COLUMNS.split(body) if c]
        if len(cells) < 3:
            continue
        rules.append(
            Rule(
                to=cells[0].strip(),
                action=cells[1].strip(),
                source=cells[2].strip(),
                comment=comment,
            )
        )

    if not saw_table and active:
        raise ParseError("could not find the rules table in `ufw status` output")
    return active, rules


@dataclass
class ChangePlan:
    to_add: list[str]
    to_remove: list[Rule]

    @property
    def empty(self) -> bool:
        return not self.to_add and not self.to_remove


def _same(a: ipaddress._BaseNetwork, b: ipaddress._BaseNetwork) -> bool:
    return a.version == b.version and a.network_address == b.network_address and a.prefixlen == b.prefixlen


def _covers(net: ipaddress._BaseNetwork, other: ipaddress._BaseNetwork) -> bool:
    """True when ``other`` is inside ``net`` (mixing v4 and v6 is never a match)."""
    if net.version != other.version:
        return False
    return other.subnet_of(net)


def plan(
    desired: list[str],
    current: list[Rule],
    keep: list[str] | tuple[str, ...] = (),
    ip_version: int = 0,
) -> ChangePlan:
    """Diff the resolved addresses against the live pure-IP ALLOW rules.

    ``desired`` wins: every other pure-IP ALLOW rule is removed unless it is
    listed in ``keep``.
    """
    wanted = [ipaddress.ip_network(d, strict=False) for d in desired]
    if ip_version:
        wanted = [n for n in wanted if n.version == ip_version]
    kept = [ipaddress.ip_network(k, strict=False) for k in keep]

    present = [(r, r.parse_source()) for r in current if r.is_ip_only]

    to_add: list[str] = []
    for net in wanted:
        if any(src is not None and _same(src, net) for _, src in present):
            continue
        text = fmt(net)
        if text not in to_add:
            to_add.append(text)

    to_remove: list[Rule] = []
    for rule, src in present:
        if src is None:
            continue
        if ip_version and src.version != ip_version:
            continue
        if any(_same(src, net) for net in wanted):
            continue
        if any(_same(src, k) or _covers(k, src) for k in kept):
            continue
        to_remove.append(rule)

    return ChangePlan(to_add=to_add, to_remove=to_remove)
