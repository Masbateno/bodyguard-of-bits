"""firewalld detection, shared by the firewall checks.

firewalld is the default firewall front-end on the RPM family (Fedora, RHEL,
CentOS, Rocky, Alma) and on openSUSE. It manages nftables (a `table inet
firewalld`) and works by *zones*: the base chain policy stays ACCEPT while the
zone chains jump to an explicit drop/reject at the end. A firewall auditor that
reads the raw base policy therefore sees "INPUT ACCEPT" and calls a properly
firewalled host wide-open — the exact false positive this module exists to stop.

Before v0.20.2 BOB had no firewalld awareness at all (measured on a real Fedora
44 server): it alerted "UFW not installed", read the base nft policy as "wide
open", and framed firewalld's own nft table as "nftables in parallel with UFW".
This snapshot lets the three firewall checks recognise firewalld and credit it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bob.checks._run import _command_exists, run_result

# A rich rule that grants access carries an explicit ``accept`` verb; ``reject``
# and ``drop`` rules deny and must not be shown as things the zone "allows".
_RICH_PORT = re.compile(r'port port="?(?P<port>\d+(?:-\d+)?)"?\s+protocol="?(?P<proto>\w+)"?')
_RICH_SERVICE = re.compile(r'service name="?(?P<name>[\w.+-]+)"?')


def _rich_rule_grant(rule: str) -> str | None:
    """Return a short descriptor of what an ``accept`` rich rule opens, else None.

    Only rules whose action is ``accept`` grant access; ``reject``/``drop`` rules
    are denials and return None so they never inflate the "zone allows" line.
    A port rule yields ``"5432/tcp (rich)"``, a service rule ``"https (rich)"``,
    and anything else that still accepts yields a generic ``"rich rule"``.
    """
    r = rule.strip()
    if not re.search(r'\baccept\b', r):
        return None
    m = _RICH_PORT.search(r)
    if m:
        return f"{m.group('port')}/{m.group('proto')} (rich)"
    m = _RICH_SERVICE.search(r)
    if m:
        return f"{m.group('name')} (rich)"
    return "rich rule"


@dataclass
class FirewalldStatus:
    """What firewalld is doing, as far as ``firewall-cmd`` will say.

    Args:
        active:        True if ``firewall-cmd --state`` reports it running.
        default_zone:  The default zone name (e.g. "FedoraServer", "public"), or "".
        services:      Named services allowed in the default zone (e.g. ssh, cockpit).
        ports:         Raw port rules allowed in the default zone (e.g. "8080/tcp").
        rich_rules:    Raw rich-rule strings from ``--list-rich-rules`` (one per rule).
        forward_ports: Raw forward-port rules from ``--list-forward-ports``.
        sources:       Source addresses bound to the default zone (``--list-sources``).
        readable:      False when firewall-cmd is present but could not be queried
                       (a refusal is not "no firewall").
    """
    active:        bool = False
    default_zone:  str = ""
    services:      list[str] = field(default_factory=list)
    ports:         list[str] = field(default_factory=list)
    rich_rules:    list[str] = field(default_factory=list)
    forward_ports: list[str] = field(default_factory=list)
    sources:       list[str] = field(default_factory=list)
    readable:      bool = True

    def allows_summary(self) -> str:
        """Everything the default zone permits, as one human-readable line.

        Named services and raw ports first, then any port/service opened by an
        ``accept`` rich rule (so a port reachable only through a rich rule is no
        longer invisible — the gap this method closes), then forward-ports.
        Returns ``"—"`` when nothing is permitted.
        """
        parts: list[str] = list(self.services) + list(self.ports)
        for rule in self.rich_rules:
            grant = _rich_rule_grant(rule)
            if grant:
                parts.append(grant)
        for fp in self.forward_ports:
            parts.append(f"forward {fp}")
        return ", ".join(parts) or "—"

    @classmethod
    def from_system(cls) -> "FirewalldStatus":
        """Collect firewalld state via ``firewall-cmd``. Never raises."""
        if not _command_exists("firewall-cmd"):
            # No client → firewalld is not the front-end here. Not an error.
            return cls(active=False, readable=True)

        state = run_result("firewall-cmd", "--state")
        # `--state` prints "running"/"not running" to stdout and, when not
        # running, also exits non-zero. Trust the word, and treat a refusal
        # (no output at all) as unreadable rather than "not running".
        text = (state.stdout or "").strip().lower()
        if "running" in text and "not running" not in text:
            zone = run_result("firewall-cmd", "--get-default-zone").stdout.strip()
            services = run_result("firewall-cmd", "--list-services").stdout.split()
            ports = run_result("firewall-cmd", "--list-ports").stdout.split()
            # Rich rules and forward-ports print one entry per line, so split on
            # newlines (a bare .split() would shred each rule into tokens).
            rich = [ln.strip() for ln in
                    run_result("firewall-cmd", "--list-rich-rules").stdout.splitlines()
                    if ln.strip()]
            fwd = [ln.strip() for ln in
                   run_result("firewall-cmd", "--list-forward-ports").stdout.splitlines()
                   if ln.strip()]
            sources = run_result("firewall-cmd", "--list-sources").stdout.split()
            return cls(active=True, default_zone=zone,
                       services=services, ports=ports,
                       rich_rules=rich, forward_ports=fwd, sources=sources,
                       readable=True)
        if not text and not state.ok:
            # firewall-cmd present but said nothing and failed — refused, not off.
            return cls(active=False, readable=False)
        return cls(active=False, readable=True)
