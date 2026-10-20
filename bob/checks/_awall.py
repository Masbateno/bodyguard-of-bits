"""awall, Alpine's firewall front-end (v0.26.0).

awall compiles JSON policies into an iptables ruleset (``awall activate``).
BOB read that ruleset as "no active firewall front-end, but the netfilter layer
is filtering" — measured on Alpine 3.24 with awall and a deny-inbound policy
keeping ssh: INPUT DROP, port 8097 dropped from the LAN, the front-end unnamed.
``awall list`` prints one optional policy per line, name first and its state
second ("enabled" / "disabled" / "required").
"""

from __future__ import annotations

from dataclasses import dataclass

from bob.checks._run import _command_exists, run_result


@dataclass(frozen=True)
class AwallStatus:
    installed: bool = False
    #: Enabled optional policies, by name.
    enabled: tuple = ()
    #: False when ``awall list`` failed: what is enabled is unknown.
    readable: bool = True

    @classmethod
    def from_system(cls) -> "AwallStatus":
        if not _command_exists("awall"):
            return cls()
        res = run_result("awall", "list")
        if not res.ok:
            return cls(installed=True, readable=False)
        # v0.26.0 — a policy another enabled one imports is listed "required"
        # and is loaded too (measured in Alpine 3.24.2: web importing base →
        # "base required"); it is named, with awall's own word.
        rows = [parts for parts in (ln.split() for ln in res.stdout.splitlines()) if len(parts) >= 2]
        enabled = tuple([p[0] for p in rows if p[1] == "enabled"] +
                        [f"{p[0]} (required)" for p in rows if p[1] == "required"])
        return cls(installed=True, enabled=enabled)
