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

from dataclasses import dataclass, field

from bob.checks._run import _command_exists, run_result


@dataclass
class FirewalldStatus:
    """What firewalld is doing, as far as ``firewall-cmd`` will say.

    Args:
        active:       True if ``firewall-cmd --state`` reports it running.
        default_zone: The default zone name (e.g. "FedoraServer", "public"), or "".
        services:     Named services allowed in the default zone (e.g. ssh, cockpit).
        ports:        Raw port rules allowed in the default zone (e.g. "8080/tcp").
        readable:     False when firewall-cmd is present but could not be queried
                      (a refusal is not "no firewall").
    """
    active:       bool = False
    default_zone: str = ""
    services:     list[str] = field(default_factory=list)
    ports:        list[str] = field(default_factory=list)
    readable:     bool = True

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
            return cls(active=True, default_zone=zone,
                       services=services, ports=ports, readable=True)
        if not text and not state.ok:
            # firewall-cmd present but said nothing and failed — refused, not off.
            return cls(active=False, readable=False)
        return cls(active=False, readable=True)
