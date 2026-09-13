"""v0.18.3 — the audit's display taxonomy, pinned.

The audit streams its ~50 sections under six thematic group headers. Until
v0.18.3 there were five, and one — SYSTEM HARDENING — carried a third of the
audit, mixing genuine hardening controls with resource/currency sections (disk,
memory, backup, updates) and the anti-intrusion tools. v0.18.3 split it into
SYSTEM HARDENING (defences you switch on), HEALTH & RESILIENCE (currency,
capacity, recoverability) and THREAT DETECTION (what catches an intrusion after
the fact).

Nothing but this file pinned which group a section falls under, so the taxonomy
could drift back one careless move at a time. This parses the runner source and
maps each section to the group header above it, then asserts the intent. It is
a source guard (like test_v0141_contract_surfaces), not a live audit — the
grouping is display-only and must not depend on the host.
"""

from __future__ import annotations

import re
from pathlib import Path

_RUNNER = Path(__file__).resolve().parent.parent / "bob" / "runner.py"
_SRC = _RUNNER.read_text(encoding="utf-8")

# The expected group order, top to bottom.
EXPECTED_ORDER = [
    "firewall_network",
    "exposure_services",
    "access_control",
    "system_hardening",
    "health_resilience",
    "detection",
]

# A section that must appear under a given group (the moves v0.18.3 made, plus
# a couple of anchors so the whole map is exercised, not just the edges).
EXPECTED_GROUP = {
    # firewall & network
    "firewall": "firewall_network",
    "network_context": "firewall_network",
    "ipv6": "firewall_network",
    # exposure & services
    "services": "exposure_services",
    "ports": "exposure_services",
    "docker": "exposure_services",
    # access control
    "ssh": "access_control",
    "user_accounts": "access_control",
    "file_perms": "access_control",
    # system hardening — defences you switch on
    "hardening": "system_hardening",
    "kernel_hardening": "system_hardening",
    "mac_policy": "system_hardening",
    "suid_audit": "system_hardening",
    "umask": "system_hardening",
    "secure_boot": "system_hardening",
    "container_security": "system_hardening",
    # health & resilience — moved out of the overloaded hardening group
    "updates": "health_resilience",
    "disk": "health_resilience",
    "memory": "health_resilience",
    "backup": "health_resilience",
    "log_rotation": "health_resilience",
    "services_health": "health_resilience",
    "ssl_certs": "health_resilience",
    "ntp": "health_resilience",
    "systemd_timers": "health_resilience",
    "firmware": "health_resilience",
    # threat detection — the anti-intrusion tools
    "auditd": "detection",
    "fail2ban": "detection",
    "clamav": "detection",
    "file_integrity": "detection",
    "rootkit": "detection",
}


def _section_to_group() -> dict[str, str]:
    """Map every emitted section to the group header above it, in source order.

    Sections are emitted by ``emit_section("x")`` (the _core pipeline) and by
    ``_sec("x", ...)``. Group headers are ``emit_group("g")``.
    """
    mapping: dict[str, str] = {}
    current: str | None = None
    pattern = re.compile(
        r'emit_group\(\s*"([a-z_]+)"'
        r'|emit_section\(\s*"([a-z0-9_]+)"'
        r'|_sec\(\s*"([a-z0-9_]+)"'
    )
    for m in pattern.finditer(_SRC):
        group, sec_es, sec = m.groups()
        if group:
            current = group
        else:
            name = sec_es or sec
            # First occurrence wins (a section is emitted once); ignore repeats.
            mapping.setdefault(name, current)
    return mapping


class TestGroupOrder:
    def test_groups_appear_in_the_expected_order(self):
        seen = [m.group(1) for m in re.finditer(r'emit_group\(\s*"([a-z_]+)"', _SRC)]
        assert seen == EXPECTED_ORDER, f"group order drifted: {seen}"

    def test_six_groups_no_more_no_less(self):
        seen = re.findall(r'emit_group\(\s*"([a-z_]+)"', _SRC)
        assert len(seen) == 6 and len(set(seen)) == 6


class TestSectionMembership:
    def test_each_section_is_in_its_intended_group(self):
        mapping = _section_to_group()
        wrong = {
            sec: (mapping.get(sec), want)
            for sec, want in EXPECTED_GROUP.items()
            if mapping.get(sec) != want
        }
        assert not wrong, f"sections in the wrong group (got, want): {wrong}"

    def test_hardening_no_longer_carries_health_sections(self):
        """The regression this split fixes: disk/memory/backup/updates must not
        drift back under SYSTEM HARDENING."""
        mapping = _section_to_group()
        for sec in ("disk", "memory", "backup", "updates", "ssl_certs"):
            assert mapping.get(sec) == "health_resilience", (
                f"{sec} drifted back into {mapping.get(sec)}"
            )

    def test_detection_is_intrusion_tools_only(self):
        mapping = _section_to_group()
        detection = {s for s, g in mapping.items() if g == "detection"}
        # Health/currency sections must not have leaked into detection.
        assert detection == {"auditd", "fail2ban", "clamav", "file_integrity", "rootkit"}, (
            f"detection group is not intrusion-tools-only: {sorted(detection)}"
        )


class TestEveryGroupIsLabelled:
    def test_all_six_groups_resolve_in_both_locales(self):
        import json
        seen = set(re.findall(r'emit_group\(\s*"([a-z_]+)"', _SRC))
        for loc in ("en", "fr"):
            groups = json.loads(
                (_RUNNER.parent / "locales" / f"{loc}.json").read_text(encoding="utf-8")
            )["groups"]
            missing = seen - set(groups)
            assert not missing, f"{loc}: groups without a label: {missing}"
