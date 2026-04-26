"""
Unit tests for bob.checks.firewall module.

All tests use FirewallStatus instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_firewall.py -v
"""

from __future__ import annotations

import pytest
from bob.checks.firewall import FirewallStatus, check_firewall, check_rules
from bob.scoring import FindingLevel
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_status(**overrides) -> FirewallStatus:
    """Return a default healthy FirewallStatus with optional overrides."""
    defaults = dict(
        installed=True,
        active=True,
        incoming_policy="deny",
        ufw_output="Status: active\nDefault: deny (incoming)",
        numbered_output="",
        ipv4_rules_count=2,
        ipv6_rules_count=2,
        ipv6_ufw_enabled=True,
    )
    defaults.update(overrides)
    return FirewallStatus(**defaults)


def has_level(result, level: str) -> bool:
    return level in _levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# UFW not installed
# ---------------------------------------------------------------------------

class TestUFWNotInstalled:
    def test_alert_when_not_installed(self):
        status = make_status(installed=False)
        result = check_firewall(status)
        assert has_level(result, "alert")

    def test_no_further_checks_when_not_installed(self):
        """If UFW is not installed, no other findings should be added."""
        status = make_status(installed=False)
        result = check_firewall(status)
        assert len(result.findings) == 1

    def test_fix_cmd_present(self):
        status = make_status(installed=False)
        result = check_firewall(status)
        assert result.findings[0].cmd != ""


# ---------------------------------------------------------------------------
# UFW inactive
# ---------------------------------------------------------------------------

class TestUFWInactive:
    def test_alert_when_inactive(self):
        status = make_status(active=False)
        result = check_firewall(status)
        assert has_level(result, "alert")

    def test_firewall_inactive_sets_cap(self):
        """Inactive firewall must embed a score cap (max=3) in the CheckResult."""
        status = make_status(active=False)
        result = check_firewall(status)
        assert len(result.caps) == 1
        assert result.caps[0].maximum == 3

    def test_fix_cmd_is_ufw_enable(self):
        status = make_status(active=False)
        result = check_firewall(status)
        alert = next(f for f in result.findings if f.level == FindingLevel.ALERT)
        assert "ufw enable" in alert.cmd

    def test_no_further_checks_when_inactive(self):
        """Policy and IPv6 checks must not run when UFW is inactive."""
        status = make_status(active=False)
        result = check_firewall(status)
        # Only one finding: the inactive alert (after the installed OK)
        alerts = [f for f in result.findings if f.level == FindingLevel.ALERT]
        assert len(alerts) == 1


# ---------------------------------------------------------------------------
# Default incoming policy
# ---------------------------------------------------------------------------

class TestIncomingPolicy:
    def test_ok_when_deny(self):
        result = check_firewall(make_status(incoming_policy="deny"))
        assert has_level(result, "ok")

    def test_alert_when_allow(self):
        result = check_firewall(make_status(incoming_policy="allow"))
        assert has_level(result, "alert")

    def test_deduction_3_when_allow(self):
        result = check_firewall(make_status(incoming_policy="allow"))
        assert total_deductions(result) >= 3

    def test_fix_cmd_deny_incoming(self):
        result = check_firewall(make_status(incoming_policy="allow"))
        alert = next(f for f in result.findings if f.level == FindingLevel.ALERT)
        assert "deny incoming" in alert.cmd

    def test_warn_when_unknown_policy(self):
        result = check_firewall(make_status(incoming_policy="unknown"))
        assert has_level(result, "warn")

    def test_no_deduction_when_deny(self):
        result = check_firewall(make_status(
            incoming_policy="deny",
            ipv4_rules_count=2,
            ipv6_rules_count=2,
        ))
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# IPv6 consistency
# ---------------------------------------------------------------------------

_IPV4_ONLY = (
    "[ 1] 22/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 80/tcp                     ALLOW IN    Anywhere                  \n"
)

_IPV4_AND_IPV6 = (
    "[ 1] 22/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)             \n"
)

_NO_RULES = ""


class TestIPv6Consistency:
    def test_warn_when_ipv4_rules_but_no_ipv6(self):
        result = check_rules("", _IPV4_ONLY, _t)
        assert has_level(result, "warn")

    def test_deduction_1_for_ipv6_missing(self):
        result = check_rules("", _IPV4_ONLY, _t)
        assert total_deductions(result) == 1

    def test_ok_when_ipv6_consistent(self):
        result = check_rules("", _IPV4_AND_IPV6, _t)
        ok_messages = [f.message for f in result.findings if f.level == FindingLevel.OK]
        assert any("rules.ipv6_ok" in m for m in ok_messages)

    def test_no_ipv6_check_when_no_rules(self):
        """No IPv6 finding if there are no rules at all."""
        result = check_rules("", _NO_RULES, _t)
        all_messages = [f.message for f in result.findings]
        assert not any("ipv6" in m.lower() for m in all_messages)

    def test_no_ipv6_warning_when_ipv6_disabled(self):
        """When IPV6=no in /etc/default/ufw, no warning even with IPv4-only rules."""
        result = check_rules("", _IPV4_ONLY, _t, ipv6_enabled=False)
        assert not has_level(result, "warn")

    def test_ipv6_warning_present_when_ipv6_enabled(self):
        """Regression: ipv6_enabled=True (default) still warns on IPv4-only rules."""
        result = check_rules("", _IPV4_ONLY, _t, ipv6_enabled=True)
        assert has_level(result, "warn")


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombinedScenarios:
    def test_clean_configuration_no_deductions(self):
        """Perfect setup — no deductions, all OK."""
        result = check_firewall(make_status(
            installed=True, active=True,
            incoming_policy="deny",
            ipv4_rules_count=3,
            ipv6_rules_count=3,
        ))
        assert total_deductions(result) == 0
        assert not has_level(result, "alert")
        assert not has_level(result, "warn")

    def test_allow_policy_plus_no_ipv6(self):
        """Open policy (check_firewall) + missing IPv6 (check_rules) — combined."""
        fw_result = check_firewall(make_status(incoming_policy="allow"))
        rules_result = check_rules("", _IPV4_ONLY, _t)
        combined_deductions = total_deductions(fw_result) + total_deductions(rules_result)
        assert combined_deductions >= 4  # 3 for policy + 1 for IPv6
        assert has_level(fw_result, "alert")
        assert has_level(rules_result, "warn")

    def test_translation_function_used(self):
        """When a translation function is provided, its output appears in findings."""
        def my_t(key, **kwargs):
            return f"TRANSLATED:{key}"

        result = check_firewall(make_status(), t=my_t)
        assert any("TRANSLATED:" in f.message for f in result.findings)


# ---------------------------------------------------------------------------
# Orphan rules
# ---------------------------------------------------------------------------

_WITH_ORPHAN = (
    "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
    "[ 2] 35839/udp                  ALLOW IN    Anywhere\n"
    "[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n"
    "[ 4] 35839/udp (v6)             ALLOW IN    Anywhere (v6)\n"
)

_ALL_COVERED = (
    "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
    "[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n"
)

_LISTENING = {"22/tcp", "5353/udp"}


class TestOrphanRules:
    def test_orphan_rule_produces_info(self):
        result = check_rules("", _WITH_ORPHAN, _t, listening_ports=_LISTENING)
        assert "info" in _levels(result)

    def test_orphan_rule_key(self):
        result = check_rules("", _WITH_ORPHAN, _t, listening_ports=_LISTENING)
        keys = [f.key for f in result.findings]
        assert "rules.orphan_rule" in keys

    def test_orphan_rule_has_delete_cmd(self):
        result = check_rules("", _WITH_ORPHAN, _t, listening_ports=_LISTENING)
        f = next(f for f in result.findings if f.key == "rules.orphan_rule")
        assert "ufw delete allow 35839/udp" in (f.cmd or "")

    def test_no_orphan_when_all_covered(self):
        result = check_rules("", _ALL_COVERED, _t, listening_ports=_LISTENING)
        keys = [f.key for f in result.findings]
        assert "rules.orphan_rule" not in keys

    def test_v6_mirror_not_flagged_as_orphan(self):
        result = check_rules("", _WITH_ORPHAN, _t, listening_ports=_LISTENING)
        orphan_msgs = [f.message for f in result.findings if f.key == "rules.orphan_rule"]
        assert all("(v6)" not in m for m in orphan_msgs)

    def test_no_orphan_check_when_listening_ports_none(self):
        result = check_rules("", _WITH_ORPHAN, _t, listening_ports=None)
        keys = [f.key for f in result.findings]
        assert "rules.orphan_rule" not in keys

    def test_no_deduction_for_orphan(self):
        result = check_rules("", _WITH_ORPHAN, _t, listening_ports=_LISTENING)
        assert total_deductions(result) == 0

    def test_open_any_rule_not_flagged_as_orphan(self):
        numbered = "[ 1] Anywhere                   ALLOW IN    Anywhere\n"
        result = check_rules("", numbered, _t, listening_ports=set())
        keys = [f.key for f in result.findings]
        assert "rules.orphan_rule" not in keys
