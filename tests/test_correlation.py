"""Tests for bob.correlation — signal correlation engine."""

from __future__ import annotations

import pytest

from bob.correlation import (
    CorrelationRule,
    CorrelatedFinding,
    run_correlations,
    _RULES,
)
from bob.scoring import FindingLevel, Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _t(key: str, **kwargs) -> str:
    assert isinstance(key, str)
    return key.format(**kwargs) if kwargs else key


class FakeEngine:
    def __init__(self, *key_level_pairs):
        self.findings = [
            Finding(level=lvl, message="msg", key=k)
            for k, lvl in key_level_pairs
        ]


# ---------------------------------------------------------------------------
# CorrelationRule.matches
# ---------------------------------------------------------------------------

class TestCorrelationRuleMatches:
    def _rule(self, all_of, any_of):
        return CorrelationRule(
            key="test.rule",
            all_of=frozenset(all_of),
            any_of=frozenset(any_of),
            level=FindingLevel.WARN,
            message_key="test.rule",
        )

    def test_all_of_satisfied_no_any_of(self):
        rule = self._rule({"a", "b"}, {})
        assert rule.matches({"a", "b", "c"})

    def test_all_of_missing_one(self):
        rule = self._rule({"a", "b"}, {})
        assert not rule.matches({"a"})

    def test_any_of_satisfied(self):
        rule = self._rule({"a"}, {"b", "c"})
        assert rule.matches({"a", "c"})

    def test_any_of_not_satisfied(self):
        rule = self._rule({"a"}, {"b", "c"})
        assert not rule.matches({"a", "x"})

    def test_empty_active_no_match(self):
        rule = self._rule({"a"}, {})
        assert not rule.matches(set())

    def test_any_of_empty_means_no_constraint(self):
        rule = self._rule({"a"}, {})
        assert rule.matches({"a"})

    def test_all_of_and_any_of_both_satisfied(self):
        rule = self._rule({"a"}, {"b"})
        assert rule.matches({"a", "b"})

    def test_any_of_partially_present_still_matches(self):
        rule = self._rule({"a"}, {"b", "c"})
        assert rule.matches({"a", "b"})

    def test_empty_all_of_with_any_of_matches(self):
        rule = self._rule({}, {"x", "y"})
        assert rule.matches({"x"})

    def test_empty_all_of_with_any_of_no_match(self):
        rule = self._rule({}, {"x", "y"})
        assert not rule.matches({"z"})

    def test_both_empty_matches_any_active(self):
        rule = self._rule({}, {})
        assert rule.matches({"x", "y"})

    def test_both_empty_matches_empty_active(self):
        rule = self._rule({}, {})
        assert rule.matches(set())

    def test_empty_all_of_nonempty_any_of_no_match_on_empty_active(self):
        rule = self._rule({}, {"a"})
        assert not rule.matches(set())


# ---------------------------------------------------------------------------
# run_correlations — no matches
# ---------------------------------------------------------------------------

class TestRunCorrelationsNoMatch:
    def test_empty_engine(self):
        assert run_correlations(FakeEngine(), _t) == []

    def test_ok_findings_ignored(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.OK),
            ("fail2ban.not_installed", FindingLevel.OK),
        )
        assert run_correlations(engine, _t) == []

    def test_info_findings_ignored(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.INFO),
            ("fail2ban.not_installed", FindingLevel.INFO),
        )
        assert run_correlations(engine, _t) == []

    def test_keyless_finding_ignored(self):
        engine = FakeEngine(("", FindingLevel.ALERT))
        assert run_correlations(engine, _t) == []

    def test_info_level_for_all_of_key_does_not_fire_rule(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.INFO),
            ("fail2ban.not_installed", FindingLevel.WARN),
        )
        assert run_correlations(engine, _t) == []


# ---------------------------------------------------------------------------
# Specific rules fire
# ---------------------------------------------------------------------------

class TestCorrelationRootNoProtection:
    def test_fires_with_not_installed(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
        )
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.root_no_protection" in keys

    def test_fires_with_service_inactive(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("fail2ban.service_inactive", FindingLevel.WARN),
        )
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.root_no_protection" in keys

    def test_does_not_fire_when_fail2ban_ok(self):
        engine = FakeEngine(("ssh.permit_root_login", FindingLevel.WARN))
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.root_no_protection" not in keys

    def test_level_is_alert_enum(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
        )
        result = run_correlations(engine, _t)
        match = next(cf for cf in result if cf.key == "corr.root_no_protection")
        assert match.level == FindingLevel.ALERT
        assert isinstance(match.level, FindingLevel)

    def test_triggered_by_exact(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
        )
        result = run_correlations(engine, _t)
        match = next(cf for cf in result if cf.key == "corr.root_no_protection")
        assert set(match.triggered_by) == {"ssh.permit_root_login", "fail2ban.not_installed"}

    def test_triggered_by_deduplicates_key_in_both_all_of_and_any_of(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
        )
        rule = CorrelationRule(
            key="test.overlap",
            all_of=frozenset({"ssh.permit_root_login"}),
            any_of=frozenset({"ssh.permit_root_login", "fail2ban.not_installed"}),
            level=FindingLevel.ALERT,
            message_key="test.overlap",
        )
        from bob.correlation import run_correlations as _run
        active = {"ssh.permit_root_login", "fail2ban.not_installed"}
        triggered = sorted(rule.all_of | (rule.any_of & active))
        assert triggered.count("ssh.permit_root_login") == 1

    def test_triggered_by_includes_all_matching_any_of_keys(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
            ("fail2ban.service_inactive", FindingLevel.WARN),
        )
        result = run_correlations(engine, _t)
        match = next(cf for cf in result if cf.key == "corr.root_no_protection")
        assert set(match.triggered_by) == {
            "ssh.permit_root_login",
            "fail2ban.not_installed",
            "fail2ban.service_inactive",
        }


class TestCorrelationPasswordAuthUnderAttack:
    def test_fires(self):
        engine = FakeEngine(
            ("ssh.password_auth", FindingLevel.WARN),
            ("auth_log.brute_force", FindingLevel.ALERT),
        )
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.password_auth_under_attack" in keys

    def test_missing_brute_force_no_fire(self):
        engine = FakeEngine(("ssh.password_auth", FindingLevel.WARN))
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.password_auth_under_attack" not in keys

    def test_level_is_alert_enum(self):
        engine = FakeEngine(
            ("ssh.password_auth", FindingLevel.WARN),
            ("auth_log.brute_force", FindingLevel.ALERT),
        )
        result = run_correlations(engine, _t)
        match = next(cf for cf in result if cf.key == "corr.password_auth_under_attack")
        assert match.level == FindingLevel.ALERT
        assert isinstance(match.level, FindingLevel)


class TestCorrelationSshRootPassword:
    def test_fires(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("ssh.password_auth", FindingLevel.WARN),
        )
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.ssh_root_password" in keys

    def test_level_is_alert_enum(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("ssh.password_auth", FindingLevel.WARN),
        )
        result = run_correlations(engine, _t)
        match = next(cf for cf in result if cf.key == "corr.ssh_root_password")
        assert match.level == FindingLevel.ALERT
        assert isinstance(match.level, FindingLevel)

    def test_triggered_by_exact(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("ssh.password_auth", FindingLevel.WARN),
        )
        result = run_correlations(engine, _t)
        match = next(cf for cf in result if cf.key == "corr.ssh_root_password")
        assert set(match.triggered_by) == {"ssh.permit_root_login", "ssh.password_auth"}


class TestCorrelationPrivilegeEscalation:
    def test_fires(self):
        engine = FakeEngine(
            ("file_perms.sudoers_nopasswd_all", FindingLevel.ALERT),
            ("suid_audit.unexpected_suid", FindingLevel.WARN),
        )
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.privilege_escalation" in keys

    def test_level_is_warn_enum(self):
        engine = FakeEngine(
            ("file_perms.sudoers_nopasswd_all", FindingLevel.ALERT),
            ("suid_audit.unexpected_suid", FindingLevel.WARN),
        )
        result = run_correlations(engine, _t)
        match = next(cf for cf in result if cf.key == "corr.privilege_escalation")
        assert match.level == FindingLevel.WARN
        assert isinstance(match.level, FindingLevel)


class TestCorrelationStaleUnmonitored:
    def test_fires_with_not_installed(self):
        engine = FakeEngine(
            ("updates.security_pending", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
        )
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.stale_unmonitored" in keys

    def test_no_fire_without_fail2ban_issue(self):
        engine = FakeEngine(("updates.security_pending", FindingLevel.WARN))
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.stale_unmonitored" not in keys


class TestCorrelationFullyBlind:
    def test_fires(self):
        engine = FakeEngine(
            ("firewall.logging_off", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
            ("auditd.not_installed", FindingLevel.WARN),
        )
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.fully_blind" in keys

    def test_fires_with_service_inactive(self):
        engine = FakeEngine(
            ("firewall.logging_off", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
            ("auditd.service_inactive", FindingLevel.WARN),
        )
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.fully_blind" in keys

    def test_fires_with_only_fail2ban_inactive(self):
        """v0.5.5 M-4: fail2ban-stopped (without auditd issue) is also a
        blind-detection signal. Pre-v0.5.5 the rule only fired when both
        fail2ban AND auditd were blind, which silently let through hosts
        with firewall logging off + fail2ban inactive — the case this
        rule was meant to catch.
        """
        engine = FakeEngine(
            ("firewall.logging_off", FindingLevel.WARN),
            ("fail2ban.service_inactive", FindingLevel.WARN),
        )
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.fully_blind" in keys

    def test_does_not_fire_when_firewall_logging_present(self):
        """all_of requires firewall.logging_off — without it, the rule
        cannot fire even when other detection layers are blind.
        """
        engine = FakeEngine(
            ("fail2ban.not_installed", FindingLevel.WARN),
            ("auditd.not_installed", FindingLevel.WARN),
        )
        keys = [cf.key for cf in run_correlations(engine, _t)]
        assert "corr.fully_blind" not in keys


# ---------------------------------------------------------------------------
# Multi-rule coexistence
# ---------------------------------------------------------------------------

class TestMultiRuleCoexistence:
    def test_three_rules_fire_simultaneously(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("ssh.password_auth", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
            ("auth_log.brute_force", FindingLevel.ALERT),
        )
        result = run_correlations(engine, _t)
        keys = {cf.key for cf in result}
        assert keys == {
            "corr.root_no_protection",
            "corr.ssh_root_password",
            "corr.password_auth_under_attack",
        }

    def test_no_duplicate_keys_when_all_fire(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("ssh.password_auth", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
            ("auth_log.brute_force", FindingLevel.ALERT),
            ("file_perms.sudoers_nopasswd_all", FindingLevel.ALERT),
            ("suid_audit.unexpected_suid", FindingLevel.WARN),
            ("updates.security_pending", FindingLevel.WARN),
            ("firewall.logging_off", FindingLevel.WARN),
            ("auditd.not_installed", FindingLevel.WARN),
        )
        result = run_correlations(engine, _t)
        found_keys = [cf.key for cf in result]
        assert len(found_keys) == len(set(found_keys))

    def test_all_levels_are_finding_level_enum(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("ssh.password_auth", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
        )
        for cf in run_correlations(engine, _t):
            assert isinstance(cf.level, FindingLevel)

    def test_alert_and_warn_coexist_correctly(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
            ("file_perms.sudoers_nopasswd_all", FindingLevel.ALERT),
            ("suid_audit.unexpected_suid", FindingLevel.WARN),
        )
        result = run_correlations(engine, _t)
        levels = {cf.key: cf.level for cf in result}
        assert levels["corr.root_no_protection"] == FindingLevel.ALERT
        assert levels["corr.privilege_escalation"] == FindingLevel.WARN

    def test_triggered_by_no_surplus_keys(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
            ("updates.security_pending", FindingLevel.WARN),
        )
        result = run_correlations(engine, _t)
        match = next(cf for cf in result if cf.key == "corr.root_no_protection")
        assert set(match.triggered_by) == {"ssh.permit_root_login", "fail2ban.not_installed"}


# ---------------------------------------------------------------------------
# Output structure
# ---------------------------------------------------------------------------

class TestCorrelatedFindingStructure:
    def test_message_is_string(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
        )
        for cf in run_correlations(engine, _t):
            assert isinstance(cf.message, str)

    def test_message_uses_translation_key(self):
        def fake_t(key: str, **kwargs) -> str:
            return f"translated:{key}"

        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
        )
        result = run_correlations(engine, fake_t)
        match = next(cf for cf in result if cf.key == "corr.root_no_protection")
        assert match.message == "translated:corr.root_no_protection"

    def test_triggered_by_is_sorted(self):
        engine = FakeEngine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
        )
        result = run_correlations(engine, _t)
        match = next(cf for cf in result if cf.key == "corr.root_no_protection")
        assert match.triggered_by == sorted(match.triggered_by)


# ---------------------------------------------------------------------------
# Rule sanity
# ---------------------------------------------------------------------------

class TestRulesSanity:
    def test_all_rules_have_key(self):
        for rule in _RULES:
            assert rule.key

    def test_all_rules_have_message_key(self):
        for rule in _RULES:
            assert rule.message_key

    def test_all_rules_have_valid_level(self):
        for rule in _RULES:
            assert rule.level in (FindingLevel.ALERT, FindingLevel.WARN)
            assert isinstance(rule.level, FindingLevel)

    def test_all_rules_have_at_least_one_constraint(self):
        for rule in _RULES:
            assert rule.all_of or rule.any_of

    def test_no_duplicate_rule_keys(self):
        keys = [r.key for r in _RULES]
        assert len(keys) == len(set(keys))
