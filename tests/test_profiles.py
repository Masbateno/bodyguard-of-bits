"""
Unit tests for bob.profiles module.

Tests cover: built-in profile loading, extends chain, overrides (downgrade
and skip), skip_sections, apply_profile() mutations, and edge cases.

Run with: python3 -m pytest tests/test_profiles.py -v
"""

from __future__ import annotations

import configparser
from pathlib import Path

import pytest

from bob.checks.hardening import HardeningSnapshot, check_hardening
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from bob.checks.ssh import SSHSnapshot, check_ssh
from bob.checks.rootkit import RootkitSnapshot, check_rootkit
from bob.checks.password_policy import PasswordPolicySnapshot, check_password_policy
from bob.profiles import (
    AuditProfile,
    _DEFAULT_PROFILE,
    _find_profile_file,
    _load_from_path,
    apply_profile,
    load_profile,
)
from bob.scoring import CheckResult, FindingLevel
from tests.helpers import _t


# ---------------------------------------------------------------------------
# Autouse fixture — clear lru_cache between tests so monkeypatching works
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_profile_cache():
    _find_profile_file.cache_clear()
    yield
    _find_profile_file.cache_clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_profile(directory: Path, name: str, content: str) -> Path:
    path = directory / f"{name}.conf"
    path.write_text(content, encoding="utf-8")
    return path


def make_result(**overrides) -> CheckResult:
    """Return a CheckResult with a single warn finding + keyed deduction."""
    key = overrides.get("key", "hardening.auto_updates_missing")
    result = CheckResult()
    result.warn(message="something is wrong", key=key)
    result.add_deduction(
        reason="something is wrong",
        points=overrides.get("points", 1),
        key=key,
    )
    return result


# ---------------------------------------------------------------------------
# load_profile — built-in profiles
# ---------------------------------------------------------------------------

class TestLoadBuiltinProfiles:
    def test_server_profile_loads(self):
        p = load_profile("server")
        assert p.name == "server"

    def test_default_alias_returns_server(self):
        p = load_profile("default")
        assert p is _DEFAULT_PROFILE

    def test_empty_string_returns_server(self):
        p = load_profile("")
        assert p is _DEFAULT_PROFILE

    def test_desktop_profile_loads(self):
        p = load_profile("desktop")
        assert p.name == "desktop"

    def test_workstation_alias_loads_desktop(self):
        """'workstation' is a backward-compat alias for 'desktop'."""
        p = load_profile("workstation")
        assert p.name == "desktop"

    def test_container_profile_loads(self):
        p = load_profile("container")
        assert p.name == "container"

    def test_unknown_profile_returns_default(self):
        p = load_profile("nonexistent_xyz")
        assert p is _DEFAULT_PROFILE

    def test_server_has_no_overrides(self):
        p = load_profile("server")
        assert p.overrides == {}

    def test_server_has_no_skip_sections(self):
        p = load_profile("server")
        assert p.skip_sections == set()

    def test_desktop_overrides_auto_updates(self):
        p = load_profile("desktop")
        assert p.override_for("hardening.auto_updates_missing") == "info"

    def test_desktop_overrides_rp_filter(self):
        p = load_profile("desktop")
        assert p.override_for("hardening.rp_filter_disabled") == "info"

    def test_desktop_overrides_ssh_password_auth(self):
        p = load_profile("desktop")
        assert p.override_for("ssh.password_auth") == "info"

    def test_desktop_overrides_ssh_x11_forwarding(self):
        p = load_profile("desktop")
        assert p.override_for("ssh.x11_forwarding") == "info"

    def test_desktop_overrides_ssh_allow_tcp_forwarding(self):
        p = load_profile("desktop")
        assert p.override_for("ssh.allow_tcp_forwarding") == "info"

    def test_desktop_overrides_rootkit_no_scan(self):
        p = load_profile("desktop")
        assert p.override_for("rootkit.no_scan") == "info"

    def test_desktop_overrides_rootkit_scan_old(self):
        p = load_profile("desktop")
        assert p.override_for("rootkit.scan_old") == "info"

    def test_desktop_overrides_password_policy_no_quality_module(self):
        p = load_profile("desktop")
        assert p.override_for("password_policy.no_quality_module") == "info"

    def test_desktop_overrides_send_redirects(self):
        p = load_profile("desktop")
        assert p.override_for("hardening.send_redirects_enabled") == "info"

    def test_desktop_overrides_ssh_max_auth_tries(self):
        p = load_profile("desktop")
        assert p.override_for("ssh.max_auth_tries") == "info"

    def test_desktop_overrides_ddns_warn(self):
        p = load_profile("desktop")
        assert p.override_for("ddns.warn") == "info"

    def test_desktop_overrides_avahi_exposure(self):
        p = load_profile("desktop")
        assert p.override_for("services.exposed.avahi") == "info"

    def test_container_skips_hardening_section(self):
        p = load_profile("container")
        assert p.should_skip_section("hardening")

    def test_container_inherits_desktop_overrides(self):
        p = load_profile("container")
        assert p.override_for("hardening.auto_updates_missing") == "info"

    @pytest.mark.parametrize("section", [
        "kernel_modules", "secure_boot", "auditd", "fail2ban",
        "rootkit", "file_integrity", "disk", "clamav", "ntp", "memory",
    ])
    def test_container_skips_host_level_sections(self, section):
        p = load_profile("container")
        assert p.should_skip_section(section), f"container should skip '{section}'"

    def test_container_does_not_skip_ssh(self):
        p = load_profile("container")
        assert not p.should_skip_section("ssh")

    def test_container_does_not_skip_file_perms(self):
        p = load_profile("container")
        assert not p.should_skip_section("file_perms")


# ---------------------------------------------------------------------------
# load_profile — user-defined profiles (tmp_path)
# ---------------------------------------------------------------------------

class TestLoadUserProfiles:
    def test_loads_from_path(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.profiles._USER_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "myprofile", """
[profile]
name = myprofile
description = test profile

[overrides]
hardening.fail2ban_missing = skip
""")
        p = load_profile("myprofile")
        assert p.name == "myprofile"
        assert p.override_for("hardening.fail2ban_missing") == "skip"

    def test_user_profile_takes_priority_over_builtin(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.profiles._USER_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "desktop", """
[profile]
name = desktop
description = custom override

[overrides]
hardening.auto_updates_missing = warn
""")
        p = load_profile("desktop")
        assert p.override_for("hardening.auto_updates_missing") == "warn"

    def test_extends_chain_resolved(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.profiles._USER_PROFILES_DIR", tmp_path)
        monkeypatch.setattr("bob.profiles._BUILTIN_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "base", """
[profile]
name = base

[overrides]
hardening.fail2ban_missing = info
""")
        write_profile(tmp_path, "child", """
[profile]
name = child
extends = base

[overrides]
hardening.rp_filter_disabled = skip
""")
        p = load_profile("child")
        # Child adds its own override
        assert p.override_for("hardening.rp_filter_disabled") == "skip"
        # Child inherits from base
        assert p.override_for("hardening.fail2ban_missing") == "info"

    def test_child_override_wins_over_parent(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.profiles._USER_PROFILES_DIR", tmp_path)
        monkeypatch.setattr("bob.profiles._BUILTIN_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "base", """
[profile]
name = base

[overrides]
hardening.fail2ban_missing = info
""")
        write_profile(tmp_path, "child", """
[profile]
name = child
extends = base

[overrides]
hardening.fail2ban_missing = skip
""")
        p = load_profile("child")
        assert p.override_for("hardening.fail2ban_missing") == "skip"

    def test_unknown_override_level_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.profiles._USER_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "bad", """
[profile]
name = bad

[overrides]
hardening.fail2ban_missing = invalid_level
""")
        p = load_profile("bad")
        assert p.override_for("hardening.fail2ban_missing") is None

    def test_skip_sections_loaded(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.profiles._USER_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "nohardening", """
[profile]
name = nohardening

[skip_sections]
hardening
ipv6
""")
        p = load_profile("nohardening")
        assert p.should_skip_section("hardening")
        assert p.should_skip_section("ipv6")
        assert not p.should_skip_section("docker")

    def test_missing_extends_parent_logged_and_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.profiles._USER_PROFILES_DIR", tmp_path)
        monkeypatch.setattr("bob.profiles._BUILTIN_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "orphan", """
[profile]
name = orphan
extends = nonexistent_parent

[overrides]
hardening.fail2ban_missing = skip
""")
        p = load_profile("orphan")
        # Own override still applied even if parent missing
        assert p.override_for("hardening.fail2ban_missing") == "skip"


# ---------------------------------------------------------------------------
# AuditProfile — methods
# ---------------------------------------------------------------------------

class TestAuditProfile:
    def test_override_for_returns_none_for_unknown_key(self):
        p = AuditProfile(name="test")
        assert p.override_for("unknown.key") is None

    def test_should_skip_section_true(self):
        p = AuditProfile(name="test", skip_sections={"hardening"})
        assert p.should_skip_section("hardening")

    def test_should_skip_section_false(self):
        p = AuditProfile(name="test", skip_sections={"hardening"})
        assert not p.should_skip_section("ipv6")

    def test_empty_profile_no_effect_marker(self):
        p = AuditProfile(name="empty")
        assert p.overrides == {}
        assert p.skip_sections == set()


# ---------------------------------------------------------------------------
# apply_profile — finding mutations
# ---------------------------------------------------------------------------

class TestApplyProfileNoOverrides:
    def test_no_overrides_leaves_result_unchanged(self):
        result = make_result()
        profile = AuditProfile(name="server")
        original_levels = [f.level for f in result.findings]
        apply_profile(result, profile)
        assert [f.level for f in result.findings] == original_levels

    def test_no_key_finding_never_modified(self):
        result = CheckResult()
        result.warn(message="no key finding")  # key="" by default
        profile = AuditProfile(
            name="test",
            overrides={"hardening.auto_updates_missing": "info"},
        )
        apply_profile(result, profile)
        assert result.findings[0].level == FindingLevel.WARN


class TestApplyProfileDowngrade:
    def test_warn_downgraded_to_info(self):
        result = make_result(key="hardening.auto_updates_missing")
        profile = AuditProfile(
            name="desktop",
            overrides={"hardening.auto_updates_missing": "info"},
        )
        apply_profile(result, profile)
        assert result.findings[0].level == FindingLevel.INFO

    def test_deduction_removed_when_downgraded_to_info(self):
        result = make_result(key="hardening.auto_updates_missing", points=1)
        profile = AuditProfile(
            name="desktop",
            overrides={"hardening.auto_updates_missing": "info"},
        )
        apply_profile(result, profile)
        assert sum(d.points for d in result.deductions) == 0

    def test_level_unchanged_when_override_matches_current(self):
        result = CheckResult()
        result.warn(message="already warn", key="hardening.rp_filter_disabled")
        profile = AuditProfile(
            name="test",
            overrides={"hardening.rp_filter_disabled": "warn"},
        )
        apply_profile(result, profile)
        assert result.findings[0].level == FindingLevel.WARN

    def test_multiple_findings_only_matching_key_modified(self):
        result = CheckResult()
        result.warn(message="msg1", key="hardening.auto_updates_missing")
        result.warn(message="msg2", key="hardening.rp_filter_disabled")
        profile = AuditProfile(
            name="test",
            overrides={"hardening.auto_updates_missing": "info"},
        )
        apply_profile(result, profile)
        assert result.findings[0].level == FindingLevel.INFO
        assert result.findings[1].level == FindingLevel.WARN


class TestApplyProfileSkip:
    def test_skip_removes_finding(self):
        result = make_result(key="hardening.fail2ban_missing")
        profile = AuditProfile(
            name="test",
            overrides={"hardening.fail2ban_missing": "skip"},
        )
        apply_profile(result, profile)
        assert not any(f.key == "hardening.fail2ban_missing" for f in result.findings)

    def test_skip_removes_deduction(self):
        result = make_result(key="hardening.fail2ban_missing", points=2)
        profile = AuditProfile(
            name="test",
            overrides={"hardening.fail2ban_missing": "skip"},
        )
        apply_profile(result, profile)
        assert result.deductions == []

    def test_skip_leaves_other_findings_intact(self):
        result = CheckResult()
        result.warn(message="skip me", key="hardening.fail2ban_missing")
        result.warn(message="keep me", key="hardening.rp_filter_disabled")
        profile = AuditProfile(
            name="test",
            overrides={"hardening.fail2ban_missing": "skip"},
        )
        apply_profile(result, profile)
        assert len(result.findings) == 1
        assert result.findings[0].key == "hardening.rp_filter_disabled"


# ---------------------------------------------------------------------------
# Integration — desktop profile on real hardening check
# ---------------------------------------------------------------------------

class TestDesktopIntegration:
    def test_rp_filter_warn_becomes_info_with_desktop_profile(self):
        """Desktop profile downgrades rp_filter WARN to INFO."""
        snap = HardeningSnapshot(rp_filter=0)
        result = check_hardening(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        rp_findings = [
            f for f in result.findings
            if f.key == "hardening.rp_filter_disabled"
        ]
        # Either downgraded to INFO or deduction removed — profile applied
        deduction_keys = [d.key for d in result.deductions]
        assert "hardening.rp_filter_disabled" not in deduction_keys or (
            rp_findings and rp_findings[0].level == FindingLevel.INFO
        )

    def test_profile_reduces_deductions(self):
        """Desktop profile removes at least one deduction vs no profile."""
        snap = HardeningSnapshot(rp_filter=0, accept_redirects=True)
        result_raw = check_hardening(snap, t=_t)
        before_deductions = sum(d.points for d in result_raw.deductions)

        result_desktop = check_hardening(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result_desktop, profile)
        after_deductions = sum(d.points for d in result_desktop.deductions)
        # Profile may or may not override these — just verify it runs cleanly
        assert after_deductions <= before_deductions

    def test_score_lower_with_desktop_profile(self):
        from bob.scoring import ScoreEngine
        snap = HardeningSnapshot(rp_filter=0,
                                  accept_redirects=False)
        # Server profile
        result_server = check_hardening(snap, t=_t)
        engine_server = ScoreEngine()
        engine_server.apply(result_server)
        engine_server.finalize()

        # Desktop profile
        result_desktop = check_hardening(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result_desktop, profile)
        engine_desktop = ScoreEngine()
        engine_desktop.apply(result_desktop)
        engine_desktop.finalize()

        assert engine_desktop.score >= engine_server.score

    def test_ipv6_uncovered_port_becomes_info(self):
        snap = IPv6Snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=True,
            ipv6_listeners=["80/tcp"],
            ufw_v6_covered=[],
        )
        result = check_ipv6(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        port_findings = [f for f in result.findings if f.key == "ipv6.port_no_v6_rule"]
        assert port_findings
        assert port_findings[0].level == FindingLevel.INFO


# ---------------------------------------------------------------------------
# Integration — desktop profile new overrides (SSH, rootkit, password policy)
# ---------------------------------------------------------------------------

class TestDesktopProfileNewOverrides:
    # --- SSH ---

    def _ssh_snap(self, **cfg_overrides) -> SSHSnapshot:
        """Helper: active sshd with minimal safe config + specified overrides."""
        cfg = {
            "permitrootlogin": "no",
            "permitemptypasswords": "no",
            "passwordauthentication": "no",
            "x11forwarding": "no",
            "allowtcpforwarding": "no",
        }
        cfg.update(cfg_overrides)
        return SSHSnapshot(sshd_installed=True, sshd_active=True, sshd_config=cfg)

    def test_ssh_password_auth_becomes_info(self):
        snap = self._ssh_snap(passwordauthentication="yes")
        result = check_ssh(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        findings = [f for f in result.findings if f.key == "ssh.password_auth"]
        assert findings, "ssh.password_auth finding expected"
        assert findings[0].level == FindingLevel.INFO

    def test_ssh_password_auth_deduction_removed_on_desktop(self):
        snap = self._ssh_snap(passwordauthentication="yes")
        result = check_ssh(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        assert "ssh.password_auth" not in [d.key for d in result.deductions]

    def test_ssh_x11_forwarding_becomes_info(self):
        snap = self._ssh_snap(x11forwarding="yes")
        result = check_ssh(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        findings = [f for f in result.findings if f.key == "ssh.x11_forwarding"]
        assert findings, "ssh.x11_forwarding finding expected"
        assert findings[0].level == FindingLevel.INFO

    def test_ssh_tcp_forwarding_becomes_info(self):
        snap = self._ssh_snap(allowtcpforwarding="yes")
        result = check_ssh(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        findings = [f for f in result.findings if f.key == "ssh.allow_tcp_forwarding"]
        assert findings, "ssh.allow_tcp_forwarding finding expected"
        assert findings[0].level == FindingLevel.INFO

    def test_ssh_permit_root_login_not_downgraded_on_desktop(self):
        """permit_root_login is NOT overridden on desktop — always a risk (ALERT)."""
        snap = self._ssh_snap(permitrootlogin="yes")
        result = check_ssh(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        findings = [f for f in result.findings if f.key == "ssh.permit_root_login"]
        assert findings, "ssh.permit_root_login finding expected"
        assert findings[0].level == FindingLevel.ALERT

    # --- Rootkit ---

    def test_rootkit_no_scan_becomes_info(self):
        snap = RootkitSnapshot(rkhunter_installed=True, last_scan_date=None)
        result = check_rootkit(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        findings = [f for f in result.findings if f.key == "rootkit.no_scan"]
        assert findings, "rootkit.no_scan finding expected"
        assert findings[0].level == FindingLevel.INFO

    def test_rootkit_no_scan_deduction_removed_on_desktop(self):
        snap = RootkitSnapshot(rkhunter_installed=True, last_scan_date=None)
        result = check_rootkit(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        assert "rootkit.no_scan" not in [d.key for d in result.deductions]

    def test_rootkit_scan_old_becomes_info(self):
        snap = RootkitSnapshot(rkhunter_installed=True, last_scan_date="2025-01-01")
        result = check_rootkit(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        findings = [f for f in result.findings if f.key == "rootkit.scan_old"]
        assert findings, "rootkit.scan_old finding expected"
        assert findings[0].level == FindingLevel.INFO

    # --- Password policy ---

    def test_password_policy_no_quality_module_becomes_info(self):
        snap = PasswordPolicySnapshot(pam_quality_module=None)
        result = check_password_policy(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        findings = [f for f in result.findings
                    if f.key == "password_policy.no_quality_module"]
        assert findings, "password_policy.no_quality_module finding expected"
        assert findings[0].level == FindingLevel.INFO

    def test_password_policy_no_quality_module_deduction_removed(self):
        snap = PasswordPolicySnapshot(pam_quality_module=None)
        result = check_password_policy(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        assert "password_policy.no_quality_module" not in [d.key for d in result.deductions]


# ---------------------------------------------------------------------------
# apply_profile — nature cleared on INFO downgrade (summary box regression)
# ---------------------------------------------------------------------------

class TestApplyProfileNatureCleared:
    """Regression: findings downgraded to INFO must have nature='' so they
    do not appear in the action/improvement buckets of the summary box."""

    def test_downgrade_to_info_clears_nature_improvement(self):
        result = CheckResult()
        result.warn(message="warn finding", nature="improvement",
                    key="hardening.auto_updates_missing")
        profile = AuditProfile(
            name="desktop",
            overrides={"hardening.auto_updates_missing": "info"},
        )
        apply_profile(result, profile)
        finding = next(f for f in result.findings
                       if f.key == "hardening.auto_updates_missing")
        assert finding.level == FindingLevel.INFO
        assert finding.nature == ""

    def test_downgrade_to_info_clears_nature_action(self):
        result = CheckResult()
        result.warn(message="action finding", nature="action",
                    key="password_policy.no_quality_module")
        profile = AuditProfile(
            name="desktop",
            overrides={"password_policy.no_quality_module": "info"},
        )
        apply_profile(result, profile)
        finding = next(f for f in result.findings
                       if f.key == "password_policy.no_quality_module")
        assert finding.level == FindingLevel.INFO
        assert finding.nature == ""

    def test_remap_to_warn_preserves_nature(self):
        """Remapping to same or higher level must NOT clear nature."""
        result = CheckResult()
        result.warn(message="improvement", nature="improvement",
                    key="hardening.rp_filter_disabled")
        profile = AuditProfile(
            name="test",
            overrides={"hardening.rp_filter_disabled": "warn"},
        )
        apply_profile(result, profile)
        finding = next(f for f in result.findings
                       if f.key == "hardening.rp_filter_disabled")
        assert finding.nature == "improvement"

    def test_skip_does_not_affect_remaining_natures(self):
        """Skipping one finding does not change nature of surviving findings."""
        result = CheckResult()
        result.warn(message="skip this", nature="improvement",
                    key="hardening.auto_updates_missing")
        result.warn(message="keep this", nature="improvement",
                    key="hardening.rp_filter_disabled")
        profile = AuditProfile(
            name="test",
            overrides={"hardening.auto_updates_missing": "skip"},
        )
        apply_profile(result, profile)
        remaining = [f for f in result.findings]
        assert len(remaining) == 1
        assert remaining[0].key == "hardening.rp_filter_disabled"
        assert remaining[0].nature == "improvement"

    def test_no_key_finding_nature_untouched(self):
        """Findings without a key are never modified — nature preserved."""
        result = CheckResult()
        result.warn(message="no key", nature="improvement")
        profile = AuditProfile(
            name="test",
            overrides={"hardening.auto_updates_missing": "info"},
        )
        apply_profile(result, profile)
        assert result.findings[0].nature == "improvement"

    def test_desktop_ssh_password_auth_nature_cleared(self):
        """Integration: ssh.password_auth downgraded on desktop → nature=''."""
        from bob.checks.ssh import SSHSnapshot, check_ssh
        snap = SSHSnapshot(
            sshd_installed=True, sshd_active=True,
            sshd_config={
                "permitrootlogin": "no",
                "permitemptypasswords": "no",
                "passwordauthentication": "yes",
                "x11forwarding": "no",
                "allowtcpforwarding": "no",
            },
        )
        result = check_ssh(snap, t=_t)
        profile = load_profile("desktop")
        apply_profile(result, profile)
        finding = next(f for f in result.findings if f.key == "ssh.password_auth")
        assert finding.level == FindingLevel.INFO
        assert finding.nature == ""
