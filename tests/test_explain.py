"""
Tests for bob/explain.py
"""

from __future__ import annotations

import io
import sys
import pytest

from bob.explain import (
    normalize_key,
    run_explain,
    EXPLAIN_KEYS,
    _has_profile_variants,
)


# ---------------------------------------------------------------------------
# normalize_key
# ---------------------------------------------------------------------------

class TestNormalizeKey:
    def test_ssh_key_unchanged(self):
        assert normalize_key("ssh.password_auth") == "ssh.password_auth"

    def test_updates_key_unchanged(self):
        assert normalize_key("updates.security_pending") == "updates.security_pending"

    def test_hardening_key_unchanged(self):
        assert normalize_key("hardening.rp_filter_disabled") == "hardening.rp_filter_disabled"

    def test_file_perms_no_middle_unchanged(self):
        assert normalize_key("file_perms.world_writable") == "file_perms.world_writable"

    def test_file_perms_world_writable_strips_middle(self):
        assert normalize_key("file_perms.shadow.world_writable") == "file_perms.world_writable"

    def test_file_perms_too_permissive_strips_middle(self):
        assert normalize_key("file_perms.authorized_keys.too_permissive") == "file_perms.too_permissive"

    def test_file_perms_sudoers_strips_middle(self):
        assert normalize_key("file_perms.sudoers.sudoers_nopasswd_all") == "file_perms.sudoers_nopasswd_all"

    def test_file_perms_ssh_host_key_perms_strips_middle(self):
        assert normalize_key("file_perms.etc_ssh.ssh_host_key_perms") == "file_perms.ssh_host_key_perms"

    def test_other_prefix_unchanged(self):
        assert normalize_key("firewall.status") == "firewall.status"

    def test_empty_string_unchanged(self):
        assert normalize_key("") == ""

    def test_single_segment_unchanged(self):
        assert normalize_key("ssh") == "ssh"

    def test_file_perms_multiple_middle_segments(self):
        """Deep nesting (3+ middle segments) must still resolve to the canonical key."""
        assert normalize_key("file_perms.a.b.c.world_writable") == "file_perms.world_writable"

    def test_file_perms_two_segments_not_modified(self):
        """A canonical file_perms key (no middle segment) must not be over-stripped."""
        assert normalize_key("file_perms.world_writable") == "file_perms.world_writable"

    def test_all_explain_keys_are_already_normalized(self):
        """Every key in EXPLAIN_KEYS must already be in canonical form."""
        for key in EXPLAIN_KEYS:
            assert normalize_key(key) == key, (
                f"EXPLAIN_KEYS contains a non-canonical key: {key!r}"
            )


# ---------------------------------------------------------------------------
# EXPLAIN_KEYS list
# ---------------------------------------------------------------------------

class TestExplainKeysList:
    def test_has_one_hundred_twelve_keys(self):
        assert len(EXPLAIN_KEYS) == 112

    def test_all_keys_are_strings(self):
        for k in EXPLAIN_KEYS:
            assert isinstance(k, str)

    def test_known_keys_present(self):
        # original 20
        assert "ssh.password_auth" in EXPLAIN_KEYS
        assert "ssh.permit_root_login" in EXPLAIN_KEYS
        assert "file_perms.world_writable" in EXPLAIN_KEYS
        assert "updates.security_pending" in EXPLAIN_KEYS
        assert "hardening.rp_filter_disabled" in EXPLAIN_KEYS
        assert "hardening.redirects_enabled" in EXPLAIN_KEYS
        # Phase A2 additions — SSH
        assert "ssh.max_auth_tries" in EXPLAIN_KEYS
        assert "ssh.permit_user_env" in EXPLAIN_KEYS
        assert "ssh.weak_ciphers" in EXPLAIN_KEYS
        assert "ssh.weak_macs" in EXPLAIN_KEYS
        assert "ssh.weak_kex" in EXPLAIN_KEYS
        # Phase A2 additions — hardening
        assert "hardening.log_martians_disabled" in EXPLAIN_KEYS
        assert "hardening.rp_filter_loose" in EXPLAIN_KEYS
        # Phase A2 additions — new checks
        assert "kernel_modules.risky_fs" in EXPLAIN_KEYS
        assert "kernel_modules.risky_net" in EXPLAIN_KEYS
        assert "cron_audit.pipe_to_shell" in EXPLAIN_KEYS
        assert "cron_audit.world_writable" in EXPLAIN_KEYS
        assert "services_state.enabled_inactive" in EXPLAIN_KEYS
        # ClamAV keys
        assert "clamav.db_very_outdated" in EXPLAIN_KEYS
        assert "clamav.db_outdated" in EXPLAIN_KEYS
        assert "clamav.scan_very_old" in EXPLAIN_KEYS
        assert "clamav.scan_old" in EXPLAIN_KEYS
        # Samba keys
        assert "samba.smb1_enabled" in EXPLAIN_KEYS
        assert "samba.null_passwords" in EXPLAIN_KEYS
        assert "samba.guest_writable" in EXPLAIN_KEYS
        assert "samba.guest_readonly" in EXPLAIN_KEYS
        assert "samba.server_signing_disabled" in EXPLAIN_KEYS
        assert "samba.map_to_guest" in EXPLAIN_KEYS

        assert "user_accounts.uid_zero" in EXPLAIN_KEYS
        assert "user_accounts.empty_password" in EXPLAIN_KEYS
        assert "user_accounts.expired_account" in EXPLAIN_KEYS
        assert "user_accounts.no_shadow" in EXPLAIN_KEYS
        # CHECKs 31/32/33
        assert "auditd.not_installed" in EXPLAIN_KEYS
        assert "auditd.service_inactive" in EXPLAIN_KEYS
        assert "auditd.no_rules" in EXPLAIN_KEYS
        assert "auditd.missing_sensitive_rules" in EXPLAIN_KEYS
        assert "secure_boot.setup_mode" in EXPLAIN_KEYS
        assert "secure_boot.disabled" in EXPLAIN_KEYS
        assert "file_integrity.not_installed" in EXPLAIN_KEYS
        assert "file_integrity.no_db" in EXPLAIN_KEYS
        assert "file_integrity.no_check" in EXPLAIN_KEYS
        assert "file_integrity.check_old" in EXPLAIN_KEYS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _identity_t(key, **_kwargs):
    """Minimal t() that returns the key itself (unknown-key behaviour)."""
    return key


def _make_t():
    """Return a t() function backed by the real en.json locale."""
    from bob import i18n
    i18n.init(lang="en")
    return i18n.t


def _capture_run_explain(key, t):
    """Call run_explain and return captured stdout."""
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        run_explain(key, t)
    finally:
        sys.stdout = old
    return buf.getvalue()


# ---------------------------------------------------------------------------
# run_explain — unknown key
# ---------------------------------------------------------------------------

class TestRunExplainUnknownKey:
    def test_unknown_key_prints_not_available(self):
        out = _capture_run_explain("firewall.unknown_key", _identity_t)
        assert "No explanation available for" in out

    def test_unknown_key_mentions_list(self):
        out = _capture_run_explain("firewall.unknown_key", _identity_t)
        # Test behaviour (shows real keys) not exact wording
        assert any(k in out for k in EXPLAIN_KEYS) or "list" in out.lower()


# ---------------------------------------------------------------------------
# run_explain — list mode
# ---------------------------------------------------------------------------

class TestRunExplainListMode:
    def test_list_prints_all_keys(self):
        t = _make_t()
        out = _capture_run_explain("list", t)
        for k in EXPLAIN_KEYS:
            assert k in out

    def test_list_shows_titles(self):
        t = _make_t()
        out = _capture_run_explain("list", t)
        # Titles should not look like key paths (i.e. not "explain.ssh.password_auth.title")
        assert "explain.ssh.password_auth.title" not in out

    def test_list_has_one_line_per_key(self):
        """Output must have at least one non-empty line per key (no silent truncation)."""
        t = _make_t()
        out = _capture_run_explain("list", t)
        non_empty_lines = [l for l in out.splitlines() if l.strip()]
        assert len(non_empty_lines) >= len(EXPLAIN_KEYS)


# ---------------------------------------------------------------------------
# run_explain — known keys with real locale
# ---------------------------------------------------------------------------

class TestRunExplainKnownKeys:
    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_known_key_shows_title(self, key):
        t = _make_t()
        out = _capture_run_explain(key, t)
        assert "No explanation available" not in out
        # No leaked i18n key paths in output
        assert "explain." not in out

    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_known_key_shows_why_and_how_headers(self, key):
        t = _make_t()
        out = _capture_run_explain(key, t)
        # Profile-variant keys replace "WHY IT IS A RISK" with per-profile sections;
        # all others show the generic header. HOW TO FIX appears in both cases.
        if _has_profile_variants(key, t):
            assert "[ server ]" in out
            assert "HOW TO FIX" in out
        else:
            assert "WHY IT IS A RISK" in out
            assert "HOW TO FIX" in out

    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_known_key_includes_cis_reference(self, key):
        """Every explainable key must show its CIS reference in the output."""
        t = _make_t()
        out = _capture_run_explain(key, t)
        assert "CIS" in out, f"No CIS reference in explain output for {key!r}"

    def test_ssh_password_auth_content(self):
        t = _make_t()
        out = _capture_run_explain("ssh.password_auth", t)
        assert any(w in out.lower() for w in ("brute", "attack", "password"))
        assert "PasswordAuthentication no" in out

    def test_file_perms_normalisation_works(self):
        """file_perms.shadow.world_writable normalises and resolves correctly."""
        t = _make_t()
        out = _capture_run_explain("file_perms.shadow.world_writable", t)
        assert "No explanation available" not in out
        assert "WHY IT IS A RISK" in out

    def test_file_perms_deep_normalisation_works(self):
        """file_perms with multiple middle segments still resolves."""
        t = _make_t()
        out = _capture_run_explain("file_perms.a.b.too_permissive", t)
        assert "No explanation available" not in out
        assert "WHY IT IS A RISK" in out

    def test_updates_security_pending_content(self):
        t = _make_t()
        out = _capture_run_explain("updates.security_pending", t)
        assert any(w in out.lower() for w in ("cve", "vulnerabilit", "patch"))

    def test_hardening_rp_filter_content(self):
        t = _make_t()
        out = _capture_run_explain("hardening.rp_filter_disabled", t)
        assert any(w in out.lower() for w in ("rp_filter", "sysctl", "spoof"))

    def test_ssh_password_auth_snapshot(self):
        """Snapshot-style: password_auth output must contain all key sections."""
        t = _make_t()
        out = _capture_run_explain("ssh.password_auth", t)
        assert "ssh.password_auth" in out          # key in header
        assert "WHY IT IS A RISK" in out
        assert "HOW TO FIX" in out
        assert "CIS" in out
        assert "PasswordAuthentication no" in out
        assert "explain." not in out               # no leaked i18n paths

    # --- content tests ------------------------------------------------

    def test_auditd_not_installed_content(self):
        t = _make_t()
        out = _capture_run_explain("auditd.not_installed", t)
        assert any(w in out.lower() for w in ("audit", "kernel", "forensic"))
        assert "apt install" in out

    def test_auditd_missing_sensitive_rules_is_profile_variant(self):
        t = _make_t()
        out = _capture_run_explain("auditd.missing_sensitive_rules", t)
        assert "[ server ]" in out
        assert "[ desktop ]" in out
        assert "HOW TO FIX" in out

    def test_secure_boot_disabled_is_profile_variant(self):
        t = _make_t()
        out = _capture_run_explain("secure_boot.disabled", t)
        assert "[ server ]" in out
        assert "[ desktop ]" in out
        assert "HOW TO FIX" in out

    def test_secure_boot_setup_mode_content(self):
        t = _make_t()
        out = _capture_run_explain("secure_boot.setup_mode", t)
        assert any(w in out.lower() for w in ("platform key", "setup mode", "bootloader", "bootkit"))
        assert "mokutil" in out

    def test_file_integrity_not_installed_content(self):
        t = _make_t()
        out = _capture_run_explain("file_integrity.not_installed", t)
        assert any(w in out.lower() for w in ("aide", "tripwire", "baseline", "integrity"))
        assert "apt install aide" in out

    def test_file_integrity_check_old_content(self):
        t = _make_t()
        out = _capture_run_explain("file_integrity.check_old", t)
        assert any(w in out.lower() for w in ("check", "aide", "cron"))


# ---------------------------------------------------------------------------
# CLI integration — parse_args
# ---------------------------------------------------------------------------

class TestCLIExplainParsing:
    def test_explain_equals_syntax(self):
        from bob.cli import parse_args
        cfg = parse_args(["--explain=ssh.password_auth"])
        assert cfg.explain_key == "ssh.password_auth"

    def test_explain_space_syntax(self):
        from bob.cli import parse_args
        cfg = parse_args(["--explain", "ssh.password_auth"])
        assert cfg.explain_key == "ssh.password_auth"

    def test_explain_list(self):
        from bob.cli import parse_args
        cfg = parse_args(["--explain=list"])
        assert cfg.explain_key == "list"

    def test_explain_with_lang(self):
        from bob.cli import parse_args
        cfg = parse_args(["--french", "--explain=ssh.password_auth"])
        assert cfg.explain_key == "ssh.password_auth"
        assert cfg.lang == "fr"

    def test_explain_default_is_empty(self):
        from bob.cli import parse_args
        cfg = parse_args([])
        assert cfg.explain_key == ""

    def test_explain_flag_without_value_launches_interactive(self):
        """--explain with no following argument sets __interactive__ sentinel."""
        from bob.cli import parse_args
        cfg = parse_args(["--explain"])
        assert cfg.explain_key == "__interactive__"

    def test_explain_short_flag_without_value_launches_interactive(self):
        """-e with no following argument sets __interactive__ sentinel."""
        from bob.cli import parse_args
        cfg = parse_args(["-e"])
        assert cfg.explain_key == "__interactive__"


# ---------------------------------------------------------------------------
# Profile variant detection — _has_profile_variants
# ---------------------------------------------------------------------------

# Keys known to have profile-specific context
_PROFILE_VARIANT_KEYS = [
    "updates.unattended_not_configured",
    "updates.security_pending",
    "hardening.rp_filter_disabled",
    "hardening.rp_filter_loose",
    "hardening.redirects_enabled",
    "hardening.log_martians_disabled",
    "ipv6.port_no_v6_rule",
    "ipv6.ufw_disabled_listeners_present",
    "memory.swappiness_ssd_wear",
    "memory.swappiness_unjustified",
    "services_state.enabled_inactive",
    "clamav.db_very_outdated",
    "clamav.db_outdated",
    "clamav.scan_very_old",
    "clamav.scan_old",
    "kernel_modules.risky_fs",
    "kernel_modules.risky_net",
]

# Keys that apply uniformly to all profiles (no variants)
_UNIFORM_KEYS = [
    "ssh.password_auth",
    "ssh.permit_root_login",
    "file_perms.world_writable",
    "rules.duplicate_found",
    "disk.smart_failed",
    "password_policy.no_quality_module",
    "user_accounts.uid_zero",
    "samba.smb1_enabled",
]


class TestHasProfileVariants:
    def setup_method(self):
        from bob import i18n
        i18n.init(lang="en")
        self.t = i18n.t

    @pytest.mark.parametrize("key", _PROFILE_VARIANT_KEYS)
    def test_profile_variant_keys_detected(self, key):
        assert _has_profile_variants(key, self.t), (
            f"{key!r} should have profile variants in en.json"
        )

    @pytest.mark.parametrize("key", _UNIFORM_KEYS)
    def test_uniform_keys_not_detected(self, key):
        assert not _has_profile_variants(key, self.t), (
            f"{key!r} should NOT have profile variants (uniform key)"
        )

    def test_mock_t_missing_returns_false(self):
        """With mock t() that returns the key path, non-variant key → False."""
        def _identity_t(k, **_):
            return k
        assert not _has_profile_variants("ssh.password_auth", _identity_t)

    def test_mock_t_variant_returns_true(self):
        """With mock t() that returns a non-key string, key is considered to have variants."""
        def _t(k, **_):
            if k == "explain.hardening.rp_filter_disabled.server.why":
                return "Real translation text"
            return k
        assert _has_profile_variants("hardening.rp_filter_disabled", _t)


# ---------------------------------------------------------------------------
# Profile variant display — run_explain output
# ---------------------------------------------------------------------------

class TestRunExplainProfileVariants:
    def setup_method(self):
        from bob import i18n
        i18n.init(lang="en")
        self.t = i18n.t

    def _capture(self, key):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            run_explain(key, self.t)
        finally:
            sys.stdout = old
        return buf.getvalue()

    def test_profile_key_shows_three_sections(self):
        out = self._capture("hardening.rp_filter_disabled")
        assert "[ server ]" in out
        assert "[ desktop ]" in out
        assert "[ container ]" in out

    def test_profile_key_no_generic_why_header(self):
        """Profile-variant keys must NOT show a generic 'WHY IT IS A RISK' header."""
        out = self._capture("hardening.rp_filter_disabled")
        # The generic header should not appear — replaced by profile sections
        assert "WHY IT IS A RISK" not in out

    def test_profile_key_how_to_fix_in_each_section(self):
        out = self._capture("hardening.rp_filter_disabled")
        assert out.count("HOW TO FIX") == 3

    def test_profile_key_no_uniform_note(self):
        """Profile-variant keys must NOT show the uniform-risk note."""
        out = self._capture("hardening.rp_filter_disabled")
        assert "applies equally" not in out

    def test_container_custom_how_shown(self):
        """Keys with container-specific how should show that text."""
        out = self._capture("hardening.rp_filter_disabled")
        assert "inside the container" in out.lower() or "host" in out.lower()

    def test_updates_server_section_content(self):
        out = self._capture("updates.unattended_not_configured")
        assert "[ server ]" in out
        # Server section should mention server risk
        server_section = out.split("[ server ]")[1].split("[ desktop ]")[0]
        assert any(w in server_section.lower() for w in ("server", "exposed", "attack"))

    def test_updates_desktop_section_content(self):
        out = self._capture("updates.unattended_not_configured")
        desktop_section = out.split("[ desktop ]")[1].split("[ container ]")[0]
        assert any(w in desktop_section.lower() for w in ("desktop", "acceptable", "manual"))

    def test_updates_container_section_content(self):
        out = self._capture("updates.unattended_not_configured")
        container_section = out.split("[ container ]")[1]
        assert any(w in container_section.lower() for w in ("image", "container", "pipeline"))

    @pytest.mark.parametrize("key", _PROFILE_VARIANT_KEYS)
    def test_all_variant_keys_show_three_sections(self, key):
        out = self._capture(key)
        assert "[ server ]" in out
        assert "[ desktop ]" in out
        assert "[ container ]" in out

    @pytest.mark.parametrize("key", _PROFILE_VARIANT_KEYS)
    def test_all_variant_keys_have_no_generic_why(self, key):
        out = self._capture(key)
        assert "WHY IT IS A RISK" not in out


# ---------------------------------------------------------------------------
# Uniform display — uniform keys show generic WHY + note
# ---------------------------------------------------------------------------

class TestRunExplainUniform:
    def setup_method(self):
        from bob import i18n
        i18n.init(lang="en")
        self.t = i18n.t

    def _capture(self, key):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            run_explain(key, self.t)
        finally:
            sys.stdout = old
        return buf.getvalue()

    def test_uniform_key_shows_why_header(self):
        out = self._capture("ssh.password_auth")
        assert "WHY IT IS A RISK" in out

    def test_uniform_key_shows_how_header(self):
        out = self._capture("ssh.password_auth")
        assert "HOW TO FIX" in out

    def test_uniform_key_shows_uniform_note(self):
        out = self._capture("ssh.password_auth")
        assert "applies equally" in out

    def test_uniform_key_no_profile_sections(self):
        out = self._capture("ssh.password_auth")
        assert "[ server ]" not in out
        assert "[ desktop ]" not in out
        assert "[ container ]" not in out

    @pytest.mark.parametrize("key", _UNIFORM_KEYS)
    def test_all_uniform_keys_show_why(self, key):
        out = self._capture(key)
        assert "WHY IT IS A RISK" in out
        assert "HOW TO FIX" in out
