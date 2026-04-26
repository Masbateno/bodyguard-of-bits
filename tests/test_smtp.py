"""
Unit tests for bob.checks.smtp — CHECK 27.

All tests use synthetic SmtpSnapshot instances; no subprocess calls.
"""

import pytest
from bob.checks.smtp import SmtpSnapshot, check_smtp, _LOCAL_BIND_RE
from bob.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_snap(
    installed=False,
    mta_name="",
    listening=False,
    bind_address="",
    exposed=False,
) -> SmtpSnapshot:
    return SmtpSnapshot(
        installed=installed,
        mta_name=mta_name,
        listening=listening,
        bind_address=bind_address,
        exposed=exposed,
    )


def _t(key, **kw):
    """Minimal translation stub — returns key with formatted kwargs."""
    if kw:
        try:
            return key.format(**kw)
        except KeyError:
            return key
    return key


# ---------------------------------------------------------------------------
# SmtpSnapshot defaults
# ---------------------------------------------------------------------------

class TestSmtpSnapshotDefaults:
    def test_defaults(self):
        s = SmtpSnapshot()
        assert not s.installed
        assert s.mta_name == ""
        assert not s.listening
        assert s.bind_address == ""
        assert not s.exposed


# ---------------------------------------------------------------------------
# _LOCAL_BIND_RE
# ---------------------------------------------------------------------------

class TestLocalBindRe:
    def test_loopback_ipv4(self):
        assert _LOCAL_BIND_RE.match("127.0.0.1")

    def test_loopback_ipv6(self):
        assert _LOCAL_BIND_RE.match("::1")

    def test_wildcard_star_is_exposed(self):
        # "*" in ss output means all interfaces — must NOT be treated as local
        assert not _LOCAL_BIND_RE.match("*")

    def test_localhost_string(self):
        assert _LOCAL_BIND_RE.match("localhost")

    def test_all_interfaces_ipv4(self):
        assert not _LOCAL_BIND_RE.match("0.0.0.0")

    def test_all_interfaces_ipv6(self):
        assert not _LOCAL_BIND_RE.match("::")

    def test_private_ip(self):
        assert not _LOCAL_BIND_RE.match("192.168.1.1")

    def test_public_ip(self):
        assert not _LOCAL_BIND_RE.match("203.0.113.5")

    def test_ipv6_loopback_bracketed(self):
        # [::1] after bracket-stripping → ::1 → local
        assert _LOCAL_BIND_RE.match("::1".strip("[]"))

    def test_ipv6_any_bracketed(self):
        # [::] after bracket-stripping → :: → exposed
        assert not _LOCAL_BIND_RE.match("::".strip("[]"))


# ---------------------------------------------------------------------------
# check_smtp — not installed
# ---------------------------------------------------------------------------

class TestSmtpNotInstalled:
    def test_ok_finding(self):
        snap = make_snap()
        result = check_smtp(snap, t=_t)
        levels = [f.level for f in result.findings]
        assert FindingLevel.OK in levels

    def test_key(self):
        snap = make_snap()
        result = check_smtp(snap, t=_t)
        keys = [f.key for f in result.findings]
        assert "smtp.not_installed" in keys

    def test_no_deduction(self):
        snap = make_snap()
        result = check_smtp(snap, t=_t)
        assert result.deductions == []


# ---------------------------------------------------------------------------
# check_smtp — installed, not listening
# ---------------------------------------------------------------------------

class TestSmtpInstalledNotListening:
    def test_info_finding(self):
        snap = make_snap(installed=True, mta_name="postfix", listening=False)
        result = check_smtp(snap, t=_t)
        levels = [f.level for f in result.findings]
        assert FindingLevel.INFO in levels

    def test_key(self):
        snap = make_snap(installed=True, mta_name="postfix", listening=False)
        result = check_smtp(snap, t=_t)
        keys = [f.key for f in result.findings]
        assert "smtp.installed_not_listening" in keys

    def test_no_deduction(self):
        snap = make_snap(installed=True, mta_name="postfix", listening=False)
        result = check_smtp(snap, t=_t)
        assert result.deductions == []

    def test_mta_name_used(self):
        # Verify a finding is produced — mta param forwarded (no crash)
        snap = make_snap(installed=True, mta_name="exim4", listening=False)
        result = check_smtp(snap, t=_t)
        keys = [f.key for f in result.findings]
        assert "smtp.installed_not_listening" in keys


# ---------------------------------------------------------------------------
# check_smtp — listening on localhost (safe)
# ---------------------------------------------------------------------------

class TestSmtpLocalOnly:
    def test_info_finding(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="127.0.0.1", exposed=False)
        result = check_smtp(snap, t=_t)
        levels = [f.level for f in result.findings]
        assert FindingLevel.INFO in levels

    def test_key(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="127.0.0.1", exposed=False)
        result = check_smtp(snap, t=_t)
        keys = [f.key for f in result.findings]
        assert "smtp.local_only" in keys

    def test_no_deduction(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="127.0.0.1", exposed=False)
        result = check_smtp(snap, t=_t)
        assert result.deductions == []

    def test_only_one_finding(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="127.0.0.1", exposed=False)
        result = check_smtp(snap, t=_t)
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# check_smtp — exposed on all interfaces
# ---------------------------------------------------------------------------

class TestSmtpExposed:
    def test_warn_finding(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        levels = [f.level for f in result.findings]
        assert FindingLevel.WARN in levels

    def test_key(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        keys = [f.key for f in result.findings]
        assert "smtp.exposed" in keys

    def test_deduction_one_point(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        assert len(result.deductions) == 1
        assert result.deductions[0].points == 1

    def test_deduction_key(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        assert result.deductions[0].key == "smtp.exposed"

    def test_deduction_context_public(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        assert result.deductions[0].context == "public"

    def test_nature_improvement(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        warn = [f for f in result.findings if f.level == FindingLevel.WARN][0]
        assert warn.nature == "improvement"

    def test_cmd_present(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        warn = [f for f in result.findings if f.level == FindingLevel.WARN][0]
        assert warn.cmd

    def test_only_one_warn_finding(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warns) == 1

    def test_exim_exposed(self):
        snap = make_snap(installed=True, mta_name="exim4",
                         listening=True, bind_address="::", exposed=True)
        result = check_smtp(snap, t=_t)
        keys = [f.key for f in result.findings]
        assert "smtp.exposed" in keys

    def test_only_one_deduction(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        assert len(result.deductions) == 1


# ---------------------------------------------------------------------------
# check_smtp — fallback mta_name
# ---------------------------------------------------------------------------

class TestSmtpFallbackName:
    def test_empty_mta_name_no_crash(self):
        # Should not crash when mta_name is empty
        snap = make_snap(installed=True, mta_name="",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        keys = [f.key for f in result.findings]
        assert "smtp.exposed" in keys


# ---------------------------------------------------------------------------
# check_smtp — cmd specificity (postfix vs others)
# ---------------------------------------------------------------------------

class TestSmtpCmd:
    def test_postfix_has_cmd(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        warn = [f for f in result.findings if f.level == FindingLevel.WARN][0]
        assert warn.cmd
        assert "postconf" in warn.cmd

    def test_postfix_has_restart_note(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        warn = [f for f in result.findings if f.level == FindingLevel.WARN][0]
        assert warn.note  # restart hint

    def test_exim_no_cmd(self):
        # Exim fix is MTA-specific — no automatable command
        snap = make_snap(installed=True, mta_name="exim4",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        warn = [f for f in result.findings if f.level == FindingLevel.WARN][0]
        assert not warn.cmd

    def test_unknown_mta_no_cmd(self):
        snap = make_snap(installed=True, mta_name="sendmail",
                         listening=True, bind_address="0.0.0.0", exposed=True)
        result = check_smtp(snap, t=_t)
        warn = [f for f in result.findings if f.level == FindingLevel.WARN][0]
        assert not warn.cmd


# ---------------------------------------------------------------------------
# _LOCAL_BIND_RE + _check_port_25 — wildcard and IPv6 edge cases
# ---------------------------------------------------------------------------

class TestSmtpWildcardExposed:
    def test_wildcard_bind_is_exposed(self):
        # "*" in ss means all interfaces — must be treated as exposed
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="*", exposed=True)
        result = check_smtp(snap, t=_t)
        keys = [f.key for f in result.findings]
        assert "smtp.exposed" in keys

    def test_ipv6_any_is_exposed(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="::", exposed=True)
        result = check_smtp(snap, t=_t)
        keys = [f.key for f in result.findings]
        assert "smtp.exposed" in keys

    def test_ipv6_loopback_not_exposed(self):
        snap = make_snap(installed=True, mta_name="postfix",
                         listening=True, bind_address="::1", exposed=False)
        result = check_smtp(snap, t=_t)
        keys = [f.key for f in result.findings]
        assert "smtp.local_only" in keys
        assert "smtp.exposed" not in keys
