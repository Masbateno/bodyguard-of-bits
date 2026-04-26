"""Tests for SSH auth.log login analysis (CHECK 42)."""

from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import patch
from bob.checks.auth_log import (
    AuthLogSnapshot, LoginEntry, check_auth_log,
    _is_private, _estimate_days, _LOG_PATHS, _BRUTE_FORCE_THRESHOLD,
    _read_auth_from_journald,
)
from bob.scoring import FindingLevel


class TestIsPrivate:
    def test_localhost_is_private(self):
        assert _is_private("127.0.0.1")

    def test_lan_192_is_private(self):
        assert _is_private("192.168.1.10")

    def test_lan_10_is_private(self):
        assert _is_private("10.0.0.1")

    def test_lan_172_is_private(self):
        assert _is_private("172.16.5.1")

    def test_public_ip_is_not_private(self):
        assert not _is_private("8.8.8.8")

    def test_another_public_ip(self):
        assert not _is_private("93.184.216.34")

    def test_invalid_returns_true(self):
        # Unparseable IPs are treated as private to avoid alerting on log noise
        assert _is_private("not-an-ip")

    def test_ipv6_loopback_is_private(self):
        assert _is_private("::1")

    def test_ipv6_ula_is_private(self):
        assert _is_private("fd00::1")

    def test_ipv6_link_local_is_private(self):
        assert _is_private("fe80::1")

    def test_ipv6_public_is_not_private(self):
        assert not _is_private("2606:4700:4700::1111")


class TestEstimateDays:
    def test_same_day_returns_one(self):
        text = "Apr 18 10:00:00 host sshd[1]: x\nApr 18 22:00:00 host sshd[1]: y"
        assert _estimate_days(text) == 1

    def test_four_days_span(self):
        text = "Apr 15 10:00:00 host sshd[1]: x\nApr 18 22:00:00 host sshd[1]: y"
        assert _estimate_days(text) == 4

    def test_empty_returns_zero(self):
        assert _estimate_days("") == 0

    def test_no_dates_returns_zero(self):
        assert _estimate_days("no timestamps here\njust plain text") == 0

    def test_month_boundary(self):
        # Mar 30 → Apr 1 = 2 days
        text = "Mar 30 10:00:00 host sshd[1]: x\nApr  1 22:00:00 host sshd[1]: y"
        assert _estimate_days(text) == 2

    def test_year_wrap_short(self):
        # Dec 31 → Jan 2 = 2 days (not 60 — year-wrap formula must not use abs())
        text = "Dec 31 10:00:00 host sshd[1]: x\nJan  2 00:00:00 host sshd[1]: y"
        assert _estimate_days(text) == 2

    def test_year_wrap_full_month(self):
        # Dec 1 → Jan 31 ≈ 61 days
        text = "Dec  1 10:00:00 host sshd[1]: x\nJan 31 22:00:00 host sshd[1]: y"
        assert _estimate_days(text) == 61

    def test_single_line_returns_one(self):
        text = "Apr 18 10:00:00 host sshd[1]: x"
        assert _estimate_days(text) == 1


class TestAuthLogParsing:
    """Tests for raw auth.log line parsing via AuthLogSnapshot.from_text()."""

    _PUBLICKEY_LINE = (
        "Apr 18 10:23:45 server sshd[1234]: "
        "Accepted publickey for so6 from 192.168.1.5 port 54321 ssh2"
    )
    _PASSWORD_LINE = (
        "Apr 18 11:00:00 server sshd[5678]: "
        "Accepted password for admin from 5.6.7.8 port 22222 ssh2"
    )
    _FAILED_PASSWORD_LINE = (
        "Apr 18 09:00:00 server sshd[999]: "
        "Failed password for root from 1.2.3.4 port 11111 ssh2"
    )
    _FAILED_INVALID_USER_LINE = (
        "Apr 18 09:01:00 server sshd[1000]: "
        "Failed password for invalid user hacker from 5.5.5.5 port 12345 ssh2"
    )
    _NOISE_LINE = "Apr 18 10:00:00 server systemd[1]: Started session."

    def test_publickey_line_parsed(self):
        snap = AuthLogSnapshot.from_text(self._PUBLICKEY_LINE)
        assert len(snap.entries) == 1
        e = snap.entries[0]
        assert e.method == "publickey"
        assert e.user == "so6"
        assert e.source == "192.168.1.5"
        assert not e.is_public

    def test_password_line_parsed(self):
        snap = AuthLogSnapshot.from_text(self._PASSWORD_LINE)
        assert len(snap.entries) == 1
        e = snap.entries[0]
        assert e.method == "password"
        assert e.user == "admin"
        assert e.source == "5.6.7.8"
        assert e.is_public

    def test_failed_password_counted(self):
        snap = AuthLogSnapshot.from_text(self._FAILED_PASSWORD_LINE)
        assert snap.entries == []
        assert snap.failed_count == 1

    def test_failed_invalid_user_counted(self):
        snap = AuthLogSnapshot.from_text(self._FAILED_INVALID_USER_LINE)
        assert snap.entries == []
        assert snap.failed_count == 1

    def test_noise_lines_ignored(self):
        snap = AuthLogSnapshot.from_text(self._NOISE_LINE)
        assert snap.entries == []
        assert snap.failed_count == 0

    def test_mixed_log_only_accepted_in_entries(self):
        text = "\n".join([
            self._PUBLICKEY_LINE,
            self._FAILED_PASSWORD_LINE,
            self._NOISE_LINE,
            self._PASSWORD_LINE,
        ])
        snap = AuthLogSnapshot.from_text(text)
        assert len(snap.entries) == 2
        assert snap.failed_count == 1

    def test_multiple_logins_same_ip(self):
        text = "\n".join([self._PUBLICKEY_LINE] * 3)
        snap = AuthLogSnapshot.from_text(text)
        assert len(snap.entries) == 3
        assert all(e.source == "192.168.1.5" for e in snap.entries)

    def test_from_text_log_available_true(self):
        snap = AuthLogSnapshot.from_text(self._PUBLICKEY_LINE)
        assert snap.log_available

    def test_from_text_empty_log_available_true(self):
        snap = AuthLogSnapshot.from_text("")
        assert snap.log_available

    def test_malformed_line_ignored(self):
        text = "Apr 18 10:00:00 server sshd[1]: Accepted for incomplete line"
        snap = AuthLogSnapshot.from_text(text)
        assert snap.entries == []

    def test_line_with_ssh_key_fingerprint_parsed(self):
        # Real-world format: "...ssh2: RSA SHA256:xxxxx" after port number
        text = (
            "Apr 18 10:23:45 server sshd[1234]: "
            "Accepted publickey for so6 from 192.168.1.5 port 54321 ssh2: RSA SHA256:AAAA/bbbb+cccc"
        )
        snap = AuthLogSnapshot.from_text(text)
        assert len(snap.entries) == 1
        assert snap.entries[0].source == "192.168.1.5"

    def test_days_analysed_from_text(self):
        text = "Apr 15 10:00:00 server sshd[1]: x\n" + self._PUBLICKEY_LINE
        snap = AuthLogSnapshot.from_text(text)
        assert snap.days_analysed == 4

    def test_volume_10k_lines(self):
        # Parser must not crash or stall on large input
        line = self._PUBLICKEY_LINE + "\n"
        failed_line = self._FAILED_PASSWORD_LINE + "\n"
        text = (line * 5000) + (failed_line * 5000)
        snap = AuthLogSnapshot.from_text(text)
        assert len(snap.entries) == 5000
        assert snap.failed_count == 5000


class TestCheckAuthLog:
    def _snap_with(self, entries, log_available=True, days=7, failed_count=0):
        return AuthLogSnapshot(
            entries=entries,
            log_available=log_available,
            days_analysed=days,
            failed_count=failed_count,
        )

    def test_log_not_available_is_info(self):
        result = check_auth_log(self._snap_with([], log_available=False))
        assert result.findings[0].level == FindingLevel.INFO
        assert result.findings[0].key == "auth_log.not_available"

    def test_no_logins_is_ok(self):
        result = check_auth_log(self._snap_with([], days=7))
        assert result.findings[0].level == FindingLevel.OK
        assert result.findings[0].key == "auth_log.no_logins"

    def test_no_logins_days_zero_is_ok(self):
        # days=0 means log exists but no analyzable date range (e.g. empty log after rotation)
        result = check_auth_log(self._snap_with([], days=0))
        assert result.findings[0].level == FindingLevel.OK
        assert result.findings[0].key == "auth_log.no_logins"

    def test_no_logins_days_zero_message_has_no_zero(self):
        # "0 dernier(s) jour(s)" must not appear — use the no_range key instead
        def _fmt(key, **kw): return f"{key}:{kw}"
        result = check_auth_log(self._snap_with([], days=0), t=_fmt)
        msg = result.findings[0].message
        assert "no_logins_no_range" in msg
        assert "no_logins:" not in msg  # the {days} version must not be chosen

    def test_local_logins_only_no_warn(self):
        entries = [LoginEntry("publickey", "so6", "192.168.1.5", is_public=False)]
        result = check_auth_log(self._snap_with(entries))
        levels = [f.level for f in result.findings]
        assert FindingLevel.WARN not in levels

    def test_public_login_warns(self):
        entries = [LoginEntry("publickey", "so6", "8.8.8.8", is_public=True)]
        result = check_auth_log(self._snap_with(entries))
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warns) == 1
        assert warns[0].key == "auth_log.public_login"

    def test_public_login_no_deduction(self):
        entries = [LoginEntry("publickey", "so6", "8.8.8.8", is_public=True)]
        result = check_auth_log(self._snap_with(entries))
        assert not result.deductions

    def test_summary_info_present(self):
        entries = [LoginEntry("publickey", "so6", "192.168.1.1", is_public=False)]
        result = check_auth_log(self._snap_with(entries))
        infos = [f for f in result.findings if f.level == FindingLevel.INFO]
        assert any(f.key == "auth_log.summary" for f in infos)

    def test_public_login_check_cmd(self):
        entries = [LoginEntry("publickey", "root", "5.6.7.8", is_public=True)]
        result = check_auth_log(self._snap_with(entries))
        warn = next(f for f in result.findings if f.level == FindingLevel.WARN)
        assert warn.cmd_type == "check"
        assert "auth.log" in warn.cmd

    def test_multiple_public_ips_single_warn(self):
        entries = [
            LoginEntry("publickey", "so6", "1.2.3.4", is_public=True),
            LoginEntry("password", "so6", "5.6.7.8", is_public=True),
            LoginEntry("publickey", "root", "9.10.11.12", is_public=True),
        ]
        result = check_auth_log(self._snap_with(entries))
        warns = [f for f in result.findings if f.key == "auth_log.public_login"]
        assert len(warns) == 1

    def test_many_logins_same_public_ip_single_warn(self):
        entries = [LoginEntry("publickey", "so6", "8.8.8.8", is_public=True)] * 10
        result = check_auth_log(self._snap_with(entries))
        warns = [f for f in result.findings if f.key == "auth_log.public_login"]
        assert len(warns) == 1

    def test_password_auth_from_public_captured(self):
        text = (
            "Apr 18 11:00:00 server sshd[5678]: "
            "Accepted password for admin from 5.6.7.8 port 22222 ssh2"
        )
        snap = AuthLogSnapshot.from_text(text)
        result = check_auth_log(snap)
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warns) == 1

    def test_brute_force_below_threshold_no_warn(self):
        result = check_auth_log(self._snap_with([], failed_count=_BRUTE_FORCE_THRESHOLD - 1))
        keys = [f.key for f in result.findings]
        assert "auth_log.brute_force" not in keys

    def test_brute_force_at_threshold_warns(self):
        result = check_auth_log(self._snap_with([], failed_count=_BRUTE_FORCE_THRESHOLD))
        warns = [f for f in result.findings if f.key == "auth_log.brute_force"]
        assert len(warns) == 1

    def test_brute_force_no_deduction(self):
        result = check_auth_log(self._snap_with([], failed_count=_BRUTE_FORCE_THRESHOLD))
        assert not result.deductions

    def test_brute_force_cmd_references_fail2ban(self):
        result = check_auth_log(self._snap_with([], failed_count=_BRUTE_FORCE_THRESHOLD))
        warn = next(f for f in result.findings if f.key == "auth_log.brute_force")
        assert "fail2ban" in warn.cmd

    def test_brute_force_and_public_login_both_warn(self):
        entries = [LoginEntry("password", "root", "8.8.8.8", is_public=True)]
        result = check_auth_log(self._snap_with(entries, failed_count=_BRUTE_FORCE_THRESHOLD))
        warn_keys = {f.key for f in result.findings if f.level == FindingLevel.WARN}
        assert "auth_log.public_login" in warn_keys
        assert "auth_log.brute_force" in warn_keys

    def test_mix_local_and_public_logins(self):
        # Summary present AND warn present when mix of local + public
        entries = [
            LoginEntry("publickey", "so6", "192.168.1.1", is_public=False),
            LoginEntry("publickey", "so6", "8.8.8.8", is_public=True),
        ]
        result = check_auth_log(self._snap_with(entries))
        keys = [f.key for f in result.findings]
        assert "auth_log.summary" in keys
        assert "auth_log.public_login" in keys

    def test_top_3_ips_in_summary(self):
        # Counter.most_common(3) — summary message must contain top IPs
        # Pass a formatting t() so the message is interpolated, not just a key
        def _fmt(key, **kw): return str(kw)
        entries = [
            LoginEntry("publickey", "so6", "10.0.0.1", is_public=False),
            LoginEntry("publickey", "so6", "10.0.0.1", is_public=False),
            LoginEntry("publickey", "so6", "10.0.0.1", is_public=False),  # 3x top
            LoginEntry("publickey", "so6", "10.0.0.2", is_public=False),
            LoginEntry("publickey", "so6", "10.0.0.2", is_public=False),  # 2x
            LoginEntry("publickey", "so6", "10.0.0.3", is_public=False),  # 1x
            LoginEntry("publickey", "so6", "10.0.0.4", is_public=False),  # 1x — outside top-3
        ]
        result = check_auth_log(self._snap_with(entries), t=_fmt)
        summary = next(f for f in result.findings if f.key == "auth_log.summary")
        assert "10.0.0.1" in summary.message
        assert "10.0.0.2" in summary.message
        assert "10.0.0.3" in summary.message
        assert "10.0.0.4" not in summary.message  # 4th IP must NOT appear

    def test_invalid_ip_in_log_not_flagged_as_public(self):
        # Unparseable IPs must be treated as private — no false-positive WARN
        entries = [LoginEntry("publickey", "so6", "not-an-ip", is_public=not _is_private("not-an-ip"))]
        result = check_auth_log(self._snap_with(entries))
        warns = [f for f in result.findings if f.key == "auth_log.public_login"]
        assert len(warns) == 0


class TestAuthLogSnapshotMocked:
    """Tests using tmp_path to avoid real /var/log/auth.log dependency."""

    _PUBLICKEY_LINE = (
        "Apr 18 10:23:45 server sshd[1234]: "
        "Accepted publickey for so6 from 192.168.1.5 port 54321 ssh2\n"
    )
    _FAILED_LINE = (
        "Apr 18 09:00:00 server sshd[999]: "
        "Failed password for root from 1.2.3.4 port 11111 ssh2\n"
    )

    def test_from_system_reads_injected_log(self, tmp_path, monkeypatch):
        log = tmp_path / "auth.log"
        log.write_text(self._PUBLICKEY_LINE * 3)
        monkeypatch.setattr("bob.checks.auth_log._LOG_PATHS", [log])
        snap = AuthLogSnapshot.from_system()
        assert snap.log_available
        assert len(snap.entries) == 3

    def test_from_system_failed_count(self, tmp_path, monkeypatch):
        log = tmp_path / "auth.log"
        log.write_text(self._FAILED_LINE * 10)
        monkeypatch.setattr("bob.checks.auth_log._LOG_PATHS", [log])
        snap = AuthLogSnapshot.from_system()
        assert snap.failed_count == 10

    def test_from_system_no_log_unavailable(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.checks.auth_log._LOG_PATHS", [tmp_path / "missing.log"])
        with patch("bob.checks.auth_log._read_auth_from_journald", return_value=""):
            snap = AuthLogSnapshot.from_system()
        assert not snap.log_available
        assert snap.entries == []

    def test_from_system_unreadable_log(self, tmp_path, monkeypatch):
        log = tmp_path / "auth.log"
        log.write_text(self._PUBLICKEY_LINE)
        log.chmod(0o000)
        try:
            monkeypatch.setattr("bob.checks.auth_log._LOG_PATHS", [log])
            with patch("bob.checks.auth_log._read_auth_from_journald", return_value=""):
                snap = AuthLogSnapshot.from_system()
            assert not snap.log_available
        finally:
            log.chmod(0o644)


class TestAuthLogSnapshotFromSystem:
    def test_returns_snapshot(self):
        snap = AuthLogSnapshot.from_system()
        assert isinstance(snap, AuthLogSnapshot)

    def test_entries_are_login_entries(self):
        snap = AuthLogSnapshot.from_system()
        for e in snap.entries:
            assert isinstance(e, LoginEntry)
            assert e.source

    def test_days_analysed_non_negative(self):
        snap = AuthLogSnapshot.from_system()
        assert snap.days_analysed >= 0

    def test_is_public_consistent_with_source(self):
        snap = AuthLogSnapshot.from_system()
        for e in snap.entries:
            assert e.is_public == (not _is_private(e.source))

    def test_method_is_non_empty_string(self):
        snap = AuthLogSnapshot.from_system()
        for e in snap.entries:
            assert isinstance(e.method, str) and e.method

    def test_failed_count_non_negative(self):
        snap = AuthLogSnapshot.from_system()
        assert snap.failed_count >= 0


# ---------------------------------------------------------------------------
# journald fallback
# ---------------------------------------------------------------------------

_JOURNALD_AUTH_SAMPLE = (
    "Apr 18 10:23:45 debian13vm sshd[1234]: "
    "Accepted publickey for so6 from 192.168.1.10 port 54321 ssh2: "
    "RSA SHA256:abc123\n"
    "Apr 18 10:30:00 debian13vm sshd[1235]: "
    "Failed password for root from 5.6.7.8 port 22222 ssh2\n"
)


class TestReadAuthFromJournald:
    def test_returns_content_on_success(self):
        import subprocess
        mock_result = type("R", (), {"returncode": 0, "stdout": _JOURNALD_AUTH_SAMPLE})()
        with patch("subprocess.run", return_value=mock_result):
            content = _read_auth_from_journald()
        assert "Accepted" in content

    def test_returns_empty_on_exception(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            content = _read_auth_from_journald()
        assert content == ""

    def test_returns_empty_on_nonzero_returncode(self):
        mock_result = type("R", (), {"returncode": 1, "stdout": ""})()
        with patch("subprocess.run", return_value=mock_result):
            content = _read_auth_from_journald()
        assert content == ""


class TestFromSystemJournaldFallback:
    def test_journald_used_when_no_auth_log(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.checks.auth_log._LOG_PATHS", [tmp_path / "missing.log"])
        with patch("bob.checks.auth_log._read_auth_from_journald",
                   return_value=_JOURNALD_AUTH_SAMPLE):
            snap = AuthLogSnapshot.from_system()
        assert snap.log_available
        assert len(snap.entries) == 1
        assert snap.entries[0].user == "so6"

    def test_journald_failed_count_parsed(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.checks.auth_log._LOG_PATHS", [tmp_path / "missing.log"])
        with patch("bob.checks.auth_log._read_auth_from_journald",
                   return_value=_JOURNALD_AUTH_SAMPLE):
            snap = AuthLogSnapshot.from_system()
        assert snap.failed_count == 1

    def test_journald_empty_returns_unavailable(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.checks.auth_log._LOG_PATHS", [tmp_path / "missing.log"])
        with patch("bob.checks.auth_log._read_auth_from_journald", return_value=""):
            snap = AuthLogSnapshot.from_system()
        assert not snap.log_available

    def test_file_preferred_over_journald(self, tmp_path, monkeypatch):
        log = tmp_path / "auth.log"
        log.write_text(_JOURNALD_AUTH_SAMPLE)
        monkeypatch.setattr("bob.checks.auth_log._LOG_PATHS", [log])
        with patch("bob.checks.auth_log._read_auth_from_journald") as mock_jd:
            snap = AuthLogSnapshot.from_system()
        mock_jd.assert_not_called()
        assert snap.log_available
