"""Tests for system umask check (CHECK 41)."""

from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import patch
from bob.checks.umask import (
    UmaskSnapshot, check_umask, _fix_cmd,
    _LOGIN_DEFS_RE, _PAM_UMASK_RE, _UMASK_RE, _PAM_UMASK_NOARG_RE,
    _get_proc_umask,
)
from bob.scoring import FindingLevel


def _snap(umask: str | None, source: str = "/etc/login.defs") -> UmaskSnapshot:
    return UmaskSnapshot(umask_value=umask, source=source if umask else None)


class TestCheckUmask:
    # --- secure values: OK ---

    def test_022_is_ok(self):
        assert check_umask(_snap("022")).findings[0].level == FindingLevel.OK

    def test_027_is_ok(self):
        assert check_umask(_snap("027")).findings[0].level == FindingLevel.OK

    def test_077_is_ok(self):
        assert check_umask(_snap("077")).findings[0].level == FindingLevel.OK

    def test_022_no_deduction(self):
        assert not check_umask(_snap("022")).deductions

    # --- 002: WARN -1 (group-writable) ---

    def test_002_warns(self):
        assert check_umask(_snap("002")).findings[0].level == FindingLevel.WARN

    def test_002_deducts_1(self):
        assert sum(d.points for d in check_umask(_snap("002")).deductions) == 1

    def test_002_has_fix_cmd(self):
        assert check_umask(_snap("002")).findings[0].cmd != ""

    # --- 000: ALERT -2 (world-writable) ---

    def test_000_alerts(self):
        assert check_umask(_snap("000")).findings[0].level == FindingLevel.ALERT

    def test_000_deducts_2(self):
        assert sum(d.points for d in check_umask(_snap("000")).deductions) == 2

    def test_000_has_fix_cmd(self):
        assert check_umask(_snap("000")).findings[0].cmd != ""

    # --- None: INFO (not found) ---

    def test_not_found_is_info(self):
        assert check_umask(_snap(None)).findings[0].level == FindingLevel.INFO

    def test_not_found_key(self):
        assert check_umask(_snap(None)).findings[0].key == "umask.not_found"

    def test_not_found_no_deduction(self):
        assert not check_umask(_snap(None)).deductions

    # --- atypical / non-standard: INFO ---

    def test_unusual_octal_is_info(self):
        assert check_umask(_snap("013")).findings[0].level == FindingLevel.INFO

    def test_unusual_key(self):
        assert check_umask(_snap("013")).findings[0].key == "umask.unusual"

    def test_unusual_no_deduction(self):
        assert not check_umask(_snap("013")).deductions

    # --- keys ---

    def test_keys_set(self):
        assert check_umask(_snap("022")).findings[0].key == "umask.ok"
        assert check_umask(_snap("002")).findings[0].key == "umask.group_writable"
        assert check_umask(_snap("000")).findings[0].key == "umask.world_writable"
        assert check_umask(_snap(None)).findings[0].key == "umask.not_found"

    # --- parsing edge cases: invalid / malformed values → INFO ---

    def test_non_octal_digits_is_info(self):
        # "999" contains 9 which is not octal — treat as unusual, not a crash
        assert check_umask(_snap("999")).findings[0].level == FindingLevel.INFO

    def test_alphabetic_value_is_info(self):
        assert check_umask(_snap("abc")).findings[0].level == FindingLevel.INFO

    def test_two_digit_value_is_info(self):
        # "22" is too short to be a canonical umask
        assert check_umask(_snap("22")).findings[0].level == FindingLevel.INFO

    def test_four_digit_value_is_info(self):
        # "0022" is 4 digits — not in the known-OK set
        assert check_umask(_snap("0022")).findings[0].level == FindingLevel.INFO

    def test_empty_string_value_is_info(self):
        assert check_umask(_snap("")).findings[0].level == FindingLevel.INFO


class TestUmaskRegexParsing:
    """Direct tests of the module-level regexes used by from_system()."""

    def test_login_defs_umask_022(self):
        m = _LOGIN_DEFS_RE.search("# /etc/login.defs\nUMASK\t\t022\n")
        assert m and m.group(1) == "022"

    def test_login_defs_umask_0022(self):
        m = _LOGIN_DEFS_RE.search("UMASK 0022\n")
        assert m and m.group(1) == "0022"

    def test_login_defs_case_insensitive(self):
        m = _LOGIN_DEFS_RE.search("umask 027\n")
        assert m and m.group(1) == "027"

    def test_pam_umask_inline(self):
        line = "session optional pam_umask.so umask=027\n"
        m = _PAM_UMASK_RE.search(line)
        assert m and m.group(1) == "027"

    def test_shell_umask_builtin(self):
        m = _UMASK_RE.search("# system profile\numask 022\n")
        assert m and m.group(1) == "022"

    def test_shell_umask_uppercase(self):
        m = _UMASK_RE.search("UMASK 027\n")
        assert m and m.group(1) == "027"

    def test_shell_umask_not_matched_in_comment(self):
        m = _UMASK_RE.search("# umask 022\n")
        assert m is None

    def test_shell_umask_not_matched_in_indented_comment(self):
        # Leading whitespace before # must also be excluded
        m = _UMASK_RE.search("   # umask 000\n")
        assert m is None

    def test_shell_umask_matched_with_leading_spaces(self):
        # Indented umask (e.g. inside an if block) must still match
        m = _UMASK_RE.search("    umask 022\n")
        assert m and m.group(1) == "022"


class TestUmaskSnapshotFromSystemMocked:
    """Inject tmp_path files — zero dependency on real /etc files."""

    def test_login_defs_wins(self, tmp_path):
        ld = tmp_path / "login.defs"
        ld.write_text("UMASK\t\t027\n")
        profile = tmp_path / "profile"
        profile.write_text("umask 022\n")
        snap = UmaskSnapshot.from_system(
            _login_defs=ld,
            _pam_session=tmp_path / "missing",
            _profile=profile,
            _bash_bashrc=tmp_path / "missing2",
            _profile_d=tmp_path / "profile.d",
        )
        assert snap.umask_value == "027"
        assert "login.defs" in snap.source

    def test_fallback_to_profile(self, tmp_path):
        profile = tmp_path / "profile"
        profile.write_text("umask 022\n")
        snap = UmaskSnapshot.from_system(
            _login_defs=tmp_path / "missing",
            _pam_session=tmp_path / "missing2",
            _profile=profile,
            _bash_bashrc=tmp_path / "missing3",
            _profile_d=tmp_path / "profile.d",
        )
        assert snap.umask_value == "022"
        assert "profile" in snap.source

    def test_fallback_to_profile_d(self, tmp_path):
        profile_d = tmp_path / "profile.d"
        profile_d.mkdir()
        (profile_d / "umask.sh").write_text("umask 027\n")
        snap = UmaskSnapshot.from_system(
            _login_defs=tmp_path / "missing",
            _pam_session=tmp_path / "missing2",
            _profile=tmp_path / "missing3",
            _bash_bashrc=tmp_path / "missing4",
            _profile_d=profile_d,
        )
        assert snap.umask_value == "027"

    def test_no_sources_returns_none(self, tmp_path):
        with patch("bob.checks.umask._get_proc_umask", return_value=None):
            snap = UmaskSnapshot.from_system(
                _login_defs=tmp_path / "m1",
                _pam_session=tmp_path / "m2",
                _profile=tmp_path / "m3",
                _bash_bashrc=tmp_path / "m4",
                _profile_d=tmp_path / "profile.d",
            )
        assert snap.umask_value is None
        assert snap.source is None

    def test_login_defs_0022_normalizes_to_022(self, tmp_path):
        ld = tmp_path / "login.defs"
        ld.write_text("UMASK\t\t0022\n")
        snap = UmaskSnapshot.from_system(
            _login_defs=ld,
            _pam_session=tmp_path / "m",
            _profile=tmp_path / "m2",
            _bash_bashrc=tmp_path / "m3",
            _profile_d=tmp_path / "pd",
        )
        assert snap.umask_value == "022"

    def test_pam_session_used_when_login_defs_missing(self, tmp_path):
        pam = tmp_path / "common-session"
        pam.write_text("session optional pam_umask.so umask=027\n")
        snap = UmaskSnapshot.from_system(
            _login_defs=tmp_path / "missing",
            _pam_session=pam,
            _profile=tmp_path / "m",
            _bash_bashrc=tmp_path / "m2",
            _profile_d=tmp_path / "pd",
        )
        assert snap.umask_value == "027"

    def test_all_sources_populated(self, tmp_path):
        ld = tmp_path / "login.defs"
        ld.write_text("UMASK\t\t022\n")
        profile = tmp_path / "profile"
        profile.write_text("umask 027\n")
        snap = UmaskSnapshot.from_system(
            _login_defs=ld,
            _pam_session=tmp_path / "missing",
            _profile=profile,
            _bash_bashrc=tmp_path / "missing2",
            _profile_d=tmp_path / "profile.d",
        )
        assert str(ld) in snap.all_sources
        assert str(profile) in snap.all_sources
        assert snap.all_sources[str(ld)] == "022"
        assert snap.all_sources[str(profile)] == "027"

    def test_all_sources_empty_when_no_files(self, tmp_path):
        snap = UmaskSnapshot.from_system(
            _login_defs=tmp_path / "m1",
            _pam_session=tmp_path / "m2",
            _profile=tmp_path / "m3",
            _bash_bashrc=tmp_path / "m4",
            _profile_d=tmp_path / "pd",
        )
        assert snap.all_sources == {}


class TestFixCmd:
    def test_login_defs_source(self):
        cmd = _fix_cmd("/etc/login.defs")
        assert "/etc/login.defs" in cmd
        assert "UMASK" in cmd

    def test_pam_source_targets_pam_file(self):
        cmd = _fix_cmd("/etc/pam.d/common-session")
        assert "/etc/pam.d/common-session" in cmd
        assert "umask=" in cmd

    def test_profile_source_targets_profile(self):
        cmd = _fix_cmd("/etc/profile")
        assert "/etc/profile" in cmd

    def test_bash_bashrc_source(self):
        cmd = _fix_cmd("/etc/bash.bashrc")
        assert "/etc/bash.bashrc" in cmd

    def test_none_source_defaults_to_login_defs(self):
        cmd = _fix_cmd(None)
        assert "/etc/login.defs" in cmd

    def test_profile_d_source(self):
        cmd = _fix_cmd("/etc/profile.d/umask.sh")
        assert "/etc/profile.d/umask.sh" in cmd


class TestCheckUmaskConflict:
    def _snap_multi(self, sources: dict[str, str]) -> UmaskSnapshot:
        first_src, first_val = next(iter(sources.items()))
        return UmaskSnapshot(
            umask_value=first_val,
            source=first_src,
            all_sources=sources,
        )

    def test_conflict_detected_as_info(self):
        snap = self._snap_multi({
            "/etc/login.defs": "022",
            "/etc/profile": "002",
        })
        result = check_umask(snap)
        keys = [f.key for f in result.findings]
        assert "umask.multiple_definitions" in keys

    def test_no_conflict_when_same_values(self):
        snap = self._snap_multi({
            "/etc/login.defs": "022",
            "/etc/profile": "022",
        })
        result = check_umask(snap)
        keys = [f.key for f in result.findings]
        assert "umask.multiple_definitions" not in keys

    def test_conflict_is_info_not_warn(self):
        snap = self._snap_multi({
            "/etc/login.defs": "022",
            "/etc/pam.d/common-session": "077",
        })
        result = check_umask(snap)
        conflict = next(f for f in result.findings if f.key == "umask.multiple_definitions")
        assert conflict.level == FindingLevel.INFO

    def test_conflict_no_deduction(self):
        snap = self._snap_multi({
            "/etc/login.defs": "022",
            "/etc/profile": "000",
        })
        # deductions come from primary value (022 → 0pts), not from conflict INFO
        result = check_umask(snap)
        assert not result.deductions

    def test_conflict_coexists_with_primary_finding(self):
        # Primary is 002 (WARN) AND conflict is detected → both findings present
        snap = self._snap_multi({
            "/etc/login.defs": "002",
            "/etc/profile": "022",
        })
        result = check_umask(snap)
        keys = [f.key for f in result.findings]
        assert "umask.group_writable" in keys
        assert "umask.multiple_definitions" in keys


class TestUmaskSnapshotFromSystem:
    def test_returns_snapshot(self):
        snap = UmaskSnapshot.from_system()
        assert isinstance(snap, UmaskSnapshot)

    def test_umask_value_is_3_digits_or_none(self):
        snap = UmaskSnapshot.from_system()
        if snap.umask_value is not None:
            assert len(snap.umask_value) == 3
            assert snap.umask_value.isdigit()

    def test_source_set_when_value_found(self):
        snap = UmaskSnapshot.from_system()
        if snap.umask_value is not None:
            assert snap.source is not None
            assert snap.source.startswith("/")

    def test_source_none_when_value_none(self):
        snap = UmaskSnapshot.from_system()
        if snap.umask_value is None:
            assert snap.source is None


# ---------------------------------------------------------------------------
# _PAM_UMASK_NOARG_RE
# ---------------------------------------------------------------------------

class TestPamUmaskNoargRe:
    def test_matches_plain_pam_umask(self):
        line = "session optional pam_umask.so\n"
        assert _PAM_UMASK_NOARG_RE.search(line)

    def test_matches_required_pam_umask(self):
        line = "session required pam_umask.so\n"
        assert _PAM_UMASK_NOARG_RE.search(line)

    def test_no_match_when_inline_umask(self):
        line = "session optional pam_umask.so umask=027\n"
        assert not _PAM_UMASK_NOARG_RE.search(line)

    def test_no_match_when_commented(self):
        line = "# session optional pam_umask.so\n"
        assert not _PAM_UMASK_NOARG_RE.search(line)


# ---------------------------------------------------------------------------
# pam_umask without explicit umask= fallback (Debian 13 scenario)
# ---------------------------------------------------------------------------

class TestUmaskPamNoargFallback:
    def test_pam_noarg_uses_default_022_when_no_login_defs(self, tmp_path):
        pam = tmp_path / "common-session"
        pam.write_text("session optional pam_umask.so\n")
        snap = UmaskSnapshot.from_system(
            _login_defs=tmp_path / "missing",
            _pam_session=pam,
            _profile=tmp_path / "m",
            _bash_bashrc=tmp_path / "m2",
            _profile_d=tmp_path / "pd",
        )
        assert snap.umask_value == "022"
        assert "common-session" in snap.source

    def test_pam_noarg_uses_login_defs_value_when_present(self, tmp_path):
        pam = tmp_path / "common-session"
        pam.write_text("session optional pam_umask.so\n")
        ld = tmp_path / "login.defs"
        ld.write_text("UMASK\t\t027\n")
        snap = UmaskSnapshot.from_system(
            _login_defs=ld,
            _pam_session=pam,
            _profile=tmp_path / "m",
            _bash_bashrc=tmp_path / "m2",
            _profile_d=tmp_path / "pd",
        )
        # login.defs is in candidates first — wins over pam noarg path
        assert snap.umask_value == "027"

    def test_pam_noarg_not_triggered_when_inline_umask_present(self, tmp_path):
        pam = tmp_path / "common-session"
        pam.write_text("session optional pam_umask.so umask=027\n")
        snap = UmaskSnapshot.from_system(
            _login_defs=tmp_path / "missing",
            _pam_session=pam,
            _profile=tmp_path / "m",
            _bash_bashrc=tmp_path / "m2",
            _profile_d=tmp_path / "pd",
        )
        assert snap.umask_value == "027"
        assert snap.source == str(pam)


# ---------------------------------------------------------------------------
# /proc/self/status fallback
# ---------------------------------------------------------------------------

class TestGetProcUmask:
    def test_parses_proc_status(self):
        content = "Name:\tbash\nUmask:\t0022\nState:\tS\n"
        with patch("bob.checks.umask.Path.read_text", return_value=content):
            val = _get_proc_umask()
        assert val == "022"

    def test_returns_none_on_oserror(self):
        with patch("bob.checks.umask.Path.read_text", side_effect=OSError):
            val = _get_proc_umask()
        assert val is None

    def test_returns_none_when_field_absent(self):
        content = "Name:\tbash\nState:\tS\n"
        with patch("bob.checks.umask.Path.read_text", return_value=content):
            val = _get_proc_umask()
        assert val is None


class TestUmaskProcFallback:
    def test_proc_used_when_no_other_source(self, tmp_path):
        with patch("bob.checks.umask._get_proc_umask", return_value="022"):
            snap = UmaskSnapshot.from_system(
                _login_defs=tmp_path / "m1",
                _pam_session=tmp_path / "m2",
                _profile=tmp_path / "m3",
                _bash_bashrc=tmp_path / "m4",
                _profile_d=tmp_path / "pd",
            )
        assert snap.umask_value == "022"
        assert snap.source == "/proc/self/status"

    def test_proc_not_used_when_login_defs_present(self, tmp_path):
        ld = tmp_path / "login.defs"
        ld.write_text("UMASK\t\t027\n")
        with patch("bob.checks.umask._get_proc_umask") as mock_proc:
            snap = UmaskSnapshot.from_system(
                _login_defs=ld,
                _pam_session=tmp_path / "m",
                _profile=tmp_path / "m2",
                _bash_bashrc=tmp_path / "m3",
                _profile_d=tmp_path / "pd",
            )
        mock_proc.assert_not_called()
        assert snap.umask_value == "027"
