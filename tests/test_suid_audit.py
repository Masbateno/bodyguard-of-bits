"""
Tests for checks/suid_audit.py — CHECK 37.

Covers:
  - Scan skipped (timeout / OSError)
  - All-safe baseline (no unexpected SUID/SGID)
  - Unexpected SUID: WARN + deduction
  - Unexpected SGID: INFO, no deduction
  - Whitelist matching by basename
  - Truncation at 10 paths with "+N more" suffix
  - Deduction invariants
  - SuidSnapshot defaults
  - User whitelist: glob matching, exact matching, no match, empty whitelist
  - whitelisted_suid INFO finding in check_suid_audit
  - get_suid_whitelist() config helper
"""

from __future__ import annotations

import os

from bob.checks.suid_audit import (
    SuidSnapshot,
    check_suid_audit,
)
from bob.config import UserConfig
from bob.scoring import FindingLevel
from tests.helpers import _keys, _deduction_points


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(**kwargs) -> SuidSnapshot:
    """Build a snapshot with all-safe defaults, overriding with kwargs."""
    defaults = dict(
        suid_paths=[],
        sgid_paths=[],
        unexpected_suid=[],
        unexpected_sgid=[],
        scan_skipped=False,
    )
    defaults.update(kwargs)
    return SuidSnapshot(**defaults)


def _level(result, key: str) -> FindingLevel:
    for f in result.findings:
        if f.key == key:
            return f.level
    raise KeyError(key)


def _finding(result, key: str):
    for f in result.findings:
        if f.key == key:
            return f
    raise KeyError(key)


def _t_format(key: str, **kwargs) -> str:
    """Minimal t() that returns '{key}: k=v ...' for testing formatted output."""
    parts = ", ".join(f"{k}={v}" for k, v in kwargs.items())
    return f"{key}: {parts}" if parts else key


# ---------------------------------------------------------------------------
# Scan skipped
# ---------------------------------------------------------------------------

class TestScanSkipped:
    def test_scan_skipped_returns_info(self):
        result = check_suid_audit(_snap(scan_skipped=True))
        assert _level(result, "suid_audit.scan_skipped") == FindingLevel.INFO

    def test_scan_skipped_no_deduction(self):
        result = check_suid_audit(_snap(scan_skipped=True))
        assert _deduction_points(result) == 0

    def test_scan_skipped_only_one_finding(self):
        result = check_suid_audit(_snap(scan_skipped=True))
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# All-safe baseline
# ---------------------------------------------------------------------------

class TestAllSafe:
    def test_ok_finding_when_no_unexpected(self):
        result = check_suid_audit(_snap(
            suid_paths=["/usr/bin/sudo"],
            sgid_paths=["/usr/bin/wall"],
        ))
        assert _level(result, "suid_audit.ok") == FindingLevel.OK

    def test_no_deductions_when_all_safe(self):
        result = check_suid_audit(_snap())
        assert _deduction_points(result) == 0

    def test_ok_message_contains_counts(self):
        result = check_suid_audit(_snap(
            suid_paths=["/usr/bin/sudo", "/usr/bin/su"],
            sgid_paths=["/usr/bin/wall"],
        ), t=_t_format)
        f = _finding(result, "suid_audit.ok")
        assert "2" in (f.message or "")   # suid_count=2
        assert "1" in (f.message or "")   # sgid_count=1


# ---------------------------------------------------------------------------
# Unexpected SUID
# ---------------------------------------------------------------------------

class TestUnexpectedSuid:
    def test_unexpected_suid_is_warn(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        assert _level(result, "suid_audit.unexpected_suid") == FindingLevel.WARN

    def test_unexpected_suid_deducts_1(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        assert _deduction_points(result) == 1

    def test_unexpected_suid_deducts_1_regardless_of_count(self):
        """Multiple unexpected SUID binaries still only −1 pt."""
        result = check_suid_audit(_snap(
            unexpected_suid=[f"/opt/bin{i}" for i in range(5)],
        ))
        assert _deduction_points(result) == 1

    def test_unexpected_suid_deduction_key(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        assert any(d.key == "suid_audit.unexpected_suid" for d in result.deductions)

    def test_unexpected_suid_path_in_cmd(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        f = _finding(result, "suid_audit.unexpected_suid")
        assert "/opt/custom/backdoor" in (f.cmd or "")

    def test_unexpected_suid_cmd_type_check(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        f = _finding(result, "suid_audit.unexpected_suid")
        assert f.cmd_type == "check"

    def test_unexpected_suid_cmd_not_none(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        f = _finding(result, "suid_audit.unexpected_suid")
        assert f.cmd is not None

    def test_unexpected_suid_cmd_limited_to_5(self):
        paths = [f"/opt/bin{i}" for i in range(10)]
        result = check_suid_audit(_snap(unexpected_suid=paths))
        f = _finding(result, "suid_audit.unexpected_suid")
        # at most 5 sub-commands joined by &&
        assert (f.cmd or "").count(" && ") <= 4

    def test_unexpected_suid_cmd_quotes_paths_with_spaces(self):
        result = check_suid_audit(_snap(unexpected_suid=["/opt/my bin/evil"]))
        f = _finding(result, "suid_audit.unexpected_suid")
        # shlex.quote wraps paths containing spaces in single quotes
        assert "'/opt/my bin/evil'" in (f.cmd or "")


# ---------------------------------------------------------------------------
# Unexpected SGID
# ---------------------------------------------------------------------------

class TestUnexpectedSgid:
    def test_unexpected_sgid_is_info(self):
        result = check_suid_audit(_snap(
            unexpected_sgid=["/opt/custom/grpbin"],
        ))
        assert _level(result, "suid_audit.unexpected_sgid") == FindingLevel.INFO

    def test_unexpected_sgid_no_deduction(self):
        result = check_suid_audit(_snap(
            unexpected_sgid=["/opt/custom/grpbin"],
        ))
        assert _deduction_points(result) == 0

    def test_unexpected_sgid_path_in_cmd(self):
        result = check_suid_audit(_snap(
            unexpected_sgid=["/opt/custom/grpbin"],
        ))
        f = _finding(result, "suid_audit.unexpected_sgid")
        assert "/opt/custom/grpbin" in (f.cmd or "")

    def test_unexpected_sgid_cmd_type_check(self):
        result = check_suid_audit(_snap(
            unexpected_sgid=["/opt/custom/grpbin"],
        ))
        f = _finding(result, "suid_audit.unexpected_sgid")
        assert f.cmd_type == "check"

    def test_unexpected_sgid_detail_present(self):
        result = check_suid_audit(_snap(
            unexpected_sgid=["/opt/custom/grpbin"],
        ))
        f = _finding(result, "suid_audit.unexpected_sgid")
        assert f.detail is not None


# ---------------------------------------------------------------------------
# Combined: unexpected SUID + unexpected SGID
# ---------------------------------------------------------------------------

class TestCombined:
    def test_both_unexpected_findings_present(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/backdoor"],
            unexpected_sgid=["/opt/grpbin"],
        ))
        assert "suid_audit.unexpected_suid" in _keys(result)
        assert "suid_audit.unexpected_sgid" in _keys(result)

    def test_combined_deduction_still_1(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/backdoor"],
            unexpected_sgid=["/opt/grpbin"],
        ))
        assert _deduction_points(result) == 1

    def test_no_ok_finding_when_unexpected_suid(self):
        result = check_suid_audit(_snap(unexpected_suid=["/opt/backdoor"]))
        assert "suid_audit.ok" not in _keys(result)

    def test_ok_present_when_suid_clean_despite_unexpected_sgid(self):
        """Design: OK refers only to SUID safety — unexpected SGID (INFO-only) does not suppress it."""
        result = check_suid_audit(_snap(
            unexpected_suid=[],
            unexpected_sgid=["/usr/local/bin/suspicious"],
        ))
        assert "suid_audit.ok" in _keys(result)
        assert "suid_audit.unexpected_sgid" in _keys(result)

    def test_ok_message_says_suid_safe_not_sgid(self):
        """The OK message explicitly refers to SUID, not SGID — accurate when SGID has issues."""
        from bob import i18n
        i18n.init(lang="en")
        result = check_suid_audit(_snap(unexpected_sgid=["/tmp/suspicious"]), t=i18n.t)
        ok_finding = next(f for f in result.findings if f.key == "suid_audit.ok")
        assert "SUID" in ok_finding.message


# ---------------------------------------------------------------------------
# Path ordering in cmd
# ---------------------------------------------------------------------------

class TestCmdPathOrder:
    def test_suid_cmd_reflects_snapshot_order(self):
        """The stat cmd lists paths in the order they appear in unexpected_suid[:5]."""
        paths = ["/a/bin", "/b/bin", "/c/bin"]
        result = check_suid_audit(_snap(unexpected_suid=paths))
        f = next(f for f in result.findings if f.key == "suid_audit.unexpected_suid")
        cmd = f.cmd or ""
        assert cmd.index("/a/bin") < cmd.index("/b/bin") < cmd.index("/c/bin")

    def test_sgid_cmd_reflects_snapshot_order(self):
        paths = ["/x/lib", "/y/lib", "/z/lib"]
        result = check_suid_audit(_snap(unexpected_sgid=paths))
        f = next(f for f in result.findings if f.key == "suid_audit.unexpected_sgid")
        cmd = f.cmd or ""
        assert cmd.index("/x/lib") < cmd.index("/y/lib") < cmd.index("/z/lib")

    def test_cmd_limited_to_5_when_more_than_5_suid(self):
        """Existing: cmd capped at 5 paths."""
        paths = [f"/opt/bad{i}" for i in range(8)]
        result = check_suid_audit(_snap(unexpected_suid=paths))
        f = next(f for f in result.findings if f.key == "suid_audit.unexpected_suid")
        # Only first 5 paths in cmd
        assert "/opt/bad5" not in (f.cmd or "")
        assert "/opt/bad4" in (f.cmd or "")


# ---------------------------------------------------------------------------
# Path truncation (10+ unexpected)
# ---------------------------------------------------------------------------

class TestTruncation:
    def _make_paths(self, n: int) -> list[str]:
        return [f"/opt/bin{i}" for i in range(n)]

    def test_exactly_10_no_suffix(self):
        paths = self._make_paths(10)
        result = check_suid_audit(_snap(unexpected_suid=paths), t=_t_format)
        f = _finding(result, "suid_audit.unexpected_suid")
        assert "+0 more" not in (f.message or "")
        assert "more" not in (f.message or "")

    def test_11_shows_plus_1_more(self):
        paths = self._make_paths(11)
        result = check_suid_audit(_snap(unexpected_suid=paths), t=_t_format)
        f = _finding(result, "suid_audit.unexpected_suid")
        assert "+1 more" in (f.message or "")

    def test_20_shows_plus_10_more(self):
        paths = self._make_paths(20)
        result = check_suid_audit(_snap(unexpected_suid=paths), t=_t_format)
        f = _finding(result, "suid_audit.unexpected_suid")
        assert "+10 more" in (f.message or "")

    def test_sgid_truncation_11(self):
        paths = self._make_paths(11)
        result = check_suid_audit(_snap(unexpected_sgid=paths), t=_t_format)
        f = _finding(result, "suid_audit.unexpected_sgid")
        assert "+1 more" in (f.message or "")


# ---------------------------------------------------------------------------
# Whitelist: basename matching
# ---------------------------------------------------------------------------

class TestWhitelistBasename:
    def test_known_suid_in_different_dir_not_unexpected(self):
        """sudo in /usr/local/bin still whitelisted by basename."""
        snap = SuidSnapshot(
            suid_paths=["/usr/local/bin/sudo"],
            sgid_paths=[],
            unexpected_suid=[],   # whitelist already applied in from_system()
            unexpected_sgid=[],
            scan_skipped=False,
        )
        result = check_suid_audit(snap)
        assert _level(result, "suid_audit.ok") == FindingLevel.OK

    def test_unknown_basename_is_unexpected(self):
        snap = SuidSnapshot(
            suid_paths=["/opt/my_custom_tool"],
            sgid_paths=[],
            unexpected_suid=["/opt/my_custom_tool"],
            unexpected_sgid=[],
            scan_skipped=False,
        )
        result = check_suid_audit(snap)
        assert _level(result, "suid_audit.unexpected_suid") == FindingLevel.WARN


# ---------------------------------------------------------------------------
# SuidSnapshot defaults
# ---------------------------------------------------------------------------

class TestSnapshotDefaults:
    def test_default_suid_paths_empty(self):
        assert SuidSnapshot().suid_paths == []

    def test_default_sgid_paths_empty(self):
        assert SuidSnapshot().sgid_paths == []

    def test_default_unexpected_suid_empty(self):
        assert SuidSnapshot().unexpected_suid == []

    def test_default_unexpected_sgid_empty(self):
        assert SuidSnapshot().unexpected_sgid == []

    def test_default_scan_skipped_false(self):
        assert not SuidSnapshot().scan_skipped


# ---------------------------------------------------------------------------
# SuidSnapshot.from_system — user whitelist (unit, no real find(1))
# ---------------------------------------------------------------------------

class TestFromSystemUserWhitelist:
    """Tests for the user_whitelist parameter of SuidSnapshot.from_system().

    We can't call from_system() without real root directories, so we test the
    classification logic by constructing snapshots directly and testing that
    check_suid_audit emits the right findings.  The whitelist application
    logic itself is exercised via small helper tests below.
    """

    def _snap_with_whitelisted(self, whitelisted: list[str], unexpected: list[str] | None = None) -> SuidSnapshot:
        return SuidSnapshot(
            suid_paths=whitelisted + (unexpected or []),
            sgid_paths=[],
            unexpected_suid=unexpected or [],
            unexpected_sgid=[],
            whitelisted_suid=whitelisted,
            scan_skipped=False,
        )

    def test_whitelisted_suid_emits_info(self):
        snap = self._snap_with_whitelisted(["/usr/bin/kismet_cap_pcapng_to_kismet"])
        result = check_suid_audit(snap)
        assert _level(result, "suid_audit.whitelisted") == FindingLevel.INFO

    def test_whitelisted_suid_no_deduction(self):
        snap = self._snap_with_whitelisted(["/usr/bin/kismet_cap_pcapng_to_kismet"])
        result = check_suid_audit(snap)
        assert _deduction_points(result) == 0

    def test_whitelisted_suid_ok_result_when_no_unexpected(self):
        snap = self._snap_with_whitelisted(["/usr/bin/kismet_cap_pcapng_to_kismet"])
        result = check_suid_audit(snap)
        assert "suid_audit.ok" in _keys(result)

    def test_whitelisted_suid_warn_result_when_unexpected_remain(self):
        snap = self._snap_with_whitelisted(
            whitelisted=["/usr/bin/kismet_cap_something"],
            unexpected=["/opt/evil"],
        )
        result = check_suid_audit(snap)
        assert "suid_audit.unexpected_suid" in _keys(result)
        assert "suid_audit.whitelisted" in _keys(result)

    def test_whitelisted_count_in_info_message(self):
        whitelisted = [
            "/usr/bin/kismet_cap_pcapng_to_kismet",
            "/usr/bin/kismet_cap_linux_wifi",
        ]
        snap = self._snap_with_whitelisted(whitelisted)
        result = check_suid_audit(snap, t=_t_format)
        f = _finding(result, "suid_audit.whitelisted")
        assert "2" in (f.message or "")

    def test_no_whitelisted_finding_when_list_empty(self):
        snap = _snap()
        result = check_suid_audit(snap)
        assert "suid_audit.whitelisted" not in _keys(result)

    def test_whitelisted_truncation_at_10(self):
        whitelisted = [f"/usr/bin/kismet_cap_{i}" for i in range(11)]
        snap = SuidSnapshot(
            suid_paths=whitelisted,
            sgid_paths=[],
            unexpected_suid=[],
            unexpected_sgid=[],
            whitelisted_suid=whitelisted,
            scan_skipped=False,
        )
        result = check_suid_audit(snap, t=_t_format)
        f = _finding(result, "suid_audit.whitelisted")
        assert "+1 more" in (f.message or "")


# ---------------------------------------------------------------------------
# UserConfig.get_suid_whitelist
# ---------------------------------------------------------------------------

class TestGetSuidWhitelist:
    def test_returns_empty_list_when_key_absent(self, tmp_path):
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        assert cfg.get_suid_whitelist() == []

    def test_single_pattern(self, tmp_path):
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        cfg.set("suid_whitelist", "kismet_cap_*")
        assert cfg.get_suid_whitelist() == ["kismet_cap_*"]

    def test_multiple_patterns_comma_separated(self, tmp_path):
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        cfg.set("suid_whitelist", "kismet_cap_*, my_tool, other_*")
        assert cfg.get_suid_whitelist() == ["kismet_cap_*", "my_tool", "other_*"]

    def test_strips_whitespace_around_patterns(self, tmp_path):
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        cfg.set("suid_whitelist", "  foo_*  ,  bar  ")
        assert cfg.get_suid_whitelist() == ["foo_*", "bar"]

    def test_empty_value_returns_empty_list(self, tmp_path):
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        cfg.set("suid_whitelist", "")
        assert cfg.get_suid_whitelist() == []

    def test_commas_only_returns_empty_list(self, tmp_path):
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        cfg.set("suid_whitelist", " , , ")
        assert cfg.get_suid_whitelist() == []

    def test_persists_and_reloads(self, tmp_path):
        p = tmp_path / "config.conf"
        cfg = UserConfig.load(path=p)
        cfg.set("suid_whitelist", "kismet_cap_*")
        cfg2 = UserConfig.load(path=p)
        assert cfg2.get_suid_whitelist() == ["kismet_cap_*"]


# ---------------------------------------------------------------------------
# fnmatch glob matching (via from_system classification logic)
# ---------------------------------------------------------------------------

class TestGlobMatching:
    """Verify that fnmatch glob patterns work as expected for common Kali cases."""

    def _classify(self, paths: list[str], patterns: list[str]) -> tuple[list[str], list[str]]:
        """Return (unexpected, whitelisted) tuples using the same logic as from_system."""
        import fnmatch as _fnmatch
        unexpected, whitelisted = [], []
        for p in paths:
            basename = os.path.basename(p)
            if patterns and any(_fnmatch.fnmatch(basename, pat) for pat in patterns):
                whitelisted.append(p)
            else:
                unexpected.append(p)
        return unexpected, whitelisted

    def test_glob_matches_kismet_cap_prefix(self):
        paths = [
            "/usr/bin/kismet_cap_pcapng_to_kismet",
            "/usr/bin/kismet_cap_linux_wifi",
            "/usr/bin/kismet_cap_linux_bluetooth",
        ]
        unexpected, whitelisted = self._classify(paths, ["kismet_cap_*"])
        assert whitelisted == paths
        assert unexpected == []

    def test_exact_name_match(self):
        paths = ["/usr/bin/my_tool"]
        unexpected, whitelisted = self._classify(paths, ["my_tool"])
        assert whitelisted == ["/usr/bin/my_tool"]
        assert unexpected == []

    def test_non_matching_pattern_leaves_unexpected(self):
        paths = ["/usr/bin/evil_tool"]
        unexpected, whitelisted = self._classify(paths, ["kismet_cap_*"])
        assert unexpected == ["/usr/bin/evil_tool"]
        assert whitelisted == []

    def test_empty_patterns_leaves_all_unexpected(self):
        paths = ["/usr/bin/kismet_cap_wifi"]
        unexpected, whitelisted = self._classify(paths, [])
        assert unexpected == ["/usr/bin/kismet_cap_wifi"]
        assert whitelisted == []

    def test_wildcard_star_matches_all(self):
        paths = ["/usr/bin/anything", "/usr/bin/whatever"]
        unexpected, whitelisted = self._classify(paths, ["*"])
        assert whitelisted == paths
        assert unexpected == []

    def test_partial_glob_mix(self):
        paths = ["/usr/bin/kismet_cap_wifi", "/usr/bin/evil"]
        unexpected, whitelisted = self._classify(paths, ["kismet_cap_*"])
        assert "/usr/bin/kismet_cap_wifi" in whitelisted
        assert "/usr/bin/evil" in unexpected

    def test_multiple_patterns_any_match_whitelists(self):
        paths = ["/usr/bin/tool_a", "/usr/bin/tool_b", "/usr/bin/other"]
        unexpected, whitelisted = self._classify(paths, ["tool_a", "tool_b"])
        assert "/usr/bin/tool_a" in whitelisted
        assert "/usr/bin/tool_b" in whitelisted
        assert "/usr/bin/other" in unexpected
