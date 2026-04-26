"""
Tests for the --explain hint injected under actionable findings in the summary box
.

Strategy: capture stdout from print_audit_summary() with a minimal FakeEngine,
then assert the hint line "? bob --explain <key>" appears or not.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

from bob.display import _wrap_for_box, print_audit_summary
from bob.explain import EXPLAIN_KEYS, normalize_key
from bob.scoring import Finding, FindingLevel, RiskLevel
from tests.helpers import _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeEngine:
    """
    Minimal engine stub — provides only the attributes read by print_audit_summary.
    Avoids touching ScoreEngine private attributes (_raw_score, _finalized, etc.).
    """

    def __init__(self, *findings: Finding):
        self.findings    = list(findings)
        self.score       = 7
        self.level       = RiskLevel.MEDIUM
        self.breakdown   = []
        self.cap_info    = None
        self.ok_count    = sum(1 for f in findings if f.level == FindingLevel.OK)
        self.warn_count  = sum(1 for f in findings if f.level == FindingLevel.WARN)
        self.alert_count = sum(1 for f in findings if f.level == FindingLevel.ALERT)


def _make_finding(key: str, nature: str = "action") -> Finding:
    return Finding(
        level=FindingLevel.ALERT,
        message="Test finding",
        nature=nature,
        key=key,
    )


def _make_report() -> MagicMock:
    report = MagicMock()
    report.write_summary = MagicMock()
    return report


def _run(engine: FakeEngine, capsys) -> str:
    """Run print_audit_summary and return captured stdout."""
    print_audit_summary(
        engine=engine,
        network_context="local",
        public_ip=None,
        config=SimpleNamespace(lang="en"),
        t=_t,
        report=_make_report(),
        snapshots=[],
    )
    return capsys.readouterr().out


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from a string."""
    return _ANSI_RE.sub("", text)


def _hint_lines(output: str, key: str) -> list[str]:
    """
    Return lines (raw, including ANSI/box chars) that carry the hint for the given key.

    Matching is done on the ANSI-stripped version of each line so that box-drawing
    characters and colour codes don't interfere.
    """
    target = f"? bob --explain {key}"
    return [
        line for line in output.splitlines()
        if target in _strip_ansi(line)
    ]


# ---------------------------------------------------------------------------
# normalize_key unit tests
# ---------------------------------------------------------------------------

class TestNormalizeKey:
    def test_ssh_key_unchanged(self):
        assert normalize_key("ssh.password_auth") == "ssh.password_auth"

    def test_updates_key_unchanged(self):
        assert normalize_key("updates.security_pending") == "updates.security_pending"

    def test_file_perms_with_middle_segment(self):
        assert normalize_key("file_perms.shadow.world_writable") == "file_perms.world_writable"

    def test_file_perms_with_multiple_segments(self):
        assert normalize_key("file_perms.a.b.c.world_writable") == "file_perms.world_writable"

    def test_file_perms_without_middle_segment_unchanged(self):
        assert normalize_key("file_perms.world_writable") == "file_perms.world_writable"

    def test_unknown_key_unchanged(self):
        assert normalize_key("firewall.inactive") == "firewall.inactive"

    def test_empty_string(self):
        assert normalize_key("") == ""

    def test_trailing_dot_unchanged(self):
        """A key ending in '.' has no middle segment pattern — returned as-is."""
        assert normalize_key("file_perms.") == "file_perms."

    def test_double_dot_unchanged(self):
        """A key with '..' does not match the normalize regex — returned as-is."""
        assert normalize_key("file_perms..world_writable") == "file_perms..world_writable"


# ---------------------------------------------------------------------------
# EXPLAIN_KEYS consistency tests
# ---------------------------------------------------------------------------

class TestExplainKeys:
    def test_all_keys_are_strings(self):
        assert all(isinstance(k, str) for k in EXPLAIN_KEYS)

    def test_all_keys_contain_dot(self):
        """Every key must be namespaced (e.g. 'ssh.password_auth')."""
        assert all("." in k for k in EXPLAIN_KEYS)

    def test_no_duplicates(self):
        assert len(EXPLAIN_KEYS) == len(set(EXPLAIN_KEYS))

    def test_ssh_password_auth_present(self):
        """Spot-check: at least one well-known SSH key is present."""
        assert "ssh.password_auth" in EXPLAIN_KEYS

    def test_updates_security_pending_present(self):
        assert "updates.security_pending" in EXPLAIN_KEYS


# ---------------------------------------------------------------------------
# A1 integration: hint appears when key is explainable
# ---------------------------------------------------------------------------

class TestExplainHintShown:
    def test_explainable_action_finding_gets_hint(self, capsys):
        engine = FakeEngine(_make_finding("ssh.password_auth"))
        output = _run(engine, capsys)
        assert _hint_lines(output, "ssh.password_auth"), \
            "Expected hint line for ssh.password_auth"

    def test_hint_line_starts_with_question_mark(self, capsys):
        """The hint must use the '? ' prefix (after stripping box chars and ANSI)."""
        engine = FakeEngine(_make_finding("ssh.password_auth"))
        output = _run(engine, capsys)
        lines = _hint_lines(output, "ssh.password_auth")
        assert lines, "No hint line found"
        # Strip ANSI + box-drawing chars, then verify '?' comes before the command
        clean = _strip_ansi(lines[0]).strip().lstrip("║ ")
        assert clean.startswith("? bob --explain")

    def test_improvement_finding_gets_hint(self, capsys):
        engine = FakeEngine(_make_finding("updates.security_pending", nature="improvement"))
        output = _run(engine, capsys)
        assert _hint_lines(output, "updates.security_pending")

    def test_file_perms_middle_segment_normalizes_in_hint(self, capsys):
        """file_perms.shadow.world_writable → hint shows normalized key."""
        engine = FakeEngine(_make_finding("file_perms.shadow.world_writable"))
        output = _run(engine, capsys)
        assert _hint_lines(output, "file_perms.world_writable")

    def test_raw_key_not_used_when_normalized(self, capsys):
        """The hint must never show the raw un-normalized key."""
        engine = FakeEngine(_make_finding("file_perms.shadow.world_writable"))
        output = _run(engine, capsys)
        assert not _hint_lines(output, "file_perms.shadow.world_writable")

    def test_multiple_findings_each_get_hint(self, capsys):
        engine = FakeEngine(
            _make_finding("ssh.password_auth"),
            _make_finding("hardening.rp_filter_disabled", nature="improvement"),
        )
        output = _run(engine, capsys)
        assert _hint_lines(output, "ssh.password_auth")
        assert _hint_lines(output, "hardening.rp_filter_disabled")


# ---------------------------------------------------------------------------
# A1 integration: hint absent when it should not appear
# ---------------------------------------------------------------------------

class TestExplainHintAbsent:
    def test_unknown_key_no_hint(self, capsys):
        engine = FakeEngine(_make_finding("firewall.inactive"))
        output = _run(engine, capsys)
        assert "bob --explain" not in output

    def test_empty_key_no_hint(self, capsys):
        engine = FakeEngine(_make_finding(""))
        output = _run(engine, capsys)
        assert "bob --explain" not in output

    def test_nature_empty_finding_not_rendered(self, capsys):
        """A finding with nature='' appears in no category → no hint."""
        engine = FakeEngine(_make_finding("ssh.password_auth", nature=""))
        output = _run(engine, capsys)
        assert "bob --explain" not in output

    def test_explainable_alongside_non_explainable(self, capsys):
        """Only the explainable finding triggers a hint."""
        engine = FakeEngine(
            _make_finding("ssh.password_auth"),
            _make_finding("firewall.inactive"),
        )
        output = _run(engine, capsys)
        assert _hint_lines(output, "ssh.password_auth")
        assert not _hint_lines(output, "firewall.inactive")


# ---------------------------------------------------------------------------
# Duplicate findings
# ---------------------------------------------------------------------------

class TestDuplicateFindings:
    def test_two_identical_findings_produce_two_hints(self, capsys):
        """Each finding is rendered independently; duplicates each get a hint."""
        engine = FakeEngine(
            _make_finding("ssh.password_auth"),
            _make_finding("ssh.password_auth"),
        )
        output = _run(engine, capsys)
        lines = _hint_lines(output, "ssh.password_auth")
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# _wrap_for_box — long token truncation
# ---------------------------------------------------------------------------

class TestWrapForBox:
    def _lines(self, prefix: str, text: str, inner: int) -> list[str]:
        return [content for content, _ in _wrap_for_box(prefix, text, inner)]

    def test_short_text_no_wrap(self):
        lines = self._lines("  ⚠  ", "short text", 78)
        assert len(lines) == 1
        assert lines[0] == "  ⚠  short text"

    def test_wraps_at_space(self):
        prefix = "  ⚠  "
        avail = 78 - len(prefix)  # 73
        text = ("word " * 20).strip()
        lines = self._lines(prefix, text, 78)
        for line in lines:
            assert len(line) <= 78

    def test_long_token_truncated_with_ellipsis(self):
        """A single token longer than avail must be truncated, not overflow."""
        prefix = "  ⚠  "
        inner = 78
        long_path = "/home/timeshift/snapshots/2026-04-04_23-00-01/localhost/opt/brave.com/brave/chrome-sandbox,"
        lines = self._lines(prefix, long_path, inner)
        assert len(lines) == 1
        assert len(lines[0]) <= inner
        assert lines[0].endswith("…")

    def test_all_lines_fit_in_box(self):
        """Every output line must fit within inner width even with long paths."""
        prefix = "  ⚠  "
        inner = 78
        text = (
            "/home/timeshift/snapshots/2026-04-04_23-00-01/localhost/opt/brave.com/brave/chrome-sandbox, "
            "/home/timeshift/snapshots/2026-04-04_23-00-01/localhost/usr/lib/xorg/Xorg.wrap, "
            "/home/timeshift/snapshots/2026-04-04_23-00-01/localhost/usr/sbin/mount.cifs"
        )
        lines = self._lines(prefix, text, inner)
        for line in lines:
            assert len(line) <= inner, f"Line too long ({len(line)}): {line!r}"

    def test_continuation_lines_indented(self):
        prefix = "  ⚠  "
        text = "word " * 30
        lines = self._lines(prefix, text.strip(), 78)
        assert len(lines) > 1
        indent = " " * len(prefix)
        for line in lines[1:]:
            assert line.startswith(indent)
