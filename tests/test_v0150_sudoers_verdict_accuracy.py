"""
v0.15.0 — verdict-accuracy guards for the sudoers NOPASSWD analysis.

The expectations below were not written by hand: each was read off
`cvtsudoers -f json`, sudo's own parser, so this file records what sudo
actually grants rather than what the rule looks like it grants.

`NOPASSWD: ALL` is passwordless root. It carries a WARN and a 2-point
deduction; the fallback branch is an INFO worth nothing. Every miss below was
therefore a silent downgrade of the harshest local-privilege finding BOB has.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob.checks import file_perms as fp
from bob.checks.file_perms import (
    _is_nopasswd_all,
    _join_continuations,
    _strip_sudoers_comment,
)


def _collect(text: str, tmp_path: Path, monkeypatch) -> tuple[list[str], list[str]]:
    """Run the real collector against a single fake /etc/sudoers."""
    f = tmp_path / "sudoers"
    f.write_text(text)
    real = fp.Path
    monkeypatch.setattr(
        fp, "Path",
        lambda p: f if str(p) == "/etc/sudoers" else real(tmp_path / "absent"),
    )
    return fp._collect_nopasswd_entries()


# Verdicts confirmed against cvtsudoers; True == sudo grants NOPASSWD on ALL.
GRANTS_UNRESTRICTED = [
    "john ALL=(ALL) NOPASSWD: ALL",
    "john ALL=(ALL) NOPASSWD: ALL # temporary, remove me",
    "john ALL=(ALL) NOPASSWD: ALL#tmp",
    "john ALL=(ALL) NOPASSWD:ALL",
    "john\tALL=(ALL:ALL)\tNOPASSWD:\tALL",
    "%sudo ALL=(ALL:ALL) NOPASSWD: ALL",
    "#1000 ALL=(ALL) NOPASSWD: ALL",
    "%#1000 ALL=(ALL) NOPASSWD: ALL",
    "john ALL=(#1000) NOPASSWD: ALL",
    "john ALL=(ALL) \\\n     NOPASSWD: ALL",
    "john ALL=(ALL) NOPASSWD: \\\n     ALL",
]

DOES_NOT = [
    "john ALL=(ALL) NOPASSWD: /usr/bin/apt",
    "john ALL=(ALL) NOPASSWD: /usr/bin/apt # ok",
    "john ALL=(ALL) /usr/bin/apt # was NOPASSWD before",
    "john ALL=(ALL) NOPASSWD: ALL, !/bin/su",
    "john ALL=(ALL) PASSWD: ALL",
    "john ALL=(ALL) ALL",
    "john ALL=(ALL) NOPASSWD: \\\n     /usr/bin/apt",
    "# john ALL=(ALL) NOPASSWD: ALL",
    "Defaults:john !authenticate",
]


class TestAgainstSudoOwnParser:
    @pytest.mark.parametrize("rule", GRANTS_UNRESTRICTED)
    def test_unrestricted_sudo_is_detected(self, rule, tmp_path, monkeypatch):
        all_, _ = _collect(rule + "\n", tmp_path, monkeypatch)
        assert all_, f"sudo grants passwordless root here, BOB saw nothing: {rule!r}"

    @pytest.mark.parametrize("rule", DOES_NOT)
    def test_restricted_rules_are_not_escalated(self, rule, tmp_path, monkeypatch):
        all_, _ = _collect(rule + "\n", tmp_path, monkeypatch)
        assert not all_, f"BOB claims unrestricted sudo, sudo disagrees: {rule!r}"

    def test_nopasswd_named_only_in_a_comment_is_not_an_entry(self, tmp_path, monkeypatch):
        """It was previously counted as a passwordless entry — an INFO about a
        rule that grants nothing."""
        all_, spec = _collect("john ALL=(ALL) /usr/bin/apt # was NOPASSWD before\n",
                              tmp_path, monkeypatch)
        assert (all_, spec) == ([], [])


class TestStripSudoersComment:
    @pytest.mark.parametrize("raw,expected", [
        ("john ALL=(ALL) NOPASSWD: ALL # note", "john ALL=(ALL) NOPASSWD: ALL"),
        ("john ALL=(ALL) NOPASSWD: ALL#tmp",    "john ALL=(ALL) NOPASSWD: ALL"),
        ("# whole line",                        ""),
        ("#includedir /etc/sudoers.d",          ""),
        # `#` + digit is a numeric id, not a comment — sudo lexes it as uid/gid.
        ("#1000 ALL=(ALL) NOPASSWD: ALL",       "#1000 ALL=(ALL) NOPASSWD: ALL"),
        ("john ALL=(#1000) NOPASSWD: ALL",      "john ALL=(#1000) NOPASSWD: ALL"),
    ])
    def test_cuts_only_real_comments(self, raw, expected):
        assert _strip_sudoers_comment(raw) == expected


class TestJoinContinuations:
    def test_a_wrapped_rule_becomes_one_line(self):
        assert _join_continuations(["john ALL=(ALL) \\", "   NOPASSWD: ALL"]) == \
            ["john ALL=(ALL)     NOPASSWD: ALL"]

    def test_unwrapped_lines_pass_through(self):
        assert _join_continuations(["a", "b"]) == ["a", "b"]

    def test_a_trailing_backslash_at_eof_is_not_lost(self):
        assert _join_continuations(["a \\"]) == ["a  "]


class TestIsNopasswdAllStillStrict:
    """The strictness documented on `_is_nopasswd_all` is intentional and must
    not be relaxed by the comment handling."""

    def test_all_plus_a_command_is_not_unrestricted(self):
        assert not _is_nopasswd_all("john ALL=(ALL) NOPASSWD: ALL /bin/sh")
