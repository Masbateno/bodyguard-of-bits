"""
v0.15.0 — hardening appended to the end of a umask file was not seen.

Same defect as `password_policy`, in a module the earlier sweep had not
reached: every file scanned here is last-one-wins, and the reader took the
first match.

Measured, not reasoned:

* `/etc/login.defs` — with shadow's own `useradd --prefix` against a file
  holding UMASK twice. `022` then `077` creates the home directory 700;
  `077` then `022` creates it 755. The final line is what shadow applies.
* `/etc/profile` — sourcing a file with `umask 022` then `umask 027` leaves
  027, which is simply how a shell reads a script.

So the operator who hardens the ordinary way — appending the stricter value —
was told the distro's original value was still in force. And the reverse, which
is the one that matters: a strict value weakened by an appended line was
reported as the strict one it had replaced.
"""

from __future__ import annotations

import pytest

import bob.checks.umask as u
from bob.checks.umask import _LOGIN_DEFS_RE, _PAM_UMASK_RE, _UMASK_RE, _scan


@pytest.fixture
def scan(tmp_path):
    def _run(body: str, regex=_UMASK_RE, name: str = "f") -> str | None:
        p = tmp_path / name
        p.write_text(body)
        return _scan(p, regex)
    return _run


class TestLoginDefs:
    def test_appended_hardening_is_seen(self, scan):
        """useradd creates the home 700 for this file."""
        assert scan("UMASK 022\nUMASK 077\n", _LOGIN_DEFS_RE) == "077"

    def test_appended_weakening_is_not_hidden(self, scan):
        """useradd creates the home 755 for this one — the dangerous
        direction, where BOB used to report the stricter value."""
        assert scan("UMASK 077\nUMASK 022\n", _LOGIN_DEFS_RE) == "022"

    def test_a_single_occurrence_is_unchanged(self, scan):
        assert scan("UMASK 027\n", _LOGIN_DEFS_RE) == "027"

    def test_four_digit_values_are_normalised(self, scan):
        assert scan("UMASK 0027\n", _LOGIN_DEFS_RE) == "027"


class TestShellFiles:
    def test_the_last_umask_command_wins(self, scan):
        """`sh -c '. file; umask'` prints 0027 for this content."""
        assert scan("umask 022\numask 027\n") == "027"

    def test_a_commented_line_is_ignored(self, scan):
        assert scan("umask 077\n#umask 000\n") == "077"

    def test_a_commented_line_does_not_shadow_a_real_one(self, scan):
        assert scan("# umask 000\numask 027\n") == "027"

    def test_an_indented_umask_still_counts(self, scan):
        """Inside a conditional block it is still the value a linear read
        leaves in effect."""
        assert scan("umask 022\n    umask 077\n") == "077"


class TestPamStack:
    def test_the_last_pam_umask_line_wins(self, scan):
        body = ("session optional pam_umask.so umask=022\n"
                "session optional pam_umask.so umask=077\n")
        assert scan(body, _PAM_UMASK_RE) == "077"


class TestNoMatch:
    def test_a_file_without_a_umask_returns_none(self, scan):
        assert scan("# nothing here\nexport PATH=/usr/bin\n") is None

    def test_a_missing_file_returns_none(self, tmp_path):
        assert _scan(tmp_path / "absent", _UMASK_RE) is None
