"""A cron file that is not there hides nothing.

`/etc/crontab` does not exist on Alpine, Arch or openSUSE. BOB listed it as
*unreadable*, which is not a cosmetic difference: `cron.unreadable_files` is a
visibility key, so it landed in `unverified`, which marks the whole score an
upper bound and makes `--target` fail closed. Three of six machines had their
audit downgraded for the absence of a file their distribution never ships.

The snapshot's own docstring already drew the line — *"Cron files that exist
but could not be opened"* — and the code did not: `FileNotFoundError` is a
subclass of `OSError`, and the one `except OSError` caught both. The directory
loops guard with `is_dir()`/`is_file()`; `_SYSTEM_CRONTABS` is read unguarded,
which is where it surfaced.

Measured on Arch before and after: `unverified` went from
`['cron.unreadable_files']` to empty, and `score_is_upper_bound` from True to
False. With a directory put in the file's place, both come back.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob.checks.cron_audit import _read_cron_file


class TestAbsenceIsNotAFailureToLook:
    def test_a_missing_file_is_not_unreadable(self, tmp_path):
        out: list = []
        assert _read_cron_file(tmp_path / "nothing-here", out) is True
        assert out == []

    def test_a_missing_parent_is_not_unreadable_either(self, tmp_path):
        """NotADirectoryError and ENOENT on a path component, same thing."""
        out: list = []
        assert _read_cron_file(tmp_path / "no" / "such" / "dir" / "crontab", out) is True

    def test_a_real_file_is_read(self, tmp_path):
        f = tmp_path / "crontab"
        f.write_text("0 3 * * * root /usr/bin/thing\n# a comment\n")
        out: list = []
        assert _read_cron_file(f, out) is True
        assert len(out) == 1, "comments and blanks are dropped, content is not"

    def test_a_directory_in_its_place_is_unreadable(self, tmp_path):
        """The polarity twin, and what was measured on Arch."""
        d = tmp_path / "crontab"
        d.mkdir()
        out: list = []
        assert _read_cron_file(d, out) is False

    def test_a_permission_denial_is_unreadable(self, tmp_path, monkeypatch):
        """The seam is `read_text_capped` now, not `Path.read_text`.

        v0.18.0 pointed the cron reader at the capped reader, so a test that
        patches the bare method never intercepts anything and passes on a file
        it never made unreadable.
        """
        from bob.checks import cron_audit as mod
        f = tmp_path / "crontab"
        f.write_text("x\n")

        def denied(*a, **k):
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(mod, "read_text_capped", denied)
        out: list = []
        assert _read_cron_file(f, out) is False, (
            "a file BOB was refused is exactly what this flag is for"
        )


class TestTheSnapshotAgreesWithItsOwnContract:
    def test_a_host_without_etc_crontab_reports_nothing_unreadable(self, tmp_path,
                                                                   monkeypatch):
        from bob.checks import cron_audit as mod
        monkeypatch.setattr(mod, "_SYSTEM_CRONTABS", [tmp_path / "crontab"])
        monkeypatch.setattr(mod, "_CRON_FORMAT_DIRS", [])
        monkeypatch.setattr(mod, "_CRON_SCRIPT_DIRS", [])
        monkeypatch.setattr(mod, "_find_unexpected_user_crons", lambda unreadable: [])
        snap = mod.CronAuditSnapshot.from_system()
        assert snap.unreadable_files == [], (
            "an absent /etc/crontab put cron.unreadable_files into `unverified`, "
            "which makes the score an upper bound and --target fail closed"
        )

    def test_the_docstring_still_says_what_the_code_does(self):
        from bob.checks import cron_audit as mod
        doc = mod.CronAuditSnapshot.__doc__ or ""
        assert "exist but could not be opened" in doc, (
            "the contract this guard enforces was written in the docstring "
            "before the code matched it; if the wording moves, re-check both"
        )
