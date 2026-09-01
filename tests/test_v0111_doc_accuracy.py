"""v0.11.1 — doc-accuracy anti-drift guards.

From the post-v0.11.0 documentation audit. Two findings were caused by
docs/help drifting out of sync with reality:

  - DOC-C: the ``--help`` profile line listed ``server, desktop, container``
    but ``workstation`` is a real first-class profile on disk (since v0.8.1).
  - DOC-A: ``--json-v1`` (retired in v0.9.0) was still documented as a usable
    flag in the tutorial and README_TECH.

These guards pin both facts so the next drift fails CI instead of shipping a
help text / tutorial that lies about the tool.
"""

from __future__ import annotations

import pathlib

import pytest


_REPO = pathlib.Path(__file__).resolve().parent.parent
_PROFILES_DIR = _REPO / "bob" / "data" / "profiles"


def _on_disk_profiles() -> set[str]:
    return {p.stem for p in _PROFILES_DIR.glob("*.conf")}


class TestProfileHelpMatchesDisk:
    """Every shipped profile .conf must be advertised in the --help profile
    line and the --profile error message (DOC-C)."""

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_help_profile_line_lists_every_on_disk_profile(self, lang):
        """v0.15.3: reads the *rendered* help rather than a literal in cli.py.

        The descriptions moved into the locale files when --help was
        translated, so scraping the source no longer finds them — and checking
        each locale is stricter anyway: a translation that dropped a profile
        name would now be caught too.
        """
        import contextlib
        import io

        from bob import i18n
        from bob.cli import print_help

        i18n.init(lang=lang)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_help(i18n.t, "0.0.0")
        line = next(
            (l for l in buf.getvalue().splitlines() if "--profile=NAME" in l), None
        )
        assert line is not None, f"could not find the --profile help line ({lang})"
        for name in _on_disk_profiles():
            assert name in line, (
                f"profile {name!r} exists on disk but is missing from the "
                f"--help profile line ({lang}): {line.strip()}"
            )

    def test_profile_error_message_lists_every_on_disk_profile(self):
        src = (_REPO / "bob" / "cli.py").read_text(encoding="utf-8")
        line = next(
            (l for l in src.splitlines() if "requires a profile name" in l), None
        )
        assert line is not None, "could not find the --profile error message in cli.py"
        for name in _on_disk_profiles():
            assert name in line, (
                f"profile {name!r} exists on disk but is missing from the "
                f"--profile error message"
            )


class TestNoJsonV1AsUsableFlag:
    """`--json-v1` was retired in v0.9.0; no user-facing doc may present it as
    a runnable command (DOC-A). History/EOL prose that explicitly says
    'retired' / 'retiré' is allowed."""

    _USER_DOCS = [
        "DOCUMENTS/TUTORIAL.md",
        "DOCUMENTS/TUTORIAL_FR.md",
        "README.md",
        "README_FR.md",
    ]

    @pytest.mark.parametrize("rel", _USER_DOCS)
    def test_no_runnable_json_v1_in_user_docs(self, rel):
        text = (_REPO / rel).read_text(encoding="utf-8")
        assert "bob --json-v1" not in text, (
            f"{rel} shows a runnable `bob --json-v1` command, but --json-v1 was "
            "retired in v0.9.0"
        )
