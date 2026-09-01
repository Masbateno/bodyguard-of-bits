"""v0.15.3 — an option the parser accepts and the manual never mentions.

The manual is BOB's reference documentation; `--help` is the reminder. Two
options had drifted out of the first while remaining in the second:
`--test-webhook`, added in v0.8.2, and `--html`, whose sibling long-form alias
`--json-full` was documented right beside it.

This is the same shape as the `config_key` finding one commit earlier — a
declaration and its implementation disagreeing — on the surface an operator
actually reads. It is pinned rather than fixed once, because v0.13.4 already
had to repair five undiscoverable options and the drift came back.

Two options are deliberately absent from the manual, and the reason for each is
recorded here rather than left to be rediscovered.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_CLI = Path("bob/cli.py")
_MAN = Path("man/bob.1")

# Absent from the manual on purpose.
_NOT_IN_MANUAL = {
    "--no-colour":
        "British spelling of --no-color. The manual documents the canonical "
        "form and `--help` names the alias beside it; documenting both would "
        "duplicate every entry that has one.",
    "--json-v1":
        "retired in v0.9.0. The parser still accepts it only to answer with "
        "the retirement message v0.9.1 fixed, so documenting it would "
        "advertise an option that refuses to work.",
}


def _declared_options() -> "set[str]":
    return set(re.findall(r'"(--[a-z0-9-]+)"', _CLI.read_text(encoding="utf-8")))


def _manual_text() -> str:
    # troff escapes every hyphen in an option name as `\-`.
    return _MAN.read_text(encoding="utf-8").replace("\\-", "-")


class TestEveryOptionIsDocumented:
    def test_the_manual_covers_the_parser(self):
        manual = _manual_text()
        missing = sorted(
            option for option in _declared_options()
            if option not in manual and option not in _NOT_IN_MANUAL
        )
        assert not missing, (
            "the parser accepts these and the manual never mentions them; add "
            "an entry, or list the option in _NOT_IN_MANUAL with its reason: "
            + ", ".join(missing)
        )

    @pytest.mark.parametrize("option", sorted(_NOT_IN_MANUAL))
    def test_a_deliberate_omission_is_still_a_real_option(self, option):
        """An exemption for an option that no longer exists is stale."""
        assert option in _declared_options(), (
            f"{option} is exempt from the manual but the parser no longer "
            "accepts it; drop the exemption"
        )

    @pytest.mark.parametrize("option,reason", sorted(_NOT_IN_MANUAL.items()))
    def test_each_omission_states_why(self, option, reason):
        assert len(reason) > 40, f"{option}: the reason is too thin to be one"


class TestTheTwoRepairedEntries:
    """Named individually so a future edit that drops one is loud."""

    @pytest.mark.parametrize("option", ["--test-webhook", "--html"])
    def test_the_entry_is_present(self, option):
        assert option in _manual_text()

    def test_html_is_described_as_the_alias_it_is(self):
        manual = _manual_text()
        index = manual.index("--html")
        assert "--format=html" in manual[index:index + 200], (
            "--html is a long-form alias; the entry should say so, as the "
            "--json-full entry beside it does"
        )


class TestTheManualIsStillValidTroff:
    """Ask groff, not a regex.

    An earlier draft here counted `\\fI` against `\\fR` and failed on a page
    groff renders without a single warning: troff also closes a font with
    `\\fB` or `\\fP`, and a redundant `\\fR` is harmless. Counting escapes
    measures the counter, not the page.
    """

    @pytest.mark.skipif(
        shutil.which("man") is None, reason="man not installed"
    )
    def test_groff_reports_no_warning(self):
        result = subprocess.run(
            ["man", "--warnings", "-l", str(_MAN)],
            capture_output=True, text=True,
            env={**os.environ, "MANWIDTH": "80", "LC_ALL": "C"},
        )
        assert not result.stderr.strip(), (
            "groff warns about the manual page:\n" + result.stderr
        )

    def test_every_option_paragraph_opens_with_tp(self):
        """`.TP` is what makes an option render as a tagged paragraph."""
        lines = _MAN.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines):
            if re.match(r"^\.B[R]?\s+\\-\\-(test\\-webhook|html)\b", line):
                assert lines[number - 1].strip() == ".TP", (
                    f"line {number + 1}: {line!r} is not preceded by .TP, so "
                    "it will not render as an option entry"
                )
