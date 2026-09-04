"""v0.16.1 — the exit-code table is a stable public API and it drifts.

README calls these codes a "Stable public API". Twice now the code has changed
under the table: v0.14.0 found the table plainly wrong, and v0.16.0 changed what
`4` means — a bounded score now fails the gate closed — and propagated that to
`--help` and to README_TECH only. README, README_FR, SNAPSHOT and the man page
kept saying "score < N" for a whole release, so the two documents a user reaches
first disagreed with the binary.

The locale string is the source of truth: it is what `bob --help` prints, and it
is the one place the code itself renders. Every document that reproduces the
table must agree with it about the condition, in its own language.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

#: Documents that reproduce the exit-code contract for a reader, as opposed to
#: recording history. Changelogs are deliberately excluded: they describe what a
#: past release did and must NOT be rewritten when the contract moves.
_CONTRACT_DOCS = (
    "README.md",
    "README_FR.md",
    "DOCUMENTS/README_TECH.md",
    "DOCUMENTS/README_TECH_FR.md",
    "DOCUMENTS/SNAPSHOT.md",
    "man/bob.1",
)

#: Wordings that carry "the score is a ceiling", per language. A document must
#: use one of them where it describes code 4.
_CEILING_WORDS = re.compile(
    r"upper bound|ceiling|borne supérieure|plafond",
    re.IGNORECASE,
)


def _locale_exit_4(lang: str) -> str:
    data = json.loads((_ROOT / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
    return data["help"]["exit"]["4"]


class TestTheHelpStringItselfCarriesBothConditions:

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_code_4_names_the_upper_bound(self, lang):
        """`--help` is what an operator reads before writing a CI gate."""
        assert _CEILING_WORDS.search(_locale_exit_4(lang)), (
            f"{lang}.json help.exit.4 no longer says a bounded score fails the "
            f"gate: {_locale_exit_4(lang)!r}"
        )

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_code_4_still_names_the_numeric_miss(self, lang):
        """Polarity: the bound must be added to the rule, not replace it."""
        assert re.search(r"target", _locale_exit_4(lang), re.IGNORECASE)


class TestEveryDocumentAgreesWithIt:

    @staticmethod
    def _passages_about_code_4(rel: str) -> "list[str]":
        """Every block of the document that describes exit code 4.

        Markdown renders it as a table row; the man page as a ``.TP`` entry
        whose head is ``.B 4``. Matching only the constant name would silently
        skip the man page, which is the surface a packaged install ships.
        """
        text = (_ROOT / rel).read_text(encoding="utf-8")
        if rel.startswith("man/"):
            blocks = re.split(r"^\.TP$", text, flags=re.M)
            return [b for b in blocks if re.match(r"\s*\.B 4\b", b)]
        return [
            block for block in re.split(r"\n\s*\n|\n(?=\|)", text)
            if "EXIT_TARGET_MISSED" in block
        ]

    @pytest.mark.parametrize("rel", _CONTRACT_DOCS)
    def test_the_document_describes_code_4(self, rel):
        """Positive control: a guard over a table nobody renders passes forever."""
        assert self._passages_about_code_4(rel), (
            f"{rel} no longer has a passage describing exit code 4 — either it "
            f"stopped documenting the contract, or this guard went blind on it"
        )

    @pytest.mark.parametrize("rel", _CONTRACT_DOCS)
    def test_code_4_mentions_the_upper_bound(self, rel):
        """The row (or entry) describing code 4 must carry both conditions."""
        chunks = self._passages_about_code_4(rel)
        assert any(_CEILING_WORDS.search(c) for c in chunks), (
            f"{rel} describes exit code 4 without saying that a bounded score "
            f"also fails the gate. The binary has behaved that way since "
            f"v0.16.0; see the --target gate in bob/__main__.py."
        )

    @pytest.mark.parametrize("rel", _CONTRACT_DOCS)
    def test_code_4_still_names_the_numeric_miss(self, rel):
        """Polarity: the bound is added to the rule, it does not replace it."""
        chunks = self._passages_about_code_4(rel)
        assert any(re.search(r"target", c, re.IGNORECASE) for c in chunks), rel


# ---------------------------------------------------------------------------
# The test history claims to cover every release
# ---------------------------------------------------------------------------

class TestTheTestHistoryKeepsItsOwnPromise:
    """`DOCUMENTS/TESTING.md` opens with "every release lists the tests added,
    removed, or corrected … the audit trail". It had stopped at v0.15.4 while
    v0.15.5, v0.16.0 and v0.16.1 shipped — a document contradicting its own
    stated scope, which is the class this project treats as a defect rather
    than as a backlog item.
    """

    @staticmethod
    def _current_version() -> str:
        text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        return re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)

    @pytest.mark.parametrize("rel", ["DOCUMENTS/TESTING.md", "DOCUMENTS/TESTING_FR.md"])
    def test_the_current_release_has_a_row(self, rel):
        version = self._current_version()
        text = (_ROOT / rel).read_text(encoding="utf-8")
        assert re.search(rf"^\|\s*v{re.escape(version)}\s*\|", text, re.M), (
            f"{rel} has no row for v{version}. The document promises an entry "
            f"per release; add one before tagging."
        )

    @pytest.mark.parametrize("rel", ["DOCUMENTS/TESTING.md", "DOCUMENTS/TESTING_FR.md"])
    def test_the_row_carries_a_plausible_test_count(self, rel):
        """A row with no number is a row that says nothing."""
        version = self._current_version()
        text = (_ROOT / rel).read_text(encoding="utf-8")
        row = re.search(rf"^\|\s*v{re.escape(version)}\s*\|\s*(\d+)\s*\|", text, re.M)
        assert row, f"{rel}: the v{version} row carries no test count"
        assert int(row.group(1)) > 4000, f"{rel}: implausible count {row.group(1)}"

    def test_both_locales_document_the_same_releases(self):
        def versions(rel):
            text = (_ROOT / rel).read_text(encoding="utf-8")
            return set(re.findall(r"^\|\s*(v0\.\d+\.\d+)\s*\|", text, re.M))

        en = versions("DOCUMENTS/TESTING.md")
        fr = versions("DOCUMENTS/TESTING_FR.md")
        assert en, "the English history table went missing"
        assert en == fr, (
            f"only in EN: {sorted(en - fr)} · only in FR: {sorted(fr - en)}"
        )
