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

#: What each gate predicate obliges the documents to say, per language.
#:
#: v0.16.2 — the first version of this guard matched "ceiling|upper bound",
#: the wording of the moment. When the gate widened from
#: ``score_is_upper_bound`` to ``score_is_uncertain`` — a run whose blindness
#: drops a whole domain is no longer a ceiling, yet must still fail the gate —
#: seven documents kept describing the narrower rule and the guard stayed
#: green. A guard that matches a word cannot notice the word became wrong.
#:
#: So the requirement is derived from the predicate the source actually uses.
#: An unlisted predicate fails loudly: whoever changes the gate has to say
#: here what the documents must now claim.
_PREDICATE_WORDS = {
    "score_is_uncertain": re.compile(
        r"could not be read|could not be fully verified|nothing verified"
        r"|not fully verified|n'a pas pu être lu|pas pu être entièrement vérifié"
        r"|que rien n'a vérifié",
        re.IGNORECASE,
    ),
    "score_is_upper_bound": re.compile(
        r"upper bound|ceiling|borne supérieure|plafond", re.IGNORECASE,
    ),
}


def _gate_predicate() -> str:
    """The property ``--target``'s gate consults, read from the source."""
    src = (_ROOT / "bob" / "__main__.py").read_text(encoding="utf-8")
    m = re.search(r"engine\.score < config\.target or engine\.(\w+)", src)
    assert m, "the --target gate no longer has its expected shape"
    return m.group(1)


def _required_words() -> "re.Pattern":
    predicate = _gate_predicate()
    assert predicate in _PREDICATE_WORDS, (
        f"the --target gate now reads `{predicate}`, which this guard does not "
        f"know. Add it to _PREDICATE_WORDS with the wording every document "
        f"must carry, then update the documents."
    )
    return _PREDICATE_WORDS[predicate]


def _locale_exit_4(lang: str) -> str:
    data = json.loads((_ROOT / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
    return data["help"]["exit"]["4"]


class TestTheHelpStringItselfCarriesBothConditions:

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_code_4_matches_the_gate_the_binary_uses(self, lang):
        """`--help` is what an operator reads before writing a CI gate."""
        assert _required_words().search(_locale_exit_4(lang)), (
            f"{lang}.json help.exit.4 describes a rule the binary no longer "
            f"applies (gate reads `{_gate_predicate()}`): {_locale_exit_4(lang)!r}"
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
        assert any(_required_words().search(c) for c in chunks), (
            f"{rel} describes exit code 4 in terms the gate no longer uses — "
            f"it reads `{_gate_predicate()}`. See bob/__main__.py."
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

    @pytest.mark.parametrize("rel", ["DOCUMENTS/TESTING.md", "DOCUMENTS/TESTING_FR.md"])
    def test_the_table_is_not_mangled(self, rel):
        """v0.16.2 — a release row must be a row, and nothing else a row.

        Written after corrupting both files three releases running with
        ``sed 's|\\| v0\\.16\\.1 \\| 8277 \\||…|'``: with ``|`` as the delimiter
        the escaped pipes read as an empty alternation, the pattern matched the
        empty string at the start of every line, and the replacement was
        prepended to all 2134 of them. v0.16.1 shipped with the document's
        first line reading ``| v0.16.1 | 8282 |*[Lire en français]…``.

        The shape is cheap to assert and the damage was not: no line may carry
        more than one release cell, and the locale link must still open the
        file.
        """
        text = (_ROOT / rel).read_text(encoding="utf-8")
        lines = text.splitlines()

        assert lines[0].startswith("*["), (
            f"{rel} no longer opens with its locale link — something was "
            f"prepended to line 1: {lines[0][:70]!r}"
        )
        doubled = [
            f"line {i}: {ln[:70]}"
            for i, ln in enumerate(lines, 1)
            if len(re.findall(r"\| v0\.\d+\.\d+ \| \d+ \|", ln)) > 1
        ]
        assert not doubled, (
            f"{rel} has lines carrying more than one release cell:\n  "
            + "\n  ".join(doubled[:5])
        )

    @pytest.mark.parametrize("rel", ["DOCUMENTS/TESTING.md", "DOCUMENTS/TESTING_FR.md"])
    def test_the_versions_run_downwards(self, rel):
        """A row inserted at the wrong anchor lands out of order and reads as a
        gap in the history. Cheap to check, and it catches a lost row too."""
        text = (_ROOT / rel).read_text(encoding="utf-8")
        found = re.findall(r"^\| v(\d+)\.(\d+)\.(\d+) \| \d+ \|", text, re.M)
        keys = [tuple(int(x) for x in v) for v in found]
        assert len(keys) >= 30, f"{rel}: only {len(keys)} release rows"
        assert keys == sorted(keys, reverse=True), (
            f"{rel}: release rows are not in descending order — "
            f"first break near {next((a for a, b in zip(keys, sorted(keys, reverse=True)) if a != b), None)}"
        )
