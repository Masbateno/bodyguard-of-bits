"""Counters in the current-state documents, swept by shape rather than by name.

The v0.13.3 guard pins four spellings of the explain-key figure. SNAPSHOT.md
writes the same number four other ways — `EXPLAIN_KEYS (187 keys, 49 prefixes)`,
`← 187 keys / 49 prefixes`, `EXPLAIN_KEYS | 169 (in 49 prefixes)` — and none of
them matched, so seven counters sat stale across six releases while the guard
reported the document clean. The section count drifted the same way in seven
places the moment a section was added.

A guard pinned to phrasings protects phrasings. This one reads every number
that sits immediately before a counted noun and checks it against the live
value, across the documents that describe the tool *as it is now*.

**Changelogs are excluded on purpose.** Their figures describe the release
whose row they are in; "46 sections" in the v0.8.x entry was true then and
rewriting it would destroy the record. So is any line that dates its own
figure — "Baseline history: v0.7.0 audit = 117 keys / 30 prefixes".
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Documents that describe the tool as it is now. A changelog is a record, not
#: a description, and TESTING.md's table is a per-release history.
_CURRENT_STATE = [
    "README.md", "README_FR.md", "SECURITY.md", "SECURITY_FR.md",
    "DOCUMENTS/README_TECH.md", "DOCUMENTS/README_TECH_FR.md",
    "DOCUMENTS/README_DEV.md", "DOCUMENTS/README_DEV_FR.md",
    "DOCUMENTS/SNAPSHOT.md",
    "DOCUMENTS/TUTORIAL.md", "DOCUMENTS/TUTORIAL_FR.md",
    "DOCUMENTS/AUTOMATION.md", "DOCUMENTS/AUTOMATION_FR.md",
]

#: A line that names a version, or says it is quoting history, is dating its own
#: figure and must be left alone.
_DATED = re.compile(
    r"v0\.[0-9]+\.[0-9]+|Baseline history|Historique de référence|baseline was|since v0\.")

#: Counted noun (in either locale) → the name of the live value it must equal.
_NOUNS = {
    "explain keys": "explain_keys", "clés explain": "explain_keys",
    "prefixes": "explain_prefixes", "préfixes": "explain_prefixes",
    "CIS references": "cis_refs", "références CIS": "cis_refs",
    "check sections": "sections", "sections de vérification": "sections",
    "filterable": "sections", "sections filtrables": "sections",
}
#: Phrases carrying a number that equals a live counter, and which this sweep
#: deliberately does not watch — either because the figure is checked by a more
#: specific guard, or because the match is a coincidence. Each entry is a
#: decision with its reason, not a silence.
#:
#: Note what is *not* here: "keys". It is ambiguous — README_TECH's "189 keys"
#: is the explain set, README_DEV's "2370 keys" is the locale file — and a rule
#: that resolved it one way would be wrong in the other document. That
#: ambiguity is why the older guard used long distinctive phrases, and why this
#: one reports rather than guesses.
_COINCIDENCES = {
    # SNAPSHOT: "(193 L)" is bob/cron/_io.py's line count, which v0.18.1
    # made equal to the EXPLAIN_KEYS count. Line counts are deliberately
    # not guarded strictly (see the SNAPSHOT guard calibration).
    "L",
    # SNAPSHOT: "43 long-form + 21 short options" is the CLI flag count
    # (bob.cli.parse_args), which v0.21.0 made equal to the section count when
    # core_dumps became the 43rd filterable section. Unrelated counter.
    "long-form",
    # v0.21.0 coincidences with the section count (now 44), all unrelated:
    # "Fedora 44 Server" (a distro version in the tier table), "44 rows below"
    # (the module-index row count), "44 non-pilot checks" (a historical
    # template_vars-migration backlog note).
    "Server",
    "rows",
    "non-pilot",
    # README_TECH: "50 failed attempts" is a brute-force threshold that happens
    # to equal the explain-prefix count. Nothing to keep in sync.
    "failed attempts",
    # README_TECH: "194 entries (108 formal CIS, 79 best-practice, 7 Docker)"
    # is the CIS reference count, and it is already checked — with its
    # breakdown — by test_v0163_readme_tech_claims.py::test_the_cis_reference
    # _counts. Watched, just not here.
    "entries",
    "entrées",
    # SNAPSHOT / README: "199 primary (109 CIS Ubuntu 22.04 + …)" is the
    # cis_refs.json entry count, the same live value watched strictly via the
    # "CIS references" / "entries" phrasings and by
    # test_v0163_readme_tech_claims.py. "primary" here distinguishes the
    # primary references from the 85 cross-benchmark citations beside them.
    "primary",
    # README_TECH: "50 log entries" / "50 tentatives échouées" are brute-force
    # thresholds. Same coincidence as "failed attempts" above.
    "log entries",
    "tentatives échouées",
    # README_TECH: "189 explainable keys across 50 prefixes" and "contains
    # **189 keys**" are the explain-set figures, both already checked — with
    # the prefix count beside them — by
    # test_v0163_readme_tech_claims.py::test_the_explain_key_and_prefix_counts.
    "explainable keys",
    # SNAPSHOT: "54 CIS Debian 12" / "54 CIS Ubuntu 24.04" are per-benchmark
    # cross-citation counts that v0.21.0 made equal to the explain-prefix count
    # (now 54) when faillock became the 54th prefix. Unrelated counters; the
    # cis_refs total is watched via "CIS references" / "entries".
    "CIS Debian",
    "CIS Ubuntu",
    "keys",
    "clés",
    # README_TECH sample output: "47 blocked attempt(s) over 7 day(s)" / FR "47
    # tentative(s) bloquée(s)" is an illustrative auth-log count in a sample
    # panel; v0.21.0 made it equal the filterable-section count (47). Arbitrary
    # sample text, not a counter.
    "blocked attempt",
    "tentative",
    # AUTOMATION: "the last 50 audit scores" is history.jsonl's retention
    # length. It equals the explain-prefix count today and will stop doing so
    # the next time a prefix is added; neither figure constrains the other.
    "audit",
    "derniers",
}

_PATTERN = re.compile(
    r"\b(\d{2,5})\s+(" + "|".join(re.escape(n) for n in _NOUNS) + r")\b")


def _live() -> dict:
    from bob.domain_scores import _PREFIX_TO_DOMAIN  # noqa: F401 (kept: see below)
    from bob.explain import EXPLAIN_KEYS
    from bob.runner import _ALL_SECTIONS

    return {
        "explain_keys": len(EXPLAIN_KEYS),
        "explain_prefixes": len({k.split(".")[0] for k in EXPLAIN_KEYS}),
        "cis_refs": len(json.loads(
            (_ROOT / "bob" / "data" / "cis_refs.json").read_text(encoding="utf-8"))),
        # What a reader means by "check sections" is what --check accepts.
        "sections": len(_ALL_SECTIONS),
    }


@pytest.mark.parametrize("rel", _CURRENT_STATE)
def test_no_counter_in_a_current_state_document_is_stale(rel):
    live = _live()
    stale = []
    for lineno, line in enumerate(
            (_ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
        if _DATED.search(line):
            continue
        for m in _PATTERN.finditer(line):
            name = _NOUNS[m.group(2)]
            if int(m.group(1)) != live[name]:
                stale.append(
                    f"{rel}:{lineno} claims {m.group(1)} {m.group(2)}, "
                    f"code says {live[name]}")
    assert not stale, "documented counters drifted from the code:\n  " + "\n  ".join(stale)


def test_the_vocabulary_covers_the_phrasings_actually_used():
    """A number that equals a live counter, beside an unwatched noun, is a
    counter nobody is checking.

    This is the failure that let SNAPSHOT drift: the v0.13.3 guard knew four
    spellings of the explain-key figure and the document used four others, so
    every occurrence was invisible to it. Rather than trusting that the
    vocabulary is complete, look for the shape — a plausible counted noun
    carrying a number that happens to equal one of the live values — and
    require it to be watched.

    A hit here is either a counter to add to `_NOUNS`, or a coincidence to
    exclude by name. Both are decisions; neither is silence.
    """
    live = _live()
    values = set(live.values())
    loose = re.compile(r"\b(\d{2,5})\s+([A-Za-zÀ-ÿ][A-Za-zÀ-ÿ_-]*(?: [A-Za-zÀ-ÿ][A-Za-zÀ-ÿ_-]*)?)")
    unwatched = []
    for rel in _CURRENT_STATE:
        for lineno, line in enumerate(
                (_ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
            if _DATED.search(line):
                continue
            for m in loose.finditer(line):
                if int(m.group(1)) not in values:
                    continue
                # Watched already? Compare positions, not words: the loose
                # matcher takes a two-word window and "sections de vérification"
                # is three, so comparing strings would report a phrase the
                # vocabulary does cover.
                if any(w.start() == m.start() for w in _PATTERN.finditer(line)):
                    continue
                noun = m.group(2)
                # The loose window takes two words ("clés sur", "keys in"),
                # so a decision recorded on the head word covers its variants.
                if noun in _COINCIDENCES or noun.split()[0] in _COINCIDENCES:
                    continue
                unwatched.append(f"{rel}:{lineno}  '{m.group(1)} {noun}'")
    assert not unwatched, (
        "these read like counters and match a live value, but no rule watches "
        "them — add the noun to _NOUNS, or the phrase to _COINCIDENCES with a "
        "reason:\n  " + "\n  ".join(unwatched)
    )


def test_the_sweep_reads_something_at_all():
    """A pattern that matched nothing would satisfy every test above."""
    hits = 0
    for rel in _CURRENT_STATE:
        for line in (_ROOT / rel).read_text(encoding="utf-8").splitlines():
            hits += len(_PATTERN.findall(line))
    assert hits >= 10, f"the counter sweep matched only {hits} figures — pattern broke"


def test_changelogs_are_excluded_deliberately():
    """Their numbers describe the release they document, not the tool today."""
    for name in ("CHANGELOG.md", "CHANGELOG_FR.md",
                 "DOCUMENTS/CHANGELOG_FULL.md", "DOCUMENTS/TESTING.md"):
        assert name not in _CURRENT_STATE, (
            f"{name} is a record; sweeping it would demand rewriting history"
        )
