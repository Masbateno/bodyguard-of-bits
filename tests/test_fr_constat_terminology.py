"""The French interface and documentation say "constat", never "finding".

CONVENTIONS §10 fixes the term: a line of a ``CheckResult`` is a *constat*.
Until this guard, the French locale said "finding" 40 times, "constat" 23 times
and "découverte" 7 times for the same thing, and the French documentation
followed it ("Nouveau finding", "le finding lui-même porte la commande…"). The
documentation cannot be corrected on its own — it would then contradict the
screen — so both are held to the glossary here.

Out of scope, on purpose: the published changelogs and TESTING history (their
entries quote the output of their time), code identifiers (``Finding``,
``result.findings``, the JSON ``findings`` key) and the ``{finding}``
placeholder, which is a variable name, not a word shown to anyone.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: "découverte" in its own sense — discovery of devices or flaws — not a finding.
_DISCOVERY_KEYS = frozenset({
    "logs.local_dominance",
    "service_risk.avahi_local_network_discovery.threat",
    "cups.browsing_on_detail",
    "explain.cpu_security.vulnerable.how",
})

#: The French documents that describe the current tool (not its history).
_FR_DOCS = (
    "README_FR.md",
    "SECURITY_FR.md",
    "DOCUMENTS/README_TECH_FR.md",
    "DOCUMENTS/README_DEV_FR.md",
    "DOCUMENTS/TUTORIAL_FR.md",
    "DOCUMENTS/AUTOMATION_FR.md",
    "DOCUMENTS/CONVENTIONS_FR.md",
    "DOCUMENTS/DOCTRINE_FR.md",
    "DOCUMENTS/RASPBERRY_PI_FR.md",
)

_FINDING = re.compile(r"\bfindings?\b")
_DECOUVERTE = re.compile(r"\bdécouvertes?\b", re.I)
#: The glossary row that names the English term on purpose.
_GLOSSARY_ROW = "| **constat** (finding) |"


def _locale_values(path: Path):
    def walk(node, prefix=""):
        for key, value in node.items():
            dotted = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                yield from walk(value, dotted)
            else:
                yield dotted, value
    yield from walk(json.loads(path.read_text(encoding="utf-8")))


def _prose_lines(text: str):
    """(line number, text) a reader sees as French prose.

    Inline code and link targets are removed; inside fenced blocks only the
    shell/Python comment after ``#`` is kept, since a comment is prose and the
    rest is code or literal output.
    """
    in_block = False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            in_block = not in_block
            continue
        if in_block:
            if "#" not in line:
                continue
            line = line.split("#", 1)[1]
        yield n, re.sub(r"`+[^`]*`+|\]\([^)]*\)", "", line)


class TestFrenchLocale:
    def test_no_value_says_finding(self):
        bad = [
            f"{key}: {value[:80]!r}"
            for key, value in _locale_values(ROOT / "bob/locales/fr.json")
            if _FINDING.search(value.replace("{finding}", ""))
        ]
        assert not bad, "fr.json says 'finding' (CONVENTIONS §10: constat):\n" + "\n".join(bad)

    def test_decouverte_only_means_discovery(self):
        bad = [
            f"{key}: {value[:80]!r}"
            for key, value in _locale_values(ROOT / "bob/locales/fr.json")
            if _DECOUVERTE.search(value) and key not in _DISCOVERY_KEYS
        ]
        assert not bad, "fr.json uses 'découverte' for a finding (say constat):\n" + "\n".join(bad)

    def test_the_discovery_allowlist_is_not_stale(self):
        values = dict(_locale_values(ROOT / "bob/locales/fr.json"))
        stale = [k for k in _DISCOVERY_KEYS if not _DECOUVERTE.search(values.get(k, ""))]
        assert not stale, f"allowlisted keys no longer say 'découverte': {stale}"


@pytest.mark.parametrize("rel", _FR_DOCS)
def test_french_doc_says_constat(rel):
    text = (ROOT / rel).read_text(encoding="utf-8")
    bad = [
        f"{rel}:{n}: {line.strip()[:100]}"
        for n, line in _prose_lines(text)
        if _GLOSSARY_ROW not in line and _FINDING.search(line)
    ]
    assert not bad, "French prose says 'finding' (CONVENTIONS §10: constat):\n" + "\n".join(bad)


def test_the_glossary_still_names_the_english_term():
    """The one sanctioned 'finding' — if the row moves, the exemption is moot."""
    text = (ROOT / "DOCUMENTS/CONVENTIONS_FR.md").read_text(encoding="utf-8")
    assert _GLOSSARY_ROW in text
