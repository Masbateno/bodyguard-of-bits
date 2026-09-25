"""Live-derivable integer claims that the shape-sweep cannot watch.

`test_v0170_doc_counters_sweep` reads every figure that sits before a counted
noun and checks it against the code — but it only matches numbers of **two to
five digits**, so the six-domain count (one digit) is structurally invisible to
it, and its noun vocabulary never grew a "domains" or a locale-key entry. Three
integers drifted across several releases for exactly that reason:

* **domains** — v0.20.0 realigned the seven score domains onto the six display
  groups, but the intros, headings and trees kept saying "7 domains" for four
  releases (the detailed section was updated, the summaries were not);
* **CIS references** — "199" / "174" entries against a file that holds 205, with
  a per-benchmark breakdown that summed but did not match the live per-category
  counts;
* **locale keys** — "2014 keys" against locale files that carry 2595.

Each is exactly derivable from the code or a data file. Pin them directly, with
a matcher that does not need the two-digit floor. Dated lines (those naming a
version or quoting a baseline) are skipped, as in the sweep: their figures
describe a past release.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Documents that describe the tool as it is now (mirrors the v0170 sweep list;
#: changelogs and the TESTING table are per-release records, excluded).
_CURRENT_STATE = [
    "README.md", "README_FR.md",
    "DOCUMENTS/README_TECH.md", "DOCUMENTS/README_TECH_FR.md",
    "DOCUMENTS/README_DEV.md", "DOCUMENTS/README_DEV_FR.md",
    "DOCUMENTS/SNAPSHOT.md",
    "DOCUMENTS/TUTORIAL.md", "DOCUMENTS/TUTORIAL_FR.md",
    "man/bob.1",
]

#: A line naming a version or quoting a baseline is dating its own figure.
_DATED = re.compile(
    r"v0\.[0-9]+\.[0-9]+|Baseline history|Historique de référence|"
    r"baseline was|since v0\.|BREAKING in v0\.|BREAKING en v0\.|realigned|réalign")


def _lines(rel: str):
    for lineno, line in enumerate(
            (_ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
        yield lineno, line


def _locale_key_count() -> int:
    def leaves(o) -> int:
        return sum(leaves(v) if isinstance(v, dict) else 1 for v in o.values())
    counts = {
        lang: leaves(json.loads(
            (_ROOT / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8")))
        for lang in ("en", "fr")
    }
    assert counts["en"] == counts["fr"], f"locale parity broken: {counts}"
    return counts["en"]


def _cis_breakdown() -> dict:
    raw = json.loads(
        (_ROOT / "bob" / "data" / "cis_refs.json").read_text(encoding="utf-8"))
    ubuntu = docker = redhat = best_practice = 0
    for v in raw.values():
        ref = v.get("ref", "")
        if not v.get("code"):
            best_practice += 1
        elif "Docker" in ref:
            docker += 1
        elif "Red Hat" in ref or "RHEL" in ref:
            redhat += 1
        else:
            ubuntu += 1
    return {
        "total": len(raw),
        "ubuntu": ubuntu,
        "docker": docker,
        "redhat": redhat,
        "best_practice": best_practice,
        "formal": ubuntu + redhat,   # README_TECH's "formal CIS" = coded, non-Docker
    }


# --- domains ---------------------------------------------------------------

#: A digit immediately before a "domain"/"domaine" word — one digit is allowed,
#: which the two-digit sweep cannot express. "6 score domains", "6 domaines de
#: score", "6-domain attribution", "6 domain keys" all match.
_DOMAIN_RE = re.compile(
    r"\b(\d+)[ -](?:score |display |on-screen )?(?:domaines?|domains?)\b",
    re.IGNORECASE)


@pytest.mark.parametrize("rel", _CURRENT_STATE)
def test_no_document_misstates_the_score_domain_count(rel):
    from bob.domain_scores import DOMAINS
    n = len(DOMAINS)
    stale = []
    for lineno, line in _lines(rel):
        if _DATED.search(line):
            continue
        for m in _DOMAIN_RE.finditer(line):
            if int(m.group(1)) != n:
                stale.append(f"{rel}:{lineno} claims {m.group(1)} domains, "
                             f"code has {n}")
    assert not stale, (
        "the score-domain count drifted (v0.20.0 realigned 7 → 6 and the "
        "summaries kept saying 7):\n  " + "\n  ".join(stale))


# --- locale keys -----------------------------------------------------------

#: A four-to-five digit figure before a keys/values noun is the locale total
#: (the explain set is three digits, so the two never collide numerically).
_LOCALE_RE = re.compile(r"\b(\d{4,5})\s+(?:keys|clés|values|valeurs)\b",
                        re.IGNORECASE)
#: The SNAPSHOT summary row writes it as "2595 EN ↔ 2595 FR".
_LOCALE_PARITY_RE = re.compile(r"\b(\d{4,5})\s+EN\s*↔\s*(\d{4,5})\s+FR\b")


@pytest.mark.parametrize("rel", _CURRENT_STATE)
def test_no_document_misstates_the_locale_key_total(rel):
    n = _locale_key_count()
    stale = []
    for lineno, line in _lines(rel):
        if _DATED.search(line):
            continue
        for m in _LOCALE_RE.finditer(line):
            if int(m.group(1)) != n:
                stale.append(f"{rel}:{lineno} claims {m.group(1)} locale keys, "
                             f"files hold {n}")
        for m in _LOCALE_PARITY_RE.finditer(line):
            for g in (1, 2):
                if int(m.group(g)) != n:
                    stale.append(f"{rel}:{lineno} claims {m.group(g)} locale "
                                 f"keys, files hold {n}")
    assert not stale, (
        "the locale-key total drifted from the .json files:\n  "
        + "\n  ".join(stale))


# --- CIS breakdown ---------------------------------------------------------

def test_the_readme_tech_cis_breakdown_matches_the_live_categories():
    """v0163 checks the total and that the parts sum to it; this checks each
    part against the live per-category count, so a wrong split that still sums
    is caught."""
    b = _cis_breakdown()
    for rel, pat in (
        ("DOCUMENTS/README_TECH.md",
         r"(\d+) entries \((\d+) formal CIS, (\d+) best-practice, (\d+) Docker\)"),
        ("DOCUMENTS/README_TECH_FR.md",
         r"(\d+) entrées \((\d+) CIS formels, (\d+) best-practice, (\d+) Docker\)"),
    ):
        text = (_ROOT / rel).read_text(encoding="utf-8")
        m = re.search(pat, text)
        assert m, f"{rel}: the CIS breakdown sentence is gone or reshaped"
        total, formal, bp, docker = (int(m.group(i)) for i in range(1, 5))
        assert (total, formal, bp, docker) == (
            b["total"], b["formal"], b["best_practice"], b["docker"]), (
            f"{rel}: says total={total} formal={formal} best-practice={bp} "
            f"Docker={docker}; live is total={b['total']} formal={b['formal']} "
            f"best-practice={b['best_practice']} Docker={b['docker']}")


def test_the_readme_four_way_cis_breakdown_matches_the_live_categories():
    b = _cis_breakdown()
    for rel, pat in (
        ("README.md",
         r"(\d+) entries: \*\*(\d+) CIS Ubuntu 22\.04 · (\d+) CIS Docker 1\.6 · "
         r"(\d+) CIS Red Hat 8/9 · (\d+) best-practice\*\*"),
        ("README_FR.md",
         r"(\d+) entrées : \*\*(\d+) CIS Ubuntu 22\.04 · (\d+) CIS Docker 1\.6 · "
         r"(\d+) CIS Red Hat 8/9 · (\d+) bonnes pratiques\*\*"),
    ):
        text = (_ROOT / rel).read_text(encoding="utf-8")
        m = re.search(pat, text)
        assert m, f"{rel}: the four-way CIS breakdown sentence is gone or reshaped"
        total, ubuntu, docker, redhat, bp = (int(m.group(i)) for i in range(1, 6))
        assert (total, ubuntu, docker, redhat, bp) == (
            b["total"], b["ubuntu"], b["docker"], b["redhat"], b["best_practice"]), (
            f"{rel}: says total={total} Ubuntu={ubuntu} Docker={docker} "
            f"RedHat={redhat} best-practice={bp}; live is total={b['total']} "
            f"Ubuntu={b['ubuntu']} Docker={b['docker']} RedHat={b['redhat']} "
            f"best-practice={b['best_practice']}")


def test_the_matchers_read_something_at_all():
    """A pattern that matched nothing would satisfy every assertion above."""
    dom = loc = 0
    for rel in _CURRENT_STATE:
        for _, line in _lines(rel):
            if _DATED.search(line):
                continue
            dom += len(_DOMAIN_RE.findall(line))
            loc += len(_LOCALE_RE.findall(line))
    assert dom >= 5, f"the domain matcher found only {dom} figures — pattern broke"
    assert loc >= 4, f"the locale matcher found only {loc} figures — pattern broke"


# --- SNAPSHOT "Numbers at a glance" table (metric-then-value layout) ----------
# This table writes each figure as `| Metric | 6 |` — the number FOLLOWS the
# noun, so neither the v0170 sweep nor the matchers above (which want
# "<number> <noun>") can see it. It sat frozen at v0.14.1 for six rows (Score
# domains 7, _PREFIX_TO_DOMAIN 36, Filterable sections 38, …) precisely because
# nothing watched a value-second row. Pin the clean single-integer rows here.

def _glance_value(label_sub: str) -> int:
    """Return the first integer in the value cell of the Numbers-at-a-glance
    row whose Metric cell contains ``label_sub``."""
    text = (_ROOT / "DOCUMENTS" / "SNAPSHOT.md").read_text(encoding="utf-8")
    body = text.split("## Numbers at a glance", 1)
    assert len(body) == 2, "the 'Numbers at a glance' section is gone or renamed"
    for line in body[1].splitlines():
        if line.startswith("|") and label_sub in line:
            cells = [c.strip() for c in line.strip("|").split("|")]
            m = re.search(r"\d+", cells[1])
            assert m, f"no integer in the value cell for {label_sub!r}: {line}"
            return int(m.group())
    raise AssertionError(f"no Numbers-at-a-glance row matched {label_sub!r}")


def test_numbers_at_a_glance_table_matches_live():
    from bob.domain_scores import DOMAINS, _PREFIX_TO_DOMAIN
    from bob.runner import _ALL_SECTIONS, _ALWAYS_ON_SECTIONS
    services = json.loads(
        (_ROOT / "bob" / "data" / "services.json").read_text(encoding="utf-8"))
    expected = {
        "Score domains": len(DOMAINS),
        "_PREFIX_TO_DOMAIN": len(_PREFIX_TO_DOMAIN),
        "Filterable sections": len(_ALL_SECTIONS),
        "Always-on sections": len(_ALWAYS_ON_SECTIONS),
        "Known services": len(services),
    }
    wrong = []
    for label, live in expected.items():
        got = _glance_value(label)
        if got != live:
            wrong.append(f"'{label}' row says {got}, live is {live}")
    assert not wrong, (
        "the SNAPSHOT 'Numbers at a glance' table drifted (value-second layout "
        "that the other guards cannot see):\n  " + "\n  ".join(wrong))
