"""v0.35.0 — every link of the short changelogs reaches a heading.

The version table of CHANGELOG.md and CHANGELOG_FR.md linked each row to
``#v0340``-style anchors. GitHub makes a heading's anchor from its text
(``## [0.34.0] — 2026-11-12`` → ``#0340--2026-11-12``) and the entries live in
DOCUMENTS/CHANGELOG_FULL(_FR).md: none of the 125 links per file went
anywhere. The anchors are computed here the way GitHub does, and every link to
a changelog file must land on a heading of that file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SHORT = ("CHANGELOG.md", "CHANGELOG_FR.md")


def _slug(heading: str) -> str:
    s = heading.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def _anchors(path: Path) -> set:
    seen: dict = {}
    out = set()
    in_code = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            in_code = not in_code
        if in_code:
            continue
        m = re.match(r"^#{1,6} (.+)$", line)
        if not m:
            continue
        base = _slug(m.group(1))
        n = seen.get(base, 0)
        out.add(base if n == 0 else f"{base}-{n}")
        seen[base] = n + 1
    return out


def test_the_slug_is_githubs():
    assert _slug("[0.34.0] — 2026-11-12") == "0340--2026-11-12"
    assert _slug("[v0.7.0b4] — 2026-06-01") == "v070b4--2026-06-01"


@pytest.mark.parametrize("name", _SHORT)
def test_every_changelog_link_lands_on_a_heading(name):
    path = _ROOT / name
    links = re.findall(r"\]\(((?:DOCUMENTS/)?CHANGELOG[A-Z_]*\.md)?#([^)\s]+)\)", path.read_text(encoding="utf-8"))
    assert len(links) >= 120, "the version table's links were not found"
    cache: dict = {}
    dead = []
    for target, anchor in links:
        f = (path.parent / target) if target else path
        if f not in cache:
            cache[f] = _anchors(f)
        if anchor not in cache[f]:
            dead.append(f"{target or name}#{anchor}")
    assert not dead, f"{name}: {len(dead)} dead link(s), first: {dead[:3]}"


@pytest.mark.parametrize("name, full", [("CHANGELOG.md", "CHANGELOG_FULL.md"),
                                        ("CHANGELOG_FR.md", "CHANGELOG_FULL_FR.md")])
def test_each_language_links_its_own_full_changelog(name, full):
    text = (_ROOT / name).read_text(encoding="utf-8")
    other = "CHANGELOG_FULL_FR.md" if full == "CHANGELOG_FULL.md" else "CHANGELOG_FULL.md"
    assert f"DOCUMENTS/{full}#" in text and f"DOCUMENTS/{other}#" not in text
