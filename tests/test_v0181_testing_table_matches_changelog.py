"""Every row of the TESTING history table matches its release's changelog.

The existing test-count guard compares SNAPSHOT with the four changelogs for
the *current* release. TESTING.md carries a row per release and nothing read
it: v0.18.0 shipped with 9959 tests and its row said 9832, the count from a
commit made before the release's last eight. Checking the table against the
changelogs turned up one older row as well — v0.15.5, where the table said
8089 and the changelog 8134. Collecting the tests at the `v0.15.5` tag gives
8089; the changelog was the one that was wrong, and is corrected.

Every row is checked, not just the top one, so a figure that was wrong at
release time cannot survive into the history.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent


def _changelog_counts(rel: str) -> "dict[str, int]":
    text = (_ROOT / rel).read_text(encoding="utf-8")
    parts = re.split(r"^## \[(v?[\d.]+[a-z0-9]*)\][^\n]*$", text, flags=re.M)
    counts = {}
    for i in range(1, len(parts), 2):
        m = re.search(r"\*\*Tests\*\*[^\n→]*→\s*\*\*(\d{3,})\*\*", parts[i + 1])
        if m:
            counts[parts[i]] = int(m.group(1))
    return counts


def _table_rows(rel: str) -> "list[tuple[str, int]]":
    text = (_ROOT / rel).read_text(encoding="utf-8")
    return [(v, int(n)) for v, n in
            re.findall(r"^\| (v?[\d.]+[a-z0-9]*) \| (\d{3,}) \|", text, re.M)]


@pytest.mark.parametrize("table,changelog", [
    ("DOCUMENTS/TESTING.md", "DOCUMENTS/CHANGELOG_FULL.md"),
    ("DOCUMENTS/TESTING_FR.md", "DOCUMENTS/CHANGELOG_FULL_FR.md"),
])
def test_every_row_matches_its_changelog(table, changelog):
    counts = _changelog_counts(changelog)
    rows = _table_rows(table)
    compared = [(v, n) for v, n in rows if v in counts]
    # The mirror: a parse that matched nothing would make this vacuous.
    assert len(compared) >= 20, f"only {len(compared)} rows could be compared"
    wrong = [f"{v}: table {n}, changelog {counts[v]}"
             for v, n in compared if n != counts[v]]
    assert not wrong, f"{table} disagrees with {changelog}:\n  " + "\n  ".join(wrong)


def test_the_current_release_has_its_row():
    version = re.search(r'^version = "([^"]+)"',
                        (_ROOT / "pyproject.toml").read_text(), re.M).group(1)
    for table in ("DOCUMENTS/TESTING.md", "DOCUMENTS/TESTING_FR.md"):
        rows = dict(_table_rows(table))
        # SemVer no-"v" from 0.21.0 on; historical rows keep their v.
        assert version in rows or f"v{version}" in rows, (
            f"{table} has no {version} row")
