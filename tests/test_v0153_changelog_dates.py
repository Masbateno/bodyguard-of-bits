"""v0.15.3 — the changelogs mixed two date formats.

The structural date fields — the version table's date column and the
``## [vX] — date`` headings — follow one convention per language: ISO
(YYYY-MM-DD) in the English files, DD-MM-YYYY in the French ones. v0.15.2 and
v0.15.3 were written ISO on the French side, breaking a column that had been
uniform for seventy releases.

Prose dates are deliberately not checked: both forms appear in running text on
both sides, and some are quoted machine output that must stay verbatim — an
ISO 8601 timestamp, a CSV row, a ``.TH`` man-page directive.

The cross-language check is the one that matters most: the same version must
carry the same actual day in both languages, whatever the format.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

ISO = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DMY = re.compile(r"^\d{2}-\d{2}-\d{4}$")

ENGLISH = ("CHANGELOG.md", "DOCUMENTS/CHANGELOG_FULL.md")
FRENCH = ("CHANGELOG_FR.md", "DOCUMENTS/CHANGELOG_FULL_FR.md")

ROW = re.compile(r"^\| \[(v[0-9.]+)\]\(#v[0-9]+\) \| ([0-9-]+) \|")
HEAD = re.compile(r"^## \[(v[0-9.]+)\] — ([0-9-]+)\s*$")


def structural_dates(rel: str) -> dict[str, str]:
    """version -> raw date string, from table rows and section headings."""
    found: dict[str, str] = {}
    for line in (ROOT / rel).read_text(encoding="utf-8").splitlines():
        m = ROW.match(line) or HEAD.match(line)
        if m:
            found.setdefault(m.group(1), m.group(2))
    return found


def as_day(raw: str) -> date:
    if ISO.match(raw):
        y, m, d = raw.split("-")
    else:
        d, m, y = raw.split("-")
    return date(int(y), int(m), int(d))


class TestOneFormatPerLanguage:
    @pytest.mark.parametrize("rel", ENGLISH)
    def test_english_files_use_iso(self, rel):
        wrong = {v: d for v, d in structural_dates(rel).items() if not ISO.match(d)}
        assert not wrong, f"{rel}: expected YYYY-MM-DD, got {wrong}"

    @pytest.mark.parametrize("rel", FRENCH)
    def test_french_files_use_day_first(self, rel):
        wrong = {v: d for v, d in structural_dates(rel).items() if not DMY.match(d)}
        assert not wrong, f"{rel}: expected DD-MM-YYYY, got {wrong}"

    @pytest.mark.parametrize("rel", ENGLISH + FRENCH)
    def test_the_check_actually_reads_dates(self, rel):
        """A regex that matched nothing would pass forever."""
        assert len(structural_dates(rel)) >= 4


class TestBothLanguagesAgreeOnTheDay:
    @pytest.mark.parametrize(
        "en_rel, fr_rel",
        [("CHANGELOG.md", "CHANGELOG_FR.md"),
         ("DOCUMENTS/CHANGELOG_FULL.md", "DOCUMENTS/CHANGELOG_FULL_FR.md")],
    )
    def test_same_version_same_day(self, en_rel, fr_rel):
        en, fr = structural_dates(en_rel), structural_dates(fr_rel)
        shared = sorted(set(en) & set(fr))
        assert shared, "no version documented in both languages"
        mismatched = {
            v: (en[v], fr[v]) for v in shared if as_day(en[v]) != as_day(fr[v])
        }
        assert not mismatched, f"same version, different day: {mismatched}"


class TestDatesAreRealAndOrdered:
    @pytest.mark.parametrize("rel", ENGLISH + FRENCH)
    def test_every_date_is_a_real_calendar_day(self, rel):
        """DD-MM vs MM-DD confusion shows up as an impossible month."""
        for version, raw in structural_dates(rel).items():
            try:
                as_day(raw)
            except ValueError as exc:
                pytest.fail(f"{rel} {version}: {raw!r} is not a date ({exc})")

    @pytest.mark.parametrize("rel", ENGLISH + FRENCH)
    def test_newest_entry_is_not_in_the_future(self, rel):
        newest = max(as_day(d) for d in structural_dates(rel).values())
        assert newest <= date.today(), f"{rel}: newest entry dated {newest}"
