"""The French changelogs are translations of the English ones, not summaries.

Measured on 2026-10-04 and again on 2026-10-08: about thirty sections of
CHANGELOG_FULL_FR and a dozen rows of CHANGELOG_FR had been condensed to a
fraction of the English entry (down to 17 %), dropping the commands, file
names and test names the English entry gives. The second measurement found
three more that the first had missed — its version pattern read ``0.7.0b4`` as
``0.7.0``, so the four betas overwrote the real 0.7.0 section and none of the
five was ever compared. The pattern here knows pre-releases, and a guard
below fails if it stops seeing them.

What is guarded, per release entry: both languages list the same versions,
and the French entry is at least 0.9 × the English length (French runs as long
as or longer than English — measured 1.0–1.2 on full translations; below 0.9
the entry has lost content).

What is not: inline-code parity. It was measured (2026-10-08) and cannot be
told apart from correct translation by a machine — French quotes the French
UI (`✔ Appliqué`, not `✔ Applied`), and nested backticks split into noise
tokens. It stays a reading step of the documentation-conformance pass.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

_VERSION = r"v?\d+\.\d+\.\d+(?:[ab]\d+)?"
_SECTION = re.compile(rf"^## \[({_VERSION})\]", re.M)
_ROW = re.compile(rf"^\| \[({_VERSION})\]\(#[^)]*\) \|.*$", re.M)
_MIN_RATIO = 0.9


def _sections(rel: str) -> "dict[str, str]":
    text = (ROOT / rel).read_text(encoding="utf-8")
    marks = [(m.start(), m.group(1).lstrip("v")) for m in _SECTION.finditer(text)]
    out: dict[str, str] = {}
    for i, (start, version) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        assert version not in out, f"{rel}: two sections for {version}"
        out[version] = text[start:end]
    return out


def _rows(rel: str) -> "dict[str, str]":
    text = (ROOT / rel).read_text(encoding="utf-8")
    return {m.group(1).lstrip("v"): m.group(0) for m in _ROW.finditer(text)}


_PAIRS = {
    "full": ("DOCUMENTS/CHANGELOG_FULL.md", "DOCUMENTS/CHANGELOG_FULL_FR.md", _sections),
    "summary": ("CHANGELOG.md", "CHANGELOG_FR.md", _rows),
}


@pytest.mark.parametrize("pair", sorted(_PAIRS))
def test_every_version_is_in_both_languages(pair):
    en_rel, fr_rel, read = _PAIRS[pair]
    en, fr = read(en_rel), read(fr_rel)
    assert set(en) == set(fr), (
        f"only in EN: {sorted(set(en) - set(fr))}, only in FR: {sorted(set(fr) - set(en))}")


@pytest.mark.parametrize("pair", sorted(_PAIRS))
def test_no_french_entry_is_condensed(pair):
    en_rel, fr_rel, read = _PAIRS[pair]
    en, fr = read(en_rel), read(fr_rel)
    short = {
        v: round(len(fr[v]) / len(en[v]), 2)
        for v in sorted(set(en) & set(fr))
        if len(fr[v]) / len(en[v]) < _MIN_RATIO
    }
    assert not short, f"{fr_rel} entries shorter than {_MIN_RATIO} × English: {short}"


@pytest.mark.parametrize("pair", sorted(_PAIRS))
def test_pre_releases_are_read(pair):
    """The pattern that hid five sections: it must still see the betas."""
    en_rel, _fr, read = _PAIRS[pair]
    assert {"0.7.0", "0.7.0b1", "0.7.0b4"} <= set(read(en_rel))
