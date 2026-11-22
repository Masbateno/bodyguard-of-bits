"""v0.42.0 — "(+N more)" goes through the translation (B-037).

The French output of the developer's workstation audit under 0.40.0 (21
November 2026) read "(+4 more)" and "(+9 more)" under the world-writable
files: ten checks wrote the suffix by hand. One helper now, one key.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bob import i18n
from bob.checks._run import more_suffix

ROOT = Path(__file__).resolve().parent.parent


def test_no_check_writes_the_suffix_by_hand():
    """Guard: the English words outside the translation, anywhere under bob/."""
    found = [f"{p.relative_to(ROOT)}:{n}" for p in sorted((ROOT / "bob").rglob("*.py"))
             for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
             if re.search(r'f".*\(\+\{.*\} more\)"', line) and "``" not in line]   # not the helper's docstring
    # The number alone, " (+{n})", stays allowed: it is language-neutral, and
    # where a value goes into template_vars (rebuilt in another locale) a
    # translated suffix would carry French into an English report.
    assert found == []


@pytest.mark.parametrize("lang, words", [("en", "(+4 more)"), ("fr", "(+4 autres)")])
def test_the_suffix_in_each_language(lang, words):
    before = i18n.current_lang()
    i18n.init(lang)
    try:
        assert more_suffix(i18n.t, 16, 12) == " " + words
        assert more_suffix(i18n.t, 12, 12) == ""
    finally:
        i18n.init(before)


def test_the_measured_section_in_french():
    """The world-writable files of the audit: 16 found, 12 shown."""
    from bob.checks.world_writable import WorldWritableSnapshot, check_world_writable
    files = [f"/home/dev/.cache/f{i}" for i in range(16)]
    before = i18n.current_lang()
    i18n.init("fr")
    try:
        r = check_world_writable(WorldWritableSnapshot(ww_files=files), i18n.t)
        msg = next(f.message for f in r.findings if "f15" not in f.message and "f0" in f.message)
        assert "(+4 autres)" in msg and "more" not in msg
    finally:
        i18n.init(before)


def test_package_integrity_says_the_rest_in_french():
    """The workstation's 28 files, 12 named: "(+16)" read beside "(+4 autres)"."""
    from bob.checks.package_integrity import PackageIntegritySnapshot, check_package_integrity
    snap = PackageIntegritySnapshot(manager="apt", tool="dpkg", tool_available=True, ran=True,
                                    changed_files=[f"/usr/share/x{i}" for i in range(28)])
    before = i18n.current_lang()
    i18n.init("fr")
    try:
        msg = next(f.message for f in check_package_integrity(snap, i18n.t).findings)
    finally:
        i18n.init(before)
    assert "(+16 autres)" in msg
