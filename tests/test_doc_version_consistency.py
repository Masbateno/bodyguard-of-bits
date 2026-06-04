"""
Documentation version consistency guard (v0.8.0 drift batch lesson).

The v0.7.4 structural audit surfaced 5 documentation surfaces that had
silently fallen behind ``pyproject.toml::version``:

  - ``man/bob.1`` / ``man/bob.conf.5`` / ``man/bob-profile.5`` ``.TH`` lines
    (``"BOB X.Y.Z"`` field)
  - ``DOCUMENTS/README_TECH.md`` + ``DOCUMENTS/README_TECH_FR.md`` shields.io
    version badge (``shields.io/badge/version-vX.Y.Z-...``)
  - ``debian/changelog`` top entry (``bodyguard-of-bits (X.Y.Z-N)``)
  - ``packaging/rpm/bob.spec`` ``Version:`` field
  - ``CHANGELOG.md`` + ``CHANGELOG_FR.md`` top-row version + corresponding
    sections in ``DOCUMENTS/CHANGELOG_FULL.md`` + ``CHANGELOG_FULL_FR.md``

This guard runs on every CI invocation and every local pre-ship pytest
so a version bump that touches only ``pyproject.toml`` + ``bob/__init__.py``
(the two covered by ``test_version_consistency.py``) but forgets the doc
surfaces fails the suite BEFORE the tag is pushed.

Pattern mirrors ``test_version_consistency.py`` from the v0.7.0b2
release-engineering lesson — same idea, broader scope.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parent.parent


def _read_pyproject_version() -> str:
    """Same helper as ``test_version_consistency.py`` — single regex pass
    over the ``[project]`` table to avoid the Python 3.10 ``tomllib`` gap."""
    content = (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(
        r"^\[project\][^\[]*?^version\s*=\s*[\"']([^\"']+)[\"']",
        content,
        re.MULTILINE | re.DOTALL,
    )
    assert m, "Could not parse pyproject.toml [project].version"
    return m.group(1)


# ---------------------------------------------------------------------------
# Man pages
# ---------------------------------------------------------------------------

_MAN_PAGES = [
    ("man/bob.1",         r'^\.TH\s+BOB\s+1\s+"[^"]+"\s+"BOB\s+([^"]+)"'),
    ("man/bob.conf.5",    r'^\.TH\s+BOB\.CONF\s+5\s+"[^"]+"\s+"BOB\s+([^"]+)"'),
    ("man/bob-profile.5", r'^\.TH\s+BOB-PROFILE\s+5\s+"[^"]+"\s+"BOB\s+([^"]+)"'),
]


@pytest.mark.parametrize("rel_path,pattern", _MAN_PAGES)
def test_man_page_version_matches_pyproject(rel_path: str, pattern: str):
    """The ``.TH`` header's ``"BOB X.Y.Z"`` field must match pyproject.

    A drift here means ``man bob`` reports a stale version, so a distro
    packager who builds a wheel for v0.7.4 ships a man page that says
    ``"BOB 0.6.2"`` — exactly the kind of trust-eroding mismatch the v0.7.4
    audit flagged.
    """
    path = _REPO_ROOT / rel_path
    assert path.exists(), f"{rel_path} not found"
    content = path.read_text(encoding="utf-8")
    m = re.search(pattern, content, re.MULTILINE)
    assert m, f"Could not find .TH line in {rel_path} (pattern {pattern!r})"
    doc_version = m.group(1).strip()
    pyproject_version = _read_pyproject_version()
    assert doc_version == pyproject_version, (
        f"Man page version drift in {rel_path}:\n"
        f"  .TH line says       = {doc_version!r}\n"
        f"  pyproject.toml says = {pyproject_version!r}\n"
        f"Bump the .TH line to match pyproject."
    )


# ---------------------------------------------------------------------------
# Shields.io badges in README_TECH
# ---------------------------------------------------------------------------

_SHIELDS_FILES = [
    "DOCUMENTS/README_TECH.md",
    "DOCUMENTS/README_TECH_FR.md",
]


@pytest.mark.parametrize("rel_path", _SHIELDS_FILES)
def test_shields_badge_version_matches_pyproject(rel_path: str):
    """The shields.io badge must match pyproject.

    Pre-fix shields displayed ``v0.6.2`` for ~5 release cycles after the
    real version had bumped to v0.7.x — a silent trust signal degradation.
    """
    path = _REPO_ROOT / rel_path
    assert path.exists(), f"{rel_path} not found"
    content = path.read_text(encoding="utf-8")
    # Match: img.shields.io/badge/version-vX.Y.Z-...
    m = re.search(
        r"img\.shields\.io/badge/version-v([\d.]+(?:[a-z]\d+)?)-",
        content,
    )
    assert m, f"Could not find shields.io version badge in {rel_path}"
    badge_version = m.group(1)
    pyproject_version = _read_pyproject_version()
    assert badge_version == pyproject_version, (
        f"Shields.io badge version drift in {rel_path}:\n"
        f"  shields.io badge    = {badge_version!r}\n"
        f"  pyproject.toml says = {pyproject_version!r}\n"
        f"Bump the shields.io badge URL to match pyproject."
    )


# ---------------------------------------------------------------------------
# debian/changelog
# ---------------------------------------------------------------------------

def test_debian_changelog_top_entry_matches_pyproject():
    """The first entry of debian/changelog must match pyproject.

    A drift here means the distro packager sees a stale changelog top —
    the very first thing they read when triaging a build. Pre-fix the top
    entry stayed at v0.6.2 even after v0.7.0/0.7.1/0.7.2/0.7.3/0.7.4 had
    shipped to PyPI.
    """
    path = _REPO_ROOT / "debian" / "changelog"
    assert path.exists(), "debian/changelog not found"
    first_line = path.read_text(encoding="utf-8").splitlines()[0]
    # Format: bodyguard-of-bits (X.Y.Z-N) DISTRIBUTION; urgency=...
    m = re.match(r"^bodyguard-of-bits\s+\((\d[^)]+)\)\s+", first_line)
    assert m, f"Could not parse debian/changelog top line: {first_line!r}"
    # Strip the Debian -N revision suffix
    debian_version = m.group(1).rsplit("-", 1)[0]
    pyproject_version = _read_pyproject_version()
    assert debian_version == pyproject_version, (
        f"debian/changelog top entry drift:\n"
        f"  debian/changelog says = {debian_version!r}\n"
        f"  pyproject.toml says   = {pyproject_version!r}\n"
        f"Add a new top entry in debian/changelog matching pyproject."
    )


# ---------------------------------------------------------------------------
# packaging/rpm/bob.spec
# ---------------------------------------------------------------------------

def test_rpm_spec_version_matches_pyproject():
    """``Version:`` field in packaging/rpm/bob.spec must match pyproject.

    Identical concern as the Debian changelog: a stale spec file means
    the COPR/Fedora build references an old release.
    """
    path = _REPO_ROOT / "packaging" / "rpm" / "bob.spec"
    assert path.exists(), "packaging/rpm/bob.spec not found"
    content = path.read_text(encoding="utf-8")
    m = re.search(r"^Version:\s*(\S+)", content, re.MULTILINE)
    assert m, "Could not find 'Version:' field in bob.spec"
    spec_version = m.group(1)
    pyproject_version = _read_pyproject_version()
    assert spec_version == pyproject_version, (
        f"bob.spec Version field drift:\n"
        f"  bob.spec says        = {spec_version!r}\n"
        f"  pyproject.toml says  = {pyproject_version!r}\n"
        f"Bump the Version: field in packaging/rpm/bob.spec."
    )


# ---------------------------------------------------------------------------
# CHANGELOG top row (EN + FR)
# ---------------------------------------------------------------------------

_CHANGELOG_FILES = [
    "CHANGELOG.md",
    "CHANGELOG_FR.md",
]


@pytest.mark.parametrize("rel_path", _CHANGELOG_FILES)
def test_changelog_top_row_matches_pyproject(rel_path: str):
    """The top row of the changelog table must match pyproject.

    Pre-fix CHANGELOG_FR.md stopped at v0.7.0b2 while CHANGELOG.md was
    current at v0.7.4 — a 5-version gap. FR users reading the changelog
    saw the project frozen at a beta. Top-row equality enforces "release
    cycle ships in both languages or the suite refuses to commit".
    """
    path = _REPO_ROOT / rel_path
    assert path.exists(), f"{rel_path} not found"
    content = path.read_text(encoding="utf-8")
    # Find the first table data row: | [vX.Y.Z](#anchor) | ... |
    # Pre-releases include suffix like b4, rc1, etc.
    m = re.search(r"^\|\s*\[v([\d.]+(?:[a-z]\d+)?)\]", content, re.MULTILINE)
    assert m, f"Could not find first version row in {rel_path}"
    top_version = m.group(1)
    pyproject_version = _read_pyproject_version()
    assert top_version == pyproject_version, (
        f"Top changelog row drift in {rel_path}:\n"
        f"  top row says         = {top_version!r}\n"
        f"  pyproject.toml says  = {pyproject_version!r}\n"
        f"Add the missing entry/entries at the top of {rel_path}."
    )


# ---------------------------------------------------------------------------
# CHANGELOG_FULL top section (EN + FR)
# ---------------------------------------------------------------------------

_CHANGELOG_FULL_FILES = [
    "DOCUMENTS/CHANGELOG_FULL.md",
    "DOCUMENTS/CHANGELOG_FULL_FR.md",
]


@pytest.mark.parametrize("rel_path", _CHANGELOG_FULL_FILES)
def test_changelog_full_top_section_matches_pyproject(rel_path: str):
    """First ``## [vX.Y.Z]`` section header must match pyproject.

    Same logic as the table version above, applied to the full-detail
    document. Catches the case where someone bumps CHANGELOG.md (the
    table) but forgets to add the long-form section in
    DOCUMENTS/CHANGELOG_FULL.md.
    """
    path = _REPO_ROOT / rel_path
    assert path.exists(), f"{rel_path} not found"
    content = path.read_text(encoding="utf-8")
    m = re.search(r"^## \[v([\d.]+(?:[a-z]\d+)?)\]", content, re.MULTILINE)
    assert m, f"Could not find first ## [vX.Y.Z] heading in {rel_path}"
    top_section = m.group(1)
    pyproject_version = _read_pyproject_version()
    assert top_section == pyproject_version, (
        f"Top section drift in {rel_path}:\n"
        f"  top section says     = {top_section!r}\n"
        f"  pyproject.toml says  = {pyproject_version!r}\n"
        f"Add the missing section header at the top of {rel_path}."
    )
