"""The Debian changelog must describe the versions it claims to describe.

Found in v0.16.3: the `0.16.3-1` entry carried the **v0.16.0** text — "the
score went up when BOB could see less" — and there was no `0.16.1` or `0.16.2`
entry at all. The file had been version-bumped three releases running without
its contents being rewritten, and nothing noticed, because nothing looked.

Two shapes of that failure, and one invariant each.

**Bumping without rewriting** leaves two entries saying the same thing. The
0.16.3 entry was byte-identical to the v0.16.0 story it should never have
carried, so requiring every entry's opening bullet to be unique catches it
exactly. It also catches the lazier version — copying the previous entry and
editing only its version number.

**Skipping releases** leaves gaps. Every version documented in
`CHANGELOG_FULL.md` at or above the oldest Debian entry must have one, and no
Debian entry may name a version the changelog has never heard of.

Neither is a style rule. A distribution packager reads this file to know what
they are shipping, and both defects tell them about a different release.
"""

from __future__ import annotations

import collections
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DEBIAN = _ROOT / "debian" / "changelog"
_FULL = _ROOT / "DOCUMENTS" / "CHANGELOG_FULL.md"

_ENTRY = re.compile(r"^bodyguard-of-bits \(([0-9.]+)-\d+\)", re.M)
_BULLET = re.compile(r"^  \* (.+)$", re.M)


def _entries() -> "dict[str, str]":
    """Version -> entry body, in file order (newest first)."""
    text = _DEBIAN.read_text(encoding="utf-8")
    blocks = re.split(r"^(?=bodyguard-of-bits \()", text, flags=re.M)
    out = {}
    for block in blocks:
        m = _ENTRY.match(block)
        if m:
            out[m.group(1)] = block
    return out


def _version_key(v: str) -> "tuple[int, ...]":
    return tuple(int(part) for part in v.split("."))


def _documented_versions() -> "list[str]":
    return re.findall(r"^## \[v?([0-9.]+)\]", _FULL.read_text(encoding="utf-8"), re.M)


def test_the_harness_reads_a_real_changelog():
    """A parser that matched nothing would satisfy every check below."""
    entries = _entries()
    assert len(entries) > 20, f"only {len(entries)} Debian entries parsed"
    assert _documented_versions(), "no versions parsed out of CHANGELOG_FULL"


def test_the_newest_entry_is_the_version_being_built():
    from bob import __version__
    newest = next(iter(_entries()))
    assert newest == __version__, (
        f"debian/changelog opens on {newest}, the package is {__version__} — "
        f"the file was not opened for this release"
    )


def test_no_two_entries_open_on_the_same_sentence():
    """Two entries saying the same thing means one was bumped, not written.

    That is precisely what happened to 0.16.3: it carried v0.16.0's text.
    """
    opening = {}
    for version, block in _entries().items():
        bullets = _BULLET.findall(block)
        if bullets:
            opening[version] = bullets[0].strip()
    shared = collections.defaultdict(list)
    for version, text in opening.items():
        shared[text].append(version)
    dupes = {t: v for t, v in shared.items() if len(v) > 1}
    assert not dupes, (
        "these versions open on identical text, so at least one was bumped "
        "without being rewritten: "
        + "; ".join(f"{v} -> {t[:70]!r}" for t, v in dupes.items())
    )


def test_every_entry_has_something_to_say():
    thin = [v for v, block in _entries().items() if not _BULLET.findall(block)]
    assert not thin, f"Debian entries with no bullet at all: {thin}"


def test_no_release_is_missing_its_entry():
    """0.16.1 and 0.16.2 had none — two published releases, unrepresented."""
    entries = _entries()
    floor = _version_key(min(entries, key=_version_key))
    expected = [v for v in _documented_versions() if _version_key(v) >= floor]
    missing = [v for v in expected if v not in entries]
    assert not missing, (
        f"released and documented, but absent from debian/changelog: {missing}"
    )


def test_no_entry_invents_a_release():
    documented = set(_documented_versions())
    unknown = [v for v in _entries() if v not in documented]
    assert not unknown, (
        f"debian/changelog names versions CHANGELOG_FULL has never heard of: "
        f"{unknown}"
    )


@pytest.mark.parametrize("version", list(_entries())[:6])
def test_the_recent_entries_do_not_repeat_the_previous_release(version):
    """A near-copy is the same defect as an exact one, one edit away.

    Compares the whole bullet list, not just the first line: an entry that
    shares every bullet with its predecessor was copied forward.
    """
    entries = _entries()
    versions = list(entries)
    i = versions.index(version)
    if i + 1 >= len(versions):
        pytest.skip("oldest entry in the window has no predecessor")
    mine = set(_BULLET.findall(entries[version]))
    theirs = set(_BULLET.findall(entries[versions[i + 1]]))
    if not mine or not theirs:
        pytest.skip("one of the two entries has no bullets")
    assert not mine <= theirs, (
        f"{version} says nothing its predecessor {versions[i + 1]} did not — "
        f"it was copied forward rather than written"
    )
