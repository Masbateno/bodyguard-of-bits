"""v0.32.0 — package integrity names its limit, "clean" or not.

The digests debsums/rpm -Va compare against live in the local package
database: a compromised root can rewrite them together with the files (review
of a real 0.31.3 audit). The OK finding now says this check attests
consistency with that database, not an external chain of trust.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.package_integrity import PackageIntegritySnapshot, check_package_integrity
from tests.helpers import _t


def test_clean_carries_the_limit():
    snap = PackageIntegritySnapshot(manager="apt", tool="debsums", tool_available=True, ran=True, changed_files=())
    result = check_package_integrity(snap, t=_t)
    f = next(f for f in result.findings if f.key == "package_integrity.clean")
    assert f.detail == "package_integrity.local_digests_limit"


def test_changed_carries_it_too():
    """Measured on Linux Mint 22.3: real hosts show changed files, not
    "clean" — a file changed together with its digest is not in that list."""
    snap = PackageIntegritySnapshot(manager="apt", tool="debsums", tool_available=True, ran=True,
                                    changed_files=("/usr/bin/x",))
    result = check_package_integrity(snap, t=_t)
    f = next(f for f in result.findings if f.key == "package_integrity.changed")
    assert "package_integrity.changed_detail" in f.detail
    assert "package_integrity.local_digests_limit" in f.detail


@pytest.mark.parametrize("lang, words", [
    ("en", "a compromised root can rewrite them"),
    ("fr", "un root compromis peut les réécrire")], ids=["en", "fr"])
def test_the_rendered_limit(lang, words):
    i18n.init(lang)
    try:
        text = i18n.t("package_integrity.local_digests_limit")
    finally:
        i18n.init(lang="en")
    assert words in text
