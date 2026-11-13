"""v0.35.0 — AIDE's baseline is taken on a system one trusts, and BOB says so.

A field audit (Mint desktop, 12 November 2026) noted that "install AIDE and
initialise its database" left out the one condition the database depends on:
it records the files as they are, so a file already changed becomes the
reference.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.file_integrity import FileIntegritySnapshot, check_file_integrity


@pytest.mark.parametrize("lang, word", [("en", "system you trust"), ("fr", "système dont vous êtes sûr")])
@pytest.mark.parametrize("snap", [FileIntegritySnapshot(),
                                  FileIntegritySnapshot(tool="aide", db_exists=False, db_readable=True)],
                         ids=["not_installed", "no_db"])
def test_the_detail_says_where_to_take_the_baseline(lang, word, snap):
    i18n.init(lang)
    try:
        details = " ".join(f.detail or "" for f in check_file_integrity(snap, t=i18n.t).findings)
    finally:
        i18n.init("en")
    assert word in details
