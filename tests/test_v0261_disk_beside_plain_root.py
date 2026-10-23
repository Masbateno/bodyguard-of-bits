"""v0.26.1 — beside an unencrypted root, the unencrypted data is named too.

Found on a Mint host (0.26.0): / on a plain ext4 partition was reported, /home
on its own plain ext4 partition was not — BOB named the data beside the root
only when the root was encrypted. Same finding, same point; the detail names it.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.disk_encryption import DiskEncryptionSnapshot, check_disk_encryption


def _snap(extra):
    return DiskEncryptionSnapshot(readable=True, root_encrypted=False, root_source="/dev/nvme1n1p2",
                                  extra_volumes=extra)


MINT = [("/home", "/dev/nvme0n1p1", False), ("swap", "/dev/nvme1n1p3", False)]


def _finding(res, key):
    return next(f for f in res.findings if f.key == key)


def test_the_data_beside_is_named_and_the_point_is_unchanged():
    res = check_disk_encryption(_snap(MINT), t=lambda k, **kw: f"{k}{kw}", profile_name="workstation")
    f = _finding(res, "disk_encryption.root_unencrypted")
    assert "/home (/dev/nvme0n1p1), swap (/dev/nvme1n1p3)" in f.detail
    assert [(d.key, d.points) for d in res.deductions] == [("disk_encryption.root_unencrypted", 1)]


def test_the_server_info_names_it_too():
    res = check_disk_encryption(_snap(MINT), t=lambda k, **kw: f"{k}{kw}", profile_name="server")
    assert "/home (/dev/nvme0n1p1)" in _finding(res, "disk_encryption.root_unencrypted_server").detail


@pytest.mark.parametrize("extra", [[], [("/data", "/dev/sdb1", None)], [("/srv", "/dev/mapper/x", True)]])
def test_nothing_unencrypted_beside_adds_nothing(extra):
    res = check_disk_encryption(_snap(extra), t=lambda k, **kw: k, profile_name="workstation")
    assert _finding(res, "disk_encryption.root_unencrypted").detail == "disk_encryption.root_unencrypted_detail"


@pytest.mark.parametrize("lang, words", [("en", "not encrypted either"), ("fr", "pas chiffrées non plus")])
def test_the_sentence_renders(lang, words):
    i18n.init(lang)
    try:
        res = check_disk_encryption(_snap(MINT), t=i18n.t, profile_name="workstation")
    finally:
        i18n.init(lang="en")
    assert words in _finding(res, "disk_encryption.root_unencrypted").detail
