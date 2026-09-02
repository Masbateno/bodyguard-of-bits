"""samba accepts spellings BOB did not read.

Backlog item 3, samba half. The path to smb.conf was verified identical across
five distribution families in v0.15.2, but *what the check reads inside it* had
never been confronted with samba's own parser.

Two directives had a synonym BOB ignored, and testparm — samba's authority on
what a configuration resolves to — was asked rather than the documentation:

    writeable = yes   →  read only = No     (identical to writable = yes)
    directory = /srv  →  path = /srv

The first is not cosmetic. A world-writable guest share written with the "e"
was reported as `samba.guest_readonly` (WARN, 1 point) instead of
`samba.guest_writable` (ALERT, 2 points) — the severity of an anonymous
writable share, halved, on a spelling samba treats as the same word.

The tests write a real smb.conf and drive ``SambaSnapshot.from_system``. An
earlier draft in v0.15.3 asserted against its own copy of the parsing logic;
reinjecting the defect killed nothing, because the tests were checking
themselves.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import bob.checks.samba as samba_mod
from bob.checks.samba import SambaSnapshot, check_samba

GLOBAL = "[global]\n   workgroup = WG\n"


def snapshot_for(conf_body: str, tmp_path: Path) -> SambaSnapshot:
    conf = tmp_path / "smb.conf"
    conf.write_text(GLOBAL + conf_body, encoding="utf-8")
    original = samba_mod._SMB_CONF_PATH
    samba_mod._SMB_CONF_PATH = conf
    try:
        return SambaSnapshot.from_system()
    finally:
        samba_mod._SMB_CONF_PATH = original


def guest_share(conf_body: str, tmp_path: Path):
    shares = snapshot_for(conf_body, tmp_path).guest_shares
    assert shares, "no guest share detected — the fixture did not bite"
    return shares[0]


SHARE = "[part]\n   guest ok = yes\n   path = /srv/data\n"


class TestEverySpellingOfWritable:
    @pytest.mark.parametrize(
        "line",
        ["writable = yes", "writeable = yes", "write ok = yes", "read only = no"],
    )
    def test_the_share_is_writable(self, line, tmp_path):
        assert guest_share(SHARE + f"   {line}\n", tmp_path).writable is True

    def test_the_benign_twin_is_not_writable(self, tmp_path):
        """Without this, a check that answered True unconditionally would pass
        every case above."""
        assert guest_share(SHARE + "   read only = yes\n", tmp_path).writable is False

    @pytest.mark.parametrize(
        "line", ["writable = yes", "writeable = yes", "write ok = yes", "read only = no"]
    )
    def test_the_finding_is_the_alert_not_the_warning(self, line, tmp_path):
        result = check_samba(snapshot_for(SHARE + f"   {line}\n", tmp_path))
        keys = [f.key for f in result.findings if "guest" in f.key]
        assert keys == ["samba.guest_writable"], (
            f"{line!r} produced {keys} — an anonymous writable share must not "
            f"degrade to guest_readonly on a spelling samba accepts"
        )
        assert sum(d.points for d in result.deductions) == 2


class TestPathSynonym:
    @pytest.mark.parametrize("line", ["path = /srv/data", "directory = /srv/data"])
    def test_the_path_is_read(self, line, tmp_path):
        body = "[part]\n   guest ok = yes\n   writable = yes\n" + f"   {line}\n"
        assert guest_share(body, tmp_path).path == "/srv/data"


class TestAgainstTestparm:
    """samba's own parser is the authority on what a spelling resolves to."""

    @pytest.mark.skipif(shutil.which("testparm") is None, reason="samba not installed")
    @pytest.mark.parametrize(
        "line", ["writable = yes", "writeable = yes", "write ok = yes"]
    )
    def test_testparm_resolves_the_spelling_to_read_only_no(self, line, tmp_path):
        conf = tmp_path / "smb.conf"
        conf.write_text(GLOBAL + SHARE + f"   {line}\n", encoding="utf-8")
        out = subprocess.run(
            ["testparm", "-s", "--suppress-prompt", str(conf)],
            capture_output=True, text=True,
        ).stdout
        assert "read only = No" in out, (
            f"testparm did not treat {line!r} as writable — the premise of the "
            f"BOB-side tests above no longer holds"
        )

    @pytest.mark.skipif(shutil.which("testparm") is None, reason="samba not installed")
    def test_testparm_resolves_directory_to_path(self, tmp_path):
        conf = tmp_path / "smb.conf"
        conf.write_text(GLOBAL + "[part]\n   guest ok = yes\n   directory = /srv/data\n",
                        encoding="utf-8")
        out = subprocess.run(
            ["testparm", "-s", "--suppress-prompt", str(conf)],
            capture_output=True, text=True,
        ).stdout
        assert "path = /srv/data" in out
