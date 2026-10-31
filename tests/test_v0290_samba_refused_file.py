"""v0.29.0 — an smb.conf samba refuses to load is said.

0.28.0 reads a value followed by "# …" or "; …" as samba does — part of the
value — and wrote the limit: samba refuses such a file for a boolean or a
protocol, and BOB did not say so. Measured on Debian 13 (samba 4.22.11, 31
October 2026, `~/.cache/bob-fieldtest/sudoesc/samba_inline_0290.sh`): each of
the 14 yes/no or fixed-choice parameters BOB weighs, with such a tail (even
`mandatory#x`), made testparm exit 1 ("Error loading services") and smbd stop
("Failed to load config file!"); `path`, `server string` and `restrict
anonymous` with the same tail loaded. BOB's list matched testparm's verdict
in all 19 cases. An INFO, and the score a ceiling: what a running smbd uses is
not established.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import samba as sb
from bob.checks.samba import SambaSnapshot, check_samba
from bob.visibility import is_visibility_key

KEY = "samba.conf_refused"


def _refused(tmp_path, glob, share="   guest ok = no"):
    conf = tmp_path / "smb.conf"
    conf.write_text(f"[global]\n   workgroup = WG\n{glob}\n[s]\n   path = /srv/s\n{share}\n")
    out: list = []
    sb._read_smb_conf(conf, refused=out)
    return out


@pytest.mark.parametrize("glob, share, refused", [
    ("   server min protocol = SMB2", "   guest ok = no", []),
    ("   server min protocol = NT1 # legacy printer", "   guest ok = no", ["server min protocol = NT1 # legacy printer"]),
    ("   server signing = mandatory # required", "   guest ok = no", ["server signing = mandatory # required"]),
    ("   map to guest = Bad User ; guests", "   guest ok = no", ["map to guest = Bad User ; guests"]),
    ("   server min protocol = SMB2", "   guest ok = yes # open share", ["guest ok = yes # open share"]),
    ("   server string = File server # main", "   guest ok = no", []),
    ("   restrict anonymous = 2 # strict", "   guest ok = no", []),
    ("   null passwords = yes # legacy", "   guest ok = no", ["null passwords = yes # legacy"]),
    ("   server max protocol = SMB3 # x", "   guest ok = no", ["server max protocol = SMB3 # x"]),
    ("   min protocol = SMB2 ; x", "   guest ok = no", ["min protocol = SMB2 ; x"]),
    ("   bind interfaces only = yes # x", "   guest ok = no", ["bind interfaces only = yes # x"]),
    ("   server min protocol = SMB2", "   public = no # x", ["public = no # x"]),
    ("   server min protocol = SMB2", "   writable = no # x", ["writable = no # x"]),
    ("   server min protocol = SMB2", "   writeable = no ; x", ["writeable = no ; x"]),
    ("   server min protocol = SMB2", "   write ok = no # x", ["write ok = no # x"]),
    ("   server min protocol = SMB2", "   read only = yes # x", ["read only = yes # x"]),
    ("   max protocol = SMB3 # x", "   guest ok = no", ["max protocol = SMB3 # x"]),
    ("   server signing = mandatory#x", "   guest ok = no", ["server signing = mandatory#x"]),
    ("   server min protocol = SMB2", "   path = /srv/s # x", []),
    ("   Server  Signing = mandatory # x", "   guest ok = no", ["Server  Signing = mandatory # x"]),
    ("# server signing = mandatory # x", "   guest ok = no", []),
], ids=["S0", "S1", "S2", "S3", "S4", "S5-string", "S6-integer", "S7", "S8", "S9", "S10", "S11", "S12", "S13",
        "S14", "S15", "S16", "S17-no-space", "S18-path", "spaced-name", "comment-line"])
def test_the_measured_cases(tmp_path, glob, share, refused):
    assert _refused(tmp_path, glob, share) == refused


def test_the_snapshot_collects_them(tmp_path, monkeypatch):
    conf = tmp_path / "smb.conf"
    conf.write_text("[global]\n   server signing = mandatory # required\n")
    monkeypatch.setattr(sb, "_SMB_CONF_PATH", conf)
    monkeypatch.setattr(sb, "_command_exists", lambda name: name == "smbd")
    assert SambaSnapshot.from_system().conf_refused == ["server signing = mandatory # required"]


@pytest.mark.parametrize("lang, words", [("en", "samba refuses to load /etc/samba/smb.conf"),
                                         ("fr", "samba refuse de charger /etc/samba/smb.conf")])
def test_said_with_a_ceiling(lang, words):
    snap = SambaSnapshot(installed=True, daemon_installed=True, conf_readable=True,
                         conf_refused=["guest ok = yes # open share"])
    i18n.init(lang)
    try:
        res = check_samba(snap, t=i18n.t)
    finally:
        i18n.init(lang="en")
    said = [f for f in res.findings if f.key == KEY]
    assert len(said) == 1 and words in said[0].message and "guest ok = yes # open share" in said[0].message
    assert is_visibility_key(KEY)


def test_a_file_samba_loads_says_nothing_of_it():
    snap = SambaSnapshot(installed=True, daemon_installed=True, conf_readable=True)
    assert KEY not in [f.key for f in check_samba(snap, t=lambda k, **kw: k).findings]


def test_the_other_findings_still_weigh_the_file():
    """Review of the 0.29.0 changelog — the INFO says what samba does with the
    file; it does not stand in for the findings that weigh it as written."""
    snap = SambaSnapshot(installed=True, daemon_installed=True, conf_readable=True,
                         smb1_enabled=True, conf_refused=["server signing = mandatory # required"])
    res = check_samba(snap, t=lambda k, **kw: k)
    assert KEY in [f.key for f in res.findings]
    assert "samba.smb1_enabled" in [d.key for d in res.deductions]
