"""v0.36.0 — smb.conf synonyms and [global] share defaults, read as samba reads them.

Measured with testparm 4.19.5 on Linux Mint 22.3 (a10360, 14 November 2026),
`testparm -s --section-name S --parameter-name P` for the effective value:

| smb.conf                                                     | testparm              | BOB 0.35.0          |
|--------------------------------------------------------------|-----------------------|---------------------|
| server min protocol = SMB2, then min protocol = NT1          | NT1                   | SMB2 (first spelling)|
| server max protocol = SMB3, then protocol = NT1              | max NT1               | SMB3 (protocol unread)|
| [s] path = /srv/a, then directory = /srv/b                   | /srv/b                | /srv/a              |
| [s] guest ok = yes, then public = no                         | guest ok = No         | guest share         |
| [s] writeable = yes, then read only = yes                    | read only = Yes       | writable            |
| [s] write ok = yes, then read only = yes                     | read only = Yes       | writable            |
| [global] guest ok = yes, read only = no; [s] path only       | s: guest, writable    | nothing             |
| [global] public = yes; [s] path only                         | s: guest ok = Yes     | nothing             |
| [s] declared before [global] guest ok = yes                  | s: guest ok = No      | nothing (right)     |
| repeated [s]: guest ok = yes, then guest ok = no             | guest ok = No         | No (right, 0.28.0)  |
"""

from __future__ import annotations

import pytest

from bob.checks import samba as sm


def _conf(tmp_path, text):
    conf = tmp_path / "smb.conf"
    conf.write_text(text, encoding="utf-8")
    return sm._read_smb_conf(conf)


def _snap(tmp_path, monkeypatch, text):
    conf = tmp_path / "smb.conf"
    conf.write_text(text, encoding="utf-8")
    monkeypatch.setattr(sm, "_SMB_CONF_PATH", conf)
    monkeypatch.setattr(sm, "_command_exists", lambda c: c == "smbd")
    return sm.SambaSnapshot.from_system()


GLOBAL = {
    "min-short-last": ("[global]\nserver min protocol = SMB2\nmin protocol = NT1\n", "server min protocol", "NT1"),
    "min-long-last": ("[global]\nmin protocol = NT1\nserver min protocol = SMB2\n", "server min protocol", "SMB2"),
    "protocol-last": ("[global]\nserver max protocol = SMB3\nprotocol = NT1\n", "server max protocol", "NT1"),
    "max-short-last": ("[global]\nserver max protocol = NT1\nmax protocol = SMB3\n", "server max protocol", "SMB3"),
}


@pytest.mark.parametrize("name", GLOBAL)
def test_the_last_spelling_wins_in_global(tmp_path, name):
    text, param, want = GLOBAL[name]
    assert sm._section_get(_conf(tmp_path, text)["global"], param) == want


def test_smb1_written_last_under_the_short_name_is_seen(tmp_path, monkeypatch):
    snap = _snap(tmp_path, monkeypatch, "[global]\nserver min protocol = SMB2\nmin protocol = NT1\n")
    assert snap.smb1_enabled is True


def test_protocol_sets_the_maximum(tmp_path, monkeypatch):
    snap = _snap(tmp_path, monkeypatch, "[global]\nserver max protocol = SMB3\nprotocol = NT1\n")
    assert snap.smb1_enabled is True


SHARES = {
    "guest-then-public-no": ("[global]\n[s]\npath=/tmp\nguest ok = yes\npublic = no\n", None),
    "public-no-then-guest": ("[global]\n[s]\npath=/tmp\npublic = no\nguest ok = yes\n", False),
    "writeable-then-ro": ("[global]\n[s]\npath=/tmp\nguest ok = yes\nwriteable = yes\nread only = yes\n", False),
    "ro-then-writeable": ("[global]\n[s]\npath=/tmp\nguest ok = yes\nread only = yes\nwriteable = yes\n", True),
    "writeok-then-ro": ("[global]\n[s]\npath=/tmp\nguest ok = yes\nwrite ok = yes\nread only = yes\n", False),
    "writable-then-writeable-no": ("[global]\n[s]\npath=/tmp\nguest ok = yes\nwritable = yes\nwriteable = no\n", False),
    "global-defaults": ("[global]\nguest ok = yes\nread only = no\n[s]\npath=/tmp\n", True),
    "global-public": ("[global]\npublic = yes\n[s]\npath=/tmp\n", False),
    "share-before-global": ("[s]\npath=/tmp\n[global]\nguest ok = yes\nread only = no\n", None),
    "share-overrides-global": ("[global]\nguest ok = yes\n[s]\npath=/tmp\nguest ok = no\n", None),
    "repeated-share": ("[global]\n[s]\npath=/tmp\nguest ok = yes\n[t]\npath=/tmp\n[s]\nguest ok = no\n", None),
}


@pytest.mark.parametrize("name", SHARES)
def test_guest_shares_as_testparm_reads_them(tmp_path, monkeypatch, name):
    """None: [s] is not a guest share; True/False: a guest share, writable or not."""
    text, want = SHARES[name]
    shares = {s.name: s for s in _snap(tmp_path, monkeypatch, text).guest_shares}
    if want is None:
        assert "s" not in shares
    else:
        assert shares["s"].writable is want


def test_directory_written_last_is_the_path(tmp_path, monkeypatch):
    snap = _snap(tmp_path, monkeypatch, "[global]\n[s]\nguest ok = yes\npath = /srv/a\ndirectory = /srv/b\n")
    assert snap.guest_shares[0].path == "/srv/b"


def test_a_global_default_writable_guest_share_is_an_alert(tmp_path, monkeypatch):
    snap = _snap(tmp_path, monkeypatch, "[global]\nguest ok = yes\nread only = no\n[data]\npath=/srv/data\n")
    r = sm.check_samba(snap)
    assert any(f.key == "samba.guest_writable" for f in r.findings)
