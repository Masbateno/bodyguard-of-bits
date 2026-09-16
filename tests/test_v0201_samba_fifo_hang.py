"""A smb.conf that is a FIFO must be refused, not read until it blocks.

``read_text_capped`` was written in v0.14.1 specifically to stop BOB hanging
forever on a named pipe ("a cron job hangs instead of failing, and does so
again on every subsequent run" — the worst outcome). But ``_read_smb_conf``
handed the path straight to ``configparser.RawConfigParser.read``, which does
``open(path).read()`` with no guard, re-introducing the exact hang for
/etc/samba/smb.conf.

Found by the v0.20.x Debian stress pass: ``mkfifo /etc/samba/smb.conf`` then
``--check samba`` never returned (killed at a 25 s timeout). The fix routes the
read through ``read_text_capped``, whose ``is_file()`` check refuses the FIFO
*before* opening it — so this test returns immediately whether or not the fix
is present; it fails (not hangs) on a regression, because the unfixed reader
would block on the empty pipe forever, which pytest's own run timeout would
surface, and the polarity test below pins the graceful-degradation behaviour.
"""

from __future__ import annotations

import errno
import os

import pytest

from bob.checks.samba import SambaSnapshot, _read_smb_conf


def test_fifo_smb_conf_is_refused_not_read(tmp_path):
    fifo = tmp_path / "smb.conf"
    os.mkfifo(fifo)
    with pytest.raises(OSError) as exc:
        _read_smb_conf(fifo)
    # Non-regular file → EINVAL from read_text_capped, never an open() that
    # blocks on the empty pipe.
    assert exc.value.errno == errno.EINVAL


def test_directory_smb_conf_is_refused(tmp_path):
    """A deterministic mutation-killer that never blocks: ``configparser.read``
    silently *skips* a directory (open() raises OSError, which it swallows and
    returns []), so a reader that bypasses ``read_text_capped`` would parse
    nothing and raise nothing. The capped reader refuses it with EINVAL."""
    d = tmp_path / "smb.conf"
    d.mkdir()
    with pytest.raises(OSError) as exc:
        _read_smb_conf(d)
    assert exc.value.errno == errno.EINVAL


def test_from_system_degrades_to_unreadable_on_a_fifo(tmp_path, monkeypatch):
    """End-to-end: the caller's `except OSError` must turn the hang into an
    honest unreadable-config snapshot, not a silent all-defaults one."""
    fifo = tmp_path / "smb.conf"
    os.mkfifo(fifo)
    monkeypatch.setattr("bob.checks.samba._SMB_CONF_PATH", fifo)
    monkeypatch.setattr("bob.checks.samba.path_exists", lambda p: True)

    snap = SambaSnapshot.from_system()

    # Honest degradation: config was not read, so nothing is asserted about it.
    assert snap.conf_readable is False


def test_a_regular_smb_conf_still_parses(tmp_path):
    conf = tmp_path / "smb.conf"
    conf.write_text("[global]\n    server min protocol = SMB2\n", encoding="utf-8")
    parsed = _read_smb_conf(conf)
    assert parsed["global"]["server min protocol"] == "SMB2"


def test_an_unreadable_smb_conf_raises_rather_than_reading_nothing(tmp_path):
    """The v0.15.x property: a present-but-unreadable file must raise, so the
    caller does not fall back to defaults after reading zero bytes."""
    conf = tmp_path / "smb.conf"
    conf.write_text("[global]\n", encoding="utf-8")
    conf.chmod(0o000)
    if os.access(conf, os.R_OK):  # running as root ignores the mode; skip then
        pytest.skip("cannot make a file unreadable as this user")
    with pytest.raises(OSError):
        _read_smb_conf(conf)
