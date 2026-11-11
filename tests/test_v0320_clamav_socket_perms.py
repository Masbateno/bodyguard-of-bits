"""v0.32.0 — the ClamAV open-socket finding shows the permissions it measured.

The finding said every local user can command the daemon without showing the
mode, owner or directory that ground that verdict (review of a real 0.31.3
audit: srw-rw-rw- clamav:clamav under a drwxr-xr-x /run/clamav on the Mint).
The detail now opens with them, wordless so both locales carry the same facts.
"""

from __future__ import annotations

import os
import socket
import stat

import pytest

from bob import i18n
from bob.checks import clamav as cl
from tests.helpers import _t


@pytest.fixture
def sock(tmp_path):
    path = tmp_path / "clamd.ctl"
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(path))
    os.chmod(path, 0o666)
    yield str(path)
    s.close()


def test_the_measured_facts(sock):
    perms = cl._socket_perms(sock)
    assert perms.startswith("srw-rw-rw- ")
    parent = os.path.dirname(sock)
    assert f"— {parent}: {stat.filemode(os.stat(parent).st_mode)}" in perms


def test_unreadable_is_empty(tmp_path):
    assert cl._socket_perms(str(tmp_path / "missing")) == ""


def test_the_detail_opens_with_them():
    snap = cl.ClamAVSnapshot(installed=True, clamd_active=True, db_age_days=0,
                             clamd_socket_open="/run/clamav/clamd.ctl",
                             clamd_socket_perms="srw-rw-rw- clamav:clamav — /run/clamav: drwxr-xr-x")
    result = cl.check_clamav(snap, t=_t)
    f = next(f for f in result.findings if f.key == "clamav.socket_open_to_all")
    assert "clamav.socket_open_perms" in f.detail and "clamav.socket_open_to_all_detail" in f.detail


def test_without_them_the_old_detail_stands_alone():
    snap = cl.ClamAVSnapshot(installed=True, clamd_active=True, db_age_days=0,
                             clamd_socket_open="/run/clamav/clamd.ctl")
    result = cl.check_clamav(snap, t=_t)
    f = next(f for f in result.findings if f.key == "clamav.socket_open_to_all")
    assert f.detail == "clamav.socket_open_to_all_detail"


def test_from_system_fills_them(monkeypatch, sock):
    monkeypatch.setattr(cl, "_socket_open_to_all", lambda: sock)
    perms = cl._socket_perms(sock)

    monkeypatch.setattr(cl, "_command_exists", lambda c: c in ("clamscan", "systemctl"))
    monkeypatch.setattr(cl, "is_unit_active", lambda u: True)      # clamd_active, deterministically
    monkeypatch.setattr(cl, "unit_active_state", lambda u: "active")
    monkeypatch.setattr(cl, "_run", lambda *a, **k: "")
    monkeypatch.setattr(cl, "path_exists", lambda p: False)
    snap = cl.ClamAVSnapshot.from_system()
    assert snap.clamd_socket_open == sock and snap.clamd_socket_perms == perms


@pytest.mark.parametrize("lang, word", [("en", "Measured: "), ("fr", "Mesuré : ")], ids=["en", "fr"])
def test_the_rendered_prefix(lang, word):
    i18n.init(lang)
    try:
        text = i18n.t("clamav.socket_open_perms", perms="srw-rw-rw- clamav:clamav — /run/clamav: drwxr-xr-x")
    finally:
        i18n.init(lang="en")
    assert text.startswith(word) and "srw-rw-rw-" in text
