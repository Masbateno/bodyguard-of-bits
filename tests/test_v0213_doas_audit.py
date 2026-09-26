"""BOB must audit doas, not only sudo.

Alpine (and OpenBSD) use **doas** in place of sudo; `permit nopass` in
/etc/doas.conf is the passwordless-root equivalent of sudo's `NOPASSWD:ALL`. A
sudo-only audit was blind to it: a forged `permit nopass baduser as root`
produced no finding (measured on a real Alpine 3.24, v0.21.2 field campaign).

The check now parses /etc/doas.conf: a `permit nopass` with no `cmd` clause is
unrestricted passwordless root (WARN −2, mirroring NOPASSWD:ALL); one scoped to a
`cmd` is the specific-command case (INFO); a `deny` never grants; a FIFO or
denied file reads as unreadable (never a hang).
"""

from __future__ import annotations

from bob.checks import file_perms
from bob.checks.file_perms import (
    FilePermsSnapshot,
    _collect_doas_nopass,
    check_file_perms,
)
from tests.helpers import _deduction_points, _keys, _t


# --- pure check logic -------------------------------------------------------

def test_full_permit_nopass_is_warned_and_scored():
    snap = FilePermsSnapshot(doas_nopass_all=["permit nopass baduser as root"])
    result = check_file_perms(snap, t=_t)
    assert "file_perms.doas_nopass_all" in _keys(result)
    assert _deduction_points(result) == 2


def test_specific_permit_nopass_is_info_only():
    snap = FilePermsSnapshot(
        doas_nopass_specific=["permit nopass deploy cmd /usr/bin/systemctl"])
    result = check_file_perms(snap, t=_t)
    assert "file_perms.doas_nopass_specific" in _keys(result)
    assert _deduction_points(result) == 0


def test_unreadable_doas_conf_is_surfaced():
    snap = FilePermsSnapshot(doas_readable=False)
    result = check_file_perms(snap, t=_t)
    assert "file_perms.doas_unreadable" in _keys(result)


# --- collector (parses /etc/doas.conf) --------------------------------------

def test_collector_classifies_permit_deny_and_cmd(tmp_path, monkeypatch):
    conf = tmp_path / "doas.conf"
    conf.write_text(
        "# comment\n"
        "permit nopass baduser as root\n"          # full → nopass_all
        "permit nopass deploy cmd /usr/bin/apk\n"   # scoped → nopass_specific
        "permit persist alice as root\n"            # nopass absent → ignored
        "deny nopass eve\n",                        # deny → never a grant
        encoding="utf-8",
    )
    monkeypatch.setattr(file_perms, "_DOAS_CONF", conf)

    nopass_all, nopass_specific, readable = _collect_doas_nopass()

    assert readable is True
    assert any("baduser" in r for r in nopass_all)
    assert not any("deploy" in r for r in nopass_all)   # scoped is not "all"
    assert any("deploy" in r for r in nopass_specific)
    assert not any("alice" in r for r in nopass_all + nopass_specific)
    assert not any("eve" in r for r in nopass_all + nopass_specific)


def test_collector_absent_file_is_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(file_perms, "_DOAS_CONF", tmp_path / "nope.conf")
    nopass_all, nopass_specific, readable = _collect_doas_nopass()
    assert (nopass_all, nopass_specific, readable) == ([], [], True)


def test_collector_fifo_reads_as_unreadable_no_hang(tmp_path, monkeypatch):
    import os
    import signal

    conf = tmp_path / "doas.conf"
    os.mkfifo(conf)
    monkeypatch.setattr(file_perms, "_DOAS_CONF", conf)

    class _Hang(BaseException):
        pass

    def _boom(signum, frame):
        raise _Hang

    old = signal.signal(signal.SIGALRM, _boom)
    signal.alarm(5)
    try:
        nopass_all, nopass_specific, readable = _collect_doas_nopass()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)

    assert readable is False
    assert nopass_all == [] and nopass_specific == []
