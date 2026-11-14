"""v0.37.0 — a clamd socket open to everyone costs a point only if SHUTDOWN works.

The point (0.25.0) was for "any local account can turn the antivirus off",
measured in 0.24.4 with ClamAV 1.4, which has no option to refuse SHUTDOWN.
ClamAV 1.5 has one, and Ubuntu 24.04's clamav-daemon 1.5.4 writes it false.
Found reviewing a real 0.37.0 audit (Linux Mint 22.3, 14 November 2026):
BOB took the point while the daemon answered an unprivileged SHUTDOWN with
COMMAND UNAVAILABLE. Measured in Ubuntu 24.04 containers, an unprivileged user
on the srw-rw-rw- socket (netnsbench a10370, clamd-shutdown-ubuntu2404.txt):

| EnableShutdownCommand | PING | SHUTDOWN            | clamd after |
|-----------------------|------|---------------------|-------------|
| false (as packaged)   | PONG | COMMAND UNAVAILABLE | running     |
| no                    | PONG | COMMAND UNAVAILABLE | running     |
| true                  | PONG | connection closed   | stopped     |
| (no line at all)      | PONG | connection closed   | stopped     |

Decided with the user (14 November 2026): refused → INFO, no point; absent (measured: stops) or
any other value → the WARN −1 stays.
"""

from __future__ import annotations

from bob.checks import clamav as cl
from tests.helpers import _t

_SOCK = "/var/run/clamav/clamd.ctl"


def _confs(monkeypatch, tmp_path, *texts):
    paths = []
    for i, text in enumerate(texts):
        p = tmp_path / f"clamd{i}.conf"
        p.write_text(text)
        paths.append(p)
    monkeypatch.setattr(cl, "_CLAMD_CONFS", tuple(paths))


def test_false_and_no_refuse(monkeypatch, tmp_path):
    for value in ("false", "no", "False"):
        _confs(monkeypatch, tmp_path, f"LocalSocket {_SOCK}\nEnableShutdownCommand {value}\n")
        assert cl._shutdown_refused(_SOCK) is True, value


def test_true_absent_or_unmeasured_keep_it(monkeypatch, tmp_path):
    for body in ("EnableShutdownCommand true\n", "", "EnableShutdownCommand 0\n",
                 "EnableShutdownCommand false\nEnableShutdownCommand true\n"):
        _confs(monkeypatch, tmp_path, f"LocalSocket {_SOCK}\n{body}")
        assert cl._shutdown_refused(_SOCK) is False, body


def test_only_the_file_that_names_the_socket_counts(monkeypatch, tmp_path):
    _confs(monkeypatch, tmp_path, "LocalSocket /run/clamd.scan/clamd.sock\nEnableShutdownCommand false\n",
           f"LocalSocket {_SOCK}\n")
    assert cl._shutdown_refused(_SOCK) is False


def _check(refused):
    snap = cl.ClamAVSnapshot(installed=True, clamd_active=True, db_age_days=0,
                             clamd_socket_open=_SOCK, clamd_shutdown_refused=refused)
    return cl.check_clamav(snap, t=_t)


def test_refused_is_said_without_a_point():
    r = _check(True)
    assert any(f.key == "clamav.socket_open_shutdown_refused" for f in r.findings)
    assert not any(d.key.startswith("clamav.socket_open") for d in r.deductions)


def test_not_refused_keeps_the_point():
    r = _check(False)
    assert [d.points for d in r.deductions if d.key == "clamav.socket_open_to_all"] == [1]
    assert not any(f.key == "clamav.socket_open_shutdown_refused" for f in r.findings)


def test_from_system_reads_it(monkeypatch, tmp_path):
    _confs(monkeypatch, tmp_path, f"LocalSocket {_SOCK}\nEnableShutdownCommand false\n")
    monkeypatch.setattr(cl, "_socket_open_to_all", lambda: _SOCK)
    monkeypatch.setattr(cl, "_socket_perms", lambda p: "")
    monkeypatch.setattr(cl, "_command_exists", lambda c: c in ("clamscan", "systemctl"))
    monkeypatch.setattr(cl, "is_unit_active", lambda u: True)
    monkeypatch.setattr(cl, "unit_active_state", lambda u: "active")
    monkeypatch.setattr(cl, "_run", lambda *a, **k: "")
    monkeypatch.setattr(cl, "path_exists", lambda p: False)
    snap = cl.ClamAVSnapshot.from_system()
    assert snap.clamd_socket_open == _SOCK and snap.clamd_shutdown_refused is True
