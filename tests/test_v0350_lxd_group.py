"""v0.35.0 — the lxd group, read as the docker group is.

LXD's security documentation (LXD 7.0): "Local access to LXD through the Unix
socket always grants full access to LXD. Therefore, you should only give such
access to users who you'd trust with root access to your system", and "The
root user and all members of the lxd group can interact with the local
daemon." 0.34.0 did not read the group.

Measured on Ubuntu Server 26.04, LXD 5.21 snap (netnsbench/a70350): the socket
/var/snap/lxd/common/lxd/unix.socket is srw-rw---- root lxd; with the daemon
idle it is held by systemd (PID 1) alone; a member's request on it was
answered "auth: trusted", a non-member's refused; `snap stop lxd.daemon`
stopped the socket too (no listener).
"""

from __future__ import annotations

import grp
import pwd
import stat
from types import SimpleNamespace

import pytest

from bob.checks import docker_audit as D

_SNAP_SOCK = "/var/snap/lxd/common/lxd/unix.socket"
_LIVE = stat.S_IFSOCK | 0o660


def _fake(monkeypatch, sock_mode=_LIVE, listening=True, uids=frozenset({0}), members=("alice",)):
    monkeypatch.setattr(grp, "getgrnam", lambda name: SimpleNamespace(gr_mem=list(members), gr_gid=101)
                        if name == "lxd" else (_ for _ in ()).throw(KeyError(name)))
    monkeypatch.setattr(pwd, "getpwall", lambda: [SimpleNamespace(pw_name="root", pw_gid=0)])

    def fake_stat(path, *a, **k):
        if sock_mode is None or str(path) != _SNAP_SOCK:
            raise FileNotFoundError(path)
        return SimpleNamespace(st_mode=sock_mode, st_gid=101)
    monkeypatch.setattr(D.os, "stat", fake_stat)
    monkeypatch.setattr(D, "_unix_listening", lambda path: listening)
    monkeypatch.setattr(D, "_socket_uids", lambda path: set(uids) if uids is not None else None)


@pytest.mark.parametrize("kw, want", [
    (dict(), (["alice"], True, [])),                         # the measured idle state: PID 1 (root) holds it
    (dict(listening=False), (["alice"], False, [])),         # snap stop: no listener
    (dict(sock_mode=None), (["alice"], False, [])),
    (dict(uids={1001}), (["alice"], False, [1001])),
    (dict(uids=None), (["alice"], None, [])),
], ids=["socket-activated", "stopped", "no-socket", "non-root-listener", "holders-unread"])
def test_the_reading(monkeypatch, kw, want):
    _fake(monkeypatch, **kw)
    members, rw, _listed, nonroot = D._group_socket("lxd", D._LXD_SOCKETS)
    assert (members, rw, nonroot) == want


def test_the_snap_socket_is_read(monkeypatch):
    assert _SNAP_SOCK in {str(p) for p in D._LXD_SOCKETS}


def _check(rw, nonroot=()):
    snap = D.DockerAuditSnapshot(lxd_group_members=["alice"], lxd_group_listed=["alice"],
                                 lxd_socket_group_rw=rw, lxd_socket_nonroot=list(nonroot))
    res = D.check_docker_audit(snap)
    return ({f.key for f in res.findings},
            sum(d.points for d in res.deductions if d.key == "docker_hardening.lxd_group_root"), res)


def test_a_root_listener_costs_two_points_and_offers_gpasswd():
    keys, points, res = _check(True)
    assert "docker_hardening.lxd_group_root" in keys and points == 2
    f = next(f for f in res.findings if f.key == "docker_hardening.lxd_group_root")
    assert f.cmd == "sudo gpasswd -d alice lxd"


@pytest.mark.parametrize("rw, nonroot, key", [
    (False, (), "docker_hardening.lxd_group_dormant"),
    (None, (), "docker_hardening.lxd_group_unknown"),
    (False, (1001,), "docker_hardening.lxd_group_not_root"),
])
def test_no_root_listener_costs_nothing(rw, nonroot, key):
    keys, points, _res = _check(rw, nonroot)
    assert key in keys and points == 0


def test_unknown_is_a_ceiling():
    from bob.visibility import VISIBILITY_KEYS
    assert "docker_hardening.lxd_group_unknown" in VISIBILITY_KEYS


def test_the_section_runs_for_the_lxd_group_alone():
    from bob import runner
    import inspect
    assert "not s.lxd_group_members" in inspect.getsource(runner)


def test_from_system_reads_the_lxd_group(monkeypatch):
    seen = []
    monkeypatch.setattr(D, "_group_socket", lambda name, socks: seen.append(name) or (["alice"], True, ["alice"], []))
    monkeypatch.setattr(D, "_command_exists", lambda n: False)
    monkeypatch.setattr(D, "_rootless_podman", lambda: {})
    monkeypatch.setattr(D, "rootless_dockerd", lambda: {})
    monkeypatch.setattr(D, "containerd_elsewhere", lambda: {})
    snap = D.DockerAuditSnapshot.from_system()
    assert "lxd" in seen and snap.lxd_group_members == ["alice"] and snap.lxd_socket_group_rw is True


# --- decided after review: the same power counts once per host, in the engine

def _both(docker_rw=True, lxd_rw=True, ignore=frozenset(), profile=None):
    from bob.scoring import ScoreEngine
    snap = D.DockerAuditSnapshot(docker_group_members=["alice"], docker_group_listed=["alice"],
                                 docker_socket_group_rw=docker_rw,
                                 lxd_group_members=["bob"], lxd_group_listed=["bob"], lxd_socket_group_rw=lxd_rw)
    res = D.check_docker_audit(snap)
    engine = ScoreEngine(profile=profile)
    engine.ignore_keys = frozenset(ignore)
    engine.apply(res, section="docker_hardening")
    return res, {d.key: d.points for d in engine.breakdown}


def test_docker_and_lxd_cost_two_points_once():
    res, kept = _both()
    assert kept == {"docker_hardening.docker_group_root": 2}
    f = next(f for f in res.findings if f.key == "docker_hardening.lxd_group_root")
    assert f.level.value == "warn" and f.note == "docker_hardening.lxd_group_root_counted_once"
    assert f.cmd == "sudo gpasswd -d bob lxd"


def test_lxd_counts_when_the_docker_group_does_not():
    res, kept = _both(docker_rw=False)
    assert kept == {"docker_hardening.lxd_group_root": 2}
    assert next(f for f in res.findings if f.key == "docker_hardening.lxd_group_root").note == ""


def test_lxd_counts_when_docker_is_unknown():
    _res, kept = _both(docker_rw=None)
    assert kept == {"docker_hardening.lxd_group_root": 2}


def test_an_ignored_docker_group_leaves_lxd_counted():
    """The hole the second review led to: decided in the check, an --ignore
    of the docker group's finding took both groups' points with it."""
    _res, kept = _both(ignore={"docker_hardening.docker_group_root"})
    assert kept == {"docker_hardening.lxd_group_root": 2}


def test_a_profile_that_waives_the_docker_group_leaves_lxd_counted():
    from bob.profiles import AuditProfile
    prof = AuditProfile(name="custom", overrides={"docker_hardening.docker_group_root": "info"})
    _res, kept = _both(profile=prof)
    assert kept == {"docker_hardening.lxd_group_root": 2}


# --- decided after review: system accounts named apart ----------------------

def test_system_accounts_are_named_apart(monkeypatch):
    accounts = {"lxd": SimpleNamespace(pw_uid=999, pw_shell="/bin/false"),
                "alice": SimpleNamespace(pw_uid=1000, pw_shell="/bin/bash"),
                "svc": SimpleNamespace(pw_uid=998, pw_shell="/bin/sh")}
    monkeypatch.setattr(pwd, "getpwnam", lambda n: accounts[n])
    assert D._system_accounts(["alice", "lxd", "svc"]) == ["lxd"]
    from bob import i18n
    i18n.init("en")
    assert D._members_text(["alice", "lxd"], ["lxd"], i18n.t) == "alice; system account(s): lxd"
    assert D._members_text(["lxd"], ["lxd"], i18n.t) == "system account(s): lxd"


def test_the_message_names_the_system_account_apart():
    snap = D.DockerAuditSnapshot(lxd_group_members=["alice", "lxd"], lxd_group_listed=["alice"],
                                 lxd_group_system=["lxd"], lxd_socket_group_rw=True)
    f = next(f for f in D.check_docker_audit(snap).findings if f.key == "docker_hardening.lxd_group_root")
    assert "users=alice; docker_hardening.group_system_accounts" in f.message


def test_a_listener_held_by_root_and_another_account_counts(monkeypatch):
    """After review 2: holders of mixed uids. A root process holding the
    listening socket can accept on it, so the group counts — a cautious
    choice, not measured (the measured listeners were all root or all not)."""
    _fake(monkeypatch, uids={0, 1001})
    assert D._group_socket("lxd", D._LXD_SOCKETS)[1] is True
