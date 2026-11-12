"""v0.34.0 — the accounts the docker group makes root-equivalent.

Docker's post-install documentation: "The docker group grants root-level
privileges to the user." BOB did not report the group. It now lists its
members (its member list and the accounts whose primary group it is) and
costs 2 points — the level of `NOPASSWD: ALL` in sudoers — while a Docker
socket is a socket owned by that group with group write; with no such socket
(dockerd and its socket stopped) the members are listed without a point.
Measured on Fedora 44 with moby-engine, oracle `docker ps` run by the member
itself (netnsbench/b30340).
"""

from __future__ import annotations

import grp
import pwd
import stat
from types import SimpleNamespace

import pytest

from bob.checks import docker_audit as D


def _fake(monkeypatch, members=("alice",), primary=(), sock_mode=None, sock_gid=999, has_group=True, listening=True):
    def getgrnam(name):
        if not has_group:
            raise KeyError(name)
        return SimpleNamespace(gr_mem=list(members), gr_gid=999)
    users = [SimpleNamespace(pw_name=u, pw_gid=999) for u in primary] + [SimpleNamespace(pw_name="root", pw_gid=0)]
    monkeypatch.setattr(grp, "getgrnam", getgrnam)
    monkeypatch.setattr(pwd, "getpwall", lambda: users)
    def fake_stat(path, *a, **k):
        if sock_mode is None or str(path) != "/var/run/docker.sock":
            raise FileNotFoundError(path)
        return SimpleNamespace(st_mode=sock_mode, st_gid=sock_gid)
    monkeypatch.setattr(D.os, "stat", fake_stat)
    monkeypatch.setattr(D, "_unix_listening", lambda path: listening)


_LIVE = stat.S_IFSOCK | 0o660


@pytest.mark.parametrize("kw, want", [
    (dict(sock_mode=_LIVE), (["alice"], True)),
    (dict(sock_mode=None), (["alice"], False)),
    (dict(sock_mode=stat.S_IFSOCK | 0o600), (["alice"], False)),
    (dict(sock_mode=_LIVE, sock_gid=0), (["alice"], False)),
    (dict(sock_mode=stat.S_IFREG | 0o660), (["alice"], False)),
    (dict(members=(), primary=("bob",), sock_mode=_LIVE), (["bob"], True)),
    (dict(has_group=False), ([], False)),
    (dict(sock_mode=_LIVE, listening=False), (["alice"], False)),
    (dict(sock_mode=_LIVE, listening=None), (["alice"], None)),
], ids=["live", "no-socket", "no-group-write", "other-group", "not-a-socket", "primary-group", "no-group",
        "stale-socket-file", "listeners-unread"])
def test_the_reading(monkeypatch, kw, want):
    _fake(monkeypatch, **kw)
    assert D._docker_group()[:2] == want          # members, socket state


def _keys(members, rw):
    snap = D.DockerAuditSnapshot(runtime="docker", runtimes=["docker"], docker_installed=True,
                                 userns_remap=True, docker_group_members=members, docker_socket_group_rw=rw,
                                 docker_group_listed=members)
    res = D.check_docker_audit(snap)
    return {f.key for f in res.findings}, sum(d.points for d in res.deductions if d.key == "docker_hardening.docker_group_root"), res


def test_live_costs_two_points():
    keys, points, res = _keys(["alice", "bob"], True)
    assert "docker_hardening.docker_group_root" in keys and points == 2
    f = next(f for f in res.findings if f.key == "docker_hardening.docker_group_root")
    assert f.cmd == "sudo gpasswd -d alice docker && sudo gpasswd -d bob docker"


def test_dormant_is_said_not_counted():
    keys, points, _ = _keys(["alice"], False)
    assert "docker_hardening.docker_group_dormant" in keys and points == 0


def test_unread_socket_is_not_counted():
    keys, points, _ = _keys(["alice"], None)
    assert points == 0


def test_the_section_runs_for_the_group_alone():
    import inspect
    from bob import runner
    assert "not s.docker_group_members" in inspect.getsource(runner)


def test_the_listening_flag(tmp_path, monkeypatch):
    """/proc/net/unix as the kernel prints it: Flags 00010000 = listening."""
    f = tmp_path / "unix"
    f.write_text("Num       RefCount Protocol Flags    Type St Inode Path\n"
                 "0000000000000000: 00000002 00000000 00010000 0001 01 4242 /run/docker.sock\n"
                 "0000000000000000: 00000003 00000000 00000000 0001 03 4243 /run/other.sock\n")
    monkeypatch.setattr(D, "_PROC_NET_UNIX", f)
    assert D._unix_listening("/run/docker.sock") is True
    assert D._unix_listening("/run/other.sock") is False
    assert D._unix_listening("/run/absent.sock") is False


# --- After self-review (12 November 2026): D1 an unread socket state is
# unknown, D2 removing a member never runs unattended, D3 the command names
# only the listed members.

def test_d1_unread_socket_state_is_unknown_and_a_ceiling():
    from bob.checks.docker_audit import DockerAuditSnapshot, check_docker_audit
    from bob.visibility import VISIBILITY_KEYS
    snap = DockerAuditSnapshot(runtime="docker", runtimes=["docker"],
                               docker_group_members=["alice"], docker_socket_group_rw=None)
    keys = [f.key for f in check_docker_audit(snap).findings]
    assert "docker_hardening.docker_group_unknown" in keys
    assert "docker_hardening.docker_group_dormant" not in keys
    assert "docker_hardening.docker_group_unknown" in VISIBILITY_KEYS


def test_d2_removing_a_member_is_never_unattended():
    from bob.fixes import _can_apply_unattended
    assert not _can_apply_unattended("sudo gpasswd -d alice docker")
    assert not _can_apply_unattended("sudo gpasswd --delete alice docker")


def test_d3_the_command_names_only_listed_members():
    from bob.checks.docker_audit import DockerAuditSnapshot, check_docker_audit
    snap = DockerAuditSnapshot(runtime="docker", runtimes=["docker"],
                               docker_group_members=["alice", "bob"], docker_group_listed=["alice"],
                               docker_socket_group_rw=True)
    f = next(f for f in check_docker_audit(snap).findings if f.key == "docker_hardening.docker_group_root")
    assert f.cmd == "sudo gpasswd -d alice docker"


def test_d3_listed_members_come_from_the_group_list(monkeypatch):
    import grp
    import pwd
    from bob.checks import docker_audit as da
    monkeypatch.setattr(grp, "getgrnam", lambda n: grp.struct_group(("docker", "x", 999, ["alice"])))
    monkeypatch.setattr(pwd, "getpwall", lambda: [pwd.struct_passwd(("bob", "x", 1001, 999, "", "/home/bob", "/bin/sh"))])
    monkeypatch.setattr(da, "_DOCKER_SOCKETS", ())
    members, rw, listed = da._docker_group()
    assert members == ["alice", "bob"] and listed == ["alice"] and rw is False
