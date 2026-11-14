"""v0.36.0 — Incus's groups, read as the lxd group is (and LXD from the Debian package).

Incus's security documentation: "Local access to Incus through the Unix
socket always grants full access to Incus. Therefore, you should only give
such access to users who you'd trust with root access to your system." /
"The root user and all members of the incus-admin group can interact with the
local daemon." The incus group: "restricted to a single project tied to their
user" (authorization page).

Measured on Debian 13 (a10360, 14 November 2026):

| socket (owner, mode)                               | held by              | incus-admin member | incus member      | other   |
|----------------------------------------------------|----------------------|--------------------|-------------------|---------|
| /var/lib/incus/unix.socket (root:incus-admin 660)  | systemd, incusd root | 200, auth trusted  | refused           | refused |
| /var/lib/incus/unix.socket.user (root:incus 660)   | systemd, incus-user root | refused        | answered: project user-1004 (restricted, disks under /home/bobiu, own uid) | refused |
| /var/lib/lxd/unix.socket (root:lxd 660), LXD 5.0.2 .deb | systemd, lxd root | lxd member: 200, auth trusted |   | refused |

LXD from the Debian package needed no change: 0.35.0 already read that path
and counted the member (the _lxd system account named apart).
"""

from __future__ import annotations

import inspect

from bob.checks import docker_audit as D


def _snap(**kw):
    base = dict(incus_admin_members=["bobia"], incus_admin_listed=["bobia"], incus_admin_socket_rw=True)
    base.update(kw)
    return D.DockerAuditSnapshot(**base)


def _engine(snap, ignore=frozenset()):
    from bob.scoring import ScoreEngine
    res = D.check_docker_audit(snap)
    engine = ScoreEngine()
    engine.ignore_keys = frozenset(ignore)
    engine.apply(res, section="docker_hardening")
    return res, {d.key: d.points for d in engine.breakdown}


def test_incus_admin_with_a_root_listener_costs_two_points():
    res, kept = _engine(_snap())
    assert kept == {"docker_hardening.incus_admin_group_root": 2}
    f = next(f for f in res.findings if f.key == "docker_hardening.incus_admin_group_root")
    assert f.level.value == "warn" and f.cmd == "sudo gpasswd -d bobia incus-admin" and f.note == ""


def test_with_the_docker_group_live_the_same_power_counts_once():
    snap = _snap(docker_group_members=["alice"], docker_group_listed=["alice"], docker_socket_group_rw=True)
    res, kept = _engine(snap)
    assert kept == {"docker_hardening.docker_group_root": 2}
    f = next(f for f in res.findings if f.key == "docker_hardening.incus_admin_group_root")
    assert f.note == "docker_hardening.incus_admin_group_root_counted_once"


def test_with_lxd_and_incus_both_live_two_points_once():
    snap = _snap(lxd_group_members=["bob"], lxd_group_listed=["bob"], lxd_socket_group_rw=True)
    _res, kept = _engine(snap)
    assert sum(kept.values()) == 2


def test_an_ignored_docker_group_leaves_incus_counted():
    snap = _snap(docker_group_members=["alice"], docker_group_listed=["alice"], docker_socket_group_rw=True)
    _res, kept = _engine(snap, ignore={"docker_hardening.docker_group_root"})
    assert kept == {"docker_hardening.incus_admin_group_root": 2}


def test_no_root_listener_costs_nothing():
    for kw, key in (({"incus_admin_socket_rw": False}, "docker_hardening.incus_admin_group_dormant"),
                    ({"incus_admin_socket_rw": None}, "docker_hardening.incus_admin_group_unknown"),
                    ({"incus_admin_socket_rw": False, "incus_admin_nonroot": [1500]}, "docker_hardening.incus_admin_group_not_root")):
        res, kept = _engine(_snap(**kw))
        assert kept == {} and key in {f.key for f in res.findings}, kw


def test_unknown_is_a_ceiling_and_the_rest_is_not():
    from bob.visibility import VISIBILITY_KEYS
    assert "docker_hardening.incus_admin_group_unknown" in VISIBILITY_KEYS
    for k in ("incus_admin_group_root", "incus_admin_group_dormant", "incus_admin_group_not_root", "incus_user_group"):
        assert f"docker_hardening.{k}" not in VISIBILITY_KEYS


def test_the_incus_group_is_said_and_not_counted():
    res, kept = _engine(D.DockerAuditSnapshot(incus_user_members=["bobiu"]))
    assert kept == {}
    f = next(f for f in res.findings if f.key == "docker_hardening.incus_user_group")
    assert f.level.value == "info" and not f.cmd


def test_from_system_reads_both_groups_on_their_own_sockets(monkeypatch):
    seen = {}

    def gs(name, socks):
        seen[name] = [str(s) for s in socks]
        return {"incus-admin": (["bobia"], True, ["bobia"], []), "incus": (["bobiu"], True, ["bobiu"], [])}.get(name, ([], False, [], []))
    monkeypatch.setattr(D, "_group_socket", gs)
    monkeypatch.setattr(D, "_command_exists", lambda n: False)
    monkeypatch.setattr(D, "_rootless_podman", lambda: {})
    monkeypatch.setattr(D, "rootless_dockerd", lambda: {})
    monkeypatch.setattr(D, "containerd_elsewhere", lambda: {})
    snap = D.DockerAuditSnapshot.from_system()
    assert seen["incus-admin"] == ["/var/lib/incus/unix.socket"]
    assert seen["incus"] == ["/var/lib/incus/unix.socket.user"]
    assert snap.incus_admin_members == ["bobia"] and snap.incus_admin_socket_rw is True
    assert snap.incus_user_members == ["bobiu"]


def test_the_section_runs_for_the_incus_groups_alone():
    from bob import runner
    src = inspect.getsource(runner)
    assert "not s.incus_admin_members" in src and "not s.incus_user_members" in src
