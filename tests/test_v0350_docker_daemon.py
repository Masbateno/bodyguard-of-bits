"""v0.35.0 — the system Docker daemon read from /proc, never started by the audit.

Measured on Linux Mint 22.3 with docker.io 29.1.3 (netnsbench/a10350,
12 November 2026), BOB 0.34.0 against this code:

| case                                               | 0.34.0                          | 0.35.0 |
|----------------------------------------------------|---------------------------------|--------|
| dockerd running                                    | as before                       | as before |
| docker.service stopped, docker.socket active       | `docker ps` STARTED dockerd     | not asked, said; no container runs |
| a live-restore container, dockerd stopped, socket  | started dockerd, audited it     | not asked: 1 container runs, not examined (ceiling) |
| a non-root process listening at /run/docker.sock   | docker group −2                 | INFO: listener uid 65534, not root |
| everything stopped                                 | as before                       | as before |

The listening socket was held by dockerd and systemd (uid 0) while dockerd
ran, by systemd (PID 1) alone under socket activation, and by the non-root
process (uid 65534) in the last case — the socket file read the same each time.
"""

from __future__ import annotations

import os
import stat
from types import SimpleNamespace

from bob.checks import _docker_daemon as DD
from bob.checks import docker as DK
from bob.checks import docker_audit as DA
from bob.visibility import VISIBILITY_KEYS


def _proc(tmp_path, procs, unix_lines=()):
    """A fake /proc: procs = [(pid, comm, uid, cmdline_args, socket_inode_or_None)]."""
    root = tmp_path / "proc"
    root.mkdir()
    (root / "net").mkdir()
    (root / "net" / "unix").write_text(
        "Num       RefCount Protocol Flags    Type St Inode Path\n" + "".join(l + "\n" for l in unix_lines))
    for pid, comm, uid, argv, inode in procs:
        d = root / str(pid)
        (d / "fd").mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
        (d / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        if inode:
            os.symlink(f"socket:[{inode}]", d / "fd" / "3")
    return root


def _patch(monkeypatch, root):
    monkeypatch.setattr(DD, "_PROC", root)
    monkeypatch.setattr(DD, "_PROC_NET_UNIX", root / "net" / "unix")


_LISTEN = "0000000000000000: 00000002 00000000 00010000 0001 01 {ino} /run/docker.sock"


def test_running_dockerd_is_running(tmp_path, monkeypatch):
    _patch(monkeypatch, _proc(tmp_path, [(1, "systemd", 0, ["/sbin/init"], 77), (42, "dockerd", 0, ["dockerd"], 77)],
                              [_LISTEN.format(ino=77)]))
    assert DD.system_dockerd_state() == "running"
    assert DD.socket_listener("/run/docker.sock") == (True, {0})


def test_socket_activation_is_systemd_alone(tmp_path, monkeypatch):
    _patch(monkeypatch, _proc(tmp_path, [(1, "systemd", 0, ["/sbin/init"], 77)], [_LISTEN.format(ino=77)]))
    assert DD.system_dockerd_state() == "socket"


def test_a_non_root_listener_is_not_socket_activation(tmp_path, monkeypatch):
    _patch(monkeypatch, _proc(tmp_path, [(1, "systemd", 0, ["/sbin/init"], None),
                                         (900, "python3", 65534, ["python3"], 88)], [_LISTEN.format(ino=88)]))
    assert DD.system_dockerd_state() == "stopped"
    assert DD.socket_listener("/run/docker.sock") == (True, {65534})


def test_nothing_listening_is_stopped(tmp_path, monkeypatch):
    _patch(monkeypatch, _proc(tmp_path, [(1, "systemd", 0, ["/sbin/init"], None)]))
    assert DD.system_dockerd_state() == "stopped"
    assert DD.socket_listener("/run/docker.sock") == (False, set())


def test_a_rootless_dockerd_is_not_the_system_daemon(tmp_path, monkeypatch):
    _patch(monkeypatch, _proc(tmp_path, [(1, "systemd", 0, ["/sbin/init"], None), (50, "dockerd", 1000, ["dockerd"], None)]))
    assert DD.system_dockerd_state() == "stopped"


def test_unreadable_proc_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(DD, "_PROC", tmp_path / "absent")
    monkeypatch.setattr(DD, "_PROC_NET_UNIX", tmp_path / "absent" / "net" / "unix")
    assert DD.system_dockerd_state() == "unknown"
    assert DD.socket_listener("/run/docker.sock") == (None, None)


def test_moby_shims_are_counted(tmp_path, monkeypatch):
    shim = ["/usr/bin/containerd-shim-runc-v2", "-namespace", "moby", "-id", "705b", "-address", "/run/containerd/containerd.sock"]
    k8s = ["/usr/bin/containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", "aa"]
    _patch(monkeypatch, _proc(tmp_path, [(10, "containerd-shim", 0, shim, None), (11, "containerd-shim", 0, k8s, None)]))
    assert DD.moby_containers() == 1


# --- the container audit -----------------------------------------------------

def _from_system(monkeypatch, state, moby, inspected=None):
    asked = []
    monkeypatch.setattr(DA, "_command_exists", lambda name: name == "docker")
    monkeypatch.setattr(DA, "_rootless_podman", lambda: {})
    monkeypatch.setattr(DA, "_docker_group", lambda: ([], False, [], []))
    monkeypatch.setattr(DA, "_read_userns_remap", lambda: True)
    monkeypatch.setattr(DA, "system_dockerd_state", lambda: state)
    monkeypatch.setattr(DA, "moby_containers", lambda: moby)
    monkeypatch.setattr(DA, "_inspect", lambda rt: asked.append(rt) or (inspected or []))
    return DA.DockerAuditSnapshot.from_system(), asked


def test_socket_activated_dockerd_is_not_asked(monkeypatch):
    snap, asked = _from_system(monkeypatch, "socket", 0)
    assert asked == [] and snap.not_started == ["docker"] and snap.moby_running == 0
    keys = [f.key for f in DA.check_docker_audit(snap).findings]
    assert "docker_hardening.runtime_not_started" in keys
    assert "docker_hardening.no_containers" not in keys


def test_an_unknown_daemon_state_is_not_asked_either(monkeypatch):
    _snap, asked = _from_system(monkeypatch, "unknown", None)
    assert asked == []


def test_a_running_dockerd_is_asked(monkeypatch):
    snap, asked = _from_system(monkeypatch, "running", 0)
    assert asked == ["docker"] and snap.not_started == []


def test_live_containers_not_examined_are_a_ceiling(monkeypatch):
    snap, _ = _from_system(monkeypatch, "socket", 1)
    f = next(f for f in DA.check_docker_audit(snap).findings if f.key.startswith("docker_hardening.runtime_not_started"))
    assert f.key == "docker_hardening.runtime_not_started_live" and f.key in VISIBILITY_KEYS
    snap, _ = _from_system(monkeypatch, "socket", None)
    f = next(f for f in DA.check_docker_audit(snap).findings if f.key.startswith("docker_hardening.runtime_not_started"))
    assert f.key == "docker_hardening.runtime_not_started_unread" and f.key in VISIBILITY_KEYS


def test_a_non_root_listener_gives_no_point(monkeypatch):
    def getgrnam(name):
        return SimpleNamespace(gr_mem=["alice"], gr_gid=999)
    import grp
    import pwd
    monkeypatch.setattr(grp, "getgrnam", getgrnam)
    monkeypatch.setattr(pwd, "getpwall", lambda: [])
    monkeypatch.setattr(DA.os, "stat", lambda p, *a, **k: SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_gid=999)
                        if str(p) == "/var/run/docker.sock" else (_ for _ in ()).throw(FileNotFoundError(p)))
    monkeypatch.setattr(DA, "_unix_listening", lambda path: True)
    monkeypatch.setattr(DA, "_socket_uids", lambda path: {65534})
    members, rw, _listed, nonroot = DA._docker_group()
    assert rw is False and nonroot == [65534]
    snap = DA.DockerAuditSnapshot(runtime="docker", runtimes=["docker"], docker_group_members=members,
                                  docker_socket_group_rw=rw, docker_group_listed=["alice"], docker_socket_nonroot=nonroot)
    res = DA.check_docker_audit(snap)
    assert "docker_hardening.docker_group_not_root" in [f.key for f in res.findings]
    assert sum(d.points for d in res.deductions) == 0
    monkeypatch.setattr(DA, "_socket_uids", lambda path: None)
    assert DA._docker_group()[1] is None                      # holders unknown: unknown


# --- the Docker analysis section ---------------------------------------------

def _docker_from_system(monkeypatch, state, moby, ps_ok=True):
    calls = []
    monkeypatch.setattr(DK, "_command_exists", lambda name: True)
    monkeypatch.setattr(DK, "_check_daemon_json", lambda: (False, False))
    monkeypatch.setattr(DK, "system_dockerd_state", lambda: state)
    monkeypatch.setattr(DK, "moby_containers", lambda: moby)
    monkeypatch.setattr(DK, "_run", lambda *a, **k: calls.append(a) or "")
    monkeypatch.setattr(DK, "run_result", lambda *a, **k: calls.append(a) or SimpleNamespace(ok=ps_ok, stdout=""))
    return DK.DockerSnapshot.from_system(), calls


def test_the_docker_section_never_wakes_a_socket_activated_daemon(monkeypatch):
    snap, calls = _docker_from_system(monkeypatch, "socket", 0)
    assert calls == [] and snap.exposed_read and snap.exposed_ports == []


def test_unlisted_ports_with_containers_running_are_said(monkeypatch):
    snap, _ = _docker_from_system(monkeypatch, "socket", 1)
    assert not snap.exposed_read
    keys = [f.key for f in DK.check_docker(snap).findings]
    assert "docker.exposed_unread" in keys and "docker.no_containers" not in keys
    assert "docker.exposed_unread" in VISIBILITY_KEYS


def test_a_failed_docker_ps_is_not_no_container(monkeypatch):
    snap, _ = _docker_from_system(monkeypatch, "stopped", 2, ps_ok=False)
    assert not snap.exposed_read
    snap, _ = _docker_from_system(monkeypatch, "stopped", 0, ps_ok=False)
    assert snap.exposed_read and snap.exposed_ports == []    # no shim: no container at all


# --- A5: rootless dockerd (measured: dockerd, containerd and the container's
# shim ran as the user; the container reached the internet with the host's
# ip_forward at 0, through slirp4netns) -----------------------------------------

_SHIM = ["/usr/bin/containerd-shim-runc-v2", "-namespace", "moby", "-id", "e6a7"]


def test_a_rootless_shim_is_not_the_system_dockers(tmp_path, monkeypatch):
    _patch(monkeypatch, _proc(tmp_path, [(10, "containerd-shim", 1001, _SHIM, None),
                                         (11, "containerd-shim", 0, _SHIM, None)]))
    assert DD.moby_containers() == 1


def test_rootless_dockerd_counted_by_user(tmp_path, monkeypatch):
    import pwd
    _patch(monkeypatch, _proc(tmp_path, [(20, "dockerd", 1001, ["dockerd"], None),
                                         (21, "containerd-shim", 1001, _SHIM, None),
                                         (22, "dockerd", 0, ["dockerd"], None)]))
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name={1001: "bob"}[uid]))
    assert DD.rootless_dockerd() == {"bob": 1}


def test_a_rootless_dockerd_routes_nothing_through_the_host(monkeypatch):
    from bob.checks import firewall_stack as FS
    from bob.checks import _docker_daemon
    monkeypatch.setattr(_docker_daemon, "system_dockerd_state", lambda: "stopped")
    monkeypatch.setattr(FS, "_process_runs", lambda name: name == "dockerd")   # a dockerd runs, as a user
    assert FS._dockerd_runs() is False


def test_rootless_dockerd_is_said_and_a_ceiling():
    snap = DA.DockerAuditSnapshot(runtime="", rootless_dockerd={"bob": 1})
    f = next(f for f in DA.check_docker_audit(snap).findings if f.key == "docker_hardening.rootless_dockerd")
    assert "bob (1)" in f.message or f.template_vars["users"] == "bob (1)"
    assert f.key in VISIBILITY_KEYS


def test_the_section_runs_for_a_rootless_dockerd_alone():
    import inspect
    from bob import runner
    assert "not s.rootless_dockerd" in inspect.getsource(runner)


# --- A6: containerd's own containers (measured: `ctr -n default run` gave a
# root shim `-namespace default` that no section of 0.34.0 saw) -------------------

def test_containerd_namespaces_outside_docker_and_kubernetes(tmp_path, monkeypatch):
    def shim(ns):
        return ["/usr/bin/containerd-shim-runc-v2", "-namespace", ns, "-id", "x"]
    _patch(monkeypatch, _proc(tmp_path, [(30, "containerd-shim", 0, shim("default"), None),
                                         (31, "containerd-shim", 0, shim("moby"), None),
                                         (32, "containerd-shim", 0, shim("moby-165536.165536"), None),
                                         (33, "containerd-shim", 0, shim("k8s.io"), None),
                                         (34, "containerd-shim", 1001, shim("default"), None)]))
    assert DD.containerd_elsewhere() == {"default": 1}
    assert DD.moby_containers() == 2                       # moby and moby-<uid>.<gid>


def test_containerd_containers_are_said_and_a_ceiling():
    snap = DA.DockerAuditSnapshot(runtime="docker", runtimes=["docker"], containerd_other={"default": 1})
    f = next(f for f in DA.check_docker_audit(snap).findings if f.key == "docker_hardening.containerd_unexamined")
    assert f.template_vars["namespaces"] == "default (1)" and f.key in VISIBILITY_KEYS


def test_the_section_runs_for_containerd_alone():
    import inspect
    from bob import runner
    assert "not s.containerd_other" in inspect.getsource(runner)


# --- after review: the two Docker sections reach the same state -------------

import pytest as _pytest


@_pytest.mark.parametrize("state, moby", [("socket", 0), ("socket", 2), ("unknown", None), ("unknown", 0)])
def test_both_sections_agree_when_dockerd_is_not_asked(monkeypatch, state, moby):
    """docker_hardening and docker read the same /proc state; neither asks
    dockerd, and when containers run (or the count is unknown) both say they
    were not examined — neither says "no container"."""
    from bob.checks import docker_audit as DA
    asked = []
    monkeypatch.setattr(DA, "_command_exists", lambda n: n == "docker")
    monkeypatch.setattr(DA, "system_dockerd_state", lambda: state)
    monkeypatch.setattr(DA, "moby_containers", lambda: moby)
    monkeypatch.setattr(DA, "_rootless_podman", lambda: {})
    monkeypatch.setattr(DA, "rootless_dockerd", lambda: {})
    monkeypatch.setattr(DA, "containerd_elsewhere", lambda: {})
    monkeypatch.setattr(DA, "_group_socket", lambda name, socks: ([], False, [], []))
    monkeypatch.setattr(DA.subprocess, "run", lambda *a, **k: asked.append(a) or SimpleNamespace(returncode=1, stdout="", stderr=""))
    hard = DA.check_docker_audit(DA.DockerAuditSnapshot.from_system())
    exp_snap, calls = _docker_from_system(monkeypatch, state, moby)
    expo = DK.check_docker(exp_snap)
    hard_keys = {f.key for f in hard.findings}
    expo_keys = {f.key for f in expo.findings}
    assert asked == [] and calls == []
    unexamined_h = hard_keys & {"docker_hardening.runtime_not_started_live", "docker_hardening.runtime_not_started_unread"}
    unexamined_e = "docker.exposed_unread" in expo_keys
    assert bool(unexamined_h) == unexamined_e == (moby != 0)
    assert not any(k.endswith("no_containers") for k in hard_keys | expo_keys) or moby == 0
