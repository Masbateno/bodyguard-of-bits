"""v0.33.0 — every container runtime present is asked; rootless podman is said.

Before: the first runtime found (Docker) was the only one asked — a host with
both left Podman's containers unexamined — and a failed `docker ps` (dockerd
stopped) read as "no running container". Rootless podman containers, which
root's `podman ps` does not list, were not mentioned at all. Decided with the
user (11 November 2026): BOB runs nothing as another user; it sees rootless
containers through their `conmon` monitor in /proc, says they were not
examined, and the score becomes a ceiling. Measured on Fedora 44 (podman
5.8.1, moby-engine) — netnsbench/b10330.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from bob.checks import docker_audit as D
from bob.visibility import VISIBILITY_KEYS


def _container(cid, name, privileged=False):
    return {"Id": cid, "Name": "/" + name, "HostConfig": {"Privileged": privileged, "NetworkMode": "bridge"},
            "Mounts": [], "Config": {"User": "1000"}}


def _env(monkeypatch, per_runtime, present=("docker", "podman")):
    """per_runtime: runtime -> list of containers, or None for a failing ps."""
    def run(argv, **kw):
        rt, verb = argv[0], argv[1]
        conts = per_runtime.get(rt)
        if conts is None:
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="Cannot connect to the Docker daemon")
        if verb == "ps":
            return subprocess.CompletedProcess(argv, 0, stdout="".join(c["Id"] + "\n" for c in conts), stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(conts), stderr="")
    monkeypatch.setattr(D, "_command_exists", lambda n: n in present)
    monkeypatch.setattr(D.subprocess, "run", run)
    monkeypatch.setattr(D, "_read_userns_remap", lambda: True)
    monkeypatch.setattr(D, "_rootless_podman", lambda: {})
    # 0.34.0, found by the CI: the GitHub runner's account is in the docker
    # group and dockerd listens there — the real group reader added
    # docker_group_root to findings these tests count exactly.
    monkeypatch.setattr(D, "_docker_group", lambda: ([], False, []))


def test_both_runtimes_are_asked(monkeypatch):
    _env(monkeypatch, {"docker": [_container("d1", "web")], "podman": [_container("p1", "pod", privileged=True)]})
    snap = D.DockerAuditSnapshot.from_system()
    assert snap.running_count == 2 and snap.privileged_containers == ["pod"]
    f = next(x for x in D.check_docker_audit(snap).findings if x.key == "docker_hardening.privileged")
    assert f.cmd.startswith("podman inspect")


def test_one_container_both_list_counts_once(monkeypatch):
    same = [_container("x1", "shared", privileged=True)]
    _env(monkeypatch, {"docker": same, "podman": same})          # podman-docker's docker runs podman
    snap = D.DockerAuditSnapshot.from_system()
    assert snap.running_count == 1 and snap.privileged_containers == ["shared"]


def test_a_failed_ps_is_not_no_container(monkeypatch):
    _env(monkeypatch, {"docker": None, "podman": [_container("p1", "pod", privileged=True)]})
    snap = D.DockerAuditSnapshot.from_system()
    assert snap.failed_runtimes == ["docker"] and not snap.scan_error
    keys = {f.key for f in D.check_docker_audit(snap).findings}
    assert {"docker_hardening.runtime_unreachable", "docker_hardening.privileged"} <= keys
    assert "docker_hardening.runtime_unreachable" in VISIBILITY_KEYS


def test_every_runtime_failing_is_the_scan_error(monkeypatch):
    _env(monkeypatch, {"docker": None}, present=("docker",))
    snap = D.DockerAuditSnapshot.from_system()
    assert snap.scan_error
    assert {f.key for f in D.check_docker_audit(snap).findings} == {"docker_hardening.scan_error"}


def _proc(tmp_path, entries):
    for pid, comm, uid in entries:
        d = tmp_path / str(pid)
        d.mkdir()
        (d / "comm").write_text(comm + "\n")
        (d / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    return tmp_path


def test_rootless_conmon_by_owner(tmp_path, monkeypatch):
    monkeypatch.setattr(D, "_PROC", _proc(tmp_path, [(10, "conmon", 0), (11, "conmon", 98765),
                                                     (12, "conmon", 98765), (13, "bash", 98765)]))
    assert D._rootless_podman() == {"98765": 2}


def test_rootless_is_said_and_a_ceiling():
    snap = D.DockerAuditSnapshot(runtime="podman", runtimes=["podman"], rootless_containers={"alice": 2})
    f = next(x for x in D.check_docker_audit(snap).findings if x.key == "docker_hardening.rootless_unexamined")
    assert "alice (2)" in f.message and not f.cmd
    assert "docker_hardening.rootless_unexamined" in VISIBILITY_KEYS


def test_rootless_only_says_nothing_of_root_containers():
    snap = D.DockerAuditSnapshot(rootless_containers={"alice": 1})
    keys = {f.key for f in D.check_docker_audit(snap).findings}
    assert keys == {"docker_hardening.rootless_unexamined"}


def test_the_section_runs_for_rootless_alone():
    import inspect
    from bob import runner
    src = inspect.getsource(runner)
    assert "skip_if=lambda s: not s.runtime and not s.rootless_containers" in src
