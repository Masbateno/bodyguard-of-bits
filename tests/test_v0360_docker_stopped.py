"""v0.36.0 — a stopped system dockerd with no container left is not asked.

Measured on Linux Mint 22.3 (a10360, 14 November 2026): docker.io installed,
docker.service and docker.socket stopped and disabled, a rootless dockerd of
another user running. No root dockerd, nothing listening on /run/docker.sock,
no root shim in Docker's containerd namespace. root's `docker ps` failed
("Cannot connect"), and 0.35.0 read that as "Container runtime not reachable":
the docker_hardening section stayed not fully read, the score an upper bound,
for a Docker that had nothing running. A root shim still running (a container
kept by live-restore) keeps the question open: asked as before.
"""

from __future__ import annotations

import subprocess

from bob.checks import docker_audit as D


def _env(monkeypatch, state, moby, ps_ok=False):
    asked = []

    def run(argv, **kw):
        asked.append(argv[:2])
        if ps_ok:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="Cannot connect to the Docker daemon")
    monkeypatch.setattr(D, "_command_exists", lambda n: n == "docker")
    monkeypatch.setattr(D.subprocess, "run", run)
    monkeypatch.setattr(D, "_read_userns_remap", lambda: True)
    monkeypatch.setattr(D, "_rootless_podman", lambda: {})
    monkeypatch.setattr(D, "rootless_dockerd", lambda: {})
    monkeypatch.setattr(D, "containerd_elsewhere", lambda: {})
    monkeypatch.setattr(D, "_group_socket", lambda name, socks: ([], False, [], []))
    monkeypatch.setattr(D, "system_dockerd_state", lambda: state)
    monkeypatch.setattr(D, "moby_containers", lambda: moby)
    return asked


def test_a_stopped_dockerd_with_no_shim_is_not_asked(monkeypatch):
    asked = _env(monkeypatch, "stopped", 0)
    snap = D.DockerAuditSnapshot.from_system()
    assert asked == [] and snap.stopped_runtimes == ["docker"] and not snap.scan_error
    keys = {f.key for f in D.check_docker_audit(snap).findings}
    assert "docker_hardening.runtime_stopped" in keys
    assert "docker_hardening.scan_error" not in keys and "docker_hardening.no_containers" not in keys


def test_a_root_shim_left_running_is_still_asked(monkeypatch):
    asked = _env(monkeypatch, "stopped", 1)
    snap = D.DockerAuditSnapshot.from_system()
    assert asked and snap.scan_error and not snap.stopped_runtimes


def test_an_unread_shim_count_is_still_asked(monkeypatch):
    asked = _env(monkeypatch, "stopped", None)
    snap = D.DockerAuditSnapshot.from_system()
    assert asked and not snap.stopped_runtimes


def test_a_running_dockerd_is_asked(monkeypatch):
    asked = _env(monkeypatch, "running", 0, ps_ok=True)
    snap = D.DockerAuditSnapshot.from_system()
    assert asked and not snap.stopped_runtimes
    assert "docker_hardening.no_containers" in {f.key for f in D.check_docker_audit(snap).findings}


def test_runtime_stopped_is_not_a_visibility_limit():
    from bob.visibility import VISIBILITY_KEYS
    assert "docker_hardening.runtime_stopped" not in VISIBILITY_KEYS
