"""Container hardening reads Podman too, not only Docker.

Measured on a real Fedora 44: a `podman run --privileged` container was
completely invisible — the check gated on the `docker` binary and never looked
at Podman. Podman's CLI is Docker-compatible (`podman ps`, `podman inspect` emit
the same JSON), so one parser serves both; Docker is preferred when both exist.
The privileged/host-network/root findings apply to Podman; the daemon.json
userns-remap section is Docker-only.
"""

from __future__ import annotations

import json
import subprocess

import bob.checks.docker_audit as D
from bob.checks.docker_audit import DockerAuditSnapshot, check_docker_audit
from tests.helpers import _keys, _levels, _t


def _fake_env(present, inspect_json):
    """present: set of runtime binaries that exist; inspect_json: list of containers."""
    def command_exists(name):
        return name in present

    def run(argv, **kwargs):
        rt = argv[0]
        if argv[1:] == ["ps", "-q"]:
            return subprocess.CompletedProcess(argv, 0, stdout="abc123\n", stderr="")
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(inspect_json), stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    return command_exists, run


_PRIV_CONTAINER = [{
    "Name": "/bobpriv",
    "Id": "abc123",
    "HostConfig": {"Privileged": True, "NetworkMode": "host"},
    "Mounts": [],
    "Config": {"User": ""},
}]


class TestPodmanAudit:
    def _snap(self, present, containers=_PRIV_CONTAINER, monkeypatch=None):
        ce, run = _fake_env(present, containers)
        monkeypatch.setattr(D, "_command_exists", ce)
        monkeypatch.setattr(D.subprocess, "run", run)
        return DockerAuditSnapshot.from_system()

    def test_podman_only_is_scanned(self, monkeypatch):
        snap = self._snap({"podman"}, monkeypatch=monkeypatch)
        assert snap.runtime == "podman"
        assert snap.privileged_containers == ["bobpriv"]
        assert snap.host_network_containers == ["bobpriv"]

    def test_privileged_podman_container_is_flagged_with_deduction(self, monkeypatch):
        snap = self._snap({"podman"}, monkeypatch=monkeypatch)
        result = check_docker_audit(snap, t=_t)
        assert "docker_hardening.privileged" in _keys(result)
        assert result.deductions          # a point was docked
        # the remediation command names the actual runtime
        priv = next(f for f in result.findings if f.key == "docker_hardening.privileged")
        assert priv.cmd.startswith("podman inspect")

    def test_docker_preferred_when_both_present(self, monkeypatch):
        snap = self._snap({"docker", "podman"}, monkeypatch=monkeypatch)
        assert snap.runtime == "docker"

    def test_no_runtime_is_empty(self, monkeypatch):
        ce, run = _fake_env(set(), [])
        monkeypatch.setattr(D, "_command_exists", ce)
        monkeypatch.setattr(D.subprocess, "run", run)
        snap = DockerAuditSnapshot.from_system()
        assert snap.runtime == ""
        assert snap.docker_installed is False

    def test_podman_skips_userns_section(self, monkeypatch):
        """userns-remap is Docker's daemon.json; it must not appear for Podman."""
        snap = self._snap({"podman"}, containers=[{
            "Name": "/web", "Id": "abc123",
            "HostConfig": {"Privileged": False, "NetworkMode": "bridge"},
            "Mounts": [], "Config": {"User": "1000"},
        }], monkeypatch=monkeypatch)
        result = check_docker_audit(snap, t=_t)
        assert "docker_hardening.userns_not_configured" not in _keys(result)
        assert "docker_hardening.userns_configured" not in _keys(result)
