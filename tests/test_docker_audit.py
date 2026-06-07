"""
Tests for checks/docker_audit.py — CHECK 38.

Covers:
  - Docker not installed
  - Scan error (daemon unreachable)
  - No running containers
  - Privileged containers: WARN + deduction
  - Docker socket mounted: WARN + deduction
  - No critical issues: OK
  - userns-remap configured / not configured
  - Root containers: INFO, no deduction
  - Host network containers: INFO, no deduction
  - Combined scenarios
  - Deduction caps and invariants
  - DockerAuditSnapshot defaults
"""

from __future__ import annotations

import pytest

from bob.checks.docker_audit import DockerAuditSnapshot, check_docker_audit
from bob.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(**kwargs) -> DockerAuditSnapshot:
    """Build a snapshot with all-safe defaults, overriding with kwargs."""
    defaults = dict(
        docker_installed=True,
        running_count=1,
        privileged_containers=[],
        socket_mounted_containers=[],
        root_containers=[],
        host_network_containers=[],
        userns_remap=True,
        scan_error=False,
    )
    defaults.update(kwargs)
    return DockerAuditSnapshot(**defaults)


def _keys(result) -> set[str]:
    return {f.key for f in result.findings}


def _deductions(result) -> int:
    return sum(d.points for d in result.deductions)


def _level(result, key: str) -> FindingLevel:
    for f in result.findings:
        if f.key == key:
            return f.level
    raise KeyError(key)


def _finding(result, key: str):
    for f in result.findings:
        if f.key == key:
            return f
    raise KeyError(key)


def _t_format(key: str, **kwargs) -> str:
    """Minimal t() that injects kwargs — for testing formatted messages."""
    parts = ", ".join(f"{k}={v}" for k, v in kwargs.items())
    return f"{key}: {parts}" if parts else key


def _deduction_keys(result) -> set[str]:
    return {d.key for d in result.deductions}


# ---------------------------------------------------------------------------
# Docker not installed
# ---------------------------------------------------------------------------

class TestDockerNotInstalled:
    def test_not_installed_snapshot_defaults(self):
        snap = DockerAuditSnapshot(docker_installed=False)
        assert snap.running_count == 0
        assert snap.privileged_containers == []
        assert not snap.scan_error

    def test_not_installed_check_returns_no_findings_by_default(self):
        # The runner skips the section entirely when docker_installed=False.
        # check_docker_audit itself is not called in that case, but if called
        # directly it should behave sensibly (scan_error=False, running=0 → OK).
        snap = DockerAuditSnapshot(docker_installed=False, running_count=0)
        result = check_docker_audit(snap)
        assert _level(result, "docker_hardening.no_containers") == FindingLevel.OK


# ---------------------------------------------------------------------------
# Scan error
# ---------------------------------------------------------------------------

class TestScanError:
    def test_scan_error_returns_info(self):
        result = check_docker_audit(_snap(scan_error=True))
        assert _level(result, "docker_hardening.scan_error") == FindingLevel.INFO

    def test_scan_error_no_deduction(self):
        result = check_docker_audit(_snap(scan_error=True))
        assert _deductions(result) == 0

    def test_scan_error_only_one_finding(self):
        result = check_docker_audit(_snap(scan_error=True))
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# No running containers
# ---------------------------------------------------------------------------

class TestNoContainers:
    def test_no_containers_returns_ok(self):
        result = check_docker_audit(_snap(running_count=0))
        assert _level(result, "docker_hardening.no_containers") == FindingLevel.OK

    def test_no_containers_no_deduction(self):
        result = check_docker_audit(_snap(running_count=0))
        assert _deductions(result) == 0

    def test_no_containers_only_one_finding(self):
        result = check_docker_audit(_snap(running_count=0))
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Privileged containers
# ---------------------------------------------------------------------------

class TestPrivilegedContainers:
    def test_privileged_is_warn(self):
        result = check_docker_audit(_snap(privileged_containers=["web"]))
        assert _level(result, "docker_hardening.privileged") == FindingLevel.WARN

    def test_privileged_deducts_1(self):
        result = check_docker_audit(_snap(privileged_containers=["web"]))
        assert _deductions(result) == 1

    def test_privileged_deducts_1_regardless_of_count(self):
        """Multiple privileged containers still only −1 pt."""
        result = check_docker_audit(_snap(privileged_containers=["a", "b", "c"]))
        assert _deductions(result) == 1

    def test_privileged_deduction_key(self):
        result = check_docker_audit(_snap(privileged_containers=["web"]))
        assert "docker_hardening.privileged" in _deduction_keys(result)

    def test_privileged_cmd_contains_container_name(self):
        result = check_docker_audit(_snap(privileged_containers=["myapp"]))
        f = _finding(result, "docker_hardening.privileged")
        assert "myapp" in (f.cmd or "")

    def test_privileged_cmd_type_check(self):
        result = check_docker_audit(_snap(privileged_containers=["myapp"]))
        f = _finding(result, "docker_hardening.privileged")
        assert f.cmd_type == "check"

    def test_privileged_cmd_contains_inspect(self):
        result = check_docker_audit(_snap(privileged_containers=["myapp"]))
        f = _finding(result, "docker_hardening.privileged")
        assert "docker inspect" in (f.cmd or "")

    def test_privileged_message_contains_count(self):
        result = check_docker_audit(_snap(privileged_containers=["a", "b"]), t=_t_format)
        f = _finding(result, "docker_hardening.privileged")
        assert "count=2" in (f.message or "")

    def test_privileged_message_contains_names(self):
        result = check_docker_audit(_snap(privileged_containers=["myapp"]), t=_t_format)
        f = _finding(result, "docker_hardening.privileged")
        assert "myapp" in (f.message or "")

    def test_privileged_5_or_fewer_no_suffix(self):
        """Exactly 5 containers → no '+N more' suffix."""
        names = [f"c{i}" for i in range(5)]
        result = check_docker_audit(_snap(privileged_containers=names), t=_t_format)
        f = _finding(result, "docker_hardening.privileged")
        assert "more" not in (f.message or "")

    def test_privileged_6_shows_plus_1_more(self):
        names = [f"c{i}" for i in range(6)]
        result = check_docker_audit(_snap(privileged_containers=names), t=_t_format)
        f = _finding(result, "docker_hardening.privileged")
        assert "+1 more" in (f.message or "")

    def test_no_ok_when_privileged(self):
        result = check_docker_audit(_snap(privileged_containers=["web"]))
        assert "docker_hardening.ok" not in _keys(result)


# ---------------------------------------------------------------------------
# Docker socket mounted
# ---------------------------------------------------------------------------

class TestSocketMounted:
    def test_socket_mounted_is_warn(self):
        result = check_docker_audit(_snap(socket_mounted_containers=["agent"]))
        assert _level(result, "docker_hardening.socket_mounted") == FindingLevel.WARN

    def test_socket_mounted_deducts_1(self):
        result = check_docker_audit(_snap(socket_mounted_containers=["agent"]))
        assert _deductions(result) == 1

    def test_socket_mounted_deducts_1_regardless_of_count(self):
        result = check_docker_audit(_snap(socket_mounted_containers=["a", "b", "c"]))
        assert _deductions(result) == 1

    def test_socket_mounted_deduction_key(self):
        result = check_docker_audit(_snap(socket_mounted_containers=["agent"]))
        assert "docker_hardening.socket_mounted" in _deduction_keys(result)

    def test_socket_mounted_cmd_contains_container_name(self):
        result = check_docker_audit(_snap(socket_mounted_containers=["myagent"]))
        f = _finding(result, "docker_hardening.socket_mounted")
        assert "myagent" in (f.cmd or "")

    def test_socket_mounted_cmd_type_check(self):
        result = check_docker_audit(_snap(socket_mounted_containers=["myagent"]))
        f = _finding(result, "docker_hardening.socket_mounted")
        assert f.cmd_type == "check"

    def test_socket_mounted_cmd_contains_mounts(self):
        result = check_docker_audit(_snap(socket_mounted_containers=["myagent"]))
        f = _finding(result, "docker_hardening.socket_mounted")
        assert "Mounts" in (f.cmd or "")

    def test_no_ok_when_socket_mounted(self):
        result = check_docker_audit(_snap(socket_mounted_containers=["agent"]))
        assert "docker_hardening.ok" not in _keys(result)


# ---------------------------------------------------------------------------
# OK finding (no critical issues)
# ---------------------------------------------------------------------------

class TestOkFinding:
    def test_ok_when_no_critical_issues(self):
        result = check_docker_audit(_snap())
        assert _level(result, "docker_hardening.ok") == FindingLevel.OK

    def test_ok_no_deduction(self):
        result = check_docker_audit(_snap())
        assert _deductions(result) == 0

    def test_ok_message_contains_count(self):
        result = check_docker_audit(_snap(running_count=3), t=_t_format)
        f = _finding(result, "docker_hardening.ok")
        assert "count=3" in (f.message or "")


# ---------------------------------------------------------------------------
# userns-remap
# ---------------------------------------------------------------------------

class TestUsernsRemap:
    def test_userns_not_configured_is_info(self):
        result = check_docker_audit(_snap(userns_remap=False))
        assert _level(result, "docker_hardening.userns_not_configured") == FindingLevel.INFO

    def test_userns_not_configured_no_deduction(self):
        result = check_docker_audit(_snap(userns_remap=False))
        assert _deductions(result) == 0

    def test_userns_not_configured_has_detail(self):
        result = check_docker_audit(_snap(userns_remap=False))
        f = _finding(result, "docker_hardening.userns_not_configured")
        assert f.detail is not None

    def test_userns_not_configured_has_fix_cmd(self):
        result = check_docker_audit(_snap(userns_remap=False))
        f = _finding(result, "docker_hardening.userns_not_configured")
        assert f.cmd is not None
        assert f.cmd_type == "fix"

    def test_userns_configured_is_ok(self):
        result = check_docker_audit(_snap(userns_remap=True))
        assert _level(result, "docker_hardening.userns_configured") == FindingLevel.OK


# ---------------------------------------------------------------------------
# Root containers (INFO only)
# ---------------------------------------------------------------------------

class TestRootContainers:
    def test_root_containers_is_info(self):
        result = check_docker_audit(_snap(root_containers=["web"]))
        assert _level(result, "docker_hardening.root_containers") == FindingLevel.INFO

    def test_root_containers_no_deduction(self):
        result = check_docker_audit(_snap(root_containers=["web"]))
        assert _deductions(result) == 0

    def test_root_containers_has_detail(self):
        result = check_docker_audit(_snap(root_containers=["web"]))
        f = _finding(result, "docker_hardening.root_containers")
        assert f.detail is not None

    def test_root_containers_message_contains_count(self):
        result = check_docker_audit(_snap(root_containers=["a", "b"]), t=_t_format)
        f = _finding(result, "docker_hardening.root_containers")
        assert "count=2" in (f.message or "")

    def test_root_containers_5_or_fewer_no_suffix(self):
        names = [f"c{i}" for i in range(5)]
        result = check_docker_audit(_snap(root_containers=names), t=_t_format)
        f = _finding(result, "docker_hardening.root_containers")
        assert "more" not in (f.message or "")

    def test_root_containers_6_shows_plus_1_more(self):
        names = [f"c{i}" for i in range(6)]
        result = check_docker_audit(_snap(root_containers=names), t=_t_format)
        f = _finding(result, "docker_hardening.root_containers")
        assert "+1 more" in (f.message or "")


# ---------------------------------------------------------------------------
# Host network containers (INFO only)
# ---------------------------------------------------------------------------

class TestHostNetworkContainers:
    def test_host_network_is_info(self):
        result = check_docker_audit(_snap(host_network_containers=["proxy"]))
        assert _level(result, "docker_hardening.host_network") == FindingLevel.INFO

    def test_host_network_no_deduction(self):
        result = check_docker_audit(_snap(host_network_containers=["proxy"]))
        assert _deductions(result) == 0

    def test_host_network_has_detail(self):
        result = check_docker_audit(_snap(host_network_containers=["proxy"]))
        f = _finding(result, "docker_hardening.host_network")
        assert f.detail is not None

    def test_host_network_message_contains_count(self):
        result = check_docker_audit(_snap(host_network_containers=["a", "b"]), t=_t_format)
        f = _finding(result, "docker_hardening.host_network")
        assert "count=2" in (f.message or "")


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombined:
    def test_privileged_and_socket_deduct_2(self):
        """Two independent critical issues → −2 pts total."""
        result = check_docker_audit(_snap(
            privileged_containers=["web"],
            socket_mounted_containers=["agent"],
        ))
        assert _deductions(result) == 2

    def test_both_warn_findings_present(self):
        result = check_docker_audit(_snap(
            privileged_containers=["web"],
            socket_mounted_containers=["agent"],
        ))
        assert "docker_hardening.privileged" in _keys(result)
        assert "docker_hardening.socket_mounted" in _keys(result)

    def test_no_ok_when_both_critical(self):
        result = check_docker_audit(_snap(
            privileged_containers=["web"],
            socket_mounted_containers=["agent"],
        ))
        assert "docker_hardening.ok" not in _keys(result)

    def test_all_findings_combined(self):
        """All possible findings fire simultaneously."""
        result = check_docker_audit(_snap(
            privileged_containers=["web"],
            socket_mounted_containers=["agent"],
            root_containers=["db"],
            host_network_containers=["proxy"],
            userns_remap=False,
        ))
        assert "docker_hardening.privileged" in _keys(result)
        assert "docker_hardening.socket_mounted" in _keys(result)
        assert "docker_hardening.root_containers" in _keys(result)
        assert "docker_hardening.host_network" in _keys(result)
        assert "docker_hardening.userns_not_configured" in _keys(result)
        assert _deductions(result) == 2  # only privileged + socket_mounted

    def test_root_and_host_net_no_deduction(self):
        result = check_docker_audit(_snap(
            root_containers=["db"],
            host_network_containers=["proxy"],
        ))
        assert _deductions(result) == 0

    def test_ok_coexists_with_info(self):
        """OK for no critical issues still fires alongside INFO findings."""
        result = check_docker_audit(_snap(
            root_containers=["db"],
            userns_remap=False,
        ))
        assert "docker_hardening.ok" in _keys(result)
        assert "docker_hardening.root_containers" in _keys(result)
        assert "docker_hardening.userns_not_configured" in _keys(result)


# ---------------------------------------------------------------------------
# DockerAuditSnapshot defaults
# ---------------------------------------------------------------------------

class TestSnapshotDefaults:
    def test_default_docker_installed_false(self):
        assert not DockerAuditSnapshot().docker_installed

    def test_default_running_count_zero(self):
        assert DockerAuditSnapshot().running_count == 0

    def test_default_privileged_empty(self):
        assert DockerAuditSnapshot().privileged_containers == []

    def test_default_socket_mounted_empty(self):
        assert DockerAuditSnapshot().socket_mounted_containers == []

    def test_default_root_containers_empty(self):
        assert DockerAuditSnapshot().root_containers == []

    def test_default_host_network_empty(self):
        assert DockerAuditSnapshot().host_network_containers == []

    def test_default_userns_remap_false(self):
        assert not DockerAuditSnapshot().userns_remap

    def test_default_scan_error_false(self):
        assert not DockerAuditSnapshot().scan_error
