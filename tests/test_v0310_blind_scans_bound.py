"""
v0.31.0 — a scan that never answered leaves the score a ceiling.

Measured on the real Kali (7 November 2026), three checks that lost their
input without the score saying so:

- the SUID ``find`` killed at its timeout on a cold rotating disk
  (``suid_audit.scan_skipped``, tests/test_v0310_suid_scan_skipped.py);
- ``dockerd`` frozen: ``docker ps`` killed at its timeout, a privileged
  container's −1 gone, ``docker_hardening.scan_error`` a plain INFO;
- fwupd unreachable (``Failed to connect to daemon``, exit 1, on stderr) or
  frozen (killed at the timeout): BOB read stdout only, found it empty and
  printed "no firmware update pending" — an OK, not even the error.

The existing sweep only looked under ``if not snapshot.<x>readable``; these
three live under ``if snapshot.scan_skipped`` / ``scan_error`` /
``fwupd_error``. The sweep below covers those names too.
"""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path
from unittest.mock import patch

from bob.checks import docker_audit as docker_mod
from bob.checks._run import CommandResult
from bob.checks.docker_audit import DockerAuditSnapshot, check_docker_audit
from bob.checks.firmware import FirmwareSnapshot, check_firmware
from bob.scoring import ScoreEngine
from bob.visibility import NOT_A_VISIBILITY_LIMIT, VISIBILITY_KEYS

_ROOT = Path(__file__).resolve().parent.parent
_BLIND = re.compile(r"snapshot\.\w*(?:skipped|scan_error|_error|timed_out)\w*")


def _keys_emitted_when_a_scan_failed() -> dict[str, str]:
    """Keys emitted in the body of ``if snapshot.<…skipped|…error|timed_out>``."""
    found: dict[str, str] = {}
    for py in sorted((_ROOT / "bob" / "checks").rglob("*.py")):
        for node in ast.walk(ast.parse(py.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.If) or not _BLIND.fullmatch(ast.unparse(node.test)):
                continue
            for stmt in node.body:
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Call):
                        for kw in sub.keywords:
                            if kw.arg == "key" and isinstance(kw.value, ast.Constant):
                                found[kw.value.value] = py.name
    return found


def _engine(result) -> ScoreEngine:
    engine = ScoreEngine()
    engine.apply(result)
    return engine


class TestTheSweepCoversFailedScans:

    def test_the_sweep_sees_the_three_measured_keys(self):
        """Positive control: a sweep that finds nothing passes forever."""
        found = _keys_emitted_when_a_scan_failed()
        for key in ("suid_audit.scan_skipped", "docker_hardening.scan_error",
                    "firmware.fwupd_error"):
            assert key in found, f"the sweep went blind to {key}: {sorted(found)}"

    def test_no_failed_scan_key_stays_out_of_the_set(self):
        missing = sorted(
            f"{k} ({src})" for k, src in _keys_emitted_when_a_scan_failed().items()
            if k not in VISIBILITY_KEYS and k not in NOT_A_VISIBILITY_LIMIT
        )
        assert not missing, (
            f"emitted because a scan failed or timed out, and in neither set: {missing}"
        )


def _docker(monkeypatch, run) -> DockerAuditSnapshot:
    monkeypatch.setattr(docker_mod, "_command_exists", lambda c: c == "docker")
    monkeypatch.setattr(docker_mod, "_read_userns_remap", lambda: False)
    monkeypatch.setattr(docker_mod.subprocess, "run", run)
    return DockerAuditSnapshot.from_system()


class TestAFrozenContainerRuntime:

    def test_docker_ps_killed_at_its_timeout_bounds_the_score(self, monkeypatch):
        def _hang(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 10))
        snap = _docker(monkeypatch, _hang)
        assert snap.scan_error is True
        engine = _engine(check_docker_audit(snap))
        assert engine.unverified == ["docker_hardening.scan_error"]
        assert engine.score_is_upper_bound is True

    def test_no_container_running_is_a_value(self, monkeypatch):
        """Polarity twin: the runtime answered, nothing runs — measured, not a ceiling."""
        snap = _docker(monkeypatch, lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""))
        assert snap.scan_error is False
        engine = _engine(check_docker_audit(snap))
        assert engine.unverified == []
        assert engine.score_is_upper_bound is False


def _fwupd(result: CommandResult) -> FirmwareSnapshot:
    with (
        patch("bob.checks.firmware._command_exists", return_value=True),
        patch("bob.checks.firmware.run_result", return_value=result),
        patch("bob.checks.firmware._detect_cpu_vendor", return_value="intel"),
        patch("bob.checks.firmware._dpkg_installed", return_value=True),
        patch("bob.checks.secure_boot.SecureBootSnapshot.from_system",
              return_value=type("S", (), {"state": "unknown"})()),
    ):
        return FirmwareSnapshot.from_system()


# What fwupdmgr 2.1.8 printed on the Kali, by case (stdout, stderr, exit).
_DAEMON_UNREACHABLE = CommandResult(
    "", False,
    "Failed to connect to daemon: Error calling StartServiceByName for "
    "org.freedesktop.fwupd: Unit fwupd.service is masked.\n", 1)
_FROZEN = CommandResult("", False, timed_out=True)
_NOTHING_TO_DO = CommandResult(
    "Devices with no available firmware updates:\n • HCC545025B9A300\n", False,
    "WARNING: UEFI capsule updates not available or enabled in firmware setup\n"
    "No updatable devices\n", 2)


class TestAnUnreachableFwupd:

    def test_the_daemon_unreachable_is_not_no_update(self):
        snap = _fwupd(_DAEMON_UNREACHABLE)
        assert snap.fwupd_error == "exit status 1"
        keys = {f.key for f in check_firmware(snap).findings}
        assert "firmware.fwupd_ok" not in keys
        assert "firmware.fwupd_error" in keys

    def test_the_stderr_text_is_not_rendered(self):
        """stderr is untrusted: matched, never put into the report."""
        assert "masked" not in _fwupd(_DAEMON_UNREACHABLE).fwupd_error

    def test_a_frozen_daemon_is_not_no_update(self):
        snap = _fwupd(_FROZEN)
        assert snap.fwupd_error.startswith("no answer within")
        assert "firmware.fwupd_ok" not in {f.key for f in check_firmware(snap).findings}

    def test_the_unreachable_daemon_bounds_the_score(self):
        engine = _engine(check_firmware(_fwupd(_DAEMON_UNREACHABLE)))
        assert "firmware.fwupd_error" in engine.unverified
        assert engine.score_is_upper_bound is True

    def test_nothing_to_do_is_a_value(self):
        """Polarity twin: exit 2, "No updatable devices" — the measured normal case."""
        snap = _fwupd(_NOTHING_TO_DO)
        assert snap.fwupd_error == ""
        assert snap.fwupd_pending_updates == []
        result = check_firmware(snap)
        assert "firmware.fwupd_ok" in {f.key for f in result.findings}
        assert _engine(result).score_is_upper_bound is False

    def test_a_resource_not_found_naming_no_device_is_a_value(self):
        """Exit 3 ("resource not found") with a "no devices found" marker: nothing to update."""
        snap = _fwupd(CommandResult("", False, "No devices found\n", 3))
        assert snap.fwupd_error == ""
