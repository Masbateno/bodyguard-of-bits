"""Tests for firmware & microcode audit (CHECK 45)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from bob.checks.firmware import (
    FirmwareSnapshot,
    _detect_cpu_vendor,
    _dpkg_installed,
    _parse_fwupd_updates,
    check_firmware,
)
from bob.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(
    fwupd_available: bool = True,
    fwupd_updates: list[str] | None = None,
    fwupd_error: str = "",
    cpu_vendor: str = "intel",
    microcode_installed: bool = True,
    microcode_package: str = "intel-microcode",
    microcode_na: bool = False,
) -> FirmwareSnapshot:
    return FirmwareSnapshot(
        fwupd_available=fwupd_available,
        fwupd_pending_updates=fwupd_updates or [],
        fwupd_error=fwupd_error,
        cpu_vendor=cpu_vendor,
        microcode_installed=microcode_installed,
        microcode_package=microcode_package,
        microcode_not_applicable=microcode_na,
    )


def _finding(result, key):
    """Return the unique finding with the given key, or raise AssertionError."""
    matches = [f for f in result.findings if f.key == key]
    assert len(matches) == 1, f"expected exactly 1 finding with key={key!r}, got {len(matches)}"
    return matches[0]


# ---------------------------------------------------------------------------
# TestCheckFirmwareFwupd
# ---------------------------------------------------------------------------

class TestCheckFirmwareFwupd:
    def test_fwupd_missing_info(self):
        result = check_firmware(_snap(fwupd_available=False))
        f = _finding(result, "firmware.fwupd_missing")
        assert f.level == FindingLevel.INFO

    def test_fwupd_missing_no_deduction(self):
        result = check_firmware(_snap(fwupd_available=False))
        assert not any(d.key == "firmware.fwupd_missing" for d in result.deductions)

    def test_fwupd_error_info(self):
        result = check_firmware(_snap(fwupd_error="no devices found"))
        f = _finding(result, "firmware.fwupd_error")
        assert f.level == FindingLevel.INFO

    def test_fwupd_error_no_deduction(self):
        result = check_firmware(_snap(fwupd_error="no devices found"))
        assert not any(d.key == "firmware.fwupd_error" for d in result.deductions)

    def test_fwupd_updates_warn(self):
        result = check_firmware(_snap(fwupd_updates=["System Firmware"]))
        f = _finding(result, "firmware.fwupd_updates")
        assert f.level == FindingLevel.WARN

    def test_fwupd_updates_deducts_1pt(self):
        result = check_firmware(_snap(fwupd_updates=["System Firmware"]))
        assert len([d for d in result.deductions if d.key == "firmware.fwupd_updates"]) == 1
        d = next(d for d in result.deductions if d.key == "firmware.fwupd_updates")
        assert d.points == 1

    def test_fwupd_no_updates_ok(self):
        result = check_firmware(_snap(fwupd_updates=[]))
        f = _finding(result, "firmware.fwupd_ok")
        assert f.level == FindingLevel.OK

    def test_fwupd_multiple_updates_flat_deduction(self):
        """Deduction is flat −1 regardless of how many devices have updates."""
        result = check_firmware(_snap(fwupd_updates=["BIOS", "NIC", "SSD"]))
        _finding(result, "firmware.fwupd_updates")
        d = next(d for d in result.deductions if d.key == "firmware.fwupd_updates")
        assert d.points == 1

    def test_fwupd_error_and_updates_both_reported(self):
        """When both fwupd_error and pending updates are set, both findings are emitted."""
        result = check_firmware(_snap(
            fwupd_updates=["BIOS"],
            fwupd_error="daemon not running",
        ))
        assert any(f.key == "firmware.fwupd_error" for f in result.findings)
        assert any(f.key == "firmware.fwupd_updates" for f in result.findings)


# ---------------------------------------------------------------------------
# TestCheckFirmwareMicrocode
# ---------------------------------------------------------------------------

class TestCheckFirmwareMicrocode:
    def test_microcode_installed_ok(self):
        result = check_firmware(_snap())
        f = _finding(result, "firmware.microcode_ok")
        assert f.level == FindingLevel.OK

    def test_microcode_missing_warn(self):
        result = check_firmware(_snap(microcode_installed=False, microcode_package=""))
        f = _finding(result, "firmware.microcode_missing")
        assert f.level == FindingLevel.WARN

    def test_microcode_missing_deducts_1pt(self):
        result = check_firmware(_snap(microcode_installed=False, microcode_package=""))
        assert len([d for d in result.deductions if d.key == "firmware.microcode_missing"]) == 1
        d = next(d for d in result.deductions if d.key == "firmware.microcode_missing")
        assert d.points == 1

    def test_microcode_missing_cmd_contains_package(self):
        result = check_firmware(_snap(cpu_vendor="intel", microcode_installed=False, microcode_package=""))
        f = _finding(result, "firmware.microcode_missing")
        assert "intel-microcode" in (f.cmd or "")

    def test_microcode_missing_amd_cmd(self):
        result = check_firmware(_snap(cpu_vendor="amd", microcode_installed=False, microcode_package=""))
        f = _finding(result, "firmware.microcode_missing")
        assert "amd64-microcode" in (f.cmd or "")

    def test_microcode_not_applicable_info(self):
        result = check_firmware(_snap(cpu_vendor="unknown", microcode_installed=False, microcode_na=True))
        f = _finding(result, "firmware.microcode_na")
        assert f.level == FindingLevel.INFO

    def test_amd_microcode_ok(self):
        result = check_firmware(_snap(
            cpu_vendor="amd",
            microcode_installed=True,
            microcode_package="amd64-microcode",
        ))
        f = _finding(result, "firmware.microcode_ok")
        assert f.level == FindingLevel.OK

    def test_total_deduction_both_issues(self):
        result = check_firmware(_snap(
            fwupd_updates=["BIOS"],
            microcode_installed=False,
            microcode_package="",
        ))
        assert sum(d.points for d in result.deductions) == 2


# ---------------------------------------------------------------------------
# TestCheckFirmwareIntegration
# ---------------------------------------------------------------------------

class TestCheckFirmwareIntegration:
    def test_clean_system_two_ok_findings(self):
        """A fully healthy system produces exactly two OK findings."""
        result = check_firmware(_snap())
        ok_findings = [f for f in result.findings if f.level == FindingLevel.OK]
        assert len(ok_findings) == 2
        assert not result.deductions

    def test_all_issues_two_deductions(self):
        """fwupd pending + microcode missing → exactly −2 pts total."""
        result = check_firmware(_snap(
            fwupd_updates=["System Firmware"],
            microcode_installed=False,
            microcode_package="",
        ))
        assert sum(d.points for d in result.deductions) == 2
        assert len([f for f in result.findings if f.level == FindingLevel.WARN]) == 2

    def test_fwupd_missing_plus_microcode_ok_no_deduction(self):
        result = check_firmware(_snap(fwupd_available=False))
        assert sum(d.points for d in result.deductions) == 0

    def test_findings_count_fwupd_error_path(self):
        """fwupd error + microcode ok → 1 INFO + 1 OK, no deductions."""
        result = check_firmware(_snap(fwupd_error="daemon unavailable"))
        assert sum(d.points for d in result.deductions) == 0
        assert any(f.level == FindingLevel.INFO for f in result.findings)
        assert any(f.level == FindingLevel.OK for f in result.findings)


# ---------------------------------------------------------------------------
# TestDetectCpuVendor
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vendor_line,expected", [
    ("vendor_id\t: GenuineIntel\n", "intel"),
    ("vendor_id\t: AuthenticAMD\n", "amd"),
    ("vendor_id\t: SomeFPGA\n",     "unknown"),
    ("vendor_id : GenuineIntel\n",  "intel"),     # space before colon
    ("VENDOR_ID\t: AuthenticAMD\n", "amd"),       # uppercase key
    ("vendor_id\t: genuineintel\n", "intel"),     # lowercase value
])
def test_detect_cpu_vendor_parametrized(vendor_line, expected):
    content = vendor_line + "model name\t: some processor\n"
    with patch("bob.checks.firmware.Path") as mock_path:
        mock_path.return_value.read_text.return_value = content
        assert _detect_cpu_vendor() == expected


class TestDetectCpuVendor:
    def test_no_vendor_id(self):
        content = "model name\t: some processor\n"
        with patch("bob.checks.firmware.Path") as mock_path:
            mock_path.return_value.read_text.return_value = content
            assert _detect_cpu_vendor() == "unknown"

    def test_oserror_returns_unknown(self):
        with patch("bob.checks.firmware.Path") as mock_path:
            mock_path.return_value.read_text.side_effect = OSError("no file")
            assert _detect_cpu_vendor() == "unknown"

    def test_multiple_vendor_id_lines_first_wins(self):
        """When /proc/cpuinfo has multiple CPU entries, the first match is used."""
        content = (
            "vendor_id\t: GenuineIntel\n"
            "vendor_id\t: AuthenticAMD\n"
        )
        with patch("bob.checks.firmware.Path") as mock_path:
            mock_path.return_value.read_text.return_value = content
            assert _detect_cpu_vendor() == "intel"


# ---------------------------------------------------------------------------
# TestDpkgInstalled
# ---------------------------------------------------------------------------

class TestDpkgInstalled:
    """`_dpkg_installed` keeps its name and delegates to the shared query.

    It used to parse `dpkg -l` columns itself, which answered False for every
    microcode package outside Debian — the package is `intel-microcode` there
    and `microcode_ctl` on Fedora, and neither was ever found by a dpkg-only
    call on an rpm system. The parsing now lives in
    `bob.checks._run.package_installed`, which asks every package manager
    present; these pin the delegation and its two answers.
    """

    def test_a_package_the_manager_reports_is_installed(self):
        with patch("bob.checks.firmware.package_installed", return_value="rpm"):
            assert _dpkg_installed("microcode_ctl")

    def test_a_package_no_manager_reports_is_not(self):
        with patch("bob.checks.firmware.package_installed", return_value=None):
            assert not _dpkg_installed("intel-microcode")

    def test_the_name_is_passed_through_unchanged(self):
        with patch("bob.checks.firmware.package_installed",
                   return_value=None) as query:
            _dpkg_installed("amd64-microcode")
        query.assert_called_once_with("amd64-microcode")


class TestParseFwupdUpdates:
    SAMPLE_OUTPUT = """\
Lenovo ThinkPad X1 Carbon Gen 8
  Update available: N2VET43W (1.43.0 -> 1.44.0)
  Summary: ThinkPad BIOS Update
  Version:  1.44.0
  Urgency:  High

Intel Management Engine
  Update available: (...)
  Version: 16.1.25.1865
"""

    def test_extracts_device_names(self):
        devices = _parse_fwupd_updates(self.SAMPLE_OUTPUT)
        assert any("ThinkPad" in d or "Lenovo" in d for d in devices)

    def test_no_key_value_lines(self):
        devices = _parse_fwupd_updates(self.SAMPLE_OUTPUT)
        for d in devices:
            assert ":" not in d

    def test_no_updates_output(self):
        out = "Devices with no available firmware updates: \nSystem Firmware\n"
        devices = _parse_fwupd_updates(out)
        assert isinstance(devices, list)

    def test_empty_output(self):
        assert _parse_fwupd_updates("") == []

    def test_only_headers_returns_empty(self):
        """Lines that are all key:value or headers should produce no device names."""
        out = (
            "Version: 1.0\n"
            "Summary: nothing\n"
            "Status: active\n"
        )
        assert _parse_fwupd_updates(out) == []

    def test_deduplicates_device_names(self):
        """Same device name appearing twice must appear only once."""
        out = "MyDevice\nMyDevice\n"
        devices = _parse_fwupd_updates(out)
        assert devices.count("MyDevice") <= 1

    def test_caps_at_ten_devices(self):
        """Parser must not return more than 10 device names."""
        out = "\n".join(f"Device{i}" for i in range(20)) + "\n"
        devices = _parse_fwupd_updates(out)
        assert len(devices) <= 10

    def test_indented_lines_skipped(self):
        """Indented lines (summary/detail) must not appear as device names."""
        out = "RealDevice\n  some detail here\n"
        devices = _parse_fwupd_updates(out)
        assert not any("detail" in d for d in devices)

    def test_strict_key_value_lines_excluded(self):
        """Lines like 'Version: 1.2' must never appear as device names."""
        out = "Version: 1.2\nUpdate available\nSummary: nothing\n"
        devices = _parse_fwupd_updates(out)
        assert "Version: 1.2" not in devices
        assert "Summary: nothing" not in devices

    def test_exact_device_names(self):
        """Device names extracted from sample output must match exactly."""
        devices = _parse_fwupd_updates(self.SAMPLE_OUTPUT)
        assert "Lenovo ThinkPad X1 Carbon Gen 8" in devices
        assert "Intel Management Engine" in devices

    TREE_OUTPUT = """\
QEMU Ubuntu 24.04 PC (Q35 + ICH9, 2009)
│
├─UEFI CA:
│     New version:        2024.01
│     Summary:            UEFI certificate update
│
├─QEMU DVD-ROM:
│     New version:        2.5
│
└─QEMU HARDDISK:
      New version:        3.1
"""

    def test_tree_format_extracts_device_names(self):
        """Tree-format output (fwupd 1.9+) must yield sub-device names only."""
        devices = _parse_fwupd_updates(self.TREE_OUTPUT)
        assert "UEFI CA" in devices
        assert "QEMU DVD-ROM" in devices
        assert "QEMU HARDDISK" in devices

    def test_tree_format_excludes_container_line(self):
        """Top-level container name must not appear as a device."""
        devices = _parse_fwupd_updates(self.TREE_OUTPUT)
        assert not any("Q35" in d for d in devices)

    def test_tree_format_excludes_tree_connectors(self):
        """Raw tree-drawing characters must not appear as device names."""
        devices = _parse_fwupd_updates(self.TREE_OUTPUT)
        assert "│" not in devices
        assert not any("├" in d or "└" in d for d in devices)

    def test_tree_format_strips_trailing_colon(self):
        """Device names from ├─ lines must not end with a colon."""
        devices = _parse_fwupd_updates(self.TREE_OUTPUT)
        for d in devices:
            assert not d.endswith(":")


# ---------------------------------------------------------------------------
# TestFromSystem
# ---------------------------------------------------------------------------

class TestFromSystem:
    def test_no_fwupd_available(self):
        with (
            patch("bob.checks.firmware._command_exists", return_value=False),
            patch("bob.checks.firmware._detect_cpu_vendor", return_value="intel"),
            patch("bob.checks.firmware._dpkg_installed", return_value=True),
        ):
            snap = FirmwareSnapshot.from_system()
        assert not snap.fwupd_available
        assert snap.fwupd_pending_updates == []

    def test_fwupd_no_updates(self):
        with (
            patch("bob.checks.firmware._command_exists", return_value=True),
            patch("bob.checks.firmware._run", return_value="No upgrades for any devices"),
            patch("bob.checks.firmware._detect_cpu_vendor", return_value="intel"),
            patch("bob.checks.firmware._dpkg_installed", return_value=True),
        ):
            snap = FirmwareSnapshot.from_system()
        assert snap.fwupd_pending_updates == []
        assert snap.fwupd_error == ""

    def test_fwupd_error_captured(self):
        with (
            patch("bob.checks.firmware._command_exists", return_value=True),
            patch("bob.checks.firmware._run", return_value="Failed to get updates: error connecting to daemon"),
            patch("bob.checks.firmware._detect_cpu_vendor", return_value="intel"),
            patch("bob.checks.firmware._dpkg_installed", return_value=True),
        ):
            snap = FirmwareSnapshot.from_system()
        assert snap.fwupd_error != ""

    def test_fwupd_run_returns_none(self):
        """_run returning None must not raise and must leave pending_updates empty."""
        with (
            patch("bob.checks.firmware._command_exists", return_value=True),
            patch("bob.checks.firmware._run", return_value=None),
            patch("bob.checks.firmware._detect_cpu_vendor", return_value="intel"),
            patch("bob.checks.firmware._dpkg_installed", return_value=True),
        ):
            snap = FirmwareSnapshot.from_system()
        assert snap.fwupd_pending_updates == []

    def test_intel_microcode_detected(self):
        with (
            patch("bob.checks.firmware._command_exists", return_value=False),
            patch("bob.checks.firmware._detect_cpu_vendor", return_value="intel"),
            patch("bob.checks.firmware._dpkg_installed", return_value=True),
        ):
            snap = FirmwareSnapshot.from_system()
        assert snap.microcode_installed
        assert snap.microcode_package == "intel-microcode"

    def test_amd_microcode_detected(self):
        with (
            patch("bob.checks.firmware._command_exists", return_value=False),
            patch("bob.checks.firmware._detect_cpu_vendor", return_value="amd"),
            patch("bob.checks.firmware._dpkg_installed", return_value=True),
        ):
            snap = FirmwareSnapshot.from_system()
        assert snap.microcode_installed
        assert snap.microcode_package == "amd64-microcode"

    def test_unknown_cpu_not_applicable(self):
        with (
            patch("bob.checks.firmware._command_exists", return_value=False),
            patch("bob.checks.firmware._detect_cpu_vendor", return_value="unknown"),
        ):
            snap = FirmwareSnapshot.from_system()
        assert snap.microcode_not_applicable
        assert not snap.microcode_installed
