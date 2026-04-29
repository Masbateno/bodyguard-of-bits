"""
Tests for bob/checks/kernel_modules.py — kernel module security audit.

Coverage:
  - check_kernel_modules(): all branches (lsmod unavailable, risky fs,
    risky net, combined, all-OK)
  - Deduction values and keys
  - _unload_cmd() helper
  - KernelModulesSnapshot dataclass construction
  - Edge cases: empty list, None, duplicates, unknown modules, case sensitivity

Note on deduction sign convention:
  Deduction.points is stored as a positive integer throughout the codebase
  (e.g. points=1 means "subtract 1 from the score"). _deduction_points()
  returns the sum of these positive values; comments indicating "-1 pt"
  describe the score effect, not the stored value.
"""

from __future__ import annotations

import pytest

from bob.checks.kernel_modules import (
    KernelModulesSnapshot,
    check_kernel_modules,
    _unload_cmd,
    _kernel_sort_key,
    _parse_installed_kernels,
    _purge_cmd,
    _strip_unsigned,
    RISKY_MODULES,
    _RISKY_FS,
    _RISKY_NET,
)
from bob.scoring import FindingLevel
from tests.helpers import _deduction_keys, _deduction_points, _get_finding, _has_finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_keys(result) -> list[str]:
    return [f.key for f in result.findings]


def base_snapshot(**kwargs) -> KernelModulesSnapshot:
    """Return a clean KernelModulesSnapshot with lsmod available and no risky modules."""
    defaults = dict(
        lsmod_available=True,
        loaded_modules=[],
    )
    defaults.update(kwargs)
    return KernelModulesSnapshot(**defaults)


# ---------------------------------------------------------------------------
# lsmod not available
# ---------------------------------------------------------------------------

class TestNoLsmod:
    def test_no_lsmod_returns_info(self):
        snap = base_snapshot(lsmod_available=False)
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.no_lsmod", FindingLevel.INFO)

    def test_no_lsmod_returns_early(self):
        """No other findings when lsmod is unavailable, even with risky modules listed."""
        snap = base_snapshot(lsmod_available=False, loaded_modules=["dccp", "cramfs"])
        result = check_kernel_modules(snap)
        assert len(result.findings) == 1
        assert result.findings[0].key == "kernel_modules.no_lsmod"

    def test_no_lsmod_no_deduction(self):
        snap = base_snapshot(lsmod_available=False)
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# All OK
# ---------------------------------------------------------------------------

class TestAllOk:
    def test_no_risky_modules_returns_ok(self):
        result = check_kernel_modules(base_snapshot())
        assert _has_finding(result, "kernel_modules.ok", FindingLevel.OK)

    def test_no_risky_modules_no_deduction(self):
        result = check_kernel_modules(base_snapshot())
        assert _deduction_points(result) == 0

    def test_ok_not_emitted_when_findings_present(self):
        snap = base_snapshot(loaded_modules=["dccp"])
        result = check_kernel_modules(snap)
        assert not _has_finding(result, "kernel_modules.ok", FindingLevel.OK)

    def test_safe_modules_do_not_trigger_findings(self):
        snap = base_snapshot(loaded_modules=["ext4", "btrfs", "tcp_bbr", "iptable_filter"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.ok", FindingLevel.OK)


# ---------------------------------------------------------------------------
# Risky filesystem modules
# ---------------------------------------------------------------------------

class TestRiskyFsModules:
    def test_cramfs_produces_warn(self):
        snap = base_snapshot(loaded_modules=["cramfs"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_fs", FindingLevel.WARN)

    def test_risky_fs_deducts_1_point(self):
        # business rule: penalty is applied once per category regardless of count
        snap = base_snapshot(loaded_modules=["cramfs"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 1  # stored as +1, effect is score −1

    def test_risky_fs_deduction_key(self):
        snap = base_snapshot(loaded_modules=["hfs"])
        result = check_kernel_modules(snap)
        assert "kernel_modules.risky_fs" in _deduction_keys(result)

    def test_multiple_risky_fs_still_one_deduction(self):
        # business rule: flat penalty per category regardless of how many modules
        snap = base_snapshot(loaded_modules=["cramfs", "hfs", "hfsplus", "jffs2"])
        result = check_kernel_modules(snap)
        fs_findings = [f for f in result.findings if f.key == "kernel_modules.risky_fs"]
        assert len(fs_findings) == 1
        assert _deduction_points(result) == 1

    def test_usb_storage_detected(self):
        """lsmod uses underscores: usb_storage, not usb-storage."""
        snap = base_snapshot(loaded_modules=["usb_storage"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_fs", FindingLevel.WARN)

    def test_risky_fs_nature_is_improvement(self):
        snap = base_snapshot(loaded_modules=["squashfs"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_fs")
        assert finding is not None
        assert finding.nature == "improvement"

    def test_risky_fs_cmd_references_module(self):
        snap = base_snapshot(loaded_modules=["cramfs"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_fs")
        assert finding is not None
        assert "cramfs" in finding.cmd

    def test_risky_fs_cmd_is_non_empty(self):
        snap = base_snapshot(loaded_modules=["hfs"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_fs")
        assert finding is not None
        assert finding.cmd


# ---------------------------------------------------------------------------
# Risky network protocol modules
# ---------------------------------------------------------------------------

class TestRiskyNetModules:
    def test_dccp_produces_warn(self):
        snap = base_snapshot(loaded_modules=["dccp"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_net", FindingLevel.WARN)

    def test_sctp_produces_warn(self):
        snap = base_snapshot(loaded_modules=["sctp"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_net", FindingLevel.WARN)

    def test_rds_produces_warn(self):
        snap = base_snapshot(loaded_modules=["rds"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_net", FindingLevel.WARN)

    def test_tipc_produces_warn(self):
        snap = base_snapshot(loaded_modules=["tipc"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_net", FindingLevel.WARN)

    def test_risky_net_deducts_1_point(self):
        # business rule: flat penalty per category
        snap = base_snapshot(loaded_modules=["dccp"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 1  # stored as +1, effect is score −1

    def test_risky_net_deduction_key(self):
        snap = base_snapshot(loaded_modules=["sctp"])
        result = check_kernel_modules(snap)
        assert "kernel_modules.risky_net" in _deduction_keys(result)

    def test_multiple_risky_net_still_one_deduction(self):
        # business rule: flat penalty per category regardless of count
        snap = base_snapshot(loaded_modules=["dccp", "sctp", "rds", "tipc"])
        result = check_kernel_modules(snap)
        net_findings = [f for f in result.findings if f.key == "kernel_modules.risky_net"]
        assert len(net_findings) == 1
        assert _deduction_points(result) == 1

    def test_risky_net_nature_is_improvement(self):
        snap = base_snapshot(loaded_modules=["dccp"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_net")
        assert finding is not None
        assert finding.nature == "improvement"

    def test_risky_net_cmd_references_module(self):
        snap = base_snapshot(loaded_modules=["dccp"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_net")
        assert finding is not None
        assert "dccp" in finding.cmd


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombined:
    def test_risky_fs_and_net_total_deduction(self):
        # risky FS (score −1) + risky net (score −1) = score −2
        snap = base_snapshot(loaded_modules=["cramfs", "dccp"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 2

    def test_risky_fs_and_net_both_findings(self):
        snap = base_snapshot(loaded_modules=["hfs", "sctp"])
        result = check_kernel_modules(snap)
        keys = set(_finding_keys(result))
        assert "kernel_modules.risky_fs" in keys
        assert "kernel_modules.risky_net" in keys

    def test_mixed_safe_and_risky(self):
        snap = base_snapshot(loaded_modules=["ext4", "cramfs", "btrfs", "dccp"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 2
        assert not _has_finding(result, "kernel_modules.ok", FindingLevel.OK)

    def test_risky_with_unknown_module(self):
        """An unknown module alongside a risky one must not prevent detection."""
        snap = base_snapshot(loaded_modules=["cramfs", "totally_unknown_mod"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_fs", FindingLevel.WARN)
        assert _deduction_points(result) == 1


# ---------------------------------------------------------------------------
# _unload_cmd helper
# ---------------------------------------------------------------------------

class TestUnloadCmd:
    def test_single_module(self):
        assert _unload_cmd(["cramfs"]) == "sudo modprobe -r cramfs"

    def test_multiple_modules(self):
        assert _unload_cmd(["cramfs", "dccp"]) == "sudo modprobe -r cramfs dccp"

    def test_empty_list_returns_empty_string(self):
        """An empty list must not produce an invalid shell command."""
        assert _unload_cmd([]) == ""

    def test_cmd_quotes_module_with_special_chars(self):
        """Shell metacharacters in module names must be quoted — prevent injection."""
        cmd = _unload_cmd(["cramfs; rm -rf /"])
        assert cmd == "sudo modprobe -r 'cramfs; rm -rf /'"

    def test_cmd_references_module_in_finding(self):
        snap = base_snapshot(loaded_modules=["cramfs"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_fs")
        assert finding is not None
        assert "cramfs" in finding.cmd


# ---------------------------------------------------------------------------
# KernelModulesSnapshot dataclass
# ---------------------------------------------------------------------------

class TestKernelModulesSnapshot:
    def test_defaults(self):
        snap = KernelModulesSnapshot()
        assert not snap.lsmod_available
        assert snap.loaded_modules == []

    def test_custom_values(self):
        snap = KernelModulesSnapshot(lsmod_available=True, loaded_modules=["ext4"])
        assert snap.lsmod_available
        assert "ext4" in snap.loaded_modules


# ---------------------------------------------------------------------------
# RISKY_MODULES set — structural invariants only
# ---------------------------------------------------------------------------

class TestRiskyModulesSets:
    def test_risky_fs_and_net_are_disjoint(self):
        """No module should belong to both the FS and net categories."""
        assert _RISKY_FS.isdisjoint(_RISKY_NET)

    def test_risky_modules_is_union_of_fs_and_net(self):
        assert RISKY_MODULES == _RISKY_FS | _RISKY_NET

    def test_all_sets_are_non_empty(self):
        assert len(_RISKY_FS) > 0
        assert len(_RISKY_NET) > 0

    def test_cramfs_triggers_fs_finding(self):
        """Spot-check: cramfs (a well-known risky FS module) is detected."""
        snap = base_snapshot(loaded_modules=["cramfs"])
        assert _has_finding(check_kernel_modules(snap), "kernel_modules.risky_fs", FindingLevel.WARN)

    def test_dccp_triggers_net_finding(self):
        """Spot-check: dccp (a well-known risky net module) is detected."""
        snap = base_snapshot(loaded_modules=["dccp"])
        assert _has_finding(check_kernel_modules(snap), "kernel_modules.risky_net", FindingLevel.WARN)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_none_loaded_modules_produce_ok_finding(self):
        """None instead of a list must not crash check_kernel_modules()."""
        snap = KernelModulesSnapshot(lsmod_available=True, loaded_modules=None)
        result = check_kernel_modules(snap)
        assert isinstance(result.findings, list)
        assert _has_finding(result, "kernel_modules.ok", FindingLevel.OK)

    def test_none_loaded_modules_no_deduction(self):
        snap = KernelModulesSnapshot(lsmod_available=True, loaded_modules=None)
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 0

    def test_duplicate_modules_single_deduction(self):
        """Duplicates in loaded_modules must not inflate deductions."""
        snap = base_snapshot(loaded_modules=["cramfs", "cramfs", "cramfs"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 1

    def test_duplicate_mixed_fs_net_correct_total(self):
        """Duplicates across both categories still cap at 2 pts total."""
        snap = base_snapshot(loaded_modules=["cramfs", "cramfs", "dccp", "dccp"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 2

    def test_snapshot_not_mutated(self):
        """check_kernel_modules() must not modify the snapshot."""
        snap = base_snapshot(loaded_modules=["cramfs", "dccp"])
        original = list(snap.loaded_modules)
        check_kernel_modules(snap)
        assert snap.loaded_modules == original

    def test_max_deduction_is_two(self):
        """Maximum total deduction is 2 pts (fs −1 + net −1)."""
        snap = base_snapshot(loaded_modules=list(_RISKY_FS | _RISKY_NET))
        result = check_kernel_modules(snap)
        assert _deduction_points(result) <= 2

    def test_finding_order_independent(self):
        """Both risky keys present regardless of module order in the list."""
        snap = base_snapshot(loaded_modules=["tipc", "hfs"])
        result = check_kernel_modules(snap)
        keys = set(_finding_keys(result))
        assert "kernel_modules.risky_fs" in keys
        assert "kernel_modules.risky_net" in keys

    def test_uppercase_module_not_detected(self):
        """lsmod always outputs lowercase on Linux; uppercase entries are not risky modules."""
        snap = base_snapshot(loaded_modules=["CRAMFS", "DCCP"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.ok", FindingLevel.OK)
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# _kernel_sort_key
# ---------------------------------------------------------------------------

class TestKernelSortKey:
    def test_orders_by_major_minor_patch_abi(self):
        versions = ["6.8.0-55-generic", "6.8.0-52-generic", "6.11.0-13-generic"]
        assert sorted(versions, key=_kernel_sort_key) == [
            "6.8.0-52-generic",
            "6.8.0-55-generic",
            "6.11.0-13-generic",
        ]

    def test_same_base_sorted_by_abi(self):
        versions = ["6.8.0-58-generic", "6.8.0-52-generic", "6.8.0-55-generic"]
        assert sorted(versions, key=_kernel_sort_key) == [
            "6.8.0-52-generic",
            "6.8.0-55-generic",
            "6.8.0-58-generic",
        ]

    def test_unparseable_returns_zero_tuple(self):
        assert _kernel_sort_key("custom-kernel") == (0, 0, 0, 0)

    def test_higher_minor_beats_higher_abi(self):
        assert _kernel_sort_key("6.11.0-1-generic") > _kernel_sort_key("6.8.0-99-generic")

    def test_debian_style_version_parseable(self):
        assert _kernel_sort_key("6.12.74+deb13+1-amd64") == (6, 12, 74, 0)

    def test_debian_sorts_correctly_against_ubuntu(self):
        assert _kernel_sort_key("6.12.74+deb13+1-amd64") > _kernel_sort_key("6.8.0-99-generic")


# ---------------------------------------------------------------------------
# _parse_installed_kernels
# ---------------------------------------------------------------------------

class TestParseInstalledKernels:
    def test_parses_standard_packages(self):
        output = (
            "linux-image-6.8.0-52-generic\n"
            "linux-image-6.8.0-55-generic\n"
            "linux-image-6.8.0-58-generic\n"
        )
        assert _parse_installed_kernels(output) == [
            "6.8.0-52-generic",
            "6.8.0-55-generic",
            "6.8.0-58-generic",
        ]

    def test_ignores_non_numeric_packages(self):
        output = (
            "linux-image-generic\n"
            "linux-image-6.8.0-52-generic\n"
            "linux-image-hwe-22.04\n"
        )
        assert _parse_installed_kernels(output) == ["6.8.0-52-generic"]

    def test_empty_output_returns_empty_list(self):
        assert _parse_installed_kernels("") == []

    def test_strips_whitespace(self):
        assert _parse_installed_kernels("  linux-image-6.8.0-52-generic  \n") == [
            "6.8.0-52-generic"
        ]

    def test_parses_debian_style_kernel(self):
        assert _parse_installed_kernels(
            "linux-image-6.12.74+deb13+1-amd64\n"
        ) == ["6.12.74+deb13+1-amd64"]

    def test_parses_mixed_ubuntu_debian(self):
        output = (
            "linux-image-6.8.0-52-generic\n"
            "linux-image-6.12.74+deb13+1-amd64\n"
        )
        result = _parse_installed_kernels(output)
        assert "6.8.0-52-generic" in result
        assert "6.12.74+deb13+1-amd64" in result


# ---------------------------------------------------------------------------
# _purge_cmd
# ---------------------------------------------------------------------------

class TestPurgeCmd:
    def test_single_kernel(self):
        assert _purge_cmd(["6.8.0-52-generic"]) == "sudo apt purge linux-image-6.8.0-52-generic"

    def test_multiple_kernels(self):
        cmd = _purge_cmd(["6.8.0-52-generic", "6.8.0-55-generic"])
        assert cmd == "sudo apt purge linux-image-6.8.0-52-generic linux-image-6.8.0-55-generic"

    def test_empty_list_returns_empty(self):
        assert _purge_cmd([]) == ""


# ---------------------------------------------------------------------------
# Kernel cleanup — helpers
# ---------------------------------------------------------------------------

def _ksnap(
    *,
    running: str = "",
    installed: list[str] | None = None,
    dpkg: bool = True,
    **kwargs,
) -> KernelModulesSnapshot:
    """Build a snapshot focused on the kernel-cleanup sub-check."""
    return KernelModulesSnapshot(
        lsmod_available=True,
        loaded_modules=[],
        dpkg_available=dpkg,
        running_kernel=running,
        installed_kernels=installed or [],
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Kernel cleanup — no-op cases
# ---------------------------------------------------------------------------

class TestKernelCleanupNoOp:
    def test_single_kernel_shows_listing(self):
        snap = _ksnap(running="6.8.0-58-generic", installed=["6.8.0-58-generic"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.kernels_listed", FindingLevel.INFO)
        assert "kernel_modules.kernels_obsolete" not in _finding_keys(result)

    def test_dpkg_unavailable_no_finding(self):
        snap = _ksnap(dpkg=False, running="6.8.0-58-generic",
                      installed=["6.8.0-52-generic", "6.8.0-58-generic"])
        result = check_kernel_modules(snap)
        assert "kernel_modules.kernels_obsolete" not in _finding_keys(result)
        assert "kernel_modules.kernels_listed" not in _finding_keys(result)

    def test_running_not_in_installed_shows_listing(self):
        """Custom kernel not in dpkg — still list the dpkg-managed kernels."""
        snap = _ksnap(running="5.15.0-custom",
                      installed=["6.8.0-52-generic", "6.8.0-58-generic"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.kernels_listed", FindingLevel.INFO)
        assert "kernel_modules.kernels_obsolete" not in _finding_keys(result)

    def test_server_3_kernels_shows_listing(self):
        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-52-generic", "6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="server")
        assert _has_finding(result, "kernel_modules.kernels_listed", FindingLevel.INFO)
        assert "kernel_modules.kernels_obsolete" not in _finding_keys(result)

    def test_desktop_2_kernels_shows_listing(self):
        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="desktop")
        assert _has_finding(result, "kernel_modules.kernels_listed", FindingLevel.INFO)
        assert "kernel_modules.kernels_obsolete" not in _finding_keys(result)

    def test_kernels_listed_count_in_message(self):
        """_t key pass-through — message key contains count kwarg (not checked here)."""
        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="desktop")
        finding = _get_finding(result, "kernel_modules.kernels_listed")
        assert finding is not None

    def test_kernels_listed_message_contains_running_annotation(self):
        """Message must include the running kernel with (*) marker."""
        def _t_verbose(key, **kw):
            return ":".join([key] + [str(v) for v in kw.values()])

        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-55-generic", "6.8.0-58-generic"],
        )
        snap.lsmod_available = True
        snap.loaded_modules = []
        result = check_kernel_modules(snap, t=_t_verbose, profile_name="desktop")
        finding = _get_finding(result, "kernel_modules.kernels_listed")
        assert finding is not None
        assert "6.8.0-58-generic (*)" in finding.message

    def test_kernels_listed_no_deduction(self):
        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="desktop")
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# Kernel cleanup — obsolete kernels detected
# ---------------------------------------------------------------------------

class TestKernelCleanupObsolete:
    def test_server_4_kernels_flags_1_obsolete(self):
        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-50-generic", "6.8.0-52-generic",
                       "6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="server")
        assert _has_finding(result, "kernel_modules.kernels_obsolete", FindingLevel.INFO)

    def test_desktop_3_kernels_flags_1_obsolete(self):
        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-52-generic", "6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="desktop")
        assert _has_finding(result, "kernel_modules.kernels_obsolete", FindingLevel.INFO)

    def test_obsolete_finding_has_purge_cmd(self):
        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-52-generic", "6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="desktop")
        finding = _get_finding(result, "kernel_modules.kernels_obsolete")
        assert finding is not None
        assert "apt purge" in finding.cmd
        assert "linux-image-6.8.0-52-generic" in finding.cmd

    def test_obsolete_cmd_type_is_check(self):
        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-52-generic", "6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="desktop")
        finding = _get_finding(result, "kernel_modules.kernels_obsolete")
        assert finding.cmd_type == "check"

    def test_obsolete_no_deduction(self):
        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-52-generic", "6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="desktop")
        assert not any(d.key == "kernel_modules.kernels_obsolete" for d in result.deductions)

    def test_running_kernel_never_in_purge_cmd(self):
        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-52-generic", "6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="desktop")
        finding = _get_finding(result, "kernel_modules.kernels_obsolete")
        assert "6.8.0-58-generic" not in finding.cmd


# ---------------------------------------------------------------------------
# Kernel cleanup — reboot pending
# ---------------------------------------------------------------------------

class TestKernelRebootPending:
    def test_reboot_pending_shows_info(self):
        snap = _ksnap(
            running="6.8.0-52-generic",
            installed=["6.8.0-52-generic", "6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="server")
        assert _has_finding(result, "kernel_modules.kernels_reboot_pending", FindingLevel.INFO)

    def test_reboot_pending_no_purge_cmd(self):
        snap = _ksnap(
            running="6.8.0-52-generic",
            installed=["6.8.0-52-generic", "6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="server")
        finding = _get_finding(result, "kernel_modules.kernels_reboot_pending")
        assert finding.cmd == ""

    def test_reboot_pending_no_deduction(self):
        snap = _ksnap(
            running="6.8.0-52-generic",
            installed=["6.8.0-52-generic", "6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="server")
        assert not any(d.key == "kernel_modules.kernels_reboot_pending"
                       for d in result.deductions)

    def test_no_reboot_pending_when_running_is_latest(self):
        snap = _ksnap(
            running="6.8.0-58-generic",
            installed=["6.8.0-52-generic", "6.8.0-55-generic", "6.8.0-58-generic"],
        )
        result = check_kernel_modules(snap, profile_name="desktop")
        assert "kernel_modules.kernels_reboot_pending" not in _finding_keys(result)

    def test_no_reboot_pending_debian_signed_plus_unsigned_same_version(self):
        # Debian installs both linux-image-X-amd64 (signed) and -unsigned for the
        # same version. Running the signed kernel while -unsigned is also installed
        # must NOT trigger a reboot-pending warning.
        snap = _ksnap(
            running="6.12.74+deb13+1-amd64",
            installed=["6.12.74+deb13+1-amd64", "6.12.74+deb13+1-amd64-unsigned"],
        )
        result = check_kernel_modules(snap, profile_name="server")
        assert "kernel_modules.kernels_reboot_pending" not in _finding_keys(result)

    def test_reboot_still_pending_when_genuinely_newer_debian_kernel(self):
        snap = _ksnap(
            running="6.12.63+deb13-amd64",
            installed=["6.12.63+deb13-amd64", "6.12.74+deb13+1-amd64"],
        )
        result = check_kernel_modules(snap, profile_name="server")
        assert _has_finding(result, "kernel_modules.kernels_reboot_pending", FindingLevel.INFO)


# ---------------------------------------------------------------------------
# _strip_unsigned helper
# ---------------------------------------------------------------------------

class TestStripUnsigned:
    def test_strips_unsigned_suffix(self):
        assert _strip_unsigned("6.12.74+deb13+1-amd64-unsigned") == "6.12.74+deb13+1-amd64"

    def test_no_change_without_suffix(self):
        assert _strip_unsigned("6.12.74+deb13+1-amd64") == "6.12.74+deb13+1-amd64"

    def test_no_change_ubuntu_style(self):
        assert _strip_unsigned("6.8.0-58-generic") == "6.8.0-58-generic"

    def test_no_change_empty(self):
        assert _strip_unsigned("") == ""


# ---------------------------------------------------------------------------
# Kernel cleanup — profile retention comparison
# ---------------------------------------------------------------------------

class TestKernelRetentionByProfile:
    def _snap_4(self) -> KernelModulesSnapshot:
        return _ksnap(
            running="6.8.0-60-generic",
            installed=["6.8.0-50-generic", "6.8.0-55-generic",
                       "6.8.0-58-generic", "6.8.0-60-generic"],
        )

    def test_server_4_kernels_keeps_3(self):
        """Server retains 3 → only 6.8.0-50 flagged as obsolete."""
        result = check_kernel_modules(self._snap_4(), profile_name="server")
        finding = _get_finding(result, "kernel_modules.kernels_obsolete")
        assert finding is not None
        assert "6.8.0-50-generic" in finding.cmd
        assert "6.8.0-55-generic" not in finding.cmd

    def test_desktop_4_kernels_keeps_2(self):
        """Desktop retains 2 → 6.8.0-50 and 6.8.0-55 flagged as obsolete."""
        result = check_kernel_modules(self._snap_4(), profile_name="desktop")
        finding = _get_finding(result, "kernel_modules.kernels_obsolete")
        assert finding is not None
        assert "6.8.0-50-generic" in finding.cmd
        assert "6.8.0-55-generic" in finding.cmd


# ---------------------------------------------------------------------------
# Kernel apt update availability
# ---------------------------------------------------------------------------

class TestKernelAptUpdate:
    def _snap(self, **kwargs) -> KernelModulesSnapshot:
        return _ksnap(
            running="6.8.0-55-generic",
            installed=["6.8.0-55-generic"],
            **kwargs,
        )

    def test_update_available_emits_info(self):
        result = check_kernel_modules(
            self._snap(apt_update_available=True, apt_candidate_kernel="6.8.0.56.57")
        )
        assert "kernel_modules.kernels_update_available" in _finding_keys(result)

    def test_update_not_available_no_finding(self):
        result = check_kernel_modules(self._snap(apt_update_available=False))
        assert "kernel_modules.kernels_update_available" not in _finding_keys(result)

    def test_up_to_date_ok_when_apt_checked(self):
        result = check_kernel_modules(
            self._snap(apt_checked=True, apt_update_available=False)
        )
        assert _has_finding(result, "kernel_modules.kernels_up_to_date", FindingLevel.OK)

    def test_no_up_to_date_ok_when_apt_not_checked(self):
        result = check_kernel_modules(
            self._snap(apt_checked=False, apt_update_available=False)
        )
        assert "kernel_modules.kernels_up_to_date" not in _finding_keys(result)

    def test_update_is_info_level(self):
        result = check_kernel_modules(
            self._snap(apt_update_available=True, apt_candidate_kernel="6.8.0.56.57")
        )
        assert _has_finding(result, "kernel_modules.kernels_update_available", FindingLevel.INFO)

    def test_update_has_apt_cmd(self):
        result = check_kernel_modules(
            self._snap(apt_update_available=True, apt_candidate_kernel="6.8.0.56.57")
        )
        f = _get_finding(result, "kernel_modules.kernels_update_available")
        assert f is not None and "apt" in (f.cmd or "")

    def test_update_no_deduction(self):
        result = check_kernel_modules(
            self._snap(apt_update_available=True, apt_candidate_kernel="6.8.0.56.57")
        )
        assert _deduction_points(result) == 0

    def test_update_shown_alongside_reboot_pending(self):
        """Both findings coexist when reboot is pending AND apt has a newer kernel."""
        snap = _ksnap(
            running="6.8.0-54-generic",
            installed=["6.8.0-54-generic", "6.8.0-55-generic"],
            apt_update_available=True,
            apt_candidate_kernel="6.8.0.56.57",
        )
        result = check_kernel_modules(snap)
        keys = _finding_keys(result)
        assert "kernel_modules.kernels_reboot_pending" in keys
        assert "kernel_modules.kernels_update_available" in keys

    def test_update_not_shown_when_candidate_empty(self):
        """apt_update_available=True but no candidate string → no finding emitted."""
        result = check_kernel_modules(
            self._snap(apt_update_available=True, apt_candidate_kernel="")
        )
        assert "kernel_modules.kernels_update_available" not in _finding_keys(result)

    def test_debian_style_kernel_up_to_date(self):
        """Debian kernel version (+ separator) correctly detected as up to date."""
        snap = _ksnap(
            running="6.12.74+deb13+1-amd64",
            installed=["6.12.74+deb13+1-amd64"],
            apt_checked=True,
            apt_update_available=False,
        )
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.kernels_up_to_date", FindingLevel.OK)

    def test_debian_style_kernel_update_available(self):
        """Debian kernel version with update available emits INFO."""
        snap = _ksnap(
            running="6.12.74+deb13+1-amd64",
            installed=["6.12.74+deb13+1-amd64"],
            apt_update_available=True,
            apt_candidate_kernel="6.12.82-1",
        )
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.kernels_update_available", FindingLevel.INFO)
