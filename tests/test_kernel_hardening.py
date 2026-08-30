"""
Tests for checks/kernel_hardening.py — CHECK 36.

Covers:
  - ASLR: full / conservative / disabled
  - ptrace scope: restricted / unrestricted
  - suid_dumpable: 0 / 1 / 2
  - kptr_restrict: ok / exposed
  - dmesg_restrict: ok / exposed
  - Deduction invariants
  - Snapshot defaults
"""

from __future__ import annotations

import pytest

from bob.checks.kernel_hardening import (
    KernelHardeningSnapshot,
    _fix_cmd,
    check_kernel_hardening,
)
from bob.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(**kwargs) -> KernelHardeningSnapshot:
    """Build a snapshot with all-safe defaults, overriding with kwargs."""
    defaults = dict(
        aslr=2,
        ptrace_scope=1,
        suid_dumpable=0,
        kptr_restrict=1,
        dmesg_restrict=1,
    )
    defaults.update(kwargs)
    return KernelHardeningSnapshot(**defaults)


def _keys(result) -> set[str]:
    return {f.key for f in result.findings}


def _deductions(result) -> int:
    return sum(d.points for d in result.deductions)


def _deduction_keys(result) -> set[str]:
    return {d.key for d in result.deductions}


def _t_format(key: str, **kwargs) -> str:
    parts = ", ".join(f"{k}={v}" for k, v in kwargs.items())
    return f"{key}: {parts}" if parts else key


def _level(result, key: str) -> FindingLevel:
    for f in result.findings:
        if f.key == key:
            return f.level
    raise KeyError(key)


# ---------------------------------------------------------------------------
# All-safe baseline
# ---------------------------------------------------------------------------

class TestAllSafe:
    def test_no_deductions_when_all_safe(self):
        result = check_kernel_hardening(_snap())
        assert _deductions(result) == 0

    def test_all_ok_findings(self):
        result = check_kernel_hardening(_snap())
        for f in result.findings:
            assert f.level == FindingLevel.OK, f"Expected OK for {f.key}, got {f.level}"


# ---------------------------------------------------------------------------
# ASLR
# ---------------------------------------------------------------------------

class TestAslr:
    def test_aslr_2_ok(self):
        result = check_kernel_hardening(_snap(aslr=2))
        assert _level(result, "kernel_hardening.aslr_full") == FindingLevel.OK

    def test_aslr_1_info(self):
        result = check_kernel_hardening(_snap(aslr=1))
        assert _level(result, "kernel_hardening.aslr_conservative") == FindingLevel.INFO

    def test_aslr_1_no_deduction(self):
        result = check_kernel_hardening(_snap(aslr=1))
        assert _deductions(result) == 0

    def test_aslr_0_warn(self):
        result = check_kernel_hardening(_snap(aslr=0))
        assert _level(result, "kernel_hardening.aslr_disabled") == FindingLevel.WARN

    def test_aslr_0_deducts_1(self):
        result = check_kernel_hardening(_snap(aslr=0))
        assert _deductions(result) == 1

    def test_aslr_0_deduction_key(self):
        result = check_kernel_hardening(_snap(aslr=0))
        assert _deduction_keys(result) == {"kernel_hardening.aslr_disabled"}

    def test_aslr_0_has_fix_cmd(self):
        result = check_kernel_hardening(_snap(aslr=0))
        f = next(f for f in result.findings if f.key == "kernel_hardening.aslr_disabled")
        assert "sysctl" in (f.cmd or "")
        assert "randomize_va_space=2" in (f.cmd or "")


# ---------------------------------------------------------------------------
# ptrace scope
# ---------------------------------------------------------------------------

class TestPtraceScope:
    @pytest.mark.parametrize("scope", [1, 2, 3])
    def test_restricted_ok(self, scope):
        result = check_kernel_hardening(_snap(ptrace_scope=scope))
        assert _level(result, "kernel_hardening.ptrace_ok") == FindingLevel.OK

    def test_scope_0_warn(self):
        result = check_kernel_hardening(_snap(ptrace_scope=0))
        assert _level(result, "kernel_hardening.ptrace_unrestricted") == FindingLevel.WARN

    def test_scope_0_deducts_1(self):
        result = check_kernel_hardening(_snap(ptrace_scope=0))
        assert _deductions(result) == 1

    def test_scope_0_deduction_key(self):
        result = check_kernel_hardening(_snap(ptrace_scope=0))
        assert _deduction_keys(result) == {"kernel_hardening.ptrace_unrestricted"}

    def test_scope_0_has_fix_cmd(self):
        result = check_kernel_hardening(_snap(ptrace_scope=0))
        f = next(f for f in result.findings if f.key == "kernel_hardening.ptrace_unrestricted")
        assert "sysctl" in (f.cmd or "")
        assert "ptrace_scope=1" in (f.cmd or "")

    def test_ptrace_ok_message_contains_scope(self):
        result = check_kernel_hardening(_snap(ptrace_scope=2), t=_t_format)
        f = next(f for f in result.findings if f.key == "kernel_hardening.ptrace_ok")
        assert "2" in (f.message or "")  # scope value injected via {scope}


# ---------------------------------------------------------------------------
# suid_dumpable
# ---------------------------------------------------------------------------

class TestSuidDumpable:
    def test_0_ok(self):
        result = check_kernel_hardening(_snap(suid_dumpable=0))
        assert _level(result, "kernel_hardening.suid_dump_ok") == FindingLevel.OK

    def test_2_info(self):
        result = check_kernel_hardening(_snap(suid_dumpable=2))
        assert _level(result, "kernel_hardening.suid_dump_root") == FindingLevel.INFO

    def test_2_no_deduction(self):
        result = check_kernel_hardening(_snap(suid_dumpable=2))
        assert _deductions(result) == 0

    def test_1_warn(self):
        result = check_kernel_hardening(_snap(suid_dumpable=1))
        assert _level(result, "kernel_hardening.suid_dump_all") == FindingLevel.WARN

    def test_1_deducts_1(self):
        result = check_kernel_hardening(_snap(suid_dumpable=1))
        assert _deductions(result) == 1

    def test_1_deduction_key(self):
        result = check_kernel_hardening(_snap(suid_dumpable=1))
        assert _deduction_keys(result) == {"kernel_hardening.suid_dump_all"}

    def test_1_has_fix_cmd(self):
        result = check_kernel_hardening(_snap(suid_dumpable=1))
        f = next(f for f in result.findings if f.key == "kernel_hardening.suid_dump_all")
        assert "sysctl" in (f.cmd or "")
        assert "suid_dumpable=0" in (f.cmd or "")


# ---------------------------------------------------------------------------
# kptr_restrict
# ---------------------------------------------------------------------------

class TestKptrRestrict:
    @pytest.mark.parametrize("val", [1, 2])
    def test_ok(self, val):
        result = check_kernel_hardening(_snap(kptr_restrict=val))
        assert _level(result, "kernel_hardening.kptr_ok") == FindingLevel.OK

    def test_0_info(self):
        result = check_kernel_hardening(_snap(kptr_restrict=0))
        assert _level(result, "kernel_hardening.kptr_exposed") == FindingLevel.INFO

    def test_0_no_deduction(self):
        result = check_kernel_hardening(_snap(kptr_restrict=0))
        assert _deductions(result) == 0

    def test_0_has_fix_cmd(self):
        result = check_kernel_hardening(_snap(kptr_restrict=0))
        f = next(f for f in result.findings if f.key == "kernel_hardening.kptr_exposed")
        assert "sysctl" in (f.cmd or "")
        assert "kptr_restrict=1" in (f.cmd or "")


# ---------------------------------------------------------------------------
# dmesg_restrict
# ---------------------------------------------------------------------------

class TestDmesgRestrict:
    def test_1_ok(self):
        result = check_kernel_hardening(_snap(dmesg_restrict=1))
        assert _level(result, "kernel_hardening.dmesg_ok") == FindingLevel.OK

    def test_0_info(self):
        result = check_kernel_hardening(_snap(dmesg_restrict=0))
        assert _level(result, "kernel_hardening.dmesg_exposed") == FindingLevel.INFO

    def test_0_no_deduction(self):
        result = check_kernel_hardening(_snap(dmesg_restrict=0))
        assert _deductions(result) == 0

    def test_0_has_fix_cmd(self):
        result = check_kernel_hardening(_snap(dmesg_restrict=0))
        f = next(f for f in result.findings if f.key == "kernel_hardening.dmesg_exposed")
        assert "sysctl" in (f.cmd or "")
        assert "dmesg_restrict=1" in (f.cmd or "")


# ---------------------------------------------------------------------------
# Combined deductions
# ---------------------------------------------------------------------------

class TestCombinedDeductions:
    def test_max_deductions_all_bad(self):
        """All three deductible params bad → −3 pts."""
        result = check_kernel_hardening(_snap(aslr=0, ptrace_scope=0, suid_dumpable=1))
        assert _deductions(result) == 3

    def test_info_only_params_never_deduct(self):
        """kptr=0 and dmesg=0 alone produce 0 deductions."""
        result = check_kernel_hardening(_snap(kptr_restrict=0, dmesg_restrict=0))
        assert _deductions(result) == 0

    def test_aslr_conservative_plus_kptr_exposed(self):
        """Conservative ASLR + kptr exposed → 0 deductions."""
        result = check_kernel_hardening(_snap(aslr=1, kptr_restrict=0))
        assert _deductions(result) == 0

    def test_two_deductible_issues(self):
        result = check_kernel_hardening(_snap(aslr=0, ptrace_scope=0))
        assert _deductions(result) == 2


# ---------------------------------------------------------------------------
# Snapshot defaults
# ---------------------------------------------------------------------------

class TestSnapshotDefaults:
    """v0.15.0 changed this contract, and the old tests here pinned the defect.

    Each field used to default to a *hardened* value — ASLR 2, ptrace_scope 1,
    kptr_restrict 1 — which the reader also returned whenever /proc/sys could
    not be read. A kernel built without Yama therefore produced an OK finding
    saying ptrace was restricted. The default now carries no opinion: None means
    "not read", and the check reports it as such rather than as a pass.
    """

    def test_nothing_is_assumed_before_a_read(self):
        snap = KernelHardeningSnapshot()
        assert (snap.aslr, snap.ptrace_scope, snap.suid_dumpable,
                snap.kptr_restrict, snap.dmesg_restrict) == (None,) * 5


# ---------------------------------------------------------------------------
# Fix commands write to 99-hardening.conf
# ---------------------------------------------------------------------------

class TestFixCommandTarget:
    @pytest.mark.parametrize("key,param", [
        ("kernel_hardening.aslr_disabled", "99-hardening.conf"),
        ("kernel_hardening.ptrace_unrestricted", "99-hardening.conf"),
        ("kernel_hardening.suid_dump_all", "99-hardening.conf"),
        ("kernel_hardening.kptr_exposed", "99-hardening.conf"),
        ("kernel_hardening.dmesg_exposed", "99-hardening.conf"),
    ])
    def test_fix_writes_to_sysctl_conf(self, key, param):
        snap_kwargs = {
            "kernel_hardening.aslr_disabled": dict(aslr=0),
            "kernel_hardening.ptrace_unrestricted": dict(ptrace_scope=0),
            "kernel_hardening.suid_dump_all": dict(suid_dumpable=1),
            "kernel_hardening.kptr_exposed": dict(kptr_restrict=0),
            "kernel_hardening.dmesg_exposed": dict(dmesg_restrict=0),
        }[key]
        result = check_kernel_hardening(_snap(**snap_kwargs))
        f = next(f for f in result.findings if f.key == key)
        assert param in (f.cmd or ""), f"Expected {param} in cmd for {key}"
        assert "tee -a" in (f.cmd or ""), f"Expected persistent write (tee -a) in cmd for {key}"


# ---------------------------------------------------------------------------
# All-safe finding completeness
# ---------------------------------------------------------------------------

class TestFindingCompleteness:
    def test_all_ok_keys_present_in_safe_snap(self):
        """Safe baseline must emit exactly one OK finding per check."""
        result = check_kernel_hardening(_snap())
        assert _keys(result) == {
            "kernel_hardening.aslr_full",
            "kernel_hardening.ptrace_ok",
            "kernel_hardening.suid_dump_ok",
            "kernel_hardening.kptr_ok",
            "kernel_hardening.dmesg_ok",
        }

    def test_no_extra_findings_in_safe_snap(self):
        result = check_kernel_hardening(_snap())
        assert len(result.findings) == 5


# ---------------------------------------------------------------------------
# Robustness: unexpected sysctl values
# ---------------------------------------------------------------------------

class TestInvalidValues:
    def test_unknown_aslr_value_does_not_raise(self):
        result = check_kernel_hardening(_snap(aslr=999))
        assert result is not None

    def test_out_of_range_aslr_treated_as_disabled(self):
        """aslr=99 falls to else → WARN + 1pt deduction (worst-case assumption)."""
        result = check_kernel_hardening(_snap(aslr=99))
        assert _level(result, "kernel_hardening.aslr_disabled") == FindingLevel.WARN
        assert _deductions(result) == 1

    def test_unknown_ptrace_value_treated_as_restricted(self):
        """Any ptrace_scope > 0 should be treated as restricted (OK)."""
        result = check_kernel_hardening(_snap(ptrace_scope=99))
        assert _level(result, "kernel_hardening.ptrace_ok") == FindingLevel.OK

    def test_negative_ptrace_scope_treated_as_unrestricted(self):
        """ptrace_scope=-1 is < 1 → WARN + 1pt deduction."""
        result = check_kernel_hardening(_snap(ptrace_scope=-1))
        assert _level(result, "kernel_hardening.ptrace_unrestricted") == FindingLevel.WARN
        assert _deductions(result) == 1

    def test_unknown_suid_dumpable_does_not_raise(self):
        result = check_kernel_hardening(_snap(suid_dumpable=5))
        assert result is not None

    def test_out_of_range_suid_dumpable_treated_as_bad(self):
        """suid_dumpable=99 falls to else → WARN + 1pt deduction (worst-case)."""
        result = check_kernel_hardening(_snap(suid_dumpable=99))
        assert _level(result, "kernel_hardening.suid_dump_all") == FindingLevel.WARN
        assert _deductions(result) == 1

    def test_large_kptr_restrict_still_ok(self):
        """kptr_restrict >= 1 → OK regardless of how large the value is."""
        result = check_kernel_hardening(_snap(kptr_restrict=99))
        assert _level(result, "kernel_hardening.kptr_ok") == FindingLevel.OK

    def test_large_dmesg_restrict_still_ok(self):
        result = check_kernel_hardening(_snap(dmesg_restrict=99))
        assert _level(result, "kernel_hardening.dmesg_ok") == FindingLevel.OK

    def test_no_duplicate_finding_keys_when_all_bad(self):
        """Each category emits exactly one finding — never duplicates."""
        result = check_kernel_hardening(_snap(
            aslr=0, ptrace_scope=0, suid_dumpable=1,
            kptr_restrict=0, dmesg_restrict=0,
        ))
        keys = [f.key for f in result.findings]
        assert len(keys) == len(set(keys))


# ---------------------------------------------------------------------------
# cmd_type: kernel fix commands must be "fix", not "check"
# ---------------------------------------------------------------------------

class TestCmdType:
    @pytest.mark.parametrize("snap_kwargs,key", [
        (dict(aslr=0),          "kernel_hardening.aslr_disabled"),
        (dict(ptrace_scope=0),  "kernel_hardening.ptrace_unrestricted"),
        (dict(suid_dumpable=1), "kernel_hardening.suid_dump_all"),
        (dict(kptr_restrict=0), "kernel_hardening.kptr_exposed"),
        (dict(dmesg_restrict=0),"kernel_hardening.dmesg_exposed"),
    ])
    def test_cmd_type_is_fix(self, snap_kwargs, key):
        """sysctl commands are remediation actions, not inspection commands."""
        result = check_kernel_hardening(_snap(**snap_kwargs))
        f = next(f for f in result.findings if f.key == key)
        assert f.cmd_type == "fix"


# ---------------------------------------------------------------------------
# _fix_cmd helper
# ---------------------------------------------------------------------------

class TestFixCmd:
    def test_contains_sysctl_w(self):
        cmd = _fix_cmd("kernel.randomize_va_space", 2)
        assert "sysctl -w" in cmd
        assert "kernel.randomize_va_space=2" in cmd

    def test_persists_to_sysctl_conf(self):
        cmd = _fix_cmd("kernel.randomize_va_space", 2)
        assert "tee -a" in cmd
        assert "99-hardening.conf" in cmd

    def test_param_appears_in_both_parts(self):
        """The parameter must appear in both the live sysctl and the conf line."""
        cmd = _fix_cmd("fs.suid_dumpable", 0)
        assert cmd.count("fs.suid_dumpable=0") == 2
