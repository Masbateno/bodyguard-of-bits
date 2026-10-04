"""CPU security — the kernel's own vulnerability verdict, boot switches, IOMMU.

The guard pins:

  1. BOB repeats the kernel: "Vulnerable…" is a WARN with one deduction however
     many flaws are open, "Mitigation…" and "Not affected" are clean;
  2. "Mitigation …; SMT vulnerable" is mitigated (INFO about SMT, not a WARN);
  3. a status the kernel did not settle ("Unknown: …", or a file listed but
     unreadable) is never counted clean — no OK while one is pending;
  4. an unreadable vulnerabilities directory is "unknown", not "no
     vulnerability";
  5. only *weakening* boot switches are reported (nosmt strengthens);
  6. IOMMU is reported on x86 only, and an unreadable state says nothing.
"""

from __future__ import annotations

import pytest

import bob.checks.cpu_security as cs
from bob.checks.cpu_security import CpuSecuritySnapshot, check_cpu_security
from tests.helpers import _t

# Real lines (Debian 13 on an AMD A4-5000, Ubuntu on Ryzen; kernel docs).
_MITIGATED = "Mitigation: Retpolines; STIBP: disabled; RSB filling; PBRSB-eIBRS: Not affected"
_SMT = "Mitigation: Clear CPU buffers; SMT vulnerable"
_VULN = "Vulnerable: Clear CPU buffers attempted, no microcode; SMT vulnerable"


def _snap(statuses, **kw):
    return CpuSecuritySnapshot(statuses=statuses, readable=True, **kw)


def _keys(r):
    return [f.key for f in r.findings]


def test_all_mitigated_or_unaffected_is_ok():
    r = check_cpu_security(_snap({"spectre_v2": _MITIGATED, "meltdown": "Not affected"}), t=_t)
    assert _keys(r) == ["cpu_security.ok"]
    assert r.deductions == []


def test_vulnerable_deducts_once():
    r = check_cpu_security(_snap({"mds": _VULN, "spectre_v2": "Vulnerable",
                                  "meltdown": "Not affected"}), t=_t)
    assert "cpu_security.vulnerable" in _keys(r)
    assert sum(d.points for d in r.deductions) == 1
    assert "cpu_security.ok" not in _keys(r)


def test_smt_exposed_is_mitigated_not_vulnerable():
    r = check_cpu_security(_snap({"mds": _SMT}), t=_t)
    assert "cpu_security.smt_exposed" in _keys(r)
    assert "cpu_security.vulnerable" not in _keys(r)
    assert r.deductions == []


@pytest.mark.parametrize("status", ["Unknown: Dependent on hypervisor status", ""])
def test_undetermined_status_blocks_the_ok(status):
    r = check_cpu_security(_snap({"itlb_multihit": status, "meltdown": "Not affected"}), t=_t)
    assert "cpu_security.status_unknown" in _keys(r)
    assert "cpu_security.ok" not in _keys(r)


def test_unreadable_directory_is_unknown():
    r = check_cpu_security(CpuSecuritySnapshot(readable=False), t=_t)
    assert "cpu_security.unknown" in _keys(r)
    assert "cpu_security.ok" not in _keys(r)


def test_weakening_cmdline_is_reported():
    r = check_cpu_security(_snap({}, cmdline_flags=["mitigations=off"]), t=_t)
    assert "cpu_security.cmdline_weakened" in _keys(r)


@pytest.mark.parametrize("x86,active,key", [
    (True, True, "cpu_security.iommu_active"),
    (True, False, "cpu_security.iommu_inactive"),
])
def test_iommu_on_x86(x86, active, key):
    r = check_cpu_security(_snap({}, is_x86=x86, iommu_active=active), t=_t)
    assert key in _keys(r)


@pytest.mark.parametrize("x86,active", [(False, False), (True, None)])
def test_iommu_silent_off_x86_or_unread(x86, active):
    r = check_cpu_security(_snap({}, is_x86=x86, iommu_active=active), t=_t)
    assert not any(k.startswith("cpu_security.iommu") for k in _keys(r))


# ---- from_system ---------------------------------------------------------------

@pytest.fixture
def sysfs(tmp_path, monkeypatch):
    vuln = tmp_path / "vulnerabilities"
    vuln.mkdir()
    cmdline = tmp_path / "cmdline"
    iommu = tmp_path / "iommu"
    monkeypatch.setattr(cs, "_VULN_DIR", vuln)
    monkeypatch.setattr(cs, "_CMDLINE", cmdline)
    monkeypatch.setattr(cs, "_IOMMU_CLASS", iommu)
    return vuln, cmdline, iommu


def test_from_system_reads_statuses_and_flags(sysfs):
    vuln, cmdline, iommu = sysfs
    (vuln / "mds").write_text(_VULN + "\n")
    (vuln / "meltdown").write_text("Not affected\n")
    cmdline.write_text("BOOT_IMAGE=/vmlinuz ro quiet mitigations=off nosmt nopti\n")
    iommu.mkdir()
    (iommu / "dmar0").mkdir()
    s = CpuSecuritySnapshot.from_system()
    assert s.readable
    assert s.statuses == {"mds": _VULN, "meltdown": "Not affected"}
    assert s.cmdline_flags == ["mitigations=off", "nopti"]
    assert s.iommu_active is True


def test_from_system_missing_iommu_class_is_inactive(sysfs):
    s = CpuSecuritySnapshot.from_system()
    assert s.iommu_active is False


def test_from_system_missing_directory_is_not_reported_not_unknown(sysfs, monkeypatch, tmp_path):
    """The Pi Zero's ARMv6 kernel has no vulnerabilities directory: the kernel
    reports nothing — not a section BOB failed to read (measured, 2026-10-04)."""
    monkeypatch.setattr(cs, "_VULN_DIR", tmp_path / "absent")
    s = CpuSecuritySnapshot.from_system()
    assert s.not_reported and not s.readable and s.statuses == {}
    keys = [f.key for f in check_cpu_security(s, t=_t).findings]
    assert "cpu_security.not_reported" in keys
    assert "cpu_security.unknown" not in keys and "cpu_security.ok" not in keys


def test_not_reported_is_not_a_visibility_limit():
    from bob.visibility import is_visibility_key
    assert not is_visibility_key("cpu_security.not_reported")
    assert is_visibility_key("cpu_security.unknown")
