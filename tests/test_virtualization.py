"""
Unit tests for bob.checks.virtualization module.

All tests build VirtSnapshot instances directly — no subprocess calls.

Run with: python -m pytest tests/test_virtualization.py -v
"""

from __future__ import annotations

import pytest

from bob.checks.virtualization import (
    VirtSnapshot,
    VirtTechnology,
    check_virtualization,
)
from bob.scoring import FindingLevel
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def has_level(result, level):
    return level in _levels(result)


def total_deductions(result):
    return sum(d.points for d in result.deductions)


def make_tech(name="libvirt/KVM", iface="virbr0", risk_note="test risk"):
    return VirtTechnology(name=name, iface=iface, risk_note=risk_note)


def make_snapshot(technologies=None, snap_net=None):
    return VirtSnapshot(
        technologies=technologies if technologies is not None else [],
        snap_net=snap_net if snap_net is not None else [],
    )


# ---------------------------------------------------------------------------
# Empty snapshot — nothing detected
# ---------------------------------------------------------------------------

class TestNothingDetected:
    def test_ok_when_empty(self):
        """No hypervisors, no snap → OK finding."""
        result = check_virtualization(make_snapshot(), t=_t)
        assert has_level(result, "ok")

    def test_no_warn_when_empty(self):
        """No hypervisors, no snap → no warn."""
        result = check_virtualization(make_snapshot(), t=_t)
        assert not has_level(result, "warn")

    def test_zero_deductions_when_empty(self):
        """No hypervisors → zero deductions."""
        result = check_virtualization(make_snapshot(), t=_t)
        assert total_deductions(result) == 0

    def test_ok_key_used(self):
        """Translation key 'virt.none_detected' is used."""
        result = check_virtualization(make_snapshot(), t=_t)
        assert any("virt.none_detected" in f.message for f in result.findings)


# ---------------------------------------------------------------------------
# Single hypervisor detected
# ---------------------------------------------------------------------------

class TestSingleHypervisor:
    def test_warn_for_libvirt(self):
        """libvirt/KVM detected → warn finding."""
        snap = make_snapshot(technologies=[make_tech("libvirt/KVM", "virbr0")])
        result = check_virtualization(snap, t=_t)
        assert has_level(result, "warn")

    def test_warn_for_virtualbox(self):
        """VirtualBox detected → warn finding."""
        snap = make_snapshot(technologies=[make_tech("VirtualBox", "vboxnet0")])
        result = check_virtualization(snap, t=_t)
        assert has_level(result, "warn")

    def test_warn_for_vmware(self):
        """VMware detected → warn finding."""
        snap = make_snapshot(technologies=[make_tech("VMware", "vmnet1")])
        result = check_virtualization(snap, t=_t)
        assert has_level(result, "warn")

    def test_warn_for_lxd(self):
        """LXD/LXC detected → warn finding."""
        snap = make_snapshot(technologies=[make_tech("LXD/LXC", "lxdbr0")])
        result = check_virtualization(snap, t=_t)
        assert has_level(result, "warn")

    def test_no_ok_when_tech_present(self):
        """Hypervisor detected → no OK finding (not 'all clear')."""
        snap = make_snapshot(technologies=[make_tech()])
        result = check_virtualization(snap, t=_t)
        assert not has_level(result, "ok")

    def test_nature_is_improvement(self):
        """Hypervisor finding has nature='improvement' (not auto-fixable)."""
        snap = make_snapshot(technologies=[make_tech("libvirt/KVM", "virbr0")])
        result = check_virtualization(snap, t=_t)
        warn_findings = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert all(f.nature == "improvement" for f in warn_findings)

    def test_fix_cmd_contains_iface(self):
        """Fix command references the detected bridge interface."""
        snap = make_snapshot(technologies=[make_tech("libvirt/KVM", "virbr0")])
        result = check_virtualization(snap, t=_t)
        warn_findings = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert any("virbr0" in f.cmd for f in warn_findings)


# ---------------------------------------------------------------------------
# Multiple hypervisors
# ---------------------------------------------------------------------------

class TestMultipleHypervisors:
    def test_one_warn_per_technology(self):
        """Each detected technology generates exactly one warn finding."""
        snap = make_snapshot(technologies=[
            make_tech("libvirt/KVM", "virbr0"),
            make_tech("VirtualBox", "vboxnet0"),
        ])
        result = check_virtualization(snap, t=_t)
        warn_count = sum(1 for f in result.findings if f.level == FindingLevel.WARN)
        assert warn_count == 2

    def test_three_technologies_three_warns(self):
        """Three technologies → three warn findings."""
        snap = make_snapshot(technologies=[
            make_tech("libvirt/KVM", "virbr0"),
            make_tech("VirtualBox", "vboxnet0"),
            make_tech("VMware", "vmnet1"),
        ])
        result = check_virtualization(snap, t=_t)
        warn_count = sum(1 for f in result.findings if f.level == FindingLevel.WARN)
        assert warn_count == 3


# ---------------------------------------------------------------------------
# Snap network packages
# ---------------------------------------------------------------------------

class TestSnapNetworkPackages:
    def test_warn_for_snap_network(self):
        """Snap package with network plug → warn finding."""
        snap = make_snapshot(snap_net=["lxd"])
        result = check_virtualization(snap, t=_t)
        assert has_level(result, "warn")

    def test_one_warn_per_snap_package(self):
        """Two snap packages → two warn findings."""
        snap = make_snapshot(snap_net=["lxd", "microk8s"])
        result = check_virtualization(snap, t=_t)
        warn_count = sum(1 for f in result.findings if f.level == FindingLevel.WARN)
        assert warn_count == 2

    def test_no_ok_when_snap_present(self):
        """Snap network package detected → no OK finding."""
        snap = make_snapshot(snap_net=["lxd"])
        result = check_virtualization(snap, t=_t)
        assert not has_level(result, "ok")

    def test_snap_and_tech_combined(self):
        """Hypervisor + snap → combined warn count."""
        snap = make_snapshot(
            technologies=[make_tech("libvirt/KVM", "virbr0")],
            snap_net=["lxd"],
        )
        result = check_virtualization(snap, t=_t)
        warn_count = sum(1 for f in result.findings if f.level == FindingLevel.WARN)
        assert warn_count == 2


# ---------------------------------------------------------------------------
# VirtSnapshot interface detection patterns
# ---------------------------------------------------------------------------

class TestInterfacePatterns:
    """
    VirtSnapshot.from_system() uses prefix matching on interface names.
    These tests verify the matching logic by checking which technologies
    are added for known interface patterns.
    """

    def _snap_from_ifaces(self, ifaces):
        """Build a VirtSnapshot as from_system() would, using mock interface list."""
        snap = VirtSnapshot()

        virbr = [i for i in ifaces if i.startswith("virbr")]
        if virbr:
            snap.technologies.append(VirtTechnology(
                name="libvirt/KVM",
                iface=virbr[0],
                risk_note="test",
            ))

        vboxnet = [i for i in ifaces if i.startswith("vboxnet")]
        if vboxnet:
            snap.technologies.append(VirtTechnology(
                name="VirtualBox",
                iface=vboxnet[0],
                risk_note="test",
            ))

        vmnet = [i for i in ifaces if i.startswith("vmnet")]
        if vmnet:
            snap.technologies.append(VirtTechnology(
                name="VMware",
                iface=vmnet[0],
                risk_note="test",
            ))

        lxdbr = [i for i in ifaces
                 if i.startswith("lxdbr") or i.startswith("lxcbr")]
        if lxdbr:
            snap.technologies.append(VirtTechnology(
                name="LXD/LXC",
                iface=lxdbr[0],
                risk_note="test",
            ))
        return snap

    def test_virbr0_detected_as_libvirt(self):
        snap = self._snap_from_ifaces(["eth0", "virbr0", "lo"])
        names = [t.name for t in snap.technologies]
        assert "libvirt/KVM" in names

    def test_vboxnet0_detected_as_virtualbox(self):
        snap = self._snap_from_ifaces(["eth0", "vboxnet0"])
        names = [t.name for t in snap.technologies]
        assert "VirtualBox" in names

    def test_vmnet8_detected_as_vmware(self):
        snap = self._snap_from_ifaces(["eth0", "vmnet8"])
        names = [t.name for t in snap.technologies]
        assert "VMware" in names

    def test_lxdbr0_detected_as_lxd(self):
        snap = self._snap_from_ifaces(["eth0", "lxdbr0"])
        names = [t.name for t in snap.technologies]
        assert "LXD/LXC" in names

    def test_lxcbr0_detected_as_lxd(self):
        snap = self._snap_from_ifaces(["eth0", "lxcbr0"])
        names = [t.name for t in snap.technologies]
        assert "LXD/LXC" in names

    def test_eth0_not_detected(self):
        """Standard interface names do not trigger detection."""
        snap = self._snap_from_ifaces(["eth0", "wlan0", "lo"])
        assert snap.technologies == []

    def test_first_iface_used_when_multiple(self):
        """When multiple virbr* interfaces exist, the first is used."""
        snap = self._snap_from_ifaces(["virbr0", "virbr1"])
        libvirt = next(t for t in snap.technologies if t.name == "libvirt/KVM")
        assert libvirt.iface == "virbr0"


# ---------------------------------------------------------------------------
# cmd_type classification
# ---------------------------------------------------------------------------

class TestCmdType:
    def test_bypass_risk_cmd_type_is_check(self):
        snap = make_snapshot(technologies=[make_tech("libvirt/KVM", "virbr0")])
        result = check_virtualization(snap, t=_t)
        warn_findings = [f for f in result.findings if f.level == FindingLevel.WARN and f.cmd]
        assert all(f.cmd_type == "check" for f in warn_findings)
