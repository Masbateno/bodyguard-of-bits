"""
v0.15.0 — an absent kernel control was reported as an enabled one.

`_sysctl_int(key, default)` returned a *hardened* default whenever /proc/sys
could not be read: ptrace_scope fell back to 1, kptr_restrict to 1, ASLR to 2.
So on a kernel built without Yama — `CONFIG_SECURITY_YAMA` is an option, and the
sysctl is also absent when `yama` is missing from the boot `lsm=` list — BOB
emitted:

    [OK] kernel_hardening.ptrace_ok    ptrace restricted (scope=1)
    [OK] kernel_hardening.kptr_ok      kernel pointers hidden

Neither protection existed. Reporting a missing control as an enabled one is the
worst answer an auditing tool can give, and here it was the *default* answer,
reached by every read failure: absent knob, restricted /proc, permission error.

Where the knobs do exist, BOB was already exact — checked against `sysctl -n`
for all five on this host.
"""

from __future__ import annotations

import pytest

import bob.checks.kernel_hardening as kh
from bob.checks.kernel_hardening import (
    KernelHardeningSnapshot,
    _sysctl_int,
    check_kernel_hardening,
)


@pytest.fixture
def missing(monkeypatch):
    """Make named sysctl paths unreadable, as a kernel without them would."""
    real = kh.Path

    def _apply(*fragments: str):
        class FakePath:
            def __init__(self, p): self.p = str(p)
            def __truediv__(self, other):
                return FakePath(self.p.rstrip("/") + "/" + str(other))
            def read_text(self, **kw):
                if any(f in self.p for f in fragments):
                    raise FileNotFoundError(self.p)
                return real(self.p).read_text(**kw)
        monkeypatch.setattr(kh, "Path", FakePath)
    return _apply


def _keys(snapshot) -> set[str]:
    return {f.key for f in check_kernel_hardening(snapshot).findings if f.key}


class TestAnAbsentKnobIsNotAPass:
    def test_a_kernel_without_yama_gets_no_ptrace_ok(self, missing):
        missing("yama")
        snap = KernelHardeningSnapshot.from_system()
        assert snap.ptrace_scope is None
        keys = _keys(snap)
        assert "kernel_hardening.ptrace_ok" not in keys, \
            "claimed ptrace was restricted on a kernel with no Yama"
        assert "kernel_hardening.params_unavailable" in keys

    def test_an_absent_knob_is_not_a_failure_either(self, missing):
        """It must not be scored as a weakness: the control is not off, it is
        not there."""
        missing("yama")
        result = check_kernel_hardening(KernelHardeningSnapshot.from_system())
        assert not [d for d in result.deductions
                    if "ptrace" in (d.key or "")]

    def test_the_message_names_the_sysctl(self, missing):
        missing("yama", "kptr_restrict")
        result = check_kernel_hardening(KernelHardeningSnapshot.from_system())
        msg = next(f.message for f in result.findings
                   if f.key == "kernel_hardening.params_unavailable")
        assert "kernel.yama.ptrace_scope" in msg
        assert "kernel.kptr_restrict" in msg

    def test_all_five_missing_produces_one_finding_not_five(self, missing):
        missing("/proc/sys")
        result = check_kernel_hardening(KernelHardeningSnapshot.from_system())
        assert [f.key for f in result.findings] == \
            ["kernel_hardening.params_unavailable"]

    def test_a_readable_knob_is_unaffected(self):
        """The change must not disturb the ordinary path."""
        snap = KernelHardeningSnapshot(aslr=2, ptrace_scope=1, suid_dumpable=0,
                                       kptr_restrict=1, dmesg_restrict=1)
        keys = _keys(snap)
        assert keys == {
            "kernel_hardening.aslr_full", "kernel_hardening.ptrace_ok",
            "kernel_hardening.suid_dump_ok", "kernel_hardening.kptr_ok",
            "kernel_hardening.dmesg_ok",
        }

    def test_a_real_weakness_is_still_scored(self):
        result = check_kernel_hardening(
            KernelHardeningSnapshot(aslr=0, ptrace_scope=0, suid_dumpable=1,
                                    kptr_restrict=0, dmesg_restrict=0))
        assert sum(d.points for d in result.deductions) == 3


class TestSysctlReader:
    def test_a_missing_path_reads_as_none_not_as_a_value(self, missing):
        missing("does.not.exist")
        assert _sysctl_int("does.not.exist") is None

    def test_a_real_key_reads_as_an_int(self):
        """kernel.randomize_va_space exists on every Linux BOB supports."""
        assert isinstance(_sysctl_int("kernel.randomize_va_space"), int)

    def test_a_non_numeric_value_reads_as_none(self, monkeypatch, tmp_path):
        f = tmp_path / "proc"; f.mkdir()
        (f / "junk").write_text("not-a-number\n")

        class FakePath:
            def __init__(self, p): self.p = str(p)
            def __truediv__(self, other): return FakePath(f / "junk")
            def read_text(self, **kw): return (f / "junk").read_text()
        monkeypatch.setattr(kh, "Path", FakePath)
        assert _sysctl_int("whatever") is None
