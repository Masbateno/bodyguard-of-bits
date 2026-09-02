"""Losing aa-status is not AppArmor being off.

Found by declining the blind-audit instrument tool by tool: rebuild PATH with
symlinks to everything, remove exactly one binary, run the audit, and look for a
deduction that *appears*. Twenty-six of the twenty-nine external tools BOB uses
stay silent correctly. Three do not, and this is the one measured on a host
where the control is demonstrably enforcing.

With `aa-status` removed, BOB reported `mac_policy.apparmor_inactive` — WARN
with a point — on a machine whose AppArmor module is loaded and enabled. The
snapshot set `apparmor_active = False` in the branch commented "module loaded
but aa-status not available", turning "the tool that answers is missing" into
"the control is not enforcing".

The kernel answers without the tool: `/sys/module/apparmor/parameters/enabled`
reads Y or N and is world-readable, and securityfs only mounts the apparmor
directory while the LSM is live. Neither says anything about the profile set,
so that stays unreadable and the check reports "active, profiles could not be
read" — the finding that already existed for the partial-privilege case, whose
comment records the same lesson: a false statement with a point attached.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import bob.checks._run as run_mod
import bob.checks.mac_policy as mac
from bob.checks.mac_policy import MacPolicySnapshot, check_mac_policy


@pytest.fixture()
def no_aa_status(monkeypatch):
    """Patch the name mac_policy holds, not the one _run defines.

    ``mac_policy`` does ``from bob.checks._run import _command_exists``, so it
    keeps its own reference: patching the helper module leaves the check
    calling the real one. A first draft of these tests did exactly that and
    reported the fix working while never exercising it.
    """
    real = mac._command_exists
    monkeypatch.setattr(
        mac, "_command_exists",
        lambda tool: False if tool == "aa-status" else real(tool),
    )


def fake_paths(monkeypatch, *, module_dir=True, enabled=None, securityfs=False):
    """Stand in for the three sysfs paths the snapshot consults."""
    real_is_dir, real_exists, real_read = Path.is_dir, Path.exists, Path.read_text

    def is_dir(self):
        if str(self) == "/sys/module/apparmor":
            return module_dir
        return real_is_dir(self)

    def exists(self):
        if str(self) == "/sys/kernel/security/apparmor/profiles":
            return securityfs
        return real_exists(self)

    def read_text(self, *a, **kw):
        if str(self) == "/sys/module/apparmor/parameters/enabled":
            if enabled is None:
                raise OSError("unreadable")
            return enabled
        return real_read(self, *a, **kw)

    monkeypatch.setattr(Path, "is_dir", is_dir)
    monkeypatch.setattr(Path, "exists", exists)
    monkeypatch.setattr(Path, "read_text", read_text)


class TestTheKernelIsAskedWhenTheToolIsGone:
    def test_enabled_y_means_active(self, no_aa_status, monkeypatch):
        fake_paths(monkeypatch, enabled="Y\n")
        assert MacPolicySnapshot.from_system().apparmor_active is True

    def test_securityfs_alone_is_enough(self, no_aa_status, monkeypatch):
        """The parameter file can be unreadable; the mounted directory is a
        second, independent signal."""
        fake_paths(monkeypatch, enabled=None, securityfs=True)
        assert MacPolicySnapshot.from_system().apparmor_active is True

    def test_enabled_n_still_means_inactive(self, no_aa_status, monkeypatch):
        """Polarity twin. Without it, a snapshot that answered True whenever
        the module directory exists would pass both tests above and stop
        auditing AppArmor entirely."""
        fake_paths(monkeypatch, enabled="N\n", securityfs=False)
        assert MacPolicySnapshot.from_system().apparmor_active is False

    def test_no_module_at_all_is_untouched(self, no_aa_status, monkeypatch):
        fake_paths(monkeypatch, module_dir=False)
        snapshot = MacPolicySnapshot.from_system()
        assert snapshot.apparmor_installed is False
        assert snapshot.apparmor_active is False


class TestTheToolCanBePresentAndMute:
    """The commoner case, and the one the first fix missed.

    Masking the binary is not how this fails in practice — running BOB without
    sudo is. `aa-status` is then present, so `_command_exists` says yes and the
    no-tool branch is never reached; the command simply answers nothing. The
    first version of this fix covered only the absent tool, and the bench
    caught it one step later by replacing the binary with a stub that refuses.
    """

    @pytest.fixture()
    def mute_aa_status(self, monkeypatch):
        monkeypatch.setattr(mac, "_run", lambda *a, **kw: "")

    def test_a_refusing_tool_falls_back_to_the_kernel(self, mute_aa_status, monkeypatch):
        fake_paths(monkeypatch, enabled="Y\n")
        snapshot = MacPolicySnapshot.from_system()
        assert snapshot.apparmor_installed is True
        assert snapshot.apparmor_active is True
        assert snapshot.apparmor_profiles_readable is False

    def test_it_does_not_report_apparmor_off(self, mute_aa_status, monkeypatch):
        fake_paths(monkeypatch, enabled="Y\n")
        result = check_mac_policy(MacPolicySnapshot.from_system())
        assert "mac_policy.apparmor_inactive" not in [f.key for f in result.findings]
        assert not result.deductions

    def test_a_refusing_tool_on_a_disabled_host_still_warns(self, mute_aa_status, monkeypatch):
        """Polarity twin: the fallback must not forgive a genuinely off LSM."""
        fake_paths(monkeypatch, enabled="N\n", securityfs=False)
        result = check_mac_policy(MacPolicySnapshot.from_system())
        assert "mac_policy.apparmor_inactive" in [f.key for f in result.findings]
        assert result.deductions


class TestTheFindingIsHonest:
    def test_an_enforcing_host_is_not_told_apparmor_is_off(self, no_aa_status, monkeypatch):
        fake_paths(monkeypatch, enabled="Y\n")
        result = check_mac_policy(MacPolicySnapshot.from_system())
        keys = [f.key for f in result.findings]
        assert "mac_policy.apparmor_inactive" not in keys, (
            "removing the tool that reads AppArmor must not report AppArmor as "
            "not enforcing"
        )
        assert "mac_policy.apparmor_profiles_unreadable" in keys
        assert not result.deductions

    def test_a_genuinely_disabled_apparmor_still_costs_points(self, no_aa_status, monkeypatch):
        """The twin that keeps the check a check."""
        fake_paths(monkeypatch, enabled="N\n", securityfs=False)
        result = check_mac_policy(MacPolicySnapshot.from_system())
        assert "mac_policy.apparmor_inactive" in [f.key for f in result.findings]
        assert result.deductions
