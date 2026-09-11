"""AppArmor built into the kernel and disabled at boot is not "active".

Measured on a Raspberry Pi Zero W (Raspbian 13, kernel 6.18 rpi-v6), as root:

    $ sudo aa-status
    apparmor filesystem is not mounted.
    apparmor module is loaded.
    (exit 3)
    /sys/module/apparmor/parameters/enabled   N
    /sys/kernel/security/apparmor             absent
    /sys/kernel/security/lsm                  capability

aa-status says "module is loaded" because the module is built in; the kernel
says it is not running. BOB 0.18.0 believed the tool: "AppArmor is active,
but its profile set could not be read", a detail describing an exit 4 that
never happened, and a score ceiling for an uncertainty that did not exist.
And the remedy the inactive branch offers, `systemctl enable --now
apparmor`, does nothing there — the unit carries ConditionSecurity=apparmor
and systemd skipped it.

The remedy that works was measured on the same board: `apparmor=1
security=apparmor` in cmdline.txt, reboot — LSM live, 121 profiles loaded,
22 enforcing, aa-status exit 0.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

import bob.checks.mac_policy as M
from bob import i18n
from bob.checks.mac_policy import MacPolicySnapshot, check_mac_policy
from bob.fixes import _can_apply_unattended
from bob.visibility import VISIBILITY_KEYS

_PI_AA_STATUS = "apparmor filesystem is not mounted.\napparmor module is loaded.\n"
_ROOT_AA_STATUS_LIVE = (
    "apparmor module is loaded.\n121 profiles are loaded.\n"
    "22 profiles are in enforce mode.\n23 profiles are in complain mode.\n"
)
_UNPRIVILEGED_AA_STATUS = "apparmor module is loaded.\n"


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


def _kernel(monkeypatch, tmp_path, *, enabled: str, securityfs: bool, aa_status: str,
            cmdline: bool = True):
    module = tmp_path / "sys_module_apparmor"
    (module / "parameters").mkdir(parents=True)
    (module / "parameters" / "enabled").write_text(enabled, encoding="utf-8")
    profiles = tmp_path / "securityfs_profiles"
    if securityfs:
        profiles.write_text("", encoding="utf-8")
    monkeypatch.setattr(M, "_AA_MODULE_DIR", module)
    monkeypatch.setattr(M, "_KERNEL_PROFILES", profiles)
    monkeypatch.setattr(M, "_command_exists", lambda name: name == "aa-status")
    monkeypatch.setattr(M, "_run", lambda *a, **k: aa_status)
    boot = None
    if cmdline:
        boot = tmp_path / "firmware"
        boot.mkdir()
        (boot / "config.txt").write_text("", encoding="utf-8")
        (boot / "cmdline.txt").write_text(
            "console=serial0,115200 console=tty1 root=PARTUUID=9ea707f3-02 rootwait",
            encoding="utf-8")
    import bob.platform
    monkeypatch.setattr(bob.platform, "boot_firmware_dir", lambda *a, **k: boot)
    return boot


def _keys(result):
    return [f.key for f in result.findings]


# ---------------------------------------------------------------------------
# The board
# ---------------------------------------------------------------------------

def test_the_pi_is_not_told_apparmor_is_active(monkeypatch, tmp_path):
    _kernel(monkeypatch, tmp_path, enabled="N\n", securityfs=False, aa_status=_PI_AA_STATUS)
    snap = MacPolicySnapshot.from_system()
    assert snap.apparmor_active is False
    assert snap.apparmor_off_in_kernel is True
    keys = _keys(check_mac_policy(snap, t=i18n.t))
    assert "mac_policy.apparmor_profiles_unreadable" not in keys, (
        "BOB 0.18.0's verdict: active, profile set unreadable"
    )
    assert "mac_policy.apparmor_off_in_kernel" in keys


def test_no_ceiling_for_an_uncertainty_that_does_not_exist(monkeypatch, tmp_path):
    _kernel(monkeypatch, tmp_path, enabled="N\n", securityfs=False, aa_status=_PI_AA_STATUS)
    result = check_mac_policy(MacPolicySnapshot.from_system(), t=i18n.t)
    assert not set(_keys(result)) & VISIBILITY_KEYS, (
        "the kernel answered; nothing here is unverified"
    )
    assert result.deductions, "no MAC in force still costs its point"


def test_the_remedy_is_the_kernel_command_line_not_systemctl(monkeypatch, tmp_path):
    boot = _kernel(monkeypatch, tmp_path, enabled="N\n", securityfs=False, aa_status=_PI_AA_STATUS)
    f = next(f for f in check_mac_policy(MacPolicySnapshot.from_system(), t=i18n.t).findings
             if f.key == "mac_policy.apparmor_off_in_kernel")
    assert "systemctl" not in f.cmd, "the unit is skipped by ConditionSecurity=apparmor"
    assert str(boot / "cmdline.txt") in f.cmd
    assert "ConditionSecurity" in f.detail
    assert _can_apply_unattended(f.cmd)


@pytest.mark.skipif(shutil.which("sed") is None, reason="needs sed")
def test_applying_the_remedy_twice_leaves_one_line_and_one_parameter(monkeypatch, tmp_path):
    """cmdline.txt must stay a single line; v0.17.1's rule on repeated appends."""
    boot = _kernel(monkeypatch, tmp_path, enabled="N\n", securityfs=False, aa_status=_PI_AA_STATUS)
    f = next(f for f in check_mac_policy(MacPolicySnapshot.from_system(), t=i18n.t).findings
             if f.key == "mac_policy.apparmor_off_in_kernel")
    for _ in range(2):
        subprocess.run(re.sub(r"^sudo ", "", f.cmd), shell=True, check=True)
    text = (boot / "cmdline.txt").read_text(encoding="utf-8")
    assert text.count("apparmor=1") == 1 and text.count("security=apparmor") == 1
    assert "\n" not in text
    assert text.startswith("console=serial0,115200 console=tty1 root=PARTUUID=9ea707f3-02 rootwait")


def test_without_a_measured_bootloader_there_is_no_command(monkeypatch, tmp_path):
    _kernel(monkeypatch, tmp_path, enabled="N\n", securityfs=False,
            aa_status=_PI_AA_STATUS, cmdline=False)
    f = next(f for f in check_mac_policy(MacPolicySnapshot.from_system(), t=i18n.t).findings
             if f.key == "mac_policy.apparmor_off_in_kernel")
    assert f.cmd == ""
    assert "GRUB_CMDLINE_LINUX" in f.detail and "not measured" in f.detail


# ---------------------------------------------------------------------------
# The mirrors: a live AppArmor is still read as live
# ---------------------------------------------------------------------------

def test_the_same_board_with_apparmor_enabled_is_read_as_enforcing(monkeypatch, tmp_path):
    """The board after `apparmor=1 security=apparmor` and a reboot."""
    _kernel(monkeypatch, tmp_path, enabled="Y\n", securityfs=True, aa_status=_ROOT_AA_STATUS_LIVE)
    snap = MacPolicySnapshot.from_system()
    assert snap.apparmor_active and not snap.apparmor_off_in_kernel
    assert "mac_policy.apparmor_ok" in _keys(check_mac_policy(snap, t=i18n.t))


def test_an_unprivileged_run_on_a_live_host_keeps_its_honest_uncertainty(monkeypatch, tmp_path):
    """The case the "profiles could not be read" branch was written for."""
    _kernel(monkeypatch, tmp_path, enabled="Y\n", securityfs=False,
            aa_status=_UNPRIVILEGED_AA_STATUS)
    snap = MacPolicySnapshot.from_system()
    assert snap.apparmor_active and not snap.apparmor_off_in_kernel
    assert "mac_policy.apparmor_profiles_unreadable" in _keys(check_mac_policy(snap, t=i18n.t))


def test_the_module_directory_really_is_the_one_consulted():
    assert Path(M._AA_MODULE_DIR) == Path("/sys/module/apparmor")
