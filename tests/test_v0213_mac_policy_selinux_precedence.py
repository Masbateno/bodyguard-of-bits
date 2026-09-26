"""On an SELinux distro, a non-enforcing SELinux must win over AppArmor-off.

openSUSE Leap 16 ships SELinux as its MAC, but its kernel still carries AppArmor
compiled-in-but-off. When SELinux was set *permissive* (or disabled), BOB's
`mac_policy` hit the `apparmor_off_in_kernel` branch first and told the admin to
enable AppArmor (`apparmor=1 security=apparmor`) — never mentioning that SELinux
was merely permissive and the real fix is `setenforce 1`. Measured on a real
openSUSE Leap 16 (v0.21.2 field campaign).

The fix defers the AppArmor-off / AppArmor-inactive branches when SELinux is the
installed MAC, so a permissive/disabled SELinux reaches its own verdict. SELinux
*enforcing* already short-circuits at the top, so only the non-enforcing case
changes; a host with no SELinux (Alpine, the Pi) still gets the AppArmor verdict.
"""

from __future__ import annotations

from bob.checks.mac_policy import MacPolicySnapshot, check_mac_policy
from tests.helpers import _keys, _t


def _suse_kernel(*, se_mode: str) -> MacPolicySnapshot:
    """A SUSE-style host: AppArmor compiled-in-but-off, SELinux is the MAC."""
    return MacPolicySnapshot(
        apparmor_installed=True,
        apparmor_active=False,
        apparmor_off_in_kernel=True,
        selinux_installed=True,
        selinux_mode=se_mode,
    )


def test_selinux_permissive_wins_over_apparmor_off():
    result = check_mac_policy(_suse_kernel(se_mode="Permissive"), t=_t)
    keys = _keys(result)
    # The SELinux verdict, with its setenforce-1 remedy:
    assert "mac_policy.no_enforce" in keys
    # NOT the misleading "enable AppArmor" advice:
    assert "mac_policy.apparmor_off_in_kernel" not in keys
    assert "mac_policy.apparmor_inactive" not in keys


def test_selinux_disabled_wins_over_apparmor_off():
    result = check_mac_policy(_suse_kernel(se_mode="Disabled"), t=_t)
    keys = _keys(result)
    assert "mac_policy.selinux_disabled" in keys
    assert "mac_policy.apparmor_off_in_kernel" not in keys


def test_apparmor_off_still_fires_without_selinux():
    """Alpine / the Pi: AppArmor compiled-off and no SELinux — the AppArmor-off
    verdict is correct there and must not regress."""
    snap = MacPolicySnapshot(
        apparmor_installed=True,
        apparmor_active=False,
        apparmor_off_in_kernel=True,
        selinux_installed=False,
        selinux_mode="",
    )
    keys = _keys(check_mac_policy(snap, t=_t))
    assert "mac_policy.apparmor_off_in_kernel" in keys


def test_apparmor_inactive_defers_to_selinux_when_present():
    """AppArmor installed-but-inactive on an SELinux host must not tell the admin
    to `systemctl enable --now apparmor`; SELinux-permissive is the real state."""
    snap = MacPolicySnapshot(
        apparmor_installed=True,
        apparmor_active=False,
        apparmor_off_in_kernel=False,
        selinux_installed=True,
        selinux_mode="Permissive",
    )
    keys = _keys(check_mac_policy(snap, t=_t))
    assert "mac_policy.apparmor_inactive" not in keys
    assert "mac_policy.no_enforce" in keys
