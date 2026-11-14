"""v0.37.0 — a kernel rpm that puts its image in /boot only is read too.

Measured on an openSUSE Leap 15.6 VM (14 November 2026): kernel-default-base
6.4.0-150600.23.100 running, `zypper install kernel-default-base` installed
23.103 beside it. `rpm -q --whatprovides kernel --qf '[%{FILENAMES}\\n]'` lists,
for each, /boot/vmlinuz-<release> and /lib/modules/<release>/kernel — no
vmlinuz in the module directory, which is all 0.36.0 read: no kernel found,
no word of the reboot the newer kernel waits for.
"""

from __future__ import annotations

from bob.checks import kernel_modules as K

_LEAP156 = """/boot/System.map-6.4.0-150600.23.100-default
/boot/vmlinux-6.4.0-150600.23.100-default.gz
/boot/vmlinuz
/boot/vmlinuz-6.4.0-150600.23.100-default
/lib/modules/6.4.0-150600.23.100-default/kernel
/boot/System.map-6.4.0-150600.23.103-default
/boot/vmlinux-6.4.0-150600.23.103-default.gz
/boot/vmlinuz
/boot/vmlinuz-6.4.0-150600.23.103-default
/lib/modules/6.4.0-150600.23.103-default/kernel
"""


def test_leap_15_6_kernels_are_read_from_boot():
    assert K._rpm_kernel_releases(_LEAP156) == ["6.4.0-150600.23.100-default", "6.4.0-150600.23.103-default"]


def test_the_reboot_they_wait_for_is_said():
    snap = K.KernelModulesSnapshot(running_kernel="6.4.0-150600.23.100-default",
                                   rpm_kernels=K._rpm_kernel_releases(_LEAP156))
    r = K.check_kernel_modules(snap, t=lambda k, **v: f"{k} {v}")
    f = next(f for f in r.findings if f.key == "kernel_modules.kernels_reboot_pending")
    assert "6.4.0-150600.23.103-default" in f.message


def test_a_kernel_listed_both_ways_counts_once():
    text = "/boot/vmlinuz-7.3.3-200.fc44.x86_64\n/lib/modules/7.3.3-200.fc44.x86_64/vmlinuz\n"
    assert K._rpm_kernel_releases(text) == ["7.3.3-200.fc44.x86_64"]
