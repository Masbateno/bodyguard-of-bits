"""A kernel of another flavour is not a newer version to reboot into.

Kernel packages carry a build-target tag — "generic", "amd64", the Pi's
"rpi-v6"/"rpi-v7"/"rpi-v8". Different tags are different builds, often
different architectures, and the board that boots one cannot boot another.

The Raspberry Pi Zero W carries all three rpt-rpi flavours at each version.
Its running kernel is 6.18.39+rpt-rpi-v6 (ARMv6). Installed:

    6.18.34+rpt-rpi-v6/v7/v8   6.18.39+rpt-rpi-v6 (*) /v7/v8

BOB 0.18.0 ranked them together, ignoring the flavour, so 6.18.39+rpt-rpi-v8
(arm64) sorted as "latest" and BOB reported:

    ℹ Reboot pending — running (6.18.39+rpt-rpi-v6) is not the latest
      installed (6.18.39+rpt-rpi-v8)

telling an ARMv6 board to reboot into an arm64 kernel it cannot run — and,
worse, the cleanup would have kept the foreign arm64/armv7 builds as the
"newest" and offered to purge the board's own 6.18.34+rpt-rpi-v6 fallback.
"""

from __future__ import annotations

import pytest

from bob.checks.kernel_modules import (
    KernelModulesSnapshot,
    _kernel_flavour,
    check_kernel_modules,
)
from bob.scoring import FindingLevel


_PI_INSTALLED = [
    "6.18.34+rpt-rpi-v6", "6.18.34+rpt-rpi-v7", "6.18.34+rpt-rpi-v8:arm64",
    "6.18.39+rpt-rpi-v6", "6.18.39+rpt-rpi-v7", "6.18.39+rpt-rpi-v8:arm64",
]
_PI_RUNNING = "6.18.39+rpt-rpi-v6"


def _ksnap(running, installed, **kw):
    return KernelModulesSnapshot(
        lsmod_available=True, loaded_modules=[], dpkg_available=True,
        running_kernel=running, installed_kernels=installed, **kw)


def _keys(result):
    return [f.key for f in result.findings]


def _finding(result, key):
    return next((f for f in result.findings if f.key == key), None)


# ---------------------------------------------------------------------------
# The flavour discriminator
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version,flavour", [
    ("6.8.0-52-generic", "generic"),
    ("6.18.39+rpt-rpi-v6", "v6"),
    ("6.18.39+rpt-rpi-v8:arm64", "v8:arm64"),
    ("6.12.63+deb13-amd64", "amd64"),
    ("6.12.74+deb13+1-amd64", "amd64"),                 # +debN revision, same arch
    ("6.12.74+deb13+1-amd64-unsigned", "amd64"),        # signing variant, same arch
])
def test_flavour_identifies_the_build_target(version, flavour):
    assert _kernel_flavour(version) == flavour


def test_debian_revision_does_not_split_one_architecture():
    assert _kernel_flavour("6.12.63+deb13-amd64") == _kernel_flavour("6.12.74+deb13+1-amd64")


def test_the_pi_flavours_are_distinct():
    assert _kernel_flavour("6.18.39+rpt-rpi-v6") != _kernel_flavour("6.18.39+rpt-rpi-v8:arm64")


# ---------------------------------------------------------------------------
# The Pi, as measured
# ---------------------------------------------------------------------------

def test_the_pi_is_not_told_to_reboot_into_arm64():
    result = check_kernel_modules(_ksnap(_PI_RUNNING, _PI_INSTALLED), profile_name="server")
    assert "kernel_modules.kernels_reboot_pending" not in _keys(result), (
        "6.18.39+rpt-rpi-v6 is the latest of its own flavour — nothing to reboot into"
    )


def test_the_pi_fallback_is_not_offered_for_purge():
    """server keeps running + 2 fallbacks; the only same-flavour fallback is
    6.18.34+rpt-rpi-v6, within the policy, so nothing is purged — and no
    foreign arm64/armv7 build may appear in a purge command."""
    result = check_kernel_modules(_ksnap(_PI_RUNNING, _PI_INSTALLED), profile_name="server")
    obsolete = _finding(result, "kernel_modules.kernels_obsolete")
    assert obsolete is None, "two v6 kernels within a 3-keep policy: nothing obsolete"
    purge_cmds = " ".join(f.cmd for f in result.findings if f.cmd)
    assert "rpi-v8" not in purge_cmds and "rpi-v7" not in purge_cmds, (
        "a foreign-flavour kernel must never be a purge target on this board"
    )


def test_a_genuinely_old_same_flavour_kernel_is_still_cleanup():
    """desktop keeps running + 1. Three v6 kernels → the oldest v6 is obsolete;
    the arm64/armv7 builds are foreign and stay out of it."""
    installed = _PI_INSTALLED + ["6.18.20+rpt-rpi-v6"]
    result = check_kernel_modules(_ksnap(_PI_RUNNING, installed), profile_name="desktop")
    obsolete = _finding(result, "kernel_modules.kernels_obsolete")
    assert obsolete is not None
    assert "6.18.20+rpt-rpi-v6" in obsolete.cmd
    assert "v7" not in obsolete.cmd and "v8" not in obsolete.cmd


# ---------------------------------------------------------------------------
# The mirror: a genuine same-flavour upgrade still reports reboot pending
# ---------------------------------------------------------------------------

def test_a_real_pending_reboot_within_one_flavour_still_fires():
    result = check_kernel_modules(
        _ksnap("6.18.34+rpt-rpi-v6", _PI_INSTALLED), profile_name="server")
    f = _finding(result, "kernel_modules.kernels_reboot_pending")
    assert f is not None and f.level == FindingLevel.INFO, (
        "running an older v6 while a newer v6 is installed is genuinely pending"
    )


def test_the_single_generic_family_is_unchanged():
    """The common case — one flavour — behaves exactly as before."""
    result = check_kernel_modules(
        _ksnap("6.8.0-52-generic", ["6.8.0-52-generic", "6.8.0-58-generic"]),
        profile_name="server")
    assert "kernel_modules.kernels_reboot_pending" in _keys(result)
