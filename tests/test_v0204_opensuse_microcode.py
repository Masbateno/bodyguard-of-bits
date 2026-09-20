"""openSUSE's microcode packages are named ucode-amd / ucode-intel.

Measured on a real openSUSE Leap 16.0: the AMD microcode package is `ucode-amd`
(installed and confirmed by `rpm -q`). Before this, the microcode maps carried
apt/dnf/pacman/apk names but no zypper entry, so on openSUSE
`package_name("microcode-amd", "zypper")` was None → `microcode_name_known` False
→ BOB reported microcode "unknown" and the score became an upper bound (≤), even
though the package was installed. Mapping the zypper names closes that.
"""

from __future__ import annotations

from bob.checks._run import package_name, package_name_candidates


def test_opensuse_amd_microcode_name():
    assert package_name("microcode-amd", "zypper") == "ucode-amd"


def test_opensuse_intel_microcode_name():
    assert package_name("microcode-intel", "zypper") == "ucode-intel"


def test_amd_candidates_include_the_opensuse_name():
    # package_name_candidates feeds the installed-check loop, so the openSUSE
    # name must be among the tried candidates or an installed ucode-amd is missed.
    assert "ucode-amd" in package_name_candidates("microcode-amd")


def test_other_managers_unchanged():
    assert package_name("microcode-amd", "apt") == "amd64-microcode"
    assert package_name("microcode-intel", "dnf") == "microcode_ctl"
