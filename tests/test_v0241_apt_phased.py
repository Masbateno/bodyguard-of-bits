"""v0.24.1 — Ubuntu's phased updates are not an "inconsistent APT state".

Measured on the Mint 22.3 desktop (Ubuntu noble base): ``apt list
--upgradable`` listed 16 packages and ``apt-get -s dist-upgrade`` installed 0,
saying why — "The following upgrades have been deferred due to phasing". BOB
read only the two counts and warned "16 package(s) reported upgradable by apt
but dist-upgrade simulation returns zero — inconsistent state", and the attack
surface said "security updates: unknown". Phasing is apt working as designed.
"""

from __future__ import annotations

import bob.checks.updates as U
from bob.checks._run import CommandResult
from bob.checks.updates import UpdatesSnapshot, check_updates

# Verbatim from the Mint desktop, 2026-10-04 (LC_ALL=C).
_PHASED = """\
NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
      Keep also in mind that locking is deactivated,
      so don't depend on the relevance to the real current situation!
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following upgrades have been deferred due to phasing:
  libegl-mesa0 libegl-mesa0:i386 libgbm1 libgbm1:i386 libgl1-mesa-dri:i386
  libgl1-mesa-dri libglx-mesa0 libglx-mesa0:i386 mesa-libgallium
  mesa-libgallium:i386 mesa-va-drivers mesa-va-drivers:i386 mesa-vdpau-drivers
  mesa-vdpau-drivers:i386 mesa-vulkan-drivers mesa-vulkan-drivers:i386
0 upgraded, 0 newly installed, 0 to remove and 16 not upgraded.
"""

_KEPT = """\
Calculating upgrade...
The following packages have been kept back:
  linux-generic linux-image-generic
0 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.
"""


def _snap(**kw) -> UpdatesSnapshot:
    base = dict(apt_available=True, manager="apt", unattended_installed=True,
                unattended_enabled=True)
    base.update(kw)
    return UpdatesSnapshot(**base)


def _keys(result):
    return {f.key for f in result.findings}


def test_phasing_list_is_counted():
    assert U._count_withheld(_PHASED.splitlines()) == (16, 0)


def test_kept_back_list_is_counted():
    assert U._count_withheld(_KEPT.splitlines()) == (0, 2)


def test_scan_reports_phasing_from_the_simulation(monkeypatch):
    monkeypatch.setattr(U, "run_result",
                        lambda *a, **k: CommandResult(_PHASED, True, "", 0))
    assert U._scan_dist_upgrade() == ([], [], 16, 0)


def test_fallback_path_does_not_claim_a_count(monkeypatch):
    def rr(*args, **kwargs):
        if args[:2] == ("apt-get", "-s"):
            return CommandResult("", False, "", None)
        return CommandResult("Listing...\n", True, "", 0)
    monkeypatch.setattr(U, "run_result", rr)
    assert U._scan_dist_upgrade()[2:] == (None, None)


def test_all_upgradable_phased_is_not_inconsistent():
    result = check_updates(_snap(upgradable_count=16, apt_phased=16, apt_kept_back=0))
    assert "updates.dist_upgrade_inconsistent" not in _keys(result)
    assert "updates.phased_deferred" in _keys(result)


def test_kept_back_is_named_not_called_inconsistent():
    result = check_updates(_snap(upgradable_count=2, apt_phased=0, apt_kept_back=2))
    assert "updates.dist_upgrade_inconsistent" not in _keys(result)
    assert "updates.kept_back" in _keys(result)


def test_unexplained_remainder_still_warns():
    result = check_updates(_snap(upgradable_count=20, apt_phased=16, apt_kept_back=0))
    assert "updates.dist_upgrade_inconsistent" in _keys(result)
