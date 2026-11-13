"""v0.35.0 — mac_policy softened by the profile file, not by the profile's name.

0.33.0 found `workstation` losing points because backup and auditd branched on
the profile name; mac_policy had the same shape (a profile named `desktop` got
INFO in code). It now always emits the WARN, and `desktop.conf` softens both
findings. Measured on every field, three profiles, three cases, both
languages: only the command and the detail of apparmor_no_enforce changed —
`sudo aa-enforce /etc/apparmor.d/*`, measured harmful in 0.31.4, became the
check `sudo aa-status`, the detail saying how to enforce one profile.
"""

from __future__ import annotations

import pytest

from bob.checks.mac_policy import MacPolicySnapshot, check_mac_policy
from bob.profiles import apply_profile, load_profile
from bob.scoring import FindingLevel
from tests.helpers import _t

_CASES = {
    "mac_policy.apparmor_no_profiles": MacPolicySnapshot(apparmor_installed=True, apparmor_active=True),
    "mac_policy.apparmor_no_enforce": MacPolicySnapshot(apparmor_installed=True, apparmor_active=True, apparmor_complain=4),
}


@pytest.mark.parametrize("key", _CASES)
def test_the_check_does_not_read_the_profile_name(key):
    seen = set()
    for name in ("server", "desktop", "workstation", "custom"):
        r = check_mac_policy(_CASES[key], t=_t, profile_name=name)
        f = next(f for f in r.findings if f.key == key)
        seen.add((f.level, sum(d.points for d in r.deductions if d.key == key)))
    assert seen == {(FindingLevel.WARN, 1)}


@pytest.mark.parametrize("key", _CASES)
@pytest.mark.parametrize("profile, level, points", [("server", FindingLevel.WARN, 1),
                                                     ("workstation", FindingLevel.WARN, 1),
                                                     ("desktop", FindingLevel.INFO, 0)])
def test_each_profile_through_its_file(key, profile, level, points):
    p = load_profile(profile)
    r = apply_profile(check_mac_policy(_CASES[key], t=_t, profile_name=p.name), p)
    f = next(f for f in r.findings if f.key == key)
    assert f.level == level and sum(d.points for d in r.deductions if d.key == key) == points
