"""v0.25.1 — the auto-desktop notice does not overstate what the profile relaxes.

It said "relaxes backup/auditd/mac_policy"; desktop.conf downgrades one
mac_policy finding (apparmor_no_enforce) of the seven mac_policy deductions,
and also downgrades SSH password authentication, which it did not mention.
"""

import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def test_every_finding_named_is_downgraded_by_desktop_conf():
    conf = (_ROOT / "bob" / "data" / "profiles" / "desktop.conf").read_text(encoding="utf-8")
    for key in ("backup.no_backup", "auditd.no_rules", "mac_policy.apparmor_no_enforce", "ssh.password_auth"):
        assert f"{key}" in conf, key
    en = json.loads((_ROOT / "bob" / "locales" / "en.json").read_text(encoding="utf-8"))
    note = en["audit"]["profile_autodetected_desktop"]
    assert "mac_policy" not in note and "AppArmor" in note and "SSH password" in note
