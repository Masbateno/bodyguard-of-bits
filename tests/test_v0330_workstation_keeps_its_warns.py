"""v0.33.0 — the profile file decides, not the profile's name.

``workstation.conf`` and the documentation have said since v0.8.1 that a
business workstation keeps ``backup.no_backup`` and ``auditd.*`` at WARN. The
checks said otherwise: backup gave its WARN only to a profile named "server",
and auditd turned ``no_rules`` / ``missing_sensitive_rules`` into INFO for a
profile named desktop or workstation. Measured on 12 November 2026: under
``-p workstation`` the three findings were INFO with no point.

The checks now emit the WARN whatever the profile, and ``desktop.conf`` (and
``container.conf`` through it) softens them — measured identical, field by
field, to what desktop and container got before.

The tests go through ``apply_profile``, the way the runner does: a test on the
bare check would have kept passing while the screen said otherwise.
"""

from __future__ import annotations

import pytest

from bob.checks.auditd import AuditdSnapshot, check_auditd
from bob.checks.backup import BackupSnapshot, check_backup
from bob.profiles import apply_profile, load_profile
from bob.scoring import FindingLevel
from tests.helpers import _t

_KEYS = ("backup.no_backup", "auditd.no_rules", "auditd.missing_sensitive_rules")


def _run(key: str, profile: str):
    p = load_profile(profile)
    if key == "backup.no_backup":
        r = check_backup(BackupSnapshot(), t=_t, profile_name=p.name)
    elif key == "auditd.no_rules":
        r = check_auditd(AuditdSnapshot(installed=True, service_active=True, rule_count=0),
                         t=_t, profile_name=p.name)
    else:
        r = check_auditd(AuditdSnapshot(installed=True, service_active=True, rule_count=1,
                                        watched_files={"/etc/passwd"}),
                         t=_t, profile_name=p.name)
    apply_profile(r, p)
    finding = next(f for f in r.findings if f.key == key)
    points = sum(d.points for d in r.deductions if d.key == key)
    return finding, points


@pytest.mark.parametrize("key", _KEYS)
def test_workstation_keeps_the_warn_and_its_point(key):
    finding, points = _run(key, "workstation")
    assert finding.level == FindingLevel.WARN
    assert points == 1


@pytest.mark.parametrize("key", _KEYS)
def test_server_keeps_the_warn_and_its_point(key):
    finding, points = _run(key, "server")
    assert finding.level == FindingLevel.WARN
    assert points == 1


@pytest.mark.parametrize("profile", ("desktop", "container"))
@pytest.mark.parametrize("key", _KEYS)
def test_desktop_and_container_soften_it_in_their_file(key, profile):
    finding, points = _run(key, profile)
    assert finding.level == FindingLevel.INFO
    assert points == 0
    assert finding.nature == ""


@pytest.mark.parametrize("key", _KEYS)
def test_the_check_does_not_read_the_profile_name(key):
    """Same finding before the profile is applied, whatever the name."""
    seen = set()
    for name in ("server", "desktop", "workstation", "container", "custom"):
        if key == "backup.no_backup":
            r = check_backup(BackupSnapshot(), t=_t, profile_name=name)
        elif key == "auditd.no_rules":
            r = check_auditd(AuditdSnapshot(installed=True, service_active=True, rule_count=0),
                             t=_t, profile_name=name)
        else:
            r = check_auditd(AuditdSnapshot(installed=True, service_active=True, rule_count=1,
                                            watched_files={"/etc/passwd"}),
                             t=_t, profile_name=name)
        f = next(f for f in r.findings if f.key == key)
        seen.add((f.level, sum(d.points for d in r.deductions if d.key == key)))
    assert seen == {(FindingLevel.WARN, 1)}


def test_workstation_file_does_not_soften_what_it_promises_to_keep():
    """The keys its own closing comment lists as kept at WARN."""
    overrides = load_profile("workstation").overrides
    for key in (*_KEYS, "auditd.service_inactive", "mac_policy.apparmor_no_enforce"):
        assert key not in overrides, key
