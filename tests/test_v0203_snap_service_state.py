"""A snap-packaged service runs under snap units, not its deb-style names.

Measured on a real Ubuntu 26.04: Nextcloud installed as a snap served HTTP 200
(`snap.nextcloud.apache.service` active) while BOB reported "installed but not
running" — `_detect_state` iterated the deb unit names (`nextcloud`, `apache2`),
all inactive, and never looked at the snap units. State detection now also
resolves `detection.snap` packages through `snap services <pkg>`.

The ports check already surfaced the real exposure, so this was an attribution
false negative, not a security hole — but "installed but not running" for a
service serving 200 is a lie an auditor must not tell.
"""

from __future__ import annotations

import bob.checks.services as S
from bob.registry import Detection, Service

_SNAP_ACTIVE = (
    "Service           Startup   Current   Notes\n"
    "nextcloud.apache  enabled   active    -\n"
    "nextcloud.mysql   enabled   active    -\n"
)
_SNAP_INACTIVE = (
    "Service           Startup   Current   Notes\n"
    "nextcloud.apache  disabled  inactive  -\n"
)


def _service(snap=("nextcloud",), services=("nextcloud", "apache2")):
    return Service(
        id="nextcloud", label="Nextcloud", packages=(), services=services,
        ports=("80/tcp",), risk="high",
        detection=Detection(binary=(), snap=snap, config_files=()),
    )


def _fake_run(snap_out: str):
    """systemctl says every deb unit is inactive/disabled; snap says snap_out."""
    def run(*args, **kwargs):
        argv = list(args)
        if argv[:2] == ["snap", "services"]:
            return snap_out
        if argv[:2] == ["systemctl", "is-active"]:
            return "inactive"
        if argv[:2] == ["systemctl", "is-enabled"]:
            return "disabled"
        if argv[:1] == ["systemctl"] and "show" in argv:
            return "TriggeredBy="
        return ""
    return run


def test_active_snap_service_reads_active(monkeypatch):
    monkeypatch.setattr(S, "_run", _fake_run(_SNAP_ACTIVE))
    assert S._detect_state(_service()) == S.ServiceState.ACTIVE_ENABLED


def test_inactive_snap_service_stays_inactive(monkeypatch):
    monkeypatch.setattr(S, "_run", _fake_run(_SNAP_INACTIVE))
    assert S._detect_state(_service()) == S.ServiceState.INACTIVE_DISABLED


def test_no_snap_detection_is_untouched(monkeypatch):
    """A service with no snap hint must not gain a snap state from a stray call."""
    monkeypatch.setattr(S, "_run", _fake_run(_SNAP_ACTIVE))
    svc = _service(snap=())
    assert S._detect_state(svc) == S.ServiceState.INACTIVE_DISABLED


def test_snap_absent_leaves_deb_verdict(monkeypatch):
    """`snap` not installed → empty output → deb-unit verdict stands."""
    monkeypatch.setattr(S, "_run", _fake_run(""))
    assert S._detect_state(_service()) == S.ServiceState.INACTIVE_DISABLED
