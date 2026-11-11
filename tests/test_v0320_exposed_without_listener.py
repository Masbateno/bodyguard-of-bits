"""v0.32.0 — a port nothing listens on is not "open to the internet".

Since v0.1.0 the services section kept a registry port OPEN_WORLD (or
OPEN_LOCAL) whenever a UFW rule admitted it, listening or not, and scored it:
measured on Ubuntu Server 26.04 (8 November 2026, rt0313), Nextcloud's 443/tcp
scored −2 with nothing listening on it. The firewall section already reports
that very rule (firewall_rules.orphan_rule, INFO). The port is now NOT_LISTENING
(INFO, no point) when the listeners are known; unknown listeners change nothing.
"""

from __future__ import annotations

from unittest import mock

import pytest

from bob.checks import services as svc
from bob.checks.services import Exposure, ServiceSnapshot, ServiceState, check_services
from tests.test_services import make_service, total_deductions

_OPEN = "[ 1] 443/tcp                    ALLOW IN    Anywhere\n"
_LAN = "[ 1] 443/tcp                    ALLOW IN    192.168.1.0/24\n"
_DENY = "[ 1] 443/tcp                    DENY IN     Anywhere\n"


def _snap(rules, listening):
    service = make_service(id="nextcloud", label="Nextcloud", ports=("443/tcp",), risk="high")
    with mock.patch.object(svc, "_detect_installation", return_value=(True, "snap")), \
         mock.patch.object(svc, "_detect_state", return_value=ServiceState.ACTIVE_ENABLED), \
         mock.patch.object(svc, "_resolve_ports", return_value=["443/tcp"]):
        return ServiceSnapshot._build_snapshot(service, rules, set(), listening, {})


@pytest.mark.parametrize("rules", [_OPEN, _LAN], ids=["allowed-from-anywhere", "allowed-from-the-lan"])
def test_a_rule_without_a_listener_exposes_nothing(rules):
    snap = _snap(rules, set())
    assert snap.exposures["443/tcp"] == Exposure.NOT_LISTENING
    result = check_services([snap])
    assert total_deductions(result) == 0
    assert "services.exposure.not_listening" in {f.key for f in result.findings}


def test_listening_and_allowed_stays_open():
    snap = _snap(_OPEN, {"443/tcp"})
    assert snap.exposures["443/tcp"] == Exposure.OPEN_WORLD
    assert total_deductions(check_services([snap])) == 2


def test_unknown_listeners_change_nothing():
    assert _snap(_OPEN, None).exposures["443/tcp"] == Exposure.OPEN_WORLD


def test_a_refusing_rule_is_left_as_said():
    assert _snap(_DENY, set()).exposures["443/tcp"] == Exposure.DENY
