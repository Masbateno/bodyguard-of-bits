"""An inactive .socket holds no port open — it is not an orphan.

An orphaned socket is one that is *listening* while the service behind it is
broken: systemd accepts the connection and then fails it. An inactive socket
listens for nothing — it is a dormant unit definition, no surface at all.

Measured on a Raspberry Pi Zero W:

    systemctl show syslog.socket -p ActiveState -p Triggers
    ActiveState=inactive   Triggers=syslog.service   (syslog.service not-found)

syslog.socket is inactive with a broken trigger. BOB 0.18.0 listed it as an
orphaned socket, though it exposes nothing. The module docstring always said
an orphan is a socket "still active while the service is broken"; the code
did not check the active part.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.socket_units import (
    SocketUnit,
    SocketUnitsSnapshot,
    check_socket_units,
)


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


def _socket(name, active, *, trigger="dead.service", listens=("/run/x",)):
    return SocketUnit(name=name, active_state=active, listens=list(listens),
                      triggers=[trigger], broken_trigger=trigger)


def _keys(result):
    return [f.key for f in check_socket_units(result, t=i18n.t).findings] \
        if isinstance(result, SocketUnitsSnapshot) else None


# ---------------------------------------------------------------------------
# The Pi case
# ---------------------------------------------------------------------------

def test_an_inactive_socket_with_a_broken_trigger_is_not_an_orphan():
    su = _socket("syslog.socket", "inactive",
                 trigger="syslog.service", listens=["/run/systemd/journal/syslog"])
    assert su.is_orphan is False


def test_the_inactive_syslog_socket_produces_no_orphan_finding():
    snap = SocketUnitsSnapshot(available=True, sockets=[
        _socket("syslog.socket", "inactive",
                trigger="syslog.service", listens=["/run/systemd/journal/syslog"])])
    keys = [f.key for f in check_socket_units(snap, t=i18n.t).findings]
    assert "socket_units.orphan" not in keys
    assert "socket_units.clean" in keys


# ---------------------------------------------------------------------------
# The mirror: an active orphan is still flagged
# ---------------------------------------------------------------------------

def test_an_active_socket_with_a_broken_trigger_is_still_an_orphan():
    assert _socket("cockpit.socket", "active").is_orphan is True


def test_an_active_orphan_still_produces_its_finding():
    snap = SocketUnitsSnapshot(available=True, sockets=[
        _socket("cockpit.socket", "active", listens=["0.0.0.0:9090"])])
    result = check_socket_units(snap, t=i18n.t)
    keys = [f.key for f in result.findings]
    assert "socket_units.orphan" in keys
    # non-loopback + broken → the exposed deduction still fires
    assert any(d.key == "socket_units.orphan_exposed" for d in result.deductions)


def test_a_failed_socket_is_still_flagged_regardless_of_orphan():
    """is_failed is independent — a socket that failed to come up is a problem
    whatever its trigger."""
    su = SocketUnit(name="broke.socket", active_state="failed",
                    listens=["127.0.0.1:1"], triggers=["x.service"], broken_trigger="")
    assert su.is_failed is True
    snap = SocketUnitsSnapshot(available=True, sockets=[su])
    assert "socket_units.failed" in [f.key for f in check_socket_units(snap, t=i18n.t).findings]
