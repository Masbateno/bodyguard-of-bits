"""v0.32.0 — send_redirects is said, not scored, where no interface forwards.

0.31.4 measured it (Linux 7.0, network namespaces): the kernel sends an ICMP
redirect only for a packet it forwards back out the interface it came in on,
and forwards only from an interface whose own forwarding value is 1; with
forwarding off and send_redirects at 1, it sent none. 0.31.4 said so in the
detail and kept the point; the user decided (9 November 2026) that the inert
case is INFO with no point in 0.32.0. Where an interface forwards, or where
forwarding could not be read, the WARN −1 stays.
"""

from __future__ import annotations

import pytest

from bob.checks import hardening as h
from bob.scoring import FindingLevel
from tests.helpers import _t


def _run(forwarding):
    snap = h.HardeningSnapshot(send_redirects=True, send_redirects_where=["enp3s0", "default"],
                               send_redirects_forwarding=forwarding)
    result = h.check_hardening(snap, t=_t)
    f = next(f for f in result.findings if f.key == "hardening.send_redirects_enabled")
    points = [d.points for d in result.deductions if d.key == "hardening.send_redirects_enabled"]
    return f, points


def test_no_interface_forwards_is_info_without_a_point():
    f, points = _run([])
    assert f.level == FindingLevel.INFO and points == []
    assert "hardening.send_redirects_idle" in f.detail


def test_the_fix_is_still_shown_when_inert():
    f, _ = _run([])
    assert "net.ipv4.conf.enp3s0.send_redirects=0" in f.cmd and f.fix_action


@pytest.mark.parametrize("forwarding", [["enp3s0"], None], ids=["an-interface-forwards", "forwarding-unread"])
def test_otherwise_the_point_stays(forwarding):
    f, points = _run(forwarding)
    assert f.level == FindingLevel.WARN and points == [1]
