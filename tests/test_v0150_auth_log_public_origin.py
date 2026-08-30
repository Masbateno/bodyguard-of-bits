"""
v0.15.0 — a host with UseDNS enabled reported no public SSH logins at all.

`_is_private` returned True on anything `ipaddress.ip_address()` could not
parse, with the comment "treat as private to avoid alerting on log noise". But
the source is captured by `from\\s+(\\S+)\\s+port` out of an sshd line, and sshd
logs a **hostname** there whenever UseDNS is on. So on such a host every remote
login parsed to a non-IP, was filed as internal, and the
`auth_log.public_login` warning could not fire. A machine accepting SSH logins
from the internet was told it accepted none.

The same question is answered the other way elsewhere in the same tool —
`DockerPort.is_public` assumes public on an unrecognised address, "to be safe".
Two helpers disagreeing about "is this address public" is how one of them ends
up wrong.
"""

from __future__ import annotations

import pytest

from bob.checks.auth_log import _is_private


class TestPrivateRanges:
    """The ranges themselves were never in doubt and must not move."""

    @pytest.mark.parametrize("ip", [
        "10.0.0.1", "172.16.0.1", "192.168.1.5", "127.0.0.1",
        "::1", "fd00::1", "fe80::1",
    ])
    def test_private_stays_private(self, ip):
        assert _is_private(ip)

    @pytest.mark.parametrize("ip", [
        "8.8.8.8", "203.0.113.7", "2001:db8::1",
    ])
    def test_public_stays_public(self, ip):
        assert not _is_private(ip)


class TestNonIpSources:
    """What sshd writes when UseDNS is on."""

    @pytest.mark.parametrize("src", [
        "host.example.com",
        "mail.corp.example",
        "workstation.lan",
        "not-an-ip",
    ])
    def test_a_name_is_not_treated_as_internal(self, src):
        assert not _is_private(src), \
            "a resolved hostname was filed as a private origin, which is how " \
            "every UseDNS host reported zero public logins"

    def test_the_alarming_direction_is_the_chosen_one(self):
        """`workstation.lan` is very likely internal, and it will now be listed.

        That is deliberate and it is the cheaper error: a false alarm naming a
        source the operator can read is recoverable, a silence is not. This test
        exists so the trade-off is a decision on record rather than an accident.
        """
        assert not _is_private("workstation.lan")
