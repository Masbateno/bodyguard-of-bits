"""
v0.15.0 — a source address made unrelated ports look firewalled.

`_classify_exposure` searched the whole `ufw status numbered` line for the port
number. One ordinary rule::

    [ 1] 80/tcp   ALLOW IN   192.168.1.22

therefore matched ports 1, 22, 168 and 192 as well as 80, and each was reported
as OPEN_LOCAL — "open, restricted to the local network". Port 22 is the worst
case and the likeliest: it is the commonest last octet on an RFC1918 network, so
a host running SSH with no firewall rule at all was told SSH was restricted to
the LAN. Falsely reassuring, on the service check that covers 38 services.

`ports.py` had this right and said why in a docstring — "to avoid matching port
numbers appearing later on the line (e.g. inside source IPs like 192.168.1.22)".
Two implementations of one rule, one of them correct: the fourth time that shape
appeared in this cycle. The grammar now lives in `bob/checks/_ufw.py` and both
callers use it, so `services` also gained the application profiles, ranges and
lists that `ports` learned earlier in the cycle.
"""

from __future__ import annotations

import pytest

from bob.checks.services import Exposure, _classify_exposure

_ONE_RULE = "[ 1] 80/tcp                     ALLOW IN    192.168.1.22\n"


class TestASourceAddressIsNotATarget:
    @pytest.mark.parametrize("port", ["22/tcp", "1/tcp", "168/tcp", "192/tcp"])
    def test_octets_of_the_source_do_not_match(self, port):
        assert _classify_exposure(port, _ONE_RULE) is Exposure.NO_RULE

    def test_the_rules_own_port_still_matches(self):
        assert _classify_exposure("80/tcp", _ONE_RULE) is Exposure.OPEN_LOCAL

    def test_a_private_destination_is_not_a_private_source(self):
        """`ufw allow from any to 192.168.1.5 port 22` prints the destination
        in front of the port. Anyone can reach it, so it is world-facing —
        reading the source restriction off the whole line called it OPEN_LOCAL
        because a private address appeared somewhere on it.

        The first version of this test asserted `is not OPEN_LOCAL` against a
        rule the parser did not match at all, so it passed without testing
        anything; a mutation survived and exposed it."""
        rules = "[ 1] 192.168.1.5 22/tcp        ALLOW IN    Anywhere\n"
        assert _classify_exposure("22/tcp", rules) is Exposure.OPEN_WORLD

    def test_a_destination_scoped_rule_still_covers_its_port(self):
        rules = "[ 1] 192.168.1.5 22/tcp        ALLOW IN    10.0.0.0/8\n"
        assert _classify_exposure("22/tcp", rules) is Exposure.OPEN_LOCAL


class TestTheOrdinaryVerdicts:
    def test_allow_from_anywhere_is_world_facing(self):
        rules = "[ 1] 22/tcp                    ALLOW IN    Anywhere\n"
        assert _classify_exposure("22/tcp", rules) is Exposure.OPEN_WORLD

    def test_allow_from_a_private_range_is_local(self):
        rules = "[ 1] 22/tcp                    ALLOW IN    10.0.0.0/8\n"
        assert _classify_exposure("22/tcp", rules) is Exposure.OPEN_LOCAL

    def test_deny_is_deny(self):
        rules = "[ 1] 3306/tcp                  DENY IN     Anywhere\n"
        assert _classify_exposure("3306/tcp", rules) is Exposure.DENY

    def test_no_matching_rule(self):
        rules = "[ 1] 80/tcp                    ALLOW IN    Anywhere\n"
        assert _classify_exposure("22/tcp", rules) is Exposure.NO_RULE

    def test_first_match_wins(self):
        """UFW evaluates rules in order."""
        rules = ("[ 1] 22/tcp                  ALLOW IN    Anywhere\n"
                 "[ 2] 22/tcp                  DENY IN     Anywhere\n")
        assert _classify_exposure("22/tcp", rules) is Exposure.OPEN_WORLD


class TestWhatServicesGainedFromTheSharedParser:
    def test_an_application_profile_is_resolved(self):
        """`ufw allow OpenSSH` prints the profile name and no port at all."""
        rules = "[ 1] OpenSSH                  ALLOW IN    10.0.0.0/8\n"
        assert _classify_exposure("22/tcp", rules, {"OpenSSH": ["22/tcp"]}) \
            is Exposure.OPEN_LOCAL

    def test_a_profile_name_containing_a_space_is_resolved(self):
        rules = "[ 1] Postfix Submission       ALLOW IN    Anywhere\n"
        assert _classify_exposure("587/tcp", rules,
                                  {"Postfix Submission": ["587/tcp"]}) \
            is Exposure.OPEN_WORLD

    def test_an_unknown_profile_matches_nothing(self):
        rules = "[ 1] Nextcloud                ALLOW IN    Anywhere\n"
        assert _classify_exposure("22/tcp", rules, {}) is Exposure.NO_RULE

    @pytest.mark.parametrize("port", ["6000/tcp", "6003/tcp", "6007/tcp"])
    def test_a_port_range_is_resolved(self, port):
        rules = "[ 1] 6000:6007/tcp            ALLOW IN    Anywhere\n"
        assert _classify_exposure(port, rules) is Exposure.OPEN_WORLD

    def test_a_range_keeps_its_protocol(self):
        rules = "[ 1] 6000:6007/tcp            ALLOW IN    Anywhere\n"
        assert _classify_exposure("6000/udp", rules) is Exposure.NO_RULE

    @pytest.mark.parametrize("port", ["80/tcp", "443/tcp"])
    def test_a_port_list_is_resolved(self, port):
        rules = "[ 1] 80,443/tcp               ALLOW IN    Anywhere\n"
        assert _classify_exposure(port, rules) is Exposure.OPEN_WORLD

    def test_an_interface_scoped_rule_is_read(self):
        rules = "[ 1] 25/tcp on eth0           ALLOW IN    Anywhere\n"
        assert _classify_exposure("25/tcp", rules) is Exposure.OPEN_WORLD


class TestRegistryValidation:
    @pytest.mark.parametrize("port", ["notaport/tcp", "0/tcp", "70000/tcp",
                                      "22/sctp"])
    def test_a_malformed_registry_entry_yields_no_rule(self, port):
        rules = "[ 1] 22/tcp                   ALLOW IN    Anywhere\n"
        assert _classify_exposure(port, rules) is Exposure.NO_RULE
