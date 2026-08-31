"""
v0.15.1 — two more private copies of the UFW rule grammar.

v0.15.0 unified `ports` and `services` onto `bob/checks/_ufw.py` after finding
they disagreed. It did not sweep for *other* copies, and there were two:

* `ipv6._extract_ufw_v6_covered` — examined during v0.15.0 and cleared on the
  grounds that it was correctly anchored on the rule number. Anchoring is not
  completeness. It matched a bare port and nothing else, so `OpenSSH (v6)`,
  `6000:6007/tcp (v6)` and `80,443/tcp (v6)` all read as *no v6 rule at all*.
  Measured on those three lines it returned an empty set — meaning every one of
  those ports raised `ipv6.port_no_v6_rule`, a warning with a deduction, on a
  host that had the rules.

* `ddns._find_open_ports` — never examined. It searched the whole line for
  `\\b(\\d+)/(tcp|udp)\\b`, so a range yielded only its upper bound and a list
  only its last element; an application profile yielded nothing. On four rules
  covering twelve ports it found two. It also tested the source restriction
  against the whole line, so `ufw allow from any to 192.168.1.5 port 8080` —
  private *destination*, public source — was filed as restricted.

The first under-reports v6 coverage, producing false alarms with deductions; the
second under-reports open ports, which is the reassuring direction. Both now
delegate to the shared parser.
"""

from __future__ import annotations

import pytest

import bob.checks.ddns as dd
import bob.checks.ipv6 as ip6

_APPS = {"OpenSSH": ["22/tcp"], "Samba": ["137,138/udp", "139,445/tcp"]}


class TestIpv6Coverage:
    _RULES = ("[ 1] OpenSSH (v6)          ALLOW IN  Anywhere (v6)\n"
              "[ 2] 6000:6007/tcp (v6)    ALLOW IN  Anywhere (v6)\n"
              "[ 3] 80,443/tcp (v6)       ALLOW IN  Anywhere (v6)\n")

    def _covered(self):
        return ip6._extract_ufw_v6_covered(self._RULES, _APPS)

    def test_an_application_profile_counts_as_coverage(self):
        assert "22/tcp" in self._covered()

    @pytest.mark.parametrize("port", [6000, 6003, 6007])
    def test_every_port_of_a_range_counts(self, port):
        assert f"{port}/tcp" in self._covered()

    def test_the_range_does_not_leak(self):
        cov = self._covered()
        assert "5999/tcp" not in cov and "6008/tcp" not in cov

    @pytest.mark.parametrize("port", [80, 443])
    def test_both_ports_of_a_list_count(self, port):
        assert f"{port}/tcp" in self._covered()

    def test_a_rule_without_v6_is_not_v6_coverage(self):
        cov = ip6._extract_ufw_v6_covered("[ 1] 22/tcp  ALLOW IN  Anywhere\n", _APPS)
        assert cov == set()

    def test_a_plain_v6_rule_still_works(self):
        cov = ip6._extract_ufw_v6_covered("[ 1] 22/tcp (v6)  ALLOW IN  Anywhere (v6)\n")
        assert cov == {"22/tcp"}

    def test_a_rule_without_a_protocol_covers_both(self):
        cov = ip6._extract_ufw_v6_covered("[ 1] 53 (v6)  ALLOW IN  Anywhere (v6)\n")
        assert cov == {"53/tcp", "53/udp"}


class TestDdnsOpenPorts:
    _RULES = ("[ 1] OpenSSH              ALLOW IN  Anywhere\n"
              "[ 2] 6000:6007/tcp        ALLOW IN  Anywhere\n"
              "[ 3] 80,443/tcp           ALLOW IN  Anywhere\n"
              "[ 4] 192.168.1.5 8080/tcp ALLOW IN  Anywhere\n"
              "[ 5] 9000/tcp             ALLOW IN  192.168.1.0/24\n"
              "[ 6] Anywhere             ALLOW IN  Anywhere\n")

    def _open(self):
        return set(dd._find_open_ports(self._RULES, loopback_ports=set(),
                                       active_ports=None, app_profiles=_APPS))

    def test_an_application_profile_is_an_open_port(self):
        assert "22/tcp" in self._open()

    def test_a_whole_range_is_open_not_just_its_bound(self):
        assert {f"{p}/tcp" for p in range(6000, 6008)} <= self._open()

    def test_a_whole_list_is_open_not_just_its_last(self):
        assert {"80/tcp", "443/tcp"} <= self._open()

    def test_a_private_destination_is_not_a_private_source(self):
        """`ufw allow from any to 192.168.1.5 port 8080` is open to the world."""
        assert "8080/tcp" in self._open()

    def test_a_private_source_is_still_excluded(self):
        assert "9000/tcp" not in self._open()

    def test_the_blanket_anywhere_row_is_not_a_port(self):
        assert not any(p.startswith("0/") for p in self._open())

    def test_a_deny_rule_is_not_an_open_port(self):
        got = dd._find_open_ports("[ 1] 3306/tcp  DENY IN  Anywhere\n",
                                  loopback_ports=set(), active_ports=None)
        assert got == []

    def test_loopback_only_ports_are_still_filtered(self):
        got = dd._find_open_ports("[ 1] 6379/tcp  ALLOW IN  Anywhere\n",
                                  loopback_ports={"6379/tcp"}, active_ports=None)
        assert got == []

    def test_a_port_with_no_listener_is_still_filtered(self):
        got = dd._find_open_ports("[ 1] 8443/tcp  ALLOW IN  Anywhere\n",
                                  loopback_ports=set(), active_ports=set())
        assert got == []


class TestFirewallOrphanRules:
    """`firewall._check_orphan_rules` was the third copy — found by the guard
    below, not by hand. It searched the line for one `<port>/<proto>`, so a
    range yielded only its upper bound and a list only its last element: two
    orphan ports reported out of eight. An orphan rule is a firewall hole left
    behind by a service that no longer runs, so under-reporting is the quiet
    direction."""

    _RULES = ["[ 1] OpenSSH              ALLOW IN  Anywhere",
              "[ 2] 6000:6007/tcp        ALLOW IN  Anywhere",
              "[ 3] 80,443/tcp           ALLOW IN  Anywhere"]
    _LISTENING = {"22/tcp", "6000/tcp", "80/tcp"}

    def _orphans(self, listening=None, rules=None):
        import bob.checks.firewall as fw
        from bob.scoring import CheckResult
        r = CheckResult()
        fw._check_orphan_rules(rules or self._RULES,
                               self._LISTENING if listening is None else listening,
                               lambda k, **kw: str(kw.get("port", "")), r,
                               {"OpenSSH": ["22/tcp"]})
        return {f.message for f in r.findings}

    @pytest.mark.parametrize("port", [6001, 6004, 6007])
    def test_every_unlistened_port_of_a_range_is_an_orphan(self, port):
        assert f"{port}/tcp" in self._orphans()

    def test_the_listened_port_of_a_range_is_not(self):
        assert "6000/tcp" not in self._orphans()

    def test_the_unlistened_half_of_a_list_is_an_orphan(self):
        assert "443/tcp" in self._orphans()

    def test_the_listened_half_of_a_list_is_not(self):
        assert "80/tcp" not in self._orphans()

    def test_an_application_profile_with_a_listener_is_not_an_orphan(self):
        assert "22/tcp" not in self._orphans()

    def test_an_application_profile_without_one_is(self):
        assert "22/tcp" in self._orphans(listening={"80/tcp"})

    def test_a_protocol_less_rule_needs_both_protocols_idle(self):
        """UFW applies such a rule to both, so one listener is enough to make it
        legitimate. The finding renders it as `5353/tcp+udp` — a v0.11.1
        formatting choice, verified here rather than assumed."""
        rules = ["[ 1] 5353  ALLOW IN  Anywhere"]
        assert self._orphans(listening={"5353/udp"}, rules=rules) == set()
        assert "5353/tcp+udp" in self._orphans(listening=set(), rules=rules)

    def test_a_v6_mirror_is_not_counted_twice(self):
        rules = ["[ 1] 8080/tcp (v6)  ALLOW IN  Anywhere (v6)"]
        assert self._orphans(listening=set(), rules=rules) == set()


class TestNoPrivateCopiesRemain:
    """The sweep that found these: any module parsing `ufw status numbered`
    must go through the shared grammar."""

    def test_every_ufw_rule_parser_uses_the_shared_module(self):
        import ast
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent / "bob"
        offenders = []
        for f in sorted(root.rglob("*.py")):
            if f.name == "_ufw.py":
                continue
            src = f.read_text(encoding="utf-8")
            # A private copy is a regex anchored on the `[ N]` rule number.
            if r"\[\s*\d+\]" not in src:
                continue
            if "_ufw." not in src:
                offenders.append(str(f.relative_to(root.parent)))
        assert not offenders, (
            "modules parsing ufw rules without the shared grammar in "
            "bob/checks/_ufw.py: " + ", ".join(offenders))
