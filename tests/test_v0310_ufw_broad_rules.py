"""
v0.31.0, review of the changelog — a UFW rule that names no port admits every
port from its source.

Under UFW's default deny, BOB called a listener with no rule of its own
"covered by the default deny" — in the ports section (since long before
0.31.0), in the IPv6 section (0.31.0) and in the services section ("covered by
default deny policy"). Measured on Kali in a network namespace (7 November
2026, review-ufwbroad.txt): with `ufw allow from <client>` or `ufw allow in on
h0`, 8099 answered over IPv4 and IPv6 while BOB said it was covered.

Decision (the user, same day): such a port is reported as admitted by the
rule, named; it decides as a rule for the port from the same source would —
no deduction in the ports and IPv6 sections, the services' own reading
(restricted to the local network, or open) in theirs.

``_UFW`` below is ``ufw status numbered`` as ufw printed it on Kali for these
rules (one namespace, rules added one by one).
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import _ufw
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
from bob.checks.services import Exposure, _allow_rule_source, _classify_exposure

_UFW = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] Anywhere                   ALLOW IN    10.77.0.1
[ 3] Anywhere                   ALLOW IN    10.77.0.3/tcp
[ 4] 10.77.0.2                  ALLOW IN    10.77.0.4
[ 5] Anywhere on h0             ALLOW IN    Anywhere
[ 6] Anywhere                   LIMIT IN    10.77.0.9
[ 7] Anywhere                   ALLOW FWD   10.77.0.6
[ 8] Anywhere                   DENY IN     10.77.0.7
[ 9] 10.77.0.8                  ALLOW OUT   Anywhere                   (out)
[10] 80                         ALLOW IN    192.168.1.0/24
[11] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[12] Anywhere (v6) on h0        ALLOW IN    Anywhere (v6)
[13] Anywhere (v6)              ALLOW IN    2001:db8::5/udp
[14] Anywhere (v6)              ALLOW IN    2001:db8::/32
"""


def _only(*numbers: int) -> str:
    keep = {f"[{n:2d}]" for n in numbers}
    return "\n".join(l for l in _UFW.splitlines() if l[:4] in keep) + "\n"


class TestWhatAdmitsEveryPort:

    def test_the_measured_rules(self):
        v4 = [r for r, _, _ in _ufw.broad_admits(_UFW, v6=False)]
        assert v4 == ["Anywhere ALLOW IN 10.77.0.1", "Anywhere ALLOW IN 10.77.0.3/tcp",
                      "10.77.0.2 ALLOW IN 10.77.0.4", "Anywhere on h0 ALLOW IN Anywhere",
                      "Anywhere LIMIT IN 10.77.0.9"]
        v6 = [r for r, _, _ in _ufw.broad_admits(_UFW, v6=True)]
        assert v6 == ["Anywhere (v6) on h0 ALLOW IN Anywhere (v6)",
                      "Anywhere (v6) ALLOW IN 2001:db8::5/udp",
                      "Anywhere (v6) ALLOW IN 2001:db8::/32"]

    def test_routed_outgoing_and_deny_rules_admit_nothing(self):
        assert _ufw.broad_admits(_only(7, 8, 9)) == []

    def test_a_rule_for_a_port_is_not_one_for_every_port(self):
        """`80` and `6000:6007` are ports, not addresses."""
        assert _ufw.broad_admits(_only(1, 10, 11)) == []

    def test_the_protocol_is_read_after_the_source(self):
        assert _ufw.broad_admits(_only(3)) == [("Anywhere ALLOW IN 10.77.0.3/tcp", "tcp", "10.77.0.3")]
        assert _ufw.admitting(_ufw.broad_admits(_only(3)), "udp") == []


def _ports(rules: str, address: str = "0.0.0.0", lang: str = "en"):
    snap = PortsSnapshot(ports=[ListeningPort(port=8099, proto="tcp", address=address, raw_line="",
                                              process="python3")],
                         ufw_rules=rules, ss_output="")
    i18n.init(lang)
    try:
        return check_ports(snap, ufw_active=True, default_incoming_policy="deny", t=i18n.t)
    finally:
        i18n.init("en")


class TestThePortsSection:

    def test_an_admitted_port_is_not_covered(self):
        res = _ports(_only(1, 2))
        keys = {f.key for f in res.findings}
        assert "ports.uncovered_broad_rule" in keys
        assert "ports.uncovered_default_deny" not in keys
        assert not res.deductions

    def test_the_rule_is_named_in_the_rendered_line(self):
        res = _ports(_only(1, 5), lang="fr")
        line = next(f.message for f in res.findings if f.key == "ports.uncovered_broad_rule")
        assert "Anywhere on h0 ALLOW IN Anywhere" in line and "pas couvert par le refus par défaut" in line

    def test_without_such_a_rule_the_default_deny_covers(self):
        """Polarity twin, measured: case A, dropped over both families."""
        keys = {f.key for f in _ports(_only(1, 8)).findings}
        assert "ports.uncovered_default_deny" in keys

    def test_an_ipv4_rule_does_not_admit_an_ipv6_listener(self):
        keys = {f.key for f in _ports(_only(1, 2), address="::").findings}
        assert "ports.uncovered_broad_rule" not in keys


def _ipv6(rules: str):
    snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=True,
                        ipv6_listeners=["8099/tcp"], ufw_v6_covered=["22/tcp"],
                        ufw_v6_admits=_ufw.broad_admits(rules, v6=True), has_global_ipv6=True)
    return check_ipv6(snap, ufw_active=True, ufw_incoming_policy="deny")


class TestTheIpv6Section:

    def test_an_admitted_listener_is_not_covered(self):
        res = _ipv6(_only(11, 12))
        keys = {f.key for f in res.findings}
        assert "ipv6.ports_broad_rule" in keys and "ipv6.ports_default_deny" not in keys
        assert not res.deductions

    def test_without_such_a_rule_the_default_deny_covers(self):
        keys = {f.key for f in _ipv6(_only(11)).findings}
        assert "ipv6.ports_default_deny" in keys and "ipv6.ports_broad_rule" not in keys

    def test_a_udp_rule_does_not_admit_a_tcp_listener(self):
        keys = {f.key for f in _ipv6(_only(11, 13)).findings}
        assert "ipv6.ports_default_deny" in keys and "ipv6.ports_broad_rule" not in keys


class TestTheServicesSection:

    @pytest.mark.parametrize("rules, port, exposure, source", [
        (_only(1, 2), "445/tcp", Exposure.OPEN_LOCAL, "10.77.0.1"),
        (_only(5), "445/tcp", Exposure.OPEN_WORLD, "Anywhere"),
        (_only(3), "5353/udp", Exposure.NO_RULE, ""),
        (_only(7, 8), "445/tcp", Exposure.NO_RULE, ""),
    ])
    def test_a_portless_rule_decides_as_a_rule_for_the_port(self, rules, port, exposure, source):
        assert _classify_exposure(port, rules) == exposure
        assert _allow_rule_source(port, rules) == source

    def test_a_rule_naming_the_port_still_decides_first(self):
        assert _classify_exposure("22/tcp", _only(1, 2)) == Exposure.OPEN_WORLD


# Second external review (7 November 2026): UFW applies the first rule that
# matches. As ufw printed them on Kali (review2-ufw.txt), 8099 answered the
# client in E and not in E'.
_E = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] Anywhere                   ALLOW IN    10.77.0.1
[ 3] 8099/tcp                   DENY IN     Anywhere
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 5] Anywhere (v6)              ALLOW IN    2001:db8:77::1
[ 6] 8099/tcp (v6)              DENY IN     Anywhere (v6)
"""
_E_FIRST = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   DENY IN     Anywhere
[ 3] Anywhere                   ALLOW IN    10.77.0.1
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 5] 8099/tcp (v6)              DENY IN     Anywhere (v6)
[ 6] Anywhere (v6)              ALLOW IN    2001:db8:77::1
"""


class TestTheRuleOrder:

    def test_a_portless_allow_before_the_deny_admits_first(self):
        earlier, action = _ufw.admitted_before_own_rule(_E, 8099, "tcp", v6=False)
        assert [r for r, _, _ in earlier] == ["Anywhere ALLOW IN 10.77.0.1"] and action == "DENY"

    def test_after_the_deny_it_does_not(self):
        assert _ufw.admitted_before_own_rule(_E_FIRST, 8099, "tcp", v6=False) == ([], "DENY")

    def test_the_families_are_walked_apart(self):
        earlier, _ = _ufw.admitted_before_own_rule(_E, 8099, "tcp", v6=True)
        assert [r for r, _, _ in earlier] == ["Anywhere (v6) ALLOW IN 2001:db8:77::1"]

    def test_the_ports_section_says_so(self):
        keys = {f.key for f in _ports(_E).findings}
        assert "ports.refused_after_broad_rule" in keys
        assert "ports.refused_after_broad_rule" not in {f.key for f in _ports(_E_FIRST).findings}

    def test_the_ipv6_section_says_so(self):
        snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=True,
                            ipv6_listeners=["8099/tcp"], ufw_v6_covered=["22/tcp", "8099/tcp"],
                            ufw_v6_admitted_first={"8099/tcp": ["Anywhere (v6) ALLOW IN 2001:db8:77::1"]},
                            has_global_ipv6=True)
        res = check_ipv6(snap, ufw_active=True, ufw_incoming_policy="deny")
        assert "ipv6.ports_refused_after_broad_rule" in {f.key for f in res.findings}
        assert not res.deductions

    def test_the_services_section_reads_it_open_to_the_source(self):
        assert _classify_exposure("8099/tcp", _E) == Exposure.OPEN_LOCAL
        assert _allow_rule_source("8099/tcp", _E) == "10.77.0.1"
        assert _classify_exposure("8099/tcp", _E_FIRST) == Exposure.DENY

    def test_a_reject_for_the_port_is_a_refusal(self):
        """It fell through as if no rule named the port."""
        rules = "[ 1] 8099/tcp                   REJECT IN   Anywhere\n[ 2] Anywhere on h0             ALLOW IN    Anywhere\n"
        assert _classify_exposure("8099/tcp", rules) == Exposure.DENY
