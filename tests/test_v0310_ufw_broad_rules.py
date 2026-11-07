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
        """Open to 10.77.0.1 over IPv4 and to 2001:db8:77::1 (public) over IPv6,
        both measured; the IPv6 admission was missed until the third review."""
        assert _classify_exposure("8099/tcp", _E) == Exposure.OPEN_WORLD
        assert _allow_rule_source("8099/tcp", _E) == "10.77.0.1, 2001:db8:77::1"
        v4_only = "\n".join(_E.splitlines()[:3]) + "\n"
        assert _classify_exposure("8099/tcp", v4_only) == Exposure.OPEN_LOCAL
        assert _allow_rule_source("8099/tcp", v4_only) == "10.77.0.1"
        assert _classify_exposure("8099/tcp", _E_FIRST) == Exposure.DENY

    def test_a_reject_for_the_port_is_a_refusal(self):
        """It fell through as if no rule named the port."""
        rules = "[ 1] 8099/tcp                   REJECT IN   Anywhere\n[ 2] Anywhere on h0             ALLOW IN    Anywhere\n"
        assert _classify_exposure("8099/tcp", rules) == Exposure.DENY


# Third external review (7 November 2026): a rule matches only its own source.
# ``ufw status numbered`` as ufw printed it on Kali for each case
# (review3-ufw.txt); C is a private client (10.77.0.1, fd77::1), P a public one
# (203.0.113.5, 2001:db8:99::5). "probe" is what P measured.
_G = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   ALLOW IN    10.77.0.1
[ 3] 8099/tcp                   ALLOW IN    Anywhere
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 5] 8099/tcp                   ALLOW IN    fd77::1
[ 6] 8099/tcp (v6)              ALLOW IN    Anywhere (v6)
"""
_H = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   ALLOW IN    10.77.0.1
[ 3] Anywhere                   ALLOW IN    203.0.113.5
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 5] 8099/tcp                   ALLOW IN    fd77::1
[ 6] Anywhere (v6)              ALLOW IN    2001:db8:99::5
"""
_I = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   DENY IN     203.0.113.9
[ 3] 8099/tcp                   ALLOW IN    Anywhere
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 5] 8099/tcp                   DENY IN     2001:db8:99::9
[ 6] 8099/tcp (v6)              ALLOW IN    Anywhere (v6)
"""
_J = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   ALLOW IN    10.77.0.1
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 4] 8099/tcp                   ALLOW IN    fd77::1
"""
_K = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   DENY IN     Anywhere
[ 3] Anywhere                   ALLOW IN    203.0.113.5
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 5] 8099/tcp (v6)              DENY IN     Anywhere (v6)
[ 6] Anywhere (v6)              ALLOW IN    2001:db8:99::5
"""
_L = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   DENY IN     Anywhere
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 4] Anywhere (v6)              ALLOW IN    2001:db8:99::5
"""
_M = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   ALLOW OUT   Anywhere                   (out)
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 4] 8099/tcp (v6)              ALLOW OUT   Anywhere (v6)              (out)
"""


class TestEverySourceDecides:

    @pytest.mark.parametrize("rules, exposure, measured", [
        (_G, Exposure.OPEN_WORLD, "G: P reached it, read restricted to local network"),
        (_H, Exposure.OPEN_WORLD, "H: P reached it, read restricted to local network"),
        (_I, Exposure.OPEN_WORLD, "I: P reached it, read explicitly blocked"),
        (_L, Exposure.OPEN_WORLD, "L: P reached it over IPv6, read explicitly blocked"),
        (_M, Exposure.NO_RULE, "M: dropped, read open to the internet"),
        (_J, Exposure.OPEN_LOCAL, "J (polarity): only C reached it"),
        (_K, Exposure.DENY, "K (polarity): nobody reached it"),
    ])
    def test_the_measured_cases(self, rules, exposure, measured):
        assert _classify_exposure("8099/tcp", rules) == exposure, measured

    def test_two_private_sources_are_not_a_single_host(self):
        """J: C reached it over IPv4 and IPv6 — two addresses BOB cannot tie to one host."""
        assert _allow_rule_source("8099/tcp", _J) == "10.77.0.1, fd77::1"

    def test_a_refusal_from_every_source_ends_the_walk(self):
        assert _ufw.admitting_sources(_K, 8099, "tcp") == ([], True)

    def test_a_refusal_for_one_source_does_not(self):
        assert _ufw.admitting_sources(_I, 8099, "tcp") == (["Anywhere", "Anywhere"], True)

    def test_an_outgoing_rule_admits_nothing(self):
        assert _ufw.admitting_sources(_M, 8099, "tcp") == ([], False)


class TestTheFamilyOfARule:
    """ufw marks "(v6)" only a rule naming no address of its own (measured)."""

    @pytest.mark.parametrize("line, v6", [
        ("[ 5] 8099/tcp                   ALLOW IN    fd77::1", True),
        ("[ 5] 8099/tcp                   DENY IN     2001:db8:99::9", True),
        ("[ 6] 8099/tcp (v6)              ALLOW IN    Anywhere (v6)", True),
        ("[ 2] 8099/tcp                   ALLOW IN    10.77.0.1", False),
        ("[ 1] 6000:6007/tcp              ALLOW IN    Anywhere", False),
        ("[ 3] 2001:db8::2 8099/tcp       ALLOW IN    Anywhere", True),
        ("[ 3] Anywhere                   ALLOW IN    2001:db8:77::1/udp", True),
    ])
    def test_the_address_says_the_family(self, line, v6):
        assert _ufw.is_v6_rule(line) is v6

    def test_an_unmarked_ipv6_rule_covers_an_ipv6_listener(self):
        from bob.checks.ipv6 import _extract_ufw_v6_covered
        assert "8099/tcp" in _extract_ufw_v6_covered(_J)

    def test_an_unmarked_ipv6_rule_is_not_an_ipv4_one(self):
        earlier, action = _ufw.admitted_before_own_rule(_J, 8099, "tcp", v6=False)
        assert action == "ALLOW"
        assert _ufw.broad_admits("[ 3] Anywhere                   ALLOW IN    2001:db8:77::1/udp\n",
                                 v6=False) == []

    def test_the_firewall_section_counts_it_as_ipv6(self):
        from bob.checks.firewall import _check_ipv6_coverage
        from bob.scoring import CheckResult
        lines = [l for l in _J.splitlines() if "(v6)" not in l]
        result = CheckResult()
        _check_ipv6_coverage(lines, lambda k, **kw: k, result, True)
        assert {f.key for f in result.findings} == {"firewall_rules.ipv6_ok"}


class TestTheDefaultPolicyDecidesARuleLessPort:
    """Third review, measured on Kali (review3-allow.txt): UFW active at default
    allow incoming, 8099 with no rule (or only `allow out 8099`) answered every
    client, and the services section said "covered by default deny policy"."""

    @staticmethod
    def _check(policy, exposure=Exposure.NO_RULE, lang="en"):
        from bob.checks.services import check_services
        from tests.test_services import make_snapshot
        snap = make_snapshot(exposures={"22/tcp": exposure})
        i18n.init(lang)
        try:
            return check_services([snap], network_context="local", ufw_active=True,
                                  t=i18n.t, ufw_incoming_policy=policy)
        finally:
            i18n.init("en")

    def test_default_allow_opens_it(self):
        res = self._check("allow")
        assert any(d.key == "services.exposed.ssh" for d in res.deductions)
        assert not any("default deny" in f.message for f in res.findings)
        assert any("default incoming policy is allow" in f.message for f in res.findings)

    def test_an_outgoing_rule_alone_under_default_allow(self):
        assert _classify_exposure("8099/tcp", _M) == Exposure.NO_RULE
        assert any(d.key == "services.exposed.ssh" for d in self._check("allow").deductions)

    @pytest.mark.parametrize("policy", ["deny", "reject"])
    def test_default_deny_covers_it(self, policy):
        """Polarity twin: the measured norm."""
        res = self._check(policy)
        assert not res.deductions
        assert any("covered by default deny" in f.message for f in res.findings)

    def test_an_unread_policy_is_not_called_deny(self):
        res = self._check("unknown", lang="fr")
        assert not res.deductions
        assert not any("deny par défaut" in f.message for f in res.findings)
        assert any("n'a pas pu être lue" in f.message for f in res.findings)

    def test_the_run_hands_the_policy(self):
        import ast
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent / "bob" / "runner.py").read_text(encoding="utf-8")
        calls = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call)
                 and getattr(n.func, "id", "") == "check_single_service_display"]
        assert calls and all(any(k.arg == "ufw_incoming_policy" for k in c.keywords) for c in calls)

    def test_the_display_path_hands_it_on(self, capsys):
        from bob.display import check_single_service_display
        from tests.test_services import make_snapshot
        snap = make_snapshot(exposures={"22/tcp": Exposure.NO_RULE})
        report = type("R", (), {"write_finding": lambda self, *a, **k: None})()
        res = check_single_service_display(snap, "local", i18n.t, report, False, quiet=True,
                                           ufw_active=True, ufw_incoming_policy="allow")
        assert any(d.key == "services.exposed.ssh" for d in res.deductions)


# v0.31.0, fourth review — measured on Kali (review4-ufw-fixed.txt): a refusal on one
# interface (P, U, V), to one destination address (Q), for one host (R), for IPv4
# only (T), or from everyone (Q2, S, the polarity twins).
_R4P = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp on h1             DENY IN     Anywhere
[ 3] 8099/tcp                   ALLOW IN    Anywhere
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 5] 8099/tcp (v6) on h1        DENY IN     Anywhere (v6)
[ 6] 8099/tcp (v6)              ALLOW IN    Anywhere (v6)
"""
_R4Q = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 203.0.113.2 8099/tcp       DENY IN     Anywhere
[ 3] 8099/tcp                   ALLOW IN    Anywhere
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 5] 2001:db8:99::2 8099/tcp    DENY IN     Anywhere (v6)
[ 6] 8099/tcp (v6)              ALLOW IN    Anywhere (v6)
"""
_R4Q2 = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   DENY IN     Anywhere
[ 3] 8099/tcp                   ALLOW IN    203.0.113.5
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 5] 8099/tcp (v6)              DENY IN     Anywhere (v6)
[ 6] 8099/tcp                   ALLOW IN    2001:db8:99::5
"""
_R4R = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   DENY IN     203.0.113.9
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 4] 8099/tcp                   DENY IN     2001:db8:99::9
"""
_R4S = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   DENY IN     Anywhere
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 4] 8099/tcp (v6)              DENY IN     Anywhere (v6)
"""
_R4T = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp                   DENY IN     Anywhere
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""
_R4U = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp on h1             DENY IN     Anywhere
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 4] 8099/tcp (v6) on h1        DENY IN     Anywhere (v6)
"""
_R4V = """[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8099/tcp on h1             DENY IN     Anywhere
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 4] 8099/tcp (v6) on h1        DENY IN     Anywhere (v6)
"""


class TestARefusalInPart:
    """Fourth review. A refusal ends the walk only when it refuses the port from
    every source, on every interface and to every address, in both families;
    what the rules leave falls to UFW's default incoming policy. Each case was
    read "explicitly blocked" while a client reached 8099."""

    @pytest.mark.parametrize("rules, exposure, closes", [
        (_R4P, Exposure.OPEN_WORLD, False),
        (_R4Q, Exposure.OPEN_WORLD, False),
        (_R4Q2, Exposure.DENY, True),
        (_R4R, Exposure.DENY, False),
        (_R4S, Exposure.DENY, True),
        (_R4T, Exposure.DENY, False),
        (_R4U, Exposure.DENY, False),
        (_R4V, Exposure.DENY, False),
    ])
    def test_the_walk(self, rules, exposure, closes):
        assert _classify_exposure("8099/tcp", rules) == exposure
        assert _ufw.refusal_closes(rules, 8099, "tcp") is closes

    @pytest.mark.parametrize("line", ["[ 2] 8099/tcp on h1             DENY IN     Anywhere",
                                      "[ 5] 8099/tcp (v6) on h1        DENY IN     Anywhere (v6)"])
    def test_the_interface_is_kept(self, line):
        rule = _ufw.parse_rule(line)
        assert (rule.iface, rule.to_col, rule.action) == ("h1", "8099/tcp", "DENY")

    @staticmethod
    def _check(rules, policy, monkeypatch, lang="en", loopback=None, listening=("8099/tcp",)):
        import bob.checks.services as S
        from bob.registry import ServiceRegistry
        monkeypatch.setattr(S, "_detect_installation", lambda s: (True, "dpkg"))
        monkeypatch.setattr(S, "_detect_state", lambda s: S.ServiceState.ACTIVE_ENABLED)
        monkeypatch.setattr(S, "_resolve_ports", lambda s: ["8099/tcp"])
        snap = S.ServiceSnapshot._build_snapshot(ServiceRegistry.load().get("ssh"), rules,
                                                 loopback, set(listening))
        i18n.init(lang)
        try:
            return snap, S.check_services([snap], network_context="local", ufw_active=True,
                                          t=i18n.t, ufw_incoming_policy=policy)
        finally:
            i18n.init("en")

    @pytest.mark.parametrize("rules, policy, opened", [
        (_R4P, "deny", True), (_R4Q, "deny", True), (_R4Q2, "deny", False),
        (_R4R, "allow", True), (_R4S, "allow", False), (_R4T, "allow", True),
        (_R4U, "allow", True), (_R4V, "deny", False),
    ])
    def test_measured(self, rules, policy, opened, monkeypatch):
        _snap, res = self._check(rules, policy, monkeypatch)
        assert any(d.key == "services.exposed.ssh" for d in res.deductions) is opened
        blocked = [f for f in res.findings if f.key == "services.exposure.deny"]
        assert bool(blocked) is not opened

    @pytest.mark.parametrize("rules", [_R4R, _R4T, _R4U])
    def test_default_allow_says_why(self, rules, monkeypatch):
        _snap, res = self._check(rules, "allow", monkeypatch)
        assert any("only for some sources, interfaces, addresses or one family" in f.message
                   for f in res.findings)

    @pytest.mark.parametrize("policy", ["deny", "reject"])
    def test_default_deny_closes_the_rest(self, policy, monkeypatch):
        """Polarity twin of the policy: what the rules leave, the default refuses."""
        _snap, res = self._check(_R4R, policy, monkeypatch)
        assert not res.deductions
        assert any(f.key == "services.exposure.deny" for f in res.findings)

    def test_an_unread_policy_is_not_called_blocked(self, monkeypatch):
        _snap, res = self._check(_R4R, "unknown", monkeypatch, lang="fr")
        assert not res.deductions
        assert not any(f.key == "services.exposure.deny" for f in res.findings)
        assert any("n'a pas pu être lue" in f.message for f in res.findings)

    def test_the_snapshot_carries_it(self, monkeypatch):
        snap, _res = self._check(_R4R, "deny", monkeypatch)
        assert snap.refused_in_part == frozenset({"8099/tcp"})
        snap, _res = self._check(_R4S, "deny", monkeypatch)
        assert snap.refused_in_part == frozenset()

    def test_a_loopback_listener_stays_unreached(self, monkeypatch):
        snap, res = self._check(_R4R, "allow", monkeypatch, loopback={"8099/tcp"})
        assert snap.refused_in_part == frozenset() and not res.deductions

    def test_a_port_nothing_listens_on_stays_unreached(self, monkeypatch):
        snap, res = self._check(_R4R, "allow", monkeypatch, listening=())
        assert snap.refused_in_part == frozenset() and not res.deductions
