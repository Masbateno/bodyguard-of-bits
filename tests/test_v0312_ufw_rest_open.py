"""v0.31.2 — the ports and IPv6 sections read UFW's rules as the services section does.

0.31.1 counted a port with any UFW rule of its own as covered in the ports and
IPv6 sections. At UFW's default allow, a rule that admits the port from some
sources only, or refuses it only in part, leaves the clients it does not name
to the default — they reach it. Measured on Kali in network namespaces (a
private and a public client; review10-ufw.txt W1, review4-ufw.txt R, T, S):
`allow 8099 from <private>` and `deny 8099 from <another host>` answered the
public client; `deny 8099` over IPv4 only answered over IPv6; `deny 8099`
refused everyone. Run through 0.31.1, both sections read W1 and R covered (no
finding, "all IPv6 listeners covered"). At default deny or reject, nothing
changes: the default refuses what the rules leave.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import _ufw
from bob.checks.ipv6 import IPv6Snapshot, _extract_ufw_v6_covered, _v6_rules_in_part, check_ipv6
from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
from tests.test_v0310_ufw_broad_rules import _H, _R4R, _R4S, _R4T, _R10W1

ALLOW_ALL = ("[ 1] 22/tcp                     ALLOW IN    Anywhere\n[ 2] 8099/tcp                   ALLOW IN    Anywhere\n"
             "[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n[ 4] 8099/tcp (v6)              ALLOW IN    Anywhere (v6)\n")
NO_RULE = "[ 1] 22/tcp                     ALLOW IN    Anywhere\n[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n"
CASES = {"W1": _R10W1, "R": _R4R, "T": _R4T, "S": _R4S, "allow-all": ALLOW_ALL, "no-rule": NO_RULE}


def _ports(rules, policy, addresses=("0.0.0.0", "::")):
    snap = PortsSnapshot(ports=[ListeningPort(port=8099, proto="tcp", address=a, raw_line="", process="web")
                                for a in addresses], ufw_rules=rules, ss_output="")
    i18n.init("en")
    return check_ports(snap, ufw_active=True, t=i18n.t, default_incoming_policy=policy)


def _ipv6(rules, policy):
    covered = sorted(_extract_ufw_v6_covered(rules, {}))
    snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=True, ipv6_listeners=["8099/tcp"],
                        ufw_v6_covered=covered, ufw_v6_in_part=_v6_rules_in_part(rules, covered),
                        has_global_ipv6=True, ufw_present=True)
    i18n.init("en")
    return check_ipv6(snap, ufw_active=True, t=i18n.t, ufw_incoming_policy=policy)


@pytest.mark.parametrize("case, ports_open, ipv6_open", [
    ("W1", True, True), ("R", True, True), ("T", True, True),
    ("S", False, False), ("allow-all", False, False), ("no-rule", True, True),
])
def test_at_default_allow(case, ports_open, ipv6_open):
    """As measured: the public client reached 8099 in W1, R and (over IPv6) T;
    S refused everyone; allow-all opens it on purpose."""
    assert any(d.key == "ports.uncovered" for d in _ports(CASES[case], "allow").deductions) is ports_open
    assert any(d.key == "ipv6.port_no_v6_rule" for d in _ipv6(CASES[case], "allow").deductions) is ipv6_open


@pytest.mark.parametrize("case", sorted(CASES))
@pytest.mark.parametrize("policy", ["deny", "reject"])
def test_at_default_deny_nothing_changes(case, policy):
    """Polarity twin: the default refuses what the rules leave."""
    assert not _ports(CASES[case], policy).deductions
    assert not _ipv6(CASES[case], policy).deductions


def test_the_ipv4_listener_refused_over_ipv4_is_covered():
    """T: `deny 8099` over IPv4 only closes the IPv4 listener; only the IPv6 one is open."""
    assert not _ports(_R4T, "allow", addresses=("0.0.0.0",)).deductions
    assert _ports(_R4T, "allow", addresses=("::",)).deductions


def test_a_loopback_listener_is_not_reached():
    assert not _ports(_R10W1, "allow", addresses=("127.0.0.1",)).deductions


def test_the_text_says_why():
    msg = next(f.message for f in _ports(_R4R, "allow").findings if f.key == "ports.uncovered")
    assert "refuse it only in part" in msg
    msg6 = next(f.message for f in _ipv6(_R4R, "allow").findings if f.key == "ipv6.port_no_v6_rule")
    assert "(v6) rules refuse it only in part" in msg6


@pytest.mark.parametrize("rules, v6, rest_open", [
    (_R10W1, False, True), (_R4R, True, True), (_R4T, False, False), (_R4T, True, True),
    (_R4S, False, False), (ALLOW_ALL, True, False),
])
def test_the_walk_per_family(rules, v6, rest_open):
    assert _ufw.rules_leave_rest_open(rules, 8099, "tcp", v6=v6) is rest_open


class TestTheServicesSayFromWhere:
    """0.31.0's limit: an open service read "from any address (Anywhere)"
    even when its rules named one public source."""

    @staticmethod
    def _message(rules):
        import bob.checks.services as S
        from bob.registry import ServiceRegistry
        snap = S.ServiceSnapshot(service=ServiceRegistry.load().get("ssh"), installed=True, install_via="dpkg",
                                 state=S.ServiceState.ACTIVE_ENABLED, ports=["8099/tcp"],
                                 exposures={"8099/tcp": S.Exposure.OPEN_WORLD},
                                 world_sources={"8099/tcp": S._allow_rule_source("8099/tcp", rules)})
        i18n.init("en")
        res = S.check_services([snap], network_context="local", ufw_active=True, t=i18n.t,
                               ufw_incoming_policy="deny")
        return next(f.message for f in res.findings if "8099" in f.message)

    def test_the_sources_named(self):
        msg = self._message(_H)
        assert "203.0.113.5" in msg and "Anywhere" not in msg

    def test_anywhere_kept_when_a_rule_admits_any_address(self):
        assert "(Anywhere)" in self._message(ALLOW_ALL)


def test_the_ipv6_snapshot_fills_it(monkeypatch):
    """The snapshot computes the listeners the check weighs (from `ufw status numbered`)."""
    import bob.checks.ipv6 as v6mod
    monkeypatch.setattr(v6mod, "_run", lambda *a, **k: _R4R if a[:3] == ("ufw", "status", "numbered") else "")
    snap = v6mod.IPv6Snapshot.from_system()
    assert snap.ufw_v6_in_part == [p for p in snap.ufw_v6_covered if p == "8099/tcp"] == ["8099/tcp"]


def test_the_command_refuses():
    f = next(f for f in _ipv6(_R4R, "allow").findings if f.key == "ipv6.port_no_v6_rule")
    assert f.cmd == "sudo ufw deny 8099/tcp"


@pytest.mark.parametrize("name", ["I", "W2"])
def test_rule_order_combinations_at_default_allow(name):
    """Review of the 0.31.2 changelog. I (measured, review3): `deny 8099 from
    <another host>` then `allow 8099` — every other client reached it: a rule
    admits any address, the port is open on purpose (covered, as in 0.31.1).
    W2 (measured, review10): `allow 8099 from <private>` then `deny 8099` — the
    private client kept its access, the public one was refused: the refusal
    from every source closes the rest (covered)."""
    from tests.test_v0310_ufw_broad_rules import _I, _R10W2
    rules = {"I": _I, "W2": _R10W2}[name]
    assert not _ufw.rules_leave_rest_open(rules, 8099, "tcp", v6=False)
    assert not _ufw.rules_leave_rest_open(rules, 8099, "tcp", v6=True)
    assert not _ports(rules, "allow").deductions and not _ipv6(rules, "allow").deductions
