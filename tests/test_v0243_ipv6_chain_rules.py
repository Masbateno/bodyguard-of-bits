"""v0.24.3 — a DROP policy is not "every IPv6 listener is unreachable".

0.24.2 read the IPv6 INPUT chain's default policy and, with UFW active and
IPV6=no, reported the IPv6 listeners as unreachable. A chain policy only
decides the packets that no rule matched: an explicit ACCEPT in the chain —
Docker, libvirt, a hand-written ``ip6tables -A INPUT -p tcp --dport 22 -j
ACCEPT`` — admits traffic the policy would have dropped, and "unreachable" was
then a claim the measurement did not support.

BOB now reads the whole chain and says "blocked" only for the shape ufw-init
leaves behind: policy DROP and, at most, the loopback rule. Any other rule
means BOB has not resolved which listeners the chain admits, and the previous,
cautious verdict stands. Other nftables tables cannot reopen what this chain
drops: a drop in any base chain at a hook is final.
"""

from __future__ import annotations

import pytest

from bob.checks import ipv6 as ipv6_mod
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from tests.helpers import _keys, _t

_LO = "-A INPUT -i lo -j ACCEPT"


def _run(rules, policy="DROP"):
    snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=False,
                        ipv6_listeners=["22/tcp"], has_global_ipv6=True,
                        ufw_present=True, ip6_input_policy=policy,
                        ip6_input_rules=rules)
    return check_ipv6(snap, ufw_active=True, t=_t)


@pytest.mark.parametrize("rules", [[_LO], []])
def test_the_ufw_init_shape_is_blocked(rules):
    assert "ipv6.ufw_v6_off_blocked" in _keys(_run(rules))


@pytest.mark.parametrize("extra", [
    "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
    "-A INPUT -j DOCKER-USER",
    "-A INPUT -s fe80::/10 -j ACCEPT",
])
def test_any_other_rule_withholds_the_claim(extra):
    """The rule may admit a listener; BOB does not resolve which, so it does
    not say "unreachable" — the previous verdict (WARN, global address) stands."""
    result = _run([_LO, extra])
    assert "ipv6.ufw_v6_off_blocked" not in _keys(result)
    assert "ipv6.ufw_disabled_listeners_present" in _keys(result)


def test_unread_rules_withhold_the_claim():
    assert "ipv6.ufw_v6_off_blocked" not in _keys(_run(None))


def test_the_reader_keeps_every_rule(monkeypatch):
    class _R:
        ok = True
        stdout = ("-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n"
                  "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n")
    monkeypatch.setattr(ipv6_mod, "run_result", lambda *a, **k: _R())
    policy, rules = ipv6_mod._read_ip6_input_chain()
    assert policy == "DROP"
    assert rules == [_LO, "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"]


def test_link_local_with_other_rules_is_neither_reachable_nor_blocked():
    """Measured on Mint 22.3 with a link-local
    neighbour: ACCEPT 22 alone left :22 unreachable, ACCEPT 22 plus ICMPv6 both
    ways made it reachable. The chain's other rules decide; BOB says it cannot
    show which, instead of "reachable from the local network"."""
    snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=False,
                        ipv6_listeners=["22/tcp"], has_global_ipv6=False,
                        ufw_present=True, ip6_input_policy="DROP",
                        ip6_input_rules=[_LO, "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"])
    result = check_ipv6(snap, ufw_active=True, t=_t)
    keys = _keys(result)
    assert "ipv6.ufw_v6_off_rules_unresolved" in keys
    assert "ipv6.ufw_disabled_listeners_link_local" not in keys
    assert "ipv6.ufw_v6_off_blocked" not in keys
    assert not result.deductions
