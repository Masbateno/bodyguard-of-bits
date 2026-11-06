"""v0.31.0 — an IPv6 listener without a UFW (v6) rule of its own, at default deny.

Measured on Ubuntu 26.04 (6 November 2026, phase B, `phaseB/ufw-L1-probe.txt`):
UFW active, IPV6=yes, default deny incoming. From a network namespace on the
host joined by a veth pair, 22 (allowed) was open over IPv4 and IPv6 and the
nine other listeners were dropped over both. BOB warned −1 each (three
counted) that they listened "without a UFW (v6) rule" and offered
`sudo ufw allow <port>`, which would have opened them — the kubelet (10250),
the API server (16443) and Samba (139, 445) among them. A listener without a
rule of its own, at default deny or reject, is covered by that default.
"""

from __future__ import annotations

import inspect

import pytest

from bob import runner
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from tests.helpers import _t

NINE = ["10250/tcp", "10257/tcp", "10259/tcp", "139/tcp", "16443/tcp", "25000/tcp", "445/tcp", "80/tcp", "9090/tcp"]


def _snap(listeners=NINE + ["22/tcp"], covered=("22/tcp",)):
    return IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=True, ipv6_listeners=list(listeners),
                        ufw_v6_covered=list(covered), has_global_ipv6=True, ufw_present=True)


def _keys(result):
    return [f.key for f in result.findings]


@pytest.mark.parametrize("policy", ["deny", "reject"])
def test_covered_by_the_default(policy):
    result = check_ipv6(_snap(), ufw_active=True, t=_t, ufw_incoming_policy=policy)
    assert "ipv6.port_no_v6_rule" not in _keys(result)
    assert not [d for d in result.deductions if d.key == "ipv6.port_no_v6_rule"]
    info = next(f for f in result.findings if f.key == "ipv6.ports_default_deny")
    assert not info.cmd
    assert "ipv6.all_ports_covered" not in _keys(result)


@pytest.mark.parametrize("policy", ["allow", "unknown"])
def test_not_covered_by_the_default(policy):
    result = check_ipv6(_snap(), ufw_active=True, t=_t, ufw_incoming_policy=policy)
    warns = [f for f in result.findings if f.key == "ipv6.port_no_v6_rule"]
    assert len(warns) == 9
    assert all(f.cmd.startswith("sudo ufw deny ") for f in warns)
    assert "ipv6.ports_default_deny" not in _keys(result)


def test_the_command_never_opens_the_port():
    result = check_ipv6(_snap(["9090/tcp"], ()), ufw_active=True, t=_t)
    assert [f.cmd for f in result.findings if f.key == "ipv6.port_no_v6_rule"] == ["sudo ufw deny 9090/tcp"]


def test_all_covered_by_rules_still_said():
    result = check_ipv6(_snap(["22/tcp"], ("22/tcp",)), ufw_active=True, t=_t, ufw_incoming_policy="deny")
    assert "ipv6.all_ports_covered" in _keys(result) and "ipv6.ports_default_deny" not in _keys(result)


def test_the_runner_passes_ufw_s_policy():
    assert "ufw_incoming_policy=fw_status.incoming_policy" in inspect.getsource(runner)
