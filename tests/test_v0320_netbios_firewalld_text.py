"""v0.32.0 — a NetBIOS port on a non-UFW host no longer gets the UFW wording.

Measured on Fedora 44 (firewalld, nmbd running beside a stopped smb, fed0314):
137/udp and 138/udp read "listening on all interfaces without explicit UFW
rule" while every other port got "governed by the firewalld zone". With UFW
inactive the dedicated NetBIOS path (a UFW penalty with a `ufw allow` command)
now falls through to the general one, which knows firewalld and a weighed
netfilter ruleset. With UFW active, the NetBIOS penalty is unchanged.
"""

from __future__ import annotations

import pytest

from bob.checks.ports import check_ports
from tests.test_ports import has_level, make_port, make_snapshot, total_deductions


def _snap():
    return make_snapshot(ports=[make_port(port=137, proto="udp", address="0.0.0.0")], ufw_rules="")


def _keys(result):
    return {f.key for f in result.findings}


def test_firewalld_gets_the_firewalld_text():
    result = check_ports(_snap(), ufw_active=False, firewalld_active=True)
    assert "ports.uncovered_firewalld" in _keys(result)
    assert "ports.uncovered" not in _keys(result) and total_deductions(result) == 0


def test_a_weighed_netfilter_ruleset_gets_its_text():
    result = check_ports(_snap(), ufw_active=False, netfilter_active=True)
    assert "ports.uncovered_netfilter" in _keys(result)
    assert "ports.uncovered" not in _keys(result)


def test_no_front_end_keeps_the_plain_info():
    result = check_ports(_snap(), ufw_active=False)
    assert has_level(result, "info") and not has_level(result, "warn")
    assert total_deductions(result) == 0


def test_with_ufw_the_penalty_is_unchanged():
    result = check_ports(_snap(), ufw_active=True)
    assert "ports.uncovered_netbios" in {d.key for d in result.deductions}
