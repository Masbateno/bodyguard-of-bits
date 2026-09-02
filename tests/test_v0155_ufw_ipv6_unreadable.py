"""
v0.15.5 — an unreadable /etc/default/ufw was read as "UFW manages IPv6".

Found by masking existing files one at a time so that reading them raises
PermissionError, then re-reading the audit for verdicts that survived. On this
host the file says ``IPV6=no``; losing the read invented ``True`` and every
uncovered IPv6 listener became ``ipv6.port_no_v6_rule`` — a warning with a
deduction for rules missing from a firewall the operator had deliberately told
not to manage IPv6.

The distinction the readers were missing is not absent-versus-present, it is
**absent versus unreadable**. An absent file is a real state: ufw's own default
is IPv6 on, so answering True there is a measurement. An unreadable one is no
answer at all. ``_read_kernel_ipv6`` in this same module already drew that line
— its comment says so — and the ufw branch never received it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import bob.checks.firewall as fw
import bob.checks.ipv6 as ipv6mod
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6


def _keys(result) -> set[str]:
    return {f.key for f in result.findings}


def _deducted(result) -> set[str]:
    return {d.key for d in getattr(result, "deductions", [])}


class TestTheReaderTellsAbsentFromUnreadable:
    """Both modules read /etc/default/ufw; both had the same conflation."""

    @pytest.mark.parametrize("reader", [
        pytest.param(lambda: ipv6mod._read_ufw_ipv6(), id="ipv6"),
        pytest.param(lambda: fw._read_ipv6_config(), id="firewall"),
    ])
    def test_an_absent_file_is_ufws_own_default(self, reader, monkeypatch, tmp_path):
        missing = tmp_path / "nothing-here"

        def _raise(*a, **k):
            raise FileNotFoundError(2, "No such file or directory", str(missing))

        monkeypatch.setattr(Path, "read_text", _raise)
        assert reader() is True

    @pytest.mark.parametrize("reader", [
        pytest.param(lambda: ipv6mod._read_ufw_ipv6(), id="ipv6"),
        pytest.param(lambda: fw._read_ipv6_config(), id="firewall"),
    ])
    def test_an_unreadable_file_is_not_an_answer(self, reader, monkeypatch):
        def _raise(*a, **k):
            raise PermissionError(13, "Permission denied", "/etc/default/ufw")

        monkeypatch.setattr(Path, "read_text", _raise)
        assert reader() is None

    @pytest.mark.parametrize("reader", [
        pytest.param(lambda: ipv6mod._read_ufw_ipv6(), id="ipv6"),
        pytest.param(lambda: fw._read_ipv6_config(), id="firewall"),
    ])
    def test_an_explicit_no_is_still_read(self, reader, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda *a, **k: "IPV6=no\n")
        assert reader() is False


class TestAnUnreadPolicyCostsNothing:
    """The deduction, and the claim of agreement, both have to go."""

    def _snap(self, ufw_ipv6):
        return IPv6Snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=ufw_ipv6,
            ipv6_listeners=["22/tcp", "80/tcp"],
            ufw_v6_covered=[],
            has_global_ipv6=True,
        )

    def test_unknown_deducts_nothing_and_says_why(self):
        result = check_ipv6(self._snap(None), ufw_active=True)
        assert "ipv6.port_no_v6_rule" not in _deducted(result)
        assert "ipv6.ufw_config_unreadable" in _keys(result)

    def test_unknown_does_not_claim_the_two_sides_agree(self):
        """Falling through to the final `else` asserted they were in sync."""
        result = check_ipv6(self._snap(None), ufw_active=True)
        assert "ipv6.config_ok" not in _keys(result)

    def test_unknown_is_not_read_as_ufw_declining_ipv6(self):
        """`not None` is True: the 2-point branch fired on an unknown."""
        result = check_ipv6(self._snap(None), ufw_active=True)
        assert "ipv6.ufw_disabled_listeners_present" not in _deducted(result)

    def test_unknown_does_not_certify_coverage_either(self):
        """
        The closing OK sits outside the branch chain, so heading that chain was
        not enough: the audit still printed "all listeners are covered" against
        a ruleset whose policy had never been read.
        """
        covered = IPv6Snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=None,
            ipv6_listeners=["22/tcp"],
            ufw_v6_covered=["22/tcp"],
            has_global_ipv6=True,
        )
        assert "ipv6.all_ports_covered" not in _keys(check_ipv6(covered, ufw_active=True))

    def test_a_read_policy_still_certifies_coverage(self):
        covered = IPv6Snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=True,
            ipv6_listeners=["22/tcp"],
            ufw_v6_covered=["22/tcp"],
            has_global_ipv6=True,
        )
        assert "ipv6.all_ports_covered" in _keys(check_ipv6(covered, ufw_active=True))

    def test_the_polarity_twin_still_warns(self):
        """A policy that WAS read, and does manage IPv6, still reports gaps."""
        result = check_ipv6(self._snap(True), ufw_active=True)
        assert "ipv6.port_no_v6_rule" in _deducted(result)

    def test_an_explicit_no_still_reaches_its_own_branch(self):
        result = check_ipv6(self._snap(False), ufw_active=True)
        assert "ipv6.ufw_config_unreadable" not in _keys(result)
