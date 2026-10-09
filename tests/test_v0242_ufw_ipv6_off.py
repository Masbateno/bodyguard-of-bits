"""v0.24.2 — UFW with IPV6=no blocks IPv6; it does not leave it open.

The IPv6 section treated ``IPV6=no`` as "UFW does not manage IPv6", and so
reported the IPv6 listeners as exposed: a WARN −2 on a host with a global
address ("services listening on IPv6 but UFW IPv6 is disabled"), and — the
0.24.1 wording — "reachable from the local network without UFW filtering" on a
link-local-only one.

Measured on a real Linux Mint 22.3 (ufw 0.36.2), with a link-local neighbour
in a network namespace joined to the host by a veth pair: UFW active +
IPV6=no → the IPv6 INPUT policy is DROP and sshd on ``[::]:22`` does not
answer; UFW inactive, same settings → policy ACCEPT and sshd answers. The
reason is in ufw itself (``/lib/ufw/ufw-init-functions``): with IPV6=no and a
working ip6tables, ufw-init installs DROP on INPUT, FORWARD and OUTPUT, loopback
excepted.

BOB does not infer the DROP from IPV6=no: it reads the IPv6 INPUT policy, and
only a DROP read while UFW is active becomes "blocked". A policy it could not
read keeps the previous verdict — unknown is not safe.
"""

from __future__ import annotations

import pytest

from bob.checks import ipv6 as ipv6_mod
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from bob.scoring import FindingLevel
from tests.helpers import _keys, _t


_UFW_INIT_RULES = ["-A INPUT -i lo -j ACCEPT"]


def _snap(policy, global_v6=True, rules=_UFW_INIT_RULES):
    return IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=False,
                        ipv6_listeners=["22/tcp"], has_global_ipv6=global_v6,
                        ufw_present=True, ip6_input_policy=policy,
                        ip6_input_rules=None if policy is None else rules)


@pytest.mark.parametrize("global_v6", [True, False])
def test_ufw_active_and_drop_is_blocked_not_exposed(global_v6):
    result = check_ipv6(_snap("DROP", global_v6), ufw_active=True, t=_t)
    keys = _keys(result)
    assert "ipv6.ufw_v6_off_blocked" in keys
    assert "ipv6.ufw_disabled_listeners_present" not in keys
    assert "ipv6.ufw_disabled_listeners_link_local" not in keys
    assert not result.deductions
    finding = next(f for f in result.findings if f.key == "ipv6.ufw_v6_off_blocked")
    assert finding.level == FindingLevel.INFO


def test_an_accept_policy_keeps_the_exposure_warning():
    """ip6tables unavailable when UFW started: IPv6 really is unfiltered."""
    result = check_ipv6(_snap("ACCEPT"), ufw_active=True, t=_t)
    assert "ipv6.ufw_disabled_listeners_present" in _keys(result)
    assert [d.points for d in result.deductions] == [2]


def test_an_unread_policy_is_not_taken_for_drop():
    result = check_ipv6(_snap(None), ufw_active=True, t=_t)
    assert "ipv6.ufw_v6_off_blocked" not in _keys(result)
    assert "ipv6.ufw_disabled_listeners_present" in _keys(result)


def test_a_drop_with_ufw_inactive_is_not_credited_to_ufw():
    """ufw-init only runs when UFW is active; a DROP then comes from elsewhere,
    and "UFW drops all IPv6" would name the wrong cause."""
    result = check_ipv6(_snap("DROP"), ufw_active=False, t=_t)
    assert "ipv6.ufw_v6_off_blocked" not in _keys(result)


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_rendered_message_says_blocked(lang):
    from bob import i18n
    i18n.init(lang)
    try:
        result = check_ipv6(_snap("DROP"), ufw_active=True, t=i18n.t)
    finally:
        i18n.init(lang="en")
    finding = next(f for f in result.findings if f.key == "ipv6.ufw_v6_off_blocked")
    assert "IPV6=no" in finding.message and "22/tcp" in finding.detail


class TestPolicyRead:
    class _R:
        def __init__(self, ok, stdout=""):
            self.ok, self.stdout = ok, stdout

    def test_reads_the_policy_line(self, monkeypatch):
        monkeypatch.setattr(ipv6_mod, "run_result", lambda *a, **k: self._R(
            True, "-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n"))
        assert ipv6_mod._read_ip6_input_chain() == ("DROP", ["-A INPUT -i lo -j ACCEPT"])

    def test_a_failed_read_is_none(self, monkeypatch):
        monkeypatch.setattr(ipv6_mod, "run_result", lambda *a, **k: self._R(False))
        assert ipv6_mod._read_ip6_input_chain() == (None, None)

    def test_read_only_when_ufw_ipv6_is_off(self, monkeypatch):
        calls = []
        monkeypatch.setattr(ipv6_mod, "_read_ip6_input_chain",
                            lambda: calls.append(1) or ("DROP", []))
        monkeypatch.setattr(ipv6_mod, "_read_kernel_ipv6", lambda: (True, True))
        monkeypatch.setattr(ipv6_mod, "_read_global_ipv6", lambda: False)
        monkeypatch.setattr(ipv6_mod, "run_result", lambda *a, **k: self._R(True, ""))
        monkeypatch.setattr(ipv6_mod, "_run", lambda *a, **k: "")
        monkeypatch.setattr(ipv6_mod._ufw, "read_app_profiles", lambda: {})
        monkeypatch.setattr(ipv6_mod, "_read_ufw_ipv6", lambda: True)
        assert IPv6Snapshot.from_system().ip6_input_policy is None
        monkeypatch.setattr(ipv6_mod, "_read_ufw_ipv6", lambda: False)
        assert IPv6Snapshot.from_system().ip6_input_policy == "DROP"
        assert calls == [1]
