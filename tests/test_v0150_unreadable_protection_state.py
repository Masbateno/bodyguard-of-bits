"""
v0.15.0 — two more protections reported as absent because they could not be read.

Both were found by widening the `auditd`/`fail2ban` sweep, and both are
demonstrable on the development host rather than hypothetical.

**AppArmor.** `aa-status` succeeds *partially* without the privilege to read the
profile set: it prints `apparmor module is loaded.` on stdout, then exits 4 with
the explanation on stderr. BOB read the module line — correctly — and parsed the
profile counters from the same truncated output, getting 0. This host carries
**120 profiles in enforce mode** and was told it had none, with a WARN and a
point. A reachable profile set always yields a count line (`%zd profiles are
loaded.` is in the binary), so its absence is the discriminator.

**Firewall ruleset.** `iptables -S` writes "Permission denied (you must be
root)" to stderr and leaves stdout empty, so the snapshot fell through to
`backend="none"` — `firewall_iptables.no_backend`, a WARN with a **3-point**
deduction, the largest in the check. A working `iptables -S` always prints its
policy lines, even on a host with no rules at all, so an empty result from an
installed binary means the query was refused.

Neither is a wrong threshold or a bad pattern. Both are a partial or refused
read presented as a complete one.
"""

from __future__ import annotations

import pytest

import bob.checks.mac_policy as mac
from bob.checks.iptables_nftables import (
    IptablesNftSnapshot,
    check_iptables_nftables,
)
from bob.checks.mac_policy import MacPolicySnapshot, check_mac_policy


def _summary(result):
    return ({f.key for f in result.findings},
            sum(d.points for d in result.deductions))


def _ipt(**kw):
    base = dict(backend="none", input_policy="unknown", forward_policy="unknown",
                has_loopback_rule=False, has_conntrack_rule=False)
    base.update(kw)
    return IptablesNftSnapshot(**base)


class TestAppArmor:
    def test_an_unreadable_profile_set_is_not_an_empty_one(self):
        keys, points = _summary(check_mac_policy(MacPolicySnapshot(
            apparmor_installed=True, apparmor_active=True,
            apparmor_profiles_readable=False)))
        assert "mac_policy.apparmor_profiles_unreadable" in keys
        assert "mac_policy.apparmor_no_profiles" not in keys
        assert points == 0

    def test_a_readable_but_empty_profile_set_still_warns(self):
        keys, points = _summary(check_mac_policy(MacPolicySnapshot(
            apparmor_installed=True, apparmor_active=True,
            apparmor_profiles_readable=True)))
        assert "mac_policy.apparmor_no_profiles" in keys
        assert points >= 1

    def test_a_protected_host_is_unaffected(self):
        keys, points = _summary(check_mac_policy(MacPolicySnapshot(
            apparmor_installed=True, apparmor_active=True,
            apparmor_enforcing=120, apparmor_profiles_readable=True)))
        assert "mac_policy.apparmor_ok" in keys
        assert points == 0

    @pytest.mark.parametrize("output,expected", [
        ("apparmor module is loaded.\n", False),                  # the real truncated case
        ("apparmor module is loaded.\n120 profiles are loaded.\n"
         "120 profiles are in enforce mode.\n", True),
        ("apparmor module is loaded.\n0 profiles are loaded.\n", True),
    ])
    def test_the_readability_signal(self, output, expected, monkeypatch):
        monkeypatch.setattr(mac, "_command_exists", lambda n: n == "aa-status")
        monkeypatch.setattr(mac, "_run", lambda *a, **k: output)
        snap = MacPolicySnapshot.from_system()
        assert snap.apparmor_active is True
        assert snap.apparmor_profiles_readable is expected


class TestFirewallRuleset:
    def test_a_refused_query_is_not_an_absent_backend(self):
        keys, points = _summary(
            check_iptables_nftables(_ipt(query_failed=True), ufw_installed=True))
        assert "firewall_iptables.ruleset_unreadable" in keys
        assert "firewall_iptables.no_backend" not in keys
        assert points == 0, "deducted 3 points for a ruleset it never read"

    def test_a_genuinely_absent_backend_still_costs_its_points(self):
        keys, points = _summary(
            check_iptables_nftables(_ipt(query_failed=False), ufw_installed=True))
        assert "firewall_iptables.no_backend" in keys
        assert points == 3

    def test_a_readable_backend_is_unaffected(self):
        keys, _ = _summary(check_iptables_nftables(
            _ipt(backend="iptables", input_policy="DROP", forward_policy="DROP",
                 has_loopback_rule=True, has_conntrack_rule=True),
            ufw_installed=True))
        assert "firewall_iptables.ruleset_unreadable" not in keys
        assert "firewall_iptables.no_backend" not in keys

    def test_the_signal_needs_an_installed_binary(self, monkeypatch):
        """No binary at all is a real absence, and must stay one."""
        import bob.checks.iptables_nftables as m
        monkeypatch.setattr(m, "_command_exists", lambda n: False)
        assert IptablesNftSnapshot.from_system().query_failed is False

    def test_an_installed_binary_with_no_output_flags_the_failure(self, monkeypatch):
        import bob.checks.iptables_nftables as m
        monkeypatch.setattr(m, "_command_exists", lambda n: True)
        monkeypatch.setattr(m, "_run", lambda *a, **k: "")
        snap = IptablesNftSnapshot.from_system()
        assert snap.backend == "none" and snap.query_failed is True
