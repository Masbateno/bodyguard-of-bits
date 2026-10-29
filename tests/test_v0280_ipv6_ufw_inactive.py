"""v0.28.0 — IPv6 with UFW installed but not active is read from the host's ruleset.

UFW installed and not running filters nothing, yet the IPv6 section judged by
its configuration: with IPV6=no, "UFW is not configured for IPv6"; with
IPV6=yes, "config OK" and −1 per listener for a missing UFW v6 rule. Measured
in a network namespace on a host with UFW installed (/etc/default/ufw at
IPV6=no, UFW not running there), a listener on [::]:8099 and a global
documentation address, 25 October 2026:

* no ruleset — "no UFW on this host and no other firewall" (UFW was there);
* an inet chain at policy drop — read "denies IPv6 inbound by default";
* policy accept with a drop for 8099 — read "not established", a ceiling;
* policy accept with nothing refusing — no firewall filters them.

The section now reads the raw ruleset whenever UFW is not active, installed or
not, and says when UFW is installed but not running.
"""

from __future__ import annotations

import inspect

import pytest

from bob import i18n
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6


def _snap(**kw):
    base = dict(kernel_ipv6_enabled=True, ufw_present=True, ufw_ipv6_enabled=False,
                ipv6_listeners=["8099/tcp"], has_global_ipv6=True)
    base.update(kw)
    return IPv6Snapshot(**base)


def _keys(res):
    return {f.key for f in res.findings}


class TestTheMeasuredCases:

    def test_u1_no_ruleset(self):
        res = check_ipv6(_snap(), ufw_active=False, t=lambda k, **kw: k)
        assert "ipv6.no_firewall_v6" in _keys(res) and not res.deductions

    def test_u2_policy_drop(self):
        res = check_ipv6(_snap(), ufw_active=False, netfilter_active=True,
                         netfilter_v6_policy="DROP", t=lambda k, **kw: k)
        assert "ipv6.netfilter_v6_filtered" in _keys(res)

    def test_u3_accept_with_refusals(self):
        res = check_ipv6(_snap(), ufw_active=False, netfilter_active=True,
                         netfilter_v6_policy="PARTIAL", t=lambda k, **kw: k)
        assert "ipv6.netfilter_v6" in _keys(res) and not res.deductions

    @pytest.mark.parametrize("ipv6_on", [True, False])
    def test_ufws_own_setting_no_longer_decides(self, ipv6_on):
        res = check_ipv6(_snap(ufw_ipv6_enabled=ipv6_on), ufw_active=False, t=lambda k, **kw: k)
        assert not ({"ipv6.port_no_v6_rule", "ipv6.config_ok", "ipv6.ufw_disabled_listeners_present"}
                    & _keys(res))
        assert not res.deductions

    def test_ufw_active_is_unchanged(self):
        res = check_ipv6(_snap(), ufw_active=True, t=lambda k, **kw: k)
        assert "ipv6.ufw_disabled_listeners_present" in _keys(res)


class TestItIsSaid:

    @pytest.mark.parametrize("lang, words", [("en", "UFW is installed but not active"),
                                             ("fr", "UFW est installé mais pas actif")])
    def test_ufw_installed_not_active(self, lang, words):
        i18n.init(lang)
        try:
            with_listener = check_ipv6(_snap(), ufw_active=False, t=i18n.t)
            no_listener = check_ipv6(_snap(ipv6_listeners=[]), ufw_active=False, t=i18n.t)
        finally:
            i18n.init(lang="en")
        assert any(words in f.message for f in with_listener.findings)
        assert any(words in f.message for f in no_listener.findings)

    def test_no_ufw_at_all_keeps_its_text(self):
        i18n.init("en")
        try:
            res = check_ipv6(_snap(ufw_present=False), ufw_active=False, t=i18n.t)
        finally:
            i18n.init(lang="en")
        assert any("no UFW on this host" in f.message for f in res.findings)


def test_the_runner_reads_the_ruleset_when_ufw_is_not_active():
    from bob import runner
    src = inspect.getsource(runner)
    assert 'not (ipv6_snapshot.ufw_present and fw_status.active)' in src
