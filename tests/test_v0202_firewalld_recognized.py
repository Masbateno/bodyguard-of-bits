"""firewalld is a firewall, not the absence of one.

Before v0.20.2 BOB was 100 % UFW-centric. On a real Fedora 44 server it read
firewalld's ACCEPT base policy as "wide open", alerted "UFW not installed",
framed firewalld's own nft table as "nftables in parallel with UFW", warned
every IPv6 listener as "no UFW v6 rule" and told the operator to "enable UFW"
for exposed ports — while the host was in fact firewalled. These guards pin the
recognition of firewalld across every sink that used to lie, each with its
polarity twin so the credit is conditional on firewalld actually being active.

The oracle is a real Fedora 44 host (192.168.1.16): before, risk ÉLEVÉ and the
false positives above; after, risk MOYEN and firewalld credited by name.
"""

from __future__ import annotations

from bob.checks._firewalld import FirewalldStatus
from bob.checks.firewall import FirewallStatus, check_firewall
from bob.checks.iptables_nftables import IptablesNftSnapshot, check_iptables_nftables
from bob.checks.firewall_stack import _has_user_nft_rules
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
from bob.checks.services import Exposure, _check_port_exposure
from bob.output import print_banner
from bob.scoring import CheckResult
from tests.helpers import _keys, _levels, _t


def _echo_t(key: str, **kwargs) -> str:
    """Translation stub that keeps the kwargs, so a nested exposure key shows."""
    if kwargs:
        return f"{key}:" + ",".join(str(v) for v in kwargs.values())
    return key


def _active_firewalld() -> FirewalldStatus:
    return FirewalldStatus(active=True, default_zone="FedoraServer",
                           services=["ssh", "cockpit"], ports=[], readable=True)


# ---------------------------------------------------------------------------
# firewall.py — "UFW not installed" is not an alert when firewalld is the front-end
# ---------------------------------------------------------------------------

class TestFirewallCheck:
    def _status(self) -> FirewallStatus:
        return FirewallStatus(installed=False, active=False,
                              incoming_policy="unknown", ufw_output="",
                              numbered_output="", ipv6_ufw_enabled=False)

    def test_firewalld_active_credits_instead_of_alerting(self):
        result = check_firewall(self._status(), firewalld=_active_firewalld(), t=_t)
        assert "firewall.firewalld_active" in _keys(result)
        assert "alert" not in _levels(result)

    def test_without_firewalld_ufw_missing_still_alerts(self):
        result = check_firewall(self._status(), firewalld=None, t=_t)
        assert "firewall.firewalld_active" not in _keys(result)
        assert "alert" in _levels(result)


# ---------------------------------------------------------------------------
# iptables_nftables.py — an ACCEPT base policy is not "wide open" under firewalld
# ---------------------------------------------------------------------------

class TestIptablesCheck:
    def _snap(self) -> IptablesNftSnapshot:
        # ACCEPT base policy with no loopback/conntrack rules — the shape that
        # otherwise reads as an unfiltered host.
        return IptablesNftSnapshot(
            backend="nftables", input_policy="ACCEPT", forward_policy="ACCEPT",
            has_loopback_rule=False, has_conntrack_rule=False, raw_output="",
        )

    def test_firewalld_active_credits_and_returns(self):
        result = check_iptables_nftables(self._snap(), firewalld=_active_firewalld(), t=_t)
        assert "firewall_iptables.firewalld_active" in _keys(result)
        assert "alert" not in _levels(result)
        assert "warn" not in _levels(result)

    def test_without_firewalld_accept_policy_is_flagged(self):
        result = check_iptables_nftables(self._snap(), firewalld=None, t=_t)
        assert "firewall_iptables.firewalld_active" not in _keys(result)
        # The raw ACCEPT policy produces a negative finding of some kind.
        assert any(lvl in _levels(result) for lvl in ("warn", "alert"))


# ---------------------------------------------------------------------------
# firewall_stack.py — firewalld's own nft table is the firewall, not a parallel one
# ---------------------------------------------------------------------------

class TestNftTableAttribution:
    def test_firewalld_table_is_not_a_parallel_ruleset(self):
        assert _has_user_nft_rules("table inet firewalld {\n}") is False

    def test_a_genuinely_foreign_table_still_counts(self):
        assert _has_user_nft_rules("table inet myrouter {\n}") is True


# ---------------------------------------------------------------------------
# ipv6.py — a missing UFW v6 rule is not a gap when firewalld filters v6
# ---------------------------------------------------------------------------

class TestIPv6Coverage:
    def _snap(self) -> IPv6Snapshot:
        return IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=True,
                            ipv6_listeners=["22/tcp"], ufw_v6_covered=[])

    def test_firewalld_active_no_v6_gap_warning(self):
        result = check_ipv6(self._snap(), ufw_active=False,
                            firewalld_active=True, t=_t)
        assert "ipv6.firewalld_v6" in _keys(result)
        assert "ipv6.port_no_v6_rule" not in _keys(result)
        assert result.deductions == []

    def test_without_firewalld_the_v6_gap_is_reported(self):
        result = check_ipv6(self._snap(), ufw_active=True,
                            firewalld_active=False, t=_t)
        assert "ipv6.firewalld_v6" not in _keys(result)
        assert "ipv6.port_no_v6_rule" in _keys(result)


# ---------------------------------------------------------------------------
# ports.py — "enable UFW" contradicts crediting firewalld
# ---------------------------------------------------------------------------

class TestPortsAdvice:
    def _snap(self) -> PortsSnapshot:
        # A public, uncovered, non-service listener on all interfaces.
        lp = ListeningPort(port=8080, proto="tcp", address="0.0.0.0", raw_line="")
        return PortsSnapshot(ports=[lp], ufw_rules="", ss_output="")

    def test_firewalld_active_reframes_the_advice(self):
        result = check_ports(self._snap(), ufw_active=False,
                             firewalld_active=True, t=_t)
        assert "ports.uncovered_firewalld" in _keys(result)
        assert "ports.uncovered_ufw_inactive" not in _keys(result)

    def test_without_firewalld_the_ufw_advice_stands(self):
        result = check_ports(self._snap(), ufw_active=False,
                             firewalld_active=False, t=_t)
        assert "ports.uncovered_firewalld" not in _keys(result)
        assert "ports.uncovered_ufw_inactive" in _keys(result)


# ---------------------------------------------------------------------------
# services.py — per-port exposure names firewalld, not "UFW inactive"
# ---------------------------------------------------------------------------

class TestServiceExposure:
    def test_firewalld_active_uses_firewalld_exposure_key(self):
        result = CheckResult()
        _check_port_exposure(None, "22/tcp", Exposure.NO_RULE, result,
                             "local", False, _echo_t, firewalld_active=True)
        msg = result.findings[0].message
        assert "no_rule_firewalld" in msg
        assert "no_rule_ufw_inactive" not in msg

    def test_without_firewalld_uses_ufw_inactive_key(self):
        result = CheckResult()
        _check_port_exposure(None, "22/tcp", Exposure.NO_RULE, result,
                             "local", False, _echo_t, firewalld_active=False)
        msg = result.findings[0].message
        assert "no_rule_ufw_inactive" in msg
        assert "no_rule_firewalld" not in msg


# ---------------------------------------------------------------------------
# banner — the header names every distro's firewall front-end and init manager,
# not just Debian's UFW + systemd
# ---------------------------------------------------------------------------

class TestHeadlineBanner:
    def _render(self, capsys, **over) -> str:
        kwargs = dict(
            version="v0.20.2", subtitle="", system="Fedora Linux 44",
            host="h", kernel="6.19", ufw_version="non installé",
            iptables="1.8.11", nftables="1.1.6", user="root", date="",
            labels={}, firewalld="v2.4.0", init_system="systemd 259",
        )
        kwargs.update(over)
        print_banner(**kwargs)
        return capsys.readouterr().out

    def test_firewalld_row_is_shown(self, capsys):
        out = self._render(capsys)
        assert "firewalld" in out
        assert "v2.4.0" in out

    def test_init_row_is_shown(self, capsys):
        out = self._render(capsys)
        assert "systemd 259" in out

    def test_openrc_host_shows_its_init(self, capsys):
        # Alpine: OpenRC, no firewalld — the banner must not hard-code systemd.
        out = self._render(capsys, init_system="OpenRC", firewalld="non installé")
        assert "OpenRC" in out
