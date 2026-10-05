"""v0.24.1 — one firewall posture for every summary, whatever filters the host.

The firewall section learnt firewalld (0.20.2) and a raw nftables/iptables
ruleset (0.23.0); the summaries built after it kept reading UFW's own state.
Reproduced with the real functions fed as the runner fed them:

  - firewalld active → attack surface "default policy is ALLOW — no filtering"
    (BOB had never read firewalld's default, and printed "unknown" as ALLOW);
  - nftables-only, inbound DROP → "No active firewall — all ports unfiltered"
    and the risk level floored at HIGH, while the firewall section itself said
    "netfilter layer is filtering inbound traffic";
  - Ubuntu ships ufw installed and inactive: a host protected by firewalld or
    by its own ruleset was alerted "UFW inactive" and capped at 3/10.
"""

from __future__ import annotations

import inspect

import bob.checks._firewalld as fw
import bob.runner as runner
from bob.checks._firewalld import FirewalldStatus
from bob.checks.firewall import (
    FirewallPosture,
    FirewallStatus,
    check_firewall,
    resolve_firewall_posture,
)
from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
from bob.checks.services import Exposure, _check_port_exposure
from bob.exposure import compute_exposure
from bob.scoring import CheckResult, ScoreEngine, set_posture_from_engine
from tests.helpers import _keys, _t


def _echo_t(key: str, **kwargs) -> str:
    return key


def _kw_t(key: str, **kwargs) -> str:
    return " ".join([key, *map(str, kwargs.values())])


def _ufw(installed: bool, active: bool, policy: str = "unknown") -> FirewallStatus:
    return FirewallStatus(installed=installed, active=active, incoming_policy=policy,
                          ufw_output="", numbered_output="", ipv6_ufw_enabled=False)


def _firewalld(target: str = "default") -> FirewalldStatus:
    return FirewalldStatus(active=True, default_zone="public", services=["ssh"],
                           target=target)


# ---------------------------------------------------------------------------
# firewalld's runtime target is read, and mapped — never guessed
# ---------------------------------------------------------------------------

class TestFirewalldTarget:
    def test_target_read_from_list_all(self, monkeypatch):
        class _R:
            def __init__(self, stdout):
                self.stdout, self.ok = stdout, True
        out = {"--state": "running", "--get-default-zone": "FedoraServer",
               "--list-all": "FedoraServer (default, active)\n  target: default\n"
                             "  ingress-priority: 0\n  services: ssh cockpit\n"}
        monkeypatch.setattr(fw, "_command_exists", lambda _c: True)
        monkeypatch.setattr(fw, "run_result", lambda _c, *a: _R(out.get(a[-1], "")))
        st = FirewalldStatus.from_system()
        assert st.target == "default"
        assert st.incoming_policy == "reject"

    def test_target_mapping(self):
        assert _firewalld("default").incoming_policy == "reject"
        assert _firewalld("%%REJECT%%").incoming_policy == "reject"
        assert _firewalld("DROP").incoming_policy == "deny"
        assert _firewalld("ACCEPT").incoming_policy == "allow"

    def test_unread_target_is_unknown_not_reject(self):
        assert _firewalld("").incoming_policy == "unknown"


# ---------------------------------------------------------------------------
# resolve_firewall_posture
# ---------------------------------------------------------------------------

class TestResolvePosture:
    def test_ufw_active(self):
        assert resolve_firewall_posture(_ufw(True, True, "deny")) == FirewallPosture("ufw", "deny")

    def test_firewalld_with_ufw_installed_but_inactive(self):
        p = resolve_firewall_posture(_ufw(True, False), _firewalld("default"))
        assert p == FirewallPosture("firewalld", "reject") and p.active

    def test_netfilter_drop(self):
        p = resolve_firewall_posture(_ufw(True, False), FirewalldStatus(), "DROP")
        assert p == FirewallPosture("netfilter", "deny") and p.active

    def test_netfilter_reject(self):
        p = resolve_firewall_posture(_ufw(False, False), None, "REJECT")
        assert p == FirewallPosture("netfilter", "reject")

    def test_nothing_filters(self):
        p = resolve_firewall_posture(_ufw(True, False), FirewalldStatus(), None)
        assert p == FirewallPosture() and not p.active


# ---------------------------------------------------------------------------
# check_firewall — ufw installed but inactive is Ubuntu's default state
# ---------------------------------------------------------------------------

class TestUbuntuDefaultUfwInactive:
    def test_firewalld_credited_not_capped(self):
        result = check_firewall(_ufw(True, False), firewalld=_firewalld(), t=_t)
        assert "firewall.firewalld_active" in _keys(result)
        assert "firewall.inactive" not in _keys(result)
        assert result.caps == []

    def test_netfilter_ruleset_credited_not_capped(self):
        result = check_firewall(_ufw(True, False), firewalld=FirewalldStatus(),
                                netfilter_protective=True, t=_t)
        assert "firewall.netfilter_active" in _keys(result)
        assert "firewall.inactive" not in _keys(result)
        assert result.caps == []

    def test_nothing_else_still_alerts_and_caps(self):
        result = check_firewall(_ufw(True, False), firewalld=FirewalldStatus(),
                                netfilter_protective=False, t=_t)
        assert "firewall.inactive" in _keys(result)
        assert result.caps


# ---------------------------------------------------------------------------
# Attack-surface line
# ---------------------------------------------------------------------------

def _exposure_fw(fw_active, fw_policy, backend):
    ps = PortsSnapshot(ports=[], ufw_rules="", ss_output="")

    class _NC:
        def __getattr__(self, _a):
            return None
    items = compute_exposure(ScoreEngine(), ps, _NC(), fw_active, fw_policy, _echo_t,
                             fw_backend=backend)
    return next(i for i in items if i.label == "exposure.firewall")


class TestAttackSurfaceLine:
    def test_firewalld_reject_is_ok_and_named(self):
        item = _exposure_fw(True, "reject", "firewalld")
        assert item.icon == "✔"
        assert item.detail == "exposure.firewall_policy_backend"

    def test_netfilter_deny_is_ok(self):
        item = _exposure_fw(True, "deny", "netfilter")
        assert item.icon == "✔"

    def test_ufw_keeps_its_line(self):
        assert _exposure_fw(True, "deny", "ufw").detail == "exposure.firewall_policy"

    def test_firewalld_trusted_zone_is_allow_all(self):
        assert _exposure_fw(True, "allow", "firewalld").detail == "exposure.firewall_allow_all"


# ---------------------------------------------------------------------------
# Risk-level floor follows the posture
# ---------------------------------------------------------------------------

def test_netfilter_posture_does_not_floor_risk_at_high():
    engine = ScoreEngine()
    set_posture_from_engine(engine, fw_active=FirewallPosture("netfilter", "deny").active)
    assert engine.posture_escalation == (None, "")


# ---------------------------------------------------------------------------
# Per-port wording on a raw-ruleset host
# ---------------------------------------------------------------------------

class TestNetfilterPortWording:
    def _snap(self, address="0.0.0.0"):
        lp = ListeningPort(port=8080, proto="tcp", address=address, raw_line="")
        return PortsSnapshot(ports=[lp], ufw_rules="", ss_output="")

    def test_all_interfaces(self):
        result = check_ports(self._snap(), ufw_active=False, netfilter_active=True, t=_t)
        assert "ports.uncovered_netfilter" in _keys(result)
        assert "ports.uncovered_ufw_inactive" not in _keys(result)

    def test_bound_address(self):
        result = check_ports(self._snap("192.168.1.10"), ufw_active=False,
                             netfilter_active=True, t=_t)
        assert "ports.uncovered_bound_address_netfilter" in _keys(result)

    def test_service_exposure(self):
        result = CheckResult()
        _check_port_exposure(None, "22/tcp", Exposure.NO_RULE, result, "local", False,
                             _kw_t, netfilter_active=True)
        assert "no_rule_netfilter" in result.findings[0].message


def test_all_covered_names_the_policy_under_default_deny():
    # 22/tcp on 0.0.0.0 with no rule, behind default deny, was "covered by a UFW rule".
    ps = PortsSnapshot(ports=[], ufw_rules="", ss_output="")
    result = check_ports(ps, ufw_active=True, default_incoming_policy="deny", t=_echo_t)
    msgs = [f.message for f in result.findings if f.key == "ports.all_covered"]
    assert msgs == ["ports.all_covered_policy"]


# ---------------------------------------------------------------------------
# Runner wiring — the summaries read the posture, not UFW's state
# ---------------------------------------------------------------------------

class TestRunnerWiring:
    src = inspect.getsource(runner)

    def test_raw_ruleset_probed_when_ufw_merely_inactive(self):
        assert "if not fw_status.active and not fwd_status.active:" in self.src

    def test_summary_fields_come_from_the_posture(self):
        assert "fw_active=fw_posture.active," in self.src
        assert "fw_policy=fw_posture.policy," in self.src

    def test_ssh_context_reads_the_posture_policy(self):
        assert "or fw_posture.policy not in (\"deny\", \"reject\")" in self.src


# ---------------------------------------------------------------------------
# IPv6 on a host without UFW (measured on real Debian 13 with nftables)
# ---------------------------------------------------------------------------

class TestIPv6WithoutUfw:
    def _snap(self, listeners=("22/tcp",)):
        from bob.checks.ipv6 import IPv6Snapshot
        return IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=True,
                            ipv6_listeners=list(listeners), ufw_present=False)

    def test_raw_ruleset_named_no_ufw_claim(self):
        from bob.checks.ipv6 import check_ipv6
        result = check_ipv6(self._snap(), ufw_active=False, t=_t, netfilter_active=True)
        keys = _keys(result)
        assert set(keys) == {"ipv6.netfilter_v6"}
        assert result.deductions == []

    def test_no_filter_at_all_is_said(self):
        from bob.checks.ipv6 import check_ipv6
        result = check_ipv6(self._snap(), ufw_active=False, t=_t)
        assert set(_keys(result)) == {"ipv6.no_firewall_v6"}

    def test_ufw_installed_keeps_its_analysis(self):
        from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
        snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=True,
                            ipv6_listeners=["22/tcp"], ufw_present=True)
        assert "ipv6.config_ok" in _keys(check_ipv6(snap, ufw_active=True, t=_t))
