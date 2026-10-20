"""v0.26.0 — no firewall at all scores like an inactive UFW, and an unknown
firewalld is not "no firewall".

Measured before the change: an openSUSE Leap 16 host with no firewall running
(firewalld stopped, an nftables ruleset filtering nothing) scored 7/10 in
Firewall & Network — `prerequisites.firewall_missing` cost nothing and capped
nothing, only the nftables finding took 3 — while an Ubuntu Server host with UFW
installed and off was capped at 3/10. Having no firewall scored better than
having one switched off.

`FirewalldStatus.readable` (firewall-cmd present, failed and printed nothing)
was collected and read by nobody: such a host fell into "firewalld installed but
not running", and with the cap it would have been capped on an unknown.
"""

from bob.checks._firewalld import FirewalldStatus
from bob.checks.firewall import FirewallStatus, check_firewall
from bob.checks.iptables_nftables import IptablesNftSnapshot, check_iptables_nftables
from bob.domain_scores import apply_domain_score_override
from bob.profiles import load_profile
from bob.scoring import CheckResult, ScoreEngine, set_posture_from_engine
from bob.visibility import is_visibility_key
from tests.helpers import _keys, _levels, _t


def _no_ufw() -> FirewallStatus:
    return FirewallStatus(installed=False, active=False, incoming_policy="unknown",
                          ufw_output="", numbered_output="", ipv6_ufw_enabled=False)


def _nft_filters_nothing() -> IptablesNftSnapshot:
    return IptablesNftSnapshot(backend="nftables", input_policy="ACCEPT", forward_policy="ACCEPT",
                               has_loopback_rule=False, has_conntrack_rule=False,
                               nft_no_input_filter=True)


def _engine(*results):
    eng = ScoreEngine(profile=load_profile("server"))
    for section, res in results:
        eng.apply(res, section)
    other = CheckResult()
    other.ok(message="ok", key="ssh.config_ok")
    eng.apply(other, "ssh")
    eng.finalize()
    apply_domain_score_override(eng)
    return eng


class TestNoFirewall:
    def test_missing_caps_the_domain_like_inactive(self):
        for fwd in (None, FirewalldStatus(active=False, installed=True)):
            fw = check_firewall(_no_ufw(), firewalld=fwd, netfilter_protective=False, t=_t, ssh_ports=[22])
            assert any(c.maximum == 3 and c.key == "prerequisites.firewall_missing" for c in fw.caps)

    def test_the_measured_host_no_longer_scores_seven(self):
        fw = check_firewall(_no_ufw(), firewalld=FirewalldStatus(active=False, installed=True),
                            netfilter_protective=False, t=_t, ssh_ports=[22])
        ipt = check_iptables_nftables(_nft_filters_nothing(), firewalld=FirewalldStatus(active=False, installed=True),
                                      t=_t, ssh_ports=[22])
        eng = _engine(("firewall", fw), ("firewall_iptables", ipt))
        assert eng.domain_scores["firewall_network"]["score"] == 3

    def test_a_filtering_raw_ruleset_is_still_credited_not_capped(self):
        fw = check_firewall(_no_ufw(), firewalld=None, netfilter_protective=True, t=_t)
        assert not fw.caps and "firewall.netfilter_active" in _keys(fw)


class TestAnUnknownFirewalld:
    def _silent(self):
        return FirewalldStatus(active=False, installed=True, readable=False)

    def test_no_alert_no_cap_a_visibility_info(self):
        fw = check_firewall(_no_ufw(), firewalld=self._silent(), netfilter_protective=False, t=_t, ssh_ports=[22])
        assert _keys(fw) == ["firewall.firewalld_unreadable"]
        assert "alert" not in _levels(fw) and not fw.caps
        assert is_visibility_key("firewall.firewalld_unreadable")

    def test_the_base_chains_are_not_judged(self):
        ipt = check_iptables_nftables(_nft_filters_nothing(), firewalld=self._silent(), t=_t, ssh_ports=[22])
        assert _keys(ipt) == ["firewall_iptables.firewalld_unreadable"] and not ipt.deductions
        assert is_visibility_key("firewall_iptables.firewalld_unreadable")

    def test_no_high_floor_on_an_unknown(self):
        fw = check_firewall(_no_ufw(), firewalld=self._silent(), netfilter_protective=False, t=_t)
        eng = _engine(("firewall", fw))
        set_posture_from_engine(eng, fw_active=False)
        floor, _key = eng.posture_escalation
        assert _key != "scoring.posture.firewall_inactive"

    def test_an_inactive_firewall_keeps_its_floor(self):
        fw = check_firewall(_no_ufw(), firewalld=None, netfilter_protective=False, t=_t, ssh_ports=[22])
        eng = _engine(("firewall", fw))
        set_posture_from_engine(eng, fw_active=False)
        assert eng.posture_escalation[1] == "scoring.posture.firewall_inactive"


def test_stopped_firewalld_2_1_writes_not_running_on_stderr(monkeypatch):
    """Measured on openSUSE Leap 16 (firewalld 2.1.2), firewalld stopped:
    `firewall-cmd --state` → stdout empty, stderr "not running", exit 252. The
    first 0.26.0 tree read that as unreadable and dropped the cap."""
    from bob.checks import _firewalld
    from bob.checks._run import CommandResult
    monkeypatch.setattr(_firewalld, "_command_exists", lambda name: True)
    monkeypatch.setattr(_firewalld, "run_result",
                        lambda *a, **k: CommandResult(stdout="", ok=False, stderr="not running\n", code=252))
    status = FirewalldStatus.from_system()
    assert status.installed and not status.active and status.readable


def test_a_silent_failure_is_still_unreadable(monkeypatch):
    from bob.checks import _firewalld
    from bob.checks._run import CommandResult
    monkeypatch.setattr(_firewalld, "_command_exists", lambda name: True)
    monkeypatch.setattr(_firewalld, "run_result", lambda *a, **k: CommandResult(stdout="", ok=False, stderr="", code=None))
    assert FirewalldStatus.from_system().readable is False


def test_the_cap_line_says_what_the_alert_says():
    """Measured on openSUSE: the breakdown read "No active firewall — neither UFW
    nor firewalld is installed" under the alert "firewalld is installed but not
    running"."""
    fw = check_firewall(_no_ufw(), firewalld=FirewalldStatus(active=False, installed=True),
                        netfilter_protective=False, t=_t, ssh_ports=[22])
    assert [c.reason for c in fw.caps] == ["prerequisites.firewall_missing_firewalld_stopped"]
