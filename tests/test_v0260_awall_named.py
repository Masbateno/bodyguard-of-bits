"""v0.26.0 — awall, Alpine's firewall front-end, is named and not read as UFW.

Measured on Alpine 3.24 (awall 1.12, iptables) with one optional policy
enabled: deny inbound, ssh kept. 0.25.1 printed "no active firewall front-end
(UFW/firewalld)", took 2 points for each of the three INPUT ACCEPT rules awall
wrote (ESTABLISHED, lo, tcp/22) and 1 for each of its two FORWARD ones, all as
"raw iptables ACCEPT rule bypassing UFW" on a host with no UFW: Firewall &
Network 2/10. The working tree: 10/10, the banner and the INFO name awall and
its policy.

With awall installed and no policy enabled (kernel chains open), 0.25.1 said
"neither UFW nor firewalld installed" and printed `apk add ufw`; the alert now
says awall has no policy enabled and prints no command.
"""

from bob import sysinfo
from bob.checks import _awall
from bob.checks._awall import AwallStatus
from bob.checks._run import CommandResult
from bob.checks.firewall import FirewallStatus, check_firewall
from bob.checks.firewall_stack import FirewallStackSnapshot, check_firewall_stack
from tests.helpers import _keys, _t

# As `awall list` printed it on the Alpine host.
LIST = "bob-test  enabled  BOB 0.26.0 test policy\nweb  disabled  Web server\n"
# As `iptables -S FORWARD` printed awall's rules there (the -L form BOB reads).
FWD = ["ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate ESTABLISHED",
       "ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22"]


def _no_ufw() -> FirewallStatus:
    return FirewallStatus(installed=False, active=False, incoming_policy="unknown",
                          ufw_output="", numbered_output="", ipv6_ufw_enabled=False)


def _status(monkeypatch, exists=True, res=None):
    monkeypatch.setattr(_awall, "_command_exists", lambda name: exists)
    monkeypatch.setattr(_awall, "run_result", lambda *a, **k: res)
    return AwallStatus.from_system()


class TestReadingAwall:
    def test_enabled_policies_by_name(self, monkeypatch):
        st = _status(monkeypatch, res=CommandResult(stdout=LIST, ok=True, code=0))
        assert st == AwallStatus(installed=True, enabled=("bob-test",))

    def test_absent(self, monkeypatch):
        assert _status(monkeypatch, exists=False) == AwallStatus()

    def test_a_failed_list_is_unknown_not_empty(self, monkeypatch):
        st = _status(monkeypatch, res=CommandResult(stdout="", ok=False, code=1))
        assert st.installed and not st.readable and st.enabled == ()


class TestTheBanner:
    def test_each_state(self, monkeypatch):
        for st, line in ((AwallStatus(), ""),
                         (AwallStatus(installed=True, readable=False), "?"),
                         (AwallStatus(installed=True), "-"),
                         (AwallStatus(installed=True, enabled=("a", "b")), "a, b")):
            monkeypatch.setattr(AwallStatus, "from_system", classmethod(lambda cls, _s=st: _s))
            assert sysinfo._awall_banner() == line


class TestAwallActive:
    def test_the_ruleset_is_credited_to_awall(self):
        fw = check_firewall(_no_ufw(), firewalld=None, netfilter_protective=True, t=_t,
                            awall=AwallStatus(installed=True, enabled=("bob-test",)))
        assert _keys(fw) == ["firewall.awall_active"] and not fw.caps
        assert fw.findings[0].template_vars == {"policies": "bob-test"}

    def test_no_policy_enabled_stays_the_generic_info(self):
        fw = check_firewall(_no_ufw(), firewalld=None, netfilter_protective=True, t=_t,
                            awall=AwallStatus(installed=True))
        assert _keys(fw) == ["firewall.netfilter_active"]

    def test_its_forward_rules_are_not_a_ufw_bypass(self):
        res = check_firewall_stack(FirewallStackSnapshot(forward_raw_accepts=list(FWD)),
                                   t=_t, ufw_active=False)
        assert not [d for d in res.deductions if d.key == "firewall_drivers.iptables_forward_bypass"]

    def test_beside_an_active_ufw_they_still_are(self):
        res = check_firewall_stack(FirewallStackSnapshot(forward_raw_accepts=list(FWD)),
                                   t=_t, ufw_active=True)
        assert len([d for d in res.deductions if d.key == "firewall_drivers.iptables_forward_bypass"]) == 2


class TestAwallIdle:
    def _missing(self, awall):
        fw = check_firewall(_no_ufw(), firewalld=None, netfilter_protective=False, t=_t,
                            ssh_ports=[22], awall=awall)
        return fw, next(f for f in fw.findings if f.key == "prerequisites.firewall_missing")

    def test_named_capped_and_no_ufw_to_install(self):
        fw, alert = self._missing(AwallStatus(installed=True))
        assert alert.message == _t("prerequisites.firewall_missing_awall_idle")
        assert not alert.cmd and alert.detail == _t("prerequisites.firewall_missing_awall_idle_detail")
        assert any(c.maximum == 3 for c in fw.caps)

    def test_an_unread_list_does_not_claim_no_policy(self):
        _, alert = self._missing(AwallStatus(installed=True, readable=False))
        assert alert.message == _t("prerequisites.firewall_missing")
        assert not alert.cmd

    def test_without_awall_ufw_is_still_suggested(self):
        _, alert = self._missing(None)
        assert alert.message == _t("prerequisites.firewall_missing") and alert.cmd


def test_the_runner_hands_awall_to_the_firewall_check():
    import inspect

    import bob.runner as runner
    src = inspect.getsource(runner)
    assert "awall=_awall," in src
    # Read only where neither UFW nor firewalld runs, behind the core barrier.
    assert src.index("if not fw_status.active and not fwd_status.active:") \
        < src.index("_awall = AwallStatus.from_system()") < src.index("awall=_awall,")


def test_a_required_policy_is_named_too(monkeypatch):
    # As `awall list` printed it in Alpine 3.24.2 after `awall enable web`,
    # web importing base.
    out = "base  required  Base policy\nweb   enabled   Web on top of base\n"
    st = _status(monkeypatch, res=CommandResult(stdout=out, ok=True, code=0))
    assert st.enabled == ("web", "base (required)")


def test_enabled_but_not_loaded_is_said_as_such():
    """After review, measured in Alpine 3.24.2: `awall enable web` without
    `awall activate` left INPUT at policy ACCEPT with no rule; the alert said
    no policy was enabled."""
    fw = check_firewall(_no_ufw(), firewalld=None, netfilter_protective=False, t=_t,
                        ssh_ports=[22], awall=AwallStatus(installed=True, enabled=("web",)))
    alert = next(f for f in fw.findings if f.key == "prerequisites.firewall_missing")
    assert alert.message == _t("prerequisites.firewall_missing_awall_not_loaded", policies="web")
    assert alert.detail == _t("prerequisites.firewall_missing_awall_not_loaded_detail")
    assert not alert.cmd and any(c.maximum == 3 for c in fw.caps)
