"""A port opened only through a firewalld rich rule must not be invisible.

Until v0.20.4 ``FirewalldStatus.from_system`` read only ``--list-services`` and
``--list-ports``; a port opened through an ``accept`` rich rule, a forward-port,
or a zone bound to specific sources was never collected, so the credited "zone
allows …" line under-reported what firewalld actually permits. The stance was
never a false *verdict* (the checks use firewalld as a boolean, never as a
per-port allow-list), but the reader could not see rich-rule access at all.

These guards pin that ``allows_summary`` now surfaces accept rich rules and
forward-ports, that deny rules are never shown as allowances, and that
``from_system`` parses rich-rule / forward-port output line-by-line rather than
shredding each rule into tokens. Oracle: a real Fedora 44 host (192.168.1.16),
where ``firewall-cmd --add-rich-rule=… accept`` opened a port BOB used to omit.
"""

from __future__ import annotations

import bob.checks._firewalld as fw
from bob.checks._firewalld import FirewalldStatus, _rich_rule_grant
from bob.checks.firewall import FirewallStatus, check_firewall


# ---------------------------------------------------------------------------
# _rich_rule_grant — accept rules grant, deny rules do not
# ---------------------------------------------------------------------------

class TestRichRuleGrant:
    def test_accept_port_rule_yields_port_proto(self):
        rule = ('rule family="ipv4" source address="10.0.0.0/8" '
                'port port="5432" protocol="tcp" accept')
        assert _rich_rule_grant(rule) == "5432/tcp (rich)"

    def test_accept_port_range_rule(self):
        rule = 'rule family="ipv6" port port="8000-8100" protocol="udp" accept'
        assert _rich_rule_grant(rule) == "8000-8100/udp (rich)"

    def test_accept_service_rule_yields_service_name(self):
        rule = 'rule family="ipv4" service name="https" accept'
        assert _rich_rule_grant(rule) == "https (rich)"

    def test_reject_rule_grants_nothing(self):
        rule = 'rule family="ipv4" port port="23" protocol="tcp" reject'
        assert _rich_rule_grant(rule) is None

    def test_drop_rule_grants_nothing(self):
        rule = 'rule family="ipv4" source address="1.2.3.4" drop'
        assert _rich_rule_grant(rule) is None

    def test_accept_without_recognisable_target_is_generic(self):
        rule = 'rule family="ipv4" source address="10.0.0.0/8" accept'
        assert _rich_rule_grant(rule) == "rich rule"


# ---------------------------------------------------------------------------
# allows_summary — everything the zone permits, on one line
# ---------------------------------------------------------------------------

class TestAllowsSummary:
    def test_allows_summary_surfaces_rich_rule_port(self):
        """The mutation guard: a rich-rule port must appear in the summary."""
        st = FirewalldStatus(
            active=True, default_zone="FedoraServer",
            services=["ssh", "cockpit"], ports=["8080/tcp"],
            rich_rules=['rule family="ipv4" port port="5432" protocol="tcp" accept'],
        )
        summary = st.allows_summary()
        assert "5432/tcp (rich)" in summary
        # and it does not drop the plain services/ports it always showed
        assert "ssh" in summary and "8080/tcp" in summary

    def test_forward_ports_are_shown(self):
        st = FirewalldStatus(active=True, services=["ssh"],
                             forward_ports=["port=80:proto=tcp:toport=8080:toaddr="])
        assert "forward port=80:proto=tcp:toport=8080:toaddr=" in st.allows_summary()

    def test_deny_rich_rule_not_shown(self):
        st = FirewalldStatus(
            active=True, services=["ssh"],
            rich_rules=['rule family="ipv4" port port="23" protocol="tcp" reject'],
        )
        summary = st.allows_summary()
        assert "23" not in summary
        assert summary == "ssh"

    def test_empty_zone_summarises_to_dash(self):
        assert FirewalldStatus(active=True).allows_summary() == "—"

    def test_services_and_ports_only_unchanged(self):
        st = FirewalldStatus(active=True, services=["ssh", "cockpit"],
                             ports=["8080/tcp"])
        assert st.allows_summary() == "ssh, cockpit, 8080/tcp"


# ---------------------------------------------------------------------------
# from_system — rich rules / forward-ports parse line-by-line, not by token
# ---------------------------------------------------------------------------

class TestFromSystem:
    def _fake_run(self, outputs):
        """Build a run_result stub returning canned stdout per firewall-cmd arg."""
        class _R:
            def __init__(self, stdout, ok=True):
                self.stdout = stdout
                self.ok = ok
        def _run(cmd, *args):
            return _R(outputs.get(args[-1], ""))
        return _run

    def test_rich_rules_split_by_line_not_token(self, monkeypatch):
        monkeypatch.setattr(fw, "_command_exists", lambda _c: True)
        rich = ('rule family="ipv4" port port="5432" protocol="tcp" accept\n'
                'rule family="ipv4" service name="https" accept\n')
        monkeypatch.setattr(fw, "run_result", self._fake_run({
            "--state": "running",
            "--get-default-zone": "FedoraServer",
            "--list-services": "ssh cockpit",
            "--list-ports": "",
            "--list-rich-rules": rich,
            "--list-forward-ports": "port=80:proto=tcp:toport=8080:toaddr=\n",
            "--list-sources": "10.0.0.0/8",
        }))
        st = FirewalldStatus.from_system()
        # each rule is ONE entry, not a pile of shredded tokens
        assert len(st.rich_rules) == 2
        assert st.forward_ports == ["port=80:proto=tcp:toport=8080:toaddr="]
        assert st.sources == ["10.0.0.0/8"]
        summary = st.allows_summary()
        assert "5432/tcp (rich)" in summary
        assert "https (rich)" in summary

    def test_inactive_firewalld_collects_nothing(self, monkeypatch):
        monkeypatch.setattr(fw, "_command_exists", lambda _c: True)
        monkeypatch.setattr(fw, "run_result",
                            self._fake_run({"--state": "not running"}))
        st = FirewalldStatus.from_system()
        assert st.active is False
        assert st.rich_rules == [] and st.forward_ports == []


# ---------------------------------------------------------------------------
# integration — the credited firewall line names the rich-rule port
# ---------------------------------------------------------------------------

def _echo_t(key: str, **kwargs) -> str:
    if kwargs:
        return f"{key}:" + ",".join(str(v) for v in kwargs.values())
    return key


def test_firewall_credit_line_names_rich_rule_port():
    status = FirewallStatus(installed=False, active=False,
                            incoming_policy="unknown", ufw_output="",
                            numbered_output="", ipv6_ufw_enabled=False)
    firewalld = FirewalldStatus(
        active=True, default_zone="FedoraServer", services=["ssh"],
        rich_rules=['rule family="ipv4" port port="5432" protocol="tcp" accept'],
    )
    result = check_firewall(status, firewalld=firewalld, t=_echo_t)
    finding = next(f for f in result.findings
                   if f.key == "firewall.firewalld_active")
    assert "5432/tcp (rich)" in finding.message
