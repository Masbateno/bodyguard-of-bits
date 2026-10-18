"""v0.25.1 — firewalld installed and stopped is not "no firewalld".

Measured on openSUSE Leap 16 (firewalld 2.1.2, nftables, no ufw) with
firewalld stopped and disabled: the alert said "neither UFW nor firewalld is
installed", the fix began with `zypper install firewalld`, and the nftables
finding told the operator to load /etc/nftables.conf, a file the host does not
have. The firewalld command itself was right: run as printed with SSH logins
arriving every quarter second and the interface in a NetworkManager zone
without ssh, 0 refused in three runs (66, 75 and 75 logins).
"""

from __future__ import annotations

from bob.checks import _firewalld
from bob.checks._firewalld import FirewalldStatus
from bob.checks._run import CommandResult
from bob.checks.firewall import FirewallStatus, check_firewall
from bob.checks.iptables_nftables import IptablesNftSnapshot, check_iptables_nftables
from tests.helpers import _t


def _no_ufw() -> FirewallStatus:
    return FirewallStatus(installed=False, active=False, incoming_policy="unknown",
                          ufw_output="", numbered_output="", ipv6_ufw_enabled=False)


def _missing(firewalld, monkeypatch, manager="zypper", ports=(22,)):
    monkeypatch.setattr("bob.checks.firewall.detect_install_manager", lambda: manager)
    monkeypatch.setattr("bob.checks._run.detect_install_manager", lambda: manager)
    result = check_firewall(_no_ufw(), firewalld=firewalld, netfilter_protective=False,
                            t=_t, ssh_ports=list(ports))
    return next(f for f in result.findings if f.key == "prerequisites.firewall_missing")


class TestTheAlert:
    def test_stopped_firewalld_is_named_installed(self, monkeypatch):
        f = _missing(FirewalldStatus(active=False, installed=True), monkeypatch)
        assert f.message == "prerequisites.firewall_missing_firewalld_stopped"

    def test_the_fix_does_not_install_what_is_there(self, monkeypatch):
        f = _missing(FirewalldStatus(active=False, installed=True), monkeypatch)
        assert "zypper" not in f.cmd and "install" not in f.cmd
        assert f.cmd.startswith("sudo firewall-offline-cmd --add-service=ssh")
        assert "sudo systemctl enable --now firewalld" in f.cmd

    def test_firewalld_is_advised_on_an_apt_host_that_has_it(self, monkeypatch):
        f = _missing(FirewalldStatus(active=False, installed=True), monkeypatch, manager="apt")
        assert "firewalld" in f.cmd and "ufw" not in f.cmd

    def test_no_sshd_port_still_starts_it(self, monkeypatch):
        f = _missing(FirewalldStatus(active=False, installed=True), monkeypatch, ports=())
        assert f.cmd == "sudo systemctl enable --now firewalld"

    def test_absent_firewalld_keeps_the_install(self, monkeypatch):
        f = _missing(FirewalldStatus(active=False, installed=False), monkeypatch)
        assert f.message == "prerequisites.firewall_missing"
        assert f.cmd.startswith("sudo zypper")


class TestCollection:
    def test_a_stopped_daemon_with_its_client_is_installed(self, monkeypatch):
        monkeypatch.setattr(_firewalld, "_command_exists", lambda name: True)
        monkeypatch.setattr(_firewalld, "run_result",
                            lambda *a, **k: CommandResult(stdout="not running\n", ok=False))
        status = FirewalldStatus.from_system()
        assert status.installed is True and status.active is False

    def test_no_client_is_not_installed(self, monkeypatch):
        monkeypatch.setattr(_firewalld, "_command_exists", lambda name: False)
        assert FirewalldStatus.from_system().installed is False


class TestTheNftablesRemedy:
    def _cmd(self, firewalld):
        snap = IptablesNftSnapshot(backend="nftables", input_policy="ACCEPT", forward_policy="ACCEPT",
                                   has_loopback_rule=False, has_conntrack_rule=False,
                                   nft_no_input_filter=True)
        result = check_iptables_nftables(snap, ufw_installed=False, firewalld=firewalld, t=_t,
                                         ssh_ports=[22])
        return next(f for f in result.findings if f.key == "firewall_iptables.nft_no_input_filter").cmd

    def test_a_stopped_firewalld_is_the_remedy(self):
        cmd = self._cmd(FirewalldStatus(active=False, installed=True))
        assert "/etc/nftables.conf" not in cmd
        assert "sudo systemctl enable --now firewalld" in cmd

    def test_without_a_front_end_the_ruleset_is(self):
        assert self._cmd(None) == "sudo nft -f /etc/nftables.conf"
