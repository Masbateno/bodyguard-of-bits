"""v0.24.4 — turning a firewall on must not cut the operator off.

ufw starts at "deny (incoming)". Measured on a Raspberry Pi (Raspbian 13
trixie) reached over SSH: the command BOB printed for its most urgent finding,
ALERT ``firewall.inactive`` — a bare ``sudo ufw enable`` — left port 22 silent
for every new connection the moment it was applied. The same bare enable
closed ``prerequisites.firewall_missing`` (after installing ufw) and
``firewall_iptables.nft_no_input_filter``.

``bob --fix --apply`` already ordered an ``ufw allow 22`` before an
``ufw enable`` when both findings were in the same run (v0.18.0); the command
printed for a human, pasted alone, had no such guard. Each enable now carries
its own allow, for the ports sshd actually answers on (``ss -tulnp``): a
non-standard port is kept too, an sshd bound to loopback needs nothing, and
when the listening set cannot be read the stock port 22 is kept — reachable
beats tidy.
"""

from __future__ import annotations

import pytest

from bob.checks import _ufw
from bob.checks.firewall import FirewallStatus, _firewall_install_fix, check_firewall
from bob.checks.iptables_nftables import IptablesNftSnapshot, check_iptables_nftables
from bob.checks.ports import ListeningPort, PortsSnapshot
from tests.helpers import _t


def _lp(port, address="0.0.0.0", process="sshd", proto="tcp"):
    return ListeningPort(port=port, proto=proto, address=address, raw_line="", process=process)


def _ports(*listeners, readable=True):
    return PortsSnapshot(ports=list(listeners), ufw_rules="", ss_output="", ports_readable=readable)


class TestTheEnableCommand:
    def test_every_ssh_port_is_allowed_before_the_enable(self):
        cmd = _ufw.enable_cmd([2222, 22])
        assert cmd == "sudo ufw allow 22/tcp && sudo ufw allow 2222/tcp && sudo ufw enable"

    def test_an_unknown_listening_set_gets_no_command(self):
        """A guess is not a way in: allowing 22 alone cuts an sshd on 2222."""
        assert _ufw.enable_cmd(None) is None

    def test_no_remote_sshd_enables_straight_away(self):
        assert _ufw.enable_cmd([]) == "sudo ufw enable"


class TestWhichPortsSshdAnswersOn:
    def test_a_non_standard_port(self):
        assert _ports(_lp(2222), _lp(2222, "::")).ssh_ports == [2222]

    def test_loopback_only_needs_nothing(self):
        assert _ports(_lp(22, "127.0.0.1"), _lp(80, process="nginx")).ssh_ports == []

    def test_a_socket_activated_sshd_is_held_by_systemd(self):
        """Ubuntu 24.04: ``ss -tulnp`` shows ``systemd`` on :22 (ssh.socket)."""
        assert _ports(_lp(22, process="systemd")).ssh_ports == [22]

    def test_a_socket_activated_non_standard_port(self):
        """Mint 22.3, ``ListenStream`` on 22 and 2222, ssh.service not yet
        started: ``ss`` names only systemd. BOB printed ``allow 22/tcp`` alone;
        applied, 2222 stopped answering."""
        from bob.checks.ports import _parse_socket_listen
        listen = _parse_socket_listen("Listen=0.0.0.0:22 (Stream)\nListen=[::]:22 (Stream)\n"
                                      "Listen=0.0.0.0:2222 (Stream)\n")   # systemctl show -p Listen, verbatim
        snap = PortsSnapshot(ports=[_lp(22, process="systemd"), _lp(2222, process="systemd"),
                                    _lp(631, process="systemd")],
                             ufw_rules="", ss_output="", ssh_socket_ports=listen)
        assert snap.ssh_ports == [22, 2222]

    def test_the_snapshot_reads_the_ssh_socket_units(self):
        import inspect
        assert '_run("systemctl", "show", "-p", "Listen", *_SSH_SOCKET_UNITS)' \
            in inspect.getsource(PortsSnapshot.from_system)

    def test_an_unreadable_listening_set_is_unknown(self):
        assert _ports(readable=False).ssh_ports is None

    def test_no_process_names_cannot_be_attributed(self):
        """``ss -tulnp`` without privileges: a port BOB cannot attribute."""
        assert _ports(_lp(2222, process="")).ssh_ports is None

    def test_unnamed_listeners_on_22_and_2222_are_unknown(self):
        """Mint, BOB run as a user: ``ss`` names no process; 22 listening is not
        proof 22 is the only way in."""
        assert _ports(_lp(22, process=""), _lp(2222, process="")).ssh_ports is None

    def test_another_ssh_server_on_22_is_kept(self):
        """dropbear (Alpine, OpenWrt) holds 22 under its own name."""
        assert _ports(_lp(22, process="dropbear")).ssh_ports == [22]

    def test_no_sshd_at_all(self):
        assert _ports(_lp(80, process="nginx")).ssh_ports == []


def _ufw_inactive():
    return FirewallStatus(installed=True, active=False, incoming_policy="unknown",
                          ufw_output="", numbered_output="", ipv6_ufw_enabled=True)


class TestEveryEnableKeepsSsh:
    def test_firewall_inactive(self):
        finding = next(f for f in check_firewall(_ufw_inactive(), t=_t, ssh_ports=[2222]).findings
                       if f.key == "firewall.inactive")
        assert finding.cmd.index("sudo ufw allow 2222/tcp") < finding.cmd.index("sudo ufw enable")

    def test_firewall_inactive_without_ports_says_why_no_command(self):
        from bob import i18n
        i18n.init("en")
        try:
            finding = next(f for f in check_firewall(_ufw_inactive(), t=i18n.t).findings
                           if f.key == "firewall.inactive")
        finally:
            i18n.init(lang="en")
        assert not finding.cmd
        assert "could not tell which ports sshd answers on" in finding.detail

    def test_installing_a_firewall_without_ports_gets_no_command(self, manager):
        for name in ("apt", "dnf"):
            manager(name)
            cmd, detail = _firewall_install_fix(_t, None)
            assert cmd is None and detail == "firewall.ssh_ports_unknown_detail"

    @pytest.fixture
    def manager(self, monkeypatch):
        def use(name):
            monkeypatch.setattr("bob.checks.firewall.detect_install_manager", lambda: name)
            monkeypatch.setattr("bob.checks._run.detect_install_manager", lambda: name)
        return use

    def test_installing_ufw(self, manager):
        manager("apt")
        cmd, _ = _firewall_install_fix(_t, [2222])
        assert cmd.index("sudo ufw allow 2222/tcp") < cmd.index("sudo ufw enable")

    def test_installing_firewalld_keeps_the_ssh_service(self, manager):
        manager("dnf")
        cmd, _ = _firewall_install_fix(_t, [22])
        assert cmd.index("systemctl enable --now firewalld") \
            < cmd.index("firewall-cmd --permanent --add-service=ssh") \
            < cmd.index("firewall-cmd --reload")

    def test_installing_firewalld_keeps_a_non_standard_port(self, manager):
        manager("zypper")
        cmd, _ = _firewall_install_fix(_t, [2222])
        assert "firewall-cmd --permanent --add-port=2222/tcp" in cmd
        assert "--add-service=ssh" not in cmd

    def test_installing_firewalld_with_no_remote_sshd_reloads_nothing(self, manager):
        manager("dnf")
        cmd, _ = _firewall_install_fix(_t, [])
        assert cmd.endswith("sudo systemctl enable --now firewalld")

    def test_installing_firewalld_keeps_ssh_in_every_active_zone(self, manager, tmp_path):
        """An interface NetworkManager binds to another zone, or a source bound
        to one, is judged by that zone, not the default. The printed command is
        run here against a stand-in firewall-cmd answering as firewalld 2.x does."""
        import os
        import subprocess
        manager("dnf")
        cmd, _ = _firewall_install_fix(_t, [2222, 22])
        then = cmd.split(" && ", 1)[1]          # past the package install
        log = tmp_path / "calls"
        for name, body in {
            "sudo": 'exec "$@"',
            "systemctl": "exit 0",
            "firewall-cmd": ('[ "$1" = --get-active-zones ] && { printf \''
                             'public (default)\\n  interfaces: enp1s0\\n'
                             'internal\\n  interfaces: enp2s0\\n'
                             'work\\n  sources: 192.168.1.0/24\\n\'; exit 0; }\n'
                             f'echo "$*" >> {log}'),
        }.items():
            (tmp_path / name).write_text(f"#!/bin/sh\n{body}\n")
            (tmp_path / name).chmod(0o755)
        env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}
        subprocess.run(["sh", "-c", then], check=True, env=env, timeout=30)
        calls = log.read_text().splitlines()
        for zone in ("public", "internal", "work"):
            assert f"--permanent --zone={zone} --add-service=ssh --add-port=2222/tcp" in calls
        assert calls[-1] == "--reload"

    def test_nft_with_no_input_filter(self):
        result = check_iptables_nftables(IptablesNftSnapshot(backend="nftables", input_policy="ACCEPT",
                                                              forward_policy="ACCEPT", has_loopback_rule=False,
                                                              has_conntrack_rule=False, nft_no_input_filter=True),
                                          ufw_installed=True, t=_t, ssh_ports=[22])
        finding = next(f for f in result.findings if f.key == "firewall_iptables.nft_no_input_filter")
        assert finding.cmd == "sudo ufw allow 22/tcp && sudo ufw enable"


def test_the_runner_hands_the_ssh_ports_to_both_checks():
    """The checks default to "unknown" (keep 22); this pins that the runner
    passes the measured ports, so a non-standard sshd port is kept too."""
    import inspect

    import bob.runner as runner
    src = inspect.getsource(runner)
    assert src.count("ssh_ports=ports_snapshot.ssh_ports") == 2
    assert src.index("ports_snapshot = PortsSnapshot.from_system()") < src.index("fw_result  = check_firewall(")


class TestAnIpv6SshPath:
    """With ufw set to IPV6=no, ufw-init drops all IPv6 once ufw is on
    (measured in v0.24.2): ``ufw allow 22/tcp`` cannot keep an SSH session that
    arrives over IPv6. IPv6 is turned on first, and the allow covers both."""

    def test_ipv6_is_turned_on_before_the_allow(self):
        cmd = _ufw.enable_cmd([22], ipv6_off=True)
        assert cmd.index("IPV6=yes") < cmd.index("ufw allow 22/tcp") < cmd.index("ufw enable")

    def test_no_remote_sshd_needs_no_ipv6_change(self):
        assert _ufw.enable_cmd([], ipv6_off=True) == "sudo ufw enable"

    @pytest.mark.parametrize("listeners, expected", [
        ((_lp(22, "::"),), True),
        ((_lp(22, "0.0.0.0"),), False),
        ((_lp(22, "::1"), _lp(22, "0.0.0.0")), False),
    ])
    def test_sshd_on_ipv6(self, listeners, expected):
        assert _ports(*listeners).ssh_on_ipv6 is expected

    def test_unknown_listeners_are_unknown(self):
        assert _ports(readable=False).ssh_on_ipv6 is None

    @pytest.mark.parametrize("on_ipv6, turned_on", [(True, True), (None, True), (False, False)])
    def test_firewall_inactive(self, on_ipv6, turned_on):
        status = FirewallStatus(installed=True, active=False, incoming_policy="unknown",
                                ufw_output="", numbered_output="", ipv6_ufw_enabled=False)
        cmd = next(f for f in check_firewall(status, t=_t, ssh_ports=[22], ssh_on_ipv6=on_ipv6).findings
                   if f.key == "firewall.inactive").cmd
        assert ("IPV6=yes" in cmd) is turned_on

    def test_ipv6_already_on_is_left_alone(self):
        cmd = next(f for f in check_firewall(_ufw_inactive(), t=_t, ssh_ports=[22], ssh_on_ipv6=True).findings
                   if f.key == "firewall.inactive").cmd
        assert "IPV6=yes" not in cmd

    def test_nft_without_input_filter(self):
        result = check_iptables_nftables(IptablesNftSnapshot(backend="nftables", input_policy="ACCEPT",
                                                              forward_policy="ACCEPT", has_loopback_rule=False,
                                                              has_conntrack_rule=False, nft_no_input_filter=True),
                                          ufw_installed=True, t=_t, ssh_ports=[22], ufw_ipv6_off=True)
        cmd = next(f for f in result.findings if f.key == "firewall_iptables.nft_no_input_filter").cmd
        assert cmd.index("IPV6=yes") < cmd.index("ufw enable")


def test_the_runner_hands_the_ipv6_state_to_both_checks():
    import inspect

    import bob.runner as runner
    src = inspect.getsource(runner)
    assert "ssh_on_ipv6=ports_snapshot.ssh_on_ipv6," in src
    assert "ufw_ipv6_off=fw_status.ipv6_ufw_enabled is False" in src


def test_the_firewalld_detail_says_ssh_stays_in_every_active_zone(monkeypatch):
    """Keeping SSH everywhere it answered is a choice, not a segmentation: the
    finding says so where the operator reads the command."""
    from bob import i18n
    monkeypatch.setattr("bob.checks.firewall.detect_install_manager", lambda: "dnf")
    monkeypatch.setattr("bob.checks._run.detect_install_manager", lambda: "dnf")
    i18n.init("en")
    try:
        _, detail = _firewall_install_fix(i18n.t, [22])
    finally:
        i18n.init(lang="en")
    assert "every active zone" in detail and "--remove-service=ssh" in detail
    assert "new SSH logins failed for about a second" in detail     # measured on Fedora
