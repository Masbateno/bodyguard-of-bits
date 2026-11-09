"""v0.31.3 — libvirt counts as a routing daemon while one of its networks routes.

0.31.2 counted libvirt as routing as soon as `libvirtd`, `virtqemud` or
/var/lib/libvirt existed: with ip_forward on, `firewall_drivers.ip_forward_enabled`
(WARN −1) then read "IP forwarding enabled — routing daemon detected" (OK).
Measured on Ubuntu Server 26.04, libvirt 12.0.0, 9 November 2026
(~/.cache/bob-fieldtest/netnsbench/virt0313/virt-survey-ubuntu.txt): the network
`default` active wrote /run/libvirt/network/default.xml (`<forward mode='nat'>`,
bridge virbr0); `virsh net-destroy default` removed it and the bridge, a
`default.pid` stayed; an isolated network wrote a state file with no
`<forward>`; stopping every libvirt daemon left the network, its file and its
bridge in place — the daemon proves nothing either way.
"""

from __future__ import annotations

import pytest

from bob.checks import firewall_stack as fs

#: The head of the state file measured on Ubuntu (default.xml), the firewall
#: part shortened: it holds no <forward> or <bridge> of its own.
_NAT = """<!--
WARNING: THIS IS AN AUTO-GENERATED FILE. CHANGES TO IT ARE LIKELY TO BE
OVERWRITTEN AND LOST.
-->

<networkstatus>
  <class_id bitmap='0-2'/>
  <floor sum='0'/>
  <network>
    <name>default</name>
    <uuid>132a888f-4e43-49e2-b8fd-5e42bb336d34</uuid>
    <forward mode='nat'>
      <nat>
        <port start='1024' end='65535'/>
      </nat>
    </forward>
    <bridge name='virbr0' stp='on' delay='0'/>
    <mac address='52:54:00:aa:d1:f1'/>
    <ip address='192.168.122.1' netmask='255.255.255.0'>
      <dhcp>
        <range start='192.168.122.2' end='192.168.122.254'/>
      </dhcp>
    </ip>
  </network>
  <firewall name='fwRemoval' backend='iptables'>
    <group ignoreErrors='yes'>
      <action layer='ipv4'>
        <args>
          <item>--table</item>
          <item>filter</item>
          <item>--delete</item>
          <item>LIBVIRT_FWO</item>
          <item>--in-interface</item>
          <item>virbr0</item>
          <item>--jump</item>
          <item>ACCEPT</item>
        </args>
      </action>
    </group>
  </firewall>
</networkstatus>
"""
#: The isolated network measured (no <forward>).
_ISOLATED = ("<networkstatus><network><name>bobiso</name><bridge name='virbr9' stp='on' delay='0'/>"
             "<ip address='192.168.209.1' netmask='255.255.255.0'/></network></networkstatus>")


@pytest.fixture
def host(tmp_path, monkeypatch):
    state = tmp_path / "run-libvirt-network"
    state.mkdir()
    net = tmp_path / "sys-class-net"
    net.mkdir()
    monkeypatch.setattr(fs, "_LIBVIRT_NETWORK_STATE", state)
    monkeypatch.setattr(fs, "_SYS_CLASS_NET", net)
    monkeypatch.setattr(fs, "_command_exists", lambda c: True)      # libvirt installed throughout

    def make(files: dict, bridges=()):
        for name, text in files.items():
            (state / name).write_text(text)
        for b in bridges:
            (net / b).mkdir()
    return make


class TestWhenLibvirtRoutes:
    def test_the_measured_nat_network(self, host):
        host({"default.xml": _NAT, "default.pid": "2643\n", "autostarted": ""}, bridges=["virbr0"])
        assert fs._libvirt_routing() is True

    @pytest.mark.parametrize("mode", ["nat", "route", "open"])
    def test_the_modes_that_route_through_the_host(self, host, mode):
        host({"n.xml": _NAT.replace("mode='nat'", f"mode='{mode}'")}, bridges=["virbr0"])
        assert fs._libvirt_routing() is True

    def test_a_forward_with_no_mode_is_nat(self, host):
        host({"n.xml": _NAT.replace(" mode='nat'", "")}, bridges=["virbr0"])
        assert fs._libvirt_routing() is True

    def test_a_state_file_bob_cannot_read_is_an_active_network(self, host, monkeypatch):
        host({"default.xml": _NAT})
        from pathlib import Path
        real = Path.read_text
        monkeypatch.setattr(Path, "read_text",
                            lambda self, *a, **k: (_ for _ in ()).throw(PermissionError(13, "denied"))
                            if self.name == "default.xml" else real(self, *a, **k))
        assert fs._libvirt_routing() is True


class TestWhenItDoesNot:
    def test_installed_with_its_network_destroyed(self, host):
        """Measured: after `virsh net-destroy default`, a default.pid stays."""
        host({"default.pid": "2643\n", "driver.pid": "1\n", "autostarted": "", "nwfilter.leases": ""})
        assert fs._libvirt_routing() is False

    def test_an_isolated_network(self, host):
        host({"bobiso.xml": _ISOLATED, "bobiso.pid": "1\n"}, bridges=["virbr9"])
        assert fs._libvirt_routing() is False

    @pytest.mark.parametrize("mode", ["bridge", "macvtap", "passthrough", "hostdev"])
    def test_modes_that_do_not_route_through_the_host(self, host, mode):
        host({"n.xml": _NAT.replace("mode='nat'", f"mode='{mode}'")}, bridges=["virbr0"])
        assert fs._libvirt_routing() is False

    def test_a_state_file_whose_bridge_is_gone(self, host):
        host({"default.xml": _NAT})
        assert fs._libvirt_routing() is False

    def test_a_bridge_with_no_name(self, host):
        host({"n.xml": _NAT.replace("name='virbr0' ", "")}, bridges=["virbr0"])
        assert fs._libvirt_routing() is False

    def test_a_broken_state_file_is_skipped(self, host):
        host({"a.xml": "<networkstatus><network>", "default.xml": _NAT}, bridges=["virbr0"])
        assert fs._libvirt_routing() is True
        assert fs._LIBVIRT_NETWORK_STATE.joinpath("default.xml").unlink() is None
        assert fs._libvirt_routing() is False

    def test_libvirt_not_there(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fs, "_LIBVIRT_NETWORK_STATE", tmp_path / "absent")
        monkeypatch.setattr(fs, "_command_exists", lambda c: True)
        assert fs._libvirt_routing() is False


class TestAnUnlistableDirectory:
    def test_falls_back_to_what_0_31_2_read(self, tmp_path, monkeypatch):
        from pathlib import Path
        monkeypatch.setattr(fs, "_LIBVIRT_NETWORK_STATE", tmp_path)
        real = Path.iterdir
        monkeypatch.setattr(Path, "iterdir", lambda self: (_ for _ in ()).throw(PermissionError(13, "denied"))
                            if self == tmp_path else real(self))
        monkeypatch.setattr(fs, "_command_exists", lambda c: c == "libvirtd")
        assert fs._libvirt_routing() is True
        monkeypatch.setattr(fs, "_command_exists", lambda c: False)
        monkeypatch.setattr(fs, "Path", lambda p: tmp_path / "no-var-lib-libvirt")
        assert fs._libvirt_routing() is False


class TestTheVerdict:
    def test_ip_forward_with_libvirt_installed_but_not_routing_is_said(self, host, monkeypatch):
        """Measured: ip_forward 1, libvirt installed, its network destroyed — 0.31.2 said OK."""
        host({"default.pid": "2643\n"})
        snap = fs.FirewallStackSnapshot(ip_forward=True, libvirt_present=fs._libvirt_routing())
        keys = [f.key for f in fs.check_firewall_stack(snap, t=lambda k, **kw: k).findings]
        assert "firewall_drivers.ip_forward_enabled" in keys and "firewall_drivers.ip_forward_ok" not in keys

    def test_ip_forward_with_a_routing_network_is_ok(self, host):
        host({"default.xml": _NAT}, bridges=["virbr0"])
        snap = fs.FirewallStackSnapshot(ip_forward=True, libvirt_present=fs._libvirt_routing())
        keys = [f.key for f in fs.check_firewall_stack(snap, t=lambda k, **kw: k).findings]
        assert "firewall_drivers.ip_forward_ok" in keys

    def test_from_system_reads_it(self, monkeypatch):
        monkeypatch.setattr(fs, "_libvirt_routing", lambda: "measured")
        monkeypatch.setattr(fs, "_run", lambda *a, **k: "")
        assert fs.FirewallStackSnapshot.from_system().libvirt_present == "measured"


class TestTheVirtualisationSection:
    """`virt.bypass_risk` said libvirt "may insert iptables rules" as soon as
    virsh, libvirtd or a virbr* interface existed. It now reads the same state
    files, for the two modes libvirt writes rules for (NAT, routed)."""

    @staticmethod
    def _techs(monkeypatch, routing):
        from bob.checks import virtualization as virt
        monkeypatch.setattr(virt, "_libvirt_routing", lambda modes: routing)
        monkeypatch.setattr(virt, "_command_exists", lambda c: True)
        monkeypatch.setattr(virt, "_get_network_interfaces", lambda: ["virbr0"])
        monkeypatch.setattr(virt, "_get_snap_network_packages", lambda: [])
        return [t for t in virt.VirtSnapshot.from_system().technologies if t.name == "libvirt/KVM"]

    def test_installed_but_not_routing_is_not_said(self, monkeypatch):
        assert self._techs(monkeypatch, False) == []

    def test_a_routing_network_is_said_with_its_bridge(self, monkeypatch):
        techs = self._techs(monkeypatch, True)
        assert len(techs) == 1 and techs[0].iface == "virbr0"

    def test_an_open_network_writes_no_rule(self, host):
        from bob.checks import virtualization as virt
        host({"n.xml": _NAT.replace("mode='nat'", "mode='open'")}, bridges=["virbr0"])
        assert fs._libvirt_routing() is True
        assert fs._libvirt_routing(modes=virt._LIBVIRT_RULE_MODES) is False

    def test_nat_and_route_write_rules(self, host):
        from bob.checks import virtualization as virt
        host({"n.xml": _NAT, "r.xml": _NAT.replace("mode='nat'", "mode='route'").replace("virbr0", "virbr1")},
             bridges=["virbr1"])
        assert fs._libvirt_routing(modes=virt._LIBVIRT_RULE_MODES) is True


class TestTheJsonFieldSaysItRoutes:
    """`firewall_drivers.libvirt_present` in --json-full said libvirt was
    installed; since 0.31.3 it says a libvirt network routes. The contract a
    consumer reads is the output, so the output is what is tested."""

    @staticmethod
    def _field(monkeypatch):
        from types import SimpleNamespace

        from bob.json_output import _populate_v2_full_blocks
        monkeypatch.setattr(fs, "_run", lambda *a, **k: "")
        snap = fs.FirewallStackSnapshot.from_system()
        data: dict = {}
        engine = SimpleNamespace(findings=[], breakdown=[])
        try:
            _populate_v2_full_blocks(data, engine, [], SimpleNamespace(ports=[]), snap, None, None, None)
        except AttributeError:
            pass                    # the blocks after firewall_drivers need snapshots this test does not build
        return data["firewall_drivers"]["libvirt_present"]

    def test_installed_with_no_network_routing_reads_false(self, host, monkeypatch):
        host({"default.pid": "2643\n"})                        # measured: what net-destroy leaves
        assert self._field(monkeypatch) is False

    def test_a_routing_network_reads_true(self, host, monkeypatch):
        host({"default.xml": _NAT}, bridges=["virbr0"])
        assert self._field(monkeypatch) is True

    def test_an_unreadable_state_file_reads_true(self, host, monkeypatch):
        """Counted conservatively: an active network BOB could not read."""
        from pathlib import Path
        host({"default.xml": _NAT})
        real = Path.read_text
        monkeypatch.setattr(Path, "read_text",
                            lambda self, *a, **k: (_ for _ in ()).throw(PermissionError(13, "denied"))
                            if self.name == "default.xml" else real(self, *a, **k))
        assert self._field(monkeypatch) is True
