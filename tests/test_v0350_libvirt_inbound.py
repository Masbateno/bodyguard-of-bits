"""v0.35.0 — what libvirt's own rules let in, read instead of supposed.

0.34.0 warned "virbr0 bridge interface may insert iptables rules, bypassing
the firewall's FORWARD policy" wherever a NAT or routed libvirt network ran.
Measured on Linux Mint 22.3, libvirt 10.0, UFW active with routing denied
(netnsbench/a30350, fake VMs as network namespaces on the bridges, a client
routed through the host):

| network            | LIBVIRT_FWI accept for it              | new connection from outside |
|--------------------|----------------------------------------|-----------------------------|
| default (NAT)      | -d 192.168.122.0/24 … RELATED,ESTABLISHED | refused                  |
| bobroute (routed)  | -d 192.168.150.0/24 -o virbr50 (no state) | answered, past UFW       |

libvirt's chains sit ahead of UFW's in FORWARD. Now a NAT network is an INFO
("only replies in"), a routed one keeps the warning, naming what passes.
"""

from __future__ import annotations

from types import SimpleNamespace

from bob.checks import virtualization as V

_FWI = """-N LIBVIRT_FWI
-A LIBVIRT_FWI -d 192.168.150.0/24 -o virbr50 -j ACCEPT
-A LIBVIRT_FWI -o virbr50 -j REJECT --reject-with icmp-port-unreachable
-A LIBVIRT_FWI -d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A LIBVIRT_FWI -o virbr0 -j REJECT --reject-with icmp-port-unreachable
"""


def _runs(monkeypatch, fwi_ok=True, fwi=_FWI, nft_ok=False):
    def run_result(*args, **kw):
        if args[:2] == ("iptables", "-S"):
            return SimpleNamespace(ok=fwi_ok, stdout=fwi if fwi_ok else "")
        return SimpleNamespace(ok=nft_ok, stdout="")
    monkeypatch.setattr(V, "run_result", run_result)


def test_the_measured_rules(monkeypatch):
    _runs(monkeypatch)
    assert V._libvirt_inbound() == {"virbr50": ("192.168.150.0/24", "open"),
                                    "virbr0": ("192.168.122.0/24", "replies")}


def test_unlisted_chain_is_none_and_an_nft_table_is_said(monkeypatch):
    _runs(monkeypatch, fwi_ok=False)
    assert V._libvirt_inbound() is None
    # The nft table with its chain unreadable: test_an_unreadable_nft_chain_is_still_unread.


def _check(inbound):
    snap = V.VirtSnapshot(technologies=[V.VirtTechnology("libvirt/KVM", "virbr0", "note")], libvirt_inbound=inbound,
                          libvirt_read=True)
    return [(f.level.value, f.key) for f in V.check_virtualization(snap).findings]


def test_a_nat_network_is_an_info():
    assert _check({"virbr0": ("192.168.122.0/24", "replies")}) == [("info", "virt.libvirt_replies_only")]


def test_a_routed_network_keeps_the_warning():
    got = _check({"virbr0": ("192.168.122.0/24", "replies"), "virbr50": ("192.168.150.0/24", "open")})
    assert ("warn", "virt.bypass_risk") in got and ("info", "virt.libvirt_replies_only") in got


def test_rules_not_read_claim_nothing():
    assert _check(None) == [("info", "virt.libvirt_rules_unread")]
    assert _check({"": "nft"}) == [("info", "virt.libvirt_rules_unread")]


def test_other_hypervisors_keep_the_generic_warning():
    snap = V.VirtSnapshot(technologies=[V.VirtTechnology("VirtualBox", "vboxnet0", "note")])
    assert [(f.level.value, f.key) for f in V.check_virtualization(snap).findings] == [("warn", "virt.bypass_risk")]


def test_a_read_empty_chain_admits_nothing():
    assert _check({}) == [("info", "virt.libvirt_no_inbound")]


def test_from_system_marks_the_rules_read(monkeypatch):
    monkeypatch.setattr(V, "_get_network_interfaces", lambda: ["virbr0"])
    monkeypatch.setattr(V, "_libvirt_routing", lambda modes: True)
    monkeypatch.setattr(V, "_libvirt_rules", lambda: ({"virbr0": ("192.168.122.0/24", "replies")}, "iptables"))
    monkeypatch.setattr(V, "_command_exists", lambda n: False)
    monkeypatch.setattr(V, "_get_snap_network_packages", lambda: [])
    snap = V.VirtSnapshot.from_system()
    assert snap.libvirt_read and snap.libvirt_inbound == {"virbr0": ("192.168.122.0/24", "replies")}


# --- nftables backend: measured on Fedora 44 (libvirt 12.0, firewalld 2.x, a3f0350)

_GUEST_INPUT = """table ip libvirt_network {
	chain guest_input {
		ip daddr 192.168.150.0/24 oif "virbr50" counter packets 0 bytes 0 accept
		oif "virbr50" counter packets 0 bytes 0 reject
		oif "virbr0" ip daddr 192.168.122.0/24 ct state established,related counter packets 0 bytes 0 accept
		oif "virbr0" counter packets 0 bytes 0 reject
	}
}
"""


def _nft_runs(monkeypatch, chain_ok=True, table_ok=True, chain=_GUEST_INPUT):
    def run_result(*args, **kw):
        if args[:2] == ("iptables", "-S"):
            return SimpleNamespace(ok=False, stdout="")
        if args[:3] == ("nft", "list", "chain"):
            return SimpleNamespace(ok=chain_ok, stdout=chain if chain_ok else "")
        return SimpleNamespace(ok=table_ok, stdout="")
    monkeypatch.setattr(V, "run_result", run_result)


def test_the_measured_nft_rules(monkeypatch):
    _nft_runs(monkeypatch)
    assert V._libvirt_inbound() == {"virbr50": ("192.168.150.0/24", "open"),
                                    "virbr0": ("192.168.122.0/24", "replies")}


def test_a_new_state_in_a_set_is_open():
    got = V._libvirt_inbound_nft('oif "virbr9" ip daddr 10.9.0.0/24 ct state { established, related, new } accept\n')
    assert got == {"virbr9": ("10.9.0.0/24", "open")}
    got = V._libvirt_inbound_nft('oif "virbr9" ip daddr 10.9.0.0/24 ct state { established, related } accept\n')
    assert got == {"virbr9": ("10.9.0.0/24", "replies")}


def test_an_unreadable_nft_chain_is_still_unread(monkeypatch):
    _nft_runs(monkeypatch, chain_ok=False)
    assert V._libvirt_inbound() == {"": "nft"}
    _nft_runs(monkeypatch, chain_ok=False, table_ok=False)
    assert V._libvirt_inbound() is None


def _check_backend(backend):
    snap = V.VirtSnapshot(technologies=[V.VirtTechnology("libvirt/KVM", "virbr0", "note")], libvirt_read=True,
                          libvirt_inbound={"virbr50": ("192.168.150.0/24", "open"),
                                           "virbr0": ("192.168.122.0/24", "replies")},
                          libvirt_backend=backend)
    return {f.key: f for f in V.check_virtualization(snap).findings}


def test_the_nft_backend_gets_its_own_text_and_command():
    got = _check_backend("nftables")
    assert got["virt.bypass_risk"].message.split()[0] == "virt.libvirt_inbound_open_nft"
    assert got["virt.bypass_risk"].cmd == "sudo nft list chain ip libvirt_network guest_input"
    assert got["virt.libvirt_replies_only"].cmd == "sudo nft list chain ip libvirt_network guest_input"


def test_the_iptables_backend_keeps_its_chain():
    got = _check_backend("iptables")
    assert got["virt.bypass_risk"].message.split()[0] == "virt.libvirt_inbound_open"
    assert "iptables -S LIBVIRT_FWI" in got["virt.bypass_risk"].cmd


def test_from_system_keeps_the_backend(monkeypatch):
    monkeypatch.setattr(V, "_get_network_interfaces", lambda: ["virbr0"])
    monkeypatch.setattr(V, "_libvirt_routing", lambda modes: True)
    monkeypatch.setattr(V, "_libvirt_rules", lambda: ({"virbr0": ("192.168.122.0/24", "replies")}, "nftables"))
    monkeypatch.setattr(V, "_command_exists", lambda n: False)
    monkeypatch.setattr(V, "_get_snap_network_packages", lambda: [])
    assert V.VirtSnapshot.from_system().libvirt_backend == "nftables"
