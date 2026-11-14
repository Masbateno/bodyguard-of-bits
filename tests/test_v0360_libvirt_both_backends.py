"""v0.36.0 — libvirt's rules read in both backends.

Measured on Debian 13 (libvirt 11.3, no firewalld, a10360, 14 November 2026):
firewall_backend left unset chose iptables ("the first available backend from
the following list: [iptables, nftables]", network.conf); set to nftables,
the rules moved to `table ip libvirt_network` while an empty LIBVIRT_FWI
(`-N LIBVIRT_FWI`, no rule) stayed in iptables. From a namespace routed
through the host: the NAT network's VM refused, the routed network's VM
reached. 0.35.0 read the empty iptables chain and said "admits nothing".
"""

from __future__ import annotations

from types import SimpleNamespace

from bob.checks import virtualization as V

_GUEST_INPUT = """table ip libvirt_network {
	chain guest_input {
		ip daddr 192.168.150.0/24 oif "virbr50" counter packets 0 bytes 0 accept
		oif "virbr50" counter packets 0 bytes 0 reject
		oif "virbr0" ip daddr 192.168.122.0/24 ct state established,related counter packets 0 bytes 0 accept
		oif "virbr0" counter packets 0 bytes 0 reject
	}
}
"""


def _runs(monkeypatch, fwi, chain=_GUEST_INPUT):
    def run_result(*args, **kw):
        if args[:2] == ("iptables", "-S"):
            return SimpleNamespace(ok=fwi is not None, stdout=fwi or "")
        if args[:3] == ("nft", "list", "chain"):
            return SimpleNamespace(ok=chain is not None, stdout=chain or "")
        return SimpleNamespace(ok=chain is not None, stdout="")
    monkeypatch.setattr(V, "run_result", run_result)


def test_an_empty_iptables_chain_left_behind_does_not_hide_the_nft_rules(monkeypatch):
    _runs(monkeypatch, "-N LIBVIRT_FWI\n")
    inbound, backend = V._libvirt_rules()
    assert backend == "nftables"
    assert inbound == {"virbr50": ("192.168.150.0/24", "open"), "virbr0": ("192.168.122.0/24", "replies")}


def test_iptables_rules_alone_are_read_as_before(monkeypatch):
    _runs(monkeypatch, "-N LIBVIRT_FWI\n-A LIBVIRT_FWI -d 192.168.150.0/24 -o virbr50 -j ACCEPT\n", chain=None)
    assert V._libvirt_rules() == ({"virbr50": ("192.168.150.0/24", "open")}, "iptables")


def test_a_bridge_both_backends_name_is_open_only_if_both_admit(monkeypatch):
    open_ipt = "-N LIBVIRT_FWI\n-A LIBVIRT_FWI -d 192.168.122.0/24 -o virbr0 -j ACCEPT\n"
    _runs(monkeypatch, open_ipt)
    inbound, _ = V._libvirt_rules()
    assert inbound["virbr0"] == ("192.168.122.0/24", "replies")      # nft requires established,related
    _runs(monkeypatch, "-N LIBVIRT_FWI\n-A LIBVIRT_FWI -d 192.168.150.0/24 -o virbr50 -j ACCEPT\n")
    inbound, _ = V._libvirt_rules()
    assert inbound["virbr50"] == ("192.168.150.0/24", "open")         # both admit new connections


def test_neither_listed_but_the_table_there_is_said(monkeypatch):
    def run_result(*args, **kw):
        if args[:3] == ("nft", "list", "table"):
            return SimpleNamespace(ok=True, stdout="table ip libvirt_network {}")
        return SimpleNamespace(ok=False, stdout="")
    monkeypatch.setattr(V, "run_result", run_result)
    assert V._libvirt_rules() == ({"": "nft"}, "")
