"""v0.42.0 — UDP ports above 32767: still not judged, no longer hidden (B-040).

Found on the developer's workstation audit under 0.40.0 (21 November 2026):
the IPv6 section named "39479/udp" among the host's IPv6 services, while the
listening-ports overview of the same run had no such port. Measured with an
ordinary account: ``[::]:39479`` belongs to uid 110 (avahi), like
``0.0.0.0:53050`` — avahi's reply ports. The overview and the ports check
dropped every UDP port above 32767 without a word; the verdict "every
listening port is filtered" carried an exception it did not state.

Decided with the user: show them and say they are not judged — no point,
attack surface and run comparison unchanged.
"""

from __future__ import annotations

from types import SimpleNamespace

from bob.checks.ports import EPHEMERAL_THRESHOLD, ListeningPort, PortsSnapshot, check_ports

_SS = ("Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
       'udp   UNCONN 0      0      [::]:39479         [::]:*            users:(("avahi-daemon",pid=1576,fd=14))\n'
       'udp   UNCONN 0      0      0.0.0.0:5353       0.0.0.0:*         users:(("avahi-daemon",pid=1576,fd=12))')


def _ports():
    lines = _SS.splitlines()
    return [ListeningPort(port=39479, proto="udp", address="::", raw_line=lines[1], process="avahi-daemon"),
            ListeningPort(port=5353, proto="udp", address="0.0.0.0", raw_line=lines[2], process="avahi-daemon")]


def test_the_ports_check_names_the_port_and_its_holder():
    r = check_ports(PortsSnapshot(ports=_ports(), ufw_rules="", ss_output=_SS))
    said = [f for f in r.findings if f.key == "ports.high_udp_not_judged"]
    assert len(said) == 1
    assert "39479/udp (avahi-daemon)" in said[0].message and "5353" not in said[0].message
    assert not r.deductions


def test_a_port_at_the_threshold_is_judged_not_said():
    p = ListeningPort(port=EPHEMERAL_THRESHOLD, proto="udp", address="0.0.0.0", raw_line="")
    r = check_ports(PortsSnapshot(ports=[p], ufw_rules="", ss_output=""))
    assert not any(f.key == "ports.high_udp_not_judged" for f in r.findings)


def test_the_overview_counts_and_shows_it():
    from bob import display
    printed: "list[str]" = []
    written: "list[str]" = []
    output = SimpleNamespace(print_info=printed.append, print_dim=printed.append)
    report = SimpleNamespace(write_section=written.append, write_finding=lambda lvl, m: written.append(m),
                             write_raw=written.append)
    config = SimpleNamespace(quiet=True, verbose=False)
    snap = PortsSnapshot(ports=_ports(), ufw_rules="", ss_output=_SS, ports_readable=True)
    display.display_ports_overview(snap, config, lambda k, **kw: f"{k}:{kw}", report, output)
    assert "ports.listening_count:{'count': 2}" in written
    assert any("[::]:39479" in w for w in written)


def test_the_two_texts_exist():
    from bob import i18n
    before = i18n.current_lang()
    for lang in ("en", "fr"):
        i18n.init(lang)
        try:
            msg = i18n.t("ports.high_udp_not_judged", count=1, ports="39479/udp (avahi-daemon)")
            assert "39479/udp (avahi-daemon)" in msg and "32767" in msg
            assert "ss -ulpn" in i18n.t("ports.high_udp_not_judged_detail")
        finally:
            i18n.init(before)
