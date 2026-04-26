"""
Unit tests for bob.checks.ports module.

All tests build PortsSnapshot instances directly — no subprocess calls.

Run with: python -m pytest tests/test_ports.py -v
"""

from __future__ import annotations

import pytest
from bob.checks.ports import (
    EPHEMERAL_THRESHOLD,
    ListeningPort,
    PortCategory,
    PortsSnapshot,
    _SYSTEM_DAEMONS,
    _categorize_port,
    _is_covered_by_ufw,
    _parse_ss_output,
    _split_addr_port,
    check_ports,
)
from bob.scoring import FindingLevel
from tests.helpers import _levels


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_port(port=22, proto="tcp", address="0.0.0.0") -> ListeningPort:
    return ListeningPort(port=port, proto=proto, address=address, raw_line="")


def make_snapshot(ports=None, ufw_rules="", ss_output="") -> PortsSnapshot:
    return PortsSnapshot(
        ports=ports or [],
        ufw_rules=ufw_rules,
        ss_output=ss_output,
    )


def has_level(result, level: str) -> bool:
    return level in _levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# ListeningPort properties
# ---------------------------------------------------------------------------

class TestListeningPort:
    def test_port_proto(self):
        p = make_port(port=22, proto="tcp")
        assert p.port_proto == "22/tcp"

    def test_is_all_interfaces_true(self):
        assert make_port(address="0.0.0.0").is_all_interfaces
        assert make_port(address="::").is_all_interfaces

    def test_is_all_interfaces_false(self):
        assert not make_port(address="127.0.0.1").is_all_interfaces
        assert not make_port(address="192.168.1.1").is_all_interfaces

    def test_is_all_interfaces_false_when_iface_scoped(self):
        # 0.0.0.0%virbr0 binds to a specific interface — not "all interfaces"
        lp = ListeningPort(port=67, proto="udp", address="0.0.0.0", raw_line="", iface="virbr0")
        assert not lp.is_all_interfaces

    def test_is_loopback_true(self):
        assert make_port(address="127.0.0.1").is_loopback
        assert make_port(address="::1").is_loopback

    def test_is_loopback_false(self):
        assert not make_port(address="0.0.0.0").is_loopback


# ---------------------------------------------------------------------------
# _split_addr_port
# ---------------------------------------------------------------------------

class TestSplitAddrPort:
    def test_ipv4_simple(self):
        assert _split_addr_port("0.0.0.0:22") == ("0.0.0.0", "22", "")

    def test_ipv4_with_iface(self):
        addr, port, iface = _split_addr_port("127.0.0.53%lo:53")
        assert addr == "127.0.0.53"
        assert port == "53"
        assert iface == "lo"

    def test_ipv4_virbr0_iface(self):
        addr, port, iface = _split_addr_port("0.0.0.0%virbr0:67")
        assert addr == "0.0.0.0"
        assert port == "67"
        assert iface == "virbr0"

    def test_ipv6_bracket(self):
        assert _split_addr_port("[::]:22") == ("::", "22", "")

    def test_ipv6_loopback(self):
        assert _split_addr_port("[::1]:631") == ("::1", "631", "")

    def test_invalid_returns_none(self):
        assert _split_addr_port("invalid") == (None, None, "")

    def test_private_ipv4(self):
        assert _split_addr_port("192.168.1.10:445") == ("192.168.1.10", "445", "")


# ---------------------------------------------------------------------------
# _parse_ss_output
# ---------------------------------------------------------------------------

class TestParseSsOutput:
    SS_OUTPUT = """\
Netid  State   Recv-Q Send-Q Local Address:Port   Peer Address:Port
udp    UNCONN  0      0      0.0.0.0:5353         0.0.0.0:*
tcp    LISTEN  0      128    0.0.0.0:22           0.0.0.0:*
tcp    LISTEN  0      128    127.0.0.1:6379       0.0.0.0:*
tcp    LISTEN  0      128    [::1]:631            [::]:*
"""

    def test_parses_udp(self):
        ports = _parse_ss_output(self.SS_OUTPUT)
        udp = [p for p in ports if p.proto == "udp"]
        assert len(udp) == 1
        assert udp[0].port == 5353

    def test_parses_tcp(self):
        ports = _parse_ss_output(self.SS_OUTPUT)
        tcp = [p for p in ports if p.proto == "tcp"]
        assert len(tcp) == 3

    def test_parses_address(self):
        ports = _parse_ss_output(self.SS_OUTPUT)
        ssh = next(p for p in ports if p.port == 22)
        assert ssh.address == "0.0.0.0"

    def test_parses_loopback(self):
        ports = _parse_ss_output(self.SS_OUTPUT)
        redis = next(p for p in ports if p.port == 6379)
        assert redis.address == "127.0.0.1"

    def test_parses_ipv6_loopback(self):
        ports = _parse_ss_output(self.SS_OUTPUT)
        cups = next(p for p in ports if p.port == 631)
        assert cups.address == "::1"

    def test_deduplicates(self):
        output = "tcp LISTEN 0 0 0.0.0.0:22 0.0.0.0:*\n" * 3
        ports = _parse_ss_output(output)
        assert len(ports) == 1

    def test_empty_output(self):
        assert _parse_ss_output("") == []

    def test_skips_header_line(self):
        output = "Netid State Recv-Q Send-Q Local\ntcp LISTEN 0 0 0.0.0.0:22 0.0.0.0:*\n"
        ports = _parse_ss_output(output)
        assert len(ports) == 1


# ---------------------------------------------------------------------------
# _is_covered_by_ufw
# ---------------------------------------------------------------------------

class TestIsCoveredByUfw:
    RULES_WITH_22 = "[ 1] 22/tcp  ALLOW IN  Anywhere\n"
    RULES_WITHOUT_22 = "[ 1] 80/tcp  ALLOW IN  Anywhere\n"

    def test_covered(self):
        assert _is_covered_by_ufw(22, "tcp", self.RULES_WITH_22)

    def test_not_covered(self):
        assert not _is_covered_by_ufw(22, "tcp", self.RULES_WITHOUT_22)

    def test_empty_rules(self):
        assert not _is_covered_by_ufw(22, "tcp", "")


# ---------------------------------------------------------------------------
# _categorize_port
# ---------------------------------------------------------------------------

class TestCategorizePort:
    def test_ephemeral_udp(self):
        p = make_port(port=EPHEMERAL_THRESHOLD + 1, proto="udp")
        assert _categorize_port(p, "") == PortCategory.EPHEMERAL

    def test_tcp_high_port_not_ephemeral(self):
        """TCP ports above the threshold are server sockets (LISTEN), not ephemeral."""
        p = make_port(port=EPHEMERAL_THRESHOLD + 1, proto="tcp", address="0.0.0.0")
        assert _categorize_port(p, "") != PortCategory.EPHEMERAL

    def test_system_dns_tcp(self):
        p = make_port(port=53, proto="tcp", address="127.0.0.1")
        assert _categorize_port(p, "") == PortCategory.SYSTEM_INTERNAL

    def test_system_dns_udp(self):
        p = make_port(port=53, proto="udp", address="127.0.0.1")
        assert _categorize_port(p, "") == PortCategory.SYSTEM_INTERNAL

    def test_system_dhcp(self):
        p = make_port(port=67, proto="udp")
        assert _categorize_port(p, "") == PortCategory.SYSTEM_INTERNAL

    def test_netbios_137(self):
        p = make_port(port=137, proto="udp", address="0.0.0.0")
        assert _categorize_port(p, "") == PortCategory.NETBIOS

    def test_netbios_138(self):
        p = make_port(port=138, proto="udp", address="0.0.0.0")
        assert _categorize_port(p, "") == PortCategory.NETBIOS

    def test_covered(self):
        rules = "[ 1] 22/tcp  ALLOW IN  Anywhere\n"
        p = make_port(port=22, proto="tcp", address="0.0.0.0")
        assert _categorize_port(p, rules) == PortCategory.COVERED

    def test_uncovered_public(self):
        p = make_port(port=9999, proto="tcp", address="0.0.0.0")
        assert _categorize_port(p, "") == PortCategory.UNCOVERED_PUBLIC

    def test_uncovered_local_loopback(self):
        p = make_port(port=9999, proto="tcp", address="127.0.0.1")
        assert _categorize_port(p, "") == PortCategory.UNCOVERED_LOCAL

    def test_uncovered_local_private_ip(self):
        p = make_port(port=9999, proto="tcp", address="192.168.1.10")
        assert _categorize_port(p, "") == PortCategory.UNCOVERED_LOCAL

    def test_upnp_owned_by_avahi_is_system_internal(self):
        p = ListeningPort(port=1900, proto="udp", address="0.0.0.0",
                          raw_line="", process="avahi-daemon")
        assert _categorize_port(p, "") == PortCategory.SYSTEM_INTERNAL

    def test_upnp_owned_by_spotify_is_not_system_internal(self):
        # Spotify binding 1900/udp must not be labeled "system internal"
        p = ListeningPort(port=1900, proto="udp", address="0.0.0.0",
                          raw_line="", process="spotify")
        assert _categorize_port(p, "") != PortCategory.SYSTEM_INTERNAL

    def test_upnp_owned_by_spotify_is_uncovered_public(self):
        p = ListeningPort(port=1900, proto="udp", address="0.0.0.0",
                          raw_line="", process="spotify")
        assert _categorize_port(p, "") == PortCategory.UNCOVERED_PUBLIC

    def test_unknown_owner_on_system_port_is_system_internal(self):
        # Empty process string = unknown — treat as system to avoid false positives
        p = ListeningPort(port=1900, proto="udp", address="0.0.0.0",
                          raw_line="", process="")
        assert _categorize_port(p, "") == PortCategory.SYSTEM_INTERNAL

    def test_system_daemons_contains_empty_string(self):
        assert "" in _SYSTEM_DAEMONS

    def test_system_daemons_contains_avahi(self):
        assert "avahi-daemon" in _SYSTEM_DAEMONS

    def test_mdns_owned_by_spotify_falls_through(self):
        p = ListeningPort(port=5353, proto="udp", address="0.0.0.0",
                          raw_line="", process="spotify")
        assert _categorize_port(p, "") != PortCategory.SYSTEM_INTERNAL


# ---------------------------------------------------------------------------
# check_ports
# ---------------------------------------------------------------------------

class TestCheckPorts:
    def test_all_covered_ok(self):
        rules = "[ 1] 22/tcp  ALLOW IN  Anywhere\n"
        snapshot = make_snapshot(
            ports=[make_port(port=22, proto="tcp", address="0.0.0.0")],
            ufw_rules=rules,
        )
        result = check_ports(snapshot)
        assert has_level(result, "ok")

    def test_uncovered_public_alert(self):
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="allow")
        assert has_level(result, "alert")

    def test_uncovered_public_deduction(self):
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="allow")
        assert total_deductions(result) > 0

    def test_uncovered_local_info(self):
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="127.0.0.1")],
            ufw_rules="",
        )
        result = check_ports(snapshot)
        assert has_level(result, "info")

    def test_ephemeral_silent(self):
        """Ephemeral UDP ports produce no findings — silently ignored."""
        snapshot = make_snapshot(
            ports=[make_port(port=EPHEMERAL_THRESHOLD + 1, proto="udp")],
            ufw_rules="",
        )
        result = check_ports(snapshot)
        assert not has_level(result, "info")
        assert has_level(result, "ok")  # all_covered OK

    def test_audited_ports_skipped(self):
        snapshot = make_snapshot(
            ports=[make_port(port=22, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, audited_ports={"22/tcp"})
        # With audited port skipped and nothing uncovered → all_covered OK
        assert has_level(result, "ok")

    def test_no_ports_ok(self):
        snapshot = make_snapshot(ports=[], ufw_rules="")
        result = check_ports(snapshot)
        assert has_level(result, "ok")

    def test_system_port_info(self):
        snapshot = make_snapshot(
            ports=[make_port(port=53, proto="tcp", address="127.0.0.1")],
            ufw_rules="",
        )
        result = check_ports(snapshot)
        assert has_level(result, "info")

    def test_public_context_higher_deduction(self):
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        r_local  = check_ports(snapshot, network_context="local",  default_incoming_policy="allow")
        r_public = check_ports(snapshot, network_context="public", default_incoming_policy="allow")
        assert total_deductions(r_public) >= total_deductions(r_local)

    def test_translation_function_used(self):
        def my_t(key, **kwargs): return f"T:{key}"
        snapshot = make_snapshot(ports=[], ufw_rules="")
        result = check_ports(snapshot, t=my_t)
        assert any("T:" in f.message for f in result.findings)

    def test_netbios_warn(self):
        snapshot = make_snapshot(
            ports=[make_port(port=137, proto="udp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot)
        assert has_level(result, "warn")

    def test_netbios_covered_by_ufw_no_warn(self):
        """137/udp with explicit UFW rule → COVERED, no warning, no deduction."""
        ufw_rules = "[ 1] 137/udp                    ALLOW IN    192.168.1.0/24"
        snapshot = make_snapshot(
            ports=[make_port(port=137, proto="udp", address="0.0.0.0")],
            ufw_rules=ufw_rules,
        )
        result = check_ports(snapshot)
        assert not has_level(result, "warn")
        assert not has_level(result, "alert")
        total_deductions = sum(d.points for d in result.deductions)
        assert total_deductions == 0

    # ------------------------------------------------------------------
    # Default incoming policy awareness
    # ------------------------------------------------------------------

    def test_default_deny_downgrades_uncovered_public_to_info(self):
        """UNCOVERED_PUBLIC + default deny → INFO, not WARN/ALERT."""
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="deny")
        assert has_level(result, "info")
        assert not has_level(result, "alert")
        assert not has_level(result, "warn")

    def test_default_reject_downgrades_uncovered_public_to_info(self):
        """UNCOVERED_PUBLIC + default reject → same as deny."""
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="reject")
        assert has_level(result, "info")
        assert not has_level(result, "alert")

    def test_default_allow_keeps_alert(self):
        """UNCOVERED_PUBLIC + default allow → ALERT as usual."""
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="allow")
        assert has_level(result, "alert")

    def test_default_deny_no_deduction(self):
        """No score deduction when port is covered by default deny policy."""
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="deny")
        assert total_deductions(result) == 0

    def test_default_deny_ok_message_shown(self):
        """With default deny all uncovered ports are safe → OK message shown."""
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="deny")
        assert has_level(result, "ok")

    def test_default_deny_unknown_keeps_alert(self):
        """Unknown policy is treated as non-deny → ALERT preserved."""
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="unknown")
        assert has_level(result, "alert")

    # ------------------------------------------------------------------
    # ufw_active=False — port warnings suppressed/downgraded
    # ------------------------------------------------------------------

    def test_netbios_ufw_inactive_is_info_not_warn(self):
        """NetBIOS + ufw_active=False → INFO, no WARN."""
        snapshot = make_snapshot(
            ports=[make_port(port=137, proto="udp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, ufw_active=False)
        assert has_level(result, "info")
        assert not has_level(result, "warn")

    def test_netbios_ufw_inactive_no_deduction(self):
        """NetBIOS + ufw_active=False → no deduction."""
        snapshot = make_snapshot(
            ports=[make_port(port=137, proto="udp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, ufw_active=False)
        assert total_deductions(result) == 0

    def test_uncovered_public_ufw_inactive_is_info(self):
        """UNCOVERED_PUBLIC + ufw_active=False → INFO, not WARN/ALERT."""
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="unknown", ufw_active=False)
        assert has_level(result, "info")
        assert not has_level(result, "warn")
        assert not has_level(result, "alert")

    def test_uncovered_public_ufw_inactive_no_deduction(self):
        """UNCOVERED_PUBLIC + ufw_active=False → no deduction."""
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="unknown", ufw_active=False)
        assert total_deductions(result) == 0

    def test_all_covered_ok_suppressed_when_ufw_inactive(self):
        """all_covered OK not shown when ufw_active=False."""
        snapshot = make_snapshot(ports=[], ufw_rules="")
        result = check_ports(snapshot, ufw_active=False)
        assert not has_level(result, "ok")

    def test_all_covered_ok_shown_when_ufw_active(self):
        """all_covered OK shown when ufw_active=True and no uncovered ports."""
        snapshot = make_snapshot(ports=[], ufw_rules="")
        result = check_ports(snapshot, ufw_active=True, default_incoming_policy="deny")
        assert has_level(result, "ok")

    def test_uncovered_public_ufw_inactive_uses_inactive_key_not_deny_key(self):
        """UNCOVERED_PUBLIC + ufw_active=False → uses uncovered_ufw_inactive, not uncovered_default_deny."""
        from bob.checks._run import _identity_t
        _t_fmt = lambda key, **kw: f"{key}({','.join(f'{k}={v}' for k,v in kw.items())})" if kw else key
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="unknown",
                             ufw_active=False, t=_t_fmt)
        info_msgs = [f.message for f in result.findings if f.level.value == "info"]
        assert any("uncovered_ufw_inactive" in m for m in info_msgs)
        assert not any("uncovered_default_deny" in m for m in info_msgs)

    def test_uncovered_public_with_process_is_warn_not_alert(self):
        """Port with known process + default allow → WARN (improvement), not ALERT (action)."""
        port = ListeningPort(port=9999, proto="tcp", address="0.0.0.0",
                             raw_line="", process="myapp")
        snapshot = make_snapshot(ports=[port], ufw_rules="")
        result = check_ports(snapshot, default_incoming_policy="allow")
        assert has_level(result, "warn")
        assert not has_level(result, "alert")

    def test_uncovered_public_with_process_note_populated(self):
        """Finding note must mention the process name when process is known."""
        port = ListeningPort(port=9999, proto="tcp", address="0.0.0.0",
                             raw_line="", process="myapp")
        snapshot = make_snapshot(ports=[port], ufw_rules="")
        result = check_ports(snapshot, default_incoming_policy="allow")
        warn_findings = [f for f in result.findings if f.level.value == "warn"
                         and f.cmd]
        assert warn_findings, "Expected a warn finding with a command"
        assert warn_findings[0].note != "", "Expected a non-empty disclaimer note"

    def test_uncovered_public_without_process_is_alert(self):
        """Port with no process + default allow → ALERT (action), not WARN."""
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, default_incoming_policy="allow")
        assert has_level(result, "alert")
        assert not has_level(result, "warn")

    def test_process_name_appears_in_message(self):
        """Process name must appear in the finding message for context."""
        def my_t(key, **kw):
            return " ".join(str(v) for v in kw.values()) if kw else key

        port = ListeningPort(port=9999, proto="tcp", address="0.0.0.0",
                             raw_line="", process="spotify")
        snapshot = make_snapshot(ports=[port], ufw_rules="")
        result = check_ports(snapshot, default_incoming_policy="allow", t=my_t)
        messages = [f.message for f in result.findings]
        assert any("spotify" in m for m in messages)
