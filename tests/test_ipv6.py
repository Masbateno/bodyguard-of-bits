"""
Unit tests for bob.checks.ipv6 module.

All tests use IPv6Snapshot instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_ipv6.py -v
"""

from __future__ import annotations

import pytest
from bob.checks.ipv6 import (
    IPv6Snapshot,
    _extract_ipv6_listeners,
    _extract_ufw_v6_covered,
    _read_global_ipv6,
    check_ipv6,
)
from tests.helpers import _levels, _t

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_snapshot(**overrides) -> IPv6Snapshot:
    """Return a clean (fully consistent) IPv6Snapshot with optional overrides."""
    defaults = dict(
        kernel_ipv6_enabled=True,
        ufw_ipv6_enabled=True,
        ipv6_listeners=["22/tcp", "80/tcp"],
        ufw_v6_covered=["22/tcp", "80/tcp"],
        has_global_ipv6=True,
    )
    defaults.update(overrides)
    return IPv6Snapshot(**defaults)


def has_level(result, level: str) -> bool:
    return level in _levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# Clean system — all covered
# ---------------------------------------------------------------------------

class TestCleanSystem:
    def test_ok_when_all_covered(self):
        result = check_ipv6(make_snapshot(), t=_t)
        assert has_level(result, "ok")

    def test_no_deductions_when_all_covered(self):
        result = check_ipv6(make_snapshot(), t=_t)
        assert total_deductions(result) == 0

    def test_no_warn_when_all_covered(self):
        result = check_ipv6(make_snapshot(), t=_t)
        assert not has_level(result, "warn")

    def test_no_listeners_no_warn(self):
        """No IPv6 listeners at all — clean."""
        snap = make_snapshot(ipv6_listeners=[], ufw_v6_covered=[])
        result = check_ipv6(snap, t=_t)
        assert not has_level(result, "warn")
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# Kernel / UFW mismatch
# ---------------------------------------------------------------------------

class TestKernelUfwMismatch:
    def test_info_when_ufw_enabled_kernel_disabled(self):
        """UFW thinks IPv6 is active but kernel has it off — INFO, no deduction."""
        snap = make_snapshot(kernel_ipv6_enabled=False, ufw_ipv6_enabled=True)
        result = check_ipv6(snap, t=_t)
        assert has_level(result, "info")

    def test_no_deduction_ufw_enabled_kernel_disabled(self):
        snap = make_snapshot(kernel_ipv6_enabled=False, ufw_ipv6_enabled=True)
        result = check_ipv6(snap, t=_t)
        assert total_deductions(result) == 0

    def test_no_warn_ufw_enabled_kernel_disabled(self):
        snap = make_snapshot(kernel_ipv6_enabled=False, ufw_ipv6_enabled=True)
        result = check_ipv6(snap, t=_t)
        assert not has_level(result, "warn")

    def test_ok_both_disabled(self):
        snap = make_snapshot(
            kernel_ipv6_enabled=False,
            ufw_ipv6_enabled=False,
            ipv6_listeners=[],
            ufw_v6_covered=[],
        )
        result = check_ipv6(snap, t=_t)
        assert has_level(result, "ok")
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# UFW IPv6 disabled + listeners present
# ---------------------------------------------------------------------------

class TestUfwDisabledWithListeners:
    def test_warn_when_ufw_disabled_listeners_present(self):
        snap = make_snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=False,
            ipv6_listeners=["22/tcp", "80/tcp"],
        )
        result = check_ipv6(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_ufw_disabled_listeners_present(self):
        snap = make_snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=False,
            ipv6_listeners=["22/tcp"],
        )
        result = check_ipv6(snap, t=_t)
        assert total_deductions(result) == 2

    def test_listeners_listed_in_detail(self):
        captured = {}

        def _capture(key, **kwargs):
            captured[key] = kwargs
            return key

        snap = make_snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=False,
            ipv6_listeners=["22/tcp", "80/tcp"],
        )
        check_ipv6(snap, t=_capture)
        ports = captured.get("ipv6.listeners_list", {}).get("ports", "")
        assert "22/tcp" in ports
        assert "80/tcp" in ports

    def test_count_passed_to_t(self):
        received = {}

        def _capture(key, **kwargs):
            if "count" in kwargs:
                received.update(kwargs)
            return key

        snap = make_snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=False,
            ipv6_listeners=["22/tcp", "443/tcp"],
        )
        check_ipv6(snap, t=_capture)
        assert received.get("count") == 2

    def test_info_when_ufw_disabled_no_listeners(self):
        snap = make_snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=False,
            ipv6_listeners=[],
        )
        result = check_ipv6(snap, t=_t)
        assert has_level(result, "info")
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# Per-port gap detection
# ---------------------------------------------------------------------------

class TestPerPortGap:
    def test_warn_on_uncovered_ipv6_port(self):
        snap = make_snapshot(
            ipv6_listeners=["22/tcp", "8080/tcp"],
            ufw_v6_covered=["22/tcp"],  # 8080 not covered
        )
        result = check_ipv6(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_on_uncovered_ipv6_port(self):
        snap = make_snapshot(
            ipv6_listeners=["8080/tcp"],
            ufw_v6_covered=[],
        )
        result = check_ipv6(snap, t=_t)
        assert total_deductions(result) == 1

    def test_port_passed_to_t(self):
        received = {}

        def _capture(key, **kwargs):
            if key == "ipv6.port_no_v6_rule":
                received.update(kwargs)
            return key

        snap = make_snapshot(
            ipv6_listeners=["8080/tcp"],
            ufw_v6_covered=[],
        )
        check_ipv6(snap, t=_capture)
        assert received.get("port") == "8080/tcp"

    def test_no_warn_when_port_covered(self):
        snap = make_snapshot(
            ipv6_listeners=["22/tcp"],
            ufw_v6_covered=["22/tcp"],
        )
        result = check_ipv6(snap, t=_t)
        assert not has_level(result, "warn")

    def test_deductions_capped_at_three(self):
        """More than 3 uncovered ports must not exceed 3 points of deduction."""
        snap = make_snapshot(
            ipv6_listeners=["80/tcp", "443/tcp", "8080/tcp", "8443/tcp", "3000/tcp"],
            ufw_v6_covered=[],
        )
        result = check_ipv6(snap, t=_t)
        assert total_deductions(result) == 3

    def test_warn_count_matches_uncovered_ports(self):
        snap = make_snapshot(
            ipv6_listeners=["80/tcp", "443/tcp", "8080/tcp"],
            ufw_v6_covered=["80/tcp"],
        )
        result = check_ipv6(snap, t=_t)
        warn_count = sum(1 for f in result.findings if f.level.value == "warn")
        assert warn_count == 2

    def test_no_deductions_when_no_uncovered(self):
        snap = make_snapshot(
            ipv6_listeners=["22/tcp", "443/tcp"],
            ufw_v6_covered=["22/tcp", "443/tcp"],
        )
        result = check_ipv6(snap, t=_t)
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# _extract_ipv6_listeners
# ---------------------------------------------------------------------------

class TestExtractIPv6Listeners:
    SS_OUTPUT = (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
        "tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*\n"
        "tcp   LISTEN 0      128    [::]:22             [::]:*\n"
        "tcp   LISTEN 0      128    [::]:80             [::]:*\n"
        "udp   UNCONN 0      0      [::]:5353           [::]:*\n"
        "tcp   LISTEN 0      128    127.0.0.1:5432      0.0.0.0:*\n"
    )

    def test_detects_ipv6_wildcard_tcp(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT)
        assert "22/tcp" in result

    def test_detects_ipv6_wildcard_udp(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT)
        assert "5353/udp" in result

    def test_does_not_include_ipv4(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT)
        # 0.0.0.0:22 is IPv4 — should not appear
        assert "22/tcp" in result  # from [::]:22 — but only once
        assert len([p for p in result if p == "22/tcp"]) == 1

    def test_does_not_include_loopback(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT)
        assert "5432/tcp" not in result

    def test_empty_string_returns_empty(self):
        assert _extract_ipv6_listeners("") == set()

    def test_multiple_ipv6_ports(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT)
        assert "80/tcp" in result
        assert "22/tcp" in result

    # --- Internal-process filtering (ss -tulnp output) ---

    SS_OUTPUT_WITH_PROC = (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
        'tcp   LISTEN 0      128    [::]:22    [::]:*    users:(("sshd",pid=972,fd=4))\n'
        'tcp   LISTEN 0      511    [::]:80    [::]:*    users:(("nginx",pid=100,fd=5))\n'
        'udp   UNCONN 0      0      [::]:5353  [::]:*    users:(("avahi-daemon",pid=709,fd=13))\n'
        'udp   UNCONN 0      0      [::]:35839 [::]:*    users:(("avahi-daemon",pid=709,fd=15))\n'
        'udp   UNCONN 0      0      [::]:53    [::]:*    users:(("systemd-resolve",pid=454,fd=17))\n'
        'tcp   LISTEN 0      4096   [::]:44707 [::]:*    users:(("containerd",pid=962,fd=15))\n'
    )

    def test_avahi_secondary_port_filtered(self):
        """avahi-daemon secondary ports must not appear in listeners."""
        result = _extract_ipv6_listeners(self.SS_OUTPUT_WITH_PROC)
        assert "35839/udp" not in result

    def test_avahi_mdns_port_filtered(self):
        """avahi-daemon is fully internal — 5353 also excluded."""
        result = _extract_ipv6_listeners(self.SS_OUTPUT_WITH_PROC)
        assert "5353/udp" not in result

    def test_systemd_resolve_filtered(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT_WITH_PROC)
        assert "53/udp" not in result

    def test_containerd_filtered(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT_WITH_PROC)
        assert "44707/tcp" not in result

    def test_legitimate_services_not_filtered(self):
        """sshd and nginx are NOT internal — must be included."""
        result = _extract_ipv6_listeners(self.SS_OUTPUT_WITH_PROC)
        assert "22/tcp" in result
        assert "80/tcp" in result

    def test_no_proc_info_includes_port(self):
        """Lines without users:((…)) info are included (backward compat)."""
        line = "udp   UNCONN 0      0      [::]:35839 [::]:*\n"
        result = _extract_ipv6_listeners(line)
        assert "35839/udp" in result


# ---------------------------------------------------------------------------
# _extract_ufw_v6_covered
# ---------------------------------------------------------------------------

class TestExtractUfwV6Covered:
    UFW_OUTPUT = (
        "Status: active\n"
        "\n"
        "     To                         Action      From\n"
        "     --                         ------      ----\n"
        "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
        "[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n"
        "[ 3] 80/tcp                     ALLOW IN    Anywhere\n"
        "[ 4] 80/tcp (v6)                ALLOW IN    Anywhere (v6)\n"
        "[ 5] 8080/tcp                   ALLOW IN    Anywhere\n"
    )

    def test_detects_v6_rule_for_22(self):
        result = _extract_ufw_v6_covered(self.UFW_OUTPUT)
        assert "22/tcp" in result

    def test_detects_v6_rule_for_80(self):
        result = _extract_ufw_v6_covered(self.UFW_OUTPUT)
        assert "80/tcp" in result

    def test_does_not_include_ipv4_only_rule(self):
        result = _extract_ufw_v6_covered(self.UFW_OUTPUT)
        assert "8080/tcp" not in result

    def test_empty_string_returns_empty(self):
        assert _extract_ufw_v6_covered("") == set()

    def test_ufw_disabled_output(self):
        assert _extract_ufw_v6_covered("Status: inactive\n") == set()

    def test_proto_defaults_to_tcp(self):
        """Rules with no explicit proto default to tcp."""
        output = "[ 1] 443 (v6)                   ALLOW IN    Anywhere (v6)\n"
        result = _extract_ufw_v6_covered(output)
        assert "443/tcp" in result

    def test_malformed_ss_output_returns_empty(self):
        assert _extract_ipv6_listeners("???") == set()

    def test_malformed_ufw_lines_returns_empty(self):
        assert _extract_ufw_v6_covered("[ x] invalid line") == set()


# ---------------------------------------------------------------------------
# _read_global_ipv6 — unit tests for the ip -6 addr parser
# ---------------------------------------------------------------------------

class TestReadGlobalIPv6:
    """Tests for the _read_global_ipv6() parser (called with fake ip output)."""

    def _parse(self, output: str) -> bool:
        """Monkey-patch _run so _read_global_ipv6 uses our fake output."""
        import bob.checks.ipv6 as mod
        original = mod._run

        def fake_run(*_args, **_kwargs):
            return output

        mod._run = fake_run
        try:
            return _read_global_ipv6()
        finally:
            mod._run = original

    def test_global_unicast_detected(self):
        output = "    inet6 2001:db8::1/64 scope global dynamic\n"
        assert self._parse(output)

    def test_3000_prefix_is_global(self):
        output = "    inet6 3ffe:501::/32 scope global\n"
        assert self._parse(output)

    def test_loopback_not_global(self):
        output = "    inet6 ::1/128 scope host\n"
        assert not self._parse(output)

    def test_link_local_not_global(self):
        output = "    inet6 fe80::1/64 scope link\n"
        assert not self._parse(output)

    def test_ula_fc_not_global(self):
        output = "    inet6 fc00::1/7 scope global\n"
        assert not self._parse(output)

    def test_ula_fd_not_global(self):
        output = "    inet6 fd12:3456:789a::1/48 scope global\n"
        assert not self._parse(output)

    def test_mixed_only_link_local(self):
        output = (
            "    inet6 ::1/128 scope host\n"
            "    inet6 fe80::a1b2:c3d4/64 scope link\n"
        )
        assert not self._parse(output)

    def test_mixed_global_wins(self):
        output = (
            "    inet6 fe80::1/64 scope link\n"
            "    inet6 2001:db8::42/64 scope global\n"
        )
        assert self._parse(output)

    def test_empty_output_returns_false(self):
        assert not self._parse("")

    def test_no_inet6_lines_returns_false(self):
        assert not self._parse("    inet 192.168.1.1/24 brd 192.168.1.255 scope global eth0\n")


# ---------------------------------------------------------------------------
# UFW disabled + link-local only (no global IPv6)
# ---------------------------------------------------------------------------

class TestUfwDisabledLinkLocalOnly:
    """When UFW IPv6 is disabled but the machine has no global IPv6 address,
    the finding is INFO (not WARN) with no deduction — link-local listeners
    are not reachable from the internet."""

    def _snap(self, listeners=None):
        return make_snapshot(
            ufw_ipv6_enabled=False,
            has_global_ipv6=False,
            ipv6_listeners=listeners if listeners is not None else ["22/tcp", "80/tcp"],
            ufw_v6_covered=[],
        )

    def test_is_info_not_warn(self):
        result = check_ipv6(self._snap(), t=_t)
        assert has_level(result, "info")
        assert not has_level(result, "warn")

    def test_no_deduction(self):
        result = check_ipv6(self._snap(), t=_t)
        assert total_deductions(result) == 0

    def test_key_is_link_local(self):
        result = check_ipv6(self._snap(), t=_t)
        keys = [f.key for f in result.findings]
        assert "ipv6.ufw_disabled_listeners_link_local" in keys

    def test_listeners_in_detail(self):
        captured = {}

        def _cap(key, **kwargs):
            captured[key] = kwargs
            return key

        check_ipv6(self._snap(["22/tcp", "443/tcp"]), t=_cap)
        ports = captured.get("ipv6.listeners_list", {}).get("ports", "")
        assert "22/tcp" in ports
        assert "443/tcp" in ports

    def test_count_passed_to_t(self):
        received = {}

        def _cap(key, **kwargs):
            if "count" in kwargs:
                received.update(kwargs)
            return key

        check_ipv6(self._snap(["22/tcp", "80/tcp", "443/tcp"]), t=_cap)
        assert received.get("count") == 3

    def test_global_ipv6_true_still_warns(self):
        snap = make_snapshot(
            ufw_ipv6_enabled=False,
            has_global_ipv6=True,
            ipv6_listeners=["22/tcp"],
            ufw_v6_covered=[],
        )
        result = check_ipv6(snap, t=_t)
        assert has_level(result, "warn")
        assert total_deductions(result) == 2

    def test_global_ipv6_true_key_is_present(self):
        snap = make_snapshot(
            ufw_ipv6_enabled=False,
            has_global_ipv6=True,
            ipv6_listeners=["22/tcp"],
            ufw_v6_covered=[],
        )
        result = check_ipv6(snap, t=_t)
        keys = [f.key for f in result.findings]
        assert "ipv6.ufw_disabled_listeners_present" in keys


# ---------------------------------------------------------------------------
# check_ipv6 — ufw_active=False contextualization
# ---------------------------------------------------------------------------

class TestUfwInactiveIPv6:
    def _snap(self):
        return make_snapshot(
            ufw_ipv6_enabled=False,
            has_global_ipv6=True,
            ipv6_listeners=["22/tcp"],
            ufw_v6_covered=[],
        )

    def test_global_ipv6_ufw_inactive_is_info_not_warn(self):
        result = check_ipv6(self._snap(), ufw_active=False, t=_t)
        assert "info" in _levels(result)
        assert "warn" not in _levels(result)

    def test_global_ipv6_ufw_inactive_no_deduction(self):
        result = check_ipv6(self._snap(), ufw_active=False, t=_t)
        assert total_deductions(result) == 0

    def test_global_ipv6_ufw_inactive_key_still_present(self):
        result = check_ipv6(self._snap(), ufw_active=False, t=_t)
        keys = [f.key for f in result.findings]
        assert "ipv6.ufw_disabled_listeners_present" in keys

    def test_global_ipv6_ufw_active_still_warns(self):
        result = check_ipv6(self._snap(), ufw_active=True, t=_t)
        assert "warn" in _levels(result)
        assert total_deductions(result) == 2
