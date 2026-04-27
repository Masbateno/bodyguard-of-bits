"""Tests for bob.exposure — real exposure view."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from bob.exposure import ExposureItem, compute_exposure
from bob.scoring import FindingLevel, Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _t(key: str, **kwargs) -> str:
    assert isinstance(key, str)
    return key.format(**kwargs) if kwargs else key


class FakeEngine:
    def __init__(self, *key_level_pairs):
        self.findings = [
            Finding(level=lvl, message="msg", key=k)
            for k, lvl in key_level_pairs
        ]


def _make_engine(*key_level_pairs) -> FakeEngine:
    return FakeEngine(*key_level_pairs)


@dataclass
class _FakeListeningPort:
    port: int
    proto: str
    address: str
    iface: str = ""
    raw_line: str = ""
    process: str = ""

    @property
    def port_proto(self) -> str:
        return f"{self.port}/{self.proto}"

    @property
    def is_all_interfaces(self) -> bool:
        return self.address in ("0.0.0.0", "::") and not self.iface

    @property
    def is_loopback(self) -> bool:
        return self.address in ("127.0.0.1", "::1")


class _FakePortsSnapshot:
    def __init__(self, ports):
        self.ports = ports


def _make_ports(*port_proto_addr) -> _FakePortsSnapshot:
    """Build a fake PortsSnapshot. Each arg is (port, proto, addr)."""
    return _FakePortsSnapshot([
        _FakeListeningPort(port=p, proto=pr, address=addr)
        for p, pr, addr in port_proto_addr
    ])


def _call(engine=None, ports=None, network_context="local",
          fw_active=True, fw_policy="deny"):
    if engine is None:
        engine = _make_engine()
    if ports is None:
        ports = _make_ports()
    return compute_exposure(engine, ports, network_context, fw_active, fw_policy, _t)


def _item(items, label_fragment: str) -> ExposureItem:
    for item in items:
        if label_fragment in item.label:
            return item
    raise KeyError(f"No item with label containing {label_fragment!r}")


# ---------------------------------------------------------------------------
# Internet exposure item
# ---------------------------------------------------------------------------

class TestInternetFacing:
    def test_public_is_alert(self):
        items = _call(network_context="public")
        item = _item(items, "internet_facing")
        assert item.color == "alert"
        assert item.icon == "✖"

    def test_local_is_ok(self):
        items = _call(network_context="local")
        item = _item(items, "internet_facing")
        assert item.color == "ok"
        assert item.icon == "✔"

    def test_ddns_warn_is_warn(self):
        engine = _make_engine(("ddns.warn", FindingLevel.WARN))
        items = _call(engine=engine, network_context="local")
        item = _item(items, "internet_facing")
        assert item.color == "warn"
        assert item.icon == "⚠"

    def test_ddns_warn_detail_contains_ddns(self):
        engine = _make_engine(("ddns.warn", FindingLevel.WARN))
        items = _call(engine=engine, network_context="local")
        item = _item(items, "internet_facing")
        assert "ddns" in item.detail.lower()

    def test_public_overrides_ddns(self):
        engine = _make_engine(("ddns.warn", FindingLevel.WARN))
        items = _call(engine=engine, network_context="public")
        item = _item(items, "internet_facing")
        assert item.color == "alert"


# ---------------------------------------------------------------------------
# Firewall item
# ---------------------------------------------------------------------------

class TestFirewallItem:
    def test_inactive_is_alert(self):
        items = _call(fw_active=False)
        item = _item(items, "firewall")
        assert item.color == "alert"
        assert item.icon == "✖"

    def test_allow_policy_is_alert(self):
        items = _call(fw_active=True, fw_policy="allow")
        item = _item(items, "firewall")
        assert item.color == "alert"

    def test_deny_policy_is_ok(self):
        items = _call(fw_active=True, fw_policy="deny")
        item = _item(items, "firewall")
        assert item.color == "ok"
        assert item.icon == "✔"

    def test_reject_policy_is_ok(self):
        items = _call(fw_active=True, fw_policy="reject")
        item = _item(items, "firewall")
        assert item.color == "ok"

    def test_policy_in_detail(self):
        items = _call(fw_active=True, fw_policy="deny")
        item = _item(items, "firewall")
        assert item.detail  # detail is non-empty when active


# ---------------------------------------------------------------------------
# Open ports item
# ---------------------------------------------------------------------------

class TestOpenPorts:
    def test_no_ports_is_ok(self):
        items = _call(ports=_make_ports())
        item = _item(items, "open_ports")
        assert item.color == "ok"
        assert item.icon == "✔"

    def test_port_on_loopback_not_counted(self):
        ports = _make_ports((22, "tcp", "127.0.0.1"))
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert item.color == "ok"

    def test_port_on_all_interfaces_counted(self):
        ports = _make_ports((22, "tcp", "0.0.0.0"))
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert "22/tcp" in item.detail

    def test_high_numbered_tcp_port_is_shown(self):
        # TCP LISTEN ports are always server sockets — shown regardless of number.
        ports = _make_ports((49152, "tcp", "0.0.0.0"))
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert "49152/tcp" in item.detail

    def test_high_numbered_udp_port_excluded(self):
        # UDP ports > 32767 are kernel-assigned ephemeral (client-side) sockets
        # — excluded from exposure, mirroring the check_ports() EPHEMERAL filter.
        ports = _make_ports((49152, "udp", "0.0.0.0"))
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert item.icon == "✔"  # no exposed ports

    def test_stable_ports_sorted(self):
        ports = _make_ports(
            (443, "tcp", "0.0.0.0"),
            (80, "tcp", "0.0.0.0"),
            (22, "tcp", "0.0.0.0"),
        )
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert item.detail == "22/tcp, 80/tcp, 443/tcp"

    def test_with_fw_inactive_port_is_alert(self):
        ports = _make_ports((22, "tcp", "0.0.0.0"))
        items = _call(ports=ports, fw_active=False)
        item = _item(items, "open_ports")
        assert item.color == "alert"

    def test_with_fw_active_port_is_warn(self):
        ports = _make_ports((22, "tcp", "0.0.0.0"))
        items = _call(ports=ports, fw_active=True, fw_policy="deny")
        item = _item(items, "open_ports")
        assert item.color == "warn"

    def test_with_fw_allow_policy_port_is_alert(self):
        ports = _make_ports((22, "tcp", "0.0.0.0"))
        items = _call(ports=ports, fw_active=True, fw_policy="allow")
        item = _item(items, "open_ports")
        assert item.color == "alert"

    def test_with_fw_unknown_policy_port_is_alert(self):
        ports = _make_ports((22, "tcp", "0.0.0.0"))
        items = _call(ports=ports, fw_active=True, fw_policy="unknown")
        item = _item(items, "open_ports")
        assert item.color == "alert"

    def test_port_32767_is_shown(self):
        ports = _make_ports((32767, "tcp", "0.0.0.0"))
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert "32767/tcp" in item.detail

    def test_port_32768_is_shown(self):
        # All-interfaces LISTEN ports are shown regardless of port number —
        # high-numbered listening ports (e.g. SSH on 49732) must appear.
        ports = _make_ports((32768, "tcp", "0.0.0.0"))
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert "32768/tcp" in item.detail

    def test_udp_port_32767_is_shown(self):
        # 32767/udp is the last UDP port below the ephemeral threshold — must appear.
        ports = _make_ports((32767, "udp", "0.0.0.0"))
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert "32767/udp" in item.detail

    def test_iface_scoped_port_not_exposed(self):
        # 0.0.0.0%virbr0 is bound to a specific bridge interface, not all interfaces.
        # dnsmasq/KVM ports like 67/udp%virbr0 must not appear in the attack surface.
        port = _FakeListeningPort(port=67, proto="udp", address="0.0.0.0", iface="virbr0")
        ports = _FakePortsSnapshot([port])
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert item.icon == "✔"  # no exposed ports

    def test_iface_scoped_tcp_port_not_exposed(self):
        # iface scoping applies to TCP too — not just UDP/dnsmasq.
        port = _FakeListeningPort(port=22, proto="tcp", address="0.0.0.0", iface="virbr0")
        ports = _FakePortsSnapshot([port])
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert item.icon == "✔"


# ---------------------------------------------------------------------------
# SSH item
# ---------------------------------------------------------------------------

class TestSshItem:
    def test_no_findings_is_ok(self):
        items = _call()
        item = _item(items, "ssh")
        assert item.color == "ok"

    def test_root_login_warn(self):
        engine = _make_engine(("ssh.permit_root_login", FindingLevel.WARN))
        items = _call(engine=engine)
        item = _item(items, "ssh")
        assert item.color in ("warn", "alert")
        assert "ssh_root" in item.detail

    def test_password_auth_warn(self):
        engine = _make_engine(("ssh.password_auth", FindingLevel.WARN))
        items = _call(engine=engine)
        item = _item(items, "ssh")
        assert "ssh_password" in item.detail

    def test_weak_ciphers_included(self):
        engine = _make_engine(("ssh.weak_ciphers", FindingLevel.WARN))
        items = _call(engine=engine)
        item = _item(items, "ssh")
        assert "ssh_weak_crypto" in item.detail

    def test_weak_kex_included(self):
        engine = _make_engine(("ssh.weak_kex", FindingLevel.WARN))
        items = _call(engine=engine)
        item = _item(items, "ssh")
        assert "ssh_weak_crypto" in item.detail

    def test_alert_level_makes_icon_x(self):
        engine = _make_engine(("ssh.permit_root_login", FindingLevel.ALERT))
        items = _call(engine=engine)
        item = _item(items, "ssh")
        assert item.icon == "✖"

    def test_not_installed_is_ok(self):
        engine = _make_engine(("ssh.not_installed", FindingLevel.WARN))
        items = _call(engine=engine)
        item = _item(items, "ssh")
        assert item.color == "ok"

    def test_not_installed_info_is_ok(self):
        # ssh.not_installed is emitted at INFO level — must still show "not running"
        engine = _make_engine(("ssh.not_installed", FindingLevel.INFO))
        items = _call(engine=engine)
        item = _item(items, "ssh")
        assert item.color == "ok"
        assert item.detail == _t("exposure.ssh_not_running")

    def test_not_installed_overrides_password_auth(self):
        engine = _make_engine(
            ("ssh.not_installed", FindingLevel.WARN),
            ("ssh.password_auth", FindingLevel.WARN),
        )
        items = _call(engine=engine)
        item = _item(items, "ssh")
        assert item.color == "ok"
        assert item.detail == _t("exposure.ssh_not_running")

    def test_info_findings_do_not_affect_ssh(self):
        engine = _make_engine(("ssh.password_auth", FindingLevel.INFO))
        items = _call(engine=engine)
        item = _item(items, "ssh")
        assert item.color == "ok"

    def test_multiple_issues_joined_with_dot(self):
        engine = _make_engine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("ssh.password_auth", FindingLevel.WARN),
        )
        items = _call(engine=engine)
        item = _item(items, "ssh")
        assert " · " in item.detail


# ---------------------------------------------------------------------------
# Brute-force item
# ---------------------------------------------------------------------------

class TestBruteForceItem:
    def test_ok_when_no_findings(self):
        items = _call()
        item = _item(items, "brute_force")
        assert item.color == "ok"

    def test_not_installed_is_warn(self):
        engine = _make_engine(("fail2ban.not_installed", FindingLevel.WARN))
        items = _call(engine=engine)
        item = _item(items, "brute_force")
        assert item.color == "warn"
        assert item.icon == "✖"

    def test_not_installed_info_is_warn(self):
        # fail2ban.not_installed is emitted at INFO level — must not show as active
        engine = _make_engine(("fail2ban.not_installed", FindingLevel.INFO))
        items = _call(engine=engine)
        item = _item(items, "brute_force")
        assert item.color == "warn"
        assert item.icon == "✖"

    def test_service_inactive_is_warn(self):
        engine = _make_engine(("fail2ban.service_inactive", FindingLevel.WARN))
        items = _call(engine=engine)
        item = _item(items, "brute_force")
        assert item.color == "warn"


# ---------------------------------------------------------------------------
# Security updates item
# ---------------------------------------------------------------------------

class TestUpdatesItem:
    def test_ok_when_no_findings(self):
        items = _call()
        item = _item(items, "updates")
        assert item.color == "ok"

    def test_pending_is_warn(self):
        engine = _make_engine(("updates.security_pending", FindingLevel.WARN))
        items = _call(engine=engine)
        item = _item(items, "updates")
        assert item.color == "warn"
        assert item.icon == "✖"


# ---------------------------------------------------------------------------
# General structure
# ---------------------------------------------------------------------------

class TestExposureStructure:
    def test_returns_list_of_exposure_items(self):
        items = _call()
        assert isinstance(items, list)
        for item in items:
            assert isinstance(item, ExposureItem)

    def test_always_six_items(self):
        items = _call()
        assert len(items) == 6

    def test_items_order(self):
        items = _call()
        labels = [item.label for item in items]
        assert labels == [
            _t("exposure.internet_facing"),
            _t("exposure.firewall"),
            _t("exposure.open_ports"),
            _t("exposure.ssh"),
            _t("exposure.brute_force"),
            _t("exposure.updates"),
        ]

    def test_all_items_have_labels(self):
        items = _call()
        for item in items:
            assert item.label

    def test_all_items_have_valid_color(self):
        items = _call()
        for item in items:
            assert item.color in ("ok", "warn", "alert")

    def test_all_items_have_valid_icon(self):
        items = _call()
        for item in items:
            assert item.icon in ("✔", "✖", "⚠")


# ---------------------------------------------------------------------------
# Port deduplication
# ---------------------------------------------------------------------------

class TestPortDeduplication:
    def test_same_port_on_ipv4_and_ipv6_appears_once(self):
        ports = _make_ports(
            (22, "tcp", "0.0.0.0"),
            (22, "tcp", "::"),
        )
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert item.detail.count("22/tcp") == 1

    def test_different_ports_both_appear(self):
        ports = _make_ports(
            (22, "tcp", "0.0.0.0"),
            (80, "tcp", "::"),
        )
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert "22/tcp" in item.detail
        assert "80/tcp" in item.detail

    def test_tcp_and_udp_same_port_appear_separately(self):
        ports = _make_ports(
            (22, "tcp", "0.0.0.0"),
            (22, "udp", "0.0.0.0"),
        )
        items = _call(ports=ports)
        item = _item(items, "open_ports")
        assert "22/tcp" in item.detail
        assert "22/udp" in item.detail


# ---------------------------------------------------------------------------
# Edge cases: fw_policy and network_context
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_fw_policy_none_does_not_crash(self):
        items = _call(fw_active=True, fw_policy=None)
        item = _item(items, "firewall")
        assert item.color == "alert"

    def test_unknown_policy_is_alert(self):
        items = _call(fw_active=True, fw_policy="unknown")
        item = _item(items, "firewall")
        assert item.color == "alert"
        assert item.icon == "✖"

    def test_network_context_unknown_is_ok(self):
        items = _call(network_context="weird_value")
        item = _item(items, "internet_facing")
        assert item.color == "ok"
        assert item.icon == "✔"


# ---------------------------------------------------------------------------
# SSH all three issues combined
# ---------------------------------------------------------------------------

class TestSshAllIssues:
    def test_root_password_weak_ciphers_all_in_detail(self):
        engine = _make_engine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("ssh.password_auth", FindingLevel.WARN),
            ("ssh.weak_ciphers", FindingLevel.WARN),
        )
        items = _call(engine=engine)
        item = _item(items, "ssh")
        assert "ssh_root" in item.detail
        assert "ssh_password" in item.detail
        assert "ssh_weak_crypto" in item.detail
        assert item.detail.count(" · ") == 2


# ---------------------------------------------------------------------------
# Icon/color invariant
# ---------------------------------------------------------------------------

class TestIconColorInvariant:
    def test_ok_always_checkmark(self):
        items = _call()
        for item in items:
            if item.color == "ok":
                assert item.icon == "✔"

    def test_alert_always_x(self):
        items = _call(network_context="public", fw_active=False)
        for item in items:
            if item.color == "alert":
                assert item.icon == "✖"

    def test_warn_never_checkmark(self):
        engine = _make_engine(("fail2ban.not_installed", FindingLevel.WARN))
        items = _call(engine=engine)
        for item in items:
            if item.color == "warn":
                assert item.icon != "✔"


# ---------------------------------------------------------------------------
# Fully exposed golden scenario
# ---------------------------------------------------------------------------

class TestFullyExposedScenario:
    def test_all_items_non_ok_when_fully_exposed(self):
        engine = _make_engine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("ssh.password_auth", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
            ("updates.security_pending", FindingLevel.WARN),
        )
        ports = _make_ports((22, "tcp", "0.0.0.0"))
        items = compute_exposure(
            engine, ports,
            network_context="public",
            fw_active=False,
            fw_policy="allow",
            t=_t,
        )
        assert len(items) == 6
        colors = [item.color for item in items]
        assert "ok" not in colors

    def test_no_ok_icon_when_fully_exposed(self):
        engine = _make_engine(
            ("ssh.permit_root_login", FindingLevel.WARN),
            ("ssh.password_auth", FindingLevel.WARN),
            ("fail2ban.not_installed", FindingLevel.WARN),
            ("updates.security_pending", FindingLevel.WARN),
        )
        ports = _make_ports((22, "tcp", "0.0.0.0"))
        items = compute_exposure(
            engine, ports,
            network_context="public",
            fw_active=False,
            fw_policy="allow",
            t=_t,
        )
        for item in items:
            assert item.icon != "✔"
