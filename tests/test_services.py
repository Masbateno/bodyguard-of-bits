"""
Unit tests for bob.checks.services module.

All tests build ServiceSnapshot instances directly — no subprocess calls.

Run with: python -m pytest tests/test_services.py -v
"""

from __future__ import annotations

import tempfile
import os
import pytest
from bob.checks.services import (
    Exposure,
    _auto_detect_port,
    ServiceSnapshot,
    ServiceState,
    _classify_exposure,
    check_services,
)
from bob.registry import Detection, Service
from bob.scoring import FindingLevel
from tests.helpers import _levels


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_service(
    id="ssh",
    label="SSH Server",
    packages=("openssh-server",),
    services=("ssh",),
    ports=("22/tcp",),
    risk="critical",
    detection=None,
) -> Service:
    if detection is None:
        detection = Detection(binary=(), snap=(), config_files=())
    return Service(
        id=id, label=label, packages=tuple(packages),
        services=tuple(services), ports=tuple(ports),
        risk=risk, detection=detection,
    )


def make_snapshot(
    service=None,
    state=ServiceState.ACTIVE_ENABLED,
    ports=None,
    exposures=None,
    install_via="dpkg",
) -> ServiceSnapshot:
    if service is None:
        service = make_service()
    if ports is None:
        ports = list(service.ports)
    if exposures is None:
        exposures = {p: Exposure.NO_RULE for p in ports}
    return ServiceSnapshot(
        service=service,
        installed=True,
        install_via=install_via,
        state=state,
        ports=ports,
        exposures=exposures,
    )


def has_level(result, level: str) -> bool:
    return level in _levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# ServiceState properties
# ---------------------------------------------------------------------------

class TestServiceState:
    def test_active_enabled_is_active(self):
        assert ServiceState.ACTIVE_ENABLED.is_active

    def test_active_disabled_is_active(self):
        assert ServiceState.ACTIVE_DISABLED.is_active

    def test_inactive_enabled_is_not_active(self):
        assert not ServiceState.INACTIVE_ENABLED.is_active

    def test_inactive_disabled_is_inactive(self):
        assert ServiceState.INACTIVE_DISABLED.is_inactive

    def test_unknown_not_active_not_inactive(self):
        assert not ServiceState.UNKNOWN.is_active
        assert not ServiceState.UNKNOWN.is_inactive


# ---------------------------------------------------------------------------
# _classify_exposure
# ---------------------------------------------------------------------------

class TestClassifyExposure:
    UFW_ALLOW_ANY = """
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""
    UFW_ALLOW_LOCAL = """
[ 1] 22/tcp                     ALLOW IN    192.168.1.0/24
"""
    UFW_DENY = """
[ 1] 22/tcp                     DENY IN     Anywhere
"""
    UFW_NO_RULE = """
[ 1] 80/tcp                     ALLOW IN    Anywhere
"""
    UFW_EMPTY = ""

    def test_open_world(self):
        assert _classify_exposure("22/tcp", self.UFW_ALLOW_ANY) == Exposure.OPEN_WORLD

    def test_open_local(self):
        assert _classify_exposure("22/tcp", self.UFW_ALLOW_LOCAL) == Exposure.OPEN_LOCAL

    def test_deny(self):
        assert _classify_exposure("22/tcp", self.UFW_DENY) == Exposure.DENY

    def test_no_rule(self):
        assert _classify_exposure("22/tcp", self.UFW_NO_RULE) == Exposure.NO_RULE

    def test_no_rule_empty_ufw(self):
        assert _classify_exposure("22/tcp", self.UFW_EMPTY) == Exposure.NO_RULE

    def test_private_range_10(self):
        rules = "[ 1] 22/tcp  ALLOW IN  10.0.0.0/8\n"
        assert _classify_exposure("22/tcp", rules) == Exposure.OPEN_LOCAL

    def test_private_range_172(self):
        rules = "[ 1] 22/tcp  ALLOW IN  172.16.0.0/12\n"
        assert _classify_exposure("22/tcp", rules) == Exposure.OPEN_LOCAL

    def test_deny_takes_precedence_over_allow_local(self):
        rules = (
            "[ 1] 22/tcp  DENY IN   Anywhere\n"
            "[ 2] 22/tcp  ALLOW IN  192.168.1.0/24\n"
        )
        # deny + local allow → DENY wins (no open world rule)
        result = _classify_exposure("22/tcp", rules)
        assert result == Exposure.DENY

    def test_udp_port(self):
        rules = "[ 1] 5353/udp  ALLOW IN  Anywhere\n"
        assert _classify_exposure("5353/udp", rules) == Exposure.OPEN_WORLD

    # CGNAT and IPv6 private ranges (regression for v0.21 fix)
    def test_cgnat_range(self):
        """ALLOW from CGNAT (100.64/10) → OPEN_LOCAL, not OPEN_WORLD."""
        rules = "[ 1] 22/tcp  ALLOW IN  100.64.0.0/10\n"
        assert _classify_exposure("22/tcp", rules) == Exposure.OPEN_LOCAL

    def test_cgnat_upper_bound(self):
        """100.127.x.x is still within CGNAT range → OPEN_LOCAL."""
        rules = "[ 1] 22/tcp  ALLOW IN  100.127.0.0/24\n"
        assert _classify_exposure("22/tcp", rules) == Exposure.OPEN_LOCAL

    def test_ipv6_ula_fc(self):
        """ALLOW from IPv6 ULA fc00::/7 → OPEN_LOCAL."""
        rules = "[ 1] 22/tcp  ALLOW IN  fc00::/7\n"
        assert _classify_exposure("22/tcp", rules) == Exposure.OPEN_LOCAL

    def test_ipv6_ula_fd(self):
        """ALLOW from IPv6 fd00::/8 → OPEN_LOCAL."""
        rules = "[ 1] 22/tcp  ALLOW IN  fd00::/8\n"
        assert _classify_exposure("22/tcp", rules) == Exposure.OPEN_LOCAL

    def test_ipv6_link_local(self):
        """ALLOW from fe80::/10 link-local → OPEN_LOCAL."""
        rules = "[ 1] 22/tcp  ALLOW IN  fe80::/10\n"
        assert _classify_exposure("22/tcp", rules) == Exposure.OPEN_LOCAL

    def test_ipv6_loopback(self):
        """ALLOW from ::1 → OPEN_LOCAL."""
        rules = "[ 1] 22/tcp  ALLOW IN  ::1\n"
        assert _classify_exposure("22/tcp", rules) == Exposure.OPEN_LOCAL

    def test_public_ipv4_still_open_world(self):
        """Non-private public IP → still OPEN_WORLD (no regression)."""
        rules = "[ 1] 22/tcp  ALLOW IN  203.0.113.0/24\n"
        assert _classify_exposure("22/tcp", rules) == Exposure.OPEN_WORLD


# ---------------------------------------------------------------------------
# check_services — inactive_disabled
# ---------------------------------------------------------------------------

class TestInactiveDisabled:
    def test_info_finding_for_low_risk_inactive(self):
        snap = make_snapshot(
            service=make_service(risk="low"),
            state=ServiceState.INACTIVE_DISABLED,
        )
        result = check_services([snap])
        assert has_level(result, "info")

    def test_warn_for_critical_inactive_disabled(self):
        """Critical service installed but disabled → WARN, not INFO."""
        snap = make_snapshot(
            service=make_service(risk="critical"),
            state=ServiceState.INACTIVE_DISABLED,
        )
        result = check_services([snap])
        assert has_level(result, "warn")
        assert not has_level(result, "info")

    def test_warn_for_high_inactive_disabled(self):
        snap = make_snapshot(
            service=make_service(risk="high"),
            state=ServiceState.INACTIVE_DISABLED,
        )
        result = check_services([snap])
        assert has_level(result, "warn")

    def test_no_deduction_for_inactive(self):
        snap = make_snapshot(
            service=make_service(risk="low"),
            state=ServiceState.INACTIVE_DISABLED,
        )
        result = check_services([snap])
        assert total_deductions(result) == 0

    def test_one_pt_deduction_for_critical_inactive(self):
        """v0.8.0 drift batch (Tier 3): critical service dormant = real
        defensive gap, +1pt so the finding actually moves the score.
        Pre-v0.8.0 behaviour was 0 deduction (warn-only); Tier 3 audit
        concluded that was inconsistent with the warn level."""
        snap = make_snapshot(
            service=make_service(risk="critical"),
            state=ServiceState.INACTIVE_DISABLED,
        )
        result = check_services([snap])
        assert total_deductions(result) == 1

    def test_no_port_check_for_inactive(self):
        """No port exposure findings for inactive_disabled services — early return for all risk levels."""
        snap = make_snapshot(
            service=make_service(risk="low"),
            state=ServiceState.INACTIVE_DISABLED,
            exposures={"22/tcp": Exposure.OPEN_WORLD},
        )
        result = check_services([snap])
        # Only 1 finding: the inactive info
        assert len(result.findings) == 1

    def test_no_port_check_for_critical_inactive(self):
        """Critical inactive_disabled also early-returns — only 1 finding (the warn)."""
        snap = make_snapshot(
            service=make_service(risk="critical"),
            state=ServiceState.INACTIVE_DISABLED,
            exposures={"22/tcp": Exposure.OPEN_WORLD},
        )
        result = check_services([snap])
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# check_services — active states
# ---------------------------------------------------------------------------

class TestActiveStates:
    def test_ok_for_active_enabled(self):
        snap = make_snapshot(state=ServiceState.ACTIVE_ENABLED)
        result = check_services([snap])
        assert has_level(result, "ok")

    def test_warn_for_active_disabled(self):
        snap = make_snapshot(state=ServiceState.ACTIVE_DISABLED)
        result = check_services([snap])
        assert has_level(result, "warn")

    def test_info_for_unknown_state(self):
        snap = make_snapshot(state=ServiceState.UNKNOWN)
        result = check_services([snap])
        assert has_level(result, "info")


# ---------------------------------------------------------------------------
# check_services — port exposure findings
# ---------------------------------------------------------------------------

class TestPortExposureFindings:
    def test_open_world_critical_adds_alert(self):
        """Critical service (SSH default) with OPEN_WORLD → alert, not warn."""
        snap = make_snapshot(
            service=make_service(risk="critical"),
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_WORLD},
        )
        result = check_services([snap])
        assert has_level(result, "alert")

    def test_open_world_medium_adds_warn(self):
        """Medium-risk service with OPEN_WORLD → warn."""
        snap = make_snapshot(
            service=make_service(risk="medium"),
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"80/tcp": Exposure.OPEN_WORLD},
        )
        result = check_services([snap])
        assert has_level(result, "warn")

    def test_open_world_adds_deduction(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_WORLD},
        )
        result = check_services([snap])
        assert total_deductions(result) > 0

    def test_open_world_critical_public_higher_deduction(self):
        svc = make_service(risk="critical")
        snap = make_snapshot(
            service=svc,
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_WORLD},
        )
        result_local  = check_services([snap], network_context="local")
        result_public = check_services([snap], network_context="public")
        assert total_deductions(result_public) > total_deductions(result_local)

    def test_open_local_adds_warn(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_LOCAL},
        )
        result = check_services([snap])
        assert has_level(result, "warn")

    def test_open_local_no_deduction(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_LOCAL},
        )
        result = check_services([snap])
        assert total_deductions(result) == 0

    def test_deny_adds_ok(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.DENY},
        )
        result = check_services([snap])
        assert has_level(result, "ok")

    def test_no_rule_adds_info(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.NO_RULE},
        )
        result = check_services([snap])
        assert has_level(result, "info")

    def test_loopback_no_rule_adds_info(self):
        """LOOPBACK_NO_RULE: loopback port without a UFW rule → INFO, no deduction."""
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"6379/tcp": Exposure.LOOPBACK_NO_RULE},
        )
        result = check_services([snap])
        assert has_level(result, "info")

    def test_loopback_no_rule_no_deduction(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"6379/tcp": Exposure.LOOPBACK_NO_RULE},
        )
        result = check_services([snap])
        assert total_deductions(result) == 0

    def test_not_listening_adds_info_for_low_risk(self):
        """NOT_LISTENING: low-risk service → INFO finding, no deduction."""
        snap = make_snapshot(
            service=make_service(risk="low"),
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"8883/tcp": Exposure.NOT_LISTENING},
        )
        result = check_services([snap])
        assert has_level(result, "info")

    def test_not_listening_critical_adds_info(self):
        """NOT_LISTENING: critical service port not listening → INFO only (not a risk)."""
        snap = make_snapshot(
            service=make_service(risk="critical"),
            state=ServiceState.UNKNOWN,
            exposures={"23/tcp": Exposure.NOT_LISTENING},
        )
        result = check_services([snap])
        assert has_level(result, "info")
        assert not has_level(result, "warn")

    def test_not_listening_high_adds_info(self):
        snap = make_snapshot(
            service=make_service(risk="high"),
            state=ServiceState.UNKNOWN,
            exposures={"9090/tcp": Exposure.NOT_LISTENING},
        )
        result = check_services([snap])
        assert has_level(result, "info")
        assert not has_level(result, "warn")

    def test_not_listening_no_deduction(self):
        snap = make_snapshot(
            service=make_service(risk="low"),
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"8883/tcp": Exposure.NOT_LISTENING},
        )
        result = check_services([snap])
        assert total_deductions(result) == 0

    def test_not_listening_critical_no_deduction(self):
        snap = make_snapshot(
            service=make_service(risk="critical"),
            state=ServiceState.UNKNOWN,
            exposures={"23/tcp": Exposure.NOT_LISTENING},
        )
        result = check_services([snap])
        assert total_deductions(result) == 0

    def test_mixed_listening_and_not_listening(self):
        """Service with one active port (loopback) + one non-listening port."""
        snap = make_snapshot(
            service=make_service(ports=("1883/tcp", "8883/tcp")),
            state=ServiceState.ACTIVE_ENABLED,
            ports=["1883/tcp", "8883/tcp"],
            exposures={
                "1883/tcp": Exposure.LOOPBACK,
                "8883/tcp": Exposure.NOT_LISTENING,
            },
        )
        result = check_services([snap])
        assert has_level(result, "info")   # from 1883 LOOPBACK and/or 8883 NOT_LISTENING
        assert total_deductions(result) == 0

    def test_multiple_ports(self):
        snap = make_snapshot(
            service=make_service(ports=("445/tcp", "139/tcp"), risk="critical"),
            state=ServiceState.ACTIVE_ENABLED,
            ports=["445/tcp", "139/tcp"],
            exposures={
                "445/tcp": Exposure.OPEN_WORLD,
                "139/tcp": Exposure.NO_RULE,
            },
        )
        result = check_services([snap])
        assert has_level(result, "alert")  # from 445 (critical OPEN_WORLD)
        assert has_level(result, "info")   # from 139


# ---------------------------------------------------------------------------
# check_services — multiple services
# ---------------------------------------------------------------------------

class TestMultipleServices:
    def test_multiple_snapshots_aggregated(self):
        snap1 = make_snapshot(
            service=make_service(id="ssh"),
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_WORLD},
        )
        snap2 = make_snapshot(
            service=make_service(id="redis"),
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"6379/tcp": Exposure.NO_RULE},
        )
        result = check_services([snap1, snap2])
        assert len(result.findings) >= 2

    def test_empty_snapshots_empty_result(self):
        result = check_services([])
        assert result.findings == []
        assert result.deductions == []


# ---------------------------------------------------------------------------
# check_services — translation
# ---------------------------------------------------------------------------

class TestTranslation:
    def test_translation_function_used(self):
        def my_t(key, **kwargs):
            return f"T:{key}"

        snap = make_snapshot(state=ServiceState.ACTIVE_ENABLED)
        result = check_services([snap], t=my_t)
        assert any("T:" in f.message for f in result.findings)


# ---------------------------------------------------------------------------
# ServiceSnapshot properties
# ---------------------------------------------------------------------------

class TestServiceSnapshotProperties:
    def test_label(self):
        snap = make_snapshot(service=make_service(label="SSH Server"))
        assert snap.label == "SSH Server"

    def test_risk(self):
        snap = make_snapshot(service=make_service(risk="critical"))
        assert snap.risk == "critical"

    def test_is_active(self):
        snap = make_snapshot(state=ServiceState.ACTIVE_ENABLED)
        assert snap.is_active

    def test_is_not_active(self):
        snap = make_snapshot(state=ServiceState.INACTIVE_DISABLED)
        assert not snap.is_active


# ---------------------------------------------------------------------------
# Exposure override — LOOPBACK_NO_RULE and NOT_LISTENING
# ---------------------------------------------------------------------------

class TestExposureOverrides:
    """Test the loopback and not-listening override logic in ServiceSnapshot."""

    UFW_OPEN = "[ 1] 22/tcp  ALLOW IN  Anywhere\n"
    UFW_EMPTY = ""

    def _make_snap_with_overrides(self, port, ufw_rules, loopback_ports=None,
                                   all_listening_ports=None):
        """Build a minimal snapshot using the override logic directly."""
        from bob.checks.services import _classify_exposure
        exposure = _classify_exposure(port, ufw_rules)
        exposures = {port: exposure}

        if loopback_ports and port in loopback_ports:
            if exposures[port] == Exposure.OPEN_WORLD:
                exposures[port] = Exposure.LOOPBACK
            elif exposures[port] == Exposure.NO_RULE:
                exposures[port] = Exposure.LOOPBACK_NO_RULE

        if all_listening_ports is not None and port not in all_listening_ports:
            if exposures.get(port) == Exposure.NO_RULE:
                exposures[port] = Exposure.NOT_LISTENING

        return make_snapshot(
            service=make_service(ports=(port,)),
            state=ServiceState.ACTIVE_ENABLED,
            ports=[port],
            exposures=exposures,
        )

    def test_no_rule_plus_loopback_gives_loopback_no_rule(self):
        """Port with no UFW rule, bound to loopback → LOOPBACK_NO_RULE."""
        snap = self._make_snap_with_overrides(
            "6379/tcp", self.UFW_EMPTY,
            loopback_ports={"6379/tcp"},
            all_listening_ports={"6379/tcp"},
        )
        assert snap.exposures["6379/tcp"] == Exposure.LOOPBACK_NO_RULE

    def test_open_world_plus_loopback_gives_loopback(self):
        """Port with ALLOW rule, bound to loopback → LOOPBACK."""
        snap = self._make_snap_with_overrides(
            "22/tcp", self.UFW_OPEN,
            loopback_ports={"22/tcp"},
            all_listening_ports={"22/tcp"},
        )
        assert snap.exposures["22/tcp"] == Exposure.LOOPBACK

    def test_no_rule_not_listening_gives_not_listening(self):
        """Port with no UFW rule, not in active listeners → NOT_LISTENING."""
        snap = self._make_snap_with_overrides(
            "8883/tcp", self.UFW_EMPTY,
            loopback_ports=set(),
            all_listening_ports=set(),
        )
        assert snap.exposures["8883/tcp"] == Exposure.NOT_LISTENING

    def test_open_world_not_in_listeners_stays_open_world(self):
        """Port with ALLOW rule but not listening — rule exists, stays OPEN_WORLD (orphan UFW rule)."""
        snap = self._make_snap_with_overrides(
            "22/tcp", self.UFW_OPEN,
            loopback_ports=set(),
            all_listening_ports=set(),
        )
        # NOT_LISTENING only overrides NO_RULE — OPEN_WORLD stays as-is
        assert snap.exposures["22/tcp"] == Exposure.OPEN_WORLD

    def test_no_rule_not_loopback_but_listening_stays_no_rule(self):
        """Port on 0.0.0.0 with no UFW rule, actively listening → stays NO_RULE."""
        snap = self._make_snap_with_overrides(
            "5353/udp", self.UFW_EMPTY,
            loopback_ports=set(),
            all_listening_ports={"5353/udp"},
        )
        assert snap.exposures["5353/udp"] == Exposure.NO_RULE


# ---------------------------------------------------------------------------
# Panorama build_panorama_rows — UFW indicator for new variants
# ---------------------------------------------------------------------------

class TestPanoramaNewVariants:
    """Verify build_panorama_rows assigns correct UFW indicator for new Exposure variants."""

    def _row_for(self, exposure: Exposure) -> dict:
        from bob.panorama import build_panorama_rows
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": exposure},
        )
        rows = build_panorama_rows([snap])
        return rows[0]

    def test_loopback_no_rule_shows_ok(self):
        assert self._row_for(Exposure.LOOPBACK_NO_RULE)["ufw"] == "ok"

    def test_not_listening_shows_ok(self):
        assert self._row_for(Exposure.NOT_LISTENING)["ufw"] == "ok"

    def test_loopback_shows_ok(self):
        assert self._row_for(Exposure.LOOPBACK)["ufw"] == "ok"

    def test_open_world_shows_warn(self):
        assert self._row_for(Exposure.OPEN_WORLD)["ufw"] == "warn"

    def test_no_rule_shows_ok(self):
        """NO_RULE is covered by the default deny policy — panorama shows ✔."""
        assert self._row_for(Exposure.NO_RULE)["ufw"] == "ok"

    def test_mixed_loopback_no_rule_and_not_listening_shows_ok(self):
        """Service with both LOOPBACK_NO_RULE and NOT_LISTENING → ok."""
        from bob.panorama import build_panorama_rows
        snap = make_snapshot(
            service=make_service(ports=("1883/tcp", "8883/tcp")),
            state=ServiceState.ACTIVE_ENABLED,
            ports=["1883/tcp", "8883/tcp"],
            exposures={
                "1883/tcp": Exposure.LOOPBACK_NO_RULE,
                "8883/tcp": Exposure.NOT_LISTENING,
            },
        )
        rows = build_panorama_rows([snap])
        assert rows[0]["ufw"] == "ok"


# ---------------------------------------------------------------------------
# _auto_detect_port — config file parsing
# ---------------------------------------------------------------------------

class TestAutoDetectPort:
    """
    _auto_detect_port() reads a service config file to find the active port.
    Tests use temporary files to avoid touching the real filesystem.
    """

    def _make_service_with_config(self, config_path, proto="tcp"):
        """Build a Service whose detection points at a temp config file."""
        return make_service(
            ports=(f"21/{proto}",),
            detection=Detection(
                binary=(),
                snap=(),
                config_files=(config_path,),
            ),
        )

    def test_detects_port_equals(self, tmp_path):
        """'port = 2121' → detects 2121."""
        cfg = tmp_path / "service.conf"
        cfg.write_text("port = 2121\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) == "2121/tcp"

    def test_detects_listen_colon(self, tmp_path):
        """'listen: 8080' → detects 8080."""
        cfg = tmp_path / "service.conf"
        cfg.write_text("listen: 8080\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) == "8080/tcp"

    def test_detects_http_port(self, tmp_path):
        """'HTTP_PORT = 3000' → detects 3000."""
        cfg = tmp_path / "service.conf"
        cfg.write_text("HTTP_PORT = 3000\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) == "3000/tcp"

    def test_ignores_commented_port(self, tmp_path):
        """'# port = 2121' (commented) → returns None, not 2121."""
        cfg = tmp_path / "service.conf"
        cfg.write_text("# port = 2121\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) is None

    def test_ignores_inline_comment_line(self, tmp_path):
        """Line starting with whitespace + '#' is treated as a comment."""
        cfg = tmp_path / "service.conf"
        cfg.write_text("  # port = 9999\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) is None

    def test_active_port_wins_over_commented(self, tmp_path):
        """Active directive takes precedence when a comment precedes it."""
        cfg = tmp_path / "service.conf"
        cfg.write_text("# port = 2121\nport = 21\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) == "21/tcp"

    def test_missing_config_file_returns_none(self, tmp_path):
        """Config file path that doesn't exist → None."""
        svc = self._make_service_with_config(str(tmp_path / "nonexistent.conf"))
        assert _auto_detect_port(svc) is None

    def test_no_matching_key_returns_none(self, tmp_path):
        """Config file exists but has no recognisable port directive → None."""
        cfg = tmp_path / "service.conf"
        cfg.write_text("bind_address = 0.0.0.0\nmax_connections = 10\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) is None

    def test_proto_from_registry(self, tmp_path):
        """Proto is taken from registry default port."""
        cfg = tmp_path / "service.conf"
        cfg.write_text("port = 5353\n")
        svc = self._make_service_with_config(str(cfg), proto="udp")
        assert _auto_detect_port(svc) == "5353/udp"

    def test_sshd_config_space_format(self, tmp_path):
        """sshd_config uses 'Port 49732' (space-separated, no = or :) — must be detected."""
        cfg = tmp_path / "sshd_config"
        cfg.write_text("# This is the sshd server system-wide configuration file.\n"
                       "# Default: 22\n"
                       "Port 49732\n"
                       "PermitRootLogin no\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) == "49732/tcp"

    def test_sshd_config_commented_port_ignored(self, tmp_path):
        """'# Port 49732' (commented) must not be detected."""
        cfg = tmp_path / "sshd_config"
        cfg.write_text("# Port 49732\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) is None

    def test_vsftpd_listen_port(self, tmp_path):
        """vsftpd uses 'listen_port=2121' — must be detected."""
        cfg = tmp_path / "vsftpd.conf"
        cfg.write_text("anonymous_enable=NO\nlisten_port=2121\nlocal_enable=YES\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) == "2121/tcp"

    def test_vsftpd_commented_listen_port_ignored(self, tmp_path):
        """'# listen_port=2121' (commented) must not be detected."""
        cfg = tmp_path / "vsftpd.conf"
        cfg.write_text("# listen_port=2121\nlisten_port=21\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) == "21/tcp"

    def test_transmission_json_rpc_port(self, tmp_path):
        """Transmission settings.json uses 'rpc-port' — must be parsed as JSON."""
        cfg = tmp_path / "settings.json"
        cfg.write_text('{\n  "rpc-port": 9191,\n  "rpc-enabled": true\n}\n')
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) == "9191/tcp"

    def test_transmission_json_default_port(self, tmp_path):
        """Transmission settings.json with default rpc-port=9091."""
        cfg = tmp_path / "settings.json"
        cfg.write_text('{"rpc-port": 9091}\n')
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) == "9091/tcp"

    def test_transmission_json_invalid_falls_back(self, tmp_path):
        """Malformed JSON → returns None (no crash)."""
        cfg = tmp_path / "settings.json"
        cfg.write_text("not valid json {\n")
        svc = self._make_service_with_config(str(cfg))
        assert _auto_detect_port(svc) is None


# ---------------------------------------------------------------------------
# ufw_active=False — exposure messages
# ---------------------------------------------------------------------------

# t stub that embeds kwargs in output so we can assert on key selection
_t_exp = lambda key, **kw: f"{key}({','.join(f'{k}={v}' for k,v in kw.items())})" if kw else key


class TestUfwInactiveExposure:
    def test_no_rule_ufw_inactive_uses_inactive_key(self):
        snap = make_snapshot(exposures={"22/tcp": Exposure.NO_RULE})
        result = check_services([snap], ufw_active=False, t=_t_exp)
        msgs = [f.message for f in result.findings]
        assert any("no_rule_ufw_inactive" in m for m in msgs)

    def test_no_rule_ufw_active_uses_normal_key(self):
        snap = make_snapshot(exposures={"22/tcp": Exposure.NO_RULE})
        result = check_services([snap], ufw_active=True, t=_t_exp)
        msgs = [f.message for f in result.findings]
        assert not any("no_rule_ufw_inactive" in m for m in msgs)

    def test_loopback_no_rule_ufw_inactive_uses_inactive_key(self):
        snap = make_snapshot(exposures={"22/tcp": Exposure.LOOPBACK_NO_RULE})
        result = check_services([snap], ufw_active=False, t=_t_exp)
        msgs = [f.message for f in result.findings]
        assert any("loopback_no_rule_ufw_inactive" in m for m in msgs)

    def test_loopback_no_rule_ufw_active_unaffected(self):
        snap = make_snapshot(exposures={"22/tcp": Exposure.LOOPBACK_NO_RULE})
        result = check_services([snap], ufw_active=True, t=_t_exp)
        msgs = [f.message for f in result.findings]
        assert not any("loopback_no_rule_ufw_inactive" in m for m in msgs)


# ---------------------------------------------------------------------------
# Service registry — new services
# ---------------------------------------------------------------------------

class TestNewServicesRegistry:
    """Verify the 5 new services load correctly from services.json."""

    def _get(self, service_id: str):
        from bob.registry import ServiceRegistry
        reg = ServiceRegistry.load()
        return next((s for s in reg if s.id == service_id), None)

    def test_smtp_exists(self):
        assert self._get("smtp") is not None

    def test_smtp_risk_high(self):
        assert self._get("smtp").risk == "high"

    def test_smtp_port(self):
        assert "25/tcp" in self._get("smtp").ports

    def test_nfs_exists(self):
        assert self._get("nfs") is not None

    def test_nfs_risk_high(self):
        assert self._get("nfs").risk == "high"

    def test_nfs_ports(self):
        svc = self._get("nfs")
        assert "2049/tcp" in svc.ports
        assert "2049/udp" in svc.ports

    def test_jenkins_exists(self):
        assert self._get("jenkins") is not None

    def test_jenkins_risk_high(self):
        assert self._get("jenkins").risk == "high"

    def test_jenkins_port(self):
        assert "8080/tcp" in self._get("jenkins").ports

    def test_openvpn_exists(self):
        assert self._get("openvpn") is not None

    def test_openvpn_risk_medium(self):
        assert self._get("openvpn").risk == "medium"

    def test_openvpn_port(self):
        assert "1194/udp" in self._get("openvpn").ports

    def test_squid_exists(self):
        assert self._get("squid") is not None

    def test_squid_risk_medium(self):
        assert self._get("squid").risk == "medium"

    def test_squid_port(self):
        assert "3128/tcp" in self._get("squid").ports
