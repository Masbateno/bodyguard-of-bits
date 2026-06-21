"""v0.13.1 — orphan / failed systemd socket-unit check (INFO-only)."""

from __future__ import annotations

from bob.checks import socket_units as su_mod
from bob.checks.socket_units import (
    SocketUnit,
    SocketUnitsSnapshot,
    check_socket_units,
    _LISTEN_ADDR,
    _is_broken,
)
from bob.scoring import FindingLevel


def _sock(name, active="active", listens=(), trigger="", trigger_load="loaded",
          trigger_active="active"):
    """Build a SocketUnit, resolving broken_trigger like from_system() does."""
    triggers = [trigger] if trigger else []
    broken = trigger if (trigger and _is_broken(trigger_load, trigger_active)) else ""
    return SocketUnit(
        name=name, active_state=active, listens=list(listens),
        triggers=triggers, broken_trigger=broken,
    )


def _snap(sockets):
    return SocketUnitsSnapshot(available=True, sockets=list(sockets))


class TestCheckLogic:
    def test_tool_absent_emits_info_no_deduction(self):
        r = check_socket_units(SocketUnitsSnapshot(available=False))
        assert any(f.key == "socket_units.no_tool" for f in r.findings)
        assert all(f.level is FindingLevel.INFO for f in r.findings)
        assert not r.deductions

    def test_all_healthy_emits_clean(self):
        snap = _snap([
            _sock("ssh.socket", listens=["0.0.0.0:22"],
                  trigger="ssh.service", trigger_load="loaded"),
            _sock("dbus.socket", listens=["/run/dbus/system_bus_socket"],
                  trigger="dbus.service", trigger_load="loaded"),
        ])
        r = check_socket_units(snap)
        assert any(f.key == "socket_units.clean" for f in r.findings)
        assert not any(f.key == "socket_units.summary" for f in r.findings)
        assert not r.deductions

    def test_empty_trigger_is_never_orphan(self):
        # systemd-coredump.socket style: active, no Triggers -> not an orphan.
        snap = _snap([
            _sock("systemd-coredump.socket",
                  listens=["/run/systemd/coredump"], trigger="", trigger_load=""),
        ])
        r = check_socket_units(snap)
        assert any(f.key == "socket_units.clean" for f in r.findings)

    def test_orphan_detected_info_only(self):
        snap = _snap([
            _sock("stale.socket", listens=["0.0.0.0:9000"],
                  trigger="stale.service", trigger_load="not-found"),
            _sock("ssh.socket", listens=["0.0.0.0:22"],
                  trigger="ssh.service", trigger_load="loaded"),
        ])
        r = check_socket_units(snap)
        summary = next(f for f in r.findings if f.key == "socket_units.summary")
        assert summary.level is FindingLevel.INFO
        assert any(f.key == "socket_units.orphan" for f in r.findings)
        assert not r.deductions            # INFO-only by design in v0.13.1

    def test_masked_trigger_is_orphan(self):
        s = _sock("x.socket", trigger="x.service", trigger_load="masked")
        assert s.is_orphan is True

    def test_loaded_but_failed_service_is_orphan(self):
        # Blind-spot guard: the backing service EXISTS (loaded) but crashed
        # (ActiveState=failed) — socket up, consumer dead. Must be an orphan.
        snap = _snap([
            _sock("crash.socket", listens=["0.0.0.0:8080"], trigger="crash.service",
                  trigger_load="loaded", trigger_active="failed"),
        ])
        r = check_socket_units(snap)
        assert any(f.key == "socket_units.orphan" for f in r.findings)
        assert not r.deductions

    def test_inactive_service_is_not_orphan(self):
        # A socket-activated service rests in 'inactive' until first connection;
        # that is healthy, never flagged.
        s = _sock("ok.socket", trigger="ok.service",
                  trigger_load="loaded", trigger_active="inactive")
        assert s.is_orphan is False

    def test_failed_socket_distinct_from_orphan(self):
        snap = _snap([
            _sock("broke.socket", active="failed", listens=["127.0.0.1:1"],
                  trigger="broke.service", trigger_load="loaded"),
        ])
        r = check_socket_units(snap)
        assert any(f.key == "socket_units.failed" for f in r.findings)
        assert not any(f.key == "socket_units.orphan" for f in r.findings)


class TestSocketUnitProperties:
    def test_network_listener_detects_all_interfaces(self):
        assert _sock("a", listens=["0.0.0.0:22"]).is_network_listener is True
        assert _sock("b", listens=["[::]:80"]).is_network_listener is True

    def test_loopback_and_unix_are_not_network(self):
        assert _sock("a", listens=["127.0.0.1:631"]).is_network_listener is False
        assert _sock("b", listens=["[::1]:25"]).is_network_listener is False
        assert _sock("c", listens=["/run/foo.sock"]).is_network_listener is False

    def test_failed_property(self):
        assert _sock("a", active="failed").is_failed is True
        assert _sock("a", active="active").is_failed is False

    def test_orphan_requires_a_trigger(self):
        # broken load but no trigger name -> not flagged as orphan
        assert _sock("a", trigger="", trigger_load="not-found").is_orphan is False


    def test_orphan_with_multiple_triggers(self):
        # A socket declaring several trigger services is orphaned if ANY is broken.
        s = SocketUnit(name="m.socket", active_state="active",
                       triggers=["a.service", "b.service"], broken_trigger="b.service")
        assert s.is_orphan is True


class TestIsBroken:
    def test_gone_states_are_broken(self):
        assert _is_broken("not-found", "inactive") is True
        assert _is_broken("masked", "active") is True
        assert _is_broken("error", "") is True

    def test_failed_active_state_is_broken(self):
        assert _is_broken("loaded", "failed") is True

    def test_healthy_loaded_active_is_not_broken(self):
        assert _is_broken("loaded", "active") is False

    def test_inactive_is_not_broken(self):
        # on-demand socket-activated service at rest
        assert _is_broken("loaded", "inactive") is False


class TestFromSystemResolution:
    def test_multiple_triggers_any_broken_marks_orphan(self, monkeypatch):
        # Triggers=a.service b.service ; a healthy, b not-found -> orphan via b.
        monkeypatch.setattr(su_mod, "_command_exists", lambda n: True)
        monkeypatch.setattr(su_mod, "_socket_unit_names", lambda: ["multi.socket"])
        monkeypatch.setattr(
            su_mod, "_socket_unit",
            lambda name: SocketUnit(name=name, active_state="active",
                                    listens=["0.0.0.0:7000"],
                                    triggers=["a.service", "b.service"]),
        )
        health = {"a.service": ("loaded", "active"),
                  "b.service": ("not-found", "inactive")}
        monkeypatch.setattr(su_mod, "_trigger_health", lambda u: health[u])
        snap = SocketUnitsSnapshot.from_system()
        assert snap.sockets[0].broken_trigger == "b.service"
        assert snap.sockets[0].is_orphan is True


class TestListenParsing:
    def test_strips_type_suffix(self):
        m = _LISTEN_ADDR.match("0.0.0.0:22 (Stream)")
        assert m and m.group(1) == "0.0.0.0:22"

    def test_unix_path(self):
        m = _LISTEN_ADDR.match("/run/dbus/system_bus_socket (Stream)")
        assert m and m.group(1) == "/run/dbus/system_bus_socket"

    def test_star_wildcard_is_network(self):
        assert _sock("a", listens=["*:22"]).is_network_listener is True
