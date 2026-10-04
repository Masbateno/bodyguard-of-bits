"""v0.24.0 — fixes from the review of a real `--exhaustive` audit (Mint 22.3 desktop).

Each case below was a sentence the audit printed that the host contradicted:

  1. the attack-surface "listening ports" line left out Samba, bound to the LAN
     address 192.168.1.10 rather than 0.0.0.0 — as reachable, not counted;
  2. the updates line said "APT cache stale or inconsistent" beside a cache
     reported 0 days old — two causes, one message;
  6. "OpenVPN active" with a VPN-concentrator threat context, on a desktop whose
     openvpn.service is Debian's `ExecStart=/bin/true` umbrella, no tunnel up;
  7. "2 sections not fully read" with nothing naming them;
  8. a pending UEFI dbx update deducted a point while Secure Boot — the only
     consumer of dbx — was measured disabled.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from bob.checks import services as S
from bob.checks.firmware import FirmwareSnapshot, check_firmware
from bob.checks.ports import is_specific_unicast, is_system_internal
from bob.exposure import compute_exposure
from bob.scoring import Finding, FindingLevel
from tests.helpers import _t


# ---- 1. attack-surface ports ------------------------------------------------------

@dataclass
class _Port:
    port: int
    proto: str
    address: str
    iface: str = ""
    process: str = ""

    @property
    def port_proto(self):
        return f"{self.port}/{self.proto}"

    @property
    def is_all_interfaces(self):
        return self.address in ("0.0.0.0", "::", "*") and not self.iface

    @property
    def is_loopback(self):
        return self.address.startswith("127.") or self.address == "::1"


class _Ports:
    def __init__(self, ports):
        self.ports, self.ports_readable = ports, True


class _Engine:
    def __init__(self, *pairs):
        self.findings = [Finding(level=lvl, message="m", key=k) for k, lvl in pairs]


def _open_ports(ports):
    items = compute_exposure(_Engine(), _Ports(ports), "local", True, "deny", _t)
    item = next(i for i in items if i.label == "exposure.open_ports")
    return item.detail


@pytest.mark.parametrize("addr,iface,expected", [
    ("192.168.1.10", "", True),
    ("fd00::5", "", True),
    ("0.0.0.0", "", False),          # counted as all-interfaces instead
    ("127.0.0.1", "", False),
    ("224.0.0.251", "", False),      # multicast (Brave mDNS)
    ("192.168.1.255", "", False),    # nmbd's subnet broadcast
    ("0.0.0.0", "virbr0", False),    # interface-scoped
])
def test_specific_unicast(addr, iface, expected):
    assert is_specific_unicast(_Port(445, "tcp", addr, iface)) is expected


def test_lan_bound_samba_is_in_the_summary():
    detail = _open_ports([_Port(22, "tcp", "0.0.0.0"),
                          _Port(445, "tcp", "192.168.1.10", process="smbd"),
                          _Port(139, "tcp", "192.168.1.10", process="smbd")])
    assert detail == "22/tcp, 139/tcp, 445/tcp"


def test_libvirt_dnsmasq_on_its_bridge_is_not_surface():
    p = _Port(53, "udp", "192.168.122.1", process="dnsmasq")
    assert is_system_internal(p)
    assert _open_ports([p]) == "exposure.no_open_ports"


# ---- 2. updates line names its cause ---------------------------------------------

@pytest.mark.parametrize("keys,expected", [
    (["updates.dist_upgrade_inconsistent"], "exposure.updates_inconsistent"),
    (["updates.apt_cache_stale"], "exposure.updates_stale"),
    (["updates.apt_cache_stale", "updates.dist_upgrade_inconsistent"], "exposure.updates_unknown"),
])
def test_updates_line_names_the_measured_cause(keys, expected):
    engine = _Engine(*[(k, FindingLevel.WARN) for k in keys])
    items = compute_exposure(engine, _Ports([]), "local", True, "deny", _t)
    assert next(i for i in items if i.label == "exposure.updates").detail == expected


# ---- 6. no-op umbrella units -------------------------------------------------------

def _systemctl(show: str, active=True, enabled=True, instances=""):
    def run(*argv, **kw):
        argv = list(argv)
        if argv[:2] == ["systemctl", "list-units"] and "--state=active" in argv:
            return instances
        if argv[:2] == ["systemctl", "is-active"]:
            return "active" if active else "inactive"
        if argv[:2] == ["systemctl", "is-enabled"]:
            return "enabled" if enabled else "disabled"
        if argv[:2] == ["systemctl", "show"] and "ExecStart" in argv:
            return show
        return ""
    return run


_UMBRELLA = ("Type=oneshot\nSubState=exited\n"
             "ExecStart={ path=/bin/true ; argv[]=/bin/true ; ignore_errors=no ; }\n")


def test_openvpn_umbrella_is_not_a_running_daemon(monkeypatch):
    monkeypatch.setattr(S, "_run", _systemctl(_UMBRELLA))
    assert S._detect_single_unit_state("openvpn") == S.ServiceState.INACTIVE_DISABLED


def test_umbrella_with_a_running_instance_stays_active(monkeypatch):
    """postfix.service is the same /bin/true umbrella, but postfix@-.service
    runs master on :25 — the regression this rule first introduced."""
    monkeypatch.setattr(S, "_run", _systemctl(
        _UMBRELLA, instances="postfix@-.service loaded active running Postfix (instance -)\n"))
    assert S._detect_single_unit_state("postfix") == S.ServiceState.ACTIVE_ENABLED


@pytest.mark.parametrize("show", [
    "Type=oneshot\nSubState=exited\nExecStart={ path=/usr/sbin/iptables-restore ; }\n",
    "Type=simple\nSubState=running\nExecStart={ path=/usr/sbin/sshd ; }\n",
    "",                                    # systemctl show said nothing
])
def test_real_services_are_unaffected(monkeypatch, show):
    monkeypatch.setattr(S, "_run", _systemctl(show))
    assert S._detect_single_unit_state("svc") == S.ServiceState.ACTIVE_ENABLED


def test_openvpn_registry_looks_at_server_instances():
    import json
    from pathlib import Path
    reg = json.loads((Path(S.__file__).parents[1] / "data" / "services.json").read_text())
    units = next(s for s in reg if s["id"] == "openvpn")["services"]
    assert {"openvpn-server@", "openvpn@"} <= set(units)
    assert "openvpn-client@" not in units, "a client listens on nothing"


# ---- 8. dbx with Secure Boot off ---------------------------------------------------

def _fw(pending, sb):
    return FirmwareSnapshot(fwupd_available=True, fwupd_pending_updates=pending,
                            secure_boot_state=sb, microcode_not_applicable=True)


def test_dbx_only_with_secure_boot_off_is_info():
    r = check_firmware(_fw(["UEFI dbx"], "disabled"), t=_t)
    assert "firmware.fwupd_dbx_sb_off" in [f.key for f in r.findings]
    assert r.deductions == []


@pytest.mark.parametrize("pending,sb", [
    (["UEFI dbx"], "enabled"),             # enforced: the update matters now
    (["UEFI dbx"], "unknown"),             # not measured: keep the deduction
    (["UEFI dbx", "System Firmware"], "disabled"),   # real firmware pending too
])
def test_other_cases_still_deduct(pending, sb):
    r = check_firmware(_fw(pending, sb), t=_t)
    assert sum(d.points for d in r.deductions) == 1


# ---- 7. the summary names the unread sections -------------------------------------

def test_unread_sections_are_named_below_the_box(capsys):
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from bob.display import print_audit_summary
    from tests.test_display_explain_hint import FakeEngine

    engine = FakeEngine()
    engine.unverified = ["world_writable.partial", "package_integrity.tool_missing"]
    engine.score_is_upper_bound = True
    report = MagicMock()
    print_audit_summary(engine=engine, network_context="local", public_ip=None,
                        config=SimpleNamespace(lang="en"),
                        t=lambda key, **kw: f"{key} {kw}" if kw else key,
                        report=report, snapshots=[])
    out = capsys.readouterr().out
    line = next(l for l in out.splitlines() if "summary.visibility_sections" in l)
    assert "package_integrity, world_writable" in line
    labels = report.write_summary.call_args.kwargs["labels"]
    assert "(package_integrity, world_writable)" in labels["visibility_value"]


# ---- follow-up found on real Debian 13 (2026-10-04) ------------------------------

@pytest.mark.parametrize("proc", ["dhcpcd", "dhclient", "udhcpc"])
def test_dhcp_clients_are_system_internal(proc):
    p = _Port(68, "udp", "192.168.1.13", process=proc)
    assert is_system_internal(p)
    assert _open_ports([p]) == "exposure.no_open_ports"


def _check_ports_messages(ports, **kw):
    from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
    snap = PortsSnapshot(
        ports=[ListeningPort(port=p, proto="tcp", address=a, raw_line="", process="app")
               for p, a in ports],
        ufw_rules="", ss_output="")
    r = check_ports(snap, t=lambda key, **k: f"{key} {k}" if k else key, **kw)
    return [f.message for f in r.findings]


def test_lan_bound_port_is_not_called_localhost():
    msgs = _check_ports_messages([(9999, "192.168.1.13")], ufw_active=False)
    assert any(m.startswith("ports.uncovered_bound_address ") and "192.168.1.13" in m for m in msgs)
    assert not any("ports.uncovered_local" in m for m in msgs)


@pytest.mark.parametrize("kw,key", [
    (dict(ufw_active=True, default_incoming_policy="deny"), "ports.uncovered_bound_address_deny"),
    (dict(ufw_active=False, firewalld_active=True), "ports.uncovered_bound_address_firewalld"),
    (dict(ufw_active=False, firewalld_active=False), "ports.uncovered_bound_address "),
    (dict(ufw_active=True, default_incoming_policy="allow"), "ports.uncovered_bound_address "),
])
def test_lan_bound_port_reachability_follows_the_firewall(kw, key):
    """'reachable from that network' is false behind a default-deny firewall."""
    msgs = _check_ports_messages([(9999, "192.168.1.13")], **kw)
    assert any(m.startswith(key) for m in msgs), msgs


def test_loopback_port_keeps_localhost_wording():
    msgs = _check_ports_messages([(9999, "127.0.0.1")])
    assert any(m.startswith("ports.uncovered_local") for m in msgs)


def test_lan_binding_wins_over_loopback_listed_first():
    msgs = _check_ports_messages([(9999, "127.0.0.1"), (9999, "192.168.1.13")])
    assert any("ports.uncovered_bound_address" in m for m in msgs)


# ---- stress-test finding (Mint, 2026-10-04): explicit slow section, no flag -------

@pytest.mark.parametrize("section", ["package_integrity", "world_writable"])
def test_slow_section_asked_without_exhaustive_says_why(section):
    from bob.runner import _REQUIRES_EXHAUSTIVE, _requires_exhaustive
    r = _requires_exhaustive(None, t=_t, section_name=section)
    assert [f.key for f in r.findings] == [f"{section}.requires_exhaustive"]
    assert r.deductions == []
    assert section in _REQUIRES_EXHAUSTIVE


def test_the_hint_is_wired_into_the_runner():
    """`--check=world_writable` alone printed nothing after "Active checks"."""
    import inspect
    import bob.runner as runner
    src = inspect.getsource(runner)
    assert "for _slow in _REQUIRES_EXHAUSTIVE:" in src
    assert "_sec(_slow, lambda: None, _requires_exhaustive, section_name=_slow)" in src


# ---- stress-test finding (Alpine, 2026-10-04): a wedged package manager -----------

def test_a_wedged_package_manager_is_asked_once(monkeypatch):
    """A FIFO at /etc/apk/config blocks apk on every call; the services registry
    asked it ~40 times at 10 s each — 623 s measured. Ask once, then stop."""
    import bob.checks._run as R
    calls = []

    def fake_run_result(*args, **kw):
        calls.append(args)
        return R.CommandResult("", False, timed_out=True)
    monkeypatch.setattr(R, "_WEDGED_MANAGERS", set())
    monkeypatch.setattr(R, "_command_exists", lambda tool: tool == "apk")
    monkeypatch.setattr(R, "run_result", fake_run_result)
    answers = [R.package_installed(n) for n in ("nginx", "samba", "redis", "mysql", "x")]
    assert answers == [None] * 5            # same answer a timeout always gave
    assert len(calls) == 1                  # but paid for once


def test_a_slow_but_answering_manager_is_not_tripped(monkeypatch):
    import bob.checks._run as R
    monkeypatch.setattr(R, "_WEDGED_MANAGERS", set())
    monkeypatch.setattr(R, "_command_exists", lambda tool: tool == "apk")
    monkeypatch.setattr(R, "run_result", lambda *a, **k: R.CommandResult("nginx\n", True, code=0))
    assert R.package_installed("nginx") == "apk"
    assert R._WEDGED_MANAGERS == set()
