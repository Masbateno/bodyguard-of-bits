"""v0.31.4 — Samba's NetBIOS daemon (nmbd) has its own registry entry.

The Samba entry declared 445/tcp and 139/tcp, the ports smbd serves. nmbd
listens on 137/udp and 138/udp — measured on Linux Mint 22.3, bound to
0.0.0.0 beside the subnet broadcast — and no entry named them, so the services
section never weighed them. UFW's own ``Samba`` application profile opens all
four (``137,138/udp|139,445/tcp``).

nmbd answers names and carries browse datagrams; it serves no file. Its entry
is medium risk: open to the internet it is a WARN worth one point per port,
open to the local network it is the structural notice with no point — what
every medium-risk service gets.

The Fedora unit ``nmb`` moves from the Samba entry to this one: Samba's state
is now smbd's state, and a running nmbd beside a stopped smbd no longer reads
as Samba running.
"""

from __future__ import annotations

import json

from bob.checks import services as svc
from bob.checks.services import Exposure, ServiceState, check_services
from bob.registry import ServiceRegistry, service_label_to_subkey
from tests.test_services import make_snapshot, total_deductions

_APPS = {"Samba": ["137,138/udp", "139,445/tcp"]}


def _entry(sid):
    return ServiceRegistry.load().get(sid)


class TestTheRegistryEntry:
    def test_nmbd_has_its_own_ports(self):
        e = _entry("samba_netbios")
        assert e is not None
        assert list(e.ports) == ["137/udp", "138/udp"]
        assert e.risk == "medium"
        assert set(e.services) == {"nmbd", "nmb"}
        assert list(e.packages) == ["samba"]

    def test_it_reads_no_samba_config_for_its_ports(self):
        # smb.conf's `smb ports` are smbd's: read for nmbd they would replace
        # 137/138 with 445/139.
        assert _entry("samba_netbios").detection.config_files == ()

    def test_samba_is_smbd_alone(self):
        e = _entry("samba")
        assert "nmb" not in e.services and "nmbd" not in e.services
        assert list(e.ports) == ["445/tcp", "139/tcp"]

    def test_its_risk_text_exists_in_both_locales(self):
        sub = service_label_to_subkey(_entry("samba_netbios").label)
        for loc, level in (("en", "MEDIUM"), ("fr", "MOYEN")):
            d = json.loads(open(f"bob/locales/{loc}.json", encoding="utf-8")
                           .read())["service_risk"][sub]
            assert d["level"] == level
            assert "nmbd" in d["threat"]


class TestTheProfileReachesIt:
    def test_a_lan_samba_rule_admits_both_ports_locally(self):
        rules = "[ 1] Samba                      ALLOW IN    192.168.1.0/24\n"
        for port in ("137/udp", "138/udp"):
            assert svc._classify_exposure(port, rules, _APPS) == Exposure.OPEN_LOCAL

    def test_an_open_samba_rule_opens_both_ports(self):
        rules = "[ 1] Samba                      ALLOW IN    Anywhere\n"
        for port in ("137/udp", "138/udp"):
            assert svc._classify_exposure(port, rules, _APPS) == Exposure.OPEN_WORLD


class TestWhatTheSectionSays:
    def _snap(self, exposure):
        e = _entry("samba_netbios")
        return make_snapshot(service=e, state=ServiceState.ACTIVE_ENABLED,
                             exposures={p: exposure for p in e.ports})

    def test_lan_only_is_a_notice_without_a_point(self):
        result = check_services([self._snap(Exposure.OPEN_LOCAL)])
        assert total_deductions(result) == 0
        assert any(f.key == "services.exposure.open_local" for f in result.findings)

    def test_open_to_the_internet_is_a_warning_per_port(self):
        result = check_services([self._snap(Exposure.OPEN_WORLD)])
        levels = [f.level.value for f in result.findings
                  if f.key == "services.exposed.samba_netbios"]
        assert levels == ["warn", "warn"]
        assert total_deductions(result) == 2

    def test_installed_through_samba(self, monkeypatch):
        seen = []
        monkeypatch.setattr(svc, "package_installed",
                            lambda p: seen.append(p) or ("dpkg-query" if p == "samba" else ""))
        assert svc._detect_installation(_entry("samba_netbios")) == (True, "dpkg-query")
        assert seen == ["samba"]
