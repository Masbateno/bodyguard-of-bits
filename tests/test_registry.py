"""
Unit tests for bob.registry module.

Run with: python -m pytest tests/test_registry.py -v
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch
from bob.registry import Detection, Service, ServiceRegistry, _load_plugins


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_service_dict(**overrides) -> dict:
    """Return a minimal valid service dict, with optional overrides."""
    base = {
        "id": "test_svc",
        "label": "Test Service",
        "packages": ["test-pkg"],
        "services": ["test-svc"],
        "ports": ["1234/tcp"],
        "risk": "medium",
        "detection": {"binary": [], "snap": [], "config_files": []},
    }
    base.update(overrides)
    return base


def write_registry(tmp_path: Path, entries: list) -> Path:
    """Write a services.json file to tmp_path and return its path."""
    path = tmp_path / "services.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

class TestDetection:
    def test_from_dict_full(self):
        d = Detection.from_dict({
            "binary": ["/usr/bin/gitea"],
            "snap": ["nextcloud"],
            "config_files": ["/etc/gitea/app.ini"],
        })
        assert d.binary == ("/usr/bin/gitea",)
        assert d.snap == ("nextcloud",)
        assert d.config_files == ("/etc/gitea/app.ini",)

    def test_from_dict_empty(self):
        d = Detection.from_dict({})
        assert d.binary == ()
        assert d.snap == ()
        assert d.config_files == ()

    def test_immutable(self):
        d = Detection.from_dict({"binary": ["/bin/foo"]})
        with pytest.raises((AttributeError, TypeError)):
            d.binary = ("/bin/bar",)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class TestService:
    def test_from_dict_valid(self):
        s = Service.from_dict(make_service_dict())
        assert s.id == "test_svc"
        assert s.label == "Test Service"
        assert s.packages == ("test-pkg",)
        assert s.ports == ("1234/tcp",)
        assert s.risk == "medium"

    def test_missing_required_field_raises(self):
        data = make_service_dict()
        del data["label"]
        with pytest.raises(ValueError, match="missing required field"):
            Service.from_dict(data)

    def test_invalid_risk_raises(self):
        with pytest.raises(ValueError, match="invalid risk"):
            Service.from_dict(make_service_dict(risk="extreme"))

    def test_valid_risks_accepted(self):
        for risk in ("low", "medium", "high", "critical"):
            s = Service.from_dict(make_service_dict(risk=risk))
            assert s.risk == risk

    def test_is_critical(self):
        s = Service.from_dict(make_service_dict(risk="critical"))
        assert s.is_critical
        s2 = Service.from_dict(make_service_dict(risk="high"))
        assert not s2.is_critical

    def test_is_high_or_critical(self):
        for risk in ("high", "critical"):
            s = Service.from_dict(make_service_dict(risk=risk))
            assert s.is_high_or_critical
        for risk in ("low", "medium"):
            s = Service.from_dict(make_service_dict(risk=risk))
            assert not s.is_high_or_critical

    def test_main_port(self):
        s = Service.from_dict(make_service_dict(ports=["22/tcp", "2222/tcp"]))
        assert s.main_port == "22/tcp"

    def test_main_port_empty(self):
        s = Service.from_dict(make_service_dict(
            ports=[], detection={"binary": [], "snap": [], "config_files": ["/etc/x.conf"]}))
        assert s.main_port == ""

    def test_immutable(self):
        s = Service.from_dict(make_service_dict())
        with pytest.raises((AttributeError, TypeError)):
            s.risk = "low"


# ---------------------------------------------------------------------------
# ServiceRegistry
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=False)
def no_plugins(tmp_path):
    """Patch _PLUGIN_DIR to a non-existent path so user plugins don't interfere."""
    with patch("bob.registry._PLUGIN_DIR", tmp_path / "no_plugins"):
        yield


class TestServiceRegistryLoad:
    def test_load_default_file(self):
        """Default services.json must load without errors."""
        registry = ServiceRegistry.load()
        assert len(registry) > 0

    def test_load_custom_path(self, tmp_path, no_plugins):
        entries = [make_service_dict(id="svc1"), make_service_dict(id="svc2")]
        path = write_registry(tmp_path, entries)
        registry = ServiceRegistry.load(path=path)
        assert len(registry) == 2

    def test_load_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ServiceRegistry.load(path=tmp_path / "nonexistent.json")

    def test_load_invalid_json_raises(self, tmp_path):
        path = tmp_path / "services.json"
        path.write_text("not valid json", encoding="utf-8")
        with pytest.raises(Exception):
            ServiceRegistry.load(path=path)

    def test_load_non_array_raises(self, tmp_path):
        path = tmp_path / "services.json"
        path.write_text('{"key": "value"}', encoding="utf-8")
        with pytest.raises(ValueError, match="array"):
            ServiceRegistry.load(path=path)

    def test_load_duplicate_id_raises(self, tmp_path, no_plugins):
        entries = [make_service_dict(id="dup"), make_service_dict(id="dup")]
        path = write_registry(tmp_path, entries)
        with pytest.raises(ValueError, match="Duplicate"):
            ServiceRegistry.load(path=path)

    def test_load_invalid_entry_raises(self, tmp_path):
        entries = [{"id": "broken"}]  # missing required fields
        path = write_registry(tmp_path, entries)
        with pytest.raises(ValueError):
            ServiceRegistry.load(path=path)


class TestServiceRegistryAccess:
    @pytest.fixture
    def registry(self, tmp_path):
        entries = [
            make_service_dict(id="ssh",   risk="critical"),
            make_service_dict(id="nginx", risk="medium"),
            make_service_dict(id="redis", risk="critical"),
            make_service_dict(id="cups",  risk="low"),
            make_service_dict(id="ha",    risk="high"),
        ]
        path = write_registry(tmp_path, entries)
        no_plugin_dir = tmp_path / "no_plugins"
        with patch("bob.registry._PLUGIN_DIR", no_plugin_dir):
            return ServiceRegistry.load(path=path)

    def test_all_returns_all(self, registry):
        assert len(registry.all()) == 5

    def test_get_existing(self, registry):
        s = registry.get("ssh")
        assert s is not None
        assert s.id == "ssh"

    def test_get_missing_returns_none(self, registry):
        assert registry.get("nonexistent") is None

    def test_by_risk_critical(self, registry):
        critical = registry.by_risk("critical")
        assert len(critical) == 2
        assert all(s.risk == "critical" for s in critical)

    def test_by_risk_low(self, registry):
        low = registry.by_risk("low")
        assert len(low) == 1
        assert low[0].id == "cups"

    def test_by_risk_empty(self, registry):
        assert registry.by_risk("medium_plus") == []

    def test_high_and_critical(self, registry):
        hc = registry.high_and_critical()
        assert len(hc) == 3  # ssh, redis (critical) + ha (high)
        assert all(s.is_high_or_critical for s in hc)

    def test_len(self, registry):
        assert len(registry) == 5

    def test_iter(self, registry):
        ids = [s.id for s in registry]
        assert ids == ["ssh", "nginx", "redis", "cups", "ha"]

    def test_order_preserved(self, registry):
        """Services must be returned in definition order."""
        all_services = registry.all()
        assert all_services[0].id == "ssh"
        assert all_services[-1].id == "ha"


class TestPluginLoading:
    """Tests for _load_plugins — uses tmp_path as the plugin directory."""

    def _write_plugin(self, plugin_dir: Path, name: str, entries: list) -> Path:
        f = plugin_dir / name
        f.write_text(json.dumps(entries), encoding="utf-8")
        return f

    def _patch_plugin_dir(self, plugin_dir: Path):
        return patch("bob.registry._PLUGIN_DIR", plugin_dir)

    def test_valid_plugin_loaded(self, tmp_path):
        plugin_dir = tmp_path / "services.d"
        plugin_dir.mkdir()
        self._write_plugin(plugin_dir, "custom.json", [make_service_dict(id="custom_svc")])
        services: list = []
        ids_seen: set = set()
        with self._patch_plugin_dir(plugin_dir):
            _load_plugins(services, ids_seen)
        assert len(services) == 1
        assert services[0].id == "custom_svc"

    def test_no_plugin_dir_does_nothing(self, tmp_path):
        missing = tmp_path / "nonexistent"
        services: list = []
        ids_seen: set = set()
        with self._patch_plugin_dir(missing):
            _load_plugins(services, ids_seen)
        assert services == []

    def test_invalid_json_skipped(self, tmp_path):
        plugin_dir = tmp_path / "services.d"
        plugin_dir.mkdir()
        (plugin_dir / "bad.json").write_text("not json", encoding="utf-8")
        services: list = []
        ids_seen: set = set()
        with self._patch_plugin_dir(plugin_dir):
            _load_plugins(services, ids_seen)
        assert services == []

    def test_non_array_json_skipped(self, tmp_path):
        plugin_dir = tmp_path / "services.d"
        plugin_dir.mkdir()
        (plugin_dir / "bad.json").write_text('{"key": "value"}', encoding="utf-8")
        services: list = []
        ids_seen: set = set()
        with self._patch_plugin_dir(plugin_dir):
            _load_plugins(services, ids_seen)
        assert services == []

    def test_invalid_entry_in_array_skipped(self, tmp_path):
        """A broken entry doesn't abort loading — valid entries in same file still load."""
        plugin_dir = tmp_path / "services.d"
        plugin_dir.mkdir()
        entries = [
            {"id": "broken"},          # missing required fields
            make_service_dict(id="ok_svc"),
        ]
        self._write_plugin(plugin_dir, "mixed.json", entries)
        services: list = []
        ids_seen: set = set()
        with self._patch_plugin_dir(plugin_dir):
            _load_plugins(services, ids_seen)
        assert len(services) == 1
        assert services[0].id == "ok_svc"

    def test_duplicate_id_skipped(self, tmp_path):
        """Plugin entry whose id is already registered is silently skipped."""
        plugin_dir = tmp_path / "services.d"
        plugin_dir.mkdir()
        self._write_plugin(plugin_dir, "dup.json", [make_service_dict(id="existing")])
        services: list = []
        ids_seen: set = {"existing"}
        with self._patch_plugin_dir(plugin_dir):
            _load_plugins(services, ids_seen)
        assert services == []

    def test_oversized_plugin_skipped(self, tmp_path):
        """Plugin exceeding 256 KB is skipped without crashing."""
        plugin_dir = tmp_path / "services.d"
        plugin_dir.mkdir()
        big = plugin_dir / "big.json"
        big.write_bytes(b"x" * (256 * 1024 + 1))
        services: list = []
        ids_seen: set = set()
        with self._patch_plugin_dir(plugin_dir):
            _load_plugins(services, ids_seen)
        assert services == []

    def test_multiple_plugins_all_loaded(self, tmp_path):
        """Multiple plugin files are merged in sorted order."""
        plugin_dir = tmp_path / "services.d"
        plugin_dir.mkdir()
        self._write_plugin(plugin_dir, "a.json", [make_service_dict(id="svc_a")])
        self._write_plugin(plugin_dir, "b.json", [make_service_dict(id="svc_b")])
        services: list = []
        ids_seen: set = set()
        with self._patch_plugin_dir(plugin_dir):
            _load_plugins(services, ids_seen)
        assert {s.id for s in services} == {"svc_a", "svc_b"}

    def test_plugin_integrated_via_registry_load(self, tmp_path):
        """End-to-end: plugin services appear in the registry after load()."""
        plugin_dir = tmp_path / "services.d"
        plugin_dir.mkdir()
        self._write_plugin(plugin_dir, "custom.json", [make_service_dict(id="my_custom")])
        with self._patch_plugin_dir(plugin_dir):
            registry = ServiceRegistry.load()
        assert registry.get("my_custom") is not None


class TestDefaultRegistry:
    def test_all_known_services_present(self):
        registry = ServiceRegistry.load()
        expected_ids = {
            "ssh", "vnc", "samba", "ftp", "apache", "nginx",
            "mysql", "postgresql", "transmission", "qbittorrent",
            "avahi", "cups", "cockpit", "wireguard", "redis",
            "jellyfin", "plex", "homeassistant", "nextcloud",
            "gitea", "mosquitto", "syncthing",
        }
        actual_ids = {s.id for s in registry}
        # User plugins may add extra services — check built-ins are a subset
        assert expected_ids.issubset(actual_ids), (
            f"Missing built-in services: {expected_ids - actual_ids}"
        )

    def test_all_services_have_valid_risk(self):
        registry = ServiceRegistry.load()
        for service in registry:
            assert service.risk in ("low", "medium", "high", "critical"), (
                f"Service {service.id!r} has invalid risk: {service.risk!r}"
            )

    def test_all_services_have_ports(self):
        registry = ServiceRegistry.load()
        for service in registry:
            assert len(service.ports) > 0, (
                f"Service {service.id!r} has no ports defined"
            )

    def test_ssh_is_critical(self):
        registry = ServiceRegistry.load()
        ssh = registry.get("ssh")
        assert ssh is not None
        assert ssh.risk == "critical"

    def test_avahi_is_low(self):
        registry = ServiceRegistry.load()
        avahi = registry.get("avahi")
        assert avahi is not None
        assert avahi.risk == "low"
