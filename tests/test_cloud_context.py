"""v0.13.1 — host-side cloud context check (INFO-only, suppressed off-cloud)."""

from __future__ import annotations

import stat

from bob.checks import cloud_context as cc
from bob.checks.cloud_context import (
    CloudContextSnapshot,
    check_cloud_context,
    _detect_provider,
    _imds_onlink,
)
from bob.scoring import FindingLevel


class TestCheckLogic:
    def test_not_cloud_emits_nothing(self):
        r = check_cloud_context(CloudContextSnapshot(is_cloud=False))
        assert r.findings == []
        assert not r.deductions

    def test_named_provider_detected(self):
        r = check_cloud_context(CloudContextSnapshot(is_cloud=True, provider="Amazon EC2"))
        assert any(f.key == "cloud_context.detected" for f in r.findings)
        assert all(f.level is FindingLevel.INFO for f in r.findings)
        assert not r.deductions

    def test_generic_provider_when_only_cloud_init(self):
        r = check_cloud_context(
            CloudContextSnapshot(is_cloud=True, provider="", cloud_init_present=True))
        assert any(f.key == "cloud_context.detected_generic" for f in r.findings)

    def test_imds_onlink_surfaced(self):
        r = check_cloud_context(
            CloudContextSnapshot(is_cloud=True, provider="Google Cloud", imds_onlink=True))
        assert any(f.key == "cloud_context.imds_reachable" for f in r.findings)

    def test_userdata_world_readable_vs_present(self):
        ro = check_cloud_context(
            CloudContextSnapshot(is_cloud=True, provider="Hetzner Cloud",
                                 userdata_path="/var/lib/cloud/instance/user-data.txt",
                                 userdata_world_read=True))
        assert any(f.key == "cloud_context.userdata_world_readable" for f in ro.findings)

        priv = check_cloud_context(
            CloudContextSnapshot(is_cloud=True, provider="Hetzner Cloud",
                                 userdata_path="/var/lib/cloud/instance/user-data.txt",
                                 userdata_world_read=False))
        assert any(f.key == "cloud_context.userdata_present" for f in priv.findings)

    def test_never_deducts(self):
        r = check_cloud_context(
            CloudContextSnapshot(is_cloud=True, provider="Amazon EC2",
                                 imds_onlink=True,
                                 userdata_path="/x", userdata_world_read=True))
        assert not r.deductions


class TestProviderDetection:
    def test_azure_asset_tag(self, monkeypatch):
        def fake_read(field):
            return cc._AZURE_ASSET_TAG if field == "chassis_asset_tag" else ""
        monkeypatch.setattr(cc, "_read_dmi", fake_read)
        assert _detect_provider() == "Microsoft Azure"

    def test_aws_vendor(self, monkeypatch):
        monkeypatch.setattr(cc, "_read_dmi",
                            lambda f: "amazon ec2" if f == "sys_vendor" else "")
        assert _detect_provider() == "Amazon EC2"
        # GCE reports product_name "Google Compute Engine".
        monkeypatch.setattr(cc, "_read_dmi",
                            lambda f: "google compute engine" if f == "product_name" else "")
        assert _detect_provider() == "Google Cloud"

    def test_plain_vm_is_not_cloud(self, monkeypatch):
        # QEMU / VMware / consumer hardware must NOT be classified as cloud.
        vals = {"sys_vendor": "qemu", "product_name": "standard pc",
                "bios_vendor": "seabios", "chassis_asset_tag": ""}
        monkeypatch.setattr(cc, "_read_dmi", lambda f: vals.get(f, ""))
        assert _detect_provider() == ""
        # A Chromebook reports sys_vendor "Google" but is NOT a cloud instance —
        # the bare-"google" substring was tightened to "google compute".
        chromebook = {"sys_vendor": "google", "product_name": "eve"}
        monkeypatch.setattr(cc, "_read_dmi", lambda f: chromebook.get(f, ""))
        assert _detect_provider() == ""


class TestImdsOnlink:
    def test_via_gateway_is_not_imds(self, monkeypatch):
        # Routed through the default gateway -> NOT an on-link IMDS endpoint.
        monkeypatch.setattr(cc, "_run",
                            lambda *a, **k: "169.254.169.254 via 192.168.1.254 dev br0 src 192.168.1.10")
        assert _imds_onlink() is False

    def test_onlink_dev_is_imds(self, monkeypatch):
        monkeypatch.setattr(cc, "_run",
                            lambda *a, **k: "169.254.169.254 dev eth0 src 10.0.0.5 uid 0")
        assert _imds_onlink() is True

    def test_empty_route_is_false(self, monkeypatch):
        monkeypatch.setattr(cc, "_run", lambda *a, **k: "")
        assert _imds_onlink() is False


class TestSnapshotRobustness:
    def test_from_system_off_cloud_is_not_cloud(self, monkeypatch):
        # No provider + no cloud-init dir -> not cloud, no further probing.
        monkeypatch.setattr(cc, "_detect_provider", lambda: "")
        monkeypatch.setattr(cc, "_path_exists", lambda p: False)
        monkeypatch.setattr(cc, "_imds_onlink", lambda: False)
        snap = CloudContextSnapshot.from_system()
        assert snap.is_cloud is False

    def test_cloud_init_without_onlink_imds_is_not_cloud(self, monkeypatch):
        # Homelab false-positive guard: Ubuntu/Proxmox/VMware ship cloud-init
        # enabled, so /var/lib/cloud/instance exists, but the metadata address
        # is routed via the gateway (not on-link). Must NOT be classified cloud.
        monkeypatch.setattr(cc, "_detect_provider", lambda: "")
        monkeypatch.setattr(cc, "_path_exists", lambda p: True)   # cloud-init dir present
        monkeypatch.setattr(cc, "_imds_onlink", lambda: False)    # routed via gateway
        snap = CloudContextSnapshot.from_system()
        assert snap.cloud_init_present is True
        assert snap.is_cloud is False

    def test_cloud_init_with_onlink_imds_is_cloud(self, monkeypatch):
        # cloud-init present AND metadata on-link -> genuinely cloud.
        monkeypatch.setattr(cc, "_detect_provider", lambda: "")
        monkeypatch.setattr(cc, "_path_exists", lambda p: True)
        monkeypatch.setattr(cc, "_imds_onlink", lambda: True)
        monkeypatch.setattr(cc, "_file_mode", lambda p: None)
        snap = CloudContextSnapshot.from_system()
        assert snap.is_cloud is True
        assert snap.provider == ""           # generic path

    def test_provider_alone_is_cloud_without_imds(self, monkeypatch):
        # A DMI-identified provider is authoritative even if IMDS is not on-link.
        monkeypatch.setattr(cc, "_detect_provider", lambda: "Amazon EC2")
        monkeypatch.setattr(cc, "_path_exists", lambda p: False)
        monkeypatch.setattr(cc, "_imds_onlink", lambda: False)
        monkeypatch.setattr(cc, "_file_mode", lambda p: None)
        snap = CloudContextSnapshot.from_system()
        assert snap.is_cloud is True

    def test_file_mode_missing_is_none(self, tmp_path):
        assert cc._file_mode(tmp_path / "nope") is None

    def test_file_mode_reads_bits(self, tmp_path):
        f = tmp_path / "user-data.txt"
        f.write_text("x")
        f.chmod(0o644)
        assert cc._file_mode(f) == 0o644
        assert bool(cc._file_mode(f) & (stat.S_IRGRP | stat.S_IROTH)) is True
