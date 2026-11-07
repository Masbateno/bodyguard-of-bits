"""v0.31.1 — usb_storage is a USB storage driver, not a filesystem module.

0.31.0 and earlier listed it among the filesystem modules: a Mint desktop
audit (7 November 2026) read "Module(s) de système de fichiers à risque
chargé(s) : usb_storage", −1 under the workstation profile, with the command
`sudo modprobe -r usb_storage` — which the kernel refuses there, since
`lsmod` shows "usb_storage ... 1 uas" (uas holds it). It now has its own
finding: −1 on a server, INFO without a deduction on a desktop or a
workstation (decided 7 November 2026), the command unloading uas first, and
the CIS reference ComplianceAsCode gives for it ("Ensure usb-storage kernel
module is not available").
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bob.checks.kernel_modules import KernelModulesSnapshot, check_kernel_modules, _RISKY_FS
from bob.profiles import load_profile
from bob.scoring import ScoreEngine


def _check(modules):
    return check_kernel_modules(KernelModulesSnapshot(lsmod_available=True, loaded_modules=list(modules)))


class TestItsOwnFinding:

    def test_not_a_filesystem_module(self):
        assert "usb_storage" not in _RISKY_FS
        keys = [f.key for f in _check(["usb_storage", "uas"]).findings]
        assert "kernel_modules.usb_storage" in keys and "kernel_modules.risky_fs" not in keys

    def test_a_filesystem_module_is_still_one(self):
        """Polarity twin: cramfs keeps the filesystem finding."""
        keys = [f.key for f in _check(["cramfs", "usb_storage"]).findings]
        assert "kernel_modules.risky_fs" in keys and "kernel_modules.usb_storage" in keys
        msg = next(f.message for f in _check(["cramfs", "usb_storage"]).findings if f.key == "kernel_modules.risky_fs")
        assert "usb_storage" not in msg

    @pytest.mark.parametrize("loaded, cmd", [
        (["usb_storage", "uas"], "sudo modprobe -r uas usb_storage"),
        (["usb_storage"], "sudo modprobe -r usb_storage"),
    ], ids=["held-by-uas", "alone"])
    def test_the_command_unloads_what_holds_it_first(self, loaded, cmd):
        f = next(f for f in _check(loaded).findings if f.key == "kernel_modules.usb_storage")
        assert f.cmd == cmd

    def test_not_loaded_is_ok(self):
        keys = [f.key for f in _check(["ext4", "uas"]).findings]
        assert "kernel_modules.usb_storage" not in keys and "kernel_modules.ok" in keys


class TestTheProfiles:

    @staticmethod
    def _score(profile):
        engine = ScoreEngine(load_profile(profile) if profile else None)
        engine.apply(_check(["usb_storage", "uas"]))
        return engine

    def test_a_server_loses_the_point(self):
        assert any(d.key == "kernel_modules.usb_storage" for d in self._score("server").breakdown)

    @pytest.mark.parametrize("profile", ["desktop", "workstation"])
    def test_a_desktop_or_workstation_does_not(self, profile):
        assert load_profile(profile).overrides.get("kernel_modules.usb_storage") == "info"
        assert not any(d.key == "kernel_modules.usb_storage" for d in self._score(profile).breakdown)


def test_its_cis_reference_comes_from_complianceascode():
    refs = json.loads((Path(__file__).resolve().parent.parent / "bob" / "data" / "cis_refs.json").read_text(encoding="utf-8"))
    ref = refs["kernel_modules.usb_storage"]
    assert ref["code"] == "CIS:1.1.1.8" and "usb-storage kernel module is not available" in ref["ref"]
