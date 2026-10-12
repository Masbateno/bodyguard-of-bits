"""v0.24.4 — a sysctl fix must still hold after the next reboot.

BOB persists sysctl fixes to ``/etc/sysctl.d/99-hardening.conf``. systemd-sysctl
applies its files in file-name order, the last assignment winning, so any file
sorting after BOB's that sets the same key undoes the fix at boot. Measured:

- Linux Mint 22.3 — ``/etc/sysctl.d/99-sysctl.conf`` is a link to
  ``/etc/sysctl.conf`` and sorts after ``99-hardening.conf``. With
  ``net.ipv4.conf.all.accept_redirects = 1`` in sysctl.conf, BOB's fix set 0 and
  BOB said OK; after a reboot the value was 1 and BOB warned again.
- Raspberry Pi (trixie) — the same with ``/etc/sysctl.d/99-zlocal.conf``.

The fix now persists where it wins: at the end of the administrator's file that
would otherwise win (a later line in one file wins), or — when the winner ships
with the system — in a new /etc/sysctl.d file sorting just after it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob.checks import _run
from bob.checks._run import SYSCTL_CONF, durable_sysctl_conf, read_sysctl_boot_files, sysctl_fix

_KEY = "net.ipv4.conf.all.accept_redirects"


@pytest.fixture
def no_links(monkeypatch):
    """Resolve paths as themselves: the test host's own /etc is not the subject."""
    monkeypatch.setattr(_run.os.path, "realpath", lambda p: p)


class TestReadingTheBootFiles:
    @pytest.fixture
    def dirs(self, tmp_path, monkeypatch):
        etc, usr = tmp_path / "etc", tmp_path / "usr"
        etc.mkdir(); usr.mkdir()
        monkeypatch.setattr(_run, "_SYSCTL_BOOT_DIRS", (str(etc), str(usr)))
        return etc, usr

    def test_file_name_order_across_directories(self, dirs):
        etc, usr = dirs
        (usr / "50-a.conf").write_text("kernel.x = 1\n")
        (etc / "10-b.conf").write_text("kernel.x = 2\n")
        (etc / "99-sysctl.conf").write_text(f"{_KEY} = 1\n")
        assert [name for name, _, _ in read_sysctl_boot_files()] == ["10-b.conf", "50-a.conf", "99-sysctl.conf"]

    def test_an_etc_file_masks_the_same_name_shipped_by_the_system(self, dirs):
        etc, usr = dirs
        (usr / "99-x.conf").write_text("kernel.x = 1\n")
        (etc / "99-x.conf").write_text("kernel.x = 2\n")
        [(_, path, settings)] = read_sysctl_boot_files()
        assert path == f"{etc}/99-x.conf" and settings == {"kernel.x": "2"}

    def test_lines_are_read_as_systemd_reads_them(self, dirs):
        etc, _ = dirs
        (etc / "50-x.conf").write_text("# c\n; c\nnet/ipv4/ip_forward=0\n-kernel.y = 3\nkernel.z=\n")
        [(_, _, settings)] = read_sysctl_boot_files()
        assert settings == {"net.ipv4.ip_forward": "0", "kernel.y": "3", "kernel.z": ""}


class TestWhereTheFixPersists:
    def test_nothing_later_keeps_bobs_file(self, no_links):
        boot = [("10-network-security.conf", "/etc/sysctl.d/10-network-security.conf", {_KEY: "1"})]
        assert durable_sysctl_conf(f"{_KEY}=0", boot) == SYSCTL_CONF

    def test_a_later_file_with_the_same_value_changes_nothing(self, no_links):
        boot = [("99-sysctl.conf", "/etc/sysctl.d/99-sysctl.conf", {_KEY: "0"})]
        assert durable_sysctl_conf(f"{_KEY}=0", boot) == SYSCTL_CONF

    def test_the_mint_case_goes_to_the_winning_admin_file(self, monkeypatch):
        monkeypatch.setattr(_run.os.path, "realpath",
                            lambda p: "/etc/sysctl.conf" if p == "/etc/sysctl.d/99-sysctl.conf" else p)
        boot = [("99-sysctl.conf", "/etc/sysctl.d/99-sysctl.conf", {_KEY: "1"})]
        assert durable_sysctl_conf(f"{_KEY}=0", boot) == "/etc/sysctl.conf"

    def test_the_last_overriding_file_wins(self, no_links):
        boot = [("99-sysctl.conf", "/etc/sysctl.d/99-sysctl.conf", {_KEY: "1"}),
                ("99-zlocal.conf", "/etc/sysctl.d/99-zlocal.conf", {_KEY: "1"})]
        assert durable_sysctl_conf(f"{_KEY}=0", boot) == "/etc/sysctl.d/99-zlocal.conf"

    def test_a_system_file_is_left_alone(self, no_links):
        boot = [("99-vendor.conf", "/usr/lib/sysctl.d/99-vendor.conf", {_KEY: "1"})]
        conf = durable_sysctl_conf(f"{_KEY}=0", boot)
        assert conf == "/etc/sysctl.d/99-vendor.conf-bob.conf"
        assert Path(conf).name > "99-vendor.conf"   # sorts after the vendor file


class TestTheChecksUseIt:
    _BOOT = [("99-sysctl.conf", "/etc/sysctl.d/99-sysctl.conf", {_KEY: "1"})]

    def test_hardening(self, no_links):
        from bob.checks.hardening import HardeningSnapshot, check_hardening
        from tests.helpers import _t
        snap = HardeningSnapshot(accept_redirects=True, boot_sysctl=self._BOOT)
        finding = next(f for f in check_hardening(snap, t=_t).findings
                       if f.key == "hardening.redirects_enabled")
        assert "/etc/sysctl.d/99-sysctl.conf" in finding.cmd
        assert finding.fix_action["conf"] == "/etc/sysctl.d/99-sysctl.conf"

    def test_kernel_hardening(self, no_links):
        from bob.checks.kernel_hardening import KernelHardeningSnapshot, check_kernel_hardening
        from tests.helpers import _t
        boot = [("99-zz.conf", "/etc/sysctl.d/99-zz.conf", {"kernel.kptr_restrict": "0"})]
        snap = KernelHardeningSnapshot(kptr_restrict=0, boot_sysctl=boot)
        finding = next(f for f in check_kernel_hardening(snap, t=_t).findings
                       if f.key == "kernel_hardening.kptr_exposed")
        assert finding.fix_action["conf"] == "/etc/sysctl.d/99-zz.conf"

    def test_without_boot_files_the_fix_is_unchanged(self):
        assert sysctl_fix(f"{_KEY}=0")["fix_action"]["conf"] == SYSCTL_CONF

    @pytest.mark.parametrize("module", ["hardening", "kernel_hardening"])
    def test_the_snapshot_reads_the_boot_files(self, module):
        import importlib
        import inspect
        src = inspect.getsource(importlib.import_module(f"bob.checks.{module}"))
        assert "boot_sysctl=read_sysctl_boot_files()," in src


class TestALiveValueTheBootFilesUndo:
    """``sysctl -w`` lasts until the next reboot. BOB judged the live value
    and said OK; on the Pi and on Mint the reboot put the files' value back."""

    def test_a_live_value_the_files_undo_is_said(self, no_links):
        from bob.checks.hardening import HardeningSnapshot, check_hardening
        from tests.helpers import _t
        boot = [("99-sysctl.conf", "/etc/sysctl.d/99-sysctl.conf", {_KEY: "1"})]
        result = check_hardening(HardeningSnapshot(accept_redirects=False, boot_sysctl=boot), t=_t)
        finding = next(f for f in result.findings if f.key == "hardening.reverts_at_boot")
        assert finding.template_vars == {"param": _KEY, "now": "0", "boot": "1",
                                         "file": "/etc/sysctl.d/99-sysctl.conf"}
        assert not [d for d in result.deductions if d.key == "hardening.reverts_at_boot"]

    def test_agreeing_files_say_nothing(self):
        from bob.checks.hardening import HardeningSnapshot, check_hardening
        from tests.helpers import _keys, _t
        boot = [("99-x.conf", "/etc/sysctl.d/99-x.conf", {_KEY: " 0 "})]
        result = check_hardening(HardeningSnapshot(accept_redirects=False, boot_sysctl=boot), t=_t)
        assert "hardening.reverts_at_boot" not in _keys(result)

    def test_the_last_file_is_the_boot_value(self, no_links):
        boot = [("10-a.conf", "/etc/sysctl.d/10-a.conf", {"kernel.x": "1"}),
                ("90-b.conf", "/etc/sysctl.d/90-b.conf", {"kernel.x": "2"})]
        assert _run.sysctl_boot_drift({"kernel.x": 1}, boot) == [("kernel.x", "1", "2", "/etc/sysctl.d/90-b.conf")]

    def test_an_unknown_live_value_is_not_compared(self):
        boot = [("10-a.conf", "/etc/sysctl.d/10-a.conf", {"kernel.x": "1"})]
        assert _run.sysctl_boot_drift({"kernel.x": None}, boot) == []

    def test_kernel_hardening_says_it_too(self, no_links):
        from bob.checks.kernel_hardening import KernelHardeningSnapshot, check_kernel_hardening
        from tests.helpers import _keys, _t
        boot = [("99-zz.conf", "/etc/sysctl.d/99-zz.conf", {"kernel.kptr_restrict": "0"})]
        result = check_kernel_hardening(KernelHardeningSnapshot(kptr_restrict=1, boot_sysctl=boot), t=_t)
        assert "kernel_hardening.reverts_at_boot" in _keys(result)

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_rendered_message(self, no_links, lang):
        from bob import i18n
        from bob.checks.hardening import HardeningSnapshot, check_hardening
        boot = [("99-sysctl.conf", "/etc/sysctl.d/99-sysctl.conf", {_KEY: "1"})]
        i18n.init(lang)
        try:
            msg = next(f for f in check_hardening(HardeningSnapshot(accept_redirects=False, boot_sysctl=boot),
                                                  t=i18n.t).findings if f.key == "hardening.reverts_at_boot").message
        finally:
            i18n.init(lang="en")
        assert _KEY in msg and "/etc/sysctl.d/99-sysctl.conf" in msg and "{" not in msg
