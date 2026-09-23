"""v0.21.0 — kexec / kernel-lockdown check (boot integrity), INFO-only.

Companion to Secure Boot/GRUB: kexec_load_disabled=0 lets a new kernel be booted
without a reboot (a Secure-Boot bypass), and kernel lockdown blocks even root
from modifying the running kernel. Both reported, neither penalised — kexec is
used by kdump and lockdown is off by default without Secure Boot. "kexec
available" is never called a vulnerability.
"""

from __future__ import annotations

import bob.checks.kexec_lockdown as kl
from bob.checks.kexec_lockdown import KexecLockdownSnapshot, check_kexec_lockdown
from tests.helpers import _keys


def _key_levels(result):
    return {f.key: f.level.value for f in result.findings}


class TestKexec:
    def test_locked_is_ok(self):
        """The mutation guard: kexec_load_disabled=1 must read as locked (OK)."""
        r = check_kexec_lockdown(KexecLockdownSnapshot(kexec_disabled=1, lockdown="none"))
        assert _key_levels(r)["kexec_lockdown.kexec_disabled"] == "ok"

    def test_allowed_is_info(self):
        r = check_kexec_lockdown(KexecLockdownSnapshot(kexec_disabled=0, lockdown="none"))
        assert _key_levels(r)["kexec_lockdown.kexec_allowed"] == "info"
        assert not r.deductions

    def test_unknown_is_info(self):
        r = check_kexec_lockdown(KexecLockdownSnapshot(kexec_disabled=None, lockdown="none"))
        assert "kexec_lockdown.kexec_unknown" in _keys(r)


class TestLockdown:
    def test_integrity_is_ok(self):
        r = check_kexec_lockdown(KexecLockdownSnapshot(kexec_disabled=1, lockdown="integrity"))
        assert _key_levels(r)["kexec_lockdown.lockdown_active"] == "ok"

    def test_confidentiality_is_ok(self):
        r = check_kexec_lockdown(KexecLockdownSnapshot(kexec_disabled=1, lockdown="confidentiality"))
        assert "kexec_lockdown.lockdown_active" in _keys(r)

    def test_none_is_info(self):
        r = check_kexec_lockdown(KexecLockdownSnapshot(kexec_disabled=1, lockdown="none"))
        assert "kexec_lockdown.lockdown_none" in _keys(r)

    def test_absent_interface_is_info(self):
        r = check_kexec_lockdown(KexecLockdownSnapshot(kexec_disabled=1, lockdown=""))
        assert "kexec_lockdown.lockdown_absent" in _keys(r)

    def test_unreadable_is_info(self):
        r = check_kexec_lockdown(KexecLockdownSnapshot(kexec_disabled=1, lockdown=None))
        assert "kexec_lockdown.lockdown_unknown" in _keys(r)


class TestFromSystem:
    def test_parses_bracketed_lockdown(self, monkeypatch):
        monkeypatch.setattr(kl, "path_exists", lambda p: True)
        def fake(p, **kw):
            s = str(p)
            if s.endswith("kexec_load_disabled"):
                return "1\n"
            if s.endswith("lockdown"):
                return "none [integrity] confidentiality\n"
            raise OSError
        monkeypatch.setattr(kl, "read_text_capped", fake)
        snap = KexecLockdownSnapshot.from_system()
        assert snap.kexec_disabled == 1
        assert snap.lockdown == "integrity"

    def test_lockdown_interface_absent(self, monkeypatch):
        monkeypatch.setattr(kl, "path_exists", lambda p: False)
        monkeypatch.setattr(kl, "read_text_capped", lambda p, **kw: "0\n")
        snap = KexecLockdownSnapshot.from_system()
        assert snap.lockdown == ""  # absent, not unknown
