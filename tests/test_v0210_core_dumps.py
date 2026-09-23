"""v0.21.0 — core-dump disposition check (CIS §1.5), INFO-only.

Core dumps can hold secrets from a crashed process. BOB reports where they go —
discarded (hard core 0 / Storage=none) → OK; kept by systemd-coredump, piped to
a handler, or written to disk → INFO with the secrets note. No deduction: a
dev/diagnostic host legitimately keeps dumps. The suid_dumpable *deduction* stays
with kernel_hardening; this check does not double-count it.
"""

from __future__ import annotations

import bob.checks.core_dumps as cd
from bob.checks.core_dumps import CoreDumpsSnapshot, check_core_dumps
from tests.helpers import _keys


def test_unreadable_is_unknown():
    assert _keys(check_core_dumps(CoreDumpsSnapshot(readable=False))) == ["core_dumps.unknown"]


class TestDisposition:
    _SYSTEMD = "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t"

    def test_hard_core_zero_is_disabled(self):
        snap = CoreDumpsSnapshot(core_pattern="core", hard_core_zero=True)
        assert _keys(check_core_dumps(snap)) == ["core_dumps.disabled"]

    def test_systemd_storage_none_is_disabled(self):
        """The mutation guard: Storage=none must read as dumps-discarded."""
        snap = CoreDumpsSnapshot(core_pattern=self._SYSTEMD, storage="none")
        assert _keys(check_core_dumps(snap)) == ["core_dumps.disabled"]

    def test_systemd_kept_is_info(self):
        snap = CoreDumpsSnapshot(core_pattern=self._SYSTEMD, storage="external")
        assert _keys(check_core_dumps(snap)) == ["core_dumps.systemd"]
        assert not check_core_dumps(snap).deductions

    def test_systemd_default_storage_is_info(self):
        snap = CoreDumpsSnapshot(core_pattern=self._SYSTEMD, storage="")
        assert _keys(check_core_dumps(snap)) == ["core_dumps.systemd"]

    def test_other_pipe_is_piped(self):
        snap = CoreDumpsSnapshot(core_pattern="|/usr/share/apport/apport %p")
        assert _keys(check_core_dumps(snap)) == ["core_dumps.piped"]

    def test_disk_pattern_is_to_disk(self):
        snap = CoreDumpsSnapshot(core_pattern="/var/crash/core.%e.%p")
        assert _keys(check_core_dumps(snap)) == ["core_dumps.to_disk"]

    def test_bare_core_is_to_disk(self):
        snap = CoreDumpsSnapshot(core_pattern="core")
        assert _keys(check_core_dumps(snap)) == ["core_dumps.to_disk"]


class TestFromSystem:
    def test_parses_pattern_storage_limits(self, monkeypatch):
        monkeypatch.setattr(cd, "path_exists", lambda p: str(p).endswith("coredump.conf")
                            or str(p).endswith("limits.conf"))
        def fake_read(p, **kw):
            s = str(p)
            if s.endswith("core_pattern"):
                return "|/usr/lib/systemd/systemd-coredump x\n"
            if s.endswith("coredump.conf"):
                return "[Coredump]\nStorage=none\n"
            if s.endswith("limits.conf"):
                return "*  hard  core  0\n"
            raise OSError("nope")
        monkeypatch.setattr(cd, "read_text_capped", fake_read)
        # avoid touching real dirs
        monkeypatch.setattr(cd.Path, "is_dir", lambda self: False)
        snap = CoreDumpsSnapshot.from_system()
        assert snap.storage == "none"
        assert snap.hard_core_zero is True
        assert "systemd-coredump" in snap.core_pattern

    def test_unreadable_core_pattern(self, monkeypatch):
        def boom(p, **kw):
            raise OSError("nope")
        monkeypatch.setattr(cd, "read_text_capped", boom)
        monkeypatch.setattr(cd, "path_exists", lambda p: False)
        assert CoreDumpsSnapshot.from_system().readable is False
