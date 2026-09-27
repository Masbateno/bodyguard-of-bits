"""v0.22.0 — kernel-module blacklist check (defense-in-depth), INFO-only.

Companion to ``kernel_modules`` (which flags rarely-needed modules that are
*loaded*): this one asks whether the rarely-needed modules that are *not* loaded
are kept from loading (a ``blacklist`` or ``install ... /bin/true`` directive).
Reported, never penalised — an un-blacklisted module is a hardening opportunity,
not a vulnerability. A single aggregated INFO, not one finding per module.
"""

from __future__ import annotations

import os

import bob.checks.module_blacklist as mb
from bob.checks.module_blacklist import (
    RECOMMENDED,
    ModuleBlacklistSnapshot,
    check_module_blacklist,
)
from tests.helpers import _keys


def _key_levels(result):
    return {f.key: f.level.value for f in result.findings}


class TestCandidates:
    def test_unblacklisted_module_is_flagged(self):
        """The mutation guard: a rarely-needed module that is neither loaded
        nor blacklisted must appear in the aggregated candidate INFO."""
        snap = ModuleBlacklistSnapshot(loaded=set(), disabled=set())
        r = check_module_blacklist(snap)
        levels = _key_levels(r)
        assert levels.get("module_blacklist.candidates") == "info"
        # every recommended module is a candidate here, and the message lists them
        msg = next(f.message for f in r.findings
                   if f.key == "module_blacklist.candidates")
        assert "dccp" in msg and "cramfs" in msg

    def test_blacklisted_module_is_not_a_candidate(self):
        snap = ModuleBlacklistSnapshot(loaded=set(), disabled=set(RECOMMENDED))
        r = check_module_blacklist(snap)
        assert _key_levels(r).get("module_blacklist.all_handled") == "ok"
        assert "module_blacklist.candidates" not in _keys(r)

    def test_loaded_module_is_not_a_candidate(self):
        """A loaded module is kernel_modules' concern, not re-reported here."""
        snap = ModuleBlacklistSnapshot(loaded=set(RECOMMENDED), disabled=set())
        r = check_module_blacklist(snap)
        assert "module_blacklist.candidates" not in _keys(r)
        assert _key_levels(r).get("module_blacklist.all_handled") == "ok"

    def test_partial_only_lists_the_gaps(self):
        snap = ModuleBlacklistSnapshot(
            loaded={"dccp"},
            disabled={"cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf"},
        )
        r = check_module_blacklist(snap)
        msg = next(f.message for f in r.findings
                   if f.key == "module_blacklist.candidates")
        assert "sctp" in msg          # neither loaded nor blacklisted
        assert "cramfs" not in msg    # blacklisted
        assert "dccp" not in msg      # loaded

    def test_is_never_more_than_info(self):
        """INFO-only invariant: no WARN/ALERT, no deduction, ever."""
        for snap in (
            ModuleBlacklistSnapshot(loaded=set(), disabled=set()),
            ModuleBlacklistSnapshot(loaded=set(), disabled=set(RECOMMENDED)),
            ModuleBlacklistSnapshot(config_read=False),
        ):
            r = check_module_blacklist(snap)
            assert not r.deductions
            assert all(f.level.value in ("ok", "info") for f in r.findings)


class TestUnknown:
    def test_unreadable_config_is_info(self):
        snap = ModuleBlacklistSnapshot(config_read=False)
        r = check_module_blacklist(snap)
        assert "module_blacklist.unreadable" in _keys(r)


class TestFromSystem:
    def test_parses_blacklist_and_install(self, tmp_path, monkeypatch):
        d = tmp_path / "modprobe.d"
        d.mkdir()
        (d / "cis.conf").write_text(
            "# hardening\n"
            "blacklist dccp\n"
            "install sctp /bin/true\n"
            "install usb-storage /bin/false\n"   # hyphen normalises to _
            "blacklist   tipc   # trailing comment\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(mb, "_MODPROBE_DIRS", (str(d),))
        monkeypatch.setattr(mb, "_PROC_MODULES", str(tmp_path / "none"))
        snap = ModuleBlacklistSnapshot.from_system()
        assert {"dccp", "sctp", "tipc", "usb_storage"} <= snap.disabled
        assert snap.config_read is True

    def test_reads_loaded_from_proc_modules(self, tmp_path, monkeypatch):
        proc = tmp_path / "modules"
        proc.write_text("dccp 12288 0 - Live 0x0\nsctp 405504 2 dccp, Live 0x0\n",
                        encoding="utf-8")
        monkeypatch.setattr(mb, "_MODPROBE_DIRS", (str(tmp_path / "absent"),))
        monkeypatch.setattr(mb, "_PROC_MODULES", str(proc))
        snap = ModuleBlacklistSnapshot.from_system()
        assert {"dccp", "sctp"} <= snap.loaded

    def test_unreadable_dir_marks_unknown(self, tmp_path, monkeypatch):
        d = tmp_path / "modprobe.d"
        d.mkdir()

        def boom(path):
            raise PermissionError(13, "denied")

        monkeypatch.setattr(mb, "_MODPROBE_DIRS", (str(d),))
        monkeypatch.setattr(mb, "_PROC_MODULES", str(tmp_path / "none"))
        monkeypatch.setattr(mb.os, "listdir", boom)
        snap = ModuleBlacklistSnapshot.from_system()
        # a directory that exists but cannot be listed is "unknown", not "clean"
        assert snap.config_read is False

    def test_absent_dirs_are_not_unknown(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mb, "_MODPROBE_DIRS", (str(tmp_path / "nope"),))
        monkeypatch.setattr(mb, "_PROC_MODULES", str(tmp_path / "none"))
        snap = ModuleBlacklistSnapshot.from_system()
        assert snap.config_read is True   # no config dir at all ≠ unreadable

    def test_fifo_conf_file_does_not_hang(self, tmp_path, monkeypatch):
        """A FIFO at a *.conf path must be skipped, not block the audit forever
        (the samba/sshd FIFO class, v0.20.1 / v0.21.2)."""
        d = tmp_path / "modprobe.d"
        d.mkdir()
        fifo = d / "evil.conf"
        os.mkfifo(fifo)
        (d / "real.conf").write_text("blacklist rds\n", encoding="utf-8")
        monkeypatch.setattr(mb, "_MODPROBE_DIRS", (str(d),))
        monkeypatch.setattr(mb, "_PROC_MODULES", str(tmp_path / "none"))
        snap = ModuleBlacklistSnapshot.from_system()   # must return, not hang
        assert "rds" in snap.disabled
        assert snap.config_read is True

    def test_from_system_never_raises(self):
        # Against the live host — the contract is that it degrades, never throws.
        ModuleBlacklistSnapshot.from_system()
