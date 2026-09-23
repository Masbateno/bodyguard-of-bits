"""v0.21.0 (Wave 3) — polkit authorization-rule check.

Scoped narrowly to the unambiguous privesc signal: polkit evaluates its rule
files as root, so a .rules/.pkla file a non-root user can write is a direct path
to root (WARN, auto-fixable with chown/chmod). A legacy .pkla granting
ResultAny=yes (auth bypass for any session) is surfaced as INFO, not scored.
"""

from __future__ import annotations

import os
import stat

import bob.checks.polkit as pk
from bob.checks.polkit import PolkitSnapshot, check_polkit
from bob.scoring import FindingLevel
from tests.helpers import _keys, _get_finding


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

class TestVerdict:
    def test_not_present_is_info(self):
        assert _keys(check_polkit(PolkitSnapshot(present=False))) == ["polkit.not_present"]

    def test_clean_rules_are_ok(self):
        snap = PolkitSnapshot(present=True, readable=True)
        assert _keys(check_polkit(snap)) == ["polkit.rules_ok"]

    def test_writable_rule_warns_and_deducts(self):
        """The mutation guard: a non-root-writable rule WARNs + deducts."""
        snap = PolkitSnapshot(present=True,
                              writable_rules=["/etc/polkit-1/rules.d/50-x.rules"])
        r = check_polkit(snap)
        f = _get_finding(r, "polkit.rule_writable")
        assert f is not None and f.level == FindingLevel.WARN
        assert sum(d.points for d in r.deductions) >= 1

    def test_writable_rule_offers_a_fix_command(self):
        snap = PolkitSnapshot(present=True,
                              writable_rules=["/etc/polkit-1/rules.d/50-x.rules"])
        f = _get_finding(check_polkit(snap), "polkit.rule_writable")
        assert f.cmd and "chown root:root" in f.cmd and "50-x.rules" in f.cmd

    def test_each_writable_rule_is_its_own_finding(self):
        snap = PolkitSnapshot(present=True,
                              writable_rules=["/a.rules", "/b.rules"])
        r = check_polkit(snap)
        assert _keys(r).count("polkit.rule_writable") == 2
        assert sum(d.points for d in r.deductions) == 2

    def test_pkla_any_yes_is_info_no_deduction(self):
        snap = PolkitSnapshot(present=True,
                              pkla_any_yes=["/etc/polkit-1/localauthority/50-local.d/x.pkla"])
        r = check_polkit(snap)
        f = _get_finding(r, "polkit.pkla_any_yes")
        assert f is not None and f.level == FindingLevel.INFO
        assert not r.deductions

    def test_unreadable_is_info_when_nothing_else(self):
        snap = PolkitSnapshot(present=True, readable=False)
        assert _keys(check_polkit(snap)) == ["polkit.unreadable"]


# ---------------------------------------------------------------------------
# from_system — permission detection
# ---------------------------------------------------------------------------

def _mk(mode, uid=0):
    return os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))


def _wire(monkeypatch, *, dirstats, filestats, listings, reads=None):
    """dirstats/filestats: path -> os.stat_result (or KeyError → OSError)."""
    reads = reads or {}

    def fake_stat(path, *a, **kw):
        p = str(path)
        if p in dirstats:
            return dirstats[p]
        if p in filestats:
            return filestats[p]
        raise OSError("no such path")

    def fake_listdir(path):
        p = str(path)
        if p in listings:
            return list(listings[p])
        raise OSError("no such dir")

    def fake_read(path, **kw):
        p = str(path)
        if p in reads:
            return reads[p]
        raise OSError("no such file")

    monkeypatch.setattr(os, "stat", fake_stat)
    monkeypatch.setattr(os, "listdir", fake_listdir)
    monkeypatch.setattr(pk, "read_text_capped", fake_read)


_DIR = stat.S_IFDIR | 0o755
_REG = stat.S_IFREG


class TestFromSystem:
    def test_group_writable_rule_is_flagged(self, monkeypatch):
        """uid 0 but group-writable — kills the mode-bit mutation."""
        d = "/etc/polkit-1/rules.d"
        f = f"{d}/50-test.rules"
        _wire(monkeypatch,
              dirstats={d: _mk(_DIR)},
              filestats={f: _mk(_REG | 0o664, uid=0)},
              listings={d: ["50-test.rules"]})
        snap = PolkitSnapshot.from_system()
        assert snap.present is True
        assert f in snap.writable_rules

    def test_nonroot_owned_rule_is_flagged(self, monkeypatch):
        d = "/etc/polkit-1/rules.d"
        f = f"{d}/50-test.rules"
        _wire(monkeypatch,
              dirstats={d: _mk(_DIR)},
              filestats={f: _mk(_REG | 0o644, uid=1000)},
              listings={d: ["50-test.rules"]})
        snap = PolkitSnapshot.from_system()
        assert f in snap.writable_rules

    def test_root_owned_0644_rule_is_clean(self, monkeypatch):
        d = "/etc/polkit-1/rules.d"
        f = f"{d}/50-test.rules"
        _wire(monkeypatch,
              dirstats={d: _mk(_DIR)},
              filestats={f: _mk(_REG | 0o644, uid=0)},
              listings={d: ["50-test.rules"]})
        snap = PolkitSnapshot.from_system()
        assert snap.present is True and snap.writable_rules == []

    def test_world_writable_rules_dir_is_flagged(self, monkeypatch):
        d = "/etc/polkit-1/rules.d"
        _wire(monkeypatch,
              dirstats={d: _mk(stat.S_IFDIR | 0o757)},  # o+w on the dir
              filestats={},
              listings={d: []})
        snap = PolkitSnapshot.from_system()
        assert d in snap.writable_rules

    def test_absent_polkit_is_not_present(self, monkeypatch):
        _wire(monkeypatch, dirstats={}, filestats={}, listings={})
        snap = PolkitSnapshot.from_system()
        assert snap.present is False

    def test_pkla_result_any_yes_detected(self, monkeypatch):
        root = "/etc/polkit-1/localauthority"
        sub = f"{root}/50-local.d"
        f = f"{sub}/nopass.pkla"
        _wire(monkeypatch,
              dirstats={root: _mk(_DIR)},
              filestats={f: _mk(_REG | 0o644, uid=0)},
              listings={root: ["50-local.d"], sub: ["nopass.pkla"]},
              reads={f: "[x]\nIdentity=unix-user:*\nAction=org.x.y\nResultAny=yes\n"})
        snap = PolkitSnapshot.from_system()
        assert f in snap.pkla_any_yes

    def test_pkla_result_active_yes_not_flagged(self, monkeypatch):
        """Only ResultAny=yes is the bypass; ResultActive=yes is normal."""
        root = "/etc/polkit-1/localauthority"
        sub = f"{root}/50-local.d"
        f = f"{sub}/ok.pkla"
        _wire(monkeypatch,
              dirstats={root: _mk(_DIR)},
              filestats={f: _mk(_REG | 0o644, uid=0)},
              listings={root: ["50-local.d"], sub: ["ok.pkla"]},
              reads={f: "[x]\nResultActive=yes\nResultInactive=auth_admin\n"})
        snap = PolkitSnapshot.from_system()
        assert snap.pkla_any_yes == []
