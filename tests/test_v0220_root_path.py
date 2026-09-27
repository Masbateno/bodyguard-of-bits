"""v0.22.0 — root PATH hardening.

A world-writable directory in root's PATH, or a '.'/empty/relative component,
lets a non-root user choose which binary root runs for a bare command name — a
classic local privilege escalation. BOB audits the *configured* root PATH
(login.defs ENV_SUPATH, sudoers secure_path), not the ambient os.environ, so the
verdict is reproducible and independent of how the audit was launched.
"""

from __future__ import annotations

import os

import bob.checks.root_path as rp
from bob.checks.root_path import RootPathSnapshot, check_root_path, _classify
from tests.helpers import _keys


def _key_levels(result):
    return {f.key: f.level.value for f in result.findings}


class TestClassify:
    def test_dot_empty_relative_are_dangerous(self):
        assert _classify(".") == "dot"
        assert _classify("") == "empty"
        assert _classify("usr/bin") == "relative"

    def test_absolute_normal_dir_is_clean(self, tmp_path):
        d = tmp_path / "bin"
        d.mkdir()
        os.chmod(d, 0o755)
        assert _classify(str(d)) is None

    def test_world_writable_dir_is_flagged(self, tmp_path):
        d = tmp_path / "wwx"
        d.mkdir()
        os.chmod(d, 0o777)
        assert _classify(str(d)) == "world_writable"

    def test_unstattable_entry_is_not_guessed(self):
        assert _classify("/nonexistent/dir/xyz") is None


class TestCheck:
    def test_dangerous_warns_and_deducts(self):
        snap = RootPathSnapshot(
            dangerous=[("login.defs ENV_SUPATH", "/tmp/ww", "world_writable")],
            read_any=True)
        r = check_root_path(snap)
        assert _key_levels(r).get("root_path.dangerous") == "warn"
        assert r.deductions

    def test_group_writable_is_info(self):
        snap = RootPathSnapshot(
            group_writable=[("sudoers secure_path", "/opt/x", "group_writable")],
            read_any=True)
        r = check_root_path(snap)
        assert _key_levels(r).get("root_path.group_writable") == "info"
        assert not r.deductions

    def test_clean_is_ok(self):
        r = check_root_path(RootPathSnapshot(read_any=True))
        assert _key_levels(r).get("root_path.clean") == "ok"

    def test_no_source_is_info_unknown(self):
        r = check_root_path(RootPathSnapshot(read_any=False))
        assert "root_path.unknown" in _keys(r)


class TestFromSystem:
    def test_world_writable_component_from_login_defs(self, tmp_path, monkeypatch):
        """The mutation guard: a world-writable dir in ENV_SUPATH must land in
        dangerous."""
        ww = tmp_path / "wwbin"
        ww.mkdir()
        os.chmod(ww, 0o777)
        ld = tmp_path / "login.defs"
        ld.write_text(f"ENV_SUPATH\tPATH=/usr/bin:{ww}\n", encoding="utf-8")
        monkeypatch.setattr(rp, "_LOGIN_DEFS", (ld,))
        monkeypatch.setattr(rp, "_SUDOERS", ())
        snap = RootPathSnapshot.from_system()
        assert snap.read_any is True
        assert any(c == str(ww) and reason == "world_writable"
                   for _s, c, reason in snap.dangerous)

    def test_dot_component_from_sudoers_secure_path(self, tmp_path, monkeypatch):
        su = tmp_path / "sudoers"
        su.write_text('Defaults secure_path="/usr/sbin:/usr/bin:."\n',
                      encoding="utf-8")
        monkeypatch.setattr(rp, "_LOGIN_DEFS", ())
        monkeypatch.setattr(rp, "_SUDOERS", (su,))
        snap = RootPathSnapshot.from_system()
        assert any(reason == "dot" for _s, _c, reason in snap.dangerous)

    def test_clean_configured_path_is_read_but_not_dangerous(self, tmp_path, monkeypatch):
        ld = tmp_path / "login.defs"
        ld.write_text("ENV_SUPATH PATH=/usr/sbin:/usr/bin:/sbin:/bin\n",
                      encoding="utf-8")
        monkeypatch.setattr(rp, "_LOGIN_DEFS", (ld,))
        monkeypatch.setattr(rp, "_SUDOERS", ())
        snap = RootPathSnapshot.from_system()
        assert snap.read_any is True
        assert snap.dangerous == []

    def test_no_sources_marks_unknown(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rp, "_LOGIN_DEFS", (tmp_path / "nope",))
        monkeypatch.setattr(rp, "_SUDOERS", (tmp_path / "nope2",))
        snap = RootPathSnapshot.from_system()
        assert snap.read_any is False

    def test_from_system_never_raises(self):
        RootPathSnapshot.from_system()
