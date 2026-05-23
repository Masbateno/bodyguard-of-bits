"""Tests for bob.ignore — ignore.yml load/add logic."""

from __future__ import annotations

import pytest
from pathlib import Path

from bob.ignore import load_ignore_keys, add_ignore_key
from bob.cli import parse_args, AuditConfig


# ---------------------------------------------------------------------------
# load_ignore_keys
# ---------------------------------------------------------------------------

class TestLoadIgnoreKeys:
    def test_missing_file_returns_empty(self, tmp_path):
        assert load_ignore_keys(tmp_path / "ignore.yml") == frozenset()

    def test_empty_file_returns_empty(self, tmp_path):
        f = tmp_path / "ignore.yml"
        f.write_text("", encoding="utf-8")
        assert load_ignore_keys(f) == frozenset()

    def test_single_key(self, tmp_path):
        f = tmp_path / "ignore.yml"
        f.write_text("ignore:\n  - key: ssh.permit_root_login\n", encoding="utf-8")
        assert load_ignore_keys(f) == frozenset({"ssh.permit_root_login"})

    def test_multiple_keys(self, tmp_path):
        f = tmp_path / "ignore.yml"
        f.write_text(
            "ignore:\n  - key: ssh.permit_root_login\n  - key: log_rotation.remote_syslog_none\n",
            encoding="utf-8",
        )
        assert load_ignore_keys(f) == frozenset({
            "ssh.permit_root_login", "log_rotation.remote_syslog_none"
        })

    def test_ignores_malformed_lines(self, tmp_path):
        f = tmp_path / "ignore.yml"
        f.write_text("ignore:\n  - ssh.permit_root_login\n  - key: valid.key\n", encoding="utf-8")
        assert load_ignore_keys(f) == frozenset({"valid.key"})

    def test_leading_trailing_whitespace_in_key(self, tmp_path):
        f = tmp_path / "ignore.yml"
        f.write_text("ignore:\n  - key:   spaced.key  \n", encoding="utf-8")
        assert "spaced.key" in load_ignore_keys(f)

    def test_returns_frozenset(self, tmp_path):
        f = tmp_path / "ignore.yml"
        f.write_text("ignore:\n  - key: k\n", encoding="utf-8")
        result = load_ignore_keys(f)
        assert isinstance(result, frozenset)

    def test_key_with_reason_field_on_next_line(self, tmp_path):
        # User-edited YAML with optional reason: field — key must still be parsed
        f = tmp_path / "ignore.yml"
        f.write_text(
            "ignore:\n  - key: ssh.permit_root_login\n    reason: intended for lab\n",
            encoding="utf-8",
        )
        assert load_ignore_keys(f) == frozenset({"ssh.permit_root_login"})

    def test_two_ignore_sections_both_loaded(self, tmp_path):
        # Duplicate ignore: blocks (hand-edited file) — all keys visible
        f = tmp_path / "ignore.yml"
        f.write_text(
            "ignore:\n  - key: a.key\nignore:\n  - key: b.key\n",
            encoding="utf-8",
        )
        assert load_ignore_keys(f) == frozenset({"a.key", "b.key"})

    def test_empty_key_value_in_file_skipped(self, tmp_path):
        # "- key:" with no value must not produce an empty string in the set
        f = tmp_path / "ignore.yml"
        f.write_text("ignore:\n  - key:\n  - key: real.key\n", encoding="utf-8")
        result = load_ignore_keys(f)
        assert "" not in result
        assert "real.key" in result

    def test_unreadable_file_returns_empty(self, tmp_path):
        f = tmp_path / "ignore.yml"
        f.write_text("ignore:\n  - key: k\n", encoding="utf-8")
        f.chmod(0o000)
        try:
            result = load_ignore_keys(f)
        finally:
            f.chmod(0o644)
        assert result == frozenset()

    def test_deep_dot_notation_key(self, tmp_path):
        f = tmp_path / "ignore.yml"
        f.write_text("ignore:\n  - key: a.b.c.d.e\n", encoding="utf-8")
        assert "a.b.c.d.e" in load_ignore_keys(f)


# ---------------------------------------------------------------------------
# add_ignore_key
# ---------------------------------------------------------------------------

class TestAddIgnoreKey:
    def test_creates_file_when_missing(self, tmp_path):
        f = tmp_path / "ignore.yml"
        result = add_ignore_key("ssh.permit_root_login", path=f)
        assert result
        assert f.exists()
        assert "ssh.permit_root_login" in f.read_text(encoding="utf-8")

    def test_creates_parent_directories(self, tmp_path):
        f = tmp_path / "sub" / "dir" / "ignore.yml"
        add_ignore_key("k", path=f)
        assert f.exists()

    def test_returns_false_for_duplicate(self, tmp_path):
        f = tmp_path / "ignore.yml"
        add_ignore_key("ssh.permit_root_login", path=f)
        result = add_ignore_key("ssh.permit_root_login", path=f)
        assert not result

    def test_does_not_add_duplicate_content(self, tmp_path):
        f = tmp_path / "ignore.yml"
        add_ignore_key("ssh.permit_root_login", path=f)
        add_ignore_key("ssh.permit_root_login", path=f)
        content = f.read_text(encoding="utf-8")
        assert content.count("ssh.permit_root_login") == 1

    def test_appends_to_existing_file(self, tmp_path):
        f = tmp_path / "ignore.yml"
        add_ignore_key("first.key", path=f)
        add_ignore_key("second.key", path=f)
        keys = load_ignore_keys(f)
        assert keys == frozenset({"first.key", "second.key"})

    def test_returns_false_for_empty_key(self, tmp_path):
        f = tmp_path / "ignore.yml"
        assert not add_ignore_key("", path=f)

    def test_returns_false_for_whitespace_only_key(self, tmp_path):
        f = tmp_path / "ignore.yml"
        assert not add_ignore_key("   ", path=f)

    def test_returns_false_for_non_string(self, tmp_path):
        f = tmp_path / "ignore.yml"
        assert add_ignore_key(None, path=f) is False  # type: ignore[arg-type]

    def test_file_contains_ignore_section_header(self, tmp_path):
        f = tmp_path / "ignore.yml"
        add_ignore_key("k", path=f)
        assert "ignore:" in f.read_text(encoding="utf-8")

    def test_key_roundtrip(self, tmp_path):
        f = tmp_path / "ignore.yml"
        add_ignore_key("hardening.send_redirects_enabled", path=f)
        assert "hardening.send_redirects_enabled" in load_ignore_keys(f)

    def test_appends_without_losing_existing_section(self, tmp_path):
        f = tmp_path / "ignore.yml"
        f.write_text("ignore:\n  - key: existing.key\n", encoding="utf-8")
        add_ignore_key("new.key", path=f)
        keys = load_ignore_keys(f)
        assert frozenset({"existing.key", "new.key"}) == keys

    def test_insertion_order_preserved_in_file(self, tmp_path):
        # Keys must appear in insertion order — stable for git diffs
        f = tmp_path / "ignore.yml"
        add_ignore_key("aaa.key", path=f)
        add_ignore_key("bbb.key", path=f)
        add_ignore_key("ccc.key", path=f)
        content = f.read_text(encoding="utf-8")
        pos_a = content.index("aaa.key")
        pos_b = content.index("bbb.key")
        pos_c = content.index("ccc.key")
        assert pos_a < pos_b < pos_c

    def test_multiple_keys_all_in_single_ignore_section(self, tmp_path):
        # All appended keys must share the same ignore: header, not create multiple
        f = tmp_path / "ignore.yml"
        for key in ("k1", "k2", "k3"):
            add_ignore_key(key, path=f)
        content = f.read_text(encoding="utf-8")
        assert content.count("ignore:") == 1


# ---------------------------------------------------------------------------
# ScoreEngine ignore_keys integration
# ---------------------------------------------------------------------------

class TestScoreEngineIgnoreKeys:
    def _make_result(self, key: str, points: int = 1):
        from bob.scoring import CheckResult
        r = CheckResult()
        r.alert("ignored finding", key=key)
        r.add_deduction("ignored deduction", points=points, key=key)
        return r

    def test_ignored_key_removes_finding(self):
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({"ssh.permit_root_login"})
        engine.apply(self._make_result("ssh.permit_root_login"))
        assert len(engine.findings) == 0

    def test_ignored_key_removes_deduction(self):
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({"ssh.permit_root_login"})
        engine.apply(self._make_result("ssh.permit_root_login", points=2))
        assert engine.score == 10

    def test_ignored_finding_stored_in_ignored_findings(self):
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({"ssh.permit_root_login"})
        engine.apply(self._make_result("ssh.permit_root_login"))
        assert len(engine.ignored_findings) == 1
        assert engine.ignored_findings[0].message == "ignored finding"

    def test_non_ignored_key_passes_through(self):
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({"other.key"})
        engine.apply(self._make_result("ssh.permit_root_login", points=2))
        assert len(engine.findings) == 1
        assert engine.score == 8

    def test_empty_ignore_keys_passes_all(self):
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        engine.ignore_keys = frozenset()
        engine.apply(self._make_result("ssh.permit_root_login", points=1))
        assert len(engine.findings) == 1
        assert engine.score == 9

    def test_finding_without_key_not_ignored(self):
        from bob.scoring import ScoreEngine, CheckResult
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({"ssh.permit_root_login"})
        r = CheckResult()
        r.alert("no key finding")
        r.add_deduction("no key deduction", points=1)
        engine.apply(r)
        assert len(engine.findings) == 1
        assert engine.score == 9

    def test_multiple_keys_ignored_simultaneously(self):
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({"key.a", "key.b"})
        engine.apply(self._make_result("key.a", points=1))
        engine.apply(self._make_result("key.b", points=2))
        assert engine.score == 10
        assert len(engine.ignored_findings) == 2

    def test_ignored_count_matches_applied_keys(self):
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({"k1", "k2", "k3"})
        for k in ("k1", "k2", "k3"):
            engine.apply(self._make_result(k))
        assert len(engine.ignored_findings) == 3
        assert engine.score == 10

    def test_partial_ignore_mixed_results(self):
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({"ignored.key"})
        engine.apply(self._make_result("ignored.key", points=3))
        engine.apply(self._make_result("visible.key", points=1))
        assert engine.score == 9
        assert len(engine.findings) == 1
        assert len(engine.ignored_findings) == 1


# ---------------------------------------------------------------------------
# CLI --ignore / --show-ignored integration
# ---------------------------------------------------------------------------

class TestIgnoreCLI:
    def test_ignore_flag_sets_key(self):
        config = parse_args(["--ignore", "ssh.permit_root_login"])
        assert config.ignore_key == "ssh.permit_root_login"

    def test_ignore_eq_syntax(self):
        config = parse_args(["--ignore=hardening.send_redirects_enabled"])
        assert config.ignore_key == "hardening.send_redirects_enabled"

    def test_show_ignored_flag(self):
        config = parse_args(["--show-ignored"])
        assert config.show_ignored

    def test_ignore_and_show_ignored_combined(self):
        config = parse_args(["--ignore=some.key", "--show-ignored"])
        assert config.ignore_key == "some.key"
        assert config.show_ignored

    def test_ignore_does_not_require_audit_run(self):
        # --ignore exits before the audit — this just verifies parse doesn't raise
        config = parse_args(["--ignore", "firewall.logging_off"])
        assert config.ignore_key == "firewall.logging_off"
        assert config.show_ignored is False  # default

    def test_ignore_add_and_load_roundtrip(self, tmp_path):
        path = tmp_path / "ignore.yml"
        add_ignore_key("ssh.permit_root_login", path=path)
        keys = load_ignore_keys(path)
        assert "ssh.permit_root_login" in keys


# ---------------------------------------------------------------------------
# Locale keys for ignored feedback
# ---------------------------------------------------------------------------

class TestIgnoreLocaleKeys:
    def test_summary_key_en(self):
        from bob.i18n import t
        import bob.i18n as i18n
        i18n.init(lang="en")
        msg = t("ignored.summary", count=3)
        assert "3" in msg

    def test_summary_key_fr(self):
        from bob.i18n import t
        import bob.i18n as i18n
        i18n.init(lang="fr")
        msg = t("ignored.summary", count=2)
        assert "2" in msg

    # M-3 (v0.5.5): test_hint_key_en removed — `ignored.hint` was an
    # orphan locale key, never used by production code. Deleted in
    # v0.5.5 alongside _meta.lang / _meta.version (3 dead keys).

    def test_header_key_exists(self):
        from bob.i18n import t
        import bob.i18n as i18n
        i18n.init(lang="en")
        assert t("ignored.header") != "ignored.header"  # key resolves
