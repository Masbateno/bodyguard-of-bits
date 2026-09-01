"""v0.15.3 — ``-r/--reconfigure`` restored.

The flag shipped in v0.1.0, was advertised in ``--help`` and twice in the man
page, and BOB printed "To reset it: bob --reconfigure" on every run that found
a saved config — while nothing ever read ``config.reconfigure``. It was parsed
and dropped for fourteen minor versions.

The guard at the bottom of this file is the part that outlives the fix: it
fails on *any* future option that gets parsed and never consumed.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import bob.config as config_mod
import bob.__main__ as main_mod
from bob.config import UserConfig

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def cfg_path(tmp_path, monkeypatch):
    """Point UserConfig at a throwaway directory."""
    monkeypatch.setattr(config_mod, "_DEFAULT_CONFIG_DIR", tmp_path / "bob")
    return tmp_path / "bob" / "config.conf"


class TestResetPrimitive:
    def test_reset_deletes_the_file(self, cfg_path):
        cfg = UserConfig.load()
        cfg.set("profile", "desktop")
        assert cfg_path.exists()
        cfg.reset()
        assert not cfg_path.exists()
        assert cfg.all_keys() == []

    def test_clear_keeps_the_file_but_reset_does_not(self, cfg_path):
        """The trap this fix exists to avoid.

        ``clear()`` persists an *empty* file, so ``exists()`` keeps answering
        True and the "Configuration found → use --reconfigure" hint would keep
        firing after a reset had already run. Reset must leave nothing behind;
        without this polarity pair the distinction is untested.
        """
        cfg = UserConfig.load()
        cfg.set("profile", "desktop")
        cfg.clear()
        assert cfg.exists(), "clear() is expected to leave an empty file"
        cfg.reset()
        assert not cfg.exists()

    def test_reset_without_a_file_is_not_an_error(self, cfg_path):
        UserConfig.load().reset()

    def test_reset_reports_an_undeletable_file(self, cfg_path, monkeypatch):
        cfg = UserConfig.load()
        cfg.set("profile", "desktop")

        def boom(self):
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(Path, "unlink", boom)
        with pytest.raises(OSError):
            cfg.reset()


class TestReconfigureCommand:
    def _run(self, monkeypatch, answer=None):
        if answer is not None:
            monkeypatch.setattr(main_mod, "safe_input", lambda prompt="": answer)
        return main_mod.main(["--reconfigure"])

    def test_no_config_exits_clean(self, cfg_path, monkeypatch, capsys):
        assert self._run(monkeypatch, answer="y") == 0
        assert not cfg_path.exists()

    def test_confirmed_deletes(self, cfg_path, monkeypatch):
        UserConfig.load().set("profile", "desktop")
        assert self._run(monkeypatch, answer="y") == 0
        assert not cfg_path.exists()

    def test_there_is_no_yes_bypass(self, cfg_path, monkeypatch):
        """-y stays scoped to --fix --apply.

        The parser has always rejected a bare -y, so a ``if not config.yes``
        guard around the prompt would have been unreachable code — the exact
        defect class this commit adds a guard against. The confirmation is
        unconditional instead, and ``bob --reconfigure -y`` is a CLI error.
        """
        from bob.cli import CLIError

        UserConfig.load().set("profile", "desktop")
        with pytest.raises(CLIError, match="requires --fix --apply"):
            from bob.cli import parse_args

            parse_args(["--reconfigure", "-y"])
        assert cfg_path.exists()

    def test_a_non_interactive_caller_cannot_destroy_silently(self, cfg_path, monkeypatch):
        """No bypass means a script that pipes nothing aborts, never deletes."""
        UserConfig.load().set("profile", "desktop")
        monkeypatch.setattr(main_mod, "safe_input", lambda prompt="": "")
        assert main_mod.main(["--reconfigure"]) == 0
        assert cfg_path.exists()

    def test_declining_keeps_the_config(self, cfg_path, monkeypatch):
        UserConfig.load().set("profile", "desktop")
        assert self._run(monkeypatch, answer="n") == 0
        assert cfg_path.exists()
        assert UserConfig.load().get("profile") == "desktop"

    def test_eof_aborts_rather_than_confirms(self, cfg_path, monkeypatch):
        """safe_input turns Ctrl+D into "", which must not read as consent."""
        UserConfig.load().set("profile", "desktop")
        assert self._run(monkeypatch, answer="") == 0
        assert cfg_path.exists()

    def test_the_saved_keys_are_listed_before_deleting(self, cfg_path, monkeypatch, capsys):
        cfg = UserConfig.load()
        cfg.set("profile", "desktop")
        cfg.set("webhook_url", "https://example.invalid/hook")
        self._run(monkeypatch, answer="y")
        out = capsys.readouterr().out
        assert "profile" in out and "webhook_url" in out

    def test_the_reconfigure_hint_stops_firing(self, cfg_path, monkeypatch):
        """End-to-end close of the loop.

        ``__main__`` prints "Configuration found / To reset it" while
        ``user_config.exists()`` — the very condition this command must clear.
        """
        UserConfig.load().set("profile", "desktop")
        assert UserConfig.load().exists()
        self._run(monkeypatch, answer="y")
        assert not UserConfig.load().exists()


class TestWordingIsAccurate:
    def test_help_no_longer_promises_a_port_wizard(self):
        text = (ROOT / "bob" / "cli.py").read_text(encoding="utf-8")
        assert "Reset saved port configuration and re-ask" not in text

    def test_man_no_longer_promises_a_first_launch_wizard(self):
        page = (ROOT / "man" / "bob.1").read_text(encoding="utf-8")
        assert "first-launch configuration wizard" not in page

    def test_man_no_longer_claims_reconfigure_sets_a_default_output_dir(self):
        page = (ROOT / "man" / "bob.1").read_text(encoding="utf-8")
        assert "to change the default permanently" not in page

    @pytest.mark.parametrize("loc", ["en", "fr"])
    @pytest.mark.parametrize(
        "key", ["nothing", "about_to", "confirm", "aborted", "done", "failed"]
    )
    def test_locale_parity(self, loc, key):
        data = json.loads(
            (ROOT / "bob" / "locales" / f"{loc}.json").read_text(encoding="utf-8")
        )
        assert key in data["cli"]["reconfigure"]


class TestNoOptionIsParsedAndDropped:
    """Anti-drift guard — the durable half of this fix.

    ``config.reconfigure`` was written by the parser and read by nobody for
    fourteen minor versions. Nothing would have caught the next one either.
    Every field ``parse_args`` assigns must be loaded somewhere in ``bob/``.
    """

    @staticmethod
    def _fields_written_by_parse_args():
        tree = ast.parse((ROOT / "bob" / "cli.py").read_text(encoding="utf-8"))
        fn = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == "parse_args"
        )
        written = {
            n.attr
            for n in ast.walk(fn)
            if isinstance(n, ast.Attribute)
            and isinstance(n.ctx, ast.Store)
            and isinstance(n.value, ast.Name)
            and n.value.id == "config"
        }
        return fn, written

    def test_every_parsed_field_has_a_reader(self):
        fn, written = self._fields_written_by_parse_args()
        assert written, "harness check: no config fields found in parse_args"

        readers: set[str] = set()
        for path in sorted((ROOT / "bob").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            in_parse_args = path.name == "cli.py"
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)):
                    continue
                if in_parse_args and fn.lineno <= node.lineno <= fn.end_lineno:
                    continue  # the parser reading its own scratch state
                readers.add(node.attr)

        orphans = sorted(written - readers)
        assert not orphans, (
            "parsed into AuditConfig but never read — the option is inert: "
            + ", ".join(orphans)
        )

    def test_the_guard_bites(self):
        """A guard that cannot fail proves nothing."""
        _, written = self._fields_written_by_parse_args()
        assert "reconfigure" in written
