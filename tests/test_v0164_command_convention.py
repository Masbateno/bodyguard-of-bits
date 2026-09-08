"""Violet marks a command. It marked two of them and missed the hints.

The summary box paints every finding's `cmd` in violet bold, and
`print_check_cmd` does the same for diagnostics — those two places, and
nowhere else. So a line whose entire purpose is *run this* arrived dimmed like
the prose around it: `To reset it: bob --reconfigure`, `Run: sudo bob
--install-cron`, `pipx inject bob geoip2`. Indistinguishable, at a glance, from
a sentence that merely mentions a flag.

The distinction the convention has to keep is exactly that one. "the run was
narrowed by --check / --skip" describes what happened and offers nothing to
type; colouring every `--flag` in the locale would make violet mean nothing.
Five hints and two bare commands are the ones an operator is meant to copy.

Curses screens are excluded on purpose: an ANSI escape there prints as garbage,
and those screens have their own colour pairs.
"""

from __future__ import annotations

import ast
import io
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

#: Locale keys whose whole point is "run this". Each became a template so the
#: command can be coloured without colouring the sentence around it.
_HINTS = (
    "config.reconfigure_hint",
    "manage_logs.no_dir",
    "manage_cron.no_crons",
    "install_cron.no_log_dir",
    "fixes.dry_run_hint",
)


class TestTheHelper:

    def test_it_paints_violet_bold(self, monkeypatch):
        from bob import output
        monkeypatch.setattr(output, "_c", output._COLOURS_ON)
        assert output.command("bob --reconfigure") == (
            "\x1b[1;38;5;135mbob --reconfigure\x1b[0m")

    def test_it_is_the_same_violet_the_summary_box_uses(self, monkeypatch):
        """One convention, or it is not one."""
        from bob import output
        monkeypatch.setattr(output, "_c", output._COLOURS_ON)
        assert output._COLOURS_ON.violet_bold in output.command("x")

    def test_no_color_leaves_it_alone(self, monkeypatch):
        from bob import output
        monkeypatch.setattr(output, "_c", output._COLOURS_OFF)
        assert output.command("bob --reconfigure") == "bob --reconfigure"


class TestTheHintsCarryIt:

    @pytest.mark.parametrize("key", _HINTS)
    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_string_is_a_template(self, key, lang):
        """A command spliced into prose needs a placeholder to be coloured."""
        from bob import i18n
        i18n.init(lang)
        try:
            raw = i18n.t(key, cmd="§")
        finally:
            i18n.init("en")
        assert "§" in raw, f"{lang}/{key} has no {{cmd}} placeholder"

    @pytest.mark.parametrize("key", _HINTS)
    def test_the_placeholder_is_not_the_whole_sentence(self, key):
        """If the hint were only the command, dimming the prose would be moot."""
        from bob import i18n
        i18n.init("en")
        assert len(i18n.t(key, cmd="")) > 8, key


class TestTheProseSurvivesTheColour:

    def test_dim_is_re_established_after_an_embedded_command(self, monkeypatch):
        """The tail of the sentence rendered brighter than its head.

        `print_dim` wraps the line in dim; `command` ends with a reset; so
        everything after the command lost the dim. Caught on a real terminal —
        `Dry run — use --fix --apply to execute fixes` came back with its
        second half at normal brightness.
        """
        from bob import output
        monkeypatch.setattr(output, "_c", output._COLOURS_ON)
        buf = io.StringIO()
        monkeypatch.setattr(output, "_p", lambda *a, **k: buf.write(" ".join(map(str, a)) + "\n"))
        output.print_dim(f"use {output.command('--fix --apply')} to execute")
        line = buf.getvalue()
        after = line.split(output._COLOURS_ON.reset, 1)[1]
        assert after.startswith(output._COLOURS_ON.dim), (
            f"the prose after the command is no longer dimmed: {line!r}"
        )

    def test_it_costs_nothing_without_colour(self, monkeypatch):
        from bob import output
        monkeypatch.setattr(output, "_c", output._COLOURS_OFF)
        buf = io.StringIO()
        monkeypatch.setattr(output, "_p", lambda *a, **k: buf.write(" ".join(map(str, a)) + "\n"))
        output.print_dim("use --fix --apply to execute")
        assert "\x1b" not in buf.getvalue()


def test_curses_screens_pass_the_command_plain():
    """An ANSI escape drawn into a curses window prints as garbage.

    Two cron screens render these same hints. They interpolate the command
    directly rather than through `output.command`, and must keep doing so.
    """
    src = (_ROOT / "bob" / "tui" / "cron.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        rendered = ast.unparse(node)
        if "output.command" in rendered or "_output.command" in rendered:
            offenders.append(f"line {node.lineno}: {rendered[:70]}")
    assert not offenders, (
        f"a curses screen sends ANSI escapes to a curses window: {offenders}"
    )


def test_a_flag_mentioned_as_context_is_not_coloured():
    """The distinction that makes the convention mean something.

    `scoring.scope_filtered` — "the run was narrowed by --check / --skip" —
    describes what happened. There is nothing to type. Turning it into a
    template would spread violet over prose until it stopped signalling.
    """
    from bob import i18n
    i18n.init("en")
    text = i18n.t("scoring.scope_filtered")
    assert "--check" in text, "the sample string changed; pick another"
    assert "{cmd}" not in text and "§" not in i18n.t("scoring.scope_filtered", cmd="§")
