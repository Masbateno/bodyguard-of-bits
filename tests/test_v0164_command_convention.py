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


class TestOnlyTheVerbatimLinesInAHowToFixBlockAreViolet:
    """A HOW TO FIX block is numbered prose *and* material to transcribe.

        1. Edit /etc/samba/smb.conf
        2. In the [global] section set:
           server signing = mandatory

    Painting the whole block violet was the first attempt and it emptied the
    colour of meaning; two thirds of a block is prose. Indentation marks the
    material — 664 indented lines against 527 numbered steps and 74 notes,
    consistent across all 187 keys.

    Violet says *reproduce this exactly*, not *you can run this*. Splitting
    commands from directives is neither reliable — 37 lines are
    `sudo nano <file> → <directive>`, both at once — nor useful, since the
    operator must copy either one and the prose above says which it is.
    """

    def test_the_predicate(self):
        from bob.explain import _is_verbatim_line
        assert _is_verbatim_line("   sudo systemctl restart ssh")
        assert not _is_verbatim_line("2. Disable root login:")
        assert not _is_verbatim_line("Note: this may break asymmetric routing")
        assert not _is_verbatim_line("")
        assert not _is_verbatim_line("   ")

    def test_the_locale_still_follows_the_rule(self):
        """If the prose stopped indenting its commands, the rule would silently
        stop marking them — and nothing else would notice."""
        from bob import i18n
        from bob.explain import EXPLAIN_KEYS, _is_verbatim_line
        i18n.init("en")
        indented = steps = 0
        for key in EXPLAIN_KEYS:
            how = i18n.t(f"explain.{key}.how")
            if how.startswith("["):
                continue
            for line in how.split("\n"):
                if _is_verbatim_line(line):
                    indented += 1
                elif line[:1].isdigit():
                    steps += 1
        assert indented > 400, f"only {indented} command lines — has the shape changed?"
        assert steps > 300, f"only {steps} numbered steps — has the shape changed?"

    def test_a_rendered_page_colours_the_commands_and_not_the_prose(self, monkeypatch):
        import io
        import sys as _sys
        from bob import i18n, output
        from bob.explain import run_explain
        monkeypatch.setattr(_sys.stdout, "isatty", lambda: True, raising=False)
        monkeypatch.setattr(output, "_c", output._COLOURS_ON)
        i18n.init("en")
        buf, old = io.StringIO(), _sys.stdout
        buf.isatty = lambda: True          # the dispatch reads sys.stdout.isatty
        _sys.stdout = buf
        try:
            run_explain("ssh.permit_root_login", i18n.t)
        finally:
            _sys.stdout = old
        violet = output._COLOURS_ON.violet_bold
        lines = buf.getvalue().splitlines()
        cmd_lines = [l for l in lines if violet in l]
        assert cmd_lines, "no command was coloured at all"
        for line in cmd_lines:
            bare = line.replace(violet, "").replace(output._COLOURS_ON.reset, "")
            assert bare.strip() and not bare.strip()[0].isdigit(), (
                f"a numbered prose step was painted as verbatim: {bare!r}"
            )

    def test_the_curses_screen_uses_the_same_predicate(self):
        """Two surfaces, one rule — the charter says so, so it must be true."""
        import ast
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "bob" / "explain.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        callers = {n.lineno for n in ast.walk(tree)
                   if isinstance(n, ast.Call)
                   and getattr(n.func, "id", "") == "_is_verbatim_line"}
        assert len(callers) >= 3, (
            f"_is_verbatim_line is called from {len(callers)} place(s); the text "
            f"path and both curses branches should each use it"
        )


def _finding(cmd_type: str, cmd: str = "/bin/true", message: str = "a finding"):
    """A minimal actionable finding, for driving the fix screen."""
    from bob.scoring import Finding, FindingLevel
    return Finding(level=FindingLevel.ALERT, message=message, key="probe.key",
                   nature="action", cmd=cmd, cmd_type=cmd_type)


class TestEveryCommandOnScreenWearsTheConvention:
    """Reported by eye, three at a time, twice.

    First `bob --reconfigure` in the audit header, then `? bob --explain <key>`
    in the summary box — and the sweep that followed found the fix screen,
    whose entire content is commands, printing them dim. Each was a place the
    convention had not reached, and each was found by a person reading output
    rather than by anything in this suite.

    So the suite reads the output now. A command is recognised where an
    operator would see one: at the start of a line, or after the `→` / `ℹ` / `?`
    that introduces one. A command *quoted inside a sentence* is deliberately
    not matched — the charter says a mention is not the canonical place to copy
    from, and colouring every mention would make violet stop signalling.
    """

    _BINARIES = (
        "bob", "ufw", "systemctl", "apt-get", "dnf", "pacman", "sysctl", "chmod",
        "fwupdmgr", "pipx", "smartctl", "freshclam", "journalctl",
        "fail2ban-client", "docker", "nano", "sed",
    )

    @staticmethod
    def _introduced_command(bare: str, binaries) -> bool:
        import re
        pattern = (r"(?:^|[→?ℹ]\s+)(?:sudo\s+)?(?:" + "|".join(binaries) + r")\b")
        return bool(re.search(pattern, bare))

    def _render(self, monkeypatch, findings, **cfg):
        import io
        import sys as _sys
        import types
        from bob import fixes, i18n, output
        monkeypatch.setattr(output, "_c", output._COLOURS_ON)
        i18n.init(cfg.pop("lang", "en"))
        buf, old = io.StringIO(), _sys.stdout
        _sys.stdout = buf
        try:
            fixes.run_fixes(types.SimpleNamespace(findings=findings),
                            types.SimpleNamespace(yes=True, fix=True, quiet=False,
                                                  apply=cfg.get("apply", False)),
                            i18n.t)
        finally:
            _sys.stdout = old
            i18n.init("en")
        return buf.getvalue()

    @pytest.mark.parametrize("lang", ["en", "fr"])
    @pytest.mark.parametrize("apply_", [False, True])
    def test_the_fix_screen_paints_its_commands(self, monkeypatch, lang, apply_):
        """Its whole content is commands, and they were dim."""
        from bob import output
        out = self._render(monkeypatch,
                           [_finding("fix", cmd="sudo ufw enable", message="firewall off")],
                           lang=lang, apply=apply_)
        violet = output._COLOURS_ON.violet_bold
        offenders = [
            _ANSI.sub("", line).strip()
            for line in out.splitlines()
            if self._introduced_command(_ANSI.sub("", line), self._BINARIES)
            and violet not in line
        ]
        assert not offenders, f"{lang}/apply={apply_}: {offenders}"

    def test_the_diagnostic_bucket_paints_its_commands_too(self, monkeypatch):
        from bob import output
        out = self._render(monkeypatch,
                           [_finding("check", cmd="sudo smartctl -a /dev/sda")])
        assert output._COLOURS_ON.violet_bold in out

    def test_the_summary_box_paints_the_explain_hint(self, monkeypatch):
        """`? bob --explain <key>` is assembled in display.py rather than
        coming from a finding's `cmd`, which is why it stayed plain."""
        from bob import display, output
        monkeypatch.setattr(output, "_c", output._COLOURS_ON)
        src = (_ROOT / "bob" / "display.py").read_text(encoding="utf-8")
        i = src.index('hint = f"bob --explain {norm}"')
        window = src[i:i + 400]
        assert "violet_bold" in window, (
            "the --explain hint in the summary box is not painted"
        )
        assert display  # imported for the failure message to be meaningful

    def test_a_command_quoted_inside_prose_is_left_alone(self):
        """`Run 'sudo fwupdmgr update' to apply pending firmware…` is a
        sentence, and the same command already sits in the finding's `cmd`
        where it is violet. Colouring both would make the colour ambient."""
        assert not self._introduced_command(
            "→ Run 'sudo fwupdmgr update' to apply pending firmware updates",
            self._BINARIES)
        assert self._introduced_command("→ sudo fwupdmgr update", self._BINARIES)
