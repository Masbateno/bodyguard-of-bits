"""Every option the CLI accepts must be offered by the completion.

Reported from the field: ``--test-email`` did not complete. The option *was*
in ``bob/data/bob.bash-completion`` and the installed copy was byte-identical
to the repository's, so the content was never the defect — the completion is
loaded when a shell starts, and ``--install-completion`` said so in one
unmarked, untranslated line under two ticks. That line is now marked and
translated (see `bob/completion.py`).

What the report did expose is that nothing checked the lists at all. The
v0.8.2 guards pinned ``_SECTIONS`` and ``_EXPLAIN_KEYS`` against their Python
sources; the option lists — the part an operator actually presses TAB for —
were unguarded, so an option added to `parse_args` and forgotten here would
never have been noticed.

Measured when this guard was written: 61 long options and 21 short ones in
`bob/cli.py`, all present. One deliberate absence, asserted below.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_CLI = _ROOT / "bob" / "cli.py"
_COMPLETION = _ROOT / "bob" / "data" / "bob.bash-completion"

#: Retired in v0.9.0 (F-3). It survives in `parse_args` only to answer with an
#: explanation instead of "unknown option", so offering it on TAB would invite
#: operators to type something the tool exists to refuse.
_RETIRED = {"--json-v1"}


def _cli_options() -> "tuple[set[str], set[str]]":
    """Every option `parse_args` compares against, long and short."""
    src = _CLI.read_text(encoding="utf-8")
    opts: set[str] = set()
    for m in re.finditer(r'arg (?:==|in) \(?((?:"[^"]+"(?:,\s*)?)+)\)?', src):
        opts |= set(re.findall(r'"([^"]+)"', m.group(1)))
    for m in re.finditer(r'arg\.startswith\("([^"]+)="\)', src):
        opts.add(m.group(1))
    opts = {o for o in opts if o.startswith("-")}
    longs = {o.rstrip("=") for o in opts if o.startswith("--")}
    shorts = {o for o in opts if not o.startswith("--")}
    return longs, shorts


def _completion_var(name: str) -> set[str]:
    m = re.search(rf'local {name}="([^"]*)"', _COMPLETION.read_text(encoding="utf-8"))
    assert m, f"{name} not found in the completion script"
    return {w.rstrip("=") for w in m.group(1).split()}


class TestTheListsAreNotEmpty:
    """Every assertion below is vacuous if an extraction silently returns none."""

    def test_the_cli_yields_options(self):
        longs, shorts = _cli_options()
        assert len(longs) >= 40, f"only {len(longs)} long options parsed — extraction broke"
        assert len(shorts) >= 15, f"only {len(shorts)} short options parsed — extraction broke"

    def test_the_completion_yields_options(self):
        assert len(_completion_var("long_opts")) >= 40
        assert len(_completion_var("short_opts")) >= 15


class TestEveryOptionIsOffered:
    def test_no_long_option_is_missing(self):
        longs, _ = _cli_options()
        missing = longs - _completion_var("long_opts") - _RETIRED
        assert not missing, (
            f"accepted by the CLI, never offered on TAB: {sorted(missing)}")

    def test_no_short_option_is_missing(self):
        _, shorts = _cli_options()
        missing = shorts - _completion_var("short_opts")
        assert not missing, (
            f"accepted by the CLI, never offered on TAB: {sorted(missing)}")

    def test_nothing_is_offered_that_the_cli_would_reject(self):
        longs, shorts = _cli_options()
        extra = (_completion_var("long_opts") - longs) | \
                (_completion_var("short_opts") - shorts)
        assert not extra, (
            f"offered on TAB, rejected by the CLI: {sorted(extra)}")

    def test_the_retired_option_stays_out(self):
        """Its absence is a decision, so it is asserted rather than assumed."""
        assert not (_RETIRED & _completion_var("long_opts")), (
            "--json-v1 was retired in v0.9.0; offering it on TAB invites the "
            "one input the CLI exists to refuse"
        )


class TestTheReportedOption:
    @pytest.mark.parametrize("opt", ["--test-email", "--test-webhook"])
    def test_it_is_there(self, opt):
        assert opt in _completion_var("long_opts")


class TestInstallCompletionSpeaksTheOperatorsLanguage:
    """The line explaining why nothing changed yet was English-only."""

    def test_no_message_is_hardcoded(self):
        src = (_ROOT / "bob" / "completion.py").read_text(encoding="utf-8")
        bare = [ln.strip() for ln in src.splitlines()
                if "print(" in ln and "i18n.t(" not in ln
                and ln.strip() != "print()"  # a blank line carries no words
                and not ln.strip().startswith("#")]
        assert not bare, f"untranslated output in completion.py: {bare}"

    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_both_locales_carry_the_keys(self, locale):
        import json
        data = json.loads((_ROOT / "bob" / "locales" / f"{locale}.json")
                          .read_text(encoding="utf-8"))
        block = data.get("completion", {})
        for key in ("data_missing", "dir_missing", "installed", "install_failed",
                    "symlink_created", "symlink_failed", "symlink_skipped_missing",
                    "symlink_skipped_no_sudo", "reload_title", "reload_how",
                    "needs_root", "needs_root_sudo_warning", "needs_root_how"):
            assert key in block, f"{locale}.json is missing completion.{key}"

    def test_the_reload_notice_is_marked_not_a_trailer(self):
        """It is the only thing between a correct install and 'it is missing'."""
        src = (_ROOT / "bob" / "completion.py").read_text(encoding="utf-8")
        i = src.index("completion.reload_title")
        assert "⚠" in src[max(0, i - 200):i], (
            "the reload notice prints unmarked under two ✔ lines, which is how "
            "it gets read as a footnote rather than as the next step"
        )
