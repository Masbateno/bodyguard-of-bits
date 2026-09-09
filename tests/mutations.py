"""The defects each guard is supposed to catch, written down so they stay caught.

Not collected by pytest — it is data, read by ``scripts/mutate.py``, which
breaks the code exactly this way and requires the named tests to go red.

**Why it is a file and not a habit.** Nine commits in v0.16.3 say
"mutation-tested with a negative control". That was true when written and
verifiable by nobody afterwards: the shell that ran it is gone, and a guard
whose anchor drifts during a later refactor goes quietly inert with the claim
still in the history. Here the claim is executable.

**Adding a guard means adding its mutation.** The entry says which single
change to make and which tests must fail because of it. If a refactor moves the
anchor, the bench stops with "the anchor appears 0 times" — which is the point:
that is the moment the guard's aim needs re-checking, and it is exactly the
moment nobody would otherwise notice.

``old`` must appear **exactly once** in the file. Prefer a distinctive line over
a short fragment, and name the tests as narrowly as the defect allows so the
run stays fast.
"""

from __future__ import annotations

from dataclasses import dataclass

from bob import __version__ as _V


@dataclass(frozen=True)
class Mutation:
    id: str
    file: str
    old: str
    new: str
    kills: "tuple[str, ...]"
    reason: str


_EXPLAIN = "tests/test_explain.py"
_CHROME = "tests/test_v0163_bottom_chrome.py"
_CLAIMS = "tests/test_v0163_readme_tech_claims.py"
_DOCEX = "tests/test_v0163_doc_examples_run.py"
_MAIL = "tests/test_v0170_mail_transport.py"
_PKGNAMES = "tests/test_v0170_package_names.py"
_PATHS = "tests/test_v0170_distro_paths.py"
_PI = "tests/test_v0170_raspberry_pi.py"
_SWEEP = "tests/test_v0170_doc_counters_sweep.py"
_UNITS = "tests/test_v0171_service_units_and_ports.py"
_FIXTMO = "tests/test_v0171_fix_timeout_stops_what_it_started.py"
_UPGFIX = "tests/test_v0171_upgrade_fix_can_install_what_it_found.py"
_DRIFT = "tests/test_v0171_config_drift_needs_more_than_a_millisecond.py"
_TWICE = "tests/test_v0171_advice_is_safe_to_apply_twice.py"
_COMPOPT = "tests/test_v0171_completion_covers_every_option.py"
_AAEMPTY = "tests/test_v0171_apparmor_empty_is_not_unreadable.py"
_DORMANT = "tests/test_v0171_dormant_service_is_reported_not_scored.py"
_WHOAMI = "tests/test_v0171_audit_user_is_measured.py"
_SENTINEL = "tests/test_v0171_no_sentinel_reaches_the_header.py"


MUTATIONS: "tuple[Mutation, ...]" = (

    # ---- --explain: what a profile does with a finding ---------------------
    Mutation(
        id="explain/uniformity-claim-unconditional",
        file="bob/explain.py",
        old="    notes: list[str] = []\n    for profile in _EXPLAIN_PROFILES:",
        new="    notes: list[str] = []\n    return notes\n    for profile in _EXPLAIN_PROFILES:",
        kills=(f"{_EXPLAIN}::TestRunExplainUniform",),
        reason="every key would again claim it applies equally to all profiles, "
               "including the 32 that three profiles downgrade",
    ),
    Mutation(
        id="explain/default-profiles-silent",
        file="bob/explain.py",
        old="        _profile_override_note(profile, key, t)\n"
            '        or t("explain.ui.profile_default", profile=profile)',
        new="        _profile_override_note(profile, key, t)\n"
            '        or ""',
        kills=(f"{_EXPLAIN}::TestRunExplainUniform",),
        reason="a profile applying the default severity would go unmentioned, "
               "leaving its operator to read the silence",
    ),
    Mutation(
        id="explain/four-lines-on-a-uniform-key",
        file="bob/explain.py",
        old="    if not profile_override_notes(key, t):\n        return []",
        new="    if False:\n        return []",
        kills=(f"{_EXPLAIN}::TestRunExplainUniform",),
        reason="a key no profile treats specially would list four profiles "
               "saying the same thing — noise, not accountability",
    ),
    Mutation(
        id="explain/workstation-unknown",
        file="bob/explain.py",
        old='_EXPLAIN_PROFILES: tuple = ("server", "desktop", "workstation", "container")',
        new='_EXPLAIN_PROFILES: tuple = ("server", "desktop", "container")',
        kills=(f"{_EXPLAIN}::TestRunExplainUniform",),
        reason="the regression a reader found by eye: workstation absent from "
               "--explain despite 28 overrides of its own since v0.8.1",
    ),
    Mutation(
        id="explain/prose-branch-skips-a-profile",
        file="bob/explain.py",
        old="                # No prose written for this profile. Say what its .conf says",
        new="                continue\n                # No prose written for this profile. Say what its .conf says",
        kills=(f"{_EXPLAIN}::TestRunExplainUniform",),
        reason="the 71 keys with per-profile prose would again drop the profile "
               "that has none — all 71 lack a workstation variant",
    ),
    Mutation(
        id="explain/how-to-fix-not-indented",
        file="bob/explain.py",
        old='            print(_indent(t("explain.ui.how_title")))',
        new='            print(t("explain.ui.how_title"))',
        kills=(f"{_EXPLAIN}::TestRunExplainUniform",),
        reason="the remedy would sit flush with the prose above it again",
    ),
    Mutation(
        id="explain/profile-header-not-orange",
        file="bob/explain.py",
        old='    return f"{_c.orange}{label}{_c.reset}" if _c.orange else label',
        new="    return label",
        kills=(f"{_EXPLAIN}::TestRunExplainUniform",),
        reason="the [ profile ] heading would lose its colour on a terminal",
    ),

    # ---- the bottom chrome every wizard shares ------------------------------
    Mutation(
        id="tui/chrome-no-reserved-line",
        file="bob/tui/_chrome.py",
        old="    _safe(stdscr, curses, h - 1 - len(lines),\n"
            "          context.ljust(w - 1)[:w - 1], ctx_attr)",
        new="    pass",
        kills=(f"{_CHROME}::TestTheGeometry", f"{_CHROME}::TestTheColours"),
        reason="prompts and confirmations would go back to painting over the "
               "key banner they ask the operator to use",
    ),
    Mutation(
        id="tui/chrome-height-frozen",
        file="bob/tui/_chrome.py",
        old="    return len(banner_lines(t, actions, width)) + 1",
        new="    return 2",
        kills=(f"{_CHROME}::TestTheGeometry",),
        reason="a screen would size its body one row short whenever the hints "
               "wrap, hiding the last entry under the banner",
    ),
    Mutation(
        id="tui/banner-loses-its-band",
        file="bob/tui/_chrome.py",
        old="    banner_attr = ((curses.color_pair(FOOTER) | curses.A_BOLD) if has_color\n"
            "                   else curses.A_REVERSE)",
        new="    banner_attr = (curses.color_pair(2) if has_color else curses.A_REVERSE)",
        kills=(f"{_CHROME}::TestTheColours",),
        reason="the key hints would go back to plain accent text with no band",
    ),
    Mutation(
        id="tui/banner-truncates-instead-of-wrapping",
        file="bob/tui/_chrome.py",
        old="    draw_text(stdscr, curses, has_color, banner_lines(t, actions, w), context=context)",
        new="    draw_text(stdscr, curses, has_color, [_keys.footer(t, actions, w)[:w - 1]], context=context)",
        kills=(f"{_CHROME}::TestNothingIsTruncatedAway", f"{_CHROME}::TestTheGeometry"),
        reason="at 80 columns five screens overflow in French and the cut would "
               "take the exit hint, which sits on the right",
    ),
    Mutation(
        id="tui/body-sized-by-a-constant",
        file="bob/manage_logs.py",
        old="        body_h = max(1, h - 1 - _ch.chrome_height(t, _MARKED_KEYS, w))",
        new="        body_h = max(1, h - 2)",
        kills=(f"{_CHROME}::TestNoScreenPaintsOverItsOwnBanner",),
        reason="the pre-v0.16.3 arithmetic, already one short when hints wrap",
    ),
    Mutation(
        id="tui/prompt-drawn-on-the-banner-row",
        file="bob/tui/cron.py",
        old='        raw = _curses_readline(stdscr, t, _INPUT_KEYS, t("cron_ui.field_expression"))',
        new='        raw = _curses_readline(stdscr, h - 1, w, "Expression")',
        kills=(f"{_CHROME}::TestNoScreenPaintsOverItsOwnBanner",),
        reason="seven cron prompts were drawn at h-1, erasing the keys they "
               "were asking the operator to use",
    ),
    Mutation(
        id="tui/input-helper-takes-a-row-again",
        file="bob/tui/cron.py",
        old="def _curses_readline(stdscr, t, actions, prompt: str",
        new="def _curses_readline(stdscr, t, row, prompt: str",
        kills=(f"{_CHROME}::TestEveryInputScreenShowsItsKeys",),
        reason="the caller could once more draw a prompt without a banner — how "
               "--install-cron's name entry ended up showing no keys at all",
    ),
    Mutation(
        id="tui/input-hides-the-submit-key",
        file="bob/tui/cron.py",
        old="_INPUT_KEYS    = (_keys.SUBMIT,) + _keys.NESTED_EXIT",
        new="_INPUT_KEYS    = _keys.NESTED_EXIT",
        kills=(f"{_CHROME}::TestEveryInputScreenShowsItsKeys",),
        reason="Enter is dispatched by every text input; undeclared, the only "
               "advertised way out of a field is to abandon it",
    ),
    Mutation(
        id="tui/cron-prompt-back-to-english",
        file="bob/tui/cron.py",
        old='t("cron_ui.field_name")',
        new='"Name"',
        kills=(f"{_CHROME}::TestTheCronScreensAreTranslated",),
        reason="a French operator would type into an English field again",
    ),
    Mutation(
        id="tui/french-colon-loses-its-space",
        file="bob/locales/fr.json",
        old='"prompt_sep": " : "',
        new='"prompt_sep": ": "',
        kills=(f"{_CHROME}::TestTheCronScreensAreTranslated",),
        reason="`Nom: nightly` is not French; the separator is a translation",
    ),
    Mutation(
        id="tui/summary-toggle-frozen",
        file="bob/manage_logs.py",
        old='    return _PREVIEW_KEYS if mode == "full" else _PREVIEW_KEYS_SUMMARY',
        new="    return _PREVIEW_KEYS",
        kills=(f"{_CHROME}::TestAToggleAdvertisesWhereItGoes",),
        reason="the banner would offer the summary to someone already reading it",
    ),
    Mutation(
        id="tui/summary-toggle-hidden",
        file="bob/manage_logs.py",
        old="_PREVIEW_KEYS_SUMMARY = _keys.NAVIGATION + (_keys.FULL,) + _keys.NESTED_EXIT",
        new="_PREVIEW_KEYS_SUMMARY = _keys.NAVIGATION + _keys.NESTED_EXIT",
        kills=(f"{_CHROME}::TestAToggleAdvertisesWhereItGoes",),
        reason="`s` still works there — hiding it is a screen acting on a key it "
               "does not advertise, the defect v0.16.3 closed everywhere else",
    ),

    # ---- what the reference manual claims -----------------------------------
    Mutation(
        id="docs/json-key-renamed-away",
        file="DOCUMENTS/README_TECH.md",
        old="| `firewall_drivers` | object |",
        new="| `firewall_stack` | object |",
        kills=(f"{_CLAIMS}::TestEveryPublishedJsonKeyIsDocumented",),
        reason="the pre-v0.9.0 name; a consumer following the document takes a "
               "KeyError",
    ),
    Mutation(
        id="docs/option-missing-from-the-reference",
        file="DOCUMENTS/README_TECH.md",
        old="| `--target=N`",
        new="| `--targetXX=N`",
        kills=(f"{_CLAIMS}::TestTheOptionsReferenceIsComplete",),
        reason="19 of 43 options were undiscoverable to a reader of the reference",
    ),
    Mutation(
        id="docs/service-missing-a-row",
        file="DOCUMENTS/README_TECH.md",
        old="| Ollama (local LLM)",
        new="| OllamaXX (local LLM)",
        kills=(f"{_CLAIMS}::TestTheCataloguesMatch",),
        reason="the table carried 31 rows for 38 shipped services",
    ),
    Mutation(
        id="docs/cis-reference-count-stale",
        file="DOCUMENTS/README_TECH.md",
        old="194 entries (108 formal CIS",
        new="174 entries (107 formal CIS",
        kills=(f"{_CLAIMS}::TestTheCataloguesMatch",),
        reason="the count drifted by 18 entries across several releases",
    ),
    Mutation(
        id="docs/network-context-phantom-value",
        file="DOCUMENTS/README_TECH.md",
        old='`{ "context": "local" \\| "public" \\| "ddns" }`',
        new='`{ "context": "local" \\| "private" \\| "public" \\| "ddns" }`',
        kills=(f"{_CLAIMS}::TestTheNamesAreReal",),
        reason='"private" was offered as a value; no code path has ever emitted it',
    ),
    Mutation(
        id="docs/sample-banner-version-stale",
        file="DOCUMENTS/README_TECH.md",
        # Anchored on the *current* version, read from the package: a literal
        # here would break the bench at every release, which is churn, not a
        # finding. The fast guard caught exactly that on the v0.16.4 bump.
        old=f"║  BOB v{_V}  │  Linux hardening auditor",
        new="║  BOB v0.13.2  │  Linux hardening auditor",
        kills=(f"{_CLAIMS}::TestTheNamesAreReal",),
        reason="the sample banner sat three minor versions behind the package",
    ),
    Mutation(
        id="docs/example-command-does-not-run",
        file="DOCUMENTS/TUTORIAL.md",
        old="bob --explain ssh.password_auth",
        new="bob --explain ssh.password_auth_enabled",
        kills=(f"{_DOCEX}::test_every_explain_key_shown_to_a_user_exists",),
        reason="the tutorial told a first-time reader to run a command that "
               "exits 3 on a key that has never existed",
    ),

    # ---- what the packaging changelog claims --------------------------------
    Mutation(
        id="packaging/debian-entry-bumped-not-written",
        file="debian/changelog",
        old='  * "This guard bites" was a claim in a commit message and nothing re-checked',
        new='  * The score went up when BOB could see less. It is a sum over the checks that',
        kills=("tests/test_v0164_debian_changelog.py::test_no_two_entries_open_on_the_same_sentence",),
        reason="reproduces v0.16.3 exactly: the entry carries an older release's "
               "story, so a packager reads about the wrong version",
    ),
    Mutation(
        id="packaging/debian-release-skipped",
        file="debian/changelog",
        old="bodyguard-of-bits (0.16.2-1) UNRELEASED; urgency=low",
        new="bodyguard-of-bits (0.16.2-XX) SKIPPED; urgency=low",
        kills=("tests/test_v0164_debian_changelog.py::test_no_release_is_missing_its_entry",),
        reason="a published release with no packaging entry — 0.16.1 and 0.16.2 "
               "were both missing until v0.16.4",
    ),

    # ---- how long the audit took --------------------------------------------
    Mutation(
        id="duration/wall-clock-instead-of-monotonic",
        file="bob/__main__.py",
        old="            _audit_started = _time.monotonic()",
        new="            _audit_started = _time.time()",
        kills=("tests/test_v0164_audit_duration.py::TestTheMeasurementIsHonest",),
        reason="a clock adjustment mid-run would print a negative duration, "
               "which is a statement about the audit that is not true",
    ),
    Mutation(
        id="duration/negative-reaches-the-screen",
        file="bob/display.py",
        old="    seconds = max(0.0, float(seconds))",
        new="    seconds = float(seconds)",
        kills=("tests/test_v0164_audit_duration.py::TestTheFormatter",),
        reason="the summary line would render `-3.0 s` rather than clamping",
    ),
    Mutation(
        id="duration/untimed-run-fabricates-a-zero",
        file="bob/json_output.py",
        old='        "duration_seconds": (None if audit_seconds is None\n'
            "                             else round(max(0.0, float(audit_seconds)), 3)),",
        new='        "duration_seconds": round(float(audit_seconds or 0.0), 3),',
        kills=("tests/test_v0164_audit_duration.py::TestThePayloadCarriesIt",),
        reason="null means 'this run did not time itself'; 0.0 claims an "
               "instantaneous audit, which is a different and false statement",
    ),
    Mutation(
        id="duration/computed-twice",
        file="bob/__main__.py",
        old="            audit_seconds = _time.monotonic() - _audit_started",
        new="            audit_seconds = _time.monotonic() - _audit_started  # noqa\n"
            "            del audit_seconds\n"
            "            audit_seconds = _time.monotonic() - _audit_started",
        kills=("tests/test_v0164_audit_duration.py::TestTheMeasurementIsHonest",),
        reason="the screen and the payload would read two different numbers "
               "for the same run",
    ),

    # ---- the title bar ------------------------------------------------------
    Mutation(
        id="header/version-dropped",
        file="bob/tui/_chrome.py",
        old='    stamp = f"v{__version__}  "',
        new='    stamp = ""',
        kills=("tests/test_v0163_bottom_chrome.py::TestTheHeaderCarriesTheVersion",),
        reason="the running version would vanish from every wizard's title bar",
    ),
    Mutation(
        id="header/title-truncated-to-fit-the-version",
        file="bob/tui/_chrome.py",
        old="    if len(left) + len(stamp) + 2 <= width:",
        new="    if True:",
        kills=("tests/test_v0163_bottom_chrome.py::TestTheHeaderCarriesTheVersion",),
        reason="a narrow terminal would lose the title to make room for a "
               "version number, which tells the operator less",
    ),

    # ---- the headless build ---------------------------------------------------
    Mutation(
        id="headless/keys-imports-curses",
        file="bob/tui/_keys.py",
        old="from __future__ import annotations",
        new="from __future__ import annotations\nimport curses  # noqa: F401",
        kills=("tests/test_v0164_headless_import.py::test_the_module_does_not_import_curses_at_all",
               "tests/test_v0164_headless_import.py::test_it_imports_with_curses_unavailable"),
        reason="bob-core would stop importing on a machine with no curses, and "
               "the full suite would stay green because the test machine has it",
    ),
    Mutation(
        id="headless/blocker-stops-blocking",
        file="tests/test_v0164_headless_import.py",
        old='    if name.split(".")[0] in ("curses", "_curses"):',
        new='    if name.split(".")[0] in ("nothing_at_all",):',
        kills=("tests/test_v0164_headless_import.py::test_the_blocker_actually_blocks",),
        reason="the bench would import curses freely and pass on every machine "
               "that has one, which is every machine that runs it",
    ),

    # ---- what the source claims about itself ---------------------------------
    Mutation(
        id="claims/second-copy-of-a-single-source",
        file="bob/display.py",
        old="def _compute_posture_annotation(engine, t) -> tuple:",
        new="def _compute_posture_annotation(engine, t) -> tuple:\n"
            "    pass\n\n\n"
            "def _compute_posture_annotation(engine, t) -> tuple:",
        kills=("tests/test_v0164_uniqueness_claims.py::test_the_symbol_is_defined_exactly_once",),
        reason="a second definition works until the two drift, which is the only "
               "way this defect ever announces itself — the colour chart lived in "
               "three modules that happened to agree for nine releases",
    ),
    Mutation(
        id="claims/stale-schema-in-a-docstring",
        file="bob/json_output.py",
        old='    """v3 producer — the only schema BOB emits.',
        new='    """v2 producer — v0.7.0 schema.',
        kills=("tests/test_v0164_uniqueness_claims.py::test_no_producer_names_a_schema_it_does_not_emit",),
        reason="the docstring named a schema retired four minors before, which "
               "is what a reader checking what BOB produces would have believed",
    ),

    # ---- what --fix --apply is allowed to run --------------------------------
    Mutation(
        id="apply/executes-a-diagnostic",
        file="bob/fixes.py",
        old='                    if f.cmd and f.cmd_type == "fix"\n'
            "                    and _can_apply_unattended(f.cmd)]",
        new="                    if f.cmd and _can_apply_unattended(f.cmd)]",
        kills=("tests/test_v0164_apply_reads_cmd_type.py::TestADiagnosticIsNeverApplied",),
        reason="the exact v0.16.3 behaviour: `smartctl -a` on a dying disk "
               "reported as '✔ Applied', and the operator told it was fixed",
    ),
    Mutation(
        id="apply/diagnostic-vanishes-from-the-screen",
        file="bob/fixes.py",
        old="    if diag_items:\n        print()",
        new="    if False:\n        print()",
        kills=("tests/test_v0164_apply_reads_cmd_type.py::TestADiagnosticIsNeverApplied",),
        reason="dropping them from the fix list without a third bucket removes "
               "six actionable findings from the screen entirely — worse than "
               "showing them mislabelled",
    ),
    Mutation(
        id="apply/a-real-fix-stops-being-applied",
        file="bob/fixes.py",
        old='                    if f.cmd and f.cmd_type == "fix"\n'
            "                    and _can_apply_unattended(f.cmd)]",
        new='                    if f.cmd and f.cmd_type == "never"\n'
            "                    and _can_apply_unattended(f.cmd)]",
        kills=("tests/test_v0164_apply_reads_cmd_type.py::TestADiagnosticIsNeverApplied",),
        reason="the polarity twin: excluding diagnostics must not exclude fixes",
    ),

    Mutation(
        id="apply/counts-a-fix-it-cannot-run",
        file="bob/fixes.py",
        old="                    and _can_apply_unattended(f.cmd)]",
        new="                    ]",
        kills=("tests/test_v0164_apply_reads_cmd_type.py::TestTheCountIsAPromiseBobCanKeep",),
        reason="twelve findings with shell operators announced as automatic "
               "fixes, then refused one by one — 'ssh.password_auth' among them",
    ),
    Mutation(
        id="apply/editor-passes-the-predicate",
        file="bob/fixes.py",
        old='_INTERACTIVE = ("nano", "vim", "vi", "emacs", "editor", "$EDITOR")',
        new="_INTERACTIVE = ()",
        kills=("tests/test_v0164_apply_reads_cmd_type.py::TestTheCountIsAPromiseBobCanKeep",),
        reason="an editor launched with stdin closed on a 30-second timeout "
               "would hang the apply run until it was killed",
    ),
    Mutation(
        id="apply/header-says-zero-over-an-urgent-list",
        file="bob/fixes.py",
        old="        if auto_items:\n            count_msg = t(\"fixes.count\", count=len(auto_items))",
        new="        if True:\n            count_msg = t(\"fixes.count\", count=len(auto_items))",
        kills=("tests/test_v0164_apply_reads_cmd_type.py::TestTheHeaderDoesNotSayZeroOverAnUrgentList",),
        reason="'0 automatic fix(es) available' over four SMART alerts reads "
               "as 'nothing to do here' to anyone skimming",
    ),

    # ---- the colour convention for runnable commands -------------------------
    Mutation(
        id="convention/command-loses-its-violet",
        file="bob/output.py",
        old='    return f"{_c.violet_bold}{text}{_c.reset}" if _c.violet_bold else text',
        new="    return text",
        kills=("tests/test_v0164_command_convention.py::TestTheHelper",),
        reason="a runnable command would read like the prose around it again",
    ),
    Mutation(
        id="convention/prose-after-a-command-loses-its-dim",
        file="bob/output.py",
        old="    body = message.replace(_c.reset, _c.reset + _c.dim) if _c.dim else message",
        new="    body = message",
        kills=("tests/test_v0164_command_convention.py::TestTheProseSurvivesTheColour",),
        reason="the tail of the sentence renders brighter than its head — found "
               "on a real terminal, not in the source",
    ),
    Mutation(
        id="convention/hint-stops-being-a-template",
        file="bob/locales/en.json",
        old='"reconfigure_hint": "To reset it: {cmd}"',
        new='"reconfigure_hint": "To reset it: bob --reconfigure"',
        kills=("tests/test_v0164_command_convention.py::TestTheHintsCarryIt",),
        reason="the command goes back inside the prose, where it cannot be "
               "coloured without colouring the sentence",
    ),

    # ---- the graphic charter -------------------------------------------------
    Mutation(
        id="charter/a-colour-goes-unused",
        file="bob/output.py",
        old='    orange       = "\\033[38;5;208m",',
        new='    orange       = "\\033[38;5;208m",\n    spare        = "\\033[38;5;99m",',
        kills=("tests/test_v0164_graphic_charter.py::TestColourIsDeclaredOnceAndConsumed",),
        reason="a declared-and-never-consumed colour — the class this project "
               "has already mined twice elsewhere",
    ),
    Mutation(
        id="charter/two-ways-to-ask-about-colour",
        file="bob/cli.py",
        old="        bold, reset = _o._c.bold, _o._c.reset",
        new='        bold, reset = (_o._c.bold, _o._c.reset) if not _o._no_color else ("", "")',
        kills=("tests/test_v0164_graphic_charter.py::TestColourIsDeclaredOnceAndConsumed",),
        reason="`_c` is already empty when colour is off; consulting `_no_color` "
               "is a second answer to one question, and print_help used it",
    ),
    Mutation(
        id="charter/the-two-violets-drift-apart",
        file="bob/tui/_palette.py",
        old="VIOLET_256 = 135",
        new="VIOLET_256 = 129",
        kills=("tests/test_v0164_graphic_charter.py::TestTheTwoSurfacesAgree",),
        reason="a command would be one violet in the terminal and another in a "
               "wizard — the charter says the surfaces agree",
    ),
    Mutation(
        id="charter/a-check-module-draws-a-box",
        file="bob/checks/firewall.py",
        old="def check_firewall(",
        new='def _rogue_box():\n    print("┌────┐")\n\n\ndef check_firewall(',
        kills=("tests/test_v0164_graphic_charter.py::TestBoxesFollowOneRule",),
        reason="frame drawing leaking out of the presentation modules is the "
               "drift the box rule exists to catch",
    ),
    Mutation(
        id="charter/how-to-fix-painted-whole",
        file="bob/explain.py",
        old="    return bool(line) and line[:1].isspace() and bool(line.strip())",
        new="    return True",
        kills=("tests/test_v0164_command_convention.py::TestOnlyTheVerbatimLinesInAHowToFixBlockAreViolet",),
        reason="numbered prose painted as verbatim material empties the "
               "colour of meaning — two thirds of a block is prose",
    ),
    Mutation(
        id="charter/readme-dev-keeps-a-second-copy",
        file="DOCUMENTS/README_DEV.md",
        old="Moved to **[CONVENTIONS.md](CONVENTIONS.md)** in v0.16.4",
        new="### Snapshot / check pattern\n\nMoved to **[CONVENTIONS.md](CONVENTIONS.md)** in v0.16.4",
        kills=("tests/test_v0164_graphic_charter.py::TestTheCharterExists",),
        reason="two copies of the conventions will disagree, which is what "
               "moving them into one document was for",
    ),

    Mutation(
        id="convention/fix-screen-commands-go-dim",
        file="bob/fixes.py",
        old='            print(f"     {_c.dim}→ {_c.reset}{_output.command(safe_cmd)}")',
        new='            print(f"     {_c.dim}→ {safe_cmd}{_c.reset}")',
        kills=("tests/test_v0164_command_convention.py::TestEveryCommandOnScreenWearsTheConvention",),
        reason="the screen whose entire content is commands printed them dim, "
               "found by sweeping the real audit rather than reading the source",
    ),
    Mutation(
        id="convention/explain-hint-goes-plain",
        file="bob/display.py",
        old="            for content, val in _wrap_for_box(hint_prefix, hint, inner):\n"
            '                lines.append((f"{_oc.violet_bold}{content}{_oc.reset}", val))',
        new="            lines.extend(_wrap_for_box(hint_prefix, hint, inner))",
        kills=("tests/test_v0164_command_convention.py::TestEveryCommandOnScreenWearsTheConvention",),
        reason="`? bob --explain <key>` in the summary box is assembled rather "
               "than coming from a finding's cmd, which is why it stayed plain",
    ),

    Mutation(
        id="fixes/install-command-waits-for-a-human",
        file="bob/checks/_run.py",
        # v0.17.0 moved this out of firewall.py: the command is built once for
        # every manager now, so the missing flag is mutated where it would
        # actually be written.
        old='("apt",     f"sudo apt install -y {_PKGS}"),',
        new='("apt",     f"sudo apt install {_PKGS}"),',
        kills=("tests/test_v0164_fix_commands_run_unattended.py::test_no_install_command_would_stop_to_ask",),
        reason="apt refuses to proceed without confirmation, so --fix --apply "
               "--yes reported `0 of 2 fix(es) applied.` — proven in a container",
    ),
    Mutation(
        id="packages/no-command-kills-the-check",
        file="bob/scoring.py",
        old='        self.cmd     = sanitize_multiline(\n'
            '            (self.cmd or "").replace("\\r\\n", "\\n").replace("\\r", " ").replace("\\t", " "))',
        new='        self.cmd     = sanitize_multiline(\n'
            '            self.cmd.replace("\\r\\n", "\\n").replace("\\r", " ").replace("\\t", " "))',
        kills=(f"{_PKGNAMES}::TestTheNoCommandBranchIsExercisedOnThisHost",),
        reason="a finding with no command raised inside a check, where fault "
               "isolation swallowed it and rendered the whole section "
               "'unavailable' — three checks died that way on Arch and Fedora "
               "while every test on this Debian host stayed green",
    ),
    Mutation(
        id="packages/rpm-error-sentence-read-as-installed",
        file="bob/checks/_run.py",
        old='    ("rpm",        ("-q", "--quiet", _PKG),      None,                   True),',
        new='    ("rpm",        ("-q", _PKG),                 None,                   False),',
        kills=(f"{_PKGNAMES}::TestRpmAnswersNoToAnAbsentPackage",),
        reason="rpm prints 'package X is not installed' on stdout, so 'any "
               "output proves installed' made every query answer yes on the "
               "whole RHEL family — measured on fedora:latest, where v0.16.4 "
               "reported a Debian package and an invented name both installed",
    ),
    Mutation(
        id="packages/exit-code-branch-ignored",
        file="bob/checks/_run.py",
        old="        if by_exit:\n            if result.ok:\n                return tool",
        new="        if False:\n            if result.ok:\n                return tool",
        kills=(f"{_PKGNAMES}::TestRpmAnswersNoToAnAbsentPackage::"
               "test_a_real_rpm_success_is_still_a_yes",),
        reason="--quiet prints nothing on success, so dropping the exit-code "
               "branch flips the fault the other way: every rpm package absent",
    ),
    Mutation(
        id="packages/debian-name-handed-to-another-manager",
        file="bob/checks/_run.py",
        old="    if any(n is None for n in names):\n        return None",
        new="    if False:\n        return None",
        kills=(f"{_PKGNAMES}::TestUnknownNamesProduceNoCommand",),
        reason="an unmapped package would render as an empty install command, "
               "so `sudo pacman -S --noconfirm` with no argument, or worse a "
               "confident command that installs nothing",
    ),
    Mutation(
        id="packages/microcode-asks-debian-names-only",
        file="bob/checks/firmware.py",
        old="        candidates = list(package_name_candidates(_logical)) if _logical else []",
        new='        candidates = ["intel-microcode"] if _logical else []',
        kills=(f"{_PKGNAMES}::TestTheMicrocodeVerdictIsNotDebianOnly",),
        reason="the false verdict this closed: rpm -q intel-microcode answers "
               "nothing on Fedora, where the package is microcode_ctl, and BOB "
               "deducted a point from every host of two distribution families",
    ),
    Mutation(
        id="packages/absence-asserted-without-a-known-name",
        file="bob/checks/firmware.py",
        old="        elif not (snapshot.package_query_possible and snapshot.microcode_name_known):",
        new="        elif not snapshot.package_query_possible:",
        kills=(f"{_PKGNAMES}::TestTheMicrocodeVerdictIsNotDebianOnly",),
        reason="on a manager whose name BOB never measured, an empty answer "
               "would again become 'not installed' rather than 'not established'",
    ),
    Mutation(
        id="packages/debian-only-suffix-travels",
        file="bob/checks/_run.py",
        old='    if cmd and then_apt and _MANAGER_ALIASES.get(mgr, mgr) != "apt":\n        cmd = None',
        new="    if False:\n        cmd = None",
        kills=(f"{_PKGNAMES}::TestDebianOnlyFollowUpsDoNotTravel",),
        reason="aideinit, pam-auth-update and dpkg-reconfigure are Debian's own "
               "tools; appending them to a dnf command hands out a remedy whose "
               "second half cannot run",
    ),

    Mutation(
        id="docs/counter-sweep-goes-blind",
        file="tests/test_v0170_doc_counters_sweep.py",
        old='    "filterable": "sections", "sections filtrables": "sections",',
        new="",
        kills=(f"{_SWEEP}::test_the_vocabulary_covers_the_phrasings_actually_used",),
        reason="dropping a counted noun is how the v0.13.3 guard went blind to "
               "the four spellings SNAPSHOT actually uses, leaving seven "
               "counters stale across six releases",
    ),
    Mutation(
        id="docs/section-count-stale-again",
        file="DOCUMENTS/SNAPSHOT.md",
        old="the 39 filterable + 10 always-on section names",
        new="the 38 filterable + 10 always-on section names",
        kills=(f"{_SWEEP}::test_no_counter_in_a_current_state_document_is_stale",),
        reason="the section count drifted in seven places the moment a section "
               "was added, and nothing was watching",
    ),

    Mutation(
        id="fixes/upgrade-waits-for-a-human",
        file="bob/checks/updates.py",
        old='cmd="sudo apt-get upgrade -y --with-new-pkgs",',
        new='cmd="sudo apt-get upgrade --with-new-pkgs",',
        kills=("tests/test_v0164_fix_commands_run_unattended.py::"
               "test_no_install_command_would_stop_to_ask",),
        reason="proven on a real Debian 13: apt-get upgrade without -y exits 1 "
               "on 'Do you want to continue? [Y/n] Abort.' inside --fix --apply "
               "--yes, the mode whose promise is not to ask",
    ),
    Mutation(
        id="fixes/verb-list-narrow-again",
        file="tests/test_v0164_fix_commands_run_unattended.py",
        old='    r"(?<![\\w-])(install|add|upgrade|remove|purge|erase|reinstall"',
        new='    r"(?<![\\w-])(install|add|remove|purge|erase|reinstall"',
        kills=("tests/test_v0164_fix_commands_run_unattended.py::"
               "test_the_mutating_list_covers_what_broke",),
        reason="the guard knew three verbs and apt-get upgrade sat in the "
               "auto-apply bucket unflagged for its whole lifetime — an "
               "allowlist protects the allowlist",
    ),

    # ---- a service believed stopped, and the port it swallowed --------------
    Mutation(
        id="services/port-credited-to-an-inactive-service",
        file="bob/runner.py",
        old="        if snap.is_active:\n            audited_ports.update(snap.ports)",
        new="        if True:\n            audited_ports.update(snap.ports)",
        kills=(f"{_UNITS}::TestAnInactiveServiceDoesNotSwallowItsPort::"
               "test_the_runner_only_credits_ports_of_an_active_service",),
        reason="a service wrongly believed stopped deletes its own exposure "
               "finding — measured on Fedora 43, where a running Apache on "
               "*:80 produced no warning anywhere in the audit",
    ),
    Mutation(
        id="services/ports-check-stops-reporting-uncredited",
        file="bob/checks/ports.py",
        old="        if pp in audited_ports:\n            continue",
        new="        if True:\n            continue",
        kills=(f"{_UNITS}::TestAnInactiveServiceDoesNotSwallowItsPort::"
               "test_the_ports_check_reports_what_is_not_credited",),
        reason="the other half of the contract: a port nobody credited must be "
               "reported, or the runner-side guard protects nothing",
    ),
    Mutation(
        id="services/unit-names-are-debians-again",
        file="bob/data/services.json",
        old='"services": [\n      "apache2",\n      "httpd"\n    ],',
        new='"services": [\n      "apache2"\n    ],',
        kills=(f"{_UNITS}::TestUnitNamesAreNotOnlyDebians::"
               "test_the_fedora_unit_is_declared[apache-httpd]",),
        reason="Fedora ships httpd.service, so asking about apache2 answers "
               "'stopped' about a running web server",
    ),
    Mutation(
        id="services/wildcard-listener-not-global",
        file="bob/checks/ports.py",
        old=r'_ALL_INTERFACES = re.compile(r"^(0\.0\.0\.0|::|\*)$")',
        new=r'_ALL_INTERFACES = re.compile(r"^(0\.0\.0\.0|::)$")',
        kills=(f"{_UNITS}::TestAnInactiveServiceDoesNotSwallowItsPort::"
               "test_a_wildcard_address_counts_as_every_interface",),
        reason="ss renders Apache's bind as *:80, not 0.0.0.0:80; dropping the "
               "wildcard makes an internet-facing listener read as local",
    ),

    # ---- what machine this is ----------------------------------------------
    Mutation(
        id="pi/probe-target-not-importable",
        file="tests/test_v0170_raspberry_pi.py",
        old="    proc = ctx.Process(target=_probe_memory_limit_child, args=(q,))",
        new="    _local = _probe_memory_limit_child\n"
            "    proc = ctx.Process(target=_local, args=(q,))",
        kills=(f"{_PI}::TestNoProbeRidesOnForkOnlyBehaviour::"
               "test_no_test_module_spawns_a_nested_target",),
        reason="a target a spawn child cannot import by name works on fork and "
               "raises PicklingError from Python 3.14 — the CI matrix caught "
               "this where five local campaigns on 3.12 did not",
    ),
    Mutation(
        id="pi/secure-boot-invents-a-bios",
        file="bob/checks/secure_boot.py",
        old="            message=(_t(\"secure_boot.no_uefi_board\", board=snapshot.board)\n"
            "                     if snapshot.board else _t(\"secure_boot.no_uefi\")),",
        new='            message=_t("secure_boot.no_uefi"),',
        kills=(f"{_PI}::TestSecureBootNoLongerInventsAFirmwareType::"
               "test_a_named_board_gets_its_own_message",),
        reason="a board that names itself would go back to the generic sentence, "
               "the one that used to say 'Legacy BIOS detected' on hardware "
               "that has no BIOS",
    ),
    Mutation(
        id="pi/credential-hash-goes-unreported",
        file="bob/checks/raspberry_pi.py",
        old="    if snapshot.userconf_user:",
        new="    if False:",
        kills=(f"{_PI}::TestTheProvisioningHashIsAFinding::"
               "test_a_hash_left_behind_is_a_warning_with_a_deduction",),
        reason="a password hash left on a FAT partition would be reported as a "
               "clean boot partition instead",
    ),
    Mutation(
        id="pi/only-sha512-hashes-recognised",
        file="bob/checks/raspberry_pi.py",
        old=r'_USERCONF_RE = re.compile(r"^([A-Za-z0-9._-]{1,32}):(\$[0-9a-z]{1,2}\$\S+)\s*$")',
        new=r'_USERCONF_RE = re.compile(r"^([A-Za-z0-9._-]{1,32}):(\$6\$\S+)\s*$")',
        kills=(f"{_PI}::TestTheProvisioningHashIsAFinding::"
               "test_every_crypt_scheme_raspberry_pi_os_uses_is_recognised",),
        reason="Bookworm's imager writes yescrypt ($y$), so pinning $6$ would "
               "miss every hash written by a current Raspberry Pi Imager",
    ),
    Mutation(
        id="pi/locked-account-read-as-usable",
        file="bob/checks/raspberry_pi.py",
        old='            return bool(secret) and not secret.startswith(("!", "*")), True',
        new="            return bool(secret), True",
        kills=(f"{_PI}::TestTheDefaultAccount::"
               "test_a_locked_account_is_not_a_way_in",),
        reason="`!` and `*` mean no password will ever match; a locked account "
               "would be reported as a way in and cost a point it should not",
    ),
    Mutation(
        id="pi/unreadable-shadow-read-as-no-password",
        file="bob/checks/raspberry_pi.py",
        old="        # Unreadable is not \"no password\": say the answer was not established.\n"
            "        return False, False",
        new="        return False, True",
        kills=(f"{_PI}::TestTheDefaultAccount::"
               "test_unreadable_shadow_is_not_established_rather_than_absent",),
        reason="an unreadable /etc/shadow would be reported as an established "
               "negative — the class v0.15.2 closed for packages",
    ),
    Mutation(
        id="pi/unmounted-boot-declared-clean",
        file="bob/checks/raspberry_pi.py",
        old="    if snapshot.boot_dir is None:",
        new="    if None is None and False:",
        kills=(f"{_PI}::TestNothingIsSaidOnAMachineThatIsNotAPi::"
               "test_an_unmounted_boot_partition_is_not_a_clean_one",),
        reason="a partition BOB never found would be reported as carrying no "
               "provisioning credentials",
    ),
    Mutation(
        id="pi/a-pc-mistaken-for-a-board",
        file="bob/platform.py",
        old='        if "raspberry pi" in model.lower():\n            return model',
        new="        return model",
        kills=(f"{_PI}::TestTheBoardIsIdentifiedFromTheFirmware::"
               "test_another_board_is_not_a_raspberry_pi",),
        reason="any device tree would name this a Raspberry Pi, so a Radxa or "
               "an Orange Pi would get advice about files it does not have",
    ),

    Mutation(
        id="pi/memory-cap-assumed-not-verified",
        file="bob/_sandbox.py",
        old="        applied_soft, _applied_hard = resource.getrlimit(resource.RLIMIT_AS)\n"
            "        _MEM_LIMIT_APPLIED = (applied_soft != resource.RLIM_INFINITY\n"
            "                              and applied_soft <= MEM_LIMIT)",
        new="        _MEM_LIMIT_APPLIED = True",
        kills=(f"{_PI}::TestTheSandboxKnowsWhetherItsMemoryCapIsReal::"
               "test_the_limit_is_read_back_not_assumed",),
        reason="setrlimit returns success and applies nothing under qemu-user on "
               "aarch64, so the sandbox claimed a 256 MiB cap it never got — "
               "found by running the suite on ARM once emulation was available",
    ),

    # ---- the files a verdict is read from ----------------------------------
    Mutation(
        id="paths/pam-stack-is-debians-only",
        file="bob/checks/_run.py",
        old='        "/etc/pam.d/system-auth",       # Fedora, RHEL, Arch, openSUSE\n'
            '        "/etc/pam.d/password-auth",     # Fedora, RHEL — the remote-login stack\n'
            '    ),\n'
            '    # Where session modules (pam_umask) are stacked.',
        new='    ),\n'
            '    # Where session modules (pam_umask) are stacked.',
        kills=(f"{_PATHS}::TestThePamStackIsNotJustDebians",),
        reason="reading only common-password produced 'no PAM quality module' "
               "— a WARN and a deduction — on every Fedora, RHEL, openSUSE and "
               "Arch host, having read nothing at all",
    ),
    Mutation(
        id="paths/unreadable-stack-becomes-absent",
        file="bob/checks/password_policy.py",
        old="    if not snapshot.pam_stack_established:",
        new="    if False:",
        kills=(f"{_PATHS}::TestNoDeductionForAStackThatCouldNotBeRead::"
               "test_alpine_shaped_host_gets_unknown_not_a_warning",),
        reason="Alpine has no PAM at all, so the deduction would be a statement "
               "about a mechanism the host does not have",
    ),
    Mutation(
        id="paths/umask-reads-one-file-again",
        file="bob/checks/umask.py",
        old="        _pam_sessions = ((_pam_session,) if _pam_session is not None\n"
            '                         else pam_stack_paths("session"))',
        new='        _pam_sessions = ((_pam_session,) if _pam_session is not None\n'
            '                         else (Path("/etc/pam.d/common-session"),))',
        kills=(f"{_PATHS}::TestUmaskReadsTheWholeSessionStack::"
               "test_the_default_path_consults_the_whole_stack",),
        reason="a pam_umask stacked in system-auth or postlogin went unseen and "
               "the scan fell through to /etc/profile as though PAM were silent",
    ),
    Mutation(
        id="paths/debian-command-back-in-the-prose",
        file="bob/locales/en.json",
        old='"ufw_missing": "UFW is not installed"',
        new='"ufw_missing": "UFW is not installed — install it with: sudo apt install ufw"',
        kills=(f"{_PATHS}::TestNoDebianCommandHidesInTranslatedProse::"
               "test_the_audits_own_messages_name_no_package_manager",),
        reason="the message said apt while the same finding's cmd said dnf — "
               "BOB contradicting itself on screen, in one finding, where no "
               "guard was looking at message strings at all",
    ),

    # ---- the cron wizard's promise of delivery -----------------------------
    Mutation(
        id="mail/presence-taken-for-delivery",
        file="bob/cron/_parse.py",
        old='        if available:\n'
            '            return "\u2714", "install_cron.mta_found", {"mta": name or "sendmail"}\n'
            '        return "\u26a0", "install_cron.mta_missing", {}',
        new='        return "\u2714", "install_cron.mta_found", {"mta": name or "sendmail"}',
        kills=(f"{_MAIL}::TestWillAnyoneHearFromThisJob::"
               "test_address_without_a_transport_is_a_warning",),
        reason="a host with no MTA at all would again be told its notifications "
               "are fine, which is the v0.16.4 message reworded",
    ),
    Mutation(
        id="mail/offline-webhook-offered-anyway",
        file="bob/cron/_parse.py",
        old='    if offline:\n        return "\u26a0", "install_cron.reports_webhook_offline", {}',
        new='    if False:\n        return "\u26a0", "install_cron.reports_webhook_offline", {}',
        kills=(f"{_MAIL}::TestWillAnyoneHearFromThisJob::"
               "test_offline_suppresses_the_webhook_so_that_job_is_mute",),
        reason="the wizard would offer the webhook as the way out to a job whose "
               "--offline suppresses the POST, so it would notify nobody",
    ),
    Mutation(
        id="mail/silent-job-declared-covered",
        file="bob/cron/_parse.py",
        old='    if not url:\n        return "\u26a0", "install_cron.reports_nobody", {}',
        new='    if not url:\n        return "\u2714", "install_cron.reports_webhook", {}',
        kills=(f"{_MAIL}::TestWillAnyoneHearFromThisJob::"
               "test_no_address_and_no_webhook_notifies_nobody",),
        reason="a job with no address and no webhook writes a report to disk on a "
               "schedule and tells nobody; saying otherwise is the whole defect",
    ),
    Mutation(
        id="mail/address-book-never-read",
        file="bob/__main__.py",
        old="        _addrs = EmailStore.load().all()",
        new="        _addrs = EmailStore().all()",
        kills=(f"{_MAIL}::TestTestEmailReportsWhatSendmailAnswered::"
               "test_the_store_is_actually_read_from_disk",
               f"{_MAIL}::TestTestEmailReportsWhatSendmailAnswered::"
               "test_sendmail_accepting_exits_zero"),
        reason="the constructor holds an empty list, so --test-email answered "
               "\"no address configured\" on every host, always \u2014 the first "
               "form this command was written in",
    ),
    Mutation(
        id="mail/refusal-reported-as-success",
        file="bob/__main__.py",
        old='            print("\u2716 " + i18n.t("cli.test_email.rejected"), file=sys.stderr)',
        new='            return EXIT_OK',
        kills=(f"{_MAIL}::TestTestEmailReportsWhatSendmailAnswered::"
               "test_sendmail_refusing_exits_nonzero",),
        reason="a refused message would exit 0, making the one command whose "
               "purpose is to catch that failure silent about it",
    ),
    Mutation(
        id="mail/attempt-announced-after-the-verdict",
        file="bob/__main__.py",
        old='        print("\u2139  " + i18n.t("cli.test_email.sending", to=_to), flush=True)',
        new='        print("\u2139  " + i18n.t("cli.test_email.sending", to=_to))',
        kills=(f"{_MAIL}::TestTestEmailReportsWhatSendmailAnswered::"
               "test_the_attempt_is_announced_before_the_verdict",),
        reason="stdout is block-buffered when redirected, so a piped run read as "
               "though the failure preceded the attempt",
    ),
    Mutation(
        id="mail/notice-sliced-to-width-again",
        file="bob/tui/cron.py",
        old="    for _i, _line in enumerate(_rendered):",
        new="    for _i, _line in enumerate([msg[:w - 3]]):",
        kills=(f"{_MAIL}::TestTheNoticeReachesTheScreenWhole::"
               "test_the_flash_wraps_rather_than_slicing",),
        reason="on 80 columns the operator read the first half of two sentences "
               "of advice and never learned there was a second half",
    ),
    Mutation(
        id="mail/flash-screen-crashes-on-sight",
        file="bob/tui/cron.py",
        old="_chrome.text_height(_banner)",
        new="_chrome.chrome_height()",
        kills=(f"{_MAIL}::TestTheNoticeReachesTheScreenWhole::"
               "test_the_flash_actually_renders",),
        reason="chrome_height takes three arguments, so the wizard died with "
               "\"Fatal error\" at the screen whose job is reporting what went "
               "wrong \u2014 found by a pty run, not by the guard reading the source",
    ),
    Mutation(
        id="mail/plain-notice-truncated",
        file="bob/cron/_install.py",
        old="    for line in textwrap.wrap(msg, width,",
        new="    for line in textwrap.wrap(msg[:width], width,",
        kills=(f"{_MAIL}::TestTheNoticeReachesTheScreenWhole::"
               "test_wrapping_keeps_every_word",),
        reason="the same cut in the plain wizard, which is the path cron "
               "installs actually take over ssh without a TTY",
    ),
    Mutation(
        id="fixes/timeout-kills-sudo-only",
        file="bob/fixes.py",
        old="        start_new_session=True,\n",
        new="",
        kills=(f"{_FIXTMO}::TestTheTimeoutStopsTheWholeTree::"
               "test_the_grandchild_does_not_survive_the_timeout",
               f"{_FIXTMO}::TestTheTimeoutStopsTheWholeTree::"
               "test_the_child_leads_its_own_group"),
        reason="without its own session the child leads no group, so the "
               "timeout signals nothing and `apt-get` outlives the `sudo` "
               "above it \u2014 measured on Debian 13, BOB exited reporting "
               "0 of 1 applied while the upgrade held the apt lock",
    ),
    Mutation(
        id="fixes/package-budget-back-to-thirty-seconds",
        file="bob/fixes.py",
        old="_TIMEOUT_PACKAGE = 900",
        new="_TIMEOUT_PACKAGE = 30",
        kills=(f"{_FIXTMO}::TestPackageTransactionsGetABudgetTheyCanFinishIn::"
               "test_the_long_budget_is_minutes_not_seconds",),
        reason="thirty seconds is a budget for `ufw delete`; a package "
               "transaction reaching it means BOB stops a healthy upgrade "
               "mid-transaction every single time",
    ),
    Mutation(
        id="fixes/timeout-told-to-rerun-by-hand",
        file="bob/fixes.py",
        old="                    print(f\"  \u26a0 {t('fixes.timed_out', seconds=timeout)}\")",
        new="                    print(f\"  \u2716 {t('fixes.manual')}\")",
        kills=(f"{_FIXTMO}::TestTheReportDoesNotLie::"
               "test_a_timeout_is_never_dressed_as_manual",
               f"{_FIXTMO}::TestTheReportDoesNotLie::"
               "test_a_timeout_names_itself_and_the_budget"),
        reason="\"apply the command manually\" after a timeout is advice to "
               "start a second package transaction over an unfinished first "
               "one, which is how the VM ended up unpacked but unconfigured",
    ),
    Mutation(
        id="updates/fix-cannot-install-a-kernel",
        file="bob/checks/updates.py",
        old='cmd="sudo apt-get upgrade -y --with-new-pkgs",',
        new='cmd="sudo apt-get upgrade -y",',
        kills=(f"{_UPGFIX}::TestDetectionAndRemediationStayReconciled::"
               "test_the_fix_offered_for_that_detection_matches_it",),
        reason="BOB collects the finding with `apt-get -s dist-upgrade` and "
               "would repair it with plain `upgrade`, which keeps every kernel "
               "update back, returns 0, and gets reported as \"1 of 1 fix(es) "
               "applied\" \u2014 measured on Debian 13",
    ),
    Mutation(
        id="updates/fix-removes-packages-unattended",
        file="bob/checks/updates.py",
        old='cmd="sudo apt-get upgrade -y --with-new-pkgs",',
        new='cmd="sudo apt-get dist-upgrade -y",',
        kills=(f"{_UPGFIX}::TestTheProposedUpgradeCanInstallAKernel",),
        reason="dist-upgrade would install the kernel, and would also remove "
               "packages with nobody watching \u2014 the line an auto-applied "
               "fix must not cross",
    ),
    Mutation(
        id="drift/millisecond-counts-as-drift",
        file="bob/checks/_run.py",
        old="    return newest_mtime - applied >= _APPLIED_RESOLUTION",
        new="    return newest_mtime > applied",
        kills=(f"{_DRIFT}::TestTheMeasuredIncident::"
               "test_the_exact_vm_numbers_are_not_drift",
               f"{_DRIFT}::TestTheMeasuredIncident::"
               "test_nothing_below_systemd_s_resolution_counts"),
        reason="systemd answers in whole seconds and st_mtime does not, so a "
               "correct edit-then-reload inside one second reads as drift and "
               "mutes every SSH finding below it \u2014 measured on Debian 13, "
               "four milliseconds",
    ),
    Mutation(
        id="drift/timestamps-back-to-the-minute",
        file="bob/checks/ssh/_snapshot.py",
        old='strftime("%Y-%m-%d %H:%M:%S")\n    snap.sshd_config_applied_at',
        new='strftime("%Y-%m-%d %H:%M")\n    snap.sshd_config_applied_at',
        kills=(f"{_DRIFT}::TestTheSentenceShowsItsEvidence",),
        reason="the sentence names two moments and says one follows the other; "
               "rendered to the minute it prints them identical and reads as a "
               "contradiction",
    ),
    Mutation(
        id="advice/append-without-looking",
        file="bob/checks/_run.py",
        old='return (f"grep -qxF {shlex.quote(line)} {path} 2>/dev/null || "',
        new='return (f"true {shlex.quote(line)} {path} 2>/dev/null || "',
        kills=(f"{_TWICE}::TestTheGeneratedCommandsAreIdempotent",),
        reason="three runs of the rp_filter fix left three identical lines in "
               "99-hardening.conf on a Debian 13 VM \u2014 advice gets followed "
               "twice, so it has to be safe twice",
    ),
    Mutation(
        id="advice/samba-back-to-the-end-of-the-file",
        file="bob/checks/samba.py",
        old="sudo sed -i '/^\\\\[global\\\\]/a {directive}' {_SMB_CONF_PATH}",
        new="sudo tee -a {_SMB_CONF_PATH}",
        kills=(f"{_TWICE}::TestTheSambaFixReachesGlobal",),
        reason="appending puts the directive in whatever section is last \u2014 "
               "[print$] on stock Debian 13, where testparm still answered "
               "SMB2_02 and samba rejected the line as unknown for that section",
    ),
    Mutation(
        id="completion/option-dropped-from-the-list",
        file="bob/data/bob.bash-completion",
        old="--test-email --test-webhook",
        new="--test-webhook",
        kills=(f"{_COMPOPT}::TestEveryOptionIsOffered::"
               "test_no_long_option_is_missing",
               f"{_COMPOPT}::TestTheReportedOption"),
        reason="an option accepted by the CLI and never offered on TAB \u2014 "
               "nothing checked the option lists at all before this guard",
    ),
    Mutation(
        id="completion/reload-notice-back-to-english",
        file="bob/completion.py",
        old='print("⚠  " + i18n.t("completion.reload_title"))',
        new='print("  Open a new shell or run: source /etc/bash_completion.d/bob")',
        kills=(f"{_COMPOPT}::TestInstallCompletionSpeaksTheOperatorsLanguage",),
        reason="the untranslated, unmarked trailer that made a correctly "
               "installed option look missing to a French operator",
    ),
    Mutation(
        id="apparmor/empty-set-called-unreadable",
        file="bob/checks/mac_policy.py",
        old="                    counts = _apparmor_profiles_from_kernel()\n"
            "                    snap.apparmor_profiles_readable = counts is not None",
        new="                    counts = None\n"
            "                    snap.apparmor_profiles_readable = counts is not None",
        kills=(f"{_AAEMPTY}::TestTheSnapshotUsesIt::"
               "test_kali_root_reports_zero_rather_than_unknown",),
        reason="Kali 2026.2 as root: AppArmor loaded, zero profiles, and BOB "
               "said the profile set could not be read \u2014 a framework "
               "enforcing nothing reported as an absence of information",
    ),
    Mutation(
        id="apparmor/no-privilege-called-zero",
        file="bob/checks/mac_policy.py",
        old="    except OSError:\n        return None\n    loaded = enforce = complain = 0",
        new="    except OSError:\n        return (0, 0, 0)\n    loaded = enforce = complain = 0",
        kills=(f"{_AAEMPTY}::TestTheSnapshotUsesIt::"
               "test_unprivileged_still_says_it_does_not_know",
               f"{_AAEMPTY}::TestTheKernelIsAsked::"
               "test_only_an_unreadable_file_is_unknown"),
        reason="the v0.15.5 defect in reverse \u2014 a host with 120 enforcing "
               "profiles, read without privilege, told it had none, with a "
               "WARN and a point attached",
    ),
    Mutation(
        id="dormant/scored-again-on-a-threat-model",
        file="bob/checks/services.py",
        old="            result.info(\n"
            '                key="services.state.installed_inactive_critical",',
        new="            result.warn_with_deduction(\n"
            "                points=1,\n"
            '                key="services.state.installed_inactive_critical",',
        kills=(f"{_DORMANT}::TestReportedAndNotScored::test_it_costs_nothing",
               f"{_DORMANT}::TestReportedAndNotScored::"
               "test_a_dormant_service_never_outweighs_a_running_one"),
        reason="seven stopped packages took the Kali domain to 3/10 \u2014 more "
               "than a world-exposed critical service costs \u2014 for a state "
               "whose only harm needs an attacker path BOB says it does not model",
    ),
    Mutation(
        id="dormant/finding-dropped-entirely",
        file="bob/checks/services.py",
        old="            result.info(\n"
            '                key="services.state.installed_inactive_critical",\n'
            '                message=_t("services.state.installed_inactive_critical", label=snap.label),\n'
            "            )",
        new="            pass",
        kills=(f"{_DORMANT}::TestReportedAndNotScored::"
               "test_the_finding_is_still_emitted",),
        reason="not scoring it must never become not showing it \u2014 the "
               "operator still needs to know the package is there",
    ),
    Mutation(
        id="identity/back-to-believing-the-environment",
        file="bob/sysinfo.py",
        old="    euid = os.geteuid()\n    try:\n        return pwd.getpwuid(euid).pw_name",
        new='    euid = os.geteuid()\n    try:\n        return os.environ.get("USER", "unknown")',
        kills=(f"{_WHOAMI}::TestTheEnvironmentIsNotTheSource",),
        reason="openSUSE Leap 15.6 arrives with no USER in the environment and "
               "the header said \"User : unknown\" about a process the kernel "
               "identifies as root \u2014 and that header is written into the "
               "report file",
    ),
    Mutation(
        id="identity/unvalidated-sudo-user",
        file="bob/sysinfo.py",
        old="            pwd.getpwnam(sudo_user)\n            return sudo_user",
        new="            return sudo_user",
        kills=(f"{_WHOAMI}::TestSudoUserKeepsItsPlace::"
               "test_a_sudo_user_naming_nobody_falls_through",),
        reason="an environment variable naming nobody would be printed as the "
               "operator's identity instead of falling through to what was "
               "measured",
    ),
    Mutation(
        id="header/ufw-placeholder-returns",
        file="bob/sysinfo.py",
        old="    ufw_version = ufw_match.group(0) if ufw_match else \"\"",
        new="    ufw_version = ufw_match.group(0) if ufw_match else \"N/A\"",
        kills=(f"{_SENTINEL}::TestTheSourceReportsAbsenceLikeItsNeighbours::"
               "test_a_missing_ufw_is_empty_not_a_placeholder",
               f"{_SENTINEL}::TestOnlyTheUfwFieldWasAffected"),
        reason="the header read \"UFW : vN/A\" on openSUSE Leap 15.6 while its "
               "two neighbours read \"not installed\" about the same kind of "
               "absence \u2014 a placeholder printed as a fact about the host",
    ),
    Mutation(
        id="header/absent-firewall-renders-blank",
        file="bob/report.py",
        old='        _ufw = (f"ufw v{info.ufw_version}" if info.ufw_version\n'
            '                else _L.get("not_installed", "not installed"))',
        new='        _ufw = f"ufw v{info.ufw_version}"',
        kills=(f"{_SENTINEL}::TestWhatTheWritersActuallyProduce::"
               "test_absent_ufw_is_named_in_the_text_report",),
        reason="with the source now empty, an unconditional version marker "
               "writes \"ufw v\" into the report file and the absence is not "
               "named at all",
    ),
)
