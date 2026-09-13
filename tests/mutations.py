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
_CMPBD = "tests/test_v0183_compare_breakdown.py"
_SSHUNIT = "tests/test_v0171_ssh_unit_is_resolved.py"
_NOSYSD = "tests/test_v0171_no_systemd_is_not_a_verdict.py"
_OPENRC = "tests/test_v0180_openrc.py"
_SUIDOWN = "tests/test_v0180_suid_ownership.py"
_NATIVE = "tests/test_v0180_native_sysctl_apply.py"
_ABSENT = "tests/test_v0180_absent_is_not_unreadable.py"
_CAPPED = "tests/test_v0180_capped_reads.py"
_STATES = "tests/test_v0180_every_service_state_speaks.py"
_LOCKOUT = "tests/test_v0180_no_fix_locks_you_out.py"
_PROFSRCH = "tests/test_v0180_profile_search_is_not_absence.py"
_HISTREAD = "tests/test_v0180_history_reads_only_what_it_wrote.py"
_SINKKEY  = "tests/test_v0180_every_sink_carries_the_key.py"
_ARCHIVE  = "tests/test_v0180_the_archive_keeps_the_remedy.py"
_SNAPMAP  = "tests/test_v0180_snapshot_maps_every_module.py"
_NATIVEALL = "tests/test_v0180_every_sysctl_fix_is_native.py"
_PY314 = "tests/test_v0180_python314_denial_is_not_absence.py"
_SSHDSESS = "tests/test_v0181_sshd_session_is_read.py"
_TESTTAB = "tests/test_v0181_testing_table_matches_changelog.py"
_SEED = "tests/test_v0181_cloud_init_seed_on_the_boot_partition.py"
_AAOFF = "tests/test_v0181_apparmor_off_in_kernel.py"
_RPF = "tests/test_v0181_rp_filter_is_per_interface.py"
_SOCK = "tests/test_v0181_socket_activated_is_not_stopped.py"
_STRANGER = "tests/test_v0180_a_stranger_is_not_a_baseline.py"


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
        old="199 entries (108 formal CIS",
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
            "                    and (f.fix_action or _can_apply_unattended(f.cmd))]",
        new="                    if f.cmd\n"
            "                    and (f.fix_action or _can_apply_unattended(f.cmd))]",
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
            "                    and (f.fix_action or _can_apply_unattended(f.cmd))]",
        new='                    if f.cmd and f.cmd_type == "never"\n'
            "                    and (f.fix_action or _can_apply_unattended(f.cmd))]",
        kills=("tests/test_v0164_apply_reads_cmd_type.py::TestADiagnosticIsNeverApplied",),
        reason="the polarity twin: excluding diagnostics must not exclude fixes",
    ),

    Mutation(
        id="apply/counts-a-fix-it-cannot-run",
        file="bob/fixes.py",
        old="                    and (f.fix_action or _can_apply_unattended(f.cmd))]",
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
        old='"apt":    "sudo apt-get upgrade -y --with-new-pkgs",',
        new='"apt":    "sudo apt-get upgrade --with-new-pkgs",',
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
        old='"apt":    "sudo apt-get upgrade -y --with-new-pkgs",',
        new='"apt":    "sudo apt-get upgrade -y",',
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
        old='"apt":    "sudo apt-get upgrade -y --with-new-pkgs",',
        new='"apt":    "sudo apt-get dist-upgrade -y",',
        kills=(f"{_UPGFIX}::TestTheProposedUpgradeCanInstallAKernel",),
        reason="dist-upgrade would install the kernel, and would also remove "
               "packages with nobody watching \u2014 the line an auto-applied "
               "fix must not cross",
    ),
    Mutation(
        id="updates/security-fix-hardcodes-apt",
        file="bob/checks/updates.py",
        old="            cmd=_upgrade_cmd(mgr),\n            nature=\"action\",",
        new="            cmd=\"sudo apt-get upgrade -y --with-new-pkgs\",\n            nature=\"action\",",
        kills=("tests/test_v0190_updates_cross_distro.py::"
               "TestCheckAcrossManagers::test_dnf_security_deducts_with_dnf_fix",),
        reason="the check was apt-only until a field test on real Fedora/openSUSE "
               "VMs showed it reported 'no apt' (blind) on 4 of 5 families; if the "
               "security remediation reverts to a hardcoded apt command, a dnf host "
               "with 93 pending security updates gets told to run a command it "
               "does not have",
    ),
    Mutation(
        id="domain-alignment/detection-scored-as-hardening",
        file="bob/domain_scores.py",
        old='"auditd":             "detection",',
        new='"auditd":             "system_hardening",',
        kills=("tests/test_v0200_domain_group_alignment.py::"
               "test_every_section_is_scored_in_its_display_group",),
        reason="v0.20.0 aligned the score domains 1:1 with the display groups; if "
               "a detection section's prefix drifts back into another domain, a "
               "reader sees the auditd finding under THREAT DETECTION but its "
               "score lands in SYSTEM HARDENING — the exact two-taxonomy split "
               "the alignment removed",
    ),
    Mutation(
        id="trust-boundary/config-path-denial-reads-as-safe",
        file="bob/checks/_run.py",
        old="    try:\n        return not strict_is_symlink(p)\n    except OSError:\n        return False",
        new="    try:\n        return not strict_is_symlink(p)\n    except OSError:\n        return True",
        kills=("tests/test_v0190_safe_path_denial_fails_closed.py::"
               "TestSafeConfigPath::test_undeterminable_fails_closed",),
        reason="a symlink under /etc/cron.d that BOB is refused permission to "
               "lstat must not read as 'not a symlink, safe' — on Python 3.14 "
               "Path.is_symlink() answers False to that denial, so failing open "
               "here would follow authorized_keys -> /etc/shadow into the report",
    ),
    Mutation(
        id="trust-boundary/user-path-denial-reads-as-safe",
        file="bob/checks/_run.py",
        old="    try:\n        is_link = strict_is_symlink(p)\n    except OSError:\n        return False",
        new="    try:\n        is_link = strict_is_symlink(p)\n    except OSError:\n        return True",
        kills=("tests/test_v0190_safe_path_denial_fails_closed.py::"
               "TestSafeUserPath::test_undeterminable_fails_closed",),
        reason="if the symlink-ness of a path under a user's home cannot be "
               "determined, treating it as a plain safe file lets a symlink "
               "escaping the home be materialised — the exact attack the "
               "home-boundary check exists to stop",
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
    Mutation(
        id="header/hostname-from-a-binary-again",
        file="bob/sysinfo.py",
        old="        hostname=_sanitize(_uname.nodename, max_len=64),",
        new='        hostname=_sanitize(run("hostname"), max_len=64),',
        kills=(f"{_SENTINEL}::TestTheMachineIdentifiesItselfWithoutHelperBinaries",),
        reason="Arch Linux ships no `hostname` binary, so the report header read "
               "\"Host : N/A\" \u2014 on the one field that says which machine "
               "the report is about",
    ),
    Mutation(
        id="sshunit/debian-spelling-hardcoded",
        file="bob/checks/ssh/_directives.py",
        old='            "@SSH_RESTART@", service_restart_cmd(ssh_unit()))',
        new='            "@SSH_RESTART@", "sudo systemctl restart ssh")',
        kills=(f"{_SSHUNIT}::TestNoCommandHardcodesTheDebianSpelling::"
               "test_the_directive_templates_go_through_the_resolver",
               f"{_SSHUNIT}::TestTheRenderedCommands"),
        reason="on Arch and openSUSE the unit is sshd, and Debian's spelling "
               "gives \"Failed to restart ssh.service: Unit ssh.service not "
               "found\" \u2014 the remediation for the most consequential "
               "findings BOB reports, inert on most distributions",
    ),
    Mutation(
        id="sshunit/resolver-stops-asking",
        file="bob/checks/_run.py",
        old="        if out.strip():\n            return name\n    # v0.18.0: OpenRC hosts",
        new="        if False:\n            return name\n    # v0.18.0: OpenRC hosts",
        kills=(f"{_SSHUNIT}::TestItAsksSystemdRatherThanGuessing::"
               "test_arch_and_opensuse_get_sshd",),
        reason="no static name works on all five machines measured \u2014 Kali "
               "has only ssh.service, Arch and openSUSE only sshd.service",
    ),
    Mutation(
        id="nosystemd/absence-read-as-stopped",
        file="bob/checks/ssh/_snapshot.py",
        old="    sshd_active_known:       bool = False",
        new="    sshd_active_known:       bool = True",
        kills=(f"{_NOSYSD}::TestTheFieldDefaultsToNotKnowing::"
               "test_a_fresh_snapshot_claims_nothing",),
        reason="Alpine Linux 3.22 runs sshd under OpenRC \u2014 rc-status says "
               "started, pid 2351 is listening \u2014 and BOB warned that it "
               "was installed but not running, having asked nothing",
    ),
    Mutation(
        id="nosystemd/flag-cleared-back-inside-the-guard",
        file="bob/checks/ssh/_snapshot.py",
        old="        snap.sshd_active_known = False\n        # v0.18.0: no init-system test here.",
        new="        snap.sshd_active_known = True\n        # v0.18.0: no init-system test here.",
        kills=(f"{_NOSYSD}::TestTheFieldDefaultsToNotKnowing::"
               "test_a_host_where_nothing_answers_stays_unknown",),
        reason="the flag has to start at \u0022nothing answered\u0022; v0.17.1 "
               "moved the assignment out of the systemd branch and v0.18.0 "
               "removed that branch entirely, so only the default protects it",
    ),
    Mutation(
        id="openrc/failed-probe-read-as-stopped",
        file="bob/checks/_run.py",
        old="    if code == _OPENRC_STOPPED:\n        return \"inactive\"\n    return None",
        new="    return \"inactive\"",
        kills=(f"{_OPENRC}::TestTheExitStatusIsTheAnswer::"
               "test_a_probe_that_could_not_run_is_not_stopped",
               f"{_OPENRC}::TestTheExitStatusIsTheAnswer::"
               "test_an_unknown_service_is_not_stopped"),
        reason="OpenRC exits 1 for a service it does not know and gives no code "
               "at all when the probe never ran; reading either as stopped is "
               "the mistake v0.17.1 had to undo four times",
    ),
    Mutation(
        id="openrc/never-asked",
        file="bob/checks/_run.py",
        old="    return openrc_state(name, timeout=timeout)",
        new="    return None",
        kills=(f"{_OPENRC}::TestOneVocabularyForBothInitSystems::"
               "test_unit_active_state_falls_through_to_openrc",),
        reason="every service on Alpine, Gentoo and Devuan came back UNKNOWN "
               "because systemd was the only thing ever asked",
    ),
    Mutation(
        id="openrc/wrong-program-not-wrong-name",
        file="bob/checks/_run.py",
        old='        return f"sudo rc-service {unit} restart"',
        new='        return f"sudo systemctl restart {unit}"',
        kills=(f"{_OPENRC}::TestTheCommandMatchesTheInitSystem::"
               "test_openrc_hosts_get_rc_service",),
        reason="on Alpine there is no systemctl to run: the remediation names "
               "a program the host does not have, not merely a misspelt unit",
    ),
    Mutation(
        id="openrc/exit-status-dropped",
        file="bob/checks/_run.py",
        old="        return CommandResult(proc.stdout, proc.returncode == 0, proc.stderr,\n"
            "                             proc.returncode)",
        new="        return CommandResult(proc.stdout, proc.returncode == 0, proc.stderr)",
        kills=(f"{_OPENRC}::TestTheExitStatusIsCarried",),
        reason="without the code, \"exited 3\" and \"could not be started\" "
               "collapse into the same False, and OpenRC answers in its exit "
               "status",
    ),
    Mutation(
        id="suidowner/silence-becomes-an-accusation",
        file="bob/checks/suid_audit.py",
        old="    return owner.known and owner.package is None",
        new="    return owner.package is None",
        kills=(f"{_SUIDOWN}::TestOnlyAProvenOrphanIsAccused::"
               "test_an_unanswerable_query_is_not",),
        reason="a host whose package manager could not be asked would have "
               "every unexpected SUID binary reported as belonging to no "
               "package \u2014 an alert built out of a failed probe",
    ),
    Mutation(
        id="suidowner/query-failure-read-as-orphan",
        file="bob/checks/_run.py",
        old="        if result.code == 1:\n            return FileOwner(None, True)\n        return FileOwner(None, False)",
        new="        return FileOwner(None, True)",
        kills=(f"{_SUIDOWN}::TestThreeStatesNotTwo::"
               "test_any_other_status_settles_nothing",),
        reason="only exit 1 means \u0022no package owns this\u0022 on all four "
               "managers; a timeout or a locked database exits otherwise and "
               "says nothing about the file",
    ),
    Mutation(
        id="suidowner/orphan-loses-its-own-finding",
        file="bob/checks/suid_audit.py",
        old="        unowned_suid = [p for p in unexpected_suid if _is_unowned(p)]",
        new="        unowned_suid = []",
        kills=(f"{_SUIDOWN}::TestTheCollectorPopulatesIt::"
               "test_an_orphan_reaches_the_snapshot",),
        reason="Kali drowns one planted SUID root binary among fifteen the "
               "distribution ships; without the split the signal is a line in "
               "a list of sixteen",
    ),
    Mutation(
        id="native/success-claimed-without-reading-back",
        file="bob/_sysctl_apply.py",
        old="    if live.split() != value.split():\n        return SysctlResult(False, False, f\"kernel holds {live!r}, not {value!r}\")",
        new="    pass",
        kills=(f"{_NATIVE}::TestItReadsBackBeforeClaimingAnything::"
               "test_a_kernel_holding_another_value_is_not_success",),
        reason="a kernel can accept the write and hold something else \u2014 a "
               "clamped range, an aliased key; only the read-back settles it, "
               "and v0.17.1 was a whole release about fixes reporting success "
               "without having succeeded",
    ),
    Mutation(
        id="native/live-but-unpersisted-called-applied",
        file="bob/_sysctl_apply.py",
        old="        return SysctlResult(True, False, reason)",
        new="        return SysctlResult(True, True, reason)",
        kills=(f"{_NATIVE}::TestLiveButNotPersistedIsReported",),
        reason="live but not persisted reverts at the next reboot while the "
               "audit reports OK \u2014 the state the shell one-liner could "
               "reach silently, which is why it moved into code",
    ),
    Mutation(
        id="native/persist-appends-instead-of-replacing",
        file="bob/_sysctl_apply.py",
        old="    kept = [ln for ln in existing if not setter.match(ln)]",
        new="    kept = list(existing)",
        kills=(f"{_NATIVE}::TestPersistingIsIdempotentByConstruction",),
        reason="applying twice would leave two lines for one key \u2014 the "
               "defect v0.17.1 fixed in the advice, reintroduced in the code "
               "that replaced it",
    ),
    Mutation(
        id="native/parameter-reaches-argv-unchecked",
        file="bob/_sysctl_apply.py",
        old="    m = _PARAM_RE.match(param.strip())\n    return (m.group(1), m.group(2).strip()) if m else None",
        new="    key, _, value = param.partition(\"=\")\n    return (key.strip(), value.strip())",
        kills=(f"{_NATIVE}::TestNothingButAnAssignmentIsAccepted",),
        reason="the parameter reaches argv; the table it comes from is exactly "
               "the kind of thing that grows an entry from somewhere else",
    ),
    Mutation(
        id="native/action-dropped-by-a-wrapper",
        file="bob/scoring.py",
        old="        self.add_finding(FindingLevel.INFO, message, detail, cmd=cmd, cmd_type=cmd_type,\n                         key=key, template_vars=template_vars, fix_action=fix_action)",
        new="        self.add_finding(FindingLevel.INFO, message, detail, cmd=cmd, cmd_type=cmd_type,\n                         key=key, template_vars=template_vars)",
        kills=(f"{_NATIVE}::TestEveryFindingWrapperCarriesTheAction",),
        reason="threading it through warn but not info made check_hardening "
               "raise, fault isolation printed \"section not evaluated\", and "
               "the suite stayed green for an afternoon",
    ),
    Mutation(
        id="cron/absence-read-as-unreadable",
        file="bob/checks/cron_audit.py",
        old="    except FileNotFoundError:",
        new="    except RecursionError:",
        kills=(f"{_ABSENT}::TestAbsenceIsNotAFailureToLook::"
               "test_a_missing_file_is_not_unreadable",
               f"{_ABSENT}::TestTheSnapshotAgreesWithItsOwnContract::"
               "test_a_host_without_etc_crontab_reports_nothing_unreadable"),
        reason="/etc/crontab does not exist on Alpine, Arch or openSUSE; calling "
               "that unreadable put cron.unreadable_files into `unverified`, "
               "which marks the score an upper bound and makes --target fail "
               "closed \u2014 three of six machines downgraded for a file their "
               "distribution never ships",
    ),
    Mutation(
        id="cron/every-failure-swallowed",
        file="bob/checks/cron_audit.py",
        old="    except OSError:\n        # Everything else",
        new="    except OSError:\n        return True\n        # Everything else",
        kills=(f"{_ABSENT}::TestAbsenceIsNotAFailureToLook::"
               "test_a_directory_in_its_place_is_unreadable",
               f"{_ABSENT}::TestAbsenceIsNotAFailureToLook::"
               "test_a_permission_denial_is_unreadable"),
        reason="the polarity twin: separating absence from denial must not "
               "silence the denial, which is the one this flag exists for",
    ),
    Mutation(
        id="install-completion/i18n-not-initialised",
        file="bob/__main__.py",
        old="        i18n.init(lang=config.lang)\n        if os.geteuid() != 0:",
        new="        if os.geteuid() != 0:",
        kills=("tests/test_v0181_install_completion_i18n.py::test_english_output_has_no_bracketed_keys",),
        reason="without i18n.init in the --install-completion branch, every "
               "message it prints falls back to bracketed locale keys",
    ),
    Mutation(
        id="manage-logs/forget-does-not-drop-the-dir",
        file="bob/manage_logs.py",
        old="    extras = [d for d in _get_extra_dirs(user_config) if d != path]\n    _set_extra_dirs(user_config, extras)",
        new="    extras = _get_extra_dirs(user_config)\n    _set_extra_dirs(user_config, extras)",
        kills=("tests/test_manage_logs.py::TestExtraDirectoriesDisplay::test_forget_drops_a_tracked_dir_but_not_the_current",),
        reason="forgetting a tracked directory must actually drop it — a "
               "declared directory is otherwise kept forever with no way to remove it",
    ),
    Mutation(
        id="cron/wide-row-truncated-not-wrapped",
        file="bob/tui/cron.py",
        old="        if fits(name, body, emails):",
        new="        if True:",
        kills=("tests/test_v0183_cron_line_wrap.py::test_a_wide_row_wraps_instead_of_truncating",),
        reason="a row wider than the screen must wrap, not be forced onto one "
               "over-long line the caller then truncates — hiding the addresses",
    ),
    Mutation(
        id="cron/email-column-not-aligned",
        file="bob/tui/cron.py",
        old="            aligned = f\"{mark}{nf}{body.ljust(body_w)}{sep}{emails}\"",
        new="            aligned = f\"{mark}{nf}{body}{sep}{emails}\"",
        kills=("tests/test_v0181_cron_email_alignment.py::test_the_address_column_is_aligned_across_fitting_rows",),
        reason="without padding the schedule column to one width, the e-mail "
               "addresses do not line up across rows",
    ),
    Mutation(
        id="cron/giant-row-drags-short-rows",
        file="bob/tui/cron.py",
        old="    body_w = max((len(body) for name, body, em, _ in rows if fits(name, body, em)),",
        new="    body_w = max((len(body) for name, body, em, _ in rows),",
        kills=("tests/test_v0181_cron_email_alignment.py::test_a_giant_row_does_not_drag_short_rows_onto_two_lines",),
        reason="aligning to every row, not just those that fit, lets one "
               "month-long schedule pad every short row past the screen so they all wrap",
    ),
    Mutation(
        id="cron/no-separator-between-jobs",
        file="bob/tui/cron.py",
        old="        if idx > 0:\n            display.append((separator, -1))",
        new="        if False:\n            display.append((separator, -1))",
        kills=("tests/test_v0181_cron_email_alignment.py::test_a_separator_sits_between_jobs",),
        reason="the dim separator between jobs is what tells them apart at a "
               "glance once a wrapped job spans several lines",
    ),
    Mutation(
        id="capped/one-big-read-again",
        file="bob/_atomic.py",
        old="            chunk = fh.read(min(remaining, _READ_CHUNK))",
        new="            chunk = fh.read(remaining)",
        kills=(f"{_CAPPED}::TestItReadsPseudoFilesystems::"
               "test_a_file_that_refuses_a_large_read_is_still_read",),
        reason="procfs allocates a buffer the size of the request and refuses "
               "a large one: read(8388609) on a sysctl raises ENOMEM, so the "
               "reader written to prevent an OOM could not read a single knob",
    ),
    Mutation(
        id="capped/chunk-as-large-as-the-cap",
        file="bob/_atomic.py",
        old="_READ_CHUNK = 256 * 1024",
        new="_READ_CHUNK = 8 * 1024 * 1024",
        kills=(f"{_CAPPED}::TestItReadsPseudoFilesystems::"
               "test_no_single_read_asks_for_the_whole_cap",),
        reason="the chunk has to stay under what procfs will allocate; 1 MiB "
               "is the largest request measured to succeed",
    ),
    Mutation(
        id="capped/shadow-read-unbounded-again",
        file="bob/checks/user_accounts.py",
        old="        shadow_text = read_text_capped(_SHADOW_PATH, ",
        new="        shadow_text = _SHADOW_PATH.read_text(",
        kills=(f"{_CAPPED}::TestTheChecksThatReadRealPathsAreCapped::"
               "test_it_uses_the_capped_reader",
               f"{_CAPPED}::TestTheChecksThatReadRealPathsAreCapped::"
               "test_shadow_and_passwd_are_among_them"),
        reason="/etc/shadow symlinked to /dev/zero took peak RSS from 113 MB to "
               "2.6 GB, and the kernel OOM-killed python3 at 7.3 GB under "
               "memory pressure",
    ),
    Mutation(
        id="capped/chunks-not-reassembled",
        file="bob/_atomic.py",
        old='    data = "".join(data_parts)',
        new="    data = data_parts[0] if data_parts else \"\"",
        kills=(f"{_CAPPED}::TestItStillRefusesWhatItWasWrittenFor::"
               "test_a_file_spanning_several_chunks_is_whole",),
        reason="reading in chunks must reassemble the file; truncating at the "
               "first chunk would silently shorten every config over 256 KiB",
    ),
    Mutation(
        id="states/enabled-but-down-goes-silent",
        file="bob/checks/services.py",
        old="    if snap.state == ServiceState.INACTIVE_ENABLED:",
        new="    if False and snap.state == ServiceState.INACTIVE_ENABLED:",
        kills=(f"{_STATES}::TestNoStateIsSilent::"
               "test_every_state_renders_a_verdict",
               f"{_STATES}::TestEnabledButDown::test_it_has_its_own_key"),
        reason="the one state in the enum that rendered nothing: the machine "
               "was told to run the service and it is not running \u2014 a "
               "crash, a failed start \u2014 while its port exposure still "
               "fired, so it sat in the panorama with no verdict beside it",
    ),
    Mutation(
        id="states/enabled-but-down-costs-nothing",
        file="bob/checks/services.py",
        old='            key="services.state.inactive_enabled",\n'
            '            message=_t("services.state.inactive_enabled", label=snap.label),\n'
            '            detail=_t("services.state.inactive_enabled_detail"),\n'
            "            points=1,",
        new='            key="services.state.inactive_enabled",\n'
            '            message=_t("services.state.inactive_enabled", label=snap.label),\n'
            '            detail=_t("services.state.inactive_enabled_detail"),\n'
            "            points=0,",
        kills=(f"{_STATES}::TestEnabledButDown::test_it_is_scored_like_its_mirror",),
        reason="its mirror \u2014 running but not enabled \u2014 has cost a "
               "point since v0.8.0 for the same kind of fact; one of the two "
               "directions counting and not the other is the asymmetry that "
               "hid this state for ten releases",
    ),
    Mutation(
        id="lockout/default-deny-applied-unattended",
        file="bob/fixes.py",
        old="    if _LOCKOUT_COMMANDS.search(cmd):\n        return False",
        new="    if False:\n        return False",
        kills=(f"{_LOCKOUT}::TestADefaultDenyPolicyIsNeverRunUnattended::"
               "test_it_is_refused",),
        reason="measured on an Arch VM: --fix --apply --yes ran `iptables -P "
               "INPUT DROP` and left the host with loopback and outbound "
               "broken, while the same audit reported the loopback and "
               "conntrack rules it needs as missing",
    ),
    Mutation(
        id="lockout/firewall-enabled-before-the-port-is-open",
        file="bob/fixes.py",
        old="    others = sorted(others, key=access_phase)",
        new="    others = list(others)",
        kills=(f"{_LOCKOUT}::TestAccessIsGrantedBeforeItIsWithdrawn::"
               "test_the_measured_arch_case",),
        reason="BOB offered `ufw enable` then `ufw allow 22` with sshd "
               "listening; unattended on a remote host the first line ends the "
               "session and the second never reaches anyone",
    ),
    Mutation(
        id="lockout/ipv6-variant-slips-through",
        file="bob/fixes.py",
        old='r"(?<![\\w-])ip6?tables(?:-nft|-legacy)?\\s+.*-P\\s+(?:INPUT|FORWARD)\\s+DROP"',
        new='r"(?<![\\w-])iptables\\s+.*-P\\s+(?:INPUT|FORWARD)\\s+DROP"',
        kills=(f"{_LOCKOUT}::TestADefaultDenyPolicyIsNeverRunUnattended::"
               "test_it_is_refused",),
        reason="ip6tables cuts IPv6 access exactly as iptables cuts IPv4; the "
               "family in the binary's name is not the point",
    ),
    Mutation(
        id="profile/blocked-search-reported-as-absence",
        file="bob/profiles.py",
        old='            unreadable.append(str(directory))',
        new='            continue',
        kills=(f"{_PROFSRCH}::test_unreadable_directory_is_recorded_not_swallowed",
               f"{_PROFSRCH}::test_load_profile_names_the_blocked_directory_in_its_warning"),
        reason="a profile directory created by root under sudo refuses the "
               "invoking user; the profile is sitting in it, and BOB answered "
               "\"not found\" for a question it never got to ask",
    ),
    Mutation(
        id="profile/kernel-refused-name-escapes-as-a-crash",
        file="bob/profiles.py",
        old="        except OSError:\n            # The kernel refused the name itself",
        new="        except ValueError:\n            # The kernel refused the name itself",
        kills=(f"{_PROFSRCH}::test_a_name_the_kernel_refuses_is_a_genuine_absence",
               f"{_PROFSRCH}::test_load_profile_survives_a_name_the_kernel_refuses"),
        reason="measured locally: `bob --profile <300 chars>` printed "
               "\"Fatal error: [Errno 36] File name too long\" instead of the "
               "profile-not-found verdict its one-character-shorter sibling gets",
    ),
    Mutation(
        id="profile/both-outcomes-share-one-sentence",
        file="bob/locales/en.json",
        old='"profile_search_blocked": "Profile \'{profile}\' could not be looked for \u2014 {dirs} unreadable \u2014 using default (server)"',
        new='"profile_search_blocked": "Profile \'{profile}\' not found \u2014 using default (server)"',
        kills=(f"{_PROFSRCH}::test_both_outcomes_have_their_own_sentence_in_both_locales",),
        reason="the distinction is only worth making if the operator can read "
               "it; two keys rendering one sentence is the old defect wearing "
               "a second name",
    ),
    Mutation(
        id="profile/shadowed-builtin-passed-off-as-the-operators",
        file="bob/profiles.py",
        old="    if lookup.unreadable:\n        # The search stops at the first hit",
        new="    if False:\n        # The search stops at the first hit",
        kills=(f"{_PROFSRCH}::test_a_resolved_profile_still_names_the_door_that_stayed_shut",),
        reason="the user profile directory is searched first, so a directory "
               "BOB was refused entry to may hold the very profile the "
               "operator configured; running the built-in instead without a "
               "word makes the audit header name a profile that was never read",
    ),
    Mutation(
        id="baseline/any-json-loads-as-a-baseline-of-zero",
        file="bob/compare.py",
        old='    if not isinstance(raw, dict) or not all(k in raw for k in ("timestamp", "score")):',
        new='    if False:',
        kills=(f"{_STRANGER}::test_a_stranger_is_refused_out_loud[unrelated-object]",
               f"{_STRANGER}::test_a_stranger_is_refused_quietly_too[empty-object]"),
        reason="measured locally: --diff against {\"unrelated\": 1} announced "
               "\"Score improved by 72 point(s)\", two newly opened ports and "
               "two newly active services, above a blank \"Previous audit:\" "
               "line — the current audit read back against a document that "
               "had recorded nothing",
    ),
    Mutation(
        id="baseline/a-score-of-zero-is-mistaken-for-a-missing-field",
        file="bob/compare.py",
        old='    if not isinstance(raw, dict) or not all(k in raw for k in ("timestamp", "score")):',
        new='    if not isinstance(raw, dict) or not all(raw.get(k) for k in ("timestamp", "score")):',
        kills=(f"{_STRANGER}::test_a_baseline_with_a_zero_score_is_still_a_baseline",),
        reason="a machine that scored 0 has a measurement, not a missing "
               "field; a truthiness test would throw away the baseline of "
               "exactly the host that most needs its diff",
    ),
    Mutation(
        id="baseline/refusal-shares-the-invalid-json-sentence",
        file="bob/locales/en.json",
        old='"not_a_baseline": "File {path} parsed as JSON but is not a BOB baseline',
        new='"not_a_baseline": "Baseline file {path} could not be read or parsed as JSON: {error}", "unused_not_a_baseline": "File {path} parsed as JSON but is not a BOB baseline',
        kills=(f"{_STRANGER}::test_both_locales_carry_the_refusal",),
        reason="\"not JSON at all\" and \"JSON, but not ours\" send the "
               "operator to different places; collapsing them hides which "
               "one happened",
    ),
    Mutation(
        id="history/an-unreadable-score-is-repaired-into-zero",
        file="bob/history.py",
        old="        return None\n    if not 0 <= score <= 10:",
        new="        e[\"score\"] = 0\n        return e\n    if not 0 <= score <= 10:",
        kills=(f"{_HISTREAD}::test_a_lost_score_no_longer_invents_a_collapse",),
        reason="the repaired figure does not merely sit in the table \u2014 it "
               "feeds the trend arrows: three audits of 8/10 with one score "
               "field lost rendered 8 \u2192 0 \u2193 then 0 \u2192 8 \u2191, "
               "a collapse and a recovery that never happened",
    ),
    Mutation(
        id="history/out-of-scale-score-is-kept",
        file="bob/history.py",
        old="    if not 0 <= score <= 10:\n        return None",
        new="    if False:\n        return None",
        kills=(f"{_HISTREAD}::test_a_score_bob_never_wrote_is_skipped[999]",
               f"{_HISTREAD}::test_a_score_bob_never_wrote_is_skipped[-5]"),
        reason="BOB writes 0\u201310 and nothing else; a 999 clamped to a "
               "perfect 10 is a posture it never measured",
    ),
    Mutation(
        id="history/a-timestamp-that-is-not-one-reaches-the-renderer",
        file="bob/history.py",
        old="    if not isinstance(ts, str) or not ts:\n        return None",
        new="    if False:\n        return None",
        kills=(f"{_HISTREAD}::test_a_timestamp_that_is_not_one_is_skipped[null]",
               f"{_HISTREAD}::test_a_timestamp_that_is_not_one_is_skipped[12345]"),
        reason="`bob --history` died with TypeError: 'NoneType' object is not "
               "subscriptable \u2014 the v0.14.1 fix checked the shape of the "
               "line and never the shape of its fields",
    ),
    Mutation(
        id="history/true-passes-for-a-score-of-one",
        file="bob/history.py",
        old="    if isinstance(score, bool) or not isinstance(score, int):",
        new="    if not isinstance(score, int):",
        kills=(f"{_HISTREAD}::test_a_score_bob_never_wrote_is_skipped[True]",),
        reason="bool is an int in Python, so `\"score\": true` would enter the "
               "table as a posture of 1/10",
    ),
    Mutation(
        id="history/null-level-prints-the-word-none",
        file="bob/history.py",
        old='        level = e.get("level") or ""',
        new='        level = e.get("level", "")',
        kills=(f"{_HISTREAD}::test_a_null_level_does_not_print_the_word_none",),
        reason="`.get(k, \"\")` returns None when the key is present holding "
               "null, and None formats as the word None in the risk-level "
               "column",
    ),
    Mutation(
        id="sinks/csv-drops-the-finding-key",
        file="bob/csv_output.py",
        old='                "key":     _csv_safe(f.key     or ""),',
        new='                "key":     "",',
        kills=(f"{_SINKKEY}::test_csv_names_the_key_of_every_finding",),
        reason="the column would exist and be empty, which is worse than "
               "absent: a consumer joins on it and gets nothing back, with "
               "no error to say why",
    ),
    Mutation(
        id="sinks/csv-key-column-moves-mid-list",
        file="bob/csv_output.py",
        old='    "fix_cmd",\n    "note",',
        new='    "key",\n    "fix_cmd",\n    "note",',
        kills=(f"{_SINKKEY}::test_csv_key_column_is_appended_not_inserted",),
        reason="T11 inserted `detail` mid-list in v0.8.1 and every "
               "column-by-index consumer had to re-index; a lookup field "
               "nobody reads in sequence has no reason to cost that again",
    ),
    Mutation(
        id="sinks/fix-action-leaks-into-the-report",
        file="bob/csv_output.py",
        old='                "note":    _csv_safe(f.note    or ""),',
        new='                "note":    _csv_safe(str(f.fix_action)),',
        kills=(f"{_SINKKEY}::test_fix_action_stays_out_of_every_sink",),
        reason="`fix_action` tells BOB how to apply a fix; it is an "
               "instruction, not a measurement, and a sink that prints it "
               "presents machinery as a fact about the host",
    ),
    Mutation(
        id="archive/the-log-drops-the-command-again",
        file="bob/display.py",
        old="            detail=finding.detail, cmd=finding.cmd,\n            cmd_type=finding.cmd_type, key=finding.key,\n        )",
        new="        )",
        kills=(f"{_ARCHIVE}::test_the_log_carries_the_command_it_showed_on_screen",
               f"{_ARCHIVE}::test_the_log_names_the_finding"),
        reason="`write_finding` accepted `detail` from the day it was written "
               "and no caller ever passed it, which is how the .log came to "
               "hold the accusation and none of the remedy for ten releases",
    ),
    Mutation(
        id="archive/quiet-strips-the-file-too",
        file="bob/display.py",
        old="                detail=finding.detail, cmd=finding.cmd,\n                cmd_type=finding.cmd_type, key=finding.key,\n            )",
        new="            )",
        kills=(f"{_ARCHIVE}::test_quiet_silences_the_screen_and_not_the_archive",),
        reason="`-q -d` is a cron job asking for a file and no output; quiet "
               "is about the terminal, and a file written under it that has "
               "no remediation is the one nobody can act on months later",
    ),
    Mutation(
        id="archive/a-check-is-rendered-as-a-fix",
        file="bob/report.py",
        old='        marker = "?" if cmd_type == "check" else "\u2192"',
        new='        marker = "\u2192"',
        kills=(f"{_ARCHIVE}::test_a_check_command_is_not_marked_as_a_fix",),
        reason="the arrow means BOB is telling you to change something; a "
               "command that only looks must not wear it, in the archive any "
               "more than on the screen",
    ),
    Mutation(
        id="archive/empty-body-writes-blank-lines",
        file="bob/report.py",
        old="        for line in detail.splitlines():\n            if line.strip():",
        new="        for line in detail.splitlines() or [\"\"]:\n            if True:",
        kills=(f"{_ARCHIVE}::test_a_finding_with_no_body_adds_no_empty_lines",),
        reason="a finding with nothing to add would gain an indented blank "
               "line, and an OK-heavy audit would double the file with them",
    ),
    Mutation(
        id="snapshot/a-module-falls-off-the-map",
        file="DOCUMENTS/SNAPSHOT.md",
        old="│   │   ├── _ufw.py            ←",
        new="│   │   ├── _ufw_parser        ←",
        kills=(f"{_SNAPMAP}::test_snapshot_names_every_module",),
        reason="bob/checks/_ufw.py was unmapped from v0.15.0 to v0.18.0 \u2014 "
               "four releases in which the map loaded first before any audit "
               "did not mention the module that parses every UFW rule",
    ),
    Mutation(
        id="sysctl/one-fix-falls-back-to-the-shell",
        file="bob/checks/hardening.py",
        old='            **sysctl_fix("net.ipv4.tcp_syncookies=1"),',
        new='            cmd=sysctl_fix_cmd("net.ipv4.tcp_syncookies=1"),',
        kills=(f"{_NATIVEALL}::test_no_check_builds_a_sysctl_command_without_its_action",),
        reason="the advice on screen is identical and every test about the "
               "advice passes, while --apply refuses the fix again \u2014 the "
               "v0.18.0 defect restored one call site at a time, silently",
    ),
    Mutation(
        id="py314/profile-lookup-trusts-is-file",
        file="bob/profiles.py",
        old="            if strict_is_file(candidate):",
        new="            if candidate.is_file():",
        kills=(f"{_PY314}::test_profile_in_a_shut_directory_is_not_reported_absent",),
        reason="caught by the CI's Python 3.14 job: from 3.14 Path.is_file() "
               "answers False to a denial, the except PermissionError never "
               "ran, and a profile sitting in a shut directory was 'not found'",
    ),
    Mutation(
        id="py314/could-not-tell-reads-as-safe",
        file="bob/checks/services.py",
        old="        if not strict_is_symlink(path):",
        new="        if not path.is_symlink():",
        kills=(f"{_PY314}::test_a_config_path_bob_cannot_inspect_is_not_safe",),
        reason="the function's own comment says the failure answer must be "
               "False because 'I could not tell' is not 'safe'; under 3.14's "
               "pathlib it answered True",
    ),
    Mutation(
        id="py314/logrotate-claims-a-read-it-never-made",
        file="bob/checks/log_rotation.py",
        old='            if strict_is_file(p) and not p.name.startswith(".")',
        new='            if p.is_file() and not p.name.startswith(".")',
        kills=(f"{_PY314}::test_logrotate_rules_it_could_not_inspect_are_not_a_count_of_zero",),
        reason="a listable but untraversable /etc/logrotate.d came back as "
               "(0, readable=True) \u2014 'no logrotate rules configured' about a "
               "directory whose entries BOB never inspected",
    ),
    Mutation(
        id="py314/plugin-denial-logged-as-irregular",
        file="bob/plugin_checks.py",
        old="        if not strict_is_file(plugin_path):",
        new="        if not plugin_path.is_file():",
        kills=(f"{_PY314}::test_a_plugin_bob_cannot_stat_is_not_called_irregular",),
        reason="the log said 'not a regular file' about a plugin BOB had not "
               "been allowed to stat",
    ),
    Mutation(
        id="py314/the-helper-swallows-a-denial-too",
        file="bob/_fs.py",
        old="        if exc.errno in _ABSENT:\n            return None\n        raise",
        new="        return None",
        kills=(f"{_PY314}::test_a_denial_still_raises",),
        reason="a strict predicate that swallows the denial is Path.is_file() "
               "on 3.14 under another name, and every call site above goes "
               "back to reading 'not allowed' as 'not there'",
    ),
    Mutation(
        id="py314/sudoers-d-denial-read-as-no-rules",
        file="bob/checks/file_perms.py",
        old="        if strict_is_dir(sudoers_d):",
        new="        if sudoers_d.is_dir():",
        kills=(f"{_PY314}::test_sudoers_d_denied_is_not_read_as_no_rules",),
        reason="a bare is_dir() on 3.14 returns False for a refused /etc/sudoers.d, "
               "so a hidden NOPASSWD:ALL reads as 'no risky sudo rule'",
    ),
    Mutation(
        id="py314/etc-ssh-denial-read-as-clean",
        file="bob/checks/file_perms.py",
        old="            key_paths = sorted(ssh_dir.glob(\"ssh_host_*_key\")) if strict_is_dir(ssh_dir) else []",
        new="            key_paths = sorted(ssh_dir.glob(\"ssh_host_*_key\")) if ssh_dir.is_dir() else []",
        kills=(f"{_PY314}::test_etc_ssh_denied_marks_host_keys_unreadable",),
        reason="a bare is_dir() on 3.14 returns False for a refused /etc/ssh, so "
               "a world-readable host key reads as clean instead of not-established",
    ),
    Mutation(
        id="py314/cron-d-denial-read-as-empty",
        file="bob/checks/cron_audit.py",
        old="        for cron_dir in _CRON_FORMAT_DIRS:\n            try:\n                entries = sorted(cron_dir.iterdir()) if strict_is_dir(cron_dir) else []",
        new="        for cron_dir in _CRON_FORMAT_DIRS:\n            try:\n                entries = sorted(cron_dir.iterdir()) if cron_dir.is_dir() else []",
        kills=(f"{_PY314}::test_cron_d_denied_is_recorded_unreadable_not_empty",),
        reason="a bare is_dir() on 3.14 returns False for a refused /etc/cron.d, "
               "so a pipe-to-shell cron inside goes unaudited and the verdict stays clean",
    ),
    Mutation(
        id="py314/user-crontab-denial-read-as-empty",
        file="bob/checks/cron_audit.py",
        old="                   if strict_is_dir(_USER_CRONTAB_DIR) else [])",
        new="                   if _USER_CRONTAB_DIR.is_dir() else [])",
        kills=(f"{_PY314}::test_user_crontab_dir_denied_is_recorded_unreadable",),
        reason="a bare is_dir() on 3.14 returns False for a refused user crontab "
               "spool, hiding a rogue user's crontab",
    ),
    Mutation(
        id="py314/journal-dir-denial-read-as-volatile",
        file="bob/checks/log_rotation.py",
        old="            journal_persistent: \"bool | None\" = strict_is_dir(_JOURNAL_DIR)",
        new="            journal_persistent: \"bool | None\" = _JOURNAL_DIR.is_dir()",
        kills=(f"{_PY314}::test_journal_dir_denied_is_not_read_as_volatile",),
        reason="a bare is_dir() on 3.14 returns False for a refused /var/log/journal, "
               "so a default-storage host reads as volatile and warns that logs are lost",
    ),
    Mutation(
        id="py314/borg-keys-denial-crashes-from-system",
        file="bob/checks/backup.py",
        old="            try:\n                borg_active = strict_is_dir(_BORG_KEYS_DIR) and any(_BORG_KEYS_DIR.iterdir())\n            except OSError:\n                borg_active = False",
        new="            borg_active = _BORG_KEYS_DIR.is_dir() and any(_BORG_KEYS_DIR.iterdir())",
        kills=(f"{_PY314}::test_borg_keys_dir_denied_is_installed_not_active",),
        reason="without the guard a refused borg keys dir raises out of from_system "
               "(which promises never to) up to 3.13, and reads as 'installed' by "
               "silent False on 3.14 — the guard makes both the honest 'installed'",
    ),
    Mutation(
        id="py314/borgmatic-config-denial-crashes-from-system",
        file="bob/checks/backup.py",
        old="    try:\n        if strict_is_file(path):\n            return True\n        if strict_is_dir(path):\n            return any(path.iterdir())\n    except OSError:\n        return False\n    return False",
        new="    if path.is_file():\n        return True\n    if path.is_dir():\n        return any(path.iterdir())\n    return False",
        kills=(f"{_PY314}::test_borgmatic_config_denied_is_installed_not_active",),
        reason="a borgmatic config path BOB may not read raised out of from_system "
               "up to 3.13; the guard turns the denial into 'installed', not a crash",
    ),
    Mutation(
        id="py314/cert-store-glob-swallows-denial",
        file="bob/checks/ssl_certs.py",
        old="        try:\n            if strict_is_dir(_SSL_PRIVATE):\n                for cert in _SSL_PRIVATE.iterdir():\n                    if cert.suffix in _PRIV_CERT_EXTS:\n                        _add_path(cert, paths)\n        except OSError:\n            snap.unreadable_dirs.append(str(_SSL_PRIVATE))",
        new="        if _SSL_PRIVATE.is_dir():\n            for ext in (\"*.pem\", \"*.crt\", \"*.cert\"):\n                for cert in _SSL_PRIVATE.glob(ext):\n                    _add_path(cert, paths)",
        kills=(f"{_PY314}::test_locked_cert_store_is_recorded_unreadable_not_absent",),
        reason="Path.glob() swallows the PermissionError on a 0700/0710 store "
               "(is_dir() is True — the parent is traversable) and returns [], so "
               "an expiring cert inside reads as 'no certificates', its deduction "
               "silently unmade; iterdir() raises and the denial is recorded",
    ),
    Mutation(
        id="py314/tripwire-db-glob-swallows-denial",
        file="bob/checks/file_integrity.py",
        old="        for entry in _TRIPWIRE_DB_DIR.iterdir():\n            if entry.suffix == \".twd\":\n                return (True, True)\n        return (False, True)\n    except FileNotFoundError:\n        return (False, True)   # not initialised — a real \"no database\"\n    except OSError:\n        return (False, False)  # denied — the verdict is unknown",
        new="        if any(_TRIPWIRE_DB_DIR.glob(\"*.twd\")):\n            return (True, True)\n        return (False, True)\n    except FileNotFoundError:\n        return (False, True)\n    except OSError:\n        return (False, False)",
        kills=(f"{_PY314}::test_tripwire_db_dir_denied_is_unknown_not_missing",),
        reason="glob() eats the read denial on a root-owned /var/lib/tripwire and "
               "returns [], so db_readable stays True and the tool reports the "
               "database not initialised — a WARN and a point on a covered host",
    ),
    Mutation(
        id="sshd/fix-ignores-the-dropin",
        file="bob/checks/ssh/_subchecks.py",
        old="    dropin = cfg.get(\"_dropin_dir\")\n    if dropin:",
        new="    dropin = cfg.get(\"_dropin_dir\")\n    if False:",
        kills=("tests/test_v0190_sshd_dropin_remediation.py::TestFixTargetsTheWinningFile::test_dropin_present_writes_the_00_override",),
        reason="ignoring the drop-in dir sends the fix back to editing the main "
               "sshd_config, a no-op when the directive lives in a drop-in that "
               "the Include reads first (field-test finding on a real Pi)",
    ),
    Mutation(
        id="sshd/parser-forgets-the-dropin-dir",
        file="bob/checks/ssh/_parsers.py",
        old='            if "*" in pattern:\n                config.setdefault("_dropin_dir", os.path.dirname(pattern))',
        new='            if False:\n                config.setdefault("_dropin_dir", os.path.dirname(pattern))',
        kills=("tests/test_v0190_sshd_dropin_remediation.py::TestParserRecordsDropinDir::test_glob_include_records_the_directory",),
        reason="without recording the drop-in dir the fix cannot target it and "
               "falls back to the ineffective main-file edit",
    ),
    Mutation(
        id="samba/fix-appends-instead-of-replacing",
        file="bob/checks/samba.py",
        old='    return f"{delete} && {insert}"',
        new='    return insert',
        kills=("tests/test_v0171_advice_is_safe_to_apply_twice.py::TestTheGeneratedCommandsAreIdempotent::test_the_samba_directive_deletes_then_inserts",),
        reason="without the delete the fix only appends a competing directive; "
               "samba resolves duplicates last-wins so the stale NT1/disabled/"
               "bad-user line keeps winning and the fix silently does nothing "
               "(field-test finding on a real Pi)",
    ),
    Mutation(
        id="grouping/health-group-collapses-into-hardening",
        file="bob/runner.py",
        old='    emit_group("health_resilience")',
        new='    emit_group("system_hardening")',
        kills=("tests/test_v0183_audit_grouping.py::TestGroupOrder::test_groups_appear_in_the_expected_order",),
        reason="collapsing the health group back into a second SYSTEM HARDENING "
               "header is exactly the overloaded-group regression v0.18.3 split, "
               "and the taxonomy guard must catch the order drift",
    ),
    Mutation(
        id="compare/breakdown-lists-unchanged-keys",
        file="bob/compare.py",
        old="            for k in (set(prev_bd) | set(curr_bd))\n            if prev_bd.get(k, 0) != curr_bd.get(k, 0)",
        new="            for k in (set(prev_bd) | set(curr_bd))",
        kills=(f"{_CMPBD}::TestDeltaPerKey::test_only_changed_keys_appear",),
        reason="without the changed-only filter the breakdown lists every key "
               "including those whose points did not move, turning the "
               "attribution into noise",
    ),
    Mutation(
        id="compare/breakdown-ignores-old-baseline-none",
        file="bob/compare.py",
        old="    if prev.deduction_breakdown is not None and curr.deduction_breakdown is not None:",
        new="    if curr.deduction_breakdown is not None:",
        kills=(f"{_CMPBD}::TestDeltaPerKey::test_old_baseline_none_degrades_to_no_per_key",),
        reason="dropping the prev-side None guard makes a pre-v0.18.3 baseline "
               "(breakdown None) be diffed as if every current key were new, "
               "attributing the whole score to controls it never measured",
    ),
    Mutation(
        id="py314/aide-db-path-exists-swallows-denial",
        file="bob/checks/file_integrity.py",
        old="        try:\n            if strict_is_file(p):\n                found = True\n        except OSError:\n            return (False, False)",
        new="        if path_exists(p):\n            found = True",
        kills=(f"{_PY314}::test_aide_db_dir_denied_is_unknown_not_missing",),
        reason="path_exists() swallows the denial on a root-owned /var/lib/aide, so "
               "db_readable stays True and an initialised database reads as missing",
    ),
    Mutation(
        id="sshd-session/the-regex-knows-only-sshd",
        file="bob/checks/auth_log.py",
        old='_SSHD_TAG = r"sshd(?:-session|-auth)?\\[\\d+\\]:"',
        new='_SSHD_TAG = r"sshd\\[\\d+\\]:"',
        kills=(f"{_SSHDSESS}::test_an_attack_logged_by_sshd_session_raises_the_brute_force_warning",
               f"{_SSHDSESS}::test_accepted_logins_from_sshd_session_are_counted"),
        reason="measured on a Raspberry Pi Zero W with OpenSSH 10.0p2: 71 failed "
               "attempts and 29 logins in the journal, all under sshd-session, "
               "and BOB 0.18.0 answered OK — no logins, no brute force",
    ),
    Mutation(
        id="sshd-session/the-journal-is-asked-for-sshd-only",
        file="bob/checks/auth_log.py",
        old='_SSHD_IDENTIFIERS = ("sshd", "sshd-session", "sshd-auth")',
        new='_SSHD_IDENTIFIERS = ("sshd",)',
        kills=(f"{_SSHDSESS}::test_the_journal_is_asked_for_sshd_session",),
        reason="a regex that knows sshd-session reads nothing if journalctl was "
               "never asked for it; on a journald-only host that query is the "
               "only source there is",
    ),
    Mutation(
        id="sshd-session/the-command-reads-a-file-that-is-not-there",
        file="bob/checks/auth_log.py",
        old='cmd=(_JOURNAL_ACCEPTED_CMD if snapshot.source == "journald"',
        new='cmd=(_JOURNAL_ACCEPTED_CMD if False',
        kills=(f"{_SSHDSESS}::test_the_offered_command_reads_where_bob_read",),
        reason="BOB told the operator to grep /var/log/auth.log on hosts where "
               "it had read the journal because that file does not exist",
    ),
    Mutation(
        id="testing-table/the-published-v0180-figure-returns",
        file="DOCUMENTS/TESTING.md",
        old="| v0.18.0 | 9959 |",
        new="| v0.18.0 | 9832 |",
        kills=(f"{_TESTTAB}::test_every_row_matches_its_changelog",),
        reason="v0.18.0 was published with this row reading 9832 \u2014 a count "
               "taken eight commits before the release \u2014 and no guard read "
               "the table",
    ),
    Mutation(
        id="rpi-seed/the-seed-is-never-read",
        file="bob/checks/raspberry_pi.py",
        old="            _read_seed(snap, snap.boot_dir, _shadow or Path(\"/etc/shadow\"))\n",
        new="",
        kills=(f"{_SEED}::test_the_password_in_the_seed_is_reported_not_passed_as_ok",
               f"{_SEED}::test_the_wifi_key_in_the_seed_is_reported"),
        reason="measured on a Pi Zero W running trixie: the seed held the sudo "
               "account's current hash and the Wi-Fi PSK, readable by every "
               "local account, and BOB 0.18.0 printed an all-clear",
    ),
    Mutation(
        id="rpi-seed/all-clear-printed-over-the-credentials",
        file="bob/checks/raspberry_pi.py",
        old="    elif not (snapshot.userconf_user or snapshot.seed_password\n              or snapshot.seed_wifi_keys):",
        new="    elif True:",
        kills=(f"{_SEED}::test_the_password_in_the_seed_is_reported_not_passed_as_ok",),
        reason="the OK line and the WARN beside it would contradict each other, "
               "and the OK is the one a skimming reader keeps",
    ),
    Mutation(
        id="rpi-seed/an-unreadable-seed-reads-as-empty",
        file="bob/checks/raspberry_pi.py",
        old="    except OSError:\n        snap.unreadable.append(path.name)\n        return None",
        new="    except OSError:\n        return None",
        kills=(f"{_SEED}::test_a_seed_bob_could_not_read_blocks_the_all_clear",),
        reason="a file BOB could not open said nothing about its contents; "
               "treating it as empty is the class this project has closed five "
               "times, reopened in a new collector",
    ),
    Mutation(
        id="rpi-seed/currency-never-established",
        file="bob/checks/raspberry_pi.py",
        old="            return parts[1] == digest",
        new="            return None",
        kills=(f"{_SEED}::test_the_hash_is_said_to_be_the_current_one_when_it_is",
               f"{_SEED}::test_a_stale_hash_is_called_stale"),
        reason="on the board the seed hash was byte-identical to /etc/shadow; "
               "saying so is the difference between a leak and a leftover",
    ),
    Mutation(
        id="rpi-seed/the-remedy-deletes-the-seed",
        file="bob/checks/raspberry_pi.py",
        old="            cmd=(\"sudo sed -i -E \"\n                 \"'/^[[:space:]]*(passwd|hashed_passwd|plain_text_passwd):/d' \"\n                 f\"{user_data}\"),",
        new="            cmd=f\"sudo rm {user_data}\",",
        kills=(f"{_SEED}::test_applying_both_commands_clears_the_findings_and_nothing_else",),
        reason="deleting the seed hands cloud-init no datasource on the next "
               "boot; it treats the machine as a new instance and re-runs its "
               "first-boot modules — the proven remedy removes only the lines",
    ),
    Mutation(
        id="apparmor/the-tool-is-believed-over-the-kernel",
        file="bob/checks/mac_policy.py",
        old="        if _AA_MODULE_DIR.is_dir() and not _apparmor_live_in_kernel():",
        new="        if False:",
        kills=(f"{_AAOFF}::test_the_pi_is_not_told_apparmor_is_active",
               f"{_AAOFF}::test_no_ceiling_for_an_uncertainty_that_does_not_exist"),
        reason="measured on a Raspberry Pi Zero W: aa-status said \"module is "
               "loaded\" and exited 3 while the kernel said enabled=N; BOB called "
               "AppArmor active and capped the score for an uncertainty it had "
               "invented",
    ),
    Mutation(
        id="apparmor/off-in-kernel-told-to-start-the-service",
        file="bob/checks/mac_policy.py",
        old='            cmd = ("sudo sed -i \'/ apparmor=1/!s/$/ apparmor=1 security=apparmor/\' "\n                   f"{snapshot.kernel_cmdline_file}")',
        new='            cmd = "sudo systemctl enable --now apparmor"',
        kills=(f"{_AAOFF}::test_the_remedy_is_the_kernel_command_line_not_systemctl",),
        reason="apparmor.service carries ConditionSecurity=apparmor; on the Pi "
               "systemd skipped it, so this advice changes nothing",
    ),
    Mutation(
        id="apparmor/the-parameter-is-appended-every-time",
        file="bob/checks/mac_policy.py",
        old="            cmd = (\"sudo sed -i '/ apparmor=1/!s/$/ apparmor=1 security=apparmor/' \"",
        new="            cmd = (\"sudo sed -i '1 s/$/ apparmor=1 security=apparmor/' \"",
        kills=(f"{_AAOFF}::test_applying_the_remedy_twice_leaves_one_line_and_one_parameter",),
        reason="v0.17.1 made every append check before it writes; a boot "
               "command line that grows by two parameters per --fix --apply is "
               "the same defect on a file the firmware parses",
    ),
    Mutation(
        id="apparmor/a-command-for-a-bootloader-never-measured",
        file="bob/checks/mac_policy.py",
        old="        cmd = \"\"\n        if snapshot.kernel_cmdline_file:",
        new="        cmd = \"sudo update-grub\"\n        if snapshot.kernel_cmdline_file:",
        kills=(f"{_AAOFF}::test_without_a_measured_bootloader_there_is_no_command",),
        reason="where BOB has no measured command it emits none and says so",
    ),
    Mutation(
        id="rp_filter/reads-conf-all-alone",
        file="bob/checks/hardening.py",
        old="        rp_filter, rp_filter_all, rp_filter_iface = _effective_rp_filter()",
        new='        rp_filter = _read_sysctl_int("net.ipv4.conf.all.rp_filter")\n        rp_filter_all = rp_filter\n        rp_filter_iface = ""',
        kills=(f"{_RPF}::test_from_system_computes_the_effective_posture_not_conf_all",),
        reason="measured on a Raspberry Pi Zero W: conf/all=0 while wlan0=2, so "
               "reading conf/all alone reported disabled on an interface that "
               "was filtering — and on the whole systemd family with it",
    ),
    Mutation(
        id="rp_filter/weakest-by-lowest-number-not-security",
        file="bob/checks/hardening.py",
        old="        if weakest is None or _RP_RANK[effective] < _RP_RANK[weakest]:",
        new="        if weakest is None or effective < weakest:",
        kills=(f"{_RPF}::test_the_weakest_interface_by_security_wins_not_the_lowest_number",),
        reason="loose (2) is weaker than strict (1) but numerically larger; a "
               "plain min() would call a strict+loose host strict",
    ),
    Mutation(
        id="rp_filter/loopback-counted-as-an-interface",
        file="bob/checks/hardening.py",
        old='_RP_NOT_AN_INTERFACE = frozenset({"all", "default", "lo"})',
        new='_RP_NOT_AN_INTERFACE = frozenset({"all", "default"})',
        kills=(f"{_RPF}::test_loopback_at_zero_does_not_read_as_disabled",),
        reason="loopback cannot receive a spoofed packet from the network; "
               "counting lo=0 would warn 'disabled' on a machine that filters "
               "every real interface",
    ),
    Mutation(
        id="rp_filter/conf-all-one-does-not-lift-a-zero-interface",
        file="bob/checks/hardening.py",
        old="        effective = max(all_val, iface_val)",
        new="        effective = iface_val",
        kills=(f"{_RPF}::test_conf_all_one_lifts_a_zero_interface_to_strict",),
        reason="the kernel OR-s conf/all into every interface; ignoring it "
               "would report an interface at 0 as off on a host where conf/all=1 "
               "makes the kernel enforce strict",
    ),
    Mutation(
        id="socket-activated/no-trigger-check-so-cups-is-stopped",
        file="bob/checks/services.py",
        old="        if _active_trigger(svc_name):\n            return ServiceState.SOCKET_ACTIVATED\n        return ServiceState.INACTIVE_ENABLED",
        new="        return ServiceState.INACTIVE_ENABLED",
        kills=(f"{_SOCK}::test_the_cups_case_is_socket_activated_not_inactive_enabled",
               f"{_SOCK}::test_the_snapshot_from_the_collector_knows_the_trigger"),
        reason="measured on a Pi Zero W: cups.service inactive+enabled with "
               "cups.socket active; without the trigger check v0.18.0 called it "
               "a crash and took a point from a service listening on demand",
    ),
    Mutation(
        id="socket-activated/a-dead-trigger-passes-for-a-live-one",
        file="bob/checks/services.py",
        old='        if _run("systemctl", "is-active", unit).strip() == "active":\n            return unit',
        new='        if unit:\n            return unit',
        kills=(f"{_SOCK}::test_enabled_and_inactive_with_no_active_trigger_is_still_stopped",),
        reason="a service with a socket unit that is itself down is stopped, "
               "not dormant-by-activation; the trigger has to be active",
    ),
    Mutation(
        id="socket-activated/counted-as-inactive-in-the-panorama",
        file="bob/checks/services.py",
        old="        return self in (ServiceState.ACTIVE_ENABLED, ServiceState.ACTIVE_DISABLED,\n                        ServiceState.SOCKET_ACTIVATED)",
        new="        return self in (ServiceState.ACTIVE_ENABLED, ServiceState.ACTIVE_DISABLED)",
        kills=(f"{_SOCK}::test_the_snapshot_from_the_collector_knows_the_trigger",),
        reason="the socket is listening and holds the port; a socket-activated "
               "service that reads as inactive would be dimmed in the panorama "
               "and its port dropped from exposure analysis",
    ),
    Mutation(
        id="kernel-flavour/all-flavours-ranked-together",
        file="bob/checks/kernel_modules.py",
        old="    family = [k for k in kernels if _kernel_flavour(k) == running_flavour]\n    most_recent = family[-1] if family else kernels[-1]",
        new="    family = kernels\n    most_recent = kernels[-1]",
        kills=("tests/test_v0181_kernel_flavour_is_not_comparable.py::test_the_pi_is_not_told_to_reboot_into_arm64",
               "tests/test_v0181_kernel_flavour_is_not_comparable.py::test_the_pi_fallback_is_not_offered_for_purge"),
        reason="measured on a Pi Zero W: ranking rpi-v6/v7/v8 together made the "
               "arm64 build the latest and told an ARMv6 board to reboot into a "
               "kernel it cannot run, then offered its own fallback for purge",
    ),
    Mutation(
        id="kernel-flavour/debian-revision-splits-one-arch",
        file="bob/checks/kernel_modules.py",
        old="    base = _strip_unsigned(version)\n    return base.rsplit(\"-\", 1)[-1]",
        new="    base = _strip_unsigned(version)\n    return base",
        kills=("tests/test_v0181_kernel_flavour_is_not_comparable.py::test_debian_revision_does_not_split_one_architecture",
               "tests/test_v0181_kernel_flavour_is_not_comparable.py::test_a_real_pending_reboot_within_one_flavour_still_fires"),
        reason="6.12.63+deb13-amd64 and 6.12.74+deb13+1-amd64 are one architecture; "
               "keying the flavour on the whole string splits them and hides a "
               "genuine pending reboot",
    ),
    Mutation(
        id="zram/treated-as-a-disk-so-lower-swappiness",
        file="bob/checks/memory.py",
        old="    if snapshot.swap_devices and all(_is_zram(d) for d in snapshot.swap_devices):",
        new="    if False:",
        kills=("tests/test_v0181_zram_swap_is_not_a_disk.py::test_zram_swap_is_reported_without_a_deduction",
               "tests/test_v0181_zram_swap_is_not_a_disk.py::test_no_lower_swappiness_advice_on_zram"),
        reason="measured on a Pi Zero W with zram-only swap: without the zram "
               "branch BOB warned swappiness=60 was too aggressive and offered "
               "to lower it to 1 — the inverse of what zram wants",
    ),
    Mutation(
        id="zram/counted-as-an-ssd-to-wear-out",
        file="bob/checks/memory.py",
        old="        snap.swap_on_ssd = _detect_swap_on_ssd(\n            [d for d in snap.swap_devices if not _is_zram(d)])",
        new="        snap.swap_on_ssd = _detect_swap_on_ssd(snap.swap_devices)",
        kills=("tests/test_v0181_zram_swap_is_not_a_disk.py::test_from_system_excludes_zram_before_the_ssd_probe",),
        reason="zram's rotational flag reads 0; counting it as an SSD would "
               "attach a physical-wear warning to a block device that is RAM",
    ),
    Mutation(
        id="zram/matches-a-swapfile-named-zram",
        file="bob/checks/memory.py",
        old='    return bool(re.match(r"^/dev/zram\\d+$", device.strip()))',
        new='    return "zram" in device',
        kills=("tests/test_v0181_zram_swap_is_not_a_disk.py::test_is_zram",),
        reason="a swapfile at /swap/zram-backup is not a zram device; only "
               "/dev/zramN is",
    ),
    Mutation(
        id="condition-skipped/blames-the-service-for-the-kernel",
        file="bob/checks/services_state.py",
        old="                if _condition_skipped(unit_id):\n                    continue",
        new="                if False:\n                    continue",
        kills=("tests/test_v0181_condition_skipped_is_not_a_gap.py::test_apparmor_skipped_by_condition_is_not_enabled_inactive",
               "tests/test_v0181_condition_skipped_is_not_a_gap.py::test_it_produces_no_finding_and_no_deduction"),
        reason="measured on a Pi: apparmor.service inactive+enabled with "
               "ConditionResult=no because the kernel has AppArmor off; without "
               "the check BOB reports a security service not running and blames "
               "the service for the kernel",
    ),
    Mutation(
        id="condition-skipped/any-condition-value-excuses",
        file="bob/checks/services_state.py",
        old='    return out.strip().lower() == "conditionresult=no"',
        new='    return "conditionresult=no" not in out.strip().lower()',
        kills=("tests/test_v0181_condition_skipped_is_not_a_gap.py::test_the_condition_check_only_excuses_condition_no",
               "tests/test_v0181_condition_skipped_is_not_a_gap.py::test_a_service_stopped_with_condition_met_is_still_a_gap"),
        reason="only ConditionResult=no means systemd skipped the unit; a "
               "condition that was met (yes) and an inactive service is a real "
               "gap, and inverting the test would silence every one of them",
    ),
    Mutation(
        id="orphan-socket/inactive-still-flagged",
        file="bob/checks/socket_units.py",
        old='        return self.active_state == "active" and bool(self.broken_trigger)',
        new='        return bool(self.broken_trigger)',
        kills=("tests/test_v0181_inactive_socket_is_not_an_orphan.py::test_an_inactive_socket_with_a_broken_trigger_is_not_an_orphan",
               "tests/test_v0181_inactive_socket_is_not_an_orphan.py::test_the_inactive_syslog_socket_produces_no_orphan_finding"),
        reason="measured on a Pi: syslog.socket is inactive with a not-found "
               "syslog.service; an inactive socket holds no port open and is no "
               "surface, but without the active check it was listed as an orphan",
    ),
    Mutation(
        id="fix-scope/check-ignored-so-every-fix-applies",
        file="bob/fixes.py",
        old="    check_only = getattr(config, \"check_only\", None)\n    if check_only:",
        new="    check_only = getattr(config, \"check_only\", None)\n    if False:",
        kills=("tests/test_v0181_fix_honours_check_scope.py::test_check_raspberry_pi_excludes_the_firewall_fix",
               "tests/test_v0181_fix_honours_check_scope.py::test_run_fixes_preview_counts_only_selected_section"),
        reason="measured on a Pi: --check=raspberry_pi --fix --apply also ran "
               "apt install -y ufw from the always-on firewall section; without "
               "the filter --fix ignores the scope --check set",
    ),
    Mutation(
        id="fix-scope/section-never-stamped",
        file="bob/scoring.py",
        old="            if section and not finding.section:\n                finding.section = section",
        new="            if False:\n                finding.section = section",
        kills=("tests/test_v0181_fix_honours_check_scope.py::test_apply_stamps_the_section_on_each_finding",
               "tests/test_v0181_fix_honours_check_scope.py::test_check_firewall_includes_the_firewall_fix"),
        reason="an unstamped finding has section '' and the filter treats it as "
               "always-included, so without the stamp the scope filter is inert",
    ),
    Mutation(
        id="fix-scope/preset-section-overwritten",
        file="bob/scoring.py",
        old="            if section and not finding.section:",
        new="            if section:",
        kills=("tests/test_v0181_fix_honours_check_scope.py::test_a_finding_that_already_names_a_section_keeps_it",),
        reason="a finding that already names its section (a check that tags its "
               "own) must keep it, not be relabelled by the apply call site",
    ),
    Mutation(
        id="explain-family/level-not-stripped-splits-ubuntu",
        file="bob/cis_refs.py",
        old="    head = _LEVEL_SUFFIX.sub(\"\", head).strip()",
        new="    head = head.strip()",
        kills=("tests/test_v0181_explain_list_grouped_by_family.py::test_the_level_is_stripped_so_l1_and_l2_group_under_one_distro",),
        reason="without stripping L1/L2, CIS Ubuntu 22.04 L1 and L2 keep their "
               "level and the Ubuntu keys scatter across more than one distro folder",
    ),
    Mutation(
        id="explain-family/best-practice-not-translated",
        file="bob/explain.py",
        old="        distro_label = (t(\"explain.ui.family_best_practice\")\n                        if distro == BEST_PRACTICE_FAMILY else distro)",
        new="        distro_label = distro",
        kills=("tests/test_v0181_explain_list_grouped_by_family.py::test_best_practice_heading_is_translated_in_french",),
        reason="the CIS names are proper nouns kept verbatim, but Best practice "
               "is prose and must read Bonne pratique under --french",
    ),
    Mutation(
        id="explain-family/distro-order-not-applied",
        file="bob/explain.py",
        old="    for distro in sorted(tree, key=cis_family_sort_key):",
        new="    for distro in sorted(tree):",
        kills=("tests/test_v0181_explain_list_grouped_by_family.py::test_distros_are_ordered_ubuntu_first_best_practice_last",),
        reason="a plain sort puts Best practice first and Ubuntu last; the "
               "deliberate order is Ubuntu first (primary benchmark), Best "
               "practice last",
    ),
    Mutation(
        id="explain-family/section-subgroups-flattened",
        file="bob/explain.py",
        old="                 .setdefault(section_of[k], []).append(k))",
        new="                 .setdefault(\"\", []).append(k))",
        kills=("tests/test_v0181_explain_list_grouped_by_family.py::test_a_version_holds_typed_sub_sections",),
        reason="the refinement keeps the SSH/ClamAV/Samba typed sub-sections "
               "inside each version folder; collapsing the label loses them",
    ),
    Mutation(
        id="explain-family/subgroups-not-alphabetical",
        file="bob/explain.py",
        old="            sections = sorted(tree[distro][bench_label].items())",
        new="            sections = list(tree[distro][bench_label].items())",
        kills=("tests/test_v0181_explain_list_grouped_by_family.py::test_sub_sections_are_sorted_alphabetically_within_a_version",),
        reason="the sub-groups inside a version must read alphabetically "
               "(Auditd, Authentication Logs, Cron, …); without the sort they "
               "follow _EXPLAIN_GROUPS order instead",
    ),
    Mutation(
        id="explain-family/benchmarks-field-ignored",
        file="bob/cis_refs.py",
        old="    for lbl in entry.get(\"benchmarks\", {}):",
        new="    for lbl in ():",
        kills=("tests/test_v0181_explain_list_grouped_by_family.py::test_a_shared_control_appears_under_each_benchmark_folder",),
        reason="the per-benchmark map is what places one control under Debian "
               "12/13 and Ubuntu 24.04 as well as its primary Ubuntu 22.04; "
               "ignoring it drops the control from every folder but the primary",
    ),
    Mutation(
        id="explain-family/list-hides-cis-benchmark-url",
        file="bob/explain.py",
        old="        url = cis_benchmark_url(distro)",
        new="        url = None",
        kills=("tests/test_v0181_explain_list_grouped_by_family.py::test_the_list_shows_the_benchmark_url_under_each_cis_family",),
        reason="each CIS family folder shows the online benchmark URL at its top; "
               "dropping it hides the resource the operator was pointed to",
    ),
    Mutation(
        id="explain-family/detail-hides-other-benchmarks",
        file="bob/explain.py",
        old="    bench_rows = _benchmark_rows(norm)\n    if bench_rows:\n        print(f\"  {t('explain.ui.label_benchmarks')}:\")",
        new="    bench_rows = []\n    if bench_rows:\n        print(f\"  {t('explain.ui.label_benchmarks')}:\")",
        kills=("tests/test_v0181_explain_list_grouped_by_family.py::test_a_shared_control_lists_its_other_benchmarks_in_the_detail",),
        reason="the point of completing the collection is that --explain <key> "
               "shows the control's number in every distribution's benchmark, "
               "not only its primary Ubuntu 22.04 reference",
    ),
)
