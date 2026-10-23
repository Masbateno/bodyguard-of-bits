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
_LIVECOUNT = "tests/test_v0211_live_count_claims.py"
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
        old='            print(_indent(t("explain.ui.how_title")))\n            print(_indent(_DIVIDER_SHORT))\n            print(_how_block(phow))',
        new='            print(t("explain.ui.how_title"))\n            print(_indent(_DIVIDER_SHORT))\n            print(_how_block(phow))',
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
        old="        body_h = max(1, h - 2 - _ch.chrome_height(t, _MARKED_KEYS, w))",
        new="        body_h = max(1, h - 2)",
        kills=(f"{_CHROME}::TestNoScreenPaintsOverItsOwnBanner",),
        reason="the pre-v0.16.3 arithmetic, already one short when hints wrap",
    ),
    Mutation(
        id="tui/log-list-off-by-one-header",
        file="bob/manage_logs.py",
        old="        body_h = max(1, h - 2 - _ch.chrome_height(t, _MARKED_KEYS, w))",
        new="        body_h = max(1, h - 1 - _ch.chrome_height(t, _MARKED_KEYS, w))",
        kills=("tests/test_v0201_manage_logs_viewport.py::"
               "test_the_last_report_is_visible_after_jumping_to_the_bottom",),
        reason="the report list has two header rows (title + dir path), so "
               "reserving only one (h-1) makes the scroll window one taller than "
               "the rows drawn: the last report is reachable by cursor but painted "
               "into the footer row and overwritten — hidden behind the key bar",
    ),
    Mutation(
        id="services/socket-activated-active-service-warns",
        file="bob/checks/services.py",
        old="        if _enabled_trigger(svc_name):",
        new="        if False:",
        kills=("tests/test_v0201_active_socket_service_restarts.py::"
               "test_active_service_with_enabled_socket_is_active_enabled",),
        reason="Ubuntu 24.04+ ships ssh socket-activated (ssh.service disabled, "
               "ssh.socket enabled); an active service whose own unit is disabled "
               "but whose enabled .socket restarts it on boot must read as "
               "ACTIVE_ENABLED, else BOB warns 'active but will not restart "
               "automatically' about ssh on a default Ubuntu server — a false "
               "positive found on a real Ubuntu 26.04 host",
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
        old="226 entries (117 formal CIS",
        new="178 entries (110 formal CIS",
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
        old=f"║  BOB {_V}  │  Linux hardening auditor",
        new="║  BOB 0.13.2  │  Linux hardening auditor",
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
        old='    stamp = f"{__version__}  "',
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
        id="firewall/no-frontend-credits-despite-unprotected-netfilter",
        file="bob/checks/firewall.py",
        old="        if netfilter_protective:",
        new="        if netfilter_protective is not None:",
        kills=("tests/test_v0202_firewalld_recognized.py::TestFirewallCheck::"
               "test_no_frontend_no_netfilter_alerts_backend_neutral",),
        reason="crediting the netfilter layer merely because it was probed (not "
               "because it filters) would re-create the UFW-centric over-claim "
               "in mirror — an unprotected host read as firewalled",
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
        old="the 57 filterable + 10 always-on section names",
        new="the 55 filterable + 10 always-on section names",
        kills=(f"{_SWEEP}::test_no_counter_in_a_current_state_document_is_stale",),
        reason="the section count drifted in seven places the moment a section "
               "was added, and nothing was watching",
    ),
    Mutation(
        id="docs/module-count-stale-again",
        file="DOCUMENTS/SNAPSHOT.md",
        old="bob/checks/*.py  ← 66 check modules · Snapshot+check_xxx pattern",
        new="bob/checks/*.py  ← 64 check modules · Snapshot+check_xxx pattern",
        kills=(f"{_SWEEP}::test_no_counter_in_a_current_state_document_is_stale",),
        reason="the check-module count said 57 (conflated with the 57 sections) "
               "in four places while the on-disk count and SNAPSHOT's own table "
               "were 56 — an independent doc audit caught it; now watched",
    ),
    Mutation(
        id="docs/glance-table-value-drifts",
        file="DOCUMENTS/SNAPSHOT.md",
        old="| Score domains | 6 | `bob.domain_scores.DOMAINS` |",
        new="| Score domains | 5 | `bob.domain_scores.DOMAINS` |",
        kills=(f"{_LIVECOUNT}::test_numbers_at_a_glance_table_matches_live",),
        reason="the 'Numbers at a glance' table (value-second `| Metric | N |` "
               "layout) sat frozen at v0.14.1 on six rows because no guard could "
               "read a number that follows its noun; now watched",
    ),
    Mutation(
        id="ssh/fifo-sshd-config-blocks-open",
        file="bob/checks/ssh/_snapshot.py",
        old="            if not stat.S_ISREG(st.st_mode):",
        new="            if False:  # mutated: drop the non-regular-file guard",
        kills=("tests/test_v0212_sshd_config_no_hang.py::"
               "test_a_fifo_sshd_config_does_not_hang_and_reads_as_unreadable",),
        reason="without the S_ISREG guard, open('rb') on a FIFO sshd_config "
               "blocks forever — `mkfifo /etc/ssh/sshd_config` hung the whole "
               "audit (the samba FIFO class); found by the v0.21.1 Debian stress "
               "test, the probe now stat()s first and fails closed",
    ),
    Mutation(
        id="ssh/usr-etc-sshd-config-not-read",
        file="bob/checks/ssh/_snapshot.py",
        old="            config_path = _SSHD_CONFIG_VENDOR_PATH",
        new="            config_path = _SSHD_CONFIG_PATH  # mutated: no /usr/etc fallback",
        kills=("tests/test_v0213_sshd_config_usr_etc_fallback.py::"
               "test_reads_vendor_config_when_etc_absent",),
        reason="openSUSE Leap 16+ ships sshd_config under /usr/etc; without the "
               "fallback BOB reads only the (absent) /etc path and reports OpenSSH "
               "defaults, masking a real PermitRootLogin yes — the MEDIUM-HIGH gap "
               "from the v0.21.2 field campaign",
    ),
    Mutation(
        id="mac_policy/apparmor-off-steals-selinux-permissive",
        file="bob/checks/mac_policy.py",
        old="    if snapshot.apparmor_off_in_kernel and not snapshot.selinux_installed:",
        new="    if snapshot.apparmor_off_in_kernel:  # mutated: no SELinux deferral",
        kills=("tests/test_v0213_mac_policy_selinux_precedence.py::"
               "test_selinux_permissive_wins_over_apparmor_off",),
        reason="on a SUSE-style kernel (AppArmor compiled-in-off) where SELinux is "
               "the MAC, a permissive SELinux hit the AppArmor-off branch first and "
               "told the admin to enable AppArmor instead of `setenforce 1` — "
               "measured on real openSUSE Leap 16",
    ),
    Mutation(
        id="file_perms/doas-nopass-not-flagged",
        file="bob/checks/file_perms.py",
        old='        if fields[0] != "permit":\n            continue  # `deny` never grants\n        if "nopass" not in fields[1:]:\n            continue',
        new='        if fields[0] != "permit":\n            continue  # `deny` never grants\n        if "nopass" not in fields[1:]:\n            continue\n        if True:\n            continue  # mutated: drop every doas nopass rule',
        kills=("tests/test_v0213_doas_audit.py::"
               "test_collector_classifies_permit_deny_and_cmd",),
        reason="Alpine/OpenBSD use doas, not sudo; without parsing /etc/doas.conf a "
               "`permit nopass` (passwordless root, the NOPASSWD:ALL equivalent) is "
               "invisible — the MEDIUM gap from the v0.21.2 Alpine field pass",
    ),
    Mutation(
        id="password_policy/login-defs-usr-etc-not-read",
        file="bob/checks/password_policy.py",
        old="        for _login_defs in (_LOGIN_DEFS_PATH, _LOGIN_DEFS_VENDOR):",
        new="        for _login_defs in (_LOGIN_DEFS_PATH,):  # mutated: no /usr/etc fallback",
        kills=("tests/test_v0213_usr_etc_login_defs_sudoers.py::"
               "test_login_defs_read_from_vendor_when_etc_absent",),
        reason="openSUSE ships login.defs under /usr/etc; without the fallback BOB "
               "reads the default PASS_MAX_DAYS and misreports a stricter vendor "
               "policy",
    ),
    Mutation(
        id="file_perms/sudoers-usr-etc-vendor-not-read",
        file="bob/checks/file_perms.py",
        old="    elif path_exists(_SUDOERS_VENDOR):\n        paths.append(_SUDOERS_VENDOR)",
        new="    elif False:  # mutated: no /usr/etc sudoers fallback\n        paths.append(_SUDOERS_VENDOR)",
        kills=("tests/test_v0213_usr_etc_login_defs_sudoers.py::"
               "test_sudoers_nopasswd_read_from_vendor_when_etc_absent",),
        reason="openSUSE ships the main sudoers under /usr/etc; without the fallback "
               "a NOPASSWD:ALL rule in the vendor file is silently missed",
    ),
    Mutation(
        id="sysinfo/firewalld-stopped-reads-not-installed",
        file="bob/sysinfo.py",
        old="    firewalld_present = bool(firewalld_version) or shutil.which(\"firewall-cmd\") is not None",
        new="    firewalld_present = bool(firewalld_version)  # mutated: drop binary-presence check",
        kills=("tests/test_v0213_firewalld_banner_presence.py::"
               "test_firewalld_present_via_binary_when_version_unavailable",),
        reason="firewalld 2.1.2 (openSUSE) needs the daemon for `firewall-cmd "
               "--version`, so a stopped-but-installed firewalld read as 'not "
               "installed' in the banner without the binary-presence fallback",
    ),
    Mutation(
        id="suid/doas-flagged-unexpected",
        file="bob/checks/suid_audit.py",
        old='    "doas",',
        new='    # "doas",  # mutated: doas dropped from the known-safe SUID set',
        kills=("tests/test_v0213_suid_doas_bbsuid.py::test_doas_is_known_safe_suid",),
        reason="doas is the standard SUID sudo-replacement on Alpine/OpenBSD; "
               "without it in _KNOWN_SUID it was flagged as an unexpected SUID "
               "(false positive on every doas host)",
    ),
    Mutation(
        id="locale/ssh-restart-hint-systemd-only",
        file="bob/locales/en.json",
        old='"permit_root_login_detail": "Set PermitRootLogin no where sshd reads it first — /etc/ssh/sshd_config.d/00-hardening.conf, or the top of /etc/ssh/sshd_config when there is no sshd_config.d — then: sudo sshd -t && sudo systemctl restart ssh   # \'sshd\' on Arch/Fedora/RHEL/openSUSE; on Alpine/OpenRC use rc-service"',
        new='"permit_root_login_detail": "Set PermitRootLogin no where sshd reads it first — /etc/ssh/sshd_config.d/00-hardening.conf, or the top of /etc/ssh/sshd_config when there is no sshd_config.d — then: sudo sshd -t && sudo systemctl restart ssh   # \'sshd\' on Arch, Fedora, RHEL, openSUSE"',
        kills=("tests/test_v0213_openrc_fix_wording.py::"
               "test_every_ssh_restart_hint_is_openrc_aware_en",),
        reason="on Alpine (OpenRC) there is no systemctl; a static `systemctl "
               "restart ssh` hint must also name the rc-service form",
    ),
    Mutation(
        id="sysinfo/offline-still-calls-urlopen",
        file="bob/sysinfo.py",
        old='    if offline:\n        return ""\n\n    import ipaddress',
        new='    if False:\n        return ""\n\n    import ipaddress',
        kills=("tests/test_webhook.py::TestOfflineModeNetworkContract::"
               "test_get_public_ip_offline_skips_urllib",),
        reason="the offline short-circuit must skip every HTTP call; the guard "
               "silently no-op'd for its whole life (it patched a non-existent "
               "`sysinfo.urllib` with raising=False, so the urlopen sabotage "
               "never installed) — it would have passed with this line gone. "
               "Fixed to patch the real `urllib.request.urlopen`.",
    ),

    Mutation(
        id="docs/domain-count-stale-again",
        file="README.md",
        old="57 check sections, 6 score domains",
        new="57 check sections, 7 score domains",
        kills=(f"{_LIVECOUNT}::test_no_document_misstates_the_score_domain_count",),
        reason="v0.20.0 realigned the seven score domains onto the six display "
               "groups, but the intros and headings kept saying 7 for four "
               "releases — a one-digit count the two-digit sweep cannot watch",
    ),
    Mutation(
        id="docs/locale-key-total-stale",
        file="DOCUMENTS/SNAPSHOT.md",
        old="locale auto-detect (POSIX), 2988 keys EN/FR",
        new="locale auto-detect (POSIX), 2987 keys EN/FR",
        kills=(f"{_LIVECOUNT}::test_no_document_misstates_the_locale_key_total",),
        reason="the locale total sat at '2014 keys' against files holding 2595 "
               "because '2014' reads as a year and the sweep's noun set had no "
               "locale entry",
    ),
    Mutation(
        id="docs/profile-prose-mix-overstated",
        file="DOCUMENTS/README_DEV.md",
        old="server, desktop and container sections for 69 of them, server and desktop for 2, container only",
        new="server, desktop and container sections for 71 of them, server and desktop for 2, container only",
        kills=("tests/test_v0151_doc_prose_figures.py::TestProfileVariantCount"
               "::test_it_matches_the_real_mechanism[en]",),
        reason="the module table said 71 keys times 3 profiles while two of "
               "them had no container section at all",
    ),
    Mutation(
        id="docs/fr-elliptic-section-count-unwatched",
        file="DOCUMENTS/README_DEV_FR.md",
        old="pour chaque section (57 filtrables + 10 toujours actives)",
        new="pour chaque section (56 filtrables + 10 toujours actives)",
        kills=("tests/test_v0170_doc_counters_sweep.py"
               "::test_no_counter_in_a_current_state_document_is_stale"
               "[DOCUMENTS/README_DEV_FR.md]",),
        reason="the French flow wrote the section count without its noun, and "
               "the sweep watched only the English elliptic form",
    ),
    Mutation(
        id="docs/dated-line-hides-current-figure",
        file="tests/_doc_dating.py",
        old="    return [seg for seg in _SEPARATOR.split(line) if not DATING_MARKER.search(seg)]",
        new="    return [] if DATING_MARKER.search(line) else [line]",
        kills=("tests/test_v0251_counter_dating.py::test_a_figure_beside_a_dated_note_is_still_read",),
        reason="skipping every line that named a release left 218 keys and 61 prefixes "
               "unread beside a v0.9.0 note while the code held 226 and 62",
    ),
    Mutation(
        id="docs/explain-count-stale-beside-dated-note",
        file="DOCUMENTS/SNAPSHOT.md",
        old="`--explain` TUI + `EXPLAIN_KEYS` (226 keys, 62 prefixes) + `EXPLAIN_KEY_ALIASES`",
        new="`--explain` TUI + `EXPLAIN_KEYS` (226 keys, 61 prefixes) + `EXPLAIN_KEY_ALIASES`",
        kills=(f"{_SWEEP}::test_no_counter_in_a_current_state_document_is_stale[DOCUMENTS/SNAPSHOT.md]",),
        reason="a stale prefix count on a SNAPSHOT row that also cites a release "
               "was invisible to the sweep for several releases",
    ),
    Mutation(
        id="locale/fr-key-order-drifts",
        file="bob/locales/fr.json",
        old='    "clean": "Votre configuration est saine. Aucune action requise.",\n    "warnings": "Configuration globalement saine pour ce type de système. Quelques améliorations sont recommandées pour renforcer la robustesse.",\n',
        new='    "warnings": "Configuration globalement saine pour ce type de système. Quelques améliorations sont recommandées pour renforcer la robustesse.",\n    "clean": "Votre configuration est saine. Aucune action requise.",\n',
        kills=("tests/test_v0251_locale_key_order.py::test_fr_keys_follow_the_en_order",),
        reason="a French key appended out of the English order breaks the "
               "line-by-line comparison 0.25.0 restored, and no guard said so",
    ),
    Mutation(
        id="ignore/legacy-name-called-dead",
        file="bob/__main__.py",
        old="        _covered = _legacy_ignore_coverage(config.ignore_key, _known)\n",
        new="        _covered = []\n",
        kills=("tests/test_v0251_ignore_legacy_key.py::test_a_former_name_is_reported_as_honoured",),
        reason="--ignore told the operator a former key name would never suppress "
               "anything while the engine went on honouring it",
    ),
    Mutation(
        id="locale/cap-note-claims-the-headline",
        file="bob/locales/en.json",
        old='"cap_note": "Firewall & Network domain capped at {max}/10 (firewall inactive)",',
        new='"cap_note": "Score capped at {max} (firewall inactive)",',
        kills=("tests/test_v0251_cap_note_names_the_domain.py::test_the_note_names_the_domain_in_both_languages",),
        reason="the breakdown said the score was capped at 3 above a summary "
               "showing seven out of ten for the same audit",
    ),
    Mutation(
        id="locale/cron-webhook-advice-misses-the-job",
        file="bob/locales/en.json",
        old="Add an address, or give the job a webhook: append --webhook URL to the bob line of its script (/usr/local/bin/bob-<name>). sudo bob --webhook=URL would save the URL in your own configuration, which this job does not read.",
        new="Add an address, or set a webhook with bob --webhook=URL (as root).",
        kills=("tests/test_v0251_cron_webhook_advice.py::test_the_advice_points_at_the_job_script_not_at_sudo_bob_webhook",),
        reason="the wizard told a sudo operator to save a webhook in a configuration "
               "the scheduled root job never reads",
    ),
    Mutation(
        id="cron/saved-profile-not-preselected",
        file="bob/cron/_options.py",
        old='    profile = getattr(config, "profile", "") or saved or "server"',
        new='    profile = getattr(config, "profile", "") or "server"',
        kills=("tests/test_v0161_cron_audit_options.py::TestSavedProfileIsPreselected::test_the_saved_profile_is_used_when_no_flag_is_given",),
        reason="an operator who had saved desktop saw the cron profile screen "
               "open on server and scheduled a stricter audit than their own",
    ),
    Mutation(
        id="cron/script-calls-an-assumed-bob",
        file="bob/cron/_io.py",
        old='        if running.name == "bob" and running.exists():\n            return str(running.absolute()), True\n',
        new='        pass\n',
        kills=("tests/test_v0251_cron_binary_path.py::test_the_running_bob_is_used_when_path_has_none",),
        reason="a job installed by the launcher's full path called a /usr/local/bin/bob "
               "that did not exist and failed on every scheduled run",
    ),
    Mutation(
        id="sysinfo/doas-user-ignored",
        file="bob/sysinfo.py",
        old='    for var in ("SUDO_USER", "DOAS_USER"):',
        new='    for var in ("SUDO_USER",):',
        kills=("tests/test_v0251_doas_invoking_user.py::test_doas_user_resolves_the_home",),
        reason="run through doas, BOB kept the operator's settings, ignore list "
               "and history in root's home and skipped the sudo-path link",
    ),
    Mutation(
        id="webhook/slack-hides-the-ceiling",
        file="bob/webhook.py",
        old="    score_display = score_out_of_ten(engine)\n",
        new='    score_display = f"{engine.score}/10"\n',
        kills=("tests/test_v0251_slack_and_watch_bound.py::test_slack_shows_the_ceiling",),
        reason="a Slack channel read a plain eight out of ten for a run that could "
               "not read part of the host",
    ),
    Mutation(
        id="help/verbose-undersells",
        file="bob/locales/en.json",
        old="\"verbose\": \"Each finding's detail, command, CIS ref; the listening ports\",",
        new="\"verbose\": \"Show detailed port exposure for each service\",",
        kills=("tests/test_v0251_verbose_help.py::test_the_help_names_the_per_finding_detail",),
        reason="the help described -v as port detail while it adds the detail, "
               "command and CIS reference of every finding",
    ),
    Mutation(
        id="explain/container-only-prose-hidden",
        file="bob/explain.py",
        old="        for _profile, _pwhy, _phow in _extra_profile_prose(norm, t):\n            print(_profile_header(_profile))\n",
        new="        for _profile, _pwhy, _phow in []:\n            print(_profile_header(_profile))\n",
        kills=("tests/test_v0151_doc_prose_figures.py::TestProfileVariantCount::test_container_only_prose_is_rendered",),
        reason="two container explanations were written and translated and never "
               "shown, because only the server prose decided the layout",
    ),
    Mutation(
        id="guards/eager-snapshot-guard-blind-to-digits",
        file="tests/test_v0141_robustness.py",
        old="""            m = re.match(r'\\s*_sec\\(\\s*"([a-z0-9_]+)",\\s*([a-z_]\\w*)\\s*[,)]', line)""",
        new="""            m = re.match(r'\\s*_sec\\(\\s*"([a-z_]+)",\\s*([a-z_]\\w*)\\s*[,)]', line)""",
        kills=("tests/test_v0141_robustness.py::TestSectionFaultBarrier::test_no_sec_call_site_collects_its_snapshot_eagerly",),
        reason="the eager-snapshot guard never examined ipv6 or fail2ban because "
               "its section pattern read no digit",
    ),
    Mutation(
        id="locale/autodesktop-notice-overstates",
        file="bob/locales/en.json",
        old="(it reports a missing backup, auditd rules, AppArmor without an enforcing profile and SSH password logins as INFO, among others).",
        new="(relaxes backup/auditd/mac_policy).",
        kills=("tests/test_v0251_autodesktop_notice.py::test_every_finding_named_is_downgraded_by_desktop_conf",),
        reason="the notice said the desktop profile relaxed the MAC policy when it "
               "relaxes one of its seven deductions",
    ),
    Mutation(
        id="raspberry_pi/unreadable-passwd-reads-as-no-account",
        file="bob/checks/raspberry_pi.py",
        old="        # same \"not established\" as an unreadable shadow (unknown ≠ clean).\n        return False, False",
        new="        # same \"not established\" as an unreadable shadow (unknown ≠ clean).\n        return False, True",
        kills=("tests/test_v0170_raspberry_pi.py::test_an_unreadable_passwd_is_not_established",),
        reason="an /etc/passwd BOB could not read was reported as a board with no "
               "default account, a clean verdict from a file never seen",
    ),
    Mutation(
        id="python/310-deprecation-unannounced",
        file="bob/_python_support.py",
        old='    (3, 10): ("2027-04-01", "3.11"),   # EoL 2026-10-01 + 6 months',
        new='',
        kills=("tests/test_v0251_python310_deprecation.py::test_only_310_is_deprecated",),
        reason="Python 3.10 passed its end of life with no release announcing the "
               "deprecation the v0.7.0 ladder promised",
    ),
    Mutation(
        id="cron/install-without-cron-d-not-refused",
        file="bob/cron/_install.py",
        old="    if not CRON_DIR.is_dir() and not use_crontab():\n        print(f\"  ✖ {with_privilege(t('install_cron.no_cron_d', path=str(CRON_DIR)))}\", file=_sys.stderr)\n        return 1\n",
        new="",
        kills=("tests/test_v0251_cron_on_busybox_alpine.py::test_no_cron_d_is_refused_before_any_question",),
        reason="on Alpine the wizard asked every question, wrote the script and then "
               "failed on an /etc/cron.d BusyBox crond never reads",
    ),
    Mutation(
        id="privilege/finding-prose-keeps-sudo",
        file="bob/scoring.py",
        old="        message, detail, note = with_privilege(message), with_privilege(detail), with_privilege(note)\n",
        new="",
        kills=("tests/test_v0251_explain_host_prefix.py::test_finding_prose_names_doas_on_a_doas_only_host",),
        reason="on Alpine a finding's detail kept telling the operator to run sudo "
               "chmod while its command said doas",
    ),
    Mutation(
        id="privilege/every-text-asks-the-host",
        file="bob/_privilege.py",
        old="    if not cmd or not _SUDO_WORD.search(cmd):\n        return cmd\n",
        new="    if not cmd:\n        return cmd\n",
        kills=("tests/test_v0251_explain_host_prefix.py::test_a_text_without_sudo_never_asks_the_host",),
        reason="every finding text resolved the host's prefix, which crashes inside "
               "the plugin sandbox where os is restricted",
    ),
    Mutation(
        id="mac_policy/unloaded-profiles-read-as-missing",
        file="bob/checks/mac_policy.py",
        old="        if snapshot.apparmor_profiles_on_disk and snapshot.apparmor_service_state != \"active\":",
        new="        if False:",
        kills=("tests/test_v0251_apparmor_profiles_not_loaded.py::test_unloaded_profiles_ask_for_the_service",),
        reason="on Alpine the profile files sat in /etc/apparmor.d while the service "
               "was stopped, and BOB told the operator to install packages already installed",
    ),
    Mutation(
        id="packages/apk-apparmor-profiles-unknown",
        file="bob/checks/_run.py",
        old="\"apparmor-profiles\": {\"apt\": \"apparmor-profiles apparmor-profiles-extra\", \"apk\": \"apparmor-profiles\"},",
        new="\"apparmor-profiles\": {\"apt\": \"apparmor-profiles apparmor-profiles-extra\"},",
        kills=("tests/test_v0251_apparmor_profiles_not_loaded.py::test_the_apk_package_name_is_known",),
        reason="apk ships apparmor-profiles under that name yet BOB said it did not know "
               "the package on Alpine",
    ),
    Mutation(
        id="firewalld-stopped/read-as-absent",
        file="bob/checks/firewall.py",
        old="        _fwd_installed = firewalld is not None and firewalld.installed",
        new="        _fwd_installed = False",
        kills=("tests/test_v0251_firewalld_stopped.py::TestTheAlert::test_stopped_firewalld_is_named_installed",
               "tests/test_v0251_firewalld_stopped.py::TestTheAlert::test_the_fix_does_not_install_what_is_there"),
        reason="on openSUSE with firewalld stopped the alert said firewalld was not installed "
               "and the fix began by installing it",
    ),
    Mutation(
        id="firewalld-stopped/collection-forgets-the-client",
        file="bob/checks/_firewalld.py",
        old="            return cls(active=False, installed=True, readable=False)\n        return cls(active=False, installed=True, readable=True)",
        new="            return cls(active=False, installed=True, readable=False)\n        return cls(active=False, readable=True)",
        kills=("tests/test_v0251_firewalld_stopped.py::TestCollection::test_a_stopped_daemon_with_its_client_is_installed",),
        reason="a stopped firewalld whose client answers not running must still be "
               "collected as installed",
    ),
    Mutation(
        id="firewalld-stopped/nft-remedy-names-a-missing-file",
        file="bob/checks/iptables_nftables.py",
        old="        elif firewalld is not None and firewalld.installed:",
        new="        elif False:",
        kills=("tests/test_v0251_firewalld_stopped.py::TestTheNftablesRemedy::test_a_stopped_firewalld_is_the_remedy",),
        reason="the nftables finding told an openSUSE host to load /etc/nftables.conf, "
               "a file it does not have, while firewalld sat stopped",
    ),
    Mutation(
        id="docker-firewalld/proxy-port-follows-the-zone",
        file="bob/checks/ports.py",
        old='if lport.process == "docker-proxy"',
        new='if lport.process == "docker-proxy-never"',
        kills=("tests/test_v0251_docker_beside_firewalld.py::test_a_docker_proxy_port_is_not_said_to_follow_the_zone",),
        reason="on Fedora a port docker-proxy held answered from the LAN while BOB said "
               "the firewalld zone governed it",
    ),
    Mutation(
        id="docker-firewalld/no-port-read-as-no-container",
        file="bob/locales/en.json",
        old='"no_containers": "No running Docker container publishes a port"',
        new='"no_containers": "No running Docker containers detected"',
        kills=("tests/test_v0251_docker_beside_firewalld.py::test_no_published_port_is_not_no_container",),
        reason="two containers ran with no published port and BOB said no container "
               "was running",
    ),
    Mutation(
        id="docker-firewalld/three-options-two-listed",
        file="bob/locales/fr.json",
        old="pas une correction simple — deux options :",
        new="pas une correction simple — trois options :",
        kills=("tests/test_v0251_docker_beside_firewalld.py::test_the_options_announced_are_the_options_listed",),
        reason="the detail announced three options and listed two, in both languages "
               "since the finding was written",
    ),
    Mutation(
        id="docker-firewalld/bypass-says-ufw",
        file="bob/locales/en.json",
        old='"iptables_bypass": "Docker may bypass the host firewall (UFW, firewalld)',
        new='"iptables_bypass": "Docker may bypass UFW rules (UFW, firewalld)',
        kills=("tests/test_v0251_docker_beside_firewalld.py::test_the_bypass_names_the_host_firewall",),
        reason="on a firewalld host without ufw the warning said Docker bypassed UFW rules",
    ),
    Mutation(
        id="cron/path-bob-before-the-running-one",
        file="bob/cron/_io.py",
        old='    import shutil\n    import sys\n    if sys.argv and sys.argv[0]:',
        new='    import shutil\n    import sys\n    if shutil.which("bob"):\n        return shutil.which("bob"), True\n    if sys.argv and sys.argv[0]:',
        kills=("tests/test_v0251_cron_binary_path.py::test_the_running_bob_wins_over_another_on_path",),
        reason="another bob on root's PATH would run the options the installing version "
               "wrote into the script",
    ),
    Mutation(
        id="docker-firewalld/docker-user-example-cuts-the-containers",
        file="bob/locales/fr.json",
        old='   sudo iptables -I DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN\\n   Elles arrêtent',
        new='   sudo iptables -A DOCKER-USER -j DROP\\n   Elles arrêtent',
        kills=("tests/test_v0251_docker_beside_firewalld.py::test_the_docker_user_example_keeps_the_containers_network",),
        reason="the former DOCKER-USER example with a bare DROP cut the containers' DNS "
               "and internet access, measured on Ubuntu with Docker 29.1.3",
    ),
    Mutation(
        id="no-firewall/missing-left-uncapped",
        file="bob/checks/firewall.py",
        old='        result.set_cap(maximum=3, reason=_t(_missing_key, policies=_policies),\n                       key="prerequisites.firewall_missing")\n',
        new='',
        kills=("tests/test_v0260_no_firewall_is_capped.py::TestNoFirewall::test_missing_caps_the_domain_like_inactive",
               "tests/test_v0260_no_firewall_is_capped.py::TestNoFirewall::test_the_measured_host_no_longer_scores_seven"),
        reason="an openSUSE host with no firewall running scored 7/10 in Firewall and "
               "Network while an inactive UFW was capped at 3",
    ),
    Mutation(
        id="no-firewall/silent-firewalld-read-as-absent",
        file="bob/checks/firewall.py",
        old="        if firewalld is not None and firewalld.installed and not firewalld.readable:",
        new="        if False:",
        kills=("tests/test_v0260_no_firewall_is_capped.py::TestAnUnknownFirewalld::test_no_alert_no_cap_a_visibility_info",),
        reason="a firewall-cmd that answered nothing was read as a stopped firewalld "
               "and, with the cap, scored on an unknown",
    ),
    Mutation(
        id="no-firewall/silent-firewalld-base-chains-judged",
        file="bob/checks/iptables_nftables.py",
        old='    if firewalld is not None and getattr(firewalld, "installed", False) \\\n            and not getattr(firewalld, "readable", True):',
        new='    if False:',
        kills=("tests/test_v0260_no_firewall_is_capped.py::TestAnUnknownFirewalld::test_the_base_chains_are_not_judged",),
        reason="a running firewalld keeps the base policy at ACCEPT, so its base chains "
               "say nothing when it cannot be queried",
    ),
    Mutation(
        id="no-firewall/silent-firewalld-gets-the-high-floor",
        file="bob/scoring.py",
        old='        firewall_inactive=not fw_active and not any(\n            f.key == "firewall.firewalld_unreadable" for f in engine.findings),',
        new='        firewall_inactive=not fw_active,',
        kills=("tests/test_v0260_no_firewall_is_capped.py::TestAnUnknownFirewalld::test_no_high_floor_on_an_unknown",),
        reason="an unknown firewall state raised the risk level to HIGH as if no "
               "firewall were running",
    ),
    Mutation(
        id="raw-accept/bypass-counted-with-ufw-off",
        file="bob/checks/firewall_stack.py",
        old="    for rule in (snapshot.input_raw_accepts if ufw_active else []):",
        new="    for rule in snapshot.input_raw_accepts:",
        kills=("tests/test_v0260_raw_accept_reach.py::test_with_ufw_off_nothing_is_a_bypass",),
        reason="with ufw off on k3s, kube-router's mark rule cost 2 points as a UFW "
               "bypass on top of the iptables section's 3",
    ),
    Mutation(
        id="raw-accept/loopback-read-as-accept-all",
        file="bob/checks/firewall_stack.py",
        old='    if _LOOPBACK.search(rule):\n        return "loopback"\n',
        new='',
        kills=("tests/test_v0260_raw_accept_reach.py::test_what_each_rule_can_let_in",
               "tests/test_v0260_raw_accept_reach.py::test_with_ufw_on_only_what_admits_is_deducted"),
        reason="iptables -L -n printed -i lo -j ACCEPT exactly as an accept-all and it "
               "was deducted as a bypass",
    ),
    Mutation(
        id="raw-accept/mark-rule-deducted",
        file="bob/checks/firewall_stack.py",
        old='    if _MARK_ONLY.match(rule):\n',
        new='    if False:\n',
        kills=("tests/test_v0260_raw_accept_reach.py::test_what_each_rule_can_let_in",
               "tests/test_v0260_raw_accept_reach.py::test_with_ufw_on_only_what_admits_is_deducted"),
        reason="a mark rule opened nothing past an active ufw yet cost the same 2 "
               "points as a port rule that opened one",
    ),
    Mutation(
        id="raw-accept/l-form-read-again",
        file="bob/checks/firewall_stack.py",
        old='        input_raw   = _parse_raw_accepts_s(input_s)',
        new='        input_raw   = _parse_raw_accepts(input_out)',
        kills=("tests/test_v0260_raw_accept_reach.py::test_collection_reads_the_s_form",),
        reason="the -L form drops the interface, so the loopback rule could not be "
               "told from an accept-all",
    ),
    Mutation(
        id="python/310-date-in-english-in-french",
        file="bob/_python_support.py",
        old='    if lang != "fr":\n        return iso\n',
        new='    return iso\n',
        kills=("tests/test_v0251_python310_deprecation.py::test_the_french_message_writes_the_date_in_french",),
        reason="the French deprecation notice read jusqu'à 2027-04-01, the English "
               "date form inside French text",
    ),
    Mutation(
        id="no-ufw/rules-analysed-without-ufw",
        file="bob/runner.py",
        old='    if fw_status.active:\n        emit_section("firewall_rules")',
        new='    if True:\n        emit_section("firewall_rules")',
        kills=("tests/test_v0260_no_ufw_no_ufw_findings.py::test_ufw_rules_are_analysed_only_while_ufw_is_active",),
        reason="openSUSE and Fedora without ufw were told no duplicate UFW rules were "
               "detected under a UFW RULES ANALYSIS header",
    ),
    Mutation(
        id="no-ufw/ufw-logs-read-without-ufw",
        file="bob/runner.py",
        old='    if fw_status.installed:\n        if not config.quiet:\n            print_section(t("sections.logs"))',
        new='    if True:\n        if not config.quiet:\n            print_section(t("sections.logs"))',
        kills=("tests/test_v0260_no_ufw_no_ufw_findings.py::test_the_ufw_log_section_needs_ufw_installed",),
        reason="hosts without ufw were credited with no UFW BLOCK events in logs UFW "
               "never wrote",
    ),
    Mutation(
        id="no-ufw/empty-log-credited-with-ufw-off",
        file="bob/checks/logs.py",
        old="        if not ufw_active:\n            # v0.26.0 — UFW off blocks nothing",
        new="        if False:\n            # v0.26.0 — UFW off blocks nothing",
        kills=("tests/test_v0260_no_ufw_no_ufw_findings.py::test_an_empty_log_with_ufw_off_is_not_credited",),
        reason="with ufw off nothing is blocked, yet the empty log was an OK as if the "
               "traffic had been quiet",
    ),
    Mutation(
        id="no-ufw/nftables-parallel-without-ufw",
        file="bob/checks/firewall_stack.py",
        old="    if snapshot.nftables_active and ufw_active:",
        new="    if snapshot.nftables_active:",
        kills=("tests/test_v0260_no_ufw_no_ufw_findings.py::test_nftables_beside_an_inactive_ufw_is_not_parallel",),
        reason="with ufw off the nftables ruleset is the firewall, not a ruleset in "
               "parallel with UFW",
    ),
    Mutation(
        id="no-ufw/system-port-names-ufw",
        file="bob/locales/en.json",
        old='legitimate OS service, no firewall rule needed): {port} ({service})',
        new='legitimate OS service, no UFW rule needed): {port} ({service})',
        kills=("tests/test_v0260_no_ufw_no_ufw_findings.py::test_port_and_ipv6_lines_do_not_name_ufw",),
        reason="firewalld hosts were told their system ports needed no UFW rule",
    ),
    Mutation(
        id="no-firewall/stderr-not-running-read-as-unreadable",
        file="bob/checks/_firewalld.py",
        old='        if "not running" in (state.stderr or "").lower() or state.code == 252:',
        new='        if False:',
        kills=("tests/test_v0260_no_firewall_is_capped.py::test_stopped_firewalld_2_1_writes_not_running_on_stderr",),
        reason="firewalld 2.1.2 writes not running on stderr and exits 252; read as "
               "unreadable, a stopped firewalld lost its no-firewall alert and cap",
    ),
    Mutation(
        id="no-firewall/cap-line-contradicts-the-alert",
        file="bob/checks/firewall.py",
        old='        result.set_cap(maximum=3, reason=_t(_missing_key, policies=_policies),',
        new='        result.set_cap(maximum=3, reason=_t("prerequisites.firewall_missing"),',
        kills=("tests/test_v0260_no_firewall_is_capped.py::test_the_cap_line_says_what_the_alert_says",),
        reason="on openSUSE the breakdown said neither UFW nor firewalld is installed "
               "under an alert saying firewalld is installed but stopped",
    ),
    Mutation(
        id="docker-backend/nftables-read-as-iptables",
        file="bob/checks/docker.py",
        old='        return "nftables" if driver.startswith("nftables") else "iptables"',
        new='        return "iptables"',
        kills=("tests/test_v0260_docker_firewall_backend.py::test_the_backend_comes_from_docker_info",),
        reason="docker info said nftables+firewalld on openSUSE and BOB still advised "
               "the DOCKER-USER chain that backend does not have",
    ),
    Mutation(
        id="docker-backend/docker-user-offered-to-nftables",
        file="bob/checks/docker.py",
        old='        result.info(message=_t("docker.iptables_bypass_detail3_nftables"\n                               if snapshot.firewall_backend == "nftables"\n                               else "docker.iptables_bypass_detail3"),',
        new='        result.info(message=_t("docker.iptables_bypass_detail3"),',
        kills=("tests/test_v0260_docker_firewall_backend.py::test_nftables_backend_gets_no_docker_user_advice",),
        reason="with Docker's nftables backend there is no DOCKER-USER chain, yet the "
               "second option told the operator to filter there",
    ),
    Mutation(
        id="docker-backend/alert-says-iptables-under-nftables",
        file="bob/checks/docker.py",
        old="""f"({_t('docker.exposed_bypass_nftables' if snapshot.firewall_backend == 'nftables' else 'docker.exposed_bypass_ufw')})\"""",
        new="""f"({_t('docker.exposed_bypass_ufw')})\"""",
        kills=("tests/test_v0260_docker_firewall_backend.py::test_nftables_backend_gets_no_docker_user_advice",),
        reason="the published-port alert said via iptables on a host whose Docker "
               "writes its rules with nftables",
    ),
    Mutation(
        id="docker-backend/disabled-says-ufw",
        file="bob/locales/en.json",
        old="it does not write most of its IPv4 firewall rules, so its published ports are left to the host firewall",
        new="UFW rules apply normally, so its published ports are left to the host firewall",
        kills=("tests/test_v0260_docker_firewall_backend.py::test_the_texts_name_no_ufw_and_no_iptables_where_wrong",),
        reason="on a firewalld host with iptables disabled BOB said UFW rules apply "
               "normally",
    ),
    Mutation(
        id="docker-backend/port-line-ignores-rules-off",
        file="bob/checks/ports.py",
        old='                                   if lport.process == "docker-proxy" and not docker_rules_off',
        new='                                   if lport.process == "docker-proxy"',
        kills=("tests/test_v0260_docker_firewall_backend.py::test_with_docker_rules_off_the_port_follows_the_zone_again",),
        reason="with iptables false the zone refused the published port from the LAN, "
               "yet the port line said the zone does not filter it",
    ),
    Mutation(
        id="firewalld-sources/cumulated-share-unsaid",
        file="bob/checks/_firewalld.py",
        old='        if (len(names) < 2 and not entry["taken"]) or not entry["open"]:\n            continue',
        new="        if True:\n            continue",
        kills=("tests/test_v0260_firewalld_sources_cumulated.py::test_the_measured_pair_is_added_up",),
        reason="two ACCEPT zones on openSUSE let every packet in from 37.5 percent of "
               "IPv4 and nothing added them up",
    ),
    Mutation(
        id="firewalld-sources/private-counted-public",
        file="bob/checks/_firewalld.py",
        old="    return total - sum(_overlap(u, p) for u in union for p in not_public), public_space",
        new="    return total, public_space",
        kills=("tests/test_v0260_firewalld_sources_cumulated.py::test_non_public_ranges_are_not_counted_public",),
        reason="a share of public addresses that counts private ranges as public "
               "overstates what the internet reaches",
    ),
    Mutation(
        id="crontab/cron-update-forgotten",
        file="bob/cron/_crontab.py",
        old='        os.write(fd, b"root\\n")',
        new='        pass',
        kills=("tests/test_v0260_cron_in_root_crontab.py::test_the_job_goes_into_roots_crontab_and_nothing_else_moves",),
        reason="BusyBox crond did not pick up an edit of root's crontab in three "
               "minutes until root was written to cron.update",
    ),
    Mutation(
        id="crontab/block-duplicated-not-replaced",
        file="bob/cron/_crontab.py",
        old="    if any(s == slug for s, _ in blocks()):\n        text = _BLOCK_RE.sub(",
        new="    if False:\n        text = _BLOCK_RE.sub(",
        kills=("tests/test_v0260_cron_in_root_crontab.py::test_jobs_are_listed_edited_and_removed_one_by_one",),
        reason="rewriting a job must replace its block, or root's crontab runs the "
               "old and the new schedule both",
    ),
    Mutation(
        id="crontab/removal-takes-the-rest",
        file="bob/cron/_crontab.py",
        old="    _write(text[:start] + text[m.end():])",
        new="    _write(text[:start])",
        kills=("tests/test_v0260_cron_in_root_crontab.py::test_jobs_are_listed_edited_and_removed_one_by_one",),
        reason="deleting a BOB job must leave the lines the system put in root's "
               "crontab, the periodic tasks included",
    ),
    Mutation(
        id="crontab/email-edit-restores-old-schedule",
        file="bob/cron/_io.py",
        old="    schedule_expr, script = current if current else (entry.schedule_expr, str(entry.script_path))",
        new="    schedule_expr, script = (entry.schedule_expr, str(entry.script_path))",
        kills=("tests/test_v0260_cron_in_root_crontab.py::test_jobs_are_listed_edited_and_removed_one_by_one",),
        reason="changing the address after the schedule put the old schedule back "
               "into the block",
    ),
    Mutation(
        id="crontab/name-writes-a-cron-line",
        file="bob/cron/_io.py",
        old='    raw_name = re.sub(r"[\\x00-\\x1f\\x7f]+", " ", raw_name).strip()',
        new='    raw_name = raw_name',
        kills=("tests/test_v0260_cron_in_root_crontab.py::test_a_name_cannot_write_a_cron_line",),
        reason="a newline in the job name would write a cron line of its own into "
               "root's whole crontab",
    ),
    Mutation(
        id="crontab/script-needs-bash",
        file="bob/cron/_io.py",
        old='        "#!/bin/sh\\n"\n        f"# BOB script',
        new='        "#!/bin/bash\\n"\n        f"# BOB script',
        kills=("tests/test_v0260_cron_in_root_crontab.py::test_the_script_is_posix_sh",),
        reason="Alpine ships no bash, so a bash script in root's crontab fails on "
               "every run",
    ),
    Mutation(
        id="crontab/crontab-host-still-refused",
        file="bob/cron/_install.py",
        old="    if not CRON_DIR.is_dir() and not use_crontab():",
        new="    if not CRON_DIR.is_dir():",
        kills=("tests/test_v0260_cron_in_root_crontab.py::test_the_installer_no_longer_refuses_a_crontab_host",),
        reason="0.25.1 refused --install-cron on Alpine; with root's crontab available "
               "the job goes there",
    ),
    Mutation(
        id="crontab/no-job-hint-says-sudo",
        file="bob/cron/_manage.py",
        old="cmd=output.command(with_privilege('sudo bob --install-cron'))",
        new="cmd=output.command('sudo bob --install-cron')",
        kills=("tests/test_v0260_cron_in_root_crontab.py::test_the_no_job_hint_uses_the_hosts_privilege_word",),
        reason="on Alpine, which has doas and no sudo, the empty job list said run "
               "sudo bob --install-cron",
    ),
    Mutation(
        id="awall/active-ruleset-unnamed",
        file="bob/checks/firewall.py",
        old="if awall is not None and awall.enabled:",
        new="if False:",
        kills=("tests/test_v0260_awall_named.py::TestAwallActive::test_the_ruleset_is_credited_to_awall",),
        reason="on Alpine with an awall policy enabled, the report said no firewall "
               "front-end was active and never named awall",
    ),
    Mutation(
        id="awall/unread-list-claims-no-policy",
        file="bob/checks/firewall.py",
        old="if _awall_here and awall.readable",
        new="if _awall_here",
        kills=("tests/test_v0260_awall_named.py::TestAwallIdle::test_an_unread_list_does_not_claim_no_policy",),
        reason="a failed awall list was reported as awall having no policy enabled",
    ),
    Mutation(
        id="awall/idle-prints-apk-add-ufw",
        file="bob/checks/firewall.py",
        old='            _cmd, _detail = None, _t("prerequisites.firewall_missing_awall_not_loaded_detail" if _not_loaded',
        new='            _detail = _t("prerequisites.firewall_missing_awall_not_loaded_detail" if _not_loaded',
        kills=("tests/test_v0260_awall_named.py::TestAwallIdle::test_named_capped_and_no_ufw_to_install",),
        reason="with awall installed and no policy enabled, the fix said install ufw "
               "beside it",
    ),
    Mutation(
        id="firewall-stack/forward-bypass-without-ufw",
        file="bob/checks/firewall_stack.py",
        old="if snapshot.forward_raw_accepts and ufw_active:",
        new="if snapshot.forward_raw_accepts:",
        kills=("tests/test_v0260_awall_named.py::TestAwallActive::test_its_forward_rules_are_not_a_ufw_bypass",),
        reason="on Alpine, awall's own FORWARD rules cost 1 each as raw ACCEPT rules "
               "bypassing a UFW the host does not have",
    ),
    Mutation(
        id="awall/disabled-policies-read-as-enabled",
        file="bob/checks/_awall.py",
        old='        enabled = tuple([p[0] for p in rows if p[1] == "enabled"] +',
        new='        enabled = tuple([p[0] for p in rows] +',
        kills=("tests/test_v0260_awall_named.py::TestReadingAwall::test_enabled_policies_by_name",),
        reason="a disabled awall policy was named as filtering the host",
    ),
    Mutation(
        id="awall/failed-list-read-as-empty",
        file="bob/checks/_awall.py",
        old="return cls(installed=True, readable=False)",
        new="return cls(installed=True)",
        kills=("tests/test_v0260_awall_named.py::TestReadingAwall::test_a_failed_list_is_unknown_not_empty",),
        reason="a failed awall list became an awall with no policy enabled",
    ),
    Mutation(
        id="awall/banner-unread-says-no-policy",
        file="bob/sysinfo.py",
        old='        return "?"\n    return ", ".join(st.enabled) if st.enabled else "-"',
        new='        return "-"\n    return ", ".join(st.enabled) if st.enabled else "-"',
        kills=("tests/test_v0260_awall_named.py::TestTheBanner::test_each_state",),
        reason="the banner said no awall policy was enabled when awall list had failed",
    ),
    Mutation(
        id="awall/runner-forgets-awall",
        file="bob/runner.py",
        old="        awall=_awall,\n",
        new="",
        kills=("tests/test_v0260_awall_named.py::test_the_runner_hands_awall_to_the_firewall_check",),
        reason="the firewall check never learns awall is there, and the host reads "
               "as having no front-end",
    ),
    Mutation(
        id="f2b-nojournal/count-never-read",
        file="bob/checks/fail2ban.py",
        old="            snap.ssh_jail_counted = _parse_total_failed(jail_status)\n",
        new="",
        kills=("tests/test_v0260_fail2ban_without_journal.py::test_the_collection_reads_count_and_routing",),
        reason="on Alpine the jail counted two failed logins and BOB never read the count",
    ),
    Mutation(
        id="f2b-nojournal/count-does-not-credit",
        file="bob/checks/fail2ban.py",
        old="and snapshot.ssh_jail_fed is None and snapshot.ssh_jail_counted:",
        new="and snapshot.ssh_jail_fed is None and False:",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestTheJailsCount::test_failures_counted_credit_the_jail",),
        reason="a jail that counted failures in its file was still reported unverified",
    ),
    Mutation(
        id="f2b-nojournal/unverified-blames-the-daemon",
        file="bob/checks/fail2ban.py",
        old="if snapshot.syslog_active and not snapshot.journal_available",
        new="if False",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestTheJailsCount::test_none_counted_stays_unverified_and_says_why",),
        reason="with busybox syslogd running, BOB said whether a syslog daemon writes "
               "the file could not be established",
    ),
    Mutation(
        id="f2b-nojournal/routed-elsewhere-unsaid",
        file="bob/checks/fail2ban.py",
        old="        if snapshot.ssh_jail_routed_to:\n",
        new="        if False:\n",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestRoutedElsewhere::test_said_with_the_file_sshd_goes_to_and_a_fix",),
        reason="Alpine's packaged jail on /var/log/messages under syslog-ng, which sends "
               "auth to /var/log/auth.log, was only 'not verified'",
    ),
    Mutation(
        id="f2b-nojournal/routed-elsewhere-not-collected",
        file="bob/checks/fail2ban.py",
        old="                    if snap.ssh_jail_routed_to:\n                        snap.ssh_jail_fed = False\n",
        new="",
        kills=("tests/test_v0260_fail2ban_without_journal.py::test_the_collection_reads_count_and_routing",),
        reason="the session logged elsewhere did not make the jail's file unfed, and an "
               "old count could credit a blind jail",
    ),
    Mutation(
        id="f2b-nojournal/session-in-the-jail-file-ignored",
        file="bob/checks/fail2ban.py",
        old='    if any(_tail_holds(f, needles) is not False for f in files):\n        return ""\n',
        new="",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestWhereTheSessionsLineIs::test_in_the_jails_file",),
        reason="a jail whose file holds the session's line was called blind because "
               "another file holds it too",
    ),
    Mutation(
        id="f2b-nojournal/session-before-the-daemon-counted",
        file="bob/checks/fail2ban.py",
        old="if start is not None and start > max(daemons)",
        new="if start is not None",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestTheNewestSession::test_only_sessions_older_than_the_daemon",),
        reason="a session opened before the syslog daemon started was read as routed by "
               "the routing in force now",
    ),
    Mutation(
        id="f2b-nojournal/syslog-ng-main-not-a-daemon",
        file="bob/checks/fail2ban.py",
        old='"syslog-ng-main", ',
        new="",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestTheNewestSession::test_the_newest_priv_session_after_the_daemon",),
        reason="on Alpine, syslog-ng 4 runs as syslog-ng-main and no session was dated",
    ),
    Mutation(
        id="f2b-nojournal/any-sshd-process-is-a-session",
        file="bob/checks/fail2ban.py",
        old='if argv0.endswith(b"[priv]"):',
        new="if True:",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestTheNewestSession::test_the_newest_priv_session_after_the_daemon",),
        reason="the session's child, which logs no Accepted line, was taken as the session",
    ),
    Mutation(
        id="f2b-nojournal/no-daemon-crashes",
        file="bob/checks/fail2ban.py",
        old="if not daemons or None in daemons:",
        new="if None in daemons:",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestTheNewestSession::test_no_daemon_process_found",),
        reason="with no syslog daemon process found, max() of nothing raised",
    ),
    Mutation(
        id="f2b-nojournal/override-named-journal",
        file="bob/checks/fail2ban.py",
        old='snapshot.jail_d_locals, "logpath")',
        new="snapshot.jail_d_locals)",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestRoutedElsewhere::test_said_with_the_file_sshd_goes_to_and_a_fix",),
        reason="the logpath override was written as zz-bob-sshd-journal.local, the name "
               "of the backend override",
    ),
    Mutation(
        id="f2b-caveat/count-caveat-unsaid",
        file="bob/checks/fail2ban.py",
        old='        result.info(\n            message=_t("fail2ban.ssh_jail_counted_caveat"',
        new='        dict(\n            message=_t("fail2ban.ssh_jail_counted_caveat"',
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestTheCaveats::test_the_count", "tests/test_v0260_fail2ban_without_journal.py::TestTheCaveats::test_the_terminal_shows_it"),
        reason="the OK on the jail's count printed no caveat on the terminal: its "
               "reason sat in a detail an OK never shows",
    ),
    Mutation(
        id="f2b-caveat/count-ok-not-qualified",
        file="bob/checks/fail2ban.py",
        old='result.qualify("fail2ban.ssh_jail_counted_caveat", since=_ok_at)',
        new="None",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestTheCaveats::test_the_count",),
        reason="JSON and webhook carried the OK with no link to its caveat",
    ),
    Mutation(
        id="f2b-caveat/sample-caveat-unsaid",
        file="bob/checks/fail2ban.py",
        old='            result.info(\n                message=_t("fail2ban.ssh_jail_sampled_caveat"',
        new='            dict(\n                message=_t("fail2ban.ssh_jail_sampled_caveat"',
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestTheCaveats::test_the_sample",),
        reason="the v0.24.4 OK on a sampled file printed its caveat on the report only",
    ),
    Mutation(
        id="f2b-caveat/sample-ok-not-qualified",
        file="bob/checks/fail2ban.py",
        old='result.qualify("fail2ban.ssh_jail_sampled_caveat", since=_ok_at)',
        new="None",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestTheCaveats::test_the_sample",),
        reason="JSON and webhook carried the sampled OK with no link to its caveat",
    ),
    Mutation(
        id="f2b-caveat/journal-jail-caveated",
        file="bob/checks/fail2ban.py",
        old="        if snapshot.ssh_jail_files and not snapshot.ssh_jail_journal:\n            # v0.26.0 — the v0.24.4 detail",
        new="        if True:\n            # v0.26.0 — the v0.24.4 detail",
        kills=("tests/test_v0260_fail2ban_without_journal.py::TestTheCaveats::test_a_journal_jail_needs_none",),
        reason="a jail reading the journal itself was given a caveat about a file sample",
    ),
    Mutation(
        id="firewalld-nested/priority-ignored",
        file="bob/checks/_firewalld.py",
        old="key=lambda z: (z.ingress_priority, z.name)",
        new="key=lambda z: z.name",
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestTheMeasuredOrder::test_what_the_drop_zone_takes",),
        reason="zzzcarve at ingress-priority -10 dropped 8099 on Debian; ordered by name "
               "alone it would take nothing",
    ),
    Mutation(
        id="firewalld-nested/name-ignored",
        file="bob/checks/_firewalld.py",
        old="key=lambda z: (z.ingress_priority, z.name)",
        new="key=lambda z: z.ingress_priority",
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestTheMeasuredOrder::test_what_the_drop_zone_takes",),
        reason="at equal priority aaacarve, sorting first by name, dropped 8099",
    ),
    Mutation(
        id="firewalld-nested/first-match-not-subtracted",
        file="bob/checks/_firewalld.py",
        old="                got = _subtract([net], claimed.get(v, []))",
        new="                got = [net]",
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestTheAlert::test_a_large_public_range_taken_first_ends_the_alert",
               "tests/test_v0260_firewalld_nested_sources.py::TestTheCumulatedShare::test_a_closed_zone_first_is_left_out"),
        reason="what a zone classified first takes was still counted to the open zones",
    ),
    Mutation(
        id="firewalld-nested/pooled-on-the-whole-family-only",
        file="bob/checks/_firewalld.py",
        old="            if not _nearly_all(public, public_space):\n                continue\n            families.add",
        new="            if not any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(entry['open'])):\n                continue\n            families.add",
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestTheAlert::test_a_drop_zone_first_is_named_and_the_alert_holds",),
        reason="decided: every public address is the alert; a private /32 taken first "
               "would otherwise drop the 3 points",
    ),
    Mutation(
        id="firewalld-nested/exception-unnamed",
        file="bob/checks/firewall.py",
        old='                               else "firewall.firewalld_policy_open_sources_pooled_except" if taken',
        new='                               else "firewall.firewalld_policy_open_sources_pooled_except" if False',
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestTheAlert::test_a_drop_zone_first_is_named_and_the_alert_holds",),
        reason="with 192.168.1.10/32 dropped first, the alert said every client gets in",
    ),
    Mutation(
        id="firewalld-nested/ipv6-public-table-0260",
        file="bob/checks/_firewalld.py",
        old='("::/3", "4000::/2", "8000::/1", "2001:db8::/32",\n                                                "3fff::/20")',
        new='("::/1", "8000::/2", "c000::/3", "2001:db8::/32", "4000::/2")',
        kills=("tests/test_v0260_firewalld_nested_sources.py::test_the_ipv6_public_space_is_2000_slash_3_less_documentation",),
        reason="the IPv6 public share was read against e000::/3, not 2000::/3",
    ),
    Mutation(
        id="firewalld-nested/short-of-all-printed-100",
        file="bob/checks/firewall.py",
        old="    elif 99.95 <= value < 100:",
        new="    elif False:",
        kills=("tests/test_v0260_firewalld_nested_sources.py::test_short_of_all_of_it_is_never_printed_100",),
        reason="on Debian, 8.8.8.0/24 taken first printed 100% (100%)",
    ),
    Mutation(
        id="firewalld-nested/closed-zones-not-passed",
        file="bob/checks/firewall.py",
        old="                    closed=[b for b in firewalld.bindings",
        new="                    closed=[b for b in []",
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestTheAlert::test_a_large_public_range_taken_first_ends_the_alert",),
        reason="the cumulated share ignored the zone classified first",
    ),
    Mutation(
        id='final-reject/nft-rule-ignored',
        file='bob/checks/iptables_nftables.py',
        old='        if m:\n            return ("DROP" if m.group(1) == "drop" else "REJECT"), True',
        new='        if False:\n            return ("DROP" if m.group(1) == "drop" else "REJECT"), True',
        kills=('tests/test_v0260_final_reject_rule.py::TestTheNftChain::test_a_final_reject_filters',),
        reason='a chain at policy accept ending in reject refused 8099; BOB read no firewall and capped the domain',
    ),
    Mutation(
        id='final-reject/a-match-read-as-everything',
        file='bob/checks/iptables_nftables.py',
        old='_DROPS_EVERYTHING = re.compile(r"^(drop|reject',
        new='_DROPS_EVERYTHING = re.compile(r"^(?:.*\\s)?(drop|reject',
        kills=('tests/test_v0260_final_reject_rule.py::TestTheNftChain::test_a_rule_with_a_match_leaves_the_rest_to_the_policy',),
        reason='a tcp-only reject leaves UDP to the policy accept; read as filtering everything',
    ),
    Mutation(
        id='final-reject/iptables-rule-ignored',
        file='bob/checks/iptables_nftables.py',
        old='m = re.match(r"^-A INPUT -j (ACCEPT|DROP|REJECT)(?:\\s+--reject-with\\s+\\S+)?\\s*$", line.strip())',
        new='m = re.match(r"^-A INPUT -j (ACCEPT)(?:\\s+--reject-with\\s+\\S+)?\\s*$", line.strip())',
        kills=('tests/test_v0260_final_reject_rule.py::TestTheIptablesChain::test_a_final_reject_filters',),
        reason='-P INPUT ACCEPT and a last -j REJECT refused 8099; read as no firewall',
    ),
    Mutation(
        id='final-reject/accept-before-reject-ignored',
        file='bob/checks/iptables_nftables.py',
        old='        if text == "accept":\n            return "ACCEPT", True',
        new='        if False:\n            return "ACCEPT", True',
        kills=('tests/test_v0260_final_reject_rule.py::TestTheNftChain::test_an_accept_everything_rule_before_it_wins',),
        reason='an accept-everything rule above the reject makes it unreachable',
    ),
    Mutation(
        id='final-reject/said-as-policy-drop',
        file='bob/checks/iptables_nftables.py',
        old='                     if snapshot.input_policy_by_rule',
        new='                     if False',
        kills=('tests/test_v0260_final_reject_rule.py::TestTheVerdict::test_no_deduction_and_said_as_it_is',),
        reason="the OK said 'default INPUT policy REJECT' on a chain at policy accept",
    ),
    Mutation(
        id='nft-loopback/iptables-nft-counter',
        file='bob/checks/iptables_nftables.py',
        old='(?:counter(?:\\s+packets\\s+\\d+\\s+bytes\\s+\\d+)?\\s+)?accept',
        new='accept',
        kills=('tests/test_v0260_final_reject_rule.py::TestTheNftChain::test_iptables_nft_counters_do_not_hide_it',),
        reason='iptables-nft writes a counter into the lo rule; -1 for a rule that was there',
    ),
    Mutation(
        id="firewalld-nested/whole-family-zone-unchecked",
        file="bob/checks/_firewalld.py",
        old="                             and self._still_takes_every_public(b)]",
        new="                             ]",
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestAZoneBoundToAWholeFamily::test_a_public_range_taken_first_makes_it_a_source_zone",),
        reason="a zone on 0.0.0.0/0 kept as the host's open default while a zone classified "
               "first kept a public range out of it",
    ),
    Mutation(
        id="firewalld-nested/whole-family-exception-unnamed",
        file="bob/checks/firewall.py",
        old="        if taken:\n            # v0.26.0 — what a zone classified first keeps (measured on Debian 13).",
        new="        if False:\n            # v0.26.0 — what a zone classified first keeps (measured on Debian 13).",
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestTheWholeFamilyAlertNamesTheException::test_classified_first",),
        reason="with 192.168.1.10/32 dropped first, trusted on 0.0.0.0/0 was said to take every client",
    ),
    Mutation(
        id="firewalld-nested/near-all-public-is-not-all",
        file="bob/checks/_firewalld.py",
        old="    return public * 100 >= public_space * NEAR_ALL_PUBLIC",
        new="    return public == public_space",
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestTheAlert::test_a_small_public_range_taken_first_keeps_the_alert",
               "tests/test_v0260_firewalld_nested_sources.py::TestTheAlert::test_the_threshold"),
        reason="decided after review: 8.8.8.0/24 kept out raised the domain from 7/10 to "
               "10/10 while nearly all of the internet stayed open",
    ),
    Mutation(
        id="firewalld-nested/near-all-said-as-all",
        file="bob/checks/firewall.py",
        old="                near = firewalld.pooled_public_share < 100.0",
        new="                near = False",
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestTheAlert::test_a_small_public_range_taken_first_keeps_the_alert",),
        reason="short of all of them, the alert said the zones take every public address",
    ),
    Mutation(
        id="raw-accept/mark-set-elsewhere-ignored",
        file="bob/checks/firewall_stack.py",
        old='        return "admits" if _mark_reachable(rule, mark_setters) else "conditional"',
        new='        return "conditional"',
        kills=("tests/test_v0260_raw_accept_reach.py::TestAMarkSetBeforehand::test_a_mark_set_on_new_packets_admits",
               "tests/test_v0260_raw_accept_reach.py::TestAMarkSetBeforehand::test_a_match_on_an_unset_bit_takes_every_new_packet"),
        reason="a mangle MARK on new 8099 packets opened 8099 past an active ufw through "
               "a mark rule BOB called conditional",
    ),
    Mutation(
        id="raw-accept/unmarked-packets-forgotten",
        file="bob/checks/firewall_stack.py",
        old='    nf, ct = {0}, {0}\n',
        new='    nf, ct = set(), {0}\n',
        kills=("tests/test_v0260_raw_accept_reach.py::TestAMarkSetBeforehand::test_a_match_on_an_unset_bit_takes_every_new_packet",),
        reason="--mark 0x0/0x4000 accepts every unmarked packet: every new connection",
    ),
    Mutation(
        id="raw-accept/any-mark-feeds-any-match",
        file="bob/checks/firewall_stack.py",
        old='            target |= {(x & ~mk) ^ v for x in target}',
        new='            target |= {0xFFFFFFFF}',
        kills=("tests/test_v0260_raw_accept_reach.py::TestAMarkSetBeforehand::test_another_mark_does_not",),
        reason="kube-proxy's 0x4000 would make kube-router's 0x20000 rule a bypass again "
               "(0.25.1's false -2 on k3s)",
    ),
    Mutation(
        id="raw-accept/setters-not-passed",
        file="bob/checks/firewall_stack.py",
        old='        reach = _accept_reach(rule, snapshot.mark_setters + _input_setters_above(snapshot.input_rules, rule))',
        new='        reach = _accept_reach(rule)',
        kills=("tests/test_v0260_raw_accept_reach.py::TestAMarkSetBeforehand::test_deducted_like_a_port_rule",),
        reason="the collected setters never reached the verdict",
    ),
    Mutation(
        id="raw-accept/mangle-not-read",
        file="bob/checks/firewall_stack.py",
        old='                                       for table in ("raw", "mangle", "nat")))',
        new='                                       for table in ("raw", "nat")))',
        kills=("tests/test_v0260_raw_accept_reach.py::TestAMarkSetBeforehand::test_the_setters_are_collected_from_the_tables",),
        reason="the measured setter was in mangle PREROUTING",
    ),
    Mutation(
        id="awall/required-policy-unnamed",
        file="bob/checks/_awall.py",
        old='                        [f"{p[0]} (required)" for p in rows if p[1] == "required"])',
        new='                        [])',
        kills=("tests/test_v0260_awall_named.py::test_a_required_policy_is_named_too",),
        reason="a policy an enabled one imports is loaded too and was not named",
    ),
    Mutation(
        id="raw-accept/input-mark-below-counted",
        file="bob/checks/firewall_stack.py",
        old="    above = input_rules[:input_rules.index(rule)] if rule in input_rules else []",
        new="    above = input_rules",
        kills=("tests/test_v0260_raw_accept_reach.py::TestAMarkSetBeforehand::test_a_mark_set_in_input_counts_only_above_the_rule",),
        reason="a MARK below the mark rule in filter INPUT left 8099 closed; counted, it "
               "would deduct 2 for nothing",
    ),
    Mutation(
        id="raw-accept/input-mark-above-ignored",
        file="bob/checks/firewall_stack.py",
        old="        reach = _accept_reach(rule, snapshot.mark_setters + _input_setters_above(snapshot.input_rules, rule))",
        new="        reach = _accept_reach(rule, snapshot.mark_setters)",
        kills=("tests/test_v0260_raw_accept_reach.py::TestAMarkSetBeforehand::test_a_mark_set_in_input_counts_only_above_the_rule",),
        reason="a MARK above the mark rule in filter INPUT opened 8099",
    ),
    Mutation(
        id='firewalld-refusing/rules-never-read',
        file='bob/checks/_firewalld.py',
        old='_REFUSING = re.compile(r\'\\s(?:reject(?:\\s+type="[^"]*")?|drop)\\s*$\')',
        new="_REFUSING = re.compile(r'(?!x)x')",
        kills=('tests/test_v0260_firewalld_nested_sources.py::TestRichRulesThatRefuse::test_which_rules_refuse', 'tests/test_v0260_firewalld_nested_sources.py::TestRichRulesThatRefuse::test_a_source_zone'),
        reason='a port reject rule refused 8099 in a zone at target ACCEPT; BOB said every port is open',
    ),
    Mutation(
        id='firewalld-refusing/caveat-unlinked',
        file='bob/checks/firewall.py',
        old='            result.qualify("firewall.firewalld_open_zone_refuses_some", since=since)\n',
        new='',
        kills=('tests/test_v0260_firewalld_nested_sources.py::TestRichRulesThatRefuse::test_a_source_zone',),
        reason='JSON and webhook carried the open finding with no link to its caveat',
    ),
    Mutation(
        id='firewalld-refusing/source-zone-unsaid',
        file='bob/checks/firewall.py',
        old='                _refusals_caveat(result, _t, [src_zone], _at)\n',
        new='',
        kills=('tests/test_v0260_firewalld_nested_sources.py::TestRichRulesThatRefuse::test_a_source_zone',),
        reason='the measured case: a source zone at ACCEPT with a reject rule',
    ),
    Mutation(
        id='firewalld-refusing/interface-zone-unsaid',
        file='bob/checks/firewall.py',
        old='                _refusals_caveat(result, _t, [zone], _at)\n',
        new='',
        kills=('tests/test_v0260_firewalld_nested_sources.py::TestRichRulesThatRefuse::test_the_interface_zone',),
        reason='an interface zone at ACCEPT said every port open past its reject rules',
    ),
    Mutation(
        id='firewalld-refusing/pooled-zones-unsaid',
        file='bob/checks/firewall.py',
        old='                _refusals_caveat(result, _t, [z for z, _ in pooled], _at)\n',
        new='',
        kills=('tests/test_v0260_firewalld_nested_sources.py::TestRichRulesThatRefuse::test_pooled_zones',),
        reason='pooled source zones said every port open past their reject rules',
    ),
    Mutation(
        id="firewalld-nested/policy-ignored-for-source-zones",
        file="bob/checks/_firewalld.py",
        old='                for v in [best_verdict(b, self.host_policies, source_families(b))] if v.policy == "allow"]',
        new='                for v in [best_verdict(b, (), source_families(b))] if v.policy == "allow"]',
        kills=("tests/test_v0260_firewalld_nested_sources.py::test_a_host_policy_that_drops_first_closes_the_pooled_zones",),
        reason="a policy ANY to HOST at -10 DROP closed 8099 on Debian; ignored, the pooled "
               "zones would be alerted open",
    ),
    Mutation(
        id="raw-accept/outbound-marks-counted",
        file="bob/checks/firewall_stack.py",
        old='    sequence = [r for hook in ("PREROUTING", "INPUT") for chains in tables\n                for r in expand(chains, hook, frozenset())]',
        new='    sequence = [r for chains in tables for rules in chains.values() for r in rules]',
        kills=("tests/test_v0260_raw_accept_reach.py::TestTheInboundPathOnly::test_outbound_chains_do_not_count",
               "tests/test_v0260_raw_accept_reach.py::TestTheInboundPathOnly::test_the_same_chain_reached_from_output_only_does_not"),
        reason="a MARK in mangle OUTPUT or POSTROUTING left 8099 closed; counted, a mark "
               "rule would cost 2 for nothing",
    ),
    Mutation(
        id="raw-accept/user-chain-jumps-not-followed",
        file="bob/checks/firewall_stack.py",
        old='                ordered += expand(chains, m.group(1), seen)',
        new='                pass',
        kills=("tests/test_v0260_raw_accept_reach.py::TestTheInboundPathOnly::test_a_user_chain_reached_from_prerouting_counts",),
        reason="a MARK in a user chain jumped from mangle PREROUTING opened 8099",
    ),
    Mutation(
        id="raw-accept/connmark-read-as-packet-mark",
        file="bob/checks/firewall_stack.py",
        old='            target = ct if "-j CONNMARK" in setter else nf',
        new='            target = nf',
        kills=("tests/test_v0260_raw_accept_reach.py::TestAConnectionMark::test_measured",),
        reason="CONNMARK --set-xmark alone left 8099 closed: it marks the connection, not the packet",
    ),
    Mutation(
        id="raw-accept/restore-masks-ignored",
        file="bob/checks/firewall_stack.py",
        old="                nf |= {(n & ~nfmask) ^ (c & ctmask) for n in nf for c in ct}",
        new="                nf |= set(ct)",
        kills=("tests/test_v0260_raw_accept_reach.py::TestAConnectionMark::test_measured",),
        reason="a restore with masks 0x10000 does not copy bit 0x20000; 8099 stayed closed",
    ),
    Mutation(
        id="raw-accept/mark-order-ignored",
        file="bob/checks/firewall_stack.py",
        old="    for setter in setters:\n        copy = _CONNMARK_COPY.search(setter)",
        new="    for setter in sorted(setters, key=lambda r: 'restore' in r):\n        copy = _CONNMARK_COPY.search(setter)",
        kills=("tests/test_v0260_raw_accept_reach.py::TestAConnectionMark::test_measured",),
        reason="a restore before the CONNMARK set left 8099 closed",
    ),
    Mutation(
        id="firewalld-nested/source-families-ignored",
        file="bob/checks/_firewalld.py",
        old="    return tuple(f for f in FAMILIES if f in fams) or FAMILIES",
        new="    return FAMILIES",
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestAWholeFamilyRefusedInTheZone::test_by_the_sources_family",),
        reason="an IPv4 source zone with a catch-all IPv4 reject was reported open through IPv6",
    ),
    Mutation(
        id="awall/enabled-not-loaded-said-none",
        file="bob/checks/firewall.py",
        old="        _not_loaded = _awall_here and awall.readable and bool(awall.enabled)",
        new="        _not_loaded = False",
        kills=("tests/test_v0260_awall_named.py::test_enabled_but_not_loaded_is_said_as_such",),
        reason="after awall enable without activate, the alert said no policy was enabled",
    ),
    Mutation(
        id="final-reject/first-base-chain-only",
        file="bob/checks/iptables_nftables.py",
        old='    effective = [_chain_verdict(c)[0] for c in chains if c["family"] in _IPV4_FAMILIES]',
        new='    effective = [_chain_verdict(c)[0] for c in chains if c["family"] in _IPV4_FAMILIES][:1]',
        kills=("tests/test_v0260_final_reject_rule.py::test_an_accept_in_one_base_chain_does_not_skip_the_next",),
        reason="an accept in chain a hands the packet to chain b, whose final reject refused 8099",
    ),
    Mutation(
        id="docker-strict/setting-never-read",
        file="bob/checks/_firewalld.py",
        old='    if re.search(r"\\bct status dnat jump filter_FORWARD_dnat\\b", chain):\n        return True\n',
        new="",
        kills=("tests/test_v0260_docker_firewall_backend.py::TestStrictForwardPorts::test_the_live_setting_is_read",),
        reason="with StrictForwardPorts=yes the published 8099 was rejected; read as no, BOB "
               "alerted a bypass",
    ),
    Mutation(
        id="docker-strict/bypass-alerted-anyway",
        file="bob/checks/docker.py",
        old='            if strict_for.get(port.port_proto) and not snapshot.iptables_disabled:',
        new='            if False:',
        kills=("tests/test_v0260_docker_firewall_backend.py::TestStrictForwardPorts::test_strict_no_bypass_alert",),
        reason="firewalld rejected the published port (StrictForwardPorts=yes); BOB alerted "
               "it bypassed the host firewall",
    ),
    Mutation(
        id="docker-strict/bypass-warning-anyway",
        file="bob/checks/docker.py",
        old='    elif all_strict:\n',
        new='    elif False:\n',
        kills=("tests/test_v0260_docker_firewall_backend.py::TestStrictForwardPorts::test_strict_no_bypass_alert",),
        reason="the 'Docker may bypass the host firewall' warning under a firewalld that "
               "rejects what Docker forwards",
    ),
    Mutation(
        id="docker-strict/port-line-says-unfiltered",
        file="bob/checks/ports.py",
        old='                                   and not (firewalld_strict and not port_forwarded(firewalld_forwarded, lport.port, lport.proto))\n',
        new='',
        kills=("tests/test_v0260_docker_firewall_backend.py::TestStrictForwardPorts::test_the_port_line_follows_the_zone",),
        reason="the port line said the zone does not filter a port firewalld rejected",
    ),
    Mutation(
        id="docker-strict/runner-forgets-docker",
        file="bob/runner.py",
        old='                                       firewalld_strict=_firewalld_strict,\n',
        new='                                       firewalld_strict=False,\n',
        kills=("tests/test_v0260_docker_firewall_backend.py::TestStrictForwardPorts::test_the_runner_reads_it_only_with_firewalld_active",),
        reason="the docker check never learned the setting",
    ),
    Mutation(
        id="raw-accept/hmark-tproxy-not-collected",
        file="bob/checks/firewall_stack.py",
        old="                or _HMARK.search(rule) or _TPROXY_MARK.search(rule))",
        new="                )",
        kills=("tests/test_v0260_raw_accept_reach.py::TestOtherMarkTargets::test_hmark_is_followed", "tests/test_v0260_raw_accept_reach.py::TestOtherMarkTargets::test_tproxy_mark"),
        reason="an HMARK with offset 0x20000 opened 8099 through a mark rule BOB called conditional",
    ),
    Mutation(
        id="raw-accept/wide-hmark-called-conditional",
        file="bob/checks/firewall_stack.py",
        old="                return True       # not established: never called conditional",
        new="                return False",
        kills=("tests/test_v0260_raw_accept_reach.py::TestOtherMarkTargets::test_a_wide_hmark_is_not_called_conditional",),
        reason="an HMARK spread over 65536 values may set the bits; called conditional, a bypass would go unsaid",
    ),
    Mutation(
        id="raw-accept/hmark-range-ignored",
        file="bob/checks/firewall_stack.py",
        old="            nf |= {offset + i for i in range(max(mod, 1))}",
        new="            nf |= {0}",
        kills=("tests/test_v0260_raw_accept_reach.py::TestOtherMarkTargets::test_hmark_is_followed",),
        reason="the measured HMARK set 0x20000 (offset 131072, mod 1)",
    ),
    Mutation(
        id="docker-strict/forwarded-port-taken-as-rejected",
        file="bob/checks/docker.py",
        old="    strict_for = {p.port_proto: firewalld_strict and not port_forwarded(firewalld_forwarded, p.host_port, p.proto)",
        new="    strict_for = {p.port_proto: firewalld_strict",
        kills=("tests/test_v0260_docker_firewall_backend.py::TestAPortAZoneAlsoForwards::test_the_forwarded_port_keeps_the_alert",),
        reason="firewalld issue #1536: a port a zone forwards stays reachable under StrictForwardPorts=yes",
    ),
    Mutation(
        id="docker-strict/forwarded-port-line-says-measured",
        file="bob/checks/ports.py",
        old='message=_t(("ports.uncovered_firewalld_docker_forwarded" if firewalld_strict',
        new='message=_t(("ports.uncovered_firewalld_docker" if firewalld_strict',
        kills=("tests/test_v0260_docker_firewall_backend.py::TestAPortAZoneAlsoForwards::test_the_port_line_keeps_its_docker_text",),
        reason="a forwarded port under StrictForwardPorts=yes was given the text of the measured default case",
    ),
    Mutation(
        id="cron-busybox/cron-update-overwritten",
        file="bob/cron/_crontab.py",
        old="    fd = os.open(CRON_UPDATE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)",
        new="    fd = os.open(CRON_UPDATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)",
        kills=("tests/test_v0260_cron_in_root_crontab.py::test_a_name_already_waiting_in_cron_update_is_kept",),
        reason="a name another crontab edit left in cron.update would be lost, and crond not re-read it",
    ),
    Mutation(
        id="raw-accept/filter-user-chains-unread",
        file="bob/checks/firewall_stack.py",
        old='        input_rules = (_input_path(_run("iptables", "-S"))\n                       or [ln.strip()',
        new='        input_rules = ([ln.strip()',
        kills=("tests/test_v0260_raw_accept_reach.py::TestAMarkSetBeforehand::test_a_mark_set_in_a_user_chain_jumped_from_input",),
        reason="measured: a MARK in a user chain jumped from INPUT above the mark rule opened 8099 while BOB said conditional",
    ),
    Mutation(
        id="raw-accept/filter-jumps-not-followed",
        file="bob/checks/firewall_stack.py",
        old="                ordered += expand(m.group(1), seen | {m.group(1)})",
        new="                ordered += []",
        kills=("tests/test_v0260_raw_accept_reach.py::TestAMarkSetBeforehand::test_a_mark_set_in_a_user_chain_jumped_from_input",),
        reason="a user chain jumped from INPUT, nested or not, is on the inbound path",
    ),
    Mutation(
        id="raw-accept/filter-jump-loop",
        file="bob/checks/firewall_stack.py",
        old="            if m and m.group(1) in chains and m.group(1) not in seen:",
        new="            if m and m.group(1) in chains:",
        kills=("tests/test_v0260_raw_accept_reach.py::TestAMarkSetBeforehand::test_a_chain_that_jumps_back_does_not_loop",),
        reason="a chain jumping back to one already on the path would recurse without end",
    ),
    Mutation(
        id="firewalld-v6/space-miscounted",
        file="bob/checks/_firewalld.py",
        old='    """(public addresses *nets* hold, public addresses of the family)."""\n    space = 2 ** (32 if version == 4 else 128)',
        new='    """(public addresses *nets* hold, public addresses of the family)."""\n    space = 2 ** (32 if version == 4 else 127)',
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestTheSameInIPv6::test_99_percent_is_the_alert",),
        reason="the IPv6 share decides the −3 at 99 %; a wrong family size moves the step",
    ),
    Mutation(
        id="firewalld-v6/families-merged",
        file="bob/checks/_firewalld.py",
        old="            v = net.version\n            entry = out.setdefault(v,",
        new="            v = 4\n            entry = out.setdefault(v,",
        kills=("tests/test_v0260_firewalld_nested_sources.py::TestTheSameInIPv6::test_the_first_match_wins_not_the_narrowest",),
        reason="IPv6 sources classified in the IPv4 order and against its space",
    ),
    Mutation(
        id="docker-strict/unread-zones-read-as-none-forwarded",
        file="bob/checks/_firewalld.py",
        old="        if not res.ok:\n            return None\n        listing = res.stdout",
        new="        listing = res.stdout",
        kills=("tests/test_v0260_docker_firewall_backend.py::TestAPortAZoneAlsoForwards::test_unlisted_zones_are_not_an_empty_set",),
        reason="zones that could not be listed would read as forwarding nothing",
    ),
    Mutation(
        id="docker-strict/rich-forward-ports-ignored",
        file="bob/checks/_firewalld.py",
        old='_FWD_RICH = re.compile(r\'forward-port port="(\\d+)(?:-(\\d+))?" protocol="(\\w+)"\')',
        new="_FWD_RICH = re.compile(r'(?!x)x')",
        kills=("tests/test_v0260_docker_firewall_backend.py::TestAPortAZoneAlsoForwards::test_forward_ports_are_read",),
        reason="a rich-rule forward-port forwards a port as well",
    ),
    Mutation(
        id="docker-strict/runner-keeps-strict-on-unread-zones",
        file="bob/runner.py",
        old="    if _firewalld_forwarded is None:     # zones unread: not taken as rejected\n",
        new="    if False:\n",
        kills=("tests/test_v0260_docker_firewall_backend.py::TestAPortAZoneAlsoForwards::test_the_runner_drops_strict_when_zones_are_unread",),
        reason="with the zones unread, a forwarded port could not be ruled out",
    ),
    Mutation(
        id="firewalld-nested/uncounted-sources-unsaid",
        file="bob/checks/firewall.py",
        old="            if _uncounted:\n",
        new="            if False:\n",
        kills=("tests/test_v0260_firewalld_nested_sources.py::test_uncounted_ipset_sources_are_said_and_make_the_score_a_ceiling",),
        reason="ipset and MAC sources are not counted; the 99% alert could be missed unsaid",
    ),
    Mutation(
        id="docker-firewalld/established-connections-unsaid",
        file="bob/locales/en.json",
        old="They stop new connections from other sources; a connection already tracked before them is let through until it expires.",
        new="They stop connections from other sources.",
        kills=("tests/test_v0260_docker_firewall_backend.py::test_the_docker_user_example_says_what_it_stops",),
        reason="the RETURN for established traffic lets a connection opened before the rules through",
    ),
    Mutation(
        id="docs/cis-kubernetes-count-stale",
        file="README.md",
        old="· 7 CIS Docker 1.6 · 4 CIS Kubernetes 2.0 ·",
        new="· 7 CIS Docker 1.6 · 3 CIS Kubernetes 2.0 ·",
        kills=(f"{_LIVECOUNT}::"
               "test_the_readme_per_benchmark_cis_breakdown_matches_the_live_categories",),
        reason="v0.25.0 added a fifth benchmark family; before the guard learned "
               "it, Kubernetes references counted as CIS Ubuntu",
    ),
    Mutation(
        id="docs/cis-breakdown-mis-split",
        file="DOCUMENTS/README_TECH.md",
        old="226 entries (117 formal CIS, 98 best-practice, 7 Docker, 4 Kubernetes)",
        new="226 entries (116 formal CIS, 99 best-practice, 7 Docker, 4 Kubernetes)",
        kills=(f"{_LIVECOUNT}::"
               "test_the_readme_tech_cis_breakdown_matches_the_live_categories",),
        reason="v0163 checks only that the parts sum to the total, so a wrong "
               "split that still sums (110+88+7=205) passed it — the per-category "
               "check catches the split against the live counts",
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
        old='"firewall_missing": "No active firewall — neither UFW nor firewalld is installed, and no netfilter chain denies inbound IPv4 traffic by default"',
        new='"firewall_missing": "No active firewall — install it with: sudo apt install ufw"',
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
        old="_TIMEOUT_PACKAGE = 3600",
        new="_TIMEOUT_PACKAGE = 30",
        kills=(f"{_FIXTMO}::TestPackageTransactionsGetABudgetTheyCanFinishIn::"
               "test_the_long_budget_is_minutes_not_seconds",),
        reason="thirty seconds is a budget for `ufw delete`; a package "
               "transaction reaching it means BOB stops a healthy upgrade "
               "mid-transaction — measured needing ~25 min on a slow-disk Mint",
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
        id="injection/interface-name-unsanitised",
        file="bob/display.py",
        old="            name   = output_mod.sanitize(iface.name, max_len=w_name * 2)",
        new="            name   = iface.name",
        kills=("tests/test_v0201_display_injection.py::"
               "test_interface_name_ansi_does_not_reach_the_terminal",),
        reason="the kernel accepts an interface name with raw ANSI bytes and an "
               "attacker with CAP_NET_ADMIN can create one; rendered raw in the "
               "interface table it injects terminal escapes — a direct-render "
               "path that bypasses the Finding sanitiser",
    ),
    Mutation(
        id="injection/disk-mountpoint-unsanitised",
        file="bob/display.py",
        old="        rows.append((output_module.sanitize(p.mountpoint, max_len=128),",
        new="        rows.append((p.mountpoint,",
        kills=("tests/test_v0201_display_injection.py::"
               "test_disk_mountpoint_and_device_ansi_do_not_reach_the_terminal",),
        reason="a mountpoint is a path (any byte but / and NUL), so a userns "
               "tmpfs an unprivileged user mounts can carry ANSI; rendered raw "
               "in the partition table it injects terminal escapes",
    ),
    Mutation(
        id="injection/deduction-reason-unsanitised",
        file="bob/scoring.py",
        old="        self.reason = _sanitize_line(self.reason)",
        new="        self.reason = self.reason",
        kills=("tests/test_v0141_robustness.py::"
               "TestCsvFormulaInjection::test_deduction_reason_is_sanitised",),
        reason="the score breakdown renders Deduction.reason raw to the terminal; "
               "an attacker-controlled string inside it (a samba share name, a "
               "file path) injects ANSI escapes there unless it passes the same "
               "sanitise choke point as Finding.message",
    ),
    Mutation(
        id="span/partial-blinding-not-widened",
        file="bob/domain_scores.py",
        old="    low = round(sum(scores[d][\"score\"] for d in scored if d not in partial) / n)",
        new="    low = round(sum(scores[d][\"score\"] for d in scored) / n)",
        kills=("tests/test_v0162_score_direction.py::"
               "TestTheSpanBracketsTheTruth::test_partial_blinding_widens_the_low_end_only",),
        reason="a domain still scored but with an unread input is an upper bound; "
               "if the span's low end does not drop for it, blinding systemctl "
               "reads exposure_services as a firm 10 while service state was "
               "never checked — the score-rise-when-blind class the span exists "
               "to make honest",
    ),
    Mutation(
        id="fix-lies/timer-chmod-caps-at-five",
        file="bob/checks/systemd_timers.py",
        old='    return "sudo chmod o-w " + " ".join(shlex.quote(s) for s in scripts)',
        new='    return "sudo chmod o-w " + " ".join(shlex.quote(s) for s in scripts[:5])',
        kills=("tests/test_systemd_timers.py::"
               "TestCheckSystemdTimers::test_the_fix_covers_every_world_writable_script",),
        reason="the finding counts every world-writable timer script but a "
               "scripts[:5] cap chmods only the first five, so --fix --apply "
               "reports success while leaving the rest world-writable — a fix "
               "that lies, the same class as the samba/ssh/ufw/umask fixes",
    ),
    Mutation(
        id="robustness/samba-conf-read-bypasses-fifo-guard",
        file="bob/checks/samba.py",
        old='    parser.read_string(read_text_capped(path, encoding="utf-8"), source=str(path))',
        new='    parser.read(str(path), encoding="utf-8")',
        kills=("tests/test_v0201_samba_fifo_hang.py::"
               "test_directory_smb_conf_is_refused",),
        reason="configparser.read does open(path).read() with no guard, so a "
               "smb.conf that is a FIFO blocks BOB forever — the exact hang "
               "read_text_capped was written to prevent (v0.14.1), re-introduced "
               "by parsing the path directly; it also swallows a directory's "
               "OSError and reads nothing, so routing through the capped reader "
               "restores both the FIFO guard and the raise-on-unreadable contract",
    ),
    Mutation(
        id="updates/dist-upgrade-timeout-read-as-zero",
        file="bob/checks/updates.py",
        old="    fallback = run_result(\"apt\", \"list\", \"--upgradable\", timeout=30)\n    if fallback.ok:",
        new="    fallback = run_result(\"apt\", \"list\", \"--upgradable\", timeout=30)\n    if False:",
        kills=("tests/test_v0201_apt_dist_upgrade_timeout.py::"
               "test_dist_upgrade_timeout_falls_back_to_apt_list",),
        reason="apt-get -s dist-upgrade takes 47s on a slow disk with hundreds "
               "of pending packages, past the timeout; without the apt list "
               "--upgradable fallback the empty (timed-out) result is read as "
               "zero pending and a host with 322 pending security updates is "
               "scored as fully patched — absence of an answer read as a negative",
    ),
    Mutation(
        id="banner/distro-logo-not-single-wide",
        file="bob/output.py",
        old='"🦎"),',
        new='"⚙️"),',
        kills=("tests/test_v0200_distro_logo.py::"
               "test_every_logo_is_single_codepoint_and_wide",),
        reason="the banner pads each boxed row with _visual_width, so a distro "
               "logo must be one East-Asian-Wide code point; a variation-selector "
               "emoji renders at a width the code cannot predict and pushes the "
               "System row's right border out of the box",
    ),
    Mutation(
        id="fix-lies/ufw-ipv6-literal-match",
        file="bob/checks/firewall.py",
        old="    return (\"sudo sed -i -E 's/^IPV6[[:space:]]*=[[:space:]]*no\\\\b.*/IPV6=yes/I' \"",
        new="    return (\"sudo sed -i -E 's/^IPV6=no/IPV6=yes/I' \"",
        kills=("tests/test_v0200_config_fix_matches_detection.py::"
               "TestUfwIpv6FixMatchesDetection::test_roundtrip_clears_the_finding",),
        reason="detection matches ^IPV6\\s*=\\s*no (spaces, any case); a literal "
               "^IPV6=no fix is a no-op on the valid variants IPV6 = no / IPV6=NO, "
               "so --fix reports success and the next audit re-raises the finding",
    ),
    Mutation(
        id="fix-lies/umask-shell-single-space",
        file="bob/checks/umask.py",
        old="    return f\"sudo sed -i -E 's/\\\\bumask[[:space:]]+[0-7]+/umask 022/' {source}\"",
        new="    return f\"sudo sed -i -E 's/\\\\bumask [0-7]+/umask 022/' {source}\"",
        kills=("tests/test_v0200_config_fix_matches_detection.py::"
               "TestUmaskFixMatchesDetection::test_shell_file_roundtrip",),
        reason="detection allows \\s+ (a tab, several spaces) between umask and "
               "its value; requiring one literal space makes the fix a no-op on "
               "umask<tab>002, a fix that lies",
    ),
    Mutation(
        id="fix-lies/umask-login-defs-case",
        file="bob/checks/umask.py",
        old="        return \"sudo sed -i 's/^UMASK[[:space:]].*/UMASK\\\\t\\\\t022/I' /etc/login.defs\"",
        new="        return \"sudo sed -i 's/^UMASK[[:space:]].*/UMASK\\\\t\\\\t022/' /etc/login.defs\"",
        kills=("tests/test_v0200_config_fix_matches_detection.py::"
               "TestUmaskFixMatchesDetection::test_login_defs_roundtrip",),
        reason="login.defs is detected case-insensitively (_LOGIN_DEFS_RE has "
               "re.IGNORECASE); dropping the GNU sed I flag makes the fix a no-op "
               "on a lowercase 'umask' line the detection still flags",
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
        old='        _ufw = (f"ufw {info.ufw_version}" if info.ufw_version\n'
            '                else _L.get("not_installed", "not installed"))',
        new='        _ufw = f"ufw {info.ufw_version}"',
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
        old='    restart = service_restart_cmd(ssh_unit())',
        new='    restart = "sudo systemctl restart ssh"',
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
        old='            **sysctl_fix("net.ipv4.tcp_syncookies=1", boot=snapshot.boot_sysctl),',
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
        file="bob/checks/ssh/_directives.py",
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
        old="            for k in _compared(set(prev_bd) | set(curr_bd))\n            if prev_bd.get(k, 0) != curr_bd.get(k, 0)",
        new="            for k in _compared(set(prev_bd) | set(curr_bd))",
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
        old="        if _active_trigger(svc_name):\n            return ServiceState.SOCKET_ACTIVATED\n        if _start_condition_unmet(svc_name):",
        new="        if _start_condition_unmet(svc_name):",
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
    Mutation(
        id="firewalld/firewall-check-ignores-front-end",
        file="bob/checks/firewall.py",
        old="        if firewalld is not None and firewalld.active:",
        new="        if firewalld is not None and firewalld.active and False:",
        kills=("tests/test_v0202_firewalld_recognized.py::TestFirewallCheck::test_firewalld_active_credits_instead_of_alerting",),
        reason="on a firewalld host UFW is legitimately absent; without this "
               "branch BOB alerts 'UFW not installed' on a firewalled Fedora "
               "(measured on 192.168.1.16)",
    ),
    Mutation(
        id="firewalld/raw-policy-reads-firewalled-host-as-wide-open",
        file="bob/checks/iptables_nftables.py",
        old="    if firewalld is not None and firewalld.active:",
        new="    if firewalld is not None and firewalld.active and False:",
        kills=("tests/test_v0202_firewalld_recognized.py::TestIptablesCheck::test_firewalld_active_credits_and_returns",),
        reason="firewalld keeps the base chain policy at ACCEPT and filters in "
               "its zone chains; reading the raw policy without crediting "
               "firewalld calls a firewalled host wide-open",
    ),
    Mutation(
        id="firewalld/own-nft-table-framed-as-parallel-ruleset",
        file="bob/checks/firewall_stack.py",
        old="                    and table_name != \"firewalld\"",
        new="                    and table_name != \"firewalld-disabled\"",
        kills=("tests/test_v0202_firewalld_recognized.py::TestNftTableAttribution::test_firewalld_table_is_not_a_parallel_ruleset",),
        reason="firewalld's own `table inet firewalld` IS the firewall; without "
               "the exclusion BOB frames a firewalld host as 'nftables running "
               "in parallel with UFW'",
    ),
    Mutation(
        id="manage-logs/no-dir-enters-curses-silently",
        file="bob/manage_logs.py",
        old="    if not user_config.get(\"log_dir\"):\n        return _run_manage_logs_plain(user_config, config, t)",
        new="    if user_config.get(\"log_dir\"):\n        return _run_manage_logs_plain(user_config, config, t)",
        kills=("tests/test_manage_logs.py::TestNoLogDirRoutesToPlain::test_no_log_dir_tty_routes_to_plain_not_curses",),
        reason="on a fresh install (no log_dir) the curses path flashes a blank "
               "screen and exits silently; the dispatcher must route to the plain "
               "path that explains 'run an audit first' — inverting the guard sends "
               "it back into curses",
    ),
    Mutation(
        id="completion/hint-shown-when-already-installed",
        file="bob/completion.py",
        old="    return is_tty and not quiet and not completion_installed()",
        new="    return is_tty and not quiet and completion_installed()",
        kills=("tests/test_v0221_completion_hint.py::TestShouldShowCompletionHint::test_shown_when_not_installed_on_tty",),
        reason="the 'run --install-completion' hint must show until completion is "
               "installed, then stop; inverting the test makes BOB nag only after "
               "it is already set up and stay silent when it is actually needed",
    ),
    Mutation(
        id="ipv6/coverage-claimed-when-ufw-v6-disabled",
        file="bob/checks/ipv6.py",
        old="    if snapshot.ufw_ipv6_enabled is True and not found_issue and not firewalld_active and not (",
        new="    if snapshot.ufw_ipv6_enabled is not None and not found_issue and not firewalld_active and not (",
        kills=("tests/test_ipv6.py::TestUfwV6CoverageClaimHonesty::test_disabled_ufw_v6_link_local_does_not_claim_coverage",),
        reason="with UFW IPv6 disabled the listeners are not covered by UFW v6 "
               "rules (there are none); reverting the guard to `is not None` makes "
               "BOB claim 'covered by UFW (v6) rules' right after saying UFW IPv6 "
               "is disabled — the contradiction this fix removes",
    ),
    Mutation(
        id="firewalld/ipv6-gap-warned-though-firewalld-filters-v6",
        file="bob/checks/ipv6.py",
        old="        if snapshot.kernel_ipv6_enabled and snapshot.ufw_ipv6_enabled and firewalld_active:",
        new="        if snapshot.kernel_ipv6_enabled and snapshot.ufw_ipv6_enabled and firewalld_active and False:",
        kills=("tests/test_v0202_firewalld_recognized.py::TestIPv6Coverage::test_both_front_ends_active_no_v6_gap_warning",),
        reason="firewalld applies the same zone rules to IPv6 as IPv4; without "
               "this branch every v6 listener is warned 'no UFW v6 rule' on a "
               "firewalld host and docks the score",
    ),
    Mutation(
        id="firewalld/ports-tells-firewalld-host-to-enable-ufw",
        file="bob/checks/ports.py",
        old="                if firewalld_active:",
        new="                if firewalld_active and False:",
        kills=("tests/test_v0202_firewalld_recognized.py::TestPortsAdvice::test_firewalld_active_reframes_the_advice",),
        reason="'enable UFW to filter it' contradicts the firewall check that "
               "just credited firewalld; the port is governed by firewalld's "
               "default zone",
    ),
    Mutation(
        id="firewalld/service-exposure-says-ufw-inactive-under-firewalld",
        file="bob/checks/services.py",
        old="    if firewalld_active and exposure in (Exposure.NO_RULE, Exposure.LOOPBACK_NO_RULE):",
        new="    if False and exposure in (Exposure.NO_RULE, Exposure.LOOPBACK_NO_RULE):",
        kills=("tests/test_v0202_firewalld_recognized.py::TestServiceExposure::test_firewalld_active_uses_firewalld_exposure_key",),
        reason="on a firewalld host a service with no UFW rule must not read as "
               "'no rule (UFW inactive)', which both misleads and contradicts "
               "the firewall check crediting firewalld",
    ),
    Mutation(
        id="firewalld/banner-omits-firewalld-front-end",
        file="bob/output.py",
        old="        (labels.get(\"firewalld\", \"firewalld\"), firewalld),",
        new="",
        kills=("tests/test_v0202_firewalld_recognized.py::TestHeadlineBanner::test_firewalld_row_is_shown",),
        reason="the header must name firewalld, not only Debian's UFW, so an "
               "RPM/openSUSE operator sees their front-end and version",
    ),
    Mutation(
        id="firewalld/banner-omits-init-manager",
        file="bob/output.py",
        old="        (labels.get(\"init\",     \"Init\"),     init_system),",
        new="",
        kills=("tests/test_v0202_firewalld_recognized.py::TestHeadlineBanner::test_init_row_is_shown",),
        reason="the header must name the service manager (systemd, OpenRC, …) so "
               "a non-systemd host is not read as systemd by default",
    ),
    Mutation(
        id="blindspot/min-level-leaks-direct-info",
        file="bob/output.py",
        old="    if not _passes_threshold(\"info\"):\n        return",
        new="    if False:\n        return",
        kills=("tests/test_v0202_blind_spots.py::TestMinLevelAtPrimitive::test_min_level_warn_keeps_warn_drops_info",),
        reason="--min-level must filter directly-printed INFO too, not only "
               "findings routed through display_result; without the primitive "
               "guard `--min-level warn` leaks every meta INFO line",
    ),
    Mutation(
        id="blindspot/watch-dumps-risk-context-under-quiet",
        file="bob/display.py",
        old="    if not quiet:\n        from bob.output import print_risk_context, print_info",
        new="    if True:\n        from bob.output import print_risk_context, print_info",
        kills=("tests/test_v0202_blind_spots.py::TestRiskContextQuiet::test_quiet_silences_screen_but_keeps_the_archive",),
        reason="watch mode runs quiet; without this gate every cycle dumps the "
               "full multi-line risk block per high/critical service, burying "
               "the terse score+delta line watch exists to show",
    ),
    Mutation(
        id="blindspot/output-dir-error-hardcoded-english",
        file="bob/manage_logs.py",
        old="            print(f\"  ✖ {t('manage_logs.cannot_create_dir', path=d, error=exc)}\")",
        new="            print(f\"  ✖ Cannot create directory {d}: {exc} — falling back to cwd\")",
        kills=("tests/test_v0202_blind_spots.py::TestOutputDirFailureIsLocalised::test_unwritable_output_dir_uses_locale_key_and_falls_back",),
        reason="the mkdir-failure message must be localised like the rest of the "
               "tool; the hardcoded English string broke a French audit's output",
    ),
    Mutation(
        id="profile/active-display-manager-not-read-as-desktop",
        file="bob/sysinfo.py",
        old="    if _run(\"systemctl\", \"is-active\", \"display-manager.service\") == \"active\":\n        return \"desktop\"",
        new="    if _run(\"systemctl\", \"is-active\", \"display-manager.service\") == \"active\":\n        return \"server\"",
        kills=("tests/test_v0203_desktop_profile_autodetect.py::TestDesktopAutodetect::test_active_display_manager_is_desktop",),
        reason="an active display-manager (gdm/lightdm/sddm) is a graphical host "
               "even when get-default is not graphical.target; it must resolve to "
               "the desktop profile",
    ),
    Mutation(
        id="microcode/opensuse-name-unmapped",
        file="bob/checks/_run.py",
        old="\"apk\": \"amd-ucode\", \"zypper\": \"ucode-amd\"}",
        new="\"apk\": \"amd-ucode\", \"zypper\": None}",
        kills=("tests/test_v0204_opensuse_microcode.py::test_opensuse_amd_microcode_name",),
        reason="openSUSE's AMD microcode package is ucode-amd; without the zypper "
               "mapping BOB cannot confirm microcode on openSUSE and the score "
               "becomes an upper bound even when the package is installed",
    ),
    Mutation(
        id="firewalld/rich-rule-port-omitted-from-allows",
        file="bob/checks/_firewalld.py",
        old="            if grant:\n                parts.append(grant)",
        new="            if grant:\n                pass",
        kills=("tests/test_v0204_firewalld_rich_rules.py::TestAllowsSummary::test_allows_summary_surfaces_rich_rule_port",),
        reason="a port opened only through a firewalld accept rich rule would be "
               "absent from the credited 'zone allows' line, hiding real access "
               "from the reader",
    ),
    Mutation(
        id="exposure/ssh-summary-ignores-info-password-auth",
        file="bob/exposure.py",
        old='    elif "ssh.password_auth" in all_keys:',
        new='    elif "ssh.password_auth" in bad_keys:',
        kills=("tests/test_v0205_kali_findings.py::TestSshGlanceSummary::test_password_on_summary_not_key_only",),
        reason="on a LAN/desktop host password auth is INFO, not a bad key; keying "
               "the glance summary off bad_keys makes it fall through to "
               "'key-only, root login disabled' while password auth is enabled — "
               "the summary contradicting its own detailed finding",
    ),
    Mutation(
        id="file_perms/nopasswd-empty-group-not-flagged",
        file="bob/checks/file_perms.py",
        old="            if group and group in snapshot.sudoers_nopasswd_empty_groups:",
        new="            if group and group not in snapshot.sudoers_nopasswd_empty_groups:",
        kills=("tests/test_v0205_kali_findings.py::TestEmptyGroupNopasswd::test_empty_group_message_says_latent",),
        reason="a NOPASSWD:ALL grant to an empty group is latent, not live; without "
               "the empty-group branch the finding implies someone currently holds "
               "passwordless root when the group has no members",
    ),
    Mutation(
        id="faillock/server-lockout-gap-not-flagged",
        file="bob/checks/faillock.py",
        old='    is_desktop = profile_name.lower() in ("desktop", "workstation")',
        new='    is_desktop = profile_name.lower() in ("desktop", "workstation", "server")',
        kills=("tests/test_v0210_faillock.py::TestNotConfigured::test_server_warns_and_deducts",),
        reason="a server with no PAM account lockout is a real brute-force surface "
               "(local logins, su, sudo unthrottled); treating server as desktop "
               "drops the deduction and the WARN",
    ),
    Mutation(
        id="polkit/group-writable-rule-not-flagged",
        file="bob/checks/polkit.py",
        old="    return bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))",
        new="    return False",
        kills=("tests/test_v0210_polkit.py::TestFromSystem::test_group_writable_rule_is_flagged",),
        reason="polkit evaluates rules as root; a group/other-writable rule file "
               "is a privilege-escalation path — ignoring the write bits lets it "
               "pass as clean",
    ),
    Mutation(
        id="disk_encryption/plain-root-read-as-unknown",
        file="bob/checks/disk_encryption.py",
        old="        if root_src.startswith(_REAL_BLOCK_PREFIXES):\n            return False",
        new="        if root_src.startswith(_REAL_BLOCK_PREFIXES):\n            return None",
        kills=("tests/test_v0210_disk_encryption.py::TestFromSystem::test_plain_root_is_false",),
        reason="a root on a raw partition is a firm 'not encrypted' (a crypt root "
               "always mounts through its mapper); reading it as unknown hides an "
               "unencrypted disk behind an INFO instead of the desktop WARN",
    ),
    Mutation(
        id="kexec_lockdown/locked-read-as-not-locked",
        file="bob/checks/kexec_lockdown.py",
        old="    if snapshot.kexec_disabled == 1:",
        new="    if snapshot.kexec_disabled == 0:",
        kills=("tests/test_v0210_kexec_lockdown.py::TestKexec::test_locked_is_ok",),
        reason="kexec_load_disabled=1 means kexec is locked for the uptime; "
               "reading 1 as anything but locked inverts the boot-integrity "
               "verdict for a hardened host",
    ),
    Mutation(
        id="core_dumps/storage-none-not-recognised-disabled",
        file="bob/checks/core_dumps.py",
        old='    if snapshot.hard_core_zero or (is_systemd and snapshot.storage == "none"):',
        new='    if snapshot.hard_core_zero or (is_systemd and snapshot.storage == "never"):',
        kills=("tests/test_v0210_core_dumps.py::TestDisposition::test_systemd_storage_none_is_disabled",),
        reason="systemd-coredump Storage=none discards dumps; not recognising it "
               "makes BOB report a host that discards core dumps as one that keeps "
               "them, inverting the disposition",
    ),
    Mutation(
        id="mount_hardening/loose-options-not-flagged",
        file="bob/checks/mount_hardening.py",
        old='        missing_hard = [o for o in ("nodev", "nosuid") if o not in m.options]',
        new='        missing_hard = [o for o in ("nodev", "nosuid") if o in m.options]',
        kills=("tests/test_v0210_mount_hardening.py::TestOptions::test_missing_nodev_nosuid_warns_and_deducts",),
        reason="a world-writable scratch mount missing nodev/nosuid honours device "
               "nodes and set-uid binaries dropped there; inverting the membership "
               "test means BOB credits an unprotected /tmp as hardened",
    ),
    Mutation(
        id="root_path/world-writable-component-not-flagged",
        file="bob/checks/root_path.py",
        old="    if st.st_mode & _stat.S_IWOTH:",
        new="    if st.st_mode & 0:",
        kills=("tests/test_v0220_root_path.py::TestFromSystem::test_world_writable_component_from_login_defs",),
        reason="a world-writable directory in root's PATH lets any user plant a "
               "binary root will run; zeroing the world-write mask means BOB "
               "treats it as a safe directory and the privesc goes unreported",
    ),
    Mutation(
        id="suid_audit/writable-setid-not-flagged",
        file="bob/checks/suid_audit.py",
        old="                    if (has_suid or has_sgid) and (\n                            mode & (stat.S_IWGRP | stat.S_IWOTH)):",
        new="                    if (has_suid or has_sgid) and (\n                            mode & 0):",
        kills=("tests/test_suid_audit.py::TestWritableSuid::test_from_system_flags_group_or_other_writable",),
        reason="a group/other-writable set-id binary is an immediate local root; "
               "zeroing the write-bit mask means BOB never collects it and the "
               "most severe SUID finding silently disappears",
    ),
    Mutation(
        id="kexec_lockdown/module-sig-enforced-misread",
        file="bob/checks/kexec_lockdown.py",
        old='    elif snapshot.sig_enforce == "Y":',
        new='    elif snapshot.sig_enforce == "N":',
        kills=("tests/test_v0210_kexec_lockdown.py::TestModuleTrust::test_sig_enforced_is_ok",),
        reason="module.sig_enforce=Y means the kernel refuses unsigned modules; "
               "misreading it as anything but enforced drops the one positive "
               "signal that unsigned-module loading is closed off",
    ),
    Mutation(
        id="password_policy/md5-hash-not-weak",
        file="bob/checks/password_policy.py",
        old='_WEAK_HASHES   = frozenset({"MD5", "DES", "BIGCRYPT"})',
        new='_WEAK_HASHES   = frozenset({"DES", "BIGCRYPT"})',
        kills=("tests/test_v0240_password_hash.py::"
               "test_weak_algorithm_on_either_source_deducts[MD5-encrypt_method]",),
        reason="ENCRYPT_METHOD MD5 makes every account useradd creates crackable "
               "offline in hours once /etc/shadow leaks; it must not pass unscored",
    ),
    Mutation(
        id="password_policy/pam-unix-hash-hidden-behind-quality-module",
        file="bob/checks/password_policy.py",
        old=("        # above stops at the quality module — so look for it on its own.\n"
             "        if pam_text:"),
        new=("        # above stops at the quality module — so look for it on its own.\n"
             "        if pam_text and snap.pam_quality_module is None:"),
        kills=("tests/test_v0240_password_hash.py::"
               "test_from_system_reads_pam_unix_hash_after_quality_module",),
        reason="every stock PAM stack puts pam_pwquality before pam_unix; reading "
               "the hash only when no quality module came first goes blind to "
               "passwd's algorithm on exactly the hosts that are configured",
    ),
    Mutation(
        id="file_capabilities/setuid-not-root-equivalent",
        file="bob/checks/file_capabilities.py",
        old='    "chown", "dac_override", "dac_read_search", "fowner", "setuid", "setgid",',
        new='    "chown", "dac_override", "dac_read_search", "fowner", "setgid",',
        kills=("tests/test_v0240_file_capabilities.py::TestClassify::"
               "test_setuid_on_an_interpreter_deducts",),
        reason="cap_setuid+ep on python3 is a root shell for every local user — "
               "the classic persistence trick the SUID audit cannot see",
    ),
    Mutation(
        id="file_capabilities/known-name-trusted-whatever-it-carries",
        file="bob/checks/file_capabilities.py",
        old="        if allowed is not None and caps <= allowed:",
        new="        if allowed is not None:",
        kills=("tests/test_v0240_file_capabilities.py::TestClassify::"
               "test_known_name_with_more_than_its_set_is_not_known",),
        reason="trusting the basename alone lets anyone hide cap_setuid on a "
               "file called ping",
    ),
    Mutation(
        id="file_capabilities/partial-walk-claims-clean",
        file="bob/checks/file_capabilities.py",
        old="    elif not dangerous and not unexpected:",
        new="    if not dangerous and not unexpected:",
        kills=("tests/test_v0240_file_capabilities.py::TestClassify::"
               "test_partial_walk_never_claims_clean",),
        reason="'no unexpected capability' quantifies over every file; a walk "
               "that skipped a directory has not seen every file",
    ),
    Mutation(
        id="user_accounts/pam-wheel-trust-read-as-restriction",
        file="bob/checks/user_accounts.py",
        old='            fails = ctl in ("required", "requisite")',
        new='            fails = ctl in ("required", "requisite", "sufficient")',
        kills=("tests/test_v0240_account_hygiene.py::test_non_restricting_lines",),
        reason="'auth sufficient pam_wheel.so trust' lets wheel members su with "
               "no password at all; reading it as a restriction calls the "
               "weakest su configuration the hardened one",
    ),
    Mutation(
        id="user_accounts/star-root-read-as-unlocked",
        file="bob/checks/user_accounts.py",
        old='                snap.root_locked = pw_hash.startswith(("!", "*"))',
        new='                snap.root_locked = pw_hash.startswith("!")',
        kills=("tests/test_v0240_account_hygiene.py::TestSuCollection::test_root_lock_state",),
        reason="'*' is how Debian-family installers lock root; missing it scores "
               "an unrestricted su on hosts where su to root is impossible",
    ),
    Mutation(
        id="user_accounts/network-home-statted",
        file="bob/checks/user_accounts.py",
        old='_BLOCKING_FS = _NETWORK_FS_TYPES | {"autofs"}',
        new='_BLOCKING_FS = frozenset()',
        kills=("tests/test_v0240_account_hygiene.py::TestHomes::test_network_home_is_not_statted",),
        reason="stat() on a home whose NFS server is gone blocks in the kernel — "
               "the audit hangs, the FIFO lesson on another file type",
    ),
    Mutation(
        id="user_accounts/netrc-group-read-ignored",
        file="bob/checks/user_accounts.py",
        old="                    if _stat.S_ISREG(lst.st_mode) and lst.st_mode & 0o077:",
        new="                    if _stat.S_ISREG(lst.st_mode) and lst.st_mode & 0o007:",
        kills=("tests/test_v0240_account_hygiene.py::TestHomes::test_netrc_mode",),
        reason="a group-readable .netrc hands its clear-text passwords to every "
               "member of the group",
    ),
    Mutation(
        id="kernel_hardening/absent-userns-clone-read-as-restricted",
        file="bob/checks/kernel_hardening.py",
        old="    elif snapshot.userns_clone == 0:",
        new="    elif not snapshot.userns_clone:",
        kills=("tests/test_v0240_kernel_attack_surface.py::"
               "test_distro_specific_userns_knobs_absent_is_not_unavailable",),
        reason="unprivileged_userns_clone is a Debian patch; on Fedora or Arch it "
               "does not exist, and reading None as 0 claims a restriction "
               "nothing on the host enforces",
    ),
    Mutation(
        id="kernel_hardening/perf-paranoid-one-read-as-restricted",
        file="bob/checks/kernel_hardening.py",
        old="    elif snapshot.perf_paranoid >= 2:",
        new="    elif snapshot.perf_paranoid >= 1:",
        kills=("tests/test_v0240_kernel_attack_surface.py::test_perf_permissive_is_info",),
        reason="at 1 users can still profile the kernel; calling it restricted "
               "hides the exposure the finding exists to name",
    ),
    Mutation(
        id="kernel_hardening/unprivileged-bpf-zero-read-as-disabled",
        file="bob/checks/kernel_hardening.py",
        old="    elif snapshot.bpf_unpriv_disabled >= 1:",
        new="    elif snapshot.bpf_unpriv_disabled >= 0:",
        kills=("tests/test_v0240_kernel_attack_surface.py::test_bpf_allowed_is_info_with_fix",),
        reason="0 means any user can load eBPF programs — the verifier-bug LPE surface",
    ),
    Mutation(
        id="cpu_security/smt-note-read-as-vulnerable",
        file="bob/checks/cpu_security.py",
        old='    if status.startswith("Vulnerable"):',
        new='    if "vulnerable" in status.lower():',
        kills=("tests/test_v0240_cpu_security.py::test_smt_exposed_is_mitigated_not_vulnerable",),
        reason="'Mitigation: …; SMT vulnerable' is a mitigated flaw with an SMT "
               "caveat; a substring match scores every hyper-threaded Intel host",
    ),
    Mutation(
        id="cpu_security/undetermined-status-counted-clean",
        file="bob/checks/cpu_security.py",
        old='        if not vulnerable and not groups.get("unknown"):',
        new='        if not vulnerable:',
        kills=("tests/test_v0240_cpu_security.py::test_undetermined_status_blocks_the_ok",),
        reason="'Unknown: Dependent on hypervisor status' is the kernel declining "
               "to answer; an OK over it claims what nobody measured",
    ),
    Mutation(
        id="package_authenticity/repo-metadata-check-read-as-package-check",
        file="bob/checks/package_authenticity.py",
        old='_INI_KEYS = {"gpgcheck", "pkg_gpgcheck"}',
        new='_INI_KEYS = {"gpgcheck", "pkg_gpgcheck", "repo_gpgcheck"}',
        kills=("tests/test_v0240_package_authenticity_crypto_policy.py::"
               "test_dnf_gpgcheck_off_on_enabled_repo",),
        reason="repo_gpgcheck=0 is the stock setting on most dnf repos and concerns "
               "metadata, not packages; flagging it scores every Fedora host",
    ),
    Mutation(
        id="package_authenticity/apt-conf-comment-read-as-setting",
        file="bob/checks/package_authenticity.py",
        old='                s = line.split("//", 1)[0].strip()',
        new='                s = line.strip()',
        kills=("tests/test_v0240_package_authenticity_crypto_policy.py::"
               "test_apt_non_switches_stay_clean",),
        reason="a commented-out AllowUnauthenticated is the fix already applied; "
               "reporting it accuses the host of the opposite",
    ),
    Mutation(
        id="crypto_policy/edited-config-judged-over-applied-state",
        file="bob/checks/crypto_policy.py",
        old='    policy = snapshot.applied or snapshot.configured or ""',
        new='    policy = snapshot.configured or snapshot.applied or ""',
        kills=("tests/test_v0240_package_authenticity_crypto_policy.py::"
               "test_applied_legacy_deducts_even_if_config_says_default",),
        reason="the libraries use the applied policy; editing config without "
               "running update-crypto-policies changes nothing they do",
    ),
    Mutation(
        id="package_authenticity/pacman-optional-siglevel-trusted",
        file="bob/checks/package_authenticity.py",
        old='                if tok in ("Never", "PackageNever", "Optional", "PackageOptional"):',
        new='                if tok in ("Never", "PackageNever"):',
        kills=("tests/test_v0240_package_authenticity_crypto_policy.py::test_pacman_weak_siglevel",),
        reason="SigLevel = Optional installs an unsigned package without a word — "
               "against a tampering mirror it is the same as Never",
    ),
    Mutation(
        id="world_writable/sticky-directory-reported",
        file="bob/checks/world_writable.py",
        old='''        tail = ["(", "-type", "f", "-perm", "-0002", "-printf", "F %p\\\\0", ")", "-o",
                "(", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000",''',
        new='''        tail = ["(", "-type", "f", "-perm", "-0002", "-printf", "F %p\\\\0", ")", "-o",
                "(", "-type", "d", "-perm", "-0002",''',
        kills=("tests/test_v0240_world_writable.py::test_sweep_finds_the_right_things",),
        reason="a sticky world-writable directory is /tmp's shape — reporting it "
               "lists every /var/tmp and shared spool on every host",
    ),
    Mutation(
        id="world_writable/tmpfs-swept",
        file="bob/checks/world_writable.py",
        old='_SKIP_FS = _PSEUDO_FS_TYPES | _NETWORK_FS_TYPES | {"autofs"}',
        new='_SKIP_FS = _NETWORK_FS_TYPES | {"autofs"}',
        kills=("tests/test_v0240_world_writable.py::test_only_local_disk_filesystems_are_roots",),
        reason="sweeping proc, sysfs and tmpfs reports kernel files and /dev/shm "
               "scratch as host misconfiguration",
    ),
    Mutation(
        id="world_writable/busybox-unowned-read-as-none",
        file="bob/checks/world_writable.py",
        old="        snap.unowned_assessed = gnu",
        new="        snap.unowned_assessed = True",
        kills=("tests/test_v0240_world_writable.py::test_sweep_finds_the_right_things",),
        reason="BusyBox find cannot ask -nouser; claiming no unowned files on "
               "Alpine is an answer to a question that was never asked",
    ),
    Mutation(
        id="completion/already-linked-reported-not-found",
        file="bob/completion.py",
        old="                already_linked = True",
        new="                pass",
        kills=("tests/test_v0240_install_completion_symlink.py::"
               "test_already_linked_says_so_and_leaves_it",),
        reason="the field-reported bug: a correctly linked bob was announced as "
               "'not found in ~/.local/bin' on every second run",
    ),
    Mutation(
        id="exposure/lan-bound-port-left-out-of-surface",
        file="bob/exposure.py",
        old="                or (is_specific_unicast(lp) and not is_system_internal(lp)))",
        new="                or False)",
        kills=("tests/test_v0240_critique_fixes.py::test_lan_bound_samba_is_in_the_summary",),
        reason="Samba bound to 192.168.1.10 is as reachable from the LAN as 0.0.0.0; "
               "the summary omitted it while the detail called it exposed",
    ),
    Mutation(
        id="exposure/libvirt-dnsmasq-counted-as-surface",
        file="bob/exposure.py",
        old="                or (is_specific_unicast(lp) and not is_system_internal(lp)))",
        new="                or is_specific_unicast(lp))",
        kills=("tests/test_v0240_critique_fixes.py::test_libvirt_dnsmasq_on_its_bridge_is_not_surface",),
        reason="libvirt's dnsmasq on its own bridge address is system plumbing "
               "check_ports already calls internal; listing it inflates the surface",
    ),
    Mutation(
        id="exposure/inconsistent-apt-called-stale",
        file="bob/exposure.py",
        old='               else "exposure.updates_inconsistent")',
        new='               else "exposure.updates_unknown")',
        kills=("tests/test_v0240_critique_fixes.py::test_updates_line_names_the_measured_cause",),
        reason="the line said 'stale' beside a cache reported 0 days old",
    ),
    Mutation(
        id="package_authenticity/apt-called-package-signatures",
        file="bob/checks/package_authenticity.py",
        old='    "apt": "package_authenticity.mechanism_apt", "apt-get": "package_authenticity.mechanism_apt",',
        new='    "apt": "package_authenticity.mechanism_rpm", "apt-get": "package_authenticity.mechanism_apt",',
        kills=("tests/test_v0240_package_authenticity_crypto_policy.py::"
               "test_the_message_names_what_the_manager_verifies",),
        reason="apt authenticates a signed index; no .deb carries a signature — "
               "'package signatures enforced' claimed a check apt never makes",
    ),
    Mutation(
        id="user_accounts/su-group-execute-read-as-mode-restriction",
        file="bob/checks/user_accounts.py",
        old="            if _stat.S_ISREG(st.st_mode) and not st.st_mode & _stat.S_IXOTH:",
        new="            if _stat.S_ISREG(st.st_mode) and not st.st_mode & _stat.S_IXGRP:",
        kills=("tests/test_v0240_account_hygiene.py::TestSuCollection::"
               "test_su_binary_not_executable_by_others_is_a_restriction",),
        reason="4750 root:sugroup restricts su to the group by denying *others*; "
               "testing the group bit inverts the meaning",
    ),
    Mutation(
        id="world_writable/unknown-parent-claimed-shut",
        file="bob/checks/world_writable.py",
        old=("        return bool(os.stat(directory).st_mode & stat.S_IXOTH)\n"
             "    except OSError:\n"
             "        return True"),
        new=("        return bool(os.stat(directory).st_mode & stat.S_IXOTH)\n"
             "    except OSError:\n"
             "        return False"),
        kills=("tests/test_v0240_world_writable.py::test_unknown_parent_is_never_claimed_shut",),
        reason="a parent BOB could not stat is not proof the path is unreachable; "
               "calling it latent hides a writable file behind BOB's own blindness",
    ),
    Mutation(
        id="services/umbrella-with-running-instance-read-as-stopped",
        file="bob/checks/services.py",
        old="    if is_active and _is_noop_umbrella(svc_name) and not _has_active_instance(svc_name):",
        new="    if is_active and _is_noop_umbrella(svc_name):",
        kills=("tests/test_v0240_critique_fixes.py::"
               "test_umbrella_with_a_running_instance_stays_active",),
        reason="postfix.service is a /bin/true umbrella too, but postfix@-.service "
               "runs master on :25 — the first version of this fix reported a "
               "listening MTA as stopped (caught on the author's own desktop)",
    ),
    Mutation(
        id="services/any-exited-oneshot-read-as-umbrella",
        file="bob/checks/services.py",
        old='    return bool(m) and os.path.basename(m.group(1)) == "true"',
        new='    return bool(m)',
        kills=("tests/test_v0240_critique_fixes.py::test_real_services_are_unaffected",),
        reason="iptables-restore-style oneshots do real work and stay active "
               "(exited); only a `true` umbrella starts nothing",
    ),
    Mutation(
        id="display/unread-sections-not-named",
        file="bob/display.py",
        old=("        if engine.unverified:\n"
             "            print()\n"
             "            print(f\"  ℹ {t('summary.visibility_sections'"),
        new=("        if not engine.unverified:\n"
             "            print()\n"
             "            print(f\"  ℹ {t('summary.visibility_sections'"),
        kills=("tests/test_v0240_critique_fixes.py::test_unread_sections_are_named_below_the_box",),
        reason="'2 sections not fully read' with no names could not be checked "
               "against the report — a reviewer counted one and called it a bug",
    ),
    Mutation(
        id="firmware/unknown-secure-boot-read-as-off",
        file="bob/checks/firmware.py",
        old='        if dbx_only and snapshot.secure_boot_state == "disabled":',
        new='        if dbx_only and snapshot.secure_boot_state != "enabled":',
        kills=("tests/test_v0240_critique_fixes.py::test_other_cases_still_deduct",),
        reason="an unread Secure Boot state is not a disabled one; dropping the "
               "deduction there trades a measured gap for an assumption",
    ),
    Mutation(
        id="ports/dhcp-client-counted-as-service",
        file="bob/checks/ports.py",
        old='    "dhcpcd", "dhclient", "udhcpc",\n',
        new='    "dhclient", "udhcpc",\n',
        kills=("tests/test_v0240_critique_fixes.py::test_dhcp_clients_are_system_internal",),
        reason="dhcpcd binds 68/udp to the leased address; as a 'service' it was "
               "listed as attack surface on every Debian 13 host",
    ),
    Mutation(
        id="ports/lan-bound-port-called-localhost",
        file="bob/checks/ports.py",
        old="            if bound.is_loopback:",
        new="            if not bound.is_all_interfaces:",
        kills=("tests/test_v0240_critique_fixes.py::test_lan_bound_port_is_not_called_localhost",),
        reason="a port bound to 192.168.1.13 on a host with no firewall is reachable "
               "from the LAN; 'localhost only — no external exposure' was false",
    ),
    Mutation(
        id="ports/first-listed-binding-wins",
        file="bob/checks/ports.py",
        old="                          if lp.port_proto == pp and not lp.is_loopback), lport)",
        new="                          if lp.port_proto == pp and lp is lport), lport)",
        kills=("tests/test_v0240_critique_fixes.py::test_lan_binding_wins_over_loopback_listed_first",),
        reason="a port on 127.0.0.1 and a LAN address was described by whichever "
               "socket ss printed first — the loopback one hid the reachable one",
    ),
    Mutation(
        id="ports/bound-address-called-reachable-behind-default-deny",
        file="bob/checks/ports.py",
        old='                if ufw_active and default_incoming_policy in ("deny", "reject"):',
        new='                if False:',
        kills=("tests/test_v0240_critique_fixes.py::"
               "test_lan_bound_port_reachability_follows_the_firewall",),
        reason="behind an active default-deny UFW a LAN-bound port is blocked; "
               "'reachable from that network' (the first wording of this fix) was false",
    ),
    Mutation(
        id="runner/slow-section-silently-skipped",
        file="bob/runner.py",
        old="                _sec(_slow, lambda: None, _requires_exhaustive, section_name=_slow)",
        new="                pass",
        kills=("tests/test_v0240_critique_fixes.py::test_the_hint_is_wired_into_the_runner",),
        reason="an explicit --check=world_writable without --exhaustive printed "
               "nothing — a request silently ignored (Mint stress pass)",
    ),
    Mutation(
        id="password_policy/unreadable-login-defs-silent",
        file="bob/checks/password_policy.py",
        old=("            except OSError:\n"
             "                snap.login_defs_unreadable = True"),
        new=("            except OSError:\n"
             "                pass"),
        kills=("tests/test_v0240_password_hash.py::"
               "test_unreadable_login_defs_withholds_strong_and_says_so",),
        reason="a FIFO at /etc/login.defs left expiry unchecked without a word and "
               "the hashing verdict said 'strong' from pam_unix alone (Mint stress pass)",
    ),
    Mutation(
        id="cpu_security/absent-interface-counted-as-blindness",
        file="bob/checks/cpu_security.py",
        old=("        except FileNotFoundError:\n"
             "            snap.not_reported = True\n"),
        new=("        except FileNotFoundError:\n"
             "            pass\n"),
        kills=("tests/test_v0240_cpu_security.py::"
               "test_from_system_missing_directory_is_not_reported_not_unknown",),
        reason="the Pi Zero's ARMv6 kernel has no vulnerabilities interface; counting "
               "that as an unread section capped every Pi audit's score for good",
    ),
    Mutation(
        id="password_policy/last-pam-stack-hides-weak-hash",
        file="bob/checks/password_policy.py",
        old=("                    if (snap.pam_unix_hash is None\n"
             "                            or _hash_rank(algo) < _hash_rank(snap.pam_unix_hash)):\n"),
        new=("                    if True:\n"),
        kills=("tests/test_v0240_password_hash.py::test_weakest_pam_unix_wins_across_stacks",),
        reason="Fedora reads system-auth then password-auth; last-one-read let "
               "password-auth's yescrypt hide md5 in system-auth (real Fedora 44)",
    ),
    Mutation(
        id="package_authenticity/vendor-zypp-conf-ignored",
        file="bob/checks/package_authenticity.py",
        old='_ZYPP_MAIN = (Path("/etc/zypp/zypp.conf"), Path("/usr/etc/zypp/zypp.conf"))',
        new='_ZYPP_MAIN = (Path("/etc/zypp/zypp.conf"),)',
        kills=("tests/test_v0240_package_authenticity_crypto_policy.py::"
               "test_zypper_main_conf_paths_are_etc_then_vendor",),
        reason="openSUSE Leap 16 keeps zypp.conf in /usr/etc; without an /etc "
               "override BOB read nothing and called the host clean",
    ),
    Mutation(
        id="password_policy/vendor-login-defs-hides-unread-override",
        file="bob/checks/password_policy.py",
        old="    if snapshot.login_defs_unreadable:\n        result.info(message=_t(\"password_policy.login_defs_unreadable\"),",
        new="    if snapshot.login_defs_unreadable and not snapshot.login_defs_readable:\n        result.info(message=_t(\"password_policy.login_defs_unreadable\"),",
        kills=("tests/test_v0240_password_hash.py::"
               "test_unreadable_etc_override_is_reported_even_if_vendor_read",),
        reason="on openSUSE the vendor /usr/etc/login.defs was read and called strong "
               "while the admin's /etc override sat unread (the Mint fix's blind spot)",
    ),
    Mutation(
        id="user_accounts/busybox-su-read-through-pam",
        file="bob/checks/user_accounts.py",
        old="            self.su_busybox = os.path.basename(os.path.realpath(binary)) in _BUSYBOX_NAMES\n",
        new="            self.su_busybox = False\n",
        kills=("tests/test_v0240_account_hygiene.py::test_busybox_su_ignores_a_pam_wheel_line",),
        reason="BusyBox su ignores PAM; reading Alpine's /usr/lib/pam.d/su turns a "
               "pam_wheel line nobody enforces into 'su restricted' — a false OK",
    ),
    Mutation(
        id="package_authenticity/apk-not-assessed",
        file="bob/checks/package_authenticity.py",
        old="        elif m == \"apk\":\n            snap._apk()\n",
        new="",
        kills=("tests/test_v0240_package_authenticity_crypto_policy.py::test_apk_config_allow_untrusted",),
        reason="apk-tools 3 honours a persistent allow-untrusted in /etc/apk/config; "
               "'not assessed' capped every Alpine score and missed the switch",
    ),
    Mutation(
        id="password_policy/bbsuid-passwd-not-recognised",
        file="bob/checks/password_policy.py",
        old='                                       in ("busybox", "bbsuid"))',
        new='                                       in ("busybox",))',
        kills=("tests/test_v0240_password_hash.py::test_busybox_passwd_detected_through_the_symlink",),
        reason="Alpine's passwd resolves to /bin/bbsuid, not /bin/busybox; matching "
               "busybox alone left every Alpine with a permanent 'unknown' hash",
    ),
    Mutation(
        id="run/wedged-package-manager-asked-every-time",
        file="bob/checks/_run.py",
        old="        if not _command_exists(tool) or tool in _WEDGED_MANAGERS:\n",
        new="        if not _command_exists(tool):\n",
        kills=("tests/test_v0240_critique_fixes.py::test_a_wedged_package_manager_is_asked_once",),
        reason="apk blocked on a FIFO config: ~40 registry lookups × 10 s = 623 s "
               "for one audit on a real Alpine (stress pass, 2026-10-04)",
    ),
    Mutation(
        id="mount_hardening/hidepid-off-read-as-restricted",
        file="bob/checks/mount_hardening.py",
        old='        if level in ("invisible", "ptraceable"):',
        new='        if level in ("invisible", "ptraceable", "off"):',
        kills=("tests/test_v0240_proc_hidepid.py::"
               "test_absent_or_zero_is_off_not_restricted",),
        reason="a /proc without hidepid lets every user list every process; "
               "calling that restricted is an OK nothing on the host enforces",
    ),
    Mutation(
        id="hardening/fifos-level-two-read-as-disabled",
        file="bob/checks/hardening.py",
        old='protected_fifos             = _read_sysctl_int("fs.protected_fifos")',
        new='protected_fifos             = _read_sysctl_bool("fs.protected_fifos")',
        kills=("tests/test_v0240_protected_fifos_regular.py::TestFromSystemReadsTwoAsTwo::"
               "test_level_two_survives_the_read",),
        reason="fs.protected_fifos takes 0/1/2; the bool reader treats only '1' as "
               "set, so the stronger value 2 would be read as disabled and flagged",
    ),
    Mutation(
        id="hardening/regular-disabled-read-as-ok",
        file="bob/checks/hardening.py",
        old="    elif snapshot.protected_regular >= 1:",
        new="    elif snapshot.protected_regular >= 0:",
        kills=("tests/test_v0240_protected_fifos_regular.py::TestLevels::"
               "test_zero_is_a_deducting_warning",),
        reason="protected_regular=0 leaves the /tmp O_CREAT race open; reading 0 "
               "as protected would hand out an OK the kernel is not enforcing",
    ),
    Mutation(
        id="package_integrity/config-files-reported-as-tampered",
        file="bob/checks/package_integrity.py",
        old='        if ftype in ("c", "d", "g", "l", "r"):',
        new='        if ftype in ("d", "g", "l", "r"):',
        kills=("tests/test_v0230_package_integrity.py::TestRpmParser::"
               "test_config_marked_c_is_excluded",),
        reason="config files are expected to be edited; reporting rpm's 'c' lines "
               "as tampering would bury the real signal under every admin's "
               "customised /etc under noise",
    ),
    Mutation(
        id="package_integrity/tool-missing-read-as-clean",
        file="bob/checks/package_integrity.py",
        old="    if not snapshot.tool_available:",
        new="    if False:",
        kills=("tests/test_v0230_package_integrity.py::TestCheckLogic::"
               "test_tool_missing_is_not_clean",),
        reason="a missing verifier means integrity was not checked, not that it "
               "passed; falling through to 'clean' manufactures an all-clear BOB "
               "never earned (unknown != clean)",
    ),
    Mutation(
        id="module_blacklist/candidate-not-flagged",
        file="bob/checks/module_blacklist.py",
        old="        if m not in snapshot.loaded and m not in snapshot.disabled",
        new="        if m in snapshot.loaded and m not in snapshot.disabled",
        kills=("tests/test_v0220_module_blacklist.py::TestCandidates::test_unblacklisted_module_is_flagged",),
        reason="a rarely-needed module that is neither loaded nor blacklisted is the "
               "whole point of the check; requiring it to be loaded before it can be "
               "a candidate means BOB stops reporting the un-blacklisted modules it "
               "exists to surface",
    ),
    Mutation(
        id="dev_privileged/world-access-not-flagged",
        file="bob/checks/dev_privileged.py",
        old="            if how is not None:",
        new="            if how is None:",
        kills=("tests/test_v0220_dev_privileged.py::TestFromSystem::test_world_writable_block_device_flagged",),
        reason="a world-writable raw disk or /dev/mem hands any user a way around "
               "filesystem permissions; inverting the world-access test makes BOB "
               "record the locked-down nodes and drop the exposed ones it exists "
               "to surface",
    ),
    Mutation(
        id="cups/exposed-listen-not-flagged",
        file="bob/checks/cups.py",
        old="                if not _is_loopback_listen(val):",
        new="                if _is_loopback_listen(val):",
        kills=("tests/test_v0210_cups_service.py::TestFromSystemParsing::test_non_loopback_listen_is_detected",),
        reason="a cupsd Listen on a routable address exposes the print service to "
               "the network; inverting the loopback test means BOB credits an "
               "exposed cupsd as localhost-only",
    ),
    Mutation(
        id="grub/loose-perms-not-flagged",
        file="bob/checks/grub.py",
        old="        group_other = mode & 0o077",
        new="        group_other = mode & 0o000",
        kills=("tests/test_v0210_grub_bootloader.py::TestPermissions::test_group_or_world_readable_warns_and_deducts",),
        reason="a group/world-readable grub.cfg discloses the boot line and any "
               "GRUB password hash; masking the group/other bits means BOB never "
               "flags a loose bootloader config (CIS §1.4.1)",
    ),
    Mutation(
        id="versioning/help-header-readds-v-prefix",
        file="bob/cli.py",
        old="    print(f\"BOB {version} — {t('help.tagline')}\")",
        new="    print(f\"BOB v{version} — {t('help.tagline')}\")",
        kills=("tests/test_v0210_semver_no_v_prefix.py::test_help_header_has_no_v_prefix",),
        reason="SemVer: BOB's own version prints with no 'v' prefix from v0.21.0; "
               "re-adding it makes the displayed version diverge from what PyPI "
               "and SemVer call it",
    ),
    Mutation(
        id="versioning/markdown-report-readds-v-to-tool-version",
        file="bob/report_markdown.py",
        old='_ufw = f"{info.ufw_version}" if info.ufw_version else "not installed"',
        new='_ufw = f"v{info.ufw_version}" if info.ufw_version else "not installed"',
        kills=("tests/test_v0210_semver_no_v_prefix.py::test_markdown_report_does_not_prepend_v_to_the_tool_version",),
        reason="CONVENTIONS §8: third-party tool versions (ufw/firewalld) are shown "
               "bare too; the Markdown report prepended a 'v' the terminal report "
               "did not — the de-v pass missed this surface",
    ),
    Mutation(
        id="updates/no-security-channel-not-flagged",
        file="bob/checks/updates.py",
        old="        if not snapshot.security_channel_present:",
        new="        if snapshot.security_channel_present:",
        kills=("tests/test_v0205_kali_findings.py::TestNoSecurityChannelUpdates::test_no_channel_emits_no_security_channel_finding",),
        reason="on a rolling distro with no security channel (Kali, Arch, Alpine) "
               "pending updates cannot be classified as security; without this "
               "branch the glance reads 'security up to date' while updates wait — "
               "false reassurance measured on real Kali (1335 pending)",
    ),
    Mutation(
        id="snap/timer-flagged-as-manually-created",
        file="bob/checks/systemd_timers.py",
        old="        and not timer_name.startswith(\"snap.\")",
        new="        and not timer_name.startswith(\"snap.DISABLED\")",
        kills=("tests/test_v0203_snap_timer_not_manual.py::test_snap_timer_is_not_manual",),
        reason="snapd writes its timers into /etc/systemd/system/ like a hand-added "
               "unit; without the snap.* exclusion every snap's timers are listed "
               "as 'manually created root timers' (noise, measured on Ubuntu 26.04)",
    ),
    Mutation(
        id="podman/container-audit-is-docker-only",
        file="bob/checks/docker_audit.py",
        old="        runtime = next((rt for rt in _RUNTIMES if _command_exists(rt)), \"\")",
        new="        runtime = next((rt for rt in (\"docker\",) if _command_exists(rt)), \"\")",
        kills=("tests/test_v0203_podman_container_audit.py::TestPodmanAudit::test_podman_only_is_scanned",),
        reason="a Podman host must be scanned for privileged/host-network/root "
               "containers too; scanning only docker left a `podman run "
               "--privileged` container invisible (measured on real Fedora 44)",
    ),
    Mutation(
        id="snap/service-state-ignores-snap-units",
        file="bob/checks/services.py",
        old="    if getattr(service.detection, \"snap\", None):\n        snap_state = _snap_service_state(service)",
        new="    if False:\n        snap_state = _snap_service_state(service)",
        kills=("tests/test_v0203_snap_service_state.py::test_active_snap_service_reads_active",),
        reason="a snap-packaged service runs under snap.<pkg>.* units, not its "
               "deb-style names; without consulting them BOB reports a serving "
               "snap (Nextcloud on 9090/80) as 'installed but not running'",
    ),
    Mutation(
        id="blindspot/static-service-active-socket-read-as-stopped",
        file="bob/checks/services.py",
        old="        if _active_trigger(svc_name):\n            return ServiceState.SOCKET_ACTIVATED\n        return ServiceState.INACTIVE_DISABLED",
        new="        if False:\n            return ServiceState.SOCKET_ACTIVATED\n        return ServiceState.INACTIVE_DISABLED",
        kills=("tests/test_v0202_socket_activated_static.py::test_static_inactive_service_with_active_socket_is_socket_activated",),
        reason="a static/disabled .service reachable through an active .socket "
               "(cockpit.service static + cockpit.socket listening on 9090) must "
               "read as socket-activated, not stopped — else a reachable web "
               "admin interface reads as 'inactive, nothing listening'",
    ),
    Mutation(
        id='posture/firewalld-target-never-read',
        file='bob/checks/_firewalld.py',
        old='''                       rich_rules=rich, forward_ports=fwd, sources=sources,
                       target=m.group(1) if m else "",''',
        new='''                       rich_rules=rich, forward_ports=fwd, sources=sources,
                       target="",''',
        kills=('tests/test_v0241_firewall_posture.py::TestFirewalldTarget::test_target_read_from_list_all',),
        reason="firewalld's inbound default lives in the zone target; unread, every firewalld host shows 'policy not read' instead of its measured reject/drop",
    ),
    Mutation(
        id='posture/firewalld-unread-target-assumed-reject',
        file='bob/checks/_firewalld.py',
        old='    return Verdict(_TARGET_POLICY.get(zone.target, "unknown"), zone)',
        new='    return Verdict(_TARGET_POLICY.get(zone.target, "reject"), zone)',
        kills=('tests/test_v0241_firewall_posture.py::TestFirewalldTarget::test_unread_target_is_unknown_not_reject',),
        reason='an unread target is unknown — calling it reject would credit a filter BOB never measured (unknown is not clean)',
    ),
    Mutation(
        id='posture/firewalld-default-target-read-as-open',
        file='bob/checks/_firewalld.py',
        old='_TARGET_POLICY = {"default": "reject",',
        new='_TARGET_POLICY = {"default": "allow",',
        kills=('tests/test_v0241_firewall_posture.py::TestFirewalldTarget::test_target_mapping',),
        reason="firewalld's 'default' target rejects unmatched packets; read as allow, every stock firewalld zone becomes 'no filtering'",
    ),
    Mutation(
        id='posture/firewalld-arm-dropped',
        file='bob/checks/firewall.py',
        old='        return FirewallPosture("firewalld", firewalld.incoming_policy)',
        new='        return FirewallPosture()',
        kills=('tests/test_v0241_firewall_posture.py::TestResolvePosture::test_firewalld_with_ufw_installed_but_inactive',),
        reason="without the firewalld arm the summaries say 'no active firewall' on a firewalld host (measured on Fedora 44 for the risk floor)",
    ),
    Mutation(
        id='posture/netfilter-arm-dropped',
        file='bob/checks/firewall.py',
        old='    if netfilter_policy in ("DROP", "REJECT"):',
        new='    if False:',
        kills=('tests/test_v0241_firewall_posture.py::TestResolvePosture::test_netfilter_drop',),
        reason="an nftables/iptables ruleset dropping inbound traffic is a firewall; dropping the arm reprints 'no active firewall — all ports unfiltered' and floors risk at HIGH",
    ),
    Mutation(
        id='posture/ubuntu-ufw-inactive-hides-other-filter',
        file='bob/checks/firewall.py',
        old='    if not status.active:\n        # firewalld is the firewall front-end',
        new='    if not status.installed:\n        # firewalld is the firewall front-end',
        kills=('tests/test_v0241_firewall_posture.py::TestUbuntuDefaultUfwInactive::test_firewalld_credited_not_capped',),
        reason="Ubuntu ships ufw installed and inactive; checking only 'not installed' alerts 'UFW inactive' and caps 3/10 on a host firewalld or nftables protects",
    ),
    Mutation(
        id='posture/exposure-unread-policy-printed-as-allow',
        file='bob/exposure.py',
        old='    elif fw_policy == "unknown":',
        new='    elif False:',
        kills=('tests/test_exposure.py::TestEdgeCases::test_unknown_policy_is_unread_not_allow_all',),
        reason="an unread default printed 'default policy is ALLOW — no filtering' on every firewalld host",
    ),
    Mutation(
        id='posture/exposure-backend-unnamed',
        file='bob/exposure.py',
        old='                      if fw_backend == "ufw" else',
        new='                      if True else',
        kills=('tests/test_v0241_firewall_posture.py::TestAttackSurfaceLine::test_firewalld_reject_is_ok_and_named',),
        reason='the attack-surface line names the firewall that filters; without it a firewalld host reads as a UFW one',
    ),
    Mutation(
        id='posture/ports-netfilter-reads-unfiltered',
        file='bob/checks/ports.py',
        old='                if netfilter_active:\n                    result.info(\n                        message=_t("ports.uncovered_netfilter", port=pp_info),',
        new='                if False:\n                    result.info(\n                        message=_t("ports.uncovered_netfilter", port=pp_info),',
        kills=('tests/test_v0241_firewall_posture.py::TestNetfilterPortWording::test_all_interfaces',),
        reason="on an nftables-only host 'no active firewall to filter it' contradicts the firewall section crediting the ruleset",
    ),
    Mutation(
        id='posture/ports-bound-address-netfilter',
        file='bob/checks/ports.py',
        old='                elif netfilter_active:\n                    key = "ports.uncovered_bound_address_netfilter"',
        new='                elif False:\n                    key = "ports.uncovered_bound_address_netfilter"',
        kills=('tests/test_v0241_firewall_posture.py::TestNetfilterPortWording::test_bound_address',),
        reason="a LAN-bound port behind a dropping ruleset is not 'reachable from the network'",
    ),
    Mutation(
        id='posture/services-netfilter-reads-unprotected',
        file='bob/checks/services.py',
        old='    elif netfilter_active and exposure in (Exposure.NO_RULE, Exposure.LOOPBACK_NO_RULE):',
        new='    elif False:',
        kills=('tests/test_v0241_firewall_posture.py::TestNetfilterPortWording::test_service_exposure',),
        reason="'no active firewall protection' per service port on a host whose ruleset drops inbound traffic",
    ),
    Mutation(
        id='posture/all-covered-claims-a-rule',
        file='bob/checks/ports.py',
        old='        if default_incoming_policy in ("deny", "reject"):\n            result.ok(message=_t("ports.all_covered_policy_ipv4" if ipv6_unproven',
        new='        if False:\n            result.ok(message=_t("ports.all_covered_policy_ipv4" if ipv6_unproven',
        kills=('tests/test_v0241_firewall_posture.py::test_all_covered_names_the_policy_under_default_deny',),
        reason="SSH on 0.0.0.0:22 with no rule, behind default deny, was said to be 'covered by a UFW rule' (measured on the Mint desktop)",
    ),
    Mutation(
        id='posture/runner-probe-only-when-ufw-absent',
        file='bob/runner.py',
        old='    if not fw_status.active and not fwd_status.active:\n        _nf_snap',
        new='    if not fw_status.installed and not fwd_status.active:\n        _nf_snap',
        kills=('tests/test_v0241_firewall_posture.py::TestRunnerWiring::test_raw_ruleset_probed_when_ufw_merely_inactive',),
        reason='the raw ruleset must be consulted whenever UFW is not running, not only when the package is absent',
    ),
    Mutation(
        id='posture/runner-summary-reads-ufw',
        file='bob/runner.py',
        old='        fw_active=fw_posture.active,',
        new='        fw_active=fw_status.active or fwd_status.active,',
        kills=('tests/test_v0241_firewall_posture.py::TestRunnerWiring::test_summary_fields_come_from_the_posture',),
        reason='the risk floor and attack surface must read the same posture the firewall section credits',
    ),
    Mutation(
        id='posture/runner-ssh-context-reads-ufw-policy',
        file='bob/runner.py',
        old='        or fw_posture.policy not in ("deny", "reject")',
        new='        or fw_status.incoming_policy not in ("deny", "reject")',
        kills=('tests/test_v0241_firewall_posture.py::TestRunnerWiring::test_ssh_context_reads_the_posture_policy',),
        reason="SSH's local-context downgrade must follow the filtering firewall's default, whichever backend it is",
    ),
    Mutation(
        id='sshd/main-file-fix-appended-into-match',
        file='bob/checks/ssh/_directives.py',
        old='            f"sudo sed -i {shlex.quote(\'1i \' + directive)} {conf} && "',
        new='            f"echo {shlex.quote(directive)} | sudo tee -a {conf} >/dev/null && "',
        kills=('tests/test_v0241_ssh_directive_fix.py::test_main_file_fix_survives_odd_spelling_and_a_trailing_match_block',),
        reason='an appended directive lands inside a trailing Match block: applied to that block only, or refused (StrictModes) so sshd no longer starts',
    ),
    Mutation(
        id='sshd/restart-without-config-test',
        file='bob/checks/ssh/_directives.py',
        old='            f"sudo sed -i {shlex.quote(\'1i \' + directive)} {conf} && "\n            f"sudo sshd -t && {restart}")',
        new='            f"sudo sed -i {shlex.quote(\'1i \' + directive)} {conf} && "\n            f"{restart}")',
        kills=('tests/test_v0241_ssh_directive_fix.py::test_every_table_directive_tests_the_config_before_restarting',),
        reason="restarting sshd on a configuration it rejects cuts the remote session BOB's own fix was applied over",
    ),
    Mutation(
        id='sshd/table-directives-ignore-the-dropin',
        file='bob/checks/ssh/_directives.py',
        old='        kwargs["cmd"] = _sshd_directive_fix(rule.fix, rule.fix.split()[0], cfg)',
        new='        kwargs["cmd"] = _sshd_directive_fix(rule.fix, rule.fix.split()[0], {})',
        kills=('tests/test_v0241_ssh_directive_fix.py::test_every_table_directive_targets_the_dropin',),
        reason='X11Forwarding/AllowTcpForwarding fixes edited the main file while a drop-in read first kept the old value (measured on the Mint desktop output)',
    ),
    Mutation(
        id='apt/phasing-read-as-inconsistent',
        file='bob/checks/updates.py',
        old='            and snapshot.upgradable_count > withheld\n',
        new='            and snapshot.upgradable_count > 0\n',
        kills=('tests/test_v0241_apt_phased.py::test_all_upgradable_phased_is_not_inconsistent',),
        reason="16 updates deferred by Ubuntu's phased rollout were reported as an inconsistent APT state on the Mint desktop",
    ),
    Mutation(
        id='apt/phasing-header-not-recognised',
        file='bob/checks/updates.py',
        old='    "The following upgrades have been deferred due to phasing:": "phased",',
        new='    "The following upgrades have been deferred due to phasing (x):": "phased",',
        kills=('tests/test_v0241_apt_phased.py::test_phasing_list_is_counted',),
        reason="the phasing count comes from apt's own header; unrecognised, every phased package reads as unexplained",
    ),
    Mutation(
        id='apt/kept-back-header-not-recognised',
        file='bob/checks/updates.py',
        old='    "The following packages have been kept back:": "kept",',
        new='    "The following packages have been kept back (x):": "kept",',
        kills=('tests/test_v0241_apt_phased.py::test_kept_back_list_is_counted',),
        reason='a held package is kept back by design and must be named, not called an inconsistency',
    ),
    Mutation(
        id='svcstate/condition-skip-read-as-stopped',
        file='bob/checks/services.py',
        old='        if _start_condition_unmet(svc_name):\n            return ServiceState.CONDITION_UNMET\n',
        new='        if False:\n            return ServiceState.CONDITION_UNMET\n',
        kills=('tests/test_v0241_service_condition_unmet.py::test_exec_condition_skip_is_condition_unmet',),
        reason="inetutils-inetd skipped by its ExecCondition (empty inetd.conf) was reported as 'Telnet Server enabled but not running', −1, on the Mint desktop",
    ),
    Mutation(
        id='svcstate/condition-directive-ignored',
        file='bob/checks/services.py',
        old='    return props.get("ConditionResult") == "no" or props.get("Result") == "exec-condition"',
        new='    return props.get("Result") == "exec-condition"',
        kills=('tests/test_v0241_service_condition_unmet.py::test_condition_directive_skip_is_condition_unmet',),
        reason='Condition…= skips leave Result=success; only ConditionResult=no says the unit was skipped by design',
    ),
    Mutation(
        id='svcstate/condition-unmet-silent',
        file='bob/checks/services.py',
        old='    if snap.state == ServiceState.CONDITION_UNMET:\n        result.info(',
        new='    if False:\n        result.info(',
        kills=('tests/test_v0241_service_condition_unmet.py::test_condition_unmet_is_info_without_deduction',),
        reason='every service state must render a verdict; a skipped unit says why it is not running',
    ),
    Mutation(
        id='wording/single-host-rule-called-local-network',
        file='bob/checks/services.py',
        old='        if _single_host(source):\n',
        new='        if False:\n',
        kills=('tests/test_v0241_wording_precision.py::test_single_host_rule_is_named_not_called_local_network',),
        reason="Samba allowed from one host (192.168.1.11) was 'restricted to local network' with advice to restrict it further (Mint desktop)",
    ),
    Mutation(
        id='wording/rule-source-keeps-direction',
        file='bob/checks/services.py',
        old='            if words and words[0] in ("IN", "OUT", "FWD"):\n',
        new='            if False:\n',
        kills=('tests/test_v0241_wording_precision.py::test_rule_source_is_the_address_alone',),
        reason="UFW's From column carries the direction; left in, no source ever reads as a single host",
    ),
    Mutation(
        id='wording/smtp-context-claims-changed-default',
        file='bob/locales/en.json',
        old='"exposure": "TCP/25 listener accepts mail submissions. Internet-exposed SMTP attracts constant spam relay attempts, SASL credential brute force, and reputation-based scanning. Default postfix configs on Debian/Ubuntu typically bind to 127.0.0.1 only — the port verdict below says whether that default still holds on this host."',
        new='"exposure": "TCP/25 listener accepts mail submissions. Internet-exposed SMTP attracts constant spam relay attempts, SASL credential brute force, and reputation-based scanning. Default postfix configs on Debian/Ubuntu typically bind to 127.0.0.1 only — this finding fires when that default has been changed."',
        kills=('tests/test_v0241_wording_precision.py::test_smtp_context_no_longer_claims_it_fires_on_a_changed_default',),
        reason='the SMTP context was printed above a postfix bound to 127.0.0.1, claiming it only fires when that default changed',
    ),
    Mutation(
        id='wwfuse/exit-status-read-as-blindness',
        file='bob/checks/world_writable.py',
        old='        snap.partial = (proc.returncode != 0\n                        and _unexplained_errors(err or b"", _skipped_mount_points()))\n',
        new='        snap.partial = proc.returncode != 0\n',
        kills=('tests/test_v0241_world_writable_fuse.py::test_sweep_with_only_a_fuse_refusal_is_complete',),
        reason="a user's FUSE mount (AppImage under /tmp) refuses root; reading find's exit status alone capped every such desktop's score as 'sweep incomplete'",
    ),
    Mutation(
        id='wwfuse/prefix-read-as-containment',
        file='bob/checks/world_writable.py',
        old='        if not path or not any(path == mp or path.startswith(mp.rstrip("/") + "/")\n',
        new='        if not path or not any(path == mp or path.startswith(mp)\n',
        kills=('tests/test_v0241_world_writable_fuse.py::test_a_name_prefix_is_not_containment',),
        reason='/tmp/.mount_ab is not under /tmp/.mount_a; a bare prefix match would excuse an error on a swept path',
    ),
    Mutation(
        id='wording/ipv6-link-local-hides-lan-reach',
        file='bob/locales/en.json',
        old='"ufw_disabled_listeners_link_local": "{count} service(s) listening on IPv6 (::) but UFW IPv6 is disabled — link-local addresses only: not reachable from the internet, but reachable from the local network without UFW filtering them"',
        new='"ufw_disabled_listeners_link_local": "{count} service(s) listening on IPv6 (::) but UFW IPv6 is disabled — link-local addresses only, no internet exposure"',
        kills=('tests/test_v0241_wording_precision.py::test_ipv6_link_local_listeners_are_said_reachable_from_the_lan',),
        reason="with UFW IPV6=no a link-local listener is unfiltered by UFW on the LAN; 'no internet exposure' alone read as 'covered'",
    ),
    Mutation(
        id='posture/ipv6-without-ufw-claims-ufw-config',
        file='bob/checks/ipv6.py',
        old='    if not snapshot.ufw_present and not firewalld_active:\n',
        new='    if False:\n',
        kills=('tests/test_v0241_firewall_posture.py::TestIPv6WithoutUfw::test_raw_ruleset_named_no_ufw_claim',),
        reason="on real Debian with nftables and no UFW, BOB said 'UFW IPv6 configuration matches kernel' and 'Port 22/tcp without a UFW (v6) rule'",
    ),
    Mutation(
        id='wwfuse/absolute-argv0-not-parsed',
        file='bob/checks/world_writable.py',
        old='_FIND_ERROR = re.compile(r"^(?:\\S*/)?find: (.+)$")',
        new='_FIND_ERROR = re.compile(r"^find: (.+)$")',
        kills=('tests/test_v0241_world_writable_fuse.py::test_real_gnu_line_with_absolute_argv0_is_understood',),
        reason="BOB runs find by absolute path, so its errors read '/usr/bin/find: …'; a 'find: ' prefix match left the Mint field run 'incomplete'",
    ),
    Mutation(
        id='busybox/ssh-delete-uses-gnu-I-flag',
        file='bob/checks/ssh/_directives.py',
        old='    kill = f"/^[[:space:]]*#?[[:space:]]*{sed_ci(param)}([[:space:]]|=)/d"',
        new='    kill = f"/^[[:space:]]*#?[[:space:]]*{param}([[:space:]]|=)/Id"',
        kills=('tests/test_v0241_busybox_sed.py::test_no_check_builds_a_gnu_only_case_insensitive_address', 'tests/test_v0241_busybox_sed.py::test_the_dropin_fix_runs_under_busybox_sed'),
        reason="BusyBox sed refuses /regex/I: every SSH drop-in fix stopped at 'sed: unsupported command I' on real Alpine 3.24",
    ),
    Mutation(
        id='busybox/samba-delete-uses-gnu-I-flag',
        file='bob/checks/samba.py',
        old='    delete = (f"sudo sed -i -E \'/^[[:space:]]*({alts})[[:space:]]*=/d\' "',
        new='    delete = (f"sudo sed -i -E \'/^[[:space:]]*({alts})[[:space:]]*=/Id\' "',
        kills=('tests/test_v0241_busybox_sed.py::test_no_check_builds_a_gnu_only_case_insensitive_address',),
        reason='the samba directive fix used the same GNU-only address flag',
    ),
    Mutation(
        id='docs/readme-dev-table-drops-a-module',
        file='DOCUMENTS/README_DEV.md',
        old='| `world_writable.py` | **v0.24.0** (INFO, `--exhaustive` only) — `find -xdev` (GNU or BusyBox) over local on-disk filesystems: world-writable files, non-sticky world-writable directories, unowned files; a path other accounts cannot traverse is reported as latent |\n',
        new='',
        kills=('tests/test_v0241_readme_dev_module_coverage.py::test_the_module_table_lists_every_check_module',),
        reason="nine modules (0.22.0–0.24.0) were missing from README_DEV's table for three releases; nothing compared it with bob/checks",
    ),
    Mutation(
        id='docs/readme-dev-tree-drops-a-module',
        file='DOCUMENTS/README_DEV.md',
        old='│   └── world_writable.py       # WorldWritableSnapshot + check_world_writable() — --exhaustive (v0.24.0)',
        new='│   └── world_writeable.py       # WorldWritableSnapshot + check_world_writable() — --exhaustive (v0.24.0)',
        kills=('tests/test_v0241_readme_dev_module_coverage.py::test_the_project_tree_lists_every_check_module',),
        reason='the project tree drifted with the table',
    ),
    Mutation(
        id='docs/readme-dev-row-names-a-gone-module',
        file='DOCUMENTS/README_DEV.md',
        old='| `cron/` | Cron management',
        new='| `cron.py` | Cron management',
        kills=('tests/test_v0241_readme_dev_module_coverage.py::test_no_row_names_a_module_that_is_gone',),
        reason='bob/cron.py became a package in v0.6.0 and the row kept the old name for eighteen releases',
    ),
    Mutation(
        id='fr-terms/locale-says-finding',
        file='bob/locales/fr.json',
        old='Nouveau constat : {finding}',
        new='Nouveau finding : {finding}',
        kills=('tests/test_fr_constat_terminology.py::TestFrenchLocale::test_no_value_says_finding',),
        reason='the French --diff line said "Nouveau finding" while CONVENTIONS §10 names it a constat',
    ),
    Mutation(
        id='fr-terms/locale-decouverte-for-finding',
        file='bob/locales/fr.json',
        old='"{count} constat(s)"',
        new='"{count} découverte(s)"',
        kills=('tests/test_fr_constat_terminology.py::TestFrenchLocale::test_decouverte_only_means_discovery',),
        reason='the HTML report counted "découverte(s)" — a third French word for one thing',
    ),
    Mutation(
        id='fr-terms/doc-prose-says-finding',
        file='DOCUMENTS/TUTORIAL_FR.md',
        old="## Étape 3 — comprendre n'importe quel constat",
        new="## Étape 3 — comprendre n'importe quel finding",
        kills=('tests/test_fr_constat_terminology.py::test_french_doc_says_constat',),
        reason='the French tutorial said "finding" throughout, contradicting the glossary',
    ),
    Mutation(
        id='fr-terms/doc-code-comment-says-finding',
        file='DOCUMENTS/CONVENTIONS_FR.md',
        old='# ✔ constat',
        new='# ✔ finding',
        kills=('tests/test_fr_constat_terminology.py::test_french_doc_says_constat',),
        reason='a comment inside a code block is prose too; the conventions example said "# ✔ finding"',
    ),
    Mutation(
        id='changelog-dates/summary-disagrees-with-full',
        file='CHANGELOG.md',
        old='| [v0.2.2](#v022) | 2026-05-03 |',
        new='| [v0.2.2](#v022) | 2026-05-02 |',
        kills=('tests/test_v0153_changelog_dates.py::TestSummaryAndFullAgreeOnTheDay::test_same_version_same_day',),
        reason='0.2.2 was dated a day early in the summary table while the detailed changelog and the tag said 03-05',
    ),
    Mutation(
        id='changelog-dates/beta-date-drifts',
        file='DOCUMENTS/CHANGELOG_FULL_FR.md',
        old='## [v0.7.0b4] — 01-06-2026',
        new='## [v0.7.0b4] — 02-06-2026',
        kills=('tests/test_v0153_changelog_dates.py::TestSummaryAndFullAgreeOnTheDay::test_same_version_same_day',
               'tests/test_v0153_changelog_dates.py::TestBothLanguagesAgreeOnTheDay::test_same_version_same_day'),
        reason='the date patterns skipped beta versions, so a beta date could drift unseen',
    ),
    Mutation(
        id='testing-table/release-without-row',
        file='DOCUMENTS/TESTING_FR.md',
        old='| v0.2.1 | 4238 |',
        new='| v0.2.1-absent | 4238 |',
        kills=('tests/test_v0181_testing_table_matches_changelog.py::test_every_released_version_has_a_row',),
        reason='TESTING had no row for 0.2.1 nor the four 0.7.0 betas, and nothing noticed',
    ),
    Mutation(
        id='changelog-parity/french-row-condensed',
        file='CHANGELOG_FR.md',
        old="Correctif urgent — passe de programmation défensive : correction d'un plantage de `--manage-logs` · 8 `except Exception` nus resserrés · 5 regex remontées au niveau du module · regex d'e-mail dédoublonnée · `getattr` retiré du score par domaine |",
        new="Correctif urgent — passe défensive. |",
        kills=('tests/test_changelog_fr_parity.py::test_no_french_entry_is_condensed',),
        reason='about forty French changelog entries had been condensed to a fraction of the English one',
    ),
    Mutation(
        id='changelog-parity/version-missing-in-french',
        file='CHANGELOG_FR.md',
        old='| [v0.7.0b2](#v070b2) | 31-05-2026 |',
        new='| [v0.7.0-b2](#v070b2) | 31-05-2026 |',
        kills=('tests/test_changelog_fr_parity.py::test_every_version_is_in_both_languages',),
        reason='a version the French table does not carry was invisible to every per-entry comparison',
    ),
    Mutation(
        id='firewalld-accept/never-alerted',
        file='bob/checks/firewall.py',
        old='            if opened is not None:',
        new='            if False:',
        kills=('tests/test_v0242_firewalld_policy_open.py::TestAcceptIsAlerted::test_accept_target_alerts_and_deducts_like_ufw',),
        reason='a firewalld zone with target ACCEPT read as an OK with no deduction while the attack surface said ALLOW',
    ),
    Mutation(
        id='firewalld-accept/no-deduction',
        file='bob/checks/firewall.py',
        old="""                    points=3,
                    cmd=_firewalld_open_fix(zone, verdict, firewalld),""",
        new="""                    points=0,
                    cmd=_firewalld_open_fix(zone, verdict, firewalld),""",
        kills=('tests/test_v0242_firewalld_policy_open.py::TestAcceptIsAlerted::test_accept_target_alerts_and_deducts_like_ufw',),
        reason="UFW's open default costs 3 points; the firewalld one must cost the same",
    ),
    Mutation(
        id='firewalld-accept/fix-drops-ssh',
        file='bob/checks/firewall.py',
        old='f"sudo firewall-cmd --permanent --zone={z} --add-service=ssh && "',
        new='f""',
        kills=('tests/test_v0242_firewalld_policy_open.py::TestTheFixDoesNotLockTheOperatorOut::test_a_named_zone_keeps_ssh_before_closing',),
        reason='closing a zone that does not list ssh locks a remote operator out',
    ),
    Mutation(
        id='firewalld-accept/zone-unquoted',
        file='bob/checks/firewall.py',
        old='    z = shlex.quote(zone)',
        new='    z = zone',
        kills=('tests/test_v0242_firewalld_policy_open.py::TestTheFixDoesNotLockTheOperatorOut::test_a_hostile_zone_name_is_quoted',),
        reason='the zone name comes from firewall-cmd output and ends up in a shell command',
    ),
    Mutation(
        id='firewalld-accept/ipv6-claims-ufw',
        file='bob/checks/ipv6.py',
        old='    if firewalld_active and not ufw_active:',
        new='    if False:',
        kills=('tests/test_v0242_firewalld_policy_open.py::TestIpv6UnderFirewalld::test_no_claim_about_ufw_when_firewalld_filters',),
        reason='a Fedora host with no ufw package was told "UFW IPv6 configuration matches kernel"',
    ),
    Mutation(
        id='firewalld-accept/ipv6-accept-called-filtered',
        file='bob/checks/ipv6.py',
        old='        if firewalld_policy == "allow":',
        new='        if firewalld_policy == "accept":',
        kills=('tests/test_v0242_firewalld_policy_open.py::TestIpv6UnderFirewalld::test_an_accepting_zone_is_not_called_filtering',),
        reason='under target ACCEPT the IPv6 section said the listeners were filtered by firewalld',
    ),
    Mutation(
        id='firewalld-accept/runner-drops-ipv6-policy',
        file='bob/runner.py',
        old='         firewalld_policy=fwd_status.family_policy("ipv6") if fwd_status.active else "")',
        new='         firewalld_policy="")',
        kills=('tests/test_v0242_firewalld_policy_open.py::test_the_runner_hands_the_zone_policy_to_ipv6',),
        reason='without the zone policy every firewalld host reads as filtered in the IPv6 section',
    ),
    Mutation(
        id='section-descriptions/firewall-says-ufw-only',
        file='bob/locales/fr.json',
        old='"firewall": "Pare-feu — UFW, firewalld ou jeu de règles nftables/iptables brut : actif, politique d\'entrée par défaut",',
        new='"firewall": "Pare-feu UFW — installé, actif, politique par défaut",',
        kills=('tests/test_v0242_firewalld_policy_open.py::test_section_descriptions_name_every_backend',),
        reason='--check list described the firewall section as UFW-only three releases after it learnt firewalld',
    ),
    Mutation(
        id='ufw-ipv6-off/drop-ignored',
        file='bob/checks/ipv6.py',
        old='    if snapshot.ip6_input_policy != "DROP" or snapshot.ip6_input_rules is None:',
        new='    if snapshot.ip6_input_policy != "REJECT" or snapshot.ip6_input_rules is None:',
        kills=('tests/test_v0242_ufw_ipv6_off.py::test_ufw_active_and_drop_is_blocked_not_exposed',),
        reason='UFW with IPV6=no drops all IPv6, yet the listeners were warned as exposed (WARN -2)',
    ),
    Mutation(
        id='ufw-ipv6-off/drop-credited-without-ufw',
        file='bob/checks/ipv6.py',
        old='            if ufw_active and _ipv6_input_closed(snapshot, extended=not snapshot.has_global_ipv6):',
        new='            if _ipv6_input_closed(snapshot, extended=not snapshot.has_global_ipv6):',
        kills=('tests/test_v0242_ufw_ipv6_off.py::test_a_drop_with_ufw_inactive_is_not_credited_to_ufw',),
        reason='ufw-init only runs with UFW active; a DROP otherwise has another cause',
    ),
    Mutation(
        id='ufw-ipv6-off/policy-never-read',
        file='bob/checks/ipv6.py',
        old='    if not res.ok:\n        return None, None\n    m = re.search(r"^-P INPUT (\\w+)", res.stdout, re.M)',
        new='    if not res.ok:\n        return None, None\n    m = re.search(r"^-P INPUT_ (\\w+)", res.stdout, re.M)',
        kills=('tests/test_v0242_ufw_ipv6_off.py::TestPolicyRead::test_reads_the_policy_line',),
        reason='a policy line that is never parsed leaves every UFW IPV6=no host warned as exposed',
    ),
    Mutation(
        id='ufw-ipv6-off/policy-read-regardless',
        file='bob/checks/ipv6.py',
        old='            _read_ip6_filter_full() if ufw_ipv6_enabled is False else (None, None, None, None))',
        new='            _read_ip6_filter_full())',
        kills=('tests/test_v0242_ufw_ipv6_off.py::TestPolicyRead::test_read_only_when_ufw_ipv6_is_off',),
        reason='the extra ip6tables call is only needed, and only meaningful, when UFW is set to IPV6=no',
    ),
    Mutation(
        id='changelog-dates/future-judged-in-utc',
        file='tests/test_v0153_changelog_dates.py',
        old='    return (now_utc + timedelta(hours=14)).date()',
        new='    return now_utc.date()',
        kills=('tests/test_v0153_changelog_dates.py::TestDatesAreRealAndOrdered::test_a_release_dated_in_local_time_is_not_the_future',),
        reason='the 0.24.2 release, dated in Paris after midnight, failed CI where the runner was still on the previous UTC day',
    ),
    Mutation(
        id='ipv6-chain/extra-rules-ignored',
        file='bob/checks/ipv6.py',
        old='        return set(snapshot.ip6_input_rules) <= _UFW_V6_OFF_RULES',
        new='        return True',
        kills=('tests/test_v0243_ipv6_chain_rules.py::test_any_other_rule_withholds_the_claim',),
        reason='a DROP policy with an explicit ACCEPT in the chain was reported as "every IPv6 listener unreachable"',
    ),
    Mutation(
        id='ipv6-chain/rules-not-collected',
        file='bob/checks/ipv6.py',
        old='    rules = [line.strip() for line in res.stdout.splitlines() if line.startswith("-A INPUT")]',
        new='    rules = []',
        kills=('tests/test_v0243_ipv6_chain_rules.py::test_the_reader_keeps_every_rule',),
        reason='reading only the policy line is what made the 0.24.2 claim stronger than the measurement',
    ),
    Mutation(
        id='firewalld-zones/catch-all-rule-ignored',
        file='bob/checks/_firewalld.py',
        old='    found = [c for c in (_catch_all(r, family) for r in rich_rules) if c is not None]',
        new='    found = []',
        kills=('tests/test_v0243_firewalld_zones.py::TestZonePolicy::test_accept_with_a_catch_all_reject_is_closed',),
        reason='libvirt / nm-shared pair target ACCEPT with a catch-all reject; read as open they would be alerted (9090 measured refused)',
    ),
    Mutation(
        id='firewalld-zones/virtual-interfaces-judged',
        file='bob/checks/_firewalld.py',
        old='        by_iface = [b for b in self.bindings if b.physical]',
        new='        by_iface = list(self.bindings)',
        kills=('tests/test_v0243_firewalld_zones.py::TestWhichZoneIsJudged::test_a_virtual_interface_zone_is_not_judged',),
        reason='a docker0 / virbr0 zone carries container or VM traffic, not the host inbound default',
    ),
    Mutation(
        id='firewalld-zones/default-zone-only',
        file='bob/checks/_firewalld.py',
        old="""        if judged:
            return judged""",
        new="""        if False:
            return judged""",
        kills=('tests/test_v0243_firewalld_zones.py::TestWhichZoneIsJudged::test_an_interface_in_trusted_is_alerted_under_a_filtering_default',),
        reason='judging the default zone alone said OK with enp3s0 in trusted and every port open (Fedora 44)',
    ),
    Mutation(
        id='firewalld-zones/fix-ignores-the-binding',
        file='bob/checks/firewall.py',
        old='        if is_default or not interfaces:',
        new='        if True:',
        kills=('tests/test_v0243_firewalld_zones.py::TestTheFixFollowsTheBinding::test_trusted_bound_to_an_interface_moves_the_interface',),
        reason='moving the default zone does not move an interface bound explicitly to trusted',
    ),
    Mutation(
        id='firewalld-zones/active-zones-unparsed',
        file='bob/checks/_firewalld.py',
        old='            zones[current] = line.split(":", 1)[1].split()',
        new='            zones[current] = []',
        kills=('tests/test_v0243_firewalld_zones.py::TestReadingTheZones::test_active_zones_are_parsed_as_measured',),
        reason='without the interface list no zone is judged and the default zone decides alone again',
    ),
    Mutation(
        id='firewalld-zones/logical-uplink-ignored',
        file='bob/checks/_firewalld.py',
        old='    return any(_physically_backed(low, depth + 1) for low in lowers)',
        new='    return False',
        kills=('tests/test_v0243_firewalld_zones.py::TestPhysicalBacking::test_a_logical_interface_over_a_nic_is_backed',),
        reason='br0 carries the default route and has no device link; a trusted br0 would have been an unjudged false OK',
    ),
    Mutation(
        id='firewalld-zones/same-priority-guessed',
        file='bob/checks/_firewalld.py',
        old='    return verdicts.pop() if len(verdicts) == 1 else "unknown"',
        new='    return verdicts.pop()',
        kills=('tests/test_v0243_firewalld_zones.py::TestZonePolicy::test_opposite_rules_at_one_priority_are_unknown',),
        reason='firewalld does not order rules of equal priority; picking one would assert an outcome nobody defined',
    ),
    Mutation(
        id='firewalld-zones/default-move-without-ssh',
        file='bob/checks/firewall.py',
        old='            return f"{keep_ssh} && sudo firewall-cmd --set-default-zone=public"',
        new='            return "sudo firewall-cmd --set-default-zone=public"',
        kills=('tests/test_v0243_firewalld_zones.py::TestTheFixFollowsTheBinding::test_ssh_is_allowed_in_public_before_anything_moves',),
        reason='public ships with ssh but nothing guarantees it still has it; moving there blind can lock a remote operator out',
    ),
    Mutation(
        id='firewalld-zones/host-policy-ignored',
        file='bob/checks/_firewalld.py',
        old='    applicable = [p for p in host_policies if "ANY" in p.ingress or zone.name in p.ingress]',
        new='    applicable = []',
        kills=('tests/test_v0243_firewalld_zones.py::TestHostPolicies::test_an_accept_policy_into_host_is_open',),
        reason='an ANY -> HOST ACCEPT policy made 8080 reachable on Fedora 44 while BOB said reject',
    ),
    Mutation(
        id='firewalld-zones/vm-policy-judged',
        file='bob/checks/_firewalld.py',
        old='    applicable = [p for p in host_policies if "ANY" in p.ingress or zone.name in p.ingress]',
        new='    applicable = list(host_policies)',
        kills=('tests/test_v0243_firewalld_zones.py::TestHostPolicies::test_a_policy_from_an_unjudged_zone_is_ignored',),
        reason='a policy from libvirt-routed concerns VM traffic, not the host uplink',
    ),
    Mutation(
        id='firewalld-zones/continue-read-as-unknown',
        file='bob/checks/_firewalld.py',
        old='        if self.target == "CONTINUE":',
        new='        if False:',
        kills=('tests/test_v0243_firewalld_zones.py::TestHostPolicies::test_allow_host_ipv6_as_shipped_decides_nothing',),
        reason='the shipped allow-host-ipv6 policy (CONTINUE) hands the packet back to the zone; it is not an unknown',
    ),
    Mutation(
        id='firewalld-order/negative-policies-skipped',
        file='bob/checks/_firewalld.py',
        old='    for prio in [x for x in priorities if x < 0]:',
        new='    for prio in []:',
        kills=('tests/test_v0243_firewalld_zones.py::TestPolicyOrder::test_m3_a_negative_accept_beats_a_positive_drop',),
        reason='a policy ACCEPT at -100 decides before a DROP at +100 (8080 reachable, Fedora 44)',
    ),
    Mutation(
        id='firewalld-order/positive-policies-skipped',
        file='bob/checks/_firewalld.py',
        old='    for prio in [x for x in priorities if x >= 0]:',
        new='    for prio in []:',
        kills=('tests/test_v0243_firewalld_zones.py::TestPolicyOrder::test_m4d_a_positive_drop_beats_an_accepting_zone_target',),
        reason='a policy DROP at +100 closed 8080 under a zone target ACCEPT; judging the target alone is a false alert',
    ),
    Mutation(
        id='firewalld-order/zone-rules-skipped',
        file='bob/checks/_firewalld.py',
        old='    rule = _rules_decide(zone.rich_rules, family)',
        new='    rule = None',
        kills=('tests/test_v0243_firewalld_zones.py::TestPolicyOrder::test_m4e_a_zone_catch_all_reject_beats_a_positive_accept',),
        reason='a zone catch-all reject refused 8080 before a policy ACCEPT at +100',
    ),
    Mutation(
        id='firewalld-order/policy-rules-skipped',
        file='bob/checks/_firewalld.py',
        old='        rule = _rules_decide(self.rich_rules, family)',
        new='        rule = None',
        kills=('tests/test_v0243_firewalld_zones.py::TestPolicyOrder::test_m1_a_policy_catch_all_beats_its_own_accept_target',),
        reason='a policy ACCEPT with its own catch-all reject refused 8080 (Fedora 44)',
    ),
    Mutation(
        id='firewalld-order/unplaced-policy-guessed',
        file='bob/checks/_firewalld.py',
        old='    if _first_decision(unordered, family) is not None:',
        new='    if False:',
        kills=('tests/test_v0243_firewalld_zones.py::TestPolicyOrder::test_a_deciding_policy_of_unread_priority_is_unknown',),
        reason='a deciding policy whose priority was not read cannot be placed before or after the zone',
    ),
    Mutation(
        id='firewalld-order/equal-priority-policies-guessed',
        file='bob/checks/_firewalld.py',
        old='    if len({d.policy for d in decided}) > 1:',
        new='    if False:',
        kills=('tests/test_v0243_firewalld_zones.py::TestPolicyOrder::test_policies_disagreeing_at_one_priority_are_unknown',),
        reason='firewalld does not order policies of equal priority; picking one asserts an undefined outcome',
    ),
    Mutation(
        id='firewalld-catch-all/qualifiers-read-as-unknown',
        file='bob/checks/_firewalld.py',
        old='        elif word not in _RICH_QUALIFIERS:',
        new='        elif True:',
        kills=('tests/test_v0243_firewalld_zones.py::TestCatchAllIsSemantic::test_log_audit_and_limit_do_not_select_packets',),
        reason='log / audit / limit accept rules opened 8080 on Fedora 44 while BOB said reject',
    ),
    Mutation(
        id='firewalld-catch-all/selectors-ignored',
        file='bob/checks/_firewalld.py',
        old='        if word in _RICH_SELECTORS:',
        new='        if word == "family":',
        kills=('tests/test_v0243_firewalld_zones.py::TestCatchAllIsSemantic::test_a_selector_makes_it_partial',),
        reason='a service-limited accept left 8080 closed; read as catch-all it would be a false alert',
    ),
    Mutation(
        id='firewalld-catch-all/limited-reject-decides',
        file='bob/checks/_firewalld.py',
        old='    if limited and action != "accept":',
        new='    if False:',
        kills=('tests/test_v0243_firewalld_zones.py::TestCatchAllIsSemantic::test_a_rate_limited_reject_decides_nothing',),
        reason='past its rate a limited reject lets packets through to the target',
    ),
    Mutation(
        id='firewalld-catch-all/unknown-word-guessed',
        file='bob/checks/_firewalld.py',
        old='    return prio, "unknown" if unknown else _CATCH_ALL_POLICY[action]',
        new='    return prio, _CATCH_ALL_POLICY[action]',
        kills=('tests/test_v0243_firewalld_zones.py::TestCatchAllIsSemantic::test_a_word_bob_does_not_know_is_unknown',),
        reason='a rule word BOB does not know may select packets; its verdict is not guessed',
    ),
    Mutation(
        id='firewalld-fix/zone-rule-left-in-place',
        file='bob/checks/firewall.py',
        old='    if verdict.by_rule:\n        where = zone_arg.strip()',
        new='    if False:\n        where = zone_arg.strip()',
        kills=('tests/test_v0243_firewalld_zones.py::TestTheFixFollowsTheCause::test_a_zone_rule_is_removed_with_ssh_kept_first',),
        reason='resetting the target leaves the catch-all accept that opened the zone',
    ),
    Mutation(
        id='firewalld-fix/policy-rule-left-in-place',
        file='bob/checks/firewall.py',
        old='        if verdict.by_rule:\n            undo',
        new='        if False:\n            undo',
        kills=('tests/test_v0243_firewalld_zones.py::TestTheFixFollowsTheCause::test_a_policy_rule_is_removed_from_the_policy',),
        reason='setting a policy to CONTINUE leaves the catch-all accept that opened it',
    ),
    Mutation(
        id='firewalld-fix/policy-fix-without-ssh',
        file='bob/checks/firewall.py',
        old='        return f"{keep_ssh}{undo} && sudo firewall-cmd --reload", zone, policies, False\n    if verdict.by_rule:',
        new='        return f"{undo} && sudo firewall-cmd --reload", zone, policies, False\n    if verdict.by_rule:',
        kills=('tests/test_v0243_firewalld_zones.py::TestTheFixFollowsTheCause::test_a_policy_target_fix_keeps_ssh_in_the_zone_first',),
        reason='handing the decision back to a zone without ssh cuts a remote operator',
    ),
    Mutation(
        id='firewalld-fix/rule-unquoted',
        file='bob/checks/firewall.py',
        old='\n        undo = " && ".join(f"sudo firewall-cmd --permanent {where} --remove-rich-rule={shlex.quote(r)}"',
        new='\n        undo = " && ".join(f"sudo firewall-cmd --permanent {where} --remove-rich-rule={r}"',
        kills=('tests/test_v0243_firewalld_zones.py::TestTheFixFollowsTheCause::test_a_zone_rule_is_removed_with_ssh_kept_first',),
        reason='a rich rule carries spaces and quotes; unquoted it is not one shell word',
    ),
    Mutation(
        id='firewalld-unread/zones-unread-guessed',
        file='bob/checks/_firewalld.py',
        old='        if not self.zones_read:\n            return "unknown"',
        new='        if False:\n            return "unknown"',
        kills=('tests/test_v0243_firewalld_zones.py::TestUnreadIsNotNone::test_unread_zones_withhold_every_verdict',),
        reason='unread is not none: which zone holds the interfaces is then unknown',
    ),
    Mutation(
        id='firewalld-unread/alert-on-unread-zones',
        file='bob/checks/_firewalld.py',
        old='        if not self.zones_read:\n            return None',
        new='        if False:\n            return None',
        kills=('tests/test_v0243_firewalld_zones.py::TestUnreadIsNotNone::test_unread_zones_withhold_every_verdict',),
        reason='an ACCEPT default zone may hold no interface; with the listing unread it is not alerted',
    ),
    Mutation(
        id='firewalld-unread/failed-zone-listing-empty',
        file='bob/checks/_firewalld.py',
        old='    if not res.ok:\n        return None\n    bindings = []',
        new='    if not res.ok:\n        return []\n    bindings = []',
        kills=('tests/test_v0243_firewalld_zones.py::TestUnreadIsNotNone::test_a_failed_zone_listing_is_none_not_empty',),
        reason='a failed listing read as empty falls back to the default zone as if it had been read',
    ),
    Mutation(
        id='firewalld-unread/no-policy-support-unread',
        file='bob/checks/_firewalld.py',
        old='        if res.code == 2 and "unrecognized arguments" in (res.stderr or ""):',
        new='        if False:',
        kills=('tests/test_v0243_firewalld_zones.py::TestUnreadIsNotNone::test_a_firewalld_without_policies_has_none',),
        reason='a firewalld without policies has none; calling that unread would blind every verdict',
    ),
    Mutation(
        id='firewalld-unread/refused-policies-empty',
        file='bob/checks/_firewalld.py',
        old='            return []\n        return None\n    found = []',
        new='            return []\n        return []\n    found = []',
        kills=('tests/test_v0243_firewalld_zones.py::TestUnreadIsNotNone::test_a_refused_policy_listing_is_unread',),
        reason='a refused policy listing may hide a deciding ACCEPT',
    ),
    Mutation(
        id='firewalld-unread/from-system-forgets',
        file='bob/checks/_firewalld.py',
        old='                       zones_read=bindings is not None and policies is not None)',
        new='                       zones_read=True)',
        kills=('tests/test_v0243_firewalld_zones.py::TestUnreadIsNotNone::test_from_system_marks_an_unread_listing',),
        reason="the readers' None must reach the status, or unread looks read",
    ),
    Mutation(
        id='firewalld-policies/priority-unread',
        file='bob/checks/_firewalld.py',
        old='                                priority=int(prio.group(1)) if prio else None))',
        new='                                priority=-1))',
        kills=('tests/test_v0243_firewalld_zones.py::TestUnreadIsNotNone::test_the_priority_is_read_as_listed',),
        reason='the order of policies and zone is the verdict; a priority not read cannot be invented',
    ),
    Mutation(
        id='firewalld-zones/mixed-bridge-unbacked',
        file='bob/checks/_firewalld.py',
        old='    return any(_physically_backed(low, depth + 1) for low in lowers)',
        new='    return bool(lowers) and all(_physically_backed(low, depth + 1) for low in lowers)',
        kills=('tests/test_v0243_firewalld_zones.py::TestTopologies::test_a_bridge_with_a_nic_among_veths_is_backed',),
        reason='a bridge holding the NIC and VM taps is still the host uplink',
    ),
    Mutation(
        id='ipv6-chain/unresolved-said-reachable',
        file='bob/checks/ipv6.py',
        old='            elif ufw_active and snapshot.ip6_input_policy == "DROP":',
        new='            elif False:',
        kills=('tests/test_v0243_ipv6_chain_rules.py::test_link_local_with_other_rules_is_neither_reachable_nor_blocked',),
        reason='ACCEPT 22 under UFW\'s DROP left :22 unreachable on Mint (ICMPv6 dropped); "reachable" was not shown',
    ),
    Mutation(
        id='firewalld-sources/whole-family-ignored',
        file='bob/checks/_firewalld.py',
        old='                             if b.all_sources and not b.physical and self._classifies(b)\n',
        new='                             if False\n',
        kills=('tests/test_v0243_firewalld_zones.py::TestSourceBoundZones::test_a_whole_family_source_is_judged_and_alerted',),
        reason='0.0.0.0/0 in trusted opened 8080 to every IPv4 client on Fedora 44 while BOB said reject',
    ),
    Mutation(
        id='firewalld-sources/sources-unparsed',
        file='bob/checks/_firewalld.py',
        old='            out[current] = line.split(":", 1)[1].split()',
        new='            out[current] = []',
        kills=('tests/test_v0243_firewalld_zones.py::TestSourceBoundZones::test_the_sources_line_is_parsed_as_measured',),
        reason='without the sources line no source-bound zone is ever seen',
    ),
    Mutation(
        id='firewalld-sources/source-only-zone-skipped',
        file='bob/checks/_firewalld.py',
        old='        if not ifaces and not sources.get(name):',
        new='        if not ifaces:',
        kills=('tests/test_v0243_firewalld_zones.py::TestSourceBoundZones::test_a_source_only_zone_is_read',),
        reason='a zone holding only sources takes precedence for them; skipping it hides the exposure',
    ),
    Mutation(
        id='firewalld-sources/narrow-source-silent',
        file='bob/checks/firewall.py',
        old='            for src_zone, _verdict in firewalld.open_sources:',
        new='            for src_zone, _verdict in []:',
        kills=('tests/test_v0243_firewalld_zones.py::TestSourceBoundZones::test_a_narrow_source_is_shown_not_scored',),
        reason='192.168.1.10/32 in trusted opened 8080 to that host; the audit said nothing',
    ),
    Mutation(
        id='firewalld-sources/fix-moves-the-default',
        file='bob/checks/firewall.py',
        old='    if zone.all_sources and not zone.physical:',
        new='    if False:',
        kills=('tests/test_v0243_firewalld_zones.py::TestSourceBoundZones::test_a_whole_family_source_is_judged_and_alerted',),
        reason='moving the default zone leaves a whole-family source bound to trusted',
    ),
    Mutation(
        id='firewalld-fix/first-cause-only',
        file='bob/checks/firewall.py',
        old='        if done or verdict.policy != "allow":',
        new='        if True:',
        kills=('tests/test_v0243_firewalld_zones.py::TestSeveralCausesAtOnce::test_a_zone_with_target_and_rule_loses_both',),
        reason='zone ACCEPT + catch-all accept stayed open on Fedora 44 once the rule alone was removed',
    ),
    Mutation(
        id='firewalld-unread/not-said',
        file='bob/checks/firewall.py',
        old='            if not firewalld.zones_read:\n                result.info(',
        new='            if False:\n                result.info(',
        kills=('tests/test_v0243_firewalld_zones.py::TestUnreadIsSaid::test_unread_listings_are_said_and_count_as_unverified',),
        reason='an inbound default never established must not read as a clean, complete audit',
    ),
    Mutation(
        id='firewalld-unread/not-a-visibility-limit',
        file='bob/visibility.py',
        old='    "firewall.firewalld_zones_unread",\n',
        new='',
        kills=('tests/test_v0243_firewalld_zones.py::TestUnreadIsSaid::test_unread_listings_are_said_and_count_as_unverified',),
        reason='the unread listing must make the score a ceiling, not a clean bill',
    ),
    Mutation(
        id='firewalld-sources/ingress-priority-ignored',
        file='bob/checks/_firewalld.py',
        old='        return any(source_zone.ingress_priority <= r.ingress_priority for r in refs)',
        new='        return True',
        kills=('tests/test_v0243_firewalld_zones.py::TestIngressPriority::test_the_source_zone_counts_only_when_it_classifies_first',
               'tests/test_v0260_firewalld_nested_sources.py::test_the_interface_zone_order_against_the_pooled_zones'),
        reason='0.0.0.0/0 in trusted at +100 under FedoraServer at -100 left 8080 refused; BOB alerted -3',
    ),
    Mutation(
        id='firewalld-sources/equal-priority-loses',
        file='bob/checks/_firewalld.py',
        old='        return any(source_zone.ingress_priority <= r.ingress_priority for r in refs)',
        new='        return any(source_zone.ingress_priority < r.ingress_priority for r in refs)',
        kills=('tests/test_v0243_firewalld_zones.py::TestIngressPriority::test_the_source_zone_counts_only_when_it_classifies_first',
               'tests/test_v0260_firewalld_nested_sources.py::test_the_interface_zone_order_against_the_pooled_zones'),
        reason='at equal ingress priority a source zone classifies first (0.0.0.0/0 in trusted opened 8080)',
    ),
    Mutation(
        id='firewalld-sources/ingress-unread',
        file='bob/checks/_firewalld.py',
        old='                                    ingress_priority=int(prio.group(1)) if prio else 0))',
        new='                                    ingress_priority=0))',
        kills=('tests/test_v0243_firewalld_zones.py::TestIngressPriority::test_the_ingress_priority_is_read_as_listed',),
        reason='the classification order is the verdict; a priority listed must be read',
    ),
    Mutation(
        id='firewalld-sources/split-prefixes-missed',
        file='bob/checks/_firewalld.py',
        old='            if any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(n for _, n in nets)):',
        new='            if any(n.prefixlen == 0 for _, n in nets):',
        kills=('tests/test_v0243_firewalld_zones.py::TestPrefixesAddUp::test_halves_that_cover_a_family_are_judged',),
        reason='0.0.0.0/1 + 128.0.0.0/1 opened 8080 to every IPv4 client while BOB said reject',
    ),
    Mutation(
        id='firewalld-sources/zones-not-pooled',
        file='bob/checks/_firewalld.py',
        old='            if not entry["open"]:\n                continue\n            public, public_space = _public_share(entry["open"], version)\n            if not _nearly_all(public, public_space):',
        new='            if True:\n                continue\n            public, public_space = _public_share(entry["open"], version)\n            if not _nearly_all(public, public_space):',
        kills=('tests/test_v0243_firewalld_zones.py::TestSourcesAcrossZones::test_halves_in_two_accepting_zones_are_alerted',),
        reason='0.0.0.0/1 and 128.0.0.0/1 in two accepting zones let every IPv4 client in',
    ),
    Mutation(
        id='firewalld-sources/pooled-not-alerted',
        file='bob/checks/firewall.py',
        old='            if opened is None and pooled:',
        new='            if False:',
        kills=('tests/test_v0243_firewalld_zones.py::TestSourcesAcrossZones::test_halves_in_two_accepting_zones_are_alerted',),
        reason='a whole family covered across zones is an open default, not two INFOs',
    ),
    Mutation(
        id='firewalld-sources/filtering-half-pooled',
        file='bob/checks/_firewalld.py',
        old='        open_names = {z.name for z, _ in self.open_sources}\n        source_zones',
        new='        open_names = {b.name for b in self.bindings}\n        source_zones',
        kills=('tests/test_v0243_firewalld_zones.py::TestSourcesAcrossZones::test_a_half_in_a_filtering_zone_does_not_add_up',),
        reason='a half bound to a filtering zone is not open; adding it up would be a false alert',
    ),
    Mutation(
        id='firewalld-sources/narrow-source-vouched-for',
        file='bob/locales/en.json',
        old="; whether they deserve that trust is not something BOB can judge",
        new="",
        kills=('tests/test_v0243_firewalld_zones.py::TestSourcesAcrossZones::test_the_narrow_source_message_does_not_vouch_for_the_source',),
        reason='no deduction for a /32 must not read as BOB vouching for that address',
    ),
    Mutation(
        id='firewalld-family/family-rule-ignored',
        file='bob/checks/_firewalld.py',
        old='            if val != family:\n                return None',
        new='            if True:\n                return None',
        kills=('tests/test_v0243_firewalld_zones.py::TestOneFamilyAtATime::test_an_ipv4_catch_all_accept_opens_ipv4_only',),
        reason='rule family="ipv4" priority="-100" accept opened 8080 over IPv4 on Fedora 44 while BOB said reject',
    ),
    Mutation(
        id='firewalld-family/family-rule-applied-to-both',
        file='bob/checks/_firewalld.py',
        old='            if val != family:\n                return None',
        new='            if False:\n                return None',
        kills=('tests/test_v0243_firewalld_zones.py::TestOneFamilyAtATime::test_an_ipv4_catch_all_accept_opens_ipv4_only',),
        reason='an IPv4-only rule says nothing about IPv6; applying it there misleads the IPv6 section',
    ),
    Mutation(
        id='firewalld-family/source-family-spread',
        file='bob/checks/_firewalld.py',
        old='    if zone.physical or not zone.sources:\n        return FAMILIES',
        new='    if True:\n        return FAMILIES',
        kills=('tests/test_v0243_firewalld_zones.py::TestOneFamilyAtATime::test_a_whole_ipv4_source_leaves_ipv6_to_the_interface_zone',),
        reason="0.0.0.0/0 opens IPv4; the IPv6 section must still see the interface zone's verdict",
    ),
    Mutation(
        id='firewalld-family/message-claims-both',
        file='bob/checks/firewall.py',
        old='    families = "/".join(f.replace("ip", "IP") for f in families_of(zone)\n                        if zone_verdict(zone, policies, f).policy == "allow")',
        new='    families = "IPv4/IPv6"',
        kills=('tests/test_v0243_firewalld_zones.py::test_the_rule_message_names_its_family',),
        reason='an IPv4-only rule said "accepts every packet": the message must name the family it opens',
    ),
    Mutation(
        id='default-deny/first-chain-only',
        file='bob/checks/iptables_nftables.py',
        old='    for restrictive in ("DROP", "REJECT"):\n        if restrictive in effective:\n            return restrictive\n',
        new='    if effective and effective[0] in ("DROP", "REJECT"):\n        return effective[0]\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestEveryBaseChainOnTheHook::test_one_dropping_chain_filters_the_hook',),
        reason='Mint: a second base chain dropped by default, port 8080 was closed, and BOB raised INPUT ACCEPT',
    ),
    Mutation(
        id='default-deny/no-icmpv6',
        file='bob/checks/iptables_nftables.py',
        old='    if target[1] in ("inet", "ip6"):\n',
        new='    if False:\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestIpv6KeepsWorking::test_an_inet_chain_accepts_neighbour_discovery',),
        reason='an inet drop policy without neighbour discovery cuts IPv6 itself, SSH over IPv6 included',
    ),
    Mutation(
        id='default-deny/runtime-unsaid',
        file='bob/checks/iptables_nftables.py',
        old='                    else _t("firewall_iptables.runtime_only_detail")),\n',
        new='                    else ""),\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestItSaysItDoesNotLast::test_the_raw_command_is_runtime_only',),
        reason='raw rules vanish at boot and the finding returns; the operator must read that where the command is',
    ),
    Mutation(
        id='default-deny/stderr-ignored',
        file='bob/checks/iptables_nftables.py',
        old='    return frozenset(m.groups() for m in re.finditer(\n        r"table\\s+(\\w+)\\s+(\\S+)\\s+is managed by iptables-nft", stderr or ""))\n',
        new='    return frozenset()\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestWhichChainTheHookUses::test_a_table_iptables_nft_manages',),
        reason='nft names the tables iptables-nft manages on stderr only; missing it hands those chains to nft',
    ),
    Mutation(
        id='default-deny/ip6-counts-for-ipv4',
        file='bob/checks/iptables_nftables.py',
        old='    effective = [_chain_verdict(c)[0] for c in chains if c["family"] in _IPV4_FAMILIES]\n',
        new='    effective = [_chain_verdict(c)[0] for c in chains]\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestWhatTheHookFiltersForIpv4::test_an_ip6_chain_filters_no_ipv4',),
        reason='Mint: an ip6 chain at policy drop left 8080 open over IPv4 while BOB read the hook as DROP',
    ),
    Mutation(
        id='default-deny/accept-everything-ignored',
        file='bob/checks/iptables_nftables.py',
        old='        if text == "accept":\n            return "ACCEPT", True',
        new='        if False:\n            return "ACCEPT", True',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestWhatTheHookFiltersForIpv4::test_a_drop_behind_an_accept_everything_rule',),
        reason='Mint: a drop policy behind an accept-everything rule left 8080 open while BOB read DROP',
    ),
    Mutation(
        id='default-deny/fix-on-ip6-chain',
        file='bob/checks/iptables_nftables.py',
        old='        if c["family"] not in _IPV4_FAMILIES:\n            continue          # an ip6 chain does not carry the IPv4 policy the finding is about\n',
        new='',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestWhatTheHookFiltersForIpv4::test_the_fix_targets_an_ipv4_chain',),
        reason='a default-deny written into an ip6 chain leaves the IPv4 policy the finding is about untouched',
    ),
    Mutation(
        id='default-deny/explain-bare-nft-policy',
        file='bob/locales/en.json',
        old='   sudo nft add rule inet filter input tcp dport 22 accept\\n',
        new='',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::test_the_explain_entry_accepts_the_way_in_before_the_nft_policy[en]',),
        reason='the explain entry handed out the bare drop policy that froze an SSH session on Mint',
    ),
    Mutation(
        id='default-deny/input-ok-scope-unsaid',
        file='bob/checks/iptables_nftables.py',
        old='            detail=_t("firewall_iptables.input_ok_detail"),\n',
        new='',
        kills=("tests/test_v0244_default_deny_keeps_ssh.py::test_input_ok_says_it_reads_policies_not_reachability[en-is not established here]",),
        reason='a later chain can refuse new SSH while the hook reads DROP; read bare, the OK sounds like reachability',
    ),
    Mutation(
        id='default-deny/insert-ahead-of-admin',
        file='bob/checks/iptables_nftables.py',
        old='    return f"sudo nft add rule {family} {shlex.quote(table)} {shlex.quote(chain)} {rule}"\n',
        new='    return f"sudo nft insert rule {family} {shlex.quote(table)} {shlex.quote(chain)} {rule}"\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestTheRulesAlreadyThere::test_no_insert_ahead_of_the_administrators_rules',),
        reason='Fedora VM: accepts inserted at the top let in a neighbour the chain refused SSH, then BOB said OK',
    ),
    Mutation(
        id='default-deny/accept-all-fix-offered',
        file='bob/checks/iptables_nftables.py',
        old='                 else None if snapshot.input_accepts_all\n',
        new='',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestTheRulesAlreadyThere::test_an_accept_everything_rule_gets_no_command',),
        reason='Fedora VM: behind an accept-everything rule the fix changed nothing and 8080 stayed open',
    ),
    Mutation(
        id='default-deny/ipt-accept-all-ignored',
        file='bob/checks/iptables_nftables.py',
        old='m = re.match(r"^-A INPUT -j (ACCEPT|DROP|REJECT)(?:',
        new='m = re.match(r"^-A INPUT -j (DROP|REJECT)(?:',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestAnIptablesChainAcceptingEverything::test_the_policy_is_never_reached',),
        reason='Fedora VM: -P INPUT DROP behind -A INPUT -j ACCEPT, 8080 answered and BOB read DROP',
    ),
    Mutation(
        id='default-deny/ipt-policy-read-raw',
        file='bob/checks/iptables_nftables.py',
        old='                    input_policy=_ipt_effective_input_policy(raw),\n',
        new='                    input_policy=_ipt_policy(raw, "INPUT"),\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestAnIptablesChainAcceptingEverything::test_the_snapshot_reads_it',),
        reason='the effective reading is only worth something if the snapshot uses it',
    ),
    Mutation(
        id='default-deny/bare-policy',
        file='bob/checks/iptables_nftables.py',
        old='        return " && ".join(steps + ["sudo iptables -P INPUT DROP"])\n',
        new='        return "sudo iptables -P INPUT DROP"\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestTheWayInIsAcceptedFirst::test_iptables',),
        reason='Mint over SSH: iptables -P INPUT DROP alone froze the session that ran it and refused new ones',
    ),
    Mutation(
        id='default-deny/nft-policy-first',
        file='bob/checks/iptables_nftables.py',
        old='    return " && ".join(steps + [_nft_drop_policy(target)])\n',
        new='    return " && ".join([_nft_drop_policy(target)] + steps)\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestTheWayInIsAcceptedFirst::test_nftables_names_the_chain_and_drops_last',),
        reason='a drop policy set before its accept rules cuts the session in between',
    ),
    Mutation(
        id='default-deny/managed-table-ignored',
        file='bob/checks/iptables_nftables.py',
        old='        if (c["family"], c["table"]) in managed:\n            return ("iptables",)\n',
        new='',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestWhichChainTheHookUses::test_a_table_iptables_nft_manages',),
        reason='nft flags a table iptables-nft manages; changing it with nft is what nft warns against',
    ),
    Mutation(
        id='default-deny/inet-filter-assumed',
        file='bob/checks/iptables_nftables.py',
        old='        return ("nft", c["family"], c["table"], c["chain"])\n',
        new='        return ("nft", "inet", "filter", hook)\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestWhichChainTheHookUses::test_an_unmanaged_ip_table',),
        reason='Mint: nft chain inet filter input failed, the hook lives in table ip filter, chain INPUT',
    ),
    Mutation(
        id='default-deny/ufw-not-preferred',
        file='bob/checks/iptables_nftables.py',
        old='            cmd=(_ufw.enable_cmd(ssh_ports, ipv6_off=ufw_ipv6_off) if ufw_installed\n                 else None if snapshot.input_accepts_all\n',
        new='            cmd=(None if snapshot.input_accepts_all\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestTheWayInIsAcceptedFirst::test_a_host_with_ufw_gets_ufw',),
        reason='a host with ufw gets the same front-end command as firewall.inactive, not raw rules beside it',
    ),
    Mutation(
        id='default-deny/target-not-collected',
        file='bob/checks/iptables_nftables.py',
        old='                    input_target=_nft_hook_target(raw, "input", _nft_managed(nft_res.stderr)),\n',
        new='                    input_target=_nft_hook_target(raw, "input"),\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestWhichChainTheHookUses::test_the_snapshot_reads_it',),
        reason="the hook's table is only worth reading if the snapshot passes it on",
    ),
    Mutation(
        id='privilege/not-applied',
        file='bob/scoring.py',
        old='        cmd = with_privilege(cmd)\n',
        new='',
        kills=('tests/test_v0250_privilege_prefix.py::test_a_finding_carries_the_hosts_prefix',),
        reason='Alpine has doas and no sudo: a fix starting with sudo fails on its first word',
    ),
    Mutation(
        id='privilege/doas-first',
        file='bob/_privilege.py',
        old='        if shutil.which("sudo"):\n            return "sudo"\n        if shutil.which("doas"):\n            return "doas"\n',
        new='        if shutil.which("doas"):\n            return "doas"\n        if shutil.which("sudo"):\n            return "sudo"\n',
        kills=('tests/test_v0250_privilege_prefix.py::TestWhichPrefix::test_the_prefix',),
        reason='a host with both keeps sudo, as every fix BOB printed so far',
    ),
    Mutation(
        id='privilege/visudo-mangled',
        file='bob/_privilege.py',
        old='_SUDO_WORD = re.compile(r"(?<![\\w./-])sudo(?=\\s|\\)|[.,;:](?!\\w)|$)")',
        new='_SUDO_WORD = re.compile(r"sudo")',
        kills=('tests/test_v0250_privilege_prefix.py::TestTheCommandWords::test_words_that_only_contain_sudo_are_left',),
        reason='visudo and /etc/sudoers are names, not the command word',
    ),
    Mutation(
        id='privilege/apply-ignores-doas',
        file='bob/fixes.py',
        old='(?:(?:sudo|doas)\\s+)?ufw',
        new='(?:sudo\\s+)?ufw',
        kills=('tests/test_v0250_privilege_prefix.py::test_apply_recognises_a_doas_ufw_delete',),
        reason='--fix --apply must still order a doas ufw delete by rule number',
    ),
    Mutation(
        id='rpm-filecaps/name-decides',
        file='bob/checks/file_capabilities.py',
        old='        if path in snapshot.rpm_caps:\n',
        new='        if False:\n',
        kills=('tests/test_v0250_rpm_filecaps.py::TestTheVerdict::test_an_unowned_copy_with_a_known_name',),
        reason='Fedora: an unowned newuidmap copy with cap_setuid passed by its name and BOB said OK',
    ),
    Mutation(
        id='rpm-filecaps/unowned-unread',
        file='bob/checks/file_capabilities.py',
        old='        elif f"file {path} is not owned by any package" in said:\n            answered[path] = None\n',
        new='',
        kills=('tests/test_v0250_rpm_filecaps.py::TestWhatRpmSays::test_owned_and_unowned',),
        reason='a file no package owns is exactly what a planted copy is',
    ),
    Mutation(
        id='rpm-filecaps/not-asked',
        file='bob/checks/file_capabilities.py',
        old='        snap.rpm_caps = _rpm_filecaps([p for p, _ in snap.entries])\n',
        new='',
        kills=('tests/test_v0250_rpm_filecaps.py::TestWhatRpmSays::test_the_snapshot_asks',),
        reason='the rpm proof is only worth something if the snapshot asks for it',
    ),
    Mutation(
        id='rpm-filecaps/bare-assignment-empty',
        file='bob/checks/file_capabilities.py',
        old='        if not m.group(1):\n            names.update(_CAP_NAMES)\n            continue\n',
        new='        if not m.group(1):\n            continue\n',
        kills=('tests/test_v0250_rpm_filecaps.py::TestTheCapabilityText::test_a_bare_assignment_is_every_capability',),
        reason='a bare =ep grants every capability; reading it as none would bless anything',
    ),
    Mutation(
        id='k8s-routing/kubelet-ignored',
        file='bob/checks/firewall_stack.py',
        old='            or snapshot.libvirt_present or snapshot.kubernetes_running)\n',
        new='            or snapshot.libvirt_present)\n',
        kills=('tests/test_v0250_kubernetes_routing.py::test_a_kubernetes_node_routes',),
        reason='MicroK8s: BOB offered ip_forward=0 as a fix, which cuts every pod off',
    ),
    Mutation(
        id='k8s-routing/not-detected',
        file='bob/checks/firewall_stack.py',
        old='            kubernetes_running=kubelet_running(),\n',
        new='',
        kills=('tests/test_v0250_kubernetes_routing.py::test_the_snapshot_asks',),
        reason='the context is only worth something if the snapshot looks for the kubelet',
    ),
    Mutation(
        id='k8s-routing/kubelite-unknown',
        file='bob/checks/_run.py',
        old='_KUBELET_NAMES = frozenset({"kubelet", "kubelite", "k3s", "k3s-server", "k3s-agent"})',
        new='_KUBELET_NAMES = frozenset({"kubelet", "k3s", "k3s-server", "k3s-agent"})',
        kills=('tests/test_v0250_kubernetes_routing.py::test_the_kubelet_by_process_name',),
        reason='MicroK8s runs its kubelet inside a single binary named kubelite',
    ),
    Mutation(
        id='enable-keeps-ssh/bare-enable',
        file='bob/checks/_ufw.py',
        old='    return " && ".join(steps + [f"sudo ufw allow {p}/tcp" for p in ports] + ["sudo ufw enable"])',
        new='    return "sudo ufw enable"',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestTheEnableCommand::test_every_ssh_port_is_allowed_before_the_enable',),
        reason='a bare ufw enable left port 22 silent on a Raspberry Pi reached over SSH',
    ),
    Mutation(
        id='enable-keeps-ssh/unknown-guessed-22',
        file='bob/checks/_ufw.py',
        old='    if ssh_ports is None:\n        return None\n    ports = sorted(set(ssh_ports))',
        new='    ports = [22] if ssh_ports is None else sorted(set(ssh_ports))',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestTheEnableCommand::test_an_unknown_listening_set_gets_no_command',),
        reason='with the listening set unread, allowing 22 alone cuts an sshd on another port; a guess is not a way in',
    ),
    Mutation(
        id='enable-keeps-ssh/install-unknown-guessed',
        file='bob/checks/firewall.py',
        old='    if ssh_ports is None:\n        # Which ports sshd answers on is unknown',
        new='    if False:\n        # Which ports sshd answers on is unknown',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestEveryEnableKeepsSsh::test_installing_a_firewall_without_ports_gets_no_command',),
        reason='installing and enabling a firewall with sshd unplaced may close the port the operator is on',
    ),
    Mutation(
        id='default-deny/unknown-guessed-22',
        file='bob/checks/iptables_nftables.py',
        old='    if target is None or ssh_ports is None:\n',
        new='    if target is None:\n',
        kills=('tests/test_v0244_default_deny_keeps_ssh.py::TestTheWayInIsAcceptedFirst::test_an_unknown_listening_set_gets_no_command',),
        reason='a default-deny with sshd unplaced may drop the port the operator is on',
    ),
    Mutation(
        id='enable-keeps-ssh/any-process-counts',
        file='bob/checks/ports.py',
        old='        ports = {lp.port for lp in external if lp.process.startswith("sshd")}',
        new='        ports = {lp.port for lp in external}',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestWhichPortsSshdAnswersOn::test_no_sshd_at_all',),
        reason='allowing every listening port would open what the firewall is meant to close',
    ),
    Mutation(
        id='enable-keeps-ssh/socket-port-unread',
        file='bob/checks/ports.py',
        old='        ports |= {lp.port for lp in external if lp.process == "systemd" and lp.port in self.ssh_socket_ports}\n',
        new='',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestWhichPortsSshdAnswersOn::test_a_socket_activated_non_standard_port',),
        reason='Mint: ssh.socket on 22 and 2222, systemd holding both; allowing 22 alone cut 2222',
    ),
    Mutation(
        id='enable-keeps-ssh/socket-units-not-read',
        file='bob/checks/ports.py',
        old='                       _run("systemctl", "show", "-p", "Listen", *_SSH_SOCKET_UNITS)))',
        new='                       ""))',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestWhichPortsSshdAnswersOn::test_the_snapshot_reads_the_ssh_socket_units',),
        reason='the parser is only worth something if the snapshot calls it',
    ),
    Mutation(
        id='enable-keeps-ssh/socket-activation-missed',
        file='bob/checks/ports.py',
        old='        if not ports and any(lp.port == 22 and lp.process for lp in external):',
        new='        if False:',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestWhichPortsSshdAnswersOn::test_a_socket_activated_sshd_is_held_by_systemd',),
        reason='Ubuntu 24.04 ssh.socket shows systemd on :22; missing it would enable ufw with nothing allowed',
    ),
    Mutation(
        id='enable-keeps-ssh/nameless-read-as-none',
        file='bob/checks/ports.py',
        old='        if external and not any(lp.process for lp in external):',
        new='        if False:',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestWhichPortsSshdAnswersOn::test_no_process_names_cannot_be_attributed',),
        reason='ss -p without privileges names no process; that is not proof sshd is absent',
    ),
    Mutation(
        id='enable-keeps-ssh/unreadable-read-as-none',
        file='bob/checks/ports.py',
        old='        if not self.ports_readable:\n            return None\n        external =',
        new='        if False:\n            return None\n        external =',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestWhichPortsSshdAnswersOn::test_an_unreadable_listening_set_is_unknown',),
        reason='ss failing is not an empty listening set',
    ),
    Mutation(
        id='enable-keeps-ssh/inactive-bare',
        file='bob/checks/firewall.py',
        old='            cmd=_ufw.enable_cmd(ssh_ports, ipv6_off=status.ipv6_ufw_enabled is False\n                                and ssh_on_ipv6 is not False),\n            detail=',
        new='            cmd="sudo ufw enable",\n            detail=',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestEveryEnableKeepsSsh::test_firewall_inactive',),
        reason='the ALERT the report puts first must not lock out the operator who follows it',
    ),
    Mutation(
        id='enable-keeps-ssh/firewalld-choice-unsaid',
        file='bob/checks/firewall.py',
        old='        return install_fix(_t, _t("firewall.firewalld_keeps_ssh_detail"), "firewalld", then=then)',
        new='        return install_fix(_t, None, "firewalld", then=then)',
        kills=('tests/test_v0244_enable_keeps_ssh.py::test_the_firewalld_detail_says_ssh_stays_in_every_active_zone',),
        reason='SSH kept in every active zone is a starting point the operator must narrow, and must be told so',
    ),
    Mutation(
        id='enable-keeps-ssh/firewalld-default-zone-only',
        file='bob/checks/firewall.py',
        old='''            *("sudo firewall-cmd --get-active-zones | awk '!/^[[:space:]]/{print $1}' | "
              f"xargs -rI{{}} sudo firewall-cmd --permanent --zone={{}} {i}" for i in items),
''',
        new='',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestEveryEnableKeepsSsh::test_installing_firewalld_keeps_ssh_in_every_active_zone',),
        reason='an interface or source bound to a zone without ssh is judged by that zone, not the default',
    ),
    Mutation(
        id='enable-keeps-ssh/install-bare',
        file='bob/checks/firewall.py',
        old='    return install_fix(_t, None, "ufw", then=_ufw.enable_cmd(ssh_ports))',
        new='    return install_fix(_t, None, "ufw", then="sudo ufw enable")',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestEveryEnableKeepsSsh::test_installing_ufw',),
        reason='installing then enabling ufw starts at deny incoming',
    ),
    Mutation(
        id='enable-keeps-ssh/firewalld-without-ssh',
        file='bob/checks/firewall.py',
        old='            *(f"sudo firewall-cmd --permanent {i}" for i in items),\n',
        new='',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestEveryEnableKeepsSsh::test_installing_firewalld_keeps_the_ssh_service',),
        reason='a fresh firewalld default zone need not list ssh',
    ),
    Mutation(
        id='enable-keeps-ssh/nft-bare',
        file='bob/checks/iptables_nftables.py',
        old='            _nft_no_input_cmd = _ufw.enable_cmd(ssh_ports, ipv6_off=ufw_ipv6_off)',
        new='            _nft_no_input_cmd = "sudo ufw enable"',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestEveryEnableKeepsSsh::test_nft_with_no_input_filter',),
        reason='the nft no-input-filter fix enabled ufw bare as well',
    ),
    Mutation(
        id='enable-keeps-ssh/runner-drops-ports',
        file='bob/runner.py',
        old='        ssh_ports=ports_snapshot.ssh_ports,\n        ssh_on_ipv6=ports_snapshot.ssh_on_ipv6,\n        awall=',
        new='        ssh_on_ipv6=ports_snapshot.ssh_on_ipv6,\n        awall=',
        kills=('tests/test_v0244_enable_keeps_ssh.py::test_the_runner_hands_the_ssh_ports_to_both_checks',),
        reason='without the measured ports a non-standard sshd port is not kept',
    ),
    Mutation(
        id='docs/dev-cis-breakdown-unguarded',
        file='DOCUMENTS/README_DEV_FR.md',
        old='226 entrées : 117 CIS formels, 98 best-practice, 7 Docker, 4 Kubernetes)',
        new='226 entrées : 117 CIS formels, 89 best-practice, 7 Docker, 4 Kubernetes)',
        kills=('tests/test_v0211_live_count_claims.py::test_the_readme_tech_cis_breakdown_matches_the_live_categories',),
        reason='README_DEV_FR said 89 best-practice and README_DEV 94 while the live count was 95; no guard read that form',
    ),
    Mutation(
        id='fail2ban-blind/never-flagged',
        file='bob/checks/fail2ban.py',
        old='            and snapshot.syslog_active is False:',
        new='            and False:',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheVerdict::test_files_with_no_syslog_daemon_are_blind',),
        reason='a jail on /var/log/auth.log with no rsyslog counted 0 of 2 failures on a Pi; BOB said protected',
    ),
    Mutation(
        id='fail2ban-blind/unknown-blamed',
        file='bob/checks/fail2ban.py',
        old='            and snapshot.syslog_active is False:',
        new='            and not snapshot.syslog_active:',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheVerdict::test_an_unknown_syslog_state_is_not_blamed',),
        reason='not knowing whether a syslog daemon runs is no proof that none does',
    ),
    Mutation(
        id='fail2ban-blind/file-list-unread',
        file='bob/checks/fail2ban.py',
        old='            files = tuple(line.split(":", 1)[1].split())',
        new='            files = ()',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestWhatTheJailReads::test_a_file_backed_jail',),
        reason='without the File list the blind jail is never seen',
    ),
    Mutation(
        id='fail2ban-blind/journal-unread',
        file='bob/checks/fail2ban.py',
        old='            journal = True',
        new='            journal = False',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestWhatTheJailReads::test_a_journal_backed_jail',),
        reason='a journal jail read as file-only would be blamed for nothing',
    ),
    Mutation(
        id='fail2ban-blind/running-daemon-missed',
        file='bob/checks/fail2ban.py',
        old='    if "active" in states:\n        return True',
        new='    if False:\n        return True',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestIsASyslogDaemonRunning::test_the_answer',),
        reason='a running rsyslog writes auth.log; the jail is not blind then',
    ),
    Mutation(
        id='fail2ban-blind/silence-read-as-none-running',
        file='bob/checks/fail2ban.py',
        old='    if all(state is not None for state in states):\n        return False',
        new='    if True:\n        return False',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestIsASyslogDaemonRunning::test_the_answer',),
        reason='an OpenRC host that names no syslog service has not said none runs',
    ),
    Mutation(
        id='fail2ban-blind/journal-fix-without-journal',
        file='bob/checks/fail2ban.py',
        old='        if snapshot.journal_available:',
        new='        if True:',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheFix::test_no_journal_no_command',),
        reason='backend = systemd is no fix where there is no systemd journal',
    ),
    Mutation(
        id='fail2ban-blind/jail-unquoted',
        file='bob/checks/fail2ban.py',
        old='{shlex.quote(jail)} | "',
        new='{jail} | "',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheFix::test_a_hostile_jail_name_stays_one_word',),
        reason='the jail name comes from fail2ban-client output and lands in a shell command',
    ),
    Mutation(
        id='fail2ban-blind/sources-not-collected',
        file='bob/checks/fail2ban.py',
        old='        if snap.ssh_jail:\n            jail_status',
        new='        if False:\n            jail_status',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestIsASyslogDaemonRunning::test_the_jail_sources_are_collected',),
        reason='the snapshot must ask the SSH jail what it reads',
    ),
    Mutation(
        id='sysctl-durable/winner-ignored',
        file='bob/checks/_run.py',
        old='    if winner is None:\n        return conf',
        new='    if True:\n        return conf',
        kills=('tests/test_v0244_sysctl_durable.py::TestWhereTheFixPersists::test_the_mint_case_goes_to_the_winning_admin_file',),
        reason="on Mint /etc/sysctl.conf undid BOB's fix at boot; persisting to 99-hardening.conf alone is not durable",
    ),
    Mutation(
        id='sysctl-durable/earlier-file-wins',
        file='bob/checks/_run.py',
        old='        if name > mine and key in settings and settings[key] != value:',
        new='        if key in settings and settings[key] != value:',
        kills=('tests/test_v0244_sysctl_durable.py::TestWhereTheFixPersists::test_nothing_later_keeps_bobs_file',),
        reason="a file applied before BOB's loses to it; writing there would be needless",
    ),
    Mutation(
        id='sysctl-durable/same-value-overrides',
        file='bob/checks/_run.py',
        old='        if name > mine and key in settings and settings[key] != value:',
        new='        if name > mine and key in settings:',
        kills=('tests/test_v0244_sysctl_durable.py::TestWhereTheFixPersists::test_a_later_file_with_the_same_value_changes_nothing',),
        reason='a later file that agrees does not undo anything',
    ),
    Mutation(
        id='sysctl-durable/system-file-edited',
        file='bob/checks/_run.py',
        old='    if path.startswith("/etc/"):',
        new='    if True:',
        kills=('tests/test_v0244_sysctl_durable.py::TestWhereTheFixPersists::test_a_system_file_is_left_alone',),
        reason='a file shipped by a package is overwritten at its next update',
    ),
    Mutation(
        id='sysctl-durable/no-masking',
        file='bob/checks/_run.py',
        old='            if name.endswith(".conf") and name not in chosen:',
        new='            if name.endswith(".conf"):',
        kills=('tests/test_v0244_sysctl_durable.py::TestReadingTheBootFiles::test_an_etc_file_masks_the_same_name_shipped_by_the_system',),
        reason='systemd-sysctl reads one file per name, the /etc one first',
    ),
    Mutation(
        id='sysctl-durable/unsorted',
        file='bob/checks/_run.py',
        old='    for name in sorted(chosen):',
        new='    for name in chosen:',
        kills=('tests/test_v0244_sysctl_durable.py::TestReadingTheBootFiles::test_file_name_order_across_directories',),
        reason='the boot order is the file-name order across every directory',
    ),
    Mutation(
        id='sysctl-durable/boot-unused',
        file='bob/checks/_run.py',
        old='    if boot:\n        conf = durable_sysctl_conf(param, boot, conf)',
        new='    if False:\n        conf = durable_sysctl_conf(param, boot, conf)',
        kills=('tests/test_v0244_sysctl_durable.py::TestTheChecksUseIt::test_hardening',),
        reason='the checks must persist where the value survives the reboot',
    ),
    Mutation(
        id='sysctl-durable/snapshot-unread',
        file='bob/checks/hardening.py',
        old='            boot_sysctl=read_sysctl_boot_files(),\n',
        new='',
        kills=('tests/test_v0244_sysctl_durable.py::TestTheChecksUseIt::test_the_snapshot_reads_the_boot_files',),
        reason='without the boot files the durable choice never runs on a live host',
    ),
    Mutation(
        id='auditd-field/directory-watch-ignored',
        file='bob/checks/auditd.py',
        old='    return any(path == w or path.startswith(w + "/") for w in watched)',
        new='    return path in watched',
        kills=('tests/test_v0244_auditd_field.py::TestCoverage::test_a_directory_watch_covers_the_files_under_it',),
        reason='-w /etc/ journalled a write to /etc/shadow on a Pi; BOB called it unwatched',
    ),
    Mutation(
        id='auditd-field/syscall-form-ignored',
        file='bob/checks/auditd.py',
        old='            for fm in re.finditer(r"-F\\s+(?:path|dir)=(\\/\\S+)", line):',
        new='            for fm in []:',
        kills=('tests/test_v0244_auditd_field.py::TestCoverage::test_the_syscall_form_is_a_watch',),
        reason='-a always,exit -F path=/etc/shadow journalled the write; BOB called it unwatched',
    ),
    Mutation(
        id='auditd-field/dir-field-ignored',
        file='bob/checks/auditd.py',
        old='            for fm in re.finditer(r"-F\\s+(?:path|dir)=(\\/\\S+)", line):',
        new='            for fm in re.finditer(r"-F\\s+(?:path)=(\\/\\S+)", line):',
        kills=('tests/test_v0244_auditd_field.py::TestCoverage::test_a_dir_field_is_a_watch',),
        reason='-F dir= watches a tree the way -w on a directory does',
    ),
    Mutation(
        id='auditd-field/prefix-without-slash',
        file='bob/checks/auditd.py',
        old='    return any(path == w or path.startswith(w + "/") for w in watched)',
        new='    return any(path == w or path.startswith(w) for w in watched)',
        kills=('tests/test_v0244_auditd_field.py::TestCoverage::test_a_shared_prefix_is_not_a_directory',),
        reason='/etc/sha is not a directory of /etc/shadow',
    ),
    Mutation(
        id='auditd-field/lock-not-said',
        file='bob/checks/auditd.py',
        old='    if snapshot.immutable:\n        result.info(message=_t("auditd.immutable")',
        new='    if False:\n        result.info(message=_t("auditd.immutable")',
        kills=('tests/test_v0244_auditd_field.py::TestLockedRules::test_the_lock_is_said_and_no_reload_is_handed_out',),
        reason='a locked audit loads new rules only at boot; the report must say so',
    ),
    Mutation(
        id='auditd-field/reload-while-locked',
        file='bob/checks/auditd.py',
        old='    return " && ".join(parts) + ("" if immutable else " && sudo augenrules --load")',
        new='    return " && ".join(parts) + " && sudo augenrules --load"',
        kills=('tests/test_v0244_auditd_field.py::TestLockedRules::test_the_lock_is_said_and_no_reload_is_handed_out',),
        reason='augenrules --load exits 0 and changes nothing while locked',
    ),
    Mutation(
        id='auditd-field/no-rules-reload-while-locked',
        file='bob/checks/auditd.py',
        old='            _no_rules_cmd = _no_rules_cmd.removesuffix("\\nsudo augenrules --load")',
        new='            pass',
        kills=('tests/test_v0244_auditd_field.py::TestLockedRules::test_no_rules_while_locked',),
        reason='the same dead reload on the no-rules fix',
    ),
    Mutation(
        id='auditd-field/locked-read-as-running',
        file='bob/checks/auditd.py',
        old='            elif pid:\n                snap.service_active = pid.group(1) != "0"\n',
        new='            elif False:\n                snap.service_active = pid.group(1) != "0"\n',
        kills=('tests/test_v0244_auditd_field.py::TestServiceStateWithoutSystemd::test_locked_with_no_daemon_is_stopped',),
        reason='Fedora: rules locked and auditd killed still read enabled 2, with pid 0',
    ),
    Mutation(
        id='auditd-field/locked-read-as-stopped',
        file='bob/checks/auditd.py',
        old='                snap.service_active = pid.group(1) != "0"\n',
        new='                snap.service_active = enabled is not None and enabled.group(1) == "1"\n',
        kills=('tests/test_v0244_auditd_field.py::TestServiceStateWithoutSystemd::test_locked_is_running',),
        reason='Alpine: auditd running with enabled 2, BOB said not running (WARN -1)',
    ),
    Mutation(
        id='auditd-field/init-asked-only-with-systemctl',
        file='bob/checks/auditd.py',
        old='        state = unit_active_state("auditd")\n        status',
        new='        state = unit_active_state("auditd") if _command_exists("systemctl") else None\n        status',
        kills=('tests/test_v0244_auditd_field.py::TestServiceStateWithoutSystemd::test_openrc_answers_without_systemctl',),
        reason='OpenRC answers for auditd; gating on systemctl skipped it',
    ),
    Mutation(
        id='service-enable/auditd-systemctl',
        file='bob/checks/auditd.py',
        old='            cmd=service_enable_cmd("auditd"),',
        new='            cmd="sudo systemctl enable --now auditd",',
        kills=('tests/test_v0244_auditd_field.py::TestTheEnableFixFollowsTheInit::test_auditd',),
        reason="Alpine has neither sudo's systemctl nor systemd",
    ),
    Mutation(
        id='service-enable/fail2ban-systemctl',
        file='bob/checks/fail2ban.py',
        old='            cmd=service_enable_cmd("fail2ban"),',
        new='            cmd="sudo systemctl enable --now fail2ban",',
        kills=('tests/test_v0244_auditd_field.py::TestTheEnableFixFollowsTheInit::test_fail2ban',),
        reason='the same hard-coded systemctl in fail2ban',
    ),
    Mutation(
        id='service-enable/apparmor-systemctl',
        file='bob/checks/mac_policy.py',
        old='            cmd=service_enable_cmd("apparmor"),',
        new='            cmd="sudo systemctl enable --now apparmor",',
        kills=('tests/test_v0244_auditd_field.py::TestTheEnableFixFollowsTheInit::test_apparmor_uses_the_helper',),
        reason='the same hard-coded systemctl in mac_policy',
    ),
    Mutation(
        id='fail2ban-blind/override-sorted-too-early',
        file='bob/checks/fail2ban.py',
        old='    later = [n for n in existing if n > name]',
        new='    later = []',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheFix::test_the_override_is_read_after_every_existing_local',),
        reason='on the Pi a later zz-bobtest.local undid the fix; the jail stayed blind',
    ),
    Mutation(
        id='clamd-openrc/state-not-asked',
        file='bob/checks/clamav.py',
        old='            snap.clamd_active = unit_active_state(snap.clamd_unit) == "active"\n',
        new='            snap.clamd_active = False\n',
        kills=('tests/test_v0244_clamd_unit.py::TestARunningDaemonWithoutSystemd::test_openrc_answers',),
        reason='Alpine: clamd running under OpenRC was reported not running',
    ),
    Mutation(
        id='clamd-openrc/configured-socket-ignored',
        file='bob/checks/clamav.py',
        old='            for socket_path in [*_CLAMD_SOCKETS, *map(Path, _configured_sockets())]:\n',
        new='            for socket_path in _CLAMD_SOCKETS:\n',
        kills=('tests/test_v0244_clamd_unit.py::TestARunningDaemonWithoutSystemd::test_the_configured_socket_shows_it_running',),
        reason="Alpine's socket is clamd.sock, not the clamd.ctl the fallback looked for",
    ),
    Mutation(
        id='clamd-socket/unscored',
        file='bob/checks/clamav.py',
        old='            points=1,\n            detail=_t("clamav.socket_open_to_all_detail"),\n',
        new='            points=0,\n            detail=_t("clamav.socket_open_to_all_detail"),\n',
        kills=('tests/test_v0244_clamd_unit.py::TestASocketEveryLocalUserCanReach::test_it_is_said_without_a_command',),
        reason='any local process can stop the antivirus through this socket; 0.25.0 scores it, and a zero would hide it again',
    ),
    Mutation(
        id='clamd-socket/mode-ignored',
        file='bob/checks/clamav.py',
        old='        if not st.st_mode & stat.S_IWOTH:\n            return False\n',
        new='',
        kills=('tests/test_v0244_clamd_unit.py::TestASocketEveryLocalUserCanReach::test_who_can_connect[493-432-False]',),
        reason='a 0660 socket refused the unprivileged user; reading it as open would be a false alarm',
    ),
    Mutation(
        id='clamd-socket/directory-ignored',
        file='bob/checks/clamav.py',
        old='            if not os.stat(parent).st_mode & stat.S_IXOTH:\n                return False\n',
        new='',
        kills=('tests/test_v0244_clamd_unit.py::TestASocketEveryLocalUserCanReach::test_who_can_connect[456-438-False]',),
        reason="Fedora's 0710 /run/clamd.scan refused the unprivileged user despite the 0666 socket",
    ),
    Mutation(
        id='clamd-socket/commented-counted',
        file='bob/checks/clamav.py',
        old='_LOCAL_SOCKET_RE = re.compile(r"^\\s*LocalSocket\\s+(\\S+)", re.MULTILINE)',
        new='_LOCAL_SOCKET_RE = re.compile(r"^\\s*#?LocalSocket\\s+(\\S+)", re.MULTILINE)',
        kills=('tests/test_v0244_clamd_unit.py::TestASocketEveryLocalUserCanReach::test_a_commented_socket_is_not_the_daemon_s',),
        reason='a commented LocalSocket is not where clamd listens',
    ),
    Mutation(
        id='clamd-socket/not-said',
        file='bob/checks/clamav.py',
        old='    elif snapshot.clamd_socket_open:\n',
        new='    elif False:\n',
        kills=('tests/test_v0244_clamd_unit.py::TestASocketEveryLocalUserCanReach::test_it_is_said_without_a_command',),
        reason='an unprivileged user stopped clamd with SHUTDOWN on Alpine and Debian as packaged',
    ),
    Mutation(
        id='clamd-socket/not-collected',
        file='bob/checks/clamav.py',
        old='            snap.clamd_socket_open = _socket_open_to_all()\n',
        new='            snap.clamd_socket_open = ""\n',
        kills=('tests/test_v0244_clamd_unit.py::TestASocketEveryLocalUserCanReach::test_the_snapshot_looks_when_the_daemon_runs',),
        reason='the probe is only worth something if the snapshot runs it',
    ),
    Mutation(
        id='clamd-unit/debian-name-everywhere',
        file='bob/checks/clamav.py',
        old='            cmd=_clamd_enable_cmd(snapshot),\n            key="clamav.clamd_inactive",',
        new='            cmd="sudo systemctl enable --now clamav-daemon",\n            key="clamav.clamd_inactive",',
        kills=('tests/test_v0244_clamd_unit.py::TestTheFix::test_fedora_gets_its_socket_and_database_first',),
        reason='Fedora ships clamd@.service, openSUSE clamd.service: clamav-daemon does not exist there',
    ),
    Mutation(
        id='clamd-unit/units-not-probed',
        file='bob/checks/clamav.py',
        old='        if any(path_exists(Path(d) / unit_file) for d in _UNIT_DIRS):',
        new='        if False:',
        kills=('tests/test_v0244_clamd_unit.py::TestWhichUnit::test_the_unit_the_package_ships',),
        reason='the unit is the one the package ships, measured per family',
    ),
    Mutation(
        id='clamd-unit/openrc-missed',
        file='bob/checks/clamav.py',
        old='        return "clamd" if path_exists(Path("/etc/init.d/clamd")) else ""',
        new='        return ""',
        kills=('tests/test_v0244_clamd_unit.py::TestWhichUnit::test_openrc_ships_clamd',),
        reason="Alpine ships clamd as an OpenRC script, with no systemd unit at all",
    ),
    Mutation(
        id='clamd-unit/socket-step-dropped',
        file='bob/checks/clamav.py',
        old='    if snapshot.clamd_needs_socket:\n        sock',
        new='    if False:\n        sock',
        kills=('tests/test_v0244_clamd_unit.py::TestTheFix::test_fedora_gets_its_socket_and_database_first',),
        reason="Fedora's clamd@scan failed: 'Please define server type' — no socket in scan.conf",
    ),
    Mutation(
        id='clamd-unit/freshclam-step-dropped',
        file='bob/checks/clamav.py',
        old='    if snapshot.db_age_days is None and snapshot.freshclam_installed:',
        new='    if False:',
        kills=('tests/test_v0244_clamd_unit.py::TestTheFix::test_fedora_gets_its_socket_and_database_first',),
        reason='clamd refuses to start without a signature database',
    ),
    Mutation(
        id='clamd-unit/command-without-daemon',
        file='bob/checks/clamav.py',
        old='    if not snapshot.clamd_unit:\n        return None',
        new='    if False:\n        return None',
        kills=('tests/test_v0244_clamd_unit.py::TestTheFix::test_no_daemon_shipped_no_command',),
        reason='enabling a unit the host does not ship fails; no command is better than a false one',
    ),
    Mutation(
        id='clamd-unit/socket-misread',
        file='bob/checks/clamav.py',
        old='    return re.search(r"^\\s*(LocalSocket|TCPSocket)\\s", text, re.MULTILINE) is None',
        new='    return True',
        kills=('tests/test_v0244_clamd_unit.py::TestScanConf::test_the_socket_lines',),
        reason='a configured scan.conf must not be edited again',
    ),
    Mutation(
        id='sysctl-drift/never-compared',
        file='bob/checks/_run.py',
        old='        if boot is not None and _sysctl_norm(boot[0]) != _sysctl_norm(value):',
        new='        if False:',
        kills=('tests/test_v0244_sysctl_durable.py::TestALiveValueTheBootFilesUndo::test_a_live_value_the_files_undo_is_said',),
        reason='sysctl -w lasts until the reboot; the OK on the live value was all BOB said',
    ),
    Mutation(
        id='sysctl-drift/raw-strings-compared',
        file='bob/checks/_run.py',
        old='        if boot is not None and _sysctl_norm(boot[0]) != _sysctl_norm(value):',
        new='        if boot is not None and boot[0] != str(value):',
        kills=('tests/test_v0244_sysctl_durable.py::TestALiveValueTheBootFilesUndo::test_agreeing_files_say_nothing',),
        reason="' 0 ' in a file and False live are the same value",
    ),
    Mutation(
        id='sysctl-drift/first-file-wins',
        file='bob/checks/_run.py',
        old='            if key in settings:\n                boot = (settings[key], path)',
        new='            if key in settings and boot is None:\n                boot = (settings[key], path)',
        kills=('tests/test_v0244_sysctl_durable.py::TestALiveValueTheBootFilesUndo::test_the_last_file_is_the_boot_value',),
        reason='the last file applied at boot sets the value',
    ),
    Mutation(
        id='sysctl-drift/unknown-compared',
        file='bob/checks/_run.py',
        old='        if value is None:\n            continue\n        boot = None',
        new='        if False:\n            continue\n        boot = None',
        kills=('tests/test_v0244_sysctl_durable.py::TestALiveValueTheBootFilesUndo::test_an_unknown_live_value_is_not_compared',),
        reason='an unexposed knob has no live value to contradict',
    ),
    Mutation(
        id='sysctl-drift/kernel-silent',
        file='bob/checks/kernel_hardening.py',
        old='    report_boot_drift(result, _t, "kernel_hardening.reverts_at_boot", {',
        new='    (lambda *a: None)(result, _t, "kernel_hardening.reverts_at_boot", {',
        kills=('tests/test_v0244_sysctl_durable.py::TestALiveValueTheBootFilesUndo::test_kernel_hardening_says_it_too',),
        reason='kernel sysctls revert the same way',
    ),
    Mutation(
        id='clamd-unit/message-names-debian-unit',
        file='bob/checks/clamav.py',
        old='            message=_t("clamav.clamd_inactive", unit=snapshot.clamd_unit or "clamd"),',
        new='            message=_t("clamav.clamd_inactive", unit="clamav-daemon"),',
        kills=('tests/test_v0244_clamd_unit.py::test_the_message_names_the_unit_this_host_ships',),
        reason='the message named clamav-daemon on a Fedora whose daemon is clamd@scan',
    ),
    Mutation(
        id='ntp-openrc/openrc-not-asked',
        file='bob/checks/ntp.py',
        old='        if is_unit_active(svc) if systemd else unit_active_state(svc) == "active":',
        new='        if is_unit_active(svc) if systemd else False:',
        kills=('tests/test_v0244_ntp_openrc.py::TestTheRunningClientIsSeen::test_busybox_ntpd_under_openrc',),
        reason="Alpine's ntpd was started; BOB asked only systemctl and said NTP was not enabled",
    ),
    Mutation(
        id='ntp-openrc/sync-assumed',
        file='bob/checks/ntp.py',
        old='    # This used to return True — an assumption reported as "synchronised".\n    return None',
        new='    # This used to return True — an assumption reported as "synchronised".\n    return True',
        kills=('tests/test_v0244_ntp_openrc.py::TestTheRunningClientIsSeen::test_no_tool_no_assumed_sync',),
        reason='BusyBox ntpd has no query tool; synchronised is not measured',
    ),
    Mutation(
        id='ntp-openrc/unknown-read-as-unsynced',
        file='bob/checks/ntp.py',
        old='    if snapshot.ntp_enabled and snapshot.ntp_synchronized is None:',
        new='    if False:',
        kills=('tests/test_v0244_ntp_openrc.py::TestTheRunningClientIsSeen::test_it_is_neither_disabled_nor_called_synchronised',),
        reason='not being able to verify sync is not a measured drift',
    ),
    Mutation(
        id='ntp-openrc/client-ignored',
        file='bob/checks/ntp.py',
        old='    if snapshot.openrc_client:\n        return service_enable_cmd(snapshot.openrc_client)',
        new='    if False:\n        return service_enable_cmd(snapshot.openrc_client)',
        kills=('tests/test_v0244_ntp_openrc.py::TestTheNotEnabledFix::test_openrc_starts_its_own_client',),
        reason='an OpenRC host starts its own client, not systemd-timesyncd',
    ),
    Mutation(
        id='ntp-openrc/command-without-client',
        file='bob/checks/ntp.py',
        old='    if openrc_available() and not _command_exists("systemctl"):\n        return None\n    return "sudo systemctl',
        new='    if False:\n        return None\n    return "sudo systemctl',
        kills=('tests/test_v0244_ntp_openrc.py::TestTheNotEnabledFix::test_openrc_without_a_client_gets_no_command',),
        reason='a systemctl command on a host without systemd is no fix',
    ),
    Mutation(
        id='ntp-openrc/scripts-unprobed',
        file='bob/checks/ntp.py',
        old='                (s for s in _OPENRC_NTP if path_exists(Path(f"/etc/init.d/{s}"))), "")',
        new='                (s for s in ()), "")',
        kills=('tests/test_v0244_ntp_openrc.py::TestTheNotEnabledFix::test_openrc_starts_its_own_client',),
        reason='the client to start is the one OpenRC has a script for',
    ),
    Mutation(
        id='auditd-filter/narrowing-field-counts',
        file='bob/checks/auditd.py',
        old='            if set(_FIELD_NAME.findall(line)) - _NEUTRAL_FIELDS or re.search(r"\\s-C\\s", line):\n',
        new='            if re.search(r"\\s-C\\s", line):\n',
        kills=('tests/test_v0244_auditd_field.py::TestAFilterThatNarrowsTheRule::test_a_narrowing_filter_does_not_count[-F success=0 ]',),
        reason='a success=0 rule journalled no successful write on Fedora and BOB called the file watched',
    ),
    Mutation(
        id='auditd-filter/field-comparison-counts',
        file='bob/checks/auditd.py',
        old='            if set(_FIELD_NAME.findall(line)) - _NEUTRAL_FIELDS or re.search(r"\\s-C\\s", line):\n',
        new='            if set(_FIELD_NAME.findall(line)) - _NEUTRAL_FIELDS:\n',
        kills=('tests/test_v0244_auditd_field.py::TestAFilterThatNarrowsTheRule::test_a_narrowing_filter_does_not_count[-C auid!=uid ]',),
        reason='a -C comparison restricts which writes a rule records, like any other filter',
    ),
    Mutation(
        id='auditd-compat/one-arch-enough',
        file='bob/checks/auditd.py',
        old='        if native_arch is None or (native_arch in seen and (compat_arch is None or compat_arch in seen)):',
        new='        if native_arch is None or (native_arch in seen and True):',
        kills=('tests/test_v0244_auditd_field.py::TestBothArchitecturesOnA64BitKernel::test_a_kernel_that_runs_32_bit_programs',),
        reason='an arch=b64 rule journalled nothing for a 32-bit write on x86_64',
    ),
    Mutation(
        id='auditd-compat/no-arch-is-not-native',
        file='bob/checks/auditd.py',
        old='            arch = arch_m.group(1) if arch_m else native_arch',
        new='            arch = arch_m.group(1) if arch_m else compat_arch',
        kills=('tests/test_v0244_auditd_field.py::TestBothArchitecturesOnA64BitKernel::test_a_kernel_that_does_not',),
        reason='a rule with no arch field is resolved against the native syscall table',
    ),
    Mutation(
        id='auditd-compat/not-passed',
        file='bob/checks/auditd.py',
        old='        snap.watched_files = _parse_watched_files(rules_out, _native_arch(), _compat_arch())',
        new='        snap.watched_files = _parse_watched_files(rules_out, _native_arch())',
        kills=('tests/test_v0244_auditd_field.py::TestOnlyRulesThatJournalAWriteCount::test_the_snapshot_passes_the_arch',),
        reason='the compat check is only worth something if the snapshot asks it',
    ),
    Mutation(
        id='auditd-compat/unreadable-config-credited',
        file='bob/checks/auditd.py',
        old='    if config is None:\n        return "b32"',
        new='    if config is None:\n        return None',
        kills=('tests/test_v0244_auditd_field.py::TestBothArchitecturesOnA64BitKernel::test_does_this_kernel_run_32_bit_programs',),
        reason='not knowing whether 32-bit programs run is no proof they do not',
    ),
    Mutation(
        id='auditd-compat/x86-config-ignored',
        file='bob/checks/auditd.py',
        old='        if not re.search(r"^CONFIG_IA32_EMULATION=y", config, re.MULTILINE):\n            return None\n',
        new='',
        kills=('tests/test_v0244_auditd_field.py::TestBothArchitecturesOnA64BitKernel::test_does_this_kernel_run_32_bit_programs',),
        reason='a kernel built without IA32 emulation runs no 32-bit program',
    ),
    Mutation(
        id='auditd-compat/cmdline-ignored',
        file='bob/checks/auditd.py',
        old='        if m:\n            return "b32" if',
        new='        if False:\n            return "b32" if',
        kills=('tests/test_v0244_auditd_field.py::TestBothArchitecturesOnA64BitKernel::test_does_this_kernel_run_32_bit_programs',),
        reason='ia32_emulation= on the command line decides over the build default',
    ),
    Mutation(
        id='auditd-compat/default-disabled-ignored',
        file='bob/checks/auditd.py',
        old='        return None if re.search(r"^CONFIG_IA32_EMULATION_DEFAULT_DISABLED=y", config, re.MULTILINE) else "b32"',
        new='        return "b32"',
        kills=('tests/test_v0244_auditd_field.py::TestBothArchitecturesOnA64BitKernel::test_does_this_kernel_run_32_bit_programs',),
        reason='IA32 emulation built but disabled by default runs no 32-bit program',
    ),
    Mutation(
        id='auditd-compat/arm-compat-ignored',
        file='bob/checks/auditd.py',
        old='    return "b32" if re.search(r"^CONFIG_COMPAT=y", config, re.MULTILINE) else None',
        new='    return None',
        kills=('tests/test_v0244_auditd_field.py::TestBothArchitecturesOnA64BitKernel::test_does_this_kernel_run_32_bit_programs',),
        reason='a 64-bit Arm kernel with CONFIG_COMPAT runs a 32-bit userland',
    ),
    Mutation(
        id='auditd-compat/32-bit-kernel-has-compat',
        file='bob/checks/auditd.py',
        old='    if _native_arch() != "b64":\n        return None\n    config',
        new='    config',
        kills=('tests/test_v0244_auditd_field.py::TestBothArchitecturesOnA64BitKernel::test_does_this_kernel_run_32_bit_programs',),
        reason='a 32-bit kernel has one syscall table',
    ),
    Mutation(
        id='auditd-negative/read-only-watch-counts',
        file='bob/checks/auditd.py',
        old='            if perm is None or "w" in perm.group(1):  # no -p means rwxa',
        new='            if True:',
        kills=('tests/test_v0244_auditd_field.py::TestOnlyRulesThatJournalAWriteCount::test_rules_that_journal_nothing_do_not_count',),
        reason='-w -p r journalled no write on Alpine; BOB called the file watched',
    ),
    Mutation(
        id='auditd-negative/never-counts',
        file='bob/checks/auditd.py',
        old='            if "always" not in action.split(","):\n                continue',
        new='            if False:\n                continue',
        kills=('tests/test_v0244_auditd_field.py::TestOnlyRulesThatJournalAWriteCount::test_rules_that_journal_nothing_do_not_count',),
        reason='an -a never,exit rule journalled nothing for a write on Alpine',
    ),
    Mutation(
        id='auditd-negative/no-perm-counts',
        file='bob/checks/auditd.py',
        old='            if perm is None or "w" not in perm.group(1):\n                continue',
        new='            if False:\n                continue',
        kills=('tests/test_v0244_auditd_field.py::TestOnlyRulesThatJournalAWriteCount::test_rules_that_journal_nothing_do_not_count',),
        reason='a -S openat rule without perm missed the write on Alpine',
    ),
    Mutation(
        id='auditd-negative/foreign-arch-counts',
        file='bob/checks/auditd.py',
        old='        if native_arch is None or (native_arch in seen and (compat_arch is None or compat_arch in seen)):',
        new='        if True:',
        kills=('tests/test_v0244_auditd_field.py::TestOnlyRulesThatJournalAWriteCount::test_rules_that_journal_nothing_do_not_count',),
        reason='an arch=b32 rule on x86_64 journalled nothing for a 64-bit write',
    ),
    Mutation(
        id='auditd-negative/arch-from-python',
        file='bob/checks/auditd.py',
        old='    return "b64" if os.uname().machine in _64BIT_MACHINES else "b32"',
        new='    return "b64"',
        kills=('tests/test_v0244_auditd_field.py::TestOnlyRulesThatJournalAWriteCount::test_the_native_arch_follows_the_kernel',),
        reason='the Pi is armv6l: its rules are b32',
    ),
    Mutation(
        id='auditd-negative/arch-not-passed',
        file='bob/checks/auditd.py',
        old='        snap.watched_files = _parse_watched_files(rules_out, _native_arch(), _compat_arch())',
        new='        snap.watched_files = _parse_watched_files(rules_out)',
        kills=('tests/test_v0244_auditd_field.py::TestOnlyRulesThatJournalAWriteCount::test_the_snapshot_passes_the_arch',),
        reason='without the native arch every arch counts',
    ),
    Mutation(
        id='fail2ban-fed/unproven-not-a-ceiling',
        file='bob/visibility.py',
        old='    "fail2ban.ssh_jail_file_silent",\n',
        new='',
        kills=("tests/test_v0244_fail2ban_blind_jail.py::test_an_unproven_jail_bounds_the_score[False-fail2ban.ssh_jail_file_silent]",),
        reason='a jail BOB cannot prove fed may hide a one-point deduction, so the score is a ceiling',
    ),
    Mutation(
        id='ntp-openrc/unknown-sync-not-a-ceiling',
        file='bob/visibility.py',
        old='    "ntp.sync_unknown",\n',
        new='',
        kills=("tests/test_v0244_ntp_openrc.py::test_an_unverified_clock_bounds_the_score",),
        reason='an unsynchronised clock costs a point BOB cannot see under BusyBox ntpd',
    ),
    Mutation(
        id='fail2ban-fed/no-journal-trusted',
        file='bob/checks/fail2ban.py',
        old='                if snap.ssh_jail_fed is True and (latest is None or _syslog_started_after(entry)):\n',
        new='                if snap.ssh_jail_fed is True and latest is not None and _syslog_started_after(entry):\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::test_without_a_journal_an_old_line_is_not_proof',),
        reason='without a journal an sshd line in the file proves it was fed once, not that it still is',
    ),
    Mutation(
        id='fail2ban-fed/reload-daemon-dated',
        file='bob/checks/fail2ban.py',
        old='        if fields.get("Id") != "rsyslog.service":\n',
        new='        if False:\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestRoutedByTheRoutingInForceNow::test_a_daemon_that_reroutes_on_reload_cannot_be_dated',),
        reason='syslog-ng re-routed on reload with its start time unchanged; dating it by that time proves nothing',
    ),
    Mutation(
        id='fail2ban-fed/ok-scope-unsaid',
        file='bob/checks/fail2ban.py',
        old='            detail=(_t("fail2ban.ssh_jail_active_file_detail")\n                    if snapshot.ssh_jail_files and not snapshot.ssh_jail_journal else ""),\n',
        new='',
        kills=("tests/test_v0244_fail2ban_blind_jail.py::test_a_file_ok_says_what_it_rests_on[en-This is not a proof that every failure reaches the file]",),
        reason='an OK on a file covers the failure kinds seen since rsyslog started; read bare it claims every kind',
    ),
    Mutation(
        id='fail2ban-fed/one-kind-enough',
        file='bob/checks/fail2ban.py',
        old='            kinds[kind] = entry\n',
        new='            kinds["failure"] = entry\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheFailuresAreWhatCounts::test_one_kind_held_another_routed_away',),
        reason='Mint: invalid users routed away, a refused key in auth.log, and the latest failure alone made BOB say OK',
    ),
    Mutation(
        id='fail2ban-fed/failures-not-required',
        file='bob/checks/fail2ban.py',
        old='                if failures:\n',
        new='                if False:\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheFailuresAreWhatCounts::test_failures_routed_elsewhere',),
        reason='Mint: failures routed to another file, the jail counted none, and the latest sshd message made BOB say OK',
    ),
    Mutation(
        id='fail2ban-fed/misses-failures-said-stale',
        file='bob/checks/fail2ban.py',
        old='        elif snapshot.ssh_jail_misses_failures:\n',
        new='        elif False:\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheFailuresAreWhatCounts::test_failures_routed_elsewhere',),
        reason='a file missing the failures is the cause to name, not a stale file',
    ),
    Mutation(
        id='fail2ban-fed/accepted-login-is-a-failure',
        file='bob/checks/fail2ban.py',
        old='_SSHD_FAILURE = re.compile(r"Failed (?:password|publickey|keyboard-interactive|none)|[Ii]nvalid user"\n',
        new='_SSHD_FAILURE = re.compile(r"Accepted|Failed (?:password|publickey|keyboard-interactive|none)|[Ii]nvalid user"\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheFailuresAreWhatCounts::test_what_is_a_failure',),
        reason='a successful login is not what the jail counts; taking it for a failure hides misrouted ones',
    ),
    Mutation(
        id='fail2ban-fed/restart-ignored',
        file='bob/checks/fail2ban.py',
        old='                if snap.ssh_jail_fed is True and (latest is None or _syslog_started_after(entry)):\n',
        new='                if False:\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestRoutedByTheRoutingInForceNow::test_the_verdict_is_unverified',),
        reason="rsyslog re-routed after sshd's last message left that message in the file, and BOB said OK",
    ),
    Mutation(
        id='fail2ban-fed/earlier-boot-trusted',
        file='bob/checks/fail2ban.py',
        old='    if boot is None or entry.get("_BOOT_ID") != boot:\n',
        new='    if boot is None:\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestRoutedByTheRoutingInForceNow::test_logged_in_an_earlier_boot',),
        reason='a message from an earlier boot predates the daemon running now, whatever its monotonic clock says',
    ),
    Mutation(
        id='fail2ban-fed/no-daemon-start-trusted',
        file='bob/checks/fail2ban.py',
        old='    return not starts or max(starts) > logged\n',
        new='    return bool(starts) and max(starts) > logged\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestRoutedByTheRoutingInForceNow::test_no_running_daemon_to_date',),
        reason='when no running daemon gives its start time the routing in force cannot be dated',
    ),
    Mutation(
        id='fail2ban-fed/restart-comparison-inverted',
        file='bob/checks/fail2ban.py',
        old='    return not starts or max(starts) > logged\n',
        new='    return not starts or max(starts) < logged\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestRoutedByTheRoutingInForceNow::test_the_daemon_restarted_since',),
        reason='a daemon started after the message routed nothing of it',
    ),
    Mutation(
        id='fail2ban-fed/old-message-is-proof',
        file='bob/checks/fail2ban.py',
        old='    if latest is not None:\n        return any(latest in tail for tail in tails)\n',
        new='',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestAnOldMessageIsNotAFeed::test_an_old_message_without_the_latest_is_not_proof',),
        reason='an sshd message from before a routing change proves the file was fed once, not that it still is',
    ),
    Mutation(
        id='fail2ban-fed/journal-not-asked',
        file='bob/checks/fail2ban.py',
        old='                entries = _sshd_entries() if snap.journal_available else []\n',
        new='                entries = []\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestAnOldMessageIsNotAFeed::test_the_snapshot_says_stale',),
        reason="without the journal's latest message an old line in the file reads as a live feed",
    ),
    Mutation(
        id='fail2ban-fed/stale-said-silent',
        file='bob/checks/fail2ban.py',
        old='        elif snapshot.ssh_jail_stale:\n',
        new='        elif False:\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestAnOldMessageIsNotAFeed::test_the_verdict',),
        reason='a file with older sshd messages is not silent; saying so would send the operator to the wrong cause',
    ),
    Mutation(
        id='fail2ban-fed/syslog-is-proof',
        file='bob/checks/fail2ban.py',
        old='            and snapshot.ssh_jail_fed is False:\n',
        new='            and False:\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheVerdict::test_a_running_syslog_daemon_is_not_proof_on_its_own',),
        reason='Mint: rsyslog running, jail on a file it does not write, 0 of 2 failures counted, BOB said OK',
    ),
    Mutation(
        id='fail2ban-fed/unread-credited',
        file='bob/checks/fail2ban.py',
        old='            and snapshot.ssh_jail_fed is None:\n',
        new='            and snapshot.syslog_active is None:\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheVerdict::test_an_unread_file_is_not_credited',),
        reason="a jail file BOB could not read is no proof sshd's messages reach it",
    ),
    Mutation(
        id='fail2ban-fed/session-process-missed',
        file='bob/checks/fail2ban.py',
        old='_SSHD_LINE = re.compile(rb"\\bsshd(?:-session)?\\[\\d+\\]:")',
        new='_SSHD_LINE = re.compile(rb"\\bsshd\\[\\d+\\]:")',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestDoesTheFileHoldSshdMessages::test_openssh_9_8_session_process',),
        reason='OpenSSH 9.8+ logs authentication from sshd-session',
    ),
    Mutation(
        id='fail2ban-fed/any-content-counts',
        file='bob/checks/fail2ban.py',
        old='    return any(_SSHD_LINE.search(tail) for tail in tails)\n',
        new='    return any(tails)\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestDoesTheFileHoldSshdMessages::test_a_file_nothing_sends_sshd_to',),
        reason='a file full of other messages is not fed by sshd',
    ),
    Mutation(
        id='fail2ban-fed/not-collected',
        file='bob/checks/fail2ban.py',
        old='                snap.ssh_jail_fed = _jail_files_fed(snap.ssh_jail_files, latest)\n',
        new='                snap.ssh_jail_fed = None\n',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestDoesTheFileHoldSshdMessages::test_the_snapshot_reads_them',),
        reason='the probe is only worth something if the snapshot runs it',
    ),
    Mutation(
        id='fail2ban-blind/unknown-credited',
        file='bob/checks/fail2ban.py',
        old='            and snapshot.ssh_jail_fed is None:\n        # Not knowing',
        new='            and False:\n        # Not knowing',
        kills=('tests/test_v0244_fail2ban_blind_jail.py::TestTheVerdict::test_an_unknown_syslog_state_is_not_credited_either',),
        reason='an unknown log source is no proof of protection; it must not read as an OK',
    ),
    Mutation(
        id='enable-keeps-ssh/ipv6-path-cut',
        file='bob/checks/_ufw.py',
        old='    steps = [_IPV6_ON] if ipv6_off and ports else []',
        new='    steps = []',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestAnIpv6SshPath::test_ipv6_is_turned_on_before_the_allow',),
        reason='with IPV6=no an allow cannot keep an SSH session over IPv6',
    ),
    Mutation(
        id='enable-keeps-ssh/ipv6-family-ignored',
        file='bob/checks/ports.py',
        old='        return any(lp.proto == "tcp" and not lp.is_loopback and ":" in lp.address',
        new='        return any(lp.proto == "tcp" and not lp.is_loopback',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestAnIpv6SshPath::test_sshd_on_ipv6',),
        reason='an IPv4-only sshd needs no IPv6 change',
    ),
    Mutation(
        id='enable-keeps-ssh/inactive-ignores-ipv6',
        file='bob/checks/firewall.py',
        old='            cmd=_ufw.enable_cmd(ssh_ports, ipv6_off=status.ipv6_ufw_enabled is False\n                                and ssh_on_ipv6 is not False),',
        new='            cmd=_ufw.enable_cmd(ssh_ports, ipv6_off=False\n                                and ssh_on_ipv6 is not False),',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestAnIpv6SshPath::test_firewall_inactive',),
        reason='the most urgent fix must keep an IPv6 SSH path',
    ),
    Mutation(
        id='enable-keeps-ssh/runner-drops-ipv6',
        file='bob/runner.py',
        old='        ssh_on_ipv6=ports_snapshot.ssh_on_ipv6,\n',
        new='',
        kills=('tests/test_v0244_enable_keeps_ssh.py::test_the_runner_hands_the_ipv6_state_to_both_checks',),
        reason='without the measured family the check falls back to unknown',
    ),
    Mutation(
        id='locale-size/cap-back-to-512k',
        file='bob/i18n.py',
        old='_MAX_LOCALE_SIZE = 1024 * 1024\n',
        new='_MAX_LOCALE_SIZE = 512 * 1024\n',
        kills=('tests/test_v0250_locale_size_headroom.py::test_each_locale_loads',),
        reason='fr.json reached 524 454 characters in v0.25.0 and French stopped loading',
    ),
    Mutation(
        id='k8s-node/cri-host-namespace-unread',
        file='bob/checks/kubernetes.py',
        old='                             host_network=opts.get("network") == "NODE",',
        new='                             host_network=False,',
        kills=('tests/test_v0250_kubernetes_node.py::TestReadingThroughTheCri::test_the_measured_cri_o_pods',),
        reason='CRI-O says NODE for a pod sharing the host network',
    ),
    Mutation(
        id='k8s-node/cri-o-never-read',
        file='bob/checks/kubernetes.py',
        old='        elif _command_exists("crictl"):',
        new='        elif False:',
        kills=('tests/test_v0250_kubernetes_node.py::TestReadingThroughTheCri::test_cri_o_is_read_when_no_ctr_answers',),
        reason='CRI-O ships no ctr: its pods would all read as unlisted',
    ),
    Mutation(
        id='k8s-node/empty-path-is-root',
        file='bob/checks/kubernetes.py',
        old='    if not isinstance(raw, str) or not raw:\n        return ""\n',
        new='    if not isinstance(raw, str):\n        return ""\n',
        kills=('tests/test_v0250_kubernetes_node.py::TestReadingThroughTheCri::test_an_empty_host_path_is_not_the_root',),
        reason='an empty mount source normalised to "/" reads as the node handed over',
    ),
    Mutation(
        id='disk-beyond-root/container-unknown',
        file='bob/checks/disk_encryption.py',
        old='    if p == "container" or snapshot.in_container:',
        new='    if p == "container":',
        kills=('tests/test_v0250_disk_encryption_beyond_root.py::TestInsideAContainer::test_detected_container_is_not_applicable',),
        reason='measured in a podman container: the overlay root counted as reduced visibility',
    ),
    Mutation(
        id='disk-beyond-root/not-looked-at',
        file='bob/checks/disk_encryption.py',
        old='                snap.extra_volumes.append((point, src, _root_is_encrypted(src, crypt_nodes)))',
        new='                pass',
        kills=('tests/test_v0250_disk_encryption_beyond_root.py::TestWhatIsLookedAt::test_a_plain_home_and_a_plain_swap',),
        reason='an encrypted root with /home on a plain partition read as an encrypted machine',
    ),
    Mutation(
        id='disk-beyond-root/zram-is-a-disk',
        file='bob/checks/disk_encryption.py',
        old='            if src.startswith("/dev/zram"):\n                continue\n',
        new='',
        kills=('tests/test_v0250_disk_encryption_beyond_root.py::TestWhatIsLookedAt::test_what_is_not_data_at_rest_on_this_disk',),
        reason='zram swap is compressed memory: nothing of it reaches a disk',
    ),
    Mutation(
        id='disk-beyond-root/boot-is-data',
        file='bob/checks/disk_encryption.py',
        old='    return not (point == "/boot" or point.startswith("/boot/") or point == "/efi")',
        new='    return True',
        kills=('tests/test_v0250_disk_encryption_beyond_root.py::TestWhatIsLookedAt::test_what_is_not_data_at_rest_on_this_disk',),
        reason='/boot and the EFI partition stay in clear on an encrypted install by design',
    ),
    Mutation(
        id='disk-beyond-root/bind-counted-twice',
        file='bob/checks/disk_encryption.py',
        old='            if _holds_data(point, src, fstype, root_src) and src not in seen_sources:',
        new='            if _holds_data(point, src, fstype, root_src):',
        kills=('tests/test_v0250_disk_encryption_beyond_root.py::TestWhatIsLookedAt::test_a_bind_mount_is_one_volume',),
        reason='a bind mount repeats its source under another path',
    ),
    Mutation(
        id='disk-beyond-root/swap-file-as-device',
        file='bob/checks/disk_encryption.py',
        old='                src = mounts[holder][0] if holder else ""',
        new='                src = swap',
        kills=('tests/test_v0250_disk_encryption_beyond_root.py::TestWhatIsLookedAt::test_a_swap_file_is_judged_by_its_filesystem',),
        reason='a swap file is as encrypted as the filesystem holding it',
    ),
    Mutation(
        id='disk-beyond-root/unscored',
        file='bob/checks/disk_encryption.py',
        old='                    points=1,\n                    detail=_t("disk_encryption.data_unencrypted_detail"),',
        new='                    points=0,\n                    detail=_t("disk_encryption.data_unencrypted_detail"),',
        kills=('tests/test_v0250_disk_encryption_beyond_root.py::TestVerdict::test_a_portable_host_with_data_in_clear',),
        reason='data in clear on a portable host weighs as a plain root does',
    ),
    Mutation(
        id='disk-beyond-root/undecided-not-visibility',
        file='bob/visibility.py',
        old='    "disk_encryption.data_unknown",\n',
        new='',
        kills=('tests/test_v0250_disk_encryption_beyond_root.py::TestVerdict::test_undecided_counts_as_reduced_visibility',),
        reason='an undecided volume leaves its deduction unknown',
    ),
    Mutation(
        id='firewalld-window/started-before-ssh',
        file='bob/checks/firewall.py',
        old='            offline_default,\n            offline_zones,\n',
        new='',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestEveryEnableKeepsSsh::test_installing_firewalld_keeps_the_ssh_service',
               'tests/test_v0244_enable_keeps_ssh.py::TestEveryEnableKeepsSsh::test_installing_firewalld_keeps_ssh_in_every_active_zone'),
        reason='measured on Fedora 43: 3 and 4 new SSH logins refused between the start and the reload',
    ),
    Mutation(
        id='firewalld-window/nm-zones-unread',
        file='bob/checks/firewall.py',
        old=('            "for z in $({ nmcli -g UUID connection show --active 2>/dev/null"\n'
             '            " | xargs -rI{} nmcli -g connection.zone connection show {} 2>/dev/null;"\n'),
        new='            "for z in $({"\n',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestEveryEnableKeepsSsh::test_installing_firewalld_keeps_ssh_in_every_active_zone',),
        reason='firewall-offline-cmd cannot see the zone NetworkManager gives an interface',
    ),
    Mutation(
        id='firewalld-window/mixed-actions-one-call',
        file='bob/checks/firewall.py',
        old='            *(f"sudo firewall-cmd --permanent {i}" for i in items),\n',
        new='            "sudo firewall-cmd --permanent " + " ".join(items),\n',
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestEveryEnableKeepsSsh::test_installing_firewalld_keeps_ssh_in_every_active_zone',),
        reason='firewalld 2.3 refuses --add-service with --add-port; the 0.24.4 chain stopped after the start (29 of 34 logins refused)',
    ),
    Mutation(
        id='firewalld-window/unknown-zone-stops-chain',
        file='bob/checks/firewall.py',
        old="""            + " ".join(f'sudo firewall-offline-cmd --zone="$z" {i} || true;' for i in items)""",
        new="""            + " ".join(f'sudo firewall-offline-cmd --zone="$z" {i};' for i in items)""",
        kills=('tests/test_v0244_enable_keeps_ssh.py::TestEveryEnableKeepsSsh::test_a_zone_the_offline_tool_does_not_know_does_not_stop_the_chain',),
        reason='a zone NetworkManager names but firewalld lacks must not leave firewalld unstarted',
    ),
    Mutation(
        id='init-aware/cups-openrc-name',
        file='bob/checks/cups.py',
        old='        return "cupsd"\n',
        new='        return "cups"\n',
        kills=('tests/test_v0250_init_aware_fixes.py::TestCupsListen::test_openrc_restarts_cupsd',),
        reason='Alpine ships /etc/init.d/cupsd, so restarting cups names a service that does not exist',
    ),
    Mutation(
        id='init-aware/cups-cupsctl-back',
        file='bob/checks/cups.py',
        old='            cmd=_listen_fix(snapshot.listen_values),',
        new='            cmd=f"sudo cupsctl --no-remote-any && {service_restart_cmd(_cups_unit())}",',
        kills=('tests/test_v0250_init_aware_fixes.py::TestCupsListen::test_no_cupsctl',),
        reason='measured on Debian, Fedora and Alpine: exit 0 and the hand-written Listen still in place',
    ),
    Mutation(
        id='init-aware/cups-commented-line-kept',
        file='bob/checks/cups.py',
        old="""            exprs.append(f"/^[[:space:]]*{sed_ci('Listen')}[[:space:]]+{escaped}([[:space:]]|#|$)/d")""",
        new="""            exprs.append(f"/^[[:space:]]*{sed_ci('Listen')}[[:space:]]+{escaped}[[:space:]]*$/d")""",
        kills=('tests/test_v0250_init_aware_fixes.py::TestCupsListen::test_the_command_rewrites_the_file',),
        reason='the detector reads past a trailing comment; the fix must too',
    ),
    Mutation(
        id='init-aware/cups-operand-unchecked',
        file='bob/checks/cups.py',
        old='            if not _SAFE_LISTEN.match(v):\n                return None\n',
        new='',
        kills=('tests/test_v0250_init_aware_fixes.py::TestCupsListen::test_an_unexpected_operand_gets_no_command',),
        reason='a value read from a file must not reach a shell command unchecked',
    ),
    Mutation(
        id='init-aware/docker-systemctl',
        file='bob/checks/docker_audit.py',
        old="""                     f'{service_restart_cmd("docker")}; }}'),""",
        new="""                     'sudo systemctl restart docker; }'),""",
        kills=('tests/test_v0250_init_aware_fixes.py::TestDockerUserns::test_openrc',),
        reason='measured on Alpine: the fix said systemctl restart docker',
    ),
    Mutation(
        id='init-aware/docker-no-directory',
        file='bob/checks/docker_audit.py',
        old="""                cmd=('test -f /etc/docker/daemon.json || { sudo mkdir -p /etc/docker && '""",
        new="""                cmd=('test -f /etc/docker/daemon.json || { '""",
        kills=('tests/test_v0250_init_aware_fixes.py::TestDockerUserns::test_the_command_runs_where_nothing_exists',),
        reason='measured on Alpine: tee into a missing /etc/docker failed',
    ),
    Mutation(
        id='init-aware/docker-user-left-to-docker',
        file='bob/checks/docker_audit.py',
        old='                     f\'{_DOCKREMAP_USER} && {_dockremap_range("/etc/subuid")} && {_dockremap_range("/etc/subgid")} && \'',
        new='                     f\'{_dockremap_range("/etc/subuid")} && {_dockremap_range("/etc/subgid")} && \'',
        kills=('tests/test_v0250_init_aware_fixes.py::TestDockerUserns::test_the_user_comes_before_the_restart',),
        reason='measured on Alpine 3.24, docker 29.8.2: no useradd/adduser binary found and dockerd stopped',
    ),
    Mutation(
        id='init-aware/docker-no-id-ranges',
        file='bob/checks/docker_audit.py',
        old='                     f\'{_DOCKREMAP_USER} && {_dockremap_range("/etc/subuid")} && {_dockremap_range("/etc/subgid")} && \'',
        new="                     ''",
        kills=('tests/test_v0250_init_aware_fixes.py::TestDockerUserns::test_the_command_runs_where_nothing_exists',),
        reason='measured on Alpine: no /etc/subuid, dockerd stopped while OpenRC said started',
    ),
    Mutation(
        id='init-aware/docker-range-overlaps',
        file='bob/checks/docker_audit.py',
        old='            "awk -F: \'BEGIN{m=100000} NF>=3 && $2+$3>m {m=$2+$3} END{print \\"dockremap:\\" m \\":65536\\"}\' | "',
        new='            "awk -F: \'BEGIN{m=100000} END{print \\"dockremap:\\" m \\":65536\\"}\' | "',
        kills=('tests/test_v0250_init_aware_fixes.py::TestDockerUserns::test_a_range_already_taken_is_not_reused',),
        reason='measured on Mint: dockremap given the range so6 already held, sharing host UIDs',
    ),
    Mutation(
        id='init-aware/apparmor-systemctl',
        file='bob/checks/mac_policy.py',
        old='        then=service_enable_cmd("apparmor"),',
        new='        then="sudo systemctl enable --now apparmor",',
        kills=('tests/test_v0250_init_aware_fixes.py::TestAppArmorEnable::test_apt_under_openrc',),
        reason='an apt host under OpenRC would be told to run systemctl, which it does not have',
    ),
    Mutation(
        id='init-aware/chrony-any-output-synced',
        file='bob/checks/ntp.py',
        old='        return leap.group(1) != "Not synchronised"',
        new='        return True',
        kills=('tests/test_v0250_ntp_chrony_leap.py::TestTheLeapStatus::test_not_in_sync',),
        reason='measured on Alpine: chrony said Not synchronised, BOB said synchronisation active',
    ),
    Mutation(
        id='init-aware/timedatectl-everywhere',
        file='bob/checks/ntp.py',
        old='            cmd="sudo timedatectl set-ntp true" if snapshot.timedatectl_ok else None,',
        new='            cmd="sudo timedatectl set-ntp true",',
        kills=('tests/test_v0250_ntp_chrony_leap.py::TestTheFix::test_no_timedatectl_no_command',),
        reason='an OpenRC host has no timedatectl',
    ),
    Mutation(
        id='info-only-domain/says-no-action-needed',
        file='bob/domain_scores.py',
        old='        REASON_INFO_ONLY:     ("domain_scores.reason.no_action",     "reported, not scored"),',
        new='        REASON_INFO_ONLY:     ("domain_scores.reason.no_action",     "no action needed"),',
        kills=('tests/test_v0250_info_only_domain_label.py::test_the_fallback_says_the_same',),
        reason='measured on Alpine: Threat Detection said no action needed with every detection tool absent',
    ),
    Mutation(
        id='init-aware/cups-append-unguarded',
        file='bob/checks/cups.py',
        old='''        f"{{ grep -qiE '^[[:space:]]*Listen[[:space:]]+localhost:{p}([[:space:]]|#|$)' {_CUPSD_CONF}"
        f" || echo 'Listen localhost:{p}' | sudo tee -a {_CUPSD_CONF} >/dev/null; }}" for p in ports)''',
        new='''        f"{{ echo 'Listen localhost:{p}' | sudo tee -a {_CUPSD_CONF} >/dev/null; }}" for p in ports)''',
        kills=('tests/test_v0250_init_aware_fixes.py::TestCupsListen::test_the_command_rewrites_the_file',),
        reason='applied twice, the fix would write a second Listen localhost line every time',
    ),
    Mutation(
        id='rpm-filecaps/provenance-unsaid',
        file='bob/checks/file_capabilities.py',
        old='            detail=_t("file_capabilities.root_equivalent_detail") + _provenance(snapshot, dangerous, _t),',
        new='            detail=_t("file_capabilities.root_equivalent_detail"),',
        kills=('tests/test_v0250_rpm_filecaps.py::TestTheDetailSaysWhyItIsNotKnown::test_unowned',),
        reason='rpm said why the file is not known; the detail spoke as if nothing had been asked',
    ),
    Mutation(
        id='review-wording/netfilter-port-unqualified',
        file='bob/locales/en.json',
        old='(inbound default: refuse; a rule may still allow this port — BOB reads the default policy, not every rule, and does not establish reachability), not a UFW rule",\n',
        new='(inbound default: refuse), not a UFW rule",\n',
        kills=('tests/test_v0250_review_wording.py::test_the_finding_names_what_was_established',),
        reason='measured on a VM: a port an nftables rule accepted read exactly like a refused one',
    ),
    Mutation(
        id='review-wording/kubelet-reach-claimed',
        file='bob/locales/en.json',
        old='(asked from this host: GET /pods answered, and a command request for a pod that does not exist passed authorisation)',
        new='(GET /pods answered)',
        kills=('tests/test_v0250_review_wording.py::test_the_finding_names_what_was_established',),
        reason='a loopback answer does not show the port is reachable from the network: the finding must say where it was asked',
    ),
    Mutation(
        id='k8s-node/run-probed-only-after-read',
        file='bob/checks/kubernetes.py',
        old='        if snap.anonymous_status != 401:',
        new='        if snap.anonymous_status is not None and 200 <= snap.anonymous_status < 300:',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheCommandProbe::test_it_is_sent_whatever_the_read_answered',),
        reason='measured: /pods 403 with commands authorised (404) must still be asked',
    ),
    Mutation(
        id='k8s-node/run-only-alert-dropped',
        file='bob/checks/kubernetes.py',
        old='    if run == RUN_AUTHORISED:',
        new='    if False:',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheKubelet::test_a_refused_read_does_not_hide_authorised_commands',),
        reason='refused reads with authorised commands would read as a plain refusal',
    ),
    Mutation(
        id='k8s-node/run-404-without-sentence',
        file='bob/checks/kubernetes.py',
        old='    if status == 404 and "does not exist" in text.lower():',
        new='    if status == 404:',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheKubelet::test_a_404_without_the_sentence_is_not_an_authorisation',),
        reason='a 404 that is not the command handler\'s own sentence is not an authorisation',
    ),
    Mutation(
        id='k8s-node/run-inconclusive-scored',
        file='bob/checks/kubernetes.py',
        old='    if status == 404 and "does not exist" in text.lower():\n        return RUN_AUTHORISED\n    return RUN_INCONCLUSIVE',
        new='    if status == 404 and "does not exist" in text.lower():\n        return RUN_AUTHORISED\n    return RUN_AUTHORISED',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheKubelet::test_405_and_5xx_are_inconclusive_not_scored_as_commands',),
        reason='measured: 405 with endpoints off and 500 when the API cannot be asked are not commands allowed',
    ),
    Mutation(
        id='k8s-node/command-name-fixed',
        file='bob/checks/kubernetes.py',
        old='    name = "BOB-PROBE-" + secrets.token_hex(8).upper()\n    return _request(f"https://127.0.0.1:10250/run/{name}/{name}/probe", method="POST")',
        new='    name = "bob-probe-0123456789abcdef"\n    return _request(f"https://127.0.0.1:10250/run/{name}/{name}/probe", method="POST")',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheCommandProbe::test_the_name_is_random_and_names_no_pod',),
        reason='a fixed name can match a real pod: the probe could then run a command',
    ),
    Mutation(
        id='k8s-node/command-probe-never-sent',
        file='bob/checks/kubernetes.py',
        old='            snap.anonymous_run_status, snap.anonymous_run_text = _probe_run()',
        new='            pass',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheCommandProbe::test_it_is_sent_whatever_the_read_answered',),
        reason='without the probe every anonymous kubelet reads as reads only, commands unasked',
    ),
    Mutation(
        id='k8s-node/anonymous-kubelet-unscored',
        file='bob/checks/kubernetes.py',
        old=(
            '                message=_t("kubernetes.kubelet_anonymous"),\n'
            '                reason=_t("kubernetes.kubelet_anonymous_reason"),\n'
            '                detail=_t("kubernetes.kubelet_anonymous_detail"),\n'
            '                points=3, nature="action",'
        ),
        new=(
            '                message=_t("kubernetes.kubelet_anonymous"),\n'
            '                reason=_t("kubernetes.kubelet_anonymous_reason"),\n'
            '                detail=_t("kubernetes.kubelet_anonymous_detail"),\n'
            '                points=0, nature="action",'
        ),
        kills=('tests/test_v0250_kubernetes_node.py::TestTheKubelet::test_one_level_per_exposure',),
        reason='an anonymous kubelet running commands in every pod with no account must cost the −3',
    ),
    Mutation(
        id='k8s-node/inconclusive-not-said',
        file='bob/checks/kubernetes.py',
        old='    if run in (RUN_INCONCLUSIVE, RUN_UNAUTHENTICATED):',
        new='    if False:',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheKubelet::test_a_404_without_the_sentence_is_not_an_authorisation',),
        reason='an inconclusive command answer must be said, not silently read as nothing',
    ),
    Mutation(
        id='k8s-node/upper-bound-not-visibility',
        file='bob/visibility.py',
        old='    "kubernetes.kubelet_run_indeterminate",\n',
        new='',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheKubelet::test_the_inconclusive_answers_are_an_upper_bound',),
        reason='an undecided command permission leaves the score an upper bound',
    ),
    Mutation(
        id='k8s-node/exec-probe-never-sent',
        file='bob/checks/kubernetes.py',
        old='            snap.anonymous_exec_status, snap.anonymous_exec_text = _probe_exec()',
        new='            pass',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheCommandProbe::test_both_command_requests_are_sent_whatever_the_read_answered',),
        reason='measured on MicroK8s 1.35.6: a get grant alone authorised GET /exec while POST /run was refused',
    ),
    Mutation(
        id='k8s-node/get-verdict-ignored',
        file='bob/checks/kubernetes.py',
        old='    if RUN_AUTHORISED in (post, get):',
        new='    if RUN_AUTHORISED == post:',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheCommandVerbs::test_a_get_alone_authorises_commands',),
        reason='a get grant on nodes/proxy reaches /exec: commands authorised with POST refused',
    ),
    Mutation(
        id='k8s-node/one-refusal-is-refusal',
        file='bob/checks/kubernetes.py',
        old='    if post == get == RUN_REFUSED:',
        new='    if post == RUN_REFUSED:',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheCommandVerbs::test_a_refusal_of_one_verb_is_not_a_refusal_of_both',),
        reason='a refused create says nothing about a get: refusing on one verb would hide the other',
    ),
    Mutation(
        id='k8s-node/probe-too-short',
        file='bob/checks/kubernetes.py',
        old='_PROBE_TIMEOUT = 15\n',
        new='_PROBE_TIMEOUT = 5\n',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheKubelet::test_the_probe_waits_long_enough_for_a_slow_first_answer',),
        reason='measured: the first answer after a kubelet restart took 9.5 s, past a 5 s limit',
    ),
    Mutation(
        id='k8s-node/kube-system-deducted',
        file='bob/checks/kubernetes.py',
        old='        apps = [p for p in snapshot.pods if p.namespace != _SYSTEM_NAMESPACE]',
        new='        apps = list(snapshot.pods)',
        kills=('tests/test_v0250_kubernetes_node.py::TestWhatThePodsMayDo::test_the_platform_is_said_not_deducted',),
        reason='calico-node runs privileged in the host network by design on MicroK8s',
    ),
    Mutation(
        id='k8s-node/any-capability-is-privileged',
        file='bob/checks/kubernetes.py',
        old='        if len(caps) > _cap_last_cap():\n            pod.privileged = True\n        for mount in spec.get("mounts") or []:',
        new='        if caps:\n            pod.privileged = True\n        for mount in spec.get("mounts") or []:',
        kills=('tests/test_v0250_kubernetes_node.py::TestReadingTheSpecs::test_the_measured_node',),
        reason='a plain container holds 14 bounding capabilities, a privileged one all 41',
    ),
    Mutation(
        id='k8s-node/sandbox-namespaces-inverted',
        file='bob/checks/kubernetes.py',
        old='            pod.host_network = "network" not in types',
        new='            pod.host_network = "network" in types',
        kills=('tests/test_v0250_kubernetes_node.py::TestReadingTheSpecs::test_a_pod_s_own_sandbox_keeps_its_namespaces',),
        reason='a pod in the host network has a sandbox with no network namespace of its own',
    ),
    Mutation(
        id='k8s-node/runtime-socket-unseen',
        file='bob/checks/kubernetes.py',
        old='    "/var/snap/microk8s/common/run/containerd.sock", "/run/k3s/containerd/containerd.sock",',
        new='    "/run/k3s/containerd/containerd.sock",',
        kills=('tests/test_v0250_kubernetes_node.py::TestReadingTheSpecs::test_the_measured_node',),
        reason="MicroK8s' containerd socket mounted in a pod hands it the node",
    ),
    Mutation(
        id='k8s-node/unread-spec-silent',
        file='bob/checks/kubernetes.py',
        old='        if not isinstance(spec_doc, dict):\n            unread += 1',
        new='        if not isinstance(spec_doc, dict):\n            pass',
        kills=('tests/test_v0250_kubernetes_node.py::TestReadingTheSpecs::test_a_spec_that_does_not_come_back_is_counted',),
        reason='measured: a pass right after a restart missed two containers a second pass read',
    ),
    Mutation(
        id='k8s-node/partial-says-ok',
        file='bob/checks/kubernetes.py',
        old='        if snapshot.unread:',
        new='        if False:',
        kills=('tests/test_v0250_kubernetes_node.py::TestWhatWasNotSeen::test_uninspected_containers_withhold_the_ok',),
        reason='"nothing to report" about containers whose rights were never read',
    ),
    Mutation(
        id='k8s-node/readonly-port-ignored',
        file='bob/checks/kubernetes.py',
        old='    if ro is not None and 200 <= ro < 300:',
        new='    if False:',
        kills=('tests/test_v0250_kubernetes_node.py::TestTheKubelet::test_the_read_only_port',),
        reason='port 10255 serves every pod spec without authentication',
    ),
    Mutation(
        id='k8s-node/runs-without-kubelet',
        file='bob/runner.py',
        old='         skip_if=lambda s: not s.kubelet_running)',
        new='         skip_if=lambda s: False)',
        kills=('tests/test_v0250_kubernetes_node.py::test_the_section_runs_only_where_a_kubelet_runs',),
        reason='a host without a kubelet would read "kubelet API did not answer"',
    ),
    Mutation(
        id='k8s-node/partial-not-visibility',
        file='bob/visibility.py',
        old='    "kubernetes.workloads_partial",\n',
        new='',
        kills=('tests/test_v0250_kubernetes_node.py::TestWhatWasNotSeen::test_each_blind_spot_counts_as_reduced_visibility',),
        reason='containers left uninspected make the score an upper bound',
    ),
    Mutation(
        id='explain/host-prefix-dropped',
        file='bob/explain.py',
        old='    t = _host_texts(t)\n    key = key.strip()\n',
        new='    key = key.strip()\n',
        kills=('tests/test_v0251_explain_host_prefix.py::test_doas_only_host_explain_names_doas',),
        reason='on a doas-only host, --explain would keep telling the operator to run sudo',
    ),
    Mutation(
        id="history/unreadable-read-as-empty",
        file="bob/history.py",
        old="        if strict:\n            raise HistoryUnreadable(",
        new="        if False:\n            raise HistoryUnreadable(",
        kills=("tests/test_v0261_history_unreadable.py::test_an_unreadable_file_is_said_with_its_owner_and_mode",),
        reason="measured on Mint: a root-owned 0600 history read as 'No score history found'",
    ),
    Mutation(
        id="history/owner-healed-only-on-create",
        file="bob/history.py",
        old="            chown_fd_to_sudo_user(f.fileno(), _HISTORY_FILE)\n        _rotate_if_needed()",
        new="        _rotate_if_needed()",
        kills=("tests/test_v0261_history_unreadable.py::test_the_owner_is_healed_on_every_write",),
        reason="a history file root once created stayed root's, unreadable by its own user",
    ),
    Mutation(
        id="compare/mode-ignored",
        file="bob/compare.py",
        old="    mode_mismatch = curr.exhaustive is not None and prev.exhaustive != curr.exhaustive",
        new="    mode_mismatch = False",
        kills=("tests/test_v0261_baseline_exhaustive_mode.py::test_exhaustive_after_normal_is_not_a_blinder_run",),
        reason="measured on Mint: an --exhaustive run after a normal one said it read less of the host",
    ),
    Mutation(
        id="compare/unknown-mode-taken-as-same",
        file="bob/compare.py",
        old="    mode_mismatch = curr.exhaustive is not None and prev.exhaustive != curr.exhaustive",
        new="    mode_mismatch = curr.exhaustive is not None and prev.exhaustive is not None and prev.exhaustive != curr.exhaustive",
        kills=("tests/test_v0261_baseline_exhaustive_mode.py::test_a_baseline_from_before_the_field_is_an_unknown_mode",),
        reason="a baseline written before 0.26.1 does not say its mode: an unknown, not a match",
    ),
    Mutation(
        id="compare/mode-not-loaded",
        file="bob/compare.py",
        old='            exhaustive=(raw["exhaustive"] if isinstance(raw.get("exhaustive"), bool) else None),',
        new="            exhaustive=None,",
        kills=("tests/test_v0261_baseline_exhaustive_mode.py::test_the_mode_survives_the_file",),
        reason="a mode written but not read back compares every run as unknown",
    ),
    Mutation(
        id="compare/counts-compared-across-modes",
        file="bob/compare.py",
        old="        info_delta=(curr.info_count - prev.info_count) if _counts else 0,",
        new="        info_delta=curr.info_count - prev.info_count,",
        kills=("tests/test_v0261_baseline_exhaustive_mode.py::test_normal_after_exhaustive_resolves_nothing",),
        reason="measured on Mint: '4 info notice(s) resolved' with nothing fixed, the exhaustive sections not run",
    ),
    Mutation(
        id="compare/main-forgets-the-mode",
        file="bob/__main__.py",
        old="                                           exhaustive=config.exhaustive)\n",
        new="                                           )\n",
        kills=("tests/test_v0261_baseline_exhaustive_mode.py::test_both_callers_hand_the_mode",),
        reason="a baseline saved without the mode leaves every comparison unknown",
    ),
    Mutation(
        id="ipv6-chain/user-chains-not-listed",
        file="bob/checks/ipv6.py",
        old="            return m.group(1), _input_path(res.stdout), chains",
        new="            return m.group(1), _input_path(res.stdout), None",
        kills=("tests/test_v0261_ipv6_user_chains.py::test_the_mint_shape_is_blocked",),
        reason="measured on Mint: INPUT jumping to two empty chains was closed, BOB said it could not show it",
    ),
    Mutation(
        id="ipv6-chain/user-chain-jump-admits",
        file="bob/checks/ipv6.py",
        old="    return not (user_chains is not None and target in user_chains)",
        new="    return True",
        kills=("tests/test_v0261_ipv6_user_chains.py::test_the_mint_shape_is_blocked",),
        reason="a jump to a user chain read inline admits only through that chain's own rules",
    ),
    Mutation(
        id="ipv6-chain/refusal-admits",
        file="bob/checks/ipv6.py",
        old="    if target in _V6_NON_ADMITTING:\n        return False\n",
        new="",
        kills=("tests/test_v0261_ipv6_user_chains.py::test_what_the_chain_holds_decides",),
        reason="measured: a chain that drops kept IPv6 closed; a DROP lets nothing in",
    ),
    Mutation(
        id="ports/ok-claims-ipv6-unestablished",
        file="bob/checks/ports.py",
        old='            result.ok(message=_t("ports.all_covered_policy_ipv4" if ipv6_unproven',
        new='            result.ok(message=_t("ports.all_covered_policy" if ipv6_unproven',
        kills=("tests/test_v0261_ipv6_user_chains.py::test_the_ports_ok_speaks_for_ipv4_when_ipv6_is_not_established",),
        reason="found by review on Mint: 'every interface filtered by UFW' while the IPv6 section said not established",
    ),
    Mutation(
        id="runner/ipv6-verdict-not-handed",
        file="bob/runner.py",
        old="                       and not _ipv6_input_closed(ipv6_snapshot,\n",
        new="                       and False and _ipv6_input_closed(ipv6_snapshot,\n",
        kills=("tests/test_v0261_ipv6_user_chains.py::test_the_runner_hands_the_ipv6_verdict",),
        reason="the ports OK would claim IPv6 whatever the IPv6 section established",
    ),
    Mutation(
        id="disk-beside-plain-root/not-named",
        file="bob/checks/disk_encryption.py",
        old="            detail=detail + also,",
        new="            detail=detail,",
        kills=("tests/test_v0261_disk_beside_plain_root.py::test_the_data_beside_is_named_and_the_point_is_unchanged",),
        reason="found on Mint: /home on its own unencrypted partition went unmentioned beside a plain root",
    ),
    Mutation(
        id="disk-beside-plain-root/unknown-listed-as-clear",
        file="bob/checks/disk_encryption.py",
        old="    clear = [f\"{what} ({src})\" for what, src, e in snapshot.extra_volumes if e is False]\n    also",
        new="    clear = [f\"{what} ({src})\" for what, src, e in snapshot.extra_volumes if not e]\n    also",
        kills=("tests/test_v0261_disk_beside_plain_root.py::test_nothing_unencrypted_beside_adds_nothing",),
        reason="a volume whose encryption could not be read is an unknown, not 'not encrypted'",
    ),
    Mutation(
        id="logs/days-covered-is-the-request",
        file="bob/checks/logs.py",
        old="        return min(self.log_days, self.days_available) if self.days_available else self.log_days",
        new="        return self.log_days",
        kills=("tests/test_v0261_logs_measured_wording.py::test_the_days_covered",),
        reason="measured on Mint: '1764 blocked attempt(s) over 7 day(s)' from a ufw.log that held 3",
    ),
    Mutation(
        id="logs/period-hides-the-rotated-files",
        file="bob/display.py",
        old='        if log_report.log_source == "file":',
        new="        if False:",
        kills=("tests/test_v0261_logs_measured_wording.py::test_the_section_says_what_it_read",),
        reason="'3 day(s) of logs available' while ufw.log.1 held the week before",
    ),
    Mutation(
        id="logs/dominance-always-discovery",
        file="bob/checks/logs.py",
        old="        discovery = ports <= _DISCOVERY_PORTS",
        new="        discovery = True",
        kills=("tests/test_v0261_logs_measured_wording.py::test_the_tv_box_is_not_called_discovery",),
        reason="measured on Mint: a TV box's unicast UDP to 413 high ports was called mDNS/SSDP discovery",
    ),
    Mutation(
        id="report/public-ip-unnamed",
        file="bob/report.py",
        old='            context_str = labels.get("context_with_ip", "{context} ({ip})").format(',
        new='            context_str = "{context} ({ip})".format(',
        kills=("tests/test_v0261_wording.py::test_the_public_ip_is_named",),
        reason="measured on Mint: 'Local network only (203.0.113.42)' read as a contradiction",
    ),
    Mutation(
        id="firewall-rules/orphan-rule-said-unused",
        file="bob/checks/firewall.py",
        old='            detail=t("firewall_rules.orphan_rule_detail"),\n',
        new="",
        kills=("tests/test_v0261_wording.py::test_an_orphan_rule_says_it_may_still_be_needed",),
        reason="Spotify Connect's rule on Mint: nothing listened at audit time, the program listens while it runs",
    ),
    Mutation(
        id="service-risk/ssh-exposed-by-default",
        file="bob/locales/en.json",
        old="brute-force attacks wherever it is reachable from the internet",
        new="brute-force attacks — internet-exposed by default",
        kills=("tests/test_v0261_wording.py::test_ssh_risk_says_where_it_is_reachable",),
        reason="the generic text said 'internet-exposed by default' two lines above BOB's measured 'not reachable'",
    ),
    Mutation(
        id="ipv6-chain/patch-moves-a-score",
        file="bob/checks/ipv6.py",
        old="            if ufw_active and _ipv6_input_closed(snapshot, extended=not snapshot.has_global_ipv6):",
        new="            if ufw_active and _ipv6_input_closed(snapshot):",
        kills=("tests/test_v0261_ipv6_user_chains.py::test_with_a_global_address_the_0260_reading_stands",),
        reason="a patch moves no score: with a global address the extended reading lifts a WARN −2 (0.27.0)",
    ),
    Mutation(
        id="ipv6-chain/extended-rules-ignored",
        file="bob/checks/ipv6.py",
        old="    return not any(_v6_rule_admits(r, snapshot.ip6_user_chains)\n                   for r in snapshot.ip6_input_rules)",
        new="    return True",
        kills=("tests/test_v0261_ipv6_user_chains.py::test_what_the_chain_holds_decides",),
        reason="measured on the bench: a user chain accepting ICMPv6 and 8099/tcp left 8099 reachable",
    ),
    Mutation(
        id="compare/exhaustive-section-deducts",
        file="bob/checks/world_writable.py",
        old='        result.ok(message=_t("world_writable.ok"), key="world_writable.ok")',
        new='        result.warn_with_deduction(key="world_writable.ok", message="x", reason="x", points=1)',
        kills=("tests/test_v0261_baseline_exhaustive_mode.py::test_the_exhaustive_sections_never_deduct",),
        reason="a deduction in an exhaustive-only section would make scores of different modes incomparable",
    ),
    Mutation(
        id="history/advice-says-sudo-on-doas-host",
        file="bob/history.py",
        old="    lines = [f\"  {with_privilege(_t('history.unreadable', path=str(_HISTORY_FILE), owner=owner, mode=mode, error=reason))}\"]",
        new="    lines = [f\"  {_t('history.unreadable', path=str(_HISTORY_FILE), owner=owner, mode=mode, error=reason)}\"]",
        kills=("tests/test_v0261_history_unreadable.py::test_on_a_doas_host_the_commands_say_doas",),
        reason="on Alpine, with doas and no sudo, 'sudo bob --history' is advice that cannot run",
    ),
    Mutation(
        id="history/hand-back-says-sudo-on-doas-host",
        file="bob/history.py",
        old="        lines.append(f\"  {with_privilege(_t('history.unreadable_hand_back', path=str(_HISTORY_FILE)))}\")",
        new="        lines.append(f\"  {_t('history.unreadable_hand_back', path=str(_HISTORY_FILE))}\")",
        kills=("tests/test_v0261_history_unreadable.py::test_on_a_doas_host_the_commands_say_doas",),
        reason="on Alpine, with doas and no sudo, 'sudo chown' is advice that cannot run",
    ),
    Mutation(
        id="ipv6-chain/extended-verdict-credits-ufw",
        file="bob/checks/ipv6.py",
        old='                    message=_t("ipv6.ufw_v6_off_blocked_chains" if _chains else "ipv6.ufw_v6_off_blocked",',
        new='                    message=_t("ipv6.ufw_v6_off_blocked",',
        kills=("tests/test_v0261_ipv6_user_chains.py::TestWhoClosesIt::test_the_mint_shape_names_the_chains",),
        reason="on Mint the chains of ExpressVPN and libvirt closed IPv6: 'UFW drops all IPv6 traffic' claimed too much",
    ),
    Mutation(
        id="ports/ok-credits-ufw-for-ipv6",
        file="bob/checks/ports.py",
        old='                                 else "ports.all_covered_policy_ipv6_closed" if ipv6_closed_by_chains\n',
        new="",
        kills=("tests/test_v0261_ipv6_user_chains.py::TestWhoClosesIt::test_the_ports_ok_does_not_credit_ufw",),
        reason="with IPV6=no, UFW filters no IPv6: inbound closed by other chains is not UFW's",
    ),
    Mutation(
        id="runner/ipv6-chains-verdict-not-handed",
        file="bob/runner.py",
        old="        ipv6_closed_by_chains=ipv6_closed_by_chains(ipv6_snapshot),\n",
        new="",
        kills=("tests/test_v0261_ipv6_user_chains.py::TestWhoClosesIt::test_the_runner_hands_it",),
        reason="the ports OK would credit UFW for IPv6 closed by other chains",
    ),
    Mutation(
        id="logs/discovery-claimed-from-ports",
        file="bob/locales/en.json",
        old="only to the conventional discovery ports",
        new="only to discovery traffic ports",
        kills=("tests/test_v0261_logs_measured_wording.py::test_discovery_is_said_of_the_ports_not_the_traffic",),
        reason="a conventional port does not prove the protocol it carries",
    ),
    Mutation(
        id="ipv6-chain/unusable-claimed-from-input-alone",
        file="bob/checks/ipv6.py",
        old="            and snapshot.ip6_ufw_init_shape is not True)",
        new="            and not set(snapshot.ip6_input_rules or []) <= _UFW_V6_OFF_RULES)",
        kills=("tests/test_v0261_ipv6_user_chains.py::TestWhoClosesIt::test_input_alone_in_shape_says_inbound_only",),
        reason="'IPv6 is unusable' needs the whole ufw-init table: INPUT alone leaves OUTPUT unjudged",
    ),
    Mutation(
        id="ipv6-chain/ufw-init-shape-loosened",
        file="bob/checks/ipv6.py",
        old="    return lines == _UFW_INIT_V6_POLICIES | _UFW_INIT_V6_RULES",
        new="    return lines >= _UFW_INIT_V6_POLICIES",
        kills=("tests/test_v0261_ipv6_user_chains.py::TestWhoClosesIt::test_input_alone_in_shape_says_inbound_only",),
        reason="another tool's OUTPUT chain beside ufw-init's policies is not ufw-init's table",
    ),
    Mutation(
        id="ipv6/unusable-ignores-loopback",
        file="bob/locales/en.json",
        old="and this host has no IPv6 connectivity beyond loopback",
        new="and IPv6 is unusable on this host",
        kills=("tests/test_v0261_ipv6_user_chains.py::test_the_ufw_init_text_keeps_loopback_out_of_the_claim",),
        reason="ufw-init with IPV6=no still accepts loopback: 'unusable' claimed more than the table blocks",
    ),
    Mutation(
        id="ipv6-chain/ufw-init-shape-forward-blind",
        file="bob/checks/ipv6.py",
        old="    return lines == _UFW_INIT_V6_POLICIES | _UFW_INIT_V6_RULES",
        new='    return {l for l in lines if "FORWARD" not in l} == {l for l in _UFW_INIT_V6_POLICIES | _UFW_INIT_V6_RULES if "FORWARD" not in l}',
        kills=("tests/test_v0261_ipv6_user_chains.py::TestWhoClosesIt::test_input_alone_in_shape_says_inbound_only",),
        reason="'no IPv6 connectivity beyond loopback' covers forwarding too: FORWARD open is not ufw-init's table",
    ),
    Mutation(
        id="as-root/history-opened-through-a-link",
        file="bob/history.py",
        old="        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW",
        new="        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT",
        kills=("tests/test_v0261_no_symlink_followed_as_root.py::test_a_link_to_an_existing_file_is_not_written_through",
               "tests/test_v0261_no_symlink_followed_as_root.py::test_a_dangling_link_creates_nothing"),
        reason="measured: root appended to a symlink's target, and created it through a dangling link",
    ),
    Mutation(
        id="as-root/chown-follows-a-link",
        file="bob/sysinfo.py",
        old="        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC",
        new="        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC",
        kills=("tests/test_v0261_no_symlink_followed_as_root.py::test_chown_to_sudo_user_leaves_a_symlink_alone",
               "tests/test_v0261_no_symlink_followed_as_root.py::test_a_symlinked_directory_is_left_alone"),
        reason="measured: os.chown on a planted link handed its target to the invoking user",
    ),
    Mutation(
        id="as-root/chown-follow-symlinks",
        file="bob/sysinfo.py",
        old="            if redirected_out_of_home(path, fd_real_path(fd)):",
        new="            if False:",
        kills=("tests/test_v0261_no_symlink_followed_as_root.py::TestASymlinkedParentDirectory::test_a_file_there_is_not_handed_over",),
        reason="measured: ~/.config/bob a symlink to another directory, last_baseline.json there handed over",
    ),
    Mutation(
        id="as-root/history-chmod-by-name",
        file="bob/history.py",
        old="            os.fchmod(f.fileno(), 0o600)",
        new="            os.chmod(str(_HISTORY_FILE), 0o600)",
        kills=("tests/test_v0261_no_symlink_followed_as_root.py::test_the_mode_is_healed_through_the_descriptor",),
        reason="re-moding by name: a link swapped in after the open would be re-moded instead",
    ),
    Mutation(
        id="as-root/history-through-a-symlinked-parent",
        file="bob/history.py",
        old="            refuse_if_redirected(_HISTORY_FILE.parent, fd_real_path(dfd))",
        new="            pass",
        kills=("tests/test_v0261_no_symlink_followed_as_root.py::TestNothingIsWrittenThroughARedirectedHome::test_the_history_checks_its_descriptor_too",),
        reason="measured: ~/.config/bob a symlink to another directory, root created history.jsonl there",
    ),
    Mutation(
        id="as-root/fd-handover-unchecked",
        file="bob/sysinfo.py",
        old="        if lexical is not None and redirected_out_of_home(lexical, fd_real_path(fd)):",
        new="        if False:",
        kills=("tests/test_v0261_no_symlink_followed_as_root.py::TestASymlinkedParentDirectory::test_a_descriptor_opened_through_it_is_not_handed_over",),
        reason="a descriptor opened through a redirected path would be handed over",
    ),
    Mutation(
        id="as-root/operator-dir-refused",
        file="bob/sysinfo.py",
        old="    if not _within(os.path.abspath(str(lexical)), home):\n        return False",
        new="    if not _within(os.path.abspath(str(lexical)), home):\n        return True",
        kills=("tests/test_v0261_no_symlink_followed_as_root.py::TestASymlinkedParentDirectory::test_a_directory_the_operator_chose_outside_the_home_is_unchanged",),
        reason="an --output-dir the operator chose outside the home must still be handed back",
    ),
    Mutation(
        id='as-root/state-dir-through-an-ancestor',
        file='bob/sysinfo.py',
        old='    refuse_if_redirected(d, os.path.realpath(probe))',
        new='    pass',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestNothingIsWrittenThroughARedirectedHome::test_a_directory_not_yet_there_is_not_created_through_an_ancestor',
               'tests/test_v0261_no_symlink_followed_as_root.py::TestNothingIsWrittenThroughARedirectedHome::test_the_state_file_is_not_created_there',),
        reason='measured: through ~/.config -> <dir>, root created <dir>/bob',
    ),
    Mutation(
        id='as-root/dir-mode-after-a-swap',
        file='bob/sysinfo.py',
        old='            refuse_if_redirected(d, fd_real_path(fd))',
        new='            pass',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestNothingIsWrittenThroughARedirectedHome::test_the_mode_is_not_set_after_a_swap',),
        reason="a directory swapped for a link after the check would be chmod'ed 0700 — /etc, on a host",
    ),
    Mutation(
        id='as-root/dir-mode-by-name',
        file='bob/sysinfo.py',
        old='            os.fchmod(fd, mode)',
        new='            os.chmod(str(d), mode)',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestNothingIsWrittenThroughARedirectedHome::test_the_mode_goes_through_a_descriptor',),
        reason='measured with 0.26.0: chmod by name followed ~/.config/bob -> <dir> and made <dir> 0700',
    ),
    Mutation(
        id='as-root/atomic-write-unchecked',
        file='bob/_atomic.py',
        old='        refuse_if_redirected(path.parent, fd_real_path(dir_fd))',
        new='        pass',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestNothingIsWrittenThroughARedirectedHome::test_atomic_write_itself_refuses',),
        reason='measured: last_baseline.json, recurrence.json, ignore.yml, config.conf created through the link',
    ),
    Mutation(
        id='as-root/report-unchecked',
        file='bob/report.py',
        old='            refuse_if_redirected(path.parent, fd_real_path(dfd))',
        new='            pass',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestNothingIsWrittenThroughARedirectedHome::test_the_report_is_not_created_there',),
        reason='measured: through ~/.local/share/bob -> <dir>, root created the report in <dir>',
    ),
    Mutation(
        id='as-root/judged-without-sudo',
        file='bob/sysinfo.py',
        old='    if not invoking_user_name() or not redirected_out_of_home(lexical, real):',
        new='    if not redirected_out_of_home(lexical, real):',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestWhatStaysWritten::test_without_sudo_the_users_own_rights_are_not_judged',),
        reason="without sudo the user writes with the user's own rights: ~/.config on another disk keeps working",
    ),
    Mutation(
        id='as-root/history-dir-nofollow',
        file='bob/history.py',
        old='        dfd = os.open(str(_HISTORY_FILE.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)',
        new='        dfd = os.open(str(_HISTORY_FILE.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestWhatStaysWritten::test_a_link_inside_the_home_is_the_users_own',),
        reason='measured: O_NOFOLLOW on the directory dropped the history of a ~/.config/bob linked inside the home',
    ),
    Mutation(
        id='as-root/refusal-unrecorded',
        file='bob/sysinfo.py',
        old='    _REDIRECT_REFUSED.setdefault(str(lexical), real)',
        new='    pass',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestNothingIsWrittenThroughARedirectedHome::test_the_refusal_is_recorded',
               'tests/test_v0261_no_symlink_followed_as_root.py::TestTheRefusalIsSaid::test_once_per_path_on_stderr',),
        reason='a refused write said nowhere: the baseline or history the user expects is missing without a word',
    ),
    Mutation(
        id='as-root/refusal-said-every-cycle',
        file='bob/sysinfo.py',
        old='        if lexical in _REDIRECT_SAID:\n            continue',
        new='        if False:\n            continue',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestTheRefusalIsSaid::test_once_per_path_on_stderr',),
        reason='--watch would repeat the line on every cycle',
    ),
    Mutation(
        id='as-root/audit-says-nothing',
        file='bob/__main__.py',
        old='            say_refused_redirects(t)\n',
        new='            pass\n',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestTheRefusalIsSaid::test_the_audit_and_watch_say_it',),
        reason='the audit would end without saying what it did not write',
    ),
    Mutation(
        id='as-root/cron-audit-stopped-by-log-dir',
        file='bob/manage_logs.py',
        old='        except OSError as exc:\n            logger.debug("log directory %s not prepared: %s", default_dir, exc)',
        new='        except ValueError as exc:\n            logger.debug("log directory %s not prepared: %s", default_dir, exc)',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestTheRefusalIsSaid::test_a_refused_log_directory_does_not_stop_a_cron_audit',),
        reason='measured end to end: a refused log directory must leave the audit running, report-less',
    ),
    Mutation(
        id='as-root/unsaved-said-saved',
        file='bob/manage_logs.py',
        old='        logger.debug("log_dir not saved: %s", exc)\n        print()\n        return chosen',
        new='        logger.debug("log_dir not saved: %s", exc)',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestTheRefusalIsSaid::test_a_choice_not_saved_is_not_said_saved',),
        reason="'saved' printed for a choice that was not",
    ),
    Mutation(
        id='history/chown-advised-for-a-link',
        file='bob/history.py',
        old='        hand_back = _stat.S_ISREG(os.lstat(_HISTORY_FILE).st_mode) and st.st_uid != os.getuid()',
        new='        hand_back = st.st_uid != os.getuid()',
        kills=('tests/test_v0261_history_unreadable.py::TestTheChownAdviceIsForWhatItFixes::test_a_link_does_not',),
        reason='after review: chown follows a link to its target — not advised for one',
    ),
    Mutation(
        id='history/chown-advised-for-own-file',
        file='bob/history.py',
        old='        hand_back = _stat.S_ISREG(os.lstat(_HISTORY_FILE).st_mode) and st.st_uid != os.getuid()',
        new='        hand_back = _stat.S_ISREG(os.lstat(_HISTORY_FILE).st_mode)',
        kills=('tests/test_v0261_history_unreadable.py::TestTheChownAdviceIsForWhatItFixes::test_a_file_already_yours_does_not',),
        reason='chown advised where it changes nothing',
    ),
    Mutation(
        id='release-chain/pip-upgraded-by-the-old-pip',
        file='.github/workflows/publish.yml',
        old='          "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"',
        new='          --upgrade pip',
        kills=('tests/test_v0261_release_chain.py::test_pip_comes_from_a_hash_pinned_wheel', ),
        reason='upgrading pip with the pip in place fetches the new one over the connection at risk (0.26.0: pip 26.2.1 fetched the build tools that way)',
    ),
    Mutation(
        id='release-chain/old-pip-accepted',
        file='.github/workflows/publish.yml',
        old='          if tuple(int(x) for x in v.split(".")[:3]) < (26, 2, 2):',
        new='          if tuple(int(x) for x in v.split(".")[:3]) < (24, 0):',
        kills=('tests/test_v0261_release_chain.py::test_the_check_refuses_an_old_pip', ),
        reason='pip below 26.2.2 still trusts the eMudhra / emSign authorities',
    ),
    Mutation(
        id='release-chain/tools-before-the-check',
        file='.github/workflows/publish.yml',
        old='      - name: Install pip from a hash-pinned wheel\n        run: >-\n',
        new='      - name: Install build first\n        run: python -m pip install build\n\n      - name: Install pip from a hash-pinned wheel\n        run: >-\n',
        kills=('tests/test_v0261_release_chain.py::test_the_build_tools_come_after_the_check', ),
        reason='build tools fetched before the check would come through the pip at risk',
    ),
    Mutation(
        id='release-chain/upload-action-floating',
        file='.github/workflows/publish.yml',
        old='        uses: pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086  # v1.14.3',
        new='        uses: pypa/gh-action-pypi-publish@release/v1',
        kills=('tests/test_v0261_release_chain.py::test_the_upload_action_is_pinned_to_the_fixed_release', ),
        reason="measured: 0.26.0 was uploaded by v1.14.2 through the floating branch, before GHSA-5xjx-3w67-w9x9's fix",
    ),
    Mutation(
        id='as-root/report-name-followed',
        file='bob/report.py',
        old='                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,',
        new='                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC,',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestTheLastComponent::test_a_link_at_the_reports_name_is_not_followed', 'tests/test_v0141_robustness.py::TestReportOpenIsSymlinkSafe::test_symlinked_report_path_is_refused', ),
        reason="after review: a link at the report's own name, which a checked directory does not stop",
    ),
    Mutation(
        id='as-root/state-file-written-through-its-name',
        file='bob/_atomic.py',
        old='            os.replace(tmp_name, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)',
        new='            open(path, "w", encoding="utf-8").write(content); os.unlink(tmp_name, dir_fd=dir_fd)',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestTheLastComponent::test_a_link_at_a_state_files_name_is_replaced_not_followed', ),
        reason='after review: writing through the final name would follow a link planted there',
    ),
    Mutation(
        id='as-root/manage-logs-lists-a-redirected-dir',
        file='bob/manage_logs.py',
        old='        cur_logs = sorted(log_dir.glob("bob_*.log"), reverse=True) if _listable(log_dir) else []',
        new='        cur_logs = sorted(log_dir.glob("bob_*.log"), reverse=True)',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestManageLogsUnderARedirectedHome::test_delete_all_leaves_the_redirected_directory_alone', ),
        reason='measured with 0.26.0: --manage-logs deleted bob_*.log in the directory a link pointed at',
    ),
    Mutation(
        id='as-root/manage-logs-lists-a-redirected-previous-dir',
        file='bob/manage_logs.py',
        old='            if extra.exists() and _listable(extra):',
        new='            if extra.exists():',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestManageLogsUnderARedirectedHome::test_delete_all_leaves_the_redirected_directory_alone', ),
        reason='a previous log directory redirected outside the home would be listed',
    ),
    Mutation(
        id='as-root/manage-logs-unlink-unchecked',
        file='bob/manage_logs.py',
        old='        refuse_if_redirected(f.parent, fd_real_path(dfd))\n        os.unlink(f.name, dir_fd=dfd)',
        new='        os.unlink(f.name, dir_fd=dfd)',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestManageLogsUnderARedirectedHome::test_a_deletion_checks_the_directory_it_goes_through', ),
        reason='a directory swapped for a link after it was listed would have its report deleted',
    ),
    Mutation(
        id='as-root/manage-logs-curses-unguarded',
        file='bob/manage_logs.py',
        old='        if browse_dir.exists() and _listable(browse_dir):',
        new='        if browse_dir.exists():',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestManageLogsUnderARedirectedHome::test_the_curses_list_is_guarded_too', ),
        reason='the curses list would show, and delete in, a redirected directory',
    ),
    Mutation(
        id='as-root/manage-logs-move-from-redirected',
        file='bob/manage_logs.py',
        old='        cur_logs = sorted(log_dir.glob("bob_*.log")) if log_dir.exists() and _listable(log_dir) else []',
        new='        cur_logs = sorted(log_dir.glob("bob_*.log")) if log_dir.exists() else []',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestManageLogsUnderARedirectedHome::test_the_curses_list_is_guarded_too', ),
        reason='changing the directory would move reports out of a redirected one',
    ),
    Mutation(
        id='as-root/manage-logs-says-it-as-an-audit',
        file='bob/manage_logs.py',
        old='        say_refused_redirects(t, key="manage_logs.dir_redirected")',
        new='        say_refused_redirects(t)',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestManageLogsUnderARedirectedHome::test_delete_all_leaves_the_redirected_directory_alone', ),
        reason="measured: the audit's text said 'wrote nothing there in this run' for a listing that deletes",
    ),
    Mutation(
        id='history/privileged-chown-advised',
        file='bob/locales/en.json',
        old='the next audit run with sudo bob gives it back to yours, through the same checked descriptor as every write',
        new='to give it back to yours: sudo chown \\"$USER\\" {path}',
        kills=('tests/test_v0261_history_unreadable.py::test_the_text_renders', 'tests/test_v0261_history_unreadable.py::TestTheChownAdviceIsForWhatItFixes::test_a_foreign_regular_file_gets_it_on_its_own_line', ),
        reason='review round 12: a chown typed with sudo resolves the path again, links included — what section 7 closes',
    ),
    Mutation(
        id='compare/exhaustive-section-new-call',
        file='bob/checks/package_integrity.py',
        old='        result.ok(message=_t("package_integrity.clean", tool=snapshot.tool),',
        new='        result.record(message=_t("package_integrity.clean", tool=snapshot.tool),',
        kills=('tests/test_v0261_baseline_exhaustive_mode.py::test_the_exhaustive_sections_never_deduct', ),
        reason='review round 12: any call on the result other than info and ok, whatever its name',
    ),
    Mutation(
        id='ipv6-chain/goto-not-followed',
        file='bob/checks/firewall_stack.py',
        old='_JUMP = re.compile(r"\\s-[jg]\\s+(\\S+)")',
        new='_JUMP = re.compile(r"\\s-j\\s+(\\S+)")',
        kills=('tests/test_v0261_ipv6_user_chains.py::test_a_goto_never_gives_a_false_blocked',),
        reason='review round 12, measured: a goto into a chain accepting 8099 left it open; not followed, BOB would say blocked',
    ),
    Mutation(
        id='ipv6-chain/chains-named-out-of-order',
        file='bob/checks/ipv6.py',
        old='                _jumped = list(dict.fromkeys(m.group(1) for r in snapshot.ip6_input_rules or []',
        new='                _jumped = sorted(dict.fromkeys(m.group(1) for r in snapshot.ip6_input_rules or []',
        kills=('tests/test_v0261_ipv6_user_chains.py::TestWhoClosesIt::test_the_text_renders_the_chains',),
        reason='review round 12: the chains are named in the order INPUT jumps to them (evpn.INPUT first on the Mint host)',
    ),
    Mutation(
        id='as-root/move-source-unchecked',
        file='bob/manage_logs.py',
        old='        refuse_if_redirected(f.parent, fd_real_path(sfd))\n',
        new='',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestManageLogsUnderARedirectedHome::test_a_move_out_of_a_redirected_directory_is_refused', ),
        reason='review round 14: a move out of a directory redirected outside the home',
    ),
    Mutation(
        id='as-root/move-destination-unchecked',
        file='bob/manage_logs.py',
        old='            refuse_if_redirected(dest_dir, fd_real_path(dfd))\n',
        new='',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestManageLogsUnderARedirectedHome::test_a_move_into_a_redirected_directory_is_refused', ),
        reason='review round 14: a move into a directory redirected outside the home',
    ),
    Mutation(
        id='as-root/move-copy-follows-a-link',
        file='bob/manage_logs.py',
        old='            src = os.open(f.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=sfd)',
        new='            src = os.open(f.name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=sfd)',
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestManageLogsUnderARedirectedHome::test_across_filesystems_it_copies_without_following_a_link', ),
        reason="across filesystems, a report that is a link to /etc/shadow would be copied into the user's directory",
    ),
    Mutation(
        id='as-root/move-by-name',
        file='bob/manage_logs.py',
        old='                                _move_report(f, chosen)',
        new="                                __import__('shutil').move(str(f), str(chosen / f.name))",
        kills=('tests/test_v0261_no_symlink_followed_as_root.py::TestManageLogsUnderARedirectedHome::test_both_move_sites_go_through_it', ),
        reason='a move by name resolves both paths again after the checks',
    ),
    Mutation(
        id='logs/count-basis-unsaid',
        file='bob/locales/en.json',
        old='"verdict_ok": "Normal activity — {total} blocked attempt(s) with a destination port over {days} day(s),',
        new='"verdict_ok": "Normal activity — {total} blocked attempt(s) over {days} day(s),',
        kills=('tests/test_v0261_logs_measured_wording.py::test_the_count_says_what_it_counts',),
        reason='review round 15, measured: 3514 of 5018 block lines counted, the IGMP ones left out unsaid',
    ),
)
