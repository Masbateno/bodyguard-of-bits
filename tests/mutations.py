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
        old="192 entries (108 formal CIS",
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
)
