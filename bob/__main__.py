"""
BOB entry point.

Run as:
    sudo bob [OPTIONS]
    sudo python -m bob [OPTIONS]
"""

from __future__ import annotations

import contextlib
import json as _json
import logging
import os
import sys
import traceback
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

_log = logging.getLogger(__name__)

# `python3 bob` executes the package *directory*, which puts <repo>/bob at the
# head of sys.path and leaves its parent — where the package actually lives —
# off it entirely. The import below then fails with a bare traceback that says
# nothing about what to run instead.
#
# The message is a hardcoded English string, not an i18n key: i18n lives in
# `bob.i18n`, which is exactly what cannot be imported here. v0.9.1 shipped a
# bracketed-fallback key on a path with the same constraint and had to be
# hotfixed; the eighteen other CLIError raises use inline strings for the same
# reason.
#
# Only "no module named bob" is caught. A missing third-party dependency raises
# ImportError too, and swallowing that would replace one unhelpful traceback
# with a wrong explanation.
try:
    from bob import __version__ as VERSION
except ModuleNotFoundError as _exc:                        # pragma: no cover
    if _exc.name != "bob":
        raise
    _prog = Path(sys.argv[0]).name if sys.argv else "bob"
    print(
        f"✖ BOB could not import its own package.\n"
        f"\n"
        f"  '{_prog}' was run as a directory, which leaves the package's parent\n"
        f"  directory off sys.path. Use one of the supported forms instead:\n"
        f"\n"
        f"      sudo bob [OPTIONS]                  # the installed command\n"
        f"      sudo python3 -m bob [OPTIONS]       # from the repository root\n",
        file=sys.stderr,
    )
    # `from None`: the traceback is what made this unhelpful in the first
    # place, and the message above replaces it entirely.
    raise SystemExit(3) from None
from bob import i18n, output
from bob.cli import AuditConfig, CLIError, parse_args, print_help  # noqa: F401
from bob._tty import safe_input
from bob.completion import install_completion
from bob.config import UserConfig
from bob.display import build_risk_context_entries, print_audit_summary, print_correlations, print_exposure
from bob.correlation import run_correlations
from bob.exposure import compute_exposure
from bob.compare import build_baseline, compute_delta, display_delta, load_baseline, save_baseline, BASELINE_PATH
from bob.json_output import build_json_data
from bob.output import print_banner
from bob.profiles import load_profile
from bob.registry import ServiceRegistry
from bob.history import display_history, save_score
from bob.ignore import add_ignore_key, is_valid_ignore_key, load_ignore_keys, remove_ignore_key, _ignore_file_path
from bob.recurrence import load_recurrence, save_recurrence, update_recurrence
from bob.runner import (
    _ALL_SECTIONS, _section_enabled as _se, init_report, run_checks,
    validate_check_filters,
)
from bob.scoring import ScoreEngine
from bob.sysinfo import collect_system_info, detect_network_context

# ---------------------------------------------------------------------------
# Exit codes — STABLE PUBLIC API
# ---------------------------------------------------------------------------
# These exit codes are part of BOB's public API. Scripts and CI pipelines may
# depend on them. They will not change within a major version (no removal,
# no semantic shift). New codes may be added at the end if needed.
#
# Documented in --help and DOCUMENTS/README_TECH.md.
# ---------------------------------------------------------------------------

EXIT_OK            = 0  # clean audit — no alerts, no warnings
EXIT_WARNINGS      = 1  # warnings detected (improvements suggested)
EXIT_ALERTS        = 2  # alerts detected (action required)
EXIT_ERROR         = 3  # technical error (CLI parsing, IO, internal)
EXIT_TARGET_MISSED = 4  # --target N specified and score < N


def require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("This script must be run as root: sudo bob")


# v0.8.2: helper hoisted to ``bob/_i18n_safe.py`` so other entry points
# (planned ``--test-webhook``, future stand-alone CLI paths) can share
# the same gating logic without importing __main__. Local alias kept so
# call sites read naturally + don't need to be retouched.
from bob._i18n_safe import t_or_hardcoded as _t_or_hardcoded
from bob.checks._run import path_exists


def _run(argv=None) -> int:
    try:
        config = parse_args(argv)
    except CLIError as exc:
        # T60: i18n is NOT initialised at this point — parse_args runs
        # before i18n.init(). The hardcoded "Error: " stays as fallback.
        # I-2 pass 7 (v0.8.1 audit): trailing colon-space is now embedded
        # in the locale value (``cli.error.prefix`` = ``"Erreur : "`` /
        # ``"Error: "``) so French typography (space-colon-space) ships
        # consistently. Pre-fix the hardcoded ``: `` after ``t()`` produced
        # ``"Erreur: …"`` (wrong French) and ``"Avertissement : échec du
        # webhook: …"`` (double-colon mixed-style).
        print(f"{_t_or_hardcoded('cli.error.prefix', 'Error: ')}{exc}", file=sys.stderr)
        return EXIT_ERROR

    if config.show_version:
        print(f"bob v{VERSION}")
        return EXIT_OK

    if config.show_help:
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        print_help(i18n.t, VERSION)
        return EXIT_OK

    if config.explain_key:
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        from bob.explain import run_explain, run_explain_interactive
        if config.explain_key == "__interactive__":
            run_explain_interactive(i18n.t)
            return EXIT_OK
        # F4 (v0.12.0): an unknown key returns a non-zero exit so scripts can
        # tell "explained" from "no such key" (the exit codes are a stable API).
        found = run_explain(config.explain_key, i18n.t)
        return EXIT_OK if found else EXIT_ERROR

    if config.show_history:
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        display_history(t=i18n.t)
        return EXIT_OK

    if config.list_checks:
        # I-3 (v0.7.4): --check=list now honours --lang for i18n.
        # v0.8.2: each section now displays a 1-line description sourced
        # from the ``sections.descriptions.<name>`` locale namespace.
        # Pre-v0.8.2 ``--check=list`` dumped raw section names with no
        # context, leaving new users guessing what ``hardening`` vs
        # ``kernel_hardening`` actually audit. The descriptions are short
        # (< 80 chars) so the 2-column layout still fits standard 80-col
        # terminals.
        i18n.init(lang=config.lang)
        from bob.runner import _ALWAYS_ON_SECTIONS as _AO_SECTIONS
        sections = sorted(_ALL_SECTIONS)
        name_col = max(len(s) for s in sections) + 2
        print(i18n.t("cli.list.header", count=len(sections)) + "\n")
        for name in sections:
            desc = i18n.t(f"sections.descriptions.{name}")
            # Fallback when no description is wired (renders as the bare
            # key in brackets). Skip rendering the description rather than
            # show the raw ``[sections.descriptions.X]`` placeholder.
            if desc.startswith("[") and desc.endswith("]"):
                print(f"  {name}")
            else:
                print(f"  {name:<{name_col}}— {desc}")
        print()
        print(i18n.t("cli.list.prefix_matching"))
        # M-1 (v0.7.0 Phase 2.1): list the always-on sections that --check
        # accepts as input (since M-7 in v0.7.0) so the help text matches
        # the validator's accepted vocabulary.
        always_on = sorted(_AO_SECTIONS)
        ao_col = max(len(s) for s in always_on) + 2 if always_on else 0
        print()
        print(i18n.t("cli.list.always_on_header", count=len(always_on)))
        for name in always_on:
            desc = i18n.t(f"sections.descriptions.{name}")
            if desc.startswith("[") and desc.endswith("]"):
                print(f"  {name}")
            else:
                print(f"  {name:<{ao_col}}— {desc}")
        print()
        print(i18n.t("cli.list.usage_header"))
        print(i18n.t("cli.list.usage_check"))
        print(i18n.t("cli.list.usage_skip"))
        return EXIT_OK

    if config.ignore_key:
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        # M-5 (v0.7.1): validate the key against the canonical EXPLAIN_KEYS
        # pattern BEFORE attempting the write. Pre-v0.7.1 a typo or a
        # quoted-multi-word value silently truncated to the first whitespace
        # and the next audit didn't ignore anything.
        if not is_valid_ignore_key(config.ignore_key):
            print(
                "✖ "
                + i18n.t("cli.ignore.invalid_key", requested=repr(config.ignore_key))
                + "\n  "
                + i18n.t("cli.ignore.invalid_key_hint"),
                file=sys.stderr,
            )
            return EXIT_ERROR
        # v0.16.2 — the shape was validated, the existence was not. A typo
        # such as `firewall.inactve` is well-formed, is written, and then
        # matches nothing for ever: the finding the operator meant to waive
        # keeps appearing while the ignore list says it is handled. `--check`
        # already refuses an unknown section with a suggestion; this warns and
        # still writes, because an ignore list may legitimately name a key for
        # a component absent from this host.
        _known = _known_finding_keys()
        if _known and config.ignore_key not in _known:
            import difflib
            _near = difflib.get_close_matches(config.ignore_key, sorted(_known), n=1, cutoff=0.6)
            print("⚠  " + i18n.t("cli.ignore.unknown_key",
                                 requested=config.ignore_key,
                                 suggestion=_near[0] if _near else "—"),
                  file=sys.stderr)

        added = add_ignore_key(config.ignore_key)
        if added:
            print("✔ " + i18n.t("cli.ignore.added", requested=config.ignore_key))
            print("  " + i18n.t("cli.ignore.added_file", path=_ignore_file_path()))
        else:
            print("ℹ  " + i18n.t("cli.ignore.already_present", requested=config.ignore_key))
        return EXIT_OK

    # T57 (v0.8.1) — --unignore=KEY: remove from ignore.yml and exit
    if config.unignore_key:
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        if not is_valid_ignore_key(config.unignore_key):
            # Reuse the same invalid-key feedback as --ignore — the canonical
            # pattern is identical, the user's mental model shouldn't shift.
            print(
                "✖ "
                + i18n.t("cli.ignore.invalid_key", requested=repr(config.unignore_key))
                + "\n  "
                + i18n.t("cli.ignore.invalid_key_hint"),
                file=sys.stderr,
            )
            return EXIT_ERROR
        removed = remove_ignore_key(config.unignore_key)
        if removed:
            print("✔ " + i18n.t("cli.ignore.removed", requested=config.unignore_key))
            print("  " + i18n.t("cli.ignore.added_file", path=_ignore_file_path()))
        else:
            print("ℹ  " + i18n.t("cli.ignore.not_present", requested=config.unignore_key))
        return EXIT_OK

    # v0.15.3 — -r/--reconfigure: delete the saved configuration and exit.
    #
    # The flag shipped in v0.1.0 and was advertised in --help and twice in the
    # man page, and BOB printed "To reset it: bob --reconfigure" on every run
    # that found a config — but nothing ever read ``config.reconfigure``. It
    # was parsed and dropped for fourteen minor versions.
    #
    # The original wording promised a wizard ("reset saved port configuration
    # and re-ask"); that wizard never existed. Profile and webhook persist from
    # their CLI flags, log_dir is asked by --manage-logs, and no <service>_port
    # key is ever written or read. So the honest contract is reset-and-exit:
    # the next run re-detects its defaults. Placed here, beside --ignore and
    # --unignore and *before* require_root(), because config.conf is a
    # per-user file resolved through SUDO_USER — root is not required to drop
    # your own configuration.
    if config.reconfigure:
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        user_config = UserConfig.load()
        if not user_config.exists():
            print("\u2139  " + i18n.t("cli.reconfigure.nothing"))
            return EXIT_OK
        print(i18n.t("cli.reconfigure.about_to", path=str(user_config.path)))
        for key in user_config.all_keys():
            print("    " + key)
        # Always confirms, with no -y bypass: the parser scopes -y to
        # --fix --apply and widening that documented contract for one
        # convenience is not worth it. The asymmetry with --reset-baseline,
        # which deletes silently, is deliberate — a baseline is regenerated by
        # the next audit, whereas config.conf holds hand-entered state (webhook
        # URL, log directories picked through the --manage-logs wizard) that
        # nothing can reconstruct.
        #
        # safe_input turns EOF into "", which is not "y" — Ctrl+D and any
        # non-interactive caller abort rather than confirm.
        answer = safe_input("  " + i18n.t("cli.reconfigure.confirm") + " ").strip().lower()
        if answer != "y":
            print("\u2139  " + i18n.t("cli.reconfigure.aborted"))
            return EXIT_OK
        try:
            user_config.reset()
        except OSError as exc:
            print(
                "\u2716 " + i18n.t("cli.reconfigure.failed", error=exc),
                file=sys.stderr,
            )
            return EXIT_ERROR
        print("\u2714 " + i18n.t("cli.reconfigure.done", path=str(user_config.path)))
        return EXIT_OK

    # v0.8.2 — --test-webhook smoke command
    if config.test_webhook:
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        t = i18n.t
        # v0.11.1 M-2: --offline is a global no-egress guard (air-gapped
        # environments). When it conflicts with the explicit --test-webhook
        # network smoke, the more restrictive flag wins: skip the POST cleanly
        # rather than silently violate the offline guarantee. The audit-time
        # webhook path already gates on ``not config.offline``; this mirrors it
        # for the explicit test command.
        if config.offline:
            print("ℹ  " + i18n.t("cli.test_webhook.offline_skipped"), file=sys.stderr)
            return EXIT_OK
        # Resolve URL: --webhook=URL takes precedence; otherwise use the saved
        # user config (same precedence as the real audit-time webhook path).
        # ``UserConfig`` is imported at module scope; do NOT re-import it inside
        # this function — a local ``from`` statement would shadow the
        # module-level binding and turn line 298 (audit path) into an
        # UnboundLocalError when ``--test-webhook`` isn't set.
        user_config = UserConfig.load()
        _url = config.webhook_url or user_config.get_webhook_url()
        if not _url:
            print(
                "✖ " + i18n.t("cli.test_webhook.no_url"),
                file=sys.stderr,
            )
            return EXIT_ERROR
        _fmt = config.webhook_format if config.webhook_format != "auto" \
            else user_config.get_webhook_format()
        try:
            from bob.webhook import redact_url_credentials, test_webhook
            _safe = redact_url_credentials(_url)
            print("ℹ  " + i18n.t("cli.test_webhook.posting", url=_safe))
            _status = test_webhook(_url, fmt=_fmt, t=t)
            print("✔ " + i18n.t("cli.test_webhook.success", url=_safe, status=_status))
            return EXIT_OK
        except Exception as _exc:  # noqa: BLE001
            # The WebhookError message is already locale-formatted via the
            # threaded ``t``; we just need a translated prefix.
            print(
                f"✖ {i18n.t('cli.test_webhook.failed')}: {_exc}",
                file=sys.stderr,
            )
            return EXIT_ERROR

    if config.install_completion:
        if os.geteuid() != 0:
            self_path = Path(sys.argv[0]).resolve()
            print(
                f"✖ --install-completion requires root.\n"
                f"\n"
                f"  ⚠ 'sudo bob' will not work — sudo uses a restricted PATH\n"
                f"    that does not include pipx binaries.\n"
                f"\n"
                f"  Copy and run this exact command:\n"
                f"    sudo {self_path} --install-completion",
                file=sys.stderr,
            )
            return EXIT_ERROR
        return install_completion()

    if config.reset_baseline:
        require_root()
        # I-3 (v0.7.4): --reset-baseline output now honours --lang.
        i18n.init(lang=config.lang)
        if path_exists(BASELINE_PATH):
            try:
                BASELINE_PATH.unlink()
                print(i18n.t("cli.baseline.deleted", path=BASELINE_PATH))
            except OSError as exc:
                print(i18n.t("cli.baseline.delete_error", error=exc), file=sys.stderr)
                return EXIT_ERROR
        else:
            print(i18n.t("cli.baseline.not_found", path=BASELINE_PATH))
        return EXIT_OK

    i18n.init(lang=config.lang)
    t = i18n.t

    # F6 (v0.12.0): validate --check / --skip tokens BEFORE the root gate.
    # The validation needs no privileges, so an unknown section name should
    # report "unknown check 'X'" rather than first demanding sudo. Pre-fix,
    # ``bob --check=typo`` (no sudo) printed "must be run as root", forcing the
    # operator to sudo + re-run only to then learn the token was wrong.
    _filter_error = validate_check_filters(config)
    if _filter_error:
        # T10 (v0.8.1): i18n the "Error:" prefix so a French audit emits
        # "Erreur :" instead of mixed-language output. The trailing message
        # may itself be EN today (CLIError messages aren't translated yet)
        # but at least the prefix matches the locale.
        # I-2 pass 7 (v0.8.1 audit): colon-space is now embedded in the
        # locale value — drop the hardcoded ``: `` to honour FR typography
        # convention (``"Erreur : message"`` not ``"Erreur: message"``).
        print(f"{t('cli.error.prefix')}{_filter_error}", file=sys.stderr)
        return EXIT_ERROR

    # C-fix (v0.12.1): surface an unknown --profile BEFORE the root gate (like
    # F6 does for --check/--skip), so `bob --profile=typo` without sudo reports
    # the bad name instead of first demanding root. Resolving a profile name
    # needs no privileges. Non-fatal — the audit still falls back to the
    # default once root is satisfied; this just removes the sudo round-trip
    # before the operator learns the name was wrong.
    _profile_prewarned = False
    if config.profile and config.profile not in ("", "default", "server"):
        from bob.profiles import _find_profile_file
        if _find_profile_file(config.profile) is None:
            print(f"{t('cli.error.warning_prefix')}"
                  + t("audit.profile_not_found", profile=config.profile),
                  file=sys.stderr)
            _profile_prewarned = True

    require_root()

    _machine_mode = config.json_mode or config.csv_mode or config.markdown_mode or config.html_mode
    # diff/breakdown suppress all audit output (bare print() calls bypass quiet=True)
    _silent_mode  = _machine_mode or config.breakdown_mode or config.diff_mode
    if _silent_mode:
        config.quiet = True
    _devnull = open(os.devnull, "w", encoding="utf-8") if _silent_mode else None

    try:
        with (redirect_stdout(_devnull) if _devnull else contextlib.nullcontext()):
            output.init(no_color=config.no_color, quiet=config.quiet, min_level=config.min_level)
            registry    = ServiceRegistry.load()
            user_config = UserConfig.load()

            if config.manage_logs:
                from bob.manage_logs import run_manage_logs
                return run_manage_logs(user_config, config, t)

            if config.install_cron:
                from bob.cron import run_install_cron
                return run_install_cron(user_config, config, t)

            if config.manage_cron:
                from bob.cron import run_manage_cron
                return run_manage_cron(config, t)

            if user_config.exists():
                output.print_info(t("config.found", path=str(user_config.path)))
                output.print_dim(t("config.reconfigure_hint"))
            if not config.quiet:
                print()

            # Resolve audit profile: CLI flag > saved config > default
            profile_name = config.profile or user_config.get_profile() or "server"
            active_profile = load_profile(profile_name)
            _profile_not_found = (
                profile_name not in ("", "default", "server")
                and active_profile.name != profile_name
            )
            # v0.12.1 (Fix B): persist an explicit --profile ONLY when it
            # resolved to a real profile. Pre-fix, `--profile=typo` saved the
            # bad name to config, so every later run fell back to the default
            # and silently lost the user's real saved profile.
            if config.profile and not _profile_not_found:
                user_config.set_profile(config.profile)
            if _profile_not_found and not _profile_prewarned:
                output.print_warn(t("audit.profile_not_found", profile=profile_name))

            if config.watch_mode:
                from bob.watch import run_watch
                return run_watch(
                    config, config.watch_interval, t, output,
                    registry, active_profile, VERSION,
                    user_config=user_config,
                )

            # v0.9.0 F-2: when --diff=PATH was passed, load the explicit
            # baseline file in strict mode so a missing/broken file surfaces
            # as a CLIError instead of the silent ``no baseline yet``
            # message. Bare --diff keeps the soft v0.8.x behaviour.
            if config.diff_baseline_path is not None:
                from bob.compare import BaselineLoadError
                try:
                    prev_baseline = load_baseline(
                        config.diff_baseline_path, strict=True,
                    )
                except BaselineLoadError as _exc:
                    print(
                        f"{t('cli.error.prefix')}{_exc}",
                        file=sys.stderr,
                    )
                    return EXIT_ERROR
            else:
                prev_baseline   = load_baseline()
            prev_recurrence = load_recurrence()
            curr_baseline   = None

            report   = init_report(config, user_config, t, VERSION)
            engine   = ScoreEngine(profile=active_profile)
            engine.ignore_keys = load_ignore_keys()
            sys_info = collect_system_info(VERSION, config.lang)
            # M-5 (v0.7.4): pass localised labels so `--french` reports have
            # a French header block (pre-v0.7.4: hardcoded English).
            report.write_header(sys_info, labels={
                "system_information": t("banner.system_information"),
                "system":             t("banner.system"),
                "host":               t("banner.host"),
                "kernel":             t("banner.kernel"),
                "firewall":           t("banner.firewall"),
                "user":               t("banner.user"),
                "language":           t("banner.language"),
                "port_config":        t("banner.port_config"),
            })

            if not config.quiet:
                not_installed = t("banner.not_installed")
                print_banner(
                    version=f"v{VERSION}",
                    subtitle=t("banner.subtitle"),
                    system=sys_info.os_name,
                    host=sys_info.hostname,
                    kernel=sys_info.kernel,
                    ufw_version=sys_info.ufw_version,
                    iptables=sys_info.iptables_version or not_installed,
                    nftables=sys_info.nftables_version or not_installed,
                    user=sys_info.user,
                    date=datetime.now().strftime("%d/%m/%Y %H:%M"),
                    labels={k: t(f"banner.{k}") for k in
                            ("system", "host", "kernel", "ufw", "iptables", "nftables", "user", "date")},
                )
                output.print_info(t("audit.starting"))
                output.print_info(t("audit.audit_profile", profile=active_profile.name))
                if config.check_only or config.skip_checks:
                    _active = [s for s in _ALL_SECTIONS if _se(s, config, active_profile)]
                    output.print_info(t("audit.running_checks", checks=", ".join(_active)))
                print()

            # Same translated string the terminal shows two lines above. It was
            # a literal, so a French audit's .log opened in English while the
            # screen said "Démarrage de l'audit" — the mixed-language content
            # v0.7.3 M-5 fixed for six field labels and missed here.
            report.write_finding("INFO", t("audit.starting"))
            network_context, public_ip = detect_network_context(offline=config.offline)

            result             = run_checks(config, t, engine, report, registry, network_context,
                                           profile=active_profile,
                                           prev_recurrence=prev_recurrence,
                                           user_config=user_config)
            network_context    = result.network_context
            snapshots          = result.snapshots
            ports_snapshot     = result.ports_snapshot
            stack_snapshot     = result.stack_snapshot
            net_snapshot       = result.net_snapshot
            hardening_snapshot = result.hardening_snapshot
            ipv6_snapshot      = result.ipv6_snapshot
            fw_active          = result.fw_active
            fw_policy          = result.fw_policy
            degraded_sections  = result.degraded_sections

            engine.finalize()
            from bob.domain_scores import apply_domain_score_override as _apply_dso
            _apply_dso(engine)

            # Posture escalation (v0.7.0) — lift the displayed risk level out
            # of LOW when the firewall is structurally broken even if the
            # weighted-average score stays high. See bob.scoring.ScoreEngine
            # docstring "posture escalation".
            # M-10 (v0.7.3): single source of truth via set_posture_from_engine.
            from bob.scoring import set_posture_from_engine
            set_posture_from_engine(engine, fw_active=fw_active)

            from bob.scoring import FindingLevel as _FL
            _active_keys = {
                f.key for f in engine.findings
                if f.key and f.level in (_FL.ALERT, _FL.WARN)
            }
            save_recurrence(update_recurrence(prev_recurrence, _active_keys))

            correlations = run_correlations(engine, t)

            # ---- Webhook notification (non-fatal) ----------------------------------
            _webhook_url = config.webhook_url or user_config.get_webhook_url()
            # v0.16.2 — say it. --offline legitimately suppresses the POST, but
            # suppressing it silently means an operator who asked for a delivery
            # gets nothing and no reason. The sibling path already announced it:
            # v0.11.1 M-2 taught --test-webhook to say "skipped: --offline is
            # set" and left the audit path mute.
            if _webhook_url and config.offline and not config.quiet and not _machine_mode:
                output.print_info(t("webhook.skipped_offline"))
            if _webhook_url and not config.offline:
                # Persist URL if supplied via CLI flag (keeps it for future runs)
                if config.webhook_url and config.webhook_url != user_config.get_webhook_url():
                    try:
                        user_config.set_webhook_url(config.webhook_url, t=t)
                    except ValueError:
                        pass  # invalid URL — will be caught by send_webhook below
                _webhook_fmt = config.webhook_format if config.webhook_format != "auto" \
                    else user_config.get_webhook_format()
                try:
                    from bob.webhook import redact_url_credentials, send_webhook
                    _status = send_webhook(
                        _webhook_url, engine, sys_info, VERSION,
                        fmt=_webhook_fmt,
                        t=t,
                        profile=getattr(active_profile, "name", "") or "server",
                        degraded_sections=degraded_sections,
                    )
                    if not config.quiet:
                        # T74 (v0.8.1): scrub embedded credentials before
                        # printing the URL to stdout + the on-disk .log
                        # report. Slack/Discord/Mattermost URLs frequently
                        # embed API tokens as user:pass.
                        _display_url = redact_url_credentials(_webhook_url)
                        output.print_info(f"Webhook: POST → {_display_url} [{_status}]")
                except Exception as _exc:  # noqa: BLE001
                    # T10 (v0.8.1): translate the "Warning: webhook failed" prefix.
                    # The exception message itself is already translated by
                    # send_webhook via the t threaded above.
                    # I-2 pass 7 (v0.8.1 audit): colon-space embedded in the
                    # locale value (FR ``"Avertissement : échec du webhook : "``,
                    # EN ``"Warning: webhook failed: "``). Pre-fix the hardcoded
                    # ``: `` after the FR value produced a visible double
                    # ``: `` mixed-style line.
                    print(f"{t('cli.error.webhook_failed_prefix')}{_exc}", file=sys.stderr)
            # ------------------------------------------------------------------------

            curr_baseline = build_baseline(engine, ports_snapshot, snapshots)
            save_baseline(curr_baseline)

            # v0.16.0 — always called, quiet handled inside.
            #
            # This sat inside `if not config.quiet:`, so `bob -q -d` wrote a
            # 440-line report with no [AUDIT SUMMARY] block at all: no score,
            # no risk level, no counts. The two flags are orthogonal — `-q` is
            # about stdout, `-d` is a file the operator explicitly asked for —
            # and display.py already states the rule this violated: "all print_*
            # calls are gated by config.quiet so bob -q produces empty stdout;
            # report.write_* calls always run so the .log file remains
            # complete". The gate is now where that sentence says it is.
            print_audit_summary(engine, network_context, public_ip, config, t, report, snapshots,
                                profile_name=active_profile.name,
                                prev_score=prev_baseline.score if prev_baseline else None,
                                fw_policy=fw_policy,
                                degraded_sections=degraded_sections)

            if not config.quiet:
                from bob.domain_scores import render_domain_scores
                _domain_scores = engine.domain_scores
                # v0.12.1: pass engine + profile so ALL domains are shown,
                # inactive ones annotated with the reason (not installed /
                # not assessed by profile / no action needed), still excluded
                # from the average.
                for _line in render_domain_scores(_domain_scores, t,
                                                  engine=engine, profile=active_profile,
                                                  config=config):
                    print(_line)
                print()
                _exposure = compute_exposure(engine, ports_snapshot, network_context,
                                             fw_active, fw_policy, t)
                print_exposure(_exposure, t, output)
                if correlations:
                    print_correlations(correlations, t, output)
                if prev_baseline:
                    print()
                    display_delta(compute_delta(prev_baseline, curr_baseline), t, output)

            report.write_risk_context_section(
                section_title=t("sections.risk_context"),
                entries=build_risk_context_entries(snapshots, config.lang, t,
                                                   network_context=network_context),
            )
            report.write_next_steps(
                [t("report.next_1"), t("report.next_2"), t("report.next_3")],
                title=t("report.next_steps_title"),
            )
            report.close()

            if engine.ignored_findings and not config.quiet:
                n = len(engine.ignored_findings)
                print()
                if config.show_ignored:
                    print(output._c.dim + t("ignored.header") + output._c.reset)
                    for _f in engine.ignored_findings:
                        output.print_ignored(_f.message)
                else:
                    output.print_ignored(t("ignored.summary", count=n))

            if config.fix:
                from bob.fixes import run_fixes
                run_fixes(engine, config, t)

            # I-4 (v0.7.0 Phase 2.1): history records the effective level
            # (matches what was displayed/JSON-emitted) AND the score-only
            # baseline as a separate field, so trend analysis can reach for
            # either view without re-parsing the audit context.
            save_score(
                engine.score,
                engine.effective_level.value,
                level_score_only=engine.level.value,
            )

            # v0.16.0 — a bounded score cannot satisfy a target.
            #
            # `--target N` asks "is the score at least N?". When a check could
            # not read its input the score is a ceiling, so the honest answer
            # is "unknown", and a CI gate that reads unknown as pass is the
            # exact failure this release is about: an audit run without the
            # privileges it needs would go green. A gate fails closed.
            # v0.16.2 — reads score_is_uncertain, not score_is_upper_bound.
            # Making the bound honest meant a run whose blindness removed a
            # whole domain stopped being "bounded", and this gate would have
            # started passing it. The gate is about verifiability, not about
            # which direction the error points.
            if config.target > 0 and (
                engine.score < config.target or engine.score_is_uncertain
            ):
                _exit = EXIT_TARGET_MISSED
            elif engine.alert_count > 0:
                _exit = EXIT_ALERTS
            elif engine.warn_count > 0:
                _exit = EXIT_WARNINGS
            else:
                _exit = EXIT_OK

        # stdout restored by redirect_stdout — safe to print machine-readable output
        if config.json_mode:
            data = build_json_data(
                engine, sys_info, network_context, public_ip,
                snapshots, ports_snapshot,
                stack_snapshot, net_snapshot,
                full=config.json_full, version=VERSION,
                hardening_snapshot=hardening_snapshot,
                ipv6_snapshot=ipv6_snapshot,
                schema_version="3",
                profile=active_profile, config=config,
                degraded_sections=degraded_sections,
            )
            print(_json.dumps(data, ensure_ascii=False, indent=2))

        if config.csv_mode:
            from bob.csv_output import build_csv_output
            print(build_csv_output(engine, sys_info), end="")

        if config.markdown_mode:
            from bob.markdown_output import build_markdown_output
            # M-4 (v0.7.2): pass the audit's bound translation function so
            # the export can be localised. The Markdown module accepts t=None
            # for backwards-compat with legacy callers / test mocks.
            print(build_markdown_output(engine, sys_info, t=t,
                                        profile=active_profile, config=config), end="")

        if config.html_mode:
            from bob.html_output import build_html_output
            # M-4 (v0.7.2): pass t + lang so the HTML report carries both
            # the localised strings and a correct <html lang="..."> attr.
            print(build_html_output(engine, sys_info, t=t, lang=config.lang,
                                    profile=active_profile, config=config), end="")

        # stdout restored — display post-audit views with full output (no quiet
        # filter). v0.15.3: this comment stated the contract since v0.9.0 but
        # only --breakdown implemented it. _silent_mode forces config.quiet =
        # True so the audit itself stays mute, and display_delta writes through
        # output.print_*, so --diff printed nothing at all — not on a change,
        # not on an unchanged system, never.
        #
        # Machine modes stay excluded: a human view printed after the JSON /
        # CSV / Markdown / HTML payload corrupts the stream its caller parses.
        # --diff was accidentally safe there while it was mute; --breakdown was
        # not, and emitted its table straight into `bob -j | jq`.
        if config.diff_mode and not _machine_mode:
            output.init(no_color=config.no_color, quiet=False)
            if not prev_baseline:
                print(t("compare.no_baseline_yet"))
            else:
                # v0.9.0 F-2: if the baseline came from an explicit
                # --diff=PATH AND the recorded hostname differs from the
                # current host, surface a one-line INFO so the operator
                # knows they are looking at a cross-machine compare.
                # ``hostname is None`` covers pre-v0.9.0 baselines (the
                # field didn't exist) — we stay silent in that case.
                if (
                    config.diff_baseline_path is not None
                    and prev_baseline.hostname
                ):
                    import socket as _sock
                    try:
                        _cur_host = _sock.gethostname()
                    except OSError:
                        _cur_host = ""
                    if _cur_host and prev_baseline.hostname != _cur_host:
                        print(t(
                            "compare.cross_machine_notice",
                            baseline_host=prev_baseline.hostname,
                            current_host=_cur_host,
                        ))
                _delta = compute_delta(prev_baseline, curr_baseline)
                display_delta(_delta, t, output)

        if config.breakdown_mode and not _machine_mode:
            output.init(no_color=config.no_color, quiet=False)
            from bob.breakdown import display_breakdown
            display_breakdown(engine, t, output)

        return _exit

    finally:
        if _devnull is not None:
            _devnull.close()


def _known_finding_keys() -> "set[str]":
    """Every finding key BOB can emit, for validating an ignore entry.

    Read from EXPLAIN_KEYS, which the project already keeps exhaustive and
    guarded. Returns an empty set if that import fails, so a warning can never
    be the thing that breaks ``--ignore``.
    """
    try:
        from bob.explain import EXPLAIN_KEYS
        return set(EXPLAIN_KEYS)
    except Exception:      # pragma: no cover — defensive
        return set()


def main(argv=None) -> int:
    try:
        return _run(argv)
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        # v0.14.1: Ctrl-C on a long audit dumped a raw Python traceback ending
        # in ``KeyboardInterrupt`` — noise on the most ordinary way to stop the
        # tool. 130 is the conventional shell code for SIGINT and is what the
        # process already returned; only the traceback was wrong.
        print(_t_or_hardcoded("cli.error.interrupted", "\n  Interrupted."),
              file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        # M-6 (v0.6.1): one-line summary + traceback under BOB_DEBUG=1 so
        # bug reports are actionable. Without the hint, users get "Fatal
        # error: 'NoneType' object has no attribute 'X'" and no way to
        # diagnose. The env var keeps everyday output clean.
        # T60 (v0.8.1): translate the prefix + the BOB_DEBUG hint when i18n
        # is already initialised. ``_t_or_hardcoded`` falls back to the EN
        # baseline when the exception fires before init or init itself
        # failed — the user always sees a consistent message.
        # v0.8.3: ``os`` and ``traceback`` are already module-scope imports
        # (see top of file). Re-importing them inside this except clause
        # would shadow the module-level binding for the entire main() body
        # and turn earlier ``os.<x>`` references into UnboundLocalError —
        # see test_v083_main_scope_guard for the regression.
        # I-2 pass 7 (v0.8.1 audit): colon-space embedded in the locale
        # value so the FR rendering ships ``"Erreur fatale : "`` and the
        # hardcoded ``: `` after the prefix is dropped.
        fatal_prefix = _t_or_hardcoded("cli.error.fatal_prefix", "Fatal error: ")
        print(f"{fatal_prefix}{exc}", file=sys.stderr)
        if os.environ.get("BOB_DEBUG"):
            traceback.print_exc(file=sys.stderr)
        else:
            print(
                _t_or_hardcoded(
                    "cli.error.bob_debug_hint",
                    "  Set BOB_DEBUG=1 for full traceback.",
                ),
                file=sys.stderr,
            )
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
