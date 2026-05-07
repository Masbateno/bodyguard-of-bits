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
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

_log = logging.getLogger(__name__)

from bob import __version__ as VERSION
from bob import i18n, output
from bob.cli import AuditConfig, CLIError, parse_args, print_help  # noqa: F401
from bob.completion import install_completion
from bob.config import UserConfig
from bob.display import build_risk_context_entries, print_audit_summary, print_correlations, print_exposure
from bob.correlation import run_correlations
from bob.exposure import compute_exposure
from bob.compare import build_baseline, compute_delta, display_delta, load_baseline, save_baseline, _BASELINE_PATH
from bob.json_output import build_json_data
from bob.output import print_banner
from bob.profiles import load_profile
from bob.registry import ServiceRegistry
from bob.history import display_history, save_score
from bob.ignore import add_ignore_key, load_ignore_keys, _ignore_file_path
from bob.recurrence import load_recurrence, save_recurrence, update_recurrence
from bob.runner import (
    _ALL_SECTIONS, _section_enabled as _se, init_report, run_checks,
    validate_check_filters,
)
from bob.scoring import ScoreEngine
from bob.sysinfo import collect_system_info, detect_network_context

EXIT_OK           = 0  # clean audit — no alerts, no warnings
EXIT_WARNINGS     = 1  # warnings detected
EXIT_ALERTS       = 2  # alerts detected (action required)
EXIT_ERROR        = 3  # technical error
EXIT_TARGET_MISSED = 4  # --target N specified and score < N


def require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("This script must be run as root: sudo bob")


def _run(argv=None) -> int:
    try:
        config = parse_args(argv)
    except CLIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
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
        else:
            run_explain(config.explain_key, i18n.t)
        return EXIT_OK

    if config.show_history:
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        display_history(t=i18n.t)
        return EXIT_OK

    if config.list_checks:
        from bob.runner import _ALL_SECTIONS
        sections = sorted(_ALL_SECTIONS)
        col = max(len(s) for s in sections) + 2
        cols = max(1, 76 // col)
        print(f"Available --check / --skip sections ({len(sections)} total):\n")
        for i, name in enumerate(sections):
            end = "\n" if (i + 1) % cols == 0 or i == len(sections) - 1 else ""
            print(f"  {name:<{col}}", end=end)
        print()
        print("Prefix matching: 'kernel' matches kernel_hardening and kernel_modules.")
        print("Core checks (firewall, ports, services, logs) always run.")
        print()
        print("Usage:")
        print("  sudo bob --check=ssh,hardening")
        print("  sudo bob --skip=clamav,rootkit")
        return EXIT_OK

    if config.ignore_key:
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        added = add_ignore_key(config.ignore_key)
        if added:
            print(f"✔ Ignored key added: {config.ignore_key}")
            print(f"  File: {_ignore_file_path()}")
        else:
            print(f"ℹ  Key already present: {config.ignore_key}")
        return EXIT_OK

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
        if _BASELINE_PATH.exists():
            try:
                _BASELINE_PATH.unlink()
                print(f"Baseline deleted: {_BASELINE_PATH}")
            except OSError as exc:
                print(f"Error: could not delete baseline: {exc}", file=sys.stderr)
                return EXIT_ERROR
        else:
            print(f"No baseline found at {_BASELINE_PATH}")
        return EXIT_OK

    require_root()
    i18n.init(lang=config.lang)
    t = i18n.t

    _filter_error = validate_check_filters(config)
    if _filter_error:
        print(f"Error: {_filter_error}", file=sys.stderr)
        return EXIT_ERROR

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
            if config.profile:
                user_config.set_profile(config.profile)
            active_profile = load_profile(profile_name)
            if profile_name not in ("", "default", "server") and active_profile.name != profile_name:
                output.print_warn(t("audit.profile_not_found", profile=profile_name))

            if config.watch_mode:
                from bob.watch import run_watch
                return run_watch(
                    config, config.watch_interval, t, output,
                    registry, active_profile, VERSION,
                )

            prev_baseline   = load_baseline()
            prev_recurrence = load_recurrence()
            curr_baseline   = None

            report   = init_report(config, user_config, t, VERSION)
            engine   = ScoreEngine()
            engine.ignore_keys = load_ignore_keys()
            sys_info = collect_system_info(VERSION, config.lang)
            report.write_header(sys_info)

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

            report.write_finding("INFO", "Starting audit")
            network_context, public_ip = detect_network_context(offline=config.offline)

            result             = run_checks(config, t, engine, report, registry, network_context,
                                           profile=active_profile,
                                           prev_recurrence=prev_recurrence)
            network_context    = result.network_context
            snapshots          = result.snapshots
            ports_snapshot     = result.ports_snapshot
            stack_snapshot     = result.stack_snapshot
            net_snapshot       = result.net_snapshot
            hardening_snapshot = result.hardening_snapshot
            ipv6_snapshot      = result.ipv6_snapshot
            fw_active          = result.fw_active
            fw_policy          = result.fw_policy

            engine.finalize()
            from bob.domain_scores import apply_domain_score_override as _apply_dso
            _apply_dso(engine)

            from bob.scoring import FindingLevel as _FL
            _active_keys = {
                f.key for f in engine.findings
                if f.key and f.level in (_FL.ALERT, _FL.WARN)
            }
            save_recurrence(update_recurrence(prev_recurrence, _active_keys))

            correlations = run_correlations(engine, t)

            # ---- Webhook notification (non-fatal) ----------------------------------
            _webhook_url = config.webhook_url or user_config.get_webhook_url()
            if _webhook_url and not config.offline:
                # Persist URL if supplied via CLI flag (keeps it for future runs)
                if config.webhook_url and config.webhook_url != user_config.get_webhook_url():
                    try:
                        user_config.set_webhook_url(config.webhook_url)
                    except ValueError:
                        pass  # invalid URL — will be caught by send_webhook below
                _webhook_fmt = config.webhook_format if config.webhook_format != "auto" \
                    else user_config.get_webhook_format()
                try:
                    from bob.webhook import WebhookError, send_webhook
                    _status = send_webhook(
                        _webhook_url, engine, sys_info, VERSION,
                        fmt=_webhook_fmt,
                    )
                    if not config.quiet:
                        output.print_info(f"Webhook: POST → {_webhook_url} [{_status}]")
                except Exception as _exc:  # noqa: BLE001
                    print(f"Warning: webhook failed: {_exc}", file=sys.stderr)
            # ------------------------------------------------------------------------

            curr_baseline = build_baseline(engine, ports_snapshot, snapshots)
            save_baseline(curr_baseline)

            if not config.quiet:
                print_audit_summary(engine, network_context, public_ip, config, t, report, snapshots,
                                    profile_name=active_profile.name,
                                    prev_score=prev_baseline.score if prev_baseline else None,
                                    fw_policy=fw_policy)
                from bob.domain_scores import render_domain_scores
                _domain_scores = engine.domain_scores
                _active        = engine.active_domains
                for _line in render_domain_scores(_domain_scores, t, active_domains=_active):
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
            report.write_next_steps([t("report.next_1"), t("report.next_2"), t("report.next_3")])
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

            save_score(engine.score, engine.level.value)

            if config.target > 0 and engine.score < config.target:
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
            )
            print(_json.dumps(data, ensure_ascii=False, indent=2))

        if config.csv_mode:
            from bob.csv_output import build_csv_output
            print(build_csv_output(engine, sys_info), end="")

        if config.markdown_mode:
            from bob.markdown_output import build_markdown_output
            print(build_markdown_output(engine, sys_info), end="")

        if config.html_mode:
            from bob.html_output import build_html_output
            print(build_html_output(engine, sys_info), end="")

        # stdout restored — display post-audit views with full output (no quiet filter)
        if config.diff_mode:
            if not prev_baseline:
                print("No previous baseline found — run a full audit first to establish a baseline.")
            else:
                _delta = compute_delta(prev_baseline, curr_baseline)
                display_delta(_delta, t, output)

        if config.breakdown_mode:
            output.init(no_color=config.no_color, quiet=False)
            from bob.breakdown import display_breakdown
            display_breakdown(engine, t, output)

        return _exit

    finally:
        if _devnull is not None:
            _devnull.close()


def main(argv=None) -> int:
    try:
        return _run(argv)
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
