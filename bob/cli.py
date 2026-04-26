"""
Command-line interface for BOB.

Parses sys.argv and returns a typed AuditConfig dataclass consumed
by the rest of the application. No business logic lives here.

Usage:
    from bob.cli import parse_args
    config = parse_args()
"""

from __future__ import annotations

import sys
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------

@dataclass
class AuditConfig:
    """
    Typed representation of all command-line options.

    Instantiated by parse_args() and passed to the audit orchestrator.
    Can also be constructed directly in tests without touching sys.argv.
    """

    lang: str = "en"
    """Interface language: 'en' or 'fr'."""

    verbose: bool = False
    """-v / --verbose: show detailed port exposure per service."""

    detailed: bool = False
    """-d / --detailed: write full report to a log file."""

    fix: bool = False
    """--fix: preview available fixes (dry run — nothing is executed)."""

    apply: bool = False
    """--apply: execute fixes (use with --fix to actually apply corrections)."""

    yes: bool = False
    """-y / --yes: auto-confirm all fixes without prompting (requires --fix --apply)."""

    reconfigure: bool = False
    """--reconfigure: reset saved port configuration and re-ask."""

    no_color: bool = False
    """--no-color: disable ANSI colour output."""

    quiet: bool = False
    """-q / --quiet: suppress all terminal output; use exit code to detect issues."""

    json_mode: bool = False
    """--json: export audit summary as JSON."""

    json_full: bool = False
    """-J / --json-full: export complete audit details as JSON (implies --json)."""

    csv_mode: bool = False
    """--output csv: export audit findings as CSV to stdout."""

    markdown_mode: bool = False
    """--output markdown: export audit as GitHub-flavored Markdown to stdout."""

    html_mode: bool = False
    """--html: export audit as standalone HTML to stdout."""

    min_level: str = ""
    """--min-level=LEVEL: only display findings at or above this severity (warn, alert)."""

    log_days: int = 7
    """--log-days=N: number of days of UFW logs to analyse."""

    manage_logs: bool = False
    """--manage-logs: standalone log management UI (list/delete reports)."""

    install_cron: bool = False
    """--install-cron: install a cron job for automated audits (scheduler wizard)."""

    manage_cron: bool = False
    """-C / --manage-cron: manage installed cron jobs (list/edit/delete)."""

    show_version: bool = False
    """--version: print version string and exit."""

    show_help: bool = False
    """-h / --help: print help message and exit."""

    install_completion: bool = False
    """--install-completion: install bash completion script to /etc/bash_completion.d/."""

    offline: bool = False
    """--offline: skip all external HTTP calls (no public IP lookup)."""

    profile: str = ""
    """-p / --profile=NAME: audit profile to apply (server|desktop|container or custom)."""

    reset_baseline: bool = False
    """--reset-baseline: delete the stored audit baseline and exit."""

    explain_key: str = ""
    """-e / --explain=KEY: print a detailed explanation for a finding key and exit."""

    diff_mode: bool = False
    """-D / --diff: run audit silently and show only changes since the last baseline."""

    watch_mode: bool = False
    """--watch[=N]: run the audit every N seconds (default 60) and show only changes."""

    watch_interval: int = 60
    """Interval in seconds between watch iterations (set by --watch=N)."""

    webhook_url: str = ""
    """-w / --webhook=URL: POST audit result as JSON to this URL after the audit."""

    webhook_format: str = "auto"
    """--webhook-format=FMT: payload format — 'auto' (default), 'generic', or 'slack'."""

    target: int = 0
    """--target=N: score target (1–10); shown in summary with gap or success indicator."""

    ignore_key: str = ""
    """--ignore=KEY: add a finding key to ignore.yml and exit."""

    show_ignored: bool = False
    """--show-ignored: display ignored findings in grey alongside normal output."""

    show_history: bool = False
    """--history: display score history sparkline and exit."""

    check_only: frozenset[str] = frozenset()
    """--check=LIST: run only the named checks (comma-separated section names)."""

    skip_checks: frozenset[str] = frozenset()
    """--skip=LIST: skip the named checks (comma-separated section names)."""

    list_checks: bool = False
    """--check=list: print all valid check names and exit (no sudo required)."""

    output_dir: str = ""
    """--output-dir=PATH: directory where the detailed report is saved (overrides saved config)."""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class CLIError(ValueError):
    """Raised when an unrecognised or malformed argument is encountered."""


def parse_args(argv: list[str] | None = None) -> AuditConfig:
    """
    Parse command-line arguments and return a populated AuditConfig.

    Args:
        argv: Argument list to parse. Defaults to sys.argv[1:].
              Pass an explicit list in tests to avoid touching sys.argv.

    Returns:
        AuditConfig with all fields populated from argv.

    Raises:
        CLIError: On unknown options or invalid argument values.
    """
    if argv is None:
        argv = sys.argv[1:]

    config = AuditConfig()

    i = 0
    while i < len(argv):
        arg = argv[i]

        if arg in ("-v", "--verbose"):
            config.verbose = True

        elif arg in ("-d", "--detailed"):
            config.detailed = True

        elif arg in ("-f", "--fix"):
            config.fix = True

        elif arg == "--apply":
            config.apply = True

        elif arg in ("-y", "--yes"):
            config.yes = True

        elif arg in ("-r", "--reconfigure"):
            config.reconfigure = True

        elif arg in ("-n", "--no-color", "--no-colour"):
            config.no_color = True
        elif arg in ("-q", "--quiet"):
            config.quiet = True

        elif arg in ("-j", "--json"):
            config.json_mode = True

        elif arg in ("-J", "--json-full"):
            config.json_mode = True
            config.json_full = True

        elif arg == "--french":
            config.lang = "fr"

        elif arg.startswith("--lang="):
            value = arg.split("=", 1)[1]
            if not value:
                raise CLIError("--lang= requires a language code (e.g. en, fr)")
            config.lang = value

        elif arg in ("-l", "--log-days") and i + 1 < len(argv):
            i += 1
            value = argv[i]
            if not value.isdigit() or not (1 <= int(value) <= 3650):
                raise CLIError(
                    f"--log-days requires a positive integer (1–3650), got: {value!r}"
                )
            config.log_days = int(value)

        elif arg.startswith("--log-days="):
            value = arg.split("=", 1)[1]
            if not value.isdigit() or not (1 <= int(value) <= 3650):
                raise CLIError(
                    f"--log-days requires a positive integer (1–3650), got: {value!r}"
                )
            config.log_days = int(value)

        elif arg in ("-m", "--manage-logs"):
            config.manage_logs = True

        elif arg in ("-c", "--install-cron"):
            config.install_cron = True

        elif arg in ("-C", "--manage-cron"):
            config.manage_cron = True

        elif arg in ("-V", "--version"):
            config.show_version = True

        elif arg in ("-h", "--help"):
            config.show_help = True

        elif arg == "--install-completion":
            config.install_completion = True

        elif arg in ("-o", "--offline"):
            config.offline = True

        elif arg.startswith("--profile="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--profile= requires a profile name (e.g. server, desktop, container)")
            config.profile = value

        elif arg in ("-p", "--profile") and i + 1 < len(argv):
            i += 1
            config.profile = argv[i].strip()

        elif arg == "--reset-baseline":
            config.reset_baseline = True

        elif arg.startswith("--explain="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--explain= requires a key (e.g. ssh.password_auth) — use --explain alone for interactive mode")
            config.explain_key = value

        elif arg in ("-e", "--explain") and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            i += 1
            config.explain_key = argv[i].strip()

        elif arg in ("-e", "--explain"):
            # No key provided → launch interactive picker
            config.explain_key = "__interactive__"

        elif arg in ("-D", "--diff"):
            config.diff_mode = True

        elif arg.startswith("--watch="):
            if config.watch_mode:
                raise CLIError("--watch specified more than once")
            value = arg.split("=", 1)[1].strip()
            try:
                n = int(value)
            except ValueError:
                raise CLIError(f"--watch=N requires a positive integer, got: {value!r}")
            if n < 10:
                raise CLIError("--watch=N: interval must be at least 10 seconds")
            config.watch_mode = True
            config.watch_interval = n

        elif arg == "--watch" and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            # --watch N (space-separated, next token is a number not a flag)
            if config.watch_mode:
                raise CLIError("--watch specified more than once")
            i += 1
            value = argv[i].strip()
            try:
                n = int(value)
            except ValueError:
                raise CLIError(f"--watch N requires a positive integer, got: {value!r}")
            if n < 10:
                raise CLIError("--watch N: interval must be at least 10 seconds")
            config.watch_mode = True
            config.watch_interval = n

        elif arg == "--watch":
            if config.watch_mode:
                raise CLIError("--watch specified more than once")
            config.watch_mode = True

        elif arg.startswith("--webhook="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--webhook= requires a URL")
            config.webhook_url = value

        elif arg in ("-w", "--webhook") and i + 1 < len(argv):
            i += 1
            config.webhook_url = argv[i].strip()

        elif arg.startswith("--webhook-format="):
            config.webhook_format = arg.split("=", 1)[1].strip()

        elif arg.startswith("--target="):
            value = arg.split("=", 1)[1].strip()
            if not value.isdigit() or not (1 <= int(value) <= 10):
                raise CLIError(
                    f"--target requires an integer between 1 and 10, got: {value!r}"
                )
            config.target = int(value)

        elif arg == "--target" and i + 1 < len(argv):
            i += 1
            value = argv[i].strip()
            if not value.isdigit() or not (1 <= int(value) <= 10):
                raise CLIError(
                    f"--target requires an integer between 1 and 10, got: {value!r}"
                )
            config.target = int(value)

        elif arg.startswith("--output="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--output= requires a format: 'csv', 'json', or 'markdown'")
            if value == "csv":
                config.csv_mode = True
            elif value == "json":
                config.json_mode = True
            elif value == "markdown":
                config.markdown_mode = True
            else:
                raise CLIError(f"--output requires 'csv', 'json', or 'markdown', got: {value!r}")

        elif arg == "--output" and i + 1 < len(argv):
            i += 1
            value = argv[i].strip()
            if not value:
                raise CLIError("--output requires a format: 'csv', 'json', or 'markdown'")
            if value == "csv":
                config.csv_mode = True
            elif value == "json":
                config.json_mode = True
            elif value == "markdown":
                config.markdown_mode = True
            else:
                raise CLIError(f"--output requires 'csv', 'json', or 'markdown', got: {value!r}")

        elif arg.startswith("--min-level="):
            value = arg.split("=", 1)[1].strip().lower()
            if value not in ("warn", "alert"):
                raise CLIError(f"--min-level requires 'warn' or 'alert', got: {value!r}")
            config.min_level = value

        elif arg == "--min-level" and i + 1 < len(argv):
            i += 1
            value = argv[i].strip().lower()
            if value not in ("warn", "alert"):
                raise CLIError(f"--min-level requires 'warn' or 'alert', got: {value!r}")
            config.min_level = value

        elif arg.startswith("--ignore="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--ignore= requires a finding key (e.g. ssh.permit_root_login)")
            config.ignore_key = value

        elif arg == "--ignore" and i + 1 < len(argv):
            i += 1
            config.ignore_key = argv[i].strip()

        elif arg == "--show-ignored":
            config.show_ignored = True

        elif arg == "--history":
            config.show_history = True

        elif arg.startswith("--check="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--check= requires a comma-separated list of check names, or 'list' to show all")
            if value.lower() == "list":
                config.list_checks = True
            else:
                config.check_only = frozenset(n.strip() for n in value.split(",") if n.strip())

        elif arg == "--check" and i + 1 < len(argv):
            i += 1
            value = argv[i].strip()
            if value.lower() == "list":
                config.list_checks = True
            else:
                config.check_only = frozenset(n.strip() for n in value.split(",") if n.strip())

        elif arg.startswith("--skip="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--skip= requires a comma-separated list of check names")
            config.skip_checks = frozenset(n.strip() for n in value.split(",") if n.strip())

        elif arg == "--skip" and i + 1 < len(argv):
            i += 1
            value = argv[i].strip()
            config.skip_checks = frozenset(n.strip() for n in value.split(",") if n.strip())

        elif arg.startswith("--output-dir="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--output-dir= requires a directory path")
            config.output_dir = value

        elif arg == "--output-dir" and i + 1 < len(argv):
            i += 1
            config.output_dir = argv[i].strip()

        elif arg == "--html":
            config.html_mode = True

        elif arg.startswith("--format="):
            value = arg.split("=", 1)[1].strip().lower()
            _VALID_FORMATS = ("json", "json-full", "csv", "markdown", "html")
            if value not in _VALID_FORMATS:
                raise CLIError(
                    f"--format requires one of: {', '.join(_VALID_FORMATS)}, got: {value!r}"
                )
            if value == "json":
                config.json_mode = True
            elif value == "json-full":
                config.json_mode = True
                config.json_full = True
            elif value == "csv":
                config.csv_mode = True
            elif value == "markdown":
                config.markdown_mode = True
            elif value == "html":
                config.html_mode = True

        elif arg == "--format" and i + 1 < len(argv):
            i += 1
            value = argv[i].strip().lower()
            _VALID_FORMATS = ("json", "json-full", "csv", "markdown", "html")
            if value not in _VALID_FORMATS:
                raise CLIError(
                    f"--format requires one of: {', '.join(_VALID_FORMATS)}, got: {value!r}"
                )
            if value == "json":
                config.json_mode = True
            elif value == "json-full":
                config.json_mode = True
                config.json_full = True
            elif value == "csv":
                config.csv_mode = True
            elif value == "markdown":
                config.markdown_mode = True
            elif value == "html":
                config.html_mode = True

        else:
            raise CLIError(f"Unknown option: {arg!r}")

        i += 1

    # Validate
    if config.check_only and config.skip_checks:
        raise CLIError("--check and --skip cannot be used together")

    if config.webhook_format not in ("auto", "generic", "slack"):
        raise CLIError(
            f"--webhook-format must be 'auto', 'generic', or 'slack', got: {config.webhook_format!r}"
        )

    if config.apply and not config.fix:
        raise CLIError("--apply requires --fix")
    if config.yes and not (config.fix and config.apply):
        raise CLIError("--yes requires --fix --apply")
    if config.quiet and config.json_mode:
        raise CLIError("--quiet is incompatible with --json (JSON output requires stdout)")
    if config.quiet and config.csv_mode:
        raise CLIError("--quiet is incompatible with --output csv (CSV output requires stdout)")
    if config.quiet and config.markdown_mode:
        raise CLIError("--quiet is incompatible with --output markdown (Markdown output requires stdout)")
    if config.quiet and config.html_mode:
        raise CLIError("--quiet is incompatible with --html (HTML output requires stdout)")
    _output_modes = sum([config.json_mode, config.csv_mode, config.markdown_mode, config.html_mode])
    if _output_modes > 1:
        raise CLIError("Output format flags cannot be combined (--format, --json, --html, --output)")
    if config.watch_mode and config.json_mode:
        raise CLIError("--watch is incompatible with --json (watch mode uses interactive output)")
    if config.watch_mode and config.csv_mode:
        raise CLIError("--watch is incompatible with --output csv (watch mode uses interactive output)")
    if config.watch_mode and config.markdown_mode:
        raise CLIError("--watch is incompatible with --output markdown (watch mode uses interactive output)")
    if config.watch_mode and config.html_mode:
        raise CLIError("--watch is incompatible with --html (watch mode uses interactive output)")
    if config.quiet and config.fix and config.apply:
        raise CLIError("--quiet is incompatible with --fix --apply (fix mode requires interactive prompts)")
    if config.json_mode and config.fix and config.apply:
        raise CLIError("--json is incompatible with --fix --apply (fix mode is interactive)")

    # Mutually exclusive operating modes
    exclusive_modes = [
        (config.manage_logs,  "--manage-logs"),
        (config.install_cron, "--install-cron"),
        (config.manage_cron,  "--manage-cron"),
        (config.fix,          "--fix"),
        (config.watch_mode,   "--watch"),
        (config.diff_mode,    "--diff"),
    ]
    active_modes = [name for flag, name in exclusive_modes if flag]
    if len(active_modes) > 1:
        raise CLIError(
            f"Incompatible options: {' and '.join(active_modes)} cannot be used together"
        )

    return config

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def print_help(t, version: str) -> None:  # noqa: ARG001 — t reserved for future i18n
    """Print the CLI help message, grouped by category."""

    def section(title: str) -> None:
        print(f"\n\033[1m{title}\033[0m")

    def opt(flags: str, desc: str, col: int = 28) -> None:
        print(f"  {flags:<{col}}  {desc}")

    print(f"BOB v{version} — UFW firewall audit tool")
    print()
    print("Usage: sudo bob [OPTIONS]")
    print("       bob --explain KEY   (standalone, no sudo required)")

    section("AUDIT — what to check and how")
    opt("-p, --profile=NAME",    "Audit profile: server (default), desktop, container")
    opt("-l N, --log-days=N",    "Analyse last N days of UFW logs (default: 7)")
    opt("-D, --diff",            "Show only changes since last audit baseline")
    opt("    --watch[=N]",       "Re-run audit every N seconds (default: 60) — Ctrl+C to quit")
    opt("-o, --offline",         "Skip external IP lookup (no HTTP calls)")
    opt("    --target=N",        "Score target (1–10): show gap or success in summary")
    opt("    --check=LIST",      "Run only these checks (comma-separated); --check=list to show all names")
    opt("    --skip=LIST",       "Skip these checks (comma-separated; mutually exclusive with --check)")
    opt("    --output-dir=PATH", "Save detailed report to PATH (overrides saved config)")

    section("OUTPUT — how to present results")
    opt("-v, --verbose",          "Show detailed port exposure for each service")
    opt("-d, --detailed",         "Save full audit report to a log file")
    opt("-q, --quiet",            "Suppress all output — use exit code to detect issues")
    opt("-n, --no-color",         "Disable colour output")
    opt("    --format=FORMAT",    "Output format: json | json-full | csv | markdown | html")
    opt("-j / -J",                "Shorthands: --format=json / --format=json-full")
    opt("    --min-level=LEVEL",  "Only show findings at or above: warn  |  alert")

    section("FIXES — apply remediation suggestions")
    opt("-f, --fix",             "Preview available fixes (dry run — nothing is executed)")
    opt("    --apply",           "Execute fixes interactively (requires --fix)")
    opt("-y, --yes",             "Auto-confirm all fixes with audit trail (requires --fix --apply)")

    section("INTEGRATIONS — external reporting")
    opt("-w, --webhook=URL",     "POST audit result as JSON to URL after audit")
    opt("    --webhook-format=F","Webhook format: auto (default), generic, or slack")

    section("CONFIGURATION — language and settings")
    opt("    --lang=CODE",       "Set interface language: en (default), fr")
    opt("    --french",          "Shortcut for --lang=fr")
    opt("-r, --reconfigure",     "Reset saved port configuration and re-ask")

    section("MAINTENANCE — cron jobs and logs")
    opt("-c, --install-cron",    "Install an automated audit cron job (schedule wizard)")
    opt("-C, --manage-cron",     "List, edit or delete installed cron jobs")
    opt("-m, --manage-logs",     "List and delete saved audit log files")
    opt("    --reset-baseline",  "Delete the stored audit baseline and exit")
    opt("    --ignore=KEY",      "Add a finding key to the ignore list (~/.config/bob/ignore.yml) and exit")
    opt("    --show-ignored",    "Display suppressed findings in grey alongside normal output")

    opt("    --history",           "Display score history sparkline (last 10 audits) and exit")

    section("STANDALONE — no sudo required")
    opt("-e, --explain [KEY]",   "Interactive explain picker, or explain a specific key")
    opt("",                      "  bob -e                      (interactive — ↑↓ navigate, Enter view, q quit)")
    opt("",                      "  bob -e list                 (list all keys)")
    opt("",                      "  bob -e ssh.password_auth    (explain a key)")
    opt("-V, --version",         "Show version and exit")
    opt("-h, --help",            "Show this help message")

    section("SETUP — requires sudo")
    opt("    --install-completion", "Install bash tab-completion to /etc/bash_completion.d/")
    import sys as _sys
    from pathlib import Path as _Path
    _self = str(_Path(_sys.argv[0]).resolve())
    opt("",                      f"  sudo {_self} --install-completion")

    section("EXAMPLES")
    print("  sudo bob                        Standard audit")
    print("  sudo bob -f                     Preview available fixes (dry run)")
    print("  sudo bob -f --apply             Apply fixes interactively")
    print("  sudo bob -f --apply -y          Auto-apply all fixes")
    print("  sudo bob -v -d                  Verbose + save full report")
    print("  sudo bob --french -d            French output + save report")
    print("  sudo bob -p desktop             Desktop profile")
    print("  sudo bob -l 14                  Analyse 14 days of UFW logs")
    print("  sudo bob -D                     Show what changed since last audit")
    print("  sudo bob --watch                Re-run every 60s and show only changes")
    print("  sudo bob --watch=30             Re-run every 30s")
    print("  sudo bob --format=json | jq '.score'  Extract score as JSON")
    print("  sudo bob -w https://hooks.slack.com/...  Send to Slack")
    print("  bob -e ssh.password_auth        Explain a finding (no sudo)")

    section("EXIT CODES  (--quiet / scripting mode)")
    print("  0   No issues detected")
    print("  1   Warnings present")
    print("  2   Alerts present — action required")
    print("  3   Technical error")

    print()
    print("Documentation: https://github.com/Masbateno/bodyguard-of-bits")
