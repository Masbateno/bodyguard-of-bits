"""
Command-line interface for BOB.

Parses sys.argv and returns a typed AuditConfig dataclass consumed
by the rest of the application. No business logic lives here.

Usage:
    from bob.cli import parse_args
    config = parse_args()
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


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
    """--json: export audit summary as JSON (schema v3 by default since v0.12.0)."""

    json_full: bool = False
    """-J / --json-full: export complete audit details as JSON (implies --json)."""

    # v0.9.0 F-3: ``--json-v1`` legacy schema (v0.6.x) retired. ``json_v1``
    # field removed. ``__main__.py`` now passes ``schema_version="3"``
    # unconditionally (v0.12.0 F9 bumped v2→v3). A user who types ``--json-v1``
    # on the CLI hits the ``CLIError`` migration message in ``parse_args`` below.

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
    """-p / --profile=NAME: audit profile to apply (server|desktop|workstation|container or custom)."""

    reset_baseline: bool = False
    """--reset-baseline: delete the stored audit baseline and exit."""

    explain_key: str = ""
    """-e / --explain=KEY: print a detailed explanation for a finding key and exit."""

    diff_mode: bool = False
    """-D / --diff[=PATH]: run audit silently and show only changes since a baseline."""

    diff_baseline_path: Path | None = None
    """v0.9.0 F-2 — explicit baseline path for --diff. When None (default),
    --diff loads ``~/.config/bob/last_baseline.json`` as before. When set
    (via ``--diff=PATH`` or ``--diff PATH``), --diff compares against the
    file at that path, enabling cross-machine compare (audit on host A →
    save → ``scp`` to host B → ``sudo bob --diff hostA-baseline.json`` on
    host B). The path is read but never written to."""

    breakdown_mode: bool = False
    """-B / --breakdown: run audit silently and print the full score computation path."""

    watch_mode: bool = False
    """--watch[=N]: run the audit every N seconds (default 60) and show only changes."""

    watch_interval: int = 60
    """Interval in seconds between watch iterations (set by --watch=N)."""

    webhook_url: str = ""
    """-w / --webhook=URL: POST audit result as JSON to this URL after the audit."""

    webhook_format: str = "auto"
    """--webhook-format=FMT: payload format — 'auto' (default), 'generic', or 'slack'."""

    test_webhook: bool = False
    """v0.8.2: --test-webhook — POST a minimal smoke payload to the configured
    webhook URL and exit. Validates the URL + scheme + reachability + receiver
    HTTP status without running a full audit. Honours the same scheme rules as
    a real audit POST (https-only by default; opt out via
    ``BOB_WEBHOOK_ALLOW_INSECURE=1``). Useful for verifying a fresh
    ``bob --webhook=URL`` setup before scheduling it via cron."""

    target: int = 0
    """--target=N: score target (1–10); shown in summary with gap or success indicator."""

    ignore_key: str = ""
    """--ignore=KEY: add a finding key to ignore.yml and exit."""

    unignore_key: str = ""
    """T57 (v0.8.1): --unignore=KEY — remove a finding key from ignore.yml
    and exit. Mirror of --ignore=KEY: same validation, same canonical-key
    pattern check, same atomic write contract. Closes the symmetry gap
    where users could add ignored keys via CLI but had to edit
    ``~/.config/bob/ignore.yml`` by hand to remove them."""

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


# v0.14.1: ``--lang`` was passed straight to ``i18n.init()``, which builds
# ``_LOCALES_DIR / f"{lang}.json"``. pathlib replaces the whole base when the
# right-hand side is absolute, so ``--lang=/tmp/x`` loaded /tmp/x.json as the
# translation table — an unvalidated argument reaching an arbitrary filesystem
# read (as root under sudo). This validates the SHAPE only: a well-formed but
# unknown code (``--lang=de``) still falls back to English with a warning, as
# before. Same discipline already applied to SUDO_USER in bob/sysinfo.py.
_LANG_RE = re.compile(r"^[A-Za-z]{2,3}(?:[_-][A-Za-z]{2,4})?$")


def _parse_section_list(value: str, opt: str) -> frozenset[str]:
    """Split a --check / --skip value into section tokens.

    v0.14.1: an all-separator value (``--check ","``) previously produced an
    empty frozenset, which is falsy — so ``--check`` silently degraded to "no
    filter" and ran the FULL audit, while the ``--check=`` form raised. Both
    forms now reject a value that yields no token.
    """
    tokens = frozenset(n.strip().lower() for n in value.split(",") if n.strip())
    if not tokens:
        raise CLIError(
            f"{opt} requires a comma-separated list of check names, got: {value!r}"
        )
    return tokens


def _validate_lang(value: str) -> str:
    """Return *value* if it is a plausible language code, else raise CLIError."""
    if not _LANG_RE.match(value):
        raise CLIError(
            f"--lang requires a language code such as 'en' or 'fr', got: {value!r}"
        )
    return value


# M-2 (v0.7.4): options that take a value AND have no valid no-arg form.
# When such an option is the LAST argv element (or is immediately followed
# by another flag), the parser would previously fall through to "Unknown
# option" — confusing, since the option *is* known. We now raise an
# explicit "requires a value" error. ``-e/--explain`` and ``--watch``
# are intentionally absent — they have a documented no-arg behaviour
# (interactive picker / default 60 s loop respectively).
_VALUE_TAKING_OPTS = frozenset({
    "--lang",
    "-l", "--log-days",
    "--target",
    "--output",
    "--min-level",
    "--ignore",
    "--unignore",
    "--check",
    "--skip",
    "--output-dir",
    "--format",
    "-p", "--profile",
    "-w", "--webhook",
    "--webhook-format",
    # M-1 pass 8 (v0.8.1 audit): ``--webhook-secret`` was listed here but
    # never wired into the parse loop and no ``webhook_secret`` field
    # exists on AuditConfig. Pre-fix, ``bob --webhook-secret foo`` raised
    # the misleading "--webhook-secret requires a value" error from the
    # value-taking missing-value path while ``bob --webhook-secret=foo``
    # fell through to "Unknown option" — inconsistent error messages for
    # the same phantom option. Dead entry removed.
})


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
    lang_explicit = False  # tracks whether --lang= or --french was passed

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

        elif arg == "--json-v1":
            # v0.9.0 F-3: legacy v0.6.x schema retired. The v2 schema has
            # been the default since v0.7.0 (4 majeures), and v0.6.x has
            # been EOL since v0.7.2. Users on a v0.6.x JSON consumer must
            # update the consumer to read the v2 layout — see
            # ``DOCUMENTS/CHANGELOG_FULL.md`` v0.9.0 entry for the
            # field-by-field mapping.
            #
            # v0.9.1 fix: parse_args runs BEFORE i18n.init(), so calling
            # i18n.t() here surfaces a bracketed-fallback to the user
            # (``Error: [cli.error.json_v1_retired]``) instead of the
            # actual message. Hardcoded English matches the other
            # CLIError raises in this file.
            raise CLIError(
                "--json-v1 was retired in v0.9.0. Schema v2 is the only "
                "supported format (v2 has been the default since v0.7.0). "
                "See CHANGELOG.md v0.9.0 entry for the field-by-field "
                "migration table from v0.6.x v1 to v2."
            )

        elif arg == "--french":
            config.lang = "fr"
            lang_explicit = True

        # E-fix (v0.12.1): symmetric explicit-English flag. A naive user who
        # sees --french reasonably tries --english; pre-fix it errored with
        # "Unknown option: '--english'". English is the default, so this just
        # makes the choice explicit (and overrides a saved/auto-detected fr).
        elif arg == "--english":
            config.lang = "en"
            lang_explicit = True

        elif arg.startswith("--lang="):
            value = arg.split("=", 1)[1]
            if not value:
                raise CLIError("--lang= requires a language code (e.g. en, fr)")
            config.lang = _validate_lang(value)
            lang_explicit = True

        # M-2 (v0.7.3): also accept the space-separated form `--lang VALUE`
        # so it matches the convention used by every other value-taking
        # option (--log-days, --target, --min-level, etc.). Pre-v0.7.3 a
        # user typing ``bob --lang fr`` got "Unknown option: 'fr'".
        elif arg == "--lang" and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            i += 1
            value = argv[i]
            if not value:
                raise CLIError("--lang requires a language code (e.g. en, fr)")
            config.lang = _validate_lang(value)
            lang_explicit = True

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
                raise CLIError("--profile= requires a profile name (e.g. server, desktop, workstation, container)")
            config.profile = value

        elif arg in ("-p", "--profile") and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            # v0.14.1: the M-4 (v0.7.3) dash guard was never applied here, so
            # ``bob -p --quiet`` set profile="--quiet" AND swallowed --quiet.
            i += 1
            value = argv[i].strip()
            if not value:
                raise CLIError("--profile requires a profile name (e.g. server, desktop, workstation, container)")
            config.profile = value

        elif arg == "--reset-baseline":
            config.reset_baseline = True

        elif arg.startswith("--explain="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--explain= requires a key (e.g. ssh.password_auth) — use --explain alone for interactive mode")
            config.explain_key = value.lower()

        elif arg in ("-e", "--explain") and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            i += 1
            value = argv[i].strip()
            # M-3 (v0.7.3): reject an empty key supplied as a separate arg
            # (``bob -e ""``) — pre-v0.7.3 it silently fell through to the
            # interactive picker after consuming the arg.
            if not value:
                raise CLIError("--explain requires a key (e.g. ssh.password_auth) — use --explain alone for interactive mode")
            config.explain_key = value.lower()

        elif arg in ("-e", "--explain"):
            # No key provided → launch interactive picker
            config.explain_key = "__interactive__"

        elif arg.startswith("--diff="):
            # v0.9.0 F-2: --diff=PATH — compare against an explicit baseline file
            if config.diff_mode:
                raise CLIError("--diff specified more than once")
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--diff= requires a path to a baseline JSON file")
            config.diff_mode = True
            config.diff_baseline_path = Path(value).expanduser()

        elif arg in ("-D", "--diff") and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            # v0.9.0 F-2: --diff PATH (space-separated) — same as --diff=PATH.
            # The peek-ahead requires the next token to not start with ``-`` so
            # ``sudo bob --diff --watch`` keeps the bare-flag semantics.
            if config.diff_mode:
                raise CLIError("--diff specified more than once")
            i += 1
            value = argv[i].strip()
            config.diff_mode = True
            config.diff_baseline_path = Path(value).expanduser()

        elif arg in ("-D", "--diff"):
            # Bare --diff / -D — load the local auto-managed baseline (v0.8.x behaviour)
            if config.diff_mode:
                raise CLIError("--diff specified more than once")
            config.diff_mode = True

        elif arg in ("-B", "--breakdown"):
            config.breakdown_mode = True

        elif arg.startswith("--watch="):
            if config.watch_mode:
                raise CLIError("--watch specified more than once")
            value = arg.split("=", 1)[1].strip()
            try:
                n = int(value)
            except ValueError:
                # from None: the int() ValueError is an implementation detail; under
                # BOB_DEBUG the user should see the CLI error, not "during handling
                # of the above exception".
                raise CLIError(f"--watch=N requires an integer ≥ 10, got: {value!r}") from None
            if n < 10:
                raise CLIError(f"--watch=N: interval must be ≥ 10 seconds, got: {n}")
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
                raise CLIError(f"--watch N requires an integer ≥ 10, got: {value!r}") from None
            if n < 10:
                raise CLIError(f"--watch N: interval must be ≥ 10 seconds, got: {n}")
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

        elif arg in ("-w", "--webhook") and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            # M-4 (v0.7.3): reject a value that starts with '-' so a typo
            # like ``bob -w --quiet`` doesn't silently parse as
            # webhook_url="--quiet". Pre-v0.7.3 the URL validation would
            # have caught it downstream with a confusing scheme error.
            i += 1
            config.webhook_url = argv[i].strip()

        elif arg.startswith("--webhook-format="):
            config.webhook_format = arg.split("=", 1)[1].strip()

        # v0.8.2: --test-webhook smoke command
        elif arg == "--test-webhook":
            config.test_webhook = True

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
            # E-fix (v0.12.1): accept html (mirrors --html) + case-insensitive.
            # ADV-D2 (v0.12.1): accept json-full so --output is a complete alias
            # of --format (which already supports it).
            value = arg.split("=", 1)[1].strip().lower()
            if not value:
                raise CLIError("--output= requires a format: 'csv', 'json', 'json-full', 'markdown', or 'html'")
            if value == "csv":
                config.csv_mode = True
            elif value == "json":
                config.json_mode = True
            elif value == "json-full":
                config.json_mode = True
                config.json_full = True
            elif value == "markdown":
                config.markdown_mode = True
            elif value == "html":
                config.html_mode = True
            else:
                raise CLIError(f"--output requires 'csv', 'json', 'json-full', 'markdown', or 'html', got: {value!r}")

        elif arg == "--output" and i + 1 < len(argv):
            i += 1
            value = argv[i].strip().lower()
            if not value:
                raise CLIError("--output requires a format: 'csv', 'json', 'json-full', 'markdown', or 'html'")
            if value == "csv":
                config.csv_mode = True
            elif value == "json":
                config.json_mode = True
            elif value == "json-full":
                config.json_mode = True
                config.json_full = True
            elif value == "markdown":
                config.markdown_mode = True
            elif value == "html":
                config.html_mode = True
            else:
                raise CLIError(f"--output requires 'csv', 'json', 'json-full', 'markdown', or 'html', got: {value!r}")

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

        elif arg == "--ignore" and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            # M-4 (v0.7.3): reject a value that starts with '-' so a typo
            # like ``bob --ignore --quiet`` doesn't silently set
            # ignore_key="--quiet" (which then fails the v0.7.1 M-5
            # canonical-key regex with a confusing message).
            i += 1
            config.ignore_key = argv[i].strip()

        # T57 (v0.8.1) — --unignore: removal counterpart to --ignore
        elif arg.startswith("--unignore="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--unignore= requires a finding key (e.g. ssh.permit_root_login)")
            config.unignore_key = value

        elif arg == "--unignore" and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            # Same value-starts-with-dash guard as --ignore (v0.7.3 M-4 pattern).
            i += 1
            config.unignore_key = argv[i].strip()

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
                config.check_only = _parse_section_list(value, "--check")

        elif arg == "--check" and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            i += 1
            value = argv[i].strip()
            if not value:
                raise CLIError("--check requires a comma-separated list of check names, or 'list' to show all")
            if value.lower() == "list":
                config.list_checks = True
            else:
                config.check_only = _parse_section_list(value, "--check")

        elif arg.startswith("--skip="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--skip= requires a comma-separated list of check names")
            config.skip_checks = _parse_section_list(value, "--skip")

        elif arg == "--skip" and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            i += 1
            value = argv[i].strip()
            if not value:
                raise CLIError("--skip requires a comma-separated list of check names")
            config.skip_checks = _parse_section_list(value, "--skip")

        elif arg.startswith("--output-dir="):
            value = arg.split("=", 1)[1].strip()
            if not value:
                raise CLIError("--output-dir= requires a directory path")
            config.output_dir = value

        elif arg == "--output-dir" and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            # M-4 (v0.7.3): reject a value that starts with '-' so
            # ``bob --output-dir --quiet`` doesn't silently set
            # output_dir="--quiet" and create a confusing directory.
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
            # M-2 (v0.7.4): distinguish "value-taking option with missing
            # value" from "unknown option". Pre-v0.7.4 `bob -l` (no value)
            # fell through to "Unknown option: '-l'" — confusing, since
            # ``-l`` is well-known and only its argument is missing.
            if arg in _VALUE_TAKING_OPTS:
                raise CLIError(f"{arg} requires a value")
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

    # M-4 (v0.8.1 audit) — ``--ignore`` and ``--unignore`` are mutually
    # exclusive. Pre-fix, ``bob --ignore=X --unignore=Y`` was accepted
    # silently: __main__.py's --ignore handler short-circuits (return
    # EXIT_OK) and the --unignore was dropped without any feedback. Now
    # surfaces as a clear CLIError consistent with the other v0.7.x
    # mutual-exclusion guards above.
    if config.ignore_key and config.unignore_key:
        raise CLIError("--ignore and --unignore are mutually exclusive")

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

    # POSIX locale auto-detection — only when --lang/--french wasn't explicitly set.
    # Honours $LC_ALL / $LC_MESSAGES / $LANG. C/POSIX → fallback to default (en).
    if not lang_explicit:
        from bob.i18n import detect_system_lang
        config.lang = detect_system_lang()

    return config

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def print_help(t, version: str) -> None:
    """Print the CLI help message, grouped by category.

    v0.15.3: every human-readable string routes through ``t``. The signature
    carried ``# noqa: ARG001 — t reserved for future i18n`` since v0.1.0 while
    the body printed English literals, so ``bob --help --french`` returned
    byte-identical English on the one screen that advertises --french.

    Flags stay untranslated — they are CLI syntax, not prose — which also
    keeps the two columns aligned identically across locales.
    """

    # v0.14.0 F: the section headers used to hardcode the bold escape, so
    # `bob --no-color --help` still emitted ANSI and `bob --help > file`
    # wrote escape codes into it. Route through the output module so --help
    # obeys the same rule as the rest of the tool (--no-color / NO_COLOR /
    # FORCE_COLOR / TTY detection).
    def section(key: str) -> None:
        from bob import output as _o
        bold, reset = (_o._c.bold, _o._c.reset) if not _o._no_color else ("", "")
        print(f"\n{bold}{t('help.section.' + key)}{reset}")

    def opt(flags: str, key: str, col: int = 28) -> None:
        print(f"  {flags:<{col}}  {t(key)}")

    def ex(cmd: str, key: str, col: int = 30) -> None:
        print(f"  {cmd:<{col}}  {t('help.example.' + key)}")

    print(f"BOB v{version} — {t('help.tagline')}")
    print()
    # The label is translated, so the continuation line is padded from its
    # rendered length rather than a hardcoded seven spaces.
    _usage = t("help.usage_label")
    print(f"{_usage} sudo bob [OPTIONS]")
    print(f"{' ' * len(_usage)} bob --explain KEY   ({t('help.usage_standalone')})")

    section("audit")
    opt("-p, --profile=NAME",    "help.opt.profile")
    # v0.14.1: the persistence was real since v0.12.1 but documented nowhere the
    # user looks — a one-off ``-p container`` silently became their permanent
    # default. Stating it here is the whole fix; the behaviour is deliberate.
    opt("",                      "help.opt.profile_saved")
    opt("-l N, --log-days=N",    "help.opt.log_days")
    opt("-D, --diff[=PATH]",     "help.opt.diff")
    opt("",                      "help.opt.diff_path")
    opt("    --watch[=N]",       "help.opt.watch")
    opt("-o, --offline",         "help.opt.offline")
    opt("    --target=N",        "help.opt.target")
    opt("    --check=LIST",      "help.opt.check")
    opt("",                      "help.opt.check_list")
    opt("    --skip=LIST",       "help.opt.skip")
    opt("    --output-dir=PATH", "help.opt.output_dir")

    section("output")
    opt("-v, --verbose",          "help.opt.verbose")
    opt("-d, --detailed",         "help.opt.detailed")
    opt("-q, --quiet",            "help.opt.quiet")
    opt("-n, --no-color",         "help.opt.no_color")
    opt("    NO_COLOR / FORCE_COLOR", "help.opt.env_color")
    opt("",                       "help.opt.env_color_2")
    opt("    --format=FORMAT",    "help.opt.format")
    opt("    --output=FORMAT",    "help.opt.output_alias")
    opt("-j / -J",                "help.opt.shorthands")
    opt("    --json / --json-full", "help.opt.long_aliases")
    opt("    --html",             "help.opt.html")
    opt("    --min-level=LEVEL",  "help.opt.min_level")

    section("fixes")
    opt("-f, --fix",             "help.opt.fix")
    opt("    --apply",           "help.opt.apply")
    opt("-y, --yes",             "help.opt.yes")

    section("integrations")
    opt("-w, --webhook=URL",     "help.opt.webhook")
    opt("    --webhook-format=F","help.opt.webhook_format")
    opt("    --test-webhook",    "help.opt.test_webhook")

    section("configuration")
    opt("    --lang=CODE",       "help.opt.lang")
    opt("    --french",          "help.opt.french")
    opt("    --english",         "help.opt.english")
    opt("-r, --reconfigure",     "help.opt.reconfigure")

    section("maintenance")
    opt("-c, --install-cron",    "help.opt.install_cron")
    opt("-C, --manage-cron",     "help.opt.manage_cron")
    opt("-m, --manage-logs",     "help.opt.manage_logs")
    opt("-B, --breakdown",       "help.opt.breakdown")
    opt("    --reset-baseline",  "help.opt.reset_baseline")
    opt("    --ignore=KEY",      "help.opt.ignore")
    opt("",                      "help.opt.ignore_file")
    opt("    --unignore=KEY",    "help.opt.unignore")
    opt("    --show-ignored",    "help.opt.show_ignored")
    opt("    --history",         "help.opt.history")

    section("standalone")
    opt("-e, --explain [KEY]",   "help.opt.explain")
    opt("    bob -e",            "help.opt.explain_interactive")
    opt("    bob -e list",       "help.opt.explain_list")
    opt("    bob -e ssh.password_auth", "help.opt.explain_key")
    opt("-V, --version",         "help.opt.version")
    opt("-h, --help",            "help.opt.help")

    section("setup")
    opt("    --install-completion", "help.opt.install_completion")
    # v0.15.3: the example used to interpolate Path(sys.argv[0]).resolve(),
    # which was wrong in both directions. From a source checkout it printed
    # "sudo .../bob/__main__.py --install-completion" — a mode-644 file with no
    # shebang, so the advertised command simply fails. Under pipx, .resolve()
    # dereferenced the stable ~/.local/bin/bob entry point into the venv's
    # internal real path, which changes on every reinstall. Print the command
    # the reader can actually paste, for each of the three ways BOB is run.
    import shutil as _shutil
    import sys as _sys
    from pathlib import Path as _Path

    _argv0 = _Path(_sys.argv[0])
    if _argv0.name == "__main__.py":          # python3 -m bob, from a checkout
        _cmd = f"{_Path(_sys.executable).name} -m bob"
    elif _shutil.which(_argv0.name):          # entry point on PATH
        _cmd = _argv0.name
    else:                                     # installed, but not on PATH
        _cmd = str(_argv0)
    print(f"  {'':<28}    sudo {_cmd} --install-completion")

    section("examples")
    ex("sudo bob",                      "standard")
    ex("sudo bob -f",                   "preview")
    ex("sudo bob -f --apply",           "apply")
    ex("sudo bob -f --apply -y",        "auto")
    ex("sudo bob -v -d",                "verbose")
    ex("sudo bob --french -d",          "french")
    ex("sudo bob -p desktop",           "desktop")
    ex("sudo bob -l 14",                "logs")
    ex("sudo bob -D",                   "diff")
    ex("sudo bob --watch",              "watch")
    ex("sudo bob --watch=30",           "watch30")
    ex("sudo bob --format=json | jq '.score'", "json")
    ex("sudo bob -w https://hooks.slack.com/...", "slack")
    ex("bob -e ssh.password_auth",      "explain")

    section("exit_codes")
    for _code in range(5):
        print(f"  {_code}   {t(f'help.exit.{_code}')}")

    print()
    print("Documentation: https://github.com/Masbateno/bodyguard-of-bits")
