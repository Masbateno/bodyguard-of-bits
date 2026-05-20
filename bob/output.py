"""
Terminal output module for BOB.

Handles all ANSI colour formatting and structured display functions.
No translation logic lives here — all strings are pre-translated
by the caller before being passed to print_* functions.

Usage:
    from bob import output
    output.init(no_color=False)

    from bob.output import print_ok, print_warn, print_section
    print_ok(t("firewall.active"))
    print_section(t("sections.firewall"))
"""

from __future__ import annotations

import re
import sys
import unicodedata
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Input sanitization — strip ANSI codes from external data before display
# ---------------------------------------------------------------------------

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[mGKHFABCDJr]")

def sanitize(value: str, max_len: int = 256) -> str:
    """
    Strip ANSI escape sequences and non-printable characters from a string,
    then truncate to max_len. Apply to all data coming from the system
    (container names, hostnames, domains, etc.) before terminal display.
    """
    value = _ANSI_ESCAPE_RE.sub("", value)
    value = "".join(c for c in value if c.isprintable())
    if len(value) > max_len:
        value = value[:max_len] + "…"
    return value


# ---------------------------------------------------------------------------
# ANSI colour codes
# ---------------------------------------------------------------------------

class _Colours(NamedTuple):
    reset:  str
    bold:   str
    dim:    str
    red:    str
    yellow: str
    orange: str
    green:  str
    cyan:   str
    blue:   str
    violet: str
    red_bold:    str
    yellow_bold: str
    orange_bold: str
    green_bold:  str
    cyan_bold:   str
    blue_bold:   str
    violet_bold: str


_COLOURS_ON = _Colours(
    reset        = "\033[0m",
    bold         = "\033[1m",
    dim          = "\033[2m",
    red          = "\033[31m",
    yellow       = "\033[33m",
    orange       = "\033[38;5;208m",
    green        = "\033[32m",
    cyan         = "\033[36m",
    blue         = "\033[34m",
    violet       = "\033[38;5;135m",
    red_bold     = "\033[1;31m",
    yellow_bold  = "\033[1;33m",
    orange_bold  = "\033[1;38;5;208m",
    green_bold   = "\033[1;32m",
    cyan_bold    = "\033[1;36m",
    blue_bold    = "\033[1;34m",
    violet_bold  = "\033[1;38;5;135m",
)

_COLOURS_OFF = _Colours(
    **{field: "" for field in _Colours._fields}
)


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_c: _Colours = _COLOURS_ON
_no_color: bool = False
_quiet:    bool = False

# Terminal width — used for section boxes and banner
_TERM_WIDTH: int = 80

# Minimum severity threshold: 0=all, 1=info+, 2=warn+, 3=alert only
_min_level_threshold: int = 0
_LEVEL_RANK = {"ok": 0, "info": 1, "warn": 2, "alert": 3}


def _passes_threshold(level: str) -> bool:
    """Return True if this level should be displayed given the current threshold."""
    return _LEVEL_RANK.get(level, 0) >= _min_level_threshold


# ---------------------------------------------------------------------------
# Score bar — shared gauge rendering for score 0–10
# ---------------------------------------------------------------------------

_SCORE_BAR_WIDTH = 10


def score_bar(score: int) -> str:
    """Return a 10-char block progress bar coloured by score level.

    Mirrors the visual style of `display._disk_bar` but with inverted
    thresholds since for scores HIGH = good:
      - score >= 8 : green  (healthy)
      - score 5–7  : yellow (moderate)
      - score 0–4  : red    (critical)

    Returns an ANSI-coloured string ready to print, terminated by
    `_c.reset`. When colours are disabled (``--no-color``), the ANSI
    codes are empty strings — the visual bar still renders, just
    monochrome.
    """
    score = max(0, min(_SCORE_BAR_WIDTH, int(score)))
    filled = score
    empty  = _SCORE_BAR_WIDTH - filled
    if score >= 8:
        color = _c.green
    elif score >= 5:
        color = _c.yellow
    else:
        color = _c.red
    return f"{color}{'█' * filled}{'░' * empty}{_c.reset}"


def init(no_color: bool = False, quiet: bool = False, min_level: str = "") -> None:
    """
    Initialise the output module.

    Must be called once before any print_* function.
    Safe to call multiple times (e.g. in tests).

    Args:
        no_color:  If True, all ANSI codes are suppressed.
        quiet:     If True, all print_* functions are silenced.
        min_level: Minimum severity to display: '' (all), 'warn', or 'alert'.
    """
    global _c, _no_color, _quiet, _min_level_threshold
    _no_color = no_color
    _quiet    = quiet
    _c = _COLOURS_OFF if (no_color or quiet) else _COLOURS_ON
    _min_level_threshold = _LEVEL_RANK.get(min_level.lower(), 0)


def _p(*args, **kwargs) -> None:
    """Internal print wrapper — respects quiet mode."""
    if not _quiet:
        print(*args, **kwargs)


# ---------------------------------------------------------------------------
# Status line printers
# ---------------------------------------------------------------------------

def print_ok(message: str, detail: str = "") -> None:
    """Print a green OK status line.

    Args:
        message: Main message text.
        detail:  Optional secondary detail printed on the next line.
    """
    _print_status(f"{_c.green_bold}✔{_c.reset}", "OK", _c.green, message, detail)


def print_warn(message: str, detail: str = "") -> None:
    """Print a yellow WARNING status line."""
    from bob.i18n import t as _t
    _print_status(f"{_c.yellow_bold}⚠{_c.reset}", _t("status.warn"), _c.yellow, message, detail)


def print_alert(message: str, detail: str = "") -> None:
    """Print a red ALERT status line."""
    from bob.i18n import t as _t
    _print_status(f"{_c.red_bold}✖{_c.reset}", _t("status.alert"), _c.red, message, detail)


def print_info(message: str, detail: str = "") -> None:
    """Print a neutral INFO status line."""
    _print_status(f"{_c.cyan}ℹ{_c.reset}", "INFO", _c.dim, message, detail)


def print_ignored(message: str) -> None:
    """Print a finding that was suppressed by ignore.yml (dim, [IGNORED] tag)."""
    if not _quiet:
        from bob.i18n import t as _t
        tag = _t("ignored.tag")
        print(f"{_c.dim}  [{_c.reset}{tag}{_c.dim}] {message}{_c.reset}")


def _print_status(
    icon: str,
    label: str,
    colour: str,
    message: str,
    detail: str,
) -> None:
    _p(f"{icon} {colour}[{label}]{_c.reset} {message}")
    if detail:
        _p(f"    {_c.dim}{detail}{_c.reset}")


# ---------------------------------------------------------------------------
# Structural display
# ---------------------------------------------------------------------------

def print_group(title: str) -> None:
    """Print a thematic group header — title centred inside the ━ bar.

    Example:
        ━━━━━━━━━━━━━━━━━━━━━━━ PARE-FEU & RÉSEAU ━━━━━━━━━━━━━━━━━━━━━━━
    """
    label = f" {title} "
    side = (_TERM_WIDTH - len(label)) // 2
    extra = _TERM_WIDTH - len(label) - 2 * side   # 0 or 1 when width is odd
    bar = "━" * side + label + "━" * (side + extra)
    _p()
    _p(f"{_c.cyan}{bar}{_c.reset}")
    _p()


def print_section(title: str) -> None:
    """Print a section header box.

    Example:
        ┌─────────────────────────────────────────────────────────────┐
        │  ÉTAT DU PARE-FEU                                           │
        └─────────────────────────────────────────────────────────────┘
    """
    inner = _TERM_WIDTH - 2  # space inside │ borders
    bar = "─" * inner
    padding = inner - 4 - _visual_width(title)
    padding = max(0, padding)

    _p()  # blank line before each section
    _p(f"{_c.blue}┌{bar}┐{_c.reset}")
    _p(f"{_c.blue}│{_c.reset}  {_c.bold}{title}{_c.reset}{' ' * padding}  {_c.blue}│{_c.reset}")
    _p(f"{_c.blue}└{bar}┘{_c.reset}")
    _p()


def print_service_header(label: str) -> None:
    """Print a service name as a sub-section marker.

    Example:
        ▶ SSH Server
    """
    _p(f"\n  {_c.bold}▶ {label}{_c.reset}")


def print_port_detail(message: str) -> None:
    """Print an indented port detail line (↳ prefix)."""
    _p(f"    {_c.dim}↳ {message}{_c.reset}")


def print_recommendation(
    lines: str | list[str],
    cmd_lines: str | list[str] | None = None,
) -> None:
    """Print a recommendation block.

    Args:
        lines:     Explanatory text lines — printed in cyan with → prefix.
        cmd_lines: Command lines — printed in violet_bold with → prefix so
                   they stand out from the explanatory text.
    """
    from bob.i18n import t as _t
    if isinstance(lines, str):
        lines = lines.splitlines()
    _p(f"\n    {_c.dim}{_t('output.recommendation_label')}{_c.reset}")
    for line in lines:
        _p(f"    {_c.cyan}→ {line}{_c.reset}")
    if cmd_lines is not None:
        if isinstance(cmd_lines, str):
            cmd_lines = cmd_lines.splitlines()
        for line in cmd_lines:
            _p(f"    {_c.violet_bold}→ {line}{_c.reset}")
    _p()


def print_check_cmd(lines: str | list[str]) -> None:
    """Print a diagnostic command block with ℹ prefix (check commands).

    Used for read-only commands that display information without making
    any change to the system (e.g. iptables -L, smartctl -a).

    Args:
        lines: Single string or list of strings. Each line is printed
               with a ℹ prefix on a new indented line.
    """
    from bob.i18n import t as _t
    if isinstance(lines, str):
        lines = lines.splitlines()
    _p(f"\n    {_c.dim}{_t('output.check_label')}{_c.reset}")
    for line in lines:
        _p(f"    {_c.violet_bold}ℹ {line}{_c.reset}")
    _p()


def print_dim(message: str) -> None:
    """Print a dimmed informational line."""
    _p(f"  {_c.dim}{message}{_c.reset}")


def yellow(text: str) -> str:
    """Wrap *text* in yellow ANSI codes (respects --no-color)."""
    return f"{_c.yellow}{text}{_c.reset}"


def print_risk_context(
    title: str,
    level: str,
    exposure_label: str,
    exposure: str,
    threat_label: str,
    threat: str,
    is_critical: bool = False,
    risk_tier: str = "low",
) -> None:
    """Print the two-axis risk context block for a service.

    Args:
        title:          Label for the context block (e.g. "Contexte de risque").
        level:          Risk level string (e.g. "CRITIQUE", "ÉLEVÉ").
        exposure_label: Translated label for exposure axis.
        exposure:       Exposure description text.
        threat_label:   Translated label for threat axis.
        threat:         Threat description text.
        is_critical:    Kept for backward compatibility. Prefer risk_tier.
        risk_tier:      "critical" → red, "medium" → orange, "low" → yellow.
    """
    if risk_tier == "critical" or is_critical:
        level_colour = _c.red_bold
    elif risk_tier == "medium":
        level_colour = _c.orange_bold
    else:
        level_colour = _c.yellow_bold
    _p(f"    {_c.dim}┄ {title} — {level_colour}{level}{_c.reset}")
    _p(f"    {_c.dim}{exposure_label} : {_c.reset}{_c.dim}{exposure}{_c.reset}")
    _p(f"    {_c.dim}{threat_label}   : {_c.reset}{_c.dim}{threat}{_c.reset}")
    _p()


# ---------------------------------------------------------------------------
# Summary box
# ---------------------------------------------------------------------------

def print_summary_box(lines: list[tuple[str, str]]) -> None:
    """Print the audit summary box.

    Args:
        lines: List of (label, value) pairs to display inside the box.
               Pass an empty string as value for section separators.

    Example:
        print_summary_box([
            ("Score de sécurité", "10/10"),
            ("Niveau de risque",  "✔ FAIBLE"),
            ("Contexte réseau",   "🏠 Réseau local uniquement"),
        ])
    """
    inner = _TERM_WIDTH - 2

    print(f"{_c.blue_bold}╔{'═' * inner}╗{_c.reset}")
    for label, value in lines:
        if label == "---":
            print(f"{_c.blue_bold}╠{'═' * inner}╣{_c.reset}")
            continue
        content = f"  {label} : {value}" if value else f"  {label}"
        padding = inner - _visual_width(content)
        padding = max(0, padding)
        print(f"{_c.blue_bold}║{_c.reset}{content}{' ' * padding}{_c.blue_bold}║{_c.reset}")
    print(f"{_c.blue_bold}╚{'═' * inner}╝{_c.reset}")


# ---------------------------------------------------------------------------
# Services panorama
# ---------------------------------------------------------------------------

def print_services_panorama(rows: list[dict], labels: dict) -> None:
    """Print a panoramic table of all known services (installed or not).

    Args:
        rows:   List of dicts with keys:
                  label   — service name
                  status  — "active" | "inactive" | "not_installed" | "unknown"
                  ports   — port string, e.g. "22/tcp" or "—"
                  ufw     — "ok" | "warn" | "none" | "na"
        labels: Dict with translated strings for headers and status values.
    """
    COL_SVC  = 32
    COL_STAT = 13
    COL_PORT = 20

    h_svc  = labels.get("header_service", "SERVICE")
    h_stat = labels.get("header_status",  "STATUS")
    h_port = labels.get("header_ports",   "PORT(S)")
    h_ufw  = labels.get("header_ufw",     "UFW")

    sep = (
        "  " + "─" * COL_SVC + "  " +
        "─" * COL_STAT + "  " +
        "─" * COL_PORT + "  " + "───"
    )

    _p(
        f"  {_c.bold}{h_svc:<{COL_SVC}}{_c.reset}  "
        f"{_c.bold}{h_stat:<{COL_STAT}}{_c.reset}  "
        f"{_c.bold}{h_port:<{COL_PORT}}{_c.reset}  "
        f"{_c.bold}{h_ufw}{_c.reset}"
    )
    _p(sep)

    l_active       = labels.get("active",        "ACTIVE")
    l_inactive     = labels.get("inactive",      "INACTIVE")
    l_not_inst     = labels.get("not_installed", "NOT INSTALLED")
    l_unknown      = labels.get("unknown",       "UNKNOWN")

    for row in rows:
        label  = row["label"]
        status = row["status"]
        ports  = row["ports"]
        ufw    = row["ufw"]

        # Status text + colour
        if status == "active":
            stat_text = l_active
            stat_col  = _c.green if ufw == "ok" else (
                _c.yellow_bold if ufw == "warn" else _c.red
            )
        elif status == "inactive":
            stat_text = l_inactive
            stat_col  = _c.dim
        elif status == "not_installed":
            stat_text = l_not_inst
            stat_col  = _c.dim
        else:
            stat_text = l_unknown
            stat_col  = _c.dim

        # UFW indicator
        if ufw == "ok":
            ufw_str = f"{_c.green}✔{_c.reset}"
        elif ufw == "warn":
            ufw_str = f"{_c.yellow_bold}⚠{_c.reset}"
        elif ufw == "none":
            ufw_str = f"{_c.red}✖{_c.reset}"
        else:
            ufw_str = f"{_c.dim}—{_c.reset}"

        # Truncate to column width to prevent layout overflow
        label = label[:COL_SVC]
        ports = ports[:COL_PORT]

        # Dim everything for not-installed rows
        if status == "not_installed":
            label_str = f"{_c.dim}{label:<{COL_SVC}}{_c.reset}"
            ports_str = f"{_c.dim}{ports:<{COL_PORT}}{_c.reset}"
        else:
            label_str = f"{label:<{COL_SVC}}"
            ports_str = f"{ports:<{COL_PORT}}"

        _p(
            f"  {label_str}  "
            f"{stat_col}{stat_text:<{COL_STAT}}{_c.reset}  "
            f"{ports_str}  "
            f"{ufw_str}"
        )


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def _build_logo() -> str:
    """
    ASCII art for 'BOB' centered in the banner width (inner=78).
    6 rows figlet Doom style, followed by a centered tagline.
    """
    B = ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██████╔╝", "╚═════╝ "]
    O = [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "]

    groups = [B, O, B]
    pad = " " * 25
    art_rows = [pad + " ".join(grp[i] for grp in groups) for i in range(6)]
    tagline = "— Bodyguard Of Bits —"
    tagline_left = " " * ((_TERM_WIDTH - 2 - len(tagline)) // 2)
    art_rows.append("")
    art_rows.append(tagline_left + tagline)
    return "\n".join(art_rows)


def print_banner(
    version: str,
    subtitle: str,
    system: str,
    host: str,
    kernel: str,
    ufw_version: str,
    iptables: str,
    nftables: str,
    user: str,
    date: str,
    labels: dict[str, str],
) -> None:
    """Print the ASCII art banner with system information.

    Args:
        version:     Application version string (e.g. "v0.9.0").
        subtitle:    Translated subtitle (e.g. "Audit pare-feu UFW").
        system:      OS/distro string.
        host:        Hostname.
        kernel:      Kernel version string.
        ufw_version: UFW version string.
        iptables:    iptables version string (or "non installé").
        nftables:    nftables version string (or "non installé").
        user:        Current user.
        date:        Formatted date string.
        labels:      Dict of translated field labels.
    """
    inner = _TERM_WIDTH - 2
    bar_double = "═" * inner

    logo = _build_logo()

    print(f"{_c.blue_bold}╔{bar_double}╗{_c.reset}")
    for line in logo.splitlines():
        padding = inner - _visual_width(line)
        padding = max(0, padding)
        print(f"{_c.blue_bold}║{_c.reset}{_c.orange_bold}{line}{_c.reset}{' ' * padding}{_c.blue_bold}║{_c.reset}")

    # Étage: version + subtitle between art and system info
    print(f"{_c.blue_bold}╠{bar_double}╣{_c.reset}")
    etage = f"  BOB {version}  │  {subtitle}"
    etage_pad = max(0, inner - _visual_width(etage))
    print(f"{_c.blue_bold}║{_c.reset}{etage}{' ' * etage_pad}{_c.blue_bold}║{_c.reset}")
    print(f"{_c.blue_bold}╠{bar_double}╣{_c.reset}")

    info_rows = [
        (labels.get("system",   "System"),   system),
        (labels.get("host",     "Host"),     host),
        (labels.get("kernel",   "Kernel"),   kernel),
        (labels.get("ufw",      "UFW"),      f"v{ufw_version}"),
        (labels.get("iptables", "iptables"), iptables),
        (labels.get("nftables", "nftables"), nftables),
        (labels.get("user",     "User"),     user),
        (labels.get("date",     "Date"),     date),
    ]
    for label, value in info_rows:
        content = f"  {label:<14}: {value}"
        padding = inner - _visual_width(content)
        padding = max(0, padding)
        print(f"{_c.blue_bold}║{_c.reset}{content}{' ' * padding}{_c.blue_bold}║{_c.reset}")

    print(f"{_c.blue_bold}╚{bar_double}╝{_c.reset}")
    print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from a string for length calculation."""
    return re.sub(r"\033\[[0-9;]*m", "", text)


def _visual_width(text: str) -> int:
    """Return the terminal display width of a string.

    Accounts for wide Unicode characters (emojis, CJK) that occupy 2 columns.
    East-Asian-width 'W' and 'F' are counted as 2; everything else as 1.
    ANSI escape codes are stripped before measurement.
    """
    width = 0
    for ch in _strip_ansi(text):
        eaw = unicodedata.east_asian_width(ch)
        width += 2 if eaw in ("W", "F") else 1
    return width


def supports_color() -> bool:
    """Return True if the current terminal supports ANSI colours."""
    return (
        hasattr(sys.stdout, "isatty")
        and sys.stdout.isatty()
        and sys.platform != "win32"
    )