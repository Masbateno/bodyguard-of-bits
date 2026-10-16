"""
ClamAV antivirus audit check for BOB.

Analyses:
  - ClamAV installation (clamscan / clamdscan)
  - Virus database freshness (daily.cld / daily.cvd mtime)
  - ClamAV daemon status (clamav-daemon / clamd)
  - Last scan date (parsed from standard log paths)

Score impact: deductions route to the "hardening" domain.

Usage:
    from bob.checks.clamav import ClamAVSnapshot, check_clamav

    snapshot = ClamAVSnapshot.from_system()
    result   = check_clamav(snapshot)
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from bob._atomic import read_text_capped
from bob.checks._run import TranslationFunc, install_fix, _command_exists, _identity_t, _run, is_unit_active, openrc_available, path_exists, service_enable_cmd, unit_active_state  # noqa: F401 — `_run` kept in the module namespace as a monkeypatch seam (tests do setattr(module, "_run", ...))
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Virus database files — checked in order of preference (daily > main)
_DB_CANDIDATES: list[Path] = [
    Path("/var/lib/clamav/daily.cld"),
    Path("/var/lib/clamav/daily.cvd"),
    Path("/var/lib/clamav/main.cld"),
    Path("/var/lib/clamav/main.cvd"),
]

# Standard log file paths where scan summaries may be written
_SCAN_LOG_CANDIDATES: list[Path] = [
    Path("/var/log/clamav/clamdscan.log"),
    Path("/var/log/clamav/clamscan.log"),
    Path("/var/log/clamav/scan.log"),
    Path("/var/log/clamav/clamav.log"),
]

# "End Date:   2026:04:10 15:30:06"  or  "End Date: 2026:04:10 15:30:06"
_END_DATE_RE = re.compile(
    r"(?i)End Date:\s+(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})"
)

# Database age thresholds (days)
_DB_WARN_DAYS:  int = 7
_DB_ALERT_DAYS: int = 30

# Scan age threshold (days)
_SCAN_WARN_DAYS:  int = 30
_SCAN_ALERT_DAYS: int = 90

# Lines to read from the end of each log file (performance guard)
_LOG_TAIL_LINES: int = 500

# Unix socket paths created by clamd when running (used as fallback when
# systemctl is unavailable, e.g. inside containers)
_CLAMD_SOCKETS: list[Path] = [
    Path("/run/clamav/clamd.ctl"),
    Path("/var/run/clamav/clamd.ctl"),
]

#: v0.24.4 — the daemon unit each family ships, measured by installing its
#: daemon package: Debian 13, Ubuntu 24.04 and Arch ``clamav-daemon.service``;
#: Fedora ``clamd@.service`` (a template, run as ``clamd@scan``); openSUSE
#: Tumbleweed ``clamd.service``. Alpine's OpenRC script is ``clamd``. The fix
#: used to name ``clamav-daemon`` everywhere.
_CLAMD_UNITS: tuple = (
    ("clamav-daemon", "clamav-daemon.service"),
    ("clamd@scan", "clamd@.service"),
    ("clamd", "clamd.service"),
)
_UNIT_DIRS: tuple = ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")
#: Fedora's ``clamd@scan`` reads this file, which ships with every socket
#: commented out: measured on Fedora 44, ``systemctl enable --now clamd@scan``
#: failed with "Please define server type (local and/or TCP)".
_SCAN_CONF = Path("/etc/clamd.d/scan.conf")
_SCAN_SOCKET = "/run/clamd.scan/clamd.sock"
#: v0.24.4 — where each family's clamd reads its ``LocalSocket``.
_CLAMD_CONFS: tuple = (Path("/etc/clamav/clamd.conf"), Path("/etc/clamd.conf"), _SCAN_CONF)
_LOCAL_SOCKET_RE = re.compile(r"^\s*LocalSocket\s+(\S+)", re.MULTILINE)

# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class ClamAVSnapshot:
    """
    Raw snapshot of ClamAV installation and runtime state.

    All file I/O and subprocess calls happen in from_system().
    check_clamav() operates on this snapshot only (pure logic).
    """
    installed:            bool           = False  # clamscan or clamdscan found
    freshclam_installed:  bool           = False  # freshclam found
    clamd_active:         bool           = False  # clamav-daemon service running
    db_age_days:          int | None  = None   # None = no DB file found
    last_scan_date:       str | None  = None   # ISO date string or None
    # v0.17.0: no longer a Debian command frozen into a default. It reached the
    # screen through ``cmd=snapshot.install_cmd``, so neither the sweep over
    # ``cmd="…"`` literals nor the guard over them saw it, and a Fedora audit
    # kept printing `sudo apt install -y clamav clamav-daemon` after every other
    # finding had been made portable.
    install_cmd:          "str | None"   = None
    #: v0.24.4 — the daemon unit this host ships ("" when none).
    clamd_unit:           str            = ""
    #: Fedora's scan.conf defines no socket, so clamd@scan cannot start yet.
    clamd_needs_socket:   bool           = False
    #: v0.24.4 — clamd's local socket when every local user can connect to it
    #: ("" when not, or when that could not be established).
    clamd_socket_open:    str            = ""

    @classmethod
    def from_system(cls) -> "ClamAVSnapshot":
        snap = cls()

        # --- detect installation ---
        snap.installed = (
            _command_exists("clamscan")
            or _command_exists("clamdscan")
            or _command_exists("freshclam")
        )
        snap.freshclam_installed = _command_exists("freshclam")

        if not snap.installed:
            return snap

        snap.clamd_unit = _clamd_unit()
        if snap.clamd_unit == "clamd@scan":
            snap.clamd_needs_socket = _scan_conf_lacks_socket()

        # --- clamd service status ---
        if _command_exists("systemctl"):
            for unit in ("clamav-daemon", "clamd", "clamd@scan"):
                if is_unit_active(unit):
                    snap.clamd_active = True
                    break
        elif snap.clamd_unit:
            # v0.24.4 — OpenRC (Alpine): asked through the host's init.
            snap.clamd_active = unit_active_state(snap.clamd_unit) == "active"
        # Fallback: check for the clamd Unix socket (present when daemon is running
        # even if systemctl is unavailable, e.g. inside containers). v0.24.4: the
        # sockets the configuration names too — Alpine's is clamd.sock, and a
        # running clamd there was reported "not running".
        if not snap.clamd_active:
            for socket_path in [*_CLAMD_SOCKETS, *map(Path, _configured_sockets())]:
                if path_exists(socket_path):
                    snap.clamd_active = True
                    break

        if snap.clamd_active:
            snap.clamd_socket_open = _socket_open_to_all()

        # --- virus database freshness ---
        for db_path in _DB_CANDIDATES:
            if path_exists(db_path):
                try:
                    mtime_dt = datetime.fromtimestamp(
                        db_path.stat().st_mtime, tz=timezone.utc
                    )
                    snap.db_age_days = max(
                        0, (datetime.now(timezone.utc) - mtime_dt).days
                    )
                except OSError:
                    pass
                break

        # --- last scan date from logs ---
        snap.last_scan_date = _find_last_scan_date()

        return snap

# ---------------------------------------------------------------------------
# Main check function (pure logic — no I/O)
# ---------------------------------------------------------------------------

def check_clamav(snapshot: ClamAVSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Check ClamAV antivirus installation and configuration.

    Args:
        snapshot: ClamAVSnapshot collected from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- Not installed ---
    if not snapshot.installed:
        _cmd, _detail = install_fix(
            _t, _t("clamav.not_installed_detail"), "clamav", "clamav-daemon")
        result.info(
            message=_t("clamav.not_installed"),
            detail=_detail,
            cmd=snapshot.install_cmd or _cmd,
            key="clamav.not_installed",
        )
        return result

    # --- Installed ---
    result.ok(message=_t("clamav.installed"), key="clamav.installed")

    # --- freshclam ---
    if not snapshot.freshclam_installed:
        _cmd, _detail = install_fix(
            _t, _t("clamav.freshclam_missing_detail"), "clamav")
        result.warn_with_deduction(
            key="clamav.freshclam_missing",
            message=_t("clamav.freshclam_missing"),
            points=1,
            detail=_detail,
            cmd=_cmd,
            nature="action",
        )

    # --- Virus database ---
    if snapshot.db_age_days is None:
        result.warn_with_deduction(
            key="clamav.db_not_found",
            message=_t("clamav.db_not_found"),
            points=1,
            detail=_t("clamav.db_not_found_detail"),
            cmd="sudo freshclam",
            nature="action",
        )
    elif snapshot.db_age_days >= _DB_ALERT_DAYS:
        result.alert_with_deduction(
            key="clamav.db_very_outdated",
            message=_t("clamav.db_very_outdated", days=snapshot.db_age_days),
            points=1,
            nature="improvement",
            detail=_t("clamav.db_very_outdated_detail"),
            cmd="sudo freshclam",
        )
    elif snapshot.db_age_days >= _DB_WARN_DAYS:
        result.warn_with_deduction(
            key="clamav.db_outdated",
            message=_t("clamav.db_outdated", days=snapshot.db_age_days),
            points=1,
            detail=_t("clamav.db_outdated_detail"),
            cmd="sudo freshclam",
            nature="improvement",
        )
    else:
        result.ok(
            message=_t("clamav.db_ok", days=snapshot.db_age_days),
            key="clamav.db_ok",
        )

    # --- clamd daemon ---
    if not snapshot.clamd_active:
        result.info(
            message=_t("clamav.clamd_inactive", unit=snapshot.clamd_unit or "clamd"),
            detail=_t("clamav.clamd_inactive_detail"),
            cmd=_clamd_enable_cmd(snapshot),
            key="clamav.clamd_inactive",
        )
    elif snapshot.clamd_socket_open:
        # No command: who must keep access (a mail filter's user, a scanner's)
        # is the operator's to say; a group-only socket cuts everyone else.
        # v0.25.0: scored. Measured in 0.24.4 — Alpine and Debian as packaged,
        # an unprivileged user sent SHUTDOWN and clamd stopped: any process
        # running as any local account can turn the antivirus off.
        result.warn_with_deduction(
            key="clamav.socket_open_to_all",
            message=_t("clamav.socket_open_to_all", path=snapshot.clamd_socket_open),
            reason=_t("clamav.socket_open_to_all_reason"),
            points=1,
            detail=_t("clamav.socket_open_to_all_detail"),
            nature="action",
            template_vars={"path": snapshot.clamd_socket_open},
        )

    # --- Last scan ---
    if snapshot.last_scan_date is None:
        result.info(
            message=_t("clamav.no_scan_log"),
            detail=_t("clamav.no_scan_log_detail"),
            cmd="sudo clamscan -r /home --infected --log=/var/log/clamav/clamscan.log",
            key="clamav.no_scan_log",
        )
    else:
        scan_age_days = _scan_age_days(snapshot.last_scan_date)
        if scan_age_days is not None and scan_age_days >= _SCAN_ALERT_DAYS:
            result.warn_with_deduction(
                key="clamav.scan_very_old",
                message=_t("clamav.scan_very_old", days=scan_age_days, date=snapshot.last_scan_date),
                points=1,
                detail=_t("clamav.scan_very_old_detail"),
                cmd="sudo clamscan -r /home --infected --log=/var/log/clamav/clamscan.log",
                nature="improvement",
            )
        elif scan_age_days is not None and scan_age_days >= _SCAN_WARN_DAYS:
            result.warn_with_deduction(
                key="clamav.scan_old",
                message=_t("clamav.scan_old", days=scan_age_days, date=snapshot.last_scan_date),
                points=1,
                detail=_t("clamav.scan_old_detail"),
                cmd="sudo clamscan -r /home --infected --log=/var/log/clamav/clamscan.log",
                nature="improvement",
            )
        else:
            result.ok(
                message=_t("clamav.scan_recent", date=snapshot.last_scan_date),
                key="clamav.scan_recent",
            )

    return result

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_last_scan_date() -> str | None:
    """
    Search standard ClamAV log paths for the most recent scan 'End Date:'.

    Returns:
        ISO date string (YYYY-MM-DD) of the most recent scan found across
        all candidate log paths, or None if no scan log line was found.
    """
    latest_dt: datetime | None = None

    for log_path in _SCAN_LOG_CANDIDATES:
        if not path_exists(log_path):
            continue
        try:
            lines = _tail_lines(log_path, _LOG_TAIL_LINES)
        except OSError:
            continue

        for line in lines:
            m = _END_DATE_RE.search(line)
            if not m:
                continue
            try:
                # ClamAV logs timestamps in local time — keep naive for comparison.
                dt = datetime(
                    int(m.group(1)), int(m.group(2)), int(m.group(3)),
                    int(m.group(4)), int(m.group(5)), int(m.group(6)),
                )
            except ValueError:
                continue
            if latest_dt is None or dt > latest_dt:
                latest_dt = dt

    if latest_dt is None:
        return None
    return latest_dt.strftime("%Y-%m-%d")

def _tail_lines(path: Path, n: int) -> list[str]:
    """Return the last n lines of a text file efficiently."""
    with path.open("rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        if size == 0:
            return []
        # Read progressively larger chunks from the end
        chunk = min(size, n * 120)  # rough estimate: 120 chars/line
        fh.seek(max(0, size - chunk))
        data = fh.read()
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[-n:]

def _scan_age_days(iso_date: str) -> int | None:
    """Return the number of days since iso_date (YYYY-MM-DD), or None on error.

    Uses naive local time to match ClamAV log timestamps.
    """
    try:
        dt = datetime.strptime(iso_date, "%Y-%m-%d")
        return max(0, (datetime.now() - dt).days)
    except ValueError:
        return None


def _clamd_unit() -> str:
    """The clamd unit this host ships, or "" when it ships none."""
    if openrc_available() and not _command_exists("systemctl"):
        return "clamd" if path_exists(Path("/etc/init.d/clamd")) else ""
    for unit, unit_file in _CLAMD_UNITS:
        if any(path_exists(Path(d) / unit_file) for d in _UNIT_DIRS):
            return unit
    return ""


def _scan_conf_lacks_socket() -> bool:
    """True when Fedora's scan.conf defines neither a local nor a TCP socket.
    An unreadable file is not evidence either way: False."""
    try:
        text = read_text_capped(_SCAN_CONF)
    except (OSError, ValueError):
        return False
    return re.search(r"^\s*(LocalSocket|TCPSocket)\s", text, re.MULTILINE) is None


def _clamd_enable_cmd(snapshot: "ClamAVSnapshot") -> "str | None":
    """Start the daemon this host actually ships (v0.24.4), with what it needs
    first: on Fedora the socket its scan.conf leaves commented out, and on any
    host a signature database (clamd refuses to start without one). Measured
    on Fedora 44: this sequence left clamd@scan active with its socket. No unit
    shipped: no command — the daemon package is not installed."""
    if not snapshot.clamd_unit:
        return None
    steps = []
    if snapshot.clamd_needs_socket:
        sock = _SCAN_SOCKET.replace("/", "\\/")
        steps.append(f"sudo sed -i '0,/^#LocalSocket {sock}$/s//LocalSocket {sock}/' {_SCAN_CONF}")
    if snapshot.db_age_days is None and snapshot.freshclam_installed:
        steps.append("sudo freshclam")
    steps.append(service_enable_cmd(snapshot.clamd_unit))
    return " && ".join(steps)


def _open_to_others(path: str) -> "bool | None":
    """Whether a user outside clamd's owner and group can connect to the
    socket at *path*: write permission on it, search permission on every
    directory above it. None when it is not a socket or cannot be read.

    Measured (v0.24.4): Alpine's packaged config leaves ``LocalSocketMode``
    commented (``srw-rw-rw-`` under a ``0755`` /run/clamav), Debian sets 666 —
    an unprivileged user sent SHUTDOWN and clamd stopped on both. Fedora's
    ``0666`` socket sits in a ``0710`` directory: refused.
    """
    try:
        st = os.stat(path)
        if not stat.S_ISSOCK(st.st_mode):
            return None
        if not st.st_mode & stat.S_IWOTH:
            return False
        parent = os.path.dirname(os.path.abspath(path))
        while True:
            if not os.stat(parent).st_mode & stat.S_IXOTH:
                return False
            if parent == "/":
                return True
            parent = os.path.dirname(parent)
    except OSError:
        return None


def _configured_sockets() -> "list[str]":
    """The ``LocalSocket`` paths clamd's configuration files name."""
    paths: list = []
    for conf in _CLAMD_CONFS:
        try:
            paths += _LOCAL_SOCKET_RE.findall(read_text_capped(conf))
        except (OSError, ValueError):
            continue
    return paths


def _socket_open_to_all() -> str:
    """The first configured clamd socket every local user can connect to."""
    for path in _configured_sockets():
        if _open_to_others(path):
            return path
    return ""
