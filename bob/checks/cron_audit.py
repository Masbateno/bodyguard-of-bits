"""
Cron job security audit for BOB.

Checks cron entries across the system for risky patterns:
  - Commands piping remote content into a shell (curl/wget | sh/bash)
  - Scripts referenced in cron that are world-writable
  - Unexpected users with root-level crontabs

The check is split into two parts:
  1. CronAuditSnapshot.from_system() — collects raw data by reading cron files.
  2. check_cron_audit(snapshot)       — pure logic, returns a CheckResult.

Usage:
    from bob.checks.cron_audit import CronAuditSnapshot, check_cron_audit

    snapshot = CronAuditSnapshot.from_system()
    result   = check_cron_audit(snapshot)
"""

from __future__ import annotations

import re
import shlex
import stat
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t, _is_safe_config_path, pipes_into_shell
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Patterns for risky cron content
# ---------------------------------------------------------------------------

# curl/wget piped directly into a shell — common supply-chain attack vector.
# The rule lives in bob/checks/_run.py because systemd_timers needs the same
# one; it used to be written twice, with two different sets of blind spots.
_PATH_RE = re.compile(r"(/[^\s;|&<>]+\.sh)\b")

# /etc/cron.d — files in crontab format; parsed for pipe-to-shell patterns
# and referenced .sh script paths.
_CRON_FORMAT_DIRS: list[Path] = [
    Path("/etc/cron.d"),
]

# cron.daily/hourly/weekly/monthly — executable scripts, NOT crontab format.
# Scanned for pipe-to-shell patterns; files themselves checked for world-writability.
_CRON_SCRIPT_DIRS: list[Path] = [
    Path("/etc/cron.daily"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
]

# System crontab files
_SYSTEM_CRONTABS: list[Path] = [
    Path("/etc/crontab"),
]

# User crontab spool
_USER_CRONTAB_DIR = Path("/var/spool/cron/crontabs")

# Users expected to have crontabs; root is always expected
_EXPECTED_CRONTAB_USERS: frozenset[str] = frozenset({"root"})

# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class CronAuditSnapshot:
    """
    Raw snapshot of cron jobs relevant to security hardening.

    Args:
        pipe_to_shell_entries:  Lines matching curl/wget | sh patterns, with source path.
        world_writable_scripts: Script paths referenced in cron that are world-writable.
        unexpected_user_crons:  Usernames with crontabs that are not in the expected set.
        unreadable_files:       Cron files that exist but could not be opened. A
                                pipe-to-shell line in one of them is invisible
                                here, so the all-clear is withheld.
    """
    pipe_to_shell_entries:  list[str] = field(default_factory=list)
    world_writable_scripts: list[str] = field(default_factory=list)
    unexpected_user_crons:  list[str] = field(default_factory=list)
    unreadable_files:       list[str] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "CronAuditSnapshot":
        """
        Collect cron job data from the live system.

        Returns:
            Populated CronAuditSnapshot. Never raises — errors reflected as defaults.
        """
        snap = cls()

        # Lines from crontab-format files (pipe-to-shell + .sh path extraction)
        format_lines: list[tuple[str, str]] = []
        # Lines from cron.daily/etc. scripts (pipe-to-shell only)
        script_lines: list[tuple[str, str]] = []
        # The script files themselves (checked directly for world-writability)
        script_files: list[Path] = []

        # System crontab files (/etc/crontab — crontab format)
        unreadable: list[str] = []
        for crontab_path in _SYSTEM_CRONTABS:
            if not _read_cron_file(crontab_path, format_lines):
                unreadable.append(str(crontab_path))

        # /etc/cron.d — crontab format
        for cron_dir in _CRON_FORMAT_DIRS:
            if cron_dir.is_dir():
                for entry in sorted(cron_dir.iterdir()):
                    if entry.is_file() and not _read_cron_file(entry, format_lines):
                        unreadable.append(str(entry))

        # cron.daily/hourly/weekly/monthly — executable scripts
        for cron_dir in _CRON_SCRIPT_DIRS:
            if cron_dir.is_dir():
                for entry in sorted(cron_dir.iterdir()):
                    if entry.is_file():
                        if not _read_cron_file(entry, script_lines):
                            unreadable.append(str(entry))
                        script_files.append(entry)

        # Pipe-to-shell: check both format and script lines, deduplicated
        pipe_seen: set[str] = set()
        for source, line in format_lines + script_lines:
            if pipes_into_shell(line):
                entry_str = f"{source}: {line.strip()}"
                if entry_str not in pipe_seen:
                    snap.pipe_to_shell_entries.append(entry_str)
                    pipe_seen.add(entry_str)

        # World-writable: .sh paths from format lines + script files themselves
        snap.world_writable_scripts = _find_world_writable_scripts(
            format_lines, script_files
        )

        snap.unexpected_user_crons = _find_unexpected_user_crons()
        snap.unreadable_files = unreadable

        return snap

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _read_cron_file(path: Path, out: list[tuple[str, str]]) -> bool:
    """Read a cron file, append (path_str, line) tuples to out, report success.

    The return value separates "this file holds nothing suspicious" from "this
    file was never opened" — the check answers the first with an explicit
    all-clear, and must not answer the second the same way.

    Skips symlinks under user-controlled directories: an attacker with write
    access to /var/spool/cron/crontabs/ could symlink an arbitrary file (e.g.
    /etc/shadow) and have its content materialise in audit reports. See
    SECURITY.md "user-controlled config files" trust boundary.
    """
    if not _is_safe_config_path(path):
        # A deliberate security skip, not a read failure — see the docstring.
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            out.append((str(path), line))
    return True

def _find_world_writable_scripts(
    cron_lines: list[tuple[str, str]],
    script_files: list[Path] | None = None,
) -> list[str]:
    """
    Return world-writable paths: .sh scripts referenced in crontab-format lines,
    plus any executable script files in cron.daily/etc. that are world-writable.

    Limiting path extraction to .sh files avoids false positives on incidental
    paths like /tmp/file in ``echo /tmp/file | mail``.
    """
    world_writable: list[str] = []
    seen: set[str] = set()

    # Check .sh paths referenced in crontab-format lines
    for _source, line in cron_lines:
        for match in _PATH_RE.finditer(line):
            script = match.group(1)
            if script in seen:
                continue
            seen.add(script)
            p = Path(script)
            try:
                mode = p.stat().st_mode
            except OSError:
                continue
            if mode & stat.S_IWOTH:
                world_writable.append(script)

    # Check the script files themselves (cron.daily/hourly/weekly/monthly)
    for p in (script_files or []):
        script = str(p)
        if script in seen:
            continue
        seen.add(script)
        try:
            mode = p.stat().st_mode
        except OSError:
            continue
        if mode & stat.S_IWOTH:
            world_writable.append(script)

    return sorted(world_writable)

def _find_unexpected_user_crons() -> list[str]:
    """
    Return usernames that have a crontab in /var/spool/cron/crontabs
    but are not in _EXPECTED_CRONTAB_USERS.
    """
    unexpected: list[str] = []
    if not _USER_CRONTAB_DIR.is_dir():
        return unexpected
    try:
        for entry in sorted(_USER_CRONTAB_DIR.iterdir()):
            if entry.is_file() and entry.name not in _EXPECTED_CRONTAB_USERS:
                unexpected.append(entry.name)
    except OSError:
        pass
    return unexpected

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_cron_audit(snapshot: CronAuditSnapshot, *, t: TranslationFunc | None = None) -> CheckResult:
    """
    Audit cron jobs for known-risky patterns.

    Scoring:
      - curl/wget piped to shell in cron:  −2 pts (flat)
      - World-writable scripts in cron:    −1 pt  (flat)
      - Unexpected user crontabs:          INFO only, no deduction

    Args:
        snapshot: CronAuditSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()

    pipe_entries    = snapshot.pipe_to_shell_entries    or []
    writable_scripts = snapshot.world_writable_scripts  or []
    unexpected_users = snapshot.unexpected_user_crons   or []

    # --- curl/wget | shell pattern ------------------------------------------
    if pipe_entries:
        count = len(pipe_entries)
        result.warn_with_deduction(
            key="cron.pipe_to_shell",
            message=_t("cron.pipe_to_shell", count=count),
            reason=_t("cron.pipe_to_shell_reason", count=count),
            points=2,
            detail=_t("cron.pipe_to_shell_detail"),
            nature="action",
        )

    # --- World-writable scripts in cron -------------------------------------
    if writable_scripts:
        scripts = ", ".join(writable_scripts[:3])
        count   = len(writable_scripts)
        if count > 3:
            scripts += f" (+{count - 3})"
        result.warn_with_deduction(
            key="cron.world_writable",
            message=_t("cron.world_writable", count=count, scripts=scripts),
            reason=_t("cron.world_writable_reason", count=count),
            points=1,
            detail=_t("cron.world_writable_detail"),
            cmd=_chmod_cmd(writable_scripts),
            nature="action",
        )

    # --- Unexpected user crontabs (informational) ---------------------------
    if unexpected_users:
        users = ", ".join(unexpected_users)
        result.info(
            message=_t("cron.unexpected_users", users=users),
            key="cron.unexpected_users",
        )

    # --- Files that never opened --------------------------------------------
    unreadable = snapshot.unreadable_files or []
    if unreadable:
        result.info(
            message=_t("cron.unreadable_files", count=len(unreadable),
                       files=", ".join(unreadable[:3])),
            detail=_t("cron.unreadable_files_detail"),
            key="cron.unreadable_files",
        )

    # --- All clear ----------------------------------------------------------
    if not result.findings:
        result.ok(
            message=_t("cron.ok"),
            key="cron.ok",
        )

    return result

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _chmod_cmd(scripts: list[str]) -> str:
    """Build a chmod o-w command for the given script list. Returns '' for empty list."""
    if not scripts:
        return ""
    return "sudo chmod o-w " + " ".join(shlex.quote(s) for s in scripts)
