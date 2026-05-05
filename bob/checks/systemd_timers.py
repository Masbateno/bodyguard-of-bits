"""
Systemd timers security audit for BOB (CHECK 44).

Complements cron_audit.py (which only covers /etc/cron.* files) by auditing
systemd timer units for security-relevant patterns.

Patterns checked:
  - ExecStart containing curl/wget piped to a shell → WARN −2 pts (flat)
  - ExecStart referencing a world-writable .sh script → WARN −1 pt  (flat)
  - User-created timer (/etc/systemd/system/) running as root → INFO only

No network calls. Reads unit files from disk plus one systemctl list-timers call.
No overlap with cron_audit.py (which never calls systemctl list-timers).

Split into:
  1. SystemdTimersSnapshot.from_system() — discovers timer units and reads their
     associated service files.
  2. check_systemd_timers(snapshot, t)   — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import re
import shlex
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Two-part detection: downloader present AND output piped to a shell.
# Splitting avoids false negatives from path prefixes (/bin/bash, bash -c, etc.)
_DOWNLOADER_RE    = re.compile(r"\b(curl|wget)\b", re.IGNORECASE)
_PIPE_TO_SHELL_RE = re.compile(r"\|\s*(/[a-z/]*/)?(?:ba)?sh\b", re.IGNORECASE)

_EXEC_START_RE     = re.compile(r"^\s*ExecStart\s*=\s*(.+)", re.MULTILINE)
_USER_DIRECTIVE_RE = re.compile(r"^\s*User\s*=\s*\S", re.MULTILINE)
_TIMER_RE          = re.compile(r"\b(\S+\.timer)\b")
_SERVICE_RE        = re.compile(r"\b(\S+\.service)\b")
_SH_PATH_RE        = re.compile(r"(/[^\s;|&<>]+\.sh)\b")

# Search order for service unit files.
_SERVICE_DIRS: list[Path] = [
    Path("/etc/systemd/system"),
    Path("/run/systemd/system"),
    Path("/lib/systemd/system"),
    Path("/usr/lib/systemd/system"),
]

_MAX_TIMERS      = 100  # hard cap to avoid stalling on large deployments
_MAX_EXEC_LENGTH = 200  # truncate ExecStart strings in findings output


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class SystemdTimersSnapshot:
    """
    Raw snapshot of systemd timers relevant to security hardening.

    Attributes:
        pipe_to_shell_entries:    Strings "{timer}: {ExecStart}" for timers whose
                                  ExecStart contains curl/wget piped to a shell.
        world_writable_scripts:   Absolute paths to .sh scripts referenced in
                                  ExecStart that are world-writable.
        user_created_root_timers: Unit names of user-created timers (in
                                  /etc/systemd/system/) whose service runs as root
                                  (no User= directive).
        timer_count:              Total timers returned by list-timers.
        systemctl_available:      True if the systemctl binary is present.
    """
    pipe_to_shell_entries:    List[str] = field(default_factory=list)
    world_writable_scripts:   List[str] = field(default_factory=list)
    user_created_root_timers: List[str] = field(default_factory=list)
    timer_count:              int  = 0
    systemctl_available:      bool = True

    @classmethod
    def from_system(cls) -> "SystemdTimersSnapshot":
        """Discover systemd timers and check their service unit files."""
        snap = cls()
        snap.systemctl_available = _command_exists("systemctl")
        if not snap.systemctl_available:
            return snap

        timer_units = _list_timer_units()
        snap.timer_count = len(timer_units)

        pipe_seen:     set[str] = set()
        writable_seen: set[str] = set()

        for timer_name, service_name in timer_units[:_MAX_TIMERS]:
            svc_path = _find_service_file(service_name)
            if svc_path is None:
                continue

            exec_starts, has_user = _parse_service_file(svc_path)
            is_user_created = svc_path.resolve().as_posix().startswith("/etc/systemd/system/")

            for exec_start in exec_starts:
                # Pipe-to-shell detection: downloader AND shell pipe must both be present
                if _DOWNLOADER_RE.search(exec_start) and _PIPE_TO_SHELL_RE.search(exec_start):
                    trimmed = exec_start.strip()
                    if len(trimmed) > _MAX_EXEC_LENGTH:
                        trimmed = trimmed[:_MAX_EXEC_LENGTH] + "…"
                    entry = f"{timer_name}: {trimmed}"
                    if entry not in pipe_seen:
                        snap.pipe_to_shell_entries.append(entry)
                        pipe_seen.add(entry)

                # World-writable .sh scripts
                for script in _SH_PATH_RE.findall(exec_start):
                    if script not in writable_seen and _is_world_writable(script):
                        snap.world_writable_scripts.append(script)
                        writable_seen.add(script)

            # User-created timer running as root (no User= directive)
            if is_user_created and not has_user and exec_starts:
                snap.user_created_root_timers.append(timer_name)

        return snap


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_systemd_timers(snapshot: SystemdTimersSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Audit systemd timers for security-relevant patterns.

    Scoring:
      - curl/wget piped to shell in ExecStart:  WARN −2 pts (flat)
      - World-writable .sh script in ExecStart: WARN −1 pt  (flat)
      - User-created timer running as root:     INFO only

    Args:
        snapshot: SystemdTimersSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.systemctl_available:
        result.info(
            message=_t("systemd_timers.no_systemctl"),
            key="systemd_timers.no_systemctl",
        )
        return result

    if snapshot.timer_count == 0:
        result.info(
            message=_t("systemd_timers.no_timers"),
            key="systemd_timers.no_timers",
        )
        return result

    # --- curl/wget | shell ---------------------------------------------------
    pipe_entries = snapshot.pipe_to_shell_entries or []
    if pipe_entries:
        count   = len(pipe_entries)
        entries = "; ".join(pipe_entries[:3])
        if count > 3:
            entries += f" (+{count - 3})"
        result.warn(
            message=_t("systemd_timers.pipe_to_shell", count=count),
            detail=_t("systemd_timers.pipe_to_shell_detail", entries=entries),
            nature="action",
            key="systemd_timers.pipe_to_shell",
        )
        result.add_deduction(
            reason=_t("systemd_timers.pipe_to_shell_reason", count=count),
            points=2,
            context="local",
            key="systemd_timers.pipe_to_shell",
        )

    # --- World-writable scripts ----------------------------------------------
    writable = snapshot.world_writable_scripts or []
    if writable:
        scripts = ", ".join(writable[:3])
        count   = len(writable)
        if count > 3:
            scripts += f" (+{count - 3})"
        result.warn(
            message=_t("systemd_timers.world_writable", count=count, scripts=scripts),
            detail=_t("systemd_timers.world_writable_detail"),
            cmd=_chmod_cmd(writable),
            nature="action",
            key="systemd_timers.world_writable",
        )
        result.add_deduction(
            reason=_t("systemd_timers.world_writable_reason", count=count),
            points=1,
            context="local",
            key="systemd_timers.world_writable",
        )

    # --- User-created timers running as root (informational) -----------------
    root_timers = snapshot.user_created_root_timers or []
    if root_timers:
        units = ", ".join(root_timers[:5])
        count = len(root_timers)
        if count > 5:
            units += f" (+{count - 5})"
        result.info(
            message=_t("systemd_timers.user_created_root", count=count, units=units),
            key="systemd_timers.user_created_root",
        )

    # --- All clear -----------------------------------------------------------
    if not result.findings:
        result.ok(
            message=_t("systemd_timers.ok", count=snapshot.timer_count),
            key="systemd_timers.ok",
        )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _list_timer_units() -> list[tuple[str, str]]:
    """
    Return (timer_unit, service_unit) pairs from systemctl list-timers.

    The ACTIVATES column is used when present; otherwise the service name is
    derived by replacing .timer with .service.
    """
    out = _run("systemctl", "list-timers", "--all", "--no-pager") or ""
    result: list[tuple[str, str]] = []
    seen: set[str] = set()

    for line in out.splitlines():
        m_timer = _TIMER_RE.search(line)
        if not m_timer:
            continue
        timer = m_timer.group(1)
        if timer in seen:
            continue
        seen.add(timer)
        services = _SERVICE_RE.findall(line)
        service = services[-1] if services else timer.replace(".timer", ".service")
        result.append((timer, service))

    return result


def _find_service_file(service: str) -> Path | None:
    """Return the first existing service unit file path, or None."""
    for d in _SERVICE_DIRS:
        p = d / service
        if p.exists():
            return p
    return None


def _parse_service_file(path: Path) -> tuple[list[str], bool]:
    """
    Read a service unit file and return (exec_starts, has_user_directive).

    exec_starts: list of ExecStart= values (stripped).
    has_user_directive: True if a non-empty User= line is present.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return [], False
    exec_starts = [m.group(1).strip().lstrip("-@") for m in _EXEC_START_RE.finditer(text)]
    has_user    = bool(_USER_DIRECTIVE_RE.search(text))
    return exec_starts, has_user


def _is_world_writable(path_str: str) -> bool:
    """Return True if the path exists and has the world-writable bit set."""
    try:
        return bool(Path(path_str).stat().st_mode & stat.S_IWOTH)
    except OSError:
        return False


def _chmod_cmd(scripts: list[str]) -> str:
    """Return a chmod o-w command for the given script list."""
    paths = " ".join(shlex.quote(s) for s in scripts[:5])
    return f"sudo chmod o-w {paths}"
