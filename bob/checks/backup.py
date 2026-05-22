"""
Backup solution audit for BOB (CHECK 35).

Detects whether a backup solution is installed and shows evidence of being
configured or actively used.  Detection is based on binary presence and
verifiable artefacts (config files, systemd service state) — not on running
the backup tool itself.

Two confidence levels are distinguished:

  active    — binary present AND at least one configuration artefact or
               running service found.  High confidence that backups are
               happening.

  installed — binary present but no configuration artefact detected.
               The tool may be installed but not yet set up.

Score impact (profile-aware):
  - At least one active solution:   OK
  - Tool(s) installed only:         INFO  (no deduction — may be configured
                                          in a way we cannot detect)
  - No backup tool found at all:    WARN  −1 pt  (server)
                                    INFO   0 pt  (desktop)

Container: section skipped in runner.py — containers do not manage their own
backups; backup is an orchestrator/host concern.

The check is split into two parts:
  1. BackupSnapshot.from_system() — collects raw data.
  2. check_backup(snapshot)        — pure logic, returns a CheckResult.

Usage:
    from bob.checks.backup import BackupSnapshot, check_backup

    snapshot = BackupSnapshot.from_system()
    result   = check_backup(snapshot, profile_name="server")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from bob.checks._run import _command_exists, _identity_t, _run, is_unit_active
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Config artefact paths (checked for root-run backups; no user enumeration)
# ---------------------------------------------------------------------------

# borgmatic
_BORGMATIC_CONFIGS: tuple[Path, ...] = (
    Path("/etc/borgmatic/config.yaml"),
    Path("/etc/borgmatic.d"),
    Path("/root/.config/borgmatic/config.yaml"),
    Path("/root/.borgmatic.yaml"),
)

# borg (repository key directory — non-empty means at least one repo initialised)
_BORG_KEYS_DIR = Path("/root/.config/borg/keys")

# timeshift
_TIMESHIFT_CONFIG = Path("/etc/timeshift/timeshift.json")

# rclone
_RCLONE_CONFIGS: tuple[Path, ...] = (
    Path("/root/.config/rclone/rclone.conf"),
    Path("/etc/rclone/rclone.conf"),
)

# tarsnap
_TARSNAP_CONFIGS: tuple[Path, ...] = (
    Path("/etc/tarsnap.conf"),
    Path("/root/.tarsnap.conf"),
)


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class BackupSnapshot:
    """
    Raw snapshot of backup solution state.

    Args:
        active_tools:    Tools confirmed active: binary present + config/service found.
        installed_tools: Tools installed but without detectable configuration.
    """
    active_tools:    List[str] = field(default_factory=list)
    installed_tools: List[str] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "BackupSnapshot":
        """
        Detect installed and configured backup solutions.

        Returns:
            Populated BackupSnapshot. Never raises — errors reflected as defaults.
        """
        snap = cls()

        # --- borgmatic (borg wrapper with explicit config) -------------------
        if _command_exists("borgmatic"):
            if any(_borgmatic_config_exists(p) for p in _BORGMATIC_CONFIGS):
                snap.active_tools.append("borgmatic")
            else:
                snap.installed_tools.append("borgmatic")

        # --- borg (standalone) -----------------------------------------------
        # Checked independently of borgmatic: borgmatic wraps borg, but if
        # borgmatic has no config, borg itself may still be configured.
        # Skip borg when borgmatic is already confirmed active (implied coverage).
        if _command_exists("borg") and "borgmatic" not in snap.active_tools:
            if _BORG_KEYS_DIR.is_dir() and any(_BORG_KEYS_DIR.iterdir()):
                snap.active_tools.append("borg")
            else:
                snap.installed_tools.append("borg")

        # --- restic -----------------------------------------------------------
        if _command_exists("restic"):
            # restic repos have no fixed location — treat as installed only
            snap.installed_tools.append("restic")

        # --- timeshift --------------------------------------------------------
        if _command_exists("timeshift"):
            if _TIMESHIFT_CONFIG.is_file():
                snap.active_tools.append("timeshift")
            else:
                snap.installed_tools.append("timeshift")

        # --- duplicati --------------------------------------------------------
        duplicati_bin = _command_exists("duplicati-cli") or _command_exists("duplicati")
        if duplicati_bin:
            if _service_active("duplicati"):
                snap.active_tools.append("duplicati")
            else:
                snap.installed_tools.append("duplicati")

        # --- bacula -----------------------------------------------------------
        if _command_exists("bacula-fd"):
            if _service_active("bacula-fd"):
                snap.active_tools.append("bacula")
            else:
                snap.installed_tools.append("bacula")

        # --- rclone -----------------------------------------------------------
        if _command_exists("rclone"):
            if any(p.is_file() for p in _RCLONE_CONFIGS):
                snap.active_tools.append("rclone")
            else:
                snap.installed_tools.append("rclone")

        # --- tarsnap ----------------------------------------------------------
        if _command_exists("tarsnap"):
            if any(p.is_file() for p in _TARSNAP_CONFIGS):
                snap.active_tools.append("tarsnap")
            else:
                snap.installed_tools.append("tarsnap")

        # --- deja-dup (GNOME Backups) -----------------------------------------
        if _command_exists("deja-dup"):
            snap.installed_tools.append("deja-dup")

        # Deduplicate — preserve insertion order (dict.fromkeys idiom)
        snap.active_tools    = list(dict.fromkeys(snap.active_tools))
        snap.installed_tools = list(dict.fromkeys(snap.installed_tools))

        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_backup(
    snapshot: BackupSnapshot,
    *,
    t=None,
    profile_name: str = "server",
) -> CheckResult:
    """
    Audit backup solution presence and configuration.

    Scoring:
      - active_tools non-empty:   OK
      - installed_tools only:     INFO (no deduction)
      - nothing found, server:    WARN  −1 pt
      - nothing found, desktop:   INFO   0 pt

    Args:
        snapshot:     BackupSnapshot from the system (or built in tests).
        t:            Translation function. Defaults to key pass-through.
        profile_name: "server" | "desktop".

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()

    active    = snapshot.active_tools    or []
    installed = snapshot.installed_tools or []

    # --- At least one active solution found ---------------------------------
    if active:
        tools_str = ", ".join(sorted(active))
        result.ok(
            message=_t("backup.active", tools=tools_str),
            key="backup.active",
        )
        also = sorted(t for t in installed if t not in active)
        if also:
            result.info(
                message=_t("backup.also_installed", tools=", ".join(also)),
                key="backup.also_installed",
            )
        return result

    # --- Tool(s) installed but not confirmed active -------------------------
    if installed:
        tools_str = ", ".join(sorted(installed))
        result.info(
            message=_t("backup.installed_only", tools=tools_str),
            detail=_t("backup.installed_only_detail"),
            key="backup.installed_only",
        )
        return result

    # --- No backup tool found -----------------------------------------------
    if profile_name == "server":
        result.warn_with_deduction(
            key="backup.no_backup",
            message=_t("backup.no_backup"),
            reason=_t("backup.no_backup_reason"),
            points=1,
            detail=_t("backup.no_backup_detail"),
            cmd="sudo apt install borgbackup borgmatic",
        )
    else:
        result.info(
            message=_t("backup.no_backup"),
            detail=_t("backup.no_backup_detail"),
            cmd="sudo apt install borgbackup borgmatic",
            key="backup.no_backup",
        )

    return result


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _borgmatic_config_exists(path: Path) -> bool:
    """Return True if path is a non-empty directory or an existing file."""
    if path.is_file():
        return True
    if path.is_dir():
        return any(path.iterdir())
    return False


def _service_active(service: str) -> bool:
    """Return True if the given systemd service is active. Never raises."""
    if not _command_exists("systemctl"):
        return False
    return is_unit_active(service)
