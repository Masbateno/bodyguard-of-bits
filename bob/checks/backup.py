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

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import _command_exists, install_fix, _identity_t, _run, is_unit_active  # noqa: F401 — `_run` kept in the module namespace as a monkeypatch seam (tests do setattr(module, "_run", ...))
from bob.scoring import CheckResult
from bob._atomic import read_text_capped
from bob._fs import strict_is_dir, strict_is_file

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
#: v0.31.4 — what Timeshift's own files say, read without running or mounting
#: anything: its schedules (timeshift.json), and, in rsync mode, the snapshot
#: directories at <backup device>/timeshift/snapshots when that device is
#: mounted. Measured on Linux Mint 22.3 (timeshift 25.12.4, 9 November 2026):
#: weekly schedule, device mounted at /home, /home/timeshift/snapshots holding
#: 2026-11-01_19-00-01 and 2026-11-08_19-00-02.
_TIMESHIFT_SCHEDULES = ("hourly", "daily", "weekly", "monthly", "boot")
_TIMESHIFT_SNAPSHOT_RE = re.compile(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}")
_DISK_BY_UUID = Path("/dev/disk/by-uuid")
_MOUNTINFO = Path("/proc/self/mountinfo")

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
# Evidence that does not depend on a binary being on PATH
# ---------------------------------------------------------------------------
#
# Every branch below used to sit behind `_command_exists`, so the artefacts were
# only ever consulted once the binary had been found. That inverts the evidence
# hierarchy: a configuration file is a *stronger* statement that backups are
# configured than a name on PATH. Reproduced on the bench — this host carries
# both /etc/timeshift/timeshift.json (a path this module already holds as a
# constant) and /etc/cron.d/timeshift-hourly, and with the binary off PATH the
# audit still reported "No backup solution installed or configured", −1 point.
# A tool in /opt, installed via snap or flatpak, or a PATH without /usr/sbin
# reaches the same place on a real host.
_ARTEFACTS_WITHOUT_BINARY: tuple[tuple[str, tuple[Path, ...]], ...] = (
    ("borgmatic", _BORGMATIC_CONFIGS),
    ("borg",      (_BORG_KEYS_DIR,)),
    ("timeshift", (_TIMESHIFT_CONFIG,)),
    ("rclone",    _RCLONE_CONFIGS),
    ("tarsnap",   _TARSNAP_CONFIGS),
)

# Backup tools named in a scheduled job. Deliberately a list of binary names
# rather than a fuzzy match: bare `rsync` and "anything whose unit is called
# *backup*" would both turn an ordinary mirror or a stale unit into "backups
# are happening", and a false clean bill of health is the dangerous half of
# this fix. Names outside the nine the module can install are the point —
# rsnapshot, duplicity, snapper and btrbk are ordinary Debian packages.
_SCHEDULED_TOOL_NAMES: frozenset[str] = frozenset({
    "amanda", "backupninja", "bacula-fd", "borg", "borgmatic", "btrbk", "bup",
    "deja-dup", "dirvish", "duplicacy", "duplicati", "duplicati-cli",
    "duplicity", "kopia", "proxmox-backup-client", "rdiff-backup", "rclone",
    "restic", "rsnapshot", "snapper", "tarsnap", "timeshift",
    "urbackupclientctl", "veeamconfig",
})

_SCHEDULE_DIRS: tuple[Path, ...] = (
    Path("/etc/cron.d"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
    Path("/etc/systemd/system"),
)

_SCHEDULE_FILES: tuple[Path, ...] = (
    Path("/etc/crontab"),
)

_MAX_SCHEDULE_FILES = 400   # a directory that has run away is not evidence


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
        evidence_without_tool: Artefacts or scheduled jobs pointing at a backup
                         tool that is not on PATH. Never upgrades the verdict to
                         "backups are fine" — it only withdraws the claim that
                         none is configured.
    """
    active_tools:    list[str] = field(default_factory=list)
    installed_tools: list[str] = field(default_factory=list)
    # Evidence that backups happen, found without any known binary on PATH:
    # a configuration artefact, or a scheduled job invoking a backup tool.
    # Each entry is human-readable and names its own source.
    evidence_without_tool: list[str] = field(default_factory=list)
    #: v0.31.4 — Timeshift as its files describe it (``_read_timeshift``).
    #: schedules: the schedule_* keys set to true, None when timeshift.json
    #: could not be read as JSON. snapshots: the snapshot directory names, None
    #: when they were not read — ``timeshift_unread`` says why. dir: where
    #: they were read.
    timeshift_schedules: "list[str] | None" = None
    timeshift_snapshots: "list[str] | None" = None
    timeshift_unread:    str = ""
    timeshift_dir:       str = ""
    #: v0.32.0 — timeshift.json's `exclude` patterns: paths no snapshot holds
    #: (on a desktop, often the home). Shown so "active" is not read as "my
    #: files are backed up". [] when none or unread.
    timeshift_excludes:  list = field(default_factory=list)

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
            # A denied keys dir is not an empty one: up to 3.13 `is_dir()` raised
            # here and the whole snapshot crashed (from_system must not); on 3.14
            # it answers False and borg fell silently to "installed". Either way
            # the honest verdict when the dir cannot be read is "installed" —
            # borg is present, its configuration could not be confirmed — never
            # "active", which would assert backups are in place.
            try:
                borg_active = strict_is_dir(_BORG_KEYS_DIR) and any(_BORG_KEYS_DIR.iterdir())
            except OSError:
                borg_active = False
            if borg_active:
                snap.active_tools.append("borg")
            else:
                snap.installed_tools.append("borg")

        # --- restic -----------------------------------------------------------
        if _command_exists("restic"):
            # restic repos have no fixed location — treat as installed only
            snap.installed_tools.append("restic")

        # --- timeshift --------------------------------------------------------
        # v0.31.4 — the config file alone said "active". It now takes a
        # schedule that is on, and no readable snapshot directory that is empty.
        if _command_exists("timeshift"):
            if _TIMESHIFT_CONFIG.is_file():
                (snap.timeshift_schedules, snap.timeshift_snapshots,
                 snap.timeshift_unread, snap.timeshift_dir) = _read_timeshift()
                snap.timeshift_excludes = _timeshift_excludes()
            if snap.timeshift_schedules and snap.timeshift_snapshots != []:
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

        # Only worth collecting when nothing was found the ordinary way: this
        # evidence withdraws a claim, it never strengthens one.
        if not snap.active_tools and not snap.installed_tools:
            snap.evidence_without_tool = list(dict.fromkeys(
                _artefact_evidence() + _scheduled_evidence()
            ))

        return snap

# ---------------------------------------------------------------------------
# Timeshift
# ---------------------------------------------------------------------------

def _read_timeshift() -> "tuple[list[str] | None, list[str] | None, str, str]":
    """v0.31.4 — (schedules, snapshots, why unread, directory) from Timeshift's
    files. Nothing is run and nothing is mounted: a backup device that is not
    mounted leaves the snapshots unread, and says so."""
    try:
        cfg = json.loads(read_text_capped(_TIMESHIFT_CONFIG, encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None, None, "config", ""
    if not isinstance(cfg, dict):
        return None, None, "config", ""
    schedules = [name for name in _TIMESHIFT_SCHEDULES
                 if str(cfg.get(f"schedule_{name}", "")).lower() == "true"]
    if str(cfg.get("btrfs_mode", "")).lower() == "true":
        return schedules, None, "btrfs", ""
    uuid = str(cfg.get("backup_device_uuid", "") or "")
    if not uuid or "/" in uuid:
        return schedules, None, "no_device", ""
    try:
        device = os.path.realpath(_DISK_BY_UUID / uuid, strict=True)
    except OSError:
        return schedules, None, "device_absent", uuid
    mountpoint = _mounted_at(device)
    if mountpoint is None:
        return schedules, None, "not_mounted", device
    directory = os.path.join(mountpoint, "timeshift", "snapshots")
    try:
        with os.scandir(directory) as entries:
            names = sorted(e.name for e in entries
                           if _TIMESHIFT_SNAPSHOT_RE.fullmatch(e.name) and e.is_dir(follow_symlinks=False))
    except FileNotFoundError:
        # Timeshift creates the directory with its first snapshot (measured on
        # Ubuntu 26.04: absent on a fresh device, present after --create).
        return schedules, [], "", directory
    except OSError:
        return schedules, None, "unreadable", directory
    return schedules, names, "", directory


def _timeshift_excludes() -> list:
    """v0.32.0 — the `exclude` patterns of timeshift.json: every path they
    match is in no snapshot (measured on Linux Mint 22.3: the home excluded
    while backup.active said "solution active"). [] when unread or not a
    list of strings."""
    try:
        cfg = json.loads(read_text_capped(_TIMESHIFT_CONFIG, encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return []
    excludes = cfg.get("exclude") if isinstance(cfg, dict) else None
    if not isinstance(excludes, list):
        return []
    return [x for x in excludes if isinstance(x, str) and x]


def _mounted_at(device: str) -> "str | None":
    """Where *device* is mounted with its own root, from /proc/self/mountinfo;
    None when it is not, or when mountinfo cannot be read."""
    try:
        lines = _MOUNTINFO.read_text(errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        head, sep, tail = line.partition(" - ")
        fields, post = head.split(), tail.split()
        if not sep or len(fields) < 5 or len(post) < 2:
            continue
        if fields[3] != "/":
            continue
        try:
            source = os.path.realpath(post[1])
        except (OSError, ValueError):
            continue
        if source == device:
            return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[4])
    return None


# ---------------------------------------------------------------------------
# Evidence collectors
# ---------------------------------------------------------------------------

def _artefact_evidence() -> list[str]:
    """Known configuration artefacts, read without the binary gate."""
    found: list[str] = []
    for tool, paths in _ARTEFACTS_WITHOUT_BINARY:
        for path in paths:
            try:
                if path.is_dir():
                    if any(path.iterdir()):
                        found.append(f"{tool}: {path}")
                        break
                elif path.is_file():
                    found.append(f"{tool}: {path}")
                    break
            except OSError:
                # Unreadable is not absent — and it is not evidence either.
                # Staying silent here is correct: the caller only ever weakens
                # a verdict with what this returns.
                continue
    return found


_WORD_RE_CACHE: "dict[str, re.Pattern[str]]" = {}


def _names_a_backup_tool(line: str) -> "str | None":
    """Return the backup tool a scheduled command invokes, if any.

    Matched on word boundaries so ``duplicity`` does not fire on
    ``duplicity-old.log.bak`` and ``borg`` does not fire on ``cyborg``.
    Comment lines are skipped — a commented-out backup job is the opposite of
    evidence that backups run.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    for name in _SCHEDULED_TOOL_NAMES:
        pattern = _WORD_RE_CACHE.get(name)
        if pattern is None:
            pattern = re.compile(rf"(?<![\w-]){re.escape(name)}(?![\w-])")
            _WORD_RE_CACHE[name] = pattern
        if pattern.search(stripped):
            return name
    return None


def _scheduled_evidence() -> list[str]:
    """Scheduled jobs whose command invokes a backup tool that is not on PATH.

    The files are the ones the cron and systemd-timer sections already open in
    the same audit run — this reads them for a different question rather than
    asking the system anything new.
    """
    found: list[str] = []
    candidates: list[Path] = list(_SCHEDULE_FILES)
    for directory in _SCHEDULE_DIRS:
        try:
            entries = sorted(p for p in directory.iterdir() if p.is_file())
        except OSError:
            continue
        candidates.extend(entries[:_MAX_SCHEDULE_FILES])

    for path in candidates:
        try:
            text = read_text_capped(path, encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            tool = _names_a_backup_tool(line)
            if tool:
                found.append(f"{tool}: {path}")
                break
    return found


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
        _timeshift_finding(snapshot, result, _t)
        return result

    # --- Tool(s) installed but not confirmed active -------------------------
    if installed:
        tools_str = ", ".join(sorted(installed))
        result.info(
            message=_t("backup.installed_only", tools=tools_str),
            detail=_t("backup.installed_only_detail"),
            key="backup.installed_only",
        )
        _timeshift_finding(snapshot, result, _t)
        return result

    # --- No known tool, but the host says otherwise --------------------------
    #
    # B1: the deduction is the part that asserts, so the deduction is what goes
    # when the evidence is ambiguous. This does not claim backups are fine — it
    # withdraws the claim that none is configured, and names what it saw so the
    # operator can settle it. Keeping the WARN and adding a second finding
    # beside it was the alternative; it preserves a statement already known to
    # be false and adds noise next to it.
    evidence = snapshot.evidence_without_tool or []
    if evidence:
        result.info(
            message=_t("backup.evidence_without_tool", count=len(evidence)),
            detail=_t("backup.evidence_without_tool_detail",
                      evidence="; ".join(sorted(evidence))),
            key="backup.evidence_without_tool",
        )
        return result

    # --- No backup tool found -----------------------------------------------
    _cmd, _detail = install_fix(
        _t, _t("backup.no_backup_detail"), "borgbackup", "borgmatic")
    if profile_name == "server":
        result.warn_with_deduction(
            key="backup.no_backup",
            message=_t("backup.no_backup"),
            reason=_t("backup.no_backup_reason"),
            points=1,
            detail=_detail,
            cmd=_cmd,
            nature="improvement",
        )
    else:
        result.info(
            message=_t("backup.no_backup"),
            detail=_detail,
            cmd=_cmd,
            key="backup.no_backup",
        )

    return result

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _timeshift_finding(snapshot: BackupSnapshot, result: CheckResult, _t) -> None:
    """v0.31.4 — what Timeshift's files said: its schedules, and its snapshots
    or why they were not read. Nothing when its config was not read."""
    schedules = snapshot.timeshift_schedules
    if schedules is None:
        return
    when = (", ".join(_t(f"backup.timeshift_every.{name}") for name in schedules)
            if schedules else _t("backup.timeshift_no_schedule"))
    snaps = snapshot.timeshift_snapshots
    # v0.32.0 — what no snapshot holds, beside the count: "active" must not
    # read as "my files are backed up" when the home is excluded.
    excl = (_t("backup.timeshift_excludes", paths=", ".join(snapshot.timeshift_excludes))
            if snapshot.timeshift_excludes else "")
    if snaps:
        result.info(
            key="backup.timeshift_snapshots",
            message=_t("backup.timeshift_snapshots", count=len(snaps), newest=snaps[-1],
                       path=snapshot.timeshift_dir, schedules=when),
            detail=excl,
        )
    elif snaps == []:
        result.info(
            key="backup.timeshift_none",
            message=_t("backup.timeshift_none", path=snapshot.timeshift_dir, schedules=when),
            detail=excl,
        )
    else:
        result.info(
            key="backup.timeshift_unread",
            message=_t("backup.timeshift_unread", schedules=when,
                       why=_t(f"backup.timeshift_why.{snapshot.timeshift_unread or 'not_read'}",
                              where=snapshot.timeshift_dir)),
            detail=excl,
        )


def _borgmatic_config_exists(path: Path) -> bool:
    """Return True if path is a non-empty directory or an existing file.

    A path BOB may not read is not a missing config: up to 3.13 `is_file()`
    raised here and the crash propagated out of `from_system` (which promises
    never to raise); on 3.14 it answers False and borgmatic fell silently to
    "installed". A denial returns False here too — but deliberately, so the
    verdict is "present, configuration unconfirmed", never a false "active".
    """
    try:
        if strict_is_file(path):
            return True
        if strict_is_dir(path):
            return any(path.iterdir())
    except OSError:
        return False
    return False

def _service_active(service: str) -> bool:
    """Return True if the given systemd service is active. Never raises."""
    if not _command_exists("systemctl"):
        return False
    return is_unit_active(service)
