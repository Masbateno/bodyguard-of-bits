"""
Sensitive file permissions and sudoers audit for BOB.

Checks:
  - Permissions on critical system files (/etc/passwd, /etc/shadow, etc.)
  - SSH host private key permissions (/etc/ssh/ssh_host_*_key)
  - Sudoers files for NOPASSWD:ALL entries

Usage:
    from bob.checks.file_perms import FilePermsSnapshot, check_file_perms

    snapshot = FilePermsSnapshot.from_system()
    result   = check_file_perms(snapshot)
"""

from __future__ import annotations

import shlex
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple, Tuple

from bob.checks._run import TranslationFunc, _identity_t
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Sensitive files specification
# ---------------------------------------------------------------------------

class _FileSpec(NamedTuple):
    path:     str
    max_mode: int   # maximum allowed permissions (low 9 octal bits)
    key:      str   # short tag used to build unique finding keys

_SENSITIVE_FILES: tuple[_FileSpec, ...] = (
    _FileSpec("/etc/passwd",  0o644, "passwd"),
    _FileSpec("/etc/shadow",  0o640, "shadow"),
    _FileSpec("/etc/gshadow", 0o640, "gshadow"),
    _FileSpec("/etc/group",   0o644, "group"),
    _FileSpec("/etc/sudoers", 0o440, "sudoers_file"),
)

# ---------------------------------------------------------------------------
# Snapshot dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FileInfo:
    """Collected information for a single sensitive file."""
    path:     str
    exists:   bool
    mode:     int   # actual permissions (low 9 bits), 0 if absent
    max_mode: int   # expected maximum
    key:      str   # short tag from _FileSpec

@dataclass
class FilePermsSnapshot:
    """
    Raw snapshot of sensitive file permissions and sudoers state.

    All I/O happens in from_system(). check_file_perms() is pure logic.
    """
    sensitive_files:           list[FileInfo]            = field(default_factory=list)
    ssh_host_key_issues:       list[Tuple[str, int]]     = field(default_factory=list)
    sudoers_nopasswd_all:      list[str]                 = field(default_factory=list)
    sudoers_nopasswd_specific: list[str]                 = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "FilePermsSnapshot":
        """
        Collect sensitive file permissions and sudoers entries from the live system.

        Returns:
            Populated FilePermsSnapshot. Never raises — errors reflected as absent/default.
        """
        snap = cls()

        # 1. Sensitive system files
        for spec in _SENSITIVE_FILES:
            p = Path(spec.path)
            if p.exists():
                try:
                    mode = stat.S_IMODE(p.stat().st_mode)
                except OSError:
                    # Cannot read permissions — assume worst case to avoid hiding issues.
                    mode = 0o777
                snap.sensitive_files.append(
                    FileInfo(path=spec.path, exists=True,
                             mode=mode, max_mode=spec.max_mode, key=spec.key)
                )
            else:
                snap.sensitive_files.append(
                    FileInfo(path=spec.path, exists=False,
                             mode=0, max_mode=spec.max_mode, key=spec.key)
                )

        # 2. SSH host private keys under /etc/ssh/
        ssh_dir = Path("/etc/ssh")
        if ssh_dir.is_dir():
            for key_path in sorted(ssh_dir.glob("ssh_host_*_key")):
                if key_path.suffix == ".pub":
                    continue
                try:
                    mode = stat.S_IMODE(key_path.stat().st_mode)
                    if mode != 0o600:
                        snap.ssh_host_key_issues.append((str(key_path), mode))
                except OSError:
                    pass

        # 3. Sudoers NOPASSWD entries
        nopasswd_all, nopasswd_specific = _collect_nopasswd_entries()
        snap.sudoers_nopasswd_all      = nopasswd_all
        snap.sudoers_nopasswd_specific = nopasswd_specific

        return snap

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect_nopasswd_entries() -> tuple[list[str], list[str]]:
    """
    Parse /etc/sudoers and /etc/sudoers.d/* for NOPASSWD entries.

    Returns:
        (nopasswd_all, nopasswd_specific) where:
        - nopasswd_all      — lines granting unrestricted passwordless sudo
        - nopasswd_specific — lines granting passwordless access to specific commands only
    """
    nopasswd_all:      list[str] = []
    nopasswd_specific: list[str] = []
    paths: list[Path] = []

    sudoers = Path("/etc/sudoers")
    if sudoers.exists():
        paths.append(sudoers)

    sudoers_d = Path("/etc/sudoers.d")
    if sudoers_d.is_dir():
        for f in sorted(sudoers_d.iterdir()):
            if f.is_file() and not f.name.startswith(".") and not f.name.endswith("~"):
                paths.append(f)

    for p in paths:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "NOPASSWD" not in stripped.upper():
                continue
            if _is_nopasswd_all(stripped):
                nopasswd_all.append(stripped)
            else:
                nopasswd_specific.append(stripped)

    return nopasswd_all, nopasswd_specific

def _is_nopasswd_all(line: str) -> bool:
    """
    Return True if this sudoers line grants unrestricted passwordless sudo.

    Matches exactly ``NOPASSWD: ALL`` (case-insensitive, colon/space optional)
    with no further command tokens. This is deliberately strict: a line like
    ``NOPASSWD: ALL /bin/sh`` is treated as specific (the command field is not
    purely ALL) and will not trigger an unrestricted-sudo alert.

    Recognises patterns such as:
        john  ALL=(ALL)       NOPASSWD:ALL
        %sudo ALL=(ALL:ALL)   NOPASSWD: ALL
    A line like ``john ALL=(ALL) NOPASSWD:/usr/bin/apt`` returns False.
    """
    upper = line.upper()
    if "NOPASSWD" not in upper:
        return False
    # Extract the command portion after "NOPASSWD", strip leading ": \t"
    after = upper.split("NOPASSWD", 1)[1]
    after = after.lstrip(": \t")
    # Only flag when the command field is exactly ALL — nothing more, nothing less
    return after.strip() == "ALL"

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_file_perms(snapshot: FilePermsSnapshot, *, t: TranslationFunc | None = None) -> CheckResult:
    """
    Check sensitive file permissions and sudoers configuration.

    Deduction caps (independent per category):
      - World-writable files: −3 pts each, no cap (each is an individual critical risk)
      - Too-permissive files: −1 pt each, capped at 3 total (WARN-level quality issues)
      - SSH host key issues:  −1 pt each, capped at 2 total
      - NOPASSWD:ALL:         −2 pts total (regardless of how many lines)

    Args:
        snapshot: FilePermsSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()
    # Cap for WARN-level permission findings only — ALERT (world-writable) is
    # uncapped because each world-writable critical file is an individual risk.
    warn_deductions = 0

    # ---- Sensitive file permissions ----------------------------------------
    for fi in snapshot.sensitive_files:
        if not fi.exists:
            continue

        # Bits set in the actual mode that exceed what max_mode allows
        extra = fi.mode & (~fi.max_mode & 0o777)

        if extra & 0o002:   # world-writable — critical risk, no deduction cap
            result.alert_with_deduction(
                key=f"file_perms.{fi.key}.world_writable",
                message=_t("file_perms.world_writable",
                           path=fi.path, mode=oct(fi.mode)),
                reason=_t("file_perms.world_writable_reason", path=fi.path),
                points=3,
                detail=_t("file_perms.world_writable_detail", path=fi.path),
                cmd=f"sudo chmod o-w {shlex.quote(str(fi.path))}",
            )

        elif extra:     # other unexpected bits (group-write, world-read…) — capped
            result.warn(
                message=_t("file_perms.too_permissive",
                           path=fi.path, mode=oct(fi.mode),
                           expected=oct(fi.max_mode)),
                detail=_t("file_perms.too_permissive_detail",
                          path=fi.path, expected=oct(fi.max_mode)),
                cmd=f"sudo chmod {oct(fi.max_mode)[2:]} {shlex.quote(str(fi.path))}",
                key=f"file_perms.{fi.key}.too_permissive",
            )
            if warn_deductions < 3:
                result.add_deduction(
                    reason=_t("file_perms.too_permissive_reason", path=fi.path),
                    points=1,
                    context="local",
                    key=f"file_perms.{fi.key}.too_permissive",
                )
                warn_deductions += 1

    # ---- SSH host private keys ----------------------------------------------
    ssh_deductions = 0
    for path, mode in snapshot.ssh_host_key_issues:
        result.warn(
            message=_t("file_perms.ssh_host_key_perms",
                       path=path, mode=oct(mode)),
            detail=_t("file_perms.ssh_host_key_perms_detail"),
            cmd=f"sudo chmod 600 {shlex.quote(str(path))}",
            key=f"file_perms.ssh_host_key.{Path(path).name}",
        )
        if ssh_deductions < 2:
            result.add_deduction(
                reason=_t("file_perms.ssh_host_key_perms_reason", path=path),
                points=1,
                context="local",
                key=f"file_perms.ssh_host_key.{Path(path).name}",
            )
            ssh_deductions += 1

    # ---- Sudoers NOPASSWD:ALL -----------------------------------------------
    if snapshot.sudoers_nopasswd_all:
        for line in snapshot.sudoers_nopasswd_all:
            display = line[:120] + ("…" if len(line) > 120 else "")
            result.warn(
                message=_t("file_perms.sudoers_nopasswd_all", line=display),
                detail=_t("file_perms.sudoers_nopasswd_all_detail"),
                key="file_perms.sudoers_nopasswd_all",
            )
        result.add_deduction(
            reason=_t("file_perms.sudoers_nopasswd_all_reason"),
            points=2,
            context="local",
            key="file_perms.sudoers_nopasswd_all",
        )

    # ---- Sudoers NOPASSWD (specific commands only) --------------------------
    if snapshot.sudoers_nopasswd_specific:
        result.info(
            message=_t("file_perms.sudoers_nopasswd_specific",
                       count=len(snapshot.sudoers_nopasswd_specific)),
            detail=_t("file_perms.sudoers_nopasswd_specific_detail"),
            key="file_perms.sudoers_nopasswd_specific",
        )

    # ---- All clear ----------------------------------------------------------
    if not result.findings:
        result.ok(
            message=_t("file_perms.ok"),
            key="file_perms.ok",
        )

    return result
