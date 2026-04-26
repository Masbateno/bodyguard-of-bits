"""
System umask check for BOB.

Reads the system-wide umask from /etc/login.defs, /etc/profile,
/etc/profile.d/*.sh, /etc/bash.bashrc, and /etc/pam.d/common-session.

A permissive umask (002 or 000) causes newly created files to be
group- or world-writable by default — a privilege escalation risk.
CIS Ubuntu 22.04 L1 — 5.4.4.

Split into two parts:
  1. UmaskSnapshot.from_system() — collects data via file reads.
  2. check_umask(snapshot, t)     — pure logic, returns CheckResult.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from bob.checks._run import _identity_t
from bob.scoring import CheckResult

_UMASK_RE = re.compile(r"^(?!\s*#)\s*(?:umask|UMASK)\s+([0-7]{3,4})\b", re.MULTILINE)
_LOGIN_DEFS_RE = re.compile(r"^UMASK\s+([0-7]{3,4})", re.MULTILINE | re.IGNORECASE)
_PAM_UMASK_RE  = re.compile(r"pam_umask\.so.*umask=([0-7]{3,4})", re.MULTILINE)
# pam_umask.so without explicit umask= — effective value comes from login.defs or default 022
_PAM_UMASK_NOARG_RE = re.compile(r"^\s*session\s+\S+\s+pam_umask\.so\s*$", re.MULTILINE)


def _normalize(raw: str) -> str:
    """Normalize raw octal string to 3 digits (e.g. '0022' → '022')."""
    return raw.zfill(4)[-3:]


def _get_proc_umask() -> Optional[str]:
    """Read the effective umask from /proc/self/status (Linux 4.7+)."""
    try:
        content = Path("/proc/self/status").read_text(encoding="utf-8")
        m = re.search(r"^Umask:\s+([0-7]{4})", content, re.MULTILINE)
        if m:
            return _normalize(m.group(1))
    except OSError:
        pass
    return None


def _fix_cmd(source: Optional[str]) -> str:
    """Return the fix command appropriate for the file where the umask was found."""
    if not source or source == "/etc/login.defs":
        return "sudo sed -i 's/^UMASK[[:space:]].*/UMASK\\t\\t022/' /etc/login.defs"
    if "/pam.d/" in source:
        return f"sudo sed -i 's/umask=[0-7]*/umask=022/' {source}"
    return f"sudo sed -i 's/\\bumask [0-7]*/umask 022/' {source}"


def _scan(path: Path, regex) -> Optional[str]:
    """Read *path* and return the first umask value matched by *regex*, or None."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        m = regex.search(content)
        if m:
            return _normalize(m.group(1))
    except OSError:
        pass
    return None


@dataclass
class UmaskSnapshot:
    """
    System-wide umask configuration collected from config files.

    Attributes:
        umask_value:  Primary detected umask (3-digit octal string), or None.
        source:       Path of the primary source file.
        all_sources:  All files that define a umask, mapped to their values.
                      Used to detect conflicting definitions.
    """
    umask_value: Optional[str] = None
    source:      Optional[str] = None
    all_sources: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_system(
        cls,
        *,
        _login_defs: Path = Path("/etc/login.defs"),
        _pam_session: Path = Path("/etc/pam.d/common-session"),
        _profile: Path = Path("/etc/profile"),
        _bash_bashrc: Path = Path("/etc/bash.bashrc"),
        _profile_d: Path = Path("/etc/profile.d"),
    ) -> UmaskSnapshot:
        """Read system-wide umask from standard configuration files."""
        snap = cls()
        found: dict[str, str] = {}  # {source_path: normalized_value}

        # Priority-ordered candidates (first hit becomes the primary)
        candidates: list[tuple[Path, object]] = [
            (_login_defs, _LOGIN_DEFS_RE),
            (_pam_session, _PAM_UMASK_RE),
            (_profile,     _UMASK_RE),
            (_bash_bashrc, _UMASK_RE),
        ]
        for path, regex in candidates:
            val = _scan(path, regex)
            if val is not None:
                found[str(path)] = val

        # /etc/profile.d/*.sh
        try:
            for sh in sorted(_profile_d.glob("*.sh")):
                val = _scan(sh, _UMASK_RE)
                if val is not None:
                    found[str(sh)] = val
        except OSError:
            pass

        snap.all_sources = found

        # Primary = first match in priority order
        for path, _ in candidates:
            if str(path) in found:
                snap.umask_value = found[str(path)]
                snap.source = str(path)
                return snap

        # Fallback: first profile.d hit (if any)
        for src, val in found.items():
            snap.umask_value = val
            snap.source = src
            return snap

        # pam_umask.so without explicit umask= — uses login.defs UMASK or default 022
        # Common on Debian 13+ where UMASK is commented out in login.defs
        try:
            pam_content = _pam_session.read_text(encoding="utf-8", errors="ignore")
            if _PAM_UMASK_NOARG_RE.search(pam_content):
                ldef_val = _scan(_login_defs, _LOGIN_DEFS_RE)
                snap.umask_value = ldef_val if ldef_val is not None else "022"
                snap.source = str(_pam_session)
                return snap
        except OSError:
            pass

        # Last resort: read effective process umask from /proc/self/status
        proc_val = _get_proc_umask()
        if proc_val is not None:
            snap.umask_value = proc_val
            snap.source = "/proc/self/status"
            return snap

        return snap


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_umask(snapshot: UmaskSnapshot, t=None) -> CheckResult:
    """
    Evaluate system umask and return a CheckResult.

    Good:    022 (files: rw-r--r--, dirs: rwxr-xr-x)
             027 (files: rw-r-----, dirs: rwxr-x---)
             077 (files: rw-------, dirs: rwx------)
    Warn:    002 (files: rw-rw-r--, dirs: rwxrwxr-x) — group-writable by default
    Alert:   000 (files: rw-rw-rw-, dirs: rwxrwxrwx) — world-writable by default
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if snapshot.umask_value is None:
        result.info(
            message=_t("umask.not_found"),
            key="umask.not_found",
        )
        return result

    umask  = snapshot.umask_value
    source = snapshot.source or "?"
    cmd    = _fix_cmd(snapshot.source)

    if umask == "000":
        result.alert(
            message=_t("umask.world_writable", umask=umask, source=source),
            nature="action",
            cmd=cmd,
            key="umask.world_writable",
        )
        result.add_deduction(
            reason=_t("umask.world_writable", umask=umask, source=source),
            points=2,
            context="local",
            key="umask.world_writable",
        )
    elif umask == "002":
        result.warn(
            message=_t("umask.group_writable", umask=umask, source=source),
            nature="improvement",
            cmd=cmd,
            key="umask.group_writable",
        )
        result.add_deduction(
            reason=_t("umask.group_writable", umask=umask, source=source),
            points=1,
            context="local",
            key="umask.group_writable",
        )
    elif umask in ("022", "027", "077"):
        result.ok(
            message=_t("umask.ok", umask=umask, source=source),
            key="umask.ok",
        )
    else:
        result.info(
            message=_t("umask.unusual", umask=umask, source=source),
            key="umask.unusual",
        )

    # Detect conflicting umask definitions across multiple files
    unique_vals = set(snapshot.all_sources.values())
    if len(unique_vals) > 1:
        definitions = ", ".join(
            f"{v} ({Path(s).name})" for s, v in snapshot.all_sources.items()
        )
        result.info(
            message=_t("umask.multiple_definitions", definitions=definitions),
            key="umask.multiple_definitions",
        )

    return result
