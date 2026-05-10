"""
SSH login analysis for BOB.

Parses /var/log/auth.log (and auth.log.1 if available) to identify
successful SSH logins, source IPs, and unusual access patterns.

UFW logs show what was *blocked*. This check shows what *got through* —
successful logins, top source IPs, and logins from public IP addresses.

Split into two parts:
  1. AuthLogSnapshot.from_system() — collects data via file reads.
  2. check_auth_log(snapshot, t)   — pure logic, returns CheckResult.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from bob.checks._run import TranslationFunc, _C_LOCALE_ENV, _identity_t
from bob.scoring import CheckResult

_LOG_PATHS: list[Path] = [
    Path("/var/log/auth.log"),
    Path("/var/log/auth.log.1"),
    Path("/var/log/secure"),       # RHEL/CentOS
    Path("/var/log/secure.1"),
]

# Matches: "Apr 18 10:23:45 host sshd[pid]: Accepted publickey for user from 1.2.3.4 port 12345 ssh2"
_ACCEPTED_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+\d+",
    re.MULTILINE,
)
_FAILED_RE = re.compile(
    r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?:Failed\s+\S+\s+for(?:\s+invalid\s+user)?\s+\S+\s+from"
    r"|\bInvalid\s+user\s+\S+\s+from)",
    re.MULTILINE,
)

_BRUTE_FORCE_THRESHOLD = 50

_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _read_auth_from_journald(max_days: int = 90) -> str:
    """
    Read SSH authentication events from journald.

    Fallback for systems without /var/log/auth.log (Debian 13+ with journald-only
    logging). Uses --output=short to produce syslog-format lines compatible with
    the existing _ACCEPTED_RE / _FAILED_RE regexes.

    Returns:
        Raw log content, or empty string if journald is unavailable.
    """
    try:
        result = subprocess.run(
            [
                "journalctl", "-t", "sshd",
                "--no-pager",
                "--output=short",
                f"--since={max_days} days ago",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env=_C_LOCALE_ENV,
        )
        if result.returncode == 0:
            return result.stdout
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        pass
    return ""


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True  # unparseable IP: treat as private to avoid alerting on log noise


@dataclass
class LoginEntry:
    """A single successful SSH login."""
    method:  str   # publickey, password, etc.
    user:    str
    source:  str   # IP address
    is_public: bool


@dataclass
class AuthLogSnapshot:
    """
    Successful SSH login data collected from auth.log.

    Attributes:
        entries:        List of recent successful login entries.
        log_available:  True if at least one auth log file was readable.
        days_analysed:  Approximate number of days covered by the log.
    """
    entries:       List[LoginEntry] = field(default_factory=list)
    log_available: bool = False
    days_analysed: int  = 0
    failed_count:  int  = 0

    @classmethod
    def from_text(cls, text: str) -> AuthLogSnapshot:
        """Parse auth.log content from a string. Useful for testing."""
        snap = cls(log_available=True)
        snap.days_analysed = _estimate_days(text)
        for m in _ACCEPTED_RE.finditer(text):
            src = m.group(4)
            snap.entries.append(LoginEntry(
                method=m.group(2),
                user=m.group(3),
                source=src,
                is_public=not _is_private(src),
            ))
        snap.failed_count = len(_FAILED_RE.findall(text))
        return snap

    @classmethod
    def from_system(cls, max_lines: int = 50_000) -> AuthLogSnapshot:
        """
        Parse auth.log for successful SSH logins.

        Reads up to max_lines lines from the most recent auth.log files
        to avoid stalling on very large logs.
        """
        snap = cls()
        lines_read: list[str] = []

        for path in _LOG_PATHS:
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                lines_read.extend(text.splitlines())
                snap.log_available = True
                if len(lines_read) >= max_lines:
                    break
            except OSError:
                continue

        if not snap.log_available:
            # Fallback: journald (Debian 13+ without /var/log/auth.log)
            journald_text = _read_auth_from_journald()
            if journald_text.strip():
                return cls.from_text(journald_text)
            return snap

        combined = "\n".join(lines_read[-max_lines:])
        snap.days_analysed = _estimate_days(combined)

        for m in _ACCEPTED_RE.finditer(combined):
            src = m.group(4)
            snap.entries.append(LoginEntry(
                method=m.group(2),
                user=m.group(3),
                source=src,
                is_public=not _is_private(src),
            ))
        snap.failed_count = len(_FAILED_RE.findall(combined))

        return snap


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_auth_log(snapshot: AuthLogSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Analyse recent SSH logins and flag public-IP access.

    Reports:
    - Total successful logins and top source IPs
    - Warning when a public IP has successfully authenticated
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.log_available:
        result.info(
            message=_t("auth_log.not_available"),
            key="auth_log.not_available",
        )
        return result

    entries = snapshot.entries
    days    = snapshot.days_analysed

    # Brute force check independent of successful logins
    if snapshot.failed_count >= _BRUTE_FORCE_THRESHOLD:
        result.warn(
            message=_t("auth_log.brute_force",
                       count=snapshot.failed_count,
                       days=days),
            nature="improvement",
            cmd="sudo fail2ban-client status sshd",
            cmd_type="check",
            key="auth_log.brute_force",
        )

    if not entries:
        result.ok(
            message=(_t("auth_log.no_logins_no_range")
                     if days == 0
                     else _t("auth_log.no_logins", days=days)),
            key="auth_log.no_logins",
        )
        return result

    # Top source IPs
    ip_counts: Counter = Counter(e.source for e in entries)
    top_ips = ip_counts.most_common(3)

    public_entries = [e for e in entries if e.is_public]
    public_ips = sorted({e.source for e in public_entries})

    result.info(
        message=_t("auth_log.summary",
                   count=len(entries),
                   days=days,
                   top=", ".join(f"{ip} ({n})" for ip, n in top_ips)),
        key="auth_log.summary",
    )

    if public_ips:
        result.warn(
            message=_t("auth_log.public_login",
                       ips=", ".join(public_ips),
                       count=len(public_entries)),
            nature="improvement",
            cmd="sudo grep 'Accepted' /var/log/auth.log | tail -20",
            cmd_type="check",
            key="auth_log.public_login",
        )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _estimate_days(text: str) -> int:
    """Estimate how many calendar days the log content spans."""
    months = {
        "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
        "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
    }
    dates: list[tuple[int, int]] = []
    for m in re.finditer(r"^(\w{3})\s+(\d{1,2})\s", text, re.MULTILINE):
        mon = months.get(m.group(1).lower())
        day = int(m.group(2))
        if mon:
            dates.append((mon, day))
    if not dates:
        return 0
    first, last = dates[0], dates[-1]
    if last[0] < first[0]:  # year wrap
        return max(1, (last[0] + 12 - first[0]) * 30 + last[1] - first[1] + 1)
    return max(1, (last[0] - first[0]) * 30 + last[1] - first[1] + 1)
