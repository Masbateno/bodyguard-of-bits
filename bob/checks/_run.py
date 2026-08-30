"""
Shared subprocess and utility helpers for BOB check modules.

All check modules import from here instead of duplicating these helpers.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

_CMD_TIMEOUT = 10  # seconds — default for short commands (ss, ufw, iptables, etc.)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Timeout policy for subprocess calls
# ---------------------------------------------------------------------------
#
# All subprocess.run() calls in BOB MUST pass a `timeout=` argument to bound
# the worst-case audit duration. The shared default is `_CMD_TIMEOUT = 10`s.
# Individual sites override when the command is known to take longer:
#
#   * 10s — default, used by `_run()` and most checks.
#   * 15s — `find` (suid_audit), `apt-cache policy` (kernel_modules):
#           filesystem walks / dpkg cache reads on slow disks.
#   * 20s — `apt list --upgradable` (kernel_modules): apt's local DB read
#           on systems with very large package lists.
#   * 30s — `apt-get -s upgrade` (updates), `journalctl --since`
#           (auth_log): legitimately slow on large package sets / long
#           journal histories.
#
# Sites that override the default should keep the `timeout=` kwarg explicit
# and add a brief comment justifying the value. There is no hard upper bound
# in the helper itself (a user with a 10-minute fwupdmgr query could pass
# `timeout=600`), but in practice no check exceeds 30s today.
#
# SECURITY note (cf. SECURITY.md trust boundaries — "subprocess output"):
# every subprocess call MUST have a finite `timeout=`. A subprocess hanging
# forever would block the entire audit. The grep target enforcing this is:
#
#   grep -rn "subprocess.run\(" bob/ | grep -v "timeout="   # must be empty
#
# ---------------------------------------------------------------------------

# Force English output for all system commands so regexes work regardless
# of the system locale (e.g. French UFW outputs "État : actif" instead of
# "Status: active" when LC_ALL is not overridden).
# LANGUAGE must be cleared explicitly: gettext gives it higher priority
# than LC_ALL, so "LANGUAGE=fr_FR" would still override LC_ALL=C.
_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C", "LANGUAGE": ""}

# Same English-forcing intent as _C_LOCALE_ENV, but with a UTF-8 charset so a
# command that draws Unicode (e.g. ``fwupdmgr get-updates`` renders its device
# tree with ├ └ ─ │) is not degraded to ``?`` placeholders. Under plain
# ``LC_ALL=C`` those box-drawing characters collapse to ``?``, which breaks
# tree parsing — see bob/checks/firmware.py::_parse_fwupd_updates (v0.11.1 F3).
# ``C.UTF-8`` is English/POSIX text with UTF-8 encoding and is present on
# modern glibc distros; if absent the command simply degrades as before and
# the caller's parser still guards against junk.
_C_UTF8_LOCALE_ENV = {**os.environ, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "LANGUAGE": ""}


def _run(*args: str, timeout: int = _CMD_TIMEOUT, env: "dict | None" = None) -> str:
    """Run a command and return stdout. Returns empty string on error.

    ``env`` defaults to the English ``LC_ALL=C`` environment so regexes match
    regardless of the host locale. Pass ``env=_C_UTF8_LOCALE_ENV`` for commands
    whose output contains Unicode that must survive (still English text).
    """
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, timeout=timeout,
            env=env if env is not None else _C_LOCALE_ENV,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Command %r failed: %s (stderr=%r)", args, exc,
                     getattr(exc, "stderr", None))
        return ""


def _command_exists(name: str) -> bool:
    """Return True if the command is available in PATH."""
    return shutil.which(name) is not None


def is_unit_active(name: str, timeout: int = _CMD_TIMEOUT) -> bool:
    """Return True if the systemd unit is in the 'active' state.

    Wraps ``systemctl is-active <name>``. Returns False if systemctl is
    missing, if the unit does not exist, or if the command times out. The
    timeout defaults to the shared ``_CMD_TIMEOUT`` (10s) — fast enough for
    is-active which never legitimately exceeds 1s.

    The output is lower-cased before comparison: upstream systemd always
    emits lowercase ``active\\n``, but defensive matching guards against
    distros or downstream forks that ship a customised systemctl output.

    For richer state detection (template services, active/enabled
    combinations) see ``bob.checks.services._detect_single_unit_state``.
    """
    return _run("systemctl", "is-active", name, timeout=timeout).strip().lower() == "active"


def _identity_t(key: str, **kwargs) -> str:
    """Fallback translation function — returns the key itself.

    When kwargs are passed (placeholder substitution), appends them in a
    stable form (``key {a=1, b=2}``) so test assertions that probe substituted
    values still succeed against the identity translator. Matches the
    contract of the real ``bob.i18n.t``: kwargs must round-trip into the
    output string.
    """
    if kwargs:
        return key.format(**kwargs) if "{" in key else key + " " + " ".join(f"{k}={v}" for k, v in kwargs.items())
    return key


TranslationFunc = Callable[..., str]
"""Type alias for BOB's translation function: t(key, **kwargs) -> str."""


def _is_safe_config_path(path) -> bool:
    """Return True if path is absolute and not a symlink (safe to read).

    Use this for **system** config paths (``/etc/cron.d/``, ``/etc/sudoers.d/``,
    ``/var/spool/cron/crontabs/``) where any symlink is suspect. For paths
    under a user's home where dotfiles symlinks are legitimate (e.g. dotfiles
    managed via git), use ``_is_safe_user_path()`` instead.
    """
    p = Path(path)
    return p.is_absolute() and not p.is_symlink()


def _is_safe_user_path(path, owner_home) -> bool:
    """Return True if reading ``path`` is safe in the context of ``owner_home``.

    Differs from ``_is_safe_config_path``: a symlink is **accepted** when its
    resolved target is inside ``owner_home``. Defends against the case where
    an attacker with write access to a user's home places a symlink pointing
    outside (e.g. ``~/.ssh/authorized_keys → /etc/shadow``) and tricks BOB
    running under sudo into materialising the target file contents in the
    audit report.

    Args:
        path:       Path to check.
        owner_home: User home directory (Path or str) that ``path`` should
                    belong to. Symlinks inside this directory are accepted.

    Returns:
        True if the path is absolute, exists, and either is not a symlink or
        is a symlink whose target stays inside ``owner_home``.
    """
    p = Path(path)
    if not p.is_absolute():
        return False
    if p.is_symlink():
        try:
            target = p.resolve(strict=True)
        except OSError:
            return False
        home = Path(owner_home).resolve()
        try:
            target.relative_to(home)
            return True
        except ValueError:
            return False
    return True


# Locale-independent month abbreviation map (English only).
# datetime.strptime("%b") parses according to the *Python process* LC_TIME, not
# the subprocess env. Even when commands are forced to LC_ALL=C via _C_LOCALE_ENV,
# a Python process running under LC_TIME=fr_FR.UTF-8 will fail to parse "May 14"
# because it expects "mai 14". This helper bypasses LC_TIME entirely.

def join_continuations(lines: "list[str]") -> "list[str]":
    """Fold backslash-continuations into single logical lines.

    Several of the files BOB parses let a directive be wrapped across lines
    with a trailing ``\\`` — sudoers rules, and PAM stacks, whose own
    ``pam.conf(5)`` man page uses a wrapped ``pam_pwquality.so`` line as its
    worked example. Read one line at a time, a wrapped directive is invisible:
    the half carrying the keyword and the half carrying its value never meet.

    Shared rather than reimplemented per module. Every defect found in the
    v0.15.0 verdict-accuracy pass had the same origin — line-level config
    handling written once per check, correct in some copies and forgotten in
    others.
    """
    out: list[str] = []
    buf = ""
    for raw in lines:
        if raw.endswith("\\"):
            buf += raw[:-1] + " "
            continue
        out.append(buf + raw)
        buf = ""
    if buf:
        out.append(buf)
    return out

_ENGLISH_MONTH_ABBR = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_english_month_day(s: str) -> tuple[int, int, int, int, int] | None:
    """
    Parse a string starting with "Mon DD HH:MM:SS" (English month abbreviation).

    Returns ``(month, day, hour, minute, second)`` or ``None`` if the format
    does not match. Year is not parsed — callers append it. Use this instead
    of ``datetime.strptime(..., "%b ...")`` whenever the input is known to be
    English (e.g. ``openssl x509 -enddate`` or syslog with LC_ALL=C).
    """
    parts = s.split(maxsplit=4)
    if len(parts) < 3:
        return None
    month = _ENGLISH_MONTH_ABBR.get(parts[0])
    if month is None:
        return None
    try:
        day = int(parts[1])
        h, m, sec = parts[2].split(":")
        return month, day, int(h), int(m), int(sec)
    except (ValueError, IndexError):
        return None
