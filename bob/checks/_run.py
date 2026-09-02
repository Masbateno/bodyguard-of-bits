"""
Shared subprocess and utility helpers for BOB check modules.

All check modules import from here instead of duplicating these helpers.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable, NamedTuple

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


class CommandResult(NamedTuple):
    """What a command printed, and whether that output can be trusted.

    ``ok`` is False when the command could not run at all (absent binary,
    timeout, OSError) or ran and exited non-zero. It is the caller's job to
    decide what that means: for ``ss`` a failure means the socket list is
    simply unknown, while ``dpkg-query -W`` exits non-zero to *tell* the
    caller the package is not installed. Only the caller knows which.

    ``stderr`` was already being captured and thrown away. It matters where a
    tool explains itself there while stdout and the exit status both look
    ordinary: ``auditctl -l`` prints "The audit system is disabled" on stderr,
    exits 0 and leaves stdout empty, which is indistinguishable from a
    reachable audit system holding no rules. It is untrusted text like any
    other subprocess output — match it against a known marker, never render it
    into a report.
    """

    stdout: str
    ok:     bool
    stderr: str = ""


def run_result(
    *args: str, timeout: int = _CMD_TIMEOUT, env: "dict | None" = None
) -> CommandResult:
    """Run a command and report both its stdout and whether it succeeded.

    Prefer this over ``_run`` wherever an empty result would otherwise be
    rendered as an affirmative "nothing found". A check that says "0 listening
    ports" because ``ss`` is not installed is not reporting a fact about the
    host, and BOB must not state it as one.

    ``env`` defaults to the English ``LC_ALL=C`` environment so regexes match
    regardless of the host locale. Pass ``env=_C_UTF8_LOCALE_ENV`` for commands
    whose output contains Unicode that must survive (still English text).
    """
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, timeout=timeout,
            env=env if env is not None else _C_LOCALE_ENV,
        )
        return CommandResult(proc.stdout, proc.returncode == 0, proc.stderr)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Command %r failed: %s (stderr=%r)", args, exc,
                     getattr(exc, "stderr", None))
        return CommandResult("", False)


def _run(*args: str, timeout: int = _CMD_TIMEOUT, env: "dict | None" = None) -> str:
    """Run a command and return stdout. Returns empty string on error.

    Thin wrapper over :func:`run_result` that drops the success flag. Keep it
    for the many call sites where an empty result and a failed command lead to
    the same, correct conclusion.
    """
    return run_result(*args, timeout=timeout, env=env).stdout



# systemd prefixes a unit it considers "not ok" with a status glyph in
# `systemctl list-units`. Which glyph depends on the locale: "●" under UTF-8,
# and "*" under the LC_ALL=C environment `_run` uses by default — so BOB's
# captures carry the asterisk form.
_UNIT_GLYPHS = ("\u25cf", "*")


def strip_unit_glyph(line: str) -> str:
    """Return a ``systemctl list-units`` line without its leading status glyph.

    The glyph marks exactly the units an audit cares about most — failed ones —
    and it shifts every column by one. A parser reading ``line.split()[0]`` as
    the unit name therefore read the glyph, and ``[2]`` as the active state read
    "loaded", on precisely the units it existed to report.

    ``--plain`` would also remove it, but stripping works on captured output and
    on every systemd version, and does not depend on a flag being honoured.
    """
    stripped = line.lstrip()
    for glyph in _UNIT_GLYPHS:
        if stripped.startswith(glyph):
            rest = stripped[len(glyph):]
            if rest[:1].isspace():
                return rest.lstrip()
    return line


# "Download something and pipe it straight into a shell" — the shape of most
# supply-chain one-liners, and the reason a cron job or timer running it is
# worth a finding.
#
# This lived twice, as two different regexes that disagreed. cron_audit used
# `\b(curl|wget)\b.*\|\s*\S*sh\b`, which matched any token ending in "sh" —
# so `| ssh backup@host` was flagged as a piped shell — and missed
# `| sudo bash`, the most published form of the pattern and the dangerous one,
# since it runs as root. systemd_timers used `\|\s*(/[a-z/]*/)?(?:ba)?sh\b`,
# which knew only sh and bash and so missed `| zsh` as well.
#
# One implementation, matching on the command word rather than on a suffix.
_DOWNLOADER_RE = re.compile(r"\b(?:curl|wget)\b", re.IGNORECASE)

_SHELL_NAMES = frozenset({
    "sh", "bash", "dash", "zsh", "ksh", "ash", "csh", "tcsh", "fish", "busybox",
})

# Commands that stand in front of the real one without changing what it is.
_WRAPPER_ARG_RE = re.compile(r"\d+[smhd]?")

_COMMAND_WRAPPERS = frozenset({
    "sudo", "doas", "env", "nice", "ionice", "nohup", "time", "timeout",
    "setsid", "stdbuf",
})


def pipes_into_shell(command: str) -> bool:
    """Return True if *command* downloads something and pipes it into a shell.

    The download must appear before the first pipe — `echo curl | sh` is not
    this pattern. Each piped stage is then examined in turn, so
    `curl … | tee /tmp/x | sh` is caught, and a leading `sudo`/`env`/`nice`
    wrapper (with its own options) is stepped over to reach the command it
    actually runs.
    """
    head, sep, _ = command.partition("|")
    if not sep or not _DOWNLOADER_RE.search(head):
        return False

    for segment in command.split("|")[1:]:
        tokens = segment.split()
        i = 0
        while i < len(tokens):
            # A unit file writes the whole thing as
            # `ExecStart=/bin/bash -c "curl … | bash"`, so the last token
            # carries the closing quote. Strip the shell punctuation that can
            # sit around a command word before comparing it.
            base = tokens[i].strip("\"'`();&").rsplit("/", 1)[-1].lower()
            if base in _COMMAND_WRAPPERS:
                i += 1
                # Step over what belongs to the wrapper rather than to the
                # command it runs: its options, a bare duration or priority
                # (`timeout 60 bash`, `nice 10 sh`), and `env`-style
                # assignments.
                while i < len(tokens) and (
                    tokens[i].startswith("-")
                    or _WRAPPER_ARG_RE.fullmatch(tokens[i])
                    or "=" in tokens[i]
                ):
                    i += 1
                continue
            if base in _SHELL_NAMES:
                return True
            break          # this stage runs something else; try the next one
    return False

def _command_exists(name: str) -> bool:
    """Return True if the command is available in PATH."""
    return shutil.which(name) is not None


# The complete set `systemctl is-active` prints, from systemd's own
# unit_active_state_to_string(). Anything else did not come from systemd —
# a stub, a wrapper, a truncated or mis-encoded stream — and is not an answer.
_UNIT_STATES = frozenset({
    "active", "reloading", "inactive", "failed",
    "activating", "deactivating", "maintenance", "refreshing", "unknown",
})


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

    Callers that must not confuse "inactive" with "could not ask systemd"
    should use :func:`unit_active_state` instead.
    """
    return unit_active_state(name, timeout=timeout) == "active"


def unit_active_state(name: str, timeout: int = _CMD_TIMEOUT) -> "str | None":
    """Return the unit's reported state, or None when systemd could not be asked.

    ``is_unit_active`` collapses "inactive" and "systemctl never answered" into
    the same False, so a host whose systemctl is absent or refusing looks like
    a host whose services are all stopped — BOB warned that a running sshd was
    "installed but not running" on exactly that basis.

    The success flag is deliberately *not* the discriminator here: `systemctl
    is-active` exits non-zero to report a legitimately inactive unit, which is
    an answer, not a failure. An empty stdout is the honest signal that no
    answer was obtained — systemd prints the state on stdout whenever it can
    determine one, and writes its own failures to stderr.
    """
    state = run_result("systemctl", "is-active", name, timeout=timeout).stdout.strip().lower()
    return state if state in _UNIT_STATES else None


def split_ss_address(raw: str) -> "tuple[str | None, str | None, str]":
    """Split an ``ss`` address column into (address, port, iface).

    One grammar for the two checks that read ``ss`` output. They had a private
    copy each, under the same name and with different behaviour: ``ports``
    learned about IPv6 brackets and ``%scope`` in v0.15.0, ``network_context``
    kept an ``rfind(":")`` that left the brackets glued to the address. Every
    IPv6 peer therefore failed the private-address test — ``[::1]`` included —
    so an ordinary local PostgreSQL connection over IPv6 loopback was reported
    as "an established connection to an external IP on a sensitive port", with
    a two-point deduction. The same shape as the UFW rule grammar unified in
    v0.15.1: two copies of one rule, one of them fixed.

    ``iface`` is non-empty when the address carries a scope
    (``0.0.0.0%virbr0:67`` → ``("0.0.0.0", "67", "virbr0")``). Returns
    ``(None, None, "")`` when the column is not an address at all.

    Handles ``0.0.0.0:22``, ``0.0.0.0%virbr0:67``, ``127.0.0.53%lo:53``,
    ``[::]:22``, ``[::1]:631``, ``[fe80::1%eth0]:22`` and ``*:port``.
    """
    ipv6_match = re.match(r"^\[([^\]]+)\]:(\d+)$", raw)
    if ipv6_match:
        addr = ipv6_match.group(1)
        iface = ""
        if "%" in addr:
            addr, _, iface = addr.partition("%")
        return addr, ipv6_match.group(2), iface

    # Wildcard notation: *:port (some ss versions)
    wild_match = re.match(r"^\*:(\d+)$", raw)
    if wild_match:
        return "*", wild_match.group(1), ""

    # IPv4 with optional %iface: addr%iface:port or addr:port
    ipv4_match = re.match(r"^([^:%]+)(?:%([^:]+))?:(\d+)$", raw)
    if ipv4_match:
        return ipv4_match.group(1), ipv4_match.group(3), ipv4_match.group(2) or ""

    return None, None, ""


# Substituted with the package name. Deliberately not a ``str.format`` field:
# dpkg's own argument is ``-f=${Status}``, and formatting it would read
# ``{Status}`` as a placeholder and raise.
_PKG = "%PKG%"

# Package managers BOB knows how to interrogate, in the order they are tried.
#
# ``marker`` is the substring proving the package is installed; ``None`` means
# any output at all does (rpm, pacman and apk print the package on success and
# nothing on stdout when it is missing). Every entry is a scripting interface:
# `dpkg-query -W`, `rpm -q`, `pacman -Q` and `apk info -e` are all stable and
# locale-independent, unlike their display counterparts.
_PACKAGE_QUERIES: "tuple[tuple[str, tuple[str, ...], str | None], ...]" = (
    ("dpkg-query", ("-W", "-f=${Status}", _PKG), "install ok installed"),
    ("rpm",        ("-q", _PKG),                    None),   # RHEL, Fedora, openSUSE
    ("pacman",     ("-Q", _PKG),                    None),   # Arch
    ("apk",        ("info", "-e", _PKG),            None),   # Alpine
)

# A package each manager necessarily owns: the manager itself. Asking for it is
# how BOB checks that the query layer answers at all — see
# ``package_query_possible``.
_PACKAGE_SENTINELS = {
    "dpkg-query": "dpkg",
    "rpm":        "rpm",
    "pacman":     "pacman",
    "apk":        "apk-tools",
}


def package_query_possible() -> bool:
    """True when at least one supported package manager is available to ask.

    ``package_installed`` answers None in two situations a caller cannot tell
    apart: the package is genuinely absent, or **no package manager exists to
    ask**. Collapsing the second into the first makes BOB state a negative it
    never verified — "no microcode package installed" on a host where nothing
    could be queried. Gentoo, NixOS, Void, Slackware and minimal images all land
    there, and so does any distribution BOB has not met yet.

    A check that turns a None into an assertion must call this first and say
    "could not check" instead. Absence of evidence is not evidence of absence,
    and the report has to keep the difference.
    """
    global _PACKAGE_QUERY_STATE
    if _PACKAGE_QUERY_STATE is None:
        _PACKAGE_QUERY_STATE = any(
            _package_query_answers(tool, args, marker)
            for tool, args, marker in _PACKAGE_QUERIES
        )
    return _PACKAGE_QUERY_STATE


_PACKAGE_QUERY_STATE: "bool | None" = None


def _package_query_answers(tool: str, args: "tuple[str, ...]", marker: "str | None") -> bool:
    """True when *tool* is present AND its database answers a known-good query.

    Presence is not enough, and dpkg proves why: with an unreadable database it
    exits 1 with `no packages found matching <pkg>` — the *same* exit code and
    the *same* message as a package that is genuinely not installed. The tool
    itself erases the distinction, so it cannot be recovered from its output.

    What can be established is whether the layer works at all: ask for a package
    the manager necessarily owns — itself. A healthy dpkg answers `dpkg 1.22.6`
    on stdout; a broken one answers nothing. BOB does not trust a negative until
    it has shown it can produce a positive.
    """
    if not _command_exists(tool):
        return False
    sentinel = _PACKAGE_SENTINELS.get(tool)
    if sentinel is None:          # unknown manager: fall back to presence
        return True
    output = _run(tool, *(a.replace(_PKG, sentinel) for a in args))
    return bool(marker in output if marker else output.strip())


def package_installed(name: str) -> "str | None":
    """Name of the package manager that reports *name* installed, else None.

    ``dpkg-query`` alone meant every service read as NOT INSTALLED on any
    distribution without dpkg — the whole RHEL family, Arch, openSUSE and
    Alpine — with no error and no crash: the audit ran, printed a services
    section, and reported every entry absent. Measured on a Fedora container
    with httpd, vsftpd, memcached and mariadb-server installed and confirmed by
    ``rpm -q``: BOB saw none of them.

    Three checks asked this question with a private dpkg call each. One answer
    now, for the same reason the UFW rule grammar and the ``ss`` address column
    were unified — a rule kept in several copies is a rule that will disagree
    with itself.
    """
    for tool, args, marker in _PACKAGE_QUERIES:
        if not _command_exists(tool):
            continue
        output = _run(tool, *(a.replace(_PKG, name) for a in args))
        if marker is None:
            if output.strip():
                return tool
        elif marker in output:
            return tool
    return None


def path_exists(path: "Path") -> bool:
    """Whether *path* exists, without raising when the answer is off-limits.

    ``Path.exists()`` looks total but is not: it swallows ENOENT, ENOTDIR,
    EBADF and ELOOP and re-raises everything else, so a file under a directory
    the auditor cannot traverse raises PermissionError. One such directory
    (`/etc/ssh` at mode 0700) aborted the entire audit from an unguarded core
    collection — no report, no findings, exit 3 — because a service's port
    auto-detection asked whether its config file existed.

    Returning False here means "not usable from where BOB stands", which is the
    right answer for callers deciding whether to open something. Callers that
    must tell "absent" from "off-limits" have to probe the open itself; the
    distinction matters to a verdict, and never to a control-flow guard.
    """
    try:
        return path.exists()
    except OSError:
        return False


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
