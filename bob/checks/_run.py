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
from datetime import datetime
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


_UNIX_TS_RE = re.compile(r"^@(\d+)$")
_TEXT_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


#: `systemctl show --timestamp=unix` answers in whole seconds — measured on a
#: Debian 13 VM: `@1788960328`, no fractional part, from either the unix form
#: or the C-locale text form parsed below. `st_mtime` carries sub-second
#: precision. The systemd side is therefore always the *floor* of the real
#: moment, so a direct `mtime > applied` is biased by up to a second, and
#: always in the direction of announcing drift.
_APPLIED_RESOLUTION = 1.0


def config_drifted(newest_mtime: float, applied: float) -> bool:
    """Whether a config file is provably newer than the applied configuration.

    Found on a real Debian 13. `/etc/ssh/sshd_config` had mtime
    `1788960328.004764624`; `systemctl show ssh -p StateChangeTimestamp` said
    `@1788960328`. The administrator had edited the file and reloaded sshd —
    the correct sequence — and BOB announced *"sshd_config was modified at
    15:25, after sshd last applied its configuration at 15:25"*, muting every
    SSH finding below it as a description of the file rather than the service.
    Four milliseconds of measurement artefact, and both timestamps printed
    identical on screen.

    systemd told us a second, not a moment: the true apply time lies anywhere
    in `[applied, applied + 1)`. A file is provably newer only when it clears
    the whole interval. Nothing real is lost — a drift worth reporting is
    minutes or hours old, never milliseconds — and the alternative is a caveat
    that fires on people doing exactly the right thing, which is the way to get
    it switched off.
    """
    return newest_mtime - applied >= _APPLIED_RESOLUTION


def unit_config_applied_at(name: str, timeout: int = _CMD_TIMEOUT) -> "float | None":
    """Epoch seconds when systemd last (re)applied this unit's configuration.

    ``StateChangeTimestamp``, and deliberately not ``ActiveEnterTimestamp`` or
    ``ExecMainStartTimestamp``. Established against systemd on a disposable
    user unit rather than assumed: after ``systemctl reload``, with the main
    PID unchanged, only StateChangeTimestamp moved — the other two still
    reported the original start. An administrator who edits a config file and
    reloads correctly is the ordinary case, and comparing against a start
    timestamp would report every one of them as drifted. A guard that fires on
    people doing the right thing gets switched off.

    ``--timestamp=unix`` needs systemd 248; older builds fall back to the
    C-locale text form, parsed as naive local time — the same clock the file
    mtimes are read on, so the comparison stays consistent.

    Returns None when systemd could not answer, which the callers treat as
    "unknown" rather than "no drift".
    """
    raw = run_result(
        "systemctl", "show", name, "-p", "StateChangeTimestamp",
        "--value", "--timestamp=unix", timeout=timeout,
    ).stdout.strip()

    unix = _UNIX_TS_RE.match(raw)
    if unix:
        return float(unix.group(1))

    if not raw:
        raw = run_result(
            "systemctl", "show", name, "-p", "StateChangeTimestamp", "--value",
            timeout=timeout,
        ).stdout.strip()

    text = _TEXT_TS_RE.search(raw)
    if not text:
        return None
    try:
        return datetime.strptime(text.group(1), "%Y-%m-%d %H:%M:%S").timestamp()
    except (ValueError, OSError):
        return None


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
# ``marker`` is the substring proving the package is installed. ``None`` means
# any output at all does — true for ``pacman -Q`` and ``apk info -e``, which
# print nothing on stdout when the package is missing (measured 2026-09-08 in
# archlinux:latest and alpine:latest).
#
# It was **not** true for rpm, and that was the entry it was written for.
# ``rpm -q nosuchpackage`` prints *"package nosuchpackage is not installed"* on
# **stdout** and exits 1, so "any output counts" made every query answer yes:
# on RHEL, Fedora and openSUSE ``package_installed`` reported every package
# installed, including names that exist nowhere — ``rpm -q amd64-microcode``,
# a Debian package, answered "installed" on a Fedora container.
#
# v0.15.2 had replaced "everything absent outside Debian" with the same fault
# inverted for the rpm family, and nothing noticed because the failure mode is
# silence: a check that believes a package is present simply stops asking.
#
# ``by_exit`` takes the verdict from the exit status instead, with ``--quiet``
# so rpm says nothing at all. Every entry remains a scripting interface —
# ``dpkg-query -W``, ``rpm -q``, ``pacman -Q`` and ``apk info -e`` are stable
# and locale-independent, unlike their display counterparts.
_PACKAGE_QUERIES: "tuple[tuple[str, tuple[str, ...], str | None, bool], ...]" = (
    ("dpkg-query", ("-W", "-f=${Status}", _PKG), "install ok installed", False),
    ("rpm",        ("-q", "--quiet", _PKG),      None,                   True),   # RHEL, Fedora, openSUSE
    ("pacman",     ("-Q", _PKG),                 None,                   False),  # Arch
    ("apk",        ("info", "-e", _PKG),         None,                   False),  # Alpine
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
            _package_query_answers(tool, args, marker, by_exit)
            for tool, args, marker, by_exit in _PACKAGE_QUERIES
        )
    return _PACKAGE_QUERY_STATE


_PACKAGE_QUERY_STATE: "bool | None" = None


def _package_query_answers(tool: str, args: "tuple[str, ...]", marker: "str | None",
                           by_exit: bool = False) -> bool:
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
    result = run_result(tool, *(a.replace(_PKG, sentinel) for a in args))
    if by_exit:
        return result.ok
    return bool(marker in result.stdout if marker else result.stdout.strip())


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
    for tool, args, marker, by_exit in _PACKAGE_QUERIES:
        if not _command_exists(tool):
            continue
        result = run_result(tool, *(a.replace(_PKG, name) for a in args))
        if by_exit:
            if result.ok:
                return tool
        elif marker is None:
            if result.stdout.strip():
                return tool
        elif marker in result.stdout:
            return tool
    return None


# ---------------------------------------------------------------------------
# The installing twin of _PACKAGE_QUERIES
# ---------------------------------------------------------------------------
#
# v0.15.2 taught BOB to *ask* five package managers instead of dpkg alone,
# because a dpkg-only query reported every service absent on four distributions
# out of five. The advice half of that lesson was never learned: eighteen
# findings told the operator to run ``sudo apt install …`` whatever host they
# were on. The verdict had been made portable; the remedy attached to it had
# not, so BOB was correct about the problem and wrong about the fix.
#
# Measured in containers rather than recalled, because the recalled version was
# wrong in three places (2026-09-08, fedora:latest, archlinux:latest,
# alpine:latest — see tests/test_v0170_package_names.py for the probe):
#
#   * ``sudo dnf install auditd`` installs nothing. The package is ``audit``.
#   * ``sudo pacman -S aide`` fails: aide is not in Arch's repositories at all.
#   * ``libpam-pwquality`` is Debian's spelling; everyone else calls the
#     package ``libpwquality``.
#
# So a synthesised command is worse than no command: it is a specific,
# confident instruction that does nothing, and the operator has no reason to
# doubt it. Where the name is not known, BOB says what it is looking for and
# admits the gap.

#: Substituted with the space-joined package list.
_PKGS = "%PKGS%"

#: Package managers BOB knows how to *install* with, in the order tried.
#: Ordered so a Debian host that also has ``dnf`` installed still gets apt.
#: ``-y`` where the manager needs it: ``--fix --apply`` runs these unattended,
#: and a command that stops to ask a question applies nothing (v0.16.4).
_INSTALL_MANAGERS: "tuple[tuple[str, str], ...]" = (
    ("apt",     f"sudo apt install -y {_PKGS}"),
    ("apt-get", f"sudo apt-get install -y {_PKGS}"),
    ("dnf",     f"sudo dnf install -y {_PKGS}"),
    ("yum",     f"sudo yum install -y {_PKGS}"),
    ("pacman",  f"sudo pacman -S --noconfirm {_PKGS}"),
    ("zypper",  f"sudo zypper --non-interactive install {_PKGS}"),
    # apk does not prompt (measured: `apk add logrotate </dev/null` exits 0 in
    # alpine:latest), but it accepts the flag, and carrying it keeps every row
    # of this table answerable by the same rule instead of one exception.
    ("apk",     f"sudo apk add --no-interactive {_PKGS}"),
)

#: What each logical package is called per install manager.
#:
#: ``None`` means **BOB does not know**, which is not the same as "not needed":
#: either the package is absent from that distribution's repositories, or it
#: exists under a name nobody measured. Both must produce advice, never a
#: command.
#:
#: ``yum`` inherits from ``dnf`` and ``apt-get`` from ``apt`` (same
#: repositories); ``zypper`` is declared only where the name was identical
#: everywhere it *was* measured, because openSUSE was not one of the probes and
#: guessing from the RHEL column is how the three errors above happened.
_PACKAGE_NAMES: "dict[str, dict[str, str | None]]" = {
    # Identical on Debian, Fedora, Arch and Alpine — safe everywhere.
    "fail2ban":      {"apt": "fail2ban",      "dnf": "fail2ban",  "pacman": "fail2ban",  "apk": "fail2ban",  "zypper": "fail2ban"},
    "logrotate":     {"apt": "logrotate",     "dnf": "logrotate", "pacman": "logrotate", "apk": "logrotate", "zypper": "logrotate"},
    "smartmontools": {"apt": "smartmontools", "dnf": "smartmontools", "pacman": "smartmontools", "apk": "smartmontools", "zypper": "smartmontools"},
    "clamav":        {"apt": "clamav",        "dnf": "clamav",    "pacman": "clamav",    "apk": "clamav",    "zypper": "clamav"},
    "ufw":           {"apt": "ufw",           "dnf": "ufw",       "pacman": "ufw",       "apk": "ufw",       "zypper": None},
    "borgmatic":     {"apt": "borgmatic",     "dnf": "borgmatic", "pacman": "borgmatic", "apk": "borgmatic", "zypper": None},

    # Measured differences.
    "auditd":        {"apt": "auditd",        "dnf": "audit",     "pacman": "audit",     "apk": "audit",     "zypper": None},
    "pwquality":     {"apt": "libpam-pwquality", "dnf": "libpwquality", "pacman": "libpwquality", "apk": "libpwquality", "zypper": None},
    "borgbackup":    {"apt": "borgbackup",    "dnf": "borgbackup", "pacman": "borg",     "apk": "borgbackup", "zypper": None},
    "clamav-daemon": {"apt": "clamav-daemon", "dnf": "clamd",     "pacman": None,        "apk": "clamav-daemon", "zypper": None},
    "rkhunter":      {"apt": "rkhunter",      "dnf": "rkhunter",  "pacman": "rkhunter",  "apk": None,        "zypper": None},
    "audit-plugins": {"apt": "audispd-plugins", "dnf": "audispd-plugins", "pacman": "audispd-plugins", "apk": None, "zypper": None},
    "apparmor":      {"apt": "apparmor",      "dnf": None,        "pacman": "apparmor",  "apk": "apparmor",  "zypper": None},

    # Debian-only, or drifting with the distribution's own version.
    #
    # ``iptables`` is not a missing measurement: Fedora ships it under a
    # different package (``iptables-nft`` / ``iptables-legacy``) and which one
    # is right depends on the host's firewall backend. That is a decision, not
    # a name lookup, so BOB does not make it.
    "apparmor-utils":    {"apt": "apparmor-utils"},
    "apparmor-profiles": {"apt": "apparmor-profiles apparmor-profiles-extra"},
    "aide":              {"apt": "aide", "dnf": "aide"},
    "iptables":          {"apt": "iptables", "pacman": "iptables", "apk": "iptables"},
    "auto-updates":      {"apt": "unattended-upgrades"},

    # CPU microcode. Measured the same day and for the same reason: the
    # firmware check asked ``rpm -q intel-microcode`` on Fedora and ``pacman -Q
    # intel-microcode`` on Arch, where those packages do not exist under those
    # names, and turned the empty answer into "no microcode package installed"
    # plus a one-point deduction. That is a false *verdict*, on every host of
    # two distribution families, not merely unusable advice — and the docstring
    # of the query helper had named ``microcode_ctl`` since v0.15.2 while the
    # list of names it was given stayed Debian's.
    "microcode-intel":   {"apt": "intel-microcode", "dnf": "microcode_ctl", "pacman": "intel-ucode", "apk": "intel-ucode"},
    "microcode-amd":     {"apt": "amd64-microcode", "dnf": "amd-ucode-firmware", "pacman": "amd-ucode", "apk": "amd-ucode"},
}


def package_name_candidates(logical: str) -> "tuple[str, ...]":
    """Every name *logical* is known by, across all managers.

    For asking rather than installing. A query costs nothing and cannot be
    wrong: ``intel-ucode`` is simply absent on Debian. Asserting *absence* is
    what needs the manager to be known — see :func:`package_name`.
    """
    names = _PACKAGE_NAMES.get(logical)
    if names is None:
        raise KeyError(f"no package mapping declared for {logical!r}")
    seen: "dict[str, None]" = {}
    for value in names.values():
        if value:
            for part in value.split():
                seen[part] = None
    return tuple(seen)

#: ``yum`` reads the same repositories as ``dnf``; ``apt-get`` the same as
#: ``apt``. Declared once rather than duplicated down the table.
_MANAGER_ALIASES = {"yum": "dnf", "apt-get": "apt"}


def detect_install_manager() -> str:
    """The package manager this host installs with, or ``""`` when unknown.

    Deliberately separate from :func:`package_installed`, which answers with the
    *query* tool: a host has ``rpm`` for asking and ``dnf`` for installing, and
    ``rpm`` cannot tell Fedora from openSUSE while ``dnf`` and ``zypper`` can.
    """
    for tool, _template in _INSTALL_MANAGERS:
        if _command_exists(tool):
            return tool
    return ""


def package_name(logical: str, manager: str) -> "str | None":
    """What *logical* is called for *manager*, or None when BOB does not know."""
    names = _PACKAGE_NAMES.get(logical)
    if names is None:
        raise KeyError(f"no package mapping declared for {logical!r}")
    return names.get(_MANAGER_ALIASES.get(manager, manager))


def install_command(*logical: str, manager: "str | None" = None) -> "str | None":
    """The command that installs *logical* here, or None when BOB cannot say.

    None is a verdict, not a failure: the caller must then leave the finding
    without a command, so it is reported as manual work rather than as a fix
    that ``--fix --apply`` would run and count. A command that installs nothing
    still exits 0 on some managers, which would have BOB report success.
    """
    mgr = detect_install_manager() if manager is None else manager
    if not mgr:
        return None
    names = [package_name(name, mgr) for name in logical]
    if any(n is None for n in names):
        return None
    template = dict(_INSTALL_MANAGERS).get(mgr)
    if template is None:
        return None
    return template.replace(_PKGS, " ".join(n for n in names if n))


def install_advice(t, *logical: str, manager: "str | None" = None) -> str:
    """Prose for the case :func:`install_command` cannot answer.

    Names the Debian package as an illustration and says plainly that the name
    on this host is not known, rather than transliterating it into a command
    that would fail. The operator's own package manager can search for it; BOB
    guessing on their behalf is what this whole module exists to stop.
    """
    mgr = detect_install_manager() if manager is None else manager
    example = " ".join(
        n for n in (package_name(name, "apt") for name in logical) if n
    ) or " ".join(logical)
    if not mgr:
        return t("install.no_manager", example=example)
    return t("install.unknown_name", manager=mgr, example=example)


def install_fix(t, detail: "str | None", *logical: str,
                then: str = "", then_apt: str = "") -> "tuple[str | None, str]":
    """``(cmd, detail)`` for a finding whose remedy is "install this package".

    The single shape every call site uses, so the decision *not* to invent a
    command is taken in one place. When the name is unknown the command becomes
    None — which puts the finding in the manual bucket rather than among the
    fixes ``--fix --apply`` will run and count — and the reason is appended to
    the detail, where the operator is already reading.

    *then* is a follow-up command that works anywhere (``systemctl enable`` and
    friends). *then_apt* is one that does **not**: ``aideinit``,
    ``pam-auth-update`` and ``dpkg-reconfigure`` are Debian's own tools, and
    three findings appended them to advice they were about to hand a Fedora or
    Arch operator. Where a *then_apt* is declared and the host does not install
    with apt, there is no command — half a remedy is not a remedy.
    """
    mgr = detect_install_manager()
    cmd = install_command(*logical, manager=mgr)
    if cmd and then_apt and _MANAGER_ALIASES.get(mgr, mgr) != "apt":
        cmd = None
    if cmd:
        for suffix in (then, then_apt):
            if suffix:
                cmd = f"{cmd} && {suffix}"
        # Never None: ``Finding.detail`` is typed ``str`` and sanitised
        # unconditionally, so a None reaches ``_flatten`` and raises.
        return cmd, detail or ""
    advice = install_advice(t, *logical, manager=mgr)
    return None, f"{detail} {advice}" if detail else advice


# ---------------------------------------------------------------------------
# PAM stacks, which are not called the same thing twice
# ---------------------------------------------------------------------------
#
# The package layer above fixed *what BOB advises*. This fixes *what BOB reads*,
# and it is the same fault one level down: `/etc/pam.d/common-password` is
# Debian's name for the password stack and exists nowhere else. The password
# policy check read it, caught the OSError, left the module unset and concluded
# "no PAM quality module" — a WARN and a deduction — on every Fedora, RHEL,
# openSUSE and Arch host, having read nothing at all.
#
# Measured 2026-09-08 in fedora:latest, archlinux:latest and alpine:latest:
#
#   Debian/Ubuntu  common-password, common-session, common-auth
#   Fedora/RHEL    system-auth, password-auth  (+ postlogin for sessions)
#   Arch           system-auth
#   Alpine         nothing at all — no /etc/pam.d, and no /etc/login.defs
#
# Alpine is the case that matters most for honesty: it does not use PAM, so
# "no quality module configured in PAM" is not a finding about the host's
# hardening. It is a statement about a mechanism the host does not have, and
# BOB must say it could not establish the answer rather than deduct a point.
_PAM_STACKS: "dict[str, tuple[str, ...]]" = {
    # Where a password-quality module (pam_pwquality, pam_cracklib) is stacked.
    "password": (
        "/etc/pam.d/common-password",   # Debian, Ubuntu, Mint, Kali
        "/etc/pam.d/system-auth",       # Fedora, RHEL, Arch, openSUSE
        "/etc/pam.d/password-auth",     # Fedora, RHEL — the remote-login stack
    ),
    # Where session modules (pam_umask) are stacked.
    "session": (
        "/etc/pam.d/common-session",    # Debian, Ubuntu, Mint, Kali
        "/etc/pam.d/system-auth",       # Fedora, RHEL, Arch, openSUSE
        "/etc/pam.d/postlogin",         # Fedora, RHEL — runs after every login
    ),
}


def pam_stack_paths(concern: str) -> "tuple[Path, ...]":
    """Every file *concern* may be configured in, on any known distribution."""
    from pathlib import Path as _Path

    names = _PAM_STACKS.get(concern)
    if names is None:
        raise KeyError(f"no PAM stack declared for {concern!r}")
    return tuple(_Path(n) for n in names)


def read_pam_stack(concern: str,
                   paths: "tuple[Path, ...] | None" = None) -> "tuple[str, bool]":
    """``(joined text, established)`` for the *concern* stack on this host.

    ``established`` is False when not one of the candidate files could be read —
    either none exists (Alpine, which has no PAM) or every one that does is
    off-limits. The caller must then report that it could not check, never that
    the thing is absent: this is the distinction v0.15.2 drew for packages and
    v0.16.0 drew for the score, applied to the files a verdict is read from.

    A file that exists but cannot be opened counts as *not established* too,
    for the same reason: unreadable is not empty.
    """
    chunks: "list[str]" = []
    established = False
    for path in (paths if paths is not None else pam_stack_paths(concern)):
        try:
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
            established = True
        except OSError:
            continue
    return "\n".join(chunks), established


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


def path_is_file(path: "Path") -> bool:
    """Whether *path* is a regular file, without raising when it is off-limits.

    v0.16.2 — the twin of :func:`path_exists`, and it was missing. ``is_file()``
    ignores the same four errnos as ``exists()`` and re-raises the rest, so an
    absolute path under an untraversable directory raises ``PermissionError``.

    That killed the whole audit, not a section: service detection probes an
    absolute binary path from the always-on core, which ``_sec``'s v0.14.1
    fault isolation deliberately does not cover. Making ``/usr/local/bin``
    untraversable produced ``[Errno 13] Permission denied:
    '/usr/local/bin/gitea'``, exit 3, no report — the exact shape v0.15.2 wrote
    ``path_exists`` to close, reachable through the one method it did not wrap.

    False means "not usable from where BOB stands", which is the right answer
    for a caller deciding whether a service is installed: a binary it cannot
    stat is a binary it cannot audit.
    """
    try:
        return path.is_file()
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
