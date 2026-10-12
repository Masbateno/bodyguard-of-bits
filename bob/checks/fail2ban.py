"""
Fail2ban audit check for BOB (CHECK 29).

Checks whether fail2ban is installed, its service is running, and at least
one jail is active.  An SSH-specific jail is highlighted separately.

Score impact:
  - Not installed:            INFO  (optional but recommended)
  - Installed, service down:  WARN  −1 pt
  - Running but no jails:     WARN  −1 pt
  - Running with jails:       OK

Split into:
  1. Fail2banSnapshot.from_system() — collects state via fail2ban-client / systemctl.
  2. check_fail2ban(snapshot, t)    — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
from pathlib import Path

from dataclasses import dataclass, field

from bob.checks._run import (
    TranslationFunc, _command_exists, _identity_t, _run, install_fix, service_enable_cmd,
    service_restart_cmd,
    unit_active_state,
)
from bob.scoring import CheckResult

# Jail names that protect SSH (checked via substring match)
_SSH_JAIL_PATTERNS = ("sshd", "ssh")

#: v0.24.4 — the daemons that write the log files a file-backed jail reads.
#: Without one of them running, sshd's failures reach the journal only.
_SYSLOG_DAEMONS = ("rsyslog", "syslog-ng", "syslog", "sysklogd", "busybox-syslogd")

@dataclass
class Fail2banSnapshot:
    """
    State collected from the system about fail2ban.

    Args:
        installed:       True if fail2ban-client is present.
        service_active:  True if the fail2ban service is running, None when
                         neither systemd nor fail2ban-client could be asked.
        active_jails:    List of active jail names reported by fail2ban-client.
        ssh_jail:        Name of the SSH jail if one is active, else "".
        status_readable: False when fail2ban-client could not be queried.
    """
    installed:      bool        = False
    service_active: "bool | None" = False
    active_jails:   list[str]   = field(default_factory=list)
    ssh_jail:       str         = ""
    # False when `fail2ban-client status` returned no jail list at all.
    status_readable: bool      = True
    #: v0.24.4 — what the SSH jail reads: the files of its ``File list:`` and
    #: whether it has ``Journal matches:``.
    ssh_jail_files:   tuple     = ()
    ssh_jail_journal: bool      = False
    #: Whether a syslog daemon is running to write those files; None when no
    #: init system could say.
    syslog_active:  "bool | None" = None
    #: Whether the systemd journal is there to read instead.
    journal_available: bool    = False
    #: Whether the end of a jail file holds an sshd message — evidence that
    #: sshd's messages reach it; None when no file could be read. Where the
    #: journal has sshd's latest message, that message is the evidence.
    ssh_jail_fed:   "bool | None" = None
    #: The files hold sshd messages, but not the latest one the journal has.
    ssh_jail_stale: bool = False
    #: The files lack sshd's latest failed login, logged since rsyslog started.
    ssh_jail_misses_failures: bool = False
    #: The ``/etc/fail2ban/jail.d/*.local`` files, read last and in name
    #: order — the last one that sets the jail's backend wins.
    jail_d_locals:  tuple       = ()

    @classmethod
    def from_system(cls) -> "Fail2banSnapshot":
        """Collect fail2ban state from the live system. Never raises."""
        snap = cls()

        if not _command_exists("fail2ban-client"):
            return snap

        snap.installed = True

        # Service status via systemctl, falling back to fail2ban's own answer
        # whenever systemd gives none — a present but failing systemctl used to
        # short-circuit straight to "inactive", warning that a running
        # fail2ban was down.
        state = unit_active_state("fail2ban") if _command_exists("systemctl") else None
        if state is not None:
            snap.service_active = state == "active"
        else:
            # Fallback: try fail2ban-client ping (prints "pong" when running).
            #
            # Same collapse as auditd, same cause: `or ""` made "the client
            # answered nothing" indistinguishable from "the client said it is
            # down". With neither systemd nor fail2ban-client able to answer,
            # BOB warned that a running fail2ban was stopped.
            ping = _run("fail2ban-client", "ping")
            snap.service_active = ("pong" in ping.lower()) if ping else None

        if not snap.service_active:
            return snap

        # Active jails.
        #
        # A successful `fail2ban-client status` always carries a "Jail list:"
        # line, even when the list is empty. Output without it means the query
        # failed — refused, timed out, or the socket was not ready — which is
        # not the same statement as "this host runs fail2ban with no jails",
        # and used to cost it a point all the same.
        status_out = _run("fail2ban-client", "status") or ""
        snap.status_readable = any(
            "jail list" in line.lower() for line in status_out.splitlines()
        )
        snap.active_jails = _parse_jails(status_out)

        # Detect SSH jail
        snap.ssh_jail = next(
            (jail for jail in snap.active_jails
             if any(pat in jail.lower() for pat in _SSH_JAIL_PATTERNS)),
            "",
        )

        # v0.24.4: an SSH jail that reads a file nothing writes is active and
        # blind. Measured on a Raspberry Pi (trixie, no rsyslog): with the jail
        # on /var/log/auth.log, two failed logins left "Total failed: 0" while
        # BOB reported "SSH brute-force protection active".
        if snap.ssh_jail:
            jail_status = _run("fail2ban-client", "status", snap.ssh_jail) or ""
            snap.ssh_jail_files, snap.ssh_jail_journal = _parse_jail_sources(jail_status)
            if snap.ssh_jail_files and not snap.ssh_jail_journal:
                snap.syslog_active = _syslog_active()
                snap.journal_available = _command_exists("journalctl")
                entries = _sshd_entries() if snap.journal_available else []
                entry = entries[-1] if entries else None
                failures = [f for f in _latest_sshd_failures(entries).values()
                            if not _syslog_started_after(f)]
                latest = _sshd_needle(entry)
                snap.ssh_jail_fed = _jail_files_fed(snap.ssh_jail_files, latest)
                if snap.ssh_jail_fed is True and (latest is None or _syslog_started_after(entry)):
                    # Fed once, not shown fed by the routing in force now: with
                    # no journal there is only an old line to go on.
                    snap.ssh_jail_fed = None
                snap.ssh_jail_stale = (latest is not None and snap.ssh_jail_fed is False
                                       and _jail_files_fed(snap.ssh_jail_files) is True)
                if failures:
                    # Failed logins routed by today's routing, the latest of
                    # each kind: that, above all, is what the file must hold.
                    held = [_jail_files_fed(snap.ssh_jail_files, _sshd_needle(f)) for f in failures]
                    snap.ssh_jail_fed = None if None in held else all(held)
                    snap.ssh_jail_misses_failures = snap.ssh_jail_fed is False
                    snap.ssh_jail_stale = False
                try:
                    snap.jail_d_locals = tuple(sorted(
                        n for n in os.listdir("/etc/fail2ban/jail.d") if n.endswith(".local")))
                except OSError:
                    snap.jail_d_locals = ()

        return snap


def _parse_jail_sources(jail_status: str) -> "tuple[tuple, bool]":
    """``fail2ban-client status <jail>`` → (files read, reads the journal).

    Measured on trixie: ``|  `- File list:\t/var/log/auth.log`` for a polling
    or pyinotify backend, ``|  `- Journal matches:\t_SYSTEMD_UNIT=…`` for the
    systemd backend."""
    files: tuple = ()
    journal = False
    for line in jail_status.splitlines():
        low = line.lower()
        if "file list:" in low:
            files = tuple(line.split(":", 1)[1].split())
        elif "journal matches:" in low:
            journal = True
    return files, journal


#: An sshd message as syslog writes it: ``sshd[812]:``, ``sshd-session[812]:``.
_SSHD_LINE = re.compile(rb"\bsshd(?:-session)?\[\d+\]:")
_JAIL_TAIL_BYTES = 256 * 1024


#: What fail2ban's sshd filter is there to count, in sshd's own wording.
_SSHD_FAILURE = re.compile(r"Failed (?:password|publickey|keyboard-interactive|none)|[Ii]nvalid user"
                           r"|authentication failure|by (?:invalid|authenticating) user"
                           r"|maximum authentication attempts")


def _sshd_entries(count: int = 500) -> "list[dict]":
    """sshd's latest journal entries older than five seconds, oldest first.

    v0.24.4 — an sshd message in the file proves it was fed once, not that it
    still is: routing changed afterwards, the old lines stay. The journal holds
    what sshd said last; a file still fed holds it too. Five seconds leave the
    syslog daemon time to write the message out.
    """
    out = _run("journalctl", "-o", "json", "-n", str(count), "--no-pager", "--until", "-5s",
               "_COMM=sshd", "_COMM=sshd-session")
    entries = []
    for line in out.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


def _latest_sshd_entry() -> "dict | None":
    """sshd's latest journal entry older than five seconds, or None."""
    entries = _sshd_entries()
    return entries[-1] if entries else None


def _failure_kind(message: str) -> "str | None":
    """Which kind of failed login *message* is, or None for none."""
    if not _SSHD_FAILURE.search(message):
        return None
    if re.search(r"[Ii]nvalid user", message):
        return "invalid user"
    if "authentication failure" in message:
        return "pam"
    if "maximum authentication attempts" in message:
        return "max attempts"
    return "user"           # an existing user's password or key refused


def _latest_sshd_failures(entries: "list[dict]") -> "dict[str, dict]":
    """The latest failed login of each kind fail2ban's sshd filter counts.

    v0.24.4 — measured on Mint: rsyslog sending "invalid user" lines to
    another file and the rest of sshd's to auth.log. The jail on auth.log
    counted 0 failures; auth.log held sshd's latest message (a session
    closing) and BOB said OK. What the jail needs is the failures — every kind:
    with "invalid user" still routed away, the latest failure was an existing
    user's refused key, auth.log held it, and BOB said OK again.
    """
    kinds: dict = {}
    for entry in entries:                       # oldest first: the last one wins
        message = entry.get("MESSAGE")
        kind = _failure_kind(message) if isinstance(message, str) else None
        if kind:
            kinds[kind] = entry
    return kinds


def _sshd_needle(entry: "dict | None") -> "bytes | None":
    """The entry as syslog writes it after the tag: ``[2536]: Server listening on :: port 22.``"""
    if entry is None:
        return None
    pid, message = entry.get("SYSLOG_PID") or entry.get("_PID"), entry.get("MESSAGE")
    if not isinstance(pid, str) or not isinstance(message, str) or not message:
        return None
    return f"[{pid}]: {message}".encode()


def _latest_sshd_message() -> "bytes | None":
    """sshd's latest journal message, as the jail's file would hold it."""
    return _sshd_needle(_latest_sshd_entry())


def _boot_id() -> "str | None":
    """This boot's id as the journal writes it (32 hex digits, no dashes)."""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(errors="replace").strip().replace("-", "")
    except OSError:
        return None


def _syslog_started_after(entry: dict) -> bool:
    """Whether the running syslog daemon started after *entry* — or that cannot
    be ruled out.

    v0.24.4 — the routing that sent sshd's last message to the file may have
    changed since, and with no sshd message after it, the file still holds the
    latest one. A syslog daemon reads its routing when it starts (logrotate's
    HUP reopens files, it does not re-route): a message logged after the running
    daemon started was routed by the routing in force now. Measured on Mint:
    rsyslog re-routed and restarted after sshd's last message, nothing from sshd
    since — the file held the journal's latest message and BOB said OK.
    """
    try:
        logged = int(entry["__MONOTONIC_TIMESTAMP"])
    except (KeyError, TypeError, ValueError):
        return True
    boot = _boot_id()
    if boot is None or entry.get("_BOOT_ID") != boot:
        return True                       # logged before this boot's daemon started
    out = _run("systemctl", "show", "-p", "Id", "-p", "ActiveState", "-p", "ActiveEnterTimestampMonotonic",
               *(f"{name}.service" for name in _SYSLOG_DAEMONS))
    starts = []
    for block in out.split("\n\n"):
        fields = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if fields.get("ActiveState") != "active":
            continue
        if fields.get("Id") != "rsyslog.service":
            # Measured: syslog-ng re-routes on reload, its start time unchanged.
            # Only rsyslog was measured to need a restart (a HUP re-routed
            # nothing on Mint) — any other daemon's routing cannot be dated.
            return True
        try:
            starts.append(int(fields.get("ActiveEnterTimestampMonotonic", "")))
        except ValueError:
            return True
    return not starts or max(starts) > logged


def _jail_files_fed(files: tuple, latest: "bytes | None" = None) -> "bool | None":
    """True when the end of a jail file holds an sshd message — *latest*, when
    the journal gave one — False when the files were read and none does, None
    when none could be read.

    v0.24.4 — measured on Mint 22.3 with rsyslog running: a jail on a file
    rsyslog does not write counted 0 of two failed logins, and BOB said
    "SSH brute-force protection active" because a syslog daemon ran. The same
    jail on /var/log/auth.log, where rsyslog sends sshd's messages, counted 2.
    Only regular files are opened: a FIFO would block the audit.
    """
    tails = []
    for path in files:
        try:
            if not stat.S_ISREG(os.stat(path).st_mode):
                continue
            with open(path, "rb") as fh:
                size = fh.seek(0, os.SEEK_END)
                fh.seek(max(0, size - _JAIL_TAIL_BYTES))
                tails.append(fh.read(_JAIL_TAIL_BYTES))
        except OSError:
            continue
    if not tails:
        return None
    if latest is not None:
        return any(latest in tail for tail in tails)
    return any(_SSHD_LINE.search(tail) for tail in tails)


def _syslog_active() -> "bool | None":
    """True when a syslog daemon runs, False when every init answer says none
    does, None when no init system could say (an unknown OpenRC service)."""
    states = [unit_active_state(name) for name in _SYSLOG_DAEMONS]
    if "active" in states:
        return True
    if all(state is not None for state in states):
        return False
    return None

def _parse_jails(status_output: str) -> list[str]:
    """
    Parse jail names from ``fail2ban-client status`` output.

    Expected format::

        Status
        |- Number of jail:      2
        `- Jail list:   sshd, nginx-http-auth

    Returns a list of jail names (stripped), or [] if parsing fails.
    """
    for line in status_output.splitlines():
        lower = line.lower()
        if "jail list" in lower and ":" in line:
            _, _, value = line.partition(":")
            jails = [j.strip() for j in value.split(",") if j.strip()]
            return jails
    return []

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_fail2ban(snapshot: Fail2banSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Analyse Fail2ban snapshot and return findings.

    Findings:
      - Not installed:           INFO  (no deduction — optional tool)
      - Service not running:     WARN  −1 pt
      - No active jails:         WARN  −1 pt
      - Running with jails:      OK
      - SSH jail active:         OK (additional finding)
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.installed:
        _cmd, _detail = install_fix(_t, _t("fail2ban.not_installed_detail"), "fail2ban")
        result.info(
            message=_t("fail2ban.not_installed"),
            detail=_detail,
            cmd=_cmd,
            key="fail2ban.not_installed",
        )
        return result

    if snapshot.service_active is None:
        result.info(
            message=_t("fail2ban.state_unknown"),
            key="fail2ban.state_unknown",
        )
        return result

    if snapshot.service_active is False:
        result.warn_with_deduction(
            key="fail2ban.service_inactive",
            message=_t("fail2ban.service_inactive"),
            reason=_t("fail2ban.service_inactive_reason"),
            points=1,
            detail=_t("fail2ban.service_inactive_detail"),
            cmd=service_enable_cmd("fail2ban"),
            nature="action",
        )
        return result

    if not snapshot.status_readable:
        # No jail list came back at all: the query failed. That is not the same
        # statement as "fail2ban is running with no jails", and it used to carry
        # the same warning and the same deduction.
        result.info(
            message=_t("fail2ban.status_unreadable"),
            detail=_t("fail2ban.status_unreadable_detail"),
            key="fail2ban.status_unreadable",
        )
        return result

    if not snapshot.active_jails:
        result.warn_with_deduction(
            key="fail2ban.no_jails",
            message=_t("fail2ban.no_jails"),
            reason=_t("fail2ban.no_jails_reason"),
            points=1,
            detail=_t("fail2ban.no_jails_detail"),
            # v0.16.4 — was `fail2ban-client status`, which reports the jail
            # count the message has just given: a diagnostic that restates the
            # finding tells the operator nothing they did not know. This names
            # the one jail the detail asks them to enable, and doubles as their
            # verification afterwards — "does not exist" before the edit, a
            # status block after it.
            cmd="sudo fail2ban-client status sshd",
            cmd_type="check",
            nature="action",
        )
        return result

    # Running with at least one jail
    jail_count = len(snapshot.active_jails)
    result.ok(
        message=_t("fail2ban.active", count=jail_count),
        key="fail2ban.active",
    )

    if snapshot.ssh_jail and snapshot.ssh_jail_files and not snapshot.ssh_jail_journal \
            and snapshot.syslog_active is False:
        # v0.24.4: the jail reads files no syslog daemon writes — failed
        # logins never reach it. On systemd the jail can read the journal
        # instead; elsewhere starting a syslog daemon is the operator's call.
        jail = snapshot.ssh_jail
        files = ", ".join(snapshot.ssh_jail_files)
        cmd = None
        if snapshot.journal_available:
            name = _override_name(_safe_name(jail), snapshot.jail_d_locals)
            cmd = (f"printf '[%s]\\nbackend = systemd\\n' {shlex.quote(jail)} | "
                   f"sudo tee /etc/fail2ban/jail.d/{name} && "
                   f"{service_restart_cmd('fail2ban')}")
        result.warn_with_deduction(
            key="fail2ban.ssh_jail_blind",
            message=_t("fail2ban.ssh_jail_blind", jail=jail, files=files),
            reason=_t("fail2ban.ssh_jail_blind_reason"),
            points=1,
            detail=_t("fail2ban.ssh_jail_blind_detail", jail=jail, files=files),
            cmd=cmd,
            nature="action",
        )
    elif snapshot.ssh_jail and snapshot.ssh_jail_files and not snapshot.ssh_jail_journal \
            and snapshot.ssh_jail_fed is False:
        # A syslog daemon running is no proof it writes this file: the file
        # holds no sshd message. Said, not credited as protection.
        files = ", ".join(snapshot.ssh_jail_files)
        tvars = {"jail": snapshot.ssh_jail, "files": files}
        if snapshot.ssh_jail_misses_failures:
            result.info(
                message=_t("fail2ban.ssh_jail_misses_failures", jail=snapshot.ssh_jail, files=files),
                key="fail2ban.ssh_jail_misses_failures",
                template_vars=tvars,
            )
        elif snapshot.ssh_jail_stale:
            result.info(
                message=_t("fail2ban.ssh_jail_file_stale", jail=snapshot.ssh_jail, files=files),
                key="fail2ban.ssh_jail_file_stale",
                template_vars=tvars,
            )
        else:
            result.info(
                message=_t("fail2ban.ssh_jail_file_silent", jail=snapshot.ssh_jail, files=files),
                key="fail2ban.ssh_jail_file_silent",
                template_vars=tvars,
            )
    elif snapshot.ssh_jail and snapshot.ssh_jail_files and not snapshot.ssh_jail_journal \
            and snapshot.ssh_jail_fed is None:
        # Not knowing whether a syslog daemon writes the file is no proof the
        # jail sees anything: said, not credited as protection.
        files = ", ".join(snapshot.ssh_jail_files)
        result.info(
            message=_t("fail2ban.ssh_jail_source_unverified", jail=snapshot.ssh_jail, files=files),
            key="fail2ban.ssh_jail_source_unverified",
            template_vars={"jail": snapshot.ssh_jail, "files": files},
        )
    elif snapshot.ssh_jail:
        result.ok(
            message=_t("fail2ban.ssh_jail_active", jail=snapshot.ssh_jail),
            # v0.24.4: on a file, what the OK rests on — and what it does not.
            detail=(_t("fail2ban.ssh_jail_active_file_detail")
                    if snapshot.ssh_jail_files and not snapshot.ssh_jail_journal else ""),
            key="fail2ban.ssh_jail_active",
        )

    return result


def _override_name(jail: str, existing: tuple) -> str:
    """A ``jail.d`` file name that fail2ban reads after every existing
    ``.local`` — they are read in name order and the last setting wins.

    v0.24.4 — measured on the Pi: with a ``zz-bobtest.local`` setting
    ``backend = polling``, BOB's ``zz-bob-sshd-journal.local`` sorted before it
    (``-`` < ``t``) and the jail stayed blind after the fix. ``~`` sorts after
    the ``.`` of ``.local``, so ``<last>~bob-…`` follows ``<last>.local``.
    """
    name = f"zz-bob-{jail}-journal.local"
    later = [n for n in existing if n > name]
    if later:
        name = f"{max(later)[:-len('.local')]}~bob-{jail}-journal.local"
    return name


def _safe_name(jail: str) -> str:
    """A jail name reduced to a file-name-safe token (jail names come from
    fail2ban-client output and end up in a path)."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in jail) or "ssh"
