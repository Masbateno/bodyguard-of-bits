"""v0.40.0 — the journal of ``--fix --apply``: one entry for each command run.

Decided with the user (19 and 20 November 2026, B-031): every command
``--fix --apply`` launches leaves a dated entry naming who launched it, the
finding it answered, the exact command, and what came of it — applied, failed,
timed out, or ran without its effect being confirmed. The entry is written in
two lines: one before the command starts, one with its outcome. A command
during which BOB dies — the firewall fix that cuts the SSH session BOB runs in,
a power cut — still shows, as started with no known outcome. One file for the host,
whoever ran BOB: ``/var/log/bob/fixes.journal``. An entry is never changed;
a note can be added to it (dated, its author recorded), never edited or
withdrawn.

Who did it: the same measure as the notes on a report (bob/annotations.py) —
the account the kernel's login uid names, the ``SUDO_USER``/``DOAS_USER``
claim beside it.

Who can write it: root, the only account that runs ``--fix --apply``. The
journal is root's, mode 0640, group ``adm`` where the host has it (the group
that reads the system's logs), so an administrator reads it without root.
The directory is root's too, 0750, same group. A journal not owned by root is
said not to be BOB's, and nothing is written to it.

What it can show: each line carries the digest of the line before it — the
whole line, text included, since nothing here is ever purged. A line changed,
removed from the middle or reordered outside BOB breaks the chain at that line.
The digests are no signature: root can rewrite the file and recompute them.
Lines removed from the end, or the file deleted, leave no trace in the file
itself. Hence the witness: each entry is also sent to the system log
(journald or syslog, through ``/dev/log``) with its line's digest, so that
erasing a trace means rewriting the system log too. Where the host has no
system log socket, the entry says it went without a witness.

Unlike the notes, a journal changed outside BOB still receives new entries: a
command that changed the system must leave a trace, and refusing to write
would leave none. The break stays visible at its line.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import secrets
import socket
import stat
import struct
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

#: Where the journal lives (a seam for the tests).
DIR = Path("/var/log/bob")
NAME = "fixes.journal"
_VERSION = 1
#: Bounds on what one entry keeps.
MAX_COMMAND = 4000
MAX_ERROR = 500
MAX_TEXT = 2000
#: The whole journal is read at most this far (bytes).
MAX_FILE = 16 << 20
_JOURNAL_UID = 0
_JOURNAL_MODE = 0o640
_DIR_MODE = 0o750
#: The group that reads the system's logs on Debian, Ubuntu, Mint, Kali.
_GROUP = "adm"
#: The system log socket the witness is sent to (a seam for the tests).
_SYSLOG_SOCKET = Path("/dev/log")
STATUSES = ("ok", "failed", "timeout", "unconfirmed")
#: An entry with no outcome line: started, and nothing more is known.
STARTED = "started"
#: The name the witness carries in the system log (SYSLOG_IDENTIFIER).
WITNESS_TAG = "bob-fix"
#: The append-only attribute (``chattr +a``): FS_APPEND_FL, read and set
#: through FS_IOC_GETFLAGS / FS_IOC_SETFLAGS — the generic ioctl encoding
#: (x86, Arm), whose size field is that of a C long.
_FS_APPEND_FL = 0x20
_LONG = struct.calcsize("l")
_FS_IOC_GETFLAGS = (2 << 30) | (_LONG << 16) | (ord("f") << 8) | 1
_FS_IOC_SETFLAGS = (1 << 30) | (_LONG << 16) | (ord("f") << 8) | 2


class FixJournalError(Exception):
    """Why nothing was written: *key* names it, *vars* fill its message."""

    def __init__(self, key: str, **vars_: object) -> None:
        super().__init__(key)
        self.key = key
        self.vars = vars_


@dataclass
class Note:
    id: str
    at: str
    who: dict
    text: str


@dataclass
class Entry:
    id: str
    at: str
    who: dict
    finding: str
    message: str
    command: str
    how: str
    witness: str
    action: "dict | None" = None
    status: str = STARTED
    rc: "int | None" = None
    error: str = ""
    seconds: "float | None" = None
    ended: str = ""
    notes: "list[Note]" = field(default_factory=list)
    #: The ids of every line that makes the entry: its start, its outcome,
    #: its notes — what the witness check looks up.
    lines: "list[str]" = field(default_factory=list)


@dataclass
class Line:
    """One line of the journal as it reads: what the witness is checked against."""
    number: int
    kind: str
    id: str
    at: str
    digest: str
    body: str
    witness: str
    append_only: "bool | None"


@dataclass
class Journal:
    entries: "list[Entry]"
    seen: "list[Line]" = field(default_factory=list)
    lines: int = 0
    intact: bool = True
    broken_at: "int | None" = None      # 1-based line where the chain first fails
    unreadable: "str | None" = None     # a key: link, denied, not_regular, too_large — else the system's words
    foreign_owner: "str | None" = None  # not owned by root: not written by BOB


def path() -> Path:
    return DIR / NAME


def _canonical(event: dict) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_GENESIS = _digest(b"bob-fixes\0")


def body_digest(event: dict) -> str:
    """The digest of what an entry says, its link to the line before left
    out: when a falsifier recomputes the chain after changing one line, every
    later line's digest changes, but not what those lines say — the witness
    carries both, so the check tells the line changed from the lines only
    re-chained after it."""
    return _digest(_canonical({k: v for k, v in event.items() if k != "prev"}))


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _group_id() -> int:
    import grp
    try:
        return grp.getgrnam(_GROUP).gr_gid
    except KeyError:
        return 0


def _owner_name(uid: int) -> str:
    from bob.annotations import _account
    return _account(uid) or f"uid {uid}"


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def parse(raw: str) -> Journal:
    """The journal rebuilt from its text, its chain checked line by line."""
    entries: "dict[str, Entry]" = {}
    order: "list[str]" = []
    journal = Journal(entries=[])
    prev = _GENESIS
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        journal.lines += 1
        try:
            event = json.loads(line)
        except ValueError:
            event = None
        if not isinstance(event, dict) or event.get("prev") != prev:
            if journal.intact:
                journal.intact, journal.broken_at = False, number
            if not isinstance(event, dict):
                continue
        prev = _digest(_canonical(event))
        kind = event.get("kind")
        if isinstance(event.get("id"), str):
            flag = event.get("append_only")
            journal.seen.append(Line(
                number=number, kind=str(kind), id=event["id"], at=str(event.get("at", "")),
                digest=prev, body=body_digest(event), witness=str(event.get("witness", "")),
                append_only=flag if isinstance(flag, bool) else None))
        if kind == "run" and isinstance(event.get("id"), str):
            entry = Entry(
                id=event["id"], at=str(event.get("at", "")), who=event.get("by") or {},
                finding=str(event.get("finding", "")), message=str(event.get("message", "")),
                command=str(event.get("command", "")), how=str(event.get("how", "")),
                witness=str(event.get("witness", "")), lines=[event["id"]],
                action=event.get("action") if isinstance(event.get("action"), dict) else None)
            if entry.id not in entries:
                order.append(entry.id)
            entries[entry.id] = entry
        elif kind == "result" and event.get("of") in entries:
            entry = entries[event["of"]]
            status = str(event.get("status", ""))
            entry.status = status if status in STATUSES else "failed"
            entry.rc, entry.seconds = event.get("rc"), event.get("seconds")
            entry.error, entry.ended = str(event.get("error", "")), str(event.get("at", ""))
            entry.lines.append(str(event.get("id", "")))
        elif kind == "note" and event.get("of") in entries:
            entries[event["of"]].lines.append(str(event.get("id", "")))
            entries[event["of"]].notes.append(
                Note(id=str(event.get("id", "")), at=str(event.get("at", "")),
                     who=event.get("by") or {}, text=str(event.get("text", ""))))
    journal.entries = [entries[i] for i in order]
    return journal


def load() -> Journal:
    """The journal as it stands; an absent journal is an empty one."""
    from bob.annotations import _read_raw
    raw, why, uid = _read_raw(path(), MAX_FILE)
    if raw is None:
        return Journal(entries=[], intact=False, unreadable=why)
    journal = parse(raw)
    if raw and uid is not None and uid != _JOURNAL_UID:
        journal.intact = False
        journal.foreign_owner = _owner_name(uid)
    return journal


def days(journal: Journal) -> "list[tuple[str, list[Entry]]]":
    """The entries grouped by local day, the most recent day first; within a
    day, in the order they were run (decided with the user: one day, one
    line of the list)."""
    by_day: "dict[str, list[Entry]]" = {}
    for entry in journal.entries:
        try:
            day = datetime.fromisoformat(entry.at).astimezone().date().isoformat()
        except ValueError:
            day = entry.at[:10] or "?"
        by_day.setdefault(day, []).append(entry)
    return sorted(by_day.items(), key=lambda item: item[0], reverse=True)


# ---------------------------------------------------------------------------
# Writing (root only)
# ---------------------------------------------------------------------------

def _open_dir() -> int:
    """The journal's directory, created root's (0750, group adm) when absent;
    a link at its name, or a directory root does not own, is refused."""
    gid = _group_id()
    try:
        os.mkdir(str(DIR), _DIR_MODE)
        created = True
    except FileExistsError:
        created = False
    try:
        dfd = os.open(str(DIR), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise FixJournalError("link") from None
        raise
    st = os.fstat(dfd)
    if created:
        os.fchown(dfd, _JOURNAL_UID, gid)
        os.fchmod(dfd, _DIR_MODE)
    elif st.st_uid != _JOURNAL_UID:
        os.close(dfd)
        raise FixJournalError("foreign_owner", owner=_owner_name(st.st_uid))
    return dfd


def _open_locked() -> "tuple[int, int]":
    if os.geteuid() != _JOURNAL_UID:
        raise FixJournalError("needs_root")
    dfd = _open_dir()
    try:
        try:
            fd = os.open(NAME, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                         _JOURNAL_MODE, dir_fd=dfd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise FixJournalError("link") from None
            raise
        fcntl.flock(fd, fcntl.LOCK_EX)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            os.close(fd)
            raise FixJournalError("not_regular")
        if st.st_size == 0:
            os.fchown(fd, _JOURNAL_UID, _group_id())
            os.fchmod(fd, _JOURNAL_MODE)
        elif st.st_uid != _JOURNAL_UID:
            os.close(fd)
            raise FixJournalError("foreign_owner", owner=_owner_name(st.st_uid))
        return fd, dfd
    except BaseException:
        os.close(dfd)
        raise


def _last_digest(fd: int) -> str:
    """The digest of the journal's last line, the genesis for an empty one."""
    size = os.fstat(fd).st_size
    if size == 0:
        return _GENESIS
    window = min(size, 1 << 20)
    data = os.pread(fd, window, size - window).decode("utf-8", errors="replace")
    lines = [ln for ln in data.splitlines() if ln.strip()]
    if not lines:
        return _GENESIS
    try:
        event = json.loads(lines[-1])
    except ValueError:
        return _digest(lines[-1].encode())
    return _digest(_canonical(event)) if isinstance(event, dict) else _digest(lines[-1].encode())


def _flags(fd: int) -> int:
    buf = bytearray(8)
    fcntl.ioctl(fd, _FS_IOC_GETFLAGS, buf, True)
    return struct.unpack_from("i", buf)[0]


def _set_append_only(fd: int) -> bool:
    """``chattr +a`` on the journal: the kernel then refuses to rewrite or
    truncate it, root included, until the attribute is taken off — which
    needs a deliberate act, and leaves the attribute missing for BOB to see.
    False where the file system has no such attribute (tmpfs, overlayfs) or
    BOB lacks the right to set it (CAP_LINUX_IMMUTABLE, inside a container)."""
    try:
        flags = _flags(fd)
        if not flags & _FS_APPEND_FL:
            buf = bytearray(8)
            struct.pack_into("i", buf, 0, flags | _FS_APPEND_FL)
            fcntl.ioctl(fd, _FS_IOC_SETFLAGS, buf, False)
        return bool(_flags(fd) & _FS_APPEND_FL)
    except OSError:
        return False


def append_only_now() -> "bool | None":
    """Whether the journal carries the append-only attribute now; None when
    it cannot be told (absent, unreadable, no such attribute here)."""
    try:
        fd = os.open(str(path()), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        return bool(_flags(fd) & _FS_APPEND_FL)
    except OSError:
        return None
    finally:
        os.close(fd)


def _has_witness() -> bool:
    try:
        return stat.S_ISSOCK(os.stat(_SYSLOG_SOCKET).st_mode)
    except OSError:
        return False


def _send_witness(event: dict, digest: str) -> None:
    """One line in the system log for *event*: best effort, never fatal."""
    try:
        import syslog
        syslog.openlog(WITNESS_TAG, syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_NOTICE, witness_message(event, digest))
        syslog.closelog()
    except Exception:  # noqa: BLE001 — a witness that cannot be written must not stop a fix
        pass


def witness_message(event: dict, digest: str) -> str:
    """The witness line for *event*: its kind, id and the digest of its
    journal line first (what the check reads back), then what a person
    reading the system log needs — who, what came of it, the command."""
    head = f"{event['kind']} id={event['id']} sha256={digest} body={body_digest(event)}"
    by = json.dumps(event.get("by", {}), sort_keys=True, separators=(",", ":"))
    if event["kind"] == "run":
        return (f"{head} by={by} finding={event.get('finding', '')} "
                f"cmd={event.get('command', '')[:500]!r}")
    if event["kind"] == "result":
        return f"{head} of={event.get('of')} status={event.get('status')} rc={event.get('rc')}"
    return f"{head} of={event.get('of')} by={by}"


def _append(event: dict) -> dict:
    fd, dfd = _open_locked()
    try:
        event.update(v=_VERSION, at=_now(), by=_operator(), host=socket.gethostname())
        event["witness"] = "syslog" if _has_witness() else "none"
        event["append_only"] = _set_append_only(fd)
        event["prev"] = _last_digest(fd)
        line = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        os.write(fd, line.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
        os.close(dfd)
    if event["witness"] == "syslog":
        _send_witness(event, _digest(_canonical(event)))
    return event


def _operator() -> dict:
    from bob.annotations import operator
    return operator()


def check_writable() -> None:
    """Raise FixJournalError when the journal cannot take an entry — asked
    before the first command, so that no command runs without one."""
    fd, dfd = _open_locked()
    os.close(fd)
    os.close(dfd)


def start(*, finding: str, message: str, command: str, how: str,
          action: "dict | None" = None) -> str:
    """A command about to run: its entry, written before it starts. Returns
    the entry's id, for :func:`finish`. *how* is ``shell`` (the command ran as
    written) or ``native`` (BOB's own code carried out *action*, the command
    being its written form — see bob/_sysctl_apply.py)."""
    event = {
        "kind": "run", "id": secrets.token_hex(6),
        "finding": finding, "message": message[:MAX_TEXT],
        "command": command[:MAX_COMMAND], "how": how,
    }
    if action:
        event["action"] = action
    return _append(event)["id"]


def finish(entry_id: str, *, status: str, rc: "int | None", error: "bytes | str",
           seconds: "float | None") -> dict:
    """What came of the command *entry_id* names."""
    if isinstance(error, bytes):
        error = error.decode("utf-8", errors="replace")
    return _append({
        "kind": "result", "id": secrets.token_hex(6), "of": entry_id,
        "status": status if status in STATUSES else "failed",
        "rc": rc, "error": error.strip()[:MAX_ERROR], "seconds": seconds,
    })


def record(*, finding: str, message: str, command: str, how: str, status: str,
           rc: "int | None", error: "bytes | str", seconds: "float | None") -> str:
    """Both lines at once — for a command whose outcome is already known."""
    entry_id = start(finding=finding, message=message, command=command, how=how)
    finish(entry_id, status=status, rc=rc, error=error, seconds=seconds)
    return entry_id


def add_note(entry_id: str, text: str) -> dict:
    """A note on an entry: added, never edited or withdrawn."""
    from bob.annotations import clean_text
    text = clean_text(text)[:MAX_TEXT]
    if not text:
        raise FixJournalError("empty")
    if not any(e.id == entry_id for e in load().entries):
        raise FixJournalError("no_entry")
    return _append({"kind": "note", "id": secrets.token_hex(6), "of": entry_id, "text": text})
