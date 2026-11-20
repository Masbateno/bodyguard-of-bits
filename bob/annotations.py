"""v0.39.0 — notes on an audit report, kept beside it and never inside it.

A report written with ``-d`` is evidence: nothing here rewrites it. Its notes
live in a companion file, ``<report>.note``, shown by ``--manage-logs`` as a
block of its own above the report.

The file is a journal: one JSON object per line, one line per action — a note
added, edited, withdrawn, or (rarely) purged. Nothing is ever removed from it
except the text of a purged note. What the viewer shows is rebuilt from the
whole journal, so every note's history can be shown too.

Who did it. On a shared server every operator runs ``sudo bob``, so "root"
says nothing. The kernel's login uid survives sudo: measured on the test
Linux Mint 22.3 (a10390, 17 November 2026), an account logged in over SSH kept
its own login uid through ``sudo``, ``sudo -i``, ``sudo su -``, ``sudo env
-i`` and a nested sudo, where ``SUDO_USER`` was absent, "root", or forged by
``sudo SUDO_USER=alice``. Each action records the login uid's name, and the
``SUDO_USER``/``DOAS_USER`` claim beside it when there is one. On that host,
with no audit setting making the login uid immutable, root could rewrite it
(measured): no local attribution resists a root that wants to lie.

Who can write it. The journal belongs to root (0640, the report's group): the
report's owner reads it, only root writes it, through ``sudo bob``. Owned by
the report's owner — the first design — that account rewrote it WITHOUT root,
recomputed the chain with BOB's own code and had it read back as intact
(measured, a10390/rewrite-as-owner.txt). A journal not owned by root is said
not to be BOB's, and nothing more is written to it.

What the digests show. Each line carries the digest of the line before it (the
first, of the report's name), computed without the note's text and salt; each
text carries its own salted digest. A line edited, removed from the middle,
reordered, or a text changed — without the whole chain recomputed — breaks it,
and the viewer says where. They are no signature: whoever can write the file
(root) can recompute the whole chain and leave no trace in it. Lines removed
from the end, or the whole file deleted by whoever owns its directory, leave
no trace in the file itself.

A purge removes a note's text and its salt from every line that held it and
adds a line saying who purged it, when, and why. The chain is unchanged by the
removal — it never covered the text. The digest left behind cannot be tested
against candidate texts: its 16-byte salt is gone with the text. Copies made
outside BOB — backups, filesystem snapshots — still hold what they held.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

#: The companion file's suffix, appended to the report's own name.
SUFFIX = ".note"
#: Journal format version written in every line.
_VERSION = 1
#: One note's text, at most (characters). A note is a line typed in a viewer.
MAX_TEXT = 2000
#: The whole journal, at most (bytes): refused beyond, read no further.
MAX_FILE = 1 << 20
_OPS = ("add", "edit", "withdraw", "purge")
_UNSET_LOGINUID = "4294967295"
#: v0.39.0, after review — who owns the journal: root. Owned by the report's
#: owner, it could be rewritten by that account WITHOUT root, its chain
#: recomputed with BOB's own (public) code, and read back as intact — measured
#: on the test Mint (a10390/rewrite-as-owner.txt). Root-owned, 0640, group of
#: the report: the report's owner still reads it, only root writes it (through
#: `sudo bob`, which leaves its own trace), and a journal owned by anyone else
#: is said not to be BOB's. A seam for the tests, which do not run as root.
_JOURNAL_UID = 0
_JOURNAL_MODE = 0o640
#: How many times the journal is reopened when it changed under the lock.
_LOCK_TRIES = 20
#: The kernel's login uid for this process (a seam for the tests).
_LOGINUID = Path("/proc/self/loginuid")


def note_path(report: Path) -> Path:
    """Where *report*'s notes live."""
    return report.with_name(report.name + SUFFIX)


# ---------------------------------------------------------------------------
# Who
# ---------------------------------------------------------------------------

def _account(uid: "int | str") -> "str | None":
    import pwd
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError, OverflowError):
        return None


def operator() -> dict:
    """The operator behind this process, as measured (see the module's text).

    ``login``: the account the kernel's login uid belongs to (or ``uid N``);
    absent outside a login session (a service, a timer). ``sudo``: the
    ``SUDO_USER``/``DOAS_USER`` claim, when set. ``uid``: the effective uid.
    """
    from bob.sysinfo import invoking_user_name
    who: dict = {"uid": os.geteuid()}
    try:
        raw = _LOGINUID.read_text(encoding="ascii", errors="replace").strip()
    except OSError:
        raw = ""
    if raw and raw != _UNSET_LOGINUID and raw.isdigit():
        who["login"] = _account(raw) or f"uid {raw}"
    claim = invoking_user_name()
    if claim:
        who["sudo"] = claim
    return who


def who_label(who: dict) -> str:
    """One name for display: the login account, the sudo claim beside it when
    it differs, else the claim, else the effective account."""
    login, claim = who.get("login"), who.get("sudo")
    if login and claim and claim != login:
        return f"{login} (sudo: {claim})"
    if login:
        return login
    if claim:
        return claim
    uid = who.get("uid")
    if uid is None:
        return "?"
    return _account(uid) or f"uid {uid}"


# ---------------------------------------------------------------------------
# The journal
# ---------------------------------------------------------------------------

def _canonical(event: dict) -> bytes:
    """What the chain covers: the line without the note's text and salt."""
    kept = {k: v for k, v in event.items() if k not in ("text", "salt")}
    return json.dumps(kept, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _genesis(report_name: str) -> str:
    return _digest(b"bob-notes\0" + report_name.encode())


def _text_digest(salt: str, text: str) -> str:
    return _digest(bytes.fromhex(salt) + text.encode())


def clean_text(text: str) -> str:
    """A note as typed, kept printable: control characters (escape sequences,
    a bare CR) dropped, whitespace runs folded, at most MAX_TEXT characters."""
    kept = "".join(c if c.isprintable() else " " for c in text)
    return " ".join(kept.split())[:MAX_TEXT]


@dataclass
class Version:
    at: str
    who: dict
    text: "str | None"          # None once purged


@dataclass
class Note:
    id: str
    number: int                 # 1, 2, … in order of creation
    versions: "list[Version]" = field(default_factory=list)
    withdrawn: "tuple[str, dict] | None" = None
    purged: "tuple[str, dict, str] | None" = None

    @property
    def created(self) -> Version:
        return self.versions[0]

    @property
    def text(self) -> "str | None":
        return self.versions[-1].text

    @property
    def edited(self) -> "Version | None":
        return self.versions[-1] if len(self.versions) > 1 else None

    @property
    def active(self) -> bool:
        return self.withdrawn is None and self.purged is None


@dataclass
class Journal:
    notes: "list[Note]"
    events: "list[dict]"
    intact: bool = True
    broken_at: "int | None" = None      # 1-based line where the chain or a text first fails
    unreadable: "str | None" = None     # the file is there and could not be read
    foreign_owner: "str | None" = None  # the file is not owned by root: not written by BOB

    @property
    def active(self) -> "list[Note]":
        return [n for n in self.notes if n.active]


#: Why a journal could not be read, as a key the viewer translates (0.39.0,
#: measured on the test Mint: a link at the name came back as the system's
#: English "Too many levels of symbolic links" inside a French screen).
_UNREADABLE_KEYS = ("link", "denied", "not_regular", "too_large")


def _read_raw(path: Path, limit: "int | None" = None) -> "tuple[str | None, str | None, int | None]":
    """The journal's text, or (None, reason), with its owner's uid. The
    reason is one of _UNREADABLE_KEYS, else the system's own message.
    Absent → ("", None, None). *limit* bounds the size read (MAX_FILE by
    default; the journal of --fix --apply, never purged, reads further)."""
    limit = MAX_FILE if limit is None else limit
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return "", None, None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None, "link", None
        if exc.errno in (errno.EACCES, errno.EPERM):
            return None, "denied", None
        return None, exc.strerror or str(exc), None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "not_regular", st.st_uid
        if st.st_size > limit:
            return None, "too_large", st.st_uid
        chunks, size = [], 0
        while size <= limit:
            chunk = os.read(fd, limit + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > limit:
            return None, "too_large", st.st_uid
        data = b"".join(chunks)
    except OSError as exc:
        return None, exc.strerror or str(exc), None
    finally:
        os.close(fd)
    return data.decode("utf-8", errors="replace"), None, st.st_uid


def parse(raw: str, report_name: str) -> Journal:
    """Rebuild the notes from the journal's text, checking the chain."""
    events: "list[dict]" = []
    notes: "dict[str, Note]" = {}
    order: "list[str]" = []
    prev = _genesis(report_name)
    intact, broken = True, None
    for lineno, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            ev = None
        if not isinstance(ev, dict) or ev.get("op") not in _OPS or not isinstance(ev.get("id"), str):
            if intact:
                intact, broken = False, lineno
            continue
        if intact and ev.get("prev") != prev:
            intact, broken = False, lineno
        text, salt = ev.get("text"), ev.get("salt")
        if intact and text is not None and (not isinstance(text, str) or not isinstance(salt, str)
                                           or _text_digest(salt, text) != ev.get("th")):
            intact, broken = False, lineno
        prev = _digest(_canonical(ev))
        events.append(ev)
        who = ev.get("by") if isinstance(ev.get("by"), dict) else {}
        at = str(ev.get("at", ""))
        nid, op = ev["id"], ev["op"]
        if op == "add" and nid not in notes:
            notes[nid] = Note(id=nid, number=len(order) + 1)
            order.append(nid)
            notes[nid].versions.append(Version(at, who, text if isinstance(text, str) else None))
        elif nid in notes:
            note = notes[nid]
            if op == "edit":
                note.versions.append(Version(at, who, text if isinstance(text, str) else None))
            elif op == "withdraw" and note.withdrawn is None:
                note.withdrawn = (at, who)
            elif op == "purge":
                note.purged = (at, who, str(ev.get("reason", "")))
        elif intact:
            intact, broken = False, lineno
    return Journal(notes=[notes[i] for i in order], events=events, intact=intact, broken_at=broken)


def load(report: Path) -> Journal:
    """*report*'s notes; an empty journal when it has none."""
    raw, why, uid = _read_raw(note_path(report))
    if raw is None:
        return Journal(notes=[], events=[], intact=False, unreadable=why)
    journal = parse(raw, report.name)
    if raw and uid != _JOURNAL_UID:
        # Not written by BOB: whoever owns it could have written every line,
        # chain included. Shown, never trusted.
        journal.intact = False
        journal.foreign_owner = _account(uid) or f"uid {uid}"
    return journal


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

class NoteError(Exception):
    """The journal could not be written. *key* names the reason, translated by
    the viewer as ``manage_logs.note_err.<key>`` with *vars*."""

    def __init__(self, key: str, **vars) -> None:
        super().__init__(key)
        self.key = key
        self.vars = vars


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _open_locked(report: Path) -> "tuple[int, int]":
    """The journal opened for appending and locked, with its directory's
    descriptor. Root only; created 0640, root's, in the report's group; one
    owned by anyone else is refused. A link at its name, or a directory under
    the operator's home resolving outside it, is refused."""
    from bob.sysinfo import fd_real_path, refuse_if_redirected
    if os.geteuid() != _JOURNAL_UID:
        raise NoteError("needs_root")
    path = note_path(report)
    dfd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        refuse_if_redirected(path.parent, fd_real_path(dfd))
        # Bounded: a name that never settles (a link, a file replaced again and
        # again) is refused rather than retried for ever — measured, unbounded,
        # a link at the name spun here without end (0.39.0 mutation run).
        for _attempt in range(_LOCK_TRIES):
            try:
                fd = os.open(path.name, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                             _JOURNAL_MODE, dir_fd=dfd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise NoteError("link") from None
                raise
            fcntl.flock(fd, fcntl.LOCK_EX)
            st = os.fstat(fd)
            try:
                now = os.stat(path.name, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                now = None
            # Replaced while we waited for the lock (a purge renames a new file
            # over the old one): what we hold is no longer the journal.
            if now is not None and (now.st_ino, now.st_dev) == (st.st_ino, st.st_dev):
                break
            os.close(fd)
        else:
            raise NoteError("busy")
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            os.close(fd)
            raise NoteError("not_regular")
        if st.st_size == 0:
            _own_journal(fd, report, dfd)
        elif st.st_uid != _JOURNAL_UID:
            os.close(fd)
            raise NoteError("foreign_owner", owner=_account(st.st_uid) or f"uid {st.st_uid}")
        return fd, dfd
    except BaseException:
        os.close(dfd)
        raise


def _own_journal(fd: int, report: Path, dfd: int) -> None:
    """The journal belongs to root, in the report's group, 0640: the report's
    owner reads it, only root writes it (see _JOURNAL_UID)."""
    try:
        gid = os.stat(report.name, dir_fd=dfd, follow_symlinks=False).st_gid
    except OSError:
        gid = -1
    os.fchown(fd, _JOURNAL_UID, gid)
    os.fchmod(fd, _JOURNAL_MODE)


def _read_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks, size = [], 0
    while size <= MAX_FILE:
        chunk = os.read(fd, 1 << 16)
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    if size > MAX_FILE:
        raise NoteError("too_large")
    return b"".join(chunks).decode("utf-8", errors="replace")


def _append(report: Path, make) -> Journal:
    """Lock, read, check, append the event — or the events, in order — that
    *make(journal)* returns. Several events are chained to one another and
    written in one write under the lock: all of them, or none."""
    fd, dfd = _open_locked(report)
    try:
        journal = parse(_read_fd(fd), report.name)
        if not journal.intact:
            raise NoteError("tampered", line=journal.broken_at)
        prev = _digest(_canonical(journal.events[-1])) if journal.events else _genesis(report.name)
        made = make(journal)
        events = made if isinstance(made, list) else [made]
        lines = []
        for event in events:
            event.update(v=_VERSION, at=_now(), by=operator(), prev=prev)
            prev = _digest(_canonical(event))
            lines.append(json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        data = "".join(lines).encode()
        if os.fstat(fd).st_size + len(data) > MAX_FILE:
            raise NoteError("too_large")
        os.write(fd, data)
        os.fsync(fd)
        return parse(_read_fd(fd), report.name)
    finally:
        os.close(fd)
        os.close(dfd)


def _with_text(event: dict, text: str) -> dict:
    text = clean_text(text)
    if not text:
        raise NoteError("empty")
    salt = secrets.token_hex(16)
    event.update(text=text, salt=salt, th=_text_digest(salt, text))
    return event


def _active(journal: Journal, number: int) -> Note:
    for note in journal.active:
        if note.number == number:
            return note
    raise NoteError("no_note", number=number)


def add(report: Path, text: str) -> Journal:
    return _append(report, lambda j: _with_text({"op": "add", "id": secrets.token_hex(4)}, text))


def edit(report: Path, number: int, text: str) -> Journal:
    return _append(report, lambda j: _with_text({"op": "edit", "id": _active(j, number).id}, text))


def withdraw(report: Path, number: int) -> Journal:
    return withdraw_many(report, [number])


def withdraw_many(report: Path, numbers: "list[int]") -> Journal:
    """v0.39.0 (user, 19 November 2026) — several notes withdrawn at once: one
    line each, chained, written together under the lock. A number with no
    active note refuses them all: nothing is written."""
    return _append(report, lambda j: [{"op": "withdraw", "id": _active(j, n).id} for n in numbers])


def purge(report: Path, number: int, reason: str) -> Journal:
    return purge_many(report, [number], reason)


def purge_many(report: Path, numbers: "list[int]", reason: str) -> Journal:
    """Remove the text of each note in *numbers* from every line, then record
    who, when, why — one purge line per note, the same reason.

    v0.39.0 (user, 19 November 2026) — several notes, or all, at once: one
    rewrite of the journal for all of them. A number with no note left to
    purge refuses them all: nothing is rewritten.

    The note may be active or withdrawn — a secret pasted by mistake is often
    withdrawn first. The rewrite goes through a temporary file renamed over
    the journal, under the lock; a writer that waited on the old file sees it
    replaced and reopens (see :func:`_open_locked`).
    """
    reason = clean_text(reason)
    if not reason:
        raise NoteError("no_reason")
    fd, dfd = _open_locked(report)
    try:
        journal = parse(_read_fd(fd), report.name)
        if not journal.intact:
            raise NoteError("tampered", line=journal.broken_at)
        targets = []
        for number in numbers:
            target = next((n for n in journal.notes if n.number == number and n.purged is None), None)
            if target is None:
                raise NoteError("no_note", number=number)
            targets.append(target)
        ids = {target.id for target in targets}
        events = [dict(e) for e in journal.events]
        for e in events:
            if e.get("id") in ids:
                e.pop("text", None)
                e.pop("salt", None)
        for target in targets:
            prev = _digest(_canonical(events[-1]))
            events.append({"op": "purge", "id": target.id, "reason": reason,
                           "v": _VERSION, "at": _now(), "by": operator(), "prev": prev})
        content = "".join(json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
                          for e in events)
        st = os.fstat(fd)
        name = note_path(report).name
        while True:
            tmp = f"{name}.{secrets.token_hex(4)}.tmp"
            try:
                tfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=dfd)
                break
            except FileExistsError:
                continue
        try:
            os.write(tfd, content.encode())
            os.fchown(tfd, st.st_uid, st.st_gid)
            os.fchmod(tfd, _JOURNAL_MODE)
            os.fsync(tfd)
            os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            raise
        finally:
            os.close(tfd)
        return parse(content, report.name)
    finally:
        os.close(fd)
        os.close(dfd)
