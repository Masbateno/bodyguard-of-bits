"""v0.40.0 — is the journal of ``--fix --apply`` the one BOB wrote?

Decided with the user (20 November 2026, B-031): "the moment the log has been
falsified, it must be shown explicitly, or at least be easy to demonstrate".
A journal on the machine can always be rewritten by root; what BOB can do is
make a rewrite show. Four measures, each said for what it is:

1. **The chain** (bob/fix_journal.py): each line carries the digest of the one
   before. A line changed, removed from the middle or moved breaks it — unless
   whoever changed it recomputed every digest after it, which root can do.

2. **The witness**: each entry was also sent to the system log, through
   ``/dev/log``, with the digest of its journal line. Read back here from
   journald (``journalctl SYSLOG_IDENTIFIER=bob-fix``), keeping only what
   journald itself recorded as sent by root: ``_UID`` is set by journald from
   the sender's socket credentials, not by the sender, so an ordinary account
   running ``logger -t bob-fix`` cannot plant a witness (measured, Linux Mint
   22.3, systemd 255: such a line carries ``_UID=1000``). Against it:

   * an entry whose line differs from its witness — rewritten, chain
     recomputed or not: **falsified**;
   * one entry, two witnesses that disagree — a witness forged as root beside
     the real one: **falsified**;
   * a witness with no entry — entries cut from the end, or the journal
     deleted: **removed**;
   * an entry sent with a witness that journald does not have, though it holds
     entries from that time: **not shown** — nothing proves a falsification,
     nothing proves the entry either;
   * an entry older than anything journald still holds: its witness went with
     the journal's own rotation — said, never called a falsification.

3. **Append-only** (``chattr +a``): BOB sets it, and each line says whether it
   was set when written. Found missing since: someone took it off, a
   deliberate act the content may have followed.

4. **Journald's own sealing** (Forward Secure Sealing): when the administrator
   has set it up, a rewrite of the system log itself shows to
   ``journalctl --verify`` with the key kept off the machine. BOB says whether
   it is set up; it never sets it up.

What stays out of reach, and is said: root rewriting the journal *and* the
system log consistently, or deleting both, on a host without sealing or a copy
sent to another machine.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from bob import fix_journal as FJ

#: Seams for the tests.
_MACHINE_ID = Path("/etc/machine-id")
_JOURNAL_ROOTS = (Path("/var/log/journal"), Path("/run/log/journal"))
_TIMEOUT = 30

#: v0.44.0 (B-050) — ``rotate``, the line that says the journal was archived:
#: measured as root on the test Mint (27 November 2026), left out it was the
#: one line of 241 "not shown", and every rotation would leave the verdict
#: unproven.
_HEAD = re.compile(r"^(run|result|note|rotate) id=([0-9a-f]{6,32}) sha256=([0-9a-f]{64}) body=([0-9a-f]{64})\b")


@dataclass
class Witness:
    kind: str
    id: str
    digest: str
    body: str
    at: "datetime | None"
    message: str


@dataclass
class WitnessRead:
    #: ok — read; no_journald — no journalctl here; unreadable — neither root
    #: nor a group journald lets read the system log; no_store — journald
    #: keeps no file here (Storage=none); failed — journalctl answered with
    #: an error.
    state: str
    items: "list[Witness]" = field(default_factory=list)
    oldest: "datetime | None" = None   # the oldest entry journald still holds
    persistent: "bool | None" = None   # kept across a reboot (/var/log/journal)
    sealed: "bool | None" = None       # Forward Secure Sealing set up
    detail: str = ""


@dataclass
class Verdict:
    #: tampered — a falsification is shown; unproven — nothing shown, but not
    #: everything could be checked; intact — every check that applies passed.
    overall: str
    chain_broken_at: "int | None" = None
    foreign_owner: "str | None" = None
    unreadable: "str | None" = None
    differs: "list[str]" = field(default_factory=list)         # what the entry says changed
    rechained: "list[str]" = field(default_factory=list)       # says the same, chain recomputed
    conflicting: "list[str]" = field(default_factory=list)     # entry ids
    removed: "list[Witness]" = field(default_factory=list)
    not_shown: "list[str]" = field(default_factory=list)
    witness_gone: "list[str]" = field(default_factory=list)
    no_witness: "list[str]" = field(default_factory=list)      # written without a system log
    confirmed: "list[str]" = field(default_factory=list)
    append_only_removed: bool = False
    append_only_now: "bool | None" = None
    witness: "WitnessRead | None" = None

    _ORDER = ("differs", "conflicting", "rechained", "not_shown", "witness_gone",
              "no_witness", "confirmed")

    def of(self, line_id: str) -> str:
        """One line's state: differs, conflicting, rechained, not_shown,
        witness_gone, no_witness, confirmed, or unchecked (the witness could
        not be read)."""
        for name in self._ORDER:
            if line_id in getattr(self, name):
                return name
        return "unchecked"

    def of_entry(self, entry: "FJ.Entry") -> str:
        """An entry's state: the worst of its lines' (start, outcome, notes)."""
        states = [self.of(line_id) for line_id in entry.lines] or ["unchecked"]
        rank = {name: i for i, name in enumerate(self._ORDER + ("unchecked",))}
        worst = min(states, key=lambda st: rank[st])
        # "unchecked" only when nothing at all could be checked.
        return worst if worst != "confirmed" or "unchecked" not in states else "unchecked"


def _machine_id() -> str:
    try:
        return _MACHINE_ID.read_text(encoding="ascii", errors="replace").strip()
    except OSError:
        return ""


def _journal_files() -> "list[Path]":
    mid = _machine_id()
    return [root / mid / "system.journal" for root in _JOURNAL_ROOTS if mid]


def _when(usec: object) -> "datetime | None":
    try:
        return datetime.fromtimestamp(int(usec) / 1e6, tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _text(value: object) -> str:
    """journald hands a MESSAGE that is not clean UTF-8 as a list of bytes."""
    if isinstance(value, list):
        try:
            return bytes(value).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return ""
    return value if isinstance(value, str) else ""


def _journalctl(*args: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(["journalctl", "-q", "--no-pager", "-o", "json", *args],
                          capture_output=True, text=True, timeout=_TIMEOUT,
                          env={"LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})


def _oldest() -> "datetime | None":
    """The oldest entry journald still holds (the first line it prints)."""
    try:
        proc = subprocess.Popen(["journalctl", "-q", "--no-pager", "-o", "json"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
    except OSError:
        return None
    try:
        line = proc.stdout.readline() if proc.stdout else ""
    finally:
        proc.kill()
        proc.wait()
    try:
        return _when(json.loads(line).get("__REALTIME_TIMESTAMP"))
    except (ValueError, AttributeError):
        return None


def read_witness() -> WitnessRead:
    """What journald holds of the witness, kept to what root sent."""
    files = [f for f in _journal_files() if f.exists()]
    persistent = any(f.parent.parent == _JOURNAL_ROOTS[0] for f in files) if files else None
    sealed = any((f.parent / "fss").exists() for f in files) if files else None
    # Before asking: journalctl run without the right says "No journal files
    # were opened due to insufficient permissions" and exits 1 (measured, Linux
    # Mint 22.3, as nobody) — not a failure, a reader without the right.
    if files and not any(os.access(f, os.R_OK) for f in files):
        return WitnessRead("unreadable", persistent=persistent, sealed=sealed)
    try:
        proc = _journalctl(f"SYSLOG_IDENTIFIER={FJ.WITNESS_TAG}", "_UID=0")
    except FileNotFoundError:
        return WitnessRead("no_journald")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return WitnessRead("failed", detail=str(exc))
    if proc.returncode != 0:
        return WitnessRead("failed", detail=proc.stderr.strip()[:300],
                           persistent=persistent, sealed=sealed)
    if not files:
        return WitnessRead("no_store")
    items = []
    for line in proc.stdout.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict) or str(record.get("_UID")) != "0":
            continue
        message = _text(record.get("MESSAGE"))
        match = _HEAD.match(message)
        if match:
            items.append(Witness(kind=match.group(1), id=match.group(2), digest=match.group(3),
                                 body=match.group(4), at=_when(record.get("__REALTIME_TIMESTAMP")), message=message))
    return WitnessRead("ok", items=items, oldest=_oldest(), persistent=persistent, sealed=sealed)


def _at(text: str) -> "datetime | None":
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def verify(journal: "FJ.Journal | None" = None, witness: "WitnessRead | None" = None,
           append_only: "bool | None | object" = ...) -> Verdict:
    """The journal against everything that can vouch for it (see the module)."""
    journal = FJ.load() if journal is None else journal
    witness = read_witness() if witness is None else witness
    now_flag = FJ.append_only_now() if append_only is ... else append_only
    verdict = Verdict(overall="intact", chain_broken_at=journal.broken_at,
                      foreign_owner=journal.foreign_owner, unreadable=journal.unreadable,
                      witness=witness, append_only_now=now_flag)
    if journal.seen and journal.seen[-1].append_only and now_flag is False:
        verdict.append_only_removed = True

    by_id: "dict[str, set[tuple[str, str]]]" = {}
    for item in witness.items:
        by_id.setdefault(item.id, set()).add((item.digest, item.body))
    in_file = {line.id for line in journal.seen}
    if witness.state == "ok":
        # v0.44.0 (B-050) — the oldest archives left unread (bob/fix_journal
        # CHAIN_BUDGET): their lines are not in what was read, and are not
        # removed for that. What the system log holds from before the first
        # line read is left out; the archives unread are said.
        first = _at(journal.seen[0].at) if journal.skipped and journal.seen else None
        verdict.removed = [item for item in witness.items if item.id not in in_file
                           and not (first and item.at and item.at < first)]
    for line in journal.seen:
        # By id first, whatever the line claims: a falsifier flipping
        # "witness" to "none" changes the line, and the witness still has it.
        sent = by_id.get(line.id) if witness.state == "ok" else None
        if sent:
            if len(sent) > 1:
                verdict.conflicting.append(line.id)
            else:
                (digest, body), = sent
                if line.body != body:
                    verdict.differs.append(line.id)
                elif line.digest != digest:
                    verdict.rechained.append(line.id)
                else:
                    verdict.confirmed.append(line.id)
            continue
        if line.witness != "syslog":
            verdict.no_witness.append(line.id)
            continue
        if witness.state != "ok":
            continue
        written = _at(line.at)
        if witness.oldest and written and written < witness.oldest:
            verdict.witness_gone.append(line.id)
        else:
            verdict.not_shown.append(line.id)

    if (verdict.chain_broken_at or verdict.foreign_owner or verdict.differs
            or verdict.rechained or verdict.conflicting or verdict.removed):
        verdict.overall = "tampered"
    elif (verdict.append_only_removed or verdict.not_shown or verdict.unreadable
          or (journal.seen and witness.state != "ok" and any(ln.witness == "syslog" for ln in journal.seen))):
        verdict.overall = "unproven"
    return verdict
