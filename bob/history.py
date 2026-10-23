"""
Score history for BOB.

Appends one JSON entry per audit run to ~/.config/bob/history.jsonl.
--history displays a sparkline of the last N scores and a short table.

Format (one JSON object per line):
    {"ts": "2026-04-18T08:30:00+00:00", "score": 8, "level": "low"}
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

from bob._atomic import atomic_write, read_text_capped
from bob.checks._run import TranslationFunc, path_exists
from bob.sysinfo import (chown_fd_to_sudo_user, chown_to_sudo_user, ensure_user_dir, fd_real_path,
                         get_user_home, refuse_if_redirected)

_log = logging.getLogger(__name__)

_CONFIG_DIR   = get_user_home() / ".config" / "bob"
_HISTORY_FILE = _CONFIG_DIR / "history.jsonl"

_SPARK_CHARS        = " ▁▂▃▄▅▆▇█"   # 9 chars → score 0–10 mapped to indices 0–8
_MAX_HISTORY_ENTRIES = 1000           # rotate after this many lines


def _score_to_spark(score: int) -> str:
    """Map score 0–10 to a sparkline character. Clamps out-of-range values."""
    score = max(0, min(10, score))
    idx   = min(8, int(score * 9 / 10))
    return _SPARK_CHARS[idx]


def _readable_entry(e: dict) -> dict | None:
    """Return *e* if it carries the shape ``save_score`` writes, else None.

    v0.18.0. This used to be ``_clamp_entry``, which repaired what it could
    not read: a score that was null, absent, a string or out of range became
    ``0``, and an unreadable timestamp was left to crash the renderer.

    Neither is a value BOB measured. The substituted score is the worse of
    the two because it does not merely sit in a table — it feeds the trend
    arrows. Measured on three audits of 8/10 with the middle line's score
    field lost::

        8/10  →
        0/10  ↓      the collapse that never happened
        8/10  ↑      the recovery that never happened

    A line BOB cannot read is not a record of a past audit, so it is skipped
    exactly as a line that is not a JSON object is skipped. The sparkline and
    the arrows then describe audits that actually ran, and nothing else.

    ``level`` is deliberately not required: it has been written since v0.7.0
    but older lines predate it, and its absence costs a label, not a fact.
    """
    ts = e.get("ts")
    if not isinstance(ts, str) or not ts:
        return None
    score = e.get("score")
    # bool is an int in Python, and ``True`` is not a score.
    if isinstance(score, bool) or not isinstance(score, int):
        return None
    if not 0 <= score <= 10:
        return None
    return e


def save_score(
    score: int,
    level: str,
    level_score_only: str | None = None,
) -> None:
    """Append current audit score to history.jsonl.

    Args:
        score: Audit score (0-10).
        level: Effective risk level (low/medium/high/critical) — reflects
            posture escalation since v0.7.0.
        level_score_only: I-4 (v0.7.0 Phase 2.1) — optional un-escalated
            baseline level. When provided, written as a separate field for
            trend analysis that needs the score-only view (matches the v2
            JSON ``posture_escalation.score_level`` semantic).
    """
    try:
        ensure_user_dir(_CONFIG_DIR)
        entry_dict: dict = {
            "ts":    datetime.now(timezone.utc).isoformat(),
            "score": score,
            "level": level,
        }
        if level_score_only is not None:
            entry_dict["level_score_only"] = level_score_only
        entry = json.dumps(entry_dict)
        # I-5 (v0.6.1): explicit mode=0o600 on creation. Python's default
        # `Path.open("a")` uses the process umask (typically 0o644 → world-
        # readable history file). Score timestamps are privacy-sensitive on
        # shared systems.
        # v0.26.1 — O_NOFOLLOW: run as root, the open followed a symlink planted
        # at this name in the user's directory — appended to its target, or
        # created it through a dangling link (found by review, measured on a
        # dummy target). A symlink here now fails the open: nothing is written.
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
        # v0.26.1, after review — O_NOFOLLOW guards the last component only:
        # with ~/.config/bob a symlink to /etc, root created /etc/history.jsonl
        # (measured on a bench). The directory is opened first and checked,
        # then the file opened relative to that very descriptor. Not
        # O_NOFOLLOW on it: a ~/.config/bob linked inside the home (dotfiles)
        # is the user's own and was written in 0.26.0 — the check is on where
        # the descriptor really is.
        dfd = os.open(str(_HISTORY_FILE.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            refuse_if_redirected(_HISTORY_FILE.parent, fd_real_path(dfd))
            fd = os.open(_HISTORY_FILE.name, flags, 0o600, dir_fd=dfd)
        finally:
            os.close(dfd)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
            # ADV-G2 (v0.12.1): os.open's mode applies only at *creation*, so a
            # legacy history file created before I-5 (or by another path) stayed
            # 0o644 and world-readable forever. Heal the mode on every write so
            # an existing loose-permission file is brought back to 0o600 — a
            # hardening tool must not leak its own state. v0.26.1: through the
            # descriptor, not the name, which a symlink could redirect.
            os.fchmod(f.fileno(), 0o600)
            # v0.26.1 — the owner is healed like the mode, on every write: found
            # on a Mint host, history.jsonl was root:root 0600 in the user's own
            # ~/.config/bob, and `bob --history` (no sudo) said there was none.
            chown_fd_to_sudo_user(f.fileno(), _HISTORY_FILE)
        _rotate_if_needed()
    except OSError as exc:
        _log.debug("Failed to save score to history: %s", exc)


def _rotate_if_needed() -> None:
    """Truncate history.jsonl to the last _MAX_HISTORY_ENTRIES lines."""
    try:
        lines = [l for l in read_text_capped(_HISTORY_FILE).splitlines() if l.strip()]
        if len(lines) > _MAX_HISTORY_ENTRIES:
            content = "\n".join(lines[-_MAX_HISTORY_ENTRIES:]) + "\n"
            atomic_write(_HISTORY_FILE, content, mode=0o600)
            chown_to_sudo_user(_HISTORY_FILE)
    except OSError as exc:
        _log.debug("Failed to rotate history file: %s", exc)


class HistoryUnreadable(OSError):
    """history.jsonl exists but could not be read (v0.26.1)."""


def load_history(max_entries: int = 50, *, strict: bool = False) -> list[dict]:
    """Load the last *max_entries* history entries.

    With *strict*, a file that exists but cannot be read raises
    :class:`HistoryUnreadable` instead of reading as no history."""
    if not path_exists(_HISTORY_FILE):
        return []
    entries: list[dict] = []
    try:
        for line in read_text_capped(_HISTORY_FILE).splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            # v0.14.1: a line that is valid JSON but not an object (``null``,
            # ``[1,2]``, ``"str"``) reached _clamp_entry and raised
            # AttributeError — which this loop does not catch, so a single
            # such line aborted ``bob --history`` with a fatal error. The
            # loop's whole intent is to skip malformed lines; make that true
            # for every malformed shape, not just unparseable ones.
            if not isinstance(parsed, dict):
                continue
            readable = _readable_entry(parsed)
            if readable is None:
                continue
            entries.append(readable)
    except OSError as exc:
        if strict:
            raise HistoryUnreadable(exc.strerror or str(exc)) from exc
        return []
    return entries[-max_entries:]


def _trend(entries: list[dict], idx: int) -> str:
    """Return ↑, ↓ or → comparing entry at idx to the previous one."""
    if idx <= 0 or idx >= len(entries):
        return " "
    delta = entries[idx]["score"] - entries[idx - 1]["score"]
    if delta > 0:
        return "↑"
    if delta < 0:
        return "↓"
    return "→"


def render_history(entries: list[dict], t: TranslationFunc | None = None) -> list[str]:
    """
    Render score history as a sparkline + table.

    Returns a list of text lines ready for print().
    """
    from bob.i18n import t as _t_default
    _t = t if t is not None else _t_default

    if not entries:
        return [f"  {_t('history.no_entries')}"]

    spark = "".join(_score_to_spark(e.get("score", 0)) for e in entries)

    lines: list[str] = [
        f"  {_t('history.title')}",
        "  " + "─" * 44,
        f"  {spark}",
        "",
    ]

    recent = entries[-10:]
    for i, e in enumerate(reversed(recent)):
        orig_idx = len(entries) - 1 - i
        # Same trap as ``level`` below: an explicit null answers .get()
        # with None, and the except branch would subscript it.
        ts_raw = e.get("ts") or ""
        if not isinstance(ts_raw, str):
            ts_raw = ""
        try:
            dt     = datetime.fromisoformat(ts_raw)
            ts_str = dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            ts_str = ts_raw[:16]
        score = e.get("score", "?")
        # ``.get(k, "")`` returns None when the key exists holding null,
        # which formats as the string "None" on the operator's screen.
        level = e.get("level") or ""
        trend = _trend(entries, orig_idx)
        lines.append(f"  {ts_str}   {score}/10  {trend}  {level}")

    return lines


def unreadable_lines(reason: str, t: TranslationFunc | None = None) -> list[str]:
    """What --history says of a history file it could not read: its owner and
    mode as stat reports them, and how to read it (v0.26.1)."""
    import pwd
    import stat as _stat

    from bob.i18n import t as _t_default
    _t = t if t is not None else _t_default
    hand_back = False
    try:
        st = os.stat(_HISTORY_FILE)
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)
        mode = f"{_stat.S_IMODE(st.st_mode):04o}"
        # After review: the hand-back is said only where it would happen — the
        # name itself a regular file (lstat: not a link, which BOB will not
        # follow), owned by another account. Round 12: no chown command is
        # printed; run with sudo it would resolve the path again, links and
        # all — the next `sudo bob` hands it back through a checked descriptor.
        hand_back = _stat.S_ISREG(os.lstat(_HISTORY_FILE).st_mode) and st.st_uid != os.getuid()
    except OSError:
        owner = mode = "?"
    from bob._privilege import with_privilege
    # The host's word: doas where there is no sudo (after review).
    lines = [f"  {with_privilege(_t('history.unreadable', path=str(_HISTORY_FILE), owner=owner, mode=mode, error=reason))}"]
    if hand_back:
        lines.append(f"  {with_privilege(_t('history.unreadable_hand_back', path=str(_HISTORY_FILE)))}")
    return lines


def display_history(t: TranslationFunc | None = None) -> None:
    """Load and print score history to stdout."""
    try:
        entries = load_history(strict=True)
    except HistoryUnreadable as exc:
        for line in unreadable_lines(str(exc), t=t):
            print(line)
        return
    for line in render_history(entries, t=t):
        print(line)
