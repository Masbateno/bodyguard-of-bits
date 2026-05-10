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

from bob.checks._run import TranslationFunc
from bob.sysinfo import chown_to_sudo_user, get_user_home

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


def _clamp_entry(e: dict) -> dict:
    """Return entry with score clamped to [0, 10]. Mutates and returns e."""
    raw = e.get("score", 0)
    try:
        e["score"] = max(0, min(10, int(raw)))
    except (TypeError, ValueError):
        e["score"] = 0
    return e


def save_score(score: int, level: str) -> None:
    """Append current audit score to history.jsonl."""
    try:
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        chown_to_sudo_user(_CONFIG_DIR)
        entry = json.dumps({
            "ts":    datetime.now(timezone.utc).isoformat(),
            "score": score,
            "level": level,
        })
        existed = _HISTORY_FILE.exists()
        with _HISTORY_FILE.open("a", encoding="utf-8") as f:
            f.write(entry + "\n")
        if not existed:
            chown_to_sudo_user(_HISTORY_FILE)
        _rotate_if_needed()
    except OSError as exc:
        _log.debug("Failed to save score to history: %s", exc)


def _rotate_if_needed() -> None:
    """Truncate history.jsonl to the last _MAX_HISTORY_ENTRIES lines."""
    try:
        lines = [l for l in _HISTORY_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]
        if len(lines) > _MAX_HISTORY_ENTRIES:
            content = "\n".join(lines[-_MAX_HISTORY_ENTRIES:]) + "\n"
            tmp = _HISTORY_FILE.with_suffix(".jsonl.tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.replace(str(tmp), str(_HISTORY_FILE))
            chown_to_sudo_user(_HISTORY_FILE)
    except OSError as exc:
        _log.debug("Failed to rotate history file: %s", exc)


def load_history(max_entries: int = 50) -> list[dict]:
    """Load the last *max_entries* history entries."""
    if not _HISTORY_FILE.exists():
        return []
    entries: list[dict] = []
    try:
        for line in _HISTORY_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(_clamp_entry(json.loads(line)))
            except (json.JSONDecodeError, ValueError):
                continue
    except OSError:
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
        ts_raw = e.get("ts", "")
        try:
            dt     = datetime.fromisoformat(ts_raw)
            ts_str = dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            ts_str = ts_raw[:16]
        score = e.get("score", "?")
        level = e.get("level", "")
        trend = _trend(entries, orig_idx)
        lines.append(f"  {ts_str}   {score}/10  {trend}  {level}")

    return lines


def display_history(t: TranslationFunc | None = None) -> None:
    """Load and print score history to stdout."""
    entries = load_history()
    for line in render_history(entries, t=t):
        print(line)
