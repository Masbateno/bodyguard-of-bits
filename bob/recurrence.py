"""Recurring finding tracker for BOB.

Counts how many consecutive audits each ALERT/WARN finding key has been present.
Counter increments when a key appears, resets (key removed) when it resolves.

File: ~/.config/bob/recurrence.json
Format: {"finding.key": N, ...}  — N = consecutive occurrences including previous runs
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from bob.sysinfo import chown_to_sudo_user, get_user_home

_log = logging.getLogger(__name__)

_CONFIG_DIR       = get_user_home() / ".config" / "bob"
_RECURRENCE_PATH  = _CONFIG_DIR / "recurrence.json"


def load_recurrence(path: Path | None = None) -> dict[str, int]:
    """
    Load the recurrence counters from disk.

    Returns an empty dict if the file is absent, unreadable, or malformed.
    """
    src = path or _RECURRENCE_PATH
    try:
        text = src.read_text(encoding="utf-8")
        data = json.loads(text)
        if isinstance(data, dict):
            return {
                k: int(v)
                for k, v in data.items()
                if isinstance(k, str) and k and isinstance(v, (int, float)) and v >= 0
            }
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        _log.debug("Failed to load recurrence data from %s: %s", src, exc)
    return {}


def save_recurrence(data: dict[str, int], path: Path | None = None) -> None:
    """
    Persist recurrence counters using an atomic write.

    Silently swallows OS errors — recurrence tracking is best-effort.
    """
    dest = path or _RECURRENCE_PATH
    tmp = dest.with_name(dest.name + ".tmp")
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        chown_to_sudo_user(dest.parent)
        # I-1 (v0.5.5): force 0o600 explicitly — relying on umask leaves
        # the file world-readable on default Debian/Ubuntu umasks (0644).
        # Aligns with bob.config / bob.compare / bob.report which all
        # use os.open(..., 0o600) for private state.
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        tmp.replace(dest)
        chown_to_sudo_user(dest)
    except OSError:
        tmp.unlink(missing_ok=True)


def update_recurrence(
    prev: dict[str, int],
    active_keys: set[str],
) -> dict[str, int]:
    """
    Return an updated recurrence dict for the current audit run.

    Keys in active_keys are incremented (or set to 1 if new).
    Keys not in active_keys are dropped — the finding was resolved.

    Args:
        prev:        Counters from the previous audit (may be empty).
        active_keys: Finding keys present in the current audit
                     (typically ALERT + WARN keys from engine.findings).

    Returns:
        New dict with updated counts — ready to be saved.
    """
    updated: dict[str, int] = {}
    for key in active_keys:
        val = prev.get(key, 0)
        if isinstance(val, (int, float)) and val >= 0:
            val = int(val)
        else:
            val = 0
        updated[key] = val + 1
    return updated
