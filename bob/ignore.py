"""
User-defined finding ignore list for BOB.

Reads and writes ~/.config/bob/ignore.yml.
Format (subset of YAML, parsed without external dependencies):

    ignore:
      - key: ssh.permit_root_login
      - key: log_rotation.remote_syslog_none

When running via sudo, the real user's home directory is used
(via SUDO_USER), so the ignore list belongs to the operator, not root.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from bob._atomic import atomic_write
from bob.sysinfo import chown_to_sudo_user, get_user_home

_log = logging.getLogger(__name__)

_IGNORE_FILENAME = "ignore.yml"

# Matches lines like "  - key: ssh.permit_root_login"
_KEY_LINE_RE = re.compile(r"^\s*-\s+key:\s+(\S+)\s*$")

# M-5 (v0.7.1): canonical EXPLAIN_KEYS pattern — same as enforced by
# ``tests/test_explain_naming_convention.py``. Lowercase + digits +
# underscores, dotted hierarchy, at least one dot. Pre-v0.7.1
# ``add_ignore_key`` accepted any non-empty string; the YAML writer then
# split on whitespace and silently truncated multi-word keys, so users
# typing ``--ignore="something with spaces"`` saw "added" but the next
# audit didn't ignore anything because the loader couldn't match the key.
_CANONICAL_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")


# ---------------------------------------------------------------------------
# Path helper
# ---------------------------------------------------------------------------

def _ignore_file_path() -> Path:
    """Return the ignore.yml path for the effective (non-root) user."""
    return get_user_home() / ".config" / "bob" / _IGNORE_FILENAME


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_ignore_keys(path: Path | None = None) -> frozenset[str]:
    """
    Load ignored finding keys from ignore.yml.

    Returns an empty frozenset if the file does not exist or cannot be read.
    """
    if path is None:
        path = _ignore_file_path()
    if not path.exists():
        return frozenset()
    keys: set[str] = set()
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            m = _KEY_LINE_RE.match(line)
            if m:
                keys.add(m.group(1))
    except OSError as exc:
        _log.debug("Cannot read ignore file %s: %s", path, exc)
    return frozenset(keys)


def is_valid_ignore_key(key: str) -> bool:
    """Return True if *key* matches the canonical EXPLAIN_KEYS pattern.

    The pattern is ``<prefix>.<finding_id>`` snake_case (lowercase + digits +
    underscores, dotted hierarchy, at least one dot). Same shape enforced by
    ``tests/test_explain_naming_convention.py`` on the 117 keys / 30 prefixes
    declared in ``bob/explain.py``.

    Used by ``add_ignore_key`` and by the CLI ``--ignore`` handler to reject
    typos before the YAML write.
    """
    return isinstance(key, str) and bool(_CANONICAL_KEY_RE.match(key))


def add_ignore_key(key: str, path: Path | None = None) -> bool:
    """
    Append *key* to ignore.yml.

    Creates the file (and parent directories) if needed.
    Returns True if the key was added, False if it was already present
    or fails the canonical-key validation (use ``is_valid_ignore_key`` to
    distinguish the two cases before calling).
    """
    if not is_valid_ignore_key(key):
        return False
    if path is None:
        path = _ignore_file_path()
    if key in load_ignore_keys(path):
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        chown_to_sudo_user(path.parent)
        if path.exists():
            content = path.read_text(encoding="utf-8")
            if "ignore:" in content:
                content = content.rstrip("\n") + f"\n  - key: {key}\n"
            else:
                content = content.rstrip("\n") + f"\nignore:\n  - key: {key}\n"
        else:
            content = f"ignore:\n  - key: {key}\n"
        # I-6 (v0.6.1): switched from raw os.open(O_TRUNC) to atomic_write.
        # Pre-fix, power-loss between truncate and write left ignore.yml
        # corrupted (lost all previously-ignored keys). atomic_write writes
        # to a .tmp sibling and atomically renames on completion. Mode 0o600
        # still enforced via the explicit mode= parameter.
        atomic_write(path, content, mode=0o600)
        chown_to_sudo_user(path)
        return True
    except OSError:
        return False
