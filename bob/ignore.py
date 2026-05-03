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
import os
import re
from pathlib import Path

_log = logging.getLogger(__name__)

_IGNORE_FILENAME = "ignore.yml"

# Matches lines like "  - key: ssh.permit_root_login"
_KEY_LINE_RE = re.compile(r"^\s*-\s+key:\s+(\S+)\s*$")


# ---------------------------------------------------------------------------
# Path helper
# ---------------------------------------------------------------------------

def _ignore_file_path() -> Path:
    """Return the ignore.yml path for the effective (non-root) user."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            home = Path(pwd.getpwnam(sudo_user).pw_dir)
        except (KeyError, ImportError):
            home = Path.home()
    else:
        home = Path.home()
    return home / ".config" / "bob" / _IGNORE_FILENAME


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


def add_ignore_key(key: str, path: Path | None = None) -> bool:
    """
    Append *key* to ignore.yml.

    Creates the file (and parent directories) if needed.
    Returns True if the key was added, False if it was already present.
    """
    if not key or not isinstance(key, str) or not key.strip():
        return False
    if path is None:
        path = _ignore_file_path()
    if key in load_ignore_keys(path):
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            content = path.read_text(encoding="utf-8")
            if "ignore:" in content:
                content = content.rstrip("\n") + f"\n  - key: {key}\n"
            else:
                content = content.rstrip("\n") + f"\nignore:\n  - key: {key}\n"
        else:
            content = f"ignore:\n  - key: {key}\n"
        path.write_text(content, encoding="utf-8")
        return True
    except OSError:
        return False
