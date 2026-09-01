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

from bob._atomic import atomic_write, read_text_capped
from bob.sysinfo import chown_to_sudo_user, get_user_home
from bob.checks._run import path_exists

_log = logging.getLogger(__name__)

_IGNORE_FILENAME = "ignore.yml"

# Matches lines like "  - key: ssh.permit_root_login" — also accepts
# trailing whitespace + inline ``# comment`` annotation.
#
# I-1 pass 8 (v0.8.1 audit) — dropped the ``\s*$`` anchor that the
# previous shape used. Pre-fix, lines with trailing inline comments
# (``  - key: ssh.password_auth  # legacy automation``) failed the
# loader regex. The pass-7 ``remove_ignore_key`` rewrite added a sibling
# unanchored regex with the documented intent of handling that case, but
# the ``if key not in load_ignore_keys(path)`` defensive guard at the
# top of ``remove_ignore_key`` short-circuited before the relaxed
# remover regex was reached — so the inline-comment relaxation was
# unreachable dead code. Dropping the anchor here unifies loader +
# remover semantics: both now accept whitespace + ``#`` + anything after
# the key value. Capture group 1 is the key value; trailing content is
# ignored at parse time and preserved at line-walk time.
_KEY_LINE_RE = re.compile(r"^\s*-\s+key:\s+(\S+)")

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
    if not path_exists(path):
        return frozenset()
    keys: set[str] = set()
    try:
        for line in read_text_capped(path).splitlines():
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
        if path_exists(path):
            content = read_text_capped(path)
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


def remove_ignore_key(key: str, path: Path | None = None) -> bool:
    """T57 (v0.8.1): remove *key* from ignore.yml. Mirror of ``add_ignore_key``.

    Returns True if the key was present and removed, False if it was not
    present (or the file doesn't exist) or the canonical-key validation
    fails. Atomic-write via ``_atomic.atomic_write`` so an in-flight power
    loss leaves the file in its previous state.

    Pre-T57 v0.8.1, users could ``bob --ignore=KEY`` to add an entry but had
    to edit ``~/.config/bob/ignore.yml`` by hand to remove it. This helper
    closes the symmetry gap.

    **I-1 (v0.8.1 audit fix) — comment preservation.** Walks the file
    line-by-line and drops only the line(s) matching ``- key: <removed>``,
    preserving every operator comment + custom YAML structure verbatim.
    Pre-I-1 the implementation re-emitted the file in canonical form
    (``ignore:\n  - key: X\n``), which silently discarded hand-curated
    annotations operators had added pre-T57 when manual edit was the only
    removal path (ticket numbers, expiry notes, justifications). A
    pre-existing orphan comment that referenced the now-removed key is
    intentionally left in place — drop-by-name heuristics would risk
    deleting unrelated multi-key comment blocks.
    """
    if not is_valid_ignore_key(key):
        return False
    if path is None:
        path = _ignore_file_path()
    if not path_exists(path):
        return False
    if key not in load_ignore_keys(path):
        return False
    try:
        original = read_text_capped(path)
        new_lines: list[str] = []
        removed = False
        for line in original.splitlines(keepends=True):
            # I-1 pass 7 (v0.8.1 audit fix): match the loader's grammar
            # instead of the one-space ``startswith("- key:")`` prefix.
            # Pre-fix, files with two-space indentation (``  -  key:
            # ssh.x``) or tabs between ``-`` and ``key:`` were silently
            # un-removable — loader saw the key, remover didn't,
            # defensive bail-out printed the misleading "Key not
            # present" message.
            # I-1 pass 8: loader + remover now share ``_KEY_LINE_RE``
            # since the anchor split that pass 7 introduced was dead
            # code (load_ignore_keys's guard masked it).
            m = _KEY_LINE_RE.match(line)
            if m is not None and m.group(1) == key:
                removed = True
                continue  # drop this line; preserve everything else
            new_lines.append(line)
        if not removed:
            # Defensive: ``load_ignore_keys`` reported the key present, but
            # the line-walk couldn't find it (e.g. multi-line YAML form).
            # Bail rather than silently no-op or destructively rewrite.
            return False
        atomic_write(path, "".join(new_lines), mode=0o600)
        chown_to_sudo_user(path)
        return True
    except OSError:
        return False
