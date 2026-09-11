"""Path predicates that still say "I was not allowed to look".

Up to Python 3.13, ``Path.exists()``, ``is_file()``, ``is_dir()`` and
``is_symlink()`` swallowed four errnos — ENOENT, ENOTDIR, EBADF, ELOOP — and
re-raised everything else. A path under a directory BOB may not traverse raised
``PermissionError``, and several call sites were written around that raise:
it was how they told *absent* from *off-limits*.

Python 3.14 changed that. Measured on 3.14.7 against a file inside a mode-000
directory::

    3.13.15   Path.is_file -> PermissionError   Path.stat -> PermissionError
    3.14.7    Path.is_file -> False             Path.stat -> PermissionError

So on 3.14 every ``except PermissionError`` around those predicates became
unreachable, and the answer silently turned into *absent* — the class this
project had closed five times, reopened by an interpreter upgrade with no
change to BOB's code. The CI caught it on one test; the same shape changed the
answer in three more places.

These helpers keep the ≤3.13 contract on every version by asking ``stat()``
directly, which still raises on 3.14. Use them wherever the *exception* is part
of the answer; where a denial and an absence are meant to be the same answer,
the plain predicates — or ``checks._run.path_exists`` — are fine.
"""

from __future__ import annotations

import errno
import stat
from pathlib import Path

# The errnos pathlib ≤3.13 turned into False. Anything else is a real failure
# to look and is raised.
_ABSENT = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP})


def _mode(path: Path, *, follow: bool) -> int | None:
    try:
        return (path.stat() if follow else path.lstat()).st_mode
    except OSError as exc:
        if exc.errno in _ABSENT:
            return None
        raise
    except ValueError:
        # An embedded NUL, as pathlib has always treated it: not there.
        return None


def strict_is_file(path: Path) -> bool:
    """``Path.is_file()`` as it behaved up to 3.13: raises on a denial."""
    mode = _mode(path, follow=True)
    return mode is not None and stat.S_ISREG(mode)


def strict_is_symlink(path: Path) -> bool:
    """``Path.is_symlink()`` as it behaved up to 3.13: raises on a denial."""
    mode = _mode(path, follow=False)
    return mode is not None and stat.S_ISLNK(mode)
