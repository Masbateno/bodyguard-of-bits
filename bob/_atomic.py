"""Atomic file write — single source of truth for crash-safe file persistence.

Consolidates the temp-write + ``os.replace`` pattern previously duplicated
across ``bob/cron/_io.py``, ``bob/config.py``, ``bob/compare.py``,
``bob/history.py``, ``bob/recurrence.py`` — and absent at sites that
should have had it (``bob/ignore.py``, ``bob/cron/_install.py``,
``bob/tui/cron.py`` first-install paths). Extracted in v0.6.1.

Contract: power loss / SIGKILL / OOM between the start of ``atomic_write``
and its successful return leaves the destination file in its previous state.
The temp file may remain on disk (caller should not assume cleanup) but the
destination is never partially written.

v0.7.1 hardening (M-2): ``fsync(fd)`` before close + ``fsync(dir_fd)`` after
rename. On ext4 default + most other Linux filesystems, ``os.replace`` is
durable across the rename metadata only after the parent directory's inode
is fsynced — and the new file's data only after ``fsync(fd)`` on the open
file descriptor. Without those, power loss between the syscall sequence
and the next kernel flush can leave a zero-byte file on disk. Pre-v0.7.1
the docstring promised "crash-safe" but the impl skipped both fsyncs.
"""

from __future__ import annotations

import os
from pathlib import Path


def atomic_write(path: Path, content: str, *, mode: int = 0o600) -> None:
    """Write *content* to *path* atomically (temp file + os.replace).

    The mode parameter is **required** for any non-private file. Default
    ``0o600`` is correct for state files in ``~/.config/bob/``. Cron files
    (``0o640``), wrapper scripts (``0o755``), and any other file mode MUST
    pass ``mode=`` explicitly — otherwise the destination inherits the tmp
    file's ``0o600``, breaking the original file's permissions.

    Args:
        path:    destination Path
        content: text to write (UTF-8 encoded)
        mode:    file mode for the new file (default 0o600)

    Raises:
        OSError: on filesystem errors. The caller decides whether to swallow
                 (best-effort persistence) or surface to the user.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
        fh.flush()
        # M-2 (v0.7.1): fsync the data + metadata of the tmp file BEFORE
        # the rename. Without this, ext4's default journal mode (data=ordered)
        # commits the rename metadata before the data, leaving a zero-byte
        # file on power loss.
        os.fsync(fh.fileno())
    os.replace(str(tmp), str(path))
    # M-2 (v0.7.1): fsync the parent directory inode so the rename is
    # durable. Best-effort: on filesystems / mounts that disallow
    # directory fsync (rare) the OSError is swallowed.
    try:
        dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass
