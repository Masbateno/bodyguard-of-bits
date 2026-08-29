"""Shared file I/O — crash-safe writes, and bounded reads.

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

import errno
import os
import tempfile
from pathlib import Path

# v0.14.1: generous ceiling for any state file BOB reads back. None of them is
# meant to approach it (history.jsonl is rotation-capped, a baseline is tens of
# KB); it exists so a read can never run away.
_DEFAULT_READ_CAP = 8 * 1024 * 1024  # 8 MB


def read_text_capped(
    path: Path,
    *,
    max_bytes: int = _DEFAULT_READ_CAP,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> str:
    """Read a *regular* file, never more than ``max_bytes``.

    v0.14.1 — every state-file reader used a bare ``read_text()``, which is
    unbounded and will happily read anything the path resolves to. Measured:

      * ``--diff=/dev/zero``, or ``~/.config/bob/ignore.yml`` symlinked to it,
        read NUL bytes until the process died (exit 3, or an outright OOM kill);
      * ``--diff=<fifo>`` **blocked forever** — the worst outcome of the two,
        because a cron job hangs instead of failing, and does so again on every
        subsequent run.

    ``--diff=PATH`` takes an arbitrary operator-supplied path, so this is
    reachable by a plain typo, not only by self-sabotage.

    Rejecting non-regular files also covers directories and sockets.
    ``Path.is_file()`` follows symlinks, so a symlink to a real file still
    reads normally.

    Raises:
        OSError: if *path* is not a regular file, or exceeds ``max_bytes``.
                 Every caller already degrades on ``OSError``.
    """
    # Order matters: a missing file must still raise FileNotFoundError, exactly
    # as ``read_text()`` did. ``bob.compare.load_baseline`` branches on it to
    # tell "baseline not found" (a normal first run, or a bad --diff path) from
    # "baseline unreadable", and v0.9.2 shipped distinct localised messages for
    # the two.
    if not path.exists():
        raise FileNotFoundError(errno.ENOENT, "no such file", str(path))
    if not path.is_file():
        raise OSError(errno.EINVAL, "not a regular file", str(path))
    with path.open(encoding=encoding, errors=errors) as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise OSError(errno.EFBIG, f"file exceeds {max_bytes} bytes", str(path))
    return data


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
    # M-7 (v0.7.2): use tempfile.NamedTemporaryFile to generate a per-call
    # unique tmp name in the destination directory. Pre-v0.7.2 the tmp
    # name was the fixed pattern ``path.suffix + ".tmp"``: two concurrent
    # ``bob`` invocations (cron + manual + watch can coincide) raced on
    # the same path; O_TRUNC let writer B overwrite A's bytes mid-flight
    # and A's ``os.replace`` then committed an inconsistent file.
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent),
    )
    try:
        os.fchmod(tmp_fd, mode)
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            # M-2 (v0.7.1): fsync the data + metadata of the tmp file BEFORE
            # the rename. Without this, ext4's default journal mode
            # (data=ordered) commits the rename metadata before the data,
            # leaving a zero-byte file on power loss.
            os.fsync(fh.fileno())
        os.replace(tmp_name, str(path))
    except BaseException:
        # M-7: clean up the tmp file on ANY failure path, otherwise tmpfile
        # litter accumulates in ~/.config/bob/ until the next successful
        # write. Best-effort: a second OSError is swallowed (the original
        # exception is re-raised).
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
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
