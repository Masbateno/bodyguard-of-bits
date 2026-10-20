"""BOB jobs kept in root's crontab, for a crond with no ``/etc/cron.d`` (v0.26.0).

BusyBox crond (Alpine) reads one file per user in ``/etc/crontabs/`` and has
no ``/etc/cron.d``: 0.25.1 refused ``--install-cron`` there. A job is now a
block of root's crontab, between two marker lines, and only that block is ever
rewritten — the lines the system or the operator put there stay as they are.

Measured on Alpine 3.24 (BusyBox v1.37.0): an edit of ``/etc/crontabs/root``
was not picked up in three minutes; with ``root`` appended to
``/etc/crontabs/cron.update`` (what ``crontab -e`` does) crond re-read the file
within a minute and removed ``cron.update``. Every change here ends with it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from bob._atomic import atomic_write

CRONTABS_DIR = Path("/etc/crontabs")
ROOT_CRONTAB = CRONTABS_DIR / "root"
CRON_UPDATE = CRONTABS_DIR / "cron.update"

_BEGIN = "# BEGIN BOB cron bob-{slug}"
_END = "# END BOB cron bob-{slug}"
_BLOCK_RE = re.compile(
    r"^# BEGIN BOB cron bob-(?P<slug>[a-z0-9-]+)\n(?P<body>.*?)^# END BOB cron bob-(?P=slug)\n?",
    re.MULTILINE | re.DOTALL,
)
_LINE_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(/\S+)\s*$", re.MULTILINE)


def available() -> bool:
    """Whether root's crontab directory is where jobs go on this host."""
    return CRONTABS_DIR.is_dir()


def _read() -> str:
    try:
        return ROOT_CRONTAB.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def blocks() -> "list[tuple[str, str]]":
    """``(slug, body)`` for each BOB block of root's crontab."""
    return [(m.group("slug"), m.group("body")) for m in _BLOCK_RE.finditer(_read())]


def block_text(slug: str, comment_lines: "list[str]", schedule_expr: str, script_path) -> str:
    """The block for one job: markers, comments, one crontab line (no user field)."""
    body = "".join(f"{c}\n" for c in comment_lines)
    return (f"{_BEGIN.format(slug=slug)}\n{body}"
            f"{schedule_expr}  {script_path}\n{_END.format(slug=slug)}\n")


def has_block(slug: str) -> bool:
    return any(s == slug for s, _ in blocks())


def parse_line(body: str) -> "tuple[str, str] | None":
    """``(schedule_expr, script)`` of a block's crontab line, or None."""
    m = _LINE_RE.search(body)
    if not m:
        return None
    return " ".join(m.groups()[:5]), m.group(6)


def _write(text: str) -> None:
    try:
        mode = ROOT_CRONTAB.stat().st_mode & 0o777
    except FileNotFoundError:
        mode = 0o600
    atomic_write(ROOT_CRONTAB, text, mode=mode)
    # crond re-reads a user's crontab when its name is in cron.update.
    fd = os.open(CRON_UPDATE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, b"root\n")
    finally:
        os.close(fd)


def put_block(slug: str, block: str) -> None:
    """Insert or replace the block for *slug*; everything else is kept."""
    text = _read()
    if any(s == slug for s, _ in blocks()):
        text = _BLOCK_RE.sub(lambda m: block if m.group("slug") == slug else m.group(0), text)
    else:
        if text and not text.endswith("\n"):
            text += "\n"
        text += ("\n" if text else "") + block
    _write(text)


def remove_block(slug: str) -> bool:
    """Remove the block for *slug*. False when there was none."""
    text = _read()
    m = next((m for m in _BLOCK_RE.finditer(text) if m.group("slug") == slug), None)
    if m is None:
        return False
    start = m.start()
    # The blank line put_block wrote before the block goes with it; nothing else.
    if start >= 2 and text[start - 2:start] == "\n\n":
        start -= 1
    _write(text[:start] + text[m.end():])
    return True
