"""
Root PATH hardening check for BOB (access control, CIS "root PATH integrity").

A world-writable directory in root's PATH, a ``.`` or empty component, or a
relative entry all mean the same thing: someone who is not root can decide which
binary root runs for a bare command name. Drop a file called ``ls`` in that
directory (or in the current directory, for ``.``/empty), wait for root to run
``ls``, and it runs as root. It is a classic, entirely deterministic privilege
escalation.

The PATH audited is the **configured** root PATH, read from files, not the
ambient ``os.environ["PATH"]``. The environment PATH depends on how BOB was
launched (``sudo`` resets it, ``sudo -i`` does not), so a verdict built on it
would not be reproducible and could not be compared across runs. The file
sources are deterministic:

  - ``/etc/login.defs`` ``ENV_SUPATH`` — the PATH the login stack gives root;
  - sudoers ``Defaults secure_path`` — the PATH ``sudo`` imposes on commands.

Both fall back to the ``/usr/etc`` vendor layout (openSUSE, image-based distros).
If neither source exists, the configured root PATH is genuinely unknown and BOB
says so rather than guessing from its own environment.

Findings:
  - world-writable dir / ``.`` / empty / relative component : WARN −1 (dangerous)
  - dir writable by a non-root group                        : INFO (weaker)
  - sources present, every component clean                  : OK
  - no configured source found                              : INFO (unknown)

Split into:
  1. RootPathSnapshot.from_system() — collects state (never raises).
  2. check_root_path(snapshot, t)   — pure analysis.
"""

from __future__ import annotations

import os
import re
import stat as _stat
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _identity_t,
    path_exists,
    read_text_capped,
)
from bob.scoring import CheckResult

_LOGIN_DEFS = (Path("/etc/login.defs"), Path("/usr/etc/login.defs"))
_SUDOERS = (Path("/etc/sudoers"), Path("/usr/etc/sudoers"))

_SECURE_PATH_RE = re.compile(r"secure_path\s*=\s*\"?([^\"#\n]+)\"?")


def _classify(entry: str) -> "str | None":
    """Classify one PATH component; return a reason string if dangerous/weak,
    or None if it is a normal, safe absolute directory.

    Returns one of: "empty", "dot", "relative", "world_writable",
    "group_writable", or None.
    """
    if entry == "":
        return "empty"          # an empty component means the current directory
    if entry == ".":
        return "dot"
    if not entry.startswith("/"):
        return "relative"
    try:
        st = os.stat(entry)     # metadata only — never blocks
    except OSError:
        return None             # cannot judge a directory we cannot stat
    if not _stat.S_ISDIR(st.st_mode):
        return None             # a non-directory in PATH is inert, not writable-privesc
    if st.st_mode & _stat.S_IWOTH:
        return "world_writable"
    if (st.st_mode & _stat.S_IWGRP) and st.st_gid != 0:
        return "group_writable"
    return None


@dataclass
class RootPathSnapshot:
    """State collected about root's configured PATH.

    Args:
        dangerous:      list of (source, component, reason) for world-writable /
                        dot / empty / relative components (WARN).
        group_writable: list of (source, component, reason) for non-root
                        group-writable directories (INFO).
        read_any:       True if at least one configured PATH source was read.
    """
    dangerous:      "list[tuple[str, str, str]]" = field(default_factory=list)
    group_writable: "list[tuple[str, str, str]]" = field(default_factory=list)
    read_any:       bool = False

    @classmethod
    def from_system(cls) -> "RootPathSnapshot":
        """Collect root's configured PATH and classify it. Never raises."""
        snap = cls()
        sources: "list[tuple[str, str]]" = []

        # login.defs ENV_SUPATH (root's login PATH)
        for p in _LOGIN_DEFS:
            if not path_exists(p):
                continue
            try:
                body = read_text_capped(p, encoding="utf-8", errors="replace")
            except OSError:
                continue
            for raw in body.splitlines():
                line = raw.strip()
                if line.startswith("ENV_SUPATH"):
                    val = line[len("ENV_SUPATH"):].strip()
                    if val.startswith("PATH="):
                        val = val[len("PATH="):]
                    sources.append(("login.defs ENV_SUPATH", val.strip()))
            break   # first existing login.defs wins (/etc over /usr/etc)

        # sudoers secure_path
        for p in _SUDOERS:
            if not path_exists(p):
                continue
            try:
                body = read_text_capped(p, encoding="utf-8", errors="replace")
            except OSError:
                continue
            for raw in body.splitlines():
                if raw.lstrip().startswith("#"):
                    continue
                m = _SECURE_PATH_RE.search(raw)
                if m:
                    sources.append(("sudoers secure_path", m.group(1).strip()))
            break

        snap.read_any = bool(sources)
        for source, path_str in sources:
            for entry in path_str.split(":"):
                reason = _classify(entry)
                if reason is None:
                    continue
                shown = entry if entry != "" else "(empty)"
                if reason == "group_writable":
                    snap.group_writable.append((source, shown, reason))
                else:
                    snap.dangerous.append((source, shown, reason))

        snap.dangerous = sorted(set(snap.dangerous))
        snap.group_writable = sorted(set(snap.group_writable))
        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_root_path(snapshot: RootPathSnapshot,
                    t: TranslationFunc | None = None) -> CheckResult:
    """Analyse RootPathSnapshot and return findings."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.read_any:
        result.info(message=_t("root_path.unknown"),
                    key="root_path.unknown")
        return result

    if snapshot.dangerous:
        listed = ", ".join(f"{c} [{src}]" for src, c, _r in snapshot.dangerous)
        result.warn_with_deduction(
            key="root_path.dangerous",
            message=_t("root_path.dangerous",
                       count=len(snapshot.dangerous), entries=listed),
            reason=_t("root_path.dangerous_reason",
                      count=len(snapshot.dangerous)),
            points=1,
            detail=_t("root_path.dangerous_detail"),
            cmd_type="check",
        )
    elif snapshot.group_writable:
        listed = ", ".join(f"{c} [{src}]" for src, c, _r in snapshot.group_writable)
        result.info(message=_t("root_path.group_writable", entries=listed),
                    key="root_path.group_writable")
    else:
        result.ok(message=_t("root_path.clean"), key="root_path.clean")

    return result
