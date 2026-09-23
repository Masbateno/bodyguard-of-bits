"""
Core-dump disposition check for BOB (CIS §1.5 — core dumps).

A core dump is a snapshot of a crashed process's memory. It can contain secrets
the process held — private keys, passwords, tokens, decrypted data. Where those
dumps go, and whether they are kept, is a real hardening question that
`kernel_hardening` only touches through `fs.suid_dumpable`. This check reports
the fuller modern picture:

  - `kernel.core_pattern` — a pipe to a handler (systemd-coredump, apport) or a
    filesystem path pattern;
  - systemd-coredump `Storage=` (none / external / journal) when it is the
    handler;
  - a global `hard core 0` limit in /etc/security/limits.conf(.d) that disables
    user core dumps outright.

Deliberately INFO-only (no deduction). A development or diagnostic host has a
legitimate reason to keep core dumps, so BOB states the disposition and the
secrets risk and lets the reader decide — it does not penalise a system for
being able to produce a core dump. The set-uid-dumpable *deduction* stays with
`kernel_hardening.suid_dumpable`; this check does not double-count it.

Findings:
  - core_pattern unreadable:                 INFO (unknown)
  - dumps discarded (Storage=none /
    hard core 0 / disabled pattern):         OK
  - handled by systemd-coredump, kept:       INFO (root-only store, may hold secrets)
  - piped to another handler:                INFO
  - written to a filesystem path:            INFO (may hold secrets)

Split into:
  1. CoreDumpsSnapshot.from_system() — collects state.
  2. check_core_dumps(snapshot, t)   — pure analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _identity_t,
    path_exists,
    read_text_capped,
)
from bob.scoring import CheckResult

_CORE_PATTERN = "/proc/sys/kernel/core_pattern"
_COREDUMP_CONF = "/etc/systemd/coredump.conf"
_COREDUMP_CONF_D = "/etc/systemd/coredump.conf.d"
_LIMITS_CONF = "/etc/security/limits.conf"
_LIMITS_D = "/etc/security/limits.d"

# `<domain> <type> core <value>` in limits.conf; we want a global (* or every)
# hard/both core 0 that disables dumps.
_HARD_CORE_ZERO = re.compile(
    r"^\s*(\*|-)\s+(hard|-)\s+core\s+0\b", re.MULTILINE)
# Storage= in coredump.conf (last wins).
_STORAGE = re.compile(r"^\s*Storage\s*=\s*(\w+)", re.MULTILINE | re.IGNORECASE)


@dataclass
class CoreDumpsSnapshot:
    """State collected about core-dump disposition.

    Args:
        core_pattern:     Raw kernel.core_pattern value, or "" if unreadable.
        readable:         False when core_pattern could not be read.
        storage:          systemd-coredump Storage= value (lowercased) or "".
        hard_core_zero:   True when a global `hard core 0` limit is set.
    """
    core_pattern:   str = ""
    readable:       bool = True
    storage:        str = ""
    hard_core_zero: bool = False

    @classmethod
    def from_system(cls) -> "CoreDumpsSnapshot":
        """Collect core-dump disposition. Never raises."""
        snap = cls()
        try:
            snap.core_pattern = read_text_capped(
                Path(_CORE_PATTERN), encoding="utf-8", errors="replace").strip()
        except OSError:
            snap.readable = False

        # systemd-coredump Storage= — main file then drop-ins (later wins).
        texts: list[str] = []
        if path_exists(Path(_COREDUMP_CONF)):
            try:
                texts.append(read_text_capped(Path(_COREDUMP_CONF),
                             encoding="utf-8", errors="replace"))
            except OSError:
                pass
        try:
            d = Path(_COREDUMP_CONF_D)
            if d.is_dir():
                for f in sorted(d.iterdir()):
                    if f.name.endswith(".conf"):
                        try:
                            texts.append(read_text_capped(
                                f, encoding="utf-8", errors="replace"))
                        except OSError:
                            pass
        except OSError:
            pass
        for text in texts:
            for m in _STORAGE.finditer(text):
                snap.storage = m.group(1).lower()

        # Global hard core 0 in limits.conf / limits.d.
        limit_texts: list[str] = []
        if path_exists(Path(_LIMITS_CONF)):
            try:
                limit_texts.append(read_text_capped(Path(_LIMITS_CONF),
                                   encoding="utf-8", errors="replace"))
            except OSError:
                pass
        try:
            d = Path(_LIMITS_D)
            if d.is_dir():
                for f in sorted(d.iterdir()):
                    if f.name.endswith(".conf"):
                        try:
                            limit_texts.append(read_text_capped(
                                f, encoding="utf-8", errors="replace"))
                        except OSError:
                            pass
        except OSError:
            pass
        snap.hard_core_zero = any(_HARD_CORE_ZERO.search(t) for t in limit_texts)

        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_core_dumps(snapshot: CoreDumpsSnapshot,
                     t: TranslationFunc | None = None) -> CheckResult:
    """Analyse CoreDumpsSnapshot and return findings (INFO-only)."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.readable:
        result.info(
            message=_t("core_dumps.unknown"),
            detail=_t("core_dumps.unknown_detail"),
            key="core_dumps.unknown",
        )
        return result

    pattern = snapshot.core_pattern
    is_pipe = pattern.startswith("|")
    is_systemd = is_pipe and "systemd-coredump" in pattern

    # Discarded outright?
    if snapshot.hard_core_zero or (is_systemd and snapshot.storage == "none"):
        result.ok(
            message=_t("core_dumps.disabled"),
            key="core_dumps.disabled",
        )
        return result

    if is_systemd:
        storage = snapshot.storage or "external"
        result.info(
            message=_t("core_dumps.systemd", storage=storage),
            detail=_t("core_dumps.systemd_detail", storage=storage),
            key="core_dumps.systemd",
        )
    elif is_pipe:
        handler = pattern[1:].split()[0] if len(pattern) > 1 else "?"
        result.info(
            message=_t("core_dumps.piped", handler=handler),
            detail=_t("core_dumps.piped_detail", handler=handler),
            key="core_dumps.piped",
        )
    else:
        result.info(
            message=_t("core_dumps.to_disk", pattern=pattern or "core"),
            detail=_t("core_dumps.to_disk_detail"),
            key="core_dumps.to_disk",
        )

    return result
