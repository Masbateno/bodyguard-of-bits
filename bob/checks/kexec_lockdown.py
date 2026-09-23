"""
kexec / kernel-lockdown check for BOB (boot-integrity surface, CIS §1.5 family).

A natural companion to Secure Boot and GRUB: those verify what runs *at* boot;
this looks at two knobs that decide whether the *running* kernel's integrity can
be undercut afterwards.

  - `kernel.kexec_load_disabled` — when 0, a new kernel image can be loaded and
    booted into with kexec, without a reboot and without going back through the
    firmware. That bypasses Secure Boot for the next kernel. Setting it to 1
    locks kexec for the rest of the uptime.
  - Kernel **lockdown** (`/sys/kernel/security/lockdown`) — `none`,
    `integrity`, or `confidentiality`. When active it blocks the classic paths
    a root user has to modify the running kernel (/dev/mem, unsigned modules,
    kexec of unsigned images, …).

Deliberately INFO-only. kexec is legitimately used by kdump (crash-dump capture),
and lockdown is off by default on most systems that do not enforce Secure Boot,
so BOB reports the state and what it means rather than penalising a host for
being able to kexec. It never says "kexec available = vulnerability".

Findings:
  - kexec_load_disabled = 1:            OK
  - kexec_load_disabled = 0:            INFO (allowed; note the Secure-Boot bypass)
  - lockdown integrity/confidentiality: OK
  - lockdown none:                      INFO (not active)
  - lockdown interface absent:          INFO (kernel without the lockdown LSM)
  - both unreadable:                    INFO (unknown)

Split into:
  1. KexecLockdownSnapshot.from_system() — collects state.
  2. check_kexec_lockdown(snapshot, t)   — pure analysis (INFO-only).
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

_KEXEC_DISABLED = "/proc/sys/kernel/kexec_load_disabled"
_LOCKDOWN = "/sys/kernel/security/lockdown"

# The active lockdown mode is the bracketed token: "[none] integrity confidentiality".
_BRACKET = re.compile(r"\[(\w+)\]")


@dataclass
class KexecLockdownSnapshot:
    """State collected about kexec locking and kernel lockdown.

    Args:
        kexec_disabled: kernel.kexec_load_disabled (0/1), or None if unreadable.
        lockdown:       active lockdown mode ("none"/"integrity"/
                        "confidentiality"), "" if the interface is absent, or
                        None if present-but-unreadable.
    """
    kexec_disabled: "int | None" = None
    lockdown:       "str | None" = ""

    @classmethod
    def from_system(cls) -> "KexecLockdownSnapshot":
        """Collect kexec/lockdown state. Never raises."""
        snap = cls()
        try:
            raw = read_text_capped(Path(_KEXEC_DISABLED), encoding="utf-8",
                                   errors="replace").strip()
            snap.kexec_disabled = int(raw) if raw in ("0", "1") else None
        except (OSError, ValueError):
            snap.kexec_disabled = None

        if not path_exists(Path(_LOCKDOWN)):
            snap.lockdown = ""   # kernel built without the lockdown LSM
        else:
            try:
                text = read_text_capped(Path(_LOCKDOWN), encoding="utf-8",
                                        errors="replace")
                m = _BRACKET.search(text)
                snap.lockdown = m.group(1).lower() if m else None
            except OSError:
                snap.lockdown = None
        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_kexec_lockdown(snapshot: KexecLockdownSnapshot,
                         t: TranslationFunc | None = None) -> CheckResult:
    """Analyse KexecLockdownSnapshot and return findings (INFO-only)."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- kexec ---------------------------------------------------------------
    if snapshot.kexec_disabled == 1:
        result.ok(message=_t("kexec_lockdown.kexec_disabled"),
                  key="kexec_lockdown.kexec_disabled")
    elif snapshot.kexec_disabled == 0:
        result.info(message=_t("kexec_lockdown.kexec_allowed"),
                    detail=_t("kexec_lockdown.kexec_allowed_detail"),
                    key="kexec_lockdown.kexec_allowed")
    else:
        result.info(message=_t("kexec_lockdown.kexec_unknown"),
                    key="kexec_lockdown.kexec_unknown")

    # --- lockdown ------------------------------------------------------------
    if snapshot.lockdown in ("integrity", "confidentiality"):
        result.ok(message=_t("kexec_lockdown.lockdown_active",
                             mode=snapshot.lockdown),
                  key="kexec_lockdown.lockdown_active")
    elif snapshot.lockdown == "none":
        result.info(message=_t("kexec_lockdown.lockdown_none"),
                    detail=_t("kexec_lockdown.lockdown_none_detail"),
                    key="kexec_lockdown.lockdown_none")
    elif snapshot.lockdown == "":
        result.info(message=_t("kexec_lockdown.lockdown_absent"),
                    key="kexec_lockdown.lockdown_absent")
    else:  # None — present but unreadable
        result.info(message=_t("kexec_lockdown.lockdown_unknown"),
                    key="kexec_lockdown.lockdown_unknown")

    return result
