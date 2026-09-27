"""
Kernel-module blacklist check for BOB (defense-in-depth, CIS §3.4 family).

Companion to ``kernel_modules``, not a duplicate:

  - ``kernel_modules`` flags rarely-needed modules that are **currently loaded**
    (the real, present attack surface — read from ``lsmod`` / /proc/modules).
  - this check looks at the modules that are **not loaded** and asks whether the
    system is configured to *keep* them from loading — a ``blacklist <mod>`` or
    an ``install <mod> /bin/true`` (or /bin/false) line under the modprobe.d
    directories. That is pure defense-in-depth: a module already loaded is the
    other check's concern and is never re-reported here.

Deliberately INFO-only, and deliberately un-noisy: rather than emitting one
finding per module, it emits a **single** aggregated INFO listing the
rarely-needed modules that are neither loaded nor prevented from loading. It
never deduces from their absence (an un-blacklisted module is not a
vulnerability — it is a hardening opportunity), and it never penalises.

The recommended set follows CIS §3.4 (filesystems + rare network protocols +
usb-storage). ``squashfs`` is deliberately excluded: it is required by ``snap``
on Ubuntu, so recommending its blacklist would be actively wrong there.

Split into:
  1. ModuleBlacklistSnapshot.from_system() — collects state (never raises).
  2. check_module_blacklist(snapshot, t)   — pure analysis (INFO-only).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _identity_t,
    read_text_capped,
)
from bob.scoring import CheckResult

# Directories modprobe reads blacklist/install directives from, in the order
# the tooling documents them. /usr/lib is the vendor location, /run the
# runtime one, /etc the administrator one.
_MODPROBE_DIRS: "tuple[str, ...]" = (
    "/etc/modprobe.d",
    "/run/modprobe.d",
    "/usr/lib/modprobe.d",
)

_PROC_MODULES = "/proc/modules"

# Rarely-needed filesystem modules (CIS §3.4.1). squashfs is EXCLUDED on
# purpose — snap mounts squashfs images on Ubuntu, so blacklisting it breaks
# the system. usb_storage is the CIS "disable USB storage" recommendation.
_RECO_FS: "frozenset[str]" = frozenset({
    "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf",
})
# Rarely-needed / historically-exploited network protocol modules (CIS §3.4.2).
_RECO_NET: "frozenset[str]" = frozenset({
    "dccp", "sctp", "rds", "tipc",
})
# modprobe treats '-' and '_' as equivalent; /proc/modules always uses '_'.
RECOMMENDED: "frozenset[str]" = _RECO_FS | _RECO_NET | frozenset({"usb_storage"})


def _norm(name: str) -> str:
    """Normalise a module name the way modprobe does ('-' and '_' equivalent)."""
    return name.strip().replace("-", "_")


@dataclass
class ModuleBlacklistSnapshot:
    """State collected about module blacklisting.

    Args:
        loaded:       set of currently-loaded module names (normalised).
        disabled:     set of modules prevented from loading via a blacklist or
                      an ``install ... /bin/true|false`` line (normalised).
        config_read:  True if at least one existing modprobe.d directory could
                      be listed; False only when every present directory was
                      unreadable (permission denied) — the honest "unknown".
    """
    loaded:      "set[str]" = field(default_factory=set)
    disabled:    "set[str]" = field(default_factory=set)
    config_read: bool = True

    @classmethod
    def from_system(cls) -> "ModuleBlacklistSnapshot":
        """Collect loaded modules and modprobe blacklist state. Never raises."""
        snap = cls()

        # --- loaded modules (kernel_modules' domain; used here only to skip) ---
        try:
            text = read_text_capped(Path(_PROC_MODULES), encoding="utf-8",
                                    errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line:
                    snap.loaded.add(_norm(line.split()[0]))
        except OSError:
            # /proc/modules unreadable — leave loaded empty. The only effect is
            # that a loaded-but-not-blacklisted module could be listed as a
            # candidate; still INFO-only, still harmless.
            pass

        # --- blacklist / install directives -----------------------------------
        any_dir_seen = False
        any_dir_readable = False
        for dpath in _MODPROBE_DIRS:
            d = Path(dpath)
            try:
                names = os.listdir(d)          # metadata only — never blocks
            except FileNotFoundError:
                continue                        # directory simply absent
            except OSError:
                any_dir_seen = True             # present but permission-denied
                continue
            any_dir_seen = True
            any_dir_readable = True
            for name in names:
                if not name.endswith(".conf"):
                    continue
                try:
                    body = read_text_capped(d / name, encoding="utf-8",
                                            errors="replace")
                except OSError:
                    # unreadable / FIFO / non-regular: skip, never hang
                    continue
                snap._absorb(body)

        # "unknown" only when directories exist but none could be read.
        snap.config_read = (not any_dir_seen) or any_dir_readable
        return snap

    def _absorb(self, body: str) -> None:
        """Parse one modprobe.d file body for blacklist/install directives."""
        for raw in body.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            directive = parts[0].lower()
            if directive == "blacklist":
                self.disabled.add(_norm(parts[1]))
            elif directive == "install" and len(parts) >= 3:
                # `install <mod> /bin/true` (or /bin/false) disables loading.
                cmd = os.path.basename(parts[2])
                if cmd in ("true", "false"):
                    self.disabled.add(_norm(parts[1]))


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_module_blacklist(snapshot: ModuleBlacklistSnapshot,
                           t: TranslationFunc | None = None) -> CheckResult:
    """Analyse ModuleBlacklistSnapshot and return findings (INFO-only)."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.config_read:
        result.info(message=_t("module_blacklist.unreadable"),
                    key="module_blacklist.unreadable")
        return result

    # A loaded module is kernel_modules' concern; a disabled one is handled.
    candidates = sorted(
        m for m in RECOMMENDED
        if m not in snapshot.loaded and m not in snapshot.disabled
    )

    if candidates:
        result.info(
            message=_t("module_blacklist.candidates",
                       count=len(candidates),
                       modules=", ".join(candidates)),
            detail=_t("module_blacklist.candidates_detail"),
            key="module_blacklist.candidates",
        )
    else:
        result.ok(message=_t("module_blacklist.all_handled"),
                  key="module_blacklist.all_handled")

    return result
