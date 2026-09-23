"""
polkit authorization-rule check for BOB (privilege-escalation surface).

polkit (formerly PolicyKit) decides who may run privileged actions — mounting a
disk, restarting a service, installing a package — and it evaluates its rules
**as root**. Two file locations feed it:

  - modern JavaScript rules in `/etc/polkit-1/rules.d/` and
    `/usr/share/polkit-1/rules.d/` (a rule can `return polkit.Result.YES`);
  - legacy `.pkla` files under `…/polkit-1/localauthority/` (INI-style, with
    `ResultAny`/`ResultInactive`/`ResultActive` keys).

BOB deliberately scopes this check to the one signal that is unambiguous and
low-noise, mirroring the sudoers.d / cron.d permission checks it already trusts:

  **a polkit rule file (or its directory) that a non-root user can write is a
  direct path to root.** Whoever can edit a `.rules` file can make polkit
  return YES for any action — that is privilege escalation, full stop. So a
  rule file that is group/other-writable, or not owned by root, is WARN with a
  concrete `chown/chmod` remediation.

It also surfaces, as INFO (not a deduction), a legacy `.pkla` that grants
`ResultAny=yes` — an auth bypass extended to *any* session including inactive
and remote ones. That can be intentional (a kiosk, a shared appliance), so it
is reported for the reader to judge, not scored.

BOB does not parse the JavaScript rules for over-broad `YES` returns: that is a
high-false-positive exercise (most rules legitimately return YES for a specific
action to a specific group), and a noisy check is worse than none.

Score impact:
  - a non-root-writable rule file or rules.d directory:  WARN −1 pt (each)
  - a `.pkla` granting ResultAny=yes:                    INFO
  - polkit rules present and correctly owned:            OK
  - no polkit configuration found:                       INFO (not present)
  - a rules directory could not be read:                 INFO (unknown)

Split into:
  1. PolkitSnapshot.from_system() — collects state.
  2. check_polkit(snapshot, t)    — pure analysis.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _identity_t,
    read_text_capped,
)
from bob.scoring import CheckResult

#: Directories holding modern JavaScript polkit rules (evaluated as root).
_RULES_DIRS = (
    "/etc/polkit-1/rules.d",
    "/usr/share/polkit-1/rules.d",
)

#: Roots under which legacy .pkla files live (recursively, one level of subdirs).
_PKLA_ROOTS = (
    "/etc/polkit-1/localauthority",
    "/var/lib/polkit-1/localauthority",
)


@dataclass
class PolkitSnapshot:
    """State collected about polkit authorization rules.

    Args:
        present:        True when any polkit rules.d dir or .pkla root exists.
        readable:       False when a present directory could not be listed/stat'd.
        writable_rules: Rule files / dirs writable by group-or-other or not
                        owned by root — each a privilege-escalation path.
        pkla_any_yes:   Legacy .pkla files that grant ResultAny=yes (auth bypass
                        for any session, including inactive/remote).
    """
    present:        bool = False
    readable:       bool = True
    writable_rules: list[str] = field(default_factory=list)
    pkla_any_yes:   list[str] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "PolkitSnapshot":
        """Inspect polkit rule files and permissions. Never raises."""
        snap = cls()

        for d in _RULES_DIRS:
            p = Path(d)
            try:
                dstat = p.stat()
            except OSError:
                continue  # directory absent — not a finding
            if not stat.S_ISDIR(dstat.st_mode):
                continue
            snap.present = True
            # The directory itself: writable by non-root is a privesc hole.
            if _is_nonroot_writable(dstat):
                snap.writable_rules.append(d)
            try:
                names = os.listdir(d)
            except OSError:
                snap.readable = False
                continue
            for name in names:
                if not name.endswith(".rules"):
                    continue
                fp = os.path.join(d, name)
                try:
                    fstat = os.stat(fp)
                except OSError:
                    snap.readable = False
                    continue
                if _is_nonroot_writable(fstat):
                    snap.writable_rules.append(fp)

        for root in _PKLA_ROOTS:
            rp = Path(root)
            try:
                if not stat.S_ISDIR(rp.stat().st_mode):
                    continue
            except OSError:
                continue
            snap.present = True
            for fp in _iter_pkla(root):
                try:
                    fstat = os.stat(fp)
                except OSError:
                    snap.readable = False
                    continue
                if _is_nonroot_writable(fstat):
                    snap.writable_rules.append(fp)
                try:
                    text = read_text_capped(Path(fp), encoding="utf-8",
                                            errors="replace")
                except OSError:
                    snap.readable = False
                    continue
                if _grants_any_yes(text):
                    snap.pkla_any_yes.append(fp)

        return snap


def _is_nonroot_writable(st: "os.stat_result") -> bool:
    """True if writable by group or other, or not owned by root."""
    if st.st_uid != 0:
        return True
    return bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def _iter_pkla(root: str) -> "list[str]":
    """Return .pkla file paths one directory level below *root*. Never raises."""
    out: list[str] = []
    try:
        subs = os.listdir(root)
    except OSError:
        return out
    for sub in subs:
        d = os.path.join(root, sub)
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for name in names:
            if name.endswith(".pkla"):
                out.append(os.path.join(d, name))
    return out


def _grants_any_yes(text: str) -> bool:
    """True if a .pkla body sets ResultAny=yes (auth bypass for any session)."""
    for raw in text.splitlines():
        line = raw.strip().lower().replace(" ", "")
        if line.startswith("resultany=") and line.split("=", 1)[1] in (
                "yes", "auth_admin_keep", "auth_self_keep"):
            # Only an unconditional "yes" is an outright bypass; the auth_*_keep
            # variants still prompt once, so restrict to a literal yes.
            if line.split("=", 1)[1] == "yes":
                return True
    return False


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_polkit(snapshot: PolkitSnapshot,
                 t: TranslationFunc | None = None) -> CheckResult:
    """Analyse PolkitSnapshot and return findings."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.present:
        result.info(
            message=_t("polkit.not_present"),
            key="polkit.not_present",
        )
        return result

    for path in snapshot.writable_rules:
        result.warn_with_deduction(
            key="polkit.rule_writable",
            message=_t("polkit.rule_writable", path=path),
            reason=_t("polkit.rule_writable_reason"),
            points=1,
            detail=_t("polkit.rule_writable_detail", path=path),
            cmd=f"sudo chown root:root {path} && sudo chmod g-w,o-w {path}",
            nature="action",
        )

    for path in snapshot.pkla_any_yes:
        result.info(
            message=_t("polkit.pkla_any_yes", path=path),
            detail=_t("polkit.pkla_any_yes_detail", path=path),
            key="polkit.pkla_any_yes",
        )

    if not snapshot.readable and not snapshot.writable_rules:
        result.info(
            message=_t("polkit.unreadable"),
            detail=_t("polkit.unreadable_detail"),
            key="polkit.unreadable",
        )

    if not result.findings:
        result.ok(
            message=_t("polkit.rules_ok"),
            key="polkit.rules_ok",
        )
    return result
