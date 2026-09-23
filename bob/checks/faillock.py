"""
PAM account-lockout check for BOB (CIS §5.3 family — pam_faillock).

BOB already checks fail2ban, but that operates at the network layer (banning an
IP after repeated failures seen in a log). PAM account lockout is a different,
complementary control: pam_faillock (or the legacy pam_tally2) locks the
*account* after N failed authentications, covering local logins, su, sudo and
every other PAM consumer — paths fail2ban never sees.

This check looks at whether an account-lockout module is present in the PAM auth
stack, and the deny= threshold when it is:

  - Debian/Ubuntu: /etc/pam.d/common-auth
  - RHEL/Fedora/openSUSE: /etc/pam.d/system-auth (+ password-auth)
  - modern threshold: /etc/security/faillock.conf `deny =`

It is profile-aware and non-dogmatic: account lockout is a real DoS lever (an
attacker can lock every account by failing on purpose), and on a single-user
desktop the physical-access threat it addresses is smaller, so the absence is
INFO there and WARN on a server. BOB does not auto-edit PAM — a wrong lockout
rule can lock everyone out — so the remediation is described, not applied.

Score impact:
  - PAM auth stack unreadable / not found:  INFO (unknown)
  - lockout configured (faillock/tally2):    OK
  - not configured, server profile:          WARN −1 pt
  - not configured, desktop/workstation:     INFO

Split into:
  1. FaillockSnapshot.from_system() — collects state.
  2. check_faillock(snapshot, t, profile_name) — pure analysis.
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

# PAM auth files that carry the interactive auth stack, per family.
_PAM_AUTH_FILES = (
    "/etc/pam.d/common-auth",   # Debian / Ubuntu / Kali
    "/etc/pam.d/system-auth",   # RHEL / Fedora / openSUSE / Arch
    "/etc/pam.d/password-auth",  # RHEL family (remote)
)
_FAILLOCK_CONF = "/etc/security/faillock.conf"

_DENY_CONF = re.compile(r"^\s*deny\s*=\s*(\d+)", re.MULTILINE)
_DENY_INLINE = re.compile(r"\bdeny=(\d+)")


@dataclass
class FaillockSnapshot:
    """State collected about PAM account lockout.

    Args:
        readable:   False when no PAM auth file could be read at all.
        module:     "faillock" / "tally2" / "" (none found in the auth stack).
        deny:       The deny= threshold if discoverable, else None.
    """
    readable: bool = True
    module:   str = ""
    deny:     "int | None" = None

    @classmethod
    def from_system(cls) -> "FaillockSnapshot":
        """Detect PAM account-lockout configuration. Never raises."""
        snap = cls()
        texts: list[str] = []
        any_file = False
        for f in _PAM_AUTH_FILES:
            if not path_exists(Path(f)):
                continue
            any_file = True
            try:
                texts.append(read_text_capped(Path(f), encoding="utf-8",
                                              errors="replace"))
            except OSError:
                pass

        if not any_file:
            # No PAM auth file present (e.g. a musl/OpenRC box without PAM).
            snap.readable = False
            return snap
        if not texts:
            # Files exist but none could be read.
            snap.readable = False
            return snap

        for text in texts:
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "pam_faillock.so" in line:
                    snap.module = "faillock"
                    m = _DENY_INLINE.search(line)
                    if m and snap.deny is None:
                        snap.deny = int(m.group(1))
                elif "pam_tally2.so" in line and not snap.module:
                    snap.module = "tally2"
                    m = _DENY_INLINE.search(line)
                    if m and snap.deny is None:
                        snap.deny = int(m.group(1))

        # Modern pam_faillock reads its threshold from faillock.conf.
        if snap.module == "faillock" and snap.deny is None and path_exists(Path(_FAILLOCK_CONF)):
            try:
                conf = read_text_capped(Path(_FAILLOCK_CONF), encoding="utf-8",
                                        errors="replace")
                m = _DENY_CONF.search(conf)
                if m:
                    snap.deny = int(m.group(1))
            except OSError:
                pass
        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_faillock(snapshot: FaillockSnapshot, t: TranslationFunc | None = None,
                   profile_name: str = "server") -> CheckResult:
    """Analyse FaillockSnapshot and return findings."""
    _t = t if t is not None else _identity_t
    result = CheckResult()
    is_desktop = profile_name.lower() in ("desktop", "workstation")

    if not snapshot.readable:
        result.info(
            message=_t("faillock.unknown"),
            detail=_t("faillock.unknown_detail"),
            key="faillock.unknown",
        )
        return result

    if snapshot.module:
        deny = snapshot.deny if snapshot.deny is not None else "?"
        result.ok(
            message=_t("faillock.configured", module=snapshot.module, deny=deny),
            key="faillock.configured",
        )
        return result

    # No lockout module in the auth stack.
    if is_desktop:
        result.info(
            message=_t("faillock.not_configured"),
            detail=_t("faillock.not_configured_desktop_detail"),
            key="faillock.not_configured",
        )
    else:
        result.warn_with_deduction(
            key="faillock.not_configured",
            message=_t("faillock.not_configured"),
            reason=_t("faillock.not_configured_reason"),
            points=1,
            detail=_t("faillock.not_configured_detail"),
            nature="action",
        )
    return result
