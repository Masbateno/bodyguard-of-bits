"""
Password policy audit for BOB.

Checks the system password policy at two levels:
  1. /etc/login.defs  — global password aging settings (PASS_MAX_DAYS, etc.).
  2. PAM              — password quality enforcement (pam_pwquality/pam_cracklib)
                        and minimum length configuration.

A system without pam_pwquality or pam_cracklib in common-password has no
complexity enforcement — users can set trivially guessable passwords.

The check is split into two parts:
  1. PasswordPolicySnapshot.from_system() — collects data from config files.
  2. check_password_policy(snapshot)      — pure logic, returns a CheckResult.

Usage:
    from bob.checks.password_policy import PasswordPolicySnapshot, check_password_policy

    snapshot = PasswordPolicySnapshot.from_system()
    result   = check_password_policy(snapshot)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t, join_continuations
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LOGIN_DEFS_PATH    = Path("/etc/login.defs")
_COMMON_PASSWORD    = Path("/etc/pam.d/common-password")
_PWQUALITY_CONF     = Path("/etc/security/pwquality.conf")
# libpwquality reads the drop-in directory *first*, in ASCII order, then the
# main file — so the main file wins where both set a value, and a drop-in
# applies wherever the main file is silent. Debian ships pwquality.conf with
# every setting commented out, which makes "silent" the common case, and the
# drop-in the place hardening actually lands. Verified against libpwquality
# 1.4.5 itself, not inferred from the man page (whose wording is ambiguous).
_PWQUALITY_CONF_D   = Path("/etc/security/pwquality.conf.d")

# PASS_MAX_DAYS threshold above which we consider expiry effectively disabled.
_MAX_DAYS_THRESHOLD = 365

# Minimum acceptable password length.
_MIN_LEN_THRESHOLD  = 8

# Deductions
_DEDUCTION_NO_QUALITY_MODULE = 1
_DEDUCTION_WEAK_MINLEN       = 1

# Regexes
_PASS_MAX_DAYS_RE   = re.compile(r"^\s*PASS_MAX_DAYS\s+(\d+)", re.MULTILINE)
_PASS_MIN_DAYS_RE   = re.compile(r"^\s*PASS_MIN_DAYS\s+(\d+)", re.MULTILINE)


def _last_int(pattern: "re.Pattern[str]", text: str) -> "int | None":
    """Return the value of the *last* match, or None.

    Both login.defs and pwquality.conf are last-one-wins: shadow's own
    ``useradd`` applies the final ``PASS_MAX_DAYS`` in the file, and
    libpwquality the final ``minlen``. Reading the first match inverted the
    verdict for the most ordinary way there is to harden either file —
    appending the hardened value to the end. Confirmed by running
    ``useradd --prefix`` against a duplicated login.defs and by calling
    libpwquality on a duplicated pwquality.conf.
    """
    last = None
    for m in pattern.finditer(text):
        last = m
    return int(last.group(1)) if last else None
_PAM_MINLEN_RE      = re.compile(r"\bminlen=(\d+)", re.IGNORECASE)
_PWQUALITY_MINLEN_RE = re.compile(r"^\s*minlen\s*=\s*(\d+)", re.IGNORECASE | re.MULTILINE)


def _pwquality_files() -> "list[Path]":
    """Return the pwquality config files in libpwquality's own parse order.

    Drop-ins from ``pwquality.conf.d`` in ASCII order, then the main file.
    Missing or unreadable paths are skipped rather than raising: this runs
    inside ``from_system``, which is documented never to raise.
    """
    files: list[Path] = []
    try:
        if _PWQUALITY_CONF_D.is_dir():
            files.extend(sorted(
                f for f in _PWQUALITY_CONF_D.iterdir()
                if f.is_file() and f.name.endswith(".conf")
            ))
    except OSError:
        pass
    files.append(_PWQUALITY_CONF)
    return files


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class PasswordPolicySnapshot:
    """
    Raw snapshot of the system password policy configuration.

    Args:
        login_defs_readable:   True if /etc/login.defs was readable.
        pass_max_days:         Value of PASS_MAX_DAYS (None if unset).
                               99999 means passwords never expire.
        pass_min_days:         Value of PASS_MIN_DAYS (None if unset).
        pam_quality_module:    Name of the PAM quality module found in
                               common-password: "pam_pwquality",
                               "pam_cracklib", or None if absent.
        pam_minlen:            Explicitly configured minimum password length
                               (from pwquality.conf or inline PAM option).
                               None means using the module default (8).
    """
    login_defs_readable: bool          = False
    pass_max_days:       int | None = None
    pass_min_days:       int | None = None
    pam_quality_module:  str | None = None
    pam_minlen:          int | None = None

    @classmethod
    def from_system(cls) -> "PasswordPolicySnapshot":
        """
        Collect password policy configuration from the live system.

        Reads /etc/login.defs, /etc/pam.d/common-password, and
        /etc/security/pwquality.conf.  Never raises — errors reflected as
        defaults (unreadable → None fields).

        Returns:
            Populated PasswordPolicySnapshot.
        """
        snap = cls()

        # ---- /etc/login.defs ------------------------------------------------
        try:
            login_defs_text = _LOGIN_DEFS_PATH.read_text(encoding="utf-8", errors="replace")
            snap.login_defs_readable = True

            v = _last_int(_PASS_MAX_DAYS_RE, login_defs_text)
            if v is not None:
                snap.pass_max_days = v

            v = _last_int(_PASS_MIN_DAYS_RE, login_defs_text)
            if v is not None:
                snap.pass_min_days = v

        except OSError:
            pass

        # ---- /etc/pam.d/common-password -------------------------------------
        pam_minlen_inline: int | None = None
        try:
            pam_text = _COMMON_PASSWORD.read_text(encoding="utf-8", errors="replace")
            # PAM stacks wrap with a trailing backslash — pam.conf(5) uses a
            # wrapped line as its own worked example. Unjoined, a module and the
            # `minlen=` it was given sit on different lines and never meet.
            for line in join_continuations(pam_text.splitlines()):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "pam_pwquality.so" in stripped:
                    snap.pam_quality_module = "pam_pwquality"
                    m = _PAM_MINLEN_RE.search(stripped)
                    if m:
                        pam_minlen_inline = int(m.group(1))
                    break
                if "pam_cracklib.so" in stripped:
                    snap.pam_quality_module = "pam_cracklib"
                    m = _PAM_MINLEN_RE.search(stripped)
                    if m:
                        pam_minlen_inline = int(m.group(1))
                    break
        except OSError:
            pass

        # ---- /etc/security/pwquality.conf -----------------------------------
        # pwquality.conf takes precedence over inline PAM option for minlen.
        # Drop-ins first, in ASCII order, then the main file — libpwquality's
        # own parse order, so the last value seen is the effective one.
        for path in _pwquality_files():
            try:
                v = _last_int(_PWQUALITY_MINLEN_RE,
                              path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            if v is not None:
                snap.pam_minlen = v

        # Fall back to inline value if pwquality.conf did not specify minlen.
        if snap.pam_minlen is None:
            snap.pam_minlen = pam_minlen_inline

        return snap

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_password_policy(snapshot: PasswordPolicySnapshot, *, t: TranslationFunc | None = None) -> CheckResult:
    """
    Audit the system password policy for security weaknesses.

    Scoring:
      - No PAM quality module:          −1 pt (WARN)
      - Explicit minlen < 8 (if module  −1 pt (WARN)
        is configured):
      - PASS_MAX_DAYS ≥ 365:            INFO only, no deduction
        (NIST SP 800-63B no longer mandates periodic expiration)

    Args:
        snapshot: PasswordPolicySnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()
    has_finding = False

    # ---- No PAM quality module ---------------------------------------------
    if snapshot.pam_quality_module is None:
        # C-2 fix: nature="action" routes the cmd through --fix --apply, which
        # rejects any shell operator (&&, ||, ;) via fixes._has_shell_ops.
        # Two-step install isn't safely chainable in a single exec — emit as
        # improvement so the user sees the guidance without --fix breaking.
        result.warn_with_deduction(
            key="password_policy.no_quality_module",
            message=_t("password_policy.no_quality_module"),
            reason=_t("password_policy.no_quality_module_reason"),
            points=_DEDUCTION_NO_QUALITY_MODULE,
            detail=_t("password_policy.no_quality_module_detail"),
            cmd="sudo apt install libpam-pwquality && sudo pam-auth-update",
            nature="improvement",
        )
        has_finding = True

    # ---- Explicit minlen too low -------------------------------------------
    # Only flag when the quality module IS configured but minlen is explicitly
    # set below threshold — the admin consciously weakened the default.
    elif (
        snapshot.pam_minlen is not None
        and snapshot.pam_minlen < _MIN_LEN_THRESHOLD
    ):
        # C-3 fix: cmd was "sudo nano FILE  →  minlen = 8" — the Unicode arrow
        # makes the string non-executable (shlex.split tokenises it as args).
        # Demote to improvement so it appears as guidance without --fix
        # trying to exec it.
        result.warn_with_deduction(
            key="password_policy.weak_minlen",
            message=_t("password_policy.weak_minlen", minlen=snapshot.pam_minlen),
            reason=_t("password_policy.weak_minlen_reason", minlen=snapshot.pam_minlen),
            points=_DEDUCTION_WEAK_MINLEN,
            detail=_t("password_policy.weak_minlen_detail"),
            cmd=(
                "sudo nano /etc/security/pwquality.conf"
                f"  →  minlen = {_MIN_LEN_THRESHOLD}"
            ),
            nature="improvement",
        )
        has_finding = True

    # ---- Password expiry not enforced --------------------------------------
    if (
        snapshot.pass_max_days is not None
        and snapshot.pass_max_days >= _MAX_DAYS_THRESHOLD
    ):
        result.info(
            message=_t("password_policy.no_expiry", days=snapshot.pass_max_days),
            detail=_t("password_policy.no_expiry_detail"),
            key="password_policy.no_expiry",
        )
        has_finding = True

    # ---- All clear ---------------------------------------------------------
    if not has_finding:
        result.ok(
            message=_t("password_policy.ok"),
            key="password_policy.ok",
        )

    return result
