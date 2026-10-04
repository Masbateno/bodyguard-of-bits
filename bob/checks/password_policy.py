"""
Password policy audit for BOB.

Checks the system password policy at two levels:
  1. /etc/login.defs  — global password aging settings (PASS_MAX_DAYS, etc.).
  2. PAM              — password quality enforcement (pam_pwquality/pam_cracklib)
                        and minimum length configuration.

A system without pam_pwquality or pam_cracklib in the PAM password stack has no
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

import os
import re
from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _identity_t,
    install_fix,
    join_continuations,
    pam_stack_paths,
    read_pam_stack,
)
from bob.scoring import CheckResult
from bob._atomic import read_text_capped

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LOGIN_DEFS_PATH    = Path("/etc/login.defs")
# openSUSE Leap 16+ ships login.defs under /usr/etc, with /etc as the optional
# override. Reading only /etc reported the OpenSSH-style default (PASS_MAX_DAYS
# 99999) on a host whose real policy lives in /usr/etc — right by coincidence
# here, wrong the moment /usr/etc sets a stricter value. /etc wins when present.
_LOGIN_DEFS_VENDOR  = Path("/usr/etc/login.defs")
_PWQUALITY_CONF     = Path("/etc/security/pwquality.conf")
_PASSWD_BINARIES    = ("/usr/bin/passwd", "/bin/passwd")
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
_DEDUCTION_WEAK_HASH         = 1

# Password-hashing algorithms, by the name login.defs (ENCRYPT_METHOD) or
# pam_unix uses. MD5, DES and bigcrypt fall to an offline crack within hours
# once /etc/shadow leaks; SHA256 is acceptable but not what CIS asks for.
_WEAK_HASHES   = frozenset({"MD5", "DES", "BIGCRYPT"})
_MEDIUM_HASHES = frozenset({"SHA256"})
_STRONG_HASHES = frozenset({"SHA512", "YESCRYPT", "GOST_YESCRYPT", "BLOWFISH", "BCRYPT"})
# The hash options pam_unix(8) accepts on its password line.
_PAM_UNIX_HASHES = ("md5", "bigcrypt", "sha256", "sha512", "blowfish",
                    "gost_yescrypt", "yescrypt")

# Regexes
_PASS_MAX_DAYS_RE   = re.compile(r"^\s*PASS_MAX_DAYS\s+(\d+)", re.MULTILINE)
_PASS_MIN_DAYS_RE   = re.compile(r"^\s*PASS_MIN_DAYS\s+(\d+)", re.MULTILINE)
_ENCRYPT_METHOD_RE  = re.compile(r"^\s*ENCRYPT_METHOD\s+(\S+)", re.MULTILINE)


def _hash_rank(algo: str) -> int:
    """0 = weak, 1 = unrecognised, 2 = acceptable, 3 = strong — lower is worse."""
    if algo in _WEAK_HASHES:
        return 0
    if algo in _MEDIUM_HASHES:
        return 2
    if algo in _STRONG_HASHES:
        return 3
    return 1


def _last_str(pattern: "re.Pattern[str]", text: str) -> "str | None":
    """The last match's value (login.defs is last-one-wins), upper-cased."""
    last = None
    for m in pattern.finditer(text):
        last = m
    return last.group(1).upper() if last else None


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
    #: v0.24.0 — a login.defs that exists but could not be read (a FIFO, a
    #: directory, denied). Absent is not this: there is nothing to verify.
    #: Unread, its expiry and hashing settings are unknown, so neither may be
    #: reported as fine.
    login_defs_unreadable: bool        = False
    #: v0.24.0 — passwd is BusyBox's applet (Alpine: /usr/bin/passwd -> bbsuid).
    #: It reads neither login.defs nor PAM: its algorithm is fixed when BusyBox
    #: is built, so "no source names one" is the design, not a blind spot.
    passwd_busybox: bool               = False
    pass_max_days:       int | None = None
    pass_min_days:       int | None = None
    pam_quality_module:  str | None = None
    #: False when not one of the PAM password-stack files could be read: none
    #: exists (Alpine has no PAM at all) or every one that does is off-limits.
    #: A verdict of "no quality module" then states something BOB never
    #: established, so the check says so instead of deducting a point.
    pam_stack_established: bool = True
    pam_minlen:          int | None = None
    #: ENCRYPT_METHOD from login.defs (upper-case), None if unset/unreadable.
    #: Unset is NOT read as DES — inferring the compiled-in default would be a
    #: claim about a value BOB never saw.
    encrypt_method:      str | None = None
    #: Hash option on the pam_unix.so password line (upper-case), None if the
    #: line names none (then pam_unix's build default applies, unknown to BOB).
    pam_unix_hash:       str | None = None

    @classmethod
    def from_system(cls, *, _pam_paths: "tuple[Path, ...] | None" = None
                    ) -> "PasswordPolicySnapshot":
        """
        Collect password policy configuration from the live system.

        Reads /etc/login.defs, the PAM password stack (whatever this
        distribution calls it — see :func:`bob.checks._run.read_pam_stack`) and
        /etc/security/pwquality.conf. Never raises — errors reflected as
        defaults (unreadable → None fields).

        Returns:
            Populated PasswordPolicySnapshot.
        """
        snap = cls()
        for _passwd in _PASSWD_BINARIES:
            if os.path.lexists(_passwd):
                snap.passwd_busybox = (os.path.basename(os.path.realpath(_passwd))
                                       in ("busybox", "bbsuid"))
                break

        # ---- login.defs (/etc, else the /usr/etc vendor path) ---------------
        for _login_defs in (_LOGIN_DEFS_PATH, _LOGIN_DEFS_VENDOR):
            try:
                login_defs_text = read_text_capped(_login_defs, encoding="utf-8", errors="replace")
            except FileNotFoundError:
                continue  # absent — try the vendor path
            except OSError:
                snap.login_defs_unreadable = True
                continue  # a FIFO/non-regular/denied file — try the vendor path
            snap.login_defs_readable = True

            v = _last_int(_PASS_MAX_DAYS_RE, login_defs_text)
            if v is not None:
                snap.pass_max_days = v

            v = _last_int(_PASS_MIN_DAYS_RE, login_defs_text)
            if v is not None:
                snap.pass_min_days = v

            snap.encrypt_method = _last_str(_ENCRYPT_METHOD_RE, login_defs_text)
            break  # /etc wins when present; only fall through when it is absent

        # ---- the PAM password stack -----------------------------------------
        # Not `/etc/pam.d/common-password` alone: that is Debian's name for it
        # and exists nowhere else, so this read caught an OSError, left the
        # module unset and produced "no PAM quality module" — a WARN and a
        # deduction — on Fedora, RHEL, openSUSE and Arch, having read nothing.
        pam_minlen_inline: int | None = None
        pam_text, snap.pam_stack_established = read_pam_stack("password", _pam_paths)
        if pam_text:
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

        # pam_unix comes after the quality module in the stack, and the loop
        # above stops at the quality module — so look for it on its own.
        if pam_text:
            for line in join_continuations(pam_text.splitlines()):
                stripped = line.strip()
                if stripped.startswith("#") or "pam_unix.so" not in stripped:
                    continue
                opts = stripped.split("pam_unix.so", 1)[1].split()
                found = [o for o in opts if o.lower() in _PAM_UNIX_HASHES]
                if found:
                    # One option per line: the last wins within a line. Across
                    # lines — Fedora reads system-auth (local passwd) AND
                    # password-auth (remote logins) — keep the WEAKEST: md5 in
                    # one stack still writes crackable hashes, and "last one
                    # read" let password-auth's yescrypt hide system-auth's md5
                    # (measured on real Fedora 44, v0.24.0 stress pass).
                    algo = found[-1].upper()
                    if (snap.pam_unix_hash is None
                            or _hash_rank(algo) < _hash_rank(snap.pam_unix_hash)):
                        snap.pam_unix_hash = algo

        # ---- /etc/security/pwquality.conf -----------------------------------
        # pwquality.conf takes precedence over inline PAM option for minlen.
        # Drop-ins first, in ASCII order, then the main file — libpwquality's
        # own parse order, so the last value seen is the effective one.
        for path in _pwquality_files():
            try:
                v = _last_int(_PWQUALITY_MINLEN_RE,
                              read_text_capped(path, encoding="utf-8", errors="replace"))
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

    # ---- The PAM stack could not be read at all -----------------------------
    if not snapshot.pam_stack_established:
        # Alpine, and any host whose PAM files are off-limits. "No quality
        # module configured in PAM" would be a statement about a mechanism this
        # host may not even have.
        result.info(
            message=_t("password_policy.pam_stack_unknown"),
            detail=_t("password_policy.pam_stack_unknown_detail",
                      paths=", ".join(str(p) for p in pam_stack_paths("password"))),
            key="password_policy.pam_stack_unknown",
        )
        has_finding = True

    # ---- No PAM quality module ---------------------------------------------
    elif snapshot.pam_quality_module is None:
        # C-2 fix: nature="action" routes the cmd through --fix --apply, which
        # rejects any shell operator (&&, ||, ;) via fixes._has_shell_ops.
        # Two-step install isn't safely chainable in a single exec — emit as
        # improvement so the user sees the guidance without --fix breaking.
        # `pam-auth-update` is Debian's PAM stack editor and exists nowhere
        # else; on any other distribution the module has to be wired into the
        # PAM files by hand, so half a command would be worse than none.
        _cmd, _detail = install_fix(
            _t, _t("password_policy.no_quality_module_detail"), "pwquality",
            then_apt="sudo pam-auth-update")
        result.warn_with_deduction(
            key="password_policy.no_quality_module",
            message=_t("password_policy.no_quality_module"),
            reason=_t("password_policy.no_quality_module_reason"),
            points=_DEDUCTION_NO_QUALITY_MODULE,
            detail=_detail,
            cmd=_cmd,
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

    # ---- login.defs present but unread (v0.24.0) ---------------------------
    # Until v0.24.0 this was silent: the expiry check simply found no value,
    # and the hashing verdict below said "strong" from pam_unix alone.
    # Also when the vendor copy was read: a present-but-unread /etc/login.defs
    # is the admin's override, and the vendor values say nothing about it.
    if snapshot.login_defs_unreadable:
        result.info(message=_t("password_policy.login_defs_unreadable"),
                    key="password_policy.login_defs_unreadable")
        has_finding = True

    # ---- Password-hashing algorithm ----------------------------------------
    # Two places name it: login.defs ENCRYPT_METHOD (useradd, chpasswd,
    # newusers) and the pam_unix option (passwd). A weak value in either one
    # produces crackable hashes for the accounts that path creates.
    sources = [(src, algo) for src, algo in (
        ("login.defs ENCRYPT_METHOD", snapshot.encrypt_method),
        ("pam_unix", snapshot.pam_unix_hash),
    ) if algo is not None]
    weak = [f"{src} {algo}" for src, algo in sources if algo in _WEAK_HASHES]
    medium = [f"{src} {algo}" for src, algo in sources if algo in _MEDIUM_HASHES]
    unknown = [f"{src} {algo}" for src, algo in sources
               if algo not in _WEAK_HASHES | _MEDIUM_HASHES | _STRONG_HASHES]
    if weak:
        result.warn_with_deduction(
            key="password_policy.weak_hash",
            message=_t("password_policy.weak_hash", where=", ".join(weak)),
            reason=_t("password_policy.weak_hash_reason"),
            points=_DEDUCTION_WEAK_HASH,
            detail=_t("password_policy.weak_hash_detail"),
            nature="improvement",
        )
        has_finding = True
    elif unknown:
        # A value BOB does not recognise is not a verdict either way.
        result.info(
            message=_t("password_policy.hash_unrecognised", where=", ".join(unknown)),
            key="password_policy.hash_unrecognised",
        )
        has_finding = True
    elif medium:
        result.info(
            message=_t("password_policy.hash_acceptable", where=", ".join(medium)),
            key="password_policy.hash_acceptable",
        )
        has_finding = True
    elif sources and snapshot.login_defs_unreadable:
        # login.defs present but unread: its ENCRYPT_METHOD is unknown, so the
        # pair cannot be called strong — the unreadable INFO above says why.
        pass
    elif sources:
        result.ok(
            message=_t("password_policy.hash_strong",
                       where=", ".join(f"{s_} {a}" for s_, a in sources)),
            key="password_policy.hash_strong",
        )
    elif snapshot.passwd_busybox:
        result.info(
            message=_t("password_policy.hash_builtin"),
            key="password_policy.hash_builtin",
        )
        has_finding = True
    else:
        result.info(
            message=_t("password_policy.hash_unknown"),
            key="password_policy.hash_unknown",
        )
        has_finding = True

    # ---- All clear ---------------------------------------------------------
    if not has_finding:
        result.ok(
            message=_t("password_policy.ok"),
            key="password_policy.ok",
        )

    return result
