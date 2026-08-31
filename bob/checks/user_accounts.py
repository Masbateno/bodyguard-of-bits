"""
User account security audit for BOB.

Checks for account-level security issues that are independent of SSH
configuration:
  1. Accounts with UID 0 other than root  — full root-equivalent access.
  2. Accounts with empty passwords        — require readable /etc/shadow.
  3. Accounts with a past expiry date     — informational cleanup notice.

The check is split into two parts:
  1. UserAccountsSnapshot.from_system() — collects data from /etc/passwd and
                                          /etc/shadow.
  2. check_user_accounts(snapshot)      — pure logic, returns a CheckResult.

Usage:
    from bob.checks.user_accounts import UserAccountsSnapshot, check_user_accounts

    snapshot = UserAccountsSnapshot.from_system()
    result   = check_user_accounts(snapshot)
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict

from bob.checks._run import TranslationFunc, _identity_t
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PASSWD_PATH = Path("/etc/passwd")
_SHADOW_PATH = Path("/etc/shadow")

# Basenames of shells that mean an account cannot perform interactive logins.
# We match by basename so that custom install paths like /usr/local/sbin/nologin
# are also caught without maintaining an exhaustive path list.
_NO_LOGIN_BASENAMES: frozenset[str] = frozenset({"nologin", "false"})

def _is_no_login_shell(shell: str | None) -> bool:
    """Return True if *shell* is a non-interactive shell (nologin / false)."""
    if not shell:
        return False
    return Path(shell).name in _NO_LOGIN_BASENAMES

# Maximum deduction from this check.
_MAX_DEDUCTION_UID_ZERO:       int = 3
_MAX_DEDUCTION_EMPTY_PASSWORD: int = 2

# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class UserAccountsSnapshot:
    """
    Raw snapshot of user account security state collected from /etc/passwd
    and /etc/shadow.

    Args:
        passwd_readable:         True if /etc/passwd was readable. It normally
                                 is (mode 0644), but when it is not, the UID 0
                                 scan finds nothing and used to look exactly
                                 like a host with no rogue root account.
        shadow_readable:         True if /etc/shadow was readable.
        uid_zero_accounts:       Usernames with UID 0 other than root.
        empty_password_accounts: Usernames with an empty password hash in
                                 /etc/shadow and a login-capable shell.
        expired_accounts:        Mapping of username → ISO expiry date string
                                 for accounts whose expiry (field 7 of
                                 /etc/shadow) is set, reached, and belong
                                 to a non-system account (UID ≥ 1000).
        ambiguous_expiry_accounts: Usernames whose expiry field is exactly 0.
                                 shadow(5) states the value "should not be used
                                 as it is interpreted as either an account with
                                 no expiration, or as an expiration on Jan 1,
                                 1970" — so the account may or may not be
                                 locked out depending on the implementation.
                                 That is a finding in itself, not something to
                                 resolve silently in either direction.
    """
    passwd_readable:         bool            = True
    shadow_readable:         bool            = False
    uid_zero_accounts:       list[str]       = field(default_factory=list)
    empty_password_accounts: list[str]       = field(default_factory=list)
    expired_accounts:        Dict[str, str]  = field(default_factory=dict)
    ambiguous_expiry_accounts: list[str]     = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "UserAccountsSnapshot":
        """
        Collect user account data from /etc/passwd and /etc/shadow.

        /etc/passwd is world-readable — UID 0 detection always works.
        /etc/shadow requires root — empty password and expiry checks only
        run when the file is readable.

        Returns:
            Populated UserAccountsSnapshot. Never raises — errors reflected
            as defaults (shadow_readable=False, empty lists).
        """
        snap = cls()

        # ---- /etc/passwd — UID 0 detection (always readable) ---------------
        login_shells: dict[str, str] = {}  # username → shell
        uids:         dict[str, int] = {}  # username → uid
        snap.passwd_readable = False
        try:
            for line in _PASSWD_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                username = parts[0]
                try:
                    uid = int(parts[2])
                except ValueError:
                    continue
                shell = parts[6].strip()
                login_shells[username] = shell
                uids[username] = uid
                if uid == 0 and username != "root":
                    snap.uid_zero_accounts.append(username)
            snap.passwd_readable = True
        except OSError:
            pass

        # ---- /etc/shadow — password and expiry checks (requires root) -------
        try:
            shadow_text = _SHADOW_PATH.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return snap

        snap.shadow_readable = True
        epoch = datetime.date(1970, 1, 1)
        today = datetime.date.today()
        today_days = (today - epoch).days

        for line in shadow_text.splitlines():
            parts = line.split(":")
            if len(parts) < 8:
                continue
            username   = parts[0]
            pw_hash    = parts[1]
            expire_raw = parts[7]  # account expiry: days since epoch, or ""

            # Empty password: field 1 is empty string AND account can log in.
            # Locked accounts (* or !) with empty fields are not a concern.
            if pw_hash == "" and not _is_no_login_shell(login_shells.get(username)):
                snap.empty_password_accounts.append(username)

            # Expired account. System accounts (UID < 1000) are excluded —
            # their expiry settings are managed by the package manager, not the
            # admin. Negative values are invalid shadow entries.
            #
            # The comparison is `<=`, not `<`: chage(1) defines the field as
            # "the date ... ON WHICH the user's account will no longer be
            # accessible", so an account expiring today is already locked out.
            # A strict `<` reported it as fine on the one day the operator most
            # needs to hear about it.
            if expire_raw:
                try:
                    expire_days = int(expire_raw)
                except ValueError:
                    expire_days = None
                if expire_days is not None and uids.get(username, 0) >= 1000:
                    if expire_days == 0:
                        # Not resolved in either direction — see the field docs.
                        snap.ambiguous_expiry_accounts.append(username)
                    elif 0 < expire_days <= today_days:
                        expiry_date = (epoch + datetime.timedelta(days=expire_days)).isoformat()
                        snap.expired_accounts[username] = expiry_date

        return snap

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_user_accounts(snapshot: UserAccountsSnapshot, *, t: TranslationFunc | None = None) -> CheckResult:
    """
    Audit user accounts for security issues.

    Scoring:
      - UID 0 account(s) other than root:  −3 pts (flat)
      - Empty password on login account:   −2 pts (flat)
      - Expired account expiry date:       INFO only, no deduction
      - Shadow not readable:               INFO only, no deduction

    Args:
        snapshot: UserAccountsSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()
    has_finding = False

    # ---- Passwd not readable -----------------------------------------------
    if not snapshot.passwd_readable:
        # The UID 0 scan produced nothing because the file never opened, not
        # because the host has no second root account.
        has_finding = True
        result.info(
            message=_t("user_accounts.no_passwd"),
            detail=_t("user_accounts.no_passwd_detail"),
            key="user_accounts.no_passwd",
        )

    # ---- Shadow not readable -----------------------------------------------
    if not snapshot.shadow_readable:
        result.info(
            message=_t("user_accounts.no_shadow"),
            key="user_accounts.no_shadow",
        )

    # ---- UID 0 (non-root) --------------------------------------------------
    uid_zero = list(dict.fromkeys(snapshot.uid_zero_accounts or []))
    if uid_zero:
        users_str = ", ".join(uid_zero)
        result.alert_with_deduction(
            key="user_accounts.uid_zero",
            message=_t("user_accounts.uid_zero", users=users_str),
            reason=_t("user_accounts.uid_zero_reason", users=users_str),
            points=_MAX_DEDUCTION_UID_ZERO,
            detail=_t("user_accounts.uid_zero_detail"),
            cmd="sudo passwd -l " + " ".join(uid_zero),
            nature="action",
        )
        has_finding = True

    # ---- Empty passwords ---------------------------------------------------
    empty_pw = list(dict.fromkeys(snapshot.empty_password_accounts or []))
    if empty_pw:
        users_str = ", ".join(empty_pw)
        result.alert_with_deduction(
            key="user_accounts.empty_password",
            message=_t("user_accounts.empty_password", users=users_str),
            reason=_t("user_accounts.empty_password_reason", users=users_str),
            points=_MAX_DEDUCTION_EMPTY_PASSWORD,
            detail=_t("user_accounts.empty_password_detail"),
            cmd="sudo passwd " + " ".join(empty_pw),
            nature="action",
        )
        has_finding = True

    # ---- Expired accounts --------------------------------------------------
    expired = dict(snapshot.expired_accounts) if snapshot.expired_accounts else {}
    if expired:
        users_str = ", ".join(
            f"{u} ({d})" for u, d in expired.items()
        )
        result.info(
            message=_t("user_accounts.expired_account", users=users_str),
            detail=_t("user_accounts.expired_account_detail"),
            key="user_accounts.expired_account",
        )
        has_finding = True

    # ---- Ambiguous expiry (field 7 == 0) -----------------------------------
    if snapshot.ambiguous_expiry_accounts:
        result.info(
            message=_t("user_accounts.ambiguous_expiry",
                       users=", ".join(snapshot.ambiguous_expiry_accounts)),
            detail=_t("user_accounts.ambiguous_expiry_detail"),
            key="user_accounts.ambiguous_expiry",
        )
        has_finding = True

    # ---- All clear ---------------------------------------------------------
    if not has_finding:
        result.ok(
            message=_t("user_accounts.ok"),
            key="user_accounts.ok",
        )

    return result
