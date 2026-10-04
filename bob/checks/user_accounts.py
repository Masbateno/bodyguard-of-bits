"""
User account security audit for BOB.

Checks for account-level security issues that are independent of SSH
configuration:
  1. Accounts with UID 0 other than root  — full root-equivalent access.
  2. Accounts with empty passwords        — require readable /etc/shadow.
  3. Accounts with a past expiry date     — informational cleanup notice.
  4. su restriction (pam_wheel)           — v0.24.0, CIS 5.2.7.
  5. Interactive users' homes and dotfiles — v0.24.0, CIS 7.2.9 / 7.2.10:
     a home another user can write or owns, a .netrc others can read, legacy
     .rhosts / .shosts / .forward files.
  6. Duplicate UIDs / user names          — v0.24.0, CIS 7.2.5 / 7.2.7 (INFO).

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
import os
import shlex
import stat as _stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict

from bob.checks._run import TranslationFunc, _identity_t, join_continuations
from bob.checks.disk import _NETWORK_FS_TYPES
from bob.scoring import CheckResult
from bob._atomic import read_text_capped

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PASSWD_PATH = Path("/etc/passwd")
_SHADOW_PATH = Path("/etc/shadow")
_MOUNTS_PATH = Path("/proc/self/mounts")

#: su's PAM file. Linux-PAM uses the first one that exists — /etc replaces the
#: vendor copy wholesale (openSUSE ships only /usr/lib/pam.d), it never merges.
_SU_PAM_PATHS = (Path("/etc/pam.d/su"), Path("/usr/lib/pam.d/su"))
#: The su binary — merged-/usr hosts have both names for one file.
_SU_BINARIES = ("/usr/bin/su", "/bin/su")
#: What BusyBox's applets resolve to (Alpine's SUID helper is bbsuid).
_BUSYBOX_NAMES = frozenset({"busybox", "bbsuid"})

#: First UID of a regular (interactive) account, as the expiry scan uses it.
_UID_MIN = 1000
_UID_NOBODY = 65534

#: Dotfiles CIS 7.2.10 names. .netrc holds credentials in clear; the others are
#: rsh-era trust (.rhosts, .shosts) and mail forwarding, which can pipe to a
#: command (.forward).
_NETRC = ".netrc"
_LEGACY_DOTFILES = (".rhosts", ".shosts", ".forward")

#: Filesystems whose stat() can block on a server that is not there. A home on
#: one of them is not probed (it is reported as not inspected): an audit that
#: hangs on a dead NFS server is the FIFO lesson again (v0.21.2, v0.20.1).
_BLOCKING_FS = _NETWORK_FS_TYPES | {"autofs"}

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
_DEDUCTION_SU_UNRESTRICTED:    int = 1
_DEDUCTION_HOME_UNSAFE:        int = 1
_DEDUCTION_NETRC_EXPOSED:      int = 1

_HOME_REASON_KEYS = {
    "world_writable": "user_accounts.home_world_writable",
    "foreign_owner":  "user_accounts.home_foreign_owner",
}


def _su_restriction(text: str) -> "str | None":
    """The group su is restricted to, or None when su's PAM file does not
    restrict it.

    A restriction is an ``auth`` line running ``pam_wheel.so`` with a control
    that fails the stack (``required``, ``requisite``, or a bracket form whose
    default is ``die``/``bad``), without ``deny`` (which inverts the test) —
    ``auth sufficient pam_wheel.so trust`` *grants* wheel members su without a
    password, it restricts nobody. With no ``group=``, pam_wheel(8) uses wheel.
    """
    for line in join_continuations(text.splitlines()):
        tokens = line.split("#", 1)[0].split()
        if len(tokens) < 3 or tokens[0].lstrip("-") != "auth":
            continue
        rest = tokens[1:]
        if rest[0].startswith("["):
            control = []
            while rest:
                control.append(rest.pop(0))
                if control[-1].endswith("]"):
                    break
            ctl = " ".join(control)
            fails = "default=die" in ctl or "default=bad" in ctl
        else:
            ctl = rest.pop(0)
            fails = ctl in ("required", "requisite")
        if not rest or os.path.basename(rest[0]) != "pam_wheel.so":
            continue
        args = rest[1:]
        if not fails or "deny" in args:
            continue
        for a in args:
            if a.startswith("group="):
                return a[len("group="):] or "wheel"
        return "wheel"
    return None


def _mount_fstype(path: str, mounts: "list[tuple[str, str]]") -> "str | None":
    """Filesystem type of the longest mount point containing *path* (textual,
    no syscall on *path* — that is the point)."""
    best, best_len = None, -1
    for mp, fstype in mounts:
        if (path == mp or path.startswith(mp.rstrip("/") + "/")) and len(mp) > best_len:
            best, best_len = fstype, len(mp)
    return best

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
    #: v0.24.0 — su restriction. None = not collected (a hand-built snapshot);
    #: from_system always sets it. False = no su PAM file could be read.
    su_pam_established:      "bool | None"   = None
    #: Group su is restricted to (pam_wheel), None when it is not restricted.
    su_group:                "str | None"    = None
    #: v0.24.0 — group su is restricted to by its *file mode*: the binary is
    #: not executable by others (dpkg-statoverride root:<group> 4750 /usr/bin/su),
    #: so only that group can run it at all. None when others may execute it.
    su_binary_group:         "str | None"    = None
    #: v0.24.0 — su is BusyBox's applet (/bin/su -> busybox or bbsuid). It does
    #: not consult PAM, so a pam_wheel line in /usr/lib/pam.d/su restricts
    #: nothing (measured on a real Alpine 3.24 with linux-pam installed).
    su_busybox:              bool            = False
    #: root's password locked ('!' / '*'), None when /etc/shadow was unreadable.
    root_locked:             "bool | None"   = None
    #: v0.24.0 — homes of interactive accounts (root and UID ≥ 1000).
    #: (user, home, reason) with reason "world_writable" or "foreign_owner".
    unsafe_homes:            "list[tuple[str, str, str]]" = field(default_factory=list)
    exposed_netrc:           list[str]       = field(default_factory=list)
    legacy_dotfiles:         list[str]       = field(default_factory=list)
    #: Users whose home could not be inspected (permission, network filesystem).
    homes_uninspected:       list[str]       = field(default_factory=list)
    #: v0.24.0 — "uid N: a, b" for each non-zero UID held by several names,
    #: and every user name listed more than once.
    duplicate_uids:          list[str]       = field(default_factory=list)
    duplicate_names:         list[str]       = field(default_factory=list)

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
        homes:        dict[str, str] = {}  # username → home
        by_uid:       dict[int, list[str]] = {}
        names_seen:   set[str] = set()
        snap.passwd_readable = False
        try:
            for line in read_text_capped(_PASSWD_PATH, encoding="utf-8", errors="replace").splitlines():
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                username = parts[0]
                try:
                    uid = int(parts[2])
                except ValueError:
                    continue
                shell = parts[6].strip()
                if username in names_seen and username not in snap.duplicate_names:
                    snap.duplicate_names.append(username)
                names_seen.add(username)
                by_uid.setdefault(uid, []).append(username)
                login_shells[username] = shell
                uids[username] = uid
                homes[username] = parts[5].strip()
                if uid == 0 and username != "root":
                    snap.uid_zero_accounts.append(username)
            snap.passwd_readable = True
        except OSError:
            pass

        # UID 0 is already the uid_zero finding; a duplicated name is its own.
        snap.duplicate_uids = [
            f"uid {uid}: {', '.join(names)}"
            for uid, names in sorted(by_uid.items())
            if uid != 0 and len(set(names)) > 1
        ]

        snap._collect_su()
        snap._collect_homes(homes, uids, login_shells)

        # ---- /etc/shadow — password and expiry checks (requires root) -------
        try:
            shadow_text = read_text_capped(_SHADOW_PATH, encoding="utf-8", errors="replace")
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

            if username == "root":
                snap.root_locked = pw_hash.startswith(("!", "*"))

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

    def _collect_su(self) -> None:
        """Read su's PAM file — the first that exists — for a pam_wheel restriction,
        and su's own mode for a permission-based one."""
        for binary in _SU_BINARIES:
            try:
                st = os.stat(binary)
            except OSError:
                continue
            self.su_busybox = os.path.basename(os.path.realpath(binary)) in _BUSYBOX_NAMES
            if _stat.S_ISREG(st.st_mode) and not st.st_mode & _stat.S_IXOTH:
                try:
                    import grp
                    self.su_binary_group = grp.getgrgid(st.st_gid).gr_name
                except (KeyError, ImportError):
                    self.su_binary_group = str(st.st_gid)
            break
        self.su_pam_established = False
        for path in _SU_PAM_PATHS:
            try:
                text = read_text_capped(path, encoding="utf-8", errors="replace")
            except FileNotFoundError:
                continue
            except OSError:
                return          # present but unreadable: the vendor copy is not used
            self.su_pam_established = True
            self.su_group = _su_restriction(text)
            return

    def _collect_homes(self, homes: "dict[str, str]", uids: "dict[str, int]",
                       shells: "dict[str, str]") -> None:
        """stat() each interactive account's home and lstat() its dotfiles.

        Metadata only — nothing is opened, so a FIFO planted as ``.netrc``
        cannot block the audit. Homes on a network filesystem are skipped.
        """
        try:
            mounts = []
            for line in read_text_capped(_MOUNTS_PATH, encoding="utf-8",
                                         errors="replace").splitlines():
                f = line.split()
                if len(f) >= 3:
                    mounts.append((f[1].replace("\\040", " "), f[2]))
        except OSError:
            mounts = []

        for user, home in homes.items():
            uid = uids.get(user, -1)
            if not (user == "root" or (uid >= _UID_MIN and uid != _UID_NOBODY)):
                continue
            if _is_no_login_shell(shells.get(user)) or home in ("", "/"):
                continue
            fstype = _mount_fstype(home, mounts)
            if fstype in _BLOCKING_FS or (fstype or "").startswith("fuse."):
                self.homes_uninspected.append(user)
                continue
            try:
                st = os.stat(home)
            except FileNotFoundError:
                continue        # no home, nothing in it to protect
            except OSError:
                self.homes_uninspected.append(user)
                continue
            if not _stat.S_ISDIR(st.st_mode):
                continue
            if st.st_mode & _stat.S_IWOTH:
                self.unsafe_homes.append((user, home, "world_writable"))
            elif st.st_uid != uid:
                self.unsafe_homes.append((user, home, "foreign_owner"))

            for name in (_NETRC, *_LEGACY_DOTFILES):
                path = os.path.join(home, name)
                try:
                    lst = os.lstat(path)
                except FileNotFoundError:
                    continue
                except OSError:
                    if user not in self.homes_uninspected:
                        self.homes_uninspected.append(user)
                    break
                if name == _NETRC:
                    if _stat.S_ISREG(lst.st_mode) and lst.st_mode & 0o077:
                        self.exposed_netrc.append(path)
                else:
                    self.legacy_dotfiles.append(path)

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

    # ---- su restriction (v0.24.0, CIS 5.2.7) -------------------------------
    # Without pam_wheel, any account that learns root's password becomes root
    # through su. Moot when root's password is locked — su to root then needs
    # a credential nobody has — so that case is not scored.
    # BusyBox su never reads PAM: its PAM file (Alpine with linux-pam) decides
    # nothing, and its absence (Alpine without) is no blind spot either — only
    # su's file mode and root's lock state apply.
    if snapshot.su_busybox or snapshot.su_pam_established:
        pam_group = None if snapshot.su_busybox else snapshot.su_group
        if pam_group is not None:
            result.ok(message=_t("user_accounts.su_restricted", group=pam_group),
                      key="user_accounts.su_restricted")
        elif snapshot.su_binary_group is not None:
            result.ok(message=_t("user_accounts.su_restricted_by_mode",
                                 group=snapshot.su_binary_group),
                      key="user_accounts.su_restricted_by_mode")
        elif snapshot.root_locked is True:
            result.ok(message=_t("user_accounts.su_root_locked"),
                      key="user_accounts.su_root_locked")
        elif snapshot.root_locked is None:
            result.info(message=_t("user_accounts.su_root_unknown"),
                        key="user_accounts.su_root_unknown")
            has_finding = True
        elif snapshot.su_busybox:
            result.warn_with_deduction(
                key="user_accounts.su_unrestricted",
                message=_t("user_accounts.su_unrestricted_busybox"),
                reason=_t("user_accounts.su_unrestricted_busybox_reason"),
                points=_DEDUCTION_SU_UNRESTRICTED,
                detail=_t("user_accounts.su_unrestricted_busybox_detail"),
                nature="improvement",
            )
            has_finding = True
        else:
            result.warn_with_deduction(
                key="user_accounts.su_unrestricted",
                message=_t("user_accounts.su_unrestricted"),
                reason=_t("user_accounts.su_unrestricted_reason"),
                points=_DEDUCTION_SU_UNRESTRICTED,
                detail=_t("user_accounts.su_unrestricted_detail"),
                nature="improvement",
            )
            has_finding = True
    elif snapshot.su_pam_established is False:
        result.info(message=_t("user_accounts.su_unknown"),
                    key="user_accounts.su_unknown")
        has_finding = True

    # ---- Homes and dotfiles (v0.24.0, CIS 7.2.9 / 7.2.10) -------------------
    if snapshot.unsafe_homes:
        homes = ", ".join(f"{h} ({u}: {_t(_HOME_REASON_KEYS[r])})"
                          for u, h, r in snapshot.unsafe_homes)
        result.warn_with_deduction(
            key="user_accounts.home_unsafe",
            message=_t("user_accounts.home_unsafe", homes=homes),
            reason=_t("user_accounts.home_unsafe_reason", count=len(snapshot.unsafe_homes)),
            points=_DEDUCTION_HOME_UNSAFE,
            detail=_t("user_accounts.home_unsafe_detail"),
            nature="action",
            cmd=" && ".join(f"stat -c '%U %a %n' {shlex.quote(h)}"
                            for _, h, _ in snapshot.unsafe_homes[:5]),
            cmd_type="check",
        )
        has_finding = True

    if snapshot.exposed_netrc:
        result.warn_with_deduction(
            key="user_accounts.netrc_exposed",
            message=_t("user_accounts.netrc_exposed", files=", ".join(snapshot.exposed_netrc)),
            reason=_t("user_accounts.netrc_exposed_reason", count=len(snapshot.exposed_netrc)),
            points=_DEDUCTION_NETRC_EXPOSED,
            detail=_t("user_accounts.netrc_exposed_detail"),
            nature="action",
            cmd=" && ".join(f"chmod 600 {shlex.quote(f)}" for f in snapshot.exposed_netrc[:5]),
        )
        has_finding = True

    if snapshot.legacy_dotfiles:
        result.info(
            message=_t("user_accounts.legacy_dotfiles", files=", ".join(snapshot.legacy_dotfiles)),
            detail=_t("user_accounts.legacy_dotfiles_detail"),
            key="user_accounts.legacy_dotfiles",
        )
        has_finding = True

    if snapshot.homes_uninspected:
        # The home and dotfile verdicts above say nothing about these accounts.
        result.info(
            message=_t("user_accounts.homes_uninspected",
                       users=", ".join(snapshot.homes_uninspected)),
            key="user_accounts.homes_uninspected",
        )
        has_finding = True

    # ---- Duplicate UIDs / names (v0.24.0, CIS 7.2.5 / 7.2.7) ---------------
    if snapshot.duplicate_uids or snapshot.duplicate_names:
        result.info(
            message=_t("user_accounts.duplicate_ids",
                       ids="; ".join(snapshot.duplicate_uids + [
                           _t("user_accounts.duplicate_name", user=n)
                           for n in snapshot.duplicate_names])),
            detail=_t("user_accounts.duplicate_ids_detail"),
            key="user_accounts.duplicate_ids",
        )
        has_finding = True

    # ---- All clear ---------------------------------------------------------
    if not has_finding:
        result.ok(
            message=_t("user_accounts.ok"),
            key="user_accounts.ok",
        )

    return result
