"""
SUID/SGID binary audit for BOB (CHECK 37).

Finds all SUID and SGID binaries on the system and flags those that are
not in the known-safe whitelist.  Root-owned SUID binaries outside the
whitelist warrant a score deduction; unexpected SGID binaries are INFO-only.

The check is split into two parts:
  1. SuidSnapshot.from_system()  — runs find(1) and collects paths + owners.
  2. check_suid_audit(snapshot)  — pure logic, returns CheckResult.
"""

from __future__ import annotations

import os
import shlex
import stat
import subprocess
from dataclasses import dataclass, field

from bob.checks._run import _C_LOCALE_ENV, _identity_t
from bob.scoring import CheckResult


# ---------------------------------------------------------------------------
# Whitelist of known-safe binaries (by basename, distro-agnostic)
# ---------------------------------------------------------------------------

_KNOWN_SUID: frozenset[str] = frozenset({
    # Core auth / privilege escalation
    "su", "sudo", "newgrp", "passwd", "chsh", "chfn", "gpasswd", "expiry",
    "chage",
    # Network tools (ping was SUID on older kernels)
    "ping", "ping6", "pppd",
    # Filesystem / mount
    "mount", "umount", "fusermount", "fusermount3", "ntfs-3g",
    "dmcrypt-get-device", "mount.cifs", "mount.ecryptfs_private",
    # Polkit / D-Bus
    "pkexec", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    # PAM helpers
    "unix_chkpwd", "unix2_chkpwd",
    # SSH
    "ssh-keysign",
    # User namespaces
    "newuidmap", "newgidmap",
    # Scheduling
    "at", "crontab",
    # Terminal / misc
    "wall", "write", "screen",
    # Display (Xorg on legacy systems)
    "Xorg", "X", "Xorg.wrap",
    # Browser / Electron sandbox (Chrome, Brave, VS Code, all Chromium-based apps)
    "chrome-sandbox",
    # Virtualisation / remote desktop helpers
    "vmware-user-suid-wrapper", "spice-client-glib-usb-acl-helper",
    # Kerberos
    "ksu",
    # Systemtap
    "staprun",
    # Screen lock authentication (xscreensaver)
    "xscreensaver-auth",
    # Mail transfer agent — local delivery (exim4, sendmail)
    "exim4", "sendmail",
})

_KNOWN_SGID: frozenset[str] = frozenset({
    "wall", "write", "bsd-write",
    "crontab",
    "mlocate", "plocate", "locate",
    "man", "mandb",
    "ssh-agent",
    "expiry", "newgrp", "chage",
    "lockfile", "utempter", "dotlockfile",
    "postdrop", "postqueue",
    "unix_chkpwd",
    # PAM extra-users helper
    "pam_extrausers_chkpwd",
    # Mail locking utilities
    "dotlock.mailutils",
    # GNOME Evolution mail client lock helper
    "camel-lock-helper-1.2",
    # ExpressVPN desktop helper
    "support-tool-launcher",
})

# Directories known to host SUID/SGID binaries on Linux systems.
# Scanning these targeted roots instead of / keeps the check under 2 seconds
# on any typical installation while covering 99%+ of real SUID binaries.
_SCAN_ROOTS = (
    "/bin", "/sbin",
    "/usr/bin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin", "/usr/local/lib",
    "/usr/lib", "/usr/lib64",
    "/lib", "/lib64",
    "/usr/libexec",
    "/opt",
)

_FIND_TIMEOUT = 15  # seconds


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class SuidSnapshot:
    """
    SUID/SGID binary inventory from the live filesystem.

    Args:
        suid_paths:        All SUID files found (absolute paths, root-owned).
        sgid_paths:        All pure-SGID files found (not also SUID).
        unexpected_suid:   SUID binaries whose basename is not in the whitelist.
        unexpected_sgid:   SGID binaries whose basename is not in the whitelist.
        scan_skipped:      True if find timed out or failed entirely.
    """
    suid_paths:      list[str] = field(default_factory=list)
    sgid_paths:      list[str] = field(default_factory=list)
    unexpected_suid: list[str] = field(default_factory=list)
    unexpected_sgid: list[str] = field(default_factory=list)
    scan_skipped:    bool      = False

    @classmethod
    def from_system(cls) -> "SuidSnapshot":
        """
        Run a single find(1) pass over targeted binary directories. Never raises.

        Scanning known roots instead of / keeps the check under 2 seconds while
        covering 99%+ of real SUID/SGID binaries on any standard Linux layout.
        One pass finds all files with either bit set; Python classifies each
        result via os.stat() — halving filesystem traversal time vs two passes.
        """
        suid_paths:  list[str] = []
        sgid_paths:  list[str] = []
        scan_skipped = False

        roots = [p for p in _SCAN_ROOTS if os.path.isdir(p)]
        if not roots:
            return cls(scan_skipped=True)

        cmd = (
            ["find"] + roots
            + ["(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
               "-type", "f", "-print"]
        )
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=_FIND_TIMEOUT, env=_C_LOCALE_ENV,
            )
            for line in proc.stdout.splitlines():
                path = line.strip()
                if not path:
                    continue
                try:
                    st = os.stat(path)
                    mode = st.st_mode
                    has_suid = bool(mode & stat.S_ISUID)
                    has_sgid = bool(mode & stat.S_ISGID)
                    if has_suid and st.st_uid == 0:
                        suid_paths.append(path)
                    elif has_sgid and not has_suid:
                        sgid_paths.append(path)
                except OSError:
                    pass
        except (subprocess.TimeoutExpired, OSError):
            scan_skipped = True

        unexpected_suid = [
            p for p in suid_paths
            if os.path.basename(p) not in _KNOWN_SUID
        ]
        unexpected_sgid = [
            p for p in sgid_paths
            if os.path.basename(p) not in _KNOWN_SGID
        ]

        return cls(
            suid_paths=sorted(suid_paths),
            sgid_paths=sorted(sgid_paths),
            unexpected_suid=sorted(unexpected_suid),
            unexpected_sgid=sorted(unexpected_sgid),
            scan_skipped=scan_skipped,
        )


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_suid_audit(snapshot: SuidSnapshot, t=None) -> CheckResult:
    """
    Check for unexpected SUID/SGID binaries.

    Deductions:
      - 1+ unexpected root-owned SUID binary: −1 pt

    INFO-only:
      - Unexpected SGID binaries (less dangerous)
      - Scan skipped (timeout)
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if snapshot.scan_skipped:
        result.info(
            message=_t("suid_audit.scan_skipped"),
            key="suid_audit.scan_skipped",
        )
        return result

    # --- Unexpected SUID ---
    if not snapshot.unexpected_suid:
        result.ok(
            message=_t(
                "suid_audit.ok",
                suid_count=len(snapshot.suid_paths),
                sgid_count=len(snapshot.sgid_paths),
            ),
            key="suid_audit.ok",
        )
    else:
        paths_str = ", ".join(snapshot.unexpected_suid[:10])
        suffix = f" (+{len(snapshot.unexpected_suid) - 10} more)" if len(snapshot.unexpected_suid) > 10 else ""
        result.warn(
            message=_t(
                "suid_audit.unexpected_suid",
                count=len(snapshot.unexpected_suid),
                paths=paths_str + suffix,
            ),
            nature="improvement",
            detail=_t("suid_audit.unexpected_suid_detail"),
            cmd=" && ".join(f"stat {shlex.quote(p)}" for p in snapshot.unexpected_suid[:5]),
            cmd_type="check",
            key="suid_audit.unexpected_suid",
        )
        result.add_deduction(
            reason=_t("suid_audit.unexpected_suid_reason",
                      count=len(snapshot.unexpected_suid)),
            points=1,
            context="local",
            key="suid_audit.unexpected_suid",
        )

    # --- Unexpected SGID (INFO only) ---
    if snapshot.unexpected_sgid:
        paths_str = ", ".join(snapshot.unexpected_sgid[:10])
        suffix = f" (+{len(snapshot.unexpected_sgid) - 10} more)" if len(snapshot.unexpected_sgid) > 10 else ""
        result.info(
            message=_t(
                "suid_audit.unexpected_sgid",
                count=len(snapshot.unexpected_sgid),
                paths=paths_str + suffix,
            ),
            detail=_t("suid_audit.unexpected_sgid_detail"),
            cmd=" && ".join(f"stat {shlex.quote(p)}" for p in snapshot.unexpected_sgid[:5]),
            cmd_type="check",
            key="suid_audit.unexpected_sgid",
        )

    return result


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _is_root_owned(path: str) -> bool:
    """Return True if the file exists and is owned by root (UID 0)."""
    try:
        return os.stat(path).st_uid == 0
    except OSError:
        return False
