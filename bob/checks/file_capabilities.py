"""
File-capability audit for BOB — the privilege that carries no SUID bit.

A file capability (the ``security.capability`` extended attribute that
``setcap`` writes) grants a slice of root's power to whoever executes the file,
with no set-id bit at all. ``find -perm -4000`` does not see it, so the SUID
audit does not either: ``cap_setuid+ep`` on a copy of ``python3`` is a root
shell for every local user, and ``suid_audit`` reports that host as clean.

What is root-equivalent here is the set of capabilities a non-root process can
turn into full root without another bug — change its UID (``setuid``), load a
kernel module (``sys_module``), bypass every file permission
(``dac_override``, ``fowner``, ``chown``), read any file (``dac_read_search``
— /etc/shadow), drive the kernel (``sys_admin``, ``sys_rawio``, ``bpf``), or
grant itself more (``setpcap``, ``setfcap``). A capability outside that set
(``net_raw`` on ping, ``net_bind_service`` on a resolver) is a reasoned grant,
reported for the record but never scored.

The scan reads the attribute directly (``os.getxattr``), not through
``getcap``: the tool is a separate package on most distributions
(libcap2-bin, libcap-progs), so depending on it would turn "not installed" into
"no capabilities" — absence read as cleanliness. Measured on a desktop host:
102 227 files in 0.7 s, the same four results as ``getcap -r``.

Findings:
  - root-equivalent capability on a binary not known to need it : WARN −1
  - any other capability on a binary not known to carry it       : INFO
  - scan incomplete (unreadable directory, time budget)          : INFO
  - nothing to scan                                              : INFO (unknown)
  - only known grants, full scan                                 : OK

Split into:
  1. FileCapabilitiesSnapshot.from_system() — walks the binary roots (never raises).
  2. check_file_capabilities(snapshot, t)   — pure classification.
"""

from __future__ import annotations

import errno
import os
import shlex
import time
from dataclasses import dataclass, field

from bob.checks._run import TranslationFunc, _identity_t
from bob.checks.suid_audit import _SCAN_ROOTS
from bob.scoring import CheckResult

_XATTR = "security.capability"

#: capabilities(7) bit numbers, in order (include/uapi/linux/capability.h).
_CAP_NAMES: "tuple[str, ...]" = (
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill",
    "setgid", "setuid", "setpcap", "linux_immutable", "net_bind_service",
    "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
    "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
    "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time",
    "sys_tty_config", "mknod", "lease", "audit_write", "audit_control",
    "setfcap", "mac_override", "mac_admin", "syslog", "wake_alarm",
    "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
)

#: Capabilities a process can turn into full root without a further bug.
_ROOT_EQUIVALENT: "frozenset[str]" = frozenset({
    "chown", "dac_override", "dac_read_search", "fowner", "setuid", "setgid",
    "setpcap", "setfcap", "sys_module", "sys_rawio", "sys_admin", "sys_ptrace",
    "bpf", "mac_admin", "mac_override",
})

#: Binaries distributions ship with a capability, and the capabilities each one
#: is known to carry. A known name holding *more* than its set is not known any
#: more — ping with cap_setuid is someone's backdoor, not iputils.
#:
#: Measured, not recalled (v0.24.0): the packages installed on Fedora 44,
#: Ubuntu 24.04, Debian 13, Arch, openSUSE Tumbleweed and Alpine, then every
#: security.capability under the binary roots read back — plus snap-confine,
#: read on a real Ubuntu Server 26.04 with snapd.
_KNOWN: "dict[str, frozenset[str]]" = {
    # Raw ICMP / probe tools, where unprivileged ICMP sockets are not used.
    **dict.fromkeys(("ping", "ping6", "arping", "tracepath",
                     "traceroute6", "traceroute6.iputils", "fping", "fping6"),
                    frozenset({"net_raw", "net_admin"})),
    # openSUSE adds sys_nice.
    "clockdiff": frozenset({"net_raw", "net_admin", "sys_nice"}),
    # Arch adds net_bind_service.
    "mtr-packet": frozenset({"net_raw", "net_admin", "net_bind_service"}),
    # GStreamer's PTP clock helper.
    "gst-ptp-helper": frozenset({"net_bind_service", "net_admin", "sys_nice"}),
    # Wireshark's capture helper. Arch ships it with cap_dac_override too, at
    # mode 0754 root:wireshark — the wireshark group is root-equivalent there
    # by packaging choice, which is the distribution's decision to report, not
    # a binary someone planted.
    "dumpcap": frozenset({"net_admin", "net_raw", "dac_override"}),
    # User-namespace id mapping — some distributions grant the capability
    # instead of the SUID bit; same power, same purpose as the SUID whitelist.
    # snapd's sandbox launcher. Recent snapd ships it with ten permitted
    # capabilities instead of the SUID bit (cap-aware: =p, raised by itself).
    # Measured on a real Ubuntu Server 26.04, snapd 2.77.1 — the one grant the
    # container bench could not see, and a false WARN on every snapd host.
    "snap-confine": frozenset({"chown", "dac_override", "dac_read_search", "fowner",
                               "setgid", "setuid", "sys_admin", "sys_chroot",
                               "sys_ptrace", "sys_resource"}),
    # Measured on a real, full Fedora 44 Server (2026-10-04) — packages the
    # container bench never installed. sssd is installed by default on Fedora
    # and RHEL, so without these every such host drew a false WARN.
    "krb5_child": frozenset({"dac_read_search", "setgid", "setuid"}),     # sssd
    "ldap_child": frozenset({"dac_read_search"}),                         # sssd
    "selinux_child": frozenset({"setgid", "setuid"}),                     # sssd
    "sssd_pam": frozenset({"dac_read_search"}),                           # sssd
    "suexec": frozenset({"setgid", "setuid"}),          # httpd: CGI under another uid
    "kwin_wayland": frozenset({"sys_nice"}),            # KDE compositor
    "ksgrd_network_helper": frozenset({"net_raw"}),     # KDE ksysguard
    "ksystemstats_intel_helper": frozenset({"perfmon"}),  # KDE system monitor
    "sipp": frozenset({"net_raw"}),                     # SIP test tool
    # Measured on a real openSUSE Leap 16.0 (2026-10-04).
    "gvfsd-nfs": frozenset({"net_bind_service"}),       # GNOME gvfs NFS backend
    "ns-slapd": frozenset({"net_bind_service"}),        # 389 Directory Server
    "newuidmap": frozenset({"setuid"}),
    "newgidmap": frozenset({"setgid"}),
}

_SCAN_BUDGET = 30.0   # seconds — same ceiling as the SUID find (suid_audit)
_BUDGET_EVERY = 512   # check the clock once per this many files


def decode_capabilities(raw: bytes) -> "frozenset[str] | None":
    """Permitted capabilities from a raw ``security.capability`` value.

    The layout is ``struct vfs_cap_data``: a little-endian magic whose top byte
    is the revision (1: one 32-bit word; 2 and 3: two words, 3 adding a root
    uid), then (permitted, inheritable) pairs. Only *permitted* is a grant —
    file-inheritable bits are ANDed with the process's own and give nothing on
    their own. None for a value BOB cannot parse.
    """
    if len(raw) < 4:
        return None
    rev = int.from_bytes(raw[0:4], "little") >> 24
    if rev == 1 and len(raw) >= 12:
        perm = int.from_bytes(raw[4:8], "little")
    elif rev in (2, 3) and len(raw) >= 20:
        perm = (int.from_bytes(raw[4:8], "little")
                | int.from_bytes(raw[12:16], "little") << 32)
    else:
        return None
    return frozenset(
        _CAP_NAMES[i] if i < len(_CAP_NAMES) else f"cap_{i}"
        for i in range(64) if perm >> i & 1
    )


@dataclass
class FileCapabilitiesSnapshot:
    """File capabilities found under the binary roots.

    Args:
        entries:      (path, permitted capabilities) for every file carrying one.
        files_seen:   regular files examined.
        scan_partial: a directory could not be listed, an attribute could not be
                      read, or the time budget ran out — what was not seen may
                      carry a capability.
        scan_skipped: none of the roots exists; nothing was examined.
    """
    entries:      "list[tuple[str, frozenset[str]]]" = field(default_factory=list)
    files_seen:   int  = 0
    scan_partial: bool = False
    scan_skipped: bool = False

    @classmethod
    def from_system(cls, *, _roots: "tuple[str, ...] | None" = None,
                    _budget: float = _SCAN_BUDGET) -> "FileCapabilitiesSnapshot":
        """Walk the binary roots and read each file's capability. Never raises."""
        snap = cls()
        roots: "list[str]" = []
        for r in (_roots if _roots is not None else _SCAN_ROOTS):
            real = os.path.realpath(r)
            # /bin -> /usr/bin on merged-/usr hosts: walk each tree once, and
            # report the canonical path.
            if os.path.isdir(real) and real not in roots:
                roots.append(real)
        if not roots:
            snap.scan_skipped = True
            return snap

        def _walk_error(_exc: OSError) -> None:
            snap.scan_partial = True

        deadline = time.monotonic() + _budget
        for root in roots:
            for dirpath, _dirs, files in os.walk(root, onerror=_walk_error):
                for name in files:
                    snap.files_seen += 1
                    if snap.files_seen % _BUDGET_EVERY == 0 and time.monotonic() > deadline:
                        snap.scan_partial = True
                        return snap
                    path = os.path.join(dirpath, name)
                    try:
                        raw = os.getxattr(path, _XATTR, follow_symlinks=False)
                    except OSError as exc:
                        # No attribute, or a filesystem without xattrs: nothing
                        # to report. Anything else is a file BOB did not see.
                        if exc.errno not in (errno.ENODATA, errno.ENOTSUP,
                                             getattr(errno, "ENOATTR", errno.ENODATA)):
                            snap.scan_partial = True
                        continue
                    caps = decode_capabilities(raw)
                    if caps is None:
                        snap.scan_partial = True
                    elif caps:
                        snap.entries.append((path, caps))
        snap.entries.sort()
        return snap


def _fmt(entries: "list[tuple[str, frozenset[str]]]") -> str:
    shown = ", ".join(f"{p} ({','.join(sorted(c))})" for p, c in entries[:10])
    return shown + (f" (+{len(entries) - 10} more)" if len(entries) > 10 else "")


def check_file_capabilities(snapshot: FileCapabilitiesSnapshot,
                            t: "TranslationFunc | None" = None) -> CheckResult:
    """Classify file capabilities: known grant, other grant, root-equivalent."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if snapshot.scan_skipped:
        result.info(message=_t("file_capabilities.unknown"),
                    key="file_capabilities.unknown")
        return result

    known: "list[tuple[str, frozenset[str]]]" = []
    dangerous: "list[tuple[str, frozenset[str]]]" = []
    unexpected: "list[tuple[str, frozenset[str]]]" = []
    for path, caps in snapshot.entries:
        allowed = _KNOWN.get(os.path.basename(path))
        if allowed is not None and caps <= allowed:
            known.append((path, caps))
        elif caps & _ROOT_EQUIVALENT:
            dangerous.append((path, caps))
        else:
            unexpected.append((path, caps))

    if dangerous:
        result.warn_with_deduction(
            key="file_capabilities.root_equivalent",
            message=_t("file_capabilities.root_equivalent",
                       count=len(dangerous), paths=_fmt(dangerous)),
            reason=_t("file_capabilities.root_equivalent_reason", count=len(dangerous)),
            points=1,
            detail=_t("file_capabilities.root_equivalent_detail"),
            nature="action",
            cmd=" && ".join(f"getcap {shlex.quote(p)}" for p, _ in dangerous[:5]),
            cmd_type="check",
        )

    if unexpected:
        result.info(
            message=_t("file_capabilities.unexpected",
                       count=len(unexpected), paths=_fmt(unexpected)),
            detail=_t("file_capabilities.unexpected_detail"),
            cmd=" && ".join(f"getcap {shlex.quote(p)}" for p, _ in unexpected[:5]),
            cmd_type="check",
            key="file_capabilities.unexpected",
        )

    if snapshot.scan_partial:
        # "Only known grants" is a claim about every file under the roots; a
        # partial walk has not seen every file.
        result.info(message=_t("file_capabilities.partial",
                               files=snapshot.files_seen, count=len(snapshot.entries)),
                    key="file_capabilities.partial")
    elif not dangerous and not unexpected:
        result.ok(message=_t("file_capabilities.ok",
                             files=snapshot.files_seen, count=len(known)),
                  key="file_capabilities.ok")

    return result
