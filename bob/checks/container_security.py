"""
Container self-hardening posture audit for BOB.

When BOB runs *inside* a container, this surfaces the container's own isolation
posture from documented, offline-readable kernel interfaces (no runtime API,
no network): the Linux capability bounding set, seccomp mode, no-new-privileges,
the user namespace mapping, and whether the root filesystem is writable.

The whole section is suppressed on a non-container host (``skip_if`` on
``in_container``), so it only appears where it is meaningful.

INFO-only by design (v0.13.0): the readings are surfaced as posture context
(a privileged container is flagged with strong wording) but carry **no score
deduction** in this first version — the deduction calibration (e.g. a real WARN
for a privileged / CAP_SYS_ADMIN container) is a fast-follow once it can be
validated inside a real container runtime. See CHANGELOG v0.13.0.

Split into:
  1. ContainerSecuritySnapshot.from_system() — detect + read /proc interfaces.
  2. check_container_security(snapshot, t)    — pure analysis, returns CheckResult.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run, path_exists
from bob.scoring import CheckResult

# Capability bit → name, limited to the ones whose presence in a container is a
# meaningful container-escape / host-impact signal.
_DANGEROUS_CAPS: dict[int, str] = {
    2:  "CAP_DAC_READ_SEARCH",   # read any file (bypass DAC)
    12: "CAP_NET_ADMIN",         # reconfigure host networking
    16: "CAP_SYS_MODULE",        # load kernel modules → full host control
    17: "CAP_SYS_RAWIO",         # raw I/O → memory / disk access
    19: "CAP_SYS_PTRACE",        # ptrace other processes
    21: "CAP_SYS_ADMIN",         # the "new root" — mount, etc.
}
_CAP_SYS_ADMIN_BIT = 21

# Highest capability number the running kernel knows, from
# /proc/sys/kernel/cap_last_cap. 40 covers Linux 5.9+ (CAP_CHECKPOINT_RESTORE)
# and is only a fallback: the file is readable inside containers too.
_CAP_LAST_CAP_FALLBACK = 40


def _read_cap_last_cap() -> int:
    """Return the kernel's highest capability number, or the fallback."""
    try:
        value = int(Path("/proc/sys/kernel/cap_last_cap").read_text().strip())
    except (OSError, ValueError):
        return _CAP_LAST_CAP_FALLBACK
    # Guard against a nonsense value shifting a mask into absurdity.
    return value if 0 < value < 64 else _CAP_LAST_CAP_FALLBACK


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class ContainerSecuritySnapshot:
    """Container isolation posture read from kernel interfaces.

    Only populated when ``in_container`` is True.
    """
    in_container: bool = False
    runtime: str = ""                       # docker / podman / lxc / "container"
    cap_bnd: int = 0                         # capability bounding set bitmask
    cap_last_cap: int = _CAP_LAST_CAP_FALLBACK  # highest capability the kernel knows
    privileged: bool = False                 # the FULL capability set is present
    cap_sys_admin: bool = False              # CAP_SYS_ADMIN granted (may be alone)
    dangerous_caps: list[str] = field(default_factory=list)
    seccomp: int = -1                        # /proc/self/status Seccomp (0/1/2), -1 unknown
    no_new_privs: bool = False
    is_root: bool = False                    # effective uid 0
    userns: bool = False                     # non-identity uid_map
    rootfs_writable: bool = True

    @classmethod
    def from_system(cls) -> "ContainerSecuritySnapshot":
        snap = cls()
        snap.runtime = _detect_container()
        snap.in_container = bool(snap.runtime)
        if not snap.in_container:
            return snap

        status = _read_proc_status()
        snap.cap_bnd = _parse_hex(status.get("CapBnd", ""))
        snap.cap_last_cap = _read_cap_last_cap()
        # v0.14.1: "privileged" now means what it says — the *full* bounding
        # set. It used to be an alias for "CAP_SYS_ADMIN is present", so a
        # container started with `--cap-add SYS_ADMIN` (one targeted grant,
        # seccomp still enforcing) was reported as PRIVILEGED with the
        # headline "full Linux capability set available", which was measurably
        # false: cap_bnd 2149844475 against 2199023255551 for a real one.
        full_mask = (1 << (snap.cap_last_cap + 1)) - 1
        snap.privileged = (snap.cap_bnd & full_mask) == full_mask
        snap.cap_sys_admin = bool(snap.cap_bnd & (1 << _CAP_SYS_ADMIN_BIT))
        snap.dangerous_caps = [
            name for bit, name in sorted(_DANGEROUS_CAPS.items())
            if snap.cap_bnd & (1 << bit)
        ]
        snap.seccomp = _parse_int(status.get("Seccomp", ""), default=-1)
        snap.no_new_privs = status.get("NoNewPrivs", "0").strip() == "1"
        snap.is_root = _effective_uid_zero(status.get("Uid", ""))
        snap.userns = _has_user_namespace()
        snap.rootfs_writable = _rootfs_writable()
        return snap


def _detect_container() -> str:
    """Return the container runtime name, or "" when not in a container."""
    if _command_exists("systemd-detect-virt"):
        out = _run("systemd-detect-virt", "--container").strip()
        if out and out != "none":
            return out
    if path_exists(Path("/.dockerenv")):
        return "docker"
    if path_exists(Path("/run/.containerenv")):
        return "podman"
    try:
        cgroup = Path("/proc/1/cgroup").read_text(encoding="utf-8", errors="replace")
        for marker in ("docker", "containerd", "lxc", "kubepods"):
            if marker in cgroup:
                return marker
    except OSError:
        pass
    return ""


def _read_proc_status() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def _parse_hex(value: str) -> int:
    try:
        return int(value.strip(), 16)
    except (ValueError, AttributeError):
        return 0


def _parse_int(value: str, default: int = 0) -> int:
    try:
        return int(value.strip().split()[0])
    except (ValueError, IndexError, AttributeError):
        return default


def _effective_uid_zero(uid_line: str) -> bool:
    # /proc/self/status Uid: real effective saved fs
    parts = uid_line.split()
    return len(parts) >= 2 and parts[1] == "0"


def _has_user_namespace() -> bool:
    """True when /proc/self/uid_map is a non-identity mapping (userns active)."""
    try:
        line = Path("/proc/self/uid_map").read_text(encoding="utf-8", errors="replace").split("\n")[0]
    except OSError:
        return False
    parts = line.split()
    if len(parts) != 3:
        return False
    # Identity map "0 0 4294967295" → no userns. Anything else → userns.
    return not (parts[0] == "0" and parts[1] == "0")


def _rootfs_writable() -> bool:
    try:
        for line in Path("/proc/mounts").read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "/":
                opts = parts[3].split(",")
                return "ro" not in opts
    except OSError:
        pass
    return True


# ---------------------------------------------------------------------------
# Check logic (INFO-only)
# ---------------------------------------------------------------------------

def check_container_security(
    snapshot: ContainerSecuritySnapshot, t: TranslationFunc | None = None
) -> CheckResult:
    """Surface the container's own isolation posture (INFO-only, no deduction)."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.in_container:
        # Section is suppressed by skip_if; this is just a safety net.
        return result

    result.info(
        message=_t("container_security.detected", runtime=snapshot.runtime),
        key="container_security.detected",
    )

    # Capabilities — the strongest isolation signal.
    if snapshot.privileged:
        result.info(
            message=_t("container_security.privileged",
                       caps=", ".join(snapshot.dangerous_caps)),
            detail=_t("container_security.privileged_detail"),
            key="container_security.privileged",
        )
    elif snapshot.cap_sys_admin:
        # CAP_SYS_ADMIN without the full set — a targeted grant (FUSE mounts,
        # for instance), not a privileged container. Still the single most
        # escape-prone capability, so it gets its own finding rather than
        # being folded into the generic dangerous-caps line.
        result.info(
            message=_t("container_security.cap_sys_admin",
                       caps=", ".join(snapshot.dangerous_caps)),
            detail=_t("container_security.cap_sys_admin_detail"),
            key="container_security.cap_sys_admin",
        )
    elif snapshot.dangerous_caps:
        result.info(
            message=_t("container_security.dangerous_caps",
                       caps=", ".join(snapshot.dangerous_caps)),
            key="container_security.dangerous_caps",
        )
    else:
        result.info(
            message=_t("container_security.caps_restricted"),
            key="container_security.caps_restricted",
        )

    # Seccomp (0 = disabled, 1 = strict, 2 = filter active, -1 = not readable).
    #
    # -1 used to fall through in silence, which read exactly like "seccomp is
    # active": the container section simply said nothing about it. The line is
    # emitted by /proc/self/status only under CONFIG_SECCOMP, so it is missing
    # precisely on a kernel that has no seccomp at all — the case where the
    # remark matters most. Unknown is now its own answer.
    if snapshot.seccomp < 0:
        result.info(
            message=_t("container_security.seccomp_unknown"),
            detail=_t("container_security.seccomp_unknown_detail"),
            key="container_security.seccomp_unknown",
        )
    elif snapshot.seccomp == 0:
        result.info(
            message=_t("container_security.no_seccomp"),
            key="container_security.no_seccomp",
        )

    # Root without a user namespace → container-root maps to host-root.
    if snapshot.is_root and not snapshot.userns:
        result.info(
            message=_t("container_security.root_no_userns"),
            key="container_security.root_no_userns",
        )

    # Writable root filesystem.
    if snapshot.rootfs_writable:
        result.info(
            message=_t("container_security.rootfs_writable"),
            key="container_security.rootfs_writable",
        )

    return result
