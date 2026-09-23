"""
Mount-hardening check for BOB (CIS §1.1 — filesystem / mount options).

The classic CIS controls ask that world-writable scratch areas — `/tmp`,
`/var/tmp`, `/dev/shm` — be mounted with `nodev`, `nosuid` and (where practical)
`noexec`, so an attacker who can drop a file there cannot make it a device node,
a set-uid binary, or an executable dropped-and-run.

BOB deliberately avoids the CIS trap of declaring a system *bad* because `/tmp`
is not a **separate partition**. Many perfectly reasonable systems keep `/tmp`
on the root filesystem; that is a topology choice, not a vulnerability, and the
mount options simply cannot be set independently there. So:

  - the check reads the **effective** options from `/proc/self/mounts`;
  - a scratch area that is its own mount and lacks `nodev`/`nosuid` is a real,
    cheap-to-fix gap → WARN;
  - lacking only `noexec` is INFO (noexec on `/tmp` breaks some legitimate
    installers and package build steps — it is a hardening choice, not a default
    expectation);
  - `/tmp` or `/var/tmp` that is **not a separate mount** is INFO, not a
    finding to be penalised;
  - if `/proc/self/mounts` cannot be read, the state is unknown, not clean.

`/dev/shm` is always its own tmpfs, so it is always assessed on options.

Score impact (per scratch area):
  - separate mount missing nodev/nosuid:   WARN −1 pt
  - separate mount missing only noexec:     INFO
  - not a separate mount (/tmp, /var/tmp):  INFO
  - all of nodev/nosuid/noexec present:     OK
  - /proc/mounts unreadable:                INFO (unknown)

Split into:
  1. MountHardeningSnapshot.from_system() — collects mount state.
  2. check_mount_hardening(snapshot, t)   — pure analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t, read_text_capped
from bob.scoring import CheckResult

_MOUNTS = "/proc/self/mounts"

#: The scratch areas we assess, in display order.
_TARGETS = ("/tmp", "/var/tmp", "/dev/shm")

#: /dev/shm is a kernel-provided tmpfs; it is always its own mount, so "not a
#: separate mount" is not a meaningful state for it.
_ALWAYS_MOUNT = ("/dev/shm",)


@dataclass
class _MountInfo:
    """Effective state of one scratch area."""
    path:      str
    is_mount:  bool = False           # its own entry in /proc/mounts
    options:   frozenset[str] = frozenset()


@dataclass
class MountHardeningSnapshot:
    """State collected about scratch-area mount options.

    Args:
        readable: False when /proc/self/mounts could not be read.
        mounts:   One _MountInfo per target (/tmp, /var/tmp, /dev/shm).
    """
    readable: bool = True
    mounts:   list[_MountInfo] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "MountHardeningSnapshot":
        """Read effective mount options from /proc/self/mounts. Never raises."""
        snap = cls()
        try:
            text = read_text_capped(Path(_MOUNTS), encoding="utf-8", errors="replace")
        except OSError:
            snap.readable = False
            return snap

        # mountpoint -> options set (last entry wins — that is what is effective).
        by_mp: dict[str, frozenset[str]] = {}
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            # fields: device mountpoint fstype options ...
            # the mountpoint is octal-escaped for spaces; scratch areas have none.
            mountpoint = parts[1]
            opts = frozenset(parts[3].split(","))
            by_mp[mountpoint] = opts

        for target in _TARGETS:
            if target in by_mp:
                snap.mounts.append(_MountInfo(path=target, is_mount=True,
                                              options=by_mp[target]))
            else:
                snap.mounts.append(_MountInfo(path=target, is_mount=False))
        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_mount_hardening(snapshot: MountHardeningSnapshot,
                          t: TranslationFunc | None = None) -> CheckResult:
    """Analyse MountHardeningSnapshot and return findings."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.readable:
        result.info(
            message=_t("mount_hardening.unreadable"),
            detail=_t("mount_hardening.unreadable_detail"),
            key="mount_hardening.unreadable",
        )
        return result

    for m in snapshot.mounts:
        if not m.is_mount:
            if m.path in _ALWAYS_MOUNT:
                # Should not happen (kernel tmpfs); treat as unknown rather than
                # inventing a verdict.
                result.info(
                    message=_t("mount_hardening.not_found", mount=m.path),
                    key="mount_hardening.not_found",
                )
            else:
                result.info(
                    message=_t("mount_hardening.not_separate", mount=m.path),
                    detail=_t("mount_hardening.not_separate_detail", mount=m.path),
                    key="mount_hardening.not_separate",
                )
            continue

        missing_hard = [o for o in ("nodev", "nosuid") if o not in m.options]
        if missing_hard:
            result.warn_with_deduction(
                key="mount_hardening.options_missing",
                message=_t("mount_hardening.options_missing", mount=m.path,
                           missing=", ".join(missing_hard)),
                reason=_t("mount_hardening.options_missing_reason", mount=m.path),
                points=1,
                detail=_t("mount_hardening.options_missing_detail"),
                nature="action",
            )
        elif "noexec" not in m.options:
            result.info(
                message=_t("mount_hardening.noexec_missing", mount=m.path),
                detail=_t("mount_hardening.noexec_missing_detail", mount=m.path),
                key="mount_hardening.noexec_missing",
            )
        else:
            result.ok(
                message=_t("mount_hardening.hardened", mount=m.path),
                key="mount_hardening.hardened",
            )

    return result
