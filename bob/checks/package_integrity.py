"""
Package-integrity check for BOB — the first consumer of ``--exhaustive``.

A package manager records a cryptographic digest for every file it installs.
Comparing the files on disk against those digests reveals binaries or libraries
that were modified after installation — a strong (though not conclusive)
intrusion signal. The verification is deliberately **slow**: ``rpm -Va`` and
``debsums -c`` re-hash every packaged file (O(installed bytes), tens of seconds
on a full system), which is why it is held out of the default fast audit and
only runs under ``--exhaustive``.

Doctrine ([[feedback_bob_doctrine]]):
  - **INFO-only.** A changed file is ambiguous — a local recompile, a sysadmin
    patch or a locale regeneration all look identical to tampering here — so the
    check never deducts. It reports what differs and leaves the judgement to the
    operator.
  - **unknown ≠ clean.** When the verifier is not installed (``debsums`` is
    frequently absent on Debian) or the run times out, BOB says integrity was
    *not verified*, never that the system is clean.
  - **Config files are expected to differ** and are filtered out — ``rpm`` marks
    them ``c``; for the others BOB drops paths under ``/etc``.
  - **Bounded + group-killed.** The verifier runs under a finite timeout and its
    whole process group is killed if it overruns ([[feedback_timeout_must_kill_the_group]]).

Split into:
  1. PackageIntegritySnapshot.from_system() — runs the verifier (never raises).
  2. check_package_integrity(snapshot, t) — pure analysis (INFO-only).
"""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass, field

from bob.checks._run import (
    _C_LOCALE_ENV,
    _MANAGER_ALIASES,
    TranslationFunc,
    _command_exists,
    _identity_t,
    detect_install_manager,
)
from bob.scoring import CheckResult

#: A **hang-guard, not a slowness cap.** ``debsums -c`` / ``rpm -Va`` re-hash every
#: packaged file — O(installed files) — so a full install legitimately takes
#: minutes (measured on real hardware: 556 s on a Pi Zero W, 511 s on a Mint
#: desktop). Killing a slow-but-progressing scan destroys a valid result, so this
#: timeout exists only to bound a genuinely *wedged* verifier (a `rpm`/`debsums`
#: stuck on a pathological filesystem). The check is opt-in (``--exhaustive``), so
#: 30 min is a safe ceiling: any real scan finishes well under it, and a true hang
#: is still stopped and reported as "not verified" (group-killed), never a false
#: "clean". An operator who wants it shorter can Ctrl-C.
_VERIFY_TIMEOUT = 1800

#: How many differing paths to name in the aggregated finding before eliding.
_SAMPLE = 12

#: Per package manager: (tool, verify-args). The tool is what must exist for the
#: check to run at all — ``debsums`` is a separate package on Debian/Ubuntu.
_VERIFIERS: "dict[str, tuple[str, tuple[str, ...]]]" = {
    "apt":    ("debsums", ("debsums", "-c")),
    "dnf":    ("rpm", ("rpm", "-Va")),
    "zypper": ("rpm", ("rpm", "-Va")),
    "pacman": ("pacman", ("pacman", "-Qkk")),
    "apk":    ("apk", ("apk", "audit", "--system")),
}


def _is_config_path(path: str) -> bool:
    """A changed file under /etc is an expected admin edit, not tampering."""
    return path == "/etc" or path.startswith("/etc/")


def _run_capped(args: "tuple[str, ...]") -> "tuple[str, bool, bool, bool]":
    """Run a verifier, killing its whole process group on overrun.

    ``subprocess.run``'s timeout SIGKILLs only the direct child; these verifiers
    are single-process so that alone would suffice, but this check is BOB's one
    deliberately-slow path, so it starts a new session and kills the group — any
    helper the verifier spawns cannot outlive the deadline.

    Returns ``(stdout, ok, timed_out, tool_found)``.
    """
    try:
        proc = subprocess.Popen(
            list(args), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, start_new_session=True, env=_C_LOCALE_ENV,
        )
    except (FileNotFoundError, OSError):
        return "", False, False, False
    try:
        out, _ = proc.communicate(timeout=_VERIFY_TIMEOUT)
        return out, proc.returncode == 0, False, True
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            pass
        return "", False, True, True


def _parse_rpm(out: str) -> "list[str]":
    """Changed non-config regular files from ``rpm -Va`` output.

    Lines are ``<9-char mask> [type] <path>``. The optional single-letter type
    marks config (c), doc (d), ghost (g), licence (l) or readme (r) — all
    expected to differ. A ``5`` in the mask is a digest mismatch: the signal.
    """
    changed = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        mask = parts[0]
        if len(parts) >= 3 and len(parts[1]) == 1 and parts[1].isalpha():
            ftype, path = parts[1], parts[-1]
        else:
            ftype, path = "", parts[-1]
        if ftype in ("c", "d", "g", "l", "r"):
            continue
        if "5" in mask and path.startswith("/") and not _is_config_path(path):
            changed.append(path)
    return changed


def _parse_debsums(out: str) -> "list[str]":
    """``debsums -c`` prints one changed-file path per line; drop /etc edits."""
    return [
        p for p in (ln.strip() for ln in out.splitlines())
        if p.startswith("/") and not _is_config_path(p)
    ]


def _parse_apk(out: str) -> "list[str]":
    """``apk audit --system`` prints ``<status> <path>`` (path relative to /).

    Only the modify/update rows ('U') are tampering candidates; filter /etc.
    """
    changed = []
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        status, rest = parts[0], parts[1].strip()
        if status not in ("U", "M"):
            continue
        path = rest if rest.startswith("/") else "/" + rest
        if not _is_config_path(path):
            changed.append(path)
    return changed


def _parse_pacman(out: str) -> "list[str]":
    """``pacman -Qkk`` prints one line per mismatch, e.g.

        warning: coreutils: /usr/bin/base64 (SHA256 checksum mismatch)

    and emits several lines for the same file (mtime + size + checksum). Count a
    file only on a size or checksum mismatch — a modification-time difference
    alone is benign — and de-duplicate, so one tampered file is one finding.
    """
    changed: "list[str]" = []
    for line in out.splitlines():
        low = line.lower()
        if "checksum mismatch" not in low and "size mismatch" not in low:
            continue
        for tok in line.replace(",", " ").split():
            if tok.startswith("/") and not _is_config_path(tok):
                path = tok.rstrip(":")
                if path not in changed:
                    changed.append(path)
                break
    return changed


_PARSERS = {
    "debsums": _parse_debsums,
    "rpm": _parse_rpm,
    "apk": _parse_apk,
    "pacman": _parse_pacman,
}


@dataclass
class PackageIntegritySnapshot:
    """
    Raw state of the package-file integrity verification.

    Args:
        manager:        Normalised package manager ("apt", "dnf", …) or "".
        tool:           The verifier binary expected ("debsums", "rpm", …).
        tool_available: True if that binary exists on the host.
        ran:            True if the verifier was launched and returned in time.
        timed_out:      True if it overran the timeout and was group-killed.
        changed_files:  Non-config packaged files that differ from the manifest.
    """
    manager:        str = ""
    tool:           str = ""
    tool_available: bool = False
    ran:            bool = False
    timed_out:      bool = False
    changed_files:  "list[str]" = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "PackageIntegritySnapshot":
        snap = cls()
        mgr = _MANAGER_ALIASES.get(detect_install_manager(), detect_install_manager())
        snap.manager = mgr
        verifier = _VERIFIERS.get(mgr)
        if verifier is None:
            return snap  # unknown manager — nothing to run
        snap.tool, args = verifier
        if not _command_exists(snap.tool):
            return snap  # tool_available stays False → "not verified"
        snap.tool_available = True
        out, _ok, timed_out, _found = _run_capped(args)
        snap.timed_out = timed_out
        if timed_out:
            return snap
        snap.ran = True
        parser = _PARSERS.get(snap.tool)
        snap.changed_files = parser(out) if parser else []
        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_package_integrity(snapshot: PackageIntegritySnapshot,
                            t: TranslationFunc | None = None) -> CheckResult:
    """Analyse PackageIntegritySnapshot and return findings (INFO-only)."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.manager or snapshot.tool not in _PARSERS:
        result.info(message=_t("package_integrity.unsupported"),
                    key="package_integrity.unsupported")
        return result

    if not snapshot.tool_available:
        result.info(
            message=_t("package_integrity.tool_missing", tool=snapshot.tool),
            detail=_t("package_integrity.tool_missing_detail", tool=snapshot.tool),
            key="package_integrity.tool_missing",
        )
        return result

    if snapshot.timed_out:
        result.info(message=_t("package_integrity.timed_out"),
                    key="package_integrity.timed_out")
        return result

    if snapshot.changed_files:
        sample = snapshot.changed_files[:_SAMPLE]
        more = len(snapshot.changed_files) - len(sample)
        listing = ", ".join(sample) + (f" (+{more})" if more > 0 else "")
        result.info(
            message=_t("package_integrity.changed",
                       count=len(snapshot.changed_files), files=listing),
            detail=_t("package_integrity.changed_detail"),
            key="package_integrity.changed",
        )
    else:
        result.ok(message=_t("package_integrity.clean", tool=snapshot.tool),
                  key="package_integrity.clean")

    return result
