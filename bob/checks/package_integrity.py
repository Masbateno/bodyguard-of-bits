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
import stat
import subprocess
from dataclasses import dataclass, field

from bob.checks._run import (
    _C_LOCALE_ENV,
    _MANAGER_ALIASES,
    TranslationFunc,
    _command_exists,
    _identity_t,
    more_suffix,
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

#: v0.42.0 (B-042) — the verifier dpkg itself ships, used when debsums is not
#: installed. Measured on the developer's workstation audit under 0.40.0: no
#: debsums, so the section stayed unread and the score a ceiling, while BOB's
#: own AIDE text recommends ``dpkg --verify``. Measured on the test Mint (dpkg
#: 1.22.6, 2025 packages, 21 November 2026): 499 s, exit 0 with 25 lines, 3 of
#: them configuration files, 22 Mint's own changes under /usr — the shape
#: 0.32.0 measured with debsums (21 files).
_FALLBACK: "dict[str, tuple[str, tuple[str, ...]]]" = {
    "apt":    ("dpkg", ("dpkg", "--verify")),
}


#: v0.43.0 (B-046) — dpkg's database: the status file (installed packages and
#: their conffiles) and, per package, the files it placed (``.list``) and the
#: digests it recorded (``.md5sums``).
_DPKG_STATUS = "/var/lib/dpkg/status"
_DPKG_INFO = "/var/lib/dpkg/info"

#: How many packages to name in the "no recorded digest" line before eliding.
_SAMPLE_PACKAGES = 8


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
    """``debsums -c`` prints one changed-file path per line; drop /etc edits.

    v0.43.0 — a ``.md5sums`` that records absolute paths (one third-party package
    on the developer's workstation does) makes debsums print ``//usr/bin/zcat``
    (measured in a Mint 22.3 container, debsums 3.0.2.1): the path is brought
    back to one leading slash, so ``//etc/…`` is still recognised as /etc.
    """
    paths = ("/" + ln.strip().lstrip("/") for ln in out.splitlines() if ln.strip().startswith("/"))
    return [p for p in paths if not _is_config_path(p)]


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


def _parse_dpkg_verify(out: str) -> "list[str]":
    """Changed non-config files from ``dpkg --verify``.

    Lines are ``<9-char mask> [c] <path>`` (rpm's layout; ``c`` marks a
    configuration file) or ``missing [c] <path>``, whose first word is no mask.
    As with debsums and rpm, only a digest mismatch (``5``) outside /etc
    counts; a missing file is not one debsums -c lists either.
    """
    changed = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        mask, path = parts[0], parts[-1]
        if len(parts) >= 3 and parts[1] == "c":
            continue
        if len(mask) == 9 and "5" in mask and path.startswith("/") and not _is_config_path(path):
            changed.append(path)
    return changed


def _dpkg_installed(status_text: str) -> "tuple[set[tuple[str, str]], set[str]]":
    """Installed ``(package, architecture)`` pairs and every conffile path."""
    installed: "set[tuple[str, str]]" = set()
    conffiles: "set[str]" = set()
    pkg = arch = status = ""
    in_conffiles = False
    for line in status_text.splitlines() + [""]:
        if not line:
            if pkg and status.endswith(" installed"):
                installed.add((pkg, arch))
            pkg = arch = status = ""
            in_conffiles = False
            continue
        if line.startswith(" "):
            if in_conffiles and line.split():
                conffiles.add(line.split()[0])
            continue
        in_conffiles = line.startswith("Conffiles:")
        if line.startswith("Package: "):
            pkg = line[9:].strip()
        elif line.startswith("Architecture: "):
            arch = line[14:].strip()
        elif line.startswith("Status: "):
            status = line[8:].strip()
    return installed, conffiles


def _dpkg_undigested(status_path: str = _DPKG_STATUS,
                     info_dir: str = _DPKG_INFO) -> "dict[str, int] | None":
    """v0.43.0 (B-046) — per package, the regular files it placed outside /etc
    that have no digest recorded, so neither debsums nor ``dpkg --verify``
    compares them. ``None`` when dpkg's database cannot be read: not counted,
    never "none".

    Measured in a Mint 22.3 container (dpkg 1.22.6, debsums 3.0.2.1, 22
    November 2026): a file modified after its line was removed from the
    package's ``.md5sums``, or a package with no ``.md5sums`` at all — both
    verifiers stay silent (debsums -c writes "no md5sums for less" on stderr,
    which this check does not read). On the developer's workstation: no
    package without digests, two with files left out (aspell-en: 23 files its
    install script rewrites; a third-party office suite: 8).

    Only ``lstat`` is called on the listed paths: nothing is opened but the
    database's own files, which are root's.
    """
    try:
        with open(status_path, encoding="utf-8", errors="replace") as fh:
            installed, conffiles = _dpkg_installed(fh.read())
    except OSError:
        return None
    found: "dict[str, int]" = {}
    for pkg, arch in sorted(installed):
        base = None
        for name in (f"{pkg}:{arch}", pkg):
            if os.path.exists(os.path.join(info_dir, name + ".list")):
                base = name
                break
        if base is None:
            continue  # a package that placed no file
        try:
            with open(os.path.join(info_dir, base + ".list"), encoding="utf-8", errors="replace") as fh:
                listed = [ln.rstrip("\n") for ln in fh]
        except OSError:
            return None
        digested: "set[str]" = set()
        try:
            with open(os.path.join(info_dir, base + ".md5sums"), encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    parts = ln.rstrip("\n").split(None, 1)
                    if len(parts) == 2:
                        # Debian writes paths without the leading slash; one
                        # third-party package on the workstation writes it.
                        digested.add("/" + parts[1].strip().lstrip("/"))
        except FileNotFoundError:
            pass  # no digests at all: every regular file it placed counts
        except OSError:
            return None
        missing = 0
        for path in listed:
            if not path.startswith("/") or path in digested or path in conffiles or _is_config_path(path):
                continue
            try:
                if stat.S_ISREG(os.lstat(path).st_mode):
                    missing += 1
            except OSError:
                continue  # gone from disk: dpkg --verify says "missing", not this
        if missing:
            found[pkg] = found.get(pkg, 0) + missing
    return found


_PARSERS = {
    "debsums": _parse_debsums,
    "dpkg": _parse_dpkg_verify,
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
        failed:         v0.42.0 — dpkg --verify exited non-zero with no output:
                        not verified (dpkg exits 0 with differences, measured).
        changed_files:  Non-config packaged files that differ from the manifest.
        undigested_checked: v0.43.0 (B-046) — dpkg's database was looked at for
                        files with no recorded digest (apt hosts, verifier run).
        undigested:     package → number of such files; ``None`` when the
                        database could not be read (not counted, never "none").
    """
    manager:        str = ""
    tool:           str = ""
    tool_available: bool = False
    ran:            bool = False
    timed_out:      bool = False
    failed:         bool = False
    changed_files:  "list[str]" = field(default_factory=list)
    undigested_checked: bool = False
    undigested:     "dict[str, int] | None" = None

    @classmethod
    def from_system(cls) -> "PackageIntegritySnapshot":
        snap = cls()
        mgr = _MANAGER_ALIASES.get(detect_install_manager(), detect_install_manager())
        snap.manager = mgr
        verifier = _VERIFIERS.get(mgr)
        if verifier is None:
            return snap  # unknown manager — nothing to run
        snap.tool, args = verifier
        if not _command_exists(snap.tool) and mgr in _FALLBACK and _command_exists(_FALLBACK[mgr][0]):
            snap.tool, args = _FALLBACK[mgr]
        if not _command_exists(snap.tool):
            return snap  # tool_available stays False → "not verified"
        snap.tool_available = True
        out, ok, timed_out, _found = _run_capped(args)
        snap.timed_out = timed_out
        if timed_out:
            return snap
        if snap.tool == "dpkg" and not ok and not out.strip():
            snap.failed = True
            return snap
        snap.ran = True
        parser = _PARSERS.get(snap.tool)
        snap.changed_files = parser(out) if parser else []
        if mgr == "apt":
            snap.undigested_checked = True
            snap.undigested = _dpkg_undigested()
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

    if snapshot.failed:
        result.info(message=_t("package_integrity.verifier_failed", tool=snapshot.tool),
                    key="package_integrity.verifier_failed")
        return result

    if snapshot.changed_files:
        sample = snapshot.changed_files[:_SAMPLE]
        listing = ", ".join(sample) + more_suffix(_t, len(snapshot.changed_files), len(sample))   # v0.42.0 (B-037)
        result.info(
            message=_t("package_integrity.changed",
                       count=len(snapshot.changed_files), files=listing),
            # v0.32.0 — the same limit: a file changed with its recorded digest
            # is not in this list (measured on Linux Mint 22.3, 11 November
            # 2026: 21 files listed, the shape real hosts show, not "clean").
            detail=" ".join((_t("package_integrity.changed_detail"),
                             _t("package_integrity.local_digests_limit"))),
            key="package_integrity.changed",
        )
    else:
        result.ok(message=_t("package_integrity.clean", tool=snapshot.tool),
                  # v0.32.0 — the digests live in the local package database; a
                  # compromised root can rewrite them with the files. Said, so
                  # "clean" is not read as an external chain of trust.
                  detail=_t("package_integrity.local_digests_limit"),
                  key="package_integrity.clean")

    if snapshot.undigested_checked:
        # v0.43.0 (B-046) — a file with no recorded digest is compared by
        # neither verifier (measured): said, so "no file differs" is not read
        # as covering it. INFO, no point: the section was read.
        if snapshot.undigested is None:
            result.info(message=_t("package_integrity.no_digest_not_counted"),
                        key="package_integrity.no_digest_not_counted")
        elif snapshot.undigested:
            names = sorted(snapshot.undigested)
            shown = names[:_SAMPLE_PACKAGES]
            listing = ", ".join(f"{n} ({snapshot.undigested[n]})" for n in shown) \
                + more_suffix(_t, len(names), len(shown))
            result.info(
                message=_t("package_integrity.no_digest",
                           files=sum(snapshot.undigested.values()),
                           count=len(names), packages=listing),
                detail=_t("package_integrity.no_digest_detail"),
                key="package_integrity.no_digest",
            )

    return result
