"""
System update status audit for BOB.

Checks:
  - Security packages pending update (apt-get -s upgrade, -security sources)
  - Regular packages pending update (informational)
  - unattended-upgrades installation and configuration

Usage:
    from bob.checks.updates import UpdatesSnapshot, check_updates

    snapshot = UpdatesSnapshot.from_system()
    result   = check_updates(snapshot)
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import install_fix, package_installed, _command_exists, _identity_t, _run, is_unit_active, path_exists
from bob.scoring import CheckResult
from bob._atomic import read_text_capped

# Age threshold (in seconds) above which the APT cache is considered stale.
# 7 days mirrors the typical unattended-upgrades refresh window; beyond this
# the cache will under-report upgrades available upstream.
_APT_CACHE_STALE_THRESHOLD = 7 * 86400  # 7 days

# pkgcache.bin is the binary APT cache; its mtime tracks the last successful
# `apt-get update`. /var/lib/apt/lists/ holds the InRelease files we could
# also stat, but pkgcache.bin is simpler and equally reliable in practice.
_APT_CACHE_FILE = Path("/var/cache/apt/pkgcache.bin")

# M-7 (v0.5.5): "transparency" INFO keys never produced by a real failure.
# Used by _has_actionable_findings to decide whether to emit the "all clear"
# OK alongside informational notes (cache age, etc.). Add new keys here as
# more transparency INFOs are introduced.
_TRANSPARENCY_KEYS: frozenset[str] = frozenset({"updates.apt_cache_age"})

def _has_actionable_findings(result) -> bool:
    """Return True if any finding signals an actual issue (not a pure note)."""
    return any(f.key not in _TRANSPARENCY_KEYS for f in result.findings)

# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class UpdatesSnapshot:
    """
    Raw snapshot of system update state.

    All I/O happens in from_system(). check_updates() is pure logic.

    Fields:
        apt_available:        ``apt-get`` is on $PATH.
        pending_security:     Package names with a ``-security`` source suite.
        pending_regular:      Package names from other sources.
        unattended_installed: ``unattended-upgrades`` package present.
        unattended_enabled:   ``unattended-upgrades`` actually configured to run.
        apt_cache_age_days:   ``None`` if pkgcache.bin not found; otherwise
                              number of full days since the cache was refreshed.
        upgradable_count:     ``apt list --upgradable`` count (cross-check
                              against the simulated dist-upgrade). ``None`` if
                              the command isn't available or failed.
        manager:              The detected package manager — "apt", "dnf",
                              "zypper", "pacman", "apk", or "" when none is
                              present. v0.19.0: the check was apt-only until a
                              field test on real Fedora/openSUSE/Alpine/Arch VMs
                              showed it reported "no apt" (blind) on 4 of the 5
                              families. ``apt_available`` is kept as the apt
                              back-compat alias (``manager == "apt"``).
    """
    apt_available:          bool = False
    pending_security:       list[str] = field(default_factory=list)
    pending_regular:        list[str] = field(default_factory=list)
    unattended_installed:   bool = False
    unattended_enabled:     bool = False
    apt_cache_age_days:     int | None = None
    upgradable_count:       int | None = None
    manager:                str = ""

    @classmethod
    def from_system(cls) -> "UpdatesSnapshot":
        """
        Collect update state from the live system.

        Detects the package manager and collects pending updates through it.
        Only apt carries the extra apt-specific state (unattended-upgrades,
        cache age, dist-upgrade cross-check); the others populate the shared
        ``pending_security`` / ``pending_regular`` lists. Managers with no
        security channel (pacman, apk) report every pending package as regular
        — BOB does not invent a severity the tool cannot supply.

        Returns:
            Populated UpdatesSnapshot. Never raises — errors reflected as defaults.
        """
        snap = cls()

        if _command_exists("apt-get"):
            snap.manager = "apt"
            snap.apt_available = True
            snap.pending_security, snap.pending_regular = _collect_pending_updates()
            snap.unattended_installed, snap.unattended_enabled = _check_unattended()
            snap.apt_cache_age_days = _apt_cache_age_days()
            snap.upgradable_count = _count_upgradable()
        elif _command_exists("dnf"):
            snap.manager = "dnf"
            snap.pending_security, snap.pending_regular = _collect_dnf()
        elif _command_exists("zypper"):
            snap.manager = "zypper"
            snap.pending_security, snap.pending_regular = _collect_zypper()
        elif _command_exists("pacman"):
            snap.manager = "pacman"
            snap.pending_security, snap.pending_regular = _collect_pacman()
        elif _command_exists("apk"):
            snap.manager = "apk"
            snap.pending_security, snap.pending_regular = _collect_apk()

        return snap

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect_pending_updates() -> tuple[list[str], list[str]]:
    """
    Run ``apt-get -s dist-upgrade`` and parse Inst lines.

    Uses ``dist-upgrade`` (not ``upgrade``) because plain ``upgrade`` is
    conservative — it refuses to upgrade any package that would require
    installing a new package or removing an existing one. On Debian/Ubuntu
    this hides every security update bundled with a kernel transition or a
    new soname (e.g. ``linux-image-amd64 → linux-image-6.12.86-amd64``).

    Returns:
        (security, regular) — lists of package names by update type.
        Security packages are identified by a ``-security`` suite in the
        apt source field (e.g. ``jammy-security``, ``debian-security``).
    """
    security: list[str] = []
    regular:  list[str] = []

    out = _run("apt-get", "-s", "dist-upgrade", timeout=30)
    if not out:
        return security, regular

    for line in out.splitlines():
        if not line.startswith("Inst "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        pkg = parts[1]
        if re.search(r"-security\b", line, re.IGNORECASE):
            security.append(pkg)
        else:
            regular.append(pkg)

    # Deduplicate while preserving order (apt can emit the same package twice)
    return list(dict.fromkeys(security)), list(dict.fromkeys(regular))


def _dedup(security: list[str], regular: list[str]) -> tuple[list[str], list[str]]:
    """Dedup both lists and drop from *regular* anything already in *security*."""
    sec = list(dict.fromkeys(security))
    secset = set(sec)
    reg = [p for p in dict.fromkeys(regular) if p not in secset]
    return sec, reg


# --- non-apt collectors (v0.19.0) ------------------------------------------
# Each reads the package manager's own local state (no network refresh, mirroring
# apt's simulated dist-upgrade), parses it against output captured on real VMs,
# and returns (security, regular) package-name lists. Managers with no security
# channel return security=[].

def _collect_dnf() -> tuple[list[str], list[str]]:
    """dnf: ``updateinfo list --security`` for security, ``check-update`` for all.

    check-update row: ``name.arch  version  repo`` (name may carry no epoch;
    the epoch sits in the version column). updateinfo row:
    ``ADVISORY security SEVERITY name-version-release.arch DATE TIME`` — the
    NEVRA's name is everything before the last two ``-`` fields.
    """
    security: list[str] = []
    sec_out = _run("dnf", "-q", "--cacheonly", "updateinfo", "list", "--security", timeout=30)
    for line in sec_out.splitlines():
        parts = line.split()
        # data rows have the literal type "security" as the 2nd column
        if len(parts) >= 4 and parts[1].lower() == "security":
            security.append(parts[3].rsplit("-", 2)[0])

    regular: list[str] = []
    all_out = _run("dnf", "-q", "--cacheonly", "check-update", timeout=30)
    for line in all_out.splitlines():
        line = line.rstrip()
        # Everything from the "Obsoleting Packages" header on is not a pending
        # update — stop rather than rely on the (version-dependent) indentation.
        if line.lower().startswith("obsoleting"):
            break
        if not line or line.startswith(" "):
            continue
        parts = line.split()
        # a package row is exactly ``name.arch  version  repo`` with a dotted name
        if len(parts) == 3 and "." in parts[0]:
            regular.append(parts[0].rsplit(".", 1)[0])

    return _dedup(security, regular)


def _collect_zypper() -> tuple[list[str], list[str]]:
    """zypper: security *patches* + all package *updates* (pipe-delimited tables).

    list-patches --category security: ``Repo | Name | Category | Severity | …``.
    list-updates: ``S | Repository | Name | Current | Available | Arch``.
    """
    security: list[str] = []
    sec_out = _run("zypper", "--non-interactive", "--quiet",
                   "list-patches", "--category", "security", timeout=45)
    for line in sec_out.splitlines():
        if "|" not in line:
            continue
        cells = [c.strip() for c in line.split("|")]
        # skip header (col 0 == "Repository") and separators
        if len(cells) >= 4 and cells[0] and cells[0] != "Repository" and "---" not in line:
            security.append(cells[1])

    regular: list[str] = []
    all_out = _run("zypper", "--non-interactive", "--quiet", "list-updates", timeout=45)
    for line in all_out.splitlines():
        if "|" not in line:
            continue
        cells = [c.strip() for c in line.split("|")]
        # data rows carry a status flag ("v") in col 0; header is "S"
        if len(cells) >= 3 and cells[0] and cells[0] != "S" and "---" not in line:
            regular.append(cells[2])

    return _dedup(security, regular)


def _collect_pacman() -> tuple[list[str], list[str]]:
    """pacman: ``pacman -Qu`` (``name old -> new``). No security channel — all
    pending updates are reported as regular."""
    regular: list[str] = []
    out = _run("pacman", "-Qu", timeout=30)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            regular.append(parts[0])
    return _dedup([], regular)


def _collect_apk() -> tuple[list[str], list[str]]:
    """apk: ``apk version -l '<'`` (``name-version-rREV < available``). No
    security channel — all pending upgrades are reported as regular."""
    regular: list[str] = []
    out = _run("apk", "version", "-l", "<", timeout=30)
    for line in out.splitlines():
        if "<" not in line or line.startswith("Installed"):
            continue
        nevra = line.split("<", 1)[0].strip()
        if nevra:
            regular.append(nevra.rsplit("-", 2)[0])
    return _dedup([], regular)


def _upgrade_cmd(manager: str) -> str:
    """The command that applies the pending (security) updates for *manager*.

    apt carries ``--with-new-pkgs`` because the finding is collected with
    ``apt-get -s dist-upgrade``: plain ``upgrade`` refuses to pull in a new
    package (every kernel security update), so it would detect with one command
    and repair with a strictly weaker one — the kernel is *kept back*, apt
    returns 0, and ``--fix --apply`` reports it applied. ``--with-new-pkgs``
    installs the kernel and, unlike ``dist-upgrade``, removes nothing. The
    ``-y`` (and the other managers' ``--security`` / ``patch`` / non-interactive
    forms) keeps ``--fix --apply --yes`` from stopping to ask.
    """
    return {
        "apt":    "sudo apt-get upgrade -y --with-new-pkgs",
        "dnf":    "sudo dnf upgrade --security -y",
        "zypper": "sudo zypper patch --category security -y",
        "pacman": "sudo pacman -Syu",
        "apk":    "sudo apk upgrade",
    }.get(manager, "")


def _apt_cache_age_days() -> int | None:
    """Return age of the APT cache in days, or ``None`` if it cannot be read.

    Reading /var/cache/apt/pkgcache.bin requires no privileges. We use mtime
    because it reflects the last successful ``apt-get update``.
    """
    try:
        mtime = _APT_CACHE_FILE.stat().st_mtime
    except OSError:
        return None
    age_seconds = time.time() - mtime
    if age_seconds < 0:
        return 0
    return int(age_seconds // 86400)

def _count_upgradable() -> int | None:
    """Return the count from ``apt list --upgradable``, or ``None`` on failure.

    Cross-check against the simulated dist-upgrade — if dist-upgrade reports 0
    pending while apt-list reports N > 0, the cache may be stale or a
    transitional state is in play and the user deserves a warning.

    Format::

        Listing... Done
        pkg/suite 1.1 amd64 [upgradable from: 1.0]
        ...
    """
    # apt list defaults to a coloured pager-aware output on TTY; force a
    # terminal-friendly mode with 2>/dev/null on the warning line apt emits
    # via stderr ("WARNING: apt does not have a stable CLI interface...").
    out = _run("apt", "list", "--upgradable", timeout=20)
    if not out:
        return None
    count = 0
    for line in out.splitlines():
        # Skip header / blank / WARNING lines.
        if "/" in line and "[upgradable from" in line:
            count += 1
    return count

# apt.conf accepts three comment syntaxes — `//` to end of line, `/* */`
# blocks, and `#` to end of line — and `20auto-upgrades` is exactly the file an
# administrator disables by commenting the line out rather than setting "0".
# Matching the raw text therefore reported unattended upgrades as *enabled* on
# a host where apt reads nothing at all: a reassuring verdict for a control
# that is off. Confirmed against `apt-config dump` for all three syntaxes.
_APT_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

def _strip_apt_comments(text: str) -> str:
    """Return `text` with apt.conf comments removed.

    `//` and `#` are honoured only outside a double-quoted string, so a value
    such as ``"http://example.invalid"`` survives intact.
    """
    text = _APT_BLOCK_COMMENT_RE.sub(" ", text)
    out: list[str] = []
    for line in text.splitlines():
        in_quotes = False
        cut = len(line)
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '"':
                in_quotes = not in_quotes
            elif not in_quotes:
                if ch == "#" or line.startswith("//", i):
                    cut = i
                    break
            i += 1
        out.append(line[:cut])
    return "\n".join(out)


def _check_unattended() -> tuple[bool, bool]:
    """
    Return (installed, enabled) for unattended-upgrades.

    installed — package present according to dpkg-query
    enabled   — configured to actually run (apt periodic config or systemd timer)
    """
    # Step 1 — package installed?
    # `unattended-upgrades` is a Debian concept, so this answers False on an
    # rpm host either way — but the query goes through the shared helper so no
    # module keeps a private package check. Two defects in this release came
    # from one rule living in several copies.
    if package_installed("unattended-upgrades") is None:
        return False, False

    # Step 2 — configured to run upgrades automatically?
    apt_conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if path_exists(apt_conf):
        try:
            content = _strip_apt_comments(
                read_text_capped(apt_conf, encoding="utf-8", errors="ignore")
            )
            if re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', content):
                return True, True
        except OSError:
            pass

    # Step 3 — fallback: systemd timer active
    enabled = is_unit_active("apt-daily-upgrade.timer")
    return True, enabled

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_updates(
    snapshot: UpdatesSnapshot,
    *,
    t=None,
    profile_name: str = "server",
) -> CheckResult:
    """
    Check system update status.

    Scoring:
      - Security packages pending:           −2 pts (flat, regardless of count)
      - Unattended-upgrades not configured
        AND security packages pending
        AND profile is not workstation:      −1 pt additional (compound risk)
      - On workstation profile, unattended not configured: INFO only (no deduction)
      - Regular packages pending:            INFO only, no deduction
      - Unattended-upgrades not configured
        AND system up to date:               INFO only

    Args:
        snapshot:     UpdatesSnapshot from the system (or built in tests).
        t:            Translation function. Defaults to key pass-through.
        profile_name: Active audit profile name. "workstation" demotes the
                      unattended-upgrades compound risk to INFO.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()

    # Guard against None being passed instead of an empty list
    security = snapshot.pending_security or []
    regular  = snapshot.pending_regular or []

    # v0.19.0: back-compat — old snapshots (and tests) set only ``apt_available``.
    mgr = snapshot.manager or ("apt" if snapshot.apt_available else "")

    # --- no supported package manager ---------------------------------------
    if not mgr:
        result.info(
            message=_t("updates.no_apt"),
            key="updates.no_apt",
        )
        return result

    # --- APT-only: cache freshness + dist-upgrade cross-check ---------------
    # These read apt-specific state; the other managers have no equivalent here.
    if mgr == "apt":
        # Without a fresh cache, dist-upgrade simulation reports stale data.
        # We warn the user before reporting "0 pending" to avoid false reassurance.
        cache_age = snapshot.apt_cache_age_days
        if cache_age is not None and cache_age * 86400 >= _APT_CACHE_STALE_THRESHOLD:
            result.warn(
                message=_t("updates.apt_cache_stale", days=cache_age),
                detail=_t("updates.apt_cache_stale_detail"),
                cmd="sudo apt update",
                key="updates.apt_cache_stale",
                nature="improvement",
            )

        # If apt list reports upgradable packages while dist-upgrade returned
        # zero, the simulation likely failed silently (locked, broken state, etc.).
        if (
            snapshot.upgradable_count is not None
            and snapshot.upgradable_count > 0
            and not security
            and not regular
        ):
            result.warn(
                message=_t(
                    "updates.dist_upgrade_inconsistent",
                    count=snapshot.upgradable_count,
                ),
                detail=_t("updates.dist_upgrade_inconsistent_detail"),
                cmd="sudo apt update && sudo apt list --upgradable",
                key="updates.dist_upgrade_inconsistent",
                nature="improvement",
            )

    # --- Security packages pending ------------------------------------------
    if security:
        count = len(security)
        pkgs  = ", ".join(security[:5])
        if count > 5:
            pkgs += f" (+{count - 5})"
        result.warn_with_deduction(
            key="updates.security_pending",
            message=_t("updates.security_pending", count=count, packages=pkgs),
            reason=_t("updates.security_pending_reason", count=count),
            points=2,
            detail=_t("updates.security_pending_detail"),
            # The remediation is the manager's own security-upgrade command.
            # apt: `-y` so --fix --apply does not stop to ask (v0.17.1); and
            # `--with-new-pkgs` because the finding is collected with
            # `-s dist-upgrade`, so plain `upgrade` (which refuses to pull in a
            # new package, i.e. every kernel security update) would detect with
            # one command and remediate with a strictly weaker one. The other
            # managers get their own `--security` / `patch` form.
            cmd=_upgrade_cmd(mgr),
            nature="action",
        )

    # --- Regular packages pending -------------------------------------------
    if regular:
        result.info(
            message=_t("updates.regular_pending",
                       count=len(regular)),
            key="updates.regular_pending",
        )

    # --- unattended-upgrades (apt / Debian concept only) --------------------
    uu_ok = snapshot.unattended_installed and snapshot.unattended_enabled

    if mgr == "apt" and not uu_ok:
        if security and profile_name not in ("workstation", "desktop"):
            # Compound risk: security gap + no automation (server/default only)
            # Unattended upgrades are a Debian package *and* a Debian concept:
            # Fedora's equivalent is dnf-automatic, whose own package name moved
            # to dnf5-plugin-automatic, and which is configured differently.
            # BOB names what it wants and stops there.
            _cmd, _detail = install_fix(
                _t, _t("updates.unattended_not_configured_detail"), "auto-updates",
                then_apt="sudo dpkg-reconfigure -plow unattended-upgrades")
            result.warn_with_deduction(
                key="updates.unattended_not_configured",
                message=_t("updates.unattended_not_configured"),
                reason=_t("updates.unattended_not_configured_reason"),
                points=1,
                detail=_detail,
                cmd=_cmd,
                nature="improvement",
            )
        else:
            # Workstation profile, or system up to date — informational only
            result.info(
                message=_t("updates.unattended_not_configured"),
                detail=_t("updates.unattended_not_configured_detail"),
                key="updates.unattended_not_configured",
            )

    # --- APT cache age (transparency when no findings security/regular) ----
    # The "all clear" verdict relies on the local APT cache state. Surface
    # the cache age so the user knows whether they are looking at a fresh
    # read or a stale snapshot. The stale-threshold warning above already
    # handles the > 7-day case — this INFO covers the "fresh-enough but
    # not zero" range that the threshold leaves silent. apt-only: it reads
    # ``apt_cache_age_days`` and the other managers have no equivalent.
    if (
        mgr == "apt"
        and snapshot.apt_cache_age_days is not None
        and not security
        and not regular
        and snapshot.apt_cache_age_days * 86400 < _APT_CACHE_STALE_THRESHOLD
    ):
        result.info(
            message=_t("updates.apt_cache_age", days=snapshot.apt_cache_age_days),
            detail=_t("updates.apt_cache_age_detail"),
            key="updates.apt_cache_age",
        )

    # --- All clear ----------------------------------------------------------
    # M-7 (v0.5.5): emit OK only when no *deductive* finding was produced.
    # The apt_cache_age INFO above is transparency, not a signal — it must
    # not block the "system is up to date" OK. Extract helper rather than
    # inline-key-blacklist so adding future transparency INFOs is safe.
    if not _has_actionable_findings(result):
        result.ok(
            message=_t("updates.ok"),
            key="updates.ok",
        )

    return result
