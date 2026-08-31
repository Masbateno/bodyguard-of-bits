"""
Mandatory Access Control (MAC) audit for BOB (CHECK 34).

Checks whether a MAC framework is installed and actively enforcing policies.
Supports AppArmor (Ubuntu/Debian default) and SELinux (RHEL/CentOS/Fedora).

Score impact:
  - No MAC framework found:               WARN  −1 pt  (all profiles)
  - AppArmor installed but inactive:       WARN  −1 pt  (all profiles)
  - AppArmor active, 0 enforce profiles:  WARN  −1 pt  (server)
                                           INFO   0 pt  (desktop — complain may be intentional)
  - AppArmor active, enforcing profiles:   OK
  - SELinux enforcing:                     OK
  - SELinux permissive:                    INFO   0 pt  (not penalised)

Container: section skipped in runner.py — MAC is managed by the host.

The check is split into two parts:
  1. MacPolicySnapshot.from_system() — collects raw data.
  2. check_mac_policy(snapshot)       — pure logic, returns a CheckResult.

Usage:
    from bob.checks.mac_policy import MacPolicySnapshot, check_mac_policy

    snapshot = MacPolicySnapshot.from_system()
    result   = check_mac_policy(snapshot, profile_name="server")
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run
from bob.scoring import CheckResult

# Regex: "   N profiles are in enforce mode."
_AA_LOADED_RE = re.compile(r"^\s*(\d+)\s+profiles?\s+are\s+loaded", re.MULTILINE)
_AA_COUNT_RE = re.compile(r"^\s*(\d+)\s+profiles?\s+are\s+in\s+(\w+)\s+mode", re.MULTILINE)


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class MacPolicySnapshot:
    """
    Raw snapshot of MAC framework state.

    Args:
        apparmor_installed:  True if ``aa-status`` is present or the apparmor
                             kernel module directory exists.
        apparmor_active:     True if the AppArmor module is loaded and the
                             service is responding.
        apparmor_enforcing:  Number of profiles currently in enforce mode.
        apparmor_complain:   Number of profiles currently in complain mode.
        apparmor_profiles_readable: False when the profile set could not be read.
        selinux_installed:   True if ``getenforce`` is present.
        selinux_mode:        "Enforcing" | "Permissive" | "Disabled" | "".
    """
    apparmor_installed: bool = False
    apparmor_active:    bool = False
    apparmor_enforcing: int  = 0
    apparmor_complain:  int  = 0
    # False when aa-status reported the module but could not read the
    # profile set — the counters above are then unknown, not zero.
    apparmor_profiles_readable: bool = True
    selinux_installed:  bool = False
    selinux_mode:       str  = ""

    @classmethod
    def from_system(cls) -> "MacPolicySnapshot":
        """
        Collect MAC framework state from the live system.

        Returns:
            Populated MacPolicySnapshot. Never raises — errors reflected as defaults.
        """
        snap = cls()

        # --- AppArmor -------------------------------------------------------
        if _command_exists("aa-status"):
            snap.apparmor_installed = True
            aa_out = _run("aa-status") or ""
            if aa_out and "module is loaded" in aa_out.lower():
                snap.apparmor_active    = True
                # aa-status succeeds *partially* without the privilege to read
                # the profile set: it prints "apparmor module is loaded." and
                # then fails, with the explanation on stderr and exit 4. The
                # counters then parse as 0 and the host is told it has no
                # profiles — measured here on a machine carrying 120 in enforce
                # mode, with a WARN and a point to go with it.
                #
                # A reachable profile set always yields a count line
                # ("%zd profiles are loaded." is in the binary), so the absence
                # of one is the discriminator.
                snap.apparmor_profiles_readable = bool(
                    _AA_COUNT_RE.search(aa_out)
                    or _AA_LOADED_RE.search(aa_out)
                )
                snap.apparmor_enforcing = _parse_aa_count(aa_out, "enforce")
                snap.apparmor_complain  = _parse_aa_count(aa_out, "complain")
        elif Path("/sys/module/apparmor").is_dir():
            # Module loaded but aa-status not available (partial install)
            snap.apparmor_installed = True
            snap.apparmor_active    = False

        # --- SELinux --------------------------------------------------------
        if _command_exists("getenforce"):
            snap.selinux_installed = True
            out = _run("getenforce") or ""
            snap.selinux_mode = out.strip()

        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_mac_policy(
    snapshot: MacPolicySnapshot,
    *,
    t: TranslationFunc | None = None,
    profile_name: str = "server",
) -> CheckResult:
    """
    Audit Mandatory Access Control (MAC) enforcement status.

    Evaluation order:
      1. SELinux enforcing  → OK (short-circuit, MAC is active)
      2. AppArmor enforcing → OK
      3. AppArmor active but no enforce profiles → WARN (server) / INFO (desktop)
      4. AppArmor installed but inactive → WARN −1
      5. SELinux disabled (installed but explicitly off) → WARN −1
      6. No MAC found → WARN −1

    Args:
        snapshot:     MacPolicySnapshot from the system (or built in tests).
        t:            Translation function. Defaults to key pass-through.
        profile_name: "server" | "desktop" | "container".

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()
    se_mode = snapshot.selinux_mode.lower()

    # --- SELinux enforcing → MAC is active, all done ------------------------
    if se_mode == "enforcing":
        result.ok(
            message=_t("mac_policy.selinux_enforcing"),
            key="mac_policy.selinux_enforcing",
        )
        return result

    # --- AppArmor active, profile set unreadable ----------------------------
    # The module is loaded, which is a real reading, but the counters below are
    # not: aa-status printed the module line and then failed on the profile set.
    # Reporting "no profiles" from that is a false statement with a point
    # attached — measured on a host carrying 120 enforced profiles.
    if snapshot.apparmor_active and not snapshot.apparmor_profiles_readable:
        result.info(
            message=_t("mac_policy.apparmor_profiles_unreadable"),
            detail=_t("mac_policy.apparmor_profiles_unreadable_detail"),
            key="mac_policy.apparmor_profiles_unreadable",
        )
        return result

    # --- AppArmor active with enforce profiles → OK -------------------------
    if snapshot.apparmor_active and snapshot.apparmor_enforcing > 0:
        result.ok(
            message=_t(
                "mac_policy.apparmor_ok",
                enforcing=snapshot.apparmor_enforcing,
                complain=snapshot.apparmor_complain,
            ),
            key="mac_policy.apparmor_ok",
        )
        if snapshot.apparmor_complain > 0:
            result.info(
                message=_t(
                    "mac_policy.apparmor_complain_profiles",
                    complain=snapshot.apparmor_complain,
                ),
                detail=_t("mac_policy.apparmor_complain_detail"),
                cmd="sudo aa-enforce /etc/apparmor.d/*",
                cmd_type="fix",
                key="mac_policy.apparmor_complain_profiles",
            )
        if se_mode == "permissive":
            result.info(
                message=_t("mac_policy.selinux_permissive"),
                key="mac_policy.selinux_permissive",
            )
        return result

    # --- AppArmor active but no profile in enforce nor in complain mode ----
    # Distinct case from "no_enforce": there are literally no profiles loaded
    # (typical on stock Kali). Phrasing matters — saying "0 in complain" inside
    # a "no_enforce" message implies complain profiles exist when they don't.
    if (
        snapshot.apparmor_active
        and snapshot.apparmor_enforcing == 0
        and snapshot.apparmor_complain == 0
    ):
        if profile_name == "desktop":
            result.info(
                message=_t("mac_policy.apparmor_no_profiles"),
                detail=_t("mac_policy.apparmor_no_profiles_detail"),
                cmd="sudo apt install apparmor-profiles apparmor-profiles-extra",
                key="mac_policy.apparmor_no_profiles",
            )
        else:
            result.warn_with_deduction(
                key="mac_policy.apparmor_no_profiles",
                message=_t("mac_policy.apparmor_no_profiles"),
                reason=_t("mac_policy.apparmor_no_profiles_reason"),
                points=1,
                detail=_t("mac_policy.apparmor_no_profiles_detail"),
                cmd="sudo apt install apparmor-profiles apparmor-profiles-extra",
                nature="action",
            )
        return result

    # --- AppArmor active but no profiles in enforce mode -------------------
    if snapshot.apparmor_active and snapshot.apparmor_enforcing == 0:
        if profile_name == "desktop":
            result.info(
                message=_t(
                    "mac_policy.apparmor_no_enforce",
                    complain=snapshot.apparmor_complain,
                ),
                detail=_t("mac_policy.apparmor_no_enforce_detail"),
                cmd="sudo aa-enforce /etc/apparmor.d/*",
                key="mac_policy.apparmor_no_enforce",
            )
        else:
            result.warn_with_deduction(
                key="mac_policy.apparmor_no_enforce",
                message=_t(
                    "mac_policy.apparmor_no_enforce",
                    complain=snapshot.apparmor_complain,
                ),
                reason=_t("mac_policy.apparmor_no_enforce_reason"),
                points=1,
                detail=_t("mac_policy.apparmor_no_enforce_detail"),
                cmd="sudo aa-enforce /etc/apparmor.d/*",
                nature="improvement",
            )
        return result

    # --- AppArmor installed but service not responding ----------------------
    if snapshot.apparmor_installed and not snapshot.apparmor_active:
        result.warn_with_deduction(
            key="mac_policy.apparmor_inactive",
            message=_t("mac_policy.apparmor_inactive"),
            reason=_t("mac_policy.apparmor_inactive_reason"),
            points=1,
            detail=_t("mac_policy.apparmor_inactive_detail"),
            cmd="sudo systemctl enable --now apparmor",
            nature="action",
        )
        return result

    # --- SELinux permissive (no AppArmor) -----------------------------------
    if se_mode == "permissive":
        result.info(
            message=_t("mac_policy.selinux_permissive"),
            detail=_t("mac_policy.selinux_permissive_detail"),
            key="mac_policy.selinux_permissive",
        )
        result.warn_with_deduction(
            key="mac_policy.no_enforce",
            message=_t("mac_policy.no_enforce"),
            reason=_t("mac_policy.no_enforce_reason"),
            points=1,
            detail=_t("mac_policy.no_enforce_detail"),
            cmd="sudo setenforce 1",
            nature="improvement",
        )
        return result

    # --- SELinux installed but explicitly disabled ---------------------------
    if snapshot.selinux_installed and se_mode == "disabled":
        result.warn_with_deduction(
            key="mac_policy.selinux_disabled",
            message=_t("mac_policy.selinux_disabled"),
            reason=_t("mac_policy.selinux_disabled_reason"),
            points=1,
            detail=_t("mac_policy.selinux_disabled_detail"),
            cmd="sudo setenforce 1",
            nature="action",
        )
        return result

    # --- No MAC framework found ---------------------------------------------
    result.warn_with_deduction(
        key="mac_policy.no_mac",
        message=_t("mac_policy.no_mac"),
        reason=_t("mac_policy.no_mac_reason"),
        points=1,
        detail=_t("mac_policy.no_mac_detail"),
        cmd="sudo apt install apparmor apparmor-utils && sudo systemctl enable --now apparmor",
        nature="action",
    )
    return result


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _parse_aa_count(aa_output: str, mode: str) -> int:
    """
    Extract the profile count for a given mode from ``aa-status`` output.

    Matches lines like: "   104 profiles are in enforce mode."
    """
    for m in _AA_COUNT_RE.finditer(aa_output):
        if m.group(2).lower().startswith(mode.lower()):
            try:
                return int(m.group(1))
            except ValueError:
                return 0
    return 0
