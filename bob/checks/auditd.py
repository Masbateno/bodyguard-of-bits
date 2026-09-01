"""
Linux Audit Framework check for BOB (CHECK 31).

Checks whether auditd is installed, its service is running, and audit rules
are configured for sensitive system files (/etc/passwd, /etc/shadow,
/etc/sudoers).  Without these rules, privilege escalation and credential
dumping go unlogged.

Score impact:
  - Not installed:                    INFO  (no deduction — optional but recommended)
  - Installed, service down:          WARN  −1 pt
  - Running but no rules at all:      WARN  −1 pt
  - Running, rules missing key files: WARN  −1 pt  (server) / INFO (desktop)
  - Running with all key files watched: OK

Split into:
  1. AuditdSnapshot.from_system() — collects state via auditctl / systemctl.
  2. check_auditd(snapshot, t)    — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Set

from bob.checks._run import (
    TranslationFunc,
    _command_exists,
    _identity_t,
    _run,
    run_result,
    unit_active_state,
)
from bob.scoring import CheckResult

# Files we consider essential to watch
_SENSITIVE_FILES = frozenset({
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
})


# auditctl's own wording for a subsystem that is switched off. Matched rather
# than rendered: stderr is untrusted subprocess text like any other.
_AUDIT_DISABLED_RE = re.compile(r"audit system is disabled", re.IGNORECASE)


@dataclass
class AuditdSnapshot:
    """
    State collected from the system about auditd.

    Args:
        installed:        True if auditctl is present on the system.
        service_active:   True if the auditd service is running.
        watched_files:    Set of file paths covered by -w watch rules.
        rule_count:       Total number of audit rules loaded.
        rules_readable:   False when `auditctl -l` could not be queried.
        audit_disabled:   True when auditctl says the subsystem is switched
                          off. Distinct from unreadable: the operator's own
                          choice, not a gap in what BOB could see.
    """
    installed:      bool        = False
    service_active: bool        = False
    watched_files:  Set[str]    = field(default_factory=set)
    rule_count:     int         = 0
    # False when `auditctl -l` produced nothing at all, which means the
    # query failed rather than that the rule set is empty.
    rules_readable: bool        = True
    audit_disabled: bool        = False

    @classmethod
    def from_system(cls) -> "AuditdSnapshot":
        """Collect auditd state from the live system. Never raises."""
        snap = cls()

        if not _command_exists("auditctl"):
            return snap

        snap.installed = True

        # Service status via systemctl, falling back to auditd's own answer
        # whenever systemd gives none — a present but failing systemctl used to
        # short-circuit straight to "inactive".
        state = unit_active_state("auditd") if _command_exists("systemctl") else None
        if state is not None:
            snap.service_active = state == "active"
        else:
            # Fallback: auditctl -s shows "enabled 1" when auditd is running
            status = _run("auditctl", "-s") or ""
            snap.service_active = "enabled 1" in status

        if not snap.service_active:
            return snap

        # Load rules.
        #
        # `auditctl -l` prints the literal "No rules" when the audit system is
        # reachable and holds none, so empty output means the *query* failed —
        # measured on this host, where a non-root call exits 4 with nothing on
        # stdout while auditd is running. `_run` discards the exit code, so
        # before v0.15.0 that was indistinguishable from a configured-but-empty
        # rule set and cost the host a point for rules BOB never saw.
        # `auditctl` reports a switched-off audit subsystem on stderr while
        # exiting 0 with an empty stdout, so stdout and the exit status both
        # look like a reachable system holding no rules. Only stderr separates
        # "the operator turned auditing off" from "BOB was refused" — a real
        # distinction, and the first one is not a gap in the audit at all.
        rules = run_result("auditctl", "-l")
        rules_out = rules.stdout or ""
        snap.audit_disabled = _AUDIT_DISABLED_RE.search(rules.stderr or "") is not None
        snap.rules_readable = bool(rules_out.strip()) or snap.audit_disabled
        snap.watched_files = _parse_watched_files(rules_out)
        snap.rule_count = _count_rules(rules_out)

        return snap


def _parse_watched_files(auditctl_output: str) -> Set[str]:
    """
    Extract file paths from ``auditctl -l`` watch rules (-w lines).

    Example input::

        -w /etc/passwd -p rwxa -k identity
        -w /etc/shadow -p rwxa -k identity
        -a always,exit -F arch=b64 -S execve -k exec

    Returns a set of absolute paths (strings).
    """
    watched: Set[str] = set()
    for line in auditctl_output.splitlines():
        line = line.strip()
        m = re.match(r"-w\s+(\/\S+)", line)
        if m:
            path = m.group(1).rstrip("/")  # normalise trailing slash
            watched.add(path)
    return watched


def _count_rules(auditctl_output: str) -> int:
    """Count actual rule lines in ``auditctl -l`` output.

    Only lines starting with ``-w`` (watch rules) or ``-a``/``-A``
    (syscall rules) are counted — other lines (headers, blank, errors)
    are ignored.
    """
    count = 0
    for line in auditctl_output.splitlines():
        line = line.strip()
        if line.startswith(("-w ", "-a ", "-A ")):
            count += 1
    return count


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_auditd(snapshot: AuditdSnapshot, t: TranslationFunc | None = None,
                 profile_name: str = "server") -> CheckResult:
    """
    Analyse AuditdSnapshot and return findings.

    Findings:
      - Not installed:                   INFO  (no deduction)
      - Service not running:             WARN  −1 pt
      - Running, no rules loaded:        WARN  −1 pt (server) / INFO (desktop)
      - Running, sensitive files missing from rules:
            WARN −1 pt on server ; INFO on desktop (profile_name in desktop/workstation)
      - Running with all sensitive files watched: OK
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()
    is_desktop = profile_name.lower() in ("desktop", "workstation")

    if not snapshot.installed:
        result.info(
            message=_t("auditd.not_installed"),
            detail=_t("auditd.not_installed_detail"),
            cmd="sudo apt install auditd audispd-plugins",
            key="auditd.not_installed",
        )
        return result

    if not snapshot.service_active:
        result.warn_with_deduction(
            key="auditd.service_inactive",
            message=_t("auditd.service_inactive"),
            reason=_t("auditd.service_inactive_reason"),
            points=1,
            detail=_t("auditd.service_inactive_detail"),
            cmd="sudo systemctl enable --now auditd",
            nature="improvement",
        )
        return result

    if snapshot.audit_disabled:
        result.info(
            message=_t("auditd.subsystem_disabled"),
            detail=_t("auditd.subsystem_disabled_detail"),
            key="auditd.subsystem_disabled",
        )
    elif not snapshot.rules_readable:
        # The query failed; the rule set is unknown, not empty. Reporting it as
        # empty cost a point for rules that were never read — and the
        # sensitive-file coverage below is derived from the same empty output,
        # so it has to stop here too rather than deduct a second point for
        # watches it could not see either.
        result.info(
            message=_t("auditd.rules_unreadable"),
            detail=_t("auditd.rules_unreadable_detail"),
            key="auditd.rules_unreadable",
        )
        return result

    if snapshot.rule_count == 0:
        _no_rules_cmd = (
            "sudo tee /etc/audit/rules.d/hardening.rules << 'EOF'\n"
            "-w /etc/passwd -p wa -k identity\n"
            "-w /etc/shadow -p wa -k identity\n"
            "-w /etc/sudoers -p wa -k privilege\n"
            "-w /etc/sudoers.d/ -p wa -k privilege\n"
            "-w /var/log/auth.log -p wa -k auth\n"
            "EOF\n"
            "sudo augenrules --load"
        )
        if is_desktop:
            result.info(
                message=_t("auditd.no_rules"),
                detail=_t("auditd.no_rules_detail"),
                cmd=_no_rules_cmd,
                cmd_type="fix",
                key="auditd.no_rules",
            )
        else:
            result.warn_with_deduction(
                key="auditd.no_rules",
                message=_t("auditd.no_rules"),
                reason=_t("auditd.no_rules_reason"),
                points=1,
                detail=_t("auditd.no_rules_detail"),
                cmd=_no_rules_cmd,
                nature="improvement",
            )
        return result

    # Check for sensitive file coverage
    missing = sorted(_SENSITIVE_FILES - snapshot.watched_files)
    if missing:
        missing_str = ", ".join(missing)
        if is_desktop:
            result.info(
                message=_t("auditd.missing_sensitive_rules"),
                detail=_t("auditd.missing_sensitive_rules_detail", files=missing_str),
                cmd=_suggest_rules_cmd(missing),
                key="auditd.missing_sensitive_rules",
            )
        else:
            result.warn_with_deduction(
                key="auditd.missing_sensitive_rules",
                message=_t("auditd.missing_sensitive_rules"),
                reason=_t("auditd.missing_sensitive_rules_reason", files=missing_str),
                points=1,
                detail=_t("auditd.missing_sensitive_rules_detail", files=missing_str),
                cmd=_suggest_rules_cmd(missing),
                nature="improvement",
            )
        return result

    # All sensitive files covered
    result.ok(
        message=_t("auditd.active", count=snapshot.rule_count),
        key="auditd.active",
    )
    result.ok(
        message=_t("auditd.sensitive_files_watched"),
        key="auditd.sensitive_files_watched",
    )
    return result


def _suggest_rules_cmd(missing_files: list[str]) -> str:
    """Build a persistent audit rules command for the missing files.

    Appends rules to /etc/audit/rules.d/99-sensitive.rules (survives reboot)
    and reloads via augenrules.
    """
    parts = [
        f"echo '-w {f} -p rwxa -k sensitive_files'"
        f" | sudo tee -a /etc/audit/rules.d/99-sensitive.rules"
        for f in missing_files
    ]
    return " && ".join(parts) + " && sudo augenrules --load"
