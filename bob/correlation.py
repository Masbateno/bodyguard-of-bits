"""Signal correlation engine for BOB.

Detects compound risk patterns by combining individual finding keys.
Called post-finalize so all findings are committed before evaluation.

Each rule specifies:
  all_of  — every key must be present in active findings
  any_of  — at least one key must be present (empty = not checked)

A rule fires when all_of ⊆ active AND (any_of is empty OR any_of ∩ active ≠ ∅).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from bob.scoring import FindingLevel

if TYPE_CHECKING:
    from bob.scoring import ScoreEngine


@dataclass
class CorrelationRule:
    key: str
    all_of: frozenset[str]
    any_of: frozenset[str]          # empty means "no OR constraint"
    level: FindingLevel
    message_key: str

    def matches(self, active: set[str]) -> bool:
        if not self.all_of.issubset(active):
            return False
        if self.any_of and not self.any_of.intersection(active):
            return False
        return True


@dataclass
class CorrelatedFinding:
    key: str
    level: FindingLevel
    message: str
    triggered_by: list[str] = field(default_factory=list)


_RULES: list[CorrelationRule] = [
    # Root login + no brute-force protection
    CorrelationRule(
        key="corr.root_no_protection",
        all_of=frozenset({"ssh.permit_root_login"}),
        any_of=frozenset({"fail2ban.not_installed", "fail2ban.service_inactive"}),
        level=FindingLevel.ALERT,
        message_key="corr.root_no_protection",
    ),
    # Password auth + active brute-force attacks detected
    CorrelationRule(
        key="corr.password_auth_under_attack",
        all_of=frozenset({"ssh.password_auth", "auth_log.brute_force"}),
        any_of=frozenset(),
        level=FindingLevel.ALERT,
        message_key="corr.password_auth_under_attack",
    ),
    # Root login + password auth → SSH doubly exposed
    CorrelationRule(
        key="corr.ssh_root_password",
        all_of=frozenset({"ssh.permit_root_login", "ssh.password_auth"}),
        any_of=frozenset(),
        level=FindingLevel.ALERT,
        message_key="corr.ssh_root_password",
    ),
    # Passwordless sudo + unexpected SUID
    CorrelationRule(
        key="corr.privilege_escalation",
        all_of=frozenset({"file_perms.sudoers_nopasswd_all", "suid_audit.unexpected_suid"}),
        any_of=frozenset(),
        level=FindingLevel.WARN,
        message_key="corr.privilege_escalation",
    ),
    # Security updates pending + no brute-force detection
    CorrelationRule(
        key="corr.stale_unmonitored",
        all_of=frozenset({"updates.security_pending"}),
        any_of=frozenset({"fail2ban.not_installed", "fail2ban.service_inactive"}),
        level=FindingLevel.WARN,
        message_key="corr.stale_unmonitored",
    ),
    # M-4 (v0.5.5): no audit trail + no firewall logs + no intrusion detection.
    # Pre-v0.5.5 the fail2ban requirement was `not_installed` only, so a host
    # with fail2ban installed-but-stopped (`service_inactive`) silently
    # escaped the rule despite being equally blind. Sibling rule
    # `corr.stale_unmonitored` already accepts both states via any_of —
    # we mirror that here by widening fail2ban to either-or.
    CorrelationRule(
        key="corr.fully_blind",
        all_of=frozenset({"firewall.logging_off"}),
        any_of=frozenset({
            "fail2ban.not_installed", "fail2ban.service_inactive",
            "auditd.not_installed", "auditd.service_inactive",
        }),
        level=FindingLevel.WARN,
        message_key="corr.fully_blind",
    ),
]


def run_correlations(engine: "ScoreEngine", t) -> list[CorrelatedFinding]:
    """
    Evaluate all correlation rules against finalized engine findings.

    Returns a list of CorrelatedFinding for every rule that fires.
    Deduplicates by rule key in case of repeated calls.
    """
    active: set[str] = {
        f.key for f in engine.findings
        if f.key and f.level in (FindingLevel.ALERT, FindingLevel.WARN)
    }

    results: list[CorrelatedFinding] = []

    for rule in _RULES:
        if rule.matches(active):
            triggered = sorted(
                (rule.all_of | (rule.any_of & active))
            )
            results.append(CorrelatedFinding(
                key=rule.key,
                level=rule.level,
                message=t(rule.message_key),
                triggered_by=triggered,
            ))

    return results
