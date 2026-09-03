"""
Findings that mean BOB could not see part of the host.

The score is a sum of deductions over the checks that ran. When a check cannot
read its input, its potential deductions are not zero — they are **unknown**,
and the score computed without them is an upper bound presented as a value.

Reproduced before this module existed: masking ``/etc/ssh/sshd_config`` removes
four deductions and moves the score from 7 to **8**. The audit says so
honestly, in its own section — ``ssh.config_unreadable`` — but the number goes
up, the risk level derived from it goes down, and ``degraded_sections`` stays
empty, because that field is reserved by contract for a section whose check
*raised*. A check that abstains cleanly leaves no trace at all in the machine
output. An operator running BOB without sudo therefore reads a better score
than one running it properly, and nothing in the report contradicts the number.

The set is explicit rather than derived from the key name. Two guards keep it
honest in both directions: nothing here may be a key BOB never emits, and no
newly added ``*_unreadable`` / ``*_unknown`` key may stay out of it.

**Not in this set, deliberately:** ``ssh.config_newer_than_service`` and
``log_rotation.journald_conf_newer_than_service``. Those qualify *what the
findings describe* — a file rather than the running service — but the
deductions themselves were computed and are present. The score is not an upper
bound there; it is a measurement of the wrong object, which is a different
problem with its own finding.
"""

from __future__ import annotations

# Keys whose presence means a check could not fully read its input, so the
# deductions it did not make are unknown rather than absent.
VISIBILITY_KEYS: frozenset[str] = frozenset({
    "auditd.rules_unreadable",
    "auditd.state_unknown",
    "container_security.seccomp_unknown",
    "cron.unreadable_files",
    "disk.smart_unknown",
    "fail2ban.state_unknown",
    "fail2ban.status_unreadable",
    "file_perms.sudoers_unreadable",
    "firewall.logging_unknown",
    "firewall.policy_unknown",
    "firewall_drivers.rules_unreadable",
    "firewall_iptables.forward_unknown",
    "firewall_iptables.input_unknown",
    "firewall_iptables.ruleset_unreadable",
    "firmware.microcode_unknown",
    "ipv6.kernel_state_unknown",
    "ipv6.listeners_unknown",
    "ipv6.ufw_config_unreadable",
    "log_rotation.journald_conf_unreadable",
    "log_rotation.logrotate_dir_unreadable",
    "mac_policy.apparmor_profiles_unreadable",
    "memory.swappiness_unknown",
    "plugin.sandbox.unreadable",
    "ports.unreadable",
    "samba.conf_unreadable",
    "secure_boot.unknown",
    "services.state.unknown",
    "ssh.active_unknown",
    "ssh.config_unreadable",
    "suid_audit.ok_partial",
    "systemd_timers.unreadable",
    "umask.sources_unreadable",
})

# Keys that match the naming convention but do not reduce visibility. Kept
# explicit so the guard can tell "not a visibility limit" from "forgotten".
NOT_A_VISIBILITY_LIMIT: frozenset[str] = frozenset()


def section_of(key: str) -> str:
    """The section a finding key belongs to — its first dotted segment."""
    return key.split(".", 1)[0]
