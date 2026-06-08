"""v0.9.0 D-1 section renames — shared map.

Single source of truth for the seven section name renames shipped in
v0.9.0 D-1. Used by:

  - ``bob.runner.validate_check_filters`` — emits the fatal migration
    error path when a user passes a legacy ``--check`` / ``--skip``
    token (e.g. ``cron_audit`` → ``cron``).

  - ``bob.compare.load_baseline`` (v0.9.2) — remaps the
    ``AuditBaseline.finding_keys`` list at load time so a baseline
    written by v0.7.x / v0.8.x (carrying the legacy prefixes
    ``iptables_nft.*``, ``cron_audit.*``, …) compares cleanly against
    a v0.9.0+ audit (emitting the canonical prefixes
    ``firewall_iptables.*``, ``cron.*``, …). Without the shim, the
    same physical issue surfaces as both *resolved* (old key) and
    *new* (new key) on the first audit post-upgrade — see the v0.9.1
    CHANGELOG entry for the field-test repro on Ubuntu 26.04.

Pre-v0.9.2 the dict lived inline in ``bob/runner.py``; v0.9.2
extracted it to break the circular import that would have arisen if
``bob/compare.py`` had tried to ``from bob.runner import ...`` (runner
already imports from compare).

The dict is read-only — neither ``runner`` nor ``compare`` mutates
it. Future renames append entries here and ``test_v092_renames_shared``
catches drift between the call sites.
"""
from __future__ import annotations


# Legacy → canonical map for section names renamed in v0.9.0 D-1.
# Migration table mirrors CHANGELOG.md v0.9.0 entry.
SECTION_RENAMES_V090: dict[str, str] = {
    "cron_audit":      "cron",
    "docker_audit":    "docker_hardening",
    "services_state":  "services_health",
    "ports_analysis":  "ports",
    "rules":           "firewall_rules",
    "iptables_nft":    "firewall_iptables",
    "firewall_stack":  "firewall_drivers",
}


def remap_finding_key(key: str) -> str:
    """Return *key* with its prefix remapped via SECTION_RENAMES_V090.

    Pre-v0.9.0 finding keys carry the legacy section prefixes
    (``iptables_nft.input_accept``, ``cron_audit.pipe_to_shell``, …);
    v0.9.0+ checks emit the canonical prefixes
    (``firewall_iptables.input_accept``, ``cron.pipe_to_shell``, …).
    The shim returns the canonical form so a baseline written by an
    older version compares cleanly against a current audit.

    Keys with no rename prefix pass through unchanged. Keys without
    a ``"."`` separator pass through unchanged (sentinel / synthetic
    keys like ``risk.escalated_posture`` already use canonical names
    and never match a legacy prefix).
    """
    if "." not in key:
        return key
    prefix, _, suffix = key.partition(".")
    new_prefix = SECTION_RENAMES_V090.get(prefix)
    if new_prefix is None:
        return key
    return f"{new_prefix}.{suffix}"
