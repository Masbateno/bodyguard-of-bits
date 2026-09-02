"""
EXPLAIN_KEYS canonical naming convention guard.

Pins the v0.7.0 canonical convention (Sub-scope C-4 of Phase 2 T2 schema v2):

  Pattern    : ``<prefix>.<finding_id>``
  Prefix     : snake_case identifier (alpha + underscore + digits)
  Finding ID : snake_case identifier
  Exception  : ``file_perms.<path>.<finding_id>`` allows path-segment middles
               (resolved by ``bob.explain.normalize_key``)

Adding a key that breaks this pattern fails one of the tests below. The
intent is to keep the EXPLAIN_KEYS contract (and its mirror in JSON
``deductions[].key`` / ``findings[].key``) predictable for clients writing
matchers against it.

The audit performed in v0.7.0 Step 5 of Phase 2 confirmed:
  - 117 keys, 100% conforming
  - 30 distinct prefixes
  - 0 orphan keys (all referenced in bob/ as string literals)
  - 0 candidates for D-3 retirement in v0.8.0

This file documents the rules so that any FUTURE addition that deviates
surfaces immediately in CI rather than slipping into a release.
"""

from __future__ import annotations

import re

import pytest

from bob.explain import (
    EXPLAIN_KEY_ALIASES,
    EXPLAIN_KEYS,
    normalize_key,
)


# Single-dot canonical form: <prefix>.<finding_id>
_SINGLE_DOT_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")

# Multi-segment file_perms exception: file_perms.<path...>.<finding_id>
_FILE_PERMS_MULTI_RE = re.compile(
    r"^file_perms\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"
)

# Multi-segment services exception (v0.8.0 drift batch): the services check
# uses a two-tier taxonomy `services.<category>.<finding_id>` where
# <category> ∈ {exposure, state} groups findings about port exposure vs.
# systemd unit state. Renaming to flat form would break the wire-format
# JSON output and the existing locale namespace structure.
_SERVICES_MULTI_RE = re.compile(
    r"^services\.(exposure|state)\.[a-z][a-z0-9_]*$"
)

# v0.10.1 D-4 Rank 1 exception: ``ssh.x11_forwarding`` was split into
# ``ssh.x11.forwarding.{server,client}`` to express server vs client side
# as orthogonal sub-keys. The legacy single-dot form is kept as an
# EXPLAIN_KEY_ALIASES entry so old --explain calls and old ignore.yml
# files keep working. Future D-4 ranks may need to extend this exception
# pattern when they ship.
_SSH_X11_FORWARDING_RE = re.compile(
    r"^ssh\.x11\.forwarding\.(server|client)$"
)


# v0.15.4 exception: the plugin sandbox emits ``plugin.sandbox.<reason>``.
# The ``sandbox`` segment is not decoration — it namespaces failures of the
# plugin *runner* against any future ``plugin.<other>`` family, and the keys
# were already emitted in this shape before they became explainable. Renaming
# them would break ignore.yml entries and the wire-format JSON.
_PLUGIN_SANDBOX_RE = re.compile(
    r"^plugin\.sandbox\.[a-z][a-z0-9_]*$"
)


def _is_canonical(key: str) -> bool:
    """Single-dot, file_perms multi-segment, services category, or
    v0.10.1 ssh.x11.forwarding sub-check exception."""
    return bool(
        _SINGLE_DOT_RE.match(key)
        or _FILE_PERMS_MULTI_RE.match(key)
        or _SERVICES_MULTI_RE.match(key)
        or _SSH_X11_FORWARDING_RE.match(key)
        or _PLUGIN_SANDBOX_RE.match(key)
    )


class TestExplainKeysCanonicalFormat:
    """All keys follow ``<prefix>.<finding_id>`` snake_case."""

    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_key_matches_canonical_pattern(self, key):
        assert _is_canonical(key), (
            f"Key {key!r} does not match canonical pattern "
            f"'<prefix>.<finding_id>' (snake_case). "
            f"Allowed exception: 'file_perms.<path>.<finding_id>'."
        )

    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_key_is_lowercase(self, key):
        assert key == key.lower(), (
            f"Key {key!r} must be lowercase. Mixed case is not allowed."
        )

    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_key_has_no_double_underscore(self, key):
        assert "__" not in key, (
            f"Key {key!r} has double underscore; use single underscore segments."
        )

    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_key_has_no_hyphen(self, key):
        assert "-" not in key, (
            f"Key {key!r} has hyphen; use snake_case (underscore)."
        )

    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_key_has_no_leading_digit_in_segments(self, key):
        for seg in key.split("."):
            assert seg and not seg[0].isdigit(), (
                f"Segment {seg!r} in key {key!r} starts with a digit. "
                f"Each segment must begin with a letter."
            )


class TestExplainKeysUnique:
    """No duplicate entries in the flat list."""

    def test_no_duplicate_keys(self):
        duplicates = {k for k in EXPLAIN_KEYS if EXPLAIN_KEYS.count(k) > 1}
        assert not duplicates, (
            f"Duplicate keys in EXPLAIN_KEYS: {duplicates}. "
            f"Each key appears at most once per group."
        )

    def test_aliases_do_not_collide_with_canonical(self):
        """An alias must NEVER map to itself or to a key that's already canonical."""
        for old, new in EXPLAIN_KEY_ALIASES.items():
            assert old != new, (
                f"Alias {old!r} → {new!r} maps to itself — broken entry."
            )
            assert old not in EXPLAIN_KEYS, (
                f"Alias source {old!r} appears as a canonical key. "
                f"Aliases must point AWAY from the canonical list."
            )


class TestExplainPrefixDiscipline:
    """Prefix vocabulary is finite and reflects the audit sections."""

    # The known set of prefixes. v0.7.0 audit baseline = 30 ; v0.8.0
    # drift batch added the 15 prefixes whose WARN/ALERT findings were
    # silently uncovered by --explain pre-backfill (see DOCUMENTS/SNAPSHOT
    # and tests/test_explain_coverage.py for the backfill rationale).
    # New additions to this set require explicit thought — DO NOT silently
    # widen by adding here without updating the EXPLAIN_KEYS audit in
    # DOCUMENTS/README_TECH.md.
    KNOWN_PREFIXES = frozenset({
        "plugin",           # v0.15.4 — plugin.sandbox.* runner failures
        # v0.7.0 baseline (30)
        "ssh", "clamav", "samba", "file_perms", "updates", "hardening",
        "kernel_modules", "firewall_rules", "ipv6", "password_policy",
        "user_accounts", "cron", "services_health", "disk", "memory",
        "auditd", "secure_boot", "file_integrity", "virt", "auth_log",
        "umask", "prerequisites", "firewall", "ssl_certs",
        "systemd_timers", "firmware", "docker_hardening", "kernel_hardening",
        "suid_audit", "risk",
        # v0.8.0 drift batch additions (15)
        "firewall_iptables", "mac_policy", "firewall_drivers", "docker",
        "services", "rootkit", "ports", "ntp", "fail2ban", "ddns",
        "log_rotation", "logs", "smtp", "backup", "network_context",
    })

    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_key_prefix_is_known(self, key):
        prefix = key.split(".", 1)[0]
        assert prefix in self.KNOWN_PREFIXES, (
            f"Key {key!r} uses unknown prefix {prefix!r}. "
            f"If this prefix is intentional, add it to "
            f"TestExplainPrefixDiscipline.KNOWN_PREFIXES and document "
            f"in DOCUMENTS/README_TECH.md → EXPLAIN_KEYS audit."
        )

    def test_no_unused_prefix_in_known_set(self):
        """KNOWN_PREFIXES must not drift away from actual usage either."""
        used = {k.split(".", 1)[0] for k in EXPLAIN_KEYS}
        unused = self.KNOWN_PREFIXES - used
        assert not unused, (
            f"Prefixes declared in KNOWN_PREFIXES but no longer used by any "
            f"key in EXPLAIN_KEYS: {unused}. Remove them from KNOWN_PREFIXES "
            f"to keep the invariant tight."
        )


class TestFilePermsMultiSegmentNormalisation:
    """The single multi-segment exception is handled by normalize_key."""

    def test_normalize_strips_middle_path_segments(self):
        # Real example from production checks/file_perms.py
        assert normalize_key("file_perms.shadow.world_writable") == "file_perms.world_writable"
        assert normalize_key("file_perms.a.b.c.world_writable") == "file_perms.world_writable"

    def test_normalize_preserves_canonical_keys(self):
        for key in EXPLAIN_KEYS:
            # Canonical keys map to themselves
            assert normalize_key(key) == key, (
                f"Canonical key {key!r} normalised to {normalize_key(key)!r} — "
                f"normalize_key should be idempotent on canonical keys."
            )

    def test_normalize_resolves_aliases(self):
        for old, new in EXPLAIN_KEY_ALIASES.items():
            assert normalize_key(old) == new, (
                f"Alias {old!r} did not resolve to {new!r} (got {normalize_key(old)!r})."
            )


class TestExplainAuditInvariants:
    """Top-level expectations from the v0.7.0 Step 5 audit, pinned as
    regression guards."""

    def test_total_keys_match_audit_count(self):
        """v0.7.0 baseline = 117. v0.8.0 drift batch backfilled 51 missing
        WARN/ALERT findings → 168, then 169. v0.15.4 added the 12
        plugin.sandbox.* entries → 181: they were the last WARN keys a user
        could meet in a report and not look up. Drifts beyond require a doc
        update in DOCUMENTS/README_TECH.md → EXPLAIN_KEYS audit."""
        assert len(EXPLAIN_KEYS) == 181, (
            f"EXPLAIN_KEYS length drifted from the v0.8.0 baseline 168 "
            f"to {len(EXPLAIN_KEYS)}. If intentional, update the audit "
            f"document and bump the constant in this test."
        )

    def test_prefix_count_does_not_drift_silently(self):
        """v0.7.0 baseline = 30 distinct prefixes ; v0.8.0 drift batch
        added 15 (iptables_nft, mac_policy, firewall_stack, docker, services,
        rootkit, ports, ntp, fail2ban, ddns, log_rotation, logs, smtp,
        backup, network_context) → 45. Further drift requires updating
        KNOWN_PREFIXES + the audit doc."""
        prefixes = {k.split(".", 1)[0] for k in EXPLAIN_KEYS}
        assert len(prefixes) == 46, (
            f"Prefix count drifted from v0.8.0 baseline 45 to "
            f"{len(prefixes)}. Update KNOWN_PREFIXES + audit doc."
        )
