"""v0.10.0 D-4 sub-check renames — shared map + ignore.yml back-compat shim.

v0.10.0 D-4 split eight previously-monolithic finding keys into more
granular sub-keys to express orthogonal concerns separately. The full
migration table is documented in ``DOCUMENTS/CHANGELOG_FULL.md`` v0.10.0
entry; this module holds the legacy → canonical mapping and the helper
that ``ScoreEngine`` consults at runtime to keep pre-v0.10.0
``ignore.yml`` entries working without forcing operators to migrate
every customisation by hand.

Shape vs v0.9.2 (``bob/_v090_renames.py``):

  - **v0.9.2 D-1** mapped section *prefixes* (``cron_audit`` → ``cron``).
    A 1-to-1 string substitution sufficed because every legacy key
    ``cron_audit.X`` had exactly one canonical form ``cron.X``.

  - **v0.10.0 D-4** maps legacy *finding keys* (``ssh.x11_forwarding``)
    to canonical sub-key *patterns* (``ssh.x11.forwarding.*``). Some
    splits are 1-to-1 (Rank 2 DSA family), some are 1-to-N (Rank 1, 3,
    5, 6), and some are 1-to-many-with-runtime-discovery (Rank 4, 7, 8
    — samba shares per name, kernel modules per name, SSH algorithms
    per algo). ``fnmatch`` glob semantics cover all three cases via a
    single uniform contract.

Design choices:

  - The map value is always a single string. 1-to-1 renames use the
    exact target name (``ssh.host_key_dsa`` → ``ssh.dsa.host_key``).
    1-to-N splits use a glob that matches any of the canonical
    siblings (``ssh.x11_forwarding`` → ``ssh.x11.forwarding.*``). The
    wildcard form also naturally handles the runtime-discovered cases
    (per-share, per-module, per-algo) without listing every instance.

  - The runtime helper ``matches_legacy_ignore(finding_key, entry)``
    returns True iff ``entry`` is a legacy key whose pattern matches
    ``finding_key`` via ``fnmatch.fnmatch``. ``ScoreEngine.apply``
    consults this in addition to the existing exact-match
    ``finding.key in self.ignore_keys`` so a v0.9.x ``ignore.yml`` with
    ``ssh.x11_forwarding`` continues to suppress both
    ``ssh.x11.forwarding.server`` and ``ssh.x11.forwarding.client``.

  - Operators who have already migrated their ``ignore.yml`` to the
    canonical sub-keys see no change in behaviour. The legacy-match
    path is a strict superset of the exact-match path.

  - This shim is ignore.yml-only. The baseline diff for D-4 keys (the
    v0.9.2-style ``finding_keys`` migration in
    ``bob/compare.py::load_baseline``) deliberately does NOT remap
    1-to-N splits — there is no defensible way to expand "one legacy
    observation" into "N canonical observations" without inventing
    information that was never recorded. The first audit post-D-4
    will surface "1 resolved + N new" for the same physical issue;
    the next audit self-heals as the baseline is rewritten in
    canonical form. This behaviour is documented in the v0.10.0
    CHANGELOG migration notes.
"""
from __future__ import annotations

import fnmatch


# Legacy finding key → canonical sub-key pattern (fnmatch glob).
#
# 1-to-1 renames use the exact target as the value (no wildcard).
# 1-to-N splits use a wildcard glob that covers every canonical sibling.
# Migration table mirrors the v0.10.0 CHANGELOG D-4 entry.
SUBCHECK_RENAMES_V100: dict[str, str] = {
    # Rank 1 — server/client split (new client detection)
    "ssh.x11_forwarding": "ssh.x11.forwarding.*",

    # Rank 2 — DSA family unification (4 × 1-to-1 simple renames)
    "ssh.host_key_dsa":           "ssh.dsa.host_key",
    "ssh.dsa_key":                "ssh.dsa.private_key",
    "ssh.authorized_keys_dsa":    "ssh.dsa.authorized_key",
    "ssh.known_hosts_deprecated": "ssh.dsa.known_host",

    # Rank 3 — auditd missing rules per sensitive-file bucket
    "auditd.missing_sensitive_rules": "auditd.missing.*",

    # Rank 4 — samba shares per share-name (wildcard required for runtime discovery)
    "samba.guest_writable": "samba.share.guest_writable.*",
    "samba.guest_readonly": "samba.share.guest_readonly.*",

    # Rank 5 — journald storage volatile vs unknown
    "log_rotation.journald_volatile": "log_rotation.journald.*",

    # Rank 6 — firewall duplicate detection algorithms
    "firewall_rules.duplicate_found": "firewall_rules.duplicate.*",

    # Rank 7 — kernel risky modules per module-name
    "kernel_modules.risky_fs":  "kernel_modules.risky.*",
    "kernel_modules.risky_net": "kernel_modules.risky.*",

    # Rank 8 — SSH weak crypto per algorithm
    "ssh.weak_ciphers": "ssh.weak.cipher.*",
    "ssh.weak_macs":    "ssh.weak.mac.*",
    "ssh.weak_kex":     "ssh.weak.kex.*",
}


def matches_legacy_ignore(finding_key: str, ignore_entry: str) -> bool:
    """Return True if a pre-v0.10.0 ``ignore_entry`` covers ``finding_key``.

    Used by ``ScoreEngine.apply`` to keep v0.9.x ignore.yml entries
    working after D-4 split. The exact-match path
    (``finding_key in ignore_keys``) handles operators who already
    migrated to canonical sub-keys; this helper covers the back-compat
    case where the ignore entry is the legacy umbrella name.

    Examples:
        matches_legacy_ignore("ssh.x11.forwarding.server",
                              "ssh.x11_forwarding")            == True
        matches_legacy_ignore("ssh.x11.forwarding.client",
                              "ssh.x11_forwarding")            == True
        matches_legacy_ignore("ssh.dsa.host_key",
                              "ssh.host_key_dsa")              == True
        matches_legacy_ignore("samba.share.guest_writable.public",
                              "samba.guest_writable")          == True
        matches_legacy_ignore("ssh.password_auth",
                              "ssh.x11_forwarding")            == False
        matches_legacy_ignore("ssh.x11.forwarding.server",
                              "ssh.password_auth")             == False
        matches_legacy_ignore("any.key",
                              "not_a_legacy_entry")            == False
    """
    pattern = SUBCHECK_RENAMES_V100.get(ignore_entry)
    if pattern is None:
        return False
    return fnmatch.fnmatch(finding_key, pattern)


def any_legacy_ignore_matches(finding_key: str, ignore_keys: "frozenset[str] | set[str]") -> bool:
    """Return True if ANY entry in ``ignore_keys`` covers ``finding_key``
    via the v0.10.0 D-4 legacy map.

    Convenience wrapper to keep the ``ScoreEngine.apply`` call site tight.
    Returns False on empty ``ignore_keys`` without computing the legacy
    map intersection — the hot-path cost is one truthiness check.
    """
    if not ignore_keys:
        return False
    for entry in ignore_keys:
        if matches_legacy_ignore(finding_key, entry):
            return True
    return False
