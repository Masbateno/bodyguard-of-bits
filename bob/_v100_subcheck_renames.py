"""v0.10.0 D-4 sub-check renames — shared map + ignore.yml back-compat shim.

v0.10.0 shipped this shim as a *foundation* for a planned 8-rank D-4
split, mapping legacy monolithic finding keys to canonical sub-key
patterns so pre-split ``ignore.yml`` entries would keep working once
the emit sites were changed. Only **Rank 1** was ever implemented
(``ssh.x11_forwarding`` → ``ssh.x11.forwarding.{server,client}``,
shipped v0.10.1 with the new client-side detection).

**v0.11.0 killed Ranks 2-8.** They were never implemented — the emit
sites still produce the monolithic keys (``ssh.host_key_dsa``,
``ssh.weak_ciphers``, ``auditd.missing_sensitive_rules``, …), so the
shim entries for those ranks were *inert*: the canonical patterns they
mapped to (``ssh.dsa.host_key``, ``ssh.weak.cipher.*``, …) were emitted
by nothing, so ``matches_legacy_ignore`` never fired for them and the
still-live legacy keys were covered by the plain exact-match path. With
zero user signal across 5+ majors that any of those splits were wanted
(the kill-dormant-features rule, cf. the v0.8.4 compare-breakdown-diff
retirement), carrying 13 inert entries was pure dead weight. Removing
them is behaviour-preserving: nothing emitted their canonical patterns,
so no live finding changes suppression state.

If a future release genuinely splits one of those keys, re-add a single
entry here at that time — same one-line pattern as Rank 1.

Shape vs v0.9.2 (``bob/_v090_renames.py``):

  - **v0.9.2 D-1** mapped section *prefixes* (``cron_audit`` → ``cron``).
    A 1-to-1 string substitution sufficed because every legacy key
    ``cron_audit.X`` had exactly one canonical form ``cron.X``.

  - **v0.10.0 D-4 (Rank 1)** maps a legacy *finding key*
    (``ssh.x11_forwarding``) to a canonical sub-key *pattern*
    (``ssh.x11.forwarding.*``). The glob covers the 1-to-N split into
    ``.server`` + ``.client`` via a single uniform contract.

Design choices:

  - The map value is a single string: a glob that matches any canonical
    sibling (``ssh.x11_forwarding`` → ``ssh.x11.forwarding.*``).

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
# v0.11.0: only the Rank 1 entry survives (the only D-4 split ever
# implemented). Ranks 2-8 were inert foundation entries and were killed
# — see the module docstring. Re-add a single line here if a future
# release actually splits one of those keys.
SUBCHECK_RENAMES_V100: dict[str, str] = {
    # Rank 1 — server/client split (new client detection, shipped v0.10.1)
    "ssh.x11_forwarding": "ssh.x11.forwarding.*",
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
