"""v0.16.0 finding-key renames — shared map.

``logs.brute_found`` named an authentication attack from evidence that cannot
carry one. A UFW BLOCK is a packet the firewall discarded: it never reached a
service, so no credential was ever offered, and repeated credential guessing
cannot be read from dropped packets. v0.15.5 fixed everything the operator
*sees* — the message states the measurement, local and UDP sources are reported
without a deduction — but deliberately left the key alone, because renaming it
breaks baselines, ``ignore.yml`` and ``--explain``, and those belong in a
planned bundle rather than a patch. This is that bundle.

The new name joins its two siblings from the same fix, so the family reads as
one: ``logs.blocked_repeat_local``, ``logs.blocked_repeat_udp``, and now
``logs.blocked_repeat_public`` for the chargeable case — a public address, over
TCP, making more than ten distinct connection attempts in a minute.

Three surfaces keep the old name working, and each fails differently if
forgotten:

  - **baselines** — ``compare.load_baseline`` remaps at load, or the first
    audit after upgrading reports the same physical issue as both *resolved*
    (old key) and *new* (new key). That exact failure was field-reproduced in
    v0.9.1 for the D-1 section renames;
  - **ignore.yml** — ``ScoreEngine.apply`` consults this map, or an operator's
    existing exception silently stops working and a finding they had waived
    comes back;
  - **--explain** — ``EXPLAIN_KEY_ALIASES`` in ``bob/explain.py``, or a script
    that pipes a key from an older report gets exit 3.
"""

from __future__ import annotations

# Legacy → canonical, for finding keys renamed in v0.16.0.
FINDING_RENAMES_V0160: dict[str, str] = {
    "logs.brute_found": "logs.blocked_repeat_public",
}


def remap_finding_key(key: str) -> str:
    """Return the canonical key for ``key``, or ``key`` itself when unmapped.

    Total on purpose: called for every key in a loaded baseline, and an
    unmapped key must pass through untouched rather than raise.
    """
    return FINDING_RENAMES_V0160.get(key, key)


def legacy_ignore_matches(finding_key: str, ignore_keys: "frozenset[str] | set[str]") -> bool:
    """True when a pre-v0.16.0 ignore entry covers ``finding_key``.

    The exact-match path in ``ScoreEngine.apply`` already handles an operator
    who migrated their ignore.yml; this covers the one who has not.
    """
    if not ignore_keys:
        return False
    for legacy, canonical in FINDING_RENAMES_V0160.items():
        if finding_key == canonical and legacy in ignore_keys:
            return True
    return False
