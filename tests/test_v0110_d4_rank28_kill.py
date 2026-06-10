"""v0.11.0 — D-4 Rank 2-8 KILL pin.

v0.10.0 shipped ``SUBCHECK_RENAMES_V100`` as a foundation for a planned
8-rank D-4 split. Only Rank 1 (``ssh.x11_forwarding`` → server/client)
was ever implemented (v0.10.1). Ranks 2-8 were inert: their canonical
patterns were emitted by nothing, so the shim entries never fired —
the still-live monolithic keys were covered by the plain exact-match
path. With zero user signal across 5+ majors (kill-dormant rule, cf.
v0.8.4 compare-breakdown-diff), v0.11.0 removed the 13 dead entries.

This module pins that the kill happened and stays clean: only Rank 1
survives, the killed keys are absent, and the killed legacy keys are
still the LIVE emitted keys (proving the removal was behaviour-
preserving — nothing emitted the canonical patterns the dead entries
mapped to).
"""

from __future__ import annotations

import pathlib

import pytest

from bob._v100_subcheck_renames import (
    SUBCHECK_RENAMES_V100,
    any_legacy_ignore_matches,
    matches_legacy_ignore,
)


_BOB_ROOT = pathlib.Path(__file__).resolve().parent.parent / "bob"

# The 13 legacy keys removed from the shim in v0.11.0.
_KILLED_LEGACY_KEYS = [
    "ssh.host_key_dsa",
    "ssh.dsa_key",
    "ssh.authorized_keys_dsa",
    "ssh.known_hosts_deprecated",
    "auditd.missing_sensitive_rules",
    "samba.guest_writable",
    "samba.guest_readonly",
    "log_rotation.journald_volatile",
    "firewall_rules.duplicate_found",
    "kernel_modules.risky_fs",
    "kernel_modules.risky_net",
    "ssh.weak_ciphers",
    "ssh.weak_macs",
    "ssh.weak_kex",
]


class TestRank1Survives:
    def test_only_rank1_entry_remains(self):
        assert SUBCHECK_RENAMES_V100 == {"ssh.x11_forwarding": "ssh.x11.forwarding.*"}

    def test_rank1_shim_still_works(self):
        assert matches_legacy_ignore("ssh.x11.forwarding.server", "ssh.x11_forwarding")
        assert matches_legacy_ignore("ssh.x11.forwarding.client", "ssh.x11_forwarding")


class TestRank28Killed:
    @pytest.mark.parametrize("legacy_key", _KILLED_LEGACY_KEYS)
    def test_killed_legacy_key_absent_from_shim(self, legacy_key: str):
        assert legacy_key not in SUBCHECK_RENAMES_V100

    @pytest.mark.parametrize("legacy_key", _KILLED_LEGACY_KEYS)
    def test_killed_legacy_key_no_longer_matches_anything(self, legacy_key: str):
        """After the kill, a (hypothetical) ignore.yml entry with a killed
        legacy key resolves to no shim match — it falls back to the plain
        exact-match path, which is correct because the key is still live."""
        assert not any_legacy_ignore_matches("anything.at.all", {legacy_key})


class TestKillIsBehaviourPreserving:
    """The killed ranks were never split — their legacy keys are still the
    LIVE emitted keys, so removing the inert shim entries changes nothing.
    Spot-check a representative sample is still emitted by production code."""

    @pytest.mark.parametrize(
        ("legacy_key", "module"),
        [
            ("ssh.weak_ciphers", "checks/ssh/_subchecks.py"),
            ("ssh.host_key_dsa", "checks/ssh/_subchecks.py"),
            ("auditd.missing_sensitive_rules", "checks/auditd.py"),
            ("samba.guest_writable", "checks/samba.py"),
            ("log_rotation.journald_volatile", "checks/log_rotation.py"),
            ("firewall_rules.duplicate_found", "checks/firewall.py"),
            ("kernel_modules.risky_fs", "checks/kernel_modules.py"),
        ],
    )
    def test_killed_key_is_still_live_in_emit_site(self, legacy_key: str, module: str):
        src = (_BOB_ROOT / module).read_text(encoding="utf-8")
        assert legacy_key in src, (
            f"{legacy_key!r} should still be a live emitted key in {module} "
            "(the Rank was never actually split — that's WHY the shim entry "
            "was inert and safe to kill)"
        )
