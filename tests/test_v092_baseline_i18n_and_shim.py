"""v0.9.2 — BaselineLoadError i18n + cross-version baseline migration shim.

Two coupled improvements that close UX gaps surfaced by the v0.9.0 field test
campaign (see ``DOCUMENTS/CHANGELOG_FULL.md`` v0.9.1 entry — "Other i18n
gaps observed during the field test campaign"):

1. **BaselineLoadError i18n** — pre-v0.9.2, ``bob.compare.load_baseline``
   raised ``BaselineLoadError`` with hardcoded English messages even on FR
   systems. Unlike the v0.9.0 F-3 issue, these raises happen AFTER
   ``i18n.init()`` (load_baseline is invoked from the audit path, not from
   ``parse_args``), so the lookup CAN be properly i18n'd via the
   ``bob._i18n_safe.t_or_hardcoded`` helper. The hotfix wires four locale
   keys (``compare.baseline_load.{not_found, invalid_json, v1_schema,
   bad_shape}``) into the four raise sites.

2. **Cross-version baseline migration shim** — pre-v0.9.2, a baseline written
   by v0.7.x / v0.8.x carried finding keys with prefixes renamed in v0.9.0
   D-1 (e.g. ``iptables_nft.input_accept``). The v0.9.0+ audit emits the
   canonical prefixes (``firewall_iptables.input_accept``), so the diff
   surfaced the SAME physical issue as both *resolved* (old key) AND
   *new* (new key). v0.9.2 remaps legacy prefixes via
   ``bob._v090_renames.remap_finding_key`` at load time so the comparison
   is clean from the first audit post-upgrade.

Both items are listed in the v0.9.1 CHANGELOG entry as "deferred to v0.10.0+"
— v0.9.2 brings them forward because the work is purely additive (no
BREAKING wire-format change, no risk to the golden audit path) and the field
test campaign already documented the bugs in production-style scenarios.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from bob import i18n
from bob.compare import BaselineLoadError, load_baseline
from bob._v090_renames import (
    SECTION_RENAMES_V090,
    remap_finding_key,
)


# ---------------------------------------------------------------------------
# Shared renames module — single source of truth contract
# ---------------------------------------------------------------------------


class TestV090RenamesSharedModule:
    """The legacy → canonical map must stay in lockstep across consumers.

    Pre-v0.9.2 the dict lived inline in ``bob/runner.py``; v0.9.2 extracted
    it to ``bob/_v090_renames.py`` so ``bob.compare`` can import it without
    forming a circular import. The runner's back-compat re-export under the
    legacy name ``_RENAMED_SECTIONS_V090`` must point at the same dict
    object — any drift surfaces here.
    """

    def test_runner_legacy_alias_points_at_shared_module(self):
        from bob import runner
        assert runner._RENAMED_SECTIONS_V090 is SECTION_RENAMES_V090, (
            "runner._RENAMED_SECTIONS_V090 must be the shared "
            "SECTION_RENAMES_V090 dict (back-compat alias). Drift here "
            "means someone re-introduced a duplicate map."
        )

    def test_seven_entries_match_d1_table(self):
        """The seven D-1 renames documented in the v0.9.0 CHANGELOG."""
        assert SECTION_RENAMES_V090 == {
            "cron_audit":      "cron",
            "docker_audit":    "docker_hardening",
            "services_state":  "services_health",
            "ports_analysis":  "ports",
            "rules":           "firewall_rules",
            "iptables_nft":    "firewall_iptables",
            "firewall_stack":  "firewall_drivers",
        }


# ---------------------------------------------------------------------------
# remap_finding_key — pure transform
# ---------------------------------------------------------------------------


class TestRemapFindingKey:

    @pytest.mark.parametrize("old,new", [
        ("iptables_nft.input_accept",          "firewall_iptables.input_accept"),
        ("iptables_nft.forward_accept",        "firewall_iptables.forward_accept"),
        ("cron_audit.pipe_to_shell",           "cron.pipe_to_shell"),
        ("docker_audit.privileged",            "docker_hardening.privileged"),
        ("services_state.service_inactive",    "services_health.service_inactive"),
        ("rules.duplicate_found",              "firewall_rules.duplicate_found"),
        ("firewall_stack.iptables_bypass",     "firewall_drivers.iptables_bypass"),
        ("ports_analysis.uncovered",           "ports.uncovered"),
    ])
    def test_legacy_prefix_remapped(self, old, new):
        assert remap_finding_key(old) == new

    @pytest.mark.parametrize("k", [
        "ssh.password_auth",
        "hardening.rp_filter_disabled",
        "kernel_hardening.ptrace_unrestricted",
        "services.exposed.ssh",
        "firewall_iptables.input_accept",     # already canonical
        "cron.pipe_to_shell",                 # already canonical
    ])
    def test_canonical_key_passes_through(self, k):
        assert remap_finding_key(k) == k

    @pytest.mark.parametrize("k", [
        "risk.escalated_posture",
        "prerequisites.ufw_missing",
        "no_dot_key",                         # no '.' separator
        "",                                   # empty
    ])
    def test_unaffected_keys_pass_through(self, k):
        assert remap_finding_key(k) == k

    def test_suffix_preserved_verbatim(self):
        """A legacy prefix with an arbitrary suffix (including dots in
        the suffix portion if any sneak in) keeps the suffix verbatim."""
        # The partition is on the FIRST '.', so any further dots in the
        # suffix are preserved.
        assert remap_finding_key("rules.with.extra.dots") == "firewall_rules.with.extra.dots"


# ---------------------------------------------------------------------------
# load_baseline — migration shim wired in
# ---------------------------------------------------------------------------


class TestLoadBaselineMigrationShim:

    def _write_baseline(self, tmp_path, *, finding_keys):
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps({
            "timestamp":       "2026-06-01T00:00:00+00:00",
            "score":           7,
            "alert_count":     0,
            "warn_count":      1,
            "info_count":      0,
            "open_ports":      [],
            "active_services": [],
            "finding_keys":    finding_keys,
            "deduction_total": 1,
        }), encoding="utf-8")
        return p

    def test_v07x_baseline_finding_keys_remapped_to_canonical(self, tmp_path):
        """Real-world repro from the v0.9.0 field test on Ubuntu 26.04:
        a v0.7.0-era baseline carries ``iptables_nft.*`` keys; v0.9.0+
        audits emit ``firewall_iptables.*``. Pre-v0.9.2 the diff would
        surface the same issue as both resolved + new. Post-v0.9.2 the
        load shim remaps before delta computation."""
        p = self._write_baseline(tmp_path, finding_keys=[
            "iptables_nft.input_accept",
            "iptables_nft.forward_accept",
            "ssh.password_auth",          # control: canonical, must pass through
        ])
        b = load_baseline(p, strict=True)
        assert b is not None
        assert set(b.finding_keys) == {
            "firewall_iptables.input_accept",
            "firewall_iptables.forward_accept",
            "ssh.password_auth",
        }

    def test_v08x_baseline_finding_keys_remapped(self, tmp_path):
        """Same shim path for v0.8.x baselines that carry e.g.
        ``cron_audit.*`` or ``docker_audit.*``."""
        p = self._write_baseline(tmp_path, finding_keys=[
            "cron_audit.pipe_to_shell",
            "docker_audit.privileged",
            "services_state.enabled_inactive",
        ])
        b = load_baseline(p, strict=True)
        assert b is not None
        assert set(b.finding_keys) == {
            "cron.pipe_to_shell",
            "docker_hardening.privileged",
            "services_health.enabled_inactive",
        }

    def test_v09x_baseline_passes_through_unchanged(self, tmp_path):
        """Baselines already written by v0.9.0+ use canonical names —
        the shim must be idempotent on canonical input."""
        p = self._write_baseline(tmp_path, finding_keys=[
            "firewall_iptables.input_accept",
            "cron.pipe_to_shell",
            "ssh.password_auth",
        ])
        b = load_baseline(p, strict=True)
        assert b is not None
        assert set(b.finding_keys) == {
            "firewall_iptables.input_accept",
            "cron.pipe_to_shell",
            "ssh.password_auth",
        }

    def test_pre_v122_baseline_with_no_finding_keys(self, tmp_path):
        """A pre-v1.22 baseline (no ``finding_keys`` field at all) loads
        with ``finding_keys=None`` — the shim must not crash on the
        absent field."""
        p = tmp_path / "old.json"
        p.write_text(json.dumps({
            "timestamp":       "2026-06-01T00:00:00+00:00",
            "score":           7,
            "alert_count":     0,
            "warn_count":      1,
            "info_count":      0,
            "open_ports":      [],
            "active_services": [],
        }), encoding="utf-8")
        b = load_baseline(p, strict=False)
        assert b is not None
        assert b.finding_keys is None


# ---------------------------------------------------------------------------
# BaselineLoadError i18n — locale-rendered messages
# ---------------------------------------------------------------------------


class TestBaselineLoadErrorI18n:

    def setup_method(self):
        # i18n is initialised by the autouse fixture in conftest.py to EN;
        # tests that need FR re-init explicitly. Reset to EN after each test
        # via teardown to keep the suite deterministic.
        pass

    def teardown_method(self):
        i18n.init("en")

    def test_not_found_message_renders_fr(self):
        i18n.init("fr")
        with pytest.raises(BaselineLoadError) as exc:
            load_baseline(Path("/tmp/nonexistent-v092-test.json"), strict=True)
        msg = str(exc.value)
        # FR locale uses « introuvable », « vérifie »
        assert "introuvable" in msg or "Baseline introuvable" in msg, (
            f"FR translation expected, got: {msg!r}"
        )

    def test_not_found_message_renders_en(self):
        i18n.init("en")
        with pytest.raises(BaselineLoadError) as exc:
            load_baseline(Path("/tmp/nonexistent-v092-test.json"), strict=True)
        msg = str(exc.value)
        assert "not found" in msg, f"EN baseline expected, got: {msg!r}"

    def test_invalid_json_message_renders_fr(self, tmp_path):
        i18n.init("fr")
        p = tmp_path / "bad.json"
        p.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(BaselineLoadError) as exc:
            load_baseline(p, strict=True)
        msg = str(exc.value)
        # FR locale uses « parsé », « lu »
        assert ("parsé" in msg) or ("lu" in msg), (
            f"FR translation expected, got: {msg!r}"
        )

    def test_v1_schema_message_renders_fr(self, tmp_path):
        i18n.init("fr")
        p = tmp_path / "v1.json"
        p.write_text(json.dumps({
            "schema_version": "1",
            "score": 9,
            "alert_count": 0,
            "warn_count": 1,
        }), encoding="utf-8")
        with pytest.raises(BaselineLoadError) as exc:
            load_baseline(p, strict=True)
        msg = str(exc.value)
        # FR locale uses « legacy v0.6.x » + « retiré »
        assert ("retiré" in msg) or ("legacy v0.6.x" in msg), (
            f"FR translation expected, got: {msg!r}"
        )
        # The retrait window must be in the message regardless of locale
        assert "v0.9.0" in msg

    def test_locale_keys_present_in_both_locales(self):
        """The 4 BaselineLoadError keys must be defined in both EN + FR
        locale files — a missing entry would fall back to the bracketed
        ``[compare.baseline_load.X]`` form which is the exact UX trap
        v0.9.1 fixed for ``cli.error.json_v1_retired``."""
        from pathlib import Path as _P
        for loc in ("en", "fr"):
            data = json.loads(_P(f"bob/locales/{loc}.json").read_text(encoding="utf-8"))
            block = data.get("compare", {}).get("baseline_load", {})
            for k in ("not_found", "invalid_json", "v1_schema", "bad_shape"):
                assert k in block, (
                    f"compare.baseline_load.{k} missing from {loc}.json — "
                    f"BaselineLoadError will surface a bracketed-fallback "
                    f"on systems with that locale."
                )
