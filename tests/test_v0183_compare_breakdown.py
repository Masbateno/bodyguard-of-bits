"""v0.18.3 — per-key attribution behind a "variable deductions" diff move.

`bob --diff` already names finding keys that appear or resolve. What it could
not name was a *graduated* deduction — a control whose point value changed
while its key stayed present (ssl_certs expiry count, an exposure moving with
network context). The score moved and the diff could only say "Variable
deductions -N pt(s)", never which control.

The baseline now stores a per-key breakdown (additive, `None` on a baseline
written before the field — the single total line is all such a baseline can
support). These tests pin: the aggregation, the round-trip, the rename
migration the breakdown must ride like `finding_keys`, the delta computation
(changed keys only), graceful degradation against an old baseline, and that the
sub-lines render only in the variable-deductions branch.
"""

from __future__ import annotations

import contextlib
import io
from types import SimpleNamespace

from bob import i18n, output
from bob.compare import (
    AuditBaseline,
    build_baseline,
    compute_delta,
    display_delta,
    load_baseline,
    save_baseline,
)


def _ded(key: str, points: int):
    return SimpleNamespace(key=key, points=points)


def _engine(breakdown):
    return SimpleNamespace(
        score=8, alert_count=0, warn_count=len(breakdown), info_count=0,
        findings=[], breakdown=breakdown,
    )


def _ports():
    return SimpleNamespace(ports=[])


# ---------------------------------------------------------------------------
# build_baseline — aggregation
# ---------------------------------------------------------------------------

class TestBuildAggregatesByKey:
    def test_one_deduction_per_key(self):
        bl = build_baseline(_engine([_ded("a.k", 2), _ded("b.k", 1)]), _ports(), [])
        assert bl.deduction_breakdown == {"a.k": 2, "b.k": 1}

    def test_two_deductions_same_key_sum(self):
        bl = build_baseline(_engine([_ded("a.k", 2), _ded("a.k", 1)]), _ports(), [])
        assert bl.deduction_breakdown == {"a.k": 3}

    def test_total_still_matches_the_sum(self):
        bl = build_baseline(_engine([_ded("a.k", 2), _ded("b.k", 1)]), _ports(), [])
        assert bl.deduction_total == sum(bl.deduction_breakdown.values()) == 3

    def test_a_clean_audit_is_empty_dict_not_none(self):
        """{} means 'feature present, no deductions'; None means 'old baseline'."""
        bl = build_baseline(_engine([]), _ports(), [])
        assert bl.deduction_breakdown == {}


# ---------------------------------------------------------------------------
# save / load round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_breakdown_survives_disk(self, tmp_path):
        p = tmp_path / "b.json"
        save_baseline(AuditBaseline(
            timestamp="t", score=8, alert_count=0, warn_count=1,
            deduction_breakdown={"ssl_certs.expired": 3, "ssh.weak_kex": 2},
        ), p)
        got = load_baseline(p)
        assert got.deduction_breakdown == {"ssl_certs.expired": 3, "ssh.weak_kex": 2}

    def test_absent_field_loads_as_none(self, tmp_path):
        """A pre-v0.18.3 baseline has no such key — None, never {}."""
        p = tmp_path / "b.json"
        p.write_text('{"timestamp": "t", "score": 8, "alert_count": 0, "warn_count": 1}',
                     encoding="utf-8")
        assert load_baseline(p).deduction_breakdown is None

    def test_malformed_values_are_skipped_not_fatal(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_text(
            '{"timestamp":"t","score":8,"alert_count":0,"warn_count":1,'
            '"deduction_breakdown":{"a.k":2,"bad":"x"}}',
            encoding="utf-8")
        assert load_baseline(p).deduction_breakdown == {"a.k": 2}


def test_load_remaps_legacy_keys_like_finding_keys(tmp_path):
    """The breakdown carries finding keys, so it must ride the same v0.9.0 /
    v0.16.0 rename migrations — else a cross-version diff attributes a move to a
    key that no longer exists."""
    from bob._v090_renames import remap_finding_key
    legacy = next((k for k in _LEGACY_PROBES if remap_finding_key(k) != k), None)
    assert legacy is not None, "no legacy prefix available to probe the migration"
    canonical = remap_finding_key(legacy)
    p = tmp_path / "b.json"
    p.write_text(
        '{"timestamp":"t","score":8,"alert_count":0,"warn_count":1,'
        f'"deduction_breakdown":{{"{legacy}":2}}}}',
        encoding="utf-8")
    bd = load_baseline(p).deduction_breakdown
    assert bd == {canonical: 2}


# Candidate legacy prefixes; whichever the remapper actually rewrites is used.
_LEGACY_PROBES = [
    "iptables_nft.input_accept",
    "iptables_nftables.input_accept",
    "ssh.x11_forwarding_server",
]


# ---------------------------------------------------------------------------
# compute_delta — per-key deltas
# ---------------------------------------------------------------------------

def _bl(breakdown, *, score=7, ts="2026-09-13T03:00:00+00:00"):
    # Identical finding_keys/counts across a pair keeps the diff in the
    # variable-deductions branch (no structural explanation).
    return AuditBaseline(
        timestamp=ts, score=score, alert_count=0, warn_count=2, info_count=3,
        finding_keys=sorted(breakdown), unverified=[],
        deduction_total=sum(breakdown.values()), deduction_breakdown=breakdown,
    )


class TestDeltaPerKey:
    def test_only_changed_keys_appear(self):
        prev = _bl({"a.k": 3, "b.k": 2, "c.k": 2}, score=6)
        curr = _bl({"a.k": 1, "b.k": 1, "c.k": 2}, score=7)
        d = compute_delta(prev, curr)
        assert d.deduction_key_deltas == [("a.k", 3, 1), ("b.k", 2, 1)]  # c.k unchanged, omitted

    def test_a_key_gained_or_lost_counts_as_zero_on_the_missing_side(self):
        prev = _bl({"a.k": 2})
        curr = _bl({"a.k": 2, "b.k": 1})
        d = compute_delta(prev, curr)
        assert ("b.k", 0, 1) in d.deduction_key_deltas

    def test_old_baseline_none_degrades_to_no_per_key(self):
        """Either side None (pre-v0.18.3) → empty; the single total line stands."""
        prev = AuditBaseline(timestamp="t", score=6, alert_count=0, warn_count=2,
                             info_count=3, finding_keys=["a.k"], unverified=[],
                             deduction_total=3, deduction_breakdown=None)
        curr = _bl({"a.k": 1}, score=7)
        assert compute_delta(prev, curr).deduction_key_deltas == []


# ---------------------------------------------------------------------------
# display — the sub-lines
# ---------------------------------------------------------------------------

def _render(delta, lang="en"):
    i18n.init(lang=lang)
    output.init(no_color=True, quiet=False)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        display_delta(delta, i18n.t, output)
    return buf.getvalue()


class TestDisplay:
    def test_sub_lines_render_under_variable_deductions(self):
        out = _render(compute_delta(_bl({"ssl_certs.expired": 3}, score=6),
                                    _bl({"ssl_certs.expired": 1}, score=7)))
        assert "Variable deductions" in out
        assert "ssl_certs.expired" in out and "3 → 1 pt" in out

    def test_no_sub_lines_when_a_structural_explanation_exists(self):
        """If a finding key resolved, that names the change — the variable-
        deductions branch (and its breakdown) must not fire."""
        prev = AuditBaseline(timestamp="t", score=6, alert_count=0, warn_count=2,
                             info_count=3, finding_keys=["ssl_certs.expired", "ssh.x"],
                             unverified=[], deduction_total=5,
                             deduction_breakdown={"ssl_certs.expired": 3, "ssh.x": 2})
        curr = AuditBaseline(timestamp="t2", score=8, alert_count=0, warn_count=1,
                             info_count=3, finding_keys=["ssl_certs.expired"],
                             unverified=[], deduction_total=3,
                             deduction_breakdown={"ssl_certs.expired": 3})
        out = _render(compute_delta(prev, curr))
        assert "Variable deductions" not in out
        assert "3 → 1 pt" not in out

    def test_french_renders_the_same_shape(self):
        out = _render(compute_delta(_bl({"ssl_certs.expired": 3}, score=6),
                                    _bl({"ssl_certs.expired": 1}, score=7)), lang="fr")
        assert "Déductions variables" in out
        assert "ssl_certs.expired  3 → 1 pt" in out
