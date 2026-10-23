"""v0.26.1 — a comparison is only made between runs of the same mode.

Measured on a Mint host (0.26.0): `sudo bob -v -d --exhaustive` after a normal
run printed "This run could read less of the host than the previous one" —
package_integrity (debsums missing) was unread, and the normal run had never
attempted it — and "6 new info notice(s)"; the next normal run printed
"4 info notice(s) resolved since last audit" with nothing fixed: the four were
package_integrity (1) and world_writable (3), not run. The baseline did not
record --exhaustive.
"""

from __future__ import annotations

import inspect
from collections import defaultdict
from unittest.mock import MagicMock

import pytest

from bob import compare as cmp
from bob import i18n
from bob.compare import AuditBaseline, compute_delta, display_delta, load_baseline, save_baseline


def _bl(exhaustive, **kw):
    base = dict(timestamp="2026-10-20T14:47:56+00:00", score=9, alert_count=0, warn_count=4,
                info_count=85, finding_keys=["clamav.socket_open_to_all"], unverified=[],
                deduction_total=3, deduction_breakdown={"clamav.socket_open_to_all": 1},
                exhaustive=exhaustive)
    base.update(kw)
    return AuditBaseline(**base)


# The Mint pair: a normal run, then an exhaustive one (+6 INFO, package_integrity unread).
NORMAL = dict(info_count=85, unverified=[])
EXHAUSTIVE = dict(info_count=91, unverified=["package_integrity.tool_missing"])


def _shown(delta, t=lambda k, **kw: k):
    calls = defaultdict(list)
    out = MagicMock()
    for level in ("ok", "warn", "info", "dim"):
        setattr(out, f"print_{level}", lambda msg, _l=level, **kw: calls[_l].append(msg))
    out.print_section = lambda msg: None
    display_delta(delta, t, out)
    return calls


def test_exhaustive_after_normal_is_not_a_blinder_run():
    d = compute_delta(_bl(False, **NORMAL), _bl(True, **EXHAUSTIVE))
    assert d.mode_mismatch and not d.visibility_dropped and d.info_delta == 0
    shown = _shown(d)
    assert "compare.mode_changed" in shown["info"]
    assert "compare.visibility_dropped" not in shown["warn"]
    assert "compare.info_increased" not in shown["info"]


def test_normal_after_exhaustive_resolves_nothing():
    prev = _bl(True, **EXHAUSTIVE, finding_keys=["clamav.socket_open_to_all", "world_writable.files_reachable"])
    d = compute_delta(prev, _bl(False, **NORMAL))
    assert d.info_delta == 0 and d.resolved_finding_keys == []
    assert "compare.info_decreased" not in _shown(d)["ok"]


def test_same_mode_keeps_the_visibility_protection():
    d = compute_delta(_bl(True, **NORMAL), _bl(True, **EXHAUSTIVE))
    assert not d.mode_mismatch and d.visibility_dropped and d.info_delta == 6


def test_a_baseline_from_before_the_field_is_an_unknown_mode():
    d = compute_delta(_bl(None, **EXHAUSTIVE), _bl(False, **NORMAL))
    assert d.mode_mismatch and d.prev_exhaustive is None and d.info_delta == 0


def test_two_unrecorded_modes_compare_as_before():
    d = compute_delta(_bl(None, **NORMAL), _bl(None, **EXHAUSTIVE))
    assert not d.mode_mismatch and d.visibility_dropped


def test_the_mode_survives_the_file(tmp_path):
    f = tmp_path / "last_baseline.json"
    save_baseline(_bl(True), f)
    assert load_baseline(f).exhaustive is True
    f.write_text('{"timestamp": "x", "score": 9, "alert_count": 0, "warn_count": 0}')
    assert load_baseline(f).exhaustive is None


def test_the_sections_are_the_runners():
    from bob import runner
    assert cmp.EXHAUSTIVE_SECTIONS == frozenset(runner._REQUIRES_EXHAUSTIVE)


def test_both_callers_hand_the_mode():
    from bob import __main__ as main, watch
    assert "exhaustive=config.exhaustive" in inspect.getsource(main)
    assert "exhaustive=config.exhaustive" in inspect.getsource(watch)


@pytest.mark.parametrize("lang, words", [("en", "not run the same way"), ("fr", "pas été lancées de la même façon")])
def test_the_line_renders(lang, words):
    i18n.init(lang)
    try:
        shown = _shown(compute_delta(_bl(False, **NORMAL), _bl(True, **EXHAUSTIVE)), t=i18n.t)
    finally:
        i18n.init(lang="en")
    line = next(m for m in shown["info"] if words in m)
    assert "--exhaustive" in line and "package_integrity, world_writable" in line


def test_the_exhaustive_sections_never_deduct():
    """After review: the score compares across modes because the sections only
    --exhaustive reads report INFO and OK, never a deduction or a cap."""
    import re
    for mod in ("world_writable", "package_integrity"):
        src = (inspect.getsourcefile(__import__(f"bob.checks.{mod}", fromlist=["x"])))
        text = open(src, encoding="utf-8").read()
        assert not re.search(r"\.(warn|alert|warn_with_deduction|add_deduction|set_cap)\(", text), mod
        # After review round 12: on every path — the only calls on the result
        # are info and ok, whatever a new one would be named.
        assert set(re.findall(r"\bresult\.([a-z_]+)\b", text)) <= {"info", "ok"}, mod
