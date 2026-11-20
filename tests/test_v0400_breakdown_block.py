"""v0.40.0 — the computation of the score in --manage-logs's preview (B-032).

Decided with the user (20 November 2026): the preview of an audit report shows,
behind the key b, the computation --breakdown prints; closed when the preview
opens, kept as it is across ←/→, like the comparison and the history. It is
rendered by display_breakdown itself: what the engine held is written into the
report's state as data and handed back in the engine's shape — so the block
says exactly what --breakdown said. A report written before 0.40.0 says it has
no such detail.
"""

from __future__ import annotations

import json

import pytest

from bob import compare as C
from bob import i18n
from bob.breakdown import _ANSI, breakdown_lines, breakdown_state, display_breakdown
from bob.history import history_entry
from bob.scoring import Deduction, ScoreCap, ScoreEngine


def _t(key, **kw):
    return i18n.t(key, **kw)


@pytest.fixture(autouse=True)
def _english():
    before = i18n.current_lang()
    i18n.init("en")
    yield
    i18n.init(before)


def _engine(*deductions, cap=None):
    from bob.domain_scores import apply_domain_score_override
    engine = ScoreEngine()
    for key, points in deductions:
        engine.breakdown.append(Deduction(reason=key, points=points, context="local", key=key))
    if cap is not None:
        engine.cap(cap.maximum, cap.reason)
    engine.finalize()
    apply_domain_score_override(engine)
    return engine


def _printed(engine):
    """What --breakdown prints for *engine*, colours and section title off."""
    sink = C._Lines()
    display_breakdown(engine, _t, sink)
    return [_ANSI.sub("", line) for line in sink.lines[1:]]


_ENGINES = {
    "flawless": lambda: _engine(),
    "deductions": lambda: _engine(("ssh.permit_root_login", 2), ("firewall.inactive", 3)),
    "tool-capped": lambda: _engine(*((f"rootkit.found_{i}", 2) for i in range(8))),
    "engine-capped": lambda: _engine(("firewall.inactive", 3), cap=ScoreCap(3, "firewall off")),
    "low": lambda: _engine(*((f"updates.k{i}", 3) for i in range(6)), ("ssh.permit_root_login", 3)),
}


#: What each engine must make --breakdown print — so that each case exercises
#: the branch it is named after, and the equality below proves something there.
_MARKS = {
    "flawless": lambda: _t("breakdown.no_deductions"),
    "deductions": lambda: "ssh.permit_root_login",
    "tool-capped": lambda: _t("breakdown.capped"),
    "engine-capped": lambda: "firewall off",
    "low": lambda: "✖ " + _t("breakdown.final_score", score=3)[:12],
}


class TestTheSameWords:
    @pytest.mark.parametrize("name", sorted(_ENGINES))
    def test_the_block_says_what_breakdown_said(self, name):
        engine = _ENGINES[name]()
        printed = _printed(engine)
        assert any(_MARKS[name]() in line for line in printed), (name, printed)
        kept = json.loads(json.dumps(breakdown_state(engine)))      # through the state file's JSON
        assert breakdown_lines(kept, _t) == printed

    def test_no_colour_reaches_the_screen(self):
        lines = breakdown_lines(breakdown_state(_ENGINES["deductions"]()), _t)
        assert lines and not any("\x1b" in line for line in lines)

    @pytest.mark.parametrize("bad", [None, [], {}, {"deductions": "x"}])
    def test_a_state_it_cannot_read_back(self, bad):
        assert breakdown_lines(bad, _t) is None


class TestTheReportsState:
    def _report(self, tmp_path, engine=None, *, state=True):
        from tests.test_v0390_preview_blocks import _baseline
        r = tmp_path / "bob_20261120_100000.log"
        r.write_text("score\n", encoding="utf-8")
        if state:
            base = _baseline(7, [], [])
            C.save_report_state(r, base, history_entry(7, "medium"),
                                breakdown_state(engine) if engine is not None else None)
        return r

    def test_kept_beside_the_report(self, tmp_path):
        engine = _ENGINES["deductions"]()
        r = self._report(tmp_path, engine)
        assert C.breakdown_block(r, _t) == _printed(engine)

    def test_a_report_from_before(self, tmp_path):
        r = self._report(tmp_path)                     # a state with no breakdown: 0.39.0
        assert C.breakdown_block(r, _t) == [_t("manage_logs.breakdown_older")]

    def test_a_report_with_no_state(self, tmp_path):
        r = self._report(tmp_path, state=False)
        assert C.breakdown_block(r, _t) == [_t("manage_logs.breakdown_no_state")]

    def test_a_state_damaged(self, tmp_path):
        r = self._report(tmp_path, _ENGINES["deductions"]())
        C.state_path(r).write_text("{not json", encoding="utf-8")
        assert C.breakdown_block(r, _t) == [_t("manage_logs.breakdown_unreadable")]


class TestThePreview:
    def _report(self, tmp_path, name):
        from tests.test_v0390_preview_blocks import _baseline
        r = tmp_path / f"bob_{name}.log"
        r.write_text("the report\n", encoding="utf-8")
        base = _baseline(7, [], [])
        C.save_report_state(r, base, history_entry(7, "medium"), breakdown_state(_ENGINES["deductions"]()))
        return r

    def test_closed_at_open_b_opens_it(self, tmp_path):
        import bob.manage_logs as ml
        r = self._report(tmp_path, "20261120_100000")
        view = ml._new_view()
        title = _t("manage_logs.block_breakdown")
        assert not any(title in text for text, _k in ml._preview_content(r, _t, view, ["the report"], 100))
        view["breakdown"] = True
        content = ml._preview_content(r, _t, view, ["the report"], 100)
        assert any(title in text for text, _k in content)
        assert any("ssh.permit_root_login" in text for text, _k in content)

    def test_b_toggles_and_the_view_follows_the_arrows(self, tmp_path, monkeypatch):
        import sys

        import bob.manage_logs as ml
        from tests.test_v0390_announced_keys import _Curses, _OutOfKeys, _Screen
        monkeypatch.setitem(sys.modules, "curses", _Curses)
        older = self._report(tmp_path, "20261119_100000")
        newer = self._report(tmp_path, "20261120_100000")
        scr = _Screen([ord("b"), _Curses.KEY_LEFT])
        try:
            ml._curses_preview_log(scr, newer, _t, [older, newer])
        except _OutOfKeys:
            pass
        title = _t("manage_logs.block_breakdown")
        shown = ["\n".join(f.values()) for f in scr.frames]
        assert title not in shown[0] and title in shown[1] and title in shown[2]
