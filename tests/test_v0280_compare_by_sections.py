"""v0.28.0 — two runs compared over what both read.

Found on the user's Mint host (25 October 2026): the run before was a
`--check=firewall` one (BOB's own bench, in a network namespace), and the full
audit after it said "Score degraded by 1 point(s)" and "New finding" for
clamav.socket_open_to_all, disk_encryption.root_unencrypted and
user_accounts.su_unrestricted — sections that had simply not run. Reproduced
with a throwaway home: `--check=ssh` then `--check=clamav` said "Score degraded
by 1", "7 info notice(s) resolved", nothing fixed, and "Variable deductions -1
pt (firewall.inactive 7 → 6)". The baseline now records the sections a run
read; the history marks a --check / --skip run as partial; and a domain with an
unread input shows "≤" as the global score does ("Score ≤ 9/10" above
"System hardening 9/10", package_integrity unread, on the same host).
"""

from __future__ import annotations

import inspect
from collections import defaultdict
from unittest.mock import MagicMock

import pytest

from bob import i18n
from bob.compare import AuditBaseline, compute_delta, display_delta, load_baseline, save_baseline, build_baseline


def _bl(sections, keys, score=9, **kw):
    base = dict(timestamp="2026-10-24T09:48:30+00:00", score=score, alert_count=0, warn_count=len(keys),
                info_count=40, finding_keys=keys, unverified=[], deduction_total=1,
                deduction_breakdown={"firewall.inactive": 7}, exhaustive=False, sections=sections)
    base.update(kw)
    return AuditBaseline(**base)


def _shown(delta, t=lambda k, **kw: k):
    calls = defaultdict(list)
    out = MagicMock()
    for level in ("ok", "warn", "info", "dim"):
        setattr(out, f"print_{level}", lambda msg, _l=level, **kw: calls[_l].append(msg))
    out.print_section = lambda msg: None
    display_delta(delta, t, out)
    return calls


# The reproduction: 7 more info notices on the ssh side, one more warning on the clamav side.
SSH_ONLY = _bl(["ssh"], ["ssh.password_auth"], score=8, deduction_breakdown={"firewall.inactive": 7},
               info_count=12, warn_count=1)
CLAMAV_ONLY = _bl(["clamav"], ["clamav.socket_open_to_all"], score=7, deduction_breakdown={"firewall.inactive": 6},
                  info_count=5, warn_count=2)


class TestDifferentSections:

    def test_a_key_whose_section_did_not_run_is_neither_new_nor_resolved(self):
        d = compute_delta(SSH_ONLY, CLAMAV_ONLY)
        assert d.sections_mismatch
        assert d.new_finding_keys == [] and d.resolved_finding_keys == []
        assert (d.sections_only_prev, d.sections_only_curr) == (["ssh"], ["clamav"])

    def test_a_key_of_a_section_both_ran_is_still_compared(self):
        d = compute_delta(_bl(["ssh"], []), _bl(["ssh", "clamav"], ["ssh.password_auth", "clamav.socket_open_to_all"]))
        assert d.new_finding_keys == ["ssh.password_auth"]

    def test_an_always_on_key_is_compared(self):
        d = compute_delta(_bl(["ssh"], []), _bl(["clamav"], ["firewall.inactive"]))
        assert d.new_finding_keys == ["firewall.inactive"]

    def test_a_correlation_is_not(self):
        d = compute_delta(_bl(["ssh"], []), _bl(["clamav"], ["corr.ssh_no_fail2ban"]))
        assert d.new_finding_keys == []

    def test_no_score_counts_or_variable_deductions(self):
        d = compute_delta(SSH_ONLY, CLAMAV_ONLY)
        assert (d.alert_delta, d.warn_delta, d.info_delta, d.deduction_delta, d.deduction_key_deltas) == (0, 0, 0, 0, [])
        shown = _shown(d)
        assert "compare.score_degraded" not in shown["warn"] and "compare.score_not_compared" in shown["info"]
        assert "compare.sections_changed" in shown["info"]

    @pytest.mark.parametrize("lang, words", [
        ("en", "did not read the same sections"), ("fr", "n'ont pas lu les mêmes sections")])
    def test_the_lines_render(self, lang, words):
        i18n.init(lang)
        try:
            shown = _shown(compute_delta(SSH_ONLY, CLAMAV_ONLY), t=i18n.t)
        finally:
            i18n.init("en")
        assert sum(words in m for m in shown["info"]) == 2
        assert any("clamav" in m and "ssh" in m for m in shown["info"])


class TestSameSections:

    def test_the_same_sections_compare_as_before(self):
        d = compute_delta(_bl(["ssh"], [], score=9), _bl(["ssh"], ["ssh.password_auth"], score=8))
        assert not d.sections_mismatch and d.score_delta == -1 and d.new_finding_keys == ["ssh.password_auth"]
        assert "compare.score_degraded" in _shown(d)["warn"]



class TestABaselineWithoutTheField:
    """After review (round 1): a baseline written before 0.28.0 has no
    `sections`, and may itself come from a --check run — the Mint host's did.
    Its coverage is unknown, not full: only the always-on sections are
    compared, and neither the score nor the counts."""

    OLD = _bl(None, ["firewall.inactive"], score=10, info_count=12, warn_count=1)
    NEW = _bl(["clamav", "ssh"], ["firewall.inactive", "clamav.socket_open_to_all", "corr.ssh_no_fail2ban"],
              score=9, info_count=40, warn_count=3)

    def test_a_filterable_or_correlation_key_is_neither_new_nor_resolved(self):
        d = compute_delta(self.OLD, self.NEW)
        assert d.sections_unrecorded and not d.sections_mismatch
        assert d.new_finding_keys == [] and d.resolved_finding_keys == []

    def test_an_always_on_key_is_still_compared(self):
        d = compute_delta(_bl(None, []), _bl(["clamav"], ["firewall.inactive"]))
        assert d.new_finding_keys == ["firewall.inactive"]

    def test_no_score_counts_or_variable_deductions(self):
        d = compute_delta(self.OLD, self.NEW)
        assert (d.alert_delta, d.warn_delta, d.info_delta, d.deduction_key_deltas) == (0, 0, 0, [])
        shown = _shown(d)
        assert "compare.score_degraded" not in shown["warn"]
        assert "compare.score_not_compared_unrecorded" in shown["info"]
        assert "compare.sections_unrecorded" in shown["info"]

    @pytest.mark.parametrize("lang, words", [("en", "the previous run's sections were not recorded"),
                                             ("fr", "les sections de l'exécution précédente ne sont pas connues")])
    def test_the_lines_render(self, lang, words):
        i18n.init(lang)
        try:
            shown = _shown(compute_delta(self.OLD, self.NEW), t=i18n.t)
        finally:
            i18n.init("en")
        assert any(words in m for m in shown["info"])

    def test_two_baselines_without_the_field_compare_as_before(self):
        """Only a real 0.28.0 run (sections known) against an older baseline is
        restricted; two in-memory baselines without the field are not."""
        d = compute_delta(_bl(None, []), _bl(None, ["clamav.socket_open_to_all"]))
        assert not d.sections_unrecorded and d.new_finding_keys == ["clamav.socket_open_to_all"]


def test_the_field_survives_the_file(tmp_path):
    path = tmp_path / "last_baseline.json"
    save_baseline(_bl(["clamav", "ssh"], []), path)
    assert load_baseline(path).sections == ["clamav", "ssh"]


def test_build_and_both_callers_record_it():
    from bob import __main__ as main, watch, runner
    assert "sections=sections_run(config, active_profile)" in inspect.getsource(main)
    assert "sections=sections_run(config, active_profile)" in inspect.getsource(watch)
    assert "sections" in inspect.signature(build_baseline).parameters
    from types import SimpleNamespace
    cfg = SimpleNamespace(check_only=["ssh"], skip_checks=[], exhaustive=False)
    assert runner.sections_run(cfg, None) == ["ssh"]
    cfg = SimpleNamespace(check_only=[], skip_checks=[], exhaustive=False)
    assert "package_integrity" not in runner.sections_run(cfg, None)
    assert "package_integrity" in runner.sections_run(SimpleNamespace(check_only=[], skip_checks=[], exhaustive=True), None)


class TestHistory:

    ENTRIES = [{"ts": "2026-10-24T07:00:00+00:00", "score": 9, "level": "low"},
               {"ts": "2026-10-24T09:48:30+00:00", "score": 10, "level": "low", "partial": True},
               {"ts": "2026-10-25T08:46:48+00:00", "score": 8, "level": "low"}]

    def test_a_partial_run_has_no_arrow_and_the_next_full_run_compares_with_the_last_full(self):
        from bob.history import _trend
        assert _trend(self.ENTRIES, 1) == " " and _trend(self.ENTRIES, 2) == "↓"

    def test_it_is_tagged_and_kept_out_of_the_sparkline(self):
        from bob.history import render_history
        lines = render_history(self.ENTRIES, t=lambda k, **kw: k)
        assert len(lines[2].strip()) == 2
        assert sum("history.partial" in ln for ln in lines) == 1

    def test_the_run_says_it(self):
        from bob import __main__ as main
        assert "partial=bool(config.check_only or config.skip_checks)" in inspect.getsource(main)


class TestDomainCeiling:

    class _E:
        domain_scores = {"system_hardening": {"score": 9, "label": "System hardening"},
                         "detection": {"score": 9, "label": "Detection"}}
        active_domains = {"system_hardening", "detection"}
        unverified = ["package_integrity.tool_missing"]
        findings = []

    def test_the_partly_read_domain(self):
        from bob.domain_scores import partially_read_domains
        assert partially_read_domains(self._E()) == {"system_hardening"}

    def test_the_terminal_marks_it(self):
        from bob.domain_scores import render_domain_scores
        from bob.scoring import CheckResult, ScoreEngine
        engine = ScoreEngine()
        r = CheckResult()
        r.warn_with_deduction(key="hardening.martians_not_logged", message="m", points=1)
        r.warn_with_deduction(key="clamav.socket_open_to_all", message="c", points=1)
        r.info(message="p", key="package_integrity.tool_missing")
        engine.apply(r)
        engine.finalize()
        from bob.domain_scores import apply_domain_score_override
        apply_domain_score_override(engine)
        assert not any("≤" in ln for ln in render_domain_scores(engine.domain_scores,
                                                                 active_domains=engine.active_domains))
        lines = render_domain_scores(engine.domain_scores, engine=engine)
        hard = next(ln for ln in lines if "System" in ln and "/10" in ln)
        det = next(ln for ln in lines if "Detection" in ln or "Threat" in ln)
        assert "≤" in hard and "≤" not in det, lines

    def test_the_reports_mark_it(self):
        from bob import domain_scores as ds
        rows = ds.domain_rows(self._E())
        assert {r["key"]: r.get("ceiling") for r in rows if r["active"]} == {"system_hardening": True, "detection": False}
        for mod in ("markdown_output", "html_output"):
            src = inspect.getsource(__import__(f"bob.{mod}", fromlist=["x"]))
            assert '("≤ " if r.get("ceiling") else "")' in src


def test_a_partial_entry_is_written(tmp_path, monkeypatch):
    import json
    from bob import history
    monkeypatch.setattr(history, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(history, "_HISTORY_FILE", tmp_path / "history.jsonl")
    history.save_score(8, "low", partial=True)
    history.save_score(9, "low")
    lines = [json.loads(ln) for ln in (tmp_path / "history.jsonl").read_text().splitlines()]
    assert [e.get("partial") for e in lines] == [True, None]
