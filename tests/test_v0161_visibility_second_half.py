"""v0.16.1 — v0.16.0 closed one half of its own class.

Three defects, one root. v0.16.0 reasoned that a check unable to read its input
makes no deductions, so the score can only be **too high** — hence the ceiling
rendering, and hence a --diff guard written for the rising direction only.

That reasoning holds for a check abstaining *inside* a domain. It does not hold
for a whole domain. The global score is an average over **active** domains, and
a domain whose input went unreadable leaves the average entirely — changing the
denominator, not the numerator. Masking ``/etc/passwd`` takes ``file_perms``
(10/10) out and the score from 7 down to **6**, with the deductions
byte-identical, nothing added to ``unverified`` and ``degraded_sections`` empty.
Against a sighted baseline that reads as ``Score degraded by 1 point(s)`` — a
regression reported on a host where nothing changed but BOB's own eyesight, and
a nightly cron mails it.

  1. ``user_accounts.no_passwd`` / ``no_shadow`` were outside VISIBILITY_KEYS.
     The set was first enumerated by *name* (``*_unreadable`` / ``*_unknown``)
     and neither matches, though both are emitted under
     ``if not snapshot.passwd_readable``. The guard here sweeps by position in
     the source instead, so the next differently-named one cannot hide.

  2. ``load_baseline`` never restored ``unverified``. ``save_baseline`` wrote it,
     the loader dropped it, so ``prev.unverified`` was always None on a real run
     and ``visibility_dropped`` could never be true. The entire --diff
     visibility protection was dead outside the unit tests — which build
     ``AuditBaseline`` objects in memory and never round-trip through the file.
     That is why the guard below round-trips through disk.

  3. There was no branch for a score that *falls* on a blinder run.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import re
import tempfile
from pathlib import Path

import pytest

from bob import i18n, output
from bob.compare import (
    AuditBaseline,
    compute_delta,
    display_delta,
    load_baseline,
    save_baseline,
)
from bob.visibility import VISIBILITY_KEYS

_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# 1 — sweep by position, not by name
# ---------------------------------------------------------------------------

def _keys_emitted_under_an_unreadability_guard() -> dict[str, str]:
    """Keys emitted in the body of a bare ``if not snapshot.<x>readable``.

    Body only — never ``orelse``. The ``else`` branch of such a test is the
    *readable* path, and reading it in reports the honest positive findings as
    if they were visibility limits (``firewall_drivers.no_issues``, which the
    source explicitly guards against, is the giveaway).
    """
    found: dict[str, str] = {}
    for py in sorted((_ROOT / "bob" / "checks").rglob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            if not re.fullmatch(r"not snapshot\.\w*readable\w*", ast.unparse(node.test)):
                continue
            for stmt in node.body:
                for sub in ast.walk(stmt):
                    if not isinstance(sub, ast.Call):
                        continue
                    for kw in sub.keywords:
                        if kw.arg == "key" and isinstance(kw.value, ast.Constant):
                            found[kw.value.value] = py.name
    return found


class TestTheSetIsSweptBySemanticsNotByName:

    def test_the_sweep_still_sees_something(self):
        """A guard that finds nothing passes forever. Positive control."""
        found = _keys_emitted_under_an_unreadability_guard()
        assert len(found) >= 10, f"the AST sweep went blind: {found}"

    def test_the_sweep_ignores_the_readable_branch(self):
        """``firewall_drivers.no_issues`` lives in the ``elif`` — the readable
        path. A sweep that walks the whole If node reports it, and the wall of
        false positives is how a real miss gets lost."""
        assert "firewall_drivers.no_issues" not in _keys_emitted_under_an_unreadability_guard()

    def test_no_unreadability_finding_stays_out_of_the_set(self):
        from bob.visibility import NOT_A_VISIBILITY_LIMIT

        found = _keys_emitted_under_an_unreadability_guard()
        missing = sorted(
            f"{k} ({src})" for k, src in found.items()
            if k not in VISIBILITY_KEYS and k not in NOT_A_VISIBILITY_LIMIT
        )
        assert not missing, (
            "these keys are emitted because a check could not read its input, "
            f"and are in neither set: {missing}. The name does not have to end "
            "in _unreadable for the meaning to be the same."
        )

    @pytest.mark.parametrize("key", ["user_accounts.no_passwd", "user_accounts.no_shadow"])
    def test_the_two_that_were_missed(self, key):
        assert key in VISIBILITY_KEYS


# ---------------------------------------------------------------------------
# 2 — the field must survive the disk, not just the process
# ---------------------------------------------------------------------------

def _baseline(score: int, unverified, *, keys=("a.b",)) -> AuditBaseline:
    return AuditBaseline(
        hostname="h", timestamp="t", score=score, alert_count=0, warn_count=0,
        info_count=0, deduction_total=0, finding_keys=list(keys),
        open_ports=[], active_services=[],
        unverified=None if unverified is None else list(unverified),
    )


class TestTheBaselineRoundTrip:
    """In-memory tests passed while the feature was dead. Go through the file."""

    def test_unverified_survives_save_then_load(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b.json"
            save_baseline(_baseline(7, ["x.y", "z.w"]), path=p)
            assert load_baseline(path=p).unverified == ["x.y", "z.w"]

    def test_an_empty_set_round_trips_as_empty_not_as_unknown(self):
        """[] is a clean run; None means the field did not exist yet."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b.json"
            save_baseline(_baseline(7, []), path=p)
            assert load_baseline(path=p).unverified == []

    def test_a_baseline_written_before_the_field_reads_as_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b.json"
            save_baseline(_baseline(7, ["x.y"]), path=p)
            raw = json.loads(p.read_text(encoding="utf-8"))
            raw.pop("unverified")
            p.write_text(json.dumps(raw), encoding="utf-8")
            assert load_baseline(path=p).unverified is None

    def test_the_drop_is_detected_across_the_file(self):
        """The end-to-end claim: visibility_dropped is reachable in real use."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b.json"
            save_baseline(_baseline(7, ["x.y"]), path=p)
            delta = compute_delta(load_baseline(path=p), _baseline(6, ["x.y", "z.w"]))
            assert delta.visibility_dropped is True

    def test_an_older_baseline_still_claims_no_drop(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b.json"
            save_baseline(_baseline(7, ["x.y"]), path=p)
            raw = json.loads(p.read_text(encoding="utf-8"))
            raw.pop("unverified")
            p.write_text(json.dumps(raw), encoding="utf-8")
            delta = compute_delta(load_baseline(path=p), _baseline(6, ["x.y", "z.w"]))
            assert delta.visibility_dropped is False


# ---------------------------------------------------------------------------
# 3 — both directions, and only when visibility actually moved
# ---------------------------------------------------------------------------

def _rendered(prev: AuditBaseline, curr: AuditBaseline, lang: str = "en") -> str:
    i18n.init(lang)
    output.init(no_color=True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        display_delta(compute_delta(prev, curr), i18n.t, output)
    return buf.getvalue()


class TestBothDirections:

    def test_a_drop_on_a_blinder_run_is_not_called_a_degradation(self):
        out = _rendered(_baseline(7, ["x.y"]), _baseline(6, ["x.y", "z.w"]))
        assert "not attributable to the host" in out
        assert "degraded" not in out.lower()

    def test_a_real_drop_is_still_called_a_degradation(self):
        """Polarity: the guard must not swallow genuine regressions."""
        out = _rendered(_baseline(7, ["x.y"]), _baseline(6, ["x.y"]))
        assert "degraded" in out.lower()
        assert "not attributable" not in out

    def test_a_rise_on_a_blinder_run_keeps_its_v0160_wording(self):
        out = _rendered(_baseline(7, ["x.y"]), _baseline(8, ["x.y", "z.w"]))
        assert "not an improvement" in out

    def test_a_real_rise_is_still_an_improvement(self):
        out = _rendered(_baseline(6, ["x.y"]), _baseline(7, ["x.y"]))
        assert "improved" in out.lower()

    def test_the_drop_wording_exists_in_both_locales(self):
        for lang, needle in (("en", "not attributable"), ("fr", "imputable")):
            out = _rendered(_baseline(7, ["x.y"]), _baseline(6, ["x.y", "z.w"]), lang)
            assert needle in out, f"{lang}: {out!r}"
            assert not re.search(r"\[compare\.[a-z_]+\]", out), f"bracketed key in {lang}"
        i18n.init("en")


# ---------------------------------------------------------------------------
# 4 — --target: the line on screen and the exit code are one claim
# ---------------------------------------------------------------------------

class TestTheTargetLineAgreesWithTheExitCode:
    """v0.16.0 made the gate fail closed on a bounded score and left the summary
    printing "✔ target reached". The same run then exited 4 while telling the
    operator the target was met — a CI reading the code and a human reading the
    line got opposite answers.
    """

    @staticmethod
    def _exit_predicate(score: int, target: int, bounded: bool) -> bool:
        """Mirror of __main__.py's gate. Asserted against the source below."""
        return target > 0 and (score < target or bounded)

    def test_the_gate_in_main_is_still_the_predicate_mirrored_here(self):
        """A mirror that drifts proves nothing. Pin it to the real source."""
        src = (_ROOT / "bob" / "__main__.py").read_text(encoding="utf-8")
        assert "engine.score < config.target or engine.score_is_upper_bound" in src, (
            "the --target gate changed shape; update _exit_predicate with it"
        )

    @staticmethod
    def _target_line(score: int, target: int, bounded: bool, lang: str = "en") -> str:
        from bob.display import _summary_header_lines

        class _Engine:
            def __init__(self):
                self.score = score
                self.score_is_upper_bound = bounded
                self.unverified = ["x.y"] if bounded else []
                self.risk_at_best = "medium"

            @property
            def effective_level(self):
                class _L:
                    value = "medium"
                return _L()
            level = effective_level

        class _Config:
            target = None
            profile = "server"
            quiet = False

        i18n.init(lang)
        output.init(no_color=True)
        cfg = _Config()
        cfg.target = target
        lines = _summary_header_lines(_Engine(), None, cfg, i18n.t,
                                     profile_name="server", prev_score=None)
        for label, value in lines:
            if "arget" in label or "bjectif" in label:
                return value
        return ""

    @pytest.mark.parametrize("score,target,bounded", [
        (7, 1, True), (7, 5, True), (7, 7, True),      # cleared, but a ceiling
        (7, 9, True), (7, 9, False),                    # genuinely short
        (7, 1, False), (7, 7, False),                   # genuinely met
    ])
    def test_the_line_never_claims_success_when_the_gate_fails(self, score, target, bounded):
        line = self._target_line(score, target, bounded)
        assert line, "no target line rendered"
        gate_fails = self._exit_predicate(score, target, bounded)
        claims_success = "✔" in line
        assert claims_success is not gate_fails, (
            f"score={score} target={target} bounded={bounded}: exit "
            f"{'4 (missed)' if gate_fails else '0-2 (met)'} but the summary says "
            f"{line!r}"
        )

    def test_a_bounded_run_that_clears_the_bar_says_why(self):
        line = self._target_line(7, 1, True)
        assert "ceiling" in line and "✔" not in line

    def test_the_wording_exists_in_both_locales(self):
        for lang, needle in (("en", "ceiling"), ("fr", "plafond")):
            line = self._target_line(7, 1, True, lang)
            assert needle in line, f"{lang}: {line!r}"
            assert not re.search(r"\[scoring\.[a-z_]+\]", line)
        i18n.init("en")
