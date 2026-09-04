"""
v0.16.0 — the score went up when BOB could see less.

Masking ``/etc/ssh/sshd_config`` removes four deductions and moves the score
from 7 to **8**. Reproduced before and after the v0.15.5 campaign; the campaign
did not touch it, because every check involved behaves correctly on its own.
``ssh.config_unreadable`` is emitted, honestly, in its own section. The defect
is one layer up: the score is a sum over the checks that *ran*, and a check
that could not read its input did not make deductions that are **unknown, not
zero**. ``degraded_sections`` stays empty throughout — by contract, it is
reserved for a section whose check *raised*, and a check that abstains cleanly
leaves no trace in the machine output at all.

So an operator running BOB without sudo reads a better score than one running
it properly, and nothing in the report contradicts the number. On this host,
unprivileged, **eight** sections cannot be fully read.

**The shape chosen, and why.** The project's rule is that when BOB cannot see
something it says so "explicitly and bluntly". A caveat printed *beside* the
score is not blunt: the number still says 8, and the number is what gets read.
So the number itself is rendered as what it is — a ceiling, ``≤ 8/10`` — and
the risk level derived from it becomes a best case rather than a verdict,
because a bounded score silently under-states risk.

Deducting for unreadability was rejected: that penalises the operator for
BOB's own privileges, and invents a number where there is none.

``score`` stays an integer in JSON so existing consumers keep working; two
additive fields say what it is worth.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from bob.compare import AuditBaseline, compute_delta
from bob.scoring import CheckResult, ScoreEngine
from bob.visibility import VISIBILITY_KEYS, section_of

_ROOT = Path(__file__).resolve().parent.parent
_CONVENTION = re.compile(r"\.(?:[a-z0-9_]*_)?(?:unreadable|unknown)$")


def _emitted_keys() -> set[str]:
    """Every literal finding key BOB can emit, read from the source."""
    keys: set[str] = set()
    for py in (_ROOT / "bob").rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        for m in re.finditer(r'key="([a-z0-9_.]+)"', py.read_text(encoding="utf-8")):
            keys.add(m.group(1))
    return keys


class TestTheKeySetStaysHonestBothWays:

    def test_no_entry_names_a_key_bob_never_emits(self):
        """A stale entry silently bounds nothing and looks like coverage."""
        emitted = _emitted_keys()
        stale = sorted(k for k in VISIBILITY_KEYS if k not in emitted)
        assert not stale, (
            f"VISIBILITY_KEYS names keys nothing emits: {stale}. Remove them, "
            f"or fix the key if it was renamed."
        )

    def test_no_new_visibility_key_stays_out_of_the_set(self):
        """
        The set is explicit rather than derived from the name, so a key added
        later would silently not bound the score. The convention catches it.
        """
        from bob.visibility import NOT_A_VISIBILITY_LIMIT

        missing = sorted(
            k for k in _emitted_keys()
            if _CONVENTION.search(k)
            and k not in VISIBILITY_KEYS
            and k not in NOT_A_VISIBILITY_LIMIT
        )
        assert not missing, (
            f"these keys look like visibility limits and are in neither set: "
            f"{missing}.\nAdd them to VISIBILITY_KEYS, or to "
            f"NOT_A_VISIBILITY_LIMIT with a reason."
        )

    def test_the_qualification_keys_are_deliberately_absent(self):
        """
        `ssh.config_newer_than_service` qualifies *what the findings describe*
        — a file rather than the running service — but the deductions were
        computed and are present. The score is not a ceiling there.
        """
        for key in ("ssh.config_newer_than_service",
                    "log_rotation.journald_conf_newer_than_service"):
            assert key not in VISIBILITY_KEYS


class TestTheEngineKnowsWhatItCouldNotSee:

    def _engine(self, *keys, ignore=()):
        result = CheckResult()
        for key in keys:
            result.info(message=key, key=key)
        result.warn_with_deduction(key="ssh.password_auth", message="x",
                                   reason="x", points=2, nature="improvement")
        engine = ScoreEngine()
        engine.ignore_keys = frozenset(ignore)
        engine.apply(result)
        return engine

    def test_a_visibility_finding_bounds_the_score(self):
        engine = self._engine("ssh.config_unreadable")
        assert engine.unverified == ["ssh.config_unreadable"]
        assert engine.score_is_upper_bound is True

    def test_a_clean_run_is_not_bounded(self):
        """The polarity twin — a full audit must still report a value."""
        engine = self._engine()
        assert engine.unverified == []
        assert engine.score_is_upper_bound is False

    def test_an_ignored_visibility_finding_does_not_bound(self):
        """
        The operator asked not to hear about it. Bounding the score anyway
        would put a ceiling on the report with nothing visible explaining it.
        """
        engine = self._engine("ssh.config_unreadable",
                              ignore=("ssh.config_unreadable",))
        assert engine.score_is_upper_bound is False


class TestTheComparisonIsNotLikeForLike:

    def _delta(self, prev_unverified, curr_unverified):
        prev = AuditBaseline(
            timestamp="t0", score=7, alert_count=0, warn_count=2, info_count=0,
            finding_keys=["ssh.password_auth", "firewall.policy_open"],
            unverified=prev_unverified,
        )
        curr = AuditBaseline(
            timestamp="t1", score=8, alert_count=0, warn_count=1, info_count=0,
            finding_keys=["firewall.policy_open"],
            unverified=curr_unverified,
        )
        return compute_delta(prev, curr)

    def test_a_key_whose_section_went_blind_is_not_resolved(self):
        delta = self._delta([], ["ssh.config_unreadable"])
        assert delta.unreevaluated_finding_keys == ["ssh.password_auth"]
        assert delta.resolved_finding_keys == []
        assert delta.visibility_dropped is True

    def test_a_key_that_really_went_away_is_still_resolved(self):
        """The polarity twin: a genuine fix must still read as a fix."""
        delta = self._delta([], [])
        assert delta.resolved_finding_keys == ["ssh.password_auth"]
        assert delta.unreevaluated_finding_keys == []
        assert delta.visibility_dropped is False

    def test_an_older_baseline_claims_no_drop(self):
        """
        `unverified=None` means the baseline predates the field, not that
        everything was visible then — reading it as visibility loss would turn
        an unknown into a claim, which is the defect this field removes.
        """
        assert self._delta(None, ["ssh.config_unreadable"]).visibility_dropped is False


class TestTheNumberSaysWhatItIs:

    def test_the_score_renders_as_a_ceiling(self):
        source = (_ROOT / "bob" / "display.py").read_text(encoding="utf-8")
        assert 'f"≤ {score}/10"' in source, (
            "a caveat beside the score is not read by whoever reads only the "
            "score — the number itself has to say it is a ceiling"
        )

    @staticmethod
    def _score_line(*, score: int, prev: int, bounded: bool,
                    uncertain: bool = False, span=None) -> str:
        """Render the summary's score line. Behavioural — the source-literal
        version of this guard had to be edited every time the condition was
        widened, which is a guard measuring its own wording."""
        from bob import i18n, output
        from bob.display import _summary_header_lines
        from bob.scoring import RiskLevel

        class _E:
            pass

        e = _E()
        e.score = score
        e.score_is_upper_bound = bounded
        e.score_is_uncertain = uncertain or bounded
        e.score_span = span or (score, score)
        e.blinded_domains = ["file_perms"] if (uncertain and not bounded) else []
        e.unverified = ["ssh.config_unreadable"] if e.score_is_uncertain else []
        e.level = e.effective_level = RiskLevel.MEDIUM
        e.risk_at_best = "medium"

        class _C:
            target = 0
            profile = "server"
            quiet = False

        i18n.init("en")
        output.init(no_color=True)
        lines = _summary_header_lines(e, None, _C(), i18n.t,
                                      profile_name="server", prev_score=prev)
        return lines[0][1]

    def test_the_delta_arrow_is_withheld_while_bounded(self):
        """"↑ +1" against a ceiling is the same false reassurance one level up."""
        line = self._score_line(score=8, prev=7, bounded=True)
        assert "≤" in line
        assert "↑" not in line and "↓" not in line

    def test_the_delta_arrow_is_withheld_while_the_direction_is_unknown(self):
        """v0.16.2 — a run whose blindness dropped a domain is precisely the one
        whose delta means nothing."""
        line = self._score_line(score=6, prev=7, bounded=False,
                                uncertain=True, span=(5, 7))
        assert "~" in line
        assert "↑" not in line and "↓" not in line

    def test_the_arrow_is_shown_on_a_fully_verified_run(self):
        """Polarity: withholding must not become permanent."""
        line = self._score_line(score=8, prev=7, bounded=False)
        assert "↑" in line and "≤" not in line and "~" not in line

    def test_both_json_fields_are_emitted(self):
        source = (_ROOT / "bob" / "json_output.py").read_text(encoding="utf-8")
        assert '"score_is_upper_bound": engine.score_is_upper_bound' in source
        assert '"unverified":      sorted(engine.unverified)' in source
