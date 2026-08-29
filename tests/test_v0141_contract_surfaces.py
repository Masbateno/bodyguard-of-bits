"""
v0.14.1 — third stress campaign: contract surfaces and reporting completeness.

Rounds 1 and 2 attacked I/O and resilience. Round 3 went after what the tool
*says*: the i18n key space, the scoring invariants, and whether a report tells
you what produced it.

  A — every dynamically-built i18n key must resolve in BOTH locales
  B — scoring invariants hold across random engine states
  C — the active audit profile must appear in every report format
  D — --profile persistence must be documented where the user looks
  E — README usage examples must be factually true
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
LOCALES = {l: json.loads((REPO / "bob" / "locales" / f"{l}.json").read_text(encoding="utf-8"))
           for l in ("en", "fr")}


def _has(key: str, data: dict) -> bool:
    cur = data
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    return True


# ---------------------------------------------------------------------------
# A — dynamic i18n keys
# ---------------------------------------------------------------------------

class TestDynamicI18nKeysResolve:
    """``t()`` returns ``[key]`` for a missing key — the v0.9.1 hotfix class.

    Literal keys are covered by the locale linter, but the keys built at
    runtime (``t(f"sections.{section}")`` and friends) are not: a new section
    added without a locale entry would print ``[sections.foo]`` to the
    operator. That path is now load-bearing — ``runner._degrade_section``
    resolves ``sections.<name>`` for whichever section failed.
    """

    def test_every_runner_section_and_group_has_a_label(self):
        src = (REPO / "bob" / "runner.py").read_text()
        names = set(re.findall(r'_sec\(\s*"([a-z_]+)"', src))
        names |= set(re.findall(r'emit_section\(\s*"([a-z_]+)"', src))
        groups = set(re.findall(r'emit_group\(\s*"([a-z_]+)"', src))
        assert names and groups, "the extraction itself must find something"
        missing = [(l, f"sections.{n}") for n in sorted(names)
                   for l in LOCALES if not _has(f"sections.{n}", LOCALES[l])]
        missing += [(l, f"groups.{g}") for g in sorted(groups)
                    for l in LOCALES if not _has(f"groups.{g}", LOCALES[l])]
        assert not missing, f"these would render as [bracketed] to the operator: {missing}"

    def test_every_domain_has_a_label(self):
        from bob.domain_scores import DOMAINS
        missing = [(l, f"domain_scores.{d}") for d in DOMAINS
                   for l in LOCALES if not _has(f"domain_scores.{d}", LOCALES[l])]
        assert not missing, missing

    def test_every_risk_level_has_a_label(self):
        from bob.scoring import RiskLevel
        missing = [(l, f"scoring.level.{r.value}") for r in RiskLevel
                   for l in LOCALES if not _has(f"scoring.level.{r.value}", LOCALES[l])]
        assert not missing, missing

    def test_every_explain_key_has_title_why_how(self):
        from bob.explain import EXPLAIN_KEYS
        missing = [(l, f"explain.{k}.{part}")
                   for k in EXPLAIN_KEYS for part in ("title", "why", "how")
                   for l in LOCALES if not _has(f"explain.{k}.{part}", LOCALES[l])]
        assert not missing, f"{len(missing)} missing, e.g. {missing[:5]}"

    def test_every_registered_service_has_risk_text(self):
        from bob.registry import ServiceRegistry
        ids = [s.label.lower().replace(" ", "_").replace("/", "_")
               .replace("(", "").replace(")", "") for s in ServiceRegistry.load().all()]
        assert ids, "the registry must not be empty"
        missing = [(l, f"service_risk.{i}.{part}")
                   for i in ids for part in ("level", "threat")
                   for l in LOCALES if not _has(f"service_risk.{i}.{part}", LOCALES[l])]
        assert not missing, f"{len(missing)} missing, e.g. {missing[:5]}"


# ---------------------------------------------------------------------------
# B — scoring invariants
# ---------------------------------------------------------------------------

class TestScoringInvariants:
    """Property-based: the score is the product, and it must never lie."""

    PREFIXES = ["ssh", "samba", "file_perms", "updates", "hardening", "disk",
                "services", "ports", "rootkit", "clamav", "firewall", "fail2ban"]

    def _random_engine(self, rnd):
        from bob.scoring import CheckResult, FindingLevel, ScoreEngine
        eng = ScoreEngine()
        expect = dict.fromkeys(FindingLevel, 0)
        ignore = set()
        if rnd.random() < 0.3:
            ignore = {f"{rnd.choice(self.PREFIXES)}.k{rnd.randint(0, 3)}"}
            eng.ignore_keys = frozenset(ignore)
        for _ in range(rnd.randint(0, 6)):
            r = CheckResult()
            for _ in range(rnd.randint(0, 4)):
                lvl = rnd.choice(list(FindingLevel))
                key = f"{rnd.choice(self.PREFIXES)}.k{rnd.randint(0, 3)}"
                r.add_finding(level=lvl, message="m", key=key)
                if key not in ignore:
                    expect[lvl] += 1
            for _ in range(rnd.randint(0, 3)):
                r.add_deduction(reason="r", points=rnd.randint(0, 6),
                                key=f"{rnd.choice(self.PREFIXES)}.k{rnd.randint(0, 3)}")
            if rnd.random() < 0.15:
                r.set_cap(maximum=rnd.randint(0, 10), reason="cap",
                          key=f"{rnd.choice(self.PREFIXES)}.c")
            eng.apply(r)
        eng.finalize()
        return eng, expect

    def test_invariants_hold_over_random_states(self):
        from bob.domain_scores import (MAX_SCORE, apply_domain_score_override,
                                       compute_domain_scores, key_to_domain)
        from bob.scoring import FindingLevel
        rnd = random.Random(20260830)
        for i in range(400):
            eng, expect = self._random_engine(rnd)
            assert 0 <= eng.raw_score <= MAX_SCORE, i
            assert eng.alert_count == expect[FindingLevel.ALERT], i
            assert eng.warn_count == expect[FindingLevel.WARN], i
            assert eng.info_count == expect[FindingLevel.INFO], i
            assert all(d.points >= 0 for d in eng.breakdown), i
            apply_domain_score_override(eng)
            assert 0 <= eng.score <= MAX_SCORE, i
            # F1 (v0.12.0): 10/10 is reserved for an audit with nothing to fix
            if eng.raw_score < MAX_SCORE:
                assert eng.score <= MAX_SCORE - 1, f"iteration {i}: 10/10 despite a deduction"
            scores, _ = compute_domain_scores(eng)
            for dom, info in scores.items():
                assert 0 <= info["score"] <= MAX_SCORE, (i, dom)
            if eng.cap_info and eng.cap_info.key:
                cd = key_to_domain(eng.cap_info.key)
                if cd in scores:
                    assert scores[cd]["score"] <= eng.cap_info.maximum, (i, cd)

    def test_ignored_findings_do_not_reach_the_counts(self):
        from bob.scoring import CheckResult, FindingLevel, ScoreEngine
        eng = ScoreEngine()
        eng.ignore_keys = frozenset({"ssh.k"})
        r = CheckResult()
        r.add_finding(level=FindingLevel.ALERT, message="m", key="ssh.k")
        r.add_finding(level=FindingLevel.ALERT, message="m", key="ssh.other")
        eng.apply(r)
        eng.finalize()
        assert eng.alert_count == 1


# ---------------------------------------------------------------------------
# C — the report must say what produced it
# ---------------------------------------------------------------------------

class TestActiveProfileIsReported:
    """Since v0.14.0 the profile changes severities, warning_count and the exit
    code — yet it appeared ONLY in the terminal text output. Two JSON payloads
    for the same host could differ in their counts with nothing explaining why,
    and an archived Markdown/HTML report did not say what it was audited
    against."""

    def test_profile_is_a_declared_v3_schema_key(self):
        from bob.json_output import SCHEMA_V3_REQUIRED_KEYS
        assert "profile" in SCHEMA_V3_REQUIRED_KEYS

    def test_markdown_and_html_declare_the_profile_field(self):
        for mod, key in (("markdown_output", "markdown_output.field_profile"),
                         ("html_output", "html_output.field_profile")):
            src = (REPO / "bob" / f"{mod}.py").read_text()
            assert "field_profile" in src, f"{mod} must render the profile"
            for lang in LOCALES:
                assert _has(key, LOCALES[lang]), f"{lang}: missing {key}"

    def test_builders_fall_back_to_server_when_no_profile(self):
        """A None profile must render 'server', never an empty cell."""
        for mod in ("json_output", "markdown_output", "html_output"):
            src = (REPO / "bob" / f"{mod}.py").read_text()
            assert 'or "server"' in src or "or 'server'" in src, (
                f"{mod} must default the profile name to 'server'")


# ---------------------------------------------------------------------------
# D + E — documentation must match behaviour
# ---------------------------------------------------------------------------

class TestDocumentationMatchesBehaviour:
    """A one-off ``-p container`` silently became the operator's permanent
    default: ``__main__`` persists a valid profile via ``set_profile``. Real
    since v0.12.1, documented nowhere the user looks — it caught the stress
    campaign itself."""

    def test_profile_persistence_still_happens(self):
        """Guard the premise: if persistence is ever removed, the doc must go."""
        src = (REPO / "bob" / "__main__.py").read_text()
        assert "user_config.set_profile(config.profile)" in src

    def test_help_documents_the_persistence(self):
        """Assert on the RENDERED help, not the source — that is what the user reads."""
        import io
        from contextlib import redirect_stdout

        from bob import i18n
        from bob.cli import print_help
        i18n.init("en")
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_help(i18n.t, "0.14.1")
        rendered = buf.getvalue()
        i = rendered.index("--profile=NAME")
        window = rendered[i:i + 300]
        assert "SAVED" in window or "saved" in window, (
            "--help must tell the user that -p persists as their default; got:\n"
            + window[:200])

    @pytest.mark.parametrize("readme", ["README.md", "README_FR.md"])
    def test_readme_examples_use_flags_that_exist(self, readme):
        from bob.cli import CLIError, parse_args
        text = (REPO / readme).read_text(encoding="utf-8")
        bad = []
        for line in text.splitlines():
            m = re.match(r"^(?:sudo )?bob ([^#]*?)\s*(?:#.*)?$", line.strip())
            if not m or not m.group(1).strip():
                continue
            argv = m.group(1).split()
            # stop at the first shell operator — "bob --format json > out.json"
            # is a shell redirection, not an option BOB ever sees
            for stop in (">", ">>", "|", "&&", ";", "2>"):
                if stop in argv:
                    argv = argv[:argv.index(stop)]
            try:
                parse_args(argv)
            except CLIError as exc:
                bad.append((line.strip(), str(exc)[:60]))
        assert not bad, f"README examples that do not parse: {bad}"

    @pytest.mark.parametrize("readme,word", [("README.md", "french"),
                                             ("README_FR.md", "français")])
    def test_the_french_example_actually_selects_french(self, readme, word):
        """``sudo bob -d  # French output`` shipped in both READMEs. ``-d`` is
        ``--detailed`` (save a report), not a language flag."""
        text = (REPO / readme).read_text(encoding="utf-8")
        offenders = []
        for line in text.splitlines():
            s = line.strip()
            if not s.startswith(("bob ", "sudo bob ")) or "#" not in s:
                continue
            cmd, _, comment = s.partition("#")
            if word in comment.lower():
                if not any(f in cmd for f in ("--french", "--lang", "-L")):
                    offenders.append(s)
        assert not offenders, (
            f"example claims {word} output without a language flag: {offenders}")
