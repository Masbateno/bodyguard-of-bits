"""v0.12.1 — all domains displayed, inactive ones annotated with the reason.

The Domain Scores block shows all domains. An inactive domain (no OK/WARN/ALERT
finding) is rendered without a score and tagged with WHY it is inactive — never
counted in the global average. See [[project_v0121_domain_display]].

v0.20.0 — the score domains ARE the six display groups (firewall_network,
exposure_services, access_control, system_hardening, health_resilience,
detection). A domain is PROFILE_SKIPPED / FILTERED only when *every* section
that feeds it is skipped / filtered, so these tests skip a whole group's
section set (detection: auditd/fail2ban/clamav/file_integrity/rootkit).
"""

from __future__ import annotations

import pytest

from types import SimpleNamespace

from bob.scoring import ScoreEngine, CheckResult
from bob.profiles import AuditProfile
from bob.domain_scores import (
    DOMAINS,
    compute_domain_scores,
    compute_global_from_domains,
    active_domains_from_engine,
    domain_inactive_reason,
    render_domain_scores,
    REASON_INFO_ONLY,
    REASON_PROFILE_SKIPPED,
    REASON_FILTERED,
    REASON_NOT_INSTALLED,
)


def _config(check_only=(), skip_checks=()):
    """Minimal stand-in for AuditConfig (the only attrs _section_enabled reads)."""
    return SimpleNamespace(check_only=list(check_only), skip_checks=list(skip_checks))


@pytest.fixture(autouse=True)
def _mono():
    """Force monochrome so rendered strings carry no ANSI codes."""
    from bob import output
    output.init(no_color=True)
    yield
    output.init(no_color=False)


def _engine(findings):
    """Build a finalized engine from (level, key) findings.

    level ∈ {"ok", "info", "warn", "alert"}.
    """
    engine = ScoreEngine()
    r = CheckResult()
    for level, key in findings:
        getattr(r, level)(message=f"{key} msg", key=key)
    engine.apply(r)
    engine.finalize()
    return engine


# ---------------------------------------------------------------------------
# domain_inactive_reason — the 3-way classification
# ---------------------------------------------------------------------------


# The five sections that feed the detection domain — skipping all of them makes
# the whole domain profile-skipped / filtered under the v0.20.0 mirror.
_DETECTION_SECTIONS = {"auditd", "fail2ban", "clamav", "file_integrity", "rootkit"}


class TestInactiveReason:
    def test_info_only_domain(self):
        """A domain with only INFO notices = assessed, no action needed."""
        eng = _engine([("info", "updates.cache_age")])   # → health_resilience
        assert "health_resilience" not in active_domains_from_engine(eng)
        assert domain_inactive_reason("health_resilience", eng) == REASON_INFO_ONLY

    def test_profile_skipped_domain(self):
        """A profile skipping every detection section = not assessed."""
        eng = _engine([("ok", "ssh.ok")])  # no detection findings
        prof = AuditProfile(name="container", skip_sections=set(_DETECTION_SECTIONS))
        assert "detection" not in active_domains_from_engine(eng)
        assert domain_inactive_reason("detection", eng, prof) == REASON_PROFILE_SKIPPED

    def test_not_installed_domain(self):
        """Detection sections ran (nothing skipped) but found nothing = not installed."""
        eng = _engine([("ok", "ssh.ok")])  # no detection findings
        prof = AuditProfile(name="desktop", skip_sections=set())
        assert "detection" not in active_domains_from_engine(eng)
        assert domain_inactive_reason("detection", eng, prof) == REASON_NOT_INSTALLED

    def test_info_beats_profile_skip(self):
        """If a domain emitted INFO, it was assessed → INFO_ONLY wins over skip."""
        eng = _engine([("info", "updates.cache_age")])
        prof = AuditProfile(name="x", skip_sections={"updates"})
        assert domain_inactive_reason("health_resilience", eng, prof) == REASON_INFO_ONLY


class TestFilteredReason:
    """A-fix (v0.12.1): --check / --skip must not be mislabelled 'not installed'."""

    def test_check_excludes_domain(self):
        """--check=ssh runs only the ssh section → every other domain is FILTERED."""
        eng = _engine([("ok", "ssh.ok")])
        cfg = _config(check_only=["ssh"])
        for dom in ("exposure_services", "health_resilience", "detection",
                    "firewall_network"):
            assert domain_inactive_reason(dom, eng, profile=None, config=cfg) == REASON_FILTERED

    def test_skip_excludes_domain(self):
        """--skip covering every detection section → detection is FILTERED."""
        eng = _engine([("ok", "ssh.ok")])
        cfg = _config(skip_checks=sorted(_DETECTION_SECTIONS))
        assert domain_inactive_reason("detection", eng, profile=None, config=cfg) == REASON_FILTERED

    def test_profile_skip_still_wins_when_no_filter(self):
        """With config present but no --check/--skip, a profile-skipped domain
        stays PROFILE_SKIPPED (the filter branch must not swallow it)."""
        eng = _engine([("ok", "ssh.ok")])
        cfg = _config()  # no check/skip
        prof = AuditProfile(name="container", skip_sections=set(_DETECTION_SECTIONS))
        assert domain_inactive_reason("detection", eng, prof, cfg) == REASON_PROFILE_SKIPPED

    def test_absent_service_with_config_still_not_installed(self):
        """Detection ran (nothing skipped) with a config and no filter = NOT_INSTALLED."""
        eng = _engine([("ok", "ssh.ok")])
        cfg = _config()
        prof = AuditProfile(name="desktop", skip_sections=set())
        assert domain_inactive_reason("detection", eng, prof, cfg) == REASON_NOT_INSTALLED

    def test_check_filtered_render_text(self):
        """The rendered line for a --check-excluded domain says check/skip, not installed."""
        eng = _engine([("ok", "ssh.ok"), ("ok", "firewall.ok")])
        scores, _ = compute_domain_scores(eng)
        cfg = _config(check_only=["ssh"])
        lines = render_domain_scores(scores, t=None, engine=eng, profile=None, config=cfg)
        text = "\n".join(lines)
        det_line = next(l for l in text.splitlines() if "Threat Detection" in l)
        assert "--check/--skip" in det_line
        assert "not installed" not in det_line


# ---------------------------------------------------------------------------
# render_domain_scores(engine=…) — all 7 shown, reasons annotated
# ---------------------------------------------------------------------------


def _mixed_engine():
    return _engine([
        ("warn", "ssh.x11_forwarding"),   # access_control active, deduction
        ("warn", "hardening.firmware"),   # system_hardening active, deduction
        ("ok", "firewall.ok"),            # firewall_network active
        ("info", "updates.cache_age"),    # health_resilience → INFO only
        # no exposure_services findings → not installed
        # no detection findings → profile-skipped (container skips them)
    ])


class TestRenderAllDomains:
    def _text(self, profile):
        eng = _mixed_engine()
        scores, _ = compute_domain_scores(eng)
        lines = render_domain_scores(scores, t=None, engine=eng, profile=profile)
        return "\n".join(lines)

    def test_all_six_labels_present(self):
        text = self._text(AuditProfile(name="container",
                                       skip_sections=set(_DETECTION_SECTIONS)))
        for label in ("Firewall & Network", "Exposure & Services", "Access Control",
                      "System Hardening", "Health & Resilience", "Threat Detection"):
            assert label in text, f"missing domain label: {label}"

    def test_active_domain_shows_score(self):
        text = self._text(AuditProfile(name="container",
                                       skip_sections=set(_DETECTION_SECTIONS)))
        ac_line = next(l for l in text.splitlines() if "Access Control" in l)
        assert "/10" in ac_line

    def test_info_only_domain_shows_reason_no_score(self):
        text = self._text(AuditProfile(name="container",
                                       skip_sections=set(_DETECTION_SECTIONS)))
        hr_line = next(l for l in text.splitlines() if "Health & Resilience" in l)
        assert "no action needed" in hr_line
        assert "/10" not in hr_line

    def test_profile_skipped_label(self):
        text = self._text(AuditProfile(name="container",
                                       skip_sections=set(_DETECTION_SECTIONS)))
        det_line = next(l for l in text.splitlines() if "Threat Detection" in l)
        assert "not assessed (container profile)" in det_line
        assert "not installed" not in det_line

    def test_absent_service_not_installed(self):
        text = self._text(AuditProfile(name="desktop", skip_sections=set()))
        exp_line = next(l for l in text.splitlines() if "Exposure & Services" in l)
        assert "not installed" in exp_line


# ---------------------------------------------------------------------------
# Invariants the user required: showing more domains must NOT change the score
# ---------------------------------------------------------------------------


class TestAverageUnaffected:
    def test_inactive_domains_excluded_from_average(self):
        """Inactive domains (score 10) must not pull the average up."""
        eng = _mixed_engine()
        scores, _ = compute_domain_scores(eng)
        active = active_domains_from_engine(eng)
        glob = compute_global_from_domains(scores, active)
        # average is over active domains only (access_control / system_hardening /
        # firewall_network); the inactive 10/10 domains are not counted.
        assert "exposure_services" not in active
        assert "detection" not in active
        assert "health_resilience" not in active
        active_scores = [scores[d]["score"] for d in DOMAINS if d in active]
        assert glob == round(sum(active_scores) / len(active_scores))


class TestFixBProfileNotPersistedWhenInvalid:
    """B-fix (v0.12.1): `--profile=typo` must NOT be saved to config (it would
    overwrite the user's real saved profile with a name that resolves nowhere)."""

    def test_unknown_profile_resolves_to_a_different_name(self):
        from bob.profiles import load_profile
        # the fix's precondition: an unknown name resolves to a fallback whose
        # .name differs from what was requested.
        assert load_profile("definitely-not-a-profile").name != "definitely-not-a-profile"

    def test_set_profile_is_guarded_in_source(self):
        """Static guard: in _run(), user_config.set_profile(...) must be gated by
        `not _profile_not_found` so an invalid --profile is never persisted."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "bob" / "__main__.py").read_text(encoding="utf-8")
        body = src[src.index("def _run("):]
        i_flag = body.index("_profile_not_found")
        i_set  = body.index("user_config.set_profile(")
        assert i_flag < i_set, "set_profile must come after the not-found check"
        guard = body[body.rindex("if ", 0, i_set):i_set]
        assert "not _profile_not_found" in guard, (
            "set_profile must be guarded by `and not _profile_not_found`"
        )


class TestFixCProfileValidatedBeforeRoot:
    """C-fix (v0.12.1): `bob --profile=typo` without sudo reports the unknown
    profile before demanding root (the test process is non-root)."""

    def test_unknown_profile_warns_then_root_error(self, capsys):
        from bob.__main__ import main, EXIT_ERROR
        rc = main(["--profile=definitely-not-real", "--offline"])
        err = capsys.readouterr().err
        assert rc == EXIT_ERROR
        assert "definitely-not-real" in err           # the bad name is surfaced
        assert err.index("definitely-not-real") < err.index("must be run as root")

    def test_prewarn_precedes_root_in_source(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "bob" / "__main__.py").read_text(encoding="utf-8")
        body = src[src.index("def _run("):]
        i_prewarn = body.index("_profile_prewarned")
        i_root = body.index("require_root()", i_prewarn)
        assert i_prewarn < i_root, "profile pre-warn must run before require_root()"


class TestFixENaivePolish:
    """E-fix (v0.12.1): --english, --output=html, case-insensitive --check/--explain."""

    def test_english_flag(self):
        from bob.cli import parse_args
        assert parse_args(["--english"]).lang == "en"

    def test_output_html_accepted(self):
        from bob.cli import parse_args
        assert parse_args(["--output=html"]).html_mode is True
        assert parse_args(["--output", "html"]).html_mode is True

    def test_output_format_case_insensitive(self):
        from bob.cli import parse_args
        assert parse_args(["--output=HTML"]).html_mode is True
        assert parse_args(["--output=JSON"]).json_mode is True

    def test_check_tokens_lowercased(self):
        from bob.cli import parse_args
        assert parse_args(["--check=SSH,Samba"]).check_only == frozenset({"ssh", "samba"})

    def test_skip_tokens_lowercased(self):
        from bob.cli import parse_args
        assert parse_args(["--skip=DISK"]).skip_checks == frozenset({"disk"})

    def test_explain_key_lowercased(self):
        from bob.cli import parse_args
        assert parse_args(["--explain=SSH.PASSWORD_AUTH"]).explain_key == "ssh.password_auth"
        assert parse_args(["--explain", "LIST"]).explain_key == "list"

    def test_output_json_full_complete_alias(self):
        """ADV-D2 (v0.12.1): --output=json-full mirrors --format=json-full."""
        from bob.cli import parse_args
        a = parse_args(["--output=json-full"])
        b = parse_args(["--format=json-full"])
        assert (a.json_mode, a.json_full) == (True, True)
        assert (a.json_mode, a.json_full) == (b.json_mode, b.json_full)


class TestADVB1MarkdownHtmlDomains:
    """ADV-B1 (v0.12.1): markdown + HTML reports now carry the domain breakdown."""

    def _engine(self):
        return _engine([
            ("ok", "ssh.ok"), ("ok", "firewall.ok"),
            ("warn", "hardening.firmware"),
            ("info", "updates.cache_age"),     # health_resilience inactive: info_only
        ])

    def test_markdown_has_domain_section(self):
        from bob.markdown_output import build_markdown_output
        from bob.report import SystemInfo
        si = SystemInfo(os_name="x", hostname="h", kernel="k", ufw_version="u",
                        iptables_version="i", nftables_version="n", user="t",
                        config_path="/dev/null", language="en", version="0")
        prof = AuditProfile(name="container", skip_sections=set(_DETECTION_SECTIONS))
        md = build_markdown_output(self._engine(), si, t=None, profile=prof, config=_config())
        assert "Domain Scores" in md
        assert "Access Control" in md and "Threat Detection" in md
        assert "no action needed" in md          # health_resilience info_only
        assert "not assessed (container profile)" in md   # detection profile-skipped

    def test_html_has_domain_section(self):
        from bob.html_output import build_html_output
        from bob.report import SystemInfo
        si = SystemInfo(os_name="x", hostname="h", kernel="k", ufw_version="u",
                        iptables_version="i", nftables_version="n", user="t",
                        config_path="/dev/null", language="en", version="0")
        prof = AuditProfile(name="container", skip_sections=set(_DETECTION_SECTIONS))
        html = build_html_output(self._engine(), si, t=None, profile=prof, config=_config())
        assert "Domain Scores" in html
        assert "<td>Threat Detection</td>" in html
        assert "not assessed (container profile)" in html


class TestLegacyRenderUnchanged:
    def test_without_engine_inactive_hidden(self):
        """engine=None keeps the legacy behaviour: inactive domains hidden."""
        eng = _mixed_engine()
        scores, _ = compute_domain_scores(eng)
        active = active_domains_from_engine(eng)
        lines = render_domain_scores(scores, t=None, active_domains=active)
        text = "\n".join(lines)
        assert "Threat Detection" not in text   # inactive → hidden (legacy)
        assert "Access Control" in text          # active → shown
