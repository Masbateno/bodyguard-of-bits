"""
T27 + T31 + T32 (v0.8.1) regression pins.

T27 — webhook payload Finding.detail + note parity.
The v0.8.0 T9 / v0.8.1 T11 format-parity sweep closed CSV + JSON + MD + HTML;
T27 closes the last sink — the webhook payload consumed by Grafana / Loki /
Slack / custom HTTP monitors. Generic payload now embeds ``detail`` + ``note``
per finding; the Slack payload concatenates ``detail`` inline with the
message so screen readers see the context.

T31 — Finding.nature coverage across warn/alert call sites.
Pre-T31 only 39 of 129 warn/alert call sites declared ``nature=`` — so
``bob --fix --apply`` (which filters on ``f.nature == "action"``) silently
skipped 88% of the actionable findings. v0.8.1 backfills nature on all
remaining sites with per-finding judgement (action / improvement / structural)
so the auto-fix path picks them up.

T32 — profile typo validation in _load_from_path.
Pre-T32 the loader accepted any dotted-identifier key in ``[overrides]``,
so a typo (``ssh.totally_not_a_key = info``) rode through without any
signal — users believed their policy applied but the override never matched
any emitted finding. v0.8.1 cross-checks each override key against the
catalogue of recognised keys (EXPLAIN_KEYS ∪ services.exposed.<id> ∪ literal
key= emit sites) and logs a warning for unrecognised entries.
"""

from __future__ import annotations

import io
import logging
import re
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ===========================================================================
# T27 — webhook payload format-parity for Finding.detail + Finding.note
# ===========================================================================

@pytest.fixture
def engine_with_rich_finding():
    """Engine carrying one ALERT finding with non-empty .detail and .note —
    the worst-case for format-parity testing."""
    from bob.scoring import ScoreEngine, Finding, FindingLevel
    e = ScoreEngine()
    e.findings.append(Finding(
        level=FindingLevel.ALERT,
        message="SSH password authentication enabled",
        detail="Brute-force surface — disable password auth or restrict to key-only.",
        nature="action",
        cmd="sudo sed -i 's/^#*PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config",
        note="Verify your key auth works before restarting sshd.",
        key="ssh.password_auth",
        template_vars={},
    ))
    e.finalize()
    return e


@pytest.fixture
def sys_info_stub():
    info = MagicMock()
    info.hostname = "testhost"
    return info


class TestT27GenericPayload:

    def test_generic_payload_finding_has_detail(self, engine_with_rich_finding, sys_info_stub):
        from bob.webhook import build_generic_payload
        payload = build_generic_payload(engine_with_rich_finding, sys_info_stub, "0.8.1")
        assert payload["findings"], "expected at least one finding in payload"
        f = payload["findings"][0]
        assert "detail" in f, f"webhook payload missing 'detail' field: {list(f.keys())}"
        assert "Brute-force surface" in f["detail"]

    def test_generic_payload_finding_has_note(self, engine_with_rich_finding, sys_info_stub):
        from bob.webhook import build_generic_payload
        payload = build_generic_payload(engine_with_rich_finding, sys_info_stub, "0.8.1")
        f = payload["findings"][0]
        assert "note" in f
        assert "Verify your key auth" in f["note"]

    def test_generic_payload_finding_without_detail_renders_empty_string(self, sys_info_stub):
        """Findings with no detail/note must still serialize cleanly — empty
        string rides through the payload schema without raising or surfacing
        ``None``."""
        from bob.scoring import ScoreEngine, Finding, FindingLevel
        from bob.webhook import build_generic_payload
        e = ScoreEngine()
        e.findings.append(Finding(
            level=FindingLevel.WARN,
            message="Bare WARN",
            detail="",
            nature="improvement",
            cmd="",
            note="",
            key="some.bare_warn",
            template_vars={},
        ))
        e.finalize()
        payload = build_generic_payload(e, sys_info_stub, "0.8.1")
        f = payload["findings"][0]
        assert f["detail"] == ""
        assert f["note"] == ""


class TestT27SlackPayload:

    def test_slack_finding_line_embeds_detail(self, engine_with_rich_finding, sys_info_stub):
        from bob.webhook import build_slack_payload
        payload = build_slack_payload(engine_with_rich_finding, sys_info_stub, "0.8.1")
        # Slack payload nests fields under attachments[0].fields[?]
        attachments = payload.get("attachments", [])
        assert attachments, "Slack payload missing attachments"
        fields = attachments[0].get("fields", [])
        findings_field = next((f for f in fields if f.get("title") == "Findings"), None)
        assert findings_field is not None, "no 'Findings' field in Slack payload"
        assert "Brute-force surface" in findings_field["value"], \
            "Slack payload dropped Finding.detail"

    def test_slack_finding_without_detail_renders_without_dash(self, sys_info_stub):
        """A finding without detail must NOT show a trailing ` — ` separator."""
        from bob.scoring import ScoreEngine, Finding, FindingLevel
        from bob.webhook import build_slack_payload
        e = ScoreEngine()
        e.findings.append(Finding(
            level=FindingLevel.WARN,
            message="Bare warn no detail",
            detail="",
            nature="improvement",
            cmd="",
            note="",
            key="some.bare",
            template_vars={},
        ))
        e.finalize()
        payload = build_slack_payload(e, sys_info_stub, "0.8.1")
        text = payload["attachments"][0]["fields"][0]["value"]
        assert " — " not in text, f"unexpected separator in {text!r}"


# ===========================================================================
# T31 — Finding.nature coverage on warn/alert call sites
# ===========================================================================

class TestT31NatureCoverage:
    """Invariant guard: every ``result.warn(...)`` / ``result.alert(...)`` /
    ``result.warn_with_deduction(...)`` / ``result.alert_with_deduction(...)``
    call site in ``bob/checks/`` MUST declare ``nature=`` so the auto-fix
    filter can route them. Pre-T31 (v0.8.0) 90 sites were uncategorised,
    silently dropping out of ``bob --fix --apply`` because that filter is
    ``f.nature == "action"``."""

    _REPO_ROOT = Path(__file__).resolve().parent.parent
    _CHECKS_DIR = _REPO_ROOT / "bob" / "checks"

    def _enumerate_call_sites(self):
        sites = []
        pattern = re.compile(
            r'result\.(warn|alert)(_with_deduction)?\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)',
            re.DOTALL,
        )
        for f in self._CHECKS_DIR.rglob("*.py"):
            src = f.read_text(encoding="utf-8")
            for m in pattern.finditer(src):
                body = m.group(3)
                ln   = src[:m.start()].count("\n") + 1
                sites.append((str(f.relative_to(self._REPO_ROOT)), ln, body))
        return sites

    def test_every_warn_alert_call_site_has_nature(self):
        sites = self._enumerate_call_sites()
        without = [
            (path, ln) for path, ln, body in sites
            if "nature=" not in body
        ]
        assert not without, (
            f"\n{len(without)} warn/alert call sites WITHOUT nature= "
            f"(T31 regression):\n"
            + "\n".join(f"  {p}:{ln}" for p, ln in without[:20])
        )

    def test_nature_values_are_canonical(self):
        """The only legal ``nature`` values are ``action`` / ``improvement`` /
        ``structural`` / empty string. A typo (e.g. ``"actoin"``) would slip
        past the auto-fix filter exactly like a missing ``nature``."""
        sites = self._enumerate_call_sites()
        canonical = {"action", "improvement", "structural", ""}
        wrong = []
        for path, ln, body in sites:
            m = re.search(r'nature\s*=\s*["\'](\w*)["\']', body)
            if m and m.group(1) not in canonical:
                wrong.append((path, ln, m.group(1)))
        assert not wrong, (
            f"\nNon-canonical nature= values found:\n"
            + "\n".join(f"  {p}:{ln} → {v!r}" for p, ln, v in wrong)
        )


class TestT31AutoFixFilterPicksUpFindings:
    """End-to-end: a finding flagged ``nature="action"`` MUST flow through
    ``bob.fixes`` filter. The pre-T31 dropout (88% of call sites silently
    invisible to ``--fix --apply``) regresses if a future contributor adds a
    new check without ``nature=`` AND the test_every_warn_alert_call_site_has_nature
    guard above is bypassed."""

    def test_fix_filter_finds_action_finding(self):
        from bob.scoring import ScoreEngine, Finding, FindingLevel
        e = ScoreEngine()
        e.findings.append(Finding(
            level=FindingLevel.WARN,
            message="m",
            detail="d",
            nature="action",
            cmd="sudo true",
            note="",
            key="some.action_key",
            template_vars={},
        ))
        e.finalize()
        actionable_with_cmd = [
            f for f in e.findings
            if f.nature == "action" and f.cmd
        ]
        assert len(actionable_with_cmd) == 1


# ===========================================================================
# T32 — profile typo validation warning path
# ===========================================================================

class TestT32ProfileTypoWarning:
    """The validator must warn about override keys that don't match any known
    finding key. Compat-preserving: the override is still applied so existing
    profiles with legacy entries don't break loading."""

    def setup_method(self):
        # Clear the LRU cache so each test sees a fresh catalogue
        from bob.profiles import _recognised_override_keys
        _recognised_override_keys.cache_clear()

    def _load_profile_with_overrides(self, override_lines: str):
        """Write a temp profile file with the supplied [overrides] block,
        load it, and return both the profile + captured log records."""
        from bob.profiles import _load_from_path
        content = (
            "[profile]\n"
            "name = t32_test\n"
            "extends = server\n"
            "description = T32 test\n"
            "\n"
            "[overrides]\n"
            + override_lines
        )
        tmpdir = Path(tempfile.mkdtemp())
        path = tmpdir / "t32_test.conf"
        path.write_text(content, encoding="utf-8")
        # Capture warnings emitted by bob.profiles logger
        records = []
        logger = logging.getLogger("bob.profiles")
        handler = logging.Handler()
        handler.emit = records.append
        logger.addHandler(handler)
        try:
            profile = _load_from_path(path, depth=0)
        finally:
            logger.removeHandler(handler)
        return profile, [r.getMessage() for r in records]

    def test_typo_key_emits_warning(self):
        p, msgs = self._load_profile_with_overrides(
            "ssh.totally_not_a_key = info\n"
        )
        assert any("totally_not_a_key" in m and "not recognised" in m for m in msgs), (
            f"expected typo warning, got: {msgs}"
        )

    def test_typo_override_still_loaded_for_compat(self):
        """The typo override is loaded (not dropped) so users with legacy
        profiles see their config preserved while getting the warning."""
        p, _ = self._load_profile_with_overrides(
            "ssh.totally_not_a_key = info\n"
        )
        assert p.overrides.get("ssh.totally_not_a_key") == "info"

    def test_legitimate_override_no_warning(self):
        """A known key (ssh.password_auth ∈ EXPLAIN_KEYS) must NOT warn."""
        p, msgs = self._load_profile_with_overrides(
            "ssh.password_auth = info\n"
        )
        assert not any("not recognised" in m for m in msgs), (
            f"expected no warning for legit key, got: {msgs}"
        )

    def test_dynamic_service_key_no_warning(self):
        """``services.exposed.<svc_id>`` keys (the dynamic ones emitted by
        services.py for every registered service) must be recognised — they
        are validly used in desktop.conf / workstation.conf."""
        p, msgs = self._load_profile_with_overrides(
            "services.exposed.avahi = info\n"
            "services.exposed.ollama = info\n"
        )
        assert not any("not recognised" in m for m in msgs), (
            f"expected no warning for dynamic service keys, got: {msgs}"
        )

    def test_invalid_section_name_warns(self):
        """A completely fabricated section.key combination warns too."""
        p, msgs = self._load_profile_with_overrides(
            "non_existent_section.foo = warn\n"
        )
        assert any("non_existent_section.foo" in m and "not recognised" in m for m in msgs)


class TestT32RecognisedKeysCatalogueSanity:
    """The recognised-keys catalogue must include enough entries that the
    validator doesn't false-positive on legitimate profile entries."""

    def test_catalogue_includes_explain_keys(self):
        from bob.profiles import _recognised_override_keys
        _recognised_override_keys.cache_clear()
        from bob.explain import EXPLAIN_KEYS
        cat = _recognised_override_keys()
        assert cat is not None
        for k in EXPLAIN_KEYS[:10]:
            assert k in cat, f"EXPLAIN_KEYS entry {k!r} missing from catalogue"

    def test_catalogue_includes_dynamic_service_keys(self):
        from bob.profiles import _recognised_override_keys
        _recognised_override_keys.cache_clear()
        from bob.registry import ServiceRegistry
        cat = _recognised_override_keys()
        for svc in list(ServiceRegistry.load().all())[:5]:
            assert f"services.exposed.{svc.id}" in cat, \
                f"services.exposed.{svc.id} missing from catalogue"

    def test_existing_builtin_profiles_have_no_typo_warnings(self):
        """Every override key shipped in the built-in profiles (server /
        desktop / container / workstation) MUST be in the catalogue — if any
        warns, either the catalogue or the profile has drifted."""
        from bob.profiles import _recognised_override_keys, _BUILTIN_PROFILES_DIR
        import configparser
        _recognised_override_keys.cache_clear()
        cat = _recognised_override_keys()
        assert cat is not None
        for conf in _BUILTIN_PROFILES_DIR.glob("*.conf"):
            cp = configparser.ConfigParser(allow_no_value=True, inline_comment_prefixes=("#",))
            cp.read(str(conf), encoding="utf-8")
            if not cp.has_section("overrides"):
                continue
            for key, _ in cp.items("overrides"):
                key = key.strip().lower()
                assert key in cat, (
                    f"profile {conf.name} declares override {key!r} but the catalogue "
                    f"doesn't include it — either the profile has a typo or the "
                    f"catalogue needs widening."
                )
