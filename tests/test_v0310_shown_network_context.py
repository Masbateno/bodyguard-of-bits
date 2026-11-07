"""
v0.31.0 — a host with a public IPv6 address is not reported "behind NAT".

``detect_network_context`` answers "local" as soon as the IPv4 gateway is
private, before it looks at IPv6. Behind a dual-stack home router — IPv4 NAT,
a global IPv6 address on every host — the report said "Local network only",
"behind NAT / no direct public IP" and tagged each service's risk "• LAN".

Measured on a real Kali behind a Freebox with its IPv6 firewall off: a phone on
mobile data, outside the home prefix, reached the host's ``[::]:8080`` (592
attempts logged). Whether the router filters inbound IPv6 cannot be seen from
the host, so the three labels now say what is known. Display only: the context
the checks score with stays "local" (treating it as unknown is for 0.31.1).
"""

from __future__ import annotations

import ast
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from bob import i18n, output
from bob.checks.ports import PortsSnapshot
from bob.display import build_risk_context_entries, print_exposure
from bob.exposure import compute_exposure
from bob.scoring import ScoreEngine
from bob.sysinfo import shown_network_context

_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def fr():
    i18n.init("fr")
    yield i18n.t
    i18n.init("en")


class TestTheShownContext:

    def test_local_with_a_global_ipv6_is_not_local_only(self):
        assert shown_network_context("local", True) == "local_v6"

    @pytest.mark.parametrize("ctx, v6, shown", [
        ("local", False, "local"),
        ("public", True, "public"),
        ("ddns", True, "ddns"),
    ])
    def test_the_other_cases_are_unchanged(self, ctx, v6, shown):
        assert shown_network_context(ctx, v6) == shown


def _glance(t, ctx: str) -> str:
    items = compute_exposure(ScoreEngine(), PortsSnapshot(ports=[], ufw_rules=[], ss_output=""), ctx,
                             fw_active=False, fw_policy="unknown", t=t)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        print_exposure(items, t, output)
    return out.getvalue()


class TestTheRenderedLabels:

    def test_the_glance_names_the_public_ipv6(self, fr):
        text = _glance(fr, "local_v6")
        assert "adresse IPv6 publique directe" in text
        assert "pas d'IP publique directe" not in text
        assert "⚠" in text.split("Exposition internet")[0].splitlines()[-1]

    def test_the_glance_without_ipv6_still_says_nat(self, fr):
        """Polarity twin: a host with no global IPv6 keeps the old line."""
        assert "derrière NAT / pas d'IP publique directe" in _glance(fr, "local")

    def test_the_summary_label_resolves(self, fr):
        label = fr("scoring.context.local_v6")
        assert "IPv6 publique" in label and not label.startswith("[")

    @pytest.mark.parametrize("lang", ["en", "fr"])
    @pytest.mark.parametrize("ctx", ["local", "local_v6", "public", "ddns"])
    def test_every_context_fits_the_summary_box(self, lang, ctx):
        """The header lines of the box are not wrapped: measured on Kali, the
        first label ran past the right border."""
        from bob.output import _ANSI_ESCAPE_RE, _visual_width, print_summary_box
        i18n.init(lang)
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                print_summary_box([(i18n.t("scoring.network_context"),
                                    i18n.t(f"scoring.context.{ctx}"))])
        finally:
            i18n.init("en")
        rows = [r for r in out.getvalue().splitlines() if r.strip()]
        widths = {_visual_width(_ANSI_ESCAPE_RE.sub("", r)) for r in rows}
        assert len(widths) == 1, f"{lang}/{ctx}: the box is ragged: {rows}"

    def test_the_risk_context_is_not_tagged_lan(self, fr):
        snap = SimpleNamespace(
            is_active=True, installed=True,
            service=SimpleNamespace(label="SSH Server", is_high_or_critical=True),
        )
        shown = build_risk_context_entries([snap], "fr", fr, network_context="local_v6")
        local = build_risk_context_entries([snap], "fr", fr, network_context="local")
        assert shown and "LAN" not in shown[0]["level"]
        assert local and local[0]["level"].endswith("• LAN")


def _calls(path: str, name: str) -> list[ast.Call]:
    tree = ast.parse((_ROOT / path).read_text(encoding="utf-8"))
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and ast.unparse(n.func).endswith(name)]


class TestTheWiring:
    """The labels are drawn from the shown context; the score is not."""

    def test_the_terminal_lan_tag_reads_the_shown_context(self):
        (call,) = _calls("bob/runner.py", "display_risk_context")
        is_local = next(k.value for k in call.keywords if k.arg == "is_local")
        assert "shown_network_context" in ast.unparse(is_local)

    def test_the_summary_is_given_the_shown_context(self):
        (call,) = _calls("bob/__main__.py", "print_audit_summary")
        assert ast.unparse(call.args[1]) == "shown_context"

    def test_the_glance_is_given_the_shown_context(self):
        (call,) = _calls("bob/__main__.py", "compute_exposure")
        assert ast.unparse(call.args[2]) == "shown_context"

    def test_the_report_risk_context_is_given_the_shown_context(self):
        (call,) = _calls("bob/__main__.py", "build_risk_context_entries")
        kw = next(k.value for k in call.keywords if k.arg == "network_context")
        assert ast.unparse(kw) == "shown_context"

    def test_the_checks_still_score_with_the_detected_context(self):
        (call,) = _calls("bob/__main__.py", "run_checks")
        assert "network_context" in [ast.unparse(a) for a in call.args]
