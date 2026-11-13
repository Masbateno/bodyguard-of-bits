"""v0.35.0 — the score breakdown grouped by domain.

A field audit of the operator's desktop (12 November 2026) read “Security
score ≤ 9/10” above a breakdown of −1, −1, −2, −1, −1 and took the headline
for 10 − 6: the headline is the average of the six domains, and each
deduction lowers its own domain only (the tutorial says so; the box did not).
The deductions are now listed under their domain, in the domains' order.
"""

from __future__ import annotations

from types import SimpleNamespace as N

from bob import display
from bob.domain_scores import group_by_domain
from tests.helpers import _t

_DEDS = [N(points=1, reason="su", key="user_accounts.su_unrestricted", context="local"),
         N(points=1, reason="disk", key="disk_encryption.root_unencrypted", context="local"),
         N(points=2, reason="updates", key="updates.security_pending", context="local"),
         N(points=1, reason="auditd", key="auditd.no_rules", context="local"),
         N(points=1, reason="clamav", key="clamav.socket_open_to_all", context="local")]


def test_grouped_in_the_domains_order():
    shuffled = [_DEDS[4], _DEDS[2], _DEDS[0], _DEDS[3], _DEDS[1]]    # arrival order ≠ domain order
    assert [d for d, _ in group_by_domain(shuffled)] == ["access_control", "system_hardening",
                                                        "health_resilience", "detection"]
    assert [x.reason for x in dict(group_by_domain(shuffled))["detection"]] == ["clamav", "auditd"]


def test_the_box_names_each_domain_above_its_lines():
    texts = [t for t, _ in display._summary_breakdown_lines(N(breakdown=_DEDS, cap_info=None), _t, 76)]
    i = texts.index("  ▸ domain_scores.detection")
    assert texts[i + 1] == "  -1  auditd" and texts[i + 2] == "  -1  clamav"
    assert sum(1 for t in texts if t.startswith("  ▸ ")) == 4


# --- B2: the "possible improvements" list is not the free one -----------------

def _findings_box(findings, breakdown):
    from bob.scoring import FindingLevel
    eng = N(findings=findings, breakdown=breakdown)
    return [t for t, _ in display._summary_findings_lines(eng, _t, 76)]


def _f(key, nature):
    from bob.scoring import FindingLevel
    return N(key=key, nature=nature, level=FindingLevel.WARN, message=key, cmd="", note="", cmd_type="fix")


def test_said_when_an_improvement_costs_points():
    texts = _findings_box([_f("auditd.no_rules", "improvement")],
                          [N(points=1, key="auditd.no_rules", reason="r", context="local")])
    assert any("summary.block_improve_points" in t for t in texts)


def test_not_said_when_no_improvement_costs_points():
    texts = _findings_box([_f("virt.bypass_risk", "improvement")], [])
    assert not any("summary.block_improve_points" in t for t in texts)
