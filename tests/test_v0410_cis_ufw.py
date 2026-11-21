"""v0.41.0 — CIS Ubuntu 26.04 states the firewall through ufw (B-034).

ComplianceAsCode's CIS Ubuntu 26.04 (v1.0.0, Level 1) has no iptables control;
its 4.1.3 "Ensure ufw incoming default is configured" (rule
ufw_default_incoming_rule) says what BOB's "default incoming policy ALLOW"
finding says, and now cites it — Debian 13, which has the same rule, too. The
iptables policy findings are left without a 26.04 number: BOB reads the
kernel's chains, the ufw controls read ufw's configuration.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import gen_cis_benchmarks as G  # noqa: E402

REFS = json.loads((ROOT / "bob" / "data" / "cis_refs.json").read_text(encoding="utf-8"))


def test_the_incoming_default_is_cited_in_26_04():
    for key in ("firewall.policy_open", "firewall.policy_unknown"):
        assert "ufw_default_incoming_rule" in G.MAP[key]
        assert REFS[key]["benchmarks"]["CIS Ubuntu 26.04"]["code"] == "4.1.3"


def test_the_primary_reference_did_not_move():
    """The first rule present wins: 22.04 and 24.04 keep set_ufw_default_rule."""
    assert G.MAP["firewall.policy_open"][0] == "set_ufw_default_rule"
    assert "Ensure ufw default deny firewall policy" in REFS["firewall.policy_open"]["benchmarks"]["CIS Ubuntu 24.04"]["title"]


def test_the_kernel_chain_findings_are_not_given_a_ufw_number():
    for key in ("firewall_iptables.input_accept", "firewall_iptables.forward_accept"):
        assert "CIS Ubuntu 26.04" not in REFS[key].get("benchmarks", {})
