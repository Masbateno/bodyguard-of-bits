"""v0.37.0 — a chain named "…reject…" is not a refusal.

Measured on Linux Mint 22.3, iptables-nft, ufw 0.36.2 (a10370, 14 November
2026). After `ufw --force enable` then `ufw disable`, INPUT still jumps to
ufw's chains, all of them now empty (`chain ufw6-reject-input { }`). BOB took
the "reject" in `jump ufw6-reject-input` for a verdict: "Default INPUT policy:
ACCEPT, with rules that refuse some traffic … not established" (INFO) and "No
active firewall front-end … rules refuse traffic" (INFO). Removing the jumps
(or rebooting) brought back what the kernel actually did: "UFW firewall is
disabled" and "Default INPUT policy: ACCEPT" (ALERT, −3).
"""

from __future__ import annotations

import pytest

from bob.checks import iptables_nftables as N

_RESIDUE = """table ip6 filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t\tcounter packets 16 bytes 1284 jump ufw6-before-input
\t\tcounter packets 15 bytes 1220 jump ufw6-reject-input
\t\tcounter packets 15 bytes 1220 jump ufw6-track-input
\t}

\tchain ufw6-before-input {
\t}

\tchain ufw6-reject-input {
\t}

\tchain ufw6-track-input {
\t}
}
"""


def _input_verdict(ruleset):
    base = [c for c in N._nft_base_chains(ruleset, "input")]
    assert len(base) == 1
    return N._chain_verdict(base[0], N._nft_all_chains(ruleset))


def test_jumps_to_ufws_empty_chains_leave_the_policy_accept():
    assert _input_verdict(_RESIDUE) == ("ACCEPT", False)


def test_the_same_chain_with_a_reject_in_it_still_refuses():
    ruleset = _RESIDUE.replace("\tchain ufw6-reject-input {\n\t}",
                               "\tchain ufw6-reject-input {\n\t\treject\n\t}")
    assert _input_verdict(ruleset) == ("PARTIAL", False)


@pytest.mark.parametrize("rule, refuses", [
    ("jump ufw6-reject-input", False), ("goto ufw-reject-input", False), ("jump x.drop", False),
    ("jump queue-in", False), ("tcp dport 22 drop", True), ("reject with icmpx type port-unreachable", True),
    ("tcp dport vmap { 22 : drop, 80 : accept }", True), ("queue num 1", True),
])
def test_a_verdict_is_a_word_of_its_own(rule, refuses):
    assert bool(N._NFT_REFUSES.search(rule)) is refuses
