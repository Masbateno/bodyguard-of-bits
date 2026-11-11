"""v0.31.4 — the libvirt check command finds libvirt's rules.

`virt.bypass_risk` printed `sudo iptables -L FORWARD | grep virbr0`, and its
explanation `sudo iptables -L FORWARD -v --line-numbers | grep virbr0`. Neither
can find anything: without -v, iptables -L prints no interface, and libvirt
keeps its rules in its own chains that FORWARD jumps to (LIBVIRT_FWX/FWI/FWO,
iptables backend) or in its own nftables table (libvirt_network). Measured on
Fedora 44, libvirt 12.0, 10 November 2026
(~/.cache/bob-fieldtest/netnsbench/virtcmd0314/virtcmd-fedora.txt):

| backend | -L FORWARD | -L FORWARD -v | iptables -S | nft list ruleset |
|---|---|---|---|---|
| nftables (shipped) | 0 | 0 | 0 | 38 |
| iptables | 0 | 0 | 13 | 47 |

The command now lists the ruleset with nft, and `iptables -S` for a host whose
iptables is the legacy one. Found by a review of a real 0.31.3 audit (the Mint
desktop, libvirt 10.0, iptables backend).
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.virtualization import check_virtualization
from tests.helpers import _t
from tests.test_virtualization import make_snapshot, make_tech


def _cmd(iface="virbr0"):
    snap = make_snapshot(technologies=[make_tech("libvirt/KVM", iface)])
    return next(f.cmd for f in check_virtualization(snap, t=_t).findings
                if f.key == "virt.bypass_risk")


class TestTheCommand:
    def test_it_lists_the_whole_ruleset(self):
        assert "sudo nft list ruleset | grep -w virbr0" in _cmd()

    def test_it_keeps_iptables_s_for_legacy_hosts(self):
        assert "sudo iptables -S | grep -w virbr0" in _cmd()

    def test_it_no_longer_greps_forward_alone(self):
        assert "-L FORWARD" not in _cmd()

    def test_the_interface_is_quoted(self):
        assert "grep -w 'br x'" in _cmd("br x")


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_explanation_says_how_to_find_them(lang):
    i18n.init(lang)
    try:
        how = i18n.t("explain.virt.bypass_risk.how")
        why = i18n.t("explain.virt.bypass_risk.why")
    finally:
        i18n.init(lang="en")
    assert "sudo nft list ruleset | grep -w virbr0" in how
    assert "sudo iptables -S | grep -w virbr0" in how
    assert "--line-numbers | grep virbr0" not in how
    assert "LIBVIRT_FWI" in why and "libvirt_network" in why
