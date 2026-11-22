"""v0.42.0 — the CIS citation of the host's own benchmark (B-043).

Measured on the developer's workstation (Linux Mint 22.3, base Ubuntu 24.04,
21 November 2026): the screen cited "CIS Ubuntu 22.04 L1 — 5.2.7" for the
unrestricted su, while ``cis_refs.json`` holds the CIS Ubuntu 24.04 citation
(generated from ComplianceAsCode). Decided with the user: the host's own
benchmark when a citation exists, the primary reference otherwise; the base
read from /etc/os-release, never guessed.
"""

from __future__ import annotations

import pytest

from bob import cis_refs

#: /etc/os-release of the workstation, as read on 21 November 2026.
MINT_22_3 = """NAME="Linux Mint"
VERSION="22.3 (Zena)"
ID=linuxmint
ID_LIKE="ubuntu debian"
PRETTY_NAME="Linux Mint 22.3"
VERSION_ID="22.3"
VERSION_CODENAME=zena
UBUNTU_CODENAME=noble
"""


@pytest.mark.parametrize("text, label", [
    (MINT_22_3, "CIS Ubuntu 24.04"),
    ('ID=linuxmint\nVERSION_ID="21.3"\nUBUNTU_CODENAME=jammy\n', "CIS Ubuntu 22.04"),
    ('ID=ubuntu\nVERSION_ID="26.04"\nUBUNTU_CODENAME=resolute\n', "CIS Ubuntu 26.04"),
    ('ID=ubuntu\nVERSION_ID="24.04"\n', "CIS Ubuntu 24.04"),
    ('ID=debian\nVERSION_ID="13"\n', "CIS Debian 13"),
    ('ID=linuxmint\nID_LIKE=debian\nVERSION_ID="6"\nDEBIAN_CODENAME=bookworm\n', "CIS Debian 12"),
    ('ID=kali\nID_LIKE=debian\nVERSION_ID="2026.4"\nVERSION_CODENAME=kali-rolling\n', None),
    ('ID=linuxmint\nUBUNTU_CODENAME=plucky\n', None),       # a codename with no citation: never guessed
    ("", None),
])
def test_the_benchmark_is_read_from_os_release(text, label):
    assert cis_refs.host_benchmark(text) == label


def test_the_workstation_cites_ubuntu_24_04():
    ref, code = cis_refs.host_cis("user_accounts.su_unrestricted", benchmark="CIS Ubuntu 24.04")
    assert ref.startswith("CIS Ubuntu 24.04 — 5.2.7 — ") and "22.04" not in ref
    assert code == "CIS:5.2.7"


def test_without_a_citation_for_the_host_the_primary_stays():
    key = "user_accounts.su_unrestricted"
    primary = (cis_refs.get_cis_ref(key, "en"), cis_refs.get_cis_code(key))
    assert cis_refs.host_cis(key, "en", benchmark="CIS Ubuntu 22.04") == primary   # the primary itself
    assert cis_refs.host_cis(key, "en", benchmark="") == primary                   # no base declared


def test_a_benchmark_with_another_number_shows_its_own():
    """CIS Ubuntu 26.04 cites ufw's 4.1.3 for an open incoming policy (0.41.0)."""
    ref, code = cis_refs.host_cis("firewall.policy_open", benchmark="CIS Ubuntu 26.04")
    assert ref.startswith("CIS Ubuntu 26.04 — 4.1.3 — ") and code == "CIS:4.1.3"


def test_the_finding_line_names_the_hosts_benchmark(monkeypatch):
    """Through the real printer: the line under a --verbose finding."""
    from bob import display
    from bob.scoring import Finding, FindingLevel
    monkeypatch.setattr(cis_refs, "host_benchmark", lambda os_release=None: "CIS Ubuntu 24.04")
    shown: "list[str]" = []
    import bob.output
    monkeypatch.setattr(bob.output, "print_dim", shown.append)
    traits = display._LevelTraits("WARN", "warn", lambda m: None, True, True, False, False, True)
    display._emit_finding_body(Finding(level=FindingLevel.WARN, message="m", key="user_accounts.su_unrestricted"),
                               traits, verbose=True)
    assert [s for s in shown if s.startswith("CIS Ubuntu 24.04 — 5.2.7")]
