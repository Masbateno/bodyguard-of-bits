"""v0.38.0 — Match blocks an earlier block covers; an Include inside a block.

0.37.0 counted every block's setting and stated the limit: a block whose
sessions an earlier block already takes, for the same key, was still counted
(measured: two identical `Match Address` blocks, no then yes — sshd applies no,
BOB −2; likewise a /25 after a /24). And it did not follow an Include inside a
block (the section a ceiling).

Measured with `sshd -T -C`, OpenSSH 9.6p1 (netnsbench a10380, 15 November
2026), global `PasswordAuthentication no`, block A first with `no`, block B
after it with `yes`:

| case | A                         | B                             | B ever applied? |
|------|---------------------------|-------------------------------|-----------------|
| 11a  | Address 192.0.2.0/24      | Address 192.0.2.0/25          | never           |
| 11b  | Address 192.0.2.0/25      | Address 192.0.2.0/24          | yes (.200)      |
| 11c  | User alice                | User alice                    | never           |
| 11d  | User alice,bob            | User alice                    | never           |
| 11e  | Address 192.0.2.0/24      | Address 192.0.2.0/24,198.51.100.0/24 | yes (198.51.100.9) |
| 11f  | Address 192.0.2.0/24      | User alice Address 192.0.2.0/24 | never         |
| 11g  | User alice Address …/24   | Address 192.0.2.0/24          | yes (bob)       |
| 11h  | Address !192.0.2.0/25,192.0.2.0/24 | Address 192.0.2.0/25 | yes (.9)        |
| 11i  | match address 192.0.2.0/24 | Match  Address   192.0.2.0/24 | never          |
| 11j  | User bob,alice            | User alice,bob                | never           |
| 11k  | User *                    | User alice                    | never           |
| 11l  | User ali*                 | User alice                    | never           |
| 11m  | Address 192.0.2.0/24      | Address 192.0.2.9             | never           |

Include inside a block (C1): what it brings is that block's, the first value
winning across the file boundary; a Match inside the included file takes a
session only when the including block does too; the including block goes on
after the Include.
"""

from __future__ import annotations

import pytest

from bob.checks.ssh import _parsers as P
from bob.checks.ssh import _subchecks as S
from bob.checks.ssh import check_ssh
from tests.test_ssh import base_snapshot

_CASES = {
    "11a": ("Address 192.0.2.0/24", "Address 192.0.2.0/25", False),
    "11b": ("Address 192.0.2.0/25", "Address 192.0.2.0/24", True),
    "11c": ("User alice", "User alice", False),
    "11d": ("User alice,bob", "User alice", False),
    "11e": ("Address 192.0.2.0/24", "Address 192.0.2.0/24,198.51.100.0/24", True),
    "11f": ("Address 192.0.2.0/24", "User alice Address 192.0.2.0/24", False),
    "11g": ("User alice Address 192.0.2.0/24", "Address 192.0.2.0/24", True),
    "11h": ("Address !192.0.2.0/25,192.0.2.0/24", "Address 192.0.2.0/25", True),
    "11i": ("address 192.0.2.0/24", " Address   192.0.2.0/24", False),
    "11j": ("User bob,alice", "User alice,bob", False),
    "11k": ("User *", "User alice", False),
    "11l": ("User ali*", "User alice", False),
    "11m": ("Address 192.0.2.0/24", "Address 192.0.2.9", False),
    # m12 (review 1): sshd's patterns know `*` and `?` only — `[` is literal.
    # 0.38.0's first draft used fnmatch classes and called 12a/12b covered.
    "12a": ("User a[lb]ice", "User alice", True),
    "12b": ("User [a]lice", "User alice", True),
    "12c": ("User al?ce", "User alice", False),
    "12d": ("User ALICE", "User alice", True),
    "12f": ("Host *.example.org", "Host web.example.org", False),
}


def _parse(tmp_path, text, dropins=None):
    d = tmp_path / "sshd_config.d"
    d.mkdir(exist_ok=True)
    for name, body in (dropins or {}).items():
        (d / name).write_text(body)
    f = tmp_path / "sshd_config"
    f.write_text(text.replace("@D@", str(d)))
    cfg: dict = {}
    P._parse_config_file(f, cfg, set())
    return cfg


@pytest.mark.parametrize("case", sorted(_CASES))
def test_a_later_block_counts_only_where_sshd_applies_it(tmp_path, case):
    a, b, applied = _CASES[case]
    cfg = _parse(tmp_path, f"PasswordAuthentication no\nMatch {a}\n    PasswordAuthentication no\n"
                           f"Match {b}\n    PasswordAuthentication yes\n")
    later = cfg["_match_blocks"][1]
    assert ("passwordauthentication" in later["settings"]) is applied, case
    assert ("passwordauthentication" in later.get("shadowed", {})) is not applied, case


@pytest.mark.parametrize("body", [
    "Match Address 192.0.2.0/24\n    PasswordAuthentication no\nMatch Address 192.0.2.0/24\n    PasswordAuthentication yes\n",
    "Match Address 192.0.2.0/24\n    AllowTcpForwarding no\nMatch Address 192.0.2.0/25\n    AllowTcpForwarding yes\n",
    "Match Address 192.0.2.0/24\n    AllowTcpForwarding no\nMatch Address 192.0.2.0/24\n    AllowTcpForwarding yes\n",
], ids=["0.37.0-8b", "0.37.0-10b", "0.37.0-10c"])
def test_the_0_37_0_limit_cases_are_no_longer_counted(tmp_path, body, monkeypatch):
    monkeypatch.setattr(S, "_match_reaches_an_account", lambda c: True)
    cfg = _parse(tmp_path, "PasswordAuthentication no\nMaxAuthTries 3\nPermitRootLogin no\n" + body)
    r = check_ssh(base_snapshot(sshd_config=cfg))
    assert not any(d.key in ("ssh.password_auth", "ssh.allow_tcp_forwarding") for d in r.deductions)
    assert any(f.key == "ssh.match_block_shadowed" for f in r.findings)


def test_two_blocks_setting_different_keys_both_count(tmp_path, monkeypatch):
    """10a (0.37.0): sshd keeps the first value per directive, not per block."""
    monkeypatch.setattr(S, "_match_reaches_an_account", lambda c: True)
    cfg = _parse(tmp_path, "PasswordAuthentication no\nMaxAuthTries 3\nPermitRootLogin no\n"
                           "Match Address 192.0.2.0/24\n    PermitRootLogin yes\n"
                           "Match Address 192.0.2.0/24\n    PasswordAuthentication yes\n")
    keys = {d.key for d in check_ssh(base_snapshot(sshd_config=cfg)).deductions}
    assert {"ssh.permit_root_login", "ssh.password_auth"} <= keys


def test_a_later_setting_of_the_earlier_block_does_not_cover(tmp_path):
    """The cover is by reading order: the earlier block must have set the key
    before the later one did, not after an Include that brought the later one."""
    cfg = _parse(tmp_path, "Match Address 192.0.2.0/24\n    Include @D@/*.conf\n    PasswordAuthentication no\n",
                 dropins={"a.conf": "Match User alice\n    PasswordAuthentication yes\n"})
    nested = cfg["_match_blocks"][1]
    assert nested["criteria"] == "Address 192.0.2.0/24 User alice"
    assert nested["settings"] == {"passwordauthentication": "yes"}


def test_an_include_brings_its_settings_into_the_block(tmp_path):
    """C1a/C1b/C1c: the block's own, the first value winning across the file."""
    cfg = _parse(tmp_path, "PasswordAuthentication no\nMatch Address 192.0.2.0/24\n    Include @D@/*.conf\n"
                           "    PasswordAuthentication no\n", dropins={"a.conf": "PasswordAuthentication yes\n"})
    assert cfg["passwordauthentication"] == "no"
    assert cfg["_match_blocks"][0]["settings"] == {"passwordauthentication": "yes"}


def test_a_match_inside_the_included_file_needs_both(tmp_path):
    """C1d: alice from the block's range only — both criteria."""
    cfg = _parse(tmp_path, "Match Address 192.0.2.0/24\n    Include @D@/*.conf\n",
                 dropins={"a.conf": "PasswordAuthentication yes\nMatch User alice\n    PermitRootLogin yes\n"})
    outer, nested = cfg["_match_blocks"]
    assert outer["settings"] == {"passwordauthentication": "yes"}
    assert nested["criteria"] == "Address 192.0.2.0/24 User alice"
    assert nested["settings"] == {"permitrootlogin": "yes"}


def test_the_block_goes_on_after_the_include(tmp_path):
    """C1e."""
    cfg = _parse(tmp_path, "Match Address 192.0.2.0/24\n    Include @D@/*.conf\n    MaxAuthTries 10\n",
                 dropins={"a.conf": "PermitRootLogin yes\n"})
    assert cfg["_match_blocks"][0]["settings"] == {"permitrootlogin": "yes", "maxauthtries": "10"}


def test_an_unreadable_included_file_keeps_the_ceiling(tmp_path, monkeypatch):
    real = P.read_text_capped

    def deny(path, *a, **k):
        if path.name == "a.conf":
            raise PermissionError(13, "denied")
        return real(path, *a, **k)
    monkeypatch.setattr(P, "read_text_capped", deny)
    cfg = _parse(tmp_path, "Match User bobm\n    Include @D@/*.conf\n", dropins={"a.conf": "PasswordAuthentication yes\n"})
    assert cfg["_match_include_unread"] == [f"User bobm: Include {tmp_path / 'sshd_config.d' / 'a.conf'}"]


def test_cover_needs_no_negation_in_the_earlier_block():
    assert P._criteria_cover("Address 192.0.2.0/24", "Address 192.0.2.0/25") is True
    assert P._criteria_cover("Address !192.0.2.0/25,192.0.2.0/24", "Address 192.0.2.0/25") is False
    assert P._criteria_cover("Host *.lan", "Host a.lan") is True
    assert P._criteria_cover("Host a.lan", "Host *.lan") is False
    assert P._criteria_cover("RDomain 1", "RDomain 1") is False          # not decided: counted


def test_the_same_file_included_in_two_blocks_belongs_to_both(tmp_path):
    """C1g, measured: alice and bob both got yes, carol the global no."""
    cfg = _parse(tmp_path, "Match User alice\n    Include @D@/*.conf\nMatch User bob\n    Include @D@/*.conf\n",
                 dropins={"a.conf": "PasswordAuthentication yes\n"})
    assert [b["settings"] for b in cfg["_match_blocks"]] == [{"passwordauthentication": "yes"}] * 2


def test_an_include_in_a_block_costs_its_points_end_to_end(tmp_path):
    """C1 from the file to the deduction (self-review point 11): 0.37.0 left an
    Include inside a Match block unread (an upper bound); measured with sshd
    -T -C, its settings are the block's. Parsed, then weighed: −2, no bound."""
    from bob.checks.ssh import check_ssh
    from tests.test_ssh import base_snapshot
    d = tmp_path / "d"
    d.mkdir()
    (d / "extra.conf").write_text("PasswordAuthentication yes\n")
    main = tmp_path / "sshd_config"
    main.write_text("PasswordAuthentication no\nMaxAuthTries 3\nPermitRootLogin prohibit-password\n"
                    f"Match Address 192.0.2.0/24\n    Include {d}/*.conf\n")
    cfg: dict = {}
    P._parse_config_file(main, cfg, set())
    cfg["_match_block"] = bool(cfg.get("_match_blocks"))
    r = check_ssh(base_snapshot(sshd_config=cfg))
    assert [(x.key, x.points) for x in r.deductions] == [("ssh.password_auth", 2)]
    assert "ssh.match_block_skipped" not in {f.key for f in r.findings}


def test_host_case_is_counted_a_point_too_many(tmp_path):
    """m12e: sshd matches host names regardless of case (the later block is
    never applied), BOB does not decide it and counts it — the declared
    direction, a point too many rather than one too few."""
    cfg = _parse(tmp_path, "PasswordAuthentication no\nMatch Host WEB.example.org\n    PasswordAuthentication no\n"
                           "Match Host web.example.org\n    PasswordAuthentication yes\n")
    assert "passwordauthentication" in cfg["_match_blocks"][1]["settings"]


def test_a_literal_bracket_entry_is_covered_by_the_same_literal():
    assert P._criteria_cover("User a[lb]ice", "User a[lb]ice") is True
