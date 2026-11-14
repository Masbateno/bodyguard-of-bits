"""v0.37.0 — sshd_config Match blocks read and weighed on the same scale.

Until 0.37.0 the reader stopped at the first Match block and said "directives
after it were not analysed": a block that reopened PermitRootLogin or password
logins for some sessions cost nothing. Measured with `sshd -T -C` on Linux Mint
22.3, OpenSSH 9.6p1 (a10370, 14 November 2026), on copies of the config:

| configuration                                      | sshd -T -C                                       |
|----------------------------------------------------|--------------------------------------------------|
| drop-in: Match User bobm → PermitRootLogin yes     | bobm: yes; others: global                        |
| drop-in Match, main file's X11Forwarding after the Include | stays global (the block ends with its file) |
| main file: Match …, then Match all, MaxAuthTries 3 | MaxAuthTries 3 for everyone                      |
| main file: Match …, then MaxAuthTries 3            | only for the block's sessions                    |
| Match User bobm → PermitRootLogin yes              | root: global (the block never takes root)       |
| Match User root / User * / Group root / User !bobm,* | root: yes                                      |
| Match Group sudo (root not in sudo)                | root: global                                     |
| Match Address 192.0.2.0/24                         | root from 192.0.2.9: yes; from elsewhere: global |

Decided with the user (14 November 2026): a weakened setting in a block costs
as if it were global, once per key; the message names the block.

Review of the first draft (14 November 2026) asked whether an explicit global
value keeps a block's value from taking effect. Measured the same day with
`sshd -T -C` (OpenSSH 9.6p1), each key both ways, from inside the block
(192.0.2.9) and outside it (203.0.113.9) — `_MEASURED` below: it does not, a
block's value wins (cases 1-3). But `Match all` is a block, not a return to the
global settings: its value beats the global one before or after it (7), and a
later block's value for the same key is never applied (4a, 4c, 4d) — the draft
read `Match all` as global, missed 7b/7c and counted 4a/4c/4d/7a.
"""

from __future__ import annotations

from pathlib import Path

from bob.checks.ssh import _parsers as P
from bob.checks.ssh import _subchecks as S
from bob.checks.ssh import check_ssh
from tests.test_ssh import base_snapshot

_HARD = {"passwordauthentication": "no", "maxauthtries": "3", "permitrootlogin": "prohibit-password"}


def _parse(tmp_path, main, dropin=None):
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    if dropin is not None:
        (d / "50-bob.conf").write_text(dropin)
    f = tmp_path / "sshd_config"
    f.write_text(main.replace("@D@", str(d)))
    cfg: dict = {}
    P._parse_config_file(f, cfg, set())
    return cfg


def test_a_dropin_match_ends_with_its_file(tmp_path):
    cfg = _parse(tmp_path, "Include @D@/*.conf\nX11Forwarding yes\n",
                 dropin="Match User bobm\n    X11Forwarding no\n")
    assert cfg["x11forwarding"] == "yes"
    assert cfg["_match_blocks"][0]["settings"] == {"x11forwarding": "no"}


def test_match_all_applies_to_every_session(tmp_path):
    cfg = _parse(tmp_path, "Match User bobm\n    PermitRootLogin yes\nMatch all\nMaxAuthTries 3\n")
    assert cfg["maxauthtries"] == "3"
    assert cfg["_match_blocks"][0] == {"criteria": "User bobm", "settings": {"permitrootlogin": "yes"},
                                       "file": str(tmp_path / "sshd_config")}


def test_without_match_all_what_follows_is_the_blocks(tmp_path):
    cfg = _parse(tmp_path, "Match User bobm\n    PermitRootLogin yes\nMaxAuthTries 3\n")
    assert "maxauthtries" not in cfg
    assert cfg["_match_blocks"][0]["settings"]["maxauthtries"] == "3"


def test_an_include_inside_a_block_is_said_not_followed(tmp_path):
    cfg = _parse(tmp_path, "Match User bobm\n    Include @D@/*.conf\n", dropin="PasswordAuthentication yes\n")
    assert "passwordauthentication" not in cfg
    assert cfg["_match_include_unread"] == [f"User bobm: Include {tmp_path / 'sshd_config.d'}/*.conf"]


def test_the_measured_reach_of_criteria(monkeypatch):
    monkeypatch.setattr(S, "_account_groups", lambda u: {"root"} if u == "root" else {"bobm", "sudo"})
    for criteria, root in (("User bobm", False), ("User root", True), ("User *", True), ("Group root", True),
                           ("Group sudo", False), ("Address 192.0.2.0/24", True), ("User !bobm,*", True),
                           ("all", True)):
        assert S._match_reaches(criteria, "root") is root, criteria
    assert S._match_reaches("User !bobm,*", "bobm") is False


def _result(monkeypatch, blocks, glob=_HARD, accounts=True):
    monkeypatch.setattr(S, "_match_reaches_an_account", lambda c: accounts)
    monkeypatch.setattr(S, "_account_groups", lambda u: {"root"} if u == "root" else {u})
    cfg = dict(glob)
    cfg["_match_block"] = True
    cfg["_match_blocks"] = [{"criteria": c, "settings": s, "file": "/etc/ssh/sshd_config"} for c, s in blocks]
    return check_ssh(base_snapshot(sshd_config=cfg))


def test_a_block_reopening_password_logins_costs_as_if_global(monkeypatch):
    r = _result(monkeypatch, [("Address 192.0.2.0/24", {"passwordauthentication": "yes"})])
    d = [x for x in r.deductions if x.key == "ssh.password_auth"]
    assert len(d) == 1 and d[0].points == 2
    f = next(f for f in r.findings if f.key == "ssh.password_auth")
    assert "Address 192.0.2.0/24" in f.message and not f.cmd


def test_root_login_in_a_block_that_takes_root_costs_its_points(monkeypatch):
    r = _result(monkeypatch, [("User root", {"permitrootlogin": "yes"})])
    assert sum(d.points for d in r.deductions if d.key == "ssh.permit_root_login") == 3


def test_root_login_in_a_block_that_never_takes_root_costs_nothing(monkeypatch):
    r = _result(monkeypatch, [("User bobm", {"permitrootlogin": "yes"})])
    assert not any(d.key == "ssh.permit_root_login" for d in r.deductions)


def test_a_key_counted_globally_is_not_counted_again(monkeypatch):
    glob = dict(_HARD, passwordauthentication="yes")
    r = _result(monkeypatch, [("User bobm", {"passwordauthentication": "yes"}),
                              ("Address 192.0.2.0/24", {"passwordauthentication": "yes"})], glob=glob)
    assert sum(1 for d in r.deductions if d.key == "ssh.password_auth") == 1


def test_two_blocks_weakening_the_same_key_count_once(monkeypatch):
    r = _result(monkeypatch, [("User bobm", {"passwordauthentication": "yes"}),
                              ("User alice", {"passwordauthentication": "yes"})])
    assert sum(1 for d in r.deductions if d.key == "ssh.password_auth") == 1


def test_a_block_matching_no_account_is_said_without_a_point(monkeypatch):
    r = _result(monkeypatch, [("User ghost", {"passwordauthentication": "yes"})], accounts=False)
    assert not any(d.key == "ssh.password_auth" for d in r.deductions)
    assert any(f.key == "ssh.match_block_no_account" for f in r.findings)


def test_a_harmless_block_is_said_read_and_the_section_stays_ok(monkeypatch):
    r = _result(monkeypatch, [("User bobm", {"x11forwarding": "no"})])
    keys = {f.key for f in r.findings}
    assert "ssh.match_blocks_read" in keys and "ssh.config_ok" in keys


def test_an_unread_include_is_a_visibility_limit():
    from bob.visibility import VISIBILITY_KEYS
    assert "ssh.match_block_skipped" in VISIBILITY_KEYS
    assert "ssh.match_blocks_read" not in VISIBILITY_KEYS


def test_the_parser_keeps_first_value_in_a_block(tmp_path):
    cfg = _parse(tmp_path, "Match User bobm\n    PasswordAuthentication yes\n    PasswordAuthentication no\n")
    assert cfg["_match_blocks"][0]["settings"]["passwordauthentication"] == "yes"
    assert Path(cfg["_match_blocks"][0]["file"]).name == "sshd_config"


# (case, sshd_config body, key, value inside the Address block, value outside) —
# from `sshd -T -C user=root,addr=192.0.2.9` / `addr=203.0.113.9`, 14 November 2026.
_B = "Match Address 192.0.2.0/24\n"
_MEASURED = [
    ("1a", "PasswordAuthentication no\n" + _B + "    PasswordAuthentication yes\n", "passwordauthentication", "yes", "no"),
    ("1b", "PasswordAuthentication yes\n" + _B + "    PasswordAuthentication no\n", "passwordauthentication", "no", "yes"),
    ("2a", "PermitRootLogin no\n" + _B + "    PermitRootLogin yes\n", "permitrootlogin", "yes", "no"),
    ("2b", "PermitRootLogin yes\n" + _B + "    PermitRootLogin no\n", "permitrootlogin", "no", "yes"),
    ("3a", "MaxAuthTries 3\n" + _B + "    MaxAuthTries 10\n", "maxauthtries", "10", "3"),
    ("3b", "MaxAuthTries 10\n" + _B + "    MaxAuthTries 3\n", "maxauthtries", "3", "10"),
    ("4a", "Match all\n    PasswordAuthentication no\n" + _B + "    PasswordAuthentication yes\n",
     "passwordauthentication", "no", "no"),
    ("4b", _B + "    PasswordAuthentication yes\nMatch all\n    PasswordAuthentication no\n",
     "passwordauthentication", "yes", "no"),
    ("4c", "Match all\n    PermitRootLogin no\n" + _B + "    PermitRootLogin yes\n", "permitrootlogin", "no", "no"),
    ("4d", "Match all\n    MaxAuthTries 3\n" + _B + "    MaxAuthTries 10\n", "maxauthtries", "3", "3"),
    ("5a", "PasswordAuthentication no\nPasswordAuthentication yes\n" + _B + "    PasswordAuthentication yes\n",
     "passwordauthentication", "yes", "no"),
    ("7a", "PasswordAuthentication yes\nMatch all\n    PasswordAuthentication no\n", "passwordauthentication", "no", "no"),
    ("7b", "PasswordAuthentication no\nMatch all\n    PasswordAuthentication yes\n", "passwordauthentication", "yes", "yes"),
    ("7c", "PermitRootLogin no\n" + _B + "    MaxAuthTries 3\nMatch all\n    PermitRootLogin yes\n",
     "permitrootlogin", "yes", "yes"),
]


def test_what_bob_weighs_is_what_sshd_applies(tmp_path):
    """The values the checks read — cfg for every session, the Address block
    laid over it for its own — are sshd's, case by case."""
    for case, body, key, inside, outside in _MEASURED:
        d = tmp_path / case
        d.mkdir()
        cfg = _parse(d, body)
        addr = next((b for b in cfg.get("_match_blocks", []) if b["criteria"].startswith("Address")), None)
        got_in = (addr["settings"] if addr else {}).get(key, cfg.get(key))
        assert (got_in, cfg.get(key)) == (inside, outside), case


def test_a_match_all_weakening_is_counted_without_a_global_command(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "_match_reaches_an_account", lambda c: True)
    cfg = _parse(tmp_path, "PasswordAuthentication no\nMaxAuthTries 3\nPermitRootLogin no\n"
                           "Match all\n    PasswordAuthentication yes\n")
    r = check_ssh(base_snapshot(sshd_config=cfg))
    d = [x for x in r.deductions if x.key == "ssh.password_auth"]
    assert len(d) == 1 and d[0].points == 2
    f = next(f for f in r.findings if f.key == "ssh.password_auth")
    assert not f.cmd
    said = next(f for f in r.findings if f.key == "ssh.match_all_sets")
    assert "passwordauthentication" in said.message


def test_a_dead_global_value_costs_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "_match_reaches_an_account", lambda c: True)
    cfg = _parse(tmp_path, "PasswordAuthentication yes\nMaxAuthTries 3\nPermitRootLogin no\n"
                           "Match all\n    PasswordAuthentication no\n")
    r = check_ssh(base_snapshot(sshd_config=cfg))
    assert not any(x.key == "ssh.password_auth" for x in r.deductions)


def test_a_global_fix_is_offered_only_where_it_takes_effect():
    from bob.checks.ssh._directives import _sshd_directive_fix
    assert _sshd_directive_fix("PasswordAuthentication no", "PasswordAuthentication",
                               {"_match_all_keys": {"passwordauthentication": "/etc/ssh/sshd_config"}}) == ""
    assert "PasswordAuthentication no" in _sshd_directive_fix("PasswordAuthentication no", "PasswordAuthentication", {})


def test_tcp_forwarding_yes_in_a_block_costs_its_point(monkeypatch):
    """Found reviewing a real 0.37.0 audit: the default's detail still said a
    block's value "is not read" (0.36.0 text) while 0.37.0 weighs it."""
    glob = {k: v for k, v in _HARD.items()}
    r = _result(monkeypatch, [("Address 192.0.2.0/24", {"allowtcpforwarding": "yes"})], glob=glob)
    assert [d.points for d in r.deductions if d.key == "ssh.allow_tcp_forwarding"] == [1]
    assert any(f.key == "ssh.allow_tcp_forwarding_default" for f in r.findings)


def test_the_default_detail_no_longer_says_a_block_is_unread():
    import json
    root = Path(__file__).resolve().parent.parent / "bob" / "locales"
    for lang, stale in (("en", "is not read"), ("fr", "n'est pas lue")):
        text = json.loads((root / f"{lang}.json").read_text(encoding="utf-8"))["ssh"]["allow_tcp_forwarding_default_detail"]
        assert stale not in text and "Match" in text, lang


def test_a_match_all_in_an_included_file_beats_a_later_global_line(tmp_path):
    """Review of the assembled dossier (14 November 2026): "after it" was only
    possible once an included file's block ends. Measured with sshd -T -C:
    drop-in `Match all` / PasswordAuthentication yes, then the main file's
    PasswordAuthentication no after the Include → yes; the other way → no."""
    for inc, glob in (("yes", "no"), ("no", "yes")):
        d = tmp_path / f"{inc}-{glob}"
        d.mkdir()
        cfg = _parse(d, f"Include @D@/*.conf\nPasswordAuthentication {glob}\n",
                     dropin=f"Match all\n    PasswordAuthentication {inc}\n")
        assert cfg["passwordauthentication"] == inc
