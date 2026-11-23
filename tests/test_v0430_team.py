"""v0.43.0 — team perimeters: actions outside a declared perimeter said, asked, written (B-045).

Decided with the user (22 November 2026): BOB prevents nothing; an action
outside the declared perimeter is announced, confirmed by a question ``-y``
does not answer, and written to the team journal, confirmed or abandoned;
without a terminal it is carried out and written as not confirmed; no login
uid → not attributed; a direct root login is an account like any other; only
actions outside a perimeter are written; without a declaration nothing
changes.
"""

from __future__ import annotations

import io
import json
import pwd
import os

import pytest

from bob import fix_journal as FJ
from bob import team
from bob import team_journal as TJ
from bob.cli import parse_args


def t(key, **kw):
    return key + ("" if not kw else " " + " ".join(f"{k}={v}" for k, v in sorted(kw.items())))


ME = pwd.getpwuid(os.geteuid()).pw_name


@pytest.fixture
def as_(monkeypatch):
    """Act as *account* (None: no login session), with or without a terminal."""
    def _set(account, tty=True, answer="n"):
        monkeypatch.setattr(team, "_actor", lambda: account)
        monkeypatch.setattr(team, "_interactive", lambda: tty)
        monkeypatch.setattr("sys.stdin", io.StringIO(answer + "\n"))
    return _set


def declare(master="alice", **members):
    decl = team.Declaration(master=master, members={k: list(v) for k, v in members.items()})
    digest = team.write(decl)
    TJ.append("team", op="init", account=master, attributes=[], digest=digest)
    return decl


def events(kind=None):
    j = TJ.load()
    return [e.data for e in j.events if kind is None or e.kind == kind]


# --- without a declaration, nothing changes --------------------------------

def test_without_a_declaration_nothing_is_asked_said_or_written(as_, capsys):
    as_("dave", tty=True, answer="n")
    assert team.load() is None
    assert team.gate("fix:firewall_network", "fix", t) is True
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""
    assert not TJ.path().exists()


# --- within, outside ---------------------------------------------------------

def test_within_the_perimeter_nothing_is_said_or_written(as_, capsys):
    declare(dave=["audit"])
    as_("dave")
    assert team.gate("audit", "audit", t) is True
    assert capsys.readouterr().err == ""
    assert events("attempt") == []


def test_the_master_holds_every_attribute(as_):
    declare()
    as_("alice")
    assert all(team.gate(a, "audit", t) for a in team.ATTRIBUTES)
    assert events("attempt") == []


def test_outside_and_confirmed_it_is_carried_out_and_written(as_, capsys):
    declare(dave=["audit"])
    as_("dave", answer="y")
    assert team.gate("fix:firewall_network", "fix", t) is True
    err = capsys.readouterr().err
    assert "team.outside" in err and "attribute=fix:firewall_network" in err and "team.confirm" in err
    [ev] = events("attempt")
    assert ev["outcome"] == "confirmed" and ev["account"] == "dave" and ev["attribute"] == "fix:firewall_network"


def test_outside_and_refused_it_is_not_carried_out_and_still_written(as_, capsys):
    declare(dave=["audit"])
    as_("dave", answer="n")
    assert team.gate("purge", "purge_report", t) is False
    assert "team.abandoned" in capsys.readouterr().err
    assert [e["outcome"] for e in events("attempt")] == ["abandoned"]


def test_an_empty_answer_is_a_refusal(as_):
    declare(dave=[])
    as_("dave", answer="")
    assert team.gate("audit", "audit", t) is False


def test_the_question_goes_to_stderr_so_a_json_stdout_stays_clean(as_, capsys):
    declare(dave=[])
    as_("dave", answer="y")
    team.gate("audit", "audit", t)
    assert capsys.readouterr().out == ""


def test_without_a_terminal_it_is_carried_out_and_written_not_confirmed(as_, capsys):
    declare(dave=["audit"])
    as_("dave", tty=False)
    assert team.gate("config", "ignore", t) is True
    assert "team.no_terminal" in capsys.readouterr().err
    assert [e["outcome"] for e in events("attempt")] == ["unconfirmed"]


def test_without_a_login_session_it_is_not_attributed(as_):
    declare(dave=["audit"])
    as_(None)
    assert team.gate("audit", "audit", t) is True
    [ev] = events("attempt")
    assert ev["outcome"] == "unattributed" and "account" not in ev


def test_a_direct_root_login_is_an_account_like_any_other(as_):
    declare(dave=["audit"])
    as_("root", answer="n")
    assert team.gate("audit", "audit", t) is False
    assert events("attempt")[0]["account"] == "root"


def test_a_full_screen_caller_asks_on_its_own_screen(as_):
    declare(dave=[])
    as_("dave", tty=False)
    asked, said = [], []
    assert team.gate("note", "note_add", t, ask=lambda q: asked.append(q) or False, say=said.append) is False
    assert asked and "team.outside" in asked[0] and "team.confirm" in asked[0]
    assert any("team.abandoned" in s for s in said)


def test_an_unwritable_journal_is_said_and_prevents_nothing(as_, monkeypatch, capsys):
    declare(dave=[])
    monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid() + 1)  # writing now refused
    as_("dave", answer="y")
    assert team.gate("audit", "audit", t) is True
    assert "team.not_recorded" in capsys.readouterr().err


# --- fix:<domain> ------------------------------------------------------------

def test_a_fix_needs_its_findings_domain():
    assert team.fix_attribute("ssh.password_auth") == "fix:access_control"
    assert team.fix_attribute(None) == team.FIX_ALL


def test_fix_star_covers_every_domain():
    decl = team.Declaration(master="alice", members={"carol": ["fix:*"]})
    assert all(team.allows(decl, "carol", f"fix:{d}") for d in team.DOMAINS)
    assert not team.allows(decl, "carol", "purge")


# --- the declaration -----------------------------------------------------------

def test_the_declaration_reads_back_as_written():
    decl = team.Declaration(master="alice", members={"carol": ["fix:firewall_network", "audit"], "dave": []})
    back = team.parse(team.render(decl))
    assert back.master == "alice" and back.members == {"carol": ["audit", "fix:firewall_network"], "dave": []}
    assert back.unread_lines == []


def test_a_line_not_understood_is_kept_to_be_said():
    decl = team.parse("master: alice\ncarol: audit, sudo-everything\ngarbage\n")
    assert decl.members["carol"] == ["audit"]
    assert decl.unread_lines == ["carol: audit, sudo-everything", "garbage"]


def test_a_declaration_changed_by_hand_is_said_written_once_and_still_applied(as_, capsys):
    declare(dave=["audit"])
    team.CONF.write_text(team.CONF.read_text() + "dave: audit, purge\n")
    as_("dave")
    assert team.gate("purge", "purge_report", t) is True  # the hand-made line is applied
    assert team.gate("purge", "purge_report", t) is True
    assert "team.altered" in capsys.readouterr().err
    assert len(events("altered")) == 1


def test_an_unreadable_declaration_is_said_never_read_as_none(as_, monkeypatch, capsys):
    declare()
    monkeypatch.setattr(team, "_MAX_FILE", 1)  # too large to read
    as_("dave")
    assert team.gate("audit", "audit", t) is True
    assert "team.err.unreadable" in capsys.readouterr().err


# --- bob --team ----------------------------------------------------------------

def test_init_names_the_login_as_master_and_refuses_a_second_time(as_):
    as_(ME)
    assert team.run(["init"], t) == 0
    assert team.load().master == ME
    assert events("team")[0]["op"] == "init"
    with pytest.raises(team.TeamError) as err:
        team.command(["init"], t)
    assert err.value.key == "exists"


def test_init_without_a_login_session_is_refused(as_):
    as_(None)
    with pytest.raises(team.TeamError) as err:
        team.command(["init"], t)
    assert err.value.key == "init_no_login" and team.load() is None


def test_grant_revoke_remove(as_):
    declare(master="alice")
    as_("alice")
    team.command(["grant", ME, "audit,fix:detection"], t)
    assert team.load().members[ME] == ["audit", "fix:detection"]
    team.command(["revoke", ME, "audit"], t)
    assert team.load().members[ME] == ["fix:detection"]
    team.command(["remove", ME], t)
    assert ME not in team.load().members
    assert [e["op"] for e in events("team")] == ["init", "grant", "revoke", "remove"]
    # each write recorded with the digest of what it wrote: no "altered" afterwards
    assert TJ.last_declaration_digest(TJ.load()) == team.load().digest


@pytest.mark.parametrize("args, key", [
    (["grant", ME, "sudo"], "unknown_attribute"),
    (["grant", "no-such-account-b045", "audit"], "no_account"),
    (["grant", "alice", "audit"], "is_master"),
    (["revoke", "nobody-declared", "audit"], "not_member"),
    (["frobnicate"], "usage"),
])
def test_what_a_team_command_refuses(as_, args, key):
    declare(master="alice")
    as_("alice")
    with pytest.raises(team.TeamError) as err:
        team.command(args, t)
    assert err.value.key == key


def test_changing_the_declaration_needs_root_before_anything_is_asked(as_, monkeypatch):
    declare(master="alice", dave=[])
    as_("dave", answer="y")
    monkeypatch.setattr(team, "_CONF_UID", os.geteuid() + 1)
    with pytest.raises(team.TeamError) as err:
        team.command(["grant", ME, "audit"], t)
    assert err.value.key == "needs_root"
    assert events("attempt") == []      # refused first: no question, no attempt written


def test_a_member_changing_the_declaration_is_outside_their_perimeter(as_):
    declare(master="alice", dave=["audit"])
    as_("dave", answer="n")
    assert team.command(["grant", ME, "audit"], t) == []
    assert ME not in team.load().members
    assert events("attempt")[0]["outcome"] == "abandoned"


def test_the_view_shows_the_readers_perimeter(as_):
    declare(master="alice", dave=["audit", "note"])
    as_("dave")
    lines = team.show(t)
    assert "team.you account=dave attributes=audit, note" in lines
    assert any("team.limits" in ln for ln in lines)


# --- the journal -------------------------------------------------------------

def test_the_journal_chain_and_its_view(as_):
    declare(dave=[])
    as_("dave", answer="y")
    team.gate("audit", "audit", t)
    lines, code = team.journal_lines(t)
    assert code == 0 and "count=2" in lines[0]
    raw = TJ.path().read_text().splitlines()
    event = json.loads(raw[0])
    event["account"] = "mallory"
    raw[0] = json.dumps(event)
    TJ.path().write_text("\n".join(raw) + "\n")
    lines, code = team.journal_lines(t)
    assert code == 2 and "line=2" in lines[0]


def test_the_journal_has_its_own_chain_start_and_witness_tag():
    assert TJ._GENESIS != FJ._GENESIS and TJ.WITNESS_TAG == "bob-team"


# --- the command line ----------------------------------------------------------

def test_the_words_after_team_are_its_arguments():
    config = parse_args(["--team", "grant", "dave", "audit,note", "--french"])
    assert config.team and config.team_args == ["grant", "dave", "audit,note"]
    assert parse_args(["--team-journal"]).team_journal
