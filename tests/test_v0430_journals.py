"""v0.43.0 — the journals of what was done with BOB, whoever did it (B-045).

Decided with the user (22 November 2026, evening): "even when the master
does it, actions must be recorded in the corresponding journal". One journal
per domain (team, cron, admin), kept even without a team, each category
switchable by ``--journals`` — never the team journal, never a change of
what is recorded. Each trace is driven through the code that carries the
action out (a gate or a trace off that path proves nothing).
"""

from __future__ import annotations

import io
import os

import pytest

from bob import _names, i18n, journals as J, team
from bob.config import EmailStore
from bob.cron._io import apply_cron_email, apply_cron_schedule, remove_cron_job
from bob.cron._parse import CronEntry


@pytest.fixture(autouse=True)
def _english():
    before = i18n.current_lang()
    i18n.init("en")
    yield
    i18n.init(before)


def kinds(name):
    return [(e.kind, e.data.get("category")) for e in J.load(name).events]


def _entry(tmp_path):
    cron_path, script = tmp_path / "bob-nightly", tmp_path / "bob-nightly.sh"
    cron_path.write_text("# email: a@example.com\n0 3 * * *  root  /usr/local/bin/x.sh\n")
    script.write_text("#!/bin/sh\nNOTIFY_EMAILS=a@example.com\n")
    return CronEntry(name="nightly", schedule_expr="0 3 * * *", hour=3, minute=0,
                     script_path=script, cron_path=cron_path)


# --- each action leaves its trace, without any team --------------------------

def test_a_scheduled_audit_changed_and_removed_is_traced(tmp_path):
    assert team.load() is None                      # no team: traced all the same
    entry = _entry(tmp_path)
    assert apply_cron_schedule(entry, "30 4 * * 1") == ""
    assert apply_cron_email(entry, "b@example.com")[0] == ""
    remove_cron_job(entry)
    events = J.load("cron").events
    assert [e.kind for e in events] == ["cron_schedule", "cron_email", "cron_removed"]
    assert events[0].data["schedule"] == "30 4 * * 1" and events[1].data["email"] == "b@example.com"
    assert all(e.data["name"] == "nightly" for e in events)


def test_a_failed_change_leaves_no_trace(tmp_path):
    entry = _entry(tmp_path)
    entry.cron_path.unlink()
    assert apply_cron_schedule(entry, "30 4 * * 1") != ""
    assert J.load("cron").events == []


def test_the_address_book_is_traced(tmp_path):
    store = EmailStore(tmp_path / "emails.json")
    store.add("ops@example.com")
    store.add("ops@example.com")                    # already there: nothing done, nothing written
    store.remove("ops@example.com")
    assert kinds("cron") == [("address_added", "carnet"), ("address_removed", "carnet")]


def test_a_deleted_report_is_traced(tmp_path):
    from bob.manage_logs import _unlink_report
    report = tmp_path / "bob_20261122_190000.log"
    report.write_text("report\n")
    _unlink_report(report)
    [ev] = J.load("admin").events
    assert ev.kind == "report_deleted" and ev.data["path"] == str(report)


def test_a_configuration_change_is_traced(monkeypatch, tmp_path):
    import bob.__main__ as M
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(M, "_ignore_file_path", lambda: tmp_path / "ignore.yml", raising=False)
    M._trace_config("ignore", "ssh.password_auth")
    [ev] = J.load("admin").events
    assert (ev.kind, ev.data["op"], ev.data["value"]) == ("config", "ignore", "ssh.password_auth")


def test_the_master_is_traced_like_anyone(monkeypatch, tmp_path):
    decl = team.Declaration(master="alice")
    J.append("team", "team", op="init", account="alice", attributes=[], digest=team.write(decl))
    monkeypatch.setattr(team, "_actor", lambda: "alice")
    EmailStore(tmp_path / "e.json").add("ops@example.com")
    assert kinds("cron") == [("address_added", "carnet")]
    assert [e.kind for e in J.load("team").events] == ["team"]   # within the perimeter: no attempt


# --- what is recorded ----------------------------------------------------------

def test_a_category_switched_off_is_not_written_and_the_switch_is(monkeypatch, tmp_path):
    monkeypatch.setattr(team, "_actor", lambda: "alice")
    J.set_categories(["carnet"], False, i18n.t)
    EmailStore(tmp_path / "e.json").add("ops@example.com")
    assert kinds("cron") == []
    [ev] = J.load("admin").events
    assert ev.kind == "journals" and ev.data["state"] == "off" and ev.data["off"] == ["carnet"]
    J.set_categories(["carnet"], True, i18n.t)
    EmailStore(tmp_path / "e.json").add("other@example.com")
    assert kinds("cron") == [("address_added", "carnet")]


def test_the_team_journal_cannot_be_switched_off():
    with pytest.raises(team.TeamError) as err:
        J.set_categories(["team"], False, i18n.t)
    assert err.value.key == "journals_unknown"


def test_switching_needs_root_before_anything_is_asked(monkeypatch):
    decl = team.Declaration(master="alice", members={"dave": []})
    J.append("team", "team", op="init", account="alice", attributes=[], digest=team.write(decl))
    monkeypatch.setattr(team, "_actor", lambda: "dave")
    monkeypatch.setattr(team, "_interactive", lambda: True)
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    monkeypatch.setattr(J, "_SETTINGS_UID", os.geteuid() + 1)
    with pytest.raises(team.TeamError) as err:
        J.set_categories(["cron"], False, i18n.t)
    assert err.value.key == "needs_root" and J.load("admin").events == []
    assert [e.kind for e in J.load("team").events] == ["team"]   # no question, no attempt


def test_a_member_switching_is_outside_their_perimeter(monkeypatch):
    decl = team.Declaration(master="alice", members={"dave": ["audit"]})
    J.append("team", "team", op="init", account="alice", attributes=[], digest=team.write(decl))
    monkeypatch.setattr(team, "_actor", lambda: "dave")
    monkeypatch.setattr(team, "_interactive", lambda: True)
    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))
    assert J.set_categories(["cron"], False, i18n.t) == []
    assert "cron" not in J.load_settings().off
    assert [e.data["outcome"] for e in J.load("team").events if e.kind == "attempt"] == ["abandoned"]


def test_settings_changed_by_hand_are_said_written_once_and_applied(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(team, "_actor", lambda: "alice")
    J.set_categories(["config"], False, i18n.t)
    J.SETTINGS.write_text(J.render_settings({"config", "carnet"}))
    EmailStore(tmp_path / "e.json").add("ops@example.com")
    EmailStore(tmp_path / "e.json").add("x@example.com")
    assert kinds("cron") == []                       # the hand-made line applies
    assert [e.kind for e in J.load("admin").events].count("journals_altered") == 1
    assert "changed outside BOB" in capsys.readouterr().err


def test_unreadable_settings_switch_nothing_off(monkeypatch, tmp_path):
    J.SETTINGS.write_text("cron: off\n")
    monkeypatch.setattr(J, "_SETTINGS_UID", os.geteuid())
    monkeypatch.setattr("bob.annotations.MAX_FILE", 1, raising=False)
    J.SETTINGS.chmod(0)
    try:
        if os.access(J.SETTINGS, os.R_OK):
            pytest.skip("running as root: the file stays readable")
        assert J.load_settings().off == set()
    finally:
        J.SETTINGS.chmod(0o644)


def test_an_unwritable_journal_is_said_and_prevents_nothing(monkeypatch, tmp_path, capsys):
    from bob import fix_journal as FJ
    monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid() + 1)
    store = EmailStore(tmp_path / "e.json")
    store.add("ops@example.com")
    assert store.all() == ["ops@example.com"]
    assert "Could not be written to the journal" in capsys.readouterr().err


# --- reading -------------------------------------------------------------------

def test_each_journal_has_its_own_chain_start():
    assert len({J._genesis(n) for n in J.CHANNELS}) == len(J.CHANNELS)


def test_the_view_says_each_event_and_the_chain(tmp_path):
    store = EmailStore(tmp_path / "e.json")
    store.add("ops@example.com")
    store.remove("ops@example.com")
    lines, code = J.journal_lines("cron", i18n.t)
    assert code == 0 and "2 event(s), chain intact" in lines[0]
    assert "address added to the book — ops@example.com" in " ".join(_names.plain(lines[2]).split())   # toned, aligned
    # A line changed shows at the next one: its digest no longer matches
    # (the last line is the system-log witness's job, as for --fix --apply).
    first, second = J.path("cron").read_text().splitlines()
    J.path("cron").write_text(first.replace("ops@", "evil@") + "\n" + second + "\n")
    lines, code = J.journal_lines("cron", i18n.t)
    assert code == 2 and "line 2" in lines[0]


@pytest.mark.parametrize("kind", sorted(J._EVENT_KEYS))
def test_every_event_kind_is_said_in_both_languages(kind):
    for lang in ("en", "fr"):
        i18n.init(lang)
        text = J.event_text(J.Event(1, kind, "", {}, {"kind": kind}), i18n.t)
        assert text and not text.startswith("journals.")


def test_the_command_line():
    from bob.cli import parse_args
    config = parse_args(["--journals", "off", "cron,carnet"])
    assert config.journals and config.journals_args == ["off", "cron,carnet"]
    assert J.run(["show", "nothing"], i18n.t) == 3


def test_the_landing_screen_offers_the_journals():
    from bob.tui import journals as TJV
    assert len(TJV.rows(i18n.t)) == len(J.CHANNELS)
