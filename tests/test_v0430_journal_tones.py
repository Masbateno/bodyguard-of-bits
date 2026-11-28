"""v0.43.0 — the journals' action terms in the colour of their effect.

Asked by the user (23 November 2026): "grant", "add" or "on" in green;
"remove", "revoke" or "off" in red; the neutral ones in yellow. The term is
marked in the text (bob/_names.py), drawn in its colour on a screen, and
stripped from every text output.
"""

from __future__ import annotations

import sys

import pytest

from bob import _names, i18n, journals as J
from tests import test_v0430_team_screen as S


@pytest.fixture(autouse=True)
def _english(monkeypatch):
    before = i18n.current_lang()
    i18n.init("en")
    monkeypatch.setitem(sys.modules, "curses", S._Curses)
    yield
    i18n.init(before)


def toned(kind, **data):
    text = J.event_text(J.Event(1, kind, "", {}, {"kind": kind, **data}), i18n.t)
    return {piece: k for piece, k in _names.segments(text) if k in ("good", "bad", "neutral")}


@pytest.mark.parametrize("kind, data, piece, tone", [
    ("team", {"op": "grant", "account": "carol", "attributes": ["audit"]}, "grant", "good"),
    ("team", {"op": "init", "account": "alice", "attributes": []}, "init", "good"),
    ("team", {"op": "revoke", "account": "carol", "attributes": ["audit"]}, "revoke", "bad"),
    ("team", {"op": "remove", "account": "carol", "attributes": []}, "remove", "bad"),
    ("cron_created", {"name": "nightly", "schedule": "0 3 * * *", "email": "a@example.com"}, "scheduled audit created", "good"),
    ("cron_removed", {"name": "nightly"}, "scheduled audit removed", "bad"),
    ("cron_schedule", {"name": "nightly", "schedule": "0 4 * * *"}, "scheduled audit changed", "neutral"),
    ("address_added", {"address": "ops@example.com"}, "address added to the book", "good"),
    ("address_removed", {"address": "ops@example.com"}, "address removed from the book", "bad"),
    ("report_deleted", {"path": "/var/log/bob/x.log"}, "report deleted", "bad"),
    ("journals", {"categories": "['config']", "state": "on"}, "on", "good"),
    ("journals", {"categories": "['config']", "state": "off"}, "off", "bad"),
    ("config", {"op": "ignore", "value": "ssh.x"}, "ignore", "bad"),
    ("config", {"op": "unignore", "value": "ssh.x"}, "unignore", "good"),
    ("config", {"op": "reconfigure", "value": "/x"}, "reconfigure", "neutral"),
    ("journals_altered", {}, "what is recorded changed outside BOB", "bad"),
    ("attempt", {"outcome": "confirmed", "action": "audit", "attribute": "audit"}, "outside the declared perimeter, confirmed", "bad"),
    ("attempt", {"outcome": "abandoned", "action": "audit", "attribute": "audit"}, "outside the declared perimeter, abandoned", "neutral"),
])
def test_each_action_term_has_the_tone_of_its_effect(kind, data, piece, tone):
    assert toned(kind, **data).get(piece) == tone


def test_the_drawer_colours_each_tone():
    from bob.tui import fixlog as _fl
    from bob.tui._palette import ACCENT, NEGATIVE, POSITIVE
    scr = S._Screen([])
    text = "  " + _names.tone("added", "good") + " " + _names.tone("removed", "bad") + " " + _names.tone("changed", "neutral")
    _fl.put_marked(scr, S._Curses, 2, 0, text, 0, True, 100)
    drawn = dict(scr.drawn)
    bold = S._Curses.A_BOLD
    assert drawn["added"] == S._Curses.color_pair(POSITIVE) | bold
    assert drawn["removed"] == S._Curses.color_pair(NEGATIVE) | bold
    assert drawn["changed"] == S._Curses.color_pair(ACCENT) | bold


def test_no_text_output_carries_a_tone_mark(capsys):
    J.append("cron", "address_added", category="carnet", address="ops@example.com")
    J.append("cron", "address_removed", category="carnet", address="ops@example.com")
    assert J.run(["show", "cron"], i18n.t) == 0
    out = capsys.readouterr().out
    assert "address added to the book — ops@example.com" in " ".join(out.split())   # columns aligned
    assert not any(c in out for c in (_names.GOOD, _names.BAD, _names.NEUTRAL, _names.OPEN, _names.CLOSE))


def test_the_team_journal_lines_up(capsys):
    """Found by the user (23 November 2026): the accounts and the attributes
    followed the length of the word before them."""
    for op, account, attrs in (("init", "alice", []), ("grant", "test", ["audit"]),
                               ("revoke", "test2", ["note"]), ("remove", "test", [])):
        J.append("team", "team", op=op, account=account, attributes=attrs, digest="x")
    assert J.run(["show", "team"], i18n.t) == 0
    lines = [x for x in capsys.readouterr().out.splitlines() if "declaration:" in x]
    starts = {x.index(name, x.index("declaration:")) for x, name in zip(lines, ("alice", "test", "test2", "test"))}
    assert len(starts) == 1                                  # every account starts in one column
    attrs = [x for x in lines if "audit" in x or "note" in x]
    assert len({x.index("audit") if "audit" in x else x.index("note") for x in attrs}) == 1


def test_the_cron_journal_lines_up(capsys):
    """Found by the user (23 November 2026) in --manage-logs › Journals ›
    cron: the details followed the length of the action before them."""
    J.append("cron", "cron_created", category="cron", name="nightly", schedule="0 3 * * *", email="a@example.com")
    J.append("cron", "address_added", category="carnet", address="ops@example.com")
    J.append("cron", "cron_removed", category="cron", name="nightly")
    assert J.run(["show", "cron"], i18n.t) == 0
    lines = [x for x in capsys.readouterr().out.splitlines() if " — " in x and x.lstrip()[:1].isdigit()]
    assert len(lines) == 3 and len({x.index(" — ") for x in lines}) == 1


def test_the_text_views_line_up(monkeypatch):
    """CONVENTIONS.md: columns line up — --team and --journals too."""
    from bob import team
    team.write(team.Declaration(master="alice", members={"carol": ["audit"], "a-much-longer-name": ["note"]}))
    monkeypatch.setattr(team, "_actor", lambda: None)
    rows = [x for x in team.show(i18n.t) if " : " in x]
    assert len(rows) == 3 and len({x.index(" : ") for x in rows}) == 1
    i18n.init("fr")
    try:
        J.set_categories(["config"], False, i18n.t)
        rows = [x for x in J.show(i18n.t) if " → " in x]
    finally:
        i18n.init("en")
    assert len(rows) == len(J.CATEGORIES) + 1 and len({x.index(" → ") for x in rows}) == 1


def test_each_journal_says_its_size_in_one_column():
    """Asked by the user (23 November 2026): the journals' size, shown."""
    J.append("cron", "address_added", category="carnet", address="ops@example.com")
    rows = [text for text, _kind in J.state_rows(i18n.t)]
    assert len(rows) == len(J.CHANNELS) and len({r.index(" — ") for r in rows}) == 1
    assert any("not created yet" in r for r in rows)               # team and admin: no file yet
    # v0.44.0 (B-050): against its ceiling, 8 MiB by default — past it, archived
    assert any("of 8.0 MB (past it, archived" in r for r in rows)  # cron: its size and the ceiling
    assert not any(". —" in r for r in rows)


def test_the_journal_of_fixes_says_its_size_too(monkeypatch):
    """Asked by the user (23 November 2026)."""
    from bob import fix_journal as FJ, fixlog
    FJ.record(finding="ssh.root_login", message="m", command="true", how="shell",
              status="ok", rc=0, error=b"", seconds=0.1)
    lines, _overall = fixlog.text_report(i18n.t)
    assert any("of 8.0 MB (past it, archived" in text for text, _kind in lines[:8])
    import bob.manage_logs as ml
    monkeypatch.setattr(ml, "_declared_dirs", lambda uc: [])
    rows = ml._home_rows(type("U", (), {"get": lambda self, k: None})(), i18n.t)
    assert "of 8.0 MB (past it, archived" in rows[1][0]


def test_a_fix_journal_row_follows_the_conventions():
    """Asked by the user (23 November 2026): in the list of --fix --apply's
    journal, the status in the colour of its effect, the command in violet."""
    from bob import fix_journal as FJ, fix_witness as W, fixlog
    for status in ("ok", "failed", "timeout"):
        FJ.record(finding="ssh.root_login", message="m", command=f"sudo true {status}", how="shell",
                  status=status, rc=0 if status == "ok" else 1, error=b"", seconds=0.1)
    journal = FJ.load()
    verdict = W.verify(journal)
    kinds = []
    for entry in journal.entries:
        text, _kind = fixlog.entry_row(entry, verdict, i18n.t)
        pieces = _names.segments(text)
        kinds.append(([k for _p, k in pieces if k in ("good", "bad", "neutral")][0],
                      [p for p, k in pieces if k == "verbatim"]))
    assert [k for k, _c in kinds] == ["good", "bad", "neutral"]
    assert [c for _k, c in kinds] == [["sudo true ok"], ["sudo true failed"], ["sudo true timeout"]]


def test_the_fix_journal_status_column_fits_its_longest_status():
    """Found while preparing the demo (23 November 2026): the French
    "⚠ non confirmée" ran into the operator's name."""
    from bob import fix_journal as FJ, fix_witness as W, fixlog
    i18n.init("fr")
    try:
        for status in ("ok", "unconfirmed", "failed"):
            FJ.record(finding="x", message="m", command="true", how="shell",
                      status=status, rc=0, error=b"", seconds=0.1)
        journal = FJ.load()
        rows = [(_names.plain(fixlog.entry_row(e, W.verify(journal), i18n.t)[0]), fixlog.who_plain(e.who))
                for e in journal.entries]
    finally:
        i18n.init("en")
    starts = {row.index(" " + who + " ") for row, who in rows}
    assert len(starts) == 1, rows                      # every operator starts in one column


def test_a_wrapped_journal_line_goes_on_under_its_last_column():
    """Found by the user (23 November 2026): a team line too long for the
    screen went on six spaces in, under the line number."""
    from bob.tui import fixlog as _fl
    J.append("team", "team", op="grant", account="test", digest="x",
             attributes=["purge", "config", "equipe", "fix:exposure_services", "fix:access_control",
                         "fix:system_hardening", "fix:health_resilience", "fix:detection", "fix:*"])
    lines, _code = J.journal_lines("team", i18n.t)
    event = [(x, "body") for x in lines if "declaration:" in x]
    wrapped = [_names.plain(x) for x, _k in _fl._wrap(event, 110)]
    assert len(wrapped) >= 2
    column = wrapped[0].index("purge")
    assert all(len(x) - len(x.lstrip(" ")) == column for x in wrapped[1:]), wrapped
