"""v0.40.0 — the journal of ``--fix --apply`` on screen and in text (B-031).

Decided with the user (20 November 2026): ``--manage-logs`` opens on two
choices, the audit reports and the journal of fixes, kept apart; the journal
reads one line per day, the most recent first, then a day's commands, then a
command's detail and notes; and "the moment the log has been falsified, it
must be shown explicitly, or at least be easy to demonstrate" — the verdict
heads the list in its own colour, a changed entry shows what the system log
recorded beside what the journal says now, the lines cut from the journal have
their own screen, and ``bob --fix-journal`` says the same in text with the
verdict in its exit code.

Every screen accepts exactly the keys it announces (the 0.39.0 rule), probed
black-box with the guard of tests/test_v0390_announced_keys.py.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

from bob import fix_journal as FJ
from bob import fix_witness as W
from bob import fixlog as L
from bob import i18n
from bob.tui import _keys
from tests.test_v0390_announced_keys import ESC, _Curses, _OutOfKeys, _Screen, _silent


@pytest.fixture
def journald(monkeypatch):
    """A system log played by a list (what _send_witness would have sent),
    read back as journald hands it."""
    monkeypatch.setattr(FJ, "_operator", lambda: {"uid": 0, "login": "alice", "sudo": "alice"})
    monkeypatch.setattr(FJ, "_has_witness", lambda: True)
    sent = []
    monkeypatch.setattr(FJ, "_send_witness", lambda e, d: sent.append(W.Witness(
        kind=e["kind"], id=e["id"], digest=d, body=FJ.body_digest(e),
        at=datetime.now(timezone.utc), message=FJ.witness_message(e, d))))
    monkeypatch.setattr(W, "read_witness", lambda: W.WitnessRead(
        "ok", items=list(sent), oldest=datetime(2000, 1, 1, tzinfo=timezone.utc), persistent=True,
        sealed=False))
    monkeypatch.setattr(FJ, "append_only_now", lambda: None)
    return sent


def _two_commands():
    FJ.record(finding="ssh.root_login", message="Root login allowed", command="sudo sed -i s/yes/no/ x",
              how="shell", status="ok", rc=0, error="", seconds=0.2)
    FJ.record(finding="pkg.fail2ban", message="fail2ban missing", command="sudo apt-get install -y fail2ban",
              how="shell", status="failed", rc=100, error="E: Unable to locate package", seconds=3.0)


def _falsify_second_outcome():
    """The second command's outcome turned into a success, the chain recomputed."""
    events = [json.loads(ln) for ln in FJ.path().read_text().splitlines()]
    events[3].update(status="ok", rc=0)
    prev = FJ._GENESIS
    for event in events:
        event["prev"] = prev
        prev = FJ._digest(FJ._canonical(event))
    FJ.path().write_text("".join(json.dumps(e) + "\n" for e in events))


def _t(key, **kw):
    return i18n.t(key, **kw)


@pytest.fixture(autouse=True)
def _english(monkeypatch):
    import sys
    before = i18n.current_lang()
    i18n.init("en")
    monkeypatch.setitem(sys.modules, "curses", _Curses)     # never the terminal's own
    yield
    i18n.init(before)


class TestInWords:
    def test_a_falsification_heads_the_text(self, journald):
        _two_commands()
        _falsify_second_outcome()
        lines, overall = L.text_report(_t)
        assert overall == "tampered"
        kinds = [k for _t2, k in lines if _t2.strip()]
        assert lines[2] == (_t("fixlog.verdict.tampered"), "alert") and kinds[1] == "alert"
        assert any("[✖ changed]" in text for text, _k in lines)

    def test_the_demonstration_is_in_the_text_too(self, journald):
        """bob --fix-journal prints the proof, not only the verdict."""
        _two_commands()
        _falsify_second_outcome()
        lines, _overall = L.text_report(_t)
        assert any("status=failed rc=100" in text and kind == "verbatim" for text, kind in lines)

    def test_only_the_contradicted_lines_are_shown(self, journald):
        """The first command's untouched lines are not printed as proof."""
        _two_commands()
        _falsify_second_outcome()
        lines, _overall = L.text_report(_t)
        proof = [text for text, kind in lines if kind == "verbatim"]
        assert len(proof) == 1 and "status=failed rc=100" in proof[0]

    def test_the_demonstration_is_on_the_entry(self, journald):
        """What the system log recorded, beside what the journal says now."""
        _two_commands()
        _falsify_second_outcome()
        journal = FJ.load()
        detail = L.entry_detail(journal.entries[1], W.verify(journal), _t)
        texts = [text for text, _k in detail]
        assert _t("fixlog.detail.status", status="✔ applied") in texts       # what the file says now
        assert any("status=failed rc=100" in text for text in texts)          # what was recorded

    def test_intact_says_how_many_lines_were_checked(self, journald):
        _two_commands()
        lines, overall = L.text_report(_t)
        assert overall == "intact" and lines[2] == (_t("fixlog.verdict.intact", count=4), "ok")

    def test_witnesses_all_gone_is_not_called_confirmed(self, journald):
        """Measured on the test Mint, journald rotated and vacuumed: the
        verdict said "INTACT — … 0 line(s) match their witness"."""
        from datetime import timedelta
        _two_commands()
        journal = FJ.load()
        gone = W.WitnessRead("ok", items=[], oldest=datetime.now(timezone.utc) + timedelta(days=1))
        verdict = W.verify(journal, gone, append_only=None)
        lines = L.verdict_lines(verdict, journal, _t)
        assert verdict.overall == "intact" and not verdict.confirmed
        assert lines[0] == (_t("fixlog.verdict.chain_only_unwitnessed"), "ok")
        assert not any(_t("fixlog.verdict.intact", count=0) == text for text, _k in lines)

    def test_an_interrupted_command_says_so(self, journald):
        FJ.start(finding="ufw.inactive", message="m", command="sudo ufw --force enable", how="shell")
        journal = FJ.load()
        detail = dict((text, kind) for text, kind in L.entry_detail(journal.entries[0], W.verify(journal), _t))
        assert detail[_t("fixlog.detail.interrupted")] == "warn"

    def test_the_cut_lines_are_shown(self, journald):
        _two_commands()
        lines = FJ.path().read_text().splitlines()
        FJ.path().write_text("\n".join(lines[:2]) + "\n")
        out, overall = L.text_report(_t)
        assert overall == "tampered"
        assert any("finding=pkg.fail2ban" in text for text, kind in out if kind == "verbatim")

    def test_a_day_in_french(self, journald):
        i18n.init("fr")
        assert L.day_label("2026-11-20", _t) == "vendredi 20 novembre 2026"
        assert L.day_label("2026-11-01", _t) == "dimanche 1er novembre 2026"


class TestTheCommand:
    @pytest.mark.parametrize("falsify, code", [(False, 0), (True, 2)])
    def test_the_exit_code_carries_the_verdict(self, journald, capsys, falsify, code):
        from bob.__main__ import _show_fix_journal
        _two_commands()
        if falsify:
            _falsify_second_outcome()
        assert _show_fix_journal(_t) == code
        assert ("FALSIFIED" in capsys.readouterr().out) is falsify

    def test_not_demonstrated_is_its_own_code(self, journald, monkeypatch):
        from bob.__main__ import EXIT_TARGET_MISSED, _show_fix_journal
        _two_commands()
        monkeypatch.setattr(W, "read_witness", lambda: W.WitnessRead("unreadable"))
        assert _show_fix_journal(_t) == EXIT_TARGET_MISSED

    def test_the_flag_is_parsed(self):
        from bob.cli import parse_args
        assert parse_args(["--fix-journal"]).fix_journal is True


class TestTheScreens:
    def test_the_landing_screen_announces_its_keys(self, journald):
        import bob.manage_logs as ml
        uc = {"log_dir": "/nonexistent/bob-logs"}
        _silent(lambda s: ml._home(s, uc, None, _t), ml._HOME_KEYS, tail=(ord("q"),))

    def test_the_second_choice_is_the_journal(self, journald):
        import bob.manage_logs as ml
        for keys in ([ord("2")], [_Curses.KEY_DOWN, 10]):
            scr = _Screen(keys)
            assert ml._home(scr, {"log_dir": "/x"}, None, _t) == "fixes"

    def test_the_journal_row_wears_its_verdict(self, journald):
        import bob.manage_logs as ml
        _two_commands()
        _falsify_second_outcome()
        rows = ml._home_rows({"log_dir": ""}, _t)
        assert rows[1][1] == "alert" and _t("manage_logs.home_verdict.tampered") in rows[1][0]

    def test_the_days_announce_their_keys(self, journald):
        from bob.tui import fixlog as fl
        _two_commands()
        _silent(lambda s: fl.run(s, _Curses, _t, False), fl._FIXDAYS_KEYS)

    def test_r_is_announced_only_when_lines_were_cut(self, journald):
        from bob.tui import fixlog as fl
        _two_commands()
        lines = FJ.path().read_text().splitlines()
        FJ.path().write_text("\n".join(lines[:2]) + "\n")
        _silent(lambda s: fl.run(s, _Curses, _t, False), fl._FIXDAYS_CUT_KEYS)

    def test_the_verdict_stands_first_in_red(self, journald):
        from bob.tui import fixlog as fl
        from bob.tui._palette import CONTEXT_ERROR
        _two_commands()
        _falsify_second_outcome()
        written = []

        class Scr(_Screen):
            def addstr(self, row, col, text, attr=0):
                written.append((row, text, attr))
                super().addstr(row, col, text, attr)
        try:
            fl.run(Scr([]), _Curses, _t, True)
        except _OutOfKeys:
            pass
        # v0.43.0 — the body starts under the empty row below the banner
        from bob.tui._chrome import BODY_TOP
        first = next((text, attr) for row, text, attr in written if row == BODY_TOP)
        assert first[0].startswith(_t("fixlog.verdict.tampered")[:20])
        assert first[1] == _Curses.color_pair(CONTEXT_ERROR) | _Curses.A_BOLD

    def test_a_day_then_a_command(self, journald):
        from bob.tui import fixlog as fl
        _two_commands()
        scr = _Screen([10, 10])                 # Enter on the day, Enter on its first command
        try:
            fl.run(scr, _Curses, _t, False)
        except _OutOfKeys:
            pass
        last = "\n".join(scr.frames[-1].values())
        assert "Finding: ssh.root_login — Root login allowed" in last
        assert "sudo sed -i s/yes/no/ x" in last

    def test_a_note_is_offered_to_root_only(self, journald, monkeypatch):
        from bob.tui import fixlog as fl
        _two_commands()
        entry = FJ.load().entries[0]
        monkeypatch.setattr(fl, "_is_root", lambda: False)
        _silent(lambda s: fl._entry(s, _Curses, _t, False, entry.id, "t"), fl._FIXENTRY_RO_KEYS)
        scr = _Screen([])                       # without the right, the screen says how
        try:
            fl._entry(scr, _Curses, _t, False, entry.id, "t")
        except _OutOfKeys:
            pass
        assert "To add a note: sudo bob --manage-logs" in "\n".join(scr.frames[0].values())
        monkeypatch.setattr(fl, "_is_root", lambda: True)
        _silent(lambda s: fl._entry(s, _Curses, _t, False, entry.id, "t"), fl._FIXENTRY_KEYS)

    def test_the_journal_owner_writes_notes(self, monkeypatch):
        """Root in real use; the account running a test or the demonstration
        when the journal is its own."""
        from bob.tui import fixlog as fl
        monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid())
        assert fl._is_root()
        monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid() + 1)
        assert not fl._is_root()

    def test_a_note_is_added(self, journald, monkeypatch):
        import bob.manage_logs as ml
        from bob.tui import fixlog as fl
        _two_commands()
        entry = FJ.load().entries[0]
        monkeypatch.setattr(fl, "_is_root", lambda: True)
        monkeypatch.setattr(ml, "_context_input", lambda *a, **k: "checked by hand")
        try:
            fl._entry(_Screen([ord("a")]), _Curses, _t, False, entry.id, "t")
        except _OutOfKeys:
            pass
        assert [n.text for n in FJ.load().entries[0].notes] == ["checked by hand"]


def test_no_log_dir_but_a_journal_opens_the_landing_screen(monkeypatch, tmp_path):
    """A host where --fix --apply ran but no audit wrote a report still has
    something behind the second choice."""
    import curses

    import bob.manage_logs as ml
    FJ.check_writable()
    monkeypatch.setattr(ml.sys.stdout, "isatty", lambda: True)
    entered = []
    monkeypatch.setattr(curses, "wrapper", lambda fn: entered.append(fn) or 0, raising=False)
    ml._run_manage_logs_dispatch({}, type("C", (), {"no_color": True})(), _t)
    assert entered
