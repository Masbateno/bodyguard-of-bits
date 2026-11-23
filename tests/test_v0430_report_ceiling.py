"""v0.43.0 — a ceiling on the reports' size (B-050).

Asked by the user (23 November 2026), for small machines such as a Pi Zero:
reports piled up, BOB never deleting one on its own. Off by default; set, the
oldest reports go after each new one until the folder fits. Never deleted:
the report just written, a report with notes. Each deletion traced in the
admin journal; setting it warns that a ceiling too low limits the proof kept.
"""

from __future__ import annotations

import os

import pytest

from bob import annotations as A
from bob import i18n, journals as J
from bob import manage_logs as ml


@pytest.fixture(autouse=True)
def _english(monkeypatch):
    before = i18n.current_lang()
    i18n.init("en")
    monkeypatch.setattr(A, "_JOURNAL_UID", os.geteuid())
    yield
    i18n.init(before)


class _Config:
    def __init__(self, **values):
        self.values = dict(values)

    def get(self, key, default=None):
        return self.values.get(key, default)

    def set(self, key, value):
        self.values[key] = value


def reports(tmp_path, n, size=1000):
    out = []
    for i in range(n):
        r = tmp_path / f"bob_2026111{i}_090000.log"
        r.write_text("x" * size)
        out.append(r)
    return out


@pytest.mark.parametrize("text, size", [("50M", 50 << 20), ("500k", 500 << 10), ("2G", 2 << 30),
                                         ("1,5M", int(1.5 * (1 << 20))), ("4096", 4096), ("off", 0)])
def test_sizes_are_read(text, size):
    assert ml.parse_size(text) == size


@pytest.mark.parametrize("text", ["", "big", "-5M", "M"])
def test_what_is_not_a_size_is_refused(text):
    with pytest.raises(ValueError):
        ml.parse_size(text)


def test_the_oldest_go_first_and_each_deletion_is_traced(tmp_path):
    rs = reports(tmp_path, 5)
    deleted, reached = ml.enforce_ceiling(tmp_path, 2500, keep=rs[-1])
    assert deleted == [rs[0].name, rs[1].name, rs[2].name] and reached
    assert [r.exists() for r in rs] == [False, False, False, True, True]
    assert [e.data["path"] for e in J.load("admin").events if e.kind == "report_deleted"] == \
        [str(rs[0]), str(rs[1]), str(rs[2])]


def test_the_newest_and_annotated_reports_are_never_deleted(tmp_path, monkeypatch):
    rs = reports(tmp_path, 3)
    monkeypatch.setattr(A, "operator", lambda: {"uid": 0, "login": "alice"})
    A.add(rs[0], "keep this one")
    deleted, reached = ml.enforce_ceiling(tmp_path, 10, keep=rs[2])
    assert deleted == [rs[1].name] and not reached
    assert rs[0].exists() and rs[2].exists()


def test_without_a_ceiling_nothing_happens(tmp_path, capsys):
    rs = reports(tmp_path, 3)
    ml.apply_ceiling_after_report(rs[-1], _Config(), i18n.t)
    assert all(r.exists() for r in rs) and capsys.readouterr().out == ""


def test_an_unreachable_ceiling_is_said(tmp_path, capsys, monkeypatch):
    rs = reports(tmp_path, 2)
    from bob import output
    output.init(no_color=True)
    ml.apply_ceiling_after_report(rs[-1], _Config(log_max_size=str(10)), i18n.t)
    out = capsys.readouterr().out
    assert "1 old report(s) deleted" in out and "stay above the ceiling" in out


def test_setting_warns_and_is_traced(monkeypatch):
    cfg = _Config()
    asked = []
    tone, lines = ml.set_ceiling(cfg, "50M", i18n.t, ask=lambda q: asked.append(q) or True)
    assert tone == "done" and cfg.get("log_max_size") == str(50 << 20)
    assert "limits how much proof is kept" in asked[0]
    [ev] = [e for e in J.load("admin").events if e.kind == "config"]
    assert ev.data["op"] == "log_max_size" and ev.data["value"] == "50M"


def test_a_refused_warning_sets_nothing():
    cfg = _Config()
    tone, _lines = ml.set_ceiling(cfg, "50M", i18n.t, ask=lambda q: False)
    assert tone == "info" and cfg.get("log_max_size") is None


def test_off_needs_no_warning():
    cfg = _Config(log_max_size="1000")
    tone, lines = ml.set_ceiling(cfg, "off", i18n.t, ask=lambda q: pytest.fail("no warning to remove a ceiling"))
    assert tone == "done" and ml.ceiling(cfg) == 0


def test_p_in_the_directory_picker_sets_it(monkeypatch):
    cfg = _Config()
    monkeypatch.setattr(ml, "_context_input", lambda *a, **k: "20M")
    monkeypatch.setattr(ml, "_context_confirm", lambda *a, **k: True)
    status = ml._ceiling_action(None, cfg, i18n.t)
    assert status.startswith("✔") and ml.ceiling(cfg) == 20 << 20
    from bob.tui import _keys
    assert _keys.CEILING in ml._DIR_KEYS and not _keys.conflicts(ml._DIR_KEYS)


def test_the_list_and_the_ceiling_measure_alike(tmp_path):
    """Found by the user (23 November 2026): the folder list counted the .log
    files only, the ceiling the files beside them too."""
    r = reports(tmp_path, 1, size=1000)[0]
    (tmp_path / (r.name + ".state")).write_text("y" * 500)
    assert ml._reports_size(tmp_path) == (1, 1500) == (1, ml._report_bytes(r))


def test_the_header_says_the_current_folder_and_all_folders(tmp_path, monkeypatch):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    reports(a, 1, size=2048); reports(b, 2, size=2048)
    monkeypatch.setattr(ml, "_declared_dirs", lambda uc: [a, b])
    label = ml.ceiling_label(_Config(log_dir=str(a)), i18n.t)
    assert label == "no size ceiling (current folder: 2 KB; all folders: 6 KB)"


def test_a_deleted_report_takes_the_files_beside_it(tmp_path):
    """External review (23 November 2026): what becomes of an old report's
    notes and state? They go with it — the deletion passes through
    _unlink_report, as by hand; a report with active notes is never deleted."""
    rs = reports(tmp_path, 3)
    (tmp_path / (rs[0].name + ".state")).write_text("s" * 100)
    deleted, _reached = ml.enforce_ceiling(tmp_path, 2500, keep=rs[-1])
    assert deleted == [rs[0].name]
    assert not (tmp_path / (rs[0].name + ".state")).exists()
