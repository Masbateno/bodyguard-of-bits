"""v0.25.1 — the cron script calls a bob that exists, or the wizard says so.

`build_script_content` wrote `shutil.which("bob") or "/usr/local/bin/bob"`.
Installed by the full path before `--install-completion` created the link,
the job called a file that did not exist and failed on every run.

The running bob comes first (external review of the 0.25.1 changelog): it
writes the script's options, which another bob on root's PATH may not know.
"""

from pathlib import Path

import bob.cron._io as io


def test_the_running_bob_is_used_when_path_has_none(monkeypatch, tmp_path):
    launcher = tmp_path / "bob"
    launcher.write_text("#!/bin/sh\n")
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setattr("sys.argv", [str(launcher), "--install-cron"])
    path, exists = io.resolve_audit_binary()
    assert path == str(launcher) and exists
    assert f"{launcher} --quiet --detailed" in io.build_script_content("", "/var/log/bob")


def test_a_missing_fallback_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setattr("sys.argv", [str(tmp_path / "__main__.py")])
    monkeypatch.setattr(io, "Path", lambda p: Path(tmp_path / "absent" / Path(p).name) if p == "/usr/local/bin/bob" else Path(p))
    path, exists = io.resolve_audit_binary()
    assert not exists


def test_the_running_bob_wins_over_another_on_path(monkeypatch, tmp_path):
    launcher = tmp_path / "bob"
    launcher.write_text("#!/bin/sh\n")
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/bob")
    monkeypatch.setattr("sys.argv", [str(launcher), "--install-cron"])
    assert io.resolve_audit_binary() == (str(launcher), True)


def test_which_is_used_when_the_launcher_is_not_bob(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/bob")
    monkeypatch.setattr("sys.argv", [str(tmp_path / "__main__.py")])
    assert io.resolve_audit_binary() == ("/usr/local/bin/bob", True)
