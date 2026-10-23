"""v0.26.1 — files BOB hands back to the user are never reached through a symlink.

Found by review, measured on a dummy target before the fix: run as root under
sudo, BOB wrote ~/.config/bob/history.jsonl with a plain open (no O_NOFOLLOW),
re-moded it by name and chowned it by name. A symlink planted at that name in
the user's own directory was followed — the JSON line appended to the target,
its mode set to 0600, and os.chown(follow_symlinks=True) on it; through a
dangling link the target was created. chown_to_sudo_user, used for every file
and directory BOB hands back (config, ignore list, baseline, recurrence,
history, log directories), followed links the same way. From an account
running under the user (no root), a link to /etc/shadow, or to a file not yet
there such as /etc/ld.so.preload, would have been handed over by root.
"""

from __future__ import annotations

import getpass
import os
import stat

import pytest

from bob import history as h
from bob import sysinfo


@pytest.fixture
def sudo(monkeypatch):
    monkeypatch.setenv("SUDO_USER", getpass.getuser())
    calls = []
    real_chown, real_fchown = os.chown, os.fchown
    def spy(p, u, g, *a, **k):
        calls.append((str(p), k.get("follow_symlinks", True)))
        return real_chown(p, u, g, *a, **k)
    def fspy(fd, u, g):
        calls.append((os.readlink(f"/proc/self/fd/{fd}"), "fd"))
        return real_fchown(fd, u, g)
    monkeypatch.setattr(sysinfo.os, "chown", spy)
    monkeypatch.setattr(sysinfo.os, "fchown", fspy)
    return calls


@pytest.fixture
def victim(tmp_path):
    t = tmp_path / "victim.conf"
    t.write_text("owned by root\n")
    t.chmod(0o644)
    return t


def _history_at(monkeypatch, tmp_path, name):
    monkeypatch.setattr(h, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(h, "_HISTORY_FILE", tmp_path / name)
    return tmp_path / name


def test_a_link_to_an_existing_file_is_not_written_through(monkeypatch, tmp_path, sudo, victim):
    link = _history_at(monkeypatch, tmp_path, "history.jsonl")
    link.symlink_to(victim)
    h.save_score(9, "low")
    assert victim.read_text() == "owned by root\n"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    assert not any(p == str(link) for p, _ in sudo)


def test_a_dangling_link_creates_nothing(monkeypatch, tmp_path, sudo):
    missing = tmp_path / "ld.so.preload"
    link = _history_at(monkeypatch, tmp_path, "history.jsonl")
    link.symlink_to(missing)
    h.save_score(9, "low")
    assert not missing.exists()


def test_a_regular_history_is_still_written(monkeypatch, tmp_path, sudo):
    f = _history_at(monkeypatch, tmp_path, "history.jsonl")
    h.save_score(9, "low")
    assert '"score": 9' in f.read_text() and stat.S_IMODE(f.stat().st_mode) == 0o600


def test_chown_to_sudo_user_leaves_a_symlink_alone(tmp_path, sudo, victim):
    link = tmp_path / "last_baseline.json"
    link.symlink_to(victim)
    sysinfo.chown_to_sudo_user(link)
    assert sudo == []


def test_chown_to_sudo_user_goes_through_a_descriptor(tmp_path, sudo):
    f = tmp_path / "config.conf"
    f.write_text("")
    sysinfo.chown_to_sudo_user(f)
    assert sudo == [(str(f), "fd")]


def test_a_symlinked_directory_is_left_alone(tmp_path, sudo):
    real = tmp_path / "etc"; real.mkdir()
    link = tmp_path / "bob"; link.symlink_to(real, target_is_directory=True)
    sysinfo.chown_to_sudo_user(link)
    assert sudo == []


def test_the_mode_is_healed_through_the_descriptor(monkeypatch, tmp_path, sudo):
    """By name, a link swapped in after the open would be re-moded instead."""
    f = _history_at(monkeypatch, tmp_path, "history.jsonl")
    f.write_text("")
    f.chmod(0o644)
    by_name = []
    real_chmod = os.chmod
    monkeypatch.setattr(h.os, "chmod", lambda p, *a, **k: (by_name.append(str(p)), real_chmod(p, *a, **k)))
    h.save_score(9, "low")
    assert stat.S_IMODE(f.stat().st_mode) == 0o600 and by_name == []



class TestASymlinkedParentDirectory:
    """After review: O_NOFOLLOW and follow_symlinks=False guard the last
    component only. Measured on a bench before the fix: with ~/.config/bob a
    symlink to another directory, history.jsonl and last_baseline.json were
    created there and handed over (fchown, chown) — on a host, a link to
    /etc/ld.so.conf.d would have handed the user a config.conf ldconfig reads."""

    @pytest.fixture(params=["bob", "config"])
    def redirected(self, request, monkeypatch, tmp_path):
        """~/.config/bob itself a symlink, or ~/.config — an ancestor, which
        O_NOFOLLOW on the last component does not see."""
        home = tmp_path / "home"; home.mkdir()
        if request.param == "bob":
            (home / ".config").mkdir()
            etc = tmp_path / "etc"; etc.mkdir()
            (home / ".config" / "bob").symlink_to(etc, target_is_directory=True)
        else:
            elsewhere = tmp_path / "elsewhere"; (elsewhere / "bob").mkdir(parents=True)
            (home / ".config").symlink_to(elsewhere, target_is_directory=True)
            etc = elsewhere / "bob"
        monkeypatch.setattr(sysinfo, "get_user_home", lambda: home)
        return home, etc

    def test_the_history_is_not_written_through_it(self, monkeypatch, redirected, sudo):
        home, etc = redirected
        d = home / ".config" / "bob"
        monkeypatch.setattr(h, "_CONFIG_DIR", d)
        monkeypatch.setattr(h, "_HISTORY_FILE", d / "history.jsonl")
        h.save_score(9, "low")
        assert list(etc.iterdir()) == [] and sudo == []

    def test_a_file_there_is_not_handed_over(self, redirected, sudo):
        home, etc = redirected
        (etc / "last_baseline.json").write_text("{}")
        sysinfo.chown_to_sudo_user(home / ".config" / "bob" / "last_baseline.json")
        assert sudo == []

    def test_a_file_really_in_the_home_is(self, monkeypatch, tmp_path, sudo):
        home = tmp_path / "home"; (home / ".config" / "bob").mkdir(parents=True)
        monkeypatch.setattr(sysinfo, "get_user_home", lambda: home)
        f = home / ".config" / "bob" / "last_baseline.json"; f.write_text("{}")
        sysinfo.chown_to_sudo_user(f)
        assert sudo == [(str(f), "fd")]

    def test_a_directory_the_operator_chose_outside_the_home_is_unchanged(self, monkeypatch, tmp_path, sudo):
        monkeypatch.setattr(sysinfo, "get_user_home", lambda: tmp_path / "home")
        logs = tmp_path / "srv" / "logs"; logs.mkdir(parents=True)
        sysinfo.chown_to_sudo_user(logs)
        assert sudo == [(str(logs), "fd")]


    def test_a_descriptor_opened_through_it_is_not_handed_over(self, redirected, sudo):
        home, etc = redirected
        (etc / "history.jsonl").write_text("")
        lexical = home / ".config" / "bob" / "history.jsonl"
        fd = os.open(str(lexical), os.O_RDONLY)
        try:
            sysinfo.chown_fd_to_sudo_user(fd, lexical)
        finally:
            os.close(fd)
        assert sudo == []


# ---------------------------------------------------------------------------
# After review round 10: not handing the file over was not enough — root still
# wrote it wherever the link pointed. Measured on a bench (user namespace,
# euid 0, SUDO_USER set) with 0.26.0: through ~/.config/bob -> <dir>,
# last_baseline.json, recurrence.json, ignore.yml, config.conf and
# history.jsonl were all created in <dir>, and <dir> was chmod'ed 0700 — with
# /etc as <dir>, /etc unreadable to every other account. Through
# ~/.local/share/bob -> <dir>, the report was created there.
# ---------------------------------------------------------------------------

from bob import compare, config, ignore, recurrence, report  # noqa: E402
from bob._atomic import atomic_write  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_refusals(monkeypatch):
    monkeypatch.setattr(sysinfo, "_REDIRECT_REFUSED", {})
    monkeypatch.setattr(sysinfo, "_REDIRECT_SAID", set())


@pytest.fixture(params=["bob", "config"])
def redirected_home(request, monkeypatch, tmp_path):
    home = tmp_path / "home"; home.mkdir()
    if request.param == "bob":
        (home / ".config").mkdir()
        target = tmp_path / "etc"; target.mkdir()
        (home / ".config" / "bob").symlink_to(target, target_is_directory=True)
    else:
        target = tmp_path / "elsewhere"; target.mkdir()
        (home / ".config").symlink_to(target, target_is_directory=True)
    target.chmod(0o755)
    monkeypatch.setattr(sysinfo, "get_user_home", lambda: home)
    return home, target


def _contents(d):
    return sorted(str(x.relative_to(d)) for x in d.rglob("*"))


_WRITERS = {
    "baseline": lambda d: compare.save_baseline(
        compare.AuditBaseline(timestamp="t", score=9, alert_count=0, warn_count=0), path=d / "last_baseline.json"),
    "recurrence": lambda d: recurrence.save_recurrence({"a.b": 1}, path=d / "recurrence.json"),
    "ignore": lambda d: ignore.add_ignore_key("ssh.root_login", path=d / "ignore.yml"),
    "config": lambda d: config.UserConfig.load(path=d / "config.conf").set("audit_profile", "desktop"),
}


class TestNothingIsWrittenThroughARedirectedHome:

    @pytest.mark.parametrize("writer", sorted(_WRITERS))
    def test_the_state_file_is_not_created_there(self, redirected_home, sudo, writer):
        home, target = redirected_home
        try:
            _WRITERS[writer](home / ".config" / "bob")
        except OSError:
            pass  # config.set raises: the write was asked for and did not happen
        assert _contents(target) == [] and sudo == []
        assert stat.S_IMODE(target.stat().st_mode) == 0o755

    def test_the_refusal_is_recorded(self, redirected_home, sudo):
        home, _ = redirected_home
        _WRITERS["baseline"](home / ".config" / "bob")
        assert [lex for lex, _ in sysinfo.refused_redirects()] == [str(home / ".config" / "bob")]

    def test_atomic_write_itself_refuses(self, redirected_home, sudo):
        """The directory may be swapped for a link after it was prepared:
        atomic_write checks the descriptor it writes through."""
        home, target = redirected_home
        (target / "bob").mkdir(exist_ok=True)
        with pytest.raises(sysinfo.RedirectedOutOfHome):
            atomic_write(home / ".config" / "bob" / "recurrence.json", "{}")
        assert not any(p.name == "recurrence.json" for p in target.rglob("*"))

    def test_the_history_checks_its_descriptor_too(self, monkeypatch, redirected_home, sudo):
        home, target = redirected_home
        d = home / ".config" / "bob"
        monkeypatch.setattr(h, "ensure_user_dir", lambda *a, **k: None)  # swapped after it
        monkeypatch.setattr(h, "_CONFIG_DIR", d)
        monkeypatch.setattr(h, "_HISTORY_FILE", d / "history.jsonl")
        h.save_score(9, "low")
        assert not any(p.name == "history.jsonl" for p in target.rglob("*"))

    def test_the_report_is_not_created_there(self, monkeypatch, tmp_path, sudo):
        home = tmp_path / "home"; (home / ".local" / "share").mkdir(parents=True)
        logs = tmp_path / "cron.d"; logs.mkdir()
        (home / ".local" / "share" / "bob").symlink_to(logs, target_is_directory=True)
        monkeypatch.setattr(sysinfo, "get_user_home", lambda: home)
        with pytest.raises(sysinfo.RedirectedOutOfHome):
            report.AuditReport(path=home / ".local" / "share" / "bob" / "bob_x.log")
        assert _contents(logs) == []

    def test_a_directory_not_yet_there_is_not_created_through_an_ancestor(self, monkeypatch, tmp_path, sudo):
        home = tmp_path / "home"; home.mkdir()
        elsewhere = tmp_path / "elsewhere"; elsewhere.mkdir()
        (home / ".config").symlink_to(elsewhere, target_is_directory=True)
        monkeypatch.setattr(sysinfo, "get_user_home", lambda: home)
        with pytest.raises(sysinfo.RedirectedOutOfHome):
            sysinfo.ensure_user_dir(home / ".config" / "bob")
        assert _contents(elsewhere) == []

    def test_the_mode_is_not_set_after_a_swap(self, monkeypatch, tmp_path, sudo):
        """The directory checked, then swapped for a link before the chmod:
        checked again on the descriptor the mode goes through."""
        home = tmp_path / "home"; (home / ".config").mkdir(parents=True)
        etc = tmp_path / "etc"; etc.mkdir(); etc.chmod(0o755)
        (home / ".config" / "bob").symlink_to(etc, target_is_directory=True)
        monkeypatch.setattr(sysinfo, "get_user_home", lambda: home)
        real = os.path.realpath
        monkeypatch.setattr(sysinfo.os.path, "realpath",
                            lambda p: str(home / ".config" / "bob") if str(p).endswith("/bob") else real(p))
        with pytest.raises(sysinfo.RedirectedOutOfHome):
            sysinfo.ensure_user_dir(home / ".config" / "bob", mode=0o700)
        assert stat.S_IMODE(etc.stat().st_mode) == 0o755

    def test_the_mode_goes_through_a_descriptor(self, monkeypatch, tmp_path, sudo):
        monkeypatch.setattr(sysinfo, "get_user_home", lambda: tmp_path)
        by_name = []
        monkeypatch.setattr(sysinfo.os, "chmod", lambda p, *a, **k: by_name.append(str(p)))
        d = tmp_path / ".config" / "bob"
        sysinfo.ensure_user_dir(d, mode=0o700)
        assert stat.S_IMODE(d.stat().st_mode) == 0o700 and by_name == []


class TestWhatStaysWritten:

    def test_a_link_inside_the_home_is_the_users_own(self, monkeypatch, tmp_path, sudo):
        """Dotfiles: ~/.config/bob -> ~/dotfiles/bob. Written in 0.26.0, and still."""
        home = tmp_path / "home"; (home / ".config").mkdir(parents=True)
        dot = home / "dotfiles" / "bob"; dot.mkdir(parents=True)
        (home / ".config" / "bob").symlink_to(dot, target_is_directory=True)
        monkeypatch.setattr(sysinfo, "get_user_home", lambda: home)
        d = home / ".config" / "bob"
        monkeypatch.setattr(h, "_CONFIG_DIR", d)
        monkeypatch.setattr(h, "_HISTORY_FILE", d / "history.jsonl")
        h.save_score(9, "low")
        _WRITERS["baseline"](d)
        assert _contents(dot) == ["history.jsonl", "last_baseline.json"]

    def test_without_sudo_the_users_own_rights_are_not_judged(self, monkeypatch, redirected_home):
        """No root, no one else's file: ~/.config on another disk keeps working."""
        monkeypatch.delenv("SUDO_USER", raising=False)
        monkeypatch.delenv("DOAS_USER", raising=False)
        home, target = redirected_home
        _WRITERS["recurrence"](home / ".config" / "bob")
        assert any(p.name == "recurrence.json" for p in target.rglob("*"))


class TestTheRefusalIsSaid:

    def test_once_per_path_on_stderr(self, redirected_home, sudo, capsys):
        from bob import i18n
        home, _ = redirected_home
        i18n.init("en")
        _WRITERS["baseline"](home / ".config" / "bob")
        _WRITERS["recurrence"](home / ".config" / "bob")
        sysinfo.say_refused_redirects(i18n.t)
        sysinfo.say_refused_redirects(i18n.t)       # --watch: not every cycle
        out = capsys.readouterr()
        assert out.out == "" and out.err.count("resolves outside the home of") == 1
        assert f"realpath {home / '.config' / 'bob'}" in out.err

    @pytest.mark.parametrize("module, line", [("__main__", "            say_refused_redirects(t)\n"),
                                              ("watch", "            say_refused_redirects(t)  #")])
    def test_the_audit_and_watch_say_it(self, module, line):
        import importlib, inspect
        assert line in inspect.getsource(importlib.import_module(f"bob.{module}"))

    def test_a_refused_log_directory_does_not_stop_a_cron_audit(self, monkeypatch, tmp_path, sudo):
        from bob import manage_logs
        home = tmp_path / "home"; (home / ".local" / "share").mkdir(parents=True)
        logs = tmp_path / "cron.d"; logs.mkdir()
        (home / ".local" / "share" / "bob").symlink_to(logs, target_is_directory=True)
        monkeypatch.setattr(sysinfo, "get_user_home", lambda: home)
        monkeypatch.setattr(manage_logs.sys.stdin, "isatty", lambda: False, raising=False)
        class _Cfg:
            output_dir = ""
            def get(self, k): return None
            def set(self, k, v): raise AssertionError("not reached")
        d = manage_logs.get_or_prompt_log_dir(_Cfg(), _Cfg(), lambda k, **kw: k)
        assert d == home / ".local" / "share" / "bob" / "logs" and _contents(logs) == []

    def test_a_choice_not_saved_is_not_said_saved(self, monkeypatch, tmp_path, capsys):
        from bob import manage_logs
        monkeypatch.setattr(sysinfo, "get_user_home", lambda: tmp_path)
        monkeypatch.setattr(manage_logs.sys.stdin, "isatty", lambda: True, raising=False)
        monkeypatch.setattr(manage_logs, "prompt_path", lambda *a, **k: tmp_path / "logs")
        class _Cfg:
            output_dir = ""
            def get(self, k): return None
            def set(self, k, v): raise sysinfo.RedirectedOutOfHome(18, "refused", "x")
        d = manage_logs.get_or_prompt_log_dir(_Cfg(), _Cfg(), lambda k, **kw: k)
        assert d == tmp_path / "logs" and "log_dir.saved" not in capsys.readouterr().out


class TestTheLastComponent:
    """After review: a directory checked by descriptor does not stop a link
    planted at the file's own name — that is O_NOFOLLOW's job, or a rename."""

    def test_a_link_at_the_reports_name_is_not_followed(self, tmp_path, sudo, victim):
        monkey_home = tmp_path  # the report directory is inside the home
        link = monkey_home / "bob_20261023_120000.log"
        link.symlink_to(victim)
        with pytest.raises(OSError):
            report.AuditReport(path=link)
        assert victim.read_text() == "owned by root\n"

    def test_a_link_at_a_state_files_name_is_replaced_not_followed(self, tmp_path, sudo, victim):
        """The temp file is renamed over the name: a link there is replaced,
        its target left alone (measured: rename(2) does not follow it)."""
        link = tmp_path / "last_baseline.json"
        link.symlink_to(victim)
        atomic_write(link, "{}")
        assert victim.read_text() == "owned by root\n"
        assert not link.is_symlink() and link.read_text() == "{}"


class TestManageLogsUnderARedirectedHome:
    """After review: --manage-logs deleted bob_*.log by name, in the directory
    configured, whatever it resolved to."""

    @pytest.fixture
    def logs(self, monkeypatch, tmp_path):
        home = tmp_path / "home"; (home / ".local" / "share" / "bob").mkdir(parents=True)
        outside = tmp_path / "cron.d"; outside.mkdir()
        (outside / "bob_20261023_120000.log").write_text("Score : 9/10\n")
        lexical = home / ".local" / "share" / "bob" / "logs"
        lexical.symlink_to(outside, target_is_directory=True)
        inside = home / "older-logs"; inside.mkdir()
        (inside / "bob_20261022_120000.log").write_text("Score : 9/10\n")
        monkeypatch.setattr(sysinfo, "get_user_home", lambda: home)
        return lexical, outside, inside

    @pytest.mark.parametrize("redirected_is", ["current", "previous"])
    def test_delete_all_leaves_the_redirected_directory_alone(self, logs, sudo, capsys, redirected_is):
        import json
        from types import SimpleNamespace
        from unittest.mock import MagicMock, patch
        from bob import i18n, manage_logs
        lexical, outside, inside = logs
        current, previous = (lexical, inside) if redirected_is == "current" else (inside, lexical)
        store = {"log_dir": str(current), "log_dirs_extra": json.dumps([str(previous)])}
        uc = MagicMock(); uc.get.side_effect = store.get
        i18n.init("en")
        with patch("builtins.input", side_effect=iter(["all", "y", "q"])):
            manage_logs.run_manage_logs(uc, SimpleNamespace(no_color=True), i18n.t)
        assert [p.name for p in outside.iterdir()] == ["bob_20261023_120000.log"]
        assert list(inside.iterdir()) == []                 # inside the home: deleted as asked
        out = capsys.readouterr()
        assert "bob_20261023_120000.log" not in out.out     # not even listed
        assert f"realpath {lexical}" in out.err and "deleted and moved nothing there" in out.err

    def test_a_deletion_checks_the_directory_it_goes_through(self, logs, sudo):
        from bob import manage_logs
        lexical, outside, _ = logs
        with pytest.raises(sysinfo.RedirectedOutOfHome):
            manage_logs._unlink_report(lexical / "bob_20261023_120000.log")
        assert (outside / "bob_20261023_120000.log").exists()

    def test_a_move_into_a_redirected_directory_is_refused(self, logs, sudo):
        from bob import manage_logs
        lexical, outside, inside = logs
        f = inside / "bob_20261022_120000.log"
        with pytest.raises(sysinfo.RedirectedOutOfHome):
            manage_logs._move_report(f, lexical)
        assert f.exists() and [p.name for p in outside.iterdir()] == ["bob_20261023_120000.log"]

    def test_a_move_out_of_a_redirected_directory_is_refused(self, logs, sudo):
        from bob import manage_logs
        lexical, outside, inside = logs
        with pytest.raises(sysinfo.RedirectedOutOfHome):
            manage_logs._move_report(lexical / "bob_20261023_120000.log", inside)
        assert (outside / "bob_20261023_120000.log").exists()

    def test_a_move_inside_the_home_goes_through(self, logs, sudo):
        from bob import manage_logs
        _, _, inside = logs
        dest = inside.parent / "new-logs"; dest.mkdir()
        manage_logs._move_report(inside / "bob_20261022_120000.log", dest)
        assert [p.name for p in dest.iterdir()] == ["bob_20261022_120000.log"] and list(inside.iterdir()) == []

    def test_across_filesystems_it_copies_without_following_a_link(self, logs, sudo, monkeypatch, victim):
        """rename(2) fails with EXDEV across filesystems: the copy opens the
        source with O_NOFOLLOW — a report that is a link to /etc/shadow is not
        copied into the user's directory."""
        import errno
        from bob import manage_logs
        _, _, inside = logs
        dest = inside.parent / "new-logs"; dest.mkdir()
        def exdev(*a, **k):
            raise OSError(errno.EXDEV, "cross-device")
        monkeypatch.setattr(manage_logs.os, "rename", exdev)
        manage_logs._move_report(inside / "bob_20261022_120000.log", dest)
        assert (dest / "bob_20261022_120000.log").read_text() == "Score : 9/10\n"
        assert not (inside / "bob_20261022_120000.log").exists()
        (inside / "bob_20261021_120000.log").symlink_to(victim)
        with pytest.raises(OSError):
            manage_logs._move_report(inside / "bob_20261021_120000.log", dest)
        assert not (dest / "bob_20261021_120000.log").exists()

    def test_both_move_sites_go_through_it(self):
        import inspect
        from bob import manage_logs
        src = inspect.getsource(manage_logs)
        assert "shutil" not in src and src.count("_move_report(") == 3   # def + two callers

    def test_the_curses_list_is_guarded_too(self, logs, sudo):
        import inspect
        from bob import manage_logs
        lexical, _, inside = logs
        assert not manage_logs._listable(lexical) and manage_logs._listable(inside)
        assert "if browse_dir.exists() and _listable(browse_dir):" in inspect.getsource(manage_logs._browse_dir)
        assert "_unlink_report(logs[li])" in inspect.getsource(manage_logs._browse_dir)
        assert "if log_dir.exists() and _listable(log_dir) else []" in inspect.getsource(manage_logs._change_log_dir)
