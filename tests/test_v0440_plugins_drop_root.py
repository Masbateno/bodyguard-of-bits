"""v0.44.0 — B-055 step 1: plugins run with the calling account's rights.

Measured on a test host (26 November 2026): under sudo, the child process that
ran a plugin taken from the calling user's ~/.config/bob/checks.d had uid 0 —
so allowing someone to run ``sudo bob`` gave their plugin code root.

The child now gives up root before reading any plugin code: to the account
behind sudo or doas, else to the owner of the plugin file, read on the very
descriptor the source is read from. These tests drive the drop with stand-ins
for ``os`` and ``pwd``: the real ones of the test process are never touched.
"""

from __future__ import annotations

import ast
import inspect
import queue
import types
from pathlib import Path

from bob import _sandbox as sb


class FakeOS:
    """What _drop_privileges and _invoker_identity use of ``os``."""

    def __init__(self, euid=0, st_uid=1001, st_gid=1003, fail=None, keep=False):
        self.euid, self.fail, self.keep = euid, fail, keep
        self.st = types.SimpleNamespace(st_uid=st_uid, st_gid=st_gid)
        self.calls: list = []
        self._uid = self._gid = None

    def geteuid(self):
        return self.euid

    def fstat(self, _fd):
        return self.st

    def getgrouplist(self, _name, gid):
        return [gid, 27]

    def setgroups(self, groups):
        self.calls.append(("setgroups", list(groups)))

    def setresgid(self, *ids):
        self.calls.append(("setresgid", ids))
        self._gid = ids

    def setresuid(self, *ids):
        if self.fail:
            raise self.fail
        self.calls.append(("setresuid", ids))
        self._uid = ids

    def getresuid(self):
        return (0, 0, 0) if self.keep else self._uid

    def getresgid(self):
        return self._gid


class FakePwd:
    def __init__(self, known=True):
        self.known = known

    def getpwuid(self, uid):
        if not self.known:
            raise KeyError(uid)
        return types.SimpleNamespace(pw_uid=uid, pw_gid=1003, pw_name="alice")

    def getpwnam(self, name):
        if not self.known:
            raise KeyError(name)
        return types.SimpleNamespace(pw_uid=1001, pw_gid=1003, pw_name=name)


# --- the drop ----------------------------------------------------------------------

def test_a_bob_that_is_not_root_gives_up_nothing():
    fos = FakeOS(euid=1000)
    assert sb._drop_privileges(3, (1001, 1003, [1003]), _os=fos, _pwd=FakePwd()) is None
    assert fos.calls == []


def test_the_invoking_account_is_taken_groups_then_group_then_user():
    fos = FakeOS()
    assert sb._drop_privileges(3, (1001, 1003, [1003, 27]), _os=fos, _pwd=FakePwd()) is None
    assert fos.calls == [("setgroups", [1003, 27]),
                         ("setresgid", (1003, 1003, 1003)),
                         ("setresuid", (1001, 1001, 1001))]


def test_without_an_invoking_account_the_file_owner_is_taken():
    fos = FakeOS(st_uid=1001)
    assert sb._drop_privileges(3, None, _os=fos, _pwd=FakePwd()) is None
    assert ("setresuid", (1001, 1001, 1001)) in fos.calls
    assert ("setgroups", [1003, 27]) in fos.calls


def test_root_running_its_own_root_owned_plugin_keeps_root():
    fos = FakeOS(st_uid=0)
    assert sb._drop_privileges(3, None, _os=fos, _pwd=FakePwd()) is None
    assert fos.calls == []


def test_an_owner_with_no_account_is_still_given_up_to():
    fos = FakeOS(st_uid=4242, st_gid=4242)
    assert sb._drop_privileges(3, None, _os=fos, _pwd=FakePwd(known=False)) is None
    assert fos.calls == [("setgroups", []), ("setresgid", (4242, 4242, 4242)),
                         ("setresuid", (4242, 4242, 4242))]


def test_a_failed_drop_refuses_the_plugin():
    fos = FakeOS(fail=PermissionError(1, "Operation not permitted"))
    why = sb._drop_privileges(3, (1001, 1003, [1003]), _os=fos, _pwd=FakePwd())
    assert why and "PermissionError" in why


def test_a_drop_that_did_not_take_refuses_the_plugin():
    fos = FakeOS(keep=True)
    assert sb._drop_privileges(3, (1001, 1003, [1003]), _os=fos, _pwd=FakePwd()) == \
        "the process kept other ids"


# --- who the invoking account is ---------------------------------------------------

def test_no_invoking_account_is_looked_for_when_bob_is_not_root(monkeypatch):
    monkeypatch.setattr("bob.sysinfo.invoking_user_name", lambda: "alice")
    assert sb._invoker_identity(_os=FakeOS(euid=1000), _pwd=FakePwd()) is None


def test_the_account_behind_sudo_is_resolved_with_its_groups(monkeypatch):
    monkeypatch.setattr("bob.sysinfo.invoking_user_name", lambda: "alice")
    assert sb._invoker_identity(_os=FakeOS(), _pwd=FakePwd()) == (1001, 1003, [1003, 27])


def test_root_without_sudo_has_no_invoking_account(monkeypatch):
    monkeypatch.setattr("bob.sysinfo.invoking_user_name", lambda: "")
    assert sb._invoker_identity(_os=FakeOS(), _pwd=FakePwd()) is None


def test_an_unknown_invoking_account_leaves_it_to_the_file_owner(monkeypatch):
    monkeypatch.setattr("bob.sysinfo.invoking_user_name", lambda: "ghost")
    assert sb._invoker_identity(_os=FakeOS(), _pwd=FakePwd(known=False)) is None


# --- where the drop happens --------------------------------------------------------

def _call_lines(func) -> dict[str, int]:
    tree = ast.parse(inspect.getsource(func).lstrip())
    lines: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
            lines.setdefault(name, node.lineno)
    return lines


def test_the_worker_gives_up_root_before_restricting_or_running_anything():
    lines = _call_lines(sb._worker_main)
    assert "_drop_privileges" in lines, "the worker no longer gives up root"
    for later in ("_apply_resource_limits", "_strip_os_dangerous_attrs", "exec"):
        assert lines["_drop_privileges"] < lines[later], later


def test_the_worker_reads_the_source_from_the_descriptor_it_checked():
    """Read by name again, the file could be swapped after the owner check."""
    source = inspect.getsource(sb._worker_main)
    assert "builtins.open(plugin_path" not in source
    assert "builtins.open(fd" in source


def test_the_runner_hands_the_invoking_account_to_the_child(monkeypatch):
    seen = {}

    class FakeProcess:
        exitcode = 0

        def __init__(self, target, args):
            seen["args"] = args

        def start(self):
            pass

        def join(self, timeout=None):
            pass

        def is_alive(self):
            return False

    class FakeQueue:
        def get(self, timeout=None):
            raise queue.Empty

        def close(self):
            pass

        def join_thread(self):
            pass

    ctx = types.SimpleNamespace(Queue=FakeQueue, Process=FakeProcess)
    monkeypatch.setattr(sb.mp, "get_context", lambda method: ctx)
    monkeypatch.setattr(sb, "_invoker_identity", lambda: (1001, 1003, [1003]))
    sb.SandboxRunner()._run_sandboxed(Path("/nonexistent/p.py"))
    assert seen["args"][2] == (1001, 1003, [1003])


def test_the_refusal_is_said_in_both_languages():
    import json
    root = Path(sb.__file__).resolve().parent / "locales"
    for lang in ("en", "fr"):
        data = json.loads((root / f"{lang}.json").read_text(encoding="utf-8"))
        assert "{plugin}" in data["plugin"]["sandbox"]["privilege_drop_failed"]
    assert "plugin.sandbox.privilege_drop_failed" in sb._WORKER_FALLBACKS


def test_a_failed_drop_returns_before_any_plugin_code():
    """The refusal branch must report and return: never fall through to exec."""
    tree = ast.parse(inspect.getsource(sb._worker_main).lstrip())
    branch = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "refused"),
                  None)
    assert branch is not None, "no `if refused:` branch in the worker"
    assert any(isinstance(s, ast.Return) for s in branch.body)
    assert "privilege_drop_failed" in ast.unparse(branch)
