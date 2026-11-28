"""v0.44.0 — B-054: no numbered temporary directory made for every test.

Found by the CI of 0.43.0 (23 November 2026): three autouse fixtures called
``tmp_path_factory.mktemp`` for every test. pytest numbers those directories by
listing their parent on each call — measured 0.7 ms at 500 entries, 8.9 ms at
10 000 — so the cost grew with the square of the number of tests: the CI jobs
went from 9-16 minutes to 25, three of them past the 30-minute limit. The fix
was one directory per session and a plain mkdir per test (``_host_dir``).

This guard reads the conftest files: no function-scoped autouse fixture, nor
any function-scoped fixture it pulls in, may call ``.mktemp(`` or request
``tmp_path`` / ``tmpdir`` (which make one numbered directory per test too).
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent

_PER_TEST_DIRS = {"tmp_path", "tmpdir"}


def _fixtures(source: str) -> dict:
    """name → (scope, autouse, params, calls_mktemp) for each fixture of *source*."""
    out = {}
    for node in ast.parse(source).body:
        if not isinstance(node, ast.FunctionDef):
            continue
        for deco in node.decorator_list:
            call = deco if isinstance(deco, ast.Call) else None
            name = ast.unparse(call.func if call else deco)
            if not name.endswith("fixture"):
                continue
            kw = {k.arg: k.value for k in (call.keywords if call else [])}
            scope = kw["scope"].value if isinstance(kw.get("scope"), ast.Constant) else "function"
            autouse = isinstance(kw.get("autouse"), ast.Constant) and kw["autouse"].value is True
            calls_mktemp = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                               and n.func.attr == "mktemp" for n in ast.walk(node))
            out[node.name] = (scope, autouse, [a.arg for a in node.args.args], calls_mktemp)
    return out


def _violations(source: str) -> list[str]:
    fixtures = _fixtures(source)
    todo = [n for n, (scope, autouse, _p, _m) in fixtures.items() if autouse and scope == "function"]
    seen, bad = set(), []
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        scope, _autouse, params, calls_mktemp = fixtures[name]
        if calls_mktemp:
            bad.append(f"{name} calls mktemp")
        bad += [f"{name} requests {p}" for p in params if p in _PER_TEST_DIRS]
        todo += [p for p in params if p in fixtures and fixtures[p][0] == "function"]
    return sorted(bad)


def _conftests() -> list[Path]:
    return sorted(ROOT.rglob("conftest.py"))


def test_no_autouse_fixture_makes_a_numbered_directory_per_test():
    bad = {str(p.relative_to(ROOT)): _violations(p.read_text(encoding="utf-8"))
           for p in _conftests()}
    bad = {k: v for k, v in bad.items() if v}
    assert not bad, (
        f"per-test numbered directories in autouse fixtures: {bad}. pytest lists the "
        "parent on each mktemp: the suite slows down as it runs (0.43.0's CI went from "
        "9-16 to 25+ minutes). Use the session root and _host_dir (tests/conftest.py)."
    )


def test_the_sweep_sees_the_autouse_fixtures():
    """Positive control: a sweep that finds no fixture passes forever."""
    fixtures = _fixtures((ROOT / "conftest.py").read_text(encoding="utf-8"))
    autouse = [n for n, (scope, auto, _p, _m) in fixtures.items() if auto and scope == "function"]
    assert len(autouse) >= 5, autouse
    assert fixtures["_host_dirs_root"][0] == "session" and fixtures["_host_dirs_root"][3]


def test_the_sweep_catches_what_it_is_for():
    """The three shapes 0.43.0 had, or could have had, are all seen."""
    sample = '''
import pytest

@pytest.fixture(autouse=True)
def direct(tmp_path_factory, monkeypatch):
    monkeypatch.setattr("x.Y", tmp_path_factory.mktemp("y"))

@pytest.fixture
def per_test_root(tmp_path_factory):
    return tmp_path_factory.mktemp("root")

@pytest.fixture(autouse=True)
def pulled_in(per_test_root):
    pass

@pytest.fixture(autouse=True)
def asks_tmp_path(tmp_path):
    pass

@pytest.fixture(scope="session")
def fine(tmp_path_factory):
    return tmp_path_factory.mktemp("once")
'''
    assert _violations(sample) == ["asks_tmp_path requests tmp_path",
                                   "direct calls mktemp",
                                   "per_test_root calls mktemp"]
