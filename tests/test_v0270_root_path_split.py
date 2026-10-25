"""v0.27.0 — a world-writable directory in root's PATH weighs −2; ".", empty or relative −1.

Decided by the user (24 October 2026). Measured on an Alpine VM: with a
world-writable /tmp/wwbin first in root's PATH, an unprivileged account placed
an `ls` there, root typed `ls` from /root, and it ran as uid 0. With "." first
instead, the planted `ls` ran only when root stood in that account's directory
— from /root it did not. The first needs nothing more than root typing a
common command: the weight of a NOPASSWD rule that is root anyway.
"""

from __future__ import annotations

from bob.checks.root_path import RootPathSnapshot, check_root_path


def _r(*dangerous, group=()):
    return check_root_path(RootPathSnapshot(dangerous=list(dangerous), group_writable=list(group), read_any=True),
                           t=lambda k, **kw: k)


def _points(res):
    return {d.key: d.points for d in res.deductions}


WW = ("login.defs ENV_SUPATH", "/tmp/wwbin", "world_writable")
DOT = ("sudoers secure_path", ".", "dot")


def test_a_world_writable_directory_weighs_two():
    assert _points(_r(WW)) == {"root_path.world_writable": 2}


def test_a_dot_keeps_one():
    assert _points(_r(DOT)) == {"root_path.dangerous": 1}


def test_both_are_said_each_with_its_weight():
    assert _points(_r(WW, DOT)) == {"root_path.world_writable": 2, "root_path.dangerous": 1}


def test_group_writable_alone_is_info_and_clean_is_ok():
    res = _r(group=[("sudoers secure_path", "/opt/x", "group_writable")])
    assert [f.key for f in res.findings] == ["root_path.group_writable"] and not res.deductions
    assert [f.key for f in _r().findings] == ["root_path.clean"]


def test_explain_and_cis():
    from bob.cis_refs import get_cis_ref
    from bob.explain import EXPLAIN_KEYS
    assert "root_path.world_writable" in EXPLAIN_KEYS and get_cis_ref("root_path.world_writable")
