"""A fix `--fix --apply --yes` runs must not stop to ask a question.

Found in a throwaway container, which is the only place `--fix --apply` can be
driven for real: `sudo apt install ufw` exits 1 under auto-fix. apt refuses to
proceed without confirmation, and says so itself — *"apt does not have a stable
CLI interface. Use with caution in scripts."* So the mode whose entire promise
is "apply these without asking me" ran a command that asks, and reported
`0 of 2 fix(es) applied.`

Seventeen install commands carried no non-interactive flag; three to four of
them reach execution. Proven in the container, before and after:

    sudo apt install ufw      -> exit 1
    sudo apt install -y ufw   -> exit 0    and the finding disappears

The suite cannot install packages, so this holds the shape rather than the
behaviour: a command BOB may run itself must not be one that waits for a human.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Package managers that prompt unless told otherwise, and the flag that tells
#: them. `apt`/`apt-get` and `dnf`/`yum` take `-y`; pacman takes `--noconfirm`.
_PROMPTS = {
    "apt": ("-y", "--yes"), "apt-get": ("-y", "--yes"),
    "dnf": ("-y", "--assumeyes"), "yum": ("-y", "--assumeyes"),
    "pacman": ("--noconfirm",), "zypper": ("-y", "--non-interactive"),
    "apk": ("--no-interactive",),
}


def _fix_commands():
    """(where, key, nature, cmd_type, literal text) for every emitted cmd."""
    out = []
    for path in sorted((_ROOT / "bob").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            kw = {k.arg: k.value for k in node.keywords}
            if "cmd" not in kw:
                continue
            get = lambda n, d=None: (kw[n].value if n in kw
                                     and isinstance(kw[n], ast.Constant) else d)
            raw = kw["cmd"]
            if isinstance(raw, ast.JoinedStr):
                text = "".join(p.value for p in raw.values
                               if isinstance(p, ast.Constant))
            elif isinstance(raw, ast.Constant):
                text = raw.value
            else:
                continue
            out.append((f"{path.relative_to(_ROOT)}:{node.lineno}", get("key"),
                        get("nature"), get("cmd_type", "fix"), text))
    return out


def test_the_scan_finds_commands_at_all():
    """A scraper that matched nothing would satisfy everything below."""
    assert len(_fix_commands()) > 100, "the cmd scrape broke"


@pytest.mark.parametrize("manager", sorted(_PROMPTS))
def test_no_install_command_would_stop_to_ask(manager):
    """Whether BOB runs it or the operator copies it, it must not hang."""
    flags = _PROMPTS[manager]
    offenders = []
    for where, key, _nature, _ctype, text in _fix_commands():
        if not re.search(rf"\b{re.escape(manager)}\b", text):
            continue
        if not re.search(r"\b(install|add|-S)\b", text):
            continue
        if any(re.search(rf"(?<!\w){re.escape(f)}(?!\w)", text) for f in flags):
            continue
        offenders.append(f"{where} ({key}): {text[:60]}")
    assert not offenders, (
        f"{manager} install commands that would wait for a human: {offenders}"
    )


def test_the_check_would_notice_one():
    """The negative control: the pattern must reject the pre-v0.16.4 form."""
    text = "sudo apt install ufw"
    assert re.search(r"\bapt\b", text) and re.search(r"\binstall\b", text)
    assert not any(re.search(rf"(?<!\w){re.escape(f)}(?!\w)", text)
                   for f in _PROMPTS["apt"])


def test_a_flag_inside_a_package_name_does_not_count():
    """`-y` must be a flag, not a substring of something else."""
    text = "sudo apt install python3-yaml"
    assert not any(re.search(rf"(?<!\w){re.escape(f)}(?!\w)", text)
                   for f in _PROMPTS["apt"]), (
        "a package name containing 'y' was mistaken for the flag"
    )
