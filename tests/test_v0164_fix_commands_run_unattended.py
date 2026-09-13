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


#: Subcommands that change what is installed. Any of these run unattended must
#: carry the manager's non-interactive flag.
#:
#: v0.17.1 — this was `install|add|-S`, three verbs, and `sudo apt-get upgrade`
#: sat in the auto-apply bucket with no `-y` for the guard's whole lifetime.
#: Proven on a real Debian 13: `--fix --apply --yes` ran it, apt stopped to ask,
#: exit 1, "0 of 1 fix(es) applied". The same shape v0.16.4 closed, in a verb
#: its list did not contain — a guard with an allowlist protects the allowlist.
_MUTATES = re.compile(
    r"(?<![\w-])(install|add|upgrade|remove|purge|erase|reinstall"
    r"|dist-upgrade|patch|-S|-Sy|-Syu|-U|-R|-Rs)(?![\w-])")

#: `update` means two different things and only one of them asks. Measured on
#: Debian 13 with stdin closed: `apt-get update` exits 0 and prompts for
#: nothing — it refreshes the index. `apt-get upgrade` without `-y` exits 1 on
#: "Do you want to continue? [Y/n] Abort." On dnf, yum and zypper, `update` *is*
#: the upgrade and does ask, so the verb is only harmless for the apt family.
_UPDATE = re.compile(r"(?<![\w-])update(?![\w-])")
_APT_FAMILY = re.compile(r"(?<![\w-])(apt|apt-get|aptitude)(?![\w-])")


def _mutates(text: str) -> bool:
    """Whether *text* changes what is installed, and therefore may prompt."""
    if _MUTATES.search(text):
        return True
    return bool(_UPDATE.search(text) and not _APT_FAMILY.search(text))

#: Subcommands that only read. They need no flag, and must be classified rather
#: than left to fall between the two — see test_no_package_verb_is_unclassified.
_READS = re.compile(
    r"(?<![\w-])(list|search|show|info|-q|-Q|-W|--version|policy|why)(?![\w-])")

#: Every package manager BOB may name in a command.
_MANAGERS = re.compile(r"\b(apt|apt-get|aptitude|dnf|yum|zypper|pacman|apk|dpkg|rpm)\b")


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


def _install_templates():
    """The rendered install commands from the shared table.

    v0.17.0 moved every ``sudo apt install …`` out of the call sites and into
    ``_INSTALL_MANAGERS``, because a Debian command is wrong advice on a Fedora
    host. That emptied this guard without failing it — the AST scrape simply
    found nothing to object to, which is how a guard goes quietly inert. The
    table is now scraped too, so a template written without its
    non-interactive flag is caught in the one place all of them live.
    """
    from bob.checks._run import _INSTALL_MANAGERS, _PKGS
    return [
        (f"bob/checks/_run.py:_INSTALL_MANAGERS[{tool}]", f"install.{tool}",
         "action", "fix", template.replace(_PKGS, "somepackage"))
        for tool, template in _INSTALL_MANAGERS
    ]


def _upgrade_templates():
    """The rendered upgrade commands from ``updates._upgrade_cmd``.

    v0.19.0 moved the pending-security remediation into a per-manager table so
    a dnf host is not told to run apt. Like the install commands, they reach a
    call site as ``cmd=_upgrade_cmd(mgr)`` — a call, not a literal — so the AST
    scrape above cannot see them. Scrape the table too, or a manager's upgrade
    command written without its non-interactive flag goes unchecked.

    Only apt/dnf/zypper are listed: they are the managers with a security
    channel, so they are the only ones whose ``_upgrade_cmd`` BOB ever hands
    over as a fix (``security_pending`` fires). pacman and apk report every
    pending package as a regular INFO with no cmd, so their full-system upgrade
    is never auto-applied — and a manually run ``pacman -Syu`` is *meant* to
    prompt.
    """
    from bob.checks.updates import _upgrade_cmd
    managers = ("apt", "dnf", "zypper")
    return [
        (f"bob/checks/updates.py:_upgrade_cmd[{m}]", f"updates.upgrade.{m}",
         "action", "fix", _upgrade_cmd(m))
        for m in managers
    ]


def test_the_scan_finds_commands_at_all():
    """A scraper that matched nothing would satisfy everything below.

    A comfortable floor, not the exact count: v0.19.0 turned the
    ``updates.security_pending`` literal cmd into ``cmd=_upgrade_cmd(mgr)`` (a
    call the AST scrape skips — _upgrade_templates carries it now), so an
    exact ``> 80`` boundary would trip on a legitimate refactor. The guard is
    against an empty scrape, so a wide margin below the real count is right.
    """
    assert len(_fix_commands()) > 70, "the cmd scrape broke"


def test_every_manager_has_a_template_to_scan():
    """The install half moved to a table; the guard has to follow it there."""
    from bob.checks._run import _INSTALL_MANAGERS
    rendered = _install_templates()
    assert len(rendered) == len(_INSTALL_MANAGERS) >= 5
    assert all("somepackage" in text for *_rest, text in rendered)


@pytest.mark.parametrize("manager", sorted(_PROMPTS))
def test_no_install_command_would_stop_to_ask(manager):
    """Whether BOB runs it or the operator copies it, it must not hang."""
    flags = _PROMPTS[manager]
    offenders = []
    for where, key, _nature, _ctype, text in _fix_commands() + _install_templates() + _upgrade_templates():
        if not re.search(rf"\b{re.escape(manager)}\b", text):
            continue
        if not _mutates(text):
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


def test_no_package_verb_is_unclassified():
    """A command naming a package manager must be read as reading or mutating.

    v0.17.1 — the third category is where `apt-get upgrade` lived: not matched
    by the mutating list, so never checked for its flag, and not declared
    read-only either. Nothing objected because nothing was looking. A verb that
    falls between the two is now a failure, so the next one has to be
    classified deliberately rather than by omission.
    """
    unclassified = []
    for where, key, _nature, _ctype, text in _fix_commands() + _install_templates() + _upgrade_templates():
        if not _MANAGERS.search(text):
            continue
        if _mutates(text) or _READS.search(text) or _UPDATE.search(text):
            continue
        unclassified.append(f"{where} ({key}): {text[:70]}")
    assert not unclassified, (
        "these name a package manager but no rule says whether they change "
        f"anything, so no rule checks their flags: {unclassified}"
    )


def test_the_mutating_list_covers_what_broke():
    """Negative control: the verbs that actually shipped without a flag."""
    for cmd in ("sudo apt-get upgrade", "sudo apt upgrade",
                "sudo apt install ufw", "sudo pacman -S ufw", "sudo apk add ufw",
                "sudo dnf update", "sudo zypper update"):
        assert _mutates(cmd), f"{cmd!r} is not read as mutating"
    # apt's `update` only refreshes the index — measured: exit 0, no prompt.
    for cmd in ("sudo apt update", "sudo apt-get update"):
        assert not _mutates(cmd), f"{cmd!r} was wrongly read as prompting"
    for cmd in ("apt list --upgradable", "rpm -q bash", "dpkg-query -W nginx"):
        assert _READS.search(cmd), f"{cmd!r} is not read as read-only"
