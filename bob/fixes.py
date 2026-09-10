"""
Fix mode UI for BOB.

Handles the --fix / --yes flow: displays actionable findings, prompts
the user to apply each fix, and runs the suggested commands.
"""

from __future__ import annotations

import os
import re
import shlex
import signal
import subprocess
from pathlib import Path

from bob import output as _output
from bob._tty import safe_input


def _has_shell_ops(cmd: str) -> bool:
    """Return True if cmd contains shell operators requiring shell=True."""
    _SHELL_TOKENS = frozenset({"&&", "||", ";", "|", ">", ">>", "<", "&"})
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return True  # malformed quoting — treat as unsafe
    return any(tok in _SHELL_TOKENS or tok.startswith("`") or tok.startswith("$(")
               for tok in tokens)



def _print_unapplied(diag_items, manual_items, t, _c) -> None:
    """The two buckets BOB cannot act on, with their commands kept visible."""
    if diag_items:
        print()
        print(f"  {_c.yellow_bold}{t('fixes.diagnostic_items_title')}{_c.reset}")
        for msg, cmd in diag_items:
            print(f"  •  {msg}")
            print(f"     {_c.dim}ℹ {_c.reset}"
                  f"{_output.command(cmd.replace(chr(10), ' ').strip())}")
    if manual_items:
        print()
        print(f"  {_c.yellow_bold}{t('fixes.manual_items_title')}{_c.reset}")
        for msg in manual_items:
            print(f"  • {msg}")


#: Commands that need a human at a keyboard. `--fix --apply` runs everything
#: with stdin closed on a 30-second timeout, so an editor would hang there
#: until it was killed.
_INTERACTIVE = ("nano", "vim", "vi", "emacs", "editor", "$EDITOR")


#: Commands that can cut the operator off from the machine they are auditing.
#:
#: Measured on an Arch VM, v0.18.0 stress pass 4. `--fix --apply --yes` ran
#: `iptables -P INPUT DROP` and left the host with loopback broken and outbound
#: broken — and BOB then reported, in the same audit, that the loopback and
#: conntrack rules it needs were missing. It applied a policy whose
#: prerequisites it knows about and does not install.
#:
#: A default-deny policy is correct hardening and the wrong thing to do
#: unattended: on a remote host it ends the session that started it. The
#: command stays on screen with its explanation; BOB does not run it.
#: A rule that opens a port, and a command that turns a default-deny firewall
#: on. The first has to run before the second, or the second removes the
#: operator's way back in before the first can be typed.
_GRANTS_ACCESS = re.compile(r"(?<![\w-])ufw\s+(?:--force\s+)?allow(?![\w-])",
                            re.IGNORECASE)
_WITHDRAWS_ACCESS = re.compile(
    r"(?<![\w-])ufw\s+(?:--force\s+)?(?:enable|default\s+deny)(?![\w-])",
    re.IGNORECASE)

_LOCKOUT_COMMANDS = re.compile(
    # ip6tables and the -nft/-legacy variants cut the same access; the family
    # in the binary's name is not the point.
    r"(?<![\w-])ip6?tables(?:-nft|-legacy)?\s+.*-P\s+(?:INPUT|FORWARD)\s+DROP"
    r"|(?<![\w-])nft\s+.*policy\s+drop",
    re.IGNORECASE,
)


def _can_apply_unattended(cmd: str) -> bool:
    """Whether BOB can actually run *cmd* itself, with nobody watching.

    This used to be asked at execution time, one command after the operator
    had already agreed to all of them — so the count above the prompt was a
    promise BOB could not keep. Twelve findings carried shell operators,
    including `ssh.password_auth`, the most consequential fix in the tool:
    BOB announced "2 automatic fix(es) available", said "2 will be applied
    automatically", and then applied `0 of 2`.

    Asking here instead makes the count true before consent is given. The
    execution-time refusal stays as a second barrier — a command reaching it
    now means these two disagree, which is worth failing on.
    """
    if _LOCKOUT_COMMANDS.search(cmd):
        return False
    if _has_shell_ops(cmd):
        return False
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return False
    # Match on the basename so an absolute path is caught too.
    return not any(arg.rsplit("/", 1)[-1] in _INTERACTIVE for arg in argv)


#: Package transactions are the one class of fix BOB proposes that
#: legitimately runs for minutes rather than seconds: a mirror to reach, an
#: archive to unpack, maintainer scripts to run. Thirty seconds was never a
#: budget for them, it was a budget for `ufw delete`.
_PACKAGE_TOOLS = frozenset({
    "apt", "apt-get", "aptitude", "dpkg", "dpkg-reconfigure",
    "dnf", "dnf5", "yum", "rpm", "zypper", "pacman", "apk",
    "snap", "flatpak", "unattended-upgrade", "unattended-upgrades",
})

_TIMEOUT_DEFAULT = 30
_TIMEOUT_PACKAGE = 900

#: How long a stopped process tree gets to unwind after SIGTERM before BOB
#: escalates. dpkg uses the window to finish the item it is on.
_TERM_GRACE = 15


def _timeout_for(argv) -> int:
    """Seconds *argv* is allowed to take.

    Matches on the basename of every argument, so `sudo /usr/bin/apt-get`
    and a bare `apt-get` land in the same bucket.
    """
    if any(arg.rsplit("/", 1)[-1] in _PACKAGE_TOOLS for arg in argv):
        return _TIMEOUT_PACKAGE
    return _TIMEOUT_DEFAULT


def _stop_tree(proc) -> None:
    """Stop the whole process group *proc* leads, SIGTERM then SIGKILL."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except OSError:
            # Already gone, or owned by root while BOB runs unprivileged —
            # either way there is nothing more BOB can do about it.
            break
        try:
            proc.communicate(timeout=_TERM_GRACE)
            return
        except subprocess.TimeoutExpired:
            continue
    try:
        proc.communicate(timeout=_TERM_GRACE)
    except subprocess.TimeoutExpired:
        pass


def _run_fix_command(argv, timeout):
    """Run *argv* to completion, or stop its whole process tree trying.

    Returns ``(status, returncode, stderr)`` with *status* one of ``"ok"``,
    ``"failed"`` or ``"timeout"``.

    `subprocess.run(timeout=…)` kills the direct child and nothing below it.
    Every package fix BOB proposes is `sudo apt-get …`, so the direct child
    is *sudo*: killing it orphans the `apt-get` underneath, which carries on
    unwatched. Measured on a Debian 13 VM — BOB printed `0 of 1 fix(es)
    applied` while `apt-get upgrade -y` was still mid-`dpkg --configure`,
    holding the apt lock, with BOB already gone.

    `start_new_session=True` makes the child a process-group leader, so the
    timeout can signal the group and actually stop what BOB started.
    """
    proc = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        _, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _stop_tree(proc)
        return "timeout", None, b""
    return ("ok" if proc.returncode == 0 else "failed"), proc.returncode, stderr


def _apply_native(action: dict):
    """Carry out a structured fix in BOB's own code, and report it like a run.

    Returns the same ``(status, code, stderr)`` triple the subprocess path
    does, so the loop that prints the outcome does not need to know which path
    ran. A fix that took effect but could not be persisted reports as failed
    with the reason attached: live-but-not-persisted reverts at the next boot,
    and calling it applied would be the exact class of lie v0.17.1 spent a
    release removing.
    """
    from bob._sysctl_apply import apply_sysctl

    if action.get("kind") != "sysctl":
        return "failed", None, b"unknown fix action"
    result = apply_sysctl(action.get("param", ""),
                          Path(action.get("conf", "/etc/sysctl.d/99-hardening.conf")))
    if result.applied and result.persisted:
        return "ok", 0, b""
    return "failed", None, result.reason.encode()


def run_fixes(engine, config, t) -> None:
    """Display and optionally apply automatic fixes.

    Three buckets, and until v0.16.4 there were two. ``cmd_type`` says whether
    a command remediates (``"fix"``) or only diagnoses (``"check"`` — its own
    docstring: *read-only diagnostic commands that do not change state*), and
    this function never read it. It selected on ``nature`` alone, so six
    findings whose command is a diagnostic were counted as automatic fixes,
    executed, and reported as ``✔ Applied``: four SMART alerts answered with
    ``smartctl -a``, a full partition answered with ``du``, and "no fail2ban
    jails" answered with ``fail2ban-client status``. The disk was still dying
    and the operator had been told it was fixed.

    Their classification was right and is unchanged — a failing disk *is* an
    action, and ``smartctl -a`` *is* a diagnostic. What was wrong is that
    ``nature`` was doing two jobs at once, "the operator must act" and "put it
    in the fix list". Reading ``cmd_type`` gives the second job back to the
    field that was written for it.

    The third bucket exists because dropping them from ``auto_items`` alone
    would have removed them from the screen entirely: ``manual_items`` holds
    findings with *no* command. Visible but mislabelled was bad; invisible
    would have been worse.
    """
    actionable   = [f for f in engine.findings if f.nature == "action"]
    # v0.18.0: a finding carrying a `fix_action` is applicable whatever its
    # displayed command looks like. The thirteen sysctl fixes read as shell
    # one-liners because that is how a human writes a two-step change; BOB
    # applies them through its own code instead — see bob/_sysctl_apply.py.
    auto_items   = [(f.message, f.cmd, f.fix_action) for f in actionable
                    if f.cmd and f.cmd_type == "fix"
                    and (f.fix_action or _can_apply_unattended(f.cmd))]
    diag_items   = [(f.message, f.cmd) for f in actionable
                    if f.cmd and not (f.cmd_type == "fix"
                                      and (f.fix_action
                                           or _can_apply_unattended(f.cmd)))]
    manual_items = [f.message for f in actionable if not f.cmd]

    _c = _output._c
    W = 62
    print()
    print(f"{_c.blue_bold}╔{'═'*(W-2)}╗{_c.reset}")
    label = t("fixes.title")
    pad = W - 6 - len(label)
    print(f"{_c.blue_bold}║{_c.reset}  {_c.bold}{label}{_c.reset}{' '*max(0,pad)}  {_c.blue_bold}║{_c.reset}")
    print(f"{_c.blue_bold}╠{'═'*(W-2)}╣{_c.reset}")

    if not auto_items and not diag_items and not manual_items:
        none_msg = t("fixes.none")
        pad = W - 6 - len(none_msg)
        print(f"{_c.blue_bold}║{_c.reset}    {none_msg}{' '*max(0,pad)}{_c.blue_bold}║{_c.reset}")
    else:
        # "0 automatic fix(es) available" over a list of urgent findings reads
        # as "nothing to do here" to anyone skimming. When BOB can apply none
        # of them, the header says what is actually true: they need a human.
        if auto_items:
            count_msg = t("fixes.count", count=len(auto_items))
            mark = "✔"
        else:
            count_msg = t("fixes.count_manual_only",
                          count=len(diag_items) + len(manual_items))
            mark = "⚠"
        pad = W - 9 - len(count_msg)
        print(f"{_c.blue_bold}║{_c.reset}    {mark}  {count_msg}{' '*max(0,pad)}{_c.blue_bold}║{_c.reset}")
    print(f"{_c.blue_bold}╚{'═'*(W-2)}╝{_c.reset}")

    if not auto_items and not diag_items and not manual_items:
        return

    # Sort ufw delete commands descending to avoid renumbering
    _UFW_DELETE_RE = re.compile(r"^(?:sudo\s+)?ufw\s+.*--force\s+delete\s+\d+$")
    ufw_deletes = [it for it in auto_items if _UFW_DELETE_RE.search(it[1])]
    others      = [it for it in auto_items if not _UFW_DELETE_RE.search(it[1])]

    def sort_key(item):
        match = re.search(r"delete (\d+)$", item[1])
        return int(match.group(1)) if match else 0

    # v0.18.0: a rule that grants access runs before one that withdraws it.
    # Measured on an Arch VM with sshd listening, BOB offered — in this order —
    # `ufw enable`, `ufw allow 22`, `ufw enable`. Applied unattended on a
    # remote host, the first line ends the session and the second never reaches
    # anyone. BOB already knew to allow the port; it simply did it second.
    def access_phase(item) -> int:
        cmd = item[1]
        if _GRANTS_ACCESS.search(cmd):
            return 0
        if _WITHDRAWS_ACCESS.search(cmd):
            return 2
        return 1

    others = sorted(others, key=access_phase)
    sorted_items = sorted(ufw_deletes, key=sort_key, reverse=True) + others

    # ── Dry-run preview (--fix without --apply) ─────────────────────────────
    if not getattr(config, "apply", False):
        print()
        _output.print_dim(t('fixes.dry_run_hint',
                            cmd=_output.command('--fix --apply')))
        print()
        for msg, cmd, _action in sorted_items:
            safe_cmd = cmd.replace("\n", " ").strip()
            print(f"  ✖  {msg}")
            # The whole point of this screen is the commands; they are the
            # canonical place to copy from, so they wear the convention.
            print(f"     {_c.dim}→ {_c.reset}{_output.command(safe_cmd)}")
            print()
        _print_unapplied(diag_items, manual_items, t, _c)
        return

    # ── Apply mode (--fix --apply) ───────────────────────────────────────────
    # Auto-fix mode banner — visible warning so the user knows what's happening
    if config.yes and sorted_items:
        auto_msg = t("fixes.auto_mode_banner", count=len(sorted_items))
        print(f"{_c.yellow_bold}  ⚠  {auto_msg}{_c.reset}")
        print()

    applied_cmds = []
    unknown_cmds = []
    skipped_cmds = 0

    print()
    for msg, cmd, action in sorted_items:
        safe_cmd = cmd.replace("\n", " ").strip()
        print(f"  ✖  {msg}")
        print(f"  → {_output.command(safe_cmd)}")
        if config.yes:
            answer = "y"
        else:
            answer = safe_input(f"  {t('fixes.apply_prompt')} ").strip().lower()

        if answer == "y":
            # v0.18.0: the native path runs no command, so the shell-operator
            # barrier below does not apply to it. That barrier stays exactly
            # where it is for everything else — v0.16.4 put it there so that a
            # command reaching execution after the selection filter let it
            # through is a disagreement worth failing on, and it caught this
            # very change the first time round.
            if _has_shell_ops(cmd) and not action:
                print(f"  ✖ {t('fixes.manual')} ({t('fixes.skipped_unsafe_shell')})")
                skipped_cmds += 1
                print()
                continue
            try:
                if action:
                    status, rc, err = _apply_native(action)
                else:
                    argv = shlex.split(cmd)
                    timeout = _timeout_for(argv)
                    status, rc, err = _run_fix_command(argv, timeout)
                if status == "ok":
                    print(f"  ✔ {t('fixes.applied')}")
                    applied_cmds.append(cmd)
                elif status == "timeout":
                    # Not "not applied" — BOB stopped waiting on a command it
                    # had already started, so the system may be halfway
                    # through the change. Telling the operator to "apply the
                    # command manually" here would be advice to run a second
                    # package transaction over the wreck of the first.
                    print(f"  ⚠ {t('fixes.timed_out', seconds=timeout)}")
                    unknown_cmds.append(cmd)
                else:
                    stderr = err.decode(errors="replace").strip()
                    detail = f" — {stderr}" if stderr else ""
                    print(f"  ✖ {t('fixes.manual')} (exit {rc}{detail})")
            except (OSError, ValueError) as exc:
                print(f"  ✖ {t('fixes.manual')} ({type(exc).__name__})")
                skipped_cmds += 1
        else:
            print(f"  ✖ {t('fixes.manual')}")
            skipped_cmds += 1
        print()

    # "0 of 0 fix(es) applied." under a list BOB never intended to run is
    # noise that reads like a failure.
    if sorted_items:
        print(f"  {t('fixes.done_summary', applied=len(applied_cmds), total=len(sorted_items))}")

    # A command BOB stopped waiting on is neither applied nor skipped, and
    # the operator has to know before touching the machine again.
    if unknown_cmds:
        print()
        print(f"  {_c.yellow_bold}{t('fixes.unknown_items_title')}{_c.reset}")
        for cmd in unknown_cmds:
            print(f"  ⚠ {_output.command(cmd)}")

    # Auto-fix summary — list every command that was applied
    if config.yes and applied_cmds:
        print()
        print(f"{_c.blue_bold}  [{t('fixes.auto_summary_title')}]{_c.reset}")
        for cmd in applied_cmds:
            print(f"  ✔ {_output.command(cmd)}")

    # What BOB did not apply: diagnostics it can only show, and findings with
    # no command at all. Same block as the dry run, so the two cannot drift.
    _print_unapplied(diag_items, manual_items, t, _c)
