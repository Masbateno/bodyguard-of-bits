"""
Fix mode UI for BOB.

Handles the --fix / --yes flow: displays actionable findings, prompts
the user to apply each fix, and runs the suggested commands.
"""

from __future__ import annotations

import re
import shlex
import subprocess

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
            print(f"     {_c.dim}ℹ {cmd.replace(chr(10), ' ').strip()}{_c.reset}")
    if manual_items:
        print()
        print(f"  {_c.yellow_bold}{t('fixes.manual_items_title')}{_c.reset}")
        for msg in manual_items:
            print(f"  • {msg}")


#: Commands that need a human at a keyboard. `--fix --apply` runs everything
#: with stdin closed on a 30-second timeout, so an editor would hang there
#: until it was killed.
_INTERACTIVE = ("nano", "vim", "vi", "emacs", "editor", "$EDITOR")


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
    if _has_shell_ops(cmd):
        return False
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return False
    # Match on the basename so an absolute path is caught too.
    return not any(arg.rsplit("/", 1)[-1] in _INTERACTIVE for arg in argv)


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
    auto_items   = [(f.message, f.cmd) for f in actionable
                    if f.cmd and f.cmd_type == "fix"
                    and _can_apply_unattended(f.cmd)]
    diag_items   = [(f.message, f.cmd) for f in actionable
                    if f.cmd and not (f.cmd_type == "fix"
                                      and _can_apply_unattended(f.cmd))]
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
    ufw_deletes = [(m, c) for m, c in auto_items if _UFW_DELETE_RE.search(c)]
    others      = [(m, c) for m, c in auto_items if not _UFW_DELETE_RE.search(c)]

    def sort_key(item):
        match = re.search(r"delete (\d+)$", item[1])
        return int(match.group(1)) if match else 0

    sorted_items = sorted(ufw_deletes, key=sort_key, reverse=True) + others

    # ── Dry-run preview (--fix without --apply) ─────────────────────────────
    if not getattr(config, "apply", False):
        print()
        print(f"  {_c.dim}{t('fixes.dry_run_hint')}{_c.reset}")
        print()
        for msg, cmd in sorted_items:
            safe_cmd = cmd.replace("\n", " ").strip()
            print(f"  ✖  {msg}")
            print(f"     {_c.dim}→ {safe_cmd}{_c.reset}")
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
    skipped_cmds = 0

    print()
    for msg, cmd in sorted_items:
        safe_cmd = cmd.replace("\n", " ").strip()
        print(f"  ✖  {msg}")
        print(f"  → {safe_cmd}")
        if config.yes:
            answer = "y"
        else:
            answer = safe_input(f"  {t('fixes.apply_prompt')} ").strip().lower()

        if answer == "y":
            if _has_shell_ops(cmd):
                print(f"  ✖ {t('fixes.manual')} ({t('fixes.skipped_unsafe_shell')})")
                skipped_cmds += 1
                print()
                continue
            try:
                proc = subprocess.run(
                    shlex.split(cmd), stdin=subprocess.DEVNULL,
                    capture_output=True, timeout=30,
                )
                if proc.returncode == 0:
                    print(f"  ✔ {t('fixes.applied')}")
                    applied_cmds.append(cmd)
                else:
                    stderr = proc.stderr.decode(errors="replace").strip()
                    detail = f" — {stderr}" if stderr else ""
                    print(f"  ✖ {t('fixes.manual')} (exit {proc.returncode}{detail})")
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
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

    # Auto-fix summary — list every command that was applied
    if config.yes and applied_cmds:
        print()
        print(f"{_c.blue_bold}  [{t('fixes.auto_summary_title')}]{_c.reset}")
        for cmd in applied_cmds:
            print(f"  ✔ {cmd}")

    # What BOB did not apply: diagnostics it can only show, and findings with
    # no command at all. Same block as the dry run, so the two cannot drift.
    _print_unapplied(diag_items, manual_items, t, _c)
