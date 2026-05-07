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


def _has_shell_ops(cmd: str) -> bool:
    """Return True if cmd contains shell operators requiring shell=True."""
    _SHELL_TOKENS = frozenset({"&&", "||", ";", "|", ">", ">>", "<", "&"})
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return True  # malformed quoting — treat as unsafe
    return any(tok in _SHELL_TOKENS or tok.startswith("`") or tok.startswith("$(")
               for tok in tokens)


def run_fixes(engine, config, t) -> None:
    """Display and optionally apply automatic fixes."""
    auto_items   = [(f.message, f.cmd) for f in engine.findings
                    if f.nature == "action" and f.cmd]
    manual_items = [f.message for f in engine.findings
                    if f.nature == "action" and not f.cmd]

    _c = _output._c
    W = 62
    print()
    print(f"{_c.blue_bold}╔{'═'*(W-2)}╗{_c.reset}")
    label = t("fixes.title")
    pad = W - 6 - len(label)
    print(f"{_c.blue_bold}║{_c.reset}  {_c.bold}{label}{_c.reset}{' '*max(0,pad)}  {_c.blue_bold}║{_c.reset}")
    print(f"{_c.blue_bold}╠{'═'*(W-2)}╣{_c.reset}")

    if not auto_items and not manual_items:
        none_msg = t("fixes.none")
        pad = W - 6 - len(none_msg)
        print(f"{_c.blue_bold}║{_c.reset}    {none_msg}{' '*max(0,pad)}{_c.blue_bold}║{_c.reset}")
    else:
        count = len(auto_items)
        count_msg = t("fixes.count", count=count)
        pad = W - 9 - len(count_msg)
        print(f"{_c.blue_bold}║{_c.reset}    ✔  {count_msg}{' '*max(0,pad)}{_c.blue_bold}║{_c.reset}")
    print(f"{_c.blue_bold}╚{'═'*(W-2)}╝{_c.reset}")

    if not auto_items and not manual_items:
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
        if manual_items:
            print(f"  {_c.yellow_bold}{t('fixes.manual_items_title')}{_c.reset}")
            for msg in manual_items:
                print(f"  • {msg}")
        return

    # ── Apply mode (--fix --apply) ───────────────────────────────────────────
    # Auto-fix mode banner — visible warning so the user knows what's happening
    if config.yes:
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
            answer = input(f"  {t('fixes.apply_prompt')} ").strip().lower()

        if answer == "y":
            if _has_shell_ops(cmd):
                print(f"  ✖ {t('fixes.manual')} (unsafe shell syntax in command)")
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

    total = len(sorted_items)
    applied = len(applied_cmds)
    print(f"  {t('fixes.done_summary', applied=applied, total=total)}")

    # Auto-fix summary — list every command that was applied
    if config.yes and applied_cmds:
        print()
        print(f"{_c.blue_bold}  [{t('fixes.auto_summary_title')}]{_c.reset}")
        for cmd in applied_cmds:
            print(f"  ✔ {cmd}")

    # Manual items — findings with no automatic fix
    if manual_items:
        print()
        print(f"  {_c.yellow_bold}{t('fixes.manual_items_title')}{_c.reset}")
        for msg in manual_items:
            print(f"  • {msg}")
