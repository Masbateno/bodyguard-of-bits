"""v0.43.0 (B-045) — ``bob --manage-team``: the team, managed step by step.

Asked by the user (22 November 2026, evening): a wizard that offers everything
the commands do — see the declaration and one's perimeter, create the team,
grant, revoke, remove, set what is recorded, read a journal. It calls the very
functions the commands call (bob/team.py, bob/journals.py): the same checks,
the same questions outside a declared perimeter, the same traces. Nothing is
done here that the commands could not do.
"""

from __future__ import annotations

import sys

from bob import journals as J
from bob import team
from bob._tty import safe_input


def _ask(t, key: str, **kw) -> str:
    return safe_input("  " + t(key, **kw) + " ").strip()


def _pick(t, items: "list[str]", key: str) -> "list[str]":
    """Numbered *items*; the answer may name several (``1,3``, ``2-4``, ``all``)."""
    from bob.selection import SelectionError, parse_selection
    for i, item in enumerate(items, 1):
        print(f"    {i:>2}  {item}")
    answer = _ask(t, key)
    if not answer:
        return []
    try:
        return [items[n - 1] for n in parse_selection(answer, range(1, len(items) + 1))]
    except SelectionError as exc:
        print("  ✖ " + t("selection." + exc.kind, **exc.vars))
        return []


def _do(t, lines_or_code) -> None:
    from bob import _names
    for line in lines_or_code:
        print("  " + _names.plain(line))


def _command(t, args: "list[str]") -> None:
    try:
        _do(t, team.command(args, t))
    except team.TeamError as exc:
        print("  ✖ " + t(f"team.err.{exc.key}", **exc.vars))


def _members(t) -> "list[str]":
    decl = team.load()
    return sorted(decl.members) if decl else []


def _ask_account(t, decl, op: str) -> str:
    """An account by number (the host's human accounts not yet declared, for a
    grant; the members, for a revoke) or by name."""
    lo, hi = team.uid_range()
    names = team.candidate_accounts(decl) if op == "grant" else sorted(decl.members) if decl else []
    if names:
        if op == "grant":
            print("  " + t("team_tui.pick_head", low=lo, high=hi))
        for i, name in enumerate(names, 1):
            print(f"    {i:>2}  {name}")
    elif op == "grant":
        print("  ℹ " + t("team_tui.no_candidates", low=lo, high=hi))
    answer = _ask(t, "team_wizard.ask_account_or_number")
    if answer.isdigit() and 1 <= int(answer) <= len(names):
        return names[int(answer) - 1]
    return answer


def _journals_menu(t) -> None:
    _do(t, J.show(t))
    cats = _pick(t, list(J.CATEGORIES), "team_wizard.pick_categories")
    if not cats:
        return
    state = _ask(t, "team_wizard.ask_on_off").lower()
    if state not in ("on", "off"):
        print("  ✖ " + t("team_wizard.cancelled"))
        return
    try:
        _do(t, J.set_categories(cats, state == "on", t))
    except team.TeamError as exc:
        print("  ✖ " + t(f"team.err.{exc.key}", **exc.vars))


def run(t) -> int:
    """The menu, until q. 0 always: what each step did is said as it goes."""
    from bob import output
    output.print_titled_box(t("team_wizard.title"))
    while True:
        print()
        try:
            decl = team.load()
        except team.TeamError as exc:
            print("  ✖ " + t(f"team.err.{exc.key}", **exc.vars))
            decl = None
        options = [("show", "team_wizard.opt.show")]
        options += [("init", "team_wizard.opt.init")] if decl is None else [
            ("grant", "team_wizard.opt.grant"), ("revoke", "team_wizard.opt.revoke"),
            ("remove", "team_wizard.opt.remove")]
        options += [("journals", "team_wizard.opt.journals")]
        for i, (_op, key) in enumerate(options, 1):
            print(f"    {i}  {t(key)}")
        print(f"    q  {t('team_wizard.opt.quit')}")
        answer = _ask(t, "team_wizard.ask_choice").lower()
        if answer in ("q", ""):
            return 0
        if not answer.isdigit() or not 1 <= int(answer) <= len(options):
            print("  ✖ " + t("team_wizard.invalid"))
            continue
        op = options[int(answer) - 1][0]
        print()
        if op == "show":
            _do(t, team.show(t))
        elif op == "init":
            _command(t, ["init"])
        elif op in ("grant", "revoke"):
            account = _ask_account(t, decl, op)
            if not account:
                continue
            attrs = _pick(t, list(team.ATTRIBUTES),
                          "team_wizard.pick_grant" if op == "grant" else "team_wizard.pick_revoke")
            if attrs:
                _command(t, [op, account, ",".join(attrs)])
        elif op == "remove":
            members = _members(t)
            if not members:
                print("  ℹ " + t("team_wizard.no_members"))
                continue
            for account in _pick(t, members, "team_wizard.pick_remove")[:1]:
                if _ask(t, "team_wizard.confirm_remove", account=account).lower() in ("y", "yes", "o", "oui"):
                    _command(t, ["remove", account])
        elif op == "journals":
            _journals_menu(t)
        sys.stdout.flush()
