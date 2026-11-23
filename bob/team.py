"""v0.43.0 (B-045) — a team's declared perimeters: actions outside them said and written.

Decided with the user (22 November 2026). A team leader — the *master* — gives
each account attributes; an action of BOB outside the attributes of the
account behind it is **not prevented**: its author is told before, asked to
confirm (a question ``-y`` does not answer), and the action, confirmed or
abandoned, is written to the team journal (bob/team_journal.py). Without a
terminal the question cannot be asked: the action is carried out and written
as not confirmed. BOB has no access control of its own — one would be
bypassed by root, and the real authorisation stays Linux's (accounts, groups,
sudoers). The term is "outside the declared perimeter": BOB measures a gap to a
declaration, it does not judge a fault.

**Without a declaration, nothing changes**: no question, no journal, no line.

Who acts: the account the kernel's login uid names (bob/annotations.py), which
survives sudo and su. No login uid (cron, a service): the action is not
attributed — carried out, written as such, never attributed by default. A
direct root login is an account like any other (decided).

What BOB sees: only its own actions. An edit of sshd_config by hand, a ufw run
by hand, escape it — auditd's business.

The declaration, ``/etc/bob/team.conf``, is root's (0644: everyone reads their
perimeter) and written by BOB only (``bob --team``). Each write records the
file's digest in the team journal; a declaration whose digest is not the last
one BOB recorded is said changed outside BOB — and still applied.
"""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from bob.domain_scores import DOMAINS

#: Where the declaration lives (a seam for the tests).
CONF = Path("/etc/bob/team.conf")
_CONF_MODE = 0o644
_CONF_UID = 0
#: The attributes (decided with the user): ``fix:<domain>`` per score domain,
#: ``fix:*`` for all of them.
BASE_ATTRIBUTES = ("audit", "note", "note-autres", "purge", "config", "equipe")
FIX_ALL = "fix:*"
ATTRIBUTES = BASE_ATTRIBUTES + tuple(f"fix:{d}" for d in DOMAINS) + (FIX_ALL,)
_MAX_FILE = 64 << 10
_HEADER = ("# BOB team declaration — written by `bob --team`; change it through\n"
           "# `sudo bob --team grant|revoke|remove`, not by hand (a change by hand is\n"
           "# seen and written to the team journal).\n")


class TeamError(Exception):
    """Why a team command did nothing: *key* names it, *vars* fill its message."""

    def __init__(self, key: str, **vars_: object) -> None:
        super().__init__(key)
        self.key = key
        self.vars = vars_


@dataclass
class Declaration:
    master: str = ""
    members: "dict[str, list[str]]" = field(default_factory=dict)
    digest: str = ""
    #: Lines not understood (a declaration changed by hand), kept to be said.
    unread_lines: "list[str]" = field(default_factory=list)
    #: Owner of a declaration root does not own ("" when root's).
    foreign_owner: str = ""


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def parse(text: str) -> Declaration:
    decl = Declaration(digest=digest(text))
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, rest = line.partition(":")
        name = name.strip()
        if not sep or not name or " " in name:
            decl.unread_lines.append(raw)
            continue
        values = [v.strip() for v in rest.split(",") if v.strip()]
        if name == "master":
            if len(values) == 1 and not decl.master:
                decl.master = values[0]
            else:
                decl.unread_lines.append(raw)
            continue
        unknown = [v for v in values if v not in ATTRIBUTES]
        if unknown:
            decl.unread_lines.append(raw)
        decl.members[name] = [v for v in values if v in ATTRIBUTES]
    return decl


def render(decl: Declaration) -> str:
    lines = [_HEADER, f"master: {decl.master}\n"]
    width = max([len(a) for a in decl.members] + [6])
    for account in sorted(decl.members):
        attrs = ", ".join(a for a in ATTRIBUTES if a in decl.members[account])
        lines.append(f"{account + ':':<{width + 1}} {attrs}\n".rstrip() + "\n")
    return "".join(lines)


def load() -> "Declaration | None":
    """The declaration, or None when there is none (BOB works as before).

    A declaration that exists but cannot be read raises TeamError: a team
    that declared perimeters is not silently treated as having none."""
    from bob.annotations import _read_raw
    raw, why, uid = _read_raw(CONF, _MAX_FILE)
    if raw is None:
        raise TeamError("unreadable", path=str(CONF), reason=why)
    if raw == "" and uid is None:
        return None  # absent
    decl = parse(raw)
    if uid is not None and uid != _CONF_UID:
        from bob.fix_journal import _owner_name
        decl.foreign_owner = _owner_name(uid)
    return decl


def write(decl: Declaration) -> str:
    """Write the declaration, root's, 0644; returns its digest."""
    if os.geteuid() != _CONF_UID:
        raise TeamError("needs_root")
    from bob._atomic import atomic_write
    text = render(decl)
    CONF.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_write(CONF, text, mode=_CONF_MODE)
    return digest(text)


def allows(decl: Declaration, account: str, attribute: str) -> bool:
    if account == decl.master:
        return True
    attrs = decl.members.get(account, [])
    return attribute in attrs or (attribute.startswith("fix:") and FIX_ALL in attrs)


def perimeter(decl: Declaration, account: str) -> "list[str]":
    if account == decl.master:
        return list(ATTRIBUTES)
    return [a for a in ATTRIBUTES if a in decl.members.get(account, [])]


#: Where the human accounts' UID range is read (a seam for the tests).
_LOGIN_DEFS = Path("/etc/login.defs")
_DEFAULT_UID_RANGE = (1000, 60000)
#: Shells that do not log in.
_NO_LOGIN_SHELLS = ("nologin", "false", "")


def uid_range() -> "tuple[int, int]":
    """UID_MIN and UID_MAX of /etc/login.defs; the usual 1000–60000 otherwise."""
    lo, hi = _DEFAULT_UID_RANGE
    try:
        text = _LOGIN_DEFS.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return lo, hi
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            if parts[0] == "UID_MIN":
                lo = int(parts[1])
            elif parts[0] == "UID_MAX":
                hi = int(parts[1])
    return lo, hi


def _accounts():
    """Every account of the host (a seam for the tests)."""
    import pwd
    return pwd.getpwall()


def candidate_accounts(decl: "Declaration | None") -> "list[str]":
    """The human accounts of the host that can still be declared: a UID in the
    login.defs range and a login shell; the master and the members left out.
    (v0.43.0 — asked by the user: list the accounts rather than type a name.)"""
    lo, hi = uid_range()
    taken = set(decl.members) | {decl.master} if decl else set()
    names = set()
    for p in _accounts():
        if not lo <= p.pw_uid <= hi:
            continue
        if os.path.basename(p.pw_shell or "") in _NO_LOGIN_SHELLS:
            continue
        if p.pw_name not in taken:
            names.add(p.pw_name)
    return sorted(names)


def fix_attribute(finding_key: "str | None") -> str:
    """The attribute a ``--fix --apply`` command needs: its finding's score domain."""
    from bob.domain_scores import key_to_domain
    domain = key_to_domain(finding_key)
    return f"fix:{domain}" if domain else FIX_ALL


# ---------------------------------------------------------------------------
# Before an action
# ---------------------------------------------------------------------------

def _actor() -> "str | None":
    """The account behind this process (login uid), None outside a session."""
    from bob.annotations import operator
    return operator().get("login")


def _interactive() -> bool:
    """Whether a person can be asked (a seam for the tests)."""
    try:
        return sys.stdin.isatty()
    except (ValueError, OSError):
        return False


def _say(text: str) -> None:
    print(text, file=sys.stderr)


def _record(t, kind: str, say=None, **data) -> None:
    from bob import team_journal as TJ
    from bob.fix_journal import FixJournalError
    try:
        TJ.append(kind, **data)
    except (FixJournalError, OSError) as exc:
        reason = t(f"fix_journal.err.{exc.key}", **exc.vars) if isinstance(exc, FixJournalError) \
            else (exc.strerror or type(exc).__name__)
        (say or _say)("  " + t("team.not_recorded", path=str(TJ.path()), reason=reason))


def _check_declaration(decl: Declaration, t, say=_say) -> None:
    """Say — and write once — a declaration BOB did not write as it reads."""
    from bob import team_journal as TJ
    if decl.foreign_owner:
        say("  " + t("team.foreign_owner", path=str(CONF), owner=decl.foreign_owner))
    journal = TJ.load()
    if journal.unreadable:
        return  # root's journal, read by an ordinary account: not checked here
    if TJ.last_declaration_digest(journal) == decl.digest and not decl.foreign_owner:
        return
    say("  " + t("team.altered", path=str(CONF)))
    if not TJ.altered_already_recorded(journal, decl.digest):
        _record(t, "altered", say=say, digest=decl.digest)


def gate(attribute: str, action: str, t, *, ask=None, say=None) -> bool:
    """Before *action*: True to carry it out, False when its author abandoned it.

    Without a declaration: True, silently. Within the author's perimeter:
    True, silently (nothing written). Outside: said, asked (``-y`` does not
    answer), written to the team journal whatever the answer.

    *ask* (question → bool) and *say* (one line) replace the terminal for a
    full-screen caller (--manage-logs): there a person is always there."""
    say = say or _say
    try:
        decl = load()
    except TeamError as exc:
        say("  " + t(f"team.err.{exc.key}", **exc.vars))
        return True  # BOB prevents nothing; the problem is said
    if decl is None:
        return True
    _check_declaration(decl, t, say)
    account = _actor()
    what = t(f"team.action.{action}")
    if account is None:
        say("  " + t("team.unattributed", action=what))
        _record(t, "attempt", say=say, action=action, attribute=attribute,
                outcome="unattributed", master=decl.master)
        return True
    if allows(decl, account, attribute):
        return True
    outside = t("team.outside", account=account, attribute=attribute, action=what,
                master=decl.master)
    if ask is None and not _interactive():
        say("")
        say("  ⚠ " + outside)
        say("  " + t("team.no_terminal"))
        _record(t, "attempt", say=say, action=action, attribute=attribute,
                outcome="unconfirmed", account=account, master=decl.master)
        return True
    if ask is not None:
        confirmed = bool(ask(outside + " " + t("team.confirm")))
    else:
        from bob._tty import safe_input
        say("")
        say("  ⚠ " + outside)
        # The question on stderr, like the warning: stdout may be a --json file.
        print("  " + t("team.confirm") + " ", end="", file=sys.stderr, flush=True)
        confirmed = safe_input().strip().lower() in ("y", "yes", "o", "oui")
    _record(t, "attempt", say=say, action=action, attribute=attribute,
            outcome="confirmed" if confirmed else "abandoned",
            account=account, master=decl.master)
    if not confirmed:
        say("  " + t("team.abandoned"))
    return confirmed


# ---------------------------------------------------------------------------
# bob --team
# ---------------------------------------------------------------------------

def _account_exists(name: str) -> bool:
    import pwd
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def _split_attrs(values: "list[str]") -> "list[str]":
    attrs = [a.strip() for v in values for a in v.split(",") if a.strip()]
    unknown = [a for a in attrs if a not in ATTRIBUTES]
    if unknown:
        raise TeamError("unknown_attribute", attribute=", ".join(unknown),
                        known=", ".join(ATTRIBUTES))
    if not attrs:
        raise TeamError("no_attribute")
    return attrs


def show(t) -> "list[str]":
    """The declaration as it reads, and the reader's own perimeter."""
    decl = load()
    if decl is None:
        return [t("team.none", path=str(CONF))]
    # v0.43.0 — one column for the accounts, padded to the longest, so the
    # attributes start in one column too (CONVENTIONS.md: columns line up).
    master_label = t("team.master")
    width = max([len(master_label)] + [len(a) for a in decl.members])
    lines = [t("team.header", path=str(CONF)), "", f"  {master_label:<{width}} : {decl.master}"]
    for account in sorted(decl.members):
        attrs = ", ".join(perimeter(decl, account)) or t("team.no_attributes")
        lines.append(f"  {account:<{width}} : {attrs}")
    if decl.unread_lines:
        lines += ["", t("team.unread_lines", count=len(decl.unread_lines))]
        lines += [f"    {ln}" for ln in decl.unread_lines]
    account = _actor()
    lines.append("")
    if account is None:
        lines.append(t("team.you_unattributed"))
    else:
        mine = perimeter(decl, account)
        lines.append(t("team.you", account=account,
                       attributes=", ".join(mine) if mine else t("team.no_attributes")))
    lines += ["", t("team.limits")]
    return lines


def command(args: "list[str]", t, *, ask=None, say=None) -> "list[str]":
    """``bob --team <init|grant|revoke|remove> …``: change the declaration.
    Returns what to print; raises TeamError when nothing was done."""
    op, rest = (args[0], args[1:]) if args else ("", [])
    if op not in ("init", "grant", "revoke", "remove"):
        raise TeamError("usage")
    if os.geteuid() != _CONF_UID:
        raise TeamError("needs_root")
    decl = load()
    if op == "init":
        if decl is not None:
            raise TeamError("exists", path=str(CONF))
        account = _actor()
        if account is None:
            raise TeamError("init_no_login")
        decl = Declaration(master=account)
        new_digest = write(decl)
        _record(t, "team", say=say, op="init", account=account, attributes=[], digest=new_digest)
        return [t("team.done.init", account=account, path=str(CONF))]
    if decl is None:
        raise TeamError("no_declaration", path=str(CONF))
    if not rest:
        raise TeamError("usage")
    account = rest[0]
    if account == decl.master:
        raise TeamError("is_master", account=account)
    if op == "remove":
        if len(rest) != 1:
            raise TeamError("usage")
        if account not in decl.members:
            raise TeamError("not_member", account=account)
        attrs: "list[str]" = []
    else:
        attrs = _split_attrs(rest[1:])
        if op == "grant" and not _account_exists(account):
            raise TeamError("no_account", account=account)
    if not gate("equipe", f"team_{op}", t, ask=ask, say=say):
        return []
    current = list(decl.members.get(account, []))
    if op == "grant":
        decl.members[account] = current + [a for a in attrs if a not in current]
    elif op == "revoke":
        if account not in decl.members:
            raise TeamError("not_member", account=account)
        decl.members[account] = [a for a in current if a not in attrs]
    else:
        del decl.members[account]
    new_digest = write(decl)
    _record(t, "team", say=say, op=op, account=account, attributes=attrs, digest=new_digest)
    after = ", ".join(perimeter(decl, account)) if account in decl.members else ""
    return [t(f"team.done.{op}", account=account, attributes=after or t("team.no_attributes"))]


def run(args: "list[str]", t) -> int:
    """``bob --team [...]``: 0 done or shown, 3 nothing done (said why)."""
    try:
        lines = show(t) if not args else command(args, t)
    except TeamError as exc:
        print(t(f"team.err.{exc.key}", **exc.vars), file=sys.stderr)
        return 3
    from bob import _names
    for line in lines:
        print(_names.plain(line))
    return 0


def journal_lines(t) -> "tuple[list[str], int]":
    """``bob --team-journal``: the events, the chain's verdict first.
    Exit 0 intact, 2 broken, 4 could not be read (bob/journals.py)."""
    from bob import journals
    return journals.journal_lines("team", t)
