"""
Shared parsing for ``ufw status numbered`` output.

Two checks read these rules — ``ports`` to decide whether a listening port is
covered at all, and ``services`` to classify a known service's exposure — and
until v0.15.0 each had its own matcher. They disagreed:

``ports`` anchored on the rule number and read only the To column, with a
docstring explaining exactly why ("to avoid matching port numbers appearing
later on the line, e.g. inside source IPs like 192.168.1.22"). ``services``
searched the whole line, so that one rule::

    [ 1] 80/tcp   ALLOW IN   192.168.1.22

made ports 1, 22, 168 and 192 all look covered by it — and port 22 in
particular, since it is the commonest last octet on an RFC1918 network. A host
running SSH with no firewall rule for it was reported as "open, restricted to
the local network".

One parser now, so the knowledge lives in one place.
"""

from __future__ import annotations

import re
from pathlib import Path

# `[ N] <To column> <ACTION> <From column>`
_NUMBERED_RE = re.compile(r"^\s*\[\s*\d+\]\s*(.*)$")
_ACTION_RE   = re.compile(r"\s(ALLOW|DENY|REJECT|LIMIT)\b", re.IGNORECASE)
# Digits with ranges (6000:6007) and lists (80,443), plus an optional protocol.
# This is exactly what ufw stores in `dport`.
_PORTSPEC_RE = re.compile(r"^([\d,:]+)(?:/(tcp|udp))?$", re.IGNORECASE)

_APPS_DIR = Path("/etc/ufw/applications.d")


class UfwRule:
    """One parsed rule line: what it covers, what it does, and from where."""

    __slots__ = ("to_col", "action", "from_col", "raw")

    def __init__(self, to_col: str, action: str, from_col: str, raw: str) -> None:
        self.to_col = to_col
        self.action = action
        self.from_col = from_col
        self.raw = raw


def parse_rule(line: str) -> "UfwRule | None":
    """Split one ``ufw status numbered`` line, or None if it is not a rule.

    The To column is cleaned of the ``(v6)`` marker, which only duplicates an
    existing rule, and of a trailing ``on <iface>`` scope, which this project
    does not model either way.
    """
    m = _NUMBERED_RE.match(line)
    if not m:
        return None
    rest = m.group(1)
    action_m = _ACTION_RE.search(rest)
    if action_m:
        to_col = rest[:action_m.start()]
        action = action_m.group(1).upper()
        from_col = rest[action_m.end():]
    else:
        to_col, action, from_col = rest, "", ""
    to_col = to_col.replace("(v6)", "").strip()
    to_col = re.sub(r"\s+on\s+\S+$", "", to_col).strip()
    return UfwRule(to_col, action, from_col.strip(), line)


def read_app_profiles(directory: "Path | None" = None) -> "dict[str, list[str]]":
    """Map each UFW application profile name to its port specifications.

    A profile file holds one or more ``[Name]`` sections with a ``ports=``
    line; ufw splits that value on ``|``, so Samba's ``137,138/udp|139,445/tcp``
    is two specifications. Names may contain spaces ("Postfix Submission").

    I/O only — call it from ``from_system``, never from a check.
    """
    apps: dict[str, list[str]] = {}
    base = directory if directory is not None else _APPS_DIR
    try:
        entries = sorted(base.iterdir())
    except OSError:
        return apps
    for path in entries:
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name: str | None = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                name = stripped[1:-1].strip()
            elif name and stripped.lower().startswith("ports="):
                apps[name] = [p for p in stripped.split("=", 1)[1].split("|") if p]
    return apps


def expand_port_spec(spec: str) -> "list[tuple[int, int, str | None]]":
    """Expand one ufw port specification into (low, high, proto) ranges.

    ``22/tcp`` -> [(22, 22, "tcp")]
    ``6000:6007/tcp`` -> [(6000, 6007, "tcp")]
    ``80,443/tcp`` -> [(80, 80, "tcp"), (443, 443, "tcp")]
    ``631`` -> [(631, 631, None)] — no protocol means any protocol.

    Ranges stay ranges: a rule may legitimately span the whole ephemeral range,
    and membership is a comparison.
    """
    m = _PORTSPEC_RE.match(spec.strip())
    if not m:
        return []
    proto = m.group(2).lower() if m.group(2) else None
    out: list[tuple[int, int, str | None]] = []
    for part in m.group(1).split(","):
        if not part:
            continue
        lo_s, _, hi_s = part.partition(":")
        try:
            lo = int(lo_s)
            hi = int(hi_s) if hi_s else lo
        except ValueError:
            continue
        if lo > hi:
            lo, hi = hi, lo
        out.append((lo, hi, proto))
    return out


def to_column_ranges(
    to_col: str,
    app_profiles: "dict[str, list[str]] | None" = None,
) -> "list[tuple[int, int, str | None]]":
    """Ranges covered by a rule's To column, resolving an application profile.

    A rule scoped to a destination address puts it in front of the port —
    `ufw allow from any to 192.168.1.5 port 22` prints `192.168.1.5 22/tcp`
    (see ufw's `backend_iptables.get_status`, which appends `" " + port` after
    a non-default destination). The port specification is therefore the last
    whitespace-separated token, and a profile name may itself contain spaces
    ("Postfix Submission"), so the whole column is tried as a profile first.
    """
    profiles = app_profiles or {}
    if to_col in profiles:
        return [r for spec in profiles[to_col] for r in expand_port_spec(spec)]
    candidate = to_col.rsplit(None, 1)[-1] if to_col else ""
    if _PORTSPEC_RE.match(candidate):
        return expand_port_spec(candidate)
    return [r for spec in profiles.get(candidate, []) for r in expand_port_spec(spec)]


def ranges_cover(
    ranges: "list[tuple[int, int, str | None]]", port: int, proto: str
) -> bool:
    """True if any range covers this port/proto.

    A rule with an explicit protocol covers only that protocol; one without
    covers any.
    """
    want = proto.lower()
    return any(lo <= port <= hi and (rp is None or rp == want)
               for lo, hi, rp in ranges)


def is_rule_line(line: str) -> bool:
    """True if *line* is a numbered rule row rather than a header or blank."""
    return _NUMBERED_RE.match(line) is not None

