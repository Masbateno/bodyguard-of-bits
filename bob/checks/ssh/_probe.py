"""v0.41.0 (B-001) — ask sshd whether a Match block's setting applies.

A Match block sets a directive an earlier block sets too, with another value;
sshd keeps the first matching block's value. When the text alone proves that
the earlier block takes every session of the later one, 0.38.0 already leaves
the later setting out (``_criteria_cover``). Otherwise the cover is uncertain —
a negation in the earlier block, a criterion only one of them has, groups,
routing domains — and the setting is counted.

Decided with the user (21 November 2026), after a measurement: asking sshd with
one representative connection is not enough. With ``Match Address
192.0.2.0/24,!192.0.2.5`` setting ``PasswordAuthentication no`` and a later
``Match Address 192.0.2.0/25`` setting ``yes``, ``sshd -T -C`` gave ``no``
from 192.0.2.1 and ``yes`` from 192.0.2.5 (OpenSSH 9.6p1): calling the block
covered on the first would have hidden a password login from the second. So
the setting is never removed on sshd's word; BOB looks for a *witness* — a
connection where the later block's value applies — among its own entries,
the edges of its address ranges, and what the earlier block leaves out. Found,
the counted setting carries that proof; not found, it is still counted, and the
number of connections sshd answered is said.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path

#: Values for a criterion neither block sets: documentation addresses
#: (RFC 5737), a name that resolves nowhere, an account that does not exist.
NEUTRAL = {"user": "bob-sshd-probe", "host": "bob-probe.invalid", "addr": "203.0.113.250",
           "laddr": "198.51.100.250", "lport": "65000"}
#: Match keywords → the -C field each one is tested through.
_FIELD = {"user": "user", "group": "user", "host": "host", "address": "addr",
          "localaddress": "laddr", "localport": "lport", "rdomain": "rdomain"}
#: At most this many connections asked per block (each one runs sshd -T).
MAX_TRIES = 16
TIMEOUT = 5


def _pairs(criteria: str) -> "dict[str, list[str]] | None":
    words = criteria.split()
    if len(words) % 2:
        return None
    out: "dict[str, list[str]]" = {}
    for kw, value in zip(words[0::2], words[1::2], strict=True):
        out.setdefault(kw.lower(), []).extend(p for p in value.split(",") if p)
    return out


def _host(net) -> str:
    """The first address a host can hold in *net* (the address itself for a
    single one)."""
    if net.num_addresses <= 2:
        return str(net.network_address)
    return str(net.network_address + 1)


def _address_points(later: "list[str]", earlier: "list[str]") -> "list[str]":
    """Addresses inside *later*'s positive entries, outside its negated ones:
    each entry's first and last host, and the edges of every earlier entry —
    negated or not — that falls inside, where the earlier block stops."""
    def nets(entries, negated):
        out = []
        for e in entries:
            if e.startswith("!") != negated:
                continue
            try:
                out.append(ipaddress.ip_network(e.lstrip("!"), strict=False))
            except ValueError:
                pass
        return out
    inside, excluded = nets(later, False), nets(later, True)
    if not inside:
        return []
    points: "list[str]" = []
    for net in inside:
        points += [_host(net), str(net.broadcast_address - 1) if net.num_addresses > 2 else str(net.broadcast_address)]
        for e in nets(earlier, False) + nets(earlier, True):
            if e.version != net.version or not e.overlaps(net):
                continue
            points.append(_host(e))
            for edge in (e.network_address - 1, e.broadcast_address + 1):
                if edge in net:
                    points.append(str(edge))
    keep = []
    for p in points:
        a = ipaddress.ip_address(p)
        if any(a in n for n in inside) and not any(a in n for n in excluded) and p not in keep:
            keep.append(p)
    return keep


def _literal_points(later: "list[str] | None", earlier: "list[str]", neutral: str) -> "list[str]":
    """Names or ports: the later block's literal entries, then what the earlier
    block leaves out (its negated entries); the neutral value when the later
    block does not constrain this criterion."""
    out: "list[str]" = []
    if later is None:
        out.append(neutral)
    else:
        out += [e for e in later if not e.startswith("!") and not any(c in e for c in "*?")]
        if not out and any(e in ("*",) for e in later):
            out.append(neutral)
    for e in earlier:
        if e.startswith("!") and not any(c in e for c in "*?"):
            name = e[1:]
            if later is None or name in later:
                out.append(name)
    seen: "list[str]" = []
    return [x for x in out if not (x in seen or seen.append(x))]


def _group_members(groups: "list[str]") -> "list[str]":
    import grp
    import pwd
    out: "list[str]" = []
    for g in groups:
        if g.startswith("!") or any(c in g for c in "*?"):
            continue
        try:
            entry = grp.getgrnam(g)
        except KeyError:
            continue
        out += list(entry.gr_mem)
        try:
            out += [p.pw_name for p in pwd.getpwall() if p.pw_gid == entry.gr_gid]
        except OSError:
            pass
    seen: "list[str]" = []
    return [x for x in out if not (x in seen or seen.append(x))]


def connections(later: str, earlier: "list[str]") -> "list[dict[str, str]]":
    """The -C connection specs worth asking for a block with criteria *later*,
    against the criteria of the earlier blocks: one base connection, then one
    criterion varied at a time. Empty when the later block cannot be read."""
    b = _pairs(later)
    if b is None or "all" in b:
        return []
    earlier_pairs = [p for p in (_pairs(c) for c in earlier) if p is not None]
    def earlier_entries(kw: str) -> "list[str]":
        return [e for p in earlier_pairs for e in p.get(kw, [])]
    fields: "dict[str, list[str]]" = {}
    if "address" in b or earlier_entries("address"):
        pts = (_address_points(b["address"], earlier_entries("address")) if "address" in b
               else _literal_points(None, earlier_entries("address"), NEUTRAL["addr"]))
        if not pts:
            return []
        fields["addr"] = pts
    if "localaddress" in b:
        pts = _address_points(b["localaddress"], earlier_entries("localaddress"))
        if not pts:
            return []
        fields["laddr"] = pts
    users = (_group_members(b["group"]) if "group" in b
             else _literal_points(b.get("user"), earlier_entries("user"), NEUTRAL["user"]))
    if "user" in b and "group" in b:
        users = [u for u in users if u in b["user"]]
    if not users:
        return []
    fields["user"] = users
    for kw, field in (("host", "host"), ("localport", "lport"), ("rdomain", "rdomain")):
        if kw in b or earlier_entries(kw):
            neutral = NEUTRAL.get(field, "")
            pts = _literal_points(b.get(kw), earlier_entries(kw), neutral)
            if not pts or (field == "rdomain" and not pts[0]):
                return []
            fields[field] = pts
    base = {f: NEUTRAL[f] for f in ("user", "host", "addr", "laddr", "lport")}
    base.update({f: v[0] for f, v in fields.items()})
    specs = [dict(base)]
    for f, values in fields.items():
        for v in values[1:]:
            spec = dict(base)
            spec[f] = v
            specs.append(spec)
    return specs[:MAX_TRIES]


def spec_text(spec: "dict[str, str]", shown: "tuple[str, ...]" = ("user", "addr", "host", "laddr", "lport", "rdomain")) -> str:
    return ",".join(f"{k}={spec[k]}" for k in shown if k in spec)


def ask_sshd(sshd: str, config: Path, spec: "dict[str, str]") -> "dict[str, str] | None":
    """The settings sshd applies to the connection *spec* (``sshd -T -C``),
    keys lowercased; None when sshd did not answer."""
    from bob.checks._run import run_result
    res = run_result(sshd, "-T", "-f", str(config), "-C", spec_text(spec), timeout=TIMEOUT)
    if not res.ok or not res.stdout.strip():
        return None
    out: "dict[str, str]" = {}
    for line in res.stdout.splitlines():
        key, _sep, value = line.partition(" ")
        if key and key.lower() not in out:
            out[key.lower()] = value.strip()
    return out


def _conflicts(blocks: "list[dict]") -> "list[tuple[dict, str, list[str]]]":
    """(block, directive, earlier criteria) for each setting an earlier block
    sets with another value, not already left out as certainly covered."""
    out = []
    for i, blk in enumerate(blocks):
        for key, value in blk["settings"].items():
            earlier = [o["criteria"] for o in blocks[:i]
                       if key in o["settings"] and o["settings"][key].lower() != value.lower()]
            if earlier:
                out.append((blk, key, earlier))
    return out


def probe_blocks(config: dict, config_path: Path, sshd: "str | None") -> None:
    """Record, for each uncertain setting, what sshd says (see the module):
    ``blk["probe"][directive] = {"applies": <connection> | None, "tried": n,
    "earlier": <criteria>, "value": <value>}``; when sshd could not be asked,
    ``config["_match_probe_unavailable"]`` holds why and how many settings."""
    blocks = config.get("_match_blocks") or []
    todo = _conflicts(blocks)
    if not todo:
        return
    if not sshd or os.geteuid() != 0:
        config["_match_probe_unavailable"] = {"reason": "sshd" if not sshd else "root", "count": len(todo)}
        return
    answered = 0
    for blk, key, earlier in todo:
        value = blk["settings"][key]
        tried, applies = 0, None
        for spec in connections(blk["criteria"], earlier):
            got = ask_sshd(sshd, config_path, spec)
            if got is None:
                continue
            tried += 1
            if got.get(key, "").lower() == value.lower():
                shown = {k: v for k, v in spec.items() if v != NEUTRAL.get(k)}
                applies = spec_text(shown) or spec_text(spec)
                break
        if tried:
            answered += 1
            blk.setdefault("probe", {})[key] = {"applies": applies, "tried": tried,
                                                "earlier": earlier[0], "value": value}
    if answered < len(todo):
        config["_match_probe_unavailable"] = {"reason": "answer", "count": len(todo) - answered}
