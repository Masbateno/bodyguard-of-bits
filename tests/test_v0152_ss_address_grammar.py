"""v0.15.2 — one grammar for the `ss` address column.

Two checks read `ss` output and each carried a private `_split_addr_port`,
same name, different behaviour. `ports` learned about IPv6 brackets and
`%scope` in v0.15.0; `network_context` kept an `rfind(":")` that left the
brackets glued to the address, so every IPv6 peer failed the private-address
test — `[::1]` included. An ordinary local PostgreSQL connection over IPv6
loopback was therefore reported as an established connection to an external IP
on a sensitive port, with a two-point deduction.

Exactly the shape v0.15.1 unified for the UFW rule grammar: two copies of one
rule, one of them fixed. The guard at the bottom is the same idea as that
release's — a private copy must not come back.
"""

import pytest

from bob.checks._run import split_ss_address


class TestTheSharedGrammar:
    @pytest.mark.parametrize("raw,expected", [
        ("0.0.0.0:22",          ("0.0.0.0", "22", "")),
        ("127.0.0.53%lo:53",    ("127.0.0.53", "53", "lo")),
        ("0.0.0.0%virbr0:67",   ("0.0.0.0", "67", "virbr0")),
        ("[::]:22",             ("::", "22", "")),
        ("[::1]:631",           ("::1", "631", "")),
        ("[fe80::1%eth0]:22",   ("fe80::1", "22", "eth0")),
        ("[2001:db8::1]:443",   ("2001:db8::1", "443", "")),
        ("*:53",                ("*", "53", "")),
    ])
    def test_known_forms(self, raw, expected):
        assert split_ss_address(raw) == expected

    @pytest.mark.parametrize("raw", ["", "nonsense", "1.2.3.4", ":", "[::1]", "host:port"])
    def test_a_non_address_is_not_invented(self, raw):
        assert split_ss_address(raw) == (None, None, "")

    def test_brackets_never_survive_into_the_address(self):
        """The bug in one word: the brackets were kept."""
        addr, _port, _iface = split_ss_address("[::1]:5432")
        assert "[" not in addr and "]" not in addr


class TestIPv6PeersAreClassifiedCorrectly:
    """`_is_private_or_loopback` only works on an address it can parse."""

    @pytest.mark.parametrize("raw,private", [
        ("[::1]:631",           True),   # loopback
        ("[fc00::1]:53",        True),   # unique local
        ("[fe80::1%eth0]:22",   True),   # link-local
        ("[2001:db8::1]:443",   False),  # genuinely global
        ("127.0.0.1:8080",      True),
        ("192.168.1.5:443",     True),
        ("8.8.8.8:53",          False),
    ])
    def test_classification(self, raw, private):
        from bob.checks.network_context import _is_private_or_loopback, _split_addr_port
        addr, _port = _split_addr_port(raw)
        assert _is_private_or_loopback(addr) is private


class TestTheFalseAlarmItCaused:
    """A local database over IPv6 loopback is not a remote exposure."""

    def _findings(self, peer: str):
        from bob.checks.network_context import (NetworkContextSnapshot,
                                                _parse_connections,
                                                check_network_context)
        out = ("Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
               f'0 0 [::1]:52344 {peer} users:(("psql",pid=1,fd=3))\n')
        snapshot = NetworkContextSnapshot(connections=_parse_connections(out))
        result = check_network_context(snapshot)
        return {f.key for f in result.findings}, result.deductions

    def test_a_loopback_database_raises_nothing(self):
        keys, deductions = self._findings("[::1]:5432")
        assert "network_context.sensitive_remote" not in keys
        assert not deductions

    def test_a_genuinely_remote_database_still_does(self):
        keys, deductions = self._findings("[2001:db8::9]:5432")
        assert "network_context.sensitive_remote" in keys
        assert [d.points for d in deductions] == [2]


class TestNoPrivateCopyComesBack:
    """The v0.15.1 guard, applied to this grammar.

    Two copies of one rule is how this defect was born; a module that parses
    an `ss` address column itself can drift from the shared answer again.
    """

    def test_no_ss_reader_splits_the_address_itself(self):
        """Scoped to the real invariant: modules that run `ss`.

        Matching bracketed-IPv6 regexes tree-wide flags honest neighbours —
        `docker.py` parses `[::]:8080->80/tcp` port mappings, a different
        format with its own grammar. The rule here is narrower and true: a
        module that reads the `ss` address column must get it from one place.
        """
        import ast
        from pathlib import Path

        offenders = []
        for path in sorted(Path("bob/checks").rglob("*.py")):
            if path.name == "_run.py":
                continue  # defines the grammar
            source = path.read_text(encoding="utf-8")
            if '"ss"' not in source:
                continue  # not an ss reader
            tree = ast.parse(source)
            for node in ast.walk(tree):
                # `<something>.rfind(":")` — taking the column apart by hand
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "rfind"
                        and node.args
                        and isinstance(node.args[0], ast.Constant)
                        and node.args[0].value == ":"):
                    offenders.append(f"{path}:{node.lineno} rfind(':')")
        assert not offenders, (
            "these read `ss` and split the address column themselves instead "
            "of calling split_ss_address(): " + ", ".join(offenders)
        )

    def test_both_ss_readers_reach_the_shared_grammar(self):
        """Positive side: the two callers really do agree now."""
        from bob.checks.network_context import _split_addr_port as nc_split
        from bob.checks.ports import _split_addr_port as ports_split

        addr, port, _iface = ports_split("[fe80::1%eth0]:22")
        nc_addr, nc_port = nc_split("[fe80::1%eth0]:22")
        assert (addr, int(port)) == (nc_addr, nc_port) == ("fe80::1", 22)
