"""v0.21.0 — versions are SemVer MAJOR.MINOR.PATCH, with no "v" prefix.

The canonical version (``pyproject.toml`` / PyPI / ``bob.__version__``) never
carried a "v"; only the display surfaces and the git tags did. SemVer 2.0.0 is
explicit that "v1.2.3" is not a semantic version. From v0.21.0 the "v" is dropped
everywhere BOB prints its own version, so what the tool shows matches what SemVer
and PyPI call it. These guards pin that the two most visible surfaces — the
``--help`` header and the audit banner — no longer prepend a "v".
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout

from bob import __version__
from bob import cli, output


def _t(key: str, **kw) -> str:
    return key.format(**kw) if kw else key


def test_help_header_has_no_v_prefix():
    """The mutation guard: the --help header prints 'BOB 0.21.0', not 'BOB v…'."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.print_help(_t, __version__)
    out = buf.getvalue()
    assert f"BOB {__version__}" in out
    assert f"BOB v{__version__}" not in out


def test_banner_renders_the_version_without_a_v():
    labels = {k: k.capitalize() for k in
              ("system", "host", "kernel", "ufw", "iptables", "nftables", "user", "date")}
    buf = io.StringIO()
    with redirect_stdout(buf):
        output.print_banner(
            version=__version__, subtitle="Linux hardening auditor",
            system="Debian GNU/Linux 13", host="h", kernel="k", ufw_version="",
            iptables="i", nftables="n", user="root", date="2026-09-21",
            labels=labels)
    out = buf.getvalue()
    assert f"BOB {__version__}" in out
    assert f"BOB v{__version__}" not in out


def test_canonical_version_never_carried_a_v():
    # the source of truth is already SemVer-clean — this is the anchor the
    # display surfaces must now match.
    assert not __version__.startswith("v")
    assert __version__[0].isdigit()
