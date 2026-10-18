"""v0.25.1 — Python 3.10 is announced as deprecated, with a dated margin.

Step 2 of the v0.7.0 ladder (announce in the changelog and --help) was never
taken, and 3.10 reached upstream end of life on 2026-10-01. The rule: 6 months
of support after the official end of life — 2027-04-01 for 3.10.
"""

import io
from contextlib import redirect_stdout

import bob._python_support as ps


def test_only_310_is_deprecated():
    assert ps.deprecation_for((3, 10, 12)) == {"running": "3.10", "until": "2027-04-01", "next": "3.11"}
    for v in ((3, 11, 0), (3, 12, 3), (3, 14, 0)):
        assert ps.deprecation_for(v) is None


def test_help_shows_the_notice_on_310_within_the_width(monkeypatch):
    from bob import i18n
    from bob.cli import print_help
    i18n.init("en")
    monkeypatch.setattr(ps, "deprecation_for", lambda version_info=None: {"running": "3.10", "until": "2027-04-01", "next": "3.11"})
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_help(i18n.t, "0.25.1")
    out = buf.getvalue()
    assert "Python 3.10 is deprecated" in out and "2027-04-01" in out
    assert all(len(line) <= 100 for line in out.splitlines())


def test_help_is_silent_elsewhere(monkeypatch):
    from bob import i18n
    from bob.cli import print_help
    i18n.init("en")
    monkeypatch.setattr(ps, "deprecation_for", lambda version_info=None: None)
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_help(i18n.t, "0.25.1")
    assert "deprecated" not in buf.getvalue()
