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
    monkeypatch.setattr(ps, "deprecation_for", lambda version_info=None, lang="en": {"running": "3.10", "until": "2027-04-01", "next": "3.11"})
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
    monkeypatch.setattr(ps, "deprecation_for", lambda version_info=None, lang="en": None)
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_help(i18n.t, "0.25.1")
    assert "deprecated" not in buf.getvalue()


def test_the_french_message_writes_the_date_in_french():
    """0.26.0 — "jusqu'à 2027-04-01" was the English form inside French text."""
    from bob import i18n
    assert ps.display_date("2027-04-01", "fr") == "1er avril 2027"
    assert ps.display_date("2026-10-15", "fr") == "15 octobre 2026"
    assert ps.display_date("2027-04-01", "en") == "2027-04-01"
    assert ps.display_date("2027-00-01", "fr") == "2027-00-01"
    i18n.init("fr")
    try:
        text = i18n.t("audit.python_deprecated", **ps.deprecation_for((3, 10, 21), lang="fr"))
    finally:
        i18n.init(lang="en")
    assert "jusqu'au 1er avril 2027" in text and "2027-04-01" not in text


def test_both_call_sites_pass_the_language():
    import inspect
    import bob.__main__ as main
    import bob.cli as cli
    assert "deprecation_for(lang=i18n.current_lang())" in inspect.getsource(main)
    assert "deprecation_for(lang=_i18n.current_lang())" in inspect.getsource(cli)
