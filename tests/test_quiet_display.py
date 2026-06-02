"""I-1 (v0.7.4) regression pins — display helpers honour ``quiet`` flag.

Pre-v0.7.4 a handful of display helpers printed to stdout regardless of
the ``--quiet`` flag, breaking the ``bob -q`` empty-stdout contract.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout


def _identity_t(key, **_kw):
    return key


def test_display_geoip_notice_quiet_silences_unavailable():
    from bob.display import display_geoip_notice
    from bob import output as output_mod

    buf = io.StringIO()
    with redirect_stdout(buf):
        display_geoip_notice("unavailable", _identity_t, output_mod, quiet=True)
    assert buf.getvalue() == ""


def test_display_geoip_notice_quiet_silences_no_database():
    from bob.display import display_geoip_notice
    from bob import output as output_mod

    buf = io.StringIO()
    with redirect_stdout(buf):
        display_geoip_notice("no_database", _identity_t, output_mod, quiet=True)
    assert buf.getvalue() == ""


def test_display_geoip_notice_loud_emits_unavailable():
    """Sanity: non-quiet path still produces output."""
    from bob.display import display_geoip_notice
    from bob import output as output_mod

    buf = io.StringIO()
    with redirect_stdout(buf):
        display_geoip_notice("unavailable", _identity_t, output_mod, quiet=False)
    assert buf.getvalue() != ""


def test_display_geoip_notice_default_quiet_is_false():
    """No keyword passed → loud behaviour (back-compat with pre-v0.7.4 callers)."""
    from bob.display import display_geoip_notice
    from bob import output as output_mod

    buf = io.StringIO()
    with redirect_stdout(buf):
        display_geoip_notice("unavailable", _identity_t, output_mod)
    assert buf.getvalue() != ""
