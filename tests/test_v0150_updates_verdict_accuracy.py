"""
v0.15.0 — verdict-accuracy guards for the unattended-upgrades detection.

The inverse direction of the comment defect found in ssh/firewall/sudoers, and
the more dangerous one: there a comment *hid* a problem, here it *invented a
reassurance*. apt reads nothing from a commented line, so unattended upgrades
are off — and BOB reported them enabled.

Expectations confirmed against `apt-config dump APT::Periodic::Unattended-Upgrade`.
"""

from __future__ import annotations

import re

import pytest

from bob.checks.updates import _strip_apt_comments

_KEY_RE = re.compile(r'APT::Periodic::Unattended-Upgrade\s+"1"')


def _enabled(raw: str) -> bool:
    """Mirror the production predicate over the stripped text."""
    return bool(_KEY_RE.search(_strip_apt_comments(raw)))


class TestCommentedOutIsNotEnabled:
    """All three apt comment syntaxes. `apt-config dump` returns nothing for
    each, i.e. the setting is not in effect."""

    @pytest.mark.parametrize("raw", [
        '// APT::Periodic::Unattended-Upgrade "1";',
        '# APT::Periodic::Unattended-Upgrade "1";',
        '/* APT::Periodic::Unattended-Upgrade "1"; */',
        'APT::Periodic::Update-Package-Lists "1";\n'
        '// APT::Periodic::Unattended-Upgrade "1";',
        '   //   APT::Periodic::Unattended-Upgrade "1";',
    ])
    def test_a_commented_line_does_not_enable_upgrades(self, raw):
        assert not _enabled(raw)

    @pytest.mark.parametrize("raw", [
        'APT::Periodic::Unattended-Upgrade "1";',
        'APT::Periodic::Unattended-Upgrade "1"; // keep this on',
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";',
    ])
    def test_a_live_line_still_enables_upgrades(self, raw):
        assert _enabled(raw)

    def test_explicit_zero_is_not_enabled(self):
        assert not _enabled('APT::Periodic::Unattended-Upgrade "0";')


class TestStripAptComments:
    def test_a_quoted_url_is_not_mistaken_for_a_comment(self):
        """`//` inside a double-quoted value is data, not a comment — stripping
        it would corrupt every proxy and mirror line in apt.conf.d."""
        raw = 'Acquire::Proxy "http://proxy.invalid:3128"; // note'
        assert _strip_apt_comments(raw).strip() == \
            'Acquire::Proxy "http://proxy.invalid:3128";'

    def test_a_block_comment_spanning_lines_is_removed(self):
        raw = 'A "1";\n/* B "1";\n   C "1"; */\nD "1";'
        out = _strip_apt_comments(raw)
        assert 'B "1"' not in out and 'C "1"' not in out
        assert 'A "1"' in out and 'D "1"' in out

    def test_plain_text_is_untouched(self):
        raw = 'APT::Periodic::Unattended-Upgrade "1";'
        assert _strip_apt_comments(raw) == raw
