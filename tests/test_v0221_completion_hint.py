"""v0.22.1 — the 'run --install-completion' hint shows until completion is set up.

pip/pipx cannot print a post-install message, so BOB surfaces the hint itself on
every interactive run until `/etc/bash_completion.d/bob` exists, then goes quiet.
`should_show_completion_hint` is the decision; it must be True only on a TTY,
not under --quiet, and not once completion is installed.
"""

from __future__ import annotations

import bob.completion as c


class TestShouldShowCompletionHint:
    def test_shown_when_not_installed_on_tty(self, monkeypatch):
        monkeypatch.setattr(c, "completion_installed", lambda: False)
        assert c.should_show_completion_hint(is_tty=True, quiet=False) is True

    def test_hidden_once_installed(self, monkeypatch):
        monkeypatch.setattr(c, "completion_installed", lambda: True)
        assert c.should_show_completion_hint(is_tty=True, quiet=False) is False

    def test_hidden_under_quiet(self, monkeypatch):
        monkeypatch.setattr(c, "completion_installed", lambda: False)
        assert c.should_show_completion_hint(is_tty=True, quiet=True) is False

    def test_hidden_off_tty(self, monkeypatch):
        """Piped/redirected output must never carry the hint."""
        monkeypatch.setattr(c, "completion_installed", lambda: False)
        assert c.should_show_completion_hint(is_tty=False, quiet=False) is False


class TestCompletionInstalledMarker:
    def test_reads_the_marker(self, monkeypatch, tmp_path):
        marker = tmp_path / "bob"
        monkeypatch.setattr(c, "_COMPLETION_MARKER", marker)
        assert c.completion_installed() is False
        marker.write_text("x")
        assert c.completion_installed() is True
