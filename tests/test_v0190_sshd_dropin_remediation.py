"""v0.19.0 — sshd remediation targets the file that actually wins.

Field-tested on a real Raspberry Pi (Raspbian trixie): modern OpenSSH reads
``Include /etc/ssh/sshd_config.d/*.conf`` at the top of sshd_config and resolves
first-value-wins, so ``50-cloud-init.conf``'s ``PasswordAuthentication yes`` beat
the main file. The three earlier fixes edited only /etc/ssh/sshd_config with a
sed match on the exact bad line — a no-op when the directive lives in a drop-in.
BOB still *detected* the value (it parses Includes), so it did not report a false
clean, but its advice did nothing on the default modern layout.

The parser now records the drop-in directory, and the fix writes
``00-bob-hardening.conf`` there — sorts before 50-cloud-init.conf, first-wins,
overrides it — deleting any prior copy of the parameter first so it is
idempotent. Proven on the Pi: sshd -T flipped yes -> no after the fix.
"""

from __future__ import annotations

from pathlib import Path

from bob.checks.ssh._parsers import _parse_config_file
from bob.checks.ssh._subchecks import _sshd_directive_fix


class TestParserRecordsDropinDir:
    def test_glob_include_records_the_directory(self, tmp_path):
        d = tmp_path / "sshd_config.d"
        d.mkdir()
        (d / "50-cloud-init.conf").write_text("PasswordAuthentication yes\n", encoding="utf-8")
        main = tmp_path / "sshd_config"
        main.write_text(f"Port 22\nInclude {d}/*.conf\n", encoding="utf-8")
        cfg: dict = {}
        _parse_config_file(main, cfg, set())
        assert cfg.get("_dropin_dir") == str(d)
        assert cfg.get("passwordauthentication") == "yes"   # read via the Include

    def test_no_glob_include_leaves_dropin_dir_unset(self, tmp_path):
        main = tmp_path / "sshd_config"
        main.write_text("Port 22\nPermitRootLogin yes\n", encoding="utf-8")
        cfg: dict = {}
        _parse_config_file(main, cfg, set())
        assert "_dropin_dir" not in cfg


class TestFixTargetsTheWinningFile:
    def test_dropin_present_writes_the_00_override(self):
        cmd = _sshd_directive_fix("PasswordAuthentication no", "PasswordAuthentication",
                                  {"_dropin_dir": "/etc/ssh/sshd_config.d"})
        assert "/etc/ssh/sshd_config.d/00-bob-hardening.conf" in cmd
        # deletes the parameter before appending → idempotent, and beats a later
        # drop-in by lexical order
        assert cmd.index("/Id") < cmd.index("tee -a")
        assert "PasswordAuthentication no" in cmd

    def test_no_dropin_edits_the_main_file(self):
        cmd = _sshd_directive_fix("PermitRootLogin prohibit-password", "PermitRootLogin", {})
        assert "/etc/ssh/sshd_config" in cmd
        assert "00-bob-hardening.conf" not in cmd
        assert cmd.index("/Id") < cmd.index("tee -a")   # delete-then-append here too

    def test_the_bad_line_is_deleted_not_matched_verbatim(self):
        """The old fix only matched `PermitRootLogin yes`; a value written as
        `permitrootlogin=yes` or with odd spacing slipped past. The delete regex
        is case-insensitive and accepts space or `=`."""
        cmd = _sshd_directive_fix("PermitRootLogin prohibit-password", "PermitRootLogin", {})
        assert "PermitRootLogin([[:space:]]|=)" in cmd
        assert "/Id" in cmd   # case-insensitive delete
