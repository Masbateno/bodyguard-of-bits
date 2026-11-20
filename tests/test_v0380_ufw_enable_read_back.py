"""v0.38.0 — after `ufw enable` exits 0, BOB asks ufw whether it is on.

`--fix --apply` counted a fix applied on its exit status. `ufw enable` under
SSH asked "Proceed with operation (y|n)?", read no answer on the closed stdin,
printed "Aborted", exited 0 and stayed inactive; BOB said "✔ Applied" (14
November 2026). `--force` (0.37.0) removed that case; this removes the class.

Measured (16 November 2026) on the test Linux Mint 22.3, ufw 0.36.2, locale
fr_FR.UTF-8, through BOB's own runner (a10380/a4-mint-real.txt):
- `sudo ufw enable` → run ok, exit 0, read back False; the fix loop now says
  "✖ manual … but `ufw status` still says inactive", "0 of 1";
- `sudo ufw --force enable` → read back True, "✔ Applied", "1 of 1";
- `sudo -n ufw status` answers in English under the French locale (the C
  environment run_result passes survives sudo);
- as `nobody` (sudo refused, ufw status refused) → None: outcome unknown.
"""

from __future__ import annotations

from types import SimpleNamespace as N

import pytest

from bob import fixes, i18n
from bob.checks import _run
from bob.checks._run import CommandResult


@pytest.mark.parametrize("out, ok, state", [
    ("Status: active\n\nTo Action From\n", True, True),
    ("Status: inactive\n", True, False),
    ("Status: active\n", False, None),          # a refused or failed read is not a reading
    ("État : actif\n", True, None),              # a translated line is not a reading
    ("", True, None),
    ("Status: activating\n", True, None),
])
def test_only_an_explicit_status_is_a_reading(monkeypatch, out, ok, state):
    monkeypatch.setattr(_run, "run_result", lambda *a, **k: CommandResult(out, ok))
    assert fixes._ufw_read_back(["sudo", "ufw", "--force", "enable"]) is state


@pytest.mark.parametrize("argv, asked", [
    (["sudo", "ufw", "--force", "enable"], ("sudo", "-n", "ufw", "status")),
    (["/usr/bin/doas", "ufw", "enable"], ("/usr/bin/doas", "-n", "ufw", "status")),
    (["ufw", "--force", "enable"], ("ufw", "status")),
])
def test_it_asks_with_the_fix_s_own_privilege_tool_never_prompting(monkeypatch, argv, asked):
    seen = []
    monkeypatch.setattr(_run, "run_result", lambda *a, **k: seen.append(a) or CommandResult("Status: active\n", True))
    fixes._ufw_read_back(argv)
    assert seen == [asked]


@pytest.mark.parametrize("cmd, hit", [
    ("sudo ufw --force enable", True), ("sudo ufw enable", True), ("ufw  --force  enable", True),
    ("sudo ufw --force disable", False), ("sudo ufw allow 22/tcp", False), ("sudo ufw-enable", False),
])
def test_which_commands_are_read_back(cmd, hit):
    assert bool(fixes._UFW_ENABLE.search(cmd)) is hit


def _loop(monkeypatch, capsys, cmd, state):
    monkeypatch.setattr(fixes, "_run_fix_command", lambda argv, timeout: ("ok", 0, b""))
    asked = []
    monkeypatch.setattr(fixes, "_ufw_read_back", lambda argv: asked.append(argv) or state)
    i18n.init("en")
    f = N(nature="action", cmd=cmd, cmd_type="fix", fix_action=None, message="Firewall off", section="firewall",
          key="firewall.ufw_inactive")
    fixes.run_fixes(N(findings=[f]), N(yes=True, apply=True, check_only=None), i18n.t)
    return capsys.readouterr().out, asked


def test_still_inactive_is_not_applied(monkeypatch, capsys):
    out, asked = _loop(monkeypatch, capsys, "sudo ufw --force enable", False)
    from bob import fix_journal                          # v0.40.0: the journal says what was said
    (entry,) = fix_journal.load().entries
    assert (entry.finding, entry.command, entry.status) == (
        "firewall.ufw_inactive", "sudo ufw --force enable", "failed")
    assert asked == [["sudo", "ufw", "--force", "enable"]]
    assert "still says inactive" in out and "0 of 1 fix(es) applied" in out
    assert "✔ Applied" not in out


def test_unread_is_unknown_not_applied(monkeypatch, capsys):
    out, _ = _loop(monkeypatch, capsys, "sudo ufw --force enable", None)
    assert "could not be read back" in out and "0 of 1 fix(es) applied" in out
    assert "OUTCOME UNKNOWN" in out and "✔ Applied" not in out


def test_active_is_applied(monkeypatch, capsys):
    out, _ = _loop(monkeypatch, capsys, "sudo ufw --force enable", True)
    assert "✔ Applied" in out and "1 of 1 fix(es) applied" in out


def test_another_command_is_not_read_back(monkeypatch, capsys):
    out, asked = _loop(monkeypatch, capsys, "sudo systemctl enable --now fail2ban", False)
    assert asked == [] and "1 of 1 fix(es) applied" in out


@pytest.mark.parametrize("lang, words", [("en", "still says inactive"), ("fr", "dit toujours inactif")])
def test_both_texts_exist(lang, words):
    i18n.init(lang)
    try:
        assert words in i18n.t("fixes.ufw_still_inactive")
        assert "ufw status" in i18n.t("fixes.ufw_unconfirmed")
    finally:
        i18n.init(lang="en")
