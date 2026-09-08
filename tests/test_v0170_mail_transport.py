"""The cron wizard promised delivery it had never established.

``install_cron.mta_found`` read *"sendmail available — notifications will be
delivered"*, and the whole basis for that sentence was
``shutil.which("sendmail")``. A Postfix installed from the distribution and
never given a relay satisfies it and drops every message, so the one promise
the operator relies on — that they will be told when the score falls — was made
from the presence of a binary on disk.

Three things are pinned here:

* ``describe_reporting`` answers the real question — will anyone hear from this
  job — over the five states that answer it differently, including the two the
  wizard could not see at all before v0.17.0: a job with no address (the
  generated script's *only* channel is that email, so it wrote a report to disk
  on a schedule and told nobody) and a job whose webhook is suppressed by
  ``--offline``.
* ``--test-email`` reports what sendmail actually answered, exit code and all,
  and reports acceptance as acceptance rather than as delivery.
* The notice reaches the screen whole. It used to be cut at the terminal width
  with ``msg[:w - 3]``, so on 80 columns the operator read the first half of
  two sentences of advice.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from bob import i18n
from bob.config import UserConfig
from bob.cron import describe_reporting

_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def _no_mta(monkeypatch):
    import shutil
    real = shutil.which
    monkeypatch.setattr(shutil, "which",
                        lambda n, *a, **k: None if n == "sendmail" else real(n, *a, **k))


@pytest.fixture
def _has_mta(monkeypatch):
    import shutil
    real = shutil.which
    monkeypatch.setattr(shutil, "which",
                        lambda n, *a, **k: "/usr/sbin/sendmail" if n == "sendmail"
                        else real(n, *a, **k))


def _cfg(tmp_path, url: str = "") -> Path:
    path = tmp_path / "root-config.conf"
    cfg = UserConfig.load(path=path)
    if url:
        cfg.set_webhook_url(url)
    return path


class TestWillAnyoneHearFromThisJob:
    """The five states, and the two the wizard used to be blind to."""

    def test_address_and_a_transport_is_not_a_promise(self, tmp_path, _has_mta):
        glyph, key, kw = describe_reporting(["a@b.co"], False, root_config_path=_cfg(tmp_path))
        assert (glyph, key) == ("✔", "install_cron.mta_found")
        assert kw == {"mta": "Postfix"} or "mta" in kw

    def test_address_without_a_transport_is_a_warning(self, tmp_path, _no_mta):
        glyph, key, _ = describe_reporting(["a@b.co"], False, root_config_path=_cfg(tmp_path))
        assert (glyph, key) == ("⚠", "install_cron.mta_missing")

    def test_no_address_and_no_webhook_notifies_nobody(self, tmp_path, _has_mta):
        # The generated script sends mail and does nothing else. Without an
        # address it has no channel at all, and until v0.17.0 the wizard said
        # nothing whatsoever about that.
        glyph, key, _ = describe_reporting([], False, root_config_path=_cfg(tmp_path))
        assert (glyph, key) == ("⚠", "install_cron.reports_nobody")

    def test_no_address_but_a_webhook_is_the_other_way_out(self, tmp_path, _has_mta):
        glyph, key, _ = describe_reporting(
            [], False, root_config_path=_cfg(tmp_path, "https://example.com/h"))
        assert (glyph, key) == ("✔", "install_cron.reports_webhook")

    def test_offline_suppresses_the_webhook_so_that_job_is_mute(self, tmp_path, _has_mta):
        # bob/__main__.py: `if _webhook_url and not config.offline`. Offering
        # the webhook without checking this would be the same defect in a new
        # place.
        glyph, key, _ = describe_reporting(
            [], True, root_config_path=_cfg(tmp_path, "https://example.com/h"))
        assert (glyph, key) == ("⚠", "install_cron.reports_webhook_offline")

    def test_the_webhook_is_read_from_the_config_the_cron_actually_uses(self, tmp_path, _has_mta):
        # A cron entry runs as root. A webhook saved by the operator's own user
        # is invisible to it, which is why the wizard already writes log_dir to
        # /root/.config/bob/config.conf.
        from bob.cron._parse import ROOT_CONFIG_PATH
        assert ROOT_CONFIG_PATH == Path("/root/.config/bob/config.conf")


class TestThePromiseIsGone:
    """Prose guard: presence of a binary is not delivery, in either locale."""

    _FORBIDDEN = {
        "en": ("will be delivered", "notifications will be"),
        "fr": ("seront envoyées", "seront délivrées"),
    }

    @pytest.mark.parametrize("lang", ("en", "fr"))
    def test_mta_found_no_longer_promises_delivery(self, lang):
        data = json.loads((_ROOT / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
        text = data["install_cron"]["mta_found"]
        for banned in self._FORBIDDEN[lang]:
            assert banned not in text, (
                f"{lang}.json install_cron.mta_found promises delivery again: {text!r}. "
                "shutil.which does not establish that mail leaves this host."
            )

    @pytest.mark.parametrize("lang", ("en", "fr"))
    def test_it_points_at_the_command_that_does_establish_it(self, lang):
        data = json.loads((_ROOT / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
        assert "--test-email" in data["install_cron"]["mta_found"]

    @pytest.mark.parametrize("lang", ("en", "fr"))
    def test_acceptance_is_reported_as_acceptance(self, lang):
        # sendmail exiting 0 means the MTA queued it. A relay or a spam filter
        # can still drop it, and saying otherwise would rebuild the same trap.
        data = json.loads((_ROOT / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
        assert data["cli"]["test_email"]["accepted_caveat"].strip()


class TestTestEmailReportsWhatSendmailAnswered:
    """End to end through the real handler, with a sendmail we control."""

    @staticmethod
    def _run(tmp_path, exit_code: int, address: str = "admin@example.com", lang="en"):
        home = tmp_path / "home"
        (home / ".config" / "bob").mkdir(parents=True, exist_ok=True)
        (home / ".config" / "bob" / "emails").write_text(address + "\n", encoding="utf-8")
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        fake = bindir / "sendmail"
        fake.write_text(f"#!/bin/sh\ncat >/dev/null\nexit {exit_code}\n", encoding="utf-8")
        fake.chmod(0o755)
        env = {
            "HOME": str(home),
            "PATH": f"{bindir}:/usr/bin:/bin",
            "PYTHONPATH": str(_ROOT),
            "NO_COLOR": "1",
            "LANG": "C",
        }
        return subprocess.run(
            [sys.executable, "-m", "bob", "--test-email", f"--lang={lang}"],
            capture_output=True, text=True, env=env, timeout=60,
        )

    def test_sendmail_accepting_exits_zero(self, tmp_path):
        r = self._run(tmp_path, 0)
        assert r.returncode == 0, r.stderr
        assert "admin@example.com" in r.stdout

    def test_sendmail_refusing_exits_nonzero(self, tmp_path):
        # This is the case shutil.which could never see, and the reason the
        # command exists at all.
        r = self._run(tmp_path, 1)
        assert r.returncode != 0
        assert "sendmail" in r.stderr

    def test_the_attempt_is_announced_before_the_verdict(self, tmp_path):
        # stdout is block-buffered when redirected while stderr is not, so
        # without an explicit flush a piped run read as though the failure
        # preceded the attempt. Both streams are merged here, because that is
        # the only arrangement in which the ordering is observable at all —
        # asserting on stdout alone proves nothing: the interpreter flushes it
        # at exit regardless.
        r = self._merged(tmp_path, 1)
        out = r.stdout
        assert "Sending a test message" in out, out
        assert "refused" in out, out
        assert out.index("Sending a test message") < out.index("refused"), (
            "the verdict was printed before the attempt it reports on:\n" + out
        )

    @staticmethod
    def _merged(tmp_path, exit_code: int):
        home = tmp_path / "home"
        (home / ".config" / "bob").mkdir(parents=True, exist_ok=True)
        (home / ".config" / "bob" / "emails").write_text("admin@example.com\n",
                                                        encoding="utf-8")
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        fake = bindir / "sendmail"
        fake.write_text(f"#!/bin/sh\ncat >/dev/null\nexit {exit_code}\n", encoding="utf-8")
        fake.chmod(0o755)
        return subprocess.run(
            [sys.executable, "-m", "bob", "--test-email", "--lang=en"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60,
            env={"HOME": str(home), "PATH": f"{bindir}:/usr/bin:/bin",
                 "PYTHONPATH": str(_ROOT), "NO_COLOR": "1", "LANG": "C"},
        )

    def test_an_empty_address_book_says_so_rather_than_sending(self, tmp_path):
        home = tmp_path / "home"
        (home / ".config" / "bob").mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            [sys.executable, "-m", "bob", "--test-email"],
            capture_output=True, text=True, timeout=60,
            env={"HOME": str(home), "PATH": "/usr/bin:/bin",
                 "PYTHONPATH": str(_ROOT), "NO_COLOR": "1", "LANG": "C"},
        )
        assert r.returncode != 0
        assert "[cli.test_email" not in r.stderr, "unresolved locale key on screen"

    def test_the_store_is_actually_read_from_disk(self, tmp_path):
        # EmailStore() is a constructor with an empty list; only EmailStore.load()
        # reads the file. Calling the former made --test-email answer
        # "no address configured" on every host, always.
        src = (_ROOT / "bob" / "__main__.py").read_text(encoding="utf-8")
        block = src[src.index("config.test_email"):]
        block = block[:block.index("test_webhook")]
        assert "EmailStore.load()" in block
        assert "EmailStore()" not in block


class TestTheNoticeReachesTheScreenWhole:
    """It was cut at the terminal width, so half the advice never arrived."""

    def test_the_flash_wraps_rather_than_slicing(self):
        src = (_ROOT / "bob" / "tui" / "cron.py").read_text(encoding="utf-8")
        fn = next(n for n in ast.walk(ast.parse(src))
                  if isinstance(n, ast.FunctionDef) and n.name == "_curses_status_flash")
        assert any(isinstance(n, ast.Attribute) and n.attr == "wrap" for n in ast.walk(fn))
        # Asked of the syntax tree, not of the text: the comment recording the
        # old behaviour contains the old expression, and a text match on it
        # would fail on the very commit that fixed it.
        sliced = [n for n in ast.walk(fn)
                  if isinstance(n, ast.Subscript)
                  and getattr(n.value, "id", "") == "msg"]
        assert not sliced, "the message is being sliced to width again"

    def test_the_flash_actually_renders(self):
        """The AST guard above passes on a flash that crashes on sight.

        It did. The first wrapping version sized its body with
        ``_chrome.chrome_height()`` — no arguments, three required — so every
        call raised TypeError and ``--install-cron`` died with *"Fatal error"*
        at the screen whose whole job is to report what went wrong. The source
        read correctly; only running it said otherwise. This drives the real
        function against a recording screen.
        """
        import types

        drawn: list[tuple[int, int, str]] = []

        class _Scr:
            def erase(self): pass
            def getmaxyx(self): return (24, 80)
            def refresh(self): pass
            def get_wch(self): return " "
            def addstr(self, y, x, text, *a):
                drawn.append((y, x, text))

        fake = types.SimpleNamespace(
            has_colors=lambda: False,
            color_pair=lambda n: 0,
            A_BOLD=0, A_REVERSE=0, A_NORMAL=0, A_DIM=0,
            error=type("error", (Exception,), {}),
        )
        import sys as _sys
        from unittest import mock
        from bob.tui.cron import _curses_status_flash

        i18n.init(lang="en")
        long_notice = i18n.t("install_cron.reports_nobody")
        with mock.patch.dict(_sys.modules, {"curses": fake}):
            _curses_status_flash(_Scr(), i18n.t, long_notice)

        body = " ".join(text for y, _x, text in drawn if 2 <= y < 20)
        assert body.strip(), "the flash drew nothing"
        # Every word of the notice reached a row, not just the first line.
        missing = [w for w in long_notice.split() if w not in body]
        assert not missing, f"the notice lost words on screen: {missing[:6]}"

    def test_the_plain_wizard_wraps_the_notice(self):
        src = (_ROOT / "bob" / "cron" / "_install.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        calls = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Call)
                 and getattr(n.func, "id", "") == "_print_wrapped"]
        assert calls, "the reporting notice no longer goes through _print_wrapped"

    def test_wrapping_keeps_every_word(self):
        from bob.cron._install import _print_wrapped
        import io
        import contextlib
        msg = " ".join(f"word{i}" for i in range(120))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_wrapped(msg)
        assert buf.getvalue().split() == msg.split()


class TestTheReasoningStillHolds:
    """describe_reporting reasons about a script it does not own."""

    def test_the_generated_script_still_notifies_only_by_mail(self):
        # If a second channel is ever added to build_script_content,
        # describe_reporting's "notifies nobody" verdict becomes wrong.
        from bob.cron._io import build_script_content
        script = build_script_content("", "/var/log/bob", "--profile server --english")
        assert "NOTIFY_EMAILS" in script
        assert "webhook" not in script.lower(), (
            "the generated script grew a channel describe_reporting does not know about"
        )

    def test_the_audit_path_still_suppresses_the_webhook_when_offline(self):
        src = (_ROOT / "bob" / "__main__.py").read_text(encoding="utf-8")
        assert re.search(r"if _webhook_url and not config\.offline", src), (
            "reports_webhook_offline describes a suppression that no longer exists"
        )


class TestBothWizardsGiveTheVerdictOnce:
    """It used to fire at the email step, before the network choice was made."""

    @pytest.mark.parametrize("path", ("bob/cron/_install.py", "bob/tui/cron.py"))
    def test_the_wizard_calls_describe_reporting(self, path):
        src = (_ROOT / path).read_text(encoding="utf-8")
        assert "describe_reporting(" in src

    @pytest.mark.parametrize("path", ("bob/cron/_install.py", "bob/tui/cron.py"))
    def test_no_wizard_decides_this_from_the_mta_alone(self, path):
        src = (_ROOT / path).read_text(encoding="utf-8")
        tree = ast.parse(src)
        calls = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_detect_mta"]
        assert not calls, (
            f"{path} decides the notification verdict from _detect_mta again; "
            "the network stance is half of that answer"
        )


class TestEveryNewKeyResolves:
    @pytest.mark.parametrize("lang", ("en", "fr"))
    def test_no_bracketed_sentinel(self, lang):
        i18n.init(lang=lang)
        keys = [
            "help.opt.test_email",
            "install_cron.reports_nobody",
            "install_cron.reports_webhook",
            "install_cron.reports_webhook_offline",
        ] + [f"cli.test_email.{k}" for k in (
            "no_address", "bad_address", "no_sendmail", "sending", "subject",
            "body", "failed", "rejected", "rejected_hint", "accepted",
            "accepted_caveat")]
        for key in keys:
            rendered = i18n.t(key, to="a@b.co", path="/x", error="e", mta="Postfix")
            assert not rendered.startswith("["), f"{lang}: {key} is unresolved"
