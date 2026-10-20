"""v0.25.1 — --install-cron on a host without /etc/cron.d (Alpine, BusyBox crond).

Measured on Alpine 3.24: BusyBox crond reads /etc/crontabs/, there is no
/etc/cron.d, and the wizard asked every question, wrote /usr/local/bin/bob-NAME,
then failed on the cron file and left the script behind. It now refuses before
the first question, and a cron write that still fails removes the script.
"""

import io
from contextlib import redirect_stderr, redirect_stdout

import bob.cron._install as inst


def test_no_cron_d_is_refused_before_any_question(monkeypatch, tmp_path):
    from bob import i18n
    i18n.init("en")
    monkeypatch.setattr(inst, "CRON_DIR", tmp_path / "cron.d")
    # v0.26.0: refused only where there is no /etc/crontabs either.
    from bob.cron import _crontab
    monkeypatch.setattr(_crontab, "CRONTABS_DIR", tmp_path / "crontabs")
    asked = []
    monkeypatch.setattr(inst, "_run_install_cron_plain", lambda *a: asked.append(1) or 0)
    err = io.StringIO()
    with redirect_stderr(err), redirect_stdout(io.StringIO()):
        rc = inst.run_install_cron(None, None, i18n.t)
    assert rc == 1 and not asked
    assert "/etc/crontabs/" in err.getvalue() and "No job was installed" in err.getvalue()


def test_the_messages_use_the_hosts_privilege_word(monkeypatch):
    from bob import i18n, _privilege
    i18n.init("en")
    monkeypatch.setattr(_privilege, "privilege_prefix", lambda: "doas")
    assert "doas ~/.local/bin/bob" in _privilege.with_privilege(i18n.t("install_cron.bob_binary_missing", path="/x"))
