"""v0.26.0 — on BusyBox crond, a BOB job is a block of root's crontab.

Alpine 3.24 (BusyBox v1.37.0) has no /etc/cron.d; crond reads
/etc/crontabs/root. Measured: an edit of that file was not picked up in three
minutes; with "root" in /etc/crontabs/cron.update, crond re-read it within a
minute and removed cron.update. The generated script was bash (`read -ra`,
`<<<`, arrays) while Alpine ships no bash.
"""

import stat

import pytest

from bob.cron import _crontab, _io, _parse

STOCK = ("# do daily/weekly/monthly maintenance\n"
         "*/15\t*\t*\t*\t*\trun-parts /etc/periodic/15min\n"
         "0\t2\t*\t*\t*\trun-parts /etc/periodic/daily\n")


@pytest.fixture
def crontab(monkeypatch, tmp_path):
    d = tmp_path / "crontabs"
    d.mkdir()
    root = d / "root"
    root.write_text(STOCK)
    root.chmod(0o600)
    monkeypatch.setattr(_crontab, "CRONTABS_DIR", d)
    monkeypatch.setattr(_crontab, "ROOT_CRONTAB", root)
    monkeypatch.setattr(_crontab, "CRON_UPDATE", d / "cron.update")
    monkeypatch.setattr(_parse, "CRON_DIR", tmp_path / "no-cron.d")
    return root


def _install(slug, name="nightly", email="ops@example.org", expr="0 3 * * *"):
    script = _crontab.CRONTABS_DIR.parent / f"bob-{slug}"
    script.write_text(f"#!/bin/sh\nNOTIFY_EMAILS={email}\n")
    return _io.write_cron_job(slug, name, email, expr, script, "2026-10-18")


def test_a_name_already_waiting_in_cron_update_is_kept(crontab):
    """busybox crontab appends the user's name to cron.update; a name another
    edit left there must survive BOB's."""
    (crontab.parent / "cron.update").write_text("alice\n")
    _install("nightly")
    assert (crontab.parent / "cron.update").read_text() == "alice\nroot\n"


def test_the_job_goes_into_roots_crontab_and_nothing_else_moves(crontab):
    assert _io.use_crontab()
    assert _install("nightly") == crontab
    text = crontab.read_text()
    assert text.startswith(STOCK)
    assert "# BEGIN BOB cron bob-nightly" in text and f"0 3 * * *  {crontab.parent.parent / 'bob-nightly'}" in text
    assert stat.S_IMODE(crontab.stat().st_mode) == 0o600
    assert (crontab.parent / "cron.update").read_text() == "root\n"


def test_jobs_are_listed_edited_and_removed_one_by_one(crontab):
    _install("nightly")
    _install("weekly", name="weekly", expr="0 4 * * 0")
    entries = {e.crontab_slug: e for e in _parse.list_installed_crons()}
    assert set(entries) == {"nightly", "weekly"}
    nightly = entries["nightly"]
    assert (nightly.name, nightly.email, nightly.schedule_expr) == ("nightly", "ops@example.org", "0 3 * * *")
    assert nightly.key != entries["weekly"].key
    assert _io.apply_cron_schedule(nightly, "30 1 * * *") == ""
    assert _io.apply_cron_email(nightly, "sec@example.org")[0] == ""
    after = {e.crontab_slug: e for e in _parse.list_installed_crons()}
    assert after["nightly"].schedule_expr == "30 1 * * *" and after["nightly"].email == "sec@example.org"
    assert after["weekly"].schedule_expr == "0 4 * * 0"
    _io.remove_cron_job(after["nightly"])
    assert [e.crontab_slug for e in _parse.list_installed_crons()] == ["weekly"]
    _io.remove_cron_job(after["weekly"])
    assert crontab.read_text() == STOCK


def test_a_name_cannot_write_a_cron_line(crontab):
    _install("evil", name="x\n* * * * * /tmp/pwn")
    lines = [ln for ln in crontab.read_text().splitlines() if ln and not ln.startswith("#")]
    assert not any("/tmp/pwn" in ln for ln in lines)


def test_the_installer_no_longer_refuses_a_crontab_host(crontab, monkeypatch):
    import io
    from contextlib import redirect_stderr, redirect_stdout
    import bob.cron._install as inst
    from bob import i18n
    i18n.init("en")
    monkeypatch.setattr(inst, "CRON_DIR", crontab.parent.parent / "no-cron.d")
    called = []
    monkeypatch.setattr(inst, "_run_install_cron_plain", lambda *a: called.append(1) or 0)
    with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
        assert inst.run_install_cron(None, None, i18n.t) == 0
    assert called


def test_the_script_is_posix_sh():
    script = _io.build_script_content("a@x.org,b@y.org", "/var/log/bob")
    assert script.startswith("#!/bin/sh\n") and "\nexport PATH\n" in script
    for bashism in ("read -ra", "<<<", "${_ADDRS"):
        assert bashism not in script


def test_the_no_job_hint_uses_the_hosts_privilege_word():
    """Measured on Alpine (doas, no sudo): "No BOB cron jobs installed. Run: sudo bob --install-cron"."""
    import inspect
    import bob.cron._manage as manage
    import bob.tui.cron as tui
    assert "with_privilege('sudo bob --install-cron')" in inspect.getsource(manage)
    assert 'with_privilege("sudo bob --install-cron")' in inspect.getsource(tui)
