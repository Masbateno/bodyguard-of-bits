"""The advice was made portable. Then BOB kept reading Debian's files.

The package layer fixed *what BOB advises*. This is the same fault one level
down, in *what BOB reads to decide*: `/etc/pam.d/common-password` is Debian's
name for the PAM password stack and exists nowhere else. The password policy
check read it, caught the OSError, left the module unset and concluded "no PAM
quality module" — a WARN and a one-point deduction — on every Fedora, RHEL,
openSUSE and Arch host, having read nothing at all.

Measured 2026-09-08 in containers:

    Debian/Ubuntu   common-password, common-session, common-auth
    Fedora/RHEL     system-auth, password-auth  (+ postlogin for sessions)
    Arch            system-auth
    Alpine          nothing — no /etc/pam.d at all, and no /etc/login.defs

Alpine is the case that decides the design. It does not use PAM, so "no quality
module configured in PAM" is not a statement about the host's hardening but
about a mechanism it does not have. BOB says it could not establish the answer,
which is the distinction v0.15.2 drew for packages and v0.16.0 drew for the
score, applied to the files a verdict is read from.

And a third hiding place for a Debian command turned up here: **translated
prose**. `prerequisites.ufw_missing` read *"UFW is not installed — install it
with: sudo apt install ufw"* while the same finding's `cmd` field said
`sudo dnf install -y ufw`. BOB contradicted itself on screen, in one finding,
and no guard looked at message strings.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from bob import i18n
from bob.checks._run import _PAM_STACKS, pam_stack_paths, read_pam_stack

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_LOCALES = _ROOT / "bob" / "locales"


class TestThePamStackIsNotJustDebians:

    @pytest.mark.parametrize("concern", ["password", "session"])
    def test_the_stack_names_more_than_one_distribution(self, concern):
        paths = [str(p) for p in pam_stack_paths(concern)]
        assert any("common-" in p for p in paths), "Debian's name is gone"
        assert any("system-auth" in p for p in paths), (
            "system-auth is what Fedora, RHEL, Arch and openSUSE call it; "
            "reading only Debian's name is the defect this closed"
        )

    def test_the_password_stack_covers_the_measured_names(self):
        assert set(_PAM_STACKS["password"]) == {
            "/etc/pam.d/common-password",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
        }

    def test_nothing_readable_is_reported_as_not_established(self, tmp_path):
        absent = (tmp_path / "no-such-file", tmp_path / "nor-this-one")
        text, established = read_pam_stack("password", paths=absent)
        assert text == ""
        assert established is False, (
            "an unreadable stack was reported as read, which is how 'absent' "
            "gets manufactured out of 'could not look'"
        )

    def test_a_readable_file_establishes_the_answer(self, tmp_path):
        f = tmp_path / "system-auth"
        f.write_text("password required pam_pwquality.so minlen=12\n", encoding="utf-8")
        text, established = read_pam_stack("password", paths=(f,))
        assert established is True
        assert "pam_pwquality.so" in text

    def test_every_readable_file_is_merged_not_just_the_first(self, tmp_path):
        # Fedora stacks pam_pwquality in system-auth and includes it from
        # password-auth; reading only the first hit can miss the module.
        a = tmp_path / "system-auth"; a.write_text("auth required pam_env.so\n", encoding="utf-8")
        b = tmp_path / "password-auth"; b.write_text("password required pam_pwquality.so\n", encoding="utf-8")
        text, established = read_pam_stack("password", paths=(a, b))
        assert established and "pam_env.so" in text and "pam_pwquality.so" in text

    def test_an_unreadable_file_does_not_establish_anything(self, tmp_path):
        f = tmp_path / "system-auth"
        f.write_text("password required pam_pwquality.so\n", encoding="utf-8")
        f.chmod(0o000)
        try:
            text, established = read_pam_stack("password", paths=(f,))
        finally:
            f.chmod(0o644)
        # Running as root defeats the permission bit; only assert the contract
        # when the read genuinely failed.
        if not text:
            assert established is False, "unreadable was counted as read"


class TestNoDeductionForAStackThatCouldNotBeRead:

    def test_alpine_shaped_host_gets_unknown_not_a_warning(self):
        from bob.checks.password_policy import PasswordPolicySnapshot, check_password_policy
        from bob.scoring import FindingLevel as FL

        i18n.init(lang="en")
        snap = PasswordPolicySnapshot()
        snap.pam_stack_established = False
        result = check_password_policy(snap, t=i18n.t)
        keys = {f.key for f in result.findings}
        assert "password_policy.pam_stack_unknown" in keys
        assert "password_policy.no_quality_module" not in keys
        assert not any(f.level in (FL.WARN, FL.ALERT) for f in result.findings), (
            "a point was deducted for a PAM module BOB never looked for"
        )

    def test_a_readable_stack_without_the_module_is_still_a_warning(self):
        """The check must not go silent on the case it exists for."""
        from bob.checks.password_policy import PasswordPolicySnapshot, check_password_policy

        i18n.init(lang="en")
        snap = PasswordPolicySnapshot()
        snap.pam_stack_established = True
        snap.pam_quality_module = None
        keys = {f.key for f in check_password_policy(snap, t=i18n.t).findings}
        assert "password_policy.no_quality_module" in keys

    @pytest.mark.parametrize("lang", ("en", "fr"))
    def test_the_unknown_message_resolves(self, lang):
        i18n.init(lang=lang)
        for key in ("password_policy.pam_stack_unknown",
                    "password_policy.pam_stack_unknown_detail"):
            assert not i18n.t(key, paths="/x").startswith("[")


class TestUmaskReadsTheWholeSessionStack:

    def test_the_candidates_include_more_than_debians_file(self, tmp_path):
        from bob.checks.umask import UmaskSnapshot

        # A pam_umask stacked where Fedora and Arch put it must be seen.
        stack = tmp_path / "system-auth"
        stack.write_text("session optional pam_umask.so umask=027\n", encoding="utf-8")
        snap = UmaskSnapshot.from_system(
            _login_defs=tmp_path / "absent-login.defs",
            _pam_session=stack,
            _profile=tmp_path / "absent-profile",
            _bash_bashrc=tmp_path / "absent-bashrc",
            _profile_d=tmp_path / "absent-profile.d",
        )
        assert snap.umask_value == "027", (
            "a pam_umask outside Debian's common-session was not read"
        )

    def test_the_default_path_consults_the_whole_stack(self, tmp_path, monkeypatch):
        """Exercise the body, not the signature.

        The first version of this guard asserted only that the parameter
        defaults to None — which stayed true when the body was changed back to
        a single hardcoded `common-session`. The mutation bench caught that in
        one run: a guard that reads a default while the code reads a file is
        not testing the same thing the code does.
        """
        import bob.checks.umask as umask_mod
        from bob.checks.umask import UmaskSnapshot

        fedora_stack = tmp_path / "system-auth"
        fedora_stack.write_text("session optional pam_umask.so umask=027\n",
                                encoding="utf-8")
        monkeypatch.setattr(umask_mod, "pam_stack_paths",
                            lambda concern: (fedora_stack,))
        snap = UmaskSnapshot.from_system(          # no _pam_session: the default path
            _login_defs=tmp_path / "absent-login.defs",
            _profile=tmp_path / "absent-profile",
            _bash_bashrc=tmp_path / "absent-bashrc",
            _profile_d=tmp_path / "absent-profile.d",
        )
        assert snap.umask_value == "027", (
            "the default path read one distribution's filename instead of the "
            "session stack, so a pam_umask on Fedora or Arch went unseen"
        )
        assert snap.source == str(fedora_stack)


class TestNoDebianCommandHidesInTranslatedProse:
    """The third hiding place, after cmd= literals and dataclass defaults."""

    _APT = re.compile(r"\b(apt|apt-get)\b[^\n]{0,40}\b(install|purge|remove)\b")
    #: Prose that is legitimately Debian-specific: the whole feature is gated on
    #: dpkg being present, so an apt command there is correct by construction.
    _DEBIAN_GATED = {"kernel_modules.kernels_obsolete_detail"}

    @staticmethod
    def _strings(lang):
        data = json.loads((_LOCALES / f"{lang}.json").read_text(encoding="utf-8"))
        out = {}

        def walk(node, path=""):
            for key, value in node.items():
                here = f"{path}.{key}" if path else key
                if isinstance(value, dict):
                    walk(value, here)
                elif isinstance(value, str):
                    out[here] = value
        walk(data)
        return out

    @pytest.mark.parametrize("lang", ("en", "fr"))
    def test_the_audits_own_messages_name_no_package_manager(self, lang):
        offenders = [
            path for path, text in self._strings(lang).items()
            if not path.startswith("explain.")
            and path not in self._DEBIAN_GATED
            and self._APT.search(text)
        ]
        assert not offenders, (
            "the audit's own prose carries a Debian command; the finding's cmd "
            f"field is built for the host's manager and these contradict it: {offenders}"
        )

    @pytest.mark.parametrize("lang", ("en", "fr"))
    def test_every_explain_block_with_a_command_says_whose_it_is(self, lang):
        # The property, not one wording: four blocks already named the family
        # in their own prose ("Debian / Ubuntu / Mint / Kali →") before this
        # pass added a preamble to the other twenty, and a guard pinned to the
        # preamble's exact words would have demanded they be rewritten to say
        # the same thing twice.
        offenders = [
            path for path, text in self._strings(lang).items()
            if path.startswith("explain.") and self._APT.search(text)
            and "Debian" not in text
        ]
        assert not offenders, (
            "an explain block hands out an apt command as though it were "
            f"universal instruction: {offenders}"
        )

    def test_the_guard_would_notice_one(self):
        """Negative control: the pattern must reject the shape it exists for."""
        assert self._APT.search("UFW is not installed — install it with: sudo apt install ufw")
        assert not self._APT.search("Run systemctl enable --now auditd")
