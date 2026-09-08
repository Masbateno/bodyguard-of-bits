"""BOB reasoned about software and never asked what machine it was on.

Three findings stated x86 facts on hardware that has no x86 in it. The clearest
was Secure Boot: with no UEFI firmware present, BOB announced *"Legacy BIOS
detected"* — and a Raspberry Pi has no BIOS either. It boots from a bootloader
in EEPROM, and the sentence was a guess wearing the clothes of an observation.

What a Pi has that a PC does not is a **FAT boot partition**. FAT carries no
ownership and no permission bits of its own: a file's apparent mode comes
entirely from the mount options, and none of it survives the card being read on
another machine. The Raspberry Pi Imager writes provisioning files there, one
of which holds a **password hash**, and the first boot is meant to consume and
delete them.

Deliberately absent: any attempt to test whether the `pi` account still has the
distribution's historical default password. That needs a crypt implementation,
and ``crypt`` was removed from the standard library in Python 3.13, which BOB
supports. A check that works on three interpreter versions and silently stops
working on the fourth is worse than one that states its limit — the lesson
v0.15.0 learned from ``importorskip``.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.raspberry_pi import RaspberryPiSnapshot, check_raspberry_pi
from bob.platform import boot_firmware_dir, machine, raspberry_pi_model
from bob.scoring import FindingLevel as FL


@pytest.fixture(autouse=True)
def _english():
    i18n.init(lang="en")


class TestTheBoardIsIdentifiedFromTheFirmware:

    def test_the_device_tree_names_the_board(self, tmp_path):
        dt = tmp_path / "model"
        # The device tree stores C strings: NUL-terminated, and `.strip()`
        # alone does not remove a NUL.
        dt.write_bytes(b"Raspberry Pi 4 Model B Rev 1.5\x00")
        assert raspberry_pi_model(_device_tree=dt,
                                  _cpuinfo=tmp_path / "absent") == "Raspberry Pi 4 Model B Rev 1.5"

    def test_cpuinfo_answers_when_there_is_no_device_tree(self, tmp_path):
        cpu = tmp_path / "cpuinfo"
        cpu.write_text(
            "processor\t: 0\nHardware\t: BCM2711\n"
            "Model\t\t: Raspberry Pi 4 Model B Rev 1.5\n", encoding="utf-8")
        assert "Raspberry Pi 4" in raspberry_pi_model(
            _device_tree=tmp_path / "absent", _cpuinfo=cpu)

    def test_another_board_is_not_a_raspberry_pi(self, tmp_path):
        dt = tmp_path / "model"
        dt.write_bytes(b"Radxa ROCK 5B\x00")
        assert raspberry_pi_model(_device_tree=dt, _cpuinfo=tmp_path / "absent") == ""

    def test_neither_source_readable_answers_empty_not_a_guess(self, tmp_path):
        assert raspberry_pi_model(_device_tree=tmp_path / "a",
                                  _cpuinfo=tmp_path / "b") == ""

    def test_the_machine_is_reported_as_uname_gives_it(self):
        assert machine() == __import__("os").uname().machine

    def test_the_boot_partition_is_found_by_content_not_by_path(self, tmp_path):
        # /boot exists on every Linux system; on Bookworm it is an ordinary
        # directory and the FAT partition is at /boot/firmware. The one the
        # firmware reads is the one holding config.txt.
        plain, fat = tmp_path / "boot", tmp_path / "firmware"
        plain.mkdir(); fat.mkdir()
        (fat / "config.txt").write_text("arm_64bit=1\n", encoding="utf-8")
        assert boot_firmware_dir(_candidates=(plain, fat)) == fat
        assert boot_firmware_dir(_candidates=(plain,)) is None


class TestTheProvisioningHashIsAFinding:

    @staticmethod
    def _snap(tmp_path, *, userconf=None, ssh=False, mode=0o644):
        boot = tmp_path / "boot"
        boot.mkdir(exist_ok=True)
        (boot / "config.txt").write_text("arm_64bit=1\n", encoding="utf-8")
        if userconf is not None:
            f = boot / "userconf.txt"
            f.write_text(userconf, encoding="utf-8")
            f.chmod(mode)
        if ssh:
            (boot / "ssh").touch()
        # The real collection path, driven on a machine that is not a Pi.
        return RaspberryPiSnapshot.from_system(
            _boot_dir=boot,
            _passwd=tmp_path / "absent-passwd",
            _shadow=tmp_path / "absent-shadow",
            _model="Raspberry Pi 4 Model B Rev 1.5",
        )

    def test_a_hash_left_behind_is_a_warning_with_a_deduction(self, tmp_path):
        snap = self._snap(tmp_path, userconf="pi:$6$salt$" + "a" * 60 + "\n")
        result = check_raspberry_pi(snap, t=i18n.t)
        f = next(f for f in result.findings if f.key == "raspberry_pi.userconf_present")
        assert f.level is FL.WARN
        assert "pi" in f.message
        assert "userconf.txt" in f.cmd, "the remedy must name the file to delete"

    def test_the_measured_mode_is_reported_not_assumed(self, tmp_path):
        snap = self._snap(tmp_path, userconf="pi:$6$salt$" + "b" * 60 + "\n", mode=0o600)
        f = next(f for f in check_raspberry_pi(snap, t=i18n.t).findings
                 if f.key == "raspberry_pi.userconf_present")
        assert "600" in f.detail, (
            "the mode is measured because FAT has none of its own; stating a "
            "fixed one would be inventing a fact about the mount options"
        )

    def test_a_file_without_a_hash_is_not_a_credential(self, tmp_path):
        # Only `user:crypt-hash` counts. A stray note in the boot partition is
        # not a password.
        snap = self._snap(tmp_path, userconf="just some text\n")
        keys = {f.key for f in check_raspberry_pi(snap, t=i18n.t).findings}
        assert "raspberry_pi.userconf_present" not in keys
        assert "raspberry_pi.userconf_absent" in keys

    @pytest.mark.parametrize("scheme", ["$6$", "$5$", "$y$"])
    def test_every_crypt_scheme_raspberry_pi_os_uses_is_recognised(self, tmp_path, scheme):
        # Bookworm's imager writes yescrypt ($y$); older ones SHA-512 ($6$).
        snap = self._snap(tmp_path, userconf=f"pi:{scheme}salt$" + "c" * 40 + "\n")
        keys = {f.key for f in check_raspberry_pi(snap, t=i18n.t).findings}
        assert "raspberry_pi.userconf_present" in keys, f"{scheme} went unrecognised"

    def test_a_clean_boot_partition_says_so(self, tmp_path):
        snap = self._snap(tmp_path)
        keys = {f.key for f in check_raspberry_pi(snap, t=i18n.t).findings}
        assert "raspberry_pi.userconf_absent" in keys

    def test_the_ssh_marker_is_information_not_a_deduction(self, tmp_path):
        snap = self._snap(tmp_path, ssh=True)
        f = next(f for f in check_raspberry_pi(snap, t=i18n.t).findings
                 if f.key == "raspberry_pi.ssh_marker")
        assert f.level is FL.INFO, (
            "the marker enables sshd; sshd's own configuration decides what "
            "that exposes, and the ssh section already judges that"
        )


class TestTheDefaultAccount:

    @staticmethod
    def _files(tmp_path, passwd_line, shadow_line):
        p = tmp_path / "passwd"; p.write_text(passwd_line, encoding="utf-8")
        s = tmp_path / "shadow"; s.write_text(shadow_line, encoding="utf-8")
        return p, s

    def _state(self, tmp_path, passwd_line, shadow_line):
        from bob.checks.raspberry_pi import _legacy_account_state
        return _legacy_account_state(*self._files(tmp_path, passwd_line, shadow_line))

    def test_a_usable_account_is_reported(self, tmp_path):
        can_login, established = self._state(
            tmp_path, "pi:x:1000:1000::/home/pi:/bin/bash\n",
            "pi:$6$salt$hash:19000:0:99999:7:::\n")
        assert (can_login, established) == (True, True)

    def test_a_locked_account_is_not_a_way_in(self, tmp_path):
        # `!` and `*` mean no password will ever match. An account that exists
        # but cannot authenticate is a leftover, not an exposure.
        for secret in ("!", "*", "!$6$salt$hash"):
            can_login, _ = self._state(
                tmp_path, "pi:x:1000:1000::/home/pi:/bin/bash\n",
                f"pi:{secret}:19000:0:99999:7:::\n")
            assert can_login is False, f"{secret!r} was read as a usable password"

    def test_a_nologin_shell_is_not_a_way_in(self, tmp_path):
        can_login, _ = self._state(
            tmp_path, "pi:x:1000:1000::/home/pi:/usr/sbin/nologin\n",
            "pi:$6$salt$hash:19000:0:99999:7:::\n")
        assert can_login is False

    def test_no_pi_account_at_all(self, tmp_path):
        can_login, established = self._state(
            tmp_path, "root:x:0:0::/root:/bin/bash\n", "root:*:19000:0:99999:7:::\n")
        assert (can_login, established) == (False, True)

    def test_unreadable_shadow_is_not_established_rather_than_absent(self, tmp_path):
        p = tmp_path / "passwd"
        p.write_text("pi:x:1000:1000::/home/pi:/bin/bash\n", encoding="utf-8")
        can_login, established = __import__(
            "bob.checks.raspberry_pi", fromlist=["_legacy_account_state"]
        )._legacy_account_state(p, tmp_path / "no-such-shadow")
        assert established is False, (
            "an unreadable /etc/shadow must not be read as 'the account has no "
            "password' — that is the class v0.15.2 closed for packages"
        )
        assert can_login is False

    def test_the_unknown_case_deducts_nothing(self, tmp_path):
        snap = RaspberryPiSnapshot(is_pi=True, model="Raspberry Pi 4", arch="aarch64")
        snap.boot_dir = tmp_path
        snap.shadow_readable = False
        result = check_raspberry_pi(snap, t=i18n.t)
        keys = {f.key for f in result.findings}
        assert "raspberry_pi.account_unknown" in keys
        assert not any(f.level in (FL.WARN, FL.ALERT) for f in result.findings)

    def test_a_usable_default_account_costs_a_point(self, tmp_path):
        snap = RaspberryPiSnapshot(is_pi=True, model="Raspberry Pi 4", arch="aarch64")
        snap.boot_dir = tmp_path
        snap.legacy_account = True
        f = next(f for f in check_raspberry_pi(snap, t=i18n.t).findings
                 if f.key == "raspberry_pi.legacy_account")
        assert f.level is FL.WARN
        assert not f.cmd, (
            "there is no safe one-line remedy: userdel destroys a home "
            "directory and usermod -l renames an account services may name"
        )


class TestNothingIsSaidOnAMachineThatIsNotAPi:

    def test_a_non_pi_produces_no_findings_at_all(self):
        assert check_raspberry_pi(RaspberryPiSnapshot(), t=i18n.t).findings == []

    def test_an_unmounted_boot_partition_is_not_a_clean_one(self):
        snap = RaspberryPiSnapshot(is_pi=True, model="Raspberry Pi 4", arch="aarch64")
        snap.boot_dir = None
        keys = {f.key for f in check_raspberry_pi(snap, t=i18n.t).findings}
        assert "raspberry_pi.boot_not_found" in keys
        assert "raspberry_pi.userconf_absent" not in keys, (
            "saying the partition is clean would be a verdict about files "
            "BOB never saw"
        )

    def test_this_host_is_not_mistaken_for_one(self):
        snap = RaspberryPiSnapshot.from_system()
        assert snap.is_pi is False, "an x86 development machine read as a Pi"


class TestSecureBootNoLongerInventsAFirmwareType:

    def test_the_generic_message_says_only_what_was_established(self):
        data = __import__("json").loads(
            (__import__("pathlib").Path(__file__).resolve().parent.parent
             / "bob" / "locales" / "en.json").read_text(encoding="utf-8"))
        generic = data["secure_boot"]["no_uefi"]
        assert "BIOS" not in generic, (
            "absent UEFI was announced as 'Legacy BIOS detected', which is "
            "false on every board that has neither"
        )
        assert "UEFI" in generic

    def test_a_named_board_gets_its_own_message(self):
        from bob.checks.secure_boot import SecureBootSnapshot, check_secure_boot

        snap = SecureBootSnapshot(state="no_uefi", board="Raspberry Pi 4 Model B")
        f = next(f for f in check_secure_boot(snap, t=i18n.t).findings
                 if f.key == "secure_boot.no_uefi")
        assert "Raspberry Pi 4 Model B" in f.message
        assert f.level is FL.INFO, "a board without UEFI is not a hardening gap"

    def test_an_unnamed_board_still_gets_the_generic_one(self):
        from bob.checks.secure_boot import SecureBootSnapshot, check_secure_boot

        snap = SecureBootSnapshot(state="no_uefi", board="")
        f = next(f for f in check_secure_boot(snap, t=i18n.t).findings
                 if f.key == "secure_boot.no_uefi")
        assert "UEFI" in f.message


class TestNoDefaultPasswordCrackIsAttempted:
    """A deliberate absence, recorded so it is not added by accident."""

    def test_the_check_does_not_import_crypt(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "bob" / "checks" / "raspberry_pi.py").read_text(encoding="utf-8")
        assert "import crypt" not in src, (
            "crypt was removed from the standard library in Python 3.13, which "
            "BOB's own metadata says it supports; a check built on it would "
            "work on three interpreters and silently stop on the fourth"
        )
