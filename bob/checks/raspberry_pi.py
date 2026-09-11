"""What a Raspberry Pi carries that a PC does not, and BOB had never looked.

BOB reasoned entirely about software. On a Pi that leaves two things unsaid.

The first is negative and was already almost right: microcode and Secure Boot
do not exist on this hardware, and the checks degrade rather than deduct — but
Secure Boot announced *"Legacy BIOS detected"*, which is false on a board that
has no BIOS at all. That is fixed in ``secure_boot`` itself.

The second is what this module is for. A Pi boots from a **FAT partition**, and
FAT has no concept of ownership or permission bits: everything on it is exposed
to whatever the mount options grant, and to anyone who takes the card out. The
Raspberry Pi Imager writes provisioning files there — including one that holds
a **password hash** — and they are meant to be consumed and deleted at first
boot. When they are still present, a credential digest is sitting on a
filesystem that cannot protect it.

What this check does *not* do is guess. It reads the files that exist, reports
their mode as measured, and says what is established rather than what is
likely. There is deliberately no attempt to test whether the ``pi`` account
still has the distribution's historical default password: that needs a crypt
implementation, and ``crypt`` was removed from the standard library in Python
3.13, which BOB supports. A check that works on three interpreter versions and
silently stops working on the next is worse than one that states its limit.
"""

from __future__ import annotations

import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t, path_exists
from bob.platform import (
    boot_firmware_dir,
    is_raspberry_pi,
    machine,
    raspberry_pi_model,
)
from bob.scoring import CheckResult
from bob._atomic import read_text_capped

#: `userconf.txt` is `username:crypt-hash`. The prefix identifies the scheme —
#: `$6$` SHA-512, `$5$` SHA-256, `$y$` yescrypt (Bookworm's default).
_USERCONF_RE = re.compile(r"^([A-Za-z0-9._-]{1,32}):(\$[0-9a-z]{1,2}\$\S+)\s*$")

#: Raspberry Pi OS trixie provisions through cloud-init, not userconf.txt:
#: the Imager writes a NoCloud seed to the boot partition and
#: /etc/cloud/cloud.cfg.d/99_raspberry-pi.cfg reads it from there
#: (``seedfrom: file:///boot/firmware``). Measured on a Pi Zero W, the day
#: after flashing: ``user-data`` still held the sudo account's yescrypt hash —
#: byte-identical to its /etc/shadow entry — and ``network-config`` the Wi-Fi
#: PSK, both mode 0755 through the vfat ``fmask=0022`` mount, both readable by
#: every local account. BOB 0.18.0 looked for userconf.txt only and said OK.
_SEED_USER_DATA = "user-data"
_SEED_NETWORK = "network-config"

#: Key lines, matched without a YAML parser — BOB has no dependencies. Values
#: are captured to classify them and are never stored or printed.
_SEED_HASH_RE = re.compile(
    r"^\s*(?:passwd|hashed_passwd)\s*:\s*['\"]?(\$[0-9a-z]{1,2}\$[^'\"\s]+)", re.M)
_SEED_CLEAR_RE = re.compile(r"^\s*plain_text_passwd\s*:\s*\S", re.M)
_SEED_NAME_RE = re.compile(r"^\s*-?\s*name\s*:\s*['\"]?([A-Za-z0-9._-]{1,32})", re.M)
_SEED_WIFI_KEY_RE = re.compile(r"^\s*password\s*:\s*\S", re.M)

#: The provisioning marker that enables sshd on first boot. Empty by design.
_SSH_MARKER = "ssh"

#: The account Raspberry Pi OS shipped with until 2022, and which every guide
#: written before then still tells people to use.
_LEGACY_ACCOUNT = "pi"


@dataclass
class RaspberryPiSnapshot:
    """State of a Raspberry Pi's boot partition and default account.

    Attributes:
        is_pi:              True when the firmware or kernel names this a Pi.
        model:              Board name, e.g. "Raspberry Pi 4 Model B Rev 1.5".
        arch:               ``uname -m``, recorded so the report can say it.
        boot_dir:           The mounted FAT boot partition, or None.
        userconf_user:      Account named in userconf.txt, or "".
        userconf_mode:      Octal mode of userconf.txt as measured, or "".
        ssh_marker:         True when the first-boot ssh marker is still there.
        legacy_account:     True when a `pi` account exists and can log in.
        shadow_readable:    False when /etc/shadow could not be read, so
                            "the account can log in" was not established.
    """

    is_pi:            bool = False
    model:            str = ""
    arch:             str = ""
    boot_dir:         "Path | None" = None
    userconf_user:    str = ""
    userconf_mode:    str = ""
    ssh_marker:       bool = False
    legacy_account:   bool = False
    shadow_readable:  bool = True
    # v0.18.1 — the cloud-init seed. ``seed_password`` is "hash", "clear" or
    # "" ; ``seed_password_current`` is True when the hash is the one the
    # account uses now, False when it is stale, None when /etc/shadow could
    # not be read to tell.
    seed_password:          str = ""
    seed_password_user:     str = ""
    seed_password_current:  "bool | None" = None
    seed_wifi_keys:         int = 0
    seed_modes:             dict = field(default_factory=dict)
    # Files present on the partition that BOB could not read. Present and
    # unread is not "no credential": it blocks the all-clear.
    unreadable:             list = field(default_factory=list)
    _notes:           list = field(default_factory=list)

    @classmethod
    def from_system(
        cls,
        *,
        _boot_dir: "Path | None" = None,
        _passwd: "Path | None" = None,
        _shadow: "Path | None" = None,
        _model: "str | None" = None,
    ) -> "RaspberryPiSnapshot":
        """Collect Raspberry Pi state. Never raises.

        ``_model`` exists so the collection path can be exercised on a machine
        that is not a Pi — which is every machine this suite runs on. Without
        it a test can only assemble a snapshot by hand, and would then be
        checking its own assembly rather than the code that does it.
        """
        snap = cls()
        snap.arch = machine()
        snap.model = _model if _model is not None else raspberry_pi_model()
        snap.is_pi = bool(snap.model) if _model is not None else is_raspberry_pi()
        if not snap.is_pi:
            return snap

        snap.boot_dir = _boot_dir if _boot_dir is not None else boot_firmware_dir()
        if snap.boot_dir is not None:
            userconf = snap.boot_dir / "userconf.txt"
            try:
                text = read_text_capped(userconf, encoding="utf-8", errors="replace")
            except FileNotFoundError:
                text = ""
            except OSError:
                # There and unread is not absent — see ``unreadable``.
                text = ""
                snap.unreadable.append(userconf.name)
            for line in text.splitlines():
                m = _USERCONF_RE.match(line.strip())
                if m:
                    snap.userconf_user = m.group(1)
                    break
            if snap.userconf_user:
                try:
                    snap.userconf_mode = oct(
                        stat.S_IMODE(userconf.stat().st_mode))[2:].rjust(3, "0")
                except OSError:
                    snap.userconf_mode = ""
            snap.ssh_marker = path_exists(snap.boot_dir / _SSH_MARKER)
            _read_seed(snap, snap.boot_dir, _shadow or Path("/etc/shadow"))

        snap.legacy_account, snap.shadow_readable = _legacy_account_state(
            _passwd or Path("/etc/passwd"), _shadow or Path("/etc/shadow"))
        return snap


def _read_text_or_note(snap: RaspberryPiSnapshot, path: Path) -> "str | None":
    """The file's text, None when absent; an unreadable file is recorded."""
    try:
        return read_text_capped(path, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return None
    except OSError:
        snap.unreadable.append(path.name)
        return None


def _mode_of(path: Path) -> str:
    try:
        return oct(stat.S_IMODE(path.stat().st_mode))[2:].rjust(3, "0")
    except OSError:
        return ""


def _read_seed(snap: RaspberryPiSnapshot, boot_dir: Path, shadow: Path) -> None:
    """What the cloud-init seed on the boot partition still discloses."""
    user_data = _read_text_or_note(snap, boot_dir / _SEED_USER_DATA)
    if user_data:
        m = _SEED_HASH_RE.search(user_data)
        if m:
            snap.seed_password = "hash"
            names = _SEED_NAME_RE.findall(user_data[: m.start()])
            snap.seed_password_user = names[-1] if names else ""
            snap.seed_password_current = _is_current_hash(
                shadow, snap.seed_password_user, m.group(1))
        elif _SEED_CLEAR_RE.search(user_data):
            snap.seed_password = "clear"
            names = _SEED_NAME_RE.findall(user_data)
            snap.seed_password_user = names[0] if names else ""
        if snap.seed_password:
            snap.seed_modes[_SEED_USER_DATA] = _mode_of(boot_dir / _SEED_USER_DATA)

    network = _read_text_or_note(snap, boot_dir / _SEED_NETWORK)
    if network:
        snap.seed_wifi_keys = len(_SEED_WIFI_KEY_RE.findall(network))
        if snap.seed_wifi_keys:
            snap.seed_modes[_SEED_NETWORK] = _mode_of(boot_dir / _SEED_NETWORK)


def _is_current_hash(shadow: Path, user: str, digest: str) -> "bool | None":
    """Whether *digest* is *user*'s password hash now. None when not established."""
    if not user:
        return None
    try:
        lines = read_text_capped(shadow, encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        parts = line.split(":")
        if parts and parts[0] == user and len(parts) > 1:
            return parts[1] == digest
    return None


def _legacy_account_state(passwd: Path, shadow: Path) -> "tuple[bool, bool]":
    """``(can log in, shadow was readable)`` for the historical `pi` account.

    "Exists" is not the finding — a `pi` account with a locked password is a
    leftover, not a way in. The password field decides: `!` and `*` mean no
    password will ever match, which is how a disabled account is spelled.
    """
    try:
        entries = read_text_capped(passwd, encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False, True
    shells = {}
    for line in entries:
        parts = line.split(":")
        if len(parts) >= 7:
            shells[parts[0]] = parts[6]
    if _LEGACY_ACCOUNT not in shells:
        return False, True
    if shells[_LEGACY_ACCOUNT] in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
        return False, True

    try:
        shadow_lines = read_text_capped(shadow, encoding="utf-8", errors="replace").splitlines()
    except OSError:
        # Unreadable is not "no password": say the answer was not established.
        return False, False
    for line in shadow_lines:
        parts = line.split(":")
        if parts and parts[0] == _LEGACY_ACCOUNT:
            secret = parts[1] if len(parts) > 1 else ""
            return bool(secret) and not secret.startswith(("!", "*")), True
    return False, True


def check_raspberry_pi(snapshot: RaspberryPiSnapshot,
                       t: TranslationFunc | None = None) -> CheckResult:
    """Report what the boot partition and the legacy account expose.

    Scoring:
      - userconf.txt still present:   WARN, −1  (a password hash on a
        filesystem with no permissions to protect it)
      - cloud-init user-data password: WARN, −1  (the same, for trixie)
      - cloud-init network-config key: WARN, −1  (the Wi-Fi PSK)
      - a provisioning file unreadable: INFO — blocks the all-clear
      - legacy `pi` account can log in: WARN, −1 on server, INFO elsewhere
      - ssh first-boot marker present: INFO
      - shadow unreadable:            INFO, no deduction — not established
    """
    _t = t or _identity_t
    result = CheckResult()

    if not snapshot.is_pi:
        return result

    result.info(
        message=_t("raspberry_pi.board", model=snapshot.model, arch=snapshot.arch),
        key="raspberry_pi.board",
    )

    if snapshot.boot_dir is None:
        # The board is a Pi but its FAT partition is not mounted where BOB
        # looks. Nothing below was established, and saying "clean" would be a
        # verdict about files it never saw.
        result.info(
            message=_t("raspberry_pi.boot_not_found"),
            detail=_t("raspberry_pi.boot_not_found_detail"),
            key="raspberry_pi.boot_not_found",
        )
        return result

    if snapshot.userconf_user:
        result.warn_with_deduction(
            key="raspberry_pi.userconf_present",
            message=_t("raspberry_pi.userconf_present",
                       user=snapshot.userconf_user,
                       path=str(snapshot.boot_dir / "userconf.txt")),
            reason=_t("raspberry_pi.userconf_present_reason"),
            points=1,
            detail=_t("raspberry_pi.userconf_present_detail",
                      mode=snapshot.userconf_mode or "?",
                      path=str(snapshot.boot_dir / "userconf.txt")),
            cmd=f"sudo rm {snapshot.boot_dir / 'userconf.txt'}",
            nature="action",
        )

    # v0.18.1 — the cloud-init seed Raspberry Pi OS trixie provisions from.
    # The remediation removes only the secret lines and leaves meta-data
    # alone: measured on a Pi Zero W, a reboot afterwards kept Wi-Fi,
    # /etc/shadow, netplan and the hostname unchanged, because cloud-init
    # sees the same instance-id and skips every once-per-instance module.
    # Deleting the seed files instead would hand cloud-init the `None`
    # datasource — a new instance — and it would re-run them.
    user_data = snapshot.boot_dir / _SEED_USER_DATA
    if snapshot.seed_password:
        if snapshot.seed_password_current is True:
            currency = _t("raspberry_pi.seed_password_current")
        elif snapshot.seed_password_current is False:
            currency = _t("raspberry_pi.seed_password_stale")
        else:
            currency = _t("raspberry_pi.seed_password_unknown")
        result.warn_with_deduction(
            key="raspberry_pi.seed_password",
            # Literal keys, not "seed_password_" + kind: the orphan-key guard
            # finds references by reading the source, and a concatenation is
            # a message nothing appears to use.
            message=_t("raspberry_pi.seed_password_clear"
                       if snapshot.seed_password == "clear"
                       else "raspberry_pi.seed_password_hash",
                       user=snapshot.seed_password_user or "?",
                       path=str(user_data)),
            reason=_t("raspberry_pi.seed_password_reason"),
            points=1,
            detail=_t("raspberry_pi.seed_password_detail",
                      mode=snapshot.seed_modes.get(_SEED_USER_DATA) or "?",
                      currency=currency),
            cmd=("sudo sed -i -E "
                 "'/^[[:space:]]*(passwd|hashed_passwd|plain_text_passwd):/d' "
                 f"{user_data}"),
            nature="action",
        )
    if snapshot.seed_wifi_keys:
        network = snapshot.boot_dir / _SEED_NETWORK
        result.warn_with_deduction(
            key="raspberry_pi.seed_wifi_key",
            message=_t("raspberry_pi.seed_wifi_key",
                       count=snapshot.seed_wifi_keys, path=str(network)),
            reason=_t("raspberry_pi.seed_wifi_key_reason"),
            points=1,
            detail=_t("raspberry_pi.seed_wifi_key_detail",
                      mode=snapshot.seed_modes.get(_SEED_NETWORK) or "?"),
            cmd=f"sudo sed -i -E '/^[[:space:]]*password:/d' {network}",
            nature="action",
        )

    if snapshot.unreadable:
        # Present and unread: the all-clear below would be a verdict about
        # contents BOB never saw.
        result.info(
            message=_t("raspberry_pi.seed_unreadable",
                       files=", ".join(snapshot.unreadable),
                       path=str(snapshot.boot_dir)),
            key="raspberry_pi.seed_unreadable",
        )
    elif not (snapshot.userconf_user or snapshot.seed_password
              or snapshot.seed_wifi_keys):
        result.ok(message=_t("raspberry_pi.userconf_absent"),
                  key="raspberry_pi.userconf_absent")

    if snapshot.ssh_marker:
        result.info(
            message=_t("raspberry_pi.ssh_marker",
                       path=str(snapshot.boot_dir / _SSH_MARKER)),
            detail=_t("raspberry_pi.ssh_marker_detail"),
            cmd=f"sudo rm {snapshot.boot_dir / _SSH_MARKER}",
            key="raspberry_pi.ssh_marker",
        )

    if not snapshot.shadow_readable:
        result.info(
            message=_t("raspberry_pi.account_unknown"),
            detail=_t("raspberry_pi.account_unknown_detail", user=_LEGACY_ACCOUNT),
            key="raspberry_pi.account_unknown",
        )
    elif snapshot.legacy_account:
        result.warn_with_deduction(
            key="raspberry_pi.legacy_account",
            message=_t("raspberry_pi.legacy_account", user=_LEGACY_ACCOUNT),
            reason=_t("raspberry_pi.legacy_account_reason"),
            points=1,
            detail=_t("raspberry_pi.legacy_account_detail", user=_LEGACY_ACCOUNT),
            nature="improvement",
        )

    return result
