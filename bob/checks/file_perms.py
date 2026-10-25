"""
Sensitive file permissions and sudoers audit for BOB.

Checks:
  - Permissions on critical system files (/etc/passwd, /etc/shadow, etc.)
  - SSH host private key permissions (/etc/ssh/ssh_host_*_key)
  - Sudoers files for NOPASSWD:ALL entries

Usage:
    from bob.checks.file_perms import FilePermsSnapshot, check_file_perms

    snapshot = FilePermsSnapshot.from_system()
    result   = check_file_perms(snapshot)
"""

from __future__ import annotations

import os
import re
import shlex
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple, Tuple

from bob.checks._run import TranslationFunc, _identity_t, _run, join_continuations, path_exists
from bob.scoring import CheckResult
from bob._atomic import read_text_capped
from bob._fs import strict_is_dir, strict_is_file

# ---------------------------------------------------------------------------
# Sensitive files specification
# ---------------------------------------------------------------------------

class _FileSpec(NamedTuple):
    path:     str
    max_mode: int   # maximum allowed permissions (low 9 octal bits)
    key:      str   # short tag used to build unique finding keys

#: Module-level so tests can point them at a mode-000 directory and prove a
#: denial reads as "not established", not "clean".
_ETC_SSH = Path("/etc/ssh")
_SUDOERS = Path("/etc/sudoers")
_SUDOERS_D = Path("/etc/sudoers.d")
# doas is Alpine's (and OpenBSD's) privilege-escalation tool in place of sudo;
# `permit nopass` in /etc/doas.conf is its NOPASSWD equivalent. A sudo-only audit
# is blind to it on a doas-based host.
_DOAS_CONF = Path("/etc/doas.conf")
# openSUSE Leap 16+ vendor layout: the main sudoers lives under /usr/etc, with
# /etc/sudoers as the optional override, and its @includedir pulls in *both*
# /etc/sudoers.d and /usr/etc/sudoers.d. Reading only the /etc paths missed a
# NOPASSWD rule set in the vendor tree.
_SUDOERS_VENDOR = Path("/usr/etc/sudoers")
_SUDOERS_D_VENDOR = Path("/usr/etc/sudoers.d")

_SENSITIVE_FILES: tuple[_FileSpec, ...] = (
    _FileSpec("/etc/passwd",  0o644, "passwd"),
    _FileSpec("/etc/shadow",  0o640, "shadow"),
    _FileSpec("/etc/gshadow", 0o640, "gshadow"),
    _FileSpec("/etc/group",   0o644, "group"),
    _FileSpec("/etc/sudoers", 0o440, "sudoers_file"),
)

# ---------------------------------------------------------------------------
# Snapshot dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FileInfo:
    """Collected information for a single sensitive file."""
    path:     str
    exists:   bool
    mode:     int   # actual permissions (low 9 bits), 0 if absent
    max_mode: int   # expected maximum
    key:      str   # short tag from _FileSpec

@dataclass
class FilePermsSnapshot:
    """
    Raw snapshot of sensitive file permissions and sudoers state.

    All I/O happens in from_system(). check_file_perms() is pure logic.
    """
    sensitive_files:           list[FileInfo]            = field(default_factory=list)
    ssh_host_key_issues:       list[Tuple[str, int]]     = field(default_factory=list)
    sudoers_nopasswd_all:      list[str]                 = field(default_factory=list)
    sudoers_nopasswd_specific: list[str]                 = field(default_factory=list)
    #: v0.27.0 — (rule, command, why, what) for each NOPASSWD / permit-nopass
    #: command that is root anyway: "escape", "editor", "arguments" or "writable".
    nopasswd_root_equivalent:  list[Tuple[str, str, str, str]] = field(default_factory=list)
    # Names of groups (%group) that a NOPASSWD:ALL rule grants to but which
    # currently have no members — the grant is real but latent (add a user and
    # it becomes live root). Kali ships %kali-trusted this way by default.
    sudoers_nopasswd_empty_groups: list[str]             = field(default_factory=list)
    sudoers_readable:          bool                      = True
    ssh_host_keys_readable:    bool                      = True
    # doas (Alpine/OpenBSD): `permit nopass` grants. Full (no `cmd` clause) is the
    # NOPASSWD:ALL equivalent; a `cmd`-scoped one is the specific-command case.
    doas_nopass_all:           list[str]                 = field(default_factory=list)
    doas_nopass_specific:      list[str]                 = field(default_factory=list)
    # False when /etc/doas.conf existed but could not be read (a denial, not an
    # absence — same distinction as sudoers_readable).
    doas_readable:             bool                      = True

    @classmethod
    def from_system(cls) -> "FilePermsSnapshot":
        """
        Collect sensitive file permissions and sudoers entries from the live system.

        Returns:
            Populated FilePermsSnapshot. Never raises — errors reflected as absent/default.
        """
        snap = cls()

        # 1. Sensitive system files
        for spec in _SENSITIVE_FILES:
            p = Path(spec.path)
            if path_exists(p):
                try:
                    mode = stat.S_IMODE(p.stat().st_mode)
                except OSError:
                    # Cannot read permissions — assume worst case to avoid hiding issues.
                    mode = 0o777
                snap.sensitive_files.append(
                    FileInfo(path=spec.path, exists=True,
                             mode=mode, max_mode=spec.max_mode, key=spec.key)
                )
            else:
                snap.sensitive_files.append(
                    FileInfo(path=spec.path, exists=False,
                             mode=0, max_mode=spec.max_mode, key=spec.key)
                )

        # 2. SSH host private keys under /etc/ssh/
        ssh_dir = _ETC_SSH
        try:
            key_paths = sorted(ssh_dir.glob("ssh_host_*_key")) if strict_is_dir(ssh_dir) else []
        except OSError:
            # /etc/ssh present but BOB was refused entry — say the host-key
            # permissions were not established, never imply they are fine. On
            # 3.14 a bare is_dir() returns False on the denial; on <=3.13 the
            # unguarded glob() raised.
            key_paths = []
            snap.ssh_host_keys_readable = False
        for key_path in key_paths:
            if key_path.suffix == ".pub":
                continue
            try:
                mode = stat.S_IMODE(key_path.stat().st_mode)
                if mode != 0o600:
                    snap.ssh_host_key_issues.append((str(key_path), mode))
            except OSError:
                pass

        # 3. Sudoers NOPASSWD entries
        nopasswd_all, nopasswd_specific, sudoers_readable = _collect_nopasswd_entries()
        snap.sudoers_nopasswd_all      = nopasswd_all
        snap.sudoers_nopasswd_specific = nopasswd_specific
        snap.sudoers_readable          = sudoers_readable
        # Flag %group NOPASSWD:ALL grants whose group currently has no members:
        # the grant is real but latent, and saying so is more truthful than an
        # unqualified alarm about a rule nobody can currently use.
        empty: list[str] = []
        for _line in nopasswd_all:
            g = _nopasswd_group(_line)
            if g and _group_has_no_members(g):
                empty.append(g)
        snap.sudoers_nopasswd_empty_groups = empty

        # 4. doas `permit nopass` entries (Alpine/OpenBSD privilege tool)
        doas_all, doas_specific, doas_readable = _collect_doas_nopass()
        snap.doas_nopass_all      = doas_all
        snap.doas_nopass_specific = doas_specific
        snap.doas_readable        = doas_readable

        # v0.27.0 — which of the scoped grants are root anyway.
        texts = []
        for f in _sudoers_files()[0]:
            try:
                texts.append(read_text_capped(f, encoding="utf-8", errors="replace"))
            except OSError:
                pass
        aliases = _cmnd_aliases(texts)
        systemd = _systemd_version()
        noexec_lib = _sudo_noexec_library() if snap.sudoers_nopasswd_specific else None
        env_passes = _sudo_env_passes_pager_secure(texts)
        runas_overrides = _runas_default_overrides(texts)
        for line in snap.sudoers_nopasswd_specific:
            # With no Runas_Spec the rule runs as runas_default, root unless a
            # Defaults says otherwise (measured: daemon, euid 1).
            if not _has_runas_spec(line) and _runas_default_may_apply(line.split()[0], runas_overrides):
                continue
            for command, noexec, setenv in _nopasswd_grants(line, aliases) or []:
                # NOEXEC holds only where it is established: sudo's library
                # present, and a dynamically linked binary it can load into.
                noexec = noexec and noexec_lib is not None and _dynamically_linked(command.split()[0])
                found = _root_equivalent(command, noexec=noexec, systemd=systemd,
                                         pager_env=setenv or env_passes)
                if found:
                    snap.nopasswd_root_equivalent.append((line, command, found[0], found[1]))
        for line in snap.doas_nopass_specific:
            command = _doas_command(line)
            # systemd's secure pager detects sudo, not doas: measured on Debian 13
            # (systemd 257, opendoas), journalctl under doas then `:e /etc/shadow`
            # showed root's hash, keepenv or not, the variable set or not.
            found = _root_equivalent(command, systemd=systemd,
                                     pager_env=True) if command else None
            if found:
                snap.nopasswd_root_equivalent.append((line, command, found[0], found[1]))

        return snap

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# `#` opens a comment in sudoers *anywhere* on a line, not only at column 0 —
# `NOPASSWD: ALL # temporary` and even `NOPASSWD: ALL#tmp` both grant
# unrestricted sudo. The one exception is `#` immediately followed by a digit,
# which sudo lexes as a numeric id: `#1000 ALL=(ALL) NOPASSWD: ALL` is a user
# spec for uid 1000, and `ALL=(#1000)` is a runas uid. Both must survive.
_SUDOERS_COMMENT_RE = re.compile(r"#(?!\d)")

def _strip_sudoers_comment(line: str) -> str:
    """Return `line` with any trailing sudoers comment removed."""
    m = _SUDOERS_COMMENT_RE.search(line)
    return (line[:m.start()] if m else line).rstrip()

# A sudoers rule may be wrapped anywhere, including between the `NOPASSWD:` tag
# and the command it applies to, so a line-at-a-time reader sees neither half as
# unrestricted sudo. Shared with the PAM parser, which has the same problem.
_join_continuations = join_continuations


def _collect_nopasswd_entries() -> "tuple[list[str], list[str], bool]":
    """
    Parse /etc/sudoers and /etc/sudoers.d/* for NOPASSWD entries.

    Returns:
        (nopasswd_all, nopasswd_specific, readable) where:
        - nopasswd_all      — lines granting unrestricted passwordless sudo
        - nopasswd_specific — lines granting passwordless access to specific commands only
        - readable          — False when a sudoers file existed but could not be
                              read. Skipping it silently made "no NOPASSWD rule
                              found" indistinguishable from "sudoers was never
                              opened", and the check answers that with an
                              explicit all-clear.
    """
    nopasswd_all:      list[str] = []
    nopasswd_specific: list[str] = []
    paths, readable = _sudoers_files()
    for p in paths:
        try:
            text = read_text_capped(p, encoding="utf-8", errors="replace")
        except OSError:
            readable = False
            continue
        for line in _join_continuations(text.splitlines()):
            # Strip the comment first: it both reveals rules hidden behind a
            # trailing comment and stops a rule that merely *mentions*
            # NOPASSWD in its comment from being counted as one.
            stripped = _strip_sudoers_comment(line).strip()
            if not stripped:
                continue
            if "NOPASSWD" not in stripped.upper():
                continue
            if _is_nopasswd_all(stripped):
                nopasswd_all.append(stripped)
            else:
                nopasswd_specific.append(stripped)

    return nopasswd_all, nopasswd_specific, readable


def _sudoers_files() -> "tuple[list[Path], bool]":
    """The sudoers files sudo reads, and False when one of their directories
    could not be listed (v0.27.0: shared by the rule and alias readers)."""
    paths: list[Path] = []

    # Main sudoers: /etc wins; fall back to the /usr/etc vendor file (openSUSE)
    # when /etc/sudoers is absent, mirroring what sudo itself reads there.
    if path_exists(_SUDOERS):
        paths.append(_SUDOERS)
    elif path_exists(_SUDOERS_VENDOR):
        paths.append(_SUDOERS_VENDOR)

    readable = True
    # Both drop-in dirs: the vendor sudoers `@includedir`s /etc/sudoers.d *and*
    # /usr/etc/sudoers.d. A denial on either is "incomplete", not "clean".
    for sudoers_d in (_SUDOERS_D, _SUDOERS_D_VENDOR):
        try:
            if strict_is_dir(sudoers_d):
                for f in sorted(sudoers_d.iterdir()):
                    if strict_is_file(f) and not f.name.startswith(".") and not f.name.endswith("~"):
                        paths.append(f)
        except OSError:
            # The dir is present but BOB was refused entry — a denial, not an
            # absence. Record the sudoers check as incomplete rather than
            # concluding there are no drop-in NOPASSWD rules. On 3.14 a bare
            # is_dir() returns False on the denial and would hide this; on <=3.13
            # the unguarded iterdir() raised and crashed the whole check.
            readable = False
    return paths, readable

# A sudoers rule's first field is the user/group spec; a group is written
# `%name` (or `%#gid`). Only the leading spec matters — a later `%group` inside
# a runas or command list is not who the rule is granted to.
_NOPASSWD_GROUP_RE = re.compile(r"^%([^\s,#]+)")

def _nopasswd_group(line: str) -> str | None:
    """Return the group name a NOPASSWD line is granted to, or None if it is
    granted to a user (not a ``%group``)."""
    m = _NOPASSWD_GROUP_RE.match(line.strip())
    return m.group(1) if m else None

def _group_has_no_members(name: str) -> bool:
    """True when the named group has no members at all — neither listed
    (secondary) members nor any user carrying it as primary GID. False when it
    has a member or cannot be resolved (never claim "empty" on uncertainty)."""
    import grp
    import pwd
    try:
        g = grp.getgrnam(name)
    except (KeyError, OSError):
        return False
    if g.gr_mem:
        return False
    try:
        return not any(u.pw_gid == g.gr_gid for u in pwd.getpwall())
    except OSError:
        return False

def _is_nopasswd_all(line: str) -> bool:
    """
    Return True if this sudoers line grants unrestricted passwordless sudo.

    Matches exactly ``NOPASSWD: ALL`` (case-insensitive, colon/space optional)
    with no further command tokens. This is deliberately strict: a line like
    ``NOPASSWD: ALL /bin/sh`` is treated as specific (the command field is not
    purely ALL) and will not trigger an unrestricted-sudo alert.

    Recognises patterns such as:
        john  ALL=(ALL)       NOPASSWD:ALL
        %sudo ALL=(ALL:ALL)   NOPASSWD: ALL
    A line like ``john ALL=(ALL) NOPASSWD:/usr/bin/apt`` returns False.
    """
    upper = line.upper()
    if "NOPASSWD" not in upper:
        return False
    # Extract the command portion after "NOPASSWD", strip leading ": \t"
    after = upper.split("NOPASSWD", 1)[1]
    after = after.lstrip(": \t")
    # Only flag when the command field is exactly ALL — nothing more, nothing less
    return after.strip() == "ALL"

# ---------------------------------------------------------------------------
# v0.27.0 — a NOPASSWD rule for a command that is root anyway
# ---------------------------------------------------------------------------
# Measured on a Mint host: `so6 ALL=(root) NOPASSWD: /home/so6/.local/bin/bob,
# /usr/bin/python3` — root without a password for any process of that user —
# was an INFO, "specific commands, often intentional". A rule is root-equivalent
# when the command gives a shell or runs code it is handed (GTFOBins' sudo
# entries), or when an account other than root can change what it runs.

#: Run code or a shell from their arguments: root-equivalent when the rule
#: leaves the arguments free (none written) or opens them with a wildcard.
_ROOT_BY_ARGUMENTS = frozenset({
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "ash", "busybox",
    "python", "python2", "python3", "perl", "ruby", "php", "lua", "luajit", "node", "nodejs",
    "tclsh", "wish", "expect", "irb", "gdb", "strace", "ltrace",
    "env", "find", "awk", "gawk", "mawk", "nawk", "sed", "xargs", "nice", "timeout", "stdbuf",
    "taskset", "ionice", "script", "socat", "tar", "zip", "rsync", "cp", "mv", "install", "dd",
    "tee", "chmod", "chown", "ln", "make", "git", "apt", "apt-get", "dpkg", "pip", "pip3",
    "docker", "podman", "mount", "systemctl", "ssh", "scp", "sftp", "nmap", "su", "sudo",
    "crontab", "openssl",
})
#: Pagers and editors: a shell escape (`!sh`, `:!sh`) whatever file the rule
#: names, so root-equivalent even with its arguments written out.
_ROOT_BY_ESCAPE = frozenset({"less", "more", "most", "man", "journalctl"})
#: Editors: they write any file as root, whatever file the rule names — NOEXEC
#: or not (measured on Debian 13, sudo 1.9.16p2: under NOEXEC, vi's `:!id` ran
#: nothing and `:e /root/x` then `:w` wrote the file as root).
_ROOT_BY_EDITOR = frozenset({"vi", "vim", "nvim", "view", "vimdiff", "ex", "nano", "pico", "emacs", "ed"})
#: Commands whose only power is to exec another: under sudo's NOEXEC they run
#: nothing (measured on Debian 13: env, xargs, nice, timeout, stdbuf, taskset,
#: ionice, then `sh -c id` — nothing ran; bash and find still wrote as root).
_EXEC_ONLY = frozenset({"env", "xargs", "nice", "timeout", "stdbuf", "taskset", "ionice"})
#: systemd 247 (its NEWS) runs less in secure mode under sudo: no shell escape
#: from journalctl's pager. Measured on Debian 13 (systemd 257): `!` answered
#: "Command not available"; root in its own session got its shell.
_SYSTEMD_SECURE_PAGER = 247
#: Tools that write a file given on the command line: with free arguments they
#: already count (_ROOT_BY_ARGUMENTS); with a fixed argument naming a protected
#: path they are root anyway too. Measured on Debian 13 (24 October 2026):
#: `sudo -n /usr/bin/tee /etc/sudoers.d/pwn` and `sudo -n /usr/bin/cp x
#: /etc/sudoers.d/y` each wrote a sudoers file owned by root.
_FILE_WRITERS = frozenset({"cp", "mv", "dd", "tee", "install", "ln", "chmod", "chown"})
#: Editors of a policy/account database by design, declared with or without a
#: path: visudo (sudoers), vipw (passwd/shadow), vigr (group). sudoedit / sudo
#: -e edit the file the rule names. sudo requires sudoedit be written with no
#: path, so these are matched by basename before the absolute-path guard.
_ALWAYS_EDIT_ROOT = {"visudo": "/etc/sudoers", "vipw": "/etc/passwd", "vigr": "/etc/group"}
#: Writing under any of these is privilege escalation: a sudoers drop-in, a
#: cron job, a systemd unit, the account databases, root's home (authorized_keys
#: handled separately), PAM, the dynamic linker, a shell profile run as root.
#: A finite list — other sensitive paths are a documented limit.
_SENSITIVE_WRITE_PATHS = (
    "/etc/sudoers", "/etc/cron", "/var/spool/cron", "/etc/systemd/", "/usr/lib/systemd/",
    "/lib/systemd/", "/etc/init.d/", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/root/", "/etc/pam.d/", "/etc/ld.so.conf", "/etc/ld.so.preload",
    "/etc/profile", "/etc/bash.bashrc", "/etc/environment",
)


def _is_sensitive_write_target(arg: str) -> bool:
    """Whether *arg* names a path writing to which escalates (v0.27.0, after
    the fifth review). Handles dd's ``of=/path`` and an authorized_keys file
    anywhere."""
    for a in (arg, arg.split("=", 1)[-1]):
        if "authorized_keys" in a:
            return True
        if any(a == p.rstrip("/") or a.startswith(p) for p in _SENSITIVE_WRITE_PATHS):
            return True
    return False
#: Pagers that open another file on request: under NOEXEC their shell is gone,
#: not that. Measured on Debian 13 after the review (24 October 2026): under
#: NOEXEC, `less /etc/services` then `:e /etc/shadow` showed root's hash, which
#: the account itself could not read; `more` and `man man` showed nothing, and
#: journalctl's secure pager answered "not available"; most's Ctrl-X Ctrl-F
#: ("Read a file from disk") then `shadow` showed root's hash too.
_READS_UNDER_NOEXEC = frozenset({"less", "most"})
_PYTHON_VERSIONED = re.compile(r"^(python|pip)[23](\.\d+)?$")
_SUDO_TAG = re.compile(r"^((?:[A-Z_]+:\s*)+)(.*)$")


def _cmnd_aliases(texts: "list[str]") -> "dict[str, list[str]]":
    """``Cmnd_Alias NAME = /a, /b args`` definitions, in the files sudo reads."""
    aliases: "dict[str, list[str]]" = {}
    for text in texts:
        for line in _join_continuations(text.splitlines()):
            line = _strip_sudoers_comment(line).strip()
            if not line.startswith("Cmnd_Alias"):
                continue
            for part in line[len("Cmnd_Alias"):].split(":"):
                name, eq, body = part.partition("=")
                if eq:
                    aliases[name.strip()] = [c.strip() for c in re.split(r"(?<!\\),", body) if c.strip()]
    return aliases


def _nopasswd_commands(line: str, aliases: "dict[str, list[str]]") -> "list[str] | None":
    """The commands a sudoers rule grants without a password, aliases
    resolved — or None when the rule runs as someone other than root, or BOB
    cannot read it. Tags carry over from one command to the next, as in sudo."""
    grants = _nopasswd_grants(line, aliases)
    return None if grants is None else [command for command, *_tags in grants]


def _nopasswd_grants(line: str, aliases: "dict[str, list[str]]") -> "list[tuple[str, bool, bool]] | None":
    """(command, under NOEXEC, under SETENV) for each command of
    :func:`_nopasswd_commands`. NOEXEC / EXEC and SETENV / NOSETENV carry over
    like NOPASSWD / PASSWD (v0.27.0)."""
    m = re.match(r"^\S+\s+\S+\s*=\s*(\([^)]*\))?\s*(.*)$", line)
    if not m:
        return None
    runas, rest = m.group(1), m.group(2)
    if runas:
        users = runas.strip("()").split(":")[0]
        names = {u.strip() for u in users.split(",") if u.strip()}
        if names and not names & {"ALL", "root", "#0"}:
            return None
    commands, nopasswd, noexec, setenv = [], False, False, False
    for entry in re.split(r"(?<!\\),", rest):
        entry = entry.strip()
        tags = _SUDO_TAG.match(entry)
        if tags:
            for tag in re.findall(r"[A-Z_]+", tags.group(1)):
                if tag == "NOPASSWD":
                    nopasswd = True
                elif tag == "PASSWD":
                    nopasswd = False
                elif tag in ("NOEXEC", "EXEC"):
                    noexec = tag == "NOEXEC"
                elif tag in ("SETENV", "NOSETENV"):
                    setenv = tag == "SETENV"
            entry = tags.group(2).strip()
        if not nopasswd or not entry:
            continue
        expanded = aliases.get(entry, [entry]) if re.fullmatch(r"[A-Z][A-Z0-9_]*", entry) else [entry]
        commands.extend((command, noexec, setenv) for command in expanded)
    return commands


def _writable_by_another(path: str) -> "str | None":
    """Who other than root can change *path* or the directory holding it — the
    owner, a group or everyone — or None. Unstatable: None (no claim)."""
    import pwd
    real = os.path.realpath(path)
    for target in (real, os.path.dirname(real)):
        try:
            st = os.stat(target)
        except OSError:
            return None
        if st.st_uid != 0:
            try:
                who = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                who = str(st.st_uid)
            return f"{target} (owner {who})"
        if st.st_mode & 0o002:
            return f"{target} (writable by everyone)"
        if st.st_mode & 0o020 and st.st_gid != 0:
            return f"{target} (writable by group {st.st_gid})"
    return None


def _sudo_noexec_library() -> "str | None":
    """The sudo_noexec.so sudo uses, when it exists (v0.27.0): ``Path noexec``
    in /etc/sudo.conf, else the libexec directory sudo was built with
    (``sudo -V``). Measured: Debian 13 (--prefix=/usr, no --libexecdir) has
    /usr/libexec/sudo/sudo_noexec.so; Alpine 3.24 (--libexecdir=/usr/lib)
    /usr/lib/sudo/sudo_noexec.so. None: NOEXEC is not established."""
    try:
        conf = read_text_capped(Path("/etc/sudo.conf"), encoding="utf-8", errors="replace")
    except OSError:
        conf = ""
    m = re.search(r"^\s*Path\s+noexec\s+(\S+)", conf, re.MULTILINE)
    if m:
        path = m.group(1)
    else:
        opts = re.search(r"^Configure options:(.*)$", _run("sudo", "-V"), re.MULTILINE)
        if not opts:
            return None
        libexec = re.search(r"--libexecdir=(\S+)", opts.group(1))
        prefix = re.search(r"--prefix=(\S+)", opts.group(1))
        base = libexec.group(1) if libexec else f"{prefix.group(1) if prefix else '/usr/local'}/libexec"
        path = f"{base}/sudo/sudo_noexec.so"
    return path if strict_is_file(Path(path)) else None


def _dynamically_linked(path: str) -> bool:
    """Whether *path* is an ELF executable with an interpreter (PT_INTERP):
    one sudo's noexec library can be loaded into. Measured on Alpine 3.24,
    sudo 1.9.17p2: under NOEXEC, a static busybox ran `sh -c id` as root,
    while the dynamic env ran nothing. Unreadable, a script or static: False."""
    import struct
    try:
        with open(os.path.realpath(path), "rb") as fh:
            head = fh.read(64)
            if len(head) < 52 or head[:4] != b"\x7fELF":
                return False
            wide, order = head[4] == 2, "<" if head[5] == 1 else ">"
            if wide:
                phoff, = struct.unpack_from(order + "Q", head, 32)
                phentsize, phnum = struct.unpack_from(order + "HH", head, 54)
            else:
                phoff, = struct.unpack_from(order + "I", head, 28)
                phentsize, phnum = struct.unpack_from(order + "HH", head, 42)
            fh.seek(phoff)
            table = fh.read(phentsize * min(phnum, 256))
    except (OSError, struct.error):
        return False
    for i in range(0, len(table) - 3, phentsize or 1):
        if struct.unpack_from(order + "I", table, i)[0] == 3:      # PT_INTERP
            return True
    return False


def _runas_default_overrides(texts: "list[str]") -> "list[tuple[str, str]]":
    """(scope, account) for each Defaults line setting runas_default to an
    account other than root (v0.27.0, after the third review). Measured on
    Debian 13: with `Defaults runas_default=daemon`, or `Defaults:bobesc
    runas_default=daemon`, a rule with no Runas_Spec ran python3 as euid 1, and
    `-u root` asked for the password; without it, euid 0."""
    out = []
    for text in texts:
        for line in _join_continuations(text.splitlines()):
            line = _strip_sudoers_comment(line).strip()
            m = re.match(r"^Defaults(\S*)\s+(.*)$", line)
            if not m:
                continue
            v = re.search(r"\brunas_default\s*=\s*\"?([^\",\s]+)", m.group(2))
            if v and v.group(1) not in ("root", "#0"):
                out.append((m.group(1), v.group(1)))
    return out


def _runas_default_may_apply(user: str, overrides: "list[tuple[str, str]]") -> bool:
    """Whether a runas_default other than root may govern *user*'s rules: a
    global Defaults, a Defaults:<user>, or a scope BOB does not resolve (a
    group, an alias, a host, a command) — counted as applying, so that no −2
    rests on an account BOB did not establish."""
    for scope, _account in overrides:
        if not scope:
            return True
        if not scope.startswith(":"):
            return True
        names = {n.strip() for n in scope[1:].split(",") if n.strip()}
        if user in names or any(n[0] in "%+" or n.isupper() for n in names):
            return True
    return False


def _has_runas_spec(line: str) -> bool:
    """Whether a sudoers rule names who it runs as: ``= (…)``."""
    return bool(re.match(r"^\S+\s+\S+\s*=\s*\(", line))


def _sudo_env_passes_pager_secure(texts: "list[str]") -> bool:
    """Whether sudo lets the caller hand SYSTEMD_PAGERSECURE through: a
    Defaults line with ``!env_reset``, or an env_keep naming the variable.
    Measured on Debian 13 (systemd 257) after the review: with SETENV, or with
    env_keep += "SYSTEMD_PAGERSECURE", `SYSTEMD_PAGERSECURE=0` turned the
    secure pager off and journalctl's `:e /etc/shadow` showed root's hash.
    Read for every account (a per-user Defaults counts for all)."""
    for text in texts:
        for line in _join_continuations(text.splitlines()):
            line = _strip_sudoers_comment(line).strip()
            if not line.startswith("Defaults"):
                continue
            if re.search(r"!\s*env_reset\b", line):
                return True
            if re.search(r"\benv_keep\b", line) and "SYSTEMD_PAGERSECURE" in line:
                return True
    return False


def _systemd_version() -> "int | None":
    """systemd's version number (``systemctl --version``), or None."""
    m = re.match(r"systemd (\d+)", _run("systemctl", "--version"))
    return int(m.group(1)) if m else None


def _root_equivalent(command: str, noexec: bool = False,
                     systemd: "int | None" = None, pager_env: bool = False) -> "tuple[str, str] | None":
    """Why *command*, run as root without a password, is root anyway:
    ("escape" | "reads" | "editor" | "arguments" | "writes" | "writable", what)
    — or None.
    *noexec*: the rule carries sudo's NOEXEC tag. *systemd*: its version,
    which decides whether journalctl's pager keeps its shell escape.
    *pager_env*: the caller can hand SYSTEMD_PAGERSECURE through (SETENV,
    env_keep, !env_reset, doas keepenv) — the secure pager then holds nothing."""
    fields = command.split()
    if fields == ["ALL"]:
        return "arguments", "ALL"      # ALL among other commands: every command
    if not fields:
        return None
    # v0.27.0, fifth review — matched by basename, before the absolute-path
    # guard: sudo requires sudoedit be written with no path, and visudo / vipw
    # / vigr are often written bare. visudo/vipw/vigr edit the policy or
    # account database whatever the arguments; sudoedit / sudo -e edit the file
    # the rule names, root-equivalent when that file is a sensitive target (or
    # left free). Measured on Debian 13: a sudoedit rule on /etc/sudoers.d
    # parsed and granted the edit.
    first = fields[1:] if os.path.basename(fields[0]) == "sudo" else fields
    editor = os.path.basename(first[0]) if first else ""
    edit_args = first[1:]
    if editor in _ALWAYS_EDIT_ROOT:
        return "writes", _ALWAYS_EDIT_ROOT[editor]
    if editor == "sudoedit" or (os.path.basename(fields[0]) == "sudo" and "-e" in fields[1:]):
        targets = [a for a in edit_args if not a.startswith("-")]
        if not targets or any(_is_sensitive_write_target(a) for a in targets):
            return "writes", (targets[0] if targets else "any file")
    if not fields[0].startswith("/"):
        return None
    path, args = fields[0], fields[1:]
    name = os.path.basename(path)
    base = _PYTHON_VERSIONED.sub(r"\1", name)      # python3.12 → python
    if base in _ROOT_BY_EDITOR:
        return "editor", name
    # A pager's shell escape: blocked by NOEXEC (measured: less, more, man ran
    # nothing), and by journalctl's own secure mode from systemd 247.
    secure_pager = (base == "journalctl" and not pager_env
                    and (systemd is None or systemd >= _SYSTEMD_SECURE_PAGER))
    if base in _ROOT_BY_ESCAPE and not noexec and not secure_pager:
        return "escape", name
    if base in _READS_UNDER_NOEXEC and noexec:
        return "reads", name
    free = not args or any(ch in a for a in args for ch in "*?[")
    exec_blocked = noexec and base in _EXEC_ONLY
    if base in _ROOT_BY_ARGUMENTS and free and args != ['""'] and not exec_blocked:
        return "arguments", name
    # A file-writer with a fixed argument naming a protected path: it writes
    # that file as root (measured: tee/cp into /etc/sudoers.d). Free arguments
    # already returned above.
    if base in _FILE_WRITERS:
        target = next((a for a in args if _is_sensitive_write_target(a)), None)
        if target:
            return "writes", target.split("=", 1)[-1]
    who = _writable_by_another(path)
    if who:
        return "writable", who
    # A script handed to an interpreter: the script is what runs.
    if base in _ROOT_BY_ARGUMENTS and args and args[0].startswith("/"):
        who = _writable_by_another(args[0])
        if who:
            return "writable", who
    return None


def _doas_command(line: str) -> "str | None":
    """``permit nopass … [as root] cmd /path [args …]`` → "/path args" (args
    free when no ``args`` keyword), or None for another target."""
    fields = line.split()
    if "as" in fields:
        target = fields[fields.index("as") + 1] if fields.index("as") + 1 < len(fields) else ""
        if target != "root":
            return None
    if "cmd" not in fields or fields.index("cmd") + 1 >= len(fields):
        return None
    i = fields.index("cmd")
    path = fields[i + 1]
    if "args" in fields[i + 2:]:
        j = fields.index("args", i + 2)
        rest = fields[j + 1:]
        return " ".join([path] + (rest if rest else ['""']))
    return path


def _collect_doas_nopass() -> "tuple[list[str], list[str], bool]":
    """Parse /etc/doas.conf for ``permit nopass`` rules — the doas equivalent of
    sudo's NOPASSWD.

    Returns (nopass_all, nopass_specific, readable):
      - nopass_all      — permit-nopass rules with no ``cmd`` clause (full root)
      - nopass_specific — permit-nopass rules scoped to a ``cmd``
      - readable        — False when the file existed but could not be read (a
                          denial, or a FIFO/non-regular file that ``read_text_capped``
                          refuses — never a hang)

    doas grammar: ``permit|deny [options] identity [as target] [cmd command …]``.
    Only ``permit`` rules grant; ``nopass`` is an option token before the
    identity. A file absent altogether is the common, non-doas case (empty, OK).
    """
    nopass_all: list[str] = []
    nopass_specific: list[str] = []
    conf = _DOAS_CONF
    if not path_exists(conf):
        return nopass_all, nopass_specific, True
    try:
        text = read_text_capped(conf, encoding="utf-8", errors="replace")
    except OSError:
        return nopass_all, nopass_specific, False
    for raw in text.splitlines():
        # doas comments start with `#` (whole-line or trailing).
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if fields[0] != "permit":
            continue  # `deny` never grants
        if "nopass" not in fields[1:]:
            continue
        display = line[:120] + ("…" if len(line) > 120 else "")
        # A `cmd` clause scopes the passwordless grant to one command (specific);
        # without it the rule is unrestricted passwordless root.
        if "cmd" in fields[1:]:
            nopass_specific.append(display)
        else:
            nopass_all.append(display)
    return nopass_all, nopass_specific, True

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_file_perms(snapshot: FilePermsSnapshot, *, t: TranslationFunc | None = None) -> CheckResult:
    """
    Check sensitive file permissions and sudoers configuration.

    Deduction caps (independent per category):
      - World-writable files: −3 pts each, no cap (each is an individual critical risk)
      - Too-permissive files: −1 pt each, capped at 3 total (WARN-level quality issues)
      - SSH host key issues:  −1 pt each, capped at 2 total
      - NOPASSWD:ALL:         −2 pts total (regardless of how many lines)

    Args:
        snapshot: FilePermsSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()
    # Cap for WARN-level permission findings only — ALERT (world-writable) is
    # uncapped because each world-writable critical file is an individual risk.
    warn_deductions = 0

    # ---- Sensitive file permissions ----------------------------------------
    for fi in snapshot.sensitive_files:
        if not fi.exists:
            continue

        # Bits set in the actual mode that exceed what max_mode allows
        extra = fi.mode & (~fi.max_mode & 0o777)

        if extra & 0o002:   # world-writable — critical risk, no deduction cap
            result.alert_with_deduction(
                key=f"file_perms.{fi.key}.world_writable",
                message=_t("file_perms.world_writable",
                           path=fi.path, mode=oct(fi.mode)),
                reason=_t("file_perms.world_writable_reason", path=fi.path),
                points=3,
                detail=_t("file_perms.world_writable_detail", path=fi.path),
                cmd=f"sudo chmod o-w {shlex.quote(str(fi.path))}",
            )

        elif extra:     # other unexpected bits (group-write, world-read…) — capped
            result.warn(
                message=_t("file_perms.too_permissive",
                           path=fi.path, mode=oct(fi.mode),
                           expected=oct(fi.max_mode)),
                detail=_t("file_perms.too_permissive_detail",
                          path=fi.path, expected=oct(fi.max_mode)),
                cmd=f"sudo chmod {oct(fi.max_mode)[2:]} {shlex.quote(str(fi.path))}",
                key=f"file_perms.{fi.key}.too_permissive",
            )
            if warn_deductions < 3:
                result.add_deduction(
                    reason=_t("file_perms.too_permissive_reason", path=fi.path),
                    points=1,
                    context="local",
                    key=f"file_perms.{fi.key}.too_permissive",
                )
                warn_deductions += 1

    # ---- SSH host private keys ----------------------------------------------
    ssh_deductions = 0
    for path, mode in snapshot.ssh_host_key_issues:
        result.warn(
            message=_t("file_perms.ssh_host_key_perms",
                       path=path, mode=oct(mode)),
            detail=_t("file_perms.ssh_host_key_perms_detail", path=path),
            cmd=f"sudo chmod 600 {shlex.quote(str(path))}",
            key=f"file_perms.ssh_host_key.{Path(path).name}",
        )
        if ssh_deductions < 2:
            result.add_deduction(
                reason=_t("file_perms.ssh_host_key_perms_reason", path=path),
                points=1,
                context="local",
                key=f"file_perms.ssh_host_key.{Path(path).name}",
            )
            ssh_deductions += 1

    if not snapshot.ssh_host_keys_readable:
        result.info(
            message=_t("file_perms.ssh_host_keys_unreadable"),
            detail=_t("file_perms.ssh_host_keys_unreadable_detail"),
            key="file_perms.ssh_host_keys_unreadable",
        )

    # ---- Sudoers NOPASSWD:ALL -----------------------------------------------
    if snapshot.sudoers_nopasswd_all:
        for line in snapshot.sudoers_nopasswd_all:
            display = line[:120] + ("…" if len(line) > 120 else "")
            group = _nopasswd_group(line)
            if group and group in snapshot.sudoers_nopasswd_empty_groups:
                # Latent: the grant is real but the group has no members yet.
                message = _t("file_perms.sudoers_nopasswd_all_empty_group",
                             line=display, group=group)
            else:
                message = _t("file_perms.sudoers_nopasswd_all", line=display)
            result.warn(
                message=message,
                detail=_t("file_perms.sudoers_nopasswd_all_detail"),
                key="file_perms.sudoers_nopasswd_all",
                nature="action",
            )
        result.add_deduction(
            reason=_t("file_perms.sudoers_nopasswd_all_reason"),
            points=2,
            context="local",
            key="file_perms.sudoers_nopasswd_all",
        )

    # ---- v0.27.0: a scoped NOPASSWD grant that is root anyway ---------------
    # Measured on a Mint host: NOPASSWD for /usr/bin/python3 was an INFO,
    # "often intentional". It weighs what NOPASSWD: ALL weighs (decided by the
    # user, 24 October 2026): the same power, the same deduction.
    if snapshot.nopasswd_root_equivalent:
        # v0.27.0, decided by the user after review: the same power counts once.
        # Where NOPASSWD:ALL or doas `permit nopass` without cmd already
        # deducts its −2, these rules are said and deduct nothing more.
        _root_already = bool(snapshot.sudoers_nopasswd_all or snapshot.doas_nopass_all)
        for line, command, why, what in snapshot.nopasswd_root_equivalent:
            display = line[:120] + ("…" if len(line) > 120 else "")
            result.warn(
                message=_t(f"file_perms.nopass_root_equivalent_{why}",
                           command=command, what=what, line=display),
                detail=_t("file_perms.nopass_root_equivalent_detail"),
                key="file_perms.nopass_root_equivalent",
                nature="action",
            )
        if not _root_already:
            result.add_deduction(
                reason=_t("file_perms.nopass_root_equivalent_reason"),
                points=2,
                context="local",
                key="file_perms.nopass_root_equivalent",
            )

    # ---- Sudoers NOPASSWD (specific commands only) --------------------------
    # The rules found root-equivalent above are not "often intentional" here.
    _root_lines = {line for line, *_ in snapshot.nopasswd_root_equivalent}
    _scoped = [l for l in snapshot.sudoers_nopasswd_specific if l not in _root_lines]
    if _scoped:
        result.info(
            message=_t("file_perms.sudoers_nopasswd_specific",
                       count=len(_scoped)),
            detail=_t("file_perms.sudoers_nopasswd_specific_detail"),
            key="file_perms.sudoers_nopasswd_specific",
        )

    # ---- Sudoers not read ---------------------------------------------------
    if not snapshot.sudoers_readable:
        result.info(
            message=_t("file_perms.sudoers_unreadable"),
            detail=_t("file_perms.sudoers_unreadable_detail"),
            key="file_perms.sudoers_unreadable",
        )

    # ---- doas permit nopass (Alpine/OpenBSD; the doas equivalent of NOPASSWD) --
    if snapshot.doas_nopass_all:
        for line in snapshot.doas_nopass_all:
            result.warn(
                message=_t("file_perms.doas_nopass_all", line=line),
                detail=_t("file_perms.doas_nopass_all_detail"),
                key="file_perms.doas_nopass_all",
                nature="action",
            )
        result.add_deduction(
            reason=_t("file_perms.doas_nopass_all_reason"),
            points=2,
            context="local",
            key="file_perms.doas_nopass_all",
        )

    # v0.27.0 — as for sudo: a doas rule found root above is not "often intentional".
    _doas_scoped = [l for l in snapshot.doas_nopass_specific if l not in _root_lines]
    if _doas_scoped:
        result.info(
            message=_t("file_perms.doas_nopass_specific",
                       count=len(_doas_scoped)),
            detail=_t("file_perms.doas_nopass_specific_detail"),
            key="file_perms.doas_nopass_specific",
        )

    if not snapshot.doas_readable:
        result.info(
            message=_t("file_perms.doas_unreadable"),
            detail=_t("file_perms.doas_unreadable_detail"),
            key="file_perms.doas_unreadable",
        )

    # ---- All clear ----------------------------------------------------------
    if not result.findings:
        result.ok(
            message=_t("file_perms.ok"),
            key="file_perms.ok",
        )

    return result
