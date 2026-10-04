"""
Package authenticity for BOB — a repository whose packages are installed
without verifying where they come from.

What is verified differs by manager, and the findings say which: apt
authenticates the signed Release/InRelease index and the per-package
checksums it lists (a .deb carries no signature of its own); dnf, zypper and
pacman verify a signature on each package.

Every supported package manager verifies signatures by default, and every one
has a switch to stop: ``[trusted=yes]`` on an apt source, ``gpgcheck=0`` in a
dnf/zypper repo file, ``SigLevel = Never`` in pacman.conf. Such a switch turns
the mirror — and anyone between the host and it — into a root shell on the
next upgrade. It is usually set once to get a third-party repo working and
never removed.

BOB only reports switches that are **written down**. A key left at its default
is not inferred either way: dnf's built-in default for ``gpgcheck`` has changed
across versions, and an inferred "off" would be a claim about a value nobody
wrote.

Files read, per manager (only the manager this host installs with):
  - apt:    sources.list, sources.list.d/*.list and *.sources (deb822),
            apt.conf, apt.conf.d/*
  - dnf:    dnf.conf / yum.conf [main], yum.repos.d/*.repo (enabled repos)
  - zypper: zypp.conf [main], zypp/repos.d/*.repo (enabled repos)
  - pacman: pacman.conf ([options] and each repository's SigLevel)
  - apk:    /etc/apk/config (apk-tools 3), for a persistent allow-untrusted
            (v0.24.0 — first reported "not assessed", which capped every
            Alpine score; apk 3 does have a persistent switch, and it is read).

Findings:
  - a signature check disabled somewhere : WARN −1
  - a config file unreadable             : INFO (unverified)
  - manager not assessed                 : INFO
  - nothing disabled                     : OK
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t, detect_install_manager
from bob._atomic import read_text_capped
from bob.scoring import CheckResult

_APT_SOURCES = Path("/etc/apt/sources.list")
_APT_SOURCES_D = Path("/etc/apt/sources.list.d")
_APT_CONF = Path("/etc/apt/apt.conf")
_APT_CONF_D = Path("/etc/apt/apt.conf.d")
_DNF_MAIN = (Path("/etc/dnf/dnf.conf"), Path("/etc/yum.conf"))
_DNF_REPOS = Path("/etc/yum.repos.d")
#: libzypp reads /etc/zypp/zypp.conf when present, else the vendor copy
#: (openSUSE Leap 16 ships both; a host without the /etc override reads only
#: /usr/etc). First that exists wins, as for dnf.conf over yum.conf.
_ZYPP_MAIN = (Path("/etc/zypp/zypp.conf"), Path("/usr/etc/zypp/zypp.conf"))
_ZYPP_REPOS = Path("/etc/zypp/repos.d")
_PACMAN_CONF = Path("/etc/pacman.conf")
#: apk-tools 3 global options, one bare long-option name per line. Measured on
#: Alpine 3.24 / apk 3.0.8: "allow-untrusted" is honoured, "--allow-untrusted"
#: draws "unrecognized option" and does nothing.
_APK_CONFIG = Path("/etc/apk/config")

#: apt ignores these names in its .d directories (Dir::Ignore-Files-Silently).
_APT_IGNORED = re.compile(r"(~|\.disabled|\.bak|\.dpkg-[a-z]+|\.ucf-[a-z]+|\.save|"
                          r"\.orig|\.distUpgrade)$")

_APT_INSECURE_OPTS = re.compile(
    r"(?i)\b(APT::Get::AllowUnauthenticated|Acquire::AllowInsecureRepositories|"
    r"Acquire::AllowDowngradeToInsecureRepositories|Acquire::AllowWeakRepositories)"
    r"\s+\"?(true|yes|1|on)\"?")
#: One-line source options and deb822 fields that drop signature checking.
_APT_ONE_LINE = re.compile(r"(?i)\b(trusted|allow-insecure|allow-weak)=yes\b")
_APT_DEB822 = re.compile(r"(?im)^\s*(Trusted|Allow-Insecure|Allow-Weak)\s*:\s*yes\s*$")

_OFF = {"0", "false", "no", "off"}

#: The locale key naming what each manager verifies.
_MECHANISM = {
    "apt": "package_authenticity.mechanism_apt", "apt-get": "package_authenticity.mechanism_apt",
    "dnf": "package_authenticity.mechanism_rpm", "yum": "package_authenticity.mechanism_rpm",
    "zypper": "package_authenticity.mechanism_rpm",
    "pacman": "package_authenticity.mechanism_pacman",
    "apk": "package_authenticity.mechanism_apk",
}
#: dnf / zypper keys that, set off, stop package signature checks.
_INI_KEYS = {"gpgcheck", "pkg_gpgcheck"}


@dataclass
class PackageAuthenticitySnapshot:
    """
    Args:
        manager:    the install manager detected ("" when none).
        disabled:   "<file>: <what>" for every switch that turns checks off.
        unreadable: config files that exist but could not be read.
        files_read: how many config files were read.
    """
    manager:    str = ""
    disabled:   "list[str]" = field(default_factory=list)
    unreadable: "list[str]" = field(default_factory=list)
    files_read: int = 0

    @classmethod
    def from_system(cls) -> "PackageAuthenticitySnapshot":
        snap = cls(manager=detect_install_manager())
        m = snap.manager
        if m in ("apt", "apt-get"):
            snap._apt()
        elif m in ("dnf", "yum"):
            snap._ini(_DNF_MAIN, _DNF_REPOS)
        elif m == "zypper":
            snap._ini(_ZYPP_MAIN, _ZYPP_REPOS)
        elif m == "pacman":
            snap._pacman()
        elif m == "apk":
            snap._apk()
        return snap

    # ---- helpers ---------------------------------------------------------------
    def _read(self, path: Path) -> "str | None":
        try:
            text = read_text_capped(path, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return None
        except OSError:
            self.unreadable.append(str(path))
            return None
        self.files_read += 1
        return text

    def _listdir(self, d: Path, suffixes: "tuple[str, ...]") -> "list[Path]":
        try:
            names = sorted(p.name for p in d.iterdir())
        except FileNotFoundError:
            return []
        except OSError:
            self.unreadable.append(str(d))
            return []
        return [d / n for n in names
                if (not suffixes or n.endswith(suffixes)) and not _APT_IGNORED.search(n)]

    # ---- apt -------------------------------------------------------------------
    def _apt(self) -> None:
        for path in [_APT_SOURCES, *self._listdir(_APT_SOURCES_D, (".list", ".sources"))]:
            text = self._read(path)
            if text is None:
                continue
            if path.suffix == ".sources":
                for stanza in re.split(r"\n\s*\n", text):
                    if re.search(r"(?im)^\s*Enabled\s*:\s*no\s*$", stanza):
                        continue
                    for m in _APT_DEB822.finditer(stanza):
                        self.disabled.append(f"{path}: {m.group(1)}: yes")
            else:
                for line in text.splitlines():
                    s = line.strip()
                    if not s.startswith(("deb ", "deb-src ", "deb\t")) or "[" not in s:
                        continue
                    opts = s[s.index("["):s.find("]") + 1]
                    for m in _APT_ONE_LINE.finditer(opts):
                        self.disabled.append(f"{path}: [{m.group(0)}]")
        for path in [_APT_CONF, *self._listdir(_APT_CONF_D, ())]:
            text = self._read(path)
            if text is None:
                continue
            for line in text.splitlines():
                s = line.split("//", 1)[0].strip()
                if not s or s.startswith("#"):
                    continue
                for m in _APT_INSECURE_OPTS.finditer(s):
                    self.disabled.append(f"{path}: {m.group(1)} \"{m.group(2)}\"")

    # ---- dnf / zypper ----------------------------------------------------------
    def _ini(self, mains: "tuple[Path, ...]", repo_dir: Path) -> None:
        for path in mains:
            text = self._read(path)
            if text is None:
                continue
            for section, keys in _ini_sections(text):
                if section == "main":
                    for k in _INI_KEYS & keys.keys():
                        if keys[k].lower() in _OFF:
                            self.disabled.append(f"{path} [main]: {k}={keys[k]}")
            break          # dnf.conf wins over yum.conf
        for path in self._listdir(repo_dir, (".repo",)):
            text = self._read(path)
            if text is None:
                continue
            for section, keys in _ini_sections(text):
                if keys.get("enabled", "1").lower() in _OFF:
                    continue
                for k in sorted(_INI_KEYS & keys.keys()):
                    if keys[k].lower() in _OFF:
                        self.disabled.append(f"{path} [{section}]: {k}={keys[k]}")

    # ---- apk -------------------------------------------------------------------
    def _apk(self) -> None:
        text = self._read(_APK_CONFIG)
        if text is None:
            return          # no global config: apk verifies every package
        for line in text.splitlines():
            if line.split("#", 1)[0].strip().split("=", 1)[0] == "allow-untrusted":
                self.disabled.append(f"{_APK_CONFIG}: allow-untrusted")

    # ---- pacman ----------------------------------------------------------------
    def _pacman(self) -> None:
        text = self._read(_PACMAN_CONF)
        if text is None:
            return
        for section, keys in _ini_sections(text, sep=r"\s*=\s*"):
            level = keys.get("SigLevel")
            if level is None:
                continue
            for tok in level.split():
                if tok in ("Never", "PackageNever", "Optional", "PackageOptional"):
                    self.disabled.append(f"{_PACMAN_CONF} [{section}]: SigLevel = {level}")
                    break


def _ini_sections(text: str, sep: str = r"\s*=\s*") -> "list[tuple[str, dict[str, str]]]":
    """[(section, {key: value})] — last value wins, comments and blanks dropped."""
    out: "list[tuple[str, dict[str, str]]]" = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            out.append((line[1:-1].strip(), {}))
            continue
        if not out:
            out.append(("", {}))
        parts = re.split(sep, line, maxsplit=1)
        if len(parts) == 2:
            out[-1][1][parts[0].strip()] = parts[1].split("#", 1)[0].strip()
    return out


def check_package_authenticity(snapshot: PackageAuthenticitySnapshot,
                          t: "TranslationFunc | None" = None) -> CheckResult:
    _t = t if t is not None else _identity_t
    result = CheckResult()
    supported = snapshot.manager in _MECHANISM

    if not supported:
        result.info(message=_t("package_authenticity.not_assessed",
                               manager=snapshot.manager or "?"),
                    key="package_authenticity.not_assessed")
        return result

    # What the manager actually verifies, named for it (v0.24.0): apt
    # authenticates the signed Release/InRelease index and the checksums it
    # lists — no .deb carries its own signature — while dnf, zypper and pacman
    # check a signature on each package. "Package signature checking" was
    # false for apt.
    mechanism = _t(_MECHANISM[snapshot.manager])

    if snapshot.disabled:
        result.warn_with_deduction(
            key="package_authenticity.disabled",
            message=_t("package_authenticity.disabled", count=len(snapshot.disabled),
                       mechanism=mechanism,
                       where="; ".join(snapshot.disabled[:10])
                       + (f" (+{len(snapshot.disabled) - 10} more)"
                          if len(snapshot.disabled) > 10 else "")),
            reason=_t("package_authenticity.disabled_reason", count=len(snapshot.disabled)),
            points=1,
            detail=_t("package_authenticity.disabled_detail"),
            nature="action",
        )
    if snapshot.unreadable:
        result.info(message=_t("package_authenticity.unreadable",
                               files=", ".join(snapshot.unreadable)),
                    key="package_authenticity.unreadable")
    if not snapshot.disabled and not snapshot.unreadable:
        result.ok(message=_t("package_authenticity.ok", mechanism=mechanism,
                             manager=snapshot.manager,
                             files=snapshot.files_read),
                  key="package_authenticity.ok")
    return result
