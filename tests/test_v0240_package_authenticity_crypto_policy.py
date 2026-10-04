"""Package-signature enforcement and the system crypto policy.

package_authenticity pins:
  1. every written switch is found — apt one-line options, deb822 fields,
     apt.conf options; dnf/zypper gpgcheck=0 / pkg_gpgcheck=0 on enabled repos
     and in [main]; pacman SigLevel Never / Optional;
  2. what is *not* a switch stays clean — a commented apt.conf line, a disabled
     repo or deb822 stanza, repo_gpgcheck=0 (metadata, not packages),
     pacman's stock "Required DatabaseOptional", apt's ignored backup files;
  3. an unreadable config file withholds the OK; an unsupported manager is
     "not assessed", never clean.

crypto_policy pins:
  4. the *applied* policy is judged (state/current), not the edited config;
     the gap is reported;
  5. LEGACY deducts; weakening modules, dated and unknown policies are INFO;
     no crypto-policies at all is an INFO, never an OK.
"""

from __future__ import annotations

import pytest

import bob.checks.crypto_policy as cp
import bob.checks.package_authenticity as ps
from bob.checks.crypto_policy import CryptoPolicySnapshot, check_crypto_policy
from bob.checks.package_authenticity import PackageAuthenticitySnapshot, check_package_authenticity
from tests.helpers import _t


def _keys(r):
    return [f.key for f in r.findings]


# ---- package_authenticity: fixture ------------------------------------------------------

@pytest.fixture
def etc(tmp_path, monkeypatch):
    for name, rel in [("_APT_SOURCES", "apt/sources.list"), ("_APT_SOURCES_D", "apt/sources.list.d"),
                      ("_APT_CONF", "apt/apt.conf"), ("_APT_CONF_D", "apt/apt.conf.d"),
                      ("_DNF_REPOS", "yum.repos.d"), ("_ZYPP_REPOS", "zypp/repos.d"),
                      ("_PACMAN_CONF", "pacman.conf")]:
        monkeypatch.setattr(ps, name, tmp_path / rel)
    monkeypatch.setattr(ps, "_DNF_MAIN", (tmp_path / "dnf.conf",))
    monkeypatch.setattr(ps, "_ZYPP_MAIN", (tmp_path / "zypp.conf",))
    for d in ("apt/sources.list.d", "apt/apt.conf.d", "yum.repos.d", "zypp/repos.d"):
        (tmp_path / d).mkdir(parents=True)

    def collect(manager, files):
        monkeypatch.setattr(ps, "detect_install_manager", lambda: manager)
        for rel, body in files.items():
            (tmp_path / rel).write_text(body)
        return PackageAuthenticitySnapshot.from_system()
    collect.root = tmp_path
    return collect


# ---- apt ------------------------------------------------------------------------

def test_apt_switches_are_found(etc):
    s = etc("apt", {
        "apt/sources.list.d/x.list": "deb [arch=amd64 trusted=yes] http://e.invalid x main\n",
        "apt/sources.list.d/y.sources": "Types: deb\nURIs: http://e.invalid\nTrusted: yes\n",
        "apt/apt.conf.d/99x": 'APT::Get::AllowUnauthenticated "true";\n',
    })
    assert len(s.disabled) == 3
    r = check_package_authenticity(s, t=_t)
    assert "package_authenticity.disabled" in _keys(r)
    assert sum(d.points for d in r.deductions) == 1


def test_apt_non_switches_stay_clean(etc):
    s = etc("apt", {
        "apt/sources.list": "deb [signed-by=/etc/apt/keyrings/k.gpg] http://e.invalid x main\n"
                            "# deb [trusted=yes] http://old.invalid x main\n",
        "apt/sources.list.d/z.sources": "Types: deb\nURIs: http://e.invalid\nEnabled: no\nTrusted: yes\n",
        "apt/apt.conf.d/98c": '// APT::Get::AllowUnauthenticated "true";\n',
        "apt/apt.conf.d/97x.dpkg-old": 'APT::Get::AllowUnauthenticated "true";\n',
        "apt/apt.conf.d/00trustcdrom": 'APT::Authentication::TrustCDROM "true";\n',
    })
    assert s.disabled == []
    assert _keys(check_package_authenticity(s, t=_t)) == ["package_authenticity.ok"]


# ---- dnf / zypper -----------------------------------------------------------------

def test_dnf_gpgcheck_off_on_enabled_repo(etc):
    s = etc("dnf", {
        "dnf.conf": "[main]\ngpgcheck=True\n",
        "yum.repos.d/a.repo": "[a]\nbaseurl=x\ngpgcheck=0\nrepo_gpgcheck=0\n"
                              "[b]\nenabled=0\ngpgcheck=0\n"
                              "[c]\ngpgcheck=1\nrepo_gpgcheck=0\n",
    })
    assert len(s.disabled) == 1 and "[a]: gpgcheck=0" in s.disabled[0]


def test_dnf_main_gpgcheck_off(etc):
    s = etc("dnf", {"dnf.conf": "[main]\ngpgcheck=False\n"})
    assert s.disabled and "[main]" in s.disabled[0]


def test_dnf_unset_gpgcheck_is_not_inferred(etc):
    s = etc("dnf", {"dnf.conf": "[main]\n", "yum.repos.d/a.repo": "[a]\nbaseurl=x\n"})
    assert s.disabled == []


def test_zypper_pkg_gpgcheck_off(etc):
    s = etc("zypper", {"zypp/repos.d/x.repo": "[x]\nenabled=1\npkg_gpgcheck=off\n"})
    assert len(s.disabled) == 1


# ---- pacman -------------------------------------------------------------------------

def test_pacman_stock_siglevel_is_clean(etc):
    s = etc("pacman", {"pacman.conf": "[options]\nSigLevel    = Required DatabaseOptional\n"
                                      "LocalFileSigLevel = Optional\n[core]\nInclude = /m\n"})
    assert s.disabled == []


@pytest.mark.parametrize("level", ["Never", "Optional TrustAll", "PackageNever"])
def test_pacman_weak_siglevel(etc, level):
    s = etc("pacman", {"pacman.conf": f"[options]\nSigLevel = Required\n[custom]\nSigLevel = {level}\n"})
    assert len(s.disabled) == 1 and "[custom]" in s.disabled[0]


# ---- visibility ----------------------------------------------------------------------

def test_unsupported_manager_is_not_assessed(etc):
    r = check_package_authenticity(etc("xbps-install", {}), t=_t)
    assert _keys(r) == ["package_authenticity.not_assessed"]


# ---- apk (apk-tools 3, measured on real Alpine 3.24) -----------------------------

@pytest.mark.parametrize("body,disabled", [
    ("allow-untrusted\n", True),
    ("cache-max-age=60\nallow-untrusted\n", True),
    ("--allow-untrusted\n", False),       # apk: "unrecognized option", no effect
    ("# allow-untrusted\n", False),
    ("cache-max-age=60\n", False),
])
def test_apk_config_allow_untrusted(etc, monkeypatch, body, disabled):
    monkeypatch.setattr(ps, "_APK_CONFIG", etc.root / "apk-config")
    (etc.root / "apk-config").write_text(body)
    s = etc("apk", {})
    assert bool(s.disabled) is disabled


def test_apk_without_config_is_checked_and_clean(etc, monkeypatch):
    monkeypatch.setattr(ps, "_APK_CONFIG", etc.root / "absent-apk-config")
    r = check_package_authenticity(etc("apk", {}), t=_t)
    assert _keys(r) == ["package_authenticity.ok"]


def test_apk_config_path_is_the_real_one():
    from pathlib import Path
    assert ps._APK_CONFIG == Path("/etc/apk/config")


def test_unreadable_file_withholds_ok():
    r = check_package_authenticity(PackageAuthenticitySnapshot(manager="apt", unreadable=["/etc/apt/x"]), t=_t)
    assert "package_authenticity.unreadable" in _keys(r)
    assert "package_authenticity.ok" not in _keys(r)


# ---- crypto_policy -------------------------------------------------------------------

@pytest.fixture
def policy(tmp_path, monkeypatch):
    cfg, cur = tmp_path / "config", tmp_path / "state" / "current"
    monkeypatch.setattr(cp, "_CONFIG", cfg)
    monkeypatch.setattr(cp, "_CURRENT", cur)

    def collect(config=None, current=None):
        if config is not None:
            cfg.write_text(config)
        if current is not None:
            cur.parent.mkdir(exist_ok=True)
            cur.write_text(current)
        return CryptoPolicySnapshot.from_system()
    return collect


def test_no_crypto_policies_is_info_not_ok(policy):
    r = check_crypto_policy(policy(), t=_t)
    assert _keys(r) == ["crypto_policy.absent"]


def test_default_is_ok(policy):
    r = check_crypto_policy(policy("# comment\nDEFAULT\n", "DEFAULT\n"), t=_t)
    assert _keys(r) == ["crypto_policy.ok"]


def test_applied_legacy_deducts_even_if_config_says_default(policy):
    r = check_crypto_policy(policy("DEFAULT\n", "LEGACY\n"), t=_t)
    assert "crypto_policy.legacy" in _keys(r)
    assert "crypto_policy.pending" in _keys(r)
    assert sum(d.points for d in r.deductions) == 1


def test_config_used_when_no_state_file(policy):
    r = check_crypto_policy(policy("LEGACY\n"), t=_t)
    assert "crypto_policy.legacy" in _keys(r)


@pytest.mark.parametrize("pol,key", [("DEFAULT:SHA1", "crypto_policy.weakening_module"),
                                     ("FEDORA43", "crypto_policy.dated"),
                                     ("MYCORP", "crypto_policy.unrecognised")])
def test_info_cases_never_deduct(policy, pol, key):
    r = check_crypto_policy(policy(pol + "\n", pol + "\n"), t=_t)
    assert key in _keys(r)
    assert r.deductions == []
    assert "crypto_policy.ok" not in _keys(r)


def test_strengthening_module_stays_ok(policy):
    r = check_crypto_policy(policy("DEFAULT:NO-SHA1\n", "DEFAULT:NO-SHA1\n"), t=_t)
    assert _keys(r) == ["crypto_policy.ok"]


@pytest.mark.parametrize("manager,mechanism", [
    ("apt", "package_authenticity.mechanism_apt"),
    ("dnf", "package_authenticity.mechanism_rpm"),
    ("zypper", "package_authenticity.mechanism_rpm"),
    ("pacman", "package_authenticity.mechanism_pacman"),
])
def test_the_message_names_what_the_manager_verifies(manager, mechanism):
    """apt verifies a signed index, not each .deb — 'package signature' was false for it."""
    r = check_package_authenticity(PackageAuthenticitySnapshot(manager=manager),
                                   t=lambda key, **kw: f"{key} {kw}" if kw else key)
    assert mechanism in r.findings[0].message


def test_zypper_vendor_main_conf_is_read_when_no_etc_override(etc, monkeypatch):
    """openSUSE Leap 16: zypp.conf lives in /usr/etc; /etc only overrides it."""
    vendor = etc.root / "usr-etc-zypp.conf"
    monkeypatch.setattr(ps, "_ZYPP_MAIN", (etc.root / "zypp.conf", vendor))
    vendor.write_text("[main]\ngpgcheck = off\n")
    s = etc("zypper", {})
    assert s.disabled and "usr-etc-zypp.conf" in s.disabled[0]


def test_zypper_etc_override_wins_over_vendor(etc, monkeypatch):
    vendor = etc.root / "usr-etc-zypp.conf"
    monkeypatch.setattr(ps, "_ZYPP_MAIN", (etc.root / "zypp.conf", vendor))
    vendor.write_text("[main]\ngpgcheck = off\n")
    s = etc("zypper", {"zypp.conf": "[main]\ngpgcheck = on\n"})
    assert s.disabled == []


def test_zypper_main_conf_paths_are_etc_then_vendor():
    """Pins the real default the two tests above replace with tmp paths."""
    from pathlib import Path
    assert ps._ZYPP_MAIN == (Path("/etc/zypp/zypp.conf"), Path("/usr/etc/zypp/zypp.conf"))
