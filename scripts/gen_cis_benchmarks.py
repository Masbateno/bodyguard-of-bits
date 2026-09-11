#!/usr/bin/env python3
"""Regenerate the CIS references in bob/data/cis_refs.json from ComplianceAsCode.

Every number written here comes from ComplianceAsCode/content (the SCAP Security
Guide) — an open, versioned, citable source — never from memory. The chain is:
a BOB finding -> the setting it checks -> the CAC rule that implements it -> the
CAC control's id + title in each benchmark. A BOB key whose CAC rule is not found
in a benchmark gets no reference there (honest); a BOB key not in the MAP at all
is left untouched.

Source: https://github.com/ComplianceAsCode/content  (controls/cis_*.yml)
Run:    python3 scripts/gen_cis_benchmarks.py   (needs network)

The CAC *rule name* is the stable anchor across benchmark versions — control
numbers are renumbered between CIS releases and even mis-cited by hand, so the
rule, not the number, is what identifies a control. From that anchor this script:

  * re-bases the primary reference (`ref` + `code`) onto CAC's CIS Ubuntu 22.04
    v2.0.0 numbering + title + level, correcting any drift or mis-citation;
  * fills the `benchmarks` block with the same control's number and title in
    CIS Ubuntu 24.04, Debian 12 and Debian 13.

Benchmarks are limited to distributions BOB officially supports that publish
their own CIS benchmark: Ubuntu (22.04 primary + 24.04) and Debian (12, 13).
openSUSE Leap and Fedora are excluded — CIS publishes SLES and RHEL, not those;
Alpine / Arch / Mint / Raspberry Pi OS have no CIS benchmark. The 7 CIS Docker
and 1 CIS Red Hat keys have single-version benchmarks with nothing to cross-cite
and are left untouched.
"""
from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

_RAW = "https://raw.githubusercontent.com/ComplianceAsCode/content/master/controls/"

#: The primary benchmark (its rule fixes ``ref``/``code``) and the cross-cited ones.
PRIMARY = ("CIS Ubuntu 22.04", "cis_ubuntu2204.yml")
CROSS = [("CIS Ubuntu 24.04", "cis_ubuntu2404.yml"),
         ("CIS Debian 12", "cis_debian12.yml"),
         ("CIS Debian 13", "cis_debian13.yml")]

# BOB finding key -> candidate CAC rule names (first one present in a given
# benchmark wins). Every rule below was verified present in the CAC controls of
# at least the primary benchmark; keys whose setting has no CAC control (e.g.
# CIS Ubuntu does not mandate disabling SSH password auth or X11 forwarding) are
# deliberately absent and keep their existing BOB reference untouched.
MAP = {
 # ---- sysctl network hardening ----
 "hardening.rp_filter_disabled": ["sysctl_net_ipv4_conf_all_rp_filter"],
 "hardening.rp_filter_loose": ["sysctl_net_ipv4_conf_all_rp_filter"],
 "hardening.redirects_enabled": ["sysctl_net_ipv4_conf_all_accept_redirects"],
 "hardening.accept_redirects_v6_enabled": ["sysctl_net_ipv6_conf_all_accept_redirects"],
 "hardening.send_redirects_enabled": ["sysctl_net_ipv4_conf_all_send_redirects"],
 "hardening.log_martians_disabled": ["sysctl_net_ipv4_conf_all_log_martians"],
 "hardening.tcp_syncookies_disabled": ["sysctl_net_ipv4_tcp_syncookies"],
 "hardening.accept_source_route_enabled": ["sysctl_net_ipv4_conf_all_accept_source_route"],
 "hardening.icmp_broadcast_enabled": ["sysctl_net_ipv4_icmp_echo_ignore_broadcasts"],
 "hardening.protected_hardlinks_disabled": ["sysctl_fs_protected_hardlinks"],
 "hardening.protected_symlinks_disabled": ["sysctl_fs_protected_symlinks"],
 # ---- sysctl kernel hardening ----
 "kernel_hardening.aslr_disabled": ["sysctl_kernel_randomize_va_space"],
 "kernel_hardening.aslr_conservative": ["sysctl_kernel_randomize_va_space"],
 "kernel_hardening.ptrace_unrestricted": ["sysctl_kernel_yama_ptrace_scope"],
 "kernel_hardening.dmesg_exposed": ["sysctl_kernel_dmesg_restrict"],
 "kernel_hardening.kptr_exposed": ["sysctl_kernel_kptr_restrict"],
 "kernel_hardening.suid_dump_all": ["sysctl_fs_suid_dumpable"],
 "firewall_drivers.ip_forward_enabled": ["sysctl_net_ipv4_ip_forward"],
 # ---- SSH daemon ----
 "ssh.permit_root_login": ["sshd_disable_root_login"],
 "ssh.permit_empty_passwords": ["sshd_disable_empty_passwords"],
 "ssh.max_auth_tries": ["sshd_set_max_auth_tries"],
 "ssh.login_grace_time": ["sshd_set_login_grace_time"],
 "ssh.ignore_rhosts_disabled": ["sshd_disable_rhosts"],
 "ssh.permit_user_env": ["sshd_do_not_permit_user_env"],
 "ssh.host_based_auth": ["disable_host_auth"],
 "ssh.no_allow_users": ["sshd_limit_user_access"],
 "ssh.weak_ciphers": ["sshd_use_strong_ciphers"],
 "ssh.weak_macs": ["sshd_use_strong_macs", "sshd_strong_macs"],
 "ssh.weak_kex": ["sshd_use_strong_kex", "sshd_strong_kex"],
 "ssh.private_key_perms": ["file_permissions_sshd_private_key"],
 "file_perms.ssh_host_key_perms": ["file_permissions_sshd_private_key"],
 # ---- auditd ----
 "auditd.not_installed": ["package_audit_installed"],
 "auditd.service_inactive": ["service_auditd_enabled"],
 # ---- MAC / AppArmor ----
 "mac_policy.no_mac": ["package_apparmor_installed"],
 "mac_policy.no_enforce": ["grub2_enable_apparmor"],
 "mac_policy.apparmor_off_in_kernel": ["grub2_enable_apparmor"],
 "mac_policy.apparmor_inactive": ["grub2_enable_apparmor"],
 "mac_policy.apparmor_no_enforce": ["all_apparmor_profiles_enforced"],
 "mac_policy.apparmor_complain_profiles": ["all_apparmor_profiles_enforced"],
 "mac_policy.apparmor_no_profiles": ["all_apparmor_profiles_in_enforce_complain_mode"],
 # ---- password / accounts ----
 "password_policy.no_quality_module": ["accounts_password_pam_pwquality_enabled"],
 "password_policy.weak_minlen": ["accounts_password_pam_minlen"],
 "password_policy.no_expiry": ["accounts_maximum_age_login_defs"],
 "user_accounts.uid_zero": ["accounts_no_uid_except_zero"],
 "user_accounts.expired_account": ["account_disable_post_pw_expiration"],
 "user_accounts.empty_password": ["no_empty_passwords_etc_shadow"],
 "umask.world_writable": ["accounts_umask_etc_login_defs"],
 "umask.group_writable": ["accounts_umask_etc_login_defs"],
 # ---- file permissions ----
 "file_perms.world_writable": ["file_permissions_unauthorized_world_writable"],
 "file_perms.sudoers_nopasswd_all": ["sudo_require_authentication"],
 # ---- firewall / UFW ----
 "prerequisites.ufw_missing": ["package_ufw_installed"],
 "firewall.inactive": ["service_ufw_enabled"],
 "firewall.policy_open": ["set_ufw_default_rule"],
 "firewall_iptables.no_loopback": ["set_ufw_loopback_traffic"],
 # ---- file integrity (AIDE) ----
 "file_integrity.not_installed": ["package_aide_installed"],
 "file_integrity.no_db": ["aide_build_database"],
 "file_integrity.no_check": ["aide_periodic_cron_checking",
                             "aide_periodic_checking_systemd_timer"],
 "file_integrity.check_old": ["aide_periodic_cron_checking",
                              "aide_periodic_checking_systemd_timer"],
}

# Keys whose CAC rule exists only in a non-primary benchmark (CIS Debian 13),
# so their previous "CIS Ubuntu 22.04" primary cannot be verified against the
# source and is demoted to a bilingual best-practice reference. BOB-authored
# prose, like every other best-practice entry; the CIS Debian 13 citation is
# still attached from the rule.
BP_FALLBACK = {
 "hardening.protected_hardlinks_disabled":
     ("Enable hardlink protection (fs.protected_hardlinks = 1)",
      "Activer la protection des liens physiques (fs.protected_hardlinks = 1)"),
 "hardening.protected_symlinks_disabled":
     ("Enable symlink protection (fs.protected_symlinks = 1)",
      "Activer la protection des liens symboliques (fs.protected_symlinks = 1)"),
}


def _index(text: str) -> dict:
    """Parse a CAC controls YAML into ``{rule: (code, title, level)}``.

    Regex state machine rather than a YAML dependency (this is a dev-only
    script). A control block is ``- id: <code>`` at four-space indent, then a
    ``title:``, a ``levels:`` list of ``lN_*`` ids, and a ``rules:`` list.
    """
    out: dict = {}
    cid = ctitle = None
    levels: list = []
    section = None            # "levels" | "rules" | None
    for line in text.splitlines():
        m = re.match(r"^ {4}-\s*id:\s*(\S+)\s*$", line)
        if m:
            cid, ctitle, levels, section = m.group(1), None, [], None
            continue
        if cid is None:
            continue
        mt = re.match(r"^ {6}title:\s*(.+?)\s*$", line)
        if mt:
            ctitle = mt.group(1).strip().strip('"')
            continue
        if re.match(r"^ {6}levels:\s*$", line):
            section = "levels"
            continue
        if re.match(r"^ {6}rules:\s*$", line):
            section = "rules"
            continue
        if re.match(r"^ {6}\w", line):     # any other key at control level
            section = None
            continue
        mi = re.match(r"^ {8,}-\s*(\S+)\s*$", line)
        if not mi:
            continue
        item = mi.group(1)
        if section == "levels":
            levels.append(item)
        elif section == "rules" and ctitle:
            level = "L1" if any(x.startswith("l1") for x in levels) else (
                    "L2" if any(x.startswith("l2") for x in levels) else "")
            out.setdefault(item, (cid, ctitle, level))
    return out


def _fetch(fname: str) -> dict:
    return _index(urllib.request.urlopen(_RAW + fname, timeout=30).read().decode())


def main() -> None:
    primary_idx = _fetch(PRIMARY[1])
    cross_idx = {fam: _fetch(f) for fam, f in CROSS}

    path = Path(__file__).resolve().parent.parent / "bob" / "data" / "cis_refs.json"
    cis = json.loads(path.read_text(encoding="utf-8"))

    rebased = crossed = 0
    for key, rules in MAP.items():
        if key not in cis:
            raise SystemExit(f"unknown BOB key: {key}")

        # Re-base the primary reference from the CAC rule, when present.
        # Gather the cross-benchmark citations first — they also supply a
        # title for the best-practice fallback below.
        blocks = {}
        for fam, _f in CROSS:
            idx = cross_idx[fam]
            chit = next((idx[r] for r in rules if r in idx), None)
            if chit:
                blocks[fam] = {"code": chit[0], "title": chit[1]}

        # Re-base the primary reference from the CAC rule, when present.
        hit = next((primary_idx[r] for r in rules if r in primary_idx), None)
        if hit:
            code, title, level = hit
            lvl = f" {level}" if level else ""
            cis[key]["ref"] = f"{PRIMARY[0]}{lvl} — {code} — {title}"
            cis[key]["code"] = f"CIS:{code}"
            rebased += 1
        elif cis[key].get("ref", "").startswith("CIS ") and key in BP_FALLBACK:
            # The CAC rule is absent from the primary benchmark, so the existing
            # "CIS Ubuntu 22.04 ..." claim cannot be verified against the source
            # (fs.protected_hardlinks/symlinks live only in CIS Debian 13, and
            # BOB's number for them was in fact the AIDE control's). Demote to a
            # bilingual best-practice reference — honest — while keeping the real
            # cross-benchmark citation below. code becomes null, like every other
            # best-practice entry.
            en, fr = BP_FALLBACK[key]
            cis[key]["ref"] = f"Best practice — {en}"
            cis[key]["ref_fr"] = f"Bonne pratique — {fr}"
            cis[key]["code"] = None

        if blocks:
            cis[key]["benchmarks"] = blocks
            crossed += 1
        else:
            cis[key].pop("benchmarks", None)

    path.write_text(json.dumps(cis, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")
    print(f"mapped {len(MAP)} keys: {rebased} primary re-based, "
          f"{crossed} with cross-benchmark citations")


if __name__ == "__main__":
    main()
