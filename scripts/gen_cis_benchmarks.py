#!/usr/bin/env python3
"""Regenerate the per-benchmark CIS references in bob/data/cis_refs.json.

Every number written here comes from ComplianceAsCode/content (the SCAP
Security Guide) — an open, versioned, citable source — never from memory. The
chain is: a BOB finding -> the setting it checks -> the CAC rule that
implements it -> the CAC control's id + title for each benchmark. A BOB key
whose CAC rule is not found in a benchmark gets no reference there (honest).

Source: https://github.com/ComplianceAsCode/content  (controls/cis_*.yml)
Run:    python3 scripts/gen_cis_benchmarks.py   (needs network)

Benchmarks are limited to distributions BOB officially supports that publish
their own CIS benchmark: Debian (12, 13) and Ubuntu (22.04 already primary;
24.04 added here). openSUSE Leap and Fedora are excluded — CIS publishes SLES
and RHEL, not those; Alpine/Arch/Mint/Raspberry Pi OS have no CIS benchmark.
"""
from __future__ import annotations
import json, re, urllib.request
from pathlib import Path

_RAW = "https://raw.githubusercontent.com/ComplianceAsCode/content/master/controls/"
BENCHES = [("CIS Debian 12", "cis_debian12.yml"),
           ("CIS Debian 13", "cis_debian13.yml"),
           ("CIS Ubuntu 24.04", "cis_ubuntu2404.yml")]

# BOB finding key -> candidate CAC rule names (first found in a benchmark wins).
MAP = {
 "hardening.rp_filter_disabled": ["sysctl_net_ipv4_conf_all_rp_filter"],
 "hardening.rp_filter_loose": ["sysctl_net_ipv4_conf_all_rp_filter"],
 "hardening.redirects_enabled": ["sysctl_net_ipv4_conf_all_accept_redirects"],
 "hardening.accept_redirects_v6_enabled": ["sysctl_net_ipv6_conf_all_accept_redirects"],
 "hardening.send_redirects_enabled": ["sysctl_net_ipv4_conf_all_send_redirects"],
 "hardening.log_martians_disabled": ["sysctl_net_ipv4_conf_all_log_martians"],
 "hardening.tcp_syncookies_disabled": ["sysctl_net_ipv4_tcp_syncookies"],
 "hardening.accept_source_route_enabled": ["sysctl_net_ipv4_conf_all_accept_source_route"],
 "hardening.protected_hardlinks_disabled": ["sysctl_fs_protected_hardlinks"],
 "hardening.protected_symlinks_disabled": ["sysctl_fs_protected_symlinks"],
 "kernel_hardening.aslr_disabled": ["sysctl_kernel_randomize_va_space"],
 "kernel_hardening.aslr_conservative": ["sysctl_kernel_randomize_va_space"],
 "kernel_hardening.ptrace_unrestricted": ["sysctl_kernel_yama_ptrace_scope"],
 "kernel_hardening.dmesg_exposed": ["sysctl_kernel_dmesg_restrict"],
 "kernel_hardening.kptr_exposed": ["sysctl_kernel_kptr_restrict"],
 "kernel_hardening.suid_dump_all": ["sysctl_fs_suid_dumpable"],
 "firewall_drivers.ip_forward_enabled": ["sysctl_net_ipv4_ip_forward"],
 "ssh.permit_root_login": ["sshd_disable_root_login"],
 "ssh.permit_empty_passwords": ["sshd_disable_empty_passwords"],
 "ssh.max_auth_tries": ["sshd_set_max_auth_tries"],
 "ssh.login_grace_time": ["sshd_set_login_grace_time"],
 "ssh.ignore_rhosts_disabled": ["sshd_disable_rhosts"],
 "ssh.permit_user_env": ["sshd_do_not_permit_user_env"],
 "ssh.private_key_perms": ["file_permissions_sshd_private_key"],
 "ssh.weak_ciphers": ["sshd_use_strong_ciphers"],
 "ssh.weak_macs": ["sshd_use_strong_macs", "sshd_strong_macs"],
 "ssh.weak_kex": ["sshd_use_strong_kex", "sshd_strong_kex"],
 "auditd.not_installed": ["package_audit_installed"],
 "auditd.service_inactive": ["service_auditd_enabled"],
 "password_policy.no_quality_module": ["accounts_password_pam_pwquality_enabled"],
 "user_accounts.uid_zero": ["accounts_no_uid_except_zero"],
}


def _index(text: str) -> dict:
    out, cid, ctitle = {}, None, None
    for line in text.splitlines():
        m = re.match(r"\s*- id:\s*(\S+)", line)
        if m and re.match(r"[\d.]+$", m.group(1)):
            cid, ctitle = m.group(1), None
            continue
        mt = re.match(r"\s*title:\s*(.+)", line)
        if mt and cid:
            ctitle = mt.group(1).strip().strip('"')
        mr = re.match(r"\s*-\s*([a-z0-9_]+)\s*$", line)
        if mr and cid and ctitle:
            out.setdefault(mr.group(1), (cid, ctitle))
    return out


def main() -> None:
    idx = {fam: _index(urllib.request.urlopen(_RAW + f, timeout=30).read().decode())
           for fam, f in BENCHES}
    path = Path(__file__).resolve().parent.parent / "bob" / "data" / "cis_refs.json"
    cis = json.loads(path.read_text(encoding="utf-8"))
    for key, rules in MAP.items():
        if key not in cis:
            raise SystemExit(f"unknown BOB key: {key}")
        blocks = {}
        for fam, _f in BENCHES:
            hit = next((idx[fam][r] for r in rules if r in idx[fam]), None)
            if hit:
                blocks[fam] = {"code": hit[0], "title": hit[1]}
        if blocks:
            cis[key]["benchmarks"] = blocks
    path.write_text(json.dumps(cis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote benchmark refs for {len(MAP)} keys")


if __name__ == "__main__":
    main()
