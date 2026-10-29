*[Lire en français](README_DEV_FR.md)*

# BOB — Developer documentation

This document is for people who want to contribute to the project, add a service, add a language, or understand the internal architecture.

---

## Table of contents

1. [Architecture](#architecture)
2. [Project structure](#project-structure)
3. [Running the tests](#running-the-tests)
4. [Adding a service](#adding-a-service)
5. [Adding a language](#adding-a-language)
6. [Code conventions](#code-conventions)
7. [Execution flow](#execution-flow)
8. [Scoring system](#scoring-system)
9. [Internationalisation](#internationalisation)

---

## Architecture

The project is built around one central principle: **separate data collection from business logic**.

Each check module follows the same two-step pattern:

```
SystemSnapshot.from_system()   →   raw data from the system (subprocess calls)
check_xxx(snapshot, t)         →   pure logic, testable without system calls
```

This separation allows the entire business logic to be tested by instantiating snapshots directly in tests, with no mocks and no real system calls.

### Core modules

| Module | Role |
|---|---|
| `__main__.py` | Orchestrator — argument parsing, snapshot collection, calls `run_checks()`, displays summary (~1059 lines) |
| `runner.py` | Audit execution engine — `run_checks()` with `_sec` section closure (57 filterable + 10 always-on sections), `_section_enabled()` (~1326 lines) |
| `cli.py` | Argument parsing — returns an `AuditConfig` dataclass |
| `config.py` | User configuration — `UserConfig` (`~/.config/bob/config.conf`), `EmailStore` |
| `display.py` | Terminal output helpers — `display_result()`, `print_audit_summary()`, etc. |
| `fixes.py` | Fix mode UI — interactive and auto-fix (`-f`/`-y`) |
| `i18n.py` | Internationalisation — `t("key.sub_key")` with dot notation |
| `manage_logs.py` | `--manage-logs` UI — `run_manage_logs()`, `get_or_prompt_log_dir()` |
| `output.py` | Low-level terminal primitives — `print_ok/warn/alert/info/section/banner` |
| `panorama.py` | Services panorama table builder — `build_panorama_rows()` |
| `registry.py` | Service registry — loads `services.json`, exposes `ServiceRegistry` |
| `report.py` | Report file — `AuditReport`, `NullReport`, writes with immediate flush |
| `report_markdown.py` | Markdown/HTML report for email — `MarkdownReport`, `send_html_email()` |
| `scoring.py` | Score engine — `ScoreEngine`, `CheckResult`, `Finding`, `Deduction` |
| `sysinfo.py` | System info — `collect_system_info()`, `detect_network_context()`, `get_user_home()` |
| `compare.py` | Comparative report — `AuditBaseline` (with `finding_keys`), `AuditDelta` (with `new_finding_keys`/`resolved_finding_keys`), `build_baseline()`, `save_baseline()`, `load_baseline()`, `compute_delta()`, `display_delta()` |
| `plugin_checks.py` | Plugin loader — `PluginCheck`, `load_plugin_checks()`, ANSI sanitization |
| `explain.py` | `--explain KEY` — `normalize_key()`, `run_explain()`, 235-key canonical list in 62 prefixes, per-profile prose for 73 keys (server, desktop and container sections for 69 of them, server and desktop for 2, container only for 2 — each shown after the generic text, which every key prints), CIS reference lookup via `cis_refs.py` |
| `cis_refs.py` | CIS benchmark reference lookup — `get_cis_ref(key)`, `get_cis_code(key)`, `_load()` with `lru_cache`; data from `data/cis_refs.json` (235 entries: 120 formal CIS, 101 best-practice, 7 Docker, 7 Kubernetes) |
| `domain_scores.py` | Per-domain sub-scores — `compute_domain_scores()`, `render_domain_scores()`, 6-domain attribution (`backup` → `health_resilience`) |
| `webhook.py` | Webhook delivery — `build_generic_payload()`, `build_slack_payload()`, `send_webhook()`, format auto-detection |
| `correlation.py` | Signal correlation engine — `CorrelationRule` (all_of/any_of frozensets), `CorrelatedFinding`, `run_correlations()`, 6 built-in compound-risk rules |
| `exposure.py` | Port exposure analysis — groups exposed listening services by interface scope and risk level; fw_policy allowlist |
| `recurrence.py` | Recurring finding tracker — `load_recurrence()`, `save_recurrence()`, `update_recurrence()`; consecutive-audit counters at `~/.config/bob/recurrence.json` |

### Cron module

| Module | Role |
|---|---|
| `cron/` | Cron management — `CronEntry`, `list_installed_crons()`, `build_script_content()`, schedule wizard logic (`run_install_cron()` / `run_manage_cron()` dispatchers — plain-text flows + lazy-import curses dispatch) |
| `tui/cron.py` | Curses TUI for cron install and management — `_WizardEntry`, `_draw()`, `_read_key()`, `_run_install_cron_curses()`, `_run_manage_cron_curses()`. Lives under `bob.tui` so the rest of `bob.*` remains importable on systems without curses (v0.4.1 extraction). |
| `_tty.py` | Raw-mode line reader — `read_line(prompt) → str \| None`; Esc returns `None`; TTY fallback to `input()` |

### Check modules (`checks/`)

| Module | What it checks |
|---|---|
| `firewall.py` | UFW status, default policy, IPv6 consistency; `check_rules()` for duplicate/open-any detection; `resolve_firewall_posture()` — the one firewall answer (UFW, firewalld zone target, or a raw DROP/REJECT ruleset) every summary reads (v0.24.1) |
| `firewall_stack.py` | Raw iptables bypass, nftables parallel rules, ip_forward detection |
| `iptables_nftables.py` | iptables/nftables audit when UFW inactive — INPUT/FORWARD policy, loopback and ESTABLISHED/RELATED rules, backend detection (iptables-legacy vs nftables); an INPUT chain whose first rule accepts everything behind a DROP policy is read as accepting everything (v0.25.0) |
| `ipv6.py` | IPv6 listener/UFW-rule consistency; `has_global_ipv6` field; link-local/ULA-only → INFO (not WARN); without UFW, listeners attributed to the governing filter (v0.24.1) |
| `network_context.py` | Network interfaces table, established TCP connections, sensitive remote ports |
| `services.py` | Installed network services, systemd/OpenRC state (incl. socket-activated, v0.18.1, and condition-unmet, v0.24.1), exposure per firewall backend |
| `services_state.py` | Service state: security services enabled at boot but currently inactive |
| `ports.py` | Listening ports via `ss`, classification, deduplication |
| `logs.py` | UFW logs — blocked attempts, bruteforce, top IPs/ports |
| `log_rotation.py` | Log rotation: logrotate config presence, journald persistence, SystemMaxUse, remote rsyslog |
| `auth_log.py` | SSH connection log analysis: successful logins, source IPs, anomalies in auth.log/journald |
| `ddns.py` | Active DDNS clients (ddclient, inadyn, No-IP DUC, DuckDNS), configured domain, crossed with open UFW ports |
| `docker.py` | Docker installation detection, iptables bypass via DOCKER chain, container port exposure |
| `docker_audit.py` | Container hardening, Docker and Podman (v0.20.3): privileged containers, the runtime socket mounted in a container (`docker.sock` / `podman.sock`), host network, containers running as root, Docker's `userns-remap` in `daemon.json` (its fix creates the dockremap user and an ID range of its own, v0.25.0) |
| `kubernetes.py` | Kubernetes node (v0.25.0): pods' rights read through `ctr` (containerd, MicroK8s, k3s) or `crictl` (CRI-O) (privileged, node-handing host paths, host namespaces; kube-system said, not deducted), kubelet anonymous access on 10250 and read-only port 10255; runs only where a kubelet runs |
| `virtualization.py` | Active hypervisors (libvirt/KVM, VirtualBox, VMware, LXD/LXC) and Snap network packages |
| `samba.py` | Samba security audit: SMBv1 disabled, null-password rejection, server signing, `map to guest`, `bind interfaces only` |
| `smtp.py` | SMTP server exposure: MTA detection (Postfix/Exim/Sendmail), listening on all interfaces vs localhost only |
| `hardening.py` | System hardening (sysctl): rp_filter, send_redirects, accept_redirects, syncookies, accept_source_route, log_martians, ICMP broadcast echo, `fs.protected_hardlinks`/`symlinks`/`fifos`/`regular` |
| `kernel_hardening.py` | Kernel hardening (sysctl): ASLR, ptrace_scope, kptr_restrict, dmesg_restrict, suid_dumpable |
| `kernel_modules.py` | Risky kernel modules — filesystems (cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, usb_storage) and network protocols (dccp, sctp, rds, tipc) — + apt kernel update availability + installed kernel listing (filtered on dpkg `ii` state since v0.4.6) |
| `mac_policy.py` | MAC policy (AppArmor / SELinux): framework state, profile counts (enforce/complain/loaded), 0-profile detection |
| `updates.py` | System update status through the host's package manager (cross-distro since v0.19.0): apt (`apt-get -s dist-upgrade`, stale-cache detection, `apt list --upgradable` cross-check — phased-rollout and kept-back packages counted, v0.24.1), `dnf updateinfo list --security`, `zypper list-patches --category security`; pacman/apk have no security channel (pending packages are INFO); unattended-upgrades detection (apt) |
| `ssh/` | SSH security audit (package: `_snapshot`, `_parsers`, `_directives`, `_subchecks`): sshd_config directives, host key strength, user key permissions, authorized_keys, known_hosts |
| `file_perms.py` | Sensitive file permissions: /etc/passwd, /etc/shadow, sudoers (incl. `NOPASSWD:ALL`), `/etc/doas.conf` `permit nopass` (v0.21.3), SSH host keys |
| `suid_audit.py` | SUID/SGID binary audit with whitelist (`config.conf`), targeted-roots scan for performance |
| `user_accounts.py` | User account audit: UID 0 non-root, empty passwords, expired accounts; v0.24.0: `su` restriction (pam_wheel, `su`'s own mode, BusyBox `su`), home directory and `.netrc` permissions, duplicate UIDs and names |
| `password_policy.py` | Password policy: PAM pam_pwquality / pam_cracklib, minlen, PASS_MAX_DAYS, login.defs; the password hashing algorithm (MD5/DES/bigcrypt in `login.defs` or a `pam_unix` stack, v0.24.0) |
| `umask.py` | System umask: /etc/profile, /etc/bash.bashrc, /etc/login.defs, /etc/pam.d/common-session |
| `cron_audit.py` | Cron security: pipe-to-shell, world-writable scripts, range validator |
| `disk.py` | Disk health: SMART health (smartctl), critical SMART attributes, partition usage; NVMe support; skip on all-virtual disks |
| `backup.py` | Backup solution detection: binaries and their artefacts (borg/borgmatic, restic, timeshift, duplicati, rclone, kopia, deja-dup, duplicity, rsnapshot, tarsnap, …) and a backup tool named in a scheduled job; active vs installed-only |
| `memory.py` | Memory & swap: SSD wear detection, unjustified swap usage (swap > 0 while RAM free), swappiness tuning |
| `desktop_apps.py` | Desktop application detection: known GUI apps running as processes (Brave, kDrive, VSCode, ExpressVPN…) |
| `ntp.py` | NTP time synchronisation: systemd-timesyncd/chronyd/ntpd active and synchronised; chrony judged by its `Leap status` line (v0.25.0) |
| `auditd.py` | Linux Audit Framework: installation, service state, loaded rules, sensitive file watches |
| `secure_boot.py` | Secure Boot: UEFI state via mokutil/efivars/bootctl; profile-aware scoring |
| `fail2ban.py` | Fail2ban intrusion prevention: service state, active jails, SSH jail detection; an SSH jail that reads a log file no syslog daemon writes is reported blind (v0.24.4) |
| `clamav.py` | ClamAV antivirus: installation, freshclam DB age, daemon state, last scan age; clamd's local socket reachable by every local user (v0.25.0) |
| `file_integrity.py` | File integrity monitoring: AIDE/Tripwire installation, DB existence, last check recency |
| `rootkit.py` | Rootkit & integrity scan: rkhunter/chkrootkit installation, DB freshness, last scan age |
| `ssl_certs.py` | TLS/SSL certificate expiry: Let's Encrypt, `/etc/ssl/private` (snakeoil filtered), nginx/apache2/postfix configs |
| `systemd_timers.py` | Systemd timer security: pipe-to-shell in ExecStart, world-writable scripts, user-created root timers |
| `firmware.py` | Firmware & microcode: fwupdmgr pending updates, CPU microcode package through the host's package manager (dpkg, rpm, pacman, apk) |
| `systemd_hardening.py` | **v0.13.0** — `systemd-analyze security` exposure score of *running* services; INFO-only, no deduction (most units ship unhardened by default) |
| `container_security.py` | **v0.13.0** — container self-posture read from `/proc` (CapBnd, seccomp mode, uid_map, rootfs writability); whole section suppressed off-container via `skip_if`; **v0.15.4** privileged (−3) / CAP_SYS_ADMIN (−2) / seccomp-off (−1) deduct as operator choices, the rest stays INFO |
| `socket_units.py` | **v0.13.1** — orphan / failed systemd `.socket` units at the systemd × listening-sockets intersection; an empty `Triggers=` is never flagged, a merely inactive backing service is healthy; **v0.15.4** an orphan bound to a non-loopback address deducts (−1), loopback-only stays INFO |
| `cloud_context.py` | **v0.13.1** — host-side cloud exposure (IMDS reachable on-link, world-readable user-data); conservative detection (DMI provider, or cloud-init + on-link IMDS route); suppressed off-cloud, no cloud API; **v0.15.4** world-readable user-data deducts (−2); IMDS reachability stays INFO — IMDSv2 enforcement cannot be read host-side |
| `raspberry_pi.py` | **v0.17.0** — Raspberry Pi board detection (device tree) + provisioning credentials on the FAT boot partition (Imager `userconf.txt`, cloud-init seed), first-boot `ssh` marker, historical `pi` account when it can log in |
| `grub.py` | **v0.21.0** — GRUB bootloader: world/group-readable `grub.cfg` (escalated if it carries a `password_pbkdf2` hash), no boot-menu password (INFO) |
| `cups.py` | **v0.21.0** — CUPS print service: non-loopback `Listen`/`Port` (since v0.25.0 the remediation rewrites the lines BOB read to `Listen localhost:<port>` and restarts CUPS through the host's init system — `cupsctl --no-remote-any` changed nothing on a hand-written `Listen`), Browsing-on (INFO) |
| `mount_hardening.py` | **v0.21.0** — `nodev`/`nosuid`/`noexec` on `/tmp`, `/var/tmp`, `/dev/shm`; a *separate* mount missing them is WARN, a non-separate one INFO (CIS separate-partition trap avoided) |
| `core_dumps.py` | **v0.21.0** (INFO) — `core_pattern`, systemd-coredump `Storage=`, `hard core 0` limits — whether crash dumps could persist |
| `kexec_lockdown.py` | **v0.21.0** (INFO) — `kexec_load_disabled` + `/sys/kernel/security/lockdown` |
| `faillock.py` | **v0.21.0** — PAM account lockout: no `pam_faillock` (or legacy `pam_tally2`) in the auth stack (WARN −1 on server, INFO on desktop/workstation) |
| `disk_encryption.py` | **v0.21.0** — root filesystem on LUKS/dm-crypt via `/proc/mounts` + dm-stack walk (LVM-on-LUKS recognised); WARN on a desktop/workstation plain root, INFO on server, N/A in a container (profile or detected, v0.25.0); **v0.25.0** other local data filesystems and disk swap beside an encrypted root (`/proc/swaps`, swap file by its filesystem, zram skipped) |
| `polkit.py` | **v0.21.0** — polkit rules: a non-root-writable `.rules`/`.pkla` (or `rules.d` dir) is a privesc path (WARN + `chown`/`chmod`); legacy `.pkla` granting `ResultAny=yes` (INFO) |
| `module_blacklist.py` | **v0.22.0** (INFO) — rarely-needed kernel modules (cramfs, udf, usb_storage, dccp, sctp…) neither loaded nor kept from loading by a modprobe.d `blacklist` / `install … /bin/true` (CIS §3.4) |
| `dev_privileged.py` | **v0.22.0** (INFO) — world access on sensitive `/dev` nodes (`/dev/mem`, `/dev/kmem`, `/dev/port`, raw block devices), stat-only |
| `root_path.py` | **v0.22.0** — root's configured PATH (`login.defs` `ENV_SUPATH`, sudoers `secure_path`): world-writable, `.` or relative components |
| `package_integrity.py` | **v0.23.0** (INFO, `--exhaustive` only) — packaged files differing from the manager's recorded digest: `rpm -Va` / `debsums -c` / `apk audit` / `pacman -Qkk`, config files filtered; bounded + group-killed |
| `file_capabilities.py` | **v0.24.0** — `security.capability` xattrs read directly (no `getcap` dependency) on the SUID scan roots: a root-equivalent capability outside the measured distro grants → WARN, any other → INFO; on an RPM host the package database decides (`rpm -qf`, v0.25.0) |
| `cpu_security.py` | **v0.24.0** — the kernel's own verdict in `/sys/devices/system/cpu/vulnerabilities` ("Vulnerable" → WARN), mitigation-disabling boot switches and IOMMU (x86) → INFO |
| `package_authenticity.py` | **v0.24.0** — written-down switches that disable package authentication: apt `trusted=yes` / `AllowUnauthenticated`, dnf/zypper `gpgcheck=0` (incl. `/usr/etc/zypp/zypp.conf`), pacman `SigLevel Never`/`Optional`, apk `allow-untrusted` → WARN |
| `crypto_policy.py` | **v0.24.0** — crypto-policies, the *applied* policy judged (`state/current` over `config`): `LEGACY` → WARN; weakening module, dated or unknown policy, configured ≠ applied, mechanism absent → INFO |
| `world_writable.py` | **v0.24.0** (INFO, `--exhaustive` only) — `find -xdev` (GNU or BusyBox) over local on-disk filesystems: world-writable files, non-sticky world-writable directories, unowned files; a path other accounts cannot traverse is reported as latent |

---

## Project structure

```
bob/
├── __init__.py
├── __main__.py          # Orchestrator (~1009 lines — pure coordination)
├── _atomic.py           # Crash-safe writes (atomic_write) and bounded reads (read_text_capped)
├── _fs.py               # strict_is_file/dir/symlink — a denied path raises instead of reading as absent
├── _i18n_safe.py        # i18n safety helpers — shared fallback patterns
├── _paths.py            # Path resolution for data files
├── _privilege.py        # privilege_prefix(), with_privilege() — sudo, else doas, in printed commands (v0.25.0)
├── _python_support.py   # DEPRECATED_PYTHON, deprecation_for() — the Python versions being phased out and until when (0.25.1)
├── _sandbox.py          # Plugin sandbox runner (v0.7.0 T3) — rlimits, import allowlist, wall-clock timeout
├── _sysctl_apply.py     # Applying a sysctl setting without a shell
├── _tty.py              # read_line() — raw-mode line reader with Esc-to-cancel, TTY fallback to input()
├── _v0160_renames.py    # v0.16.0 finding-key renames — shared map
├── _v090_renames.py     # v0.9.0 section renames — shared map
├── _v100_subcheck_renames.py # v0.10.0 sub-check renames — shared map + ignore.yml back-compat shim
├── breakdown.py         # Score breakdown engine — full per-deduction trace for --breakdown / -B
├── cis_refs.py          # CIS reference lookup — get_cis_ref(), get_cis_code() with lru_cache
├── cli.py               # AuditConfig + parse_args()
├── compare.py           # AuditBaseline (finding_keys) + AuditDelta (new/resolved keys) + comparative report
├── completion.py        # bash completion installer — `bob --install-completion`
├── config.py            # UserConfig, EmailStore
├── correlation.py       # CorrelationRule + run_correlations() — 6 compound-risk rules
├── cron/                # CronEntry, schedule wizard logic, build_script_content()
├── csv_output.py        # CSV output formatter (--format csv)
├── display.py           # Terminal output helpers (display_result, print_audit_summary…)
├── domain_scores.py     # compute_domain_scores(), render_domain_scores() — backup→health_resilience attribution
├── explain.py           # run_explain(), normalize_key(), EXPLAIN_KEYS — 235 keys in 62 prefixes
├── exposure.py          # Port exposure grouping — interface scope + risk level
├── fixes.py             # Fix mode UI (interactive + auto-fix)
├── formatter.py         # bob.formatter — locale-independent rendering via Finding.template_vars (v0.4.1)
├── history.py           # Score history tracking — sparkline display for --history
├── html_output.py       # build_html_output() — standalone HTML export (--html)
├── i18n.py              # t(key) with dot notation
├── ignore.py            # Persistent finding-key ignore list (~/.config/bob/ignore.yml)
├── json_output.py       # JSON output formatter (--json / --json-full) with schema_version=3
├── manage_logs.py       # --manage-logs UI, get_or_prompt_log_dir()
├── markdown_output.py   # Markdown output formatter (--format markdown)
├── output.py            # Low-level terminal primitives
├── panorama.py          # build_panorama_rows()
├── platform.py          # machine(), Raspberry Pi model from the device tree, boot firmware directory (v0.17.0)
├── plugin_checks.py     # PluginCheck + load_plugin_checks()
├── profiles.py          # Audit profile loader (server/workstation/desktop/container + user profiles)
├── recurrence.py        # Recurring finding tracker — consecutive-audit counters
├── registry.py          # ServiceRegistry.load()
├── report.py            # AuditReport + NullReport
├── report_markdown.py   # MarkdownReport, HTML email
├── runner.py            # Audit execution engine — run_checks() with _sec section closure (57 filterable + 10 always-on)
├── scoring.py           # ScoreEngine, CheckResult, Finding, Deduction
├── sysinfo.py           # collect_system_info(), detect_network_context(), get_user_home()
├── visibility.py        # VISIBILITY_KEYS — findings that mean BOB could not see part of the host
├── watch.py             # --watch=N mode — re-run audit every N seconds
├── webhook.py           # build_generic_payload(), build_slack_payload(), send_webhook()
├── tui/
│   ├── __init__.py      # bob.tui — optional curses subpackage (v0.4.1)
│   └── cron.py          # Curses TUI for --install-cron / --manage-cron
├── checks/
│   ├── __init__.py
│   ├── _awall.py           # AwallStatus — awall installed, its enabled policies
│   │                       #   (`awall list`), read where no UFW/firewalld runs (0.26.0)
│   ├── _firewalld.py       # FirewalldStatus — firewall-cmd state/zone/services,
│   │                       #   shared by firewall, iptables_nftables, ports,
│   │                       #   ipv6 and services so a firewalld host is not read
│   │                       #   as "wide open / UFW not installed" (v0.20.2)
│   ├── _run.py             # Shared _run() subprocess helper + C locale env,
│   │                       #   run_result() — stdout *and* exit status, for
│   │                       #   callers that must not read "could not run" as
│   │                       #   "nothing found" (v0.15.2),
│   │                       #   unit_active_state() — a unit's state or None
│   │                       #   when systemd was never asked (v0.15.2),
│   │                       #   path_exists() — Path.exists() re-raises EACCES;
│   │                       #   one bare call lost a whole audit (v0.15.2),
│   │                       #   split_ss_address() — one grammar for the `ss`
│   │                       #   address column, shared by ports and
│   │                       #   network_context (v0.15.2),
│   │                       #   package_installed() — dpkg-query, rpm, pacman
│   │                       #   or apk; dpkg alone read every service as
│   │                       #   absent on 4 distros out of 5 (v0.15.2),
│   │                       #   join_continuations(), strip_unit_glyph(),
│   │                       #   pipes_into_shell() — one copy of each rule,
│   │                       #   config_drifted() — systemd answers in whole
│   │                       #   seconds and st_mtime does not; four ms of
│   │                       #   artefact muted a whole section (v0.17.1),
│   │                       #   append_once(), sysctl_fix_cmd() — advice that
│   │                       #   is safe to apply twice, and one filename for
│   │                       #   one setting (v0.17.1),
│   │                       #   ssh_unit() — the unit is `ssh` on Debian and
│   │                       #   `sshd` on Arch, Fedora, RHEL, openSUSE; no
│   │                       #   static name works on all of them (v0.17.1)
│   ├── _ufw.py             # `ufw status numbered` grammar, shared by ports,
│   │                       #   services, ipv6, ddns and firewall (v0.15.1)
│   ├── firewall.py         # FirewallStatus + check_firewall() + check_rules()
│   ├── firewall_stack.py   # FirewallStackSnapshot + check_firewall_stack()
│   ├── iptables_nftables.py # IptablesNftablesSnapshot + check_iptables_nftables() — raw firewall audit
│   ├── ipv6.py             # IPv6Snapshot + check_ipv6()
│   ├── network_context.py  # NetworkContextSnapshot + check_network_context()
│   ├── services.py         # ServiceSnapshot + check_services()
│   ├── services_state.py   # ServicesStateSnapshot + check_services_state()
│   ├── ports.py            # PortsSnapshot + check_ports()
│   ├── logs.py             # LogsSnapshot + check_logs()
│   ├── log_rotation.py     # LogRotationSnapshot + check_log_rotation()
│   ├── auth_log.py         # AuthLogSnapshot + check_auth_log() — SSH auth log analysis
│   ├── ddns.py             # DdnsSnapshot + check_ddns()
│   ├── docker.py           # DockerSnapshot + check_docker()
│   ├── docker_audit.py     # DockerAuditSnapshot + check_docker_audit() — daemon + container hardening
│   ├── kubernetes.py       # KubernetesSnapshot + check_kubernetes() — node pods' rights + kubelet anonymous access
│   ├── virtualization.py   # VirtSnapshot + check_virtualization()
│   ├── samba.py            # SambaSnapshot + check_samba() — SMBv1, signing, map-to-guest
│   ├── smtp.py             # SmtpSnapshot + check_smtp() — MTA exposure
│   ├── hardening.py        # HardeningSnapshot + check_hardening() — sysctl net.* / fs.*
│   ├── kernel_hardening.py # KernelHardeningSnapshot + check_kernel_hardening() — sysctl kernel.*
│   ├── kernel_modules.py   # KernelModulesSnapshot + check_kernel_modules() — risky modules + apt kernel update
│   ├── mac_policy.py       # MacPolicySnapshot + check_mac_policy() — AppArmor / SELinux
│   ├── updates.py          # UpdatesSnapshot + check_updates() — security updates per package manager (apt, dnf, zypper) + apt stale cache
│   ├── ssh/                # SSHSnapshot + check_ssh() — package: _snapshot, _parsers, _directives, _subchecks
│   ├── file_perms.py       # FilePermsSnapshot + check_file_perms()
│   ├── suid_audit.py       # SuidSnapshot + check_suid_audit() — SUID/SGID with whitelist
│   ├── user_accounts.py    # UserAccountsSnapshot + check_user_accounts()
│   ├── password_policy.py  # PasswordPolicySnapshot + check_password_policy()
│   ├── umask.py            # UmaskSnapshot + check_umask() — login.defs, common-session
│   ├── cron_audit.py       # CronAuditSnapshot + check_cron_audit()
│   ├── disk.py             # DiskSnapshot + check_disk() — SMART, partitions, NVMe
│   ├── backup.py           # BackupSnapshot + check_backup() — backup tools: binaries, artefacts, scheduled jobs
│   ├── memory.py           # MemorySnapshot + check_memory() — SSD wear, swappiness
│   ├── desktop_apps.py     # DesktopAppsSnapshot + check_desktop_apps() — GUI app detection
│   ├── ntp.py              # NtpSnapshot + check_ntp() — time sync status
│   ├── auditd.py           # AuditdSnapshot + check_auditd() — Linux Audit Framework
│   ├── secure_boot.py      # SecureBootSnapshot + check_secure_boot() — UEFI state
│   ├── fail2ban.py         # Fail2banSnapshot + check_fail2ban() — service, jails, SSH jail
│   ├── clamav.py           # ClamAVSnapshot + check_clamav() — DB freshness, last scan, clamd socket (v0.25.0)
│   ├── file_integrity.py   # FileIntegritySnapshot + check_file_integrity() — AIDE/Tripwire
│   ├── rootkit.py          # RootkitSnapshot + check_rootkit() — rkhunter/chkrootkit
│   ├── ssl_certs.py        # SslCertsSnapshot + check_ssl_certs() — cert expiry
│   ├── systemd_timers.py   # SystemdTimersSnapshot + check_systemd_timers() — timer security
│   ├── firmware.py         # FirmwareSnapshot + check_firmware() — fwupd + microcode
│   ├── systemd_hardening.py    # ServiceHardeningSnapshot + check_service_hardening() (v0.13.0)
│   ├── container_security.py   # ContainerSecuritySnapshot + check_container_security() (v0.13.0)
│   ├── socket_units.py         # SocketUnitsSnapshot + check_socket_units() (v0.13.1)
│   ├── cloud_context.py        # CloudContextSnapshot + check_cloud_context() (v0.13.1)
│   ├── raspberry_pi.py         # RaspberryPiSnapshot + check_raspberry_pi() — board + boot-partition creds (v0.17.0)
│   ├── grub.py                 # GrubSnapshot + check_grub() — grub.cfg perms + boot password (v0.21.0)
│   ├── cups.py                 # CupsSnapshot + check_cups() — print service exposure (v0.21.0)
│   ├── mount_hardening.py      # MountHardeningSnapshot + check_mount_hardening() — nodev/nosuid/noexec (v0.21.0)
│   ├── core_dumps.py           # CoreDumpsSnapshot + check_core_dumps() — crash-dump persistence (v0.21.0)
│   ├── kexec_lockdown.py       # KexecLockdownSnapshot + check_kexec_lockdown() — kexec + lockdown (v0.21.0)
│   ├── faillock.py             # FaillockSnapshot + check_faillock() — PAM account lockout (v0.21.0)
│   ├── disk_encryption.py      # DiskEncryptionSnapshot + check_disk_encryption() — LUKS/dm-crypt root (v0.21.0), data and swap beyond / (v0.25.0)
│   ├── polkit.py               # PolkitSnapshot + check_polkit() — writable polkit rules (v0.21.0)
│   ├── module_blacklist.py     # ModuleBlacklistSnapshot + check_module_blacklist() — modprobe.d blacklist (v0.22.0)
│   ├── dev_privileged.py       # DevPrivilegedSnapshot + check_dev_privileged() — sensitive /dev nodes (v0.22.0)
│   ├── root_path.py            # RootPathSnapshot + check_root_path() — root's configured PATH (v0.22.0)
│   ├── package_integrity.py    # PackageIntegritySnapshot + check_package_integrity() — --exhaustive (v0.23.0)
│   ├── file_capabilities.py    # FileCapabilitiesSnapshot + check_file_capabilities() — file capabilities (v0.24.0)
│   ├── cpu_security.py         # CpuSecuritySnapshot + check_cpu_security() — kernel CPU-vulnerability verdict (v0.24.0)
│   ├── package_authenticity.py # PackageAuthenticitySnapshot + check_package_authenticity() — signature switches (v0.24.0)
│   ├── crypto_policy.py        # CryptoPolicySnapshot + check_crypto_policy() — crypto-policies (v0.24.0)
│   └── world_writable.py       # WorldWritableSnapshot + check_world_writable() — --exhaustive (v0.24.0)
├── data/
│   ├── services.json            # Declarative registry of the 38 services
│   ├── cis_refs.json            # CIS benchmark references — 235 entries {ref, code}
│   ├── profiles/                # Built-in audit profiles: server, desktop, workstation, container (.conf)
│   ├── schemas/                 # JSON Schemas: service entry, services list, plugin file
│   └── bob.bash-completion  # Bash completion script
└── locales/
    ├── en.json          # English translation keys
    └── fr.json          # French translation keys

tests/                   # one file per check module, release guards (test_v0XYZ_*.py) and the mutation registry (mutations.py) — a selection:
├── helpers.py           # Shared test utilities: _t, levels, _has_finding, _get_finding, _deduction_keys…
├── test_check_rules.py
├── test_cli.py
├── test_compare.py
├── test_config.py
├── test_cron.py
├── test_ddns.py
├── test_degraded.py
├── test_docker.py
├── test_email_store_mgmt.py
├── test_firewall.py
├── test_firewall_stack.py
├── test_fixes.py
├── test_hardening.py
├── test_i18n.py
├── test_ipv6.py
├── test_logs.py
├── test_network_context.py
├── test_output.py
├── test_plugin_checks.py
├── test_ports.py
├── test_registry.py
├── test_report.py
├── test_scoring.py
├── test_services.py
├── test_sysinfo.py
├── test_virtualization.py
├── test_updates.py
├── test_explain.py
├── test_domain_scores.py
├── test_webhook.py
├── test_user_accounts.py
├── test_password_policy.py
├── test_display_explain_hint.py
├── test_disk.py
├── test_memory.py
├── test_desktop_apps.py
├── test_ntp.py
├── test_fail2ban.py
├── test_rootkit.py
├── test_exit_codes.py
├── test_ssl_certs.py
├── test_systemd_timers.py
├── test_firmware.py
├── test_html_output.py
├── test_correlation.py
├── test_exposure.py
├── test_recurrence.py
├── test_manage_logs.py
├── test_iptables_nftables.py
└── test_cis_refs.py

pyproject.toml                     # Build config (setuptools, pip/pipx install)
README.md / README_FR.md           # User documentation (EN/FR)
CHANGELOG.md / CHANGELOG_FR.md     # Release table (EN/FR)
SECURITY.md / SECURITY_FR.md       # Threat model and vulnerability disclosure (EN/FR)
DOCUMENTS/                         # README_TECH, README_DEV (this file), TUTORIAL, AUTOMATION, TESTING,
                                   #   CHANGELOG_FULL, CONVENTIONS, DOCTRINE, RASPBERRY_PI (EN and FR),
                                   #   SNAPSHOT and DISTRO_MATRIX (EN only)
man/                               # bob.1, bob.conf.5, bob-profile.5
debian/ · packaging/rpm/           # Debian source package · RPM spec
scripts/                           # mutate.py (mutation bench), lint_locales.py, regen_loc.py, gen_cis_benchmarks.py
ci/arm64_smoke.sh                  # arm64 smoke run of the Integration workflow
```

---

## Running the tests

### Prerequisites

```bash
python3 --version   # 3.10+ required
```

BOB itself has no PyPI dependency (stdlib only). The suite needs `pytest`; `jsonschema` is optional — without it the schema tests are skipped.

### Run all tests

```bash
cd bodyguard-of-bits
python3 -m pytest tests/ -v
```

### Run a specific module

```bash
python3 -m pytest tests/test_scoring.py -v
python3 -m pytest tests/test_logs.py -v
```

### Without pytest

Not possible: the suite is written for pytest (plain test functions, fixtures, `parametrize`) — `python3 -m unittest tests/test_firewall.py` runs 0 tests.

### Expected result

```
NNNNN passed in X.XXs
```

Every collected test passes (a few skip when an optional tool such as `jsonschema` is absent); `python3 -m pytest --collect-only -q | tail -n 1` gives the live count.

Check logic is tested on snapshots built in the test files, so the suite runs without `sudo` and without UFW. A few guards start a real subprocess on purpose: pytest's own collection (`test_v0134_docs_accuracy.py`, `test_v0164_mutation_contract.py`), the locale linter (`test_v082_items.py`), and `python3 -m bob` (`--help` and similar, e.g. `test_explain.py`).

---

## Adding a service

Everything happens in `bob/data/services.json`. No Python code changes are needed for services with standard detection.

### Service entry structure

```json
{
  "id": "my_service",
  "label": "My Service",
  "packages": ["my-service"],
  "services": ["my-service"],
  "ports": ["1234/tcp"],
  "risk": "medium",
  "detection": {
    "binary": [],
    "snap": [],
    "config_files": []
  }
}
```

### Fields (all required except `detection`)

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique identifier, snake_case |
| `label` | string | Name displayed on screen |
| `packages` | array | Package names to detect (queried through dpkg, rpm, pacman or apk) |
| `services` | array | Service unit names (systemd, or OpenRC since v0.18.0) |
| `ports` | array | Default ports — format `"number/proto"` |
| `risk` | string | `"critical"`, `"high"`, `"medium"`, `"low"` |
| `detection` | object | Optional — alternative detection methods (`binary`, `snap`, `config_files`) |

### Risk levels

| Value | Meaning | Effect |
|---|---|---|
| `critical` | Highly sensitive service | Risk context displayed; a port open to the internet is an ALERT deducting 2 points, 3 when the host has a public IP or an active DDNS client |
| `high` | Sensitive service | Same as `critical`: risk context displayed; ALERT, 2 points, 3 with a public IP or DDNS |
| `medium` | Standard service | No risk context; a port open to the internet is a WARN deducting 1 point |
| `low` | Internal service | No risk context; a port open to the internet is a WARN deducting 1 point |

### Detection via binary or snap

For services without a standard dpkg package:

```json
"detection": {
  "binary": ["/usr/local/bin/my-service"],
  "snap": ["my-service-snap"],
  "config_files": []
}
```

### Auto-detected port from config file

If the service can listen on a configurable port, name its configuration file — BOB parses it whenever one is declared:

```json
"detection": {
  "config_files": ["/etc/my-service/my-service.conf"]
}
```

The `services.py` module will attempt to extract the port from common patterns (`port = 1234`, `listen = 1234`, etc.).

### Adding risk context (critical/high services only)

For `critical` or `high` services, add the keys to both locale files.

The key is built from the label: lowercase, spaces → `_`, `/` → `_`, `(` and `)` removed.

Example for `"label": "My Service (daemon)"` → key `my_service_daemon`:

In `locales/en.json`:
```json
"service_risk": {
  "my_service_daemon": {
    "level": "HIGH",
    "exposure": "Description of the exposure vector",
    "threat": "Description of the potential threat"
  }
}
```

In `locales/fr.json`:
```json
"service_risk": {
  "my_service_daemon": {
    "level": "ÉLEVÉ",
    "exposure": "Description du vecteur d'exposition",
    "threat": "Description de la menace potentielle"
  }
}
```

### Verify key parity

After any change to the locales:

```bash
python3 -c "
import json
def keys(d, p=''):
    out = []
    for a, v in d.items():
        f = f'{p}.{a}' if p else a
        out += keys(v, f) if isinstance(v, dict) else [f]
    return out
en = keys(json.load(open('bob/locales/en.json')))
fr = keys(json.load(open('bob/locales/fr.json')))
print(f'EN keys: {len(en)}')
print(f'FR keys: {len(fr)}')
missing = set(en) - set(fr)
print(f'Missing in FR: {missing if missing else \"none\"}')
print(f'Same order: {en == fr}')
"
```

Expected output — the two files hold the same keys **in the same order**:
```
EN keys: 3090
FR keys: 3090
Missing in FR: none
Same order: True
```

---

## Adding a language

### 1. Create the locale file

```bash
cp bob/locales/en.json bob/locales/de.json
```

### 2. Translate all values

The file contains exactly 3090 keys organised into sections (verified with `bob/locales/en.json` vs `fr.json` strict-parity test). Translate all values while keeping `{variable}` placeholders intact.

Example:
```json
"ports.listening_count": "{count} listening port(s) detected on this system"
```
becomes:
```json
"ports.listening_count": "{count} lauschende(r) Port(s) auf diesem System erkannt"
```

### 3. Declare the language

Append `"de"` to `SUPPORTED_LANGS` in `bob/i18n.py` (currently `("en", "fr")`). An undeclared code falls back to English, with a warning.

### 4. Add the CLI flag

In `bob/cli.py`, add the option in `parse_args()`:

```python
elif arg in ("--german", "--deutsch"):
    config.lang = "de"
```

### 5. Verify parity

```bash
python3 -c "
import json
def keys(d, p=''):
    k = set()
    for a,v in d.items():
        f = f'{p}.{a}' if p else a
        k |= keys(v,f) if isinstance(v,dict) else {f}
    return k
en = keys(json.load(open('bob/locales/en.json')))
de = keys(json.load(open('bob/locales/de.json')))
missing = en - de
print(f'Missing: {missing if missing else \"none\"}')
"
```

---

## Code conventions

Moved to **[CONVENTIONS.md](CONVENTIONS.md)** in v0.16.4, where they sit
beside the graphic charter — what a colour means, what a symbol means —
which had never been written down at all. One document answers "how does
this project do things"; this one stays about the architecture.

## Execution flow

```
main()
  │
  ├── parse_args()                 → AuditConfig
  ├── i18n.init(lang)              → load locales
  ├── standalone commands (--version, --explain, --history, --manage-logs,
  │   cron, completion, ignore list…) run here and return
  ├── ServiceRegistry.load()       → services.json + user plugins
  ├── UserConfig.load()            → ~/.config/bob/config.conf
  ├── AuditReport.open() / .null()
  ├── ScoreEngine(profile=active_profile)
  │
  ├── run_checks(config, t, engine, report, registry, network_context, …)   ← runner.py
  │     for each section (57 filterable + 10 always-on), through the _sec closure:
  │       skipped when the profile or --check / --skip excludes it
  │       snapshot = XxxSnapshot.from_system()     (skip_if may drop the section)
  │       result   = check_xxx(snapshot, t)
  │       engine.apply(result, section)            → profile overrides applied first
  │       display_result(result, report, …)
  │       an exception degrades that one section, never the audit
  │
  ├── engine.finalize()                     → final score
  ├── set_posture_from_engine(engine, …)    → risk-level floor
  ├── update_recurrence() → save_recurrence()
  ├── run_correlations(engine, t)           ← correlation.py
  ├── send_webhook(…)                       when configured (not with --offline)
  ├── save_baseline(…)                      ← compare.py
  ├── print_audit_summary(engine, …)        ← display.py
  ├── render_domain_scores(…)               ← domain_scores.py
  ├── display_delta(compute_delta(…))       ← compare.py
  ├── build_risk_context_entries(…)         ← display.py
  ├── report.close()
  └── save_score(…)                         ← history.py
```

---

## Scoring system

### Score calculation

The score starts at 10/10. Each `Deduction` subtracts points. After all checks run, the global score is replaced by the mean of the active domain scores, capped at 9 when any deduction was applied (v0.12.0 F1: 10/10 is kept for an audit with nothing to fix).

```python
engine = ScoreEngine(profile=active_profile)   # v0.14.0: the engine carries the profile
engine.apply(check_result)              # applies profile overrides, then findings, deductions and caps
                                        # (a check caps the score with result.set_cap(maximum=3,
                                        #  reason=..., key="firewall.inactive"); apply forwards it
                                        #  to engine.cap(maximum, reason, key))
engine.finalize()                       # apply cap, clamp to [0, 10]
apply_domain_score_override(engine)     # global = mean of active domain scores, capped at 9
                                        # if any deduction was applied — MUST follow finalize()

score = engine.score         # int 0–10 — domain-averaged if override set
level = engine.level         # RiskLevel.LOW / MEDIUM / HIGH / CRITICAL
raw   = engine._raw_score    # pre-override raw deduction total (debug only)
```

**Orchestrator contract:** `apply_domain_score_override(engine)` from `bob.domain_scores` must be called after `engine.finalize()`. Before that call, `engine.score` returns the raw deduction-based score. Do not call `engine.set_global_score()` directly.

**Active domain set:** a domain counts as "active" in the global average as soon as any check from it emits a `OK`, `WARN`, or `ALERT` finding (or a keyed deduction). `INFO`-only findings (purely advisory observations) do not promote a domain on their own — they're explicitly excluded so domains with only informational notices stay hidden. The `OK` inclusion is the v0.4.6 fix (Bug 2): before it, a domain that went clean after remediation (only `updates.ok` left after `apt upgrade`) dropped out of the active set and the global score *decreased* despite the system being strictly more secure.

**Equal domain weighting:** all active domains contribute equally to the global average — there is no per-domain weight. A machine where only SSH is degraded and all others score 10/10 benefits from dilution; a machine with all six domains active gives the same weight to firewall as to health & resilience. This is an intentional design choice retained through v0.4.x.

**`ScoreCap.key`:** caps carry a `key` field propagated to their synthetic breakdown deduction, enabling domain attribution for cap-triggered deductions.

### Network context

The `"public"` context (a direct internet-facing IP) and `"ddns"` (an active DDNS client exposing an unrestricted port) weigh exposure more: an internet-exposed high/critical service deducts 3 points instead of 2, an uncovered open port 2 instead of 1. The check reads the context and chooses the points:

```python
result.add_deduction(reason="...", points=2, context="public")
```

### Risk levels

| Score | Level |
|---|---|
| 8–10 | LOW |
| 5–7 | MEDIUM |
| 3–4 | HIGH |
| 0–2 | CRITICAL |

---

## Internationalisation

### Accessing translations

```python
from bob.i18n import t

# Simple key
t("firewall.active")
# → "UFW firewall is active"

# Key with variable
t("ports.listening_count", count=17)
# → "17 listening port(s) detected on this system"
```

### Missing key

If a key does not exist, `t()` returns `"[missing.key]"` — never an exception. This makes incremental development easier.

### Data file location

Locale files and `services.json` are read from the `locales/` and `data/` directories relative to the Python module (`Path(__file__).parent`). This works both in development and with pipx (which includes the package data files in the isolated environment).

`$BOB_SHARE` can point to a shared data directory (e.g. `/usr/local/share/bob/`) for system-package installs. When set to an existing absolute directory it takes priority over the in-package path; otherwise BOB falls back to the package-relative `locales/` and `data/`. Resolution lives in `bob/_paths.py` (strict — a missing, relative, or unsafe path is ignored with a warning). Not used by pipx installs.

```python
# bob/_paths.py — share-dir resolution
share = os.environ.get("BOB_SHARE", "").strip()
if share:
    resolved = Path(share).resolve(strict=True)   # ignored if missing / not absolute
    # → resolved / "locales", resolved / "data"
```

> The legacy `UFW_AUDIT_SHARE` alias was deprecated in v0.5.4 and **removed** in v0.6.0 — use `BOB_SHARE`.

---

## Environment variables

| Variable | Effect |
|---|---|
| `BOB_SHARE` | Shared data directory (locales, services.json) — overrides in-package path when set to an existing absolute dir; not used by pipx installs. (Legacy `UFW_AUDIT_SHARE`: deprecated in v0.5.4, removed in v0.6.0.) |
| `SUDO_USER`, `DOAS_USER` | Real user under sudo or (0.25.1) doas — used for config path and report |
| `NO_COLOR` | Disables ANSI colours (standard) |
| `FORCE_COLOR` | Forces colour on even when stdout is not a terminal (v0.14.0) |
| `BOB_DEBUG` | Full traceback on an internal error, and a logging handler that makes BOB's `logger` warnings visible (a skipped plugin entry, for instance) |
| `BOB_WEBHOOK_ALLOW_INSECURE` | `1` allows a plain `http://` webhook URL (webhooks are HTTPS-only since v0.7.1) |

---

© 2026 Cédric Clauzel
