*[Lire en français](TESTING_FR.md)*

# BOB — Test plan: dangerous UFW rules

Manual regression tests using deliberately dangerous UFW rules.
Each test verifies that BOB correctly detects (and fixes) a specific misconfiguration.

---

## Unit test history

| Version | Tests | Notes |
|---------|-------|-------|
| v0.1.0  | 4200  | Initial release — 65 test files; 39 new tests in `test_cis_refs.py` (CIS benchmark mapping); full coverage across all 46 checks |

---

### v0.1.0 — 4200/4200 (2026-04-26)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4200 passed in 4.93s
```

#### Test files (65 total)

| File | Tests | Domain |
|------|-------|--------|
| `test_cis_refs.py` | 39 | CIS benchmark mapping |
| `test_iptables_nftables.py` | 51 | Firewall stack (CHECK 46) |
| `test_firewall.py` | — | UFW rules audit |
| `test_ssh.py` | — | SSH configuration |
| `test_hardening.py` | — | Kernel hardening sysctl |
| `test_kernel_hardening.py` | — | Kernel hardening extended |
| `test_kernel_modules.py` | — | Kernel module audit |
| `test_services.py` | — | Service registry + risk |
| `test_services_state.py` | — | Service state audit |
| `test_docker.py` | — | Docker UFW bypass |
| `test_docker_audit.py` | — | Docker daemon hardening |
| `test_ports.py` | — | Port classification |
| `test_exposure.py` | — | Port exposure analysis |
| `test_scoring.py` | — | Scoring engine |
| `test_domain_scores.py` | — | Domain scores |
| `test_explain.py` | — | --explain TUI |
| `test_display_explain_hint.py` | — | CIS hint display |
| `test_cli.py` | — | CLI argument parsing |
| `test_exit_codes.py` | — | Exit code logic |
| `test_correlation.py` | — | Signal correlation |
| `test_recurrence.py` | — | Recurring findings |
| `test_compare.py` | — | Diff/baseline |
| `test_history.py` | — | Score history |
| `test_ignore.py` | — | Ignore list |
| `test_fixes.py` | — | --fix / --apply |
| `test_auth_log.py` | — | Auth log analysis |
| `test_ufw_logging.py` | — | UFW logging level |
| `test_log_rotation.py` | — | Log rotation |
| `test_cron.py` | — | Cron scheduling |
| `test_cron_audit.py` | — | Cron job security |
| `test_manage_logs.py` | — | Log management TUI |
| `test_webhook.py` | — | Webhook notifications |
| `test_profiles.py` | — | Audit profiles |
| `test_registry.py` | — | Service registry |
| `test_config.py` | — | Configuration store |
| `test_sysinfo.py` | — | System information |
| `test_network_context.py` | — | Network context |
| `test_degraded.py` | — | Degraded mode (ss/rules/log absent) |
| `test_output.py` | — | Terminal output |
| `test_markdown_output.py` | — | Markdown output |
| `test_html_output.py` | — | HTML output |
| `test_csv_output.py` | — | CSV output |
| `test_report.py` | — | Report generation |
| `test_min_level.py` | — | --min-level filter |
| `test_watch.py` | — | --watch mode |
| `test_check_rules.py` | — | Rule validation |
| `test_file_perms.py` | — | File permissions |
| `test_suid_audit.py` | — | SUID/SGID audit |
| `test_user_accounts.py` | — | User accounts |
| `test_password_policy.py` | — | Password policy |
| `test_umask.py` | — | System umask |
| `test_updates.py` | — | System updates |
| `test_ntp.py` | — | NTP sync |
| `test_fail2ban.py` | — | Fail2ban |
| `test_rootkit.py` | — | Rootkit scan |
| `test_auditd.py` | — | Audit daemon |
| `test_secure_boot.py` | — | Secure Boot |
| `test_file_integrity.py` | — | File integrity |
| `test_clamav.py` | — | ClamAV |
| `test_mac_policy.py` | — | AppArmor/SELinux |
| `test_backup.py` | — | Backup detection |
| `test_disk.py` | — | Disk health |
| `test_memory.py` | — | Memory/swap |
| `test_ssl_certs.py` | — | TLS cert expiry |
| `test_systemd_timers.py` | — | Systemd timers |
| `test_desktop_apps.py` | — | Desktop apps |
| `test_samba.py` | — | Samba hardening |
| `test_ddns.py` | — | DDNS detection |
| `test_firmware.py` | — | Firmware/microcode |
| `test_smtp.py` | — | SMTP exposure |
| `test_ipv6.py` | — | IPv6 consistency |
| `test_virtualization.py` | — | Virtualization detection |
| `test_email_store_mgmt.py` | — | Email store management |
| `test_recurrence.py` | — | Recurrence tracking |
| `tests/helpers.py` | — | Shared test utilities |

---


**Test VM:** Linux Mint 22.3 — `so6minttest`
**Reference state** (clean baseline after each test):

```bash
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80
sudo ufw enable
```

---

## Category A — Open-any wildcards

Rules that open all ports to all sources — highest severity.

### A1 — Full wildcard `Anywhere ALLOW IN Anywhere`

```bash
sudo ufw allow from any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.1.0.0 |
| `-2` score deduction | ✔ |
| Fix proposed: `sudo ufw --force delete N` | ✔ |
| Fix applied correctly | ✔ v0.1.0 |
| **IPv6 rule also detected and fixed** (`Anywhere (v6) ALLOW IN Anywhere (v6)`) | ✔ v0.1.0 |

**Root cause fixed :** `ufw status numbered` pads lines with trailing spaces — the `$` anchor in the regex never matched. Fixed: `Anywhere$` → `Anywhere\s*$`. (commit `8ccd9b6`)

**Root cause fixed :** IPv6 wildcard rules (`Anywhere (v6) ALLOW IN Anywhere (v6)`) escaped detection — `open_any_pattern` did not account for the `(v6)` suffix. Fixed: pattern extended with `(?:\s+\(v6\))?` on both sides. Both IPv4 and IPv6 rules are now flagged and fixed independently.

---

### A2 — TCP wildcard `Anywhere/tcp ALLOW IN Anywhere/tcp`

```bash
sudo ufw allow proto tcp from any to any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.1.0 |
| `-2` score deduction | ✔ v0.1.0 |
| Fix applied correctly | ✔ v0.1.0 |
| **IPv6 variant also detected** (`Anywhere/tcp (v6) ALLOW IN Anywhere/tcp (v6)`) | ✔ v0.1.0 |

**Root cause fixed :** Pattern extended to `Anywhere(?:/\w+)?` on both sides to cover `/tcp`, `/udp` variants. (commit `1dd9ede`)

**v0.1.0:** Same IPv6 fix as A1 applies here.

---

### A3 — UDP wildcard `Anywhere/udp ALLOW IN Anywhere/udp`

```bash
sudo ufw allow proto udp from any to any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.1.0 |
| `-2` score deduction | ✔ v0.1.0 |
| Fix applied correctly | ✔ v0.1.0 |
| **IPv6 variant also detected** | ✔ v0.1.0 |

---

### A4 — All three wildcards simultaneously

```bash
sudo ufw allow from any
sudo ufw allow proto tcp from any to any
sudo ufw allow proto udp from any to any
```

| Expected | Result |
|----------|--------|
| 3 distinct `✖ [ALERT]` findings (IPv4 only, IPV6=no) | ✔ v0.1.0 |
| 6 distinct `✖ [ALERT]` findings (IPv4 + IPv6, IPV6=yes) | ✔ v0.1.0 |
| Score: 1/10 (IPV6=no), Risk level: CRITICAL | ✔ v0.1.0 |
| 6 fixes proposed and applied in reverse index order (avoids renumbering) | ✔ v0.1.0 |

---

### A5 — False positive: source-restricted rule

```bash
sudo ufw allow from 192.168.1.0/24
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` No 'allow from any' rule without port restriction detected | ✔ v0.1.0 |
| Source-restricted rule is NOT flagged as open-any | ✔ |

> `ufw status numbered` shows `Anywhere ALLOW IN 192.168.1.0/24` — destination is `Anywhere` but source is restricted. Pattern correctly requires BOTH sides to be `Anywhere` to flag.

---

## Category B — Duplicate rules

### B1 — Exact duplicate

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/tcp   # UFW says: "Skipping adding existing rule"
```

| Expected | Result |
|----------|--------|
| UFW natively prevents true exact duplicates | ✔ confirmed |
| Not testable via CLI — would require direct file manipulation | noted |

> **Note:** Exact duplicates can only arise from direct `/etc/ufw/` file editing or external tools (Ansible, scripts). UFW's CLI prevents them.

---

### B2 — Same rule, different comments

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (no proto) already present in baseline
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Duplicate UFW rule detected: `80/tcp ALLOW IN Anywhere` | ✔ v0.1.0 |
| Comment stripped before comparison — `# test2` ignored | ✔ v0.1.0 |
| Redundant `80/tcp` deleted, `80` kept | ✔ v0.1.0 |

**Root cause fixed:** Comparison now uses comment-stripped, whitespace-normalized text. (commit `b7a285a`)

---

### B3 — Semantic duplicate: `PORT/proto` redundant when `PORT` exists

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (no proto) already present → 80/tcp is redundant
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Duplicate UFW rule detected: `80/tcp ALLOW IN Anywhere` | ✔ v0.1.0 |
| `-1` score deduction | ✔ v0.1.0 |
| Fix deletes the protocol-specific rule, keeps the broader one | ✔ v0.1.0 |

**Root cause fixed:** Two-pass detection — first pass collects all protocol-less rules, second pass checks if `PORT/proto` is a subset of an existing `PORT` rule. (commit `b7a285a`)

---

### B4 — Semantic duplicate: UDP variant

```bash
sudo ufw allow 53/udp
sudo ufw allow 53
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` `53/udp` detected as redundant | ✔ unit test |

> Validated via unit test only (DNS port — not in services registry, no practical risk on the VM).

---

### B5 — No false positive: `PORT/tcp` + `PORT/udp` without `PORT`

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/udp
# No bare "80" rule
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` No duplicate UFW rules detected | ✔ v0.1.0 |
| `80/tcp` and `80/udp` are complementary — not flagged | ✔ v0.1.0 |

> Also note: when baseline has `80` (bare), adding `80/tcp` + `80/udp` correctly flags BOTH as semantic duplicates of `80`. Verified live.

---

## Category C — Critical services exposed

### C1 — SSH exposed (baseline state)

SSH is always present in the reference state (`ufw allow 22/tcp`). This scenario documents the expected behaviour for a critical service with an unrestricted UFW ALLOW rule.

```bash
# Baseline state — SSH already exposed
sudo bob
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 22/tcp — open to internet — no source restriction in UFW | ✔ v0.1.0.0 |
| Risk context CRITICAL displayed | ✔ v0.1.0.0 |
| `-2` score deduction (NAT/local context) | ✔ v0.1.0.0 |
| Panorama: SSH `⚠` (OPEN_WORLD) | ✔ v0.1.0.0 |
| DDNS `→ 22/tcp` | ✔ v0.1.0.0 |
| **Remediation:** source-restrict → switches to OPEN_LOCAL (WARN not ALERT, no deduction) | ✔ v0.1.0.0 |

> **Note:** `openssh-server` must be installed and active (`sudo apt install openssh-server && sudo systemctl enable --now ssh`). If inactive/disabled, the service is INFO-only with no port exposure check.

---

### C3 — Redis exposed on all interfaces (service installed and active)

```bash
sudo ufw allow 6379
# Redis configured to bind 0.0.0.0 (not the default)
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 6379/tcp — open to internet (Action required) | ✔ v0.1.0 |
| Risk context CRITICAL displayed | ✔ v0.1.0 |
| `-2` score deduction (NAT context) | ✔ v0.1.0 |
| Panorama: Redis `⚠` | ✔ v0.1.0 |
| DDNS cross-check: `→ 6379/tcp` | ✔ v0.1.0 (`6379/udp` filtered — no UDP listener) |

**Root cause fixed (obs 1):** CRITICAL/HIGH services with `OPEN_WORLD` exposure now raise `alert()` instead of `warn()`, moving them to "Action required". (commit `e01b24b`)

---

### C3b — Redis loopback only — false positive fix 

Default Redis configuration: binds to `127.0.0.1` only, but a permissive UFW rule exists.

```bash
sudo ufw allow 6379
# Redis default: bind 127.0.0.1 (loopback only)
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 6379/tcp — bound to localhost only — UFW rule has no effect on external access | ✔ v0.1.0 |
| No ALERT, no score deduction | ✔ v0.1.0 |
| Panorama: Redis `✔` (rule exists, exposure = LOOPBACK) | ✔ v0.1.0 |
| DDNS: `6379/tcp` NOT in exposed ports (loopback only) | ✔ v0.1.0 |
| DDNS: `6379/udp` NOT in exposed ports (no UDP listener) | ✔ v0.1.0 |

**Root cause fixed :** `_classify_exposure()` was UFW-only and did not cross-check actual socket bindings. Fix: `PortsSnapshot` is now collected before CHECK 3; ports where all `ss` bindings are loopback get `Exposure.LOOPBACK` (INFO, no deduction). `_find_open_ports()` in `ddns.py` now also receives the `loopback_ports` and `active_ports` sets. (commits `2bfc85b`, `64311be`)

---

### C2 — MySQL exposed (service not installed)

```bash
sudo ufw allow 3306
```

| Expected | Result |
|----------|--------|
| No service alert (MySQL not installed) | ✔ v0.1.0 |
| Port 3306 open in UFW but unmatched to any installed service | ✔ v0.1.0 |
| DDNS: `3306/tcp` and `3306/udp` NOT in exposed ports (no active listener) | ✔ v0.1.0 |

> **Behaviour updated :** `_find_open_ports()` now cross-checks against actual non-loopback listeners (`active_ports` set from `ss`). Orphan UFW rules (port open, no service running) are excluded from the DDNS exposed ports list. `3306/tcp` and `3306/udp` no longer appear in DDNS findings when MySQL is not installed.

---

### C4 — Nginx exposed (medium-risk service, installed and active)

```bash
sudo apt install nginx
sudo ufw allow 80
sudo bob
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` Port 80/tcp — open to internet — no source restriction in UFW | ✔ v0.1.0.0 |
| Risk context MEDIUM displayed | ✔ v0.1.0.0 |
| `-1` score deduction | ✔ v0.1.0.0 |
| Panorama: Nginx `⚠` | ✔ v0.1.0.0 |
| Finding appears in *Possible improvements* (not *Action required*) | ✔ v0.1.0.0 |

> Medium-risk services (`warn()` not `alert()`) — distinction from critical services like SSH or Redis.

---

### C5 — Samba exposed (critical service, installed and active)

```bash
sudo apt install samba
sudo ufw allow 445
sudo ufw allow 139
sudo bob
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 445/tcp — open to internet — no source restriction in UFW | ✔ v0.1.0.0 |
| `✖ [ALERT]` Port 139/tcp — open to internet | ✔ v0.1.0.0 |
| Risk context CRITICAL displayed (ransomware vector, EternalBlue) | ✔ v0.1.0.0 |
| `-2` deduction × 2 ports (−4 total) | ✔ v0.1.0.0 |
| Panorama: Samba `⚠` (OPEN_WORLD) | ✔ v0.1.0.0 |
| Both ports in *Action required* block | ✔ v0.1.0.0 |
| DDNS `→ 445/tcp`, `→ 139/tcp` | ✔ v0.1.0.0 |

> **Cleanup:** `sudo apt remove --purge samba && sudo ufw delete allow 445 && sudo ufw delete allow 139`

---

### C6 — Ports open in UFW, services not installed (multiple services)

For each entry below: open the port in UFW with no matching service installed. Expected behaviour: **no service-level alert**, port may appear as an unmatched open rule.

```bash
sudo ufw allow <PORT>
sudo bob
```

| Service | Port | Expected behaviour | Result |
|---------|------|--------------------|--------|
| VNC Server | 5900/tcp | No service alert — VNC not detected | ✔ v0.1.0.0 |
| FTP Server | 21/tcp | No service alert — FTP not detected | ✔ v0.1.0.0 |
| PostgreSQL | 5432/tcp | No service alert — PostgreSQL not detected | ✔ v0.1.0.0 |
| Mosquitto (MQTT) | 1883/tcp | `ℹ [INFO]` 1883/tcp loopback — UFW rule has no effect; 8883/tcp not listening — no message; Panorama ✔ | ✔ v0.1.0.0 ² |
| WireGuard | 51820/udp | `ℹ [INFO]` WireGuard installed but stopped/disabled — no port exposure check (INACTIVE early return) | ✔ v0.1.0.0 ¹ |
| Gitea | 3000/tcp | No service alert — Gitea not detected | ✔ v0.1.0.0 |
| Jellyfin | 8096/tcp | No service alert — Jellyfin not detected | ✔ v0.1.0.0 |
| Home Assistant | 8123/tcp | No service alert — HASS not detected | ✔ v0.1.0.0 |
| Cockpit | 9090/tcp | No service alert — Cockpit not detected | ✔ v0.1.0.0 |

> For all above: the port should appear in **UFW RULES ANALYSIS** if an active listener exists, but since the service is not installed there is no listener — no ALERT in NETWORK SERVICES ANALYSIS.
> DDNS cross-check: none of these ports should appear in DDNS exposed list (no active listener — v0.1.0).

> ¹ WireGuard was already installed (but inactive) on the test VM. The "not installed" path for WireGuard remains untested — behaviour confirmed: INACTIVE service with an open UFW rule → INFO only, no ALERT, no score deduction.

> ² Mosquitto was installed and ACTIVE on the test VM (not matching the "not installed" C6 scenario). Test revealed a bug: registry ports not actively listening (8883/tcp) incorrectly triggered `Exposure.NO_RULE` → panorama ✖. Fixed in beta (commit `67743ca`): `Exposure.NOT_LISTENING` for non-listening registry ports → panorama ✔.

> **Already validated:** MySQL / MariaDB (3306) → C2

---

### C7 — CUPS exposed (low-risk service, usually pre-installed on desktop Linux)

CUPS (print server) listens on `127.0.0.1:631` by default. This test verifies behaviour when CUPS is active and a UFW rule exists.

```bash
# CUPS is often pre-installed on Linux Mint
sudo ufw allow 631
sudo bob
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 631/tcp — bound to localhost only — UFW rule has no effect | ✔ v0.1.0.0 |
| No ALERT, no score deduction (loopback binding) | ✔ v0.1.0.0 |
| Panorama: CUPS `✔` (rule exists, loopback → INFO) | ✔ v0.1.0.0 |

> If CUPS binds to `0.0.0.0`: `⚠ [WARNING]` Port 631/tcp — open to internet (low risk, nature=improvement).

---

## Category D — IPv6 consistency

### D1 — IPv4 rules present, no IPv6 equivalent (warning expected)

```bash
# From baseline: 22/tcp and 80 are present, no (v6) rules
sudo ufw status numbered
```

> **Note:** Some distributions (or VMs with `IPV6=no` in `/etc/default/ufw`) do not add IPv6 rules. If all rules are already paired (IPv4 + IPv6), use `sudo ufw --force reset` and re-add only IPv4 rules:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   # Do NOT let UFW create (v6) rules — requires IPV6=no
sudo ufw enable
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` IPv6 rules missing — only IPv4 rules present | ✔ v0.1.0 live (IPV6=no VM) |
| `-1` score deduction | ✔ v0.1.0 live |
| Live test | ✔ v0.1.0 |

---

### D2 — IPv4 and IPv6 rules both present (no warning)

```bash
# Baseline with IPV6=yes (default): 22/tcp and 22/tcp (v6) both present
sudo bob
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` IPv4 and IPv6 rules both present | ✔ v0.1.0 live (IPV6=yes, A1 test) |
| No deduction | ✔ v0.1.0 live |
| Live test | ✔ v0.1.0 |

---

## Category E — Loopback-only ports 

### C8 — SSH restricted to LAN (OPEN_LOCAL path)

```bash
sudo ufw delete allow 22/tcp
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp
sudo bob
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` Port 22/tcp — restricted to local network by UFW rule | ✔ v0.1.0 |
| No score deduction (OPEN_LOCAL ≠ OPEN_WORLD) | ✔ v0.1.0 |
| Panorama: SSH `✔` (LAN restriction = correct config) | ✔ v0.1.0 |
| DDNS: `ℹ` Port 22/tcp restricted to local network (not ALERT) | ✔ v0.1.0 |
| Risk context CRITICAL still displayed | ✔ v0.1.0 |

> **Cleanup:** `sudo ufw delete allow from 192.168.1.0/24 to any port 22 proto tcp && sudo ufw allow 22/tcp`

---



### E1 — Port listening on localhost only, no UFW rule — INFO not ALERT

```bash
# Any process bound exclusively to 127.0.0.1 without a UFW rule
# Example: netcat listening on loopback (or rely on Redis default config)
# Redis default: bind 127.0.0.1 — no UFW rule needed
sudo bob
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 6379/tcp — bound to localhost only — no UFW rule needed (covered by default deny) | ✔ v0.1.0.0 |
| No ALERT, no score deduction | ✔ v0.1.0.0 |
| Redis panorama ✔ | ✔ v0.1.0.0 |
| Message uses `services.exposure.loopback_no_rule` locale key (added with `Exposure.LOOPBACK_NO_RULE` fix) | ✔ v0.1.0.0 |

> **Note:** The original expected message referenced `ports.uncovered_local`. In practice, Redis on loopback with no UFW rule is handled by the services check path (`Exposure.LOOPBACK_NO_RULE`), not the ports check. The `ports.uncovered_local` key (`"Port {port} — bound to localhost only — no external exposure"`) applies to the ports section for processes not covered by the service registry.

---

## Additional observations

### Obs — Avahi panorama shows ✖ despite INFO message (v0.1.0)

Avahi binds on `0.0.0.0:5353/udp` (mDNS multicast). No UFW rule exists for 5353 → `Exposure.NO_RULE` → panorama ✖. The service check correctly emits `ℹ [INFO]` "covered by default deny policy", but the panorama symbol is set by the `NO_RULE` enum value regardless of the INFO severity.

**Root cause:** `NO_RULE` on a non-loopback, non-listening-externally port (multicast/LAN-only in practice) is treated identically to `NO_RULE` on a genuinely exposed port. A future fix could introduce `Exposure.NO_RULE_MULTICAST` or a broader mechanism to distinguish locally-scoped `NO_RULE` from truly exposed `NO_RULE`.

**Impact:** cosmetic only — no false ALERT, no score deduction.

---



### Obs — DDNS does not detect protocol-less rules (fixed)

With `80 ALLOW IN Anywhere` (no `/tcp`), the DDNS cross-check previously showed nothing for port 80.

**Root cause fixed:** `_find_open_ports()` now handles bare port rules — adds both `PORT/tcp` and `PORT/udp` to the open ports list. (commit `e01b24b`)

**Validated (v0.1.0):** Bare rule `80 ALLOW` with Nginx listening on `0.0.0.0:80` → DDNS correctly lists `→ 80/tcp` only (`80/udp` filtered — no UDP listener on port 80).

---

### Obs — DDNS false positives: system ports and orphan rules 

```bash
sudo ufw allow 53
sudo ufw allow 3306
sudo ufw allow 6379
# Redis on 127.0.0.1 only, MySQL not installed
```

| Expected | Result |
|----------|--------|
| DDNS: `53/tcp`, `53/udp` NOT listed (system port filter) | ✔ v0.1.0.0 |
| DDNS: `3306/tcp`, `3306/udp` NOT listed (no active listener) | ✔ v0.1.0.0 |
| DDNS: `6379/tcp`, `6379/udp` NOT listed (loopback only / no UDP listener) | ✔ v0.1.0.0 |

**Root cause fixed :** Added `_DDNS_SYSTEM_PORTS` constant (53, 67, 68, 546, 547, 5353) and `active_ports` cross-check in `_find_open_ports()`. Only ports with an actual non-loopback listener in `ss` output are included in the DDNS exposed list. (commit `64311be`)

---

### Obs — UFW allows wildcard rules after specific rules without error

```
Anywhere/tcp    ALLOW IN    Anywhere/tcp
22/tcp          ALLOW IN    Anywhere
```

UFW does not warn that `Anywhere/tcp` makes `22/tcp` redundant. bob correctly flags the wildcard.

---

## B1 note — exact duplicates via file manipulation

To test exact duplicates that UFW's CLI prevents, rules can be injected directly:

```bash
sudo cp /etc/ufw/user.rules /etc/ufw/user.rules.bak
# Manually duplicate a rule line in user.rules
sudo ufw reload
sudo bob
# Cleanup:
sudo cp /etc/ufw/user.rules.bak /etc/ufw/user.rules
sudo ufw reload
```

Not yet tested — low practical priority since UFW CLI prevents this.
