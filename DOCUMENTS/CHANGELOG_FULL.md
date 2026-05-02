*[Lire en français](CHANGELOG_FULL_FR.md)* · *[TL;DR](../CHANGELOG.md)*

# BOB — Bodyguard Of Bits — Changelog

All notable changes to this project are documented here.

---

## [v0.2.1] — 2026-05-02

Defensive programming hotfix — 17 targeted improvements identified by a dual-agent code audit (independent runs by Claude and Copilot). No new features, no behavior changes, no new tests. 4238/4238 unchanged.

### `bob/manage_logs.py` — crash fix: unguarded `.stat()` in plain-text mode

#### Problem

The plain-text rendering loops in `_run_manage_logs_plain()` called `f.stat()` directly:

```python
size_kb = max(1, f.stat().st_size // 1024)
mtime = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
```

If a log file was deleted between the directory scan and the display loop (e.g. by a parallel `logrotate` run), this raised `OSError` and crashed `--manage-logs`. The curses mode (lines 792–796) already had the correct guard:

```python
try:
    size_kb = max(1, f.stat().st_size // 1024)
    mtime   = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
except OSError:
    size_kb, mtime = 0, "?"
```

#### Fix

Both loops in the plain-text path (`cur_logs` and `extra_sections`) now wrap `.stat()` identically to the curses path, using `(0, "?")` as fallback values.

---

### Exception handling narrowed — 8 locations

All `except Exception` handlers (which also catch programming errors and make debugging harder) replaced with the specific exception types that can actually be raised at each site.

#### `bob/cis_refs.py` — `_load()`

`_load()` reads and parses a JSON file. The only failures are I/O (`OSError`) and malformed JSON (`json.JSONDecodeError`).

```python
# before
except Exception:
    return {}

# after
except (OSError, json.JSONDecodeError):
    return {}
```

#### `bob/manage_logs.py` — `_get_extra_dirs()`

Parses a JSON-encoded list of strings from user config. Failures: malformed JSON, unexpected value types.

```python
# before
except Exception:
    return []

# after
except (json.JSONDecodeError, ValueError, TypeError):
    return []
```

#### `bob/manage_logs.py` + `bob/explain.py` + `bob/cron.py` — curses fallbacks

Three `curses.wrapper()` calls that fall back to plain-text mode on terminal failure. The `curses.error` exception covers all terminal initialization and rendering failures; `OSError` covers I/O-level terminal errors.

```python
# before (all three sites)
except Exception:
    return _run_*_plain(...)

# after
except (curses.error, OSError):          # manage_logs.py, explain.py
    return _run_*_plain(...)

except (_curses.error, OSError):         # cron.py (curses imported as _curses)
    return _run_*_plain(...)
```

#### `bob/checks/ssh.py` — binary key parsing

`_rsa_bits_from_blob()`: decodes base64 and unpacks a binary SSH wire format. Failures: invalid base64 (`binascii.Error`, subclass of `ValueError`) and malformed struct data (`struct.error`).

```python
# before
except Exception:
    return None

# after
except (struct.error, ValueError):
    return None
```

`_has_passphrase()`: decodes base64 OpenSSH key data. Only `binascii.Error` (invalid base64, subclass of `ValueError`) can be raised inside the try block.

```python
# before
except Exception:
    return None

# after
except (binascii.Error, ValueError):
    return None
```

`import binascii` added at top of `ssh.py`.

---

### Regex patterns moved to module level — 3 files

Patterns that were `re.compile()`d inside function bodies — recompiled on every call — moved to module-level constants. Python does not cache `re.compile()` results automatically when called inside functions.

#### `bob/checks/firewall.py`

```python
# moved to module level
_OPEN_ANY_RE = re.compile(
    r"Anywhere(?:/\w+)?(?:\s+\(v6\))?\s+ALLOW\s+IN\s+Anywhere(?:/\w+)?(?:\s+\(v6\))?\s*$",
    re.IGNORECASE,
)
_ALLOW_IN_RE   = re.compile(r"\bALLOW\s+IN\b", re.IGNORECASE)
_PORT_PROTO_RE = re.compile(r"\b(\d{1,5}/(?:tcp|udp))\b", re.IGNORECASE)
```

`_check_open_any()` and `_check_orphan_rules()` updated to reference the module-level constants.

#### `bob/checks/cron_audit.py`

```python
_PATH_RE = re.compile(r"(/[^\s;|&<>]+\.sh)\b")
```

Moved from inside `_find_world_writable_scripts()` to module level alongside the existing `_PIPE_TO_SHELL_RE`.

#### `bob/checks/firmware.py`

```python
_FLAT_SKIP_RE = re.compile(
    r"^(Update|Version|Summary|Description|Requires|Urgency|Remote|Size|"
    r"Flags|Status|GUID|Device|AppStream|Release|\[|WARNING|Error|\s)",
    re.IGNORECASE,
)
```

Moved from inside `_parse_fwupd_updates()` to module level alongside `_TREE_ITEM_RE`.

---

### `bob/cron.py` — email regex deduplicated

`_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")` was defined identically inside three separate functions: `_select_emails_plain()` (line 325), `_curses_email_list_sub()` (line 1273), `_curses_email_store_sub()` (line 1398). Moved to a single module-level constant (line 20). The same pattern exists independently in `bob/config.py` for config validation; both are intentionally kept as each module owns its own constraint.

---

### `bob/manage_logs.py` — `_resolve_path()` helper extracted

```python
def _resolve_path(raw: str, default: Path) -> Path:
    """Expand, resolve and return *raw* as a Path, or *default* if empty."""
    return Path(raw).expanduser().resolve() if raw else default
```

The one-liner `Path(raw).expanduser().resolve() if raw else default` appeared at two call sites: inside `_prompt_path()` (return statement) and inside the change-directory flow. Both now call `_resolve_path()`. The security comment (`resolve() normalises ".." components…`) is kept at the first call site.

---

### `bob/domain_scores.py` — direct attribute access

`active_domains_from_engine()` and `compute_domain_scores()` used `getattr(engine, "findings", [])`, `getattr(finding, "key", None)`, and `getattr(deduction, "points", 0)` as defensive guards. `ScoreEngine.__init__` always initializes `findings`, `ignored_findings`, and `breakdown` as empty lists; `Finding` and `Deduction` are dataclasses with `key` and `points` as required fields. The `getattr` calls hid potential API drift instead of surfacing it. Replaced with direct access throughout.

---

### `bob/recurrence.py` — debug log on load failure

```python
# before
except (OSError, json.JSONDecodeError, ValueError):
    pass

# after
except (OSError, json.JSONDecodeError, ValueError) as exc:
    _log.debug("Failed to load recurrence data from %s: %s", src, exc)
```

`import logging` and `_log = logging.getLogger(__name__)` added. Failures are still non-fatal (recurrence tracking is best-effort) but now surface under `--debug` log level.

---

### `bob/__main__.py` — webhook failure logging

```python
# before
except Exception as _exc:  # noqa: BLE001
    print(f"Warning: webhook failed: {_exc}", file=sys.stderr)

# after
except Exception as _exc:  # noqa: BLE001
    _log.warning("Webhook failed: %s", _exc)
    print(f"Warning: webhook failed: {_exc}", file=sys.stderr)
```

`import logging` and `_log = logging.getLogger(__name__)` added. Webhook failures are now captured by the logging system in addition to the user-visible stderr print.

---

### Tests

4238/4238 — no new tests, no behavior changes. All existing tests pass unmodified.

---

## [v0.2.0] — 2026-05-01

Five improvements found during first-run analysis on Ubuntu 26.04 LTS and Debian 13.

### `bob/scoring.py` + `bob/domain_scores.py` — scoring refactoring

#### Problem

The global score was computed as `10 − sum(all_deductions)`. On Debian 13 with 8 deductions of −1 each, this produced a 2/10 CRITICAL rating even though SSH, firewall, updates, and file permissions were all perfect. The score did not represent the actual security posture of the machine.

Two additional issues:
- **Double penalty on single tools** — rkhunter emitting both `rootkit.db_outdated` and `rootkit.no_scan` deducted 2 points from the global score, punishing a single misconfiguration twice.
- **Disconnection between global and domain scores** — domain scores were computed independently but the global score was not derived from them, creating a contradiction in the output.

#### Fix 1 — Tool caps in `compute_domain_scores()`

New `_TOOL_CAPS` dict in `domain_scores.py`:

```python
_TOOL_CAPS: dict[str, int] = {
    "rootkit":        1,   # rkhunter/chkrootkit — db age + scan age
    "clamav":         1,   # ClamAV — db age + scan frequency
    "file_integrity": 1,   # AIDE/Tripwire — presence + freshness
}
```

When `compute_domain_scores()` accumulates deductions per domain, each tool prefix is capped at its maximum contribution. A second deduction from `rootkit.*` when the cap is already reached contributes 0 points to the domain score. Uncapped prefixes (e.g. `hardening.*`, `ssh.*`) accumulate normally.

#### Fix 2 — Global score = mean of active domain scores

New `compute_global_from_domains(domain_scores, active_domains) -> int` in `domain_scores.py`:

```python
active = [d for d in DOMAINS if d in active_domains and d in domain_scores]
return max(0, min(MAX_SCORE, round(total / len(active))))
```

New `apply_domain_score_override(engine)` calls `compute_domain_scores`, `active_domains_from_engine`, and `compute_global_from_domains`, then calls `engine.set_global_score()` with the result.

New `ScoreEngine.set_global_score(score: int)` stores the domain-averaged value in `_global_override`. The `score` property returns `_global_override` when set, falling back to `_raw_score` otherwise. The internal raw score is never modified — it remains available at `engine._raw_score` for debugging.

`apply_domain_score_override(engine)` is called immediately after `engine.finalize()` in both `bob/__main__.py` and `bob/watch.py`.

#### Effect

Debian 13 reference case (8 deductions, all domains otherwise healthy):
- Before: 2/10 CRITICAL (raw sum)
- After: 6/10 (hardening=4, disk=9, average of 2 active domains in the test scenario; 9/10 in real use with SSH/firewall/updates active at 10/10)

### `bob/cron.py` — MTA detection (`_detect_mta()`)

#### Problem

The cron wizard checked `shutil.which("mail")` and warned `'mail' not available — install mailutils`. Email delivery in `report_markdown.py` uses `sendmail -t -f`, not `mail`. The check was testing the wrong binary and recommending an unnecessary package.

#### Fix

New `_detect_mta() -> tuple[bool, str]` helper:

```python
def _detect_mta() -> tuple[bool, str]:
    import shutil
    if not shutil.which("sendmail"):
        return False, ""
    for name, check in [
        ("Postfix", lambda: Path("/etc/postfix/main.cf").exists()),
        ("Exim",    lambda: bool(shutil.which("exim4") or shutil.which("exim"))),
        ("msmtp",   lambda: bool(shutil.which("msmtp"))),
        ("ssmtp",   lambda: bool(shutil.which("ssmtp"))),
    ]:
        if check():
            return True, name
    return True, ""
```

Both call sites in `_run_install_cron_plain` and `_run_install_cron_curses` now use `_detect_mta()`. When an email is configured:
- MTA found: `✔ Mail transport: Postfix (sendmail available — notifications will be delivered)`
- MTA missing: `⚠ No sendmail found — notification emails won't be delivered. Install: sudo apt install postfix  or  sudo apt install msmtp-mta`

Locale keys `mail_missing` replaced by `mta_missing` and `mta_found` in `bob/locales/en.json` and `bob/locales/fr.json`.

### `bob/checks/kernel_modules.py` — Debian `-unsigned` false positive

#### Problem

On Debian with Secure Boot enabled, apt installs both:
- `linux-image-6.12.74+deb13+1-amd64` — signed kernel (booted when Secure Boot is active)
- `linux-image-6.12.74+deb13+1-amd64-unsigned` — unsigned variant (same version, different package)

`_check_installed_kernels()` sorted all installed kernels by `_kernel_sort_key()`. Both variants produce the same numeric sort key `(6, 12, 74, 0)`. Python's stable sort then falls back to lexicographic order, placing `-amd64-unsigned` after `-amd64`. `most_recent` was set to the unsigned variant, making `running != most_recent` evaluate to `True` — triggering a spurious reboot warning.

#### Fix

New `_strip_unsigned(version: str) -> str` helper:

```python
def _strip_unsigned(version: str) -> str:
    return version[:-len("-unsigned")] if version.endswith("-unsigned") else version
```

`reboot_pending` now compares stripped versions:

```python
reboot_pending = running in kernels and _strip_unsigned(running) != _strip_unsigned(most_recent)
```

A genuine version difference (e.g. `6.12.63+deb13-amd64` running while `6.12.74+deb13+1-amd64` is installed) still triggers the reboot warning correctly.

### Tests

- `tests/test_kernel_modules.py` — +6 tests:
  - `TestKernelRebootPending.test_no_reboot_pending_debian_signed_plus_unsigned_same_version`
  - `TestKernelRebootPending.test_reboot_still_pending_when_genuinely_newer_debian_kernel`
  - `TestStripUnsigned` — 4 unit tests for `_strip_unsigned()`
- `tests/test_cron.py` — +6 tests in `TestDetectMta`: no sendmail, Postfix (via config file), Exim, msmtp, ssmtp, unknown MTA
- `tests/test_scoring.py` — +6 tests in `TestSetGlobalScore`: override replaces raw, no override by default, clamp above max, clamp below zero, level reflects override, raw score unchanged
- `tests/test_domain_scores.py` — +14 tests:
  - `TestToolCaps` (7 tests) — rootkit/clamav/file_integrity capped at 1; uncapped prefixes accumulate; caps don't bleed across tools; partial deduction respects cap
  - `TestComputeGlobalFromDomains` (4 tests) — average, empty domains, clamp max, clamp zero
  - `TestApplyDomainScoreOverride` (3 tests) — override applied, valid range, Debian 13 scenario
- **Total: 4238 tests** (4206 → 4238, +32)

### `bob/checks/logs.py` — IoT local dominance: WARN −1 pt

#### Problem

When a single private IP accounted for ≥ 70 % of all blocked UFW traffic over ≥ 50 log entries, BOB emitted an `INFO` finding with no score deduction. The feature was documented as WARN −1 pt in README_TECH.md but the implementation called `result.info()` with no `add_deduction()` call — the deduction was never applied.

Discovered during first local test run on `so6desktop`: `192.168.1.50` accounted for 2267/2415 blocks (93 %) with no WARN or deduction emitted.

#### Fix

`bob/checks/logs.py`:
```python
result.warn(
    message=_t("logs.local_dominance", ip=local_ip, count=local_count,
               total=snapshot.total, pct=local_pct),
    key="logs.local_dominance",
    nature="improvement",
)
result.add_deduction(
    reason=_t("deduction.local_dominance", ip=local_ip, pct=local_pct),
    points=1,
    key="logs.local_dominance",
)
```

New locale key `deduction.local_dominance` added in `bob/locales/en.json` and `bob/locales/fr.json`.

Three existing tests in `tests/test_logs.py` corrected to assert the now-correct behaviour:
- `test_check_logs_emits_warn_finding` (was `test_check_logs_emits_info_finding`)
- `test_finding_is_warn_level` (was `test_finding_is_info_level`)
- `test_score_deduction_one_point` (was `test_no_score_deduction`)

Test count unchanged at 4238.

### `bob/output.py` — Orange ASCII banner

The `BOB` ASCII art rendered inside the terminal banner box is now coloured orange bold (`_c.orange_bold` = `\033[1;38;5;208m`). Border characters (`║`, `╔`, `╠`, `╚`) retain their existing blue bold colour. No output format or log file impact — terminal rendering only.

---

## [v0.1.1] — 2026-04-29

Hotfix release. Three targeted fixes found during first runs on Ubuntu 26.04 LTS and Debian 13.

### Fixes

#### `bob/checks/firmware.py` — fwupd 1.9+ tree-format parser

`fwupdmgr get-updates` changed its output format in fwupd 1.9+ (shipped with Ubuntu 26.04 LTS). The previous flat-format assumed device names at column 0 with metadata indented; the new format uses a tree structure:

```
QEMU Ubuntu 24.04 PC (Q35 + ICH9, 2009)
│
├─UEFI CA:
│   New version: 2024.01
│
└─QEMU DVD-ROM:
    New version: 2.5
```

The previous `_parse_fwupd_updates()` parser captured `│` and `├─UEFI CA:` as device names, producing garbled output: `10 pending firmware updates: QEMU Ubuntu 24.04 PC (Q35 + ICH9, 2009), │, ├─UEFI CA: (+7)`.

Fix: tree format auto-detected (any `├─`/`└─` line present); in tree mode, device names extracted from `├─`/`└─` lines by stripping the prefix and trailing colon; `│` lines and top-level container lines skipped. Flat format unchanged.

New module-level constant: `_TREE_ITEM_RE = re.compile(r"^[├└]─\s*")`.

#### `bob/__main__.py` — `--install-completion` error message

When `bob --install-completion` is run without root, the error message showed the correct full-path command (`sudo /path/to/bob --install-completion`) but users naturally typed `sudo bob --install-completion` instead, which fails because sudo's restricted PATH does not include pipx's `~/.local/bin`.

New message explicitly explains that `sudo bob` will not work (pipx PATH restriction) and instructs to copy-paste the exact command shown.

#### `bob/locales/en.json`, `bob/locales/fr.json` — services panorama column header

`services.panorama.header_ufw`: `"UFW"` → `"SCOPE"` (EN) / `"PORTÉE"` (FR).

The column uses `Exposure.OPEN_WORLD` to determine the indicator — it reflects whether a service has internet-scope exposure, not whether an active UFW rule covers it. With UFW inactive, LAN-scoped services (Avahi, CUPS) correctly showed `✔` but the `UFW` label implied firewall protection was active. The renamed label eliminates this ambiguity.

### Tests

- `tests/test_firmware.py` — 4 new regression tests covering the tree-format parser:
  - `test_tree_format_extracts_device_names` — `├─`/`└─` lines yield correct device names
  - `test_tree_format_excludes_container_line` — top-level container not captured
  - `test_tree_format_excludes_tree_connectors` — `│`, `├`, `└` chars absent from results
  - `test_tree_format_strips_trailing_colon` — names from `├─Name:` have no trailing colon
- **Total: 4206 tests** (4202 → 4206, +4)

---

## [v0.1.0] — 26-04-2026

Initial release of BOB — Bodyguard Of Bits.

### Architecture

- **Module** `bob/` — Python package; CLI entry point `bob` via `bob.__main__:main`
- **46 checks** organised across 9 security domains; each check produces typed `Finding` objects consumed by the scoring engine
- **Scoring engine** (`bob/scoring.py`) — weighted deductions per finding, clamped 0–10; 5 domain sub-scores (firewall, ssh, hardening, updates, file_perms)
- **i18n** (`bob/i18n.py`, `bob/locales/en.json`, `bob/locales/fr.json`) — all user-facing strings externalised; `--french` / `-d` switches locale at runtime
- **Audit profiles** (`bob/profiles.py`, `bob/data/profiles/`) — `server`, `workstation`, `desktop`, `docker`; each profile declares severity overrides and skipped sections
- **Plugin API** (`bob/plugin_checks.py`, `bob/registry.py`) — custom checks via `~/.config/bob/checks.d/`; custom service definitions via `~/.config/bob/services.d/`

### Security checks

#### Firewall
- `bob/checks/firewall.py` — UFW rules: duplicate rules, open-any rules, IPv6 coverage, default deny policy awareness
- `bob/checks/iptables_nftables.py` — CHECK 46: iptables/nftables audit when UFW is inactive; INPUT/FORWARD/OUTPUT policy; conntrack detection; nftables ruleset parsing
- `bob/checks/ipv6.py` — IPv6 consistency between UFW rules and sysctl
- `bob/checks/firewall_stack.py` — firewall stack detection (UFW/iptables/nftables/none); active stack reported in banner
- `bob/checks/ports.py` — port exposure analysis: public vs LAN vs loopback; service identification; ephemeral port filtering

#### SSH
- `bob/checks/ssh.py` — PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, X11Forwarding, MaxAuthTries, ClientAliveInterval, UsePAM, AllowTcpForwarding, key algorithm quality, ListenAddress, Banner

#### Kernel hardening
- `bob/checks/kernel_hardening.py` — 20+ sysctl parameters (net.ipv4/ipv6, fs.*, kernel.*); randomize_va_space, dmesg_restrict, kptr_restrict, ptrace_scope, etc.
- `bob/checks/kernel_modules.py` — risky filesystem and network modules (cramfs, freevxfs, jffs2, hfs, udf, dccp, sctp, rds, tipc)
- `bob/checks/secure_boot.py` — Secure Boot state via mokutil/efibootmgr
- `bob/checks/firmware.py` — fwupd pending updates; microcode package presence

#### Services
- `bob/checks/services.py` — 32 known services with risk classification; listens on expected ports; risk context shown per active service
- `bob/checks/services_state.py` — enabled+active systemd service audit; CRITICAL/HIGH installed-but-inactive → warning
- `bob/checks/docker.py` — Docker installation detection; UFW firewall bypass via iptables DOCKER chain
- `bob/checks/docker_audit.py` — daemon.json hardening; privileged containers; host network/pid/ipc; sensitive volume mounts; no-new-privileges
- `bob/checks/smtp.py` — SMTP server exposure; inet_interfaces; open relay risk

#### File permissions
- `bob/checks/file_perms.py` — world-writable files; /etc/passwd /etc/shadow /etc/sudoers permissions
- `bob/checks/suid_audit.py` — SUID/SGID audit with whitelist; targeted roots for performance

#### User accounts
- `bob/checks/user_accounts.py` — expired accounts (UID≥1000); locked accounts with recent logins
- `bob/checks/password_policy.py` — /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE); PAM pam_cracklib/pam_pwquality; PAM password history
- `bob/checks/umask.py` — system umask (/etc/profile, /etc/bash.bashrc, /etc/login.defs)

#### System
- `bob/checks/updates.py` — apt pending security updates (−2 flat); regular updates (INFO); unattended-upgrades compound (−1); kernel apt update check
- `bob/checks/logs.py` — UFW logging level (off/low/medium/high/full)
- `bob/checks/log_rotation.py` — logrotate configuration; /var/log/ufw.log size; log retention
- `bob/checks/auth_log.py` — failed login count from auth.log/journald; repeated failure patterns
- `bob/checks/ntp.py` — NTP sync state (systemd-timesyncd / chrony / ntpd)
- `bob/checks/fail2ban.py` — Fail2ban active; sshd jail enabled
- `bob/checks/rootkit.py` — rkhunter / chkrootkit presence and last scan age
- `bob/checks/auditd.py` — auditd active; audit rules present; key rules (privileged commands, sudoers changes)
- `bob/checks/file_integrity.py` — AIDE / Tripwire presence and last run
- `bob/checks/clamav.py` — ClamAV package; freshclam DB age; last scan age
- `bob/checks/mac_policy.py` — AppArmor (profiles loaded, enforce vs complain) / SELinux (enforcing vs permissive)
- `bob/checks/backup.py` — backup solution detection (restic, duplicati, borgbackup, rsync cron, timeshift)
- `bob/checks/disk.py` — SMART health (smartctl); partition usage; NVMe wear level
- `bob/checks/memory.py` — swap present; SSD swap wear; swappiness tuning
- `bob/checks/ssl_certs.py` — TLS/SSL certificate expiry scan (≤30 days → WARN, ≤7 → ALERT)
- `bob/checks/systemd_timers.py` — active system timers; missed timers; timer-unit security options
- `bob/checks/desktop_apps.py` — installed desktop applications (browsers, mail, etc.) on server profile
- `bob/checks/samba.py` — Samba hardening (map to guest, null passwords, min protocol, signing)
- `bob/checks/cron_audit.py` — world-writable cron scripts; pipe-to-shell patterns; /etc/cron.d format
- `bob/checks/ddns.py` — DDNS client activity (ddclient); reflected in internet exposure analysis

#### Network
- `bob/sysinfo.py` — public IP detection (3-provider fallback: ipify → ifconfig.me → icanhazip); IPv6 public address; network context (server/LAN/CGNAT/VPN); GeoIP2 optional
- `bob/checks/network_context.py` — network type classification; exposure context shown per finding
- `bob/checks/virtualization.py` — virtualization detection (KVM/VirtualBox/VMware/LXC/Docker)

### CIS benchmark mapping

- `bob/cis_refs.json` — 133 entries: `{"ref": "...", "code": "CIS:X.Y.Z"|null}`
  - 99 CIS Ubuntu 22.04 benchmarks (with `code: "CIS:X.Y.Z"`)
  - 4 CIS Docker benchmarks (with `code: "CIS Docker:X.Y"`)
  - 34 best-practice entries (with `code: null`)
- `bob/cis_refs.py` — `get_cis_ref(key)` / `get_cis_code(key)` — `_load()` with `lru_cache(maxsize=1)`
- `bob/display.py` — `[CIS:X.Y.Z]` injected inline in summary box per finding; full ref shown in `--verbose`
- `bob/explain.py` — `--explain KEY` TUI and direct-key mode; calls `get_cis_ref()` directly

### Output and formatting

- `bob/output.py` — terminal colored output; summary box; domain score bar chart; services panorama
- `bob/display.py` — finding line rendering; CIS code injection; score color; scope qualifiers (`[CRITICAL • INTERNET]`)
- `bob/json_output.py` — `--format=json` / `--json`
- `bob/csv_output.py` — `--format=csv`
- `bob/markdown_output.py` — `--format=markdown`
- `bob/report_markdown.py` — full markdown report
- `bob/html_output.py` — `--html` standalone HTML report

### Automation and scheduling

- `bob/cron.py` — `--install-cron` curses wizard; `--manage-cron` TUI; named jobs (`/etc/cron.d/bob-{name}`); email notification on exit code > 0; legacy cron detection
- `bob/manage_logs.py` — `--manage-logs` TUI; log directory management; score history sparkline
- `bob/webhook.py` — generic JSON webhook + Slack (auto-detected); non-fatal; UTC timestamps; domain scores included
- `bob/history.py` — score history appended to `~/.config/bob/history.jsonl`; `--history` sparkline
- `bob/domain_scores.py` — 5-domain 0–10 scores; bar chart; included in JSON/webhook output
- `bob/watch.py` — `--watch[=N]` polling loop; reruns full audit every N seconds (default 60)
- `bob/compare.py` — `--diff` baseline diff; delta-only display; baseline at `~/.config/bob/last_baseline.json`
- `bob/recurrence.py` — recurring finding tracker; consecutive appearance count per key

### CLI and configuration

- `bob/cli.py` — argument parser; 7 sections; short options (-V -v -d -j -C -p -e -D -w -o); `--check`/`--skip`; `--format`; `--output-dir`; `--target`; `--min-level`
- `bob/completion.py` — `--install-completion`; bash completion script at `/etc/bash_completion.d/bob`
- `bob/config.py` — persistent key=value store at `~/.config/bob/config.conf`
- `bob/ignore.py` — `--ignore`/`--show-ignored`; `~/.config/bob/ignore.yml`
- `bob/fixes.py` — `--fix` dry-run UI; `--apply` execution

### Tests

4200 tests across 65 test files.

| File | Coverage |
|------|----------|
| `test_cis_refs.py` | `cis_refs.py` / `cis_refs.json` — 39 tests |
| `test_iptables_nftables.py` | CHECK 46 — iptables/nftables |
| `test_firewall.py` | UFW rules audit |
| `test_ssh.py` | SSH configuration checks |
| `test_hardening.py` | Kernel hardening sysctl |
| `test_kernel_modules.py` | Kernel module audit |
| `test_services.py` | Service registry + risk |
| `test_services_state.py` | Service state audit |
| `test_docker.py` · `test_docker_audit.py` | Docker checks |
| `test_ports.py` · `test_exposure.py` | Port exposure |
| `test_scoring.py` · `test_domain_scores.py` | Scoring engine |
| `test_explain.py` · `test_display_explain_hint.py` | --explain TUI |
| `test_cli.py` · `test_exit_codes.py` | CLI + exit codes |
| `tests/helpers.py` | Shared test utilities |
| *(+ 50 additional test files)* | Full coverage across all modules |
