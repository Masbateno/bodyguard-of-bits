# BOB — Distribution particularities matrix

A field-tested catalogue of the distribution quirks that matter to BOB's checks:
init system, config-file layout, package manager, firewall, MAC framework,
privilege-escalation tool, bootloader path, and more — with, per row, **whether
BOB handles it today** and a pointer to the gap when it does not.

Its purpose is to save us re-discovering the same quirk on the next machine, and
to make cross-distro check design deliberate instead of Debian-by-default.

## Provenance

Everything here is **measured on real machines**, not inferred. The rows below
come from eight real field-tested hosts (plus supporting VMs):

| Distro | Version | Arch / libc | Python | Init |
|--------|---------|-------------|--------|------|
| Debian | 13 (trixie) | x86-64 / glibc | 3.13.5 | systemd |
| Ubuntu Server | 26.04 LTS | x86-64 / glibc | 3.14.4 | systemd |
| Linux Mint | 22.3 (Ubuntu noble base) | x86-64 / glibc | 3.12.3 | systemd |
| Fedora | 44 Server | x86-64 / glibc | 3.14.3 | systemd |
| openSUSE Leap | 16.0 | x86-64 / glibc | 3.13.14 | systemd |
| Kali | Rolling | x86-64 / glibc | 3.13.12 | systemd |
| Alpine | 3.24 | x86-64 / **musl** | 3.14.7 | **OpenRC** / busybox-init |
| Raspberry Pi OS | trixie (Pi Zero W) | **armv6l** / glibc | 3.13.5 | systemd |

Anything not yet seen on real hardware (Arch, *BSD) is called out as unverified
rather than guessed.

## Coverage legend

- **✓** — BOB handles this correctly, **verified on ≥1 real machine**.
- **✓ (0.21.3)** — gap closed in code for 0.21.3, **guarded + mutation-tested**, but
  **field re-verification on the real distro is still pending** (the fix is proven
  by tests, not yet re-confirmed on the hardware that surfaced it).
- **⚠** — partial or cosmetic issue (verdict usually right, wording/edge off).
- **✗** — genuine gap; BOB is wrong or blind here. Each ✗/⚠ names the finding.

**Two governance rules for this file** (it exists to prevent the very doc-drift
0.21.1 corrected, so it holds itself to the same bar):

1. A **✓** must have been verified on at least one real machine, or be marked
   explicitly as unverified / test-only. A **✓ (0.21.3)** is test-only until a
   field pass moves it to plain ✓.
2. A quirk **not encountered** is never inferred just because it is "known" for a
   distribution. Rows for untested distros (Arch, *BSD) say so.

**Convention vs observed state.** A "Distro → mechanism" cell (e.g. *Fedora →
firewalld*) is the distribution's *convention*; a runtime property (e.g.
*firewalld active*) is a *property of the measured host*. They differ: a Fedora
can ship firewalld yet have it stopped, and a Kali can have nftables/iptables
available with no firewall actually active. Where the distinction bites, it is
called out.

**Status verified against BOB 0.21.3.** A ✓ describes 0.21.3, not necessarily a
later HEAD.

---

## 1. Init / service manager

| Distro | Manager | Service-state command | `systemd-analyze` |
|--------|---------|-----------------------|-------------------|
| Debian, Ubuntu, Mint, Fedora, openSUSE, Kali, Pi OS | systemd | `systemctl is-active/is-enabled` | available |
| Alpine | **OpenRC** (busybox-init as PID 1) | `rc-service <svc> status`, `rc-status` | **absent** |

**BOB status:**
- **✓** Banner names the manager (systemd / OpenRC …); on OpenRC, `systemd-analyze`
  and `systemctl` service-state checks degrade honestly ("not available →
  skipped") rather than reading a service as stopped.
- **✓ (0.21.3)** The dynamic fix commands were already OpenRC-aware via
  `service_restart_cmd()`; the static SSH explain/detail strings that hardcoded
  `systemctl restart ssh` now also name the `rc-service` form. *Fix: extend the 27
  static hints (EN+FR); guard `test_v0213_openrc_fix_wording.py` forbids any
  `systemctl restart ssh` string without an `rc-service` mention.*
  **Evidence/oracle:** on Alpine, `bob --explain ssh.permit_root_login` must not
  show a systemd-only restart.
  **Design rule:** service-lifecycle remediation abstracts over the init system;
  never emit `systemctl` unconditionally.

## 2. Config-file layout — `/etc` vs `/usr/etc`

Most distros keep editable config in `/etc`. **openSUSE Leap 16** ships vendor
defaults under `/usr/etc/<file>`, with `/etc/<file>` as the *optional* override
(the systemd vendor-config convention: `/etc` wins when present, else `/usr/etc`).

| File | Debian family / Fedora / Kali / Alpine / Pi | openSUSE Leap 16 |
|------|---------------------------------------------|------------------|
| `sshd_config` | `/etc/ssh/sshd_config` | **`/usr/etc/ssh/sshd_config`** (absent from `/etc`) |
| `login.defs` | `/etc/login.defs` | **`/usr/etc/login.defs`** |
| `sudoers` | `/etc/sudoers` | **`/usr/etc/sudoers`** (mode 444; `@includedir /etc/sudoers.d` **and** `/usr/etc/sudoers.d`) |

**BOB status:** before 0.21.3 BOB read only the `/etc` paths, so on openSUSE:
- **sshd_config** — `/etc/ssh/sshd_config` is absent, so BOB never followed the
  `Include /etc/ssh/sshd_config.d/*.conf` declared in the `/usr/etc` file and
  **reported OpenSSH compiled-in defaults for every config-derived SSH finding**;
  a real `PermitRootLogin yes` was masked as "✔ root login restricted".
  *(MEDIUM-HIGH — was the most serious gap; host keys, read by a separate glob,
  were always real.)*
- **login.defs** — reported the default `PASS_MAX_DAYS 99999` (coincidentally
  correct here; would misreport a stricter `/usr/etc` policy). *(LOW.)*
- **sudoers** — main file unread, but `/etc/sudoers.d` **was** read (a
  `NOPASSWD:ALL` there is caught); only rules directly in `/usr/etc/sudoers[.d]`
  escaped. *(LOW.)*

- **✓ (0.21.3)** BOB now resolves `/etc/<f>` first, then falls back to
  `/usr/etc/<f>` (`sshd_config`, `login.defs`, `sudoers` + both `sudoers.d` dirs).
  Guards `test_v0213_sshd_config_usr_etc_fallback.py`,
  `test_v0213_usr_etc_login_defs_sudoers.py`; mutations
  `ssh/usr-etc-sshd-config-not-read`, `password_policy/login-defs-usr-etc-not-read`,
  `file_perms/sudoers-usr-etc-vendor-not-read`.
  **Evidence/oracle (field re-verify pending):** on openSUSE Leap 16, forge
  `PermitRootLogin yes` (`sshd -T` = yes) → BOB must ALERT; forge `permit`/`NOPASSWD`
  under `/usr/etc/sudoers.d` → must be caught.
  **Design rule:** for config that a distro may ship under `/usr/etc`, resolve
  `/etc/<f>` then `/usr/etc/<f>` (systemd vendor-config precedence); prefer the
  service's *effective* view (`sshd -T`) where practical.
- **✓** Where `/etc/ssh/sshd_config` exists (every other distro), the parser was
  always correct — a forged `PermitRootLogin yes` on Alpine is detected as an
  ALERT. This is what isolated the bug to the `/usr/etc` layout.

## 3. Package manager & updates

| Distro | Manager | Security channel | BOB updates query |
|--------|---------|------------------|-------------------|
| Debian, Ubuntu, Mint, Pi OS | apt | `*-security` suite (debian-/noble-/jammy-security) | `apt list --upgradable`, classify by suite |
| Kali | apt (**rolling**) | **none** (no `-security` suite) | pending counted, "no security channel to classify" |
| Fedora | dnf | yes | `dnf updateinfo --security` + `check-update` |
| openSUSE | zypper | yes | `zypper list-patches --category security` + `list-updates` |
| Alpine | **apk** | **none** | `apk version -l '<'` (all pending = regular) |
| Arch *(unverified)* | pacman | **none** | `pacman -Qu` (all pending = regular) |

**BOB status:**
- **✓** The **four field-tested managers** (apt / dnf / zypper / apk) are handled
  and real-machine-verified; **pacman is implemented but unverified** (Arch has
  never been field-tested — see the provenance rule). The "no security channel"
  case (Kali/Alpine, and pacman by design) is explicit — BOB does not read "0
  security pending" as "secure".
- **✓** Microcode-package mapping per manager: apt `amd64-microcode`, dnf
  `amd-ucode-firmware`, **zypper `ucode-amd` / `ucode-intel`** (added v0.20.4),
  apk/pacman standard.

## 4. Firewall

Column is the distro *convention* (default front-end); the *observed* state on
the tested host is in the last column where it differs.

| Distro | Default front-end | BOB support | Observed on tested host |
|--------|-------------------|-------------|-------------------------|
| Ubuntu, Mint, Debian, Pi OS | ufw / nftables | **✓** ufw active↔inactive, v6 awareness | ufw inactive |
| Fedora, openSUSE | firewalld | **✓** credited by zone (v0.20.2); rich-rules/forward-ports shown (v0.20.4) | firewalld active |
| Kali | nftables (no ufw) | **✓** underlying nft/iptables layer inspected | no active firewall |
| Alpine | **none by default** (awall available) | **✓** honest "no firewall / unprotected"; **✗** awall front-end not recognised (soft — nft/iptables layer still inspected) | no firewall |

**BOB status:**
- **✓ (0.21.3)** firewalld that is **installed but stopped** used to show
  "firewalld: not installed" in the banner — `firewall-cmd --version` needs the
  daemon (firewalld 2.1.2 exits non-zero when stopped), so the version probe
  returned empty. Presence is now detected by the client binary (`shutil.which`)
  and the banner reads **"installed (inactive)"** when the version is unobtainable
  but the binary is there. Guard `test_v0213_firewalld_banner_presence.py`,
  mutation `sysinfo/firewalld-stopped-reads-not-installed`. *(The score verdict —
  ALERT/unprotected — was always correct; only the banner presence line was
  wrong.)*
  **Evidence/oracle (field re-verify pending):** on Fedora/openSUSE, `systemctl
  stop firewalld` → banner must read "installed (inactive)", not "not installed".

## 5. MAC framework (LSM)

| Distro | MAC | Notes |
|--------|-----|-------|
| Debian, Ubuntu, Mint, Kali | AppArmor | Kali ships **0 profiles** (framework active, nothing enforced) |
| Fedora | SELinux | enforcing by default |
| **openSUSE Leap 16** | **SELinux** | enforcing (Leap 16 switched from AppArmor to SELinux, but the kernel still has AppArmor **compiled-in but off**) |
| Alpine | **none** | AppArmor compiled-in but not enabled; no SELinux userspace |
| Pi OS | AppArmor **compiled-in, off at boot** | needs `apparmor=1 security=apparmor` on the kernel cmdline |

**BOB status:**
- **✓** AppArmor enforcing / complain / 0-profile (read from kernel securityfs,
  not the exit-2 `aa-status`), SELinux enforcing, and "no MAC" all read correctly.
- **✓ (0.21.3)** `mac_policy` branch ordering: on a **SUSE-style kernel (AppArmor
  compiled-in-off) where SELinux is the real MAC**, a **Permissive** (or Disabled)
  SELinux used to hit the `apparmor_off_in_kernel` branch first and suggest
  `apparmor=1` instead of `setenforce 1`. The AppArmor-off / inactive branches now
  defer when SELinux is the installed MAC, so a permissive/disabled SELinux
  reaches its own verdict. Guard `test_v0213_mac_policy_selinux_precedence.py`,
  mutation `mac_policy/apparmor-off-steals-selinux-permissive`. *(MEDIUM.
  SELinux-enforcing short-circuits at the top, so only the non-enforcing case
  changed; Alpine's identical AppArmor-off warning stays **correct** — Alpine
  genuinely has no MAC and no SELinux.)*
  **Evidence/oracle (field re-verify pending):** on openSUSE Leap 16, `setenforce
  0` → verdict must be the SELinux-permissive one (`setenforce 1`), not "enable
  AppArmor".
  **Design rule:** when a distro ships SELinux as its MAC, AppArmor-compiled-in-off
  is by design, not a finding; the SELinux state is the verdict.

## 6. Privilege escalation — sudo vs doas

| Distro | Tool | Config | Passwordless grant |
|--------|------|--------|--------------------|
| Debian, Ubuntu, Mint, Fedora, openSUSE, Kali, Pi OS | sudo | `/etc/sudoers`, `/etc/sudoers.d/` | `NOPASSWD:ALL` |
| **Alpine** (BSD-style) | **doas** | **`/etc/doas.conf`** | **`permit nopass`** |

**BOB status:**
- **✓** sudo: `/etc/sudoers` + `/etc/sudoers.d`, `NOPASSWD:ALL` and empty-group
  latent grants flagged.
- **✓ (0.21.3)** **doas is now audited.** `/etc/doas.conf` is parsed: a
  `permit nopass` with no `cmd` clause is unrestricted passwordless root (WARN −2,
  the `NOPASSWD:ALL` equivalent), a `cmd`-scoped one is INFO, a `deny` never
  grants, and a FIFO/denied file reads as unreadable (never a hang). Dedicated
  `--explain file_perms.doas_nopass_all`. Guard `test_v0213_doas_audit.py`,
  mutation `file_perms/doas-nopass-not-flagged`.
  **Evidence/oracle (field re-verify pending):** on Alpine, forge `permit nopass
  baduser as root` in `/etc/doas.conf` → BOB must WARN.
  **Design rule:** privilege-escalation detection abstracts over the backend
  (sudo *and* doas), never assumes sudo.
- **✓ (0.21.3)** SUID baseline: `doas` (standard SUID sudo-replacement) and
  `/bin/bbsuid` (busybox-suid) are now in the known-safe SUID set, so they are no
  longer flagged "unexpected" on Alpine. Guard `test_v0213_suid_doas_bbsuid.py`,
  mutation `suid/doas-flagged-unexpected`. *(LOW.)*

## 7. Bootloader / GRUB

| Distro | grub.cfg path | Notes |
|--------|---------------|-------|
| Debian, Ubuntu, Mint, Kali, Alpine | `/boot/grub/grub.cfg` | |
| Fedora, openSUSE | `/boot/grub2/grub.cfg` | RPM family uses `grub2` |
| Raspberry Pi | *(none)* | Broadcom bootloader — no GRUB |

**BOB status:** **✓** Both `/boot/grub` and `/boot/grub2` are found; the Pi's
absence of GRUB is not a false warning (bootloader is firmware).

## 8. Banner distro logo (emoji)

🔴 Debian · 🟠 Ubuntu · 🌿 Linux Mint · 🔵 Fedora · 🦎 openSUSE · 🐉 Kali ·
🗻 Alpine · 🍓 Raspberry Pi · 🐧 anything unrecognised. Each is a single
East-Asian-Wide code point so the banner box stays aligned.

## 9. Other measured quirks

- **Alpine ships minimal:** no `bash`, no `python3` by default (`apk add` both).
  BOB itself is pure Python (0 stdlib deps) so it needs only `python3`; test
  harnesses that assume `#!/bin/bash` fail silently.
- **kexec:** Alpine locks it by default (`kexec_load_disabled=1`); most others do
  not — INFO, not a verdict.
- **Raspberry Pi:** cloud-init / imager can leave provisioning credentials on the
  boot partition; the ssh daemon may appear as `sshd-session`. ARM `armv6l`
  (Pi Zero) is genuinely slow — see the perf note below.
- **`/etc/os-release`** is the reliable distro identifier everywhere; hostname is
  not (a reinstalled/cloned box keeps an inherited name — several test boxes read
  `debiantest` regardless of the actual OS).

## 10. Performance note (not a distro quirk, but bites field tests)

A slow BOB run is almost always **external CPU/disk starvation, not BOB**: a
loaded server (measured: Wekan/mongod on a 4-core box, load 6–8) makes a normal
~10 s audit take 80–120 s. A **real hang is unbounded**; slowness completes. When
a run looks stuck, disprove a hang by: (1) `uptime` load vs `nproc`, (2) a clean
audit under a generous timeout, (3) per-check FIFO probes with a timeout far above
a single check's runtime — never conclude "hang" from a whole-audit timeout on a
busy host.

## Gaps and their resolution

These are not eight independent bugs. They fall into a few classes, and the two
most serious share one root cause — *BOB knew the security control but not the
mechanism the distribution actually uses*:

```
Distro-aware mechanism resolution        Distro-aware baseline
├── SSH config layout (/usr/etc)         └── SUID expectations (doas/bbsuid)
├── privilege-escalation backend (doas)
├── config file layout (login.defs/sudoers)   Pure wording
└── init/service-manager remediation     └── generic firewall / systemctl hints
```

**Resolved in 0.21.3** (all guarded + mutation-tested, and — as of 2026-09-26 —
**all field-re-verified on real hardware**; no gap is test-only). The **Field**
column names the machine and the oracle replayed.

| # | Gap | Sev. | § | Field re-verified | Guard / mutation |
|---|-----|------|---|-------------------|------------------|
| 1 | SSH audit blind on `/usr/etc` (reported OpenSSH defaults) | MEDIUM-HIGH | §2 | **✓ openSUSE Leap 16** (forged `PermitRootLogin yes`, sshd -T=yes → ALERT); `/etc` non-regression ✓ Alpine+Pi | `test_v0213_sshd_config_usr_etc_fallback` · `ssh/usr-etc-sshd-config-not-read` |
| 2 | `/etc/doas.conf` not audited (passwordless doas invisible) | MEDIUM | §6 | **✓ Alpine 3.24** (forged `permit nopass` → WARN; full/scoped/deny/persist polarity + FIFO + hostile) | `test_v0213_doas_audit` · `file_perms/doas-nopass-not-flagged` |
| 3 | `mac_policy` mis-ordered SELinux-permissive vs AppArmor-off | MEDIUM | §5 | **✓ openSUSE Leap 16** (`setenforce 0` → "SELinux permissive → setenforce 1", not AppArmor); no-SELinux side ✓ Pi | `test_v0213_mac_policy_selinux_precedence` · `mac_policy/apparmor-off-steals-selinux-permissive` |
| 4 | `login.defs` / `sudoers` in `/usr/etc` not read | LOW | §2 | **✓ openSUSE Leap 16** (`/usr/etc/login.defs` value read — 99999-finding disappears at 42; `/usr/etc/sudoers.d` NOPASSWD caught) | `test_v0213_usr_etc_login_defs_sudoers` · 2 mutations |
| 5 | firewalld "not installed" when merely stopped | LOW | §4 | **✓ openSUSE Leap 16** (`systemctl stop firewalld` → banner "installed (inactive)") | `test_v0213_firewalld_banner_presence` · `sysinfo/firewalld-stopped-reads-not-installed` |
| 6 | doas / bbsuid flagged "unexpected SUID" | LOW | §6 | **✓ Alpine 3.24** ("All SUID known-safe (2 SUID)") | `test_v0213_suid_doas_bbsuid` · `suid/doas-flagged-unexpected` |
| 7 | fix wording `systemctl` vs OpenRC `rc-service` | LOW | §1 | **✓ Alpine 3.24** (`--explain` shows rc-service) | `test_v0213_openrc_fix_wording` · `locale/ssh-restart-hint-systemd-only` |

*Alpine 3.24 field pass (0.21.3, 2026-09-26): baseline clean (0.21.3, OpenRC, 0
sentinels). doas parser verified across all four cases — full `permit nopass`
→ WARN −2, `cmd`-scoped → INFO, `deny` and `permit persist` → ignored; its new
read path is FIFO-safe (mkfifo `/etc/doas.conf` → no-hang) and fail-closed on a
dangling symlink. SUID: "All SUID known-safe (2 SUID)". rc-service hint present.
firewalld-absent still reads "not installed" (no false "installed (inactive)").
FIFO-sshd no-hang and forged `PermitRootLogin yes` → ALERT confirm the ssh-probe
restructure did not regress `/etc` detection. **A/B audit 0.21.2 ↔ 0.21.3
(normalised): the only substantive diff is the intended SUID fix (2 unexpected →
known-safe, System Hardening 6→7); everything else is the dedup counter shifting
by the one removed finding — no unintended regression.***

*Raspberry Pi OS field pass (0.21.3, 2026-09-26, Pi Zero W armv6l): a
Debian-style host with **none** of the fixed conditions (no doas, no `/usr/etc`,
no SELinux, no firewalld) — the cleanest non-regression bench. A JSON A/B
0.21.2 ↔ 0.21.3 is **identical**: same global score (6), same per-domain scores,
same finding-key set (∅ added, ∅ removed). Regressions confirmed on ARM: FIFO
`sshd_config` no-hang; forged `PermitRootLogin yes` → ALERT (ssh-probe
restructure intact); `mac_policy` still emits `apparmor_off_in_kernel` (the
`not selinux_installed` guard did not break a no-SELinux host); doas parser
portable (forged `permit nopass` → WARN on ARM/Debian too). So 0.21.3 changes
nothing on a host without the fixed conditions — proven on two real hosts
(Alpine + Pi).*

*openSUSE Leap 16 field pass (0.21.3, 2026-09-26, real, SELinux enforcing +
firewalld active, `/etc/ssh/sshd_config` absent → `/usr/etc`): the four openSUSE
gaps re-verified on hardware. **#1** — forged `PermitRootLogin yes` (drop-in,
sshd -T=yes) → ✖ ALERT (0.21.2 read OpenSSH defaults and missed it). **#3** —
`setenforce 0` → "SELinux is in permissive mode → setenforce 1", not the false
"enable AppArmor"; `setenforce 1` restored. **#4** — `PASS_MAX_DAYS 42` appended
to `/usr/etc/login.defs` → the "not enforced (99999)" finding disappears (BOB
reads the vendor value, not the absent-`/etc` default); a NOPASSWD:ALL in
`/usr/etc/sudoers.d` → caught. **#5** — `systemctl stop firewalld` → banner
"firewalld: installed (inactive)"; restarted. Box fully restored (Enforcing,
firewalld active, all forges removed). **With this, all seven 0.21.3 fixes are
field-verified on real hardware (Alpine + Pi + openSUSE) — no test-only rows
remain.***

*Linux Mint 22.3 field pass (0.21.3, 2026-09-26, real, Ubuntu-noble base): a
second Debian-style non-regression bench, and a new context — **AppArmor active
with enforcing profiles** (25 enforce, 6 complain), where the `mac_policy` fix
must *not* change the verdict (branch 3, untouched by the `not selinux_installed`
guard). Confirmed: `mac_policy` reads "AppArmor enforcing — 25 enforce, 6
complain" unchanged. JSON A/B 0.21.2 ↔ 0.21.3 (`--profile server`) **identical**
(score 5, same domains, same finding-keys). Regressions/portability all green:
firewalld-absent → "not installed"; FIFO-sshd no-hang; forged `PermitRootLogin
yes` → ALERT; doas parser portable (forged `permit nopass` → WARN); `/etc/sudoers.d`
NOPASSWD caught; SUID all-known-safe (18 SUID). Non-regression now proven on three
Debian-style real hosts (Pi + Mint + Alpine's A/B). Full CLI matrix clean on Mint
(exit codes for `--version`/`--help`/valid & invalid `--explain`/`--check`/
`--min-level`/`--target`/`--badflag`/`--profile bogus`/`--lang zz`; 0 traceback),
and the new `--explain file_perms.doas_nopass_all` renders title/why/how/CIS in
both locales, appears in `--explain list`, and JSON stays valid.*

*Ubuntu Server 26.04 field pass (0.21.3, 2026-09-26, real, heavily loaded — php/
node/Wekan, load 6–9 on 4 cores): a third Debian-style non-regression bench and a
**perf-discipline** stress. JSON A/B 0.21.2 ↔ 0.21.3 (`--profile server`)
**identical** (score 6, same domains, same finding-keys). The loaded box made the
FIFO-sshd probe take **195 s** — it still completed (no-hang); with a naive 40 s
timeout it would have read as a false HANG (the lesson: never call a hang from a
whole-check timeout on a starved host). CLI matrix clean; polarity (PermitRootLogin/
shadow/sudoers.d/doas) all fire; SUID all-known-safe (15); firewalld-absent →
"not installed"; updates classify the apt `-security` channel ("5 security
pending"); AppArmor 214-enforce unchanged. `--fix --apply` correctly says **"No
automatic fix available"** for the sensitive `chmod /etc/shadow` (shows it for
manual run) — it declines rather than lies (v0.16.4 behaviour). Samba: the
initial re-check was blocked by a pre-existing interrupted-dpkg state
(unattended-upgrades kept re-grabbing the lock); after masking the apt timers,
`dpkg --configure -a` + install succeeded, and the oracles passed — forged
`server min protocol = NT1` → ✖ ALERT (EternalBlue), FIFO `smb.conf` no-hang
(12 s). apt timers unmasked afterwards; dpkg state left repaired. Non-regression
now proven on **four real hosts** (Pi + Mint + Ubuntu + Alpine's A/B).*

*Fedora 44 Server field pass (0.21.3, 2026-09-26, real, SELinux enforcing +
firewalld active + dnf/rpm — a distro family not otherwise exercised): JSON A/B
0.21.2 ↔ 0.21.3 (`--profile server`) **identical** (score 7, same domains, same
finding-keys — SELinux-enforce + firewalld-active means no fixed condition
triggers). **#3 on native SELinux** (no AppArmor compiled in, so a clean path):
enforcing → OK; `setenforce 0` → "SELinux permissive → setenforce 1" (not the
false AppArmor advice). **#5 on native firewalld**: active → credited (zone
FedoraServer); `systemctl stop firewalld` → banner "installed (inactive)".
Mechanisms: GRUB `/boot/grub2` 0600, dnf `-security` channel ("363 security
pending"). CLI matrix clean; polarity (PermitRootLogin/shadow/sudoers.d/doas) all
fire; FIFO-sshd no-hang; samba via **dnf** → SMB1 ALERT + FIFO `smb.conf` no-hang.
`--fix` honestly declines the sensitive `chmod /etc/shadow`. *(Pre-existing box
observation, identical in 0.21.2 by A/B: 21 "unexpected SUID" from installed
kismet/glusterfs helpers — a real WARN, not a regression.)* Non-regression proven
on **five real hosts** (Pi + Mint + Ubuntu + Fedora + Alpine's A/B); 0.21.3 now
field-verified across Alpine, Pi, openSUSE, Mint, Ubuntu and Fedora.*

**Still open:**

| Gap | Sev. | § | Note |
|-----|------|---|------|
| awall front-end not recognised | soft | §4 | The Alpine-native firewall builder is not read as a front-end, but the underlying nft/iptables ruleset it generates *is* inspected — so a host with active awall rules is not read as unprotected. Low urgency. |

---
© 2026 Cédric Clauzel
