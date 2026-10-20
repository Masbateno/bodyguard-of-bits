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
- **✓ (0.21.3)** — gap closed in code for 0.21.3, **guarded + mutation-tested**, then
  **field-re-verified on real hardware** on 2026-09-26 (all seven; the machine and
  the oracle replayed are in *Gaps and their resolution*).
- **⚠** — partial or cosmetic issue (verdict usually right, wording/edge off).
- **✗** — genuine gap; BOB is wrong or blind here. Each ✗/⚠ names the finding.

**Two governance rules for this file** (it exists to prevent the very doc-drift
0.21.1 corrected, so it holds itself to the same bar):

1. A **✓** must have been verified on at least one real machine, or be marked
   explicitly as unverified / test-only. A row found by reading the code and not
   yet seen on a machine says so.
2. A quirk **not encountered** is never inferred just because it is "known" for a
   distribution. Rows for untested distros (Arch, *BSD) say so.

**Convention vs observed state.** A "Distro → mechanism" cell (e.g. *Fedora →
firewalld*) is the distribution's *convention*; a runtime property (e.g.
*firewalld active*) is a *property of the measured host*. They differ: a Fedora
can ship firewalld yet have it stopped, and a Kali can have nftables/iptables
available with no firewall actually active. Where the distinction bites, it is
called out.

**Status.** Sections 1–10 were verified against BOB 0.21.3 and are amended where a
later release changed a row (the amendment names its release); the field-pass
sections that follow *Gaps and their resolution* record 0.22.0 → 0.25.0. A ✓ is
only as current as the release it names.

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
  **Evidence/oracle (field-verified 2026-09-26 on openSUSE Leap 16):** forged
  `PermitRootLogin yes` (`sshd -T` = yes) → ALERT; a `NOPASSWD` under
  `/usr/etc/sudoers.d` → caught.
  **Design rule:** for config that a distro may ship under `/usr/etc`, resolve
  `/etc/<f>` then `/usr/etc/<f>` (systemd vendor-config precedence); prefer the
  service's *effective* view (`sshd -T`) where practical.
- **✓** Where `/etc/ssh/sshd_config` exists (every other distro), the parser was
  always correct — a forged `PermitRootLogin yes` on Alpine is detected as an
  ALERT. This is what isolated the bug to the `/usr/etc` layout.

## 3. Package manager & updates

| Distro | Manager | Security channel | BOB updates query |
|--------|---------|------------------|-------------------|
| Debian, Ubuntu, Mint, Pi OS | apt | `*-security` suite (debian-/noble-/jammy-security) | `apt-get -s dist-upgrade` (fallback `apt list --upgradable`), classify by suite |
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
| Fedora, openSUSE | firewalld | **✓** credited by zone (v0.20.2); rich-rules/forward-ports shown (v0.20.4); judged by the zones of the interfaces, the policies, the sources and the address family since 0.24.3 (see the 0.24.2 / 0.24.3 field passes) | firewalld active |
| Kali | nftables (no ufw) | **✓** underlying nft/iptables layer inspected | no active firewall |
| Alpine | **none by default** (awall available) | **✓** honest "no firewall / unprotected", capped like an inactive UFW since 0.26.0; **✓** awall named as the front-end with its enabled policies, and "installed, no policy enabled" said as such (0.26.0, see the 0.26.0 Alpine field pass) | no firewall; awall measured active and idle |

**BOB status:**
- **✓ (0.21.3)** firewalld that is **installed but stopped** used to show
  "firewalld: not installed" in the banner — `firewall-cmd --version` needs the
  daemon (firewalld 2.1.2 exits non-zero when stopped), so the version probe
  returned empty. Presence is now detected by the client binary (`shutil.which`)
  and the banner reads **"installed (inactive)"** when the version is unobtainable
  but the binary is there. Guard `test_v0213_firewalld_banner_presence.py`,
  mutation `sysinfo/firewalld-stopped-reads-not-installed`. *(The score verdict —
  ALERT/unprotected — was always correct; the banner presence line was the
  wrong part found then. 0.25.1 found the alert's own wording wrong too — next
  item.)*
  **Evidence/oracle (field-verified 2026-09-26 on openSUSE Leap 16 and Fedora 44):**
  `systemctl stop firewalld` → banner reads "installed (inactive)", not "not installed".
- **✓ (0.25.1)** the same stopped firewalld, in the alert itself: the message said
  "neither UFW nor firewalld is installed", the fix began with `zypper install
  firewalld`, and the nftables finding told the operator to load
  `/etc/nftables.conf`, which openSUSE Leap 16 does not have. The alert now says
  firewalld is installed but not running, and both findings carry the firewalld
  command without the install step; key, level and score unchanged (8 before and
  after on the test host). Guard `test_v0251_firewalld_stopped.py`, mutations
  `firewalld-stopped/*` (3).

## 5. MAC framework (LSM)

| Distro | MAC | Notes |
|--------|-----|-------|
| Debian, Ubuntu, Mint, Kali | AppArmor | Kali ships **0 profiles** (framework active, nothing enforced) |
| Fedora | SELinux | enforcing by default |
| **openSUSE Leap 16** | **SELinux** | enforcing (Leap 16 switched from AppArmor to SELinux, but the kernel still has AppArmor **compiled-in but off**) |
| Alpine | **none** by default | AppArmor compiled-in but not enabled (not in `CONFIG_LSM`); no SELinux userspace. `apparmor=1 security=apparmor` turns it on; the OpenRC `apparmor` service loads the profiles |
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
  **Evidence/oracle (field-verified 2026-09-26 on openSUSE Leap 16 and Fedora 44):**
  `setenforce 0` → the SELinux-permissive verdict (`setenforce 1`), not "enable
  AppArmor".
  **Design rule:** when a distro ships SELinux as its MAC, AppArmor-compiled-in-off
  is by design, not a finding; the SELinux state is the verdict.
- **✓ (0.25.1)** AppArmor live in the kernel, profile files in `/etc/apparmor.d`,
  none loaded because the `apparmor` service is not running: BOB used to ask for the
  profile packages (already installed) and named no apk package. It now counts the
  profile files and, when the service is not active, prints the command that starts
  it (`rc-update add apparmor boot && rc-service apparmor start` on OpenRC,
  `systemctl enable --now apparmor` on systemd); with no profile file it still asks
  for the packages, and names `apparmor-profiles` for apk. Guard
  `test_v0251_apparmor_profiles_not_loaded.py`, mutations
  `mac_policy/unloaded-profiles-read-as-missing` and
  `packages/apk-apparmor-profiles-unknown`. Field-verified on Alpine 3.24 (below).

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
  **Evidence/oracle (field-verified 2026-09-26 on Alpine 3.24):** forged `permit
  nopass baduser as root` in `/etc/doas.conf` → WARN.
  **Design rule:** privilege-escalation detection abstracts over the backend
  (sudo *and* doas), never assumes sudo.
- **✓ (0.25.0)** Printed commands use `doas` where there is no `sudo` (17 of 17
  commands on Alpine 3.24; `bob/_privilege.py`, applied in
  `CheckResult.add_finding`). The 0.25.1 work tree applies the same word to the
  `--explain` texts (guarded; not yet field-tested).
- **✓ (0.25.1, field-verified on Alpine 3.24, 2026-10-17)** BOB found the
  invoking user's home only through sudo's `SUDO_USER`, so run through `doas` its
  settings, ignore list, baseline and history went to `/root/.config/bob` and
  `--install-completion` skipped the `/usr/local/bin/bob` link. It now also reads
  `DOAS_USER`, which OpenBSD doas and OpenDoas set (`sysinfo.invoking_user_name`;
  guard `test_v0251_doas_invoking_user.py`, mutation `sysinfo/doas-user-ignored`).
  **Evidence/oracle (replayed on Alpine 3.24):** `doas env` carries
  `DOAS_USER=<operator>` and `HOME=/root`; `doas ~/.local/bin/bob --ignore
  ssh.password_auth` → the key lands in the operator's `~/.config/bob/ignore.yml`
  (owned by the operator), not root's; `doas ~/.local/bin/bob --install-completion`
  → `/usr/local/bin/bob` created; a full audit through doas writes history,
  baseline and recurrence to the operator's `~/.config/bob` and names the operator
  in the banner, while root's files stay untouched.
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

### 0.22.0 field passes — the five new coverage checks

0.22.0 added five additive checks: **kernel-module blacklist** (INFO, CIS §3.4),
**privileged `/dev` nodes** (INFO), **module-signature enforcement** (INFO, folded
into the kexec/lockdown check), **world/group-writable set-id binaries** (ALERT),
and **root PATH integrity** (WARN, from `login.defs ENV_SUPATH` / sudoers
`secure_path`). Three are INFO-only; the two deducting ones fire only on the
forged conditions below. Field-verified on two real hosts (both A/B-clean):

*Ubuntu Server 26.04 field pass (0.22.0, 2026-09-27, real, loaded — Wekan/
microk8s): JSON A/B 0.21.3 ↔ 0.22.0 (`--profile server`) **identical** — score 6,
same per-domain scores, same WARN/ALERT finding-key set (the new checks emit only
INFO/OK on this host, no trigger condition). All four forgeable new checks
round-tripped: **root_path** — `ENV_SUPATH` pointed at a world-writable dir → WARN
`root_path.dangerous` (names the source `login.defs ENV_SUPATH`), restored → OK
(this validates the *configured-source* design: BOB reads the file, not the
ambient `os.environ`); **module_blacklist** — `blacklist dccp` → candidates 11→10,
restored → 11; **dev_privileged** — `chmod o+w /dev/sda` → INFO world-accessible,
restored 660 → OK; **suid_audit.writable_suid** — a `chmod 6777` set-id binary →
✖ ALERT. Hostile: FIFO `/etc/modprobe.d/*.conf` → no-hang. module-sig reads
"unsigned modules accepted" (INFO). Two honest observations, neither a bug:
`--fix --apply` **shows** the `chmod go-w` for a writable SUID but does not
auto-apply it — **by design**: a world-writable set-id root binary is a
compromise *symptom* (something made it writable; the timestamps are evidence),
so BOB surfaces the command for the operator to run *after* investigating rather
than silently flipping the bit and hiding the cause. It never claims success. And
under CPU
starvation the SUID `find` (15 s) timed out once → honest "scan skipped", not a
hang (the full audit always completed, ~1:48).*

*Fedora 44 Server field pass (0.22.0, 2026-09-27, real, SELinux enforcing +
firewalld active + dnf/rpm): JSON A/B 0.21.3 ↔ 0.22.0 (`--profile server`)
**identical** — score 7, same domains, same WARN/ALERT keys. Same four polarity
round-trips all green (root_path via `ENV_SUPATH`, module_blacklist `blacklist
sctp` 11→10, dev_privileged `/dev/sda`, suid-writable → ALERT). **SELinux
precedence re-confirmed on native SELinux** (the 0.21.3 `mac_policy` fix): enforcing
→ OK, `setenforce 0` → INFO "SELinux permissive" + WARN "No MAC policy actively
enforcing" — **not** a false "AppArmor" verdict — `setenforce 1` restored. firewalld
credited (zone FedoraServer); GRUB `/boot/grub2` 0600; FIFO `modprobe.d` no-hang;
module-sig "unsigned accepted" (INFO). SUID `find` completed here (less loaded) —
writable-SUID ALERT confirmed live. Box restored (Enforcing, sleep unmasked).*

### 0.23.0 field pass — package integrity + the nft-aware firewall prerequisite

*Raspberry Pi OS field pass (0.23.0 WIP, 2026-10-02, Pi Zero W armv6l, Raspbian
trixie, no ufw / no firewalld / empty nft / no MAC): stress-test-total of the
0.23.0 WIP (`--exhaustive` + `package_integrity`, and the de-UFW-ised firewall
prerequisite) in A/B vs published 0.22.1. **0 regression.** A/B (`--profile
server`, corrected to compare `deductions` + counts, not a nonexistent `findings`
array): **identical** — score 6, same domain scores, same deduction keys, same
alert/warning/info counts. The B change is non-scoring; the text diff is exactly
the intended firewall-prerequisite rewording + the one-time history churn of the
key rename, and nothing else (the rest — `↩ N×` recurrence counts, live SSH-login
count, swap, a load-correlated systemd-analyze transient — is drift between two
sequential runs, not code).*

***Firewall nft-aware (B) — both polarities validated on real ARM:*** a forged
protective nftables ruleset (policy drop + established/lo/ssh accept) →
`ℹ [INFO] No managed firewall front-end (UFW/firewalld), but the netfilter layer
is filtering inbound traffic` (**no** false "no firewall" ALERT); the empty ruleset
→ `✖ [ALERT] No active firewall — neither UFW nor firewalld is installed, and the
netfilter layer is not filtering inbound traffic`, explain
`prerequisites.firewall_missing`. The doctrine-positive fix (do not cry "no
firewall" when nftables is filtering) holds in both directions. Watchdog +
self-restoring ruleset; SSH survived the policy-drop.

***package_integrity:*** debsums absent → `ℹ [INFO] Package integrity was not
verified — debsums is not installed` (honest, unknown ≠ clean). With debsums
installed, the check **times out every run** on this hardware — see the new "Still
open" row. The timeout path itself is correct: group-killed, honest "result not
established", no hang, no crash. CLI: `--explain prerequisites.firewall_missing`
renders title/why/how EN + FR; the old `prerequisites.ufw_missing` explain key is
gone (exit 3); `package_integrity.*` has no explain (INFO-only, exit 3); `--exhaustive`
is in `--help` and bash-completion. Box fully restored (nft flushed, base64 restored
from backup, debsums removed, `/root/st` cleaned).*

*Linux Mint 22.3 field pass (0.23.0 WIP, 2026-10-02, real so6minttest, x86_64
4-core, Py 3.12.3, **ufw installed but inactive**, AppArmor enabled, French
locale): A/B 0.23.0 ↔ 0.22.1 (`--profile server`, comparing `deductions` +
counts) **identical** — score 6, same domains, same deduction keys, same
alert/warning/info counts; text diff = only the "previous audit" timestamp. The
expected non-regression: with ufw **installed**, `check_firewall` never reaches
the B branch (the netfilter signal is not even probed), so B is a no-op here —
proving it does not touch the common ufw path. `package_integrity` renders
correctly in **French** ("INTÉGRITÉ DES PAQUETS" / "Intégrité des paquets non
vérifiée — debsums n'est pas installé"), 0 sentinels. `debsums -c` = **511 s** on
this full desktop install (21 genuinely-changed files). Box restored (base64 from
backup, debsums removed, `/root/st` cleaned).*

*Ubuntu Server 26.04.1 LTS field pass (0.23.0 WIP, 2026-10-02, real
so6ubuntuservertest, x86_64 4-core, **Python 3.14.4**, ufw installed but
inactive, AppArmor enabled, freshly booted → load 7–12): A/B 0.23.0 ↔ 0.22.1
(`deductions` + counts) clean — score 6, same domains, same deduction keys, same
alert/warning counts; the only diff is `info_count` 62 vs 63, traced to the live
"established TCP connection(s)" line (53 vs 52) — network drift, not code. Banner
🟠 Ubuntu, 0 traceback. **B is a no-op here too** (ufw installed → the B branch is
never reached, the netfilter signal not even probed) — confirmed on a second
Ubuntu base **and on Python 3.14.4**. Under genuine CPU starvation (load 7–12 from
the boot storm) the audits still completed in ~5 min — slowness, not a hang
(the "famine is not a hang" lesson holds). **`package_integrity` under
famine:** `debsums -c` took **639 s**, and the `--exhaustive` audit **completed
under the 1800 s hang-guard without false-timing-out** — the decisive validation
that 1800 s is a hang-guard, not a slowness cap. Two real-world observations, not
bugs: (1) an earlier `apt-get install debsums` **failed on the dpkg lock held by
`unattended-upgrades`** during the boot storm, so BOB correctly reported "debsums
not installed" (honest — it genuinely was not); (2) on stock Ubuntu 26.04,
**`debsums` reports ~115 `rust-coreutils` files as changed** — uutils ships one
multicall binary with 115 hardlinks whose recorded digest does not match, so BOB
surfaces one aggregated INFO "115 packaged file(s) differ" (config-filtered,
sample-capped). Faithful to `debsums`, INFO-only (reported-not-scored), but
notably noisy on 26.04 — the operator reads it as the packaging artifact it is.
The GNU-coreutils tamper round-trip is cleanly shown on Mint instead (a uutils
multicall binary cannot be individually tampered — every name is the same inode).
Box restored (`rust-coreutils` reinstalled to undo the test write, debsums
removed, `/root/st` cleaned).*

*Fedora Server 44 field pass (0.23.0 WIP, 2026-10-02, real, x86_64 4-core,
**Python 3.14.3**, **SELinux enforcing**, **firewalld active**, GNU coreutils,
rpm 6.0.1): A/B 0.23.0 ↔ 0.22.1 **identical** — score 7, same domains, same
deduction keys, same alert/warning/info counts; text diff = only a non-deterministic
listening-port order (5355/tcp↔udp) and the previous-audit timestamp. Banner 🔵
Fedora, firewalld credited (zone FedoraServer: cockpit, dhcpv6-client, ssh), 0
traceback. **B is a no-op here too** — firewalld active, so `check_firewall`
returns on the firewalld-credit branch before the B netfilter code; third
mechanism confirmed after ufw ×2, and on **Python 3.14.3**. **`package_integrity`
via `rpm -Va` — the complementary verifier, full round-trip on real hardware:**
`rpm -Va` = 496 s / 20 lines; the clean audit reports **2** files
(`/usr/share/texlive/.../language.dat`, `.def` — regular, digest-changed) and
correctly **filters** rpm's config (`c` `/etc/texlive/.../updmap.cfg`) and ghost
(`g` `fmtutil.cnf`) lines — the `c`-flag filtering proven on real rpm output, not
just podman; tampering `/usr/bin/base64` → **3** (base64 added, first); restoring →
back to **2**. Completes well under the 1800 s hang-guard. With Mint's debsums
round-trip, **both package verifiers are now validated end-to-end on real
hardware.** Box restored (base64 from backup — GNU coreutils is a real file, no
uutils multicall trap — `/root/st` cleaned).*

*Kali Rolling field pass (0.23.0 WIP, 2026-10-02, real so6kalitest, x86_64,
**Python 3.14.7**, no ufw, empty nft ruleset, firewalld inactive, AppArmor
enabled): the B change fires **naturally** here (unlike the Pi, where the
protective-nft side had to be forged) — a genuine nft-only host with no filtering
ruleset. A/B 0.23.0 ↔ 0.22.1: JSON **identical** (score 6, same deduction keys /
counts — `firewall_missing` is a non-deducting ALERT, so the rename does not move
the score), and the text diff is **exactly** the intended B change and nothing
else: ALERT `UFW is not installed` → `No active firewall — neither UFW nor
firewalld is installed, and the netfilter layer is not filtering inbound traffic`,
remediation `sudo apt install -y ufw` → `… && sudo ufw enable`, explain key
`ufw_missing` → `firewall_missing`, plus the one-time history churn of the rename.
Banner 🐉, 0 traceback, `package_integrity` → honest "not verified" (debsums
absent). Re-confirms B on x86 + the newest Python (3.14.7). Box cleaned.*

*Debian 13 (trixie) field pass (0.23.0 WIP, 2026-10-03, real so6debiantest,
x86_64, Python 3.13.5, minimal — 369 packages, no ufw, empty nft, firewalld
inactive, AppArmor enabled, GNU coreutils): A/B 0.23.0 ↔ 0.22.1 **identical**
(score 7, same deduction keys / counts), text diff = **exactly** the B rename
(`UFW is not installed` → `No active firewall …`, remediation `… && sudo ufw
enable`, explain `ufw_missing` → `firewall_missing`, one-time history churn) and
nothing else. Banner 🔴 Debian, 0 traceback. **B fires naturally** here too
(third natural-fire host after Pi and Kali). **`package_integrity` — the cleanest
debsums round-trip of the campaign:** after configuring sources + installing
debsums, `debsums -c` = 48 s / 0 changed (minimal install, genuinely clean), so
the audit shows the **OK/clean verdict** — `✔ No packaged file differs from the
manager's recorded digest (debsums verified)` — the only host where that path is
seen (Mint had 21 real changes, Fedora 2, Ubuntu 115 uutils); tampering
`/usr/bin/base64` → exactly **1** file differs (no baseline noise); `truncate -s
-2` → back to OK. A full **OK → 1 → OK** round-trip. Sixth real machine, 0
regression.*

### 0.24.0 field pass — the new coverage checks, on eight real machines

*Stress-test-total of the 0.24.0 WIP (2026-10-04) on every real machine: baseline,
A/B vs published 0.23.0 (`deductions` + counts + text diff), CLI matrix, both
polarities of every new check, hostile inputs (FIFO / dangling symlink / directory)
on every new read path, a `--fix` round-trip and an integrity check. Fourteen
defects were found and fixed before release; the A/B diff on every host is the new
checks plus, where it applies, `su_unrestricted` (root with a usable password).*

| Host | Defects found → fixed | Distribution facts measured |
|------|-----------------------|-----------------------------|
| Mint 22.3 (ufw inactive) | 4 — bound-address wording behind a default-deny firewall; `--check` on a slow section silent; present-but-unreadable `login.defs` silent; lazy-snapshot contract | `openvpn.service` is a `/bin/true` umbrella; `fs.protected_fifos=1`, `regular=2` |
| Ubuntu Server 26.04 (snaps) | 1 — snapd's `snap-confine` carries 10 permitted capabilities instead of SUID | apparmor restricts unprivileged userns; load 6–9 at boot from snaps (famine, not BOB) |
| Raspberry Pi Zero W (ARMv6) | 1 — no `/sys/devices/system/cpu/vulnerabilities` on ARMv6: now "not reported", not a visibility limit | no Yama (`kernel.yama.ptrace_scope` absent, as in 0.23.0); 160–357 s per audit |
| Kali Rolling | 0 | — |
| Fedora 44 (SELinux enforcing, firewalld) | 2 — sssd helpers / httpd `suexec` / KDE capabilities; `pam_unix` md5 in `system-auth` hidden by `password-auth` | crypto-policies `DEFAULT` (real `LEGACY` / `DEFAULT:SHA1` round-trips); 0 AVC denials; `rpm -Va` 606 s |
| openSUSE Leap 16 (SELinux, firewalld) | 3 — vendor `/usr/etc/zypp/zypp.conf` unread; unreadable `/etc/login.defs` hidden by the vendor copy; a negated-unreadable branch | `login.defs` and su PAM only under `/usr/etc` / `/usr/lib/pam.d`; `hostname` is BusyBox (no `-I`) |
| Alpine 3.24 (BusyBox, apk 3) | 3 — BusyBox su ignores PAM (possible false OK); hash/apk "unknown" capped every Alpine score; a wedged apk queried ~40× (623 s → 13 s) | linux-pam installed but su/passwd are `/bin/bbsuid`; apk 3.0.8 reads `/etc/apk/config` (bare `allow-untrusted`; `--allow-untrusted` ignored); `fs.protected_fifos/regular=0` (no systemd); no `ss` |
| Debian 13 | 0 | `dhcpcd` binds 68/udp to the leased address (now system-internal) |

**Still open:**

| Gap | Sev. | § | Note |
|-----|------|---|------|
| ~~awall front-end not recognised~~ | — | §4 | **Resolved in 0.26.0** (see the 0.26.0 Alpine field pass): named in the banner and the firewall section; its own INPUT/FORWARD rules no longer cost points as "bypassing UFW". |
| `package_integrity` timeout is a hang-guard, not a slowness cap | decision | §10 | `debsums -c` / `rpm -Va` re-hash **every** packaged file — O(installed files) — so a full install legitimately takes minutes: measured **556 s** (Pi Zero W) and **511 s** (Mint 22.3 desktop, x86 4-core). A 60 s then 300 s wall-clock kill destroyed those valid scans (honest "result not established", group-killed, never a false "clean" — but no result). The timeout's real job is to stop a *wedged* process, not to cap a slow-but-progressing one, and the check is opt-in (`--exhaustive`), so it is a generous **hang-guard**: `_VERIFY_TIMEOUT` raised 60 → **1800 s** (30 min) in 0.23.0 — any real scan finishes well under it (Pi 556 s, Mint 511 s), a true hang stays bounded, and an operator can Ctrl-C. Parser validated against real output (podman Debian/Fedora/Arch) **and the full tamper round-trip on real hardware** (Mint, 1800 s: a clean scan completes and lists 21 genuinely-changed non-config files; tampering `/usr/bin/base64` raises it to 22 with base64 first). |
| ~~SUID `find` skips under CPU starvation~~ | — | §10 | **Resolved in 0.22.1**: `_FIND_TIMEOUT` raised 15 → 30 s. |


### 0.24.1 field pass — firewall posture, SSH remediation, false findings

*A/B of the 0.24.1 WIP against published 0.24.0 (2026-10-04) on four real
machines, each fix measured in both polarities, every forged state restored.
On a host without the targeted condition the two versions are identical (score,
findings, deductions) apart from the SSH `--fix` command strings.*

| Host | Measured | Result |
|------|----------|--------|
| Debian 13 | nftables-only DROP; UFW installed-inactive + nft DROP; X11Forwarding in a drop-in; main file ending in a `Match` block; inetutils-inetd with an empty `inetd.conf` | 0.24.0 "No active firewall" + HIGH → 0.24.1 "active (nftables/iptables) — default deny", LOW; UFW-inactive + nft **score 8 → 9** (false `firewall.inactive` −3 gone); 0.24.0 SSH fix a no-op behind the drop-in, appending `StrictModes` inside `Match` made `sshd -t` refuse → 0.24.1 drop-in / top-of-file insertion applied, idempotent, findings gone; inetd `Result=exec-condition` → INFO `condition_unmet` (reverse polarity: a telnet line → inetd runs, :23 reported). **Found a pre-existing defect**: a host without UFW was told "UFW IPv6 configuration matches kernel" — fixed (§5 of the changelog) |
| Linux Mint 22.3 | a user's squashfuse mount (the AppImage mechanism) under `--exhaustive` | 0.24.0 `world_writable.partial` → 0.24.1 clean; without the mount both clean, so FUSE was the only cause. **The parser first missed the real line** (`/usr/bin/find: '…': Permission denied`, absolute argv0) — caught here, fixed, tested on the verbatim line |
| Fedora 44 (SELinux enforcing, firewalld) | `firewall-cmd --list-all` zone target `default` / `DROP` / `ACCEPT`; `50-redhat.conf` ships `X11Forwarding yes` | 0.24.0 "✖ default policy is ALLOW — no filtering" → 0.24.1 "✔ active (firewalld) — reject"; DROP → deny, ACCEPT → ALLOW (true); SSH drop-in fix applied, file context `etc_t`, **0 AVC** |
| Alpine 3.24 (BusyBox) | SSH drop-in and main-file fixes with BusyBox sed; no `ss` | **Found a pre-existing defect (since 0.19.0)**: BusyBox sed refuses `/regex/I` — every SSH drop-in fix and the Samba fixes failed at step one; fixed with per-letter classes, replayed OK (`sshd -t && rc-service sshd restart`); IPv6 "config_ok (UFW)" with neither UFW nor `ss` → `ipv6.listeners_unknown` |

**Still open:**

| Gap | Sev. | § | Note |
|-----|------|---|------|
| ~~firewalld zone target `ACCEPT` (trusted)~~ | — | §4 | **Resolved in 0.24.2**: ALERT −3 `firewall.firewalld_policy_open`, field-validated on Fedora 44 (below). |


### 0.24.2 field pass — firewalld ACCEPT, UFW IPV6=no

*A/B of the 0.24.2 WIP against published 0.24.1 (2026-10-08) on two real machines,
each fix in both polarities, every forged state restored.*

| Host | Measured | Result |
|------|----------|--------|
| Fedora 44 (SELinux enforcing, firewalld) | default zone target `default` / `DROP` / `ACCEPT`; the proposed fix applied for `trusted` and for FedoraServer set to ACCEPT **without** ssh (automatic rollback armed, then cancelled) | `default`/`DROP`: identical (score 7); `ACCEPT`: 7 → **6**, ALERT −3 `firewall.firewalld_policy_open`. `trusted` → `--set-default-zone=public`; named zone → ssh added before `--set-target=default`; a new SSH connection succeeds both times, the finding is gone, a second run exits 0. **Found two false IPv6 lines**: "filtered by firewalld" under ACCEPT, and "UFW IPv6 configuration matches kernel" with no ufw package — fixed. Changing the default zone moved `enp3s0` with it (NetworkManager binds no zone) |
| Linux Mint 22.3 (ufw 0.36.2) | UFW active + IPV6=no, link-local only (global addresses flushed, RA off); a link-local neighbour in a network namespace joined by a veth pair | UFW active: IPv6 INPUT policy DROP, sshd on `[::]:22` unreachable; UFW inactive (control): ACCEPT, sshd answers. Source: `/lib/ufw/ufw-init-functions` installs DROP on INPUT/FORWARD/OUTPUT when IPV6=no. **The 0.24.1 link-local wording and the WARN −2 `ipv6.ufw_disabled_listeners_present` were both wrong** — now INFO `ipv6.ufw_v6_off_blocked`. A cross-machine test was invalid (the other machine's own IPV6=no DROP broke neighbour discovery) |

**Still open:**

| Gap | Sev. | § | Note |
|-----|------|---|------|
| ~~firewalld judged by its **default** zone only~~ | — | §4 | **Resolved in 0.24.3**: the zones holding the interfaces, the policies into the host and the source zones are judged, per address family (below). |


### 0.24.3 field pass — firewalld per interface, policy, source and family; IPv6 chain rules

*A/B of the 0.24.3 WIP against published 0.24.2 (2026-10-09) on two real machines.
Every forged firewalld state was armed with an automatic rollback; every alert was
followed by its own fix, applied exactly as printed, then `systemctl restart
firewalld`, a probe from another LAN host and a new audit.*

| Host | Measured | Result |
|------|----------|--------|
| Fedora 44 (SELinux enforcing, firewalld 2.4.0) | enp3s0 in `trusted` / in `nm-shared`; default zone `trusted` with enp3s0 in `public`; policies ANY → HOST at −100 / +100 (ACCEPT, DROP, CONTINUE, with and without their own catch-all); catch-all rich rules with `log`, `audit`, `limit`, `family="ipv4"`; zone and policy carrying two causes at once; `trusted` bound to `/32`, `/1`, `0.0.0.0/0` at ingress priorities −100 / 0 / +100; two accepting zones each holding one `/1` | 0.24.2 false OK (enp3s0 in `trusted`, `0.0.0.0/0`, the `/1` pair across one or two zones, catch-all accept rules, accepting policies) → 0.24.3 ALERT −3; 0.24.2 false alert (default `trusted` holding no interface, zone ACCEPT overridden by a policy DROP or a catch-all reject, `0.0.0.0/0` classified after the interface) → 0.24.3 nothing. Each fix closed 8080 and kept SSH after the restart, including SSH reachable only through the policy. firewalld refuses an element-less rich rule without a non-zero priority (`INVALID_RULE`). Narrow sources → INFO without a deduction |
| Linux Mint 22.3 (ufw 0.36.2) | UFW active + IPV6=no, link-local only, neighbour in a network namespace; IPv6 chain at the ufw-init shape, + ACCEPT tcp/22 in INPUT, + INPUT and OUTPUT, + ICMPv6 both ways | `[::]:22` reachable only in the last case, where 0.24.2 said "blocked"; 0.24.3 says "blocked" only for the ufw-init shape and otherwise the new INFO `ipv6.ufw_v6_off_rules_unresolved`, replayed with the final code on all four rows |

**Still open:**

| Gap | Sev. | § | Note |
|-----|------|---|------|
| IPv6 source forms (`::/1` + `8000::/1`) | soft | §1 | Covered by the guards only: the probing host had no global IPv6 address. |
| ~~Exposure split across zones by narrower, non-adding sources~~ | — | §1 | **Resolved in 0.26.0** (see the 0.26.0 firewalld field pass): an INFO adds up what the zones reach together, as a share of the family's space and of its public addresses; not scored. |


### 0.24.4 field pass — service checks against the service's own answer, fixes applied as printed

*A field campaign (2026-10-09 → 2026-10-12): each service check compared with what the
service itself reports, each fix BOB prints applied exactly as printed and re-audited,
rebooted where persistence was the claim. Every change to a remote firewall was armed
with an automatic rollback first, and access checked between cases.*

| Host | Measured | Result |
|------|----------|--------|
| Raspberry Pi Zero W (Raspbian 13 trixie, armv6l) | `ufw enable` over SSH; fail2ban jail on `/var/log/auth.log` with no rsyslog vs `Journal matches:`; sysctl fix against a later `99-zlocal.conf`, rebooted; auditd `-w /etc/`, `-F path=` (b32), `-e 2` then reboot | ufw: the bare enable cut port 22, the new allow-first command kept it; jail on a file nothing wrote counted 0 failures → WARN, the journal fix counted them; sysctl held after reboot in the winning file; auditd coverage read as the audit log showed it, the locked state said |
| Linux Mint 22.3 (ufw 0.36.2, iptables-nft, rsyslog) | sshd on 22+2222 and `ssh.socket` on 22+2222; ufw `IPV6=no` with a link-local neighbour in a netns; `/etc/sysctl.conf` overriding; raw `iptables -P INPUT DROP` and the nft form; a second nftables input chain (inet / ip6 / ip, accept-everything); an SSH restriction for one neighbour; fail2ban under rsyslog — file not written, stale copy, rsyslog re-routed and restarted, failures of one kind routed away; BOB run as a user | allow-first kept every sshd port, socket-activated ones too; IPv6 turned on first kept the neighbour; raw DROP froze the session (old form) and the nft form named a missing table → appended accepts in the hook's real chain kept SSH and the neighbour's restriction; policy read per IPv4 family; fail2ban OK only with sshd's latest message and failures of each kind in the file since rsyslog started; unnamed listeners → no command |
| Fedora 44 Server (SELinux enforcing, firewalld) | clamd@scan from the printed fix; timesyncd fix; sysctl live value vs `50-default.conf` | clamd@scan needed its socket and database first, then active; socket 0666 under a 0710 dir refused `nobody`; reverts-at-boot INFO on `protected_hardlinks` |
| Alpine 3.24 (OpenRC, BusyBox, musl) | auditd locked (`enabled 2`) and running; the auditd fix under OpenRC; negative audit rules (read-only, never, b32, no perm) against the audit log; BusyBox ntpd | locked auditd read as running; the rc-update/rc-service fix applied, auditd started, the finding cleared; BOB matched the audit log on six rule forms; ntpd seen, sync said unverifiable |
| Fedora 43 VM (firewalld 2.3.2, NetworkManager, auditd) | interface bound to `block`, firewalld absent / stopped, the printed fix, reboot, start-up window under authenticated probes; auditd b64/b32 with a static i386 writer, `success=`/`auid`/`exe` filters, `-S` beside `perm`, `-e 2` with auditd killed; raw nft chain with an SSH restriction and with an accept-everything rule | ssh in every active zone (block kept SSH, reboot too), ~1 s of refused new logins while firewalld starts, open session kept; audit coverage needs both ABIs and no narrowing filter (BOB = audit log on every set); `pid 0` with `enabled 2` read as stopped; appended accepts kept the restriction; no fix behind accept-everything |
| Containers (Debian 13, Ubuntu 24.04, Arch, openSUSE Tumbleweed, Alpine 3.22/edge, Fedora 44) | each family's clamd unit and packaged socket; unprivileged `SHUTDOWN`; `LocalSocketGroup` + `660`; syslog-ng 4.8.1 reload | unit per family named; SHUTDOWN stopped clamd as packaged (Alpine, Debian) → INFO; 660 group socket refused the user, served the group; syslog-ng re-routes on reload without restarting |

**Still open:**

| Gap | Sev. | § | Note |
|-----|------|---|------|
| nftables rules are not evaluated one by one | soft | §1 | BOB reads base-chain policies (family, accept-everything); `input_ok` says reachability is not established. |
| fail2ban routing is sampled, not proven | soft | §3 | Latest sshd message and latest failure of each kind seen since rsyslog started. With no journal (OpenRC), since 0.26.0: the jail's own failure count credits it, and a jail whose file lacks the latest SSH session's line while another log file holds it is said blind (see the 0.26.0 Alpine field pass); a syslog-ng or busybox routing cannot be dated, so a file holding that line is not taken as proof. |
| ~~ClamAV socket open to every local user~~ | — | §5 | **Resolved in 0.25.0**: WARN −1 (was INFO). |
| ~~`sudo` vs Alpine's `doas`~~ | — | — | **Resolved in 0.25.0**: `doas` where there is no `sudo` (17 of 17 commands on Alpine). |


### 0.25.0 field pass — a Kubernetes node, encryption beyond `/`, fixes as printed

*Measured before the 0.25.0 release (2026-10-16) on Fedora 44, Linux Mint 22.3,
Alpine 3.24 and Ubuntu Server 26.04 (MicroK8s 1.35), with Fedora 43 and Alpine
3.22 VMs and Debian 13 / Fedora 43 containers for what those hosts could not
stage; every fix applied as printed and re-audited. Figures as published in the
0.25.0 changelog entry (`CHANGELOG_FULL.md`).*

| Host | Measured | Result |
|------|----------|--------|
| Alpine 3.24 (OpenRC, doas) | every printed command on a host with `doas` and no `sudo`; Docker user-namespace remapping (Docker 29.8.2); CUPS fix | 17 of 17 commands use `doas`; the remapping fix had stopped Docker (no `useradd`) → now creates `/etc/docker`, the dockremap user and its own ID range, and restarts Docker through OpenRC; CUPS listens on localhost only after the new fix |
| Alpine 3.22 VM | Docker remapping | dockerd stopped with no `/etc/subuid` while OpenRC said "started" (the old fix) |
| Fedora 44 Server (firewalld) | turning firewalld on with SSH logins arriving, interface in a NetworkManager zone without ssh; sshd on 22 and 2222; CUPS fix | 10 of 118 new logins refused while firewalld started → ssh now written to the permanent configuration first; the two-port chain completes, 0 of 115 refused; CUPS listens on localhost only |
| Fedora 43 (VM; container where noted in the changelog) | the 0.24.4 two-port firewalld chain; an iptables-legacy INPUT chain with DROP policy whose first rule accepts everything; LUKS root on LVM; CRI-O pods | 29 of 34 new SSH logins refused until rollback (`--add-service` + `--add-port` in one call refused) → separate calls; port 8080 answered behind the "DROP" chain → −3; root encryption and the data beside it resolved; pods read through `crictl` |
| Linux Mint 22.3 | Docker remapping (Docker 29.1.3); CUPS fix | the old fix gave dockremap the range another user held → a range after the highest one; CUPS listens on localhost only |
| Ubuntu Server 26.04 + MicroK8s 1.35 | the kubelet asked anonymously from the host on 10250 / 10255, by HTTP verb; Docker remapping (final command) | commands authorised with reads refused → ALERT −3; commands authorised by `get` alone → ALERT −3; reads only → WARN −1; everything refused → INFO (reachability from the network not tested); remapping up, the finding gone |
| Debian 13, Fedora 43, Alpine | `cupsctl --no-remote-any` with a hand-written `Listen 0.0.0.0:631` | exits 0 and changes nothing (the reason for the new CUPS fix) |

**Still open:**

| Gap | Sev. | § | Note |
|-----|------|---|------|
| nftables rules are not evaluated one by one | soft | §1 | Unchanged since 0.24.4, except the accept-everything first rule of a DROP chain (read above). |
| ~~Per-user files under `doas`~~ | — | §6 | **Resolved in the 0.25.1 work tree** (`DOAS_USER`), field-verified on Alpine 3.24 (see the 0.25.1 field pass). |


### 0.26.0 bench — no firewall, and raw INPUT ACCEPT rules

*No machine on the multiboot host was up; measured instead in a network namespace
on the development machine (user namespace, root mapped): a server namespace
running the real ufw 0.36 from the package templates (default deny incoming),
two listeners on 8097 and 8099, probed from a second namespace over a veth pair.
2026-10-18.*

| Raw rule put first in INPUT, ufw active | 8097 | 8099 | `iptables -L INPUT -n` shows | 0.25.1 deducted | 0.26.0 |
|---|---|---|---|---|---|
| none | refused | refused | — | — | — |
| `-p tcp --dport 8099 -j ACCEPT` | refused | **open** | `ACCEPT … tcp dpt:8099` | −2 | WARN −2 |
| `-m mark --mark 0x20000/0x20000 -j ACCEPT` | refused | refused | `ACCEPT … mark match …` | −2 | INFO |
| `-i lo -j ACCEPT` | — | — | `ACCEPT 0 -- 0.0.0.0/0 0.0.0.0/0`, the same as an accept-all | −2 | not reported |
| the mark rule, and `-t mangle -A PREROUTING -p tcp --dport 8099 -j MARK --set-xmark 0x20000/0x20000` (19 October) | refused | **open** | `ACCEPT … mark match …` | −2 | WARN −2 (the first 0.26.0 tree: INFO) — a mark rule admits when a raw, mangle or nat rule, or an INPUT rule above it, sets its mark |
| the mark rule, and the same MARK in raw PREROUTING / nat PREROUTING / mangle INPUT / filter INPUT above it / filter INPUT below it (19 October, iptables 1.8.10 nf_tables — every rule accepted) | refused | open / open / open / open / **closed** | — | — | WARN −2 for the first four, INFO for the last |
| the mark rule, and a MARK in mangle OUTPUT + POSTROUTING / in a user chain jumped from mangle PREROUTING / the same chain jumped from OUTPUT only / CONNMARK `--set-xmark` + `--restore-mark` in mangle PREROUTING (19 October) | refused | closed / **open** / closed / **open** | — | — | INFO / WARN −2 / INFO / WARN −2 — only setters on the inbound path count |
| the mark rule, and CONNMARK `--set-xmark` alone / with a restore whose masks miss the bits / restored before it is set / set then restored (19 October) | refused | closed / closed / closed / **open** | — | — | INFO / INFO / INFO / WARN −2 — the connection's mark reaches the packet only through a restore after it |
| the mark rule, and a MARK in a filter user chain jumped from INPUT above it / the same, nested one chain deeper / jumped below it (20 October) | refused | **open** / **open** / closed | — | — | WARN −2 / WARN −2 / INFO (before the fix: INFO for all three) — filter INPUT's jumps are followed |
| no UFW, INPUT DROP and the mark rule, each case in a fresh namespace (Linux 7.0), iptables 1.8.10, iptables-nft and iptables-legacy: a MARK in raw / mangle / nat PREROUTING, without then with an `ESTABLISHED,RELATED` accept (20 October) | — | raw, mangle: **open** both ways; nat: closed without, **open** with — nat sees only a connection's first packet, and none while conntrack is unused | — | — | with `iptables` the legacy backend and UFW taken as active: WARN −2 for raw and nat |

With the three rules in place, BOB's own collection run in that namespace read the
`-S` lines; 0.25.1's module on the same ruleset deducted −6, 0.26.0 −2. With ufw
off, 0.26.0 reports none of them: the INPUT chain is then the host's ruleset,
judged by the iptables/nftables section (on k3s, kube-router's mark rule had cost
2 there on top of that section's 3).

No UFW at all (the ufw binary masked in a mount namespace, the real iptables of the
namespace, policy ACCEPT): 0.25.1 printed a *UFW RULES ANALYSIS* section with "No
duplicate UFW rules detected", and a *UFW LOG ANALYSIS* section that read the host's
own ufw log (`logs.local_dominance`); *Firewall & Network* 6/10. 0.26.0 prints
neither section and caps the domain at 3/10.

No firewall at all: the openSUSE Leap 16 audit of the 0.25.1 pass (firewalld
stopped, an nftables ruleset filtering nothing) scored *Firewall & Network* 7/10,
the Ubuntu Server audit with UFW installed and off 3/10. 0.26.0 caps the first at
3 as well — replayed on the host, below.

### 0.26.0 field pass — source-bound ACCEPT zones on openSUSE

*openSUSE Leap 16.0, firewalld 2.1.2, 18 October 2026: zones `bobA` (source
0.0.0.0/2) and `bobB` (64.0.0.0/3), target ACCEPT, runtime sources; both zones
deleted afterwards.*

| | 0.25.1 | 0.26.0 |
|---|---|---|
| findings | one INFO per zone, nothing more | the same two INFO, plus "The sources bound to firewalld zones bobA, bobB, each of which accepts every packet from its sources, together cover 37.5% of the IPv4 address space (42.6% of its public addresses)" — in French with a decimal comma (wording as released; measured with the first wording, same figures) |
| score | unchanged | unchanged (decided: BOB cannot judge whether those sources deserve the trust) |

Two zones covering a whole family together keep the existing ALERT; one zone alone
keeps its own INFO.

### 0.26.0 field pass — Docker's firewall backend on openSUSE

*openSUSE Leap 16.0, firewalld active (zone `public`: dhcpv6-client, ssh), Docker
29.4.0 from the distribution (installed for the pass, removed afterwards with its
15 packages and the `docker-forwarding` policy it wrote; host rebooted). A
container publishing 8099, one making outbound connections, probed from the LAN.
Each backend measured from a clean state: after an iptables-backend run, Docker's
own `FORWARD` policy DROP stayed behind and made the nftables backend look
filtered — the nftables rows below come from a fresh boot.*

| `daemon.json` | `docker info` backend | 8099 from the LAN | DOCKER-USER | container outbound | 0.26.0 says |
|---|---|---|---|---|---|
| (shipped file) | `iptables+firewalld` | answers | yes | works | bypass via iptables; option 2 with DOCKER-USER |
| `"firewall-backend": "nftables"` | `nftables+firewalld` | answers | **no** | works | bypass via **nftables**; option 2 with your own nftables rules |
| the same + `"iptables": false` | `nftables+firewalld` | refused | no | no NAT | iptables disabled, IPv4 rules not written (an `ip6 docker-bridges` table remained); the port line says the zone governs it |

Before 0.26.0 BOB said "via iptables" and offered DOCKER-USER under the nftables
backend, kept "the zone does not filter it" for the port with `"iptables": false`,
and said "UFW rules apply normally" on this firewalld host. With the nftables
backend Docker refused to start while `net.ipv4.ip_forward` was 0 (it sets it itself
only with the iptables backend). openSUSE ships an `/etc/docker/daemon.json`
(log options, `selinux-enabled`): the user-namespace fix, which writes the file only
where none exists, does nothing there, as its detail already says.

### 0.26.0 field pass — a stopped and a silent firewalld on openSUSE

*openSUSE Leap 16.0, firewalld 2.1.2, real, 18 October 2026; 0.25.1 and the 0.26.0
tree on the same host state. firewalld active and enabled again afterwards, nothing
left in `/etc/firewalld/zones`.*

| Host state | 0.25.1 | 0.26.0 |
|---|---|---|
| firewalld active | score 8, *Firewall & Network* 10/10, `firewall_rules` OK lines | 8, 10/10, no `firewall_rules` section |
| firewalld stopped | 7, 7/10, "No active firewall — neither UFW nor firewalld is installed", risk HIGH | 6, **3/10**, "… firewalld is installed but not running", the cap note, risk HIGH; no UFW sections |
| firewalld active, `firewall-cmd` failing with no output (a wrapper first on `PATH`) | 6, 6/10, "No active firewall", HIGH floor — on a host firewalld was filtering | 7 as an upper bound, `firewall.firewalld_unreadable` INFO, risk MEDIUM, no floor |
| the same, `firewall-cmd` hanging | as above | as above; both audits finish past the timeout (93 s for the two) |

The replay found two defects in the first 0.26.0 tree, both fixed before this table:
firewalld 2.1.2 prints `--state` "not running" on **stderr**, stdout empty, exit 252
— read as "unreadable", a stopped firewalld lost its alert and its cap (10/10); and
the cap line of the breakdown said "neither UFW nor firewalld is installed" under the
"installed but not running" alert.

### 0.26.0 field pass — raw INPUT ACCEPT rules on Ubuntu Server

*Ubuntu Server 26.04.1, ufw 0.36 installed, real, 18 October 2026. Three raw rules put
first in INPUT: `--dport 8099 -j ACCEPT`, `-i lo -j ACCEPT`, a `-m mark --mark
0x20000/0x20000 -j ACCEPT` rule as kube-router writes it; listeners on 8097 and 8099;
probed from the LAN. 0.25.1 and the 0.26.0 tree run on the same host state;
everything removed afterwards, the heavy snap services paused during the pass and
restarted.*

| UFW | 8099 / 8097 from the LAN | 0.25.1 | 0.26.0 |
|---|---|---|---|
| inactive | — | *Firewall & Network* 1/10, `iptables_bypass` −6 (the three rules, `-i lo` included), *UFW RULES ANALYSIS* shown | 3/10 (the inactive-UFW cap), no `iptables_bypass`, no UFW rules section; the empty UFW log is INFO |
| active (default deny) | **8099 open**, 8097 filtered, SSH up | 4/10, −6 | 8/10, −2 for the `--dport` rule only; the mark rule INFO; `-i lo` not reported |

### 0.26.0 bench — a chain at policy accept that ends by rejecting everything

*Network namespace on the development machine (user namespace, root mapped), a
listener on 8097 and 8099 probed from a second namespace over a veth pair, `ufw`
masked. 19 October 2026.*

| Ruleset (8097 accepted, then) | 8099 | 0.25.1 | 0.26.0 before the fix | 0.26.0 |
|---|---|---|---|---|
| nft `policy accept`, last rule `reject` | refused | "no active firewall", −3 | the same, capped at 3/10 | filtering (`firewall.netfilter_active`), no deduction |
| iptables-nft `-P INPUT ACCEPT`, last `-j REJECT` | refused | the same | the same | the same as nft; the `-i lo` rule, printed `iifname "lo" counter … accept`, no longer read as missing (−1) |

A `reject` with a match (`ip protocol tcp … reject with tcp reset`) leaves the rest to
the policy; an accept-everything rule above the reject wins.

### 0.26.0 field pass — Docker beside firewalld, StrictForwardPorts, on Debian

*Debian 13.7, firewalld 2.3.1 and docker.io 26.1.5 installed for the pass (73 packages
with tcpdump, purged afterwards), a busybox container publishing 8099, probed from
192.168.1.10; nftrace and tcpdump on the host. 19 October 2026.*

| `StrictForwardPorts` | 8099 from the LAN | what firewalld did | BOB |
|---|---|---|---|
| `no` (default) | open | `filter_FORWARD`: `ct status dnat accept` | ALERT, the port bypasses the host firewall (−1 local) |
| `yes` | **rejected** (`No route to host`) | `filter_FORWARD_dnat`: `reject with icmpx admin-prohibited` | the first 0.26.0 tree: the same ALERT; now INFO, no bypass, no deduction |

A first attempt, before purging and reinstalling, saw 8099 time out with `no`, across
restarts and with a `docker-forwarding` policy added by hand (the SYN reached the
container, replies left docker0); it could not be reproduced on the fresh install and
is unexplained. Docker 26.1.5 created no `docker-forwarding` policy (Docker 29.4.0 on
openSUSE did).

The setting as loaded, not as written (firewalld 2.3.1 alone, 44 packages, purged
afterwards): started with `no`, the forward chain held `ct status dnat accept`;
the file set to `yes` without a reload, the chain still accepted; after
`firewall-cmd --reload`, `ct status dnat jump filter_FORWARD_dnat`; set back to `no`
without a restart, the chain still jumped. BOB now reads the loaded chain.

### 0.26.0 field pass — firewalld source zones nested in each other, on Debian

*Debian 13.7, firewalld 2.3.1 installed for the pass (twice) and purged afterwards with the
47 packages it brought (15 of them kept by `autoremove` as recommended by installed
packages, purged by name), real, 19 October 2026. Runtime sources only; a listener on
8099; probed from 192.168.1.10. Zones bobA (0.0.0.0/1) and bobB (128.0.0.0/1), target
ACCEPT; a DROP zone keeping ssh, bound to 192.168.1.10/32.*

| DROP zone | 8099 from 192.168.1.10 | 0.26.0 before the fix | 0.26.0 |
|---|---|---|---|
| none | open | ALERT −3, "every client" | the same |
| `aaacarve` (sorts first) | **dropped**, SSH up | ALERT −3, "every client … every port is open" | ALERT −3, "every public address … except for 192.168.1.10/32 (aaacarve)" |
| `zzzcarve` (sorts last) | open | ALERT −3 | ALERT −3, "every client" |
| `zzzcarve`, ingress-priority −10 | **dropped** | — | (as `aaacarve`) |
| `aaacarve`, ingress-priority +10 | open | — | (as `zzzcarve`) |
| `aaacarve` on 8.8.8.0/24 | open from .10 | INFO "> 99.9% of the IPv4 address space (> 99.9% of its public addresses)"; *Firewall & Network* 7/10 → 10/10, headline 8 → 9 | ALERT −3, "take > 99.9% of the public addresses … nearly all of the internet, except for 8.8.8.0/24 (aaacarve)" — decided after the review (at least 99% of the public addresses); the same configuration in the guard, not replayed on the host |
| `trusted` on 0.0.0.0/0 alone | open | ALERT −3 | the same |
| `trusted` on 0.0.0.0/0 + `aaacarve` | **dropped** | ALERT −3, "every client … goes through it" | ALERT −3, "… except for 192.168.1.10/32 (aaacarve)" |
| `trusted` on 0.0.0.0/0 + `zzzcarve` | open | ALERT −3 | ALERT −3, "every client" |

The same with the policy at priority +10 (firewalld installed a fifth time): 8099
**dropped**, no ALERT. A zone of my /32 at ACCEPT with `rule priority="-20" service
name="ssh" accept` and `rule priority="-10" family="ipv4" reject`: 8099 **refused**,
SSH up; the first 0.26.0 tree reported the zone open through IPv6, it is now judged on
its sources' family.

bobA (0.0.0.0/1) and bobB (128.0.0.0/1) at ACCEPT, and a policy `bobpol` ANY → HOST,
priority −10, target DROP, ssh allowed (19 October, firewalld installed a fourth
time): 8099 **dropped**, SSH up; BOB: no ALERT, *Firewall & Network* 10/10. Policy
removed: 8099 open.

A zone at target ACCEPT bound to 192.168.1.10/32 with `rule family="ipv4" port
port="8099" protocol="tcp" reject` (19 October, firewalld installed a third time):
8099 **refused**, 8097 open; BOB said "every port is open to those addresses", and
now follows that INFO with `firewall.firewalld_open_zone_refuses_some`, linked in
`qualified_by` (terminal and `--json-full` checked on the host).

Between source zones: the lowest `ingress-priority` first, then the zone name; the
first source that matches wins, not the narrowest. `--set-ingress-priority` works in
the permanent configuration only (runtime refused). Found on the way: the IPv6
public-address table, wrong since the first 0.26.0 tree, and a share printed "100%"
short of all of it.

### 0.26.0 field pass — Alpine: cron in root's crontab, awall, fail2ban with no journal

*Alpine 3.24 (OpenRC, BusyBox v1.37.0, Python 3.14.7), real, 18 October 2026. 0.25.1
and the 0.26.0 tree run on the same host state. awall 1.12, fail2ban 1.1 and
syslog-ng 4 installed from apk for the pass and removed afterwards (iptables, pulled
in by awall, went with it, as before the pass).*

| Measured | 0.25.1 | 0.26.0 |
|---|---|---|
| `--install-cron` (BusyBox crond, no `/etc/cron.d`) | refused before the first question | a block between `# BEGIN BOB cron bob-NAME` / `# END …` in `/etc/crontabs/root`, then `root` in `cron.update` (without it crond did not re-read the file in three minutes); crond ran the job at the scheduled minute and the report was written; a schedule change rewrote the block only; removal left the crontab byte for byte as before |
| awall, one policy enabled (deny inbound, ssh kept) | "no active front-end (UFW/firewalld)"; *Firewall & Network* 2/10: −2 × 3 INPUT and −1 × 2 FORWARD rules awall wrote, all "bypassing UFW" | awall and its policy named in the banner and the firewall section; 10/10 |
| awall installed, no policy enabled, chains open | "neither UFW nor firewalld installed", `apk add ufw` printed | "awall is installed but no policy is enabled"; no command; capped at 3/10 |
| fail2ban's packaged jail (`/var/log/messages`), busybox syslogd, two refused logins: `Total failed: 2` | "whether a syslog daemon writes it could not be established" — one was running | SSH jail credited on its own count, followed by an INFO saying it rests on that count (routing changed since would not show) |
| same, before any failure (`Total failed: 0`) | same line | "a syslog daemon runs, but with no systemd journal to compare against and no failure counted … not verified" |
| syslog-ng with Alpine's own `syslog-ng.conf` (auth to `/var/log/auth.log`), a refused login: `Total failed: 0` — the jail is blind | "not verified" | the latest SSH session's `Accepted` line is in `/var/log/auth.log`, not in `/var/log/messages`: said, with a `logpath` override; run as written (as root, `doas` dropped — doas without a tty refuses), the jail counted the next failure and the audit credited it |

The sampled-file caveat (the 0.24.4 OK) was replayed on Debian 13.7 (real, 19
October 2026; rsyslog and fail2ban installed for the pass and purged afterwards): a
jail on `/var/log/auth.log`, two refused logins, `Total failed: 2`. 0.25.1 printed
the OK alone; 0.26.0 prints it followed by the INFO, and `--json-full` gives the OK
`qualified_by: ["fail2ban.ssh_jail_sampled_caveat"]`. Score unchanged (8/10, not a
ceiling).

awall `required` (19 October, in an Alpine 3.24.2 container): with `web` importing
`base`, `awall enable web` left `awall list` printing `base required` and `web
enabled`; BOB named `web` only, and now names `web, base (required)`.

Measured along the way: syslog-ng 4 names itself `syslog-ng-main` in
`/proc/<pid>/comm`; a restarted fail2ban did not count failures already in its
file, within `findtime`; stopping OpenRC's `syslog` stops `crond` (`need logger`),
which does not come back when a logger starts again.

### 0.25.1 field pass — doas on Alpine

*Alpine 3.24 (OpenRC, BusyBox, doas, Python 3.14.7), real, 2026-10-17. The 0.25.1
work tree copied to a dedicated operator account given a temporary
`permit nopass` doas rule (removed afterwards).*

| Measured | Result |
|---|---|
| `doas env` | `DOAS_USER` names the operator; `HOME=/root`, `USER=root` |
| `--ignore`, `--install-completion`, a full audit — all through doas | everything per-user lands in the operator's `~/.config/bob`, owned by the operator; the `/usr/local/bin/bob` link is created; the banner names the operator; root's own BOB files unchanged |
| `--explain ssh.password_auth`, a verbose audit through doas | every printed command reads `doas`; no `sudo` command word left in the output (finding prose included, once 0.25.1 applied the host's word to it) |
| running BOB without doas | "This script must be run as root: doas bob" |
| `--install-cron` | **Alpine has no `/etc/cron.d`** (BusyBox crond reads `/etc/crontabs/`): the wizard asked every question, wrote `/usr/local/bin/bob-NAME`, then failed on the cron file and left the script. 0.25.1 refuses before the first question, says how to schedule an audit with root's crontab, and removes the script if a cron write still fails |

### 0.25.1 field pass — AppArmor under OpenRC on Alpine

*The same Alpine 3.24 host, 2026-10-17. Kernel cmdline and runlevels restored
afterwards; the `apparmor` and `apparmor-profiles` packages left installed.*

| Step | Measured |
|---|---|
| stock boot | `/sys/kernel/security/lsm` without `apparmor`; BOB: AppArmor off in the kernel, add `apparmor=1 security=apparmor` |
| that advice applied (GRUB, reboot) | AppArmor live in the kernel, 145 profile files in `/etc/apparmor.d`, **0 loaded**, service stopped. 0.25.0 asked to install the profile packages (installed) and did not know the apk name; 0.25.1 says the files are there and not loaded, and prints `doas rc-update add apparmor boot && doas rc-service apparmor start` |
| that command applied as printed | 161 profiles loaded; BOB: "AppArmor enforcing — 78 profile(s) enforce, 5 complain" |
| reboot | the verdict holds (service in the `boot` runlevel) |

The fix holds `&&`, so `--fix --apply` lists it as a manual step rather than running
it; that is the existing rule for shell operators.

### 0.25.1 field pass — firewalld started from stopped on openSUSE

*openSUSE Leap 16.0 (firewalld 2.1.2, nftables backend, NetworkManager 1.52,
SELinux enforcing, Python 3.13.14), real, 2026-10-17. firewalld stopped and
disabled, the wired connection put in a NetworkManager zone `bobzone` that lists
nothing (no ssh); a rollback armed before each run; SSH logins opened every
quarter second from the LAN during the command. Original zones, connection and
service state restored afterwards.*

| Run | Command | New SSH logins refused | After |
|---|---|---|---|
| 1–3 | as printed by 0.25.0 (install step included) | 0 / 66, 0 / 75, 0 / 75 | firewalld active, `bobzone` holds ssh in runtime and permanent configuration; re-audit: "firewalld is the active firewall" |
| 4 | as printed by 0.25.1 (no install step) | 0 / 75 | same |

firewalld started 58 s after the command in run 1 (the first `zypper` call of
the session), 16 s in runs 2 and 3, 8 s in run 4 without the install step; the
whole chain ended 8 s after the start each time. Nothing filters before the
start, so SSH stays reachable during the offline part.
The loop also gives the `docker` zone ssh (it is active, with `docker0`); its
target is ACCEPT, so nothing changes there.

### 0.25.1 field pass — Docker beside firewalld on Fedora

*Fedora 44 Server (firewalld, the wired interface in the `FedoraServer` zone
allowing cockpit, dhcpv6-client and ssh; SELinux enforcing; Python 3.14.3), real,
2026-10-17. Docker 29.8.2 installed from Fedora's `moby-engine` for the pass
(firewall backend `iptables+firewalld`), removed afterwards with its zone,
policy, user and ranges; `runc` stays, required by `containers-common-extra`.*

| Measured | Result |
|---|---|
| a container publishing 8099; a host service on 8097; both probed from the LAN | 8099 answered, 8097 refused: the zone does not filter a published port. BOB said Docker "may bypass UFW rules" (no ufw on the host), announced "three options" and listed two, recommended "explicit UFW rules", tagged the port "bypasses UFW", and the ports section said 8099 (docker-proxy) was "governed by the firewalld zone". 0.25.1 names the host firewall, lists two options, the second being to publish on 127.0.0.1 a port that should stay on the host and to filter in DOCKER-USER who reaches the others, and says a docker-proxy port is not filtered by the zone; keys, levels and points unchanged |
| a container publishing on `127.0.0.1:8096` | answered on the host, refused from the LAN (option 2 holds) |
| two containers running, no port published | BOB said "No running Docker containers detected" while its Docker hardening section counted 2. The OK fires when no port is published; it now says so |
| the `userns-remap` fix, applied as printed | `useradd -r -U` created dockremap (uid 388); its range `589824:65536` starts after so6's `524288:65536`; Docker restarted with `userns`; a container's root maps to host uid 589824 under SELinux enforcing; re-audit: "userns-remap enabled". The existing containers and images no longer listed (Docker root `/var/lib/docker/589824.589824`), as the detail warns |

### 0.25.1 field pass — Docker's DOCKER-USER chain on Ubuntu Server

*Ubuntu Server 26.04.1, Docker 29.1.3 (`docker.io`), real, 2026-10-17; a
container publishing 8099 and one making outbound connections; the trusted
source set to an address that is not the probing host. Removed afterwards with
the seven packages it pulled in.*

| Rules in `DOCKER-USER` | 8099 from an untrusted LAN host | the containers' DNS and HTTP out |
|---|---|---|
| none | answers | work |
| `-s <trusted> -j ACCEPT`, then `-A … -j DROP` (the former `--explain` example) | refused | **cut** |
| `-i enp3s0 ! -s <trusted> -j DROP` | refused | **cut** |
| `-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN` ahead of the previous rule | refused (the trusted host gets 200) | work |
| `firewall-backend: nftables` (after removing the iptables backend's leftovers) | — | no IPv4 `DOCKER-USER` chain is created |

Switching to `firewall-backend: nftables` left the iptables backend's `FORWARD -j DOCKER-USER` jump and chain in place, and a rule put there still filtered the published port; the row above was measured once they were removed. The rules were applied in the order the explain prints them (`-I … DROP`, then `-I … RETURN`), and `iptables -S DOCKER-USER` listed RETURN first. IPv6, and a host that forwards other networks through the same interface, were not measured.

### 0.25.1 field pass — a k3s node on Ubuntu Server

*Ubuntu Server 26.04.1 (4 CPUs, 3 GB, ufw installed and inactive, MicroK8s
installed and disabled), real, 2026-10-17. k3s v1.36.5+k3s1 (containerd
2.3.4-k3s1, kube-router network policies) installed with the official script for
the pass and removed with `k3s-uninstall.sh`; three pods in `default`: one
privileged, one mounting `/etc`, one non-root. No code change came out of it.*

| Measured | Result |
|---|---|
| pods read through `ctr` (k3s symlinks `ctr`, `crictl` and `kubectl` to its own binary) | the privileged pod and the `/etc` mount reported, −1 each; the non-root pod not reported |
| the kubelet asked anonymously from the host (k3s default) | 401 → "kubelet refuses anonymous requests" (OK) |
| `kubelet-arg: anonymous-auth=true, authorization-mode=AlwaysAllow` | `GET /pods` 200, `POST /run` for a missing pod 404 → ALERT "kubelet authorises anonymous commands"; back to 401 and OK after the revert |
| `sudo iptables -P FORWARD DROP` (the `forward_accept` fix), applied as printed | DNS through the service IP, pod to pod, pod to the internet and pod to the API service all still answer: k3s accepts its pod traffic in its own FORWARD chains |
| `sudo ufw allow 22/tcp && sudo ufw enable` (the `firewall.inactive` fix), applied as printed | SSH kept, the four pod probes answer, 6443 no longer answers from the LAN (default deny incoming); restored with `ufw disable` |
| a full audit while the host's snaps (Rocket.Chat, Nextcloud, Wekan, Prometheus) and k3s's first image pulls ran | 20 min 47 s at load average up to 64, the kubelet unprobed and the pods unread, both reported as not evaluated; 59 s once those snaps were stopped |

**Still open:**

| Gap | Sev. | § | Note |
|-----|------|---|------|
| ~~`--install-cron` / `--manage-cron` on BusyBox crond (`/etc/crontabs/`)~~ | — | §1 | **Resolved in 0.26.0** (see the 0.26.0 Alpine field pass): a job is a marked block of root's crontab. |
| ~~`firewall_drivers.iptables_bypass` deducts 2 for every INPUT rule whose target is ACCEPT, whatever it matches~~ | — | §4 | **Resolved in 0.26.0** (see the 0.26.0 bench above): reported only while UFW is active, read with `iptables -S`, deducted only for a rule that can let a new connection in. |
| ~~UFW-worded OK lines on hosts without UFW (`firewall_rules.no_duplicates`, `firewall_rules.no_open_any`, `logs.*` "UFW log source", "No UFW BLOCK events")~~ | — | §4 | **Resolved in 0.26.0** (see the 0.26.0 bench above): UFW rules analysed only while UFW is active, UFW logs only where UFW is installed. |

---
© 2026 Cédric Clauzel
