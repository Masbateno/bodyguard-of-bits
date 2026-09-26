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

- **✓** — BOB handles this correctly (field-verified).
- **⚠** — partial or cosmetic issue (verdict usually right, wording/edge off).
- **✗** — genuine gap; BOB is wrong or blind here. Each ✗/⚠ names the finding.

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
- **⚠** Some remediation commands hard-code `systemctl restart …`. On Alpine that
  should be `rc-service <svc> restart` (e.g. the SSH-hardening fix). *Wording gap
  — verdict is correct, the suggested command is not runnable as-is on OpenRC.*

## 2. Config-file layout — `/etc` vs `/usr/etc`

Most distros keep editable config in `/etc`. **openSUSE Leap 16** ships vendor
defaults under `/usr/etc/<file>`, with `/etc/<file>` as the *optional* override
(the systemd vendor-config convention: `/etc` wins when present, else `/usr/etc`).

| File | Debian family / Fedora / Kali / Alpine / Pi | openSUSE Leap 16 |
|------|---------------------------------------------|------------------|
| `sshd_config` | `/etc/ssh/sshd_config` | **`/usr/etc/ssh/sshd_config`** (absent from `/etc`) |
| `login.defs` | `/etc/login.defs` | **`/usr/etc/login.defs`** |
| `sudoers` | `/etc/sudoers` | **`/usr/etc/sudoers`** (mode 444; `@includedir /etc/sudoers.d` **and** `/usr/etc/sudoers.d`) |

**BOB status:**
- **✗** BOB reads only the `/etc` paths (`bob/checks/ssh/_snapshot.py`,
  `password_policy.py:44`, `file_perms.py:42`). On openSUSE:
  - **sshd_config** — `/etc/ssh/sshd_config` is absent, so BOB never follows the
    `Include /etc/ssh/sshd_config.d/*.conf` declared in the `/usr/etc` file and
    **reports OpenSSH compiled-in defaults for every config-derived SSH finding**
    (PermitRootLogin, PasswordAuthentication, …). A real `PermitRootLogin yes`
    set in `/usr/etc` or a drop-in is masked as "✔ root login restricted".
    *MEDIUM-HIGH — the most serious open gap. Host keys (read by separate glob)
    are still real.*
  - **login.defs** — reported as the default `PASS_MAX_DAYS 99999` (coincidentally
    correct here; would misreport a stricter `/usr/etc` policy). *LOW.*
  - **sudoers** — the main file is not read, but `/etc/sudoers.d` **is** (field-
    verified: a `NOPASSWD:ALL` dropped there is caught), so real admin rules are
    seen; only rules directly in `/usr/etc/sudoers[.d]` escape. *LOW.*
- **Fix direction (0.21.3 candidate):** read `/etc/<f>` then fall back to
  `/usr/etc/<f>`; or, for SSH, resolve the effective config via `sshd -T`. This is
  the coherent "distro-mechanism-awareness" lot together with §6 (doas).
- **✓** Where `/etc/ssh/sshd_config` exists (all other distros), the parser is
  correct: it follows `Include`, sorts drop-ins, and applies first-value-wins —
  a forced `PermitRootLogin yes` on Alpine is detected as an ALERT.

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
- **✓** All five managers handled; the "no security channel" case (Kali/Alpine/
  Arch/pacman) is explicit — BOB does not read "0 security pending" as "secure".
- **✓** Microcode-package mapping per manager: apt `amd64-microcode`, dnf
  `amd-ucode-firmware`, **zypper `ucode-amd` / `ucode-intel`** (added v0.20.4),
  apk/pacman standard.

## 4. Firewall

| Distro | Default firewall | BOB support |
|--------|------------------|-------------|
| Ubuntu, Mint, Debian, Pi OS | ufw (often inactive) / nftables | **✓** ufw active↔inactive, v6 awareness |
| Fedora, openSUSE | firewalld | **✓** credited by zone (v0.20.2); rich-rules/forward-ports shown (v0.20.4) |
| Kali | nftables (no ufw) | **✓** underlying nft/iptables layer inspected |
| Alpine | **none by default** (awall available) | **✓** honest "no firewall / unprotected"; **✗** awall front-end not recognised (soft — nft/iptables layer still inspected) |

**BOB status:**
- **⚠** firewalld that is **installed but stopped** is shown in the banner as
  "firewalld: not installed" — `firewall-cmd --version` needs the daemon
  (exits 252 when stopped), so the version probe returns empty. Verdict (ALERT /
  unprotected) is correct; only the banner presence line is wrong. *LOW —
  detect presence via `command -v firewall-cmd`, not `--version` success.*

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
- **✗** `mac_policy` branch ordering: on a **SUSE-style kernel (AppArmor
  compiled-in-off) where SELinux is the real MAC**, when SELinux is **Permissive**
  (or Disabled), the `apparmor_off_in_kernel` branch fires *before* the SELinux
  branch, so BOB says "AppArmor built into the kernel but not enabled" and
  suggests `apparmor=1` — never mentioning that SELinux is merely permissive and
  the real fix is `setenforce 1`. *MEDIUM — misleading remediation on an SELinux
  distro. SELinux-enforcing short-circuits at the top, so it only bites in the
  permissive/disabled state. Alpine's identical AppArmor-off warning is **correct**
  there — Alpine genuinely has no MAC and no SELinux.*

## 6. Privilege escalation — sudo vs doas

| Distro | Tool | Config | Passwordless grant |
|--------|------|--------|--------------------|
| Debian, Ubuntu, Mint, Fedora, openSUSE, Kali, Pi OS | sudo | `/etc/sudoers`, `/etc/sudoers.d/` | `NOPASSWD:ALL` |
| **Alpine** (BSD-style) | **doas** | **`/etc/doas.conf`** | **`permit nopass`** |

**BOB status:**
- **✓** sudo: `/etc/sudoers` + `/etc/sudoers.d`, `NOPASSWD:ALL` and empty-group
  latent grants flagged.
- **✗** **doas is not audited at all.** A forged `permit nopass baduser as root`
  (passwordless root — the doas equivalent of `NOPASSWD:ALL`) produces **no BOB
  finding**. On doas-based systems this is a blind spot for the whole privilege-
  escalation surface. *MEDIUM — 0.21.3 candidate alongside §2.*
- **⚠** SUID baseline is sudo/Debian-centric: on Alpine, `/usr/bin/doas` and
  `/bin/bbsuid` (busybox-suid) are flagged as "unexpected SUID" though both are
  standard there. *LOW — recognise them when an apk package owns them.*

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

## Open gaps summary (0.21.3 / 0.22 backlog)

The ✗/⚠ above, most-actionable first. The first three share one root cause —
*BOB does not know the distro's actual mechanism* — and make a coherent lot:

| # | Gap | Severity | §  |
|---|-----|----------|----|
| 1 | SSH audit blind on `/usr/etc` layout (reports OpenSSH defaults) | MEDIUM-HIGH | §2 |
| 2 | `/etc/doas.conf` not audited (passwordless doas invisible) | MEDIUM | §6 |
| 3 | `mac_policy` mis-orders SELinux-permissive vs AppArmor-off | MEDIUM | §5 |
| 4 | `login.defs` / `sudoers` in `/usr/etc` not read | LOW | §2 |
| 5 | firewalld "not installed" when merely stopped | LOW | §4 |
| 6 | doas / bbsuid flagged as "unexpected SUID" on Alpine | LOW | §6 |
| 7 | fix wording `systemctl` vs OpenRC `rc-service` | LOW | §1 |
| 8 | awall front-end not recognised (nft/iptables still inspected) | soft | §4 |

---
© 2026 Cédric Clauzel
