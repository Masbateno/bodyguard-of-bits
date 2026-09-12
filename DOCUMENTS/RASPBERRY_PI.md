*[Lire en français](RASPBERRY_PI_FR.md)*

# BOB on Raspberry Pi

This guide covers installing and running BOB on a Raspberry Pi, and what BOB
checks that is specific to this hardware. It ends with **exactly what was
validated on a real board** — a Pi Zero W — so you can tell measured behaviour
from expectation.

> **Honest scope.** Everything in the "Validated on real hardware" section below
> was reproduced and fixed on **one board: a Raspberry Pi Zero W (ARMv6) running
> Raspberry Pi OS 13 (trixie)**. Other models — Pi 4/5 (arm64), and OS releases
> before trixie that provision through `userconf.txt` rather than a cloud-init
> seed — will differ in details, and a solid Raspberry Pi matrix still needs them
> tested. Where this guide states a number, it is one BOB read on that board;
> where it generalises, it says so.

---

## Why a Pi needs its own pass

BOB reasons about software, and until v0.18.1 it reasoned about a PC. A Raspberry
Pi differs in ways that changed real verdicts:

- It **boots from a FAT partition** (`/boot/firmware`). FAT has no concept of
  ownership or permission bits, so anything written there — including the
  provisioning files the Raspberry Pi Imager creates — is exposed to whatever the
  mount grants and to anyone who takes the card out.
- Its **kernel builds AppArmor in but leaves it off at boot**, so a tool that
  trusts `aa-status` is misled.
- Its **swap is zram** (compressed RAM), not a disk.
- It carries **several kernel flavours** (`rpi-v6`, `rpi-v7`, `rpi-v8`) and can
  only boot its own.
- Recent images ship **OpenSSH ≥ 9.8**, which logs authentication under
  `sshd-session`, not `sshd`.

All of these are handled from v0.18.1 onward.

---

## Install

The prerequisites are the same as anywhere, via `pipx`:

```bash
sudo apt install pipx && pipx ensurepath
```

Open a new terminal so the `PATH` change takes effect, then:

```bash
pipx install bodyguard-of-bits
```

Enable `sudo bob` and bash completion once (pipx installs into `~/.local/bin`,
which is not in sudo's `PATH`):

```bash
sudo ~/.local/bin/bob --install-completion
source /etc/bash_completion.d/bob
```

> **Pi Zero / Zero W / 1 (ARMv6).** These are slow boards. A first audit takes
> longer than the few seconds it takes on a desktop; BOB reports its own
> duration at the end, so you need not guess. Installation pulls pure-Python
> wheels — no compiler needed.

### The virtualenv `pipx` creates

`pipx` installs BOB into its **own isolated virtualenv** — measured on the Pi
Zero W at `~/.local/share/pipx/venvs/bodyguard-of-bits`, about **5 MB**, on top
of a **~13 MB** pip/setuptools base that `pipx` shares across every app it
installs (created once). It uses the board's **system Python** (3.13 on trixie),
so no second interpreter is downloaded, and it touches **nothing** apt manages —
BOB's dependencies cannot clash with system packages, and vice versa. The only
thing placed on your `PATH` is the launcher `~/.local/bin/bob` (via
`pipx ensurepath`).

Managing it, all without a compiler and without root:

```bash
pipx upgrade bodyguard-of-bits     # in place, keeps the same venv + launcher
pipx list                          # shows the venv, its version and Python
pipx reinstall bodyguard-of-bits   # rebuild the venv (e.g. after an OS Python bump)
```

`sudo bob` runs the same code: the `--install-completion` step above symlinks
`/usr/local/bin/bob` to the venv launcher so root finds it (otherwise call
`sudo ~/.local/bin/bob` directly). Uninstalling removes the whole venv cleanly —
nothing is left behind in the system Python.

### Uninstall

```bash
sudo rm -f /usr/local/bin/bob /etc/bash_completion.d/bob
pipx uninstall bodyguard-of-bits          # removes the isolated venv entirely
```

---

## First audit

```bash
sudo bob
```

`sudo` matters more on a Pi than elsewhere: reading the credential files on the
boot partition and `/etc/shadow` (to tell a live password hash from a stale one)
needs root. Without it BOB still runs and says, for each thing it could not read,
that the answer was **not established** — it never reports "clean" about a file
it never saw.

To run only the Pi-specific checks:

```bash
sudo bob --check=raspberry_pi
```

To see what any finding means, in plain language with the CIS reference:

```bash
bob --explain raspberry_pi.seed_password
```

---

## What BOB checks on a Pi

### The boot partition (the `raspberry_pi` section)

BOB reads the provisioning files the Imager may have left on `/boot/firmware`
and reports **what is measurably there**, never a guess:

| Finding | What it means | Remediation BOB offers |
|---|---|---|
| `raspberry_pi.seed_password` | The cloud-init seed (`user-data`) still holds an account's password — hash or clear text. On trixie BOB also says whether the hash is the one the account uses *now*. | `sudo sed -i -E '/^[[:space:]]*(passwd\|hashed_passwd\|plain_text_passwd):/d' /boot/firmware/user-data` |
| `raspberry_pi.seed_wifi_key` | The seed (`network-config`) still holds the Wi-Fi PSK. | `sudo sed -i -E '/^[[:space:]]*password:/d' /boot/firmware/network-config` |
| `raspberry_pi.userconf_present` | Older images: `userconf.txt` (`user:hash`) is still present. | `sudo rm /boot/firmware/userconf.txt` |
| `raspberry_pi.legacy_account` | The historical `pi` account exists **and can log in** (not merely exists). | Rename or lock it. |

The remediation for the seed removes **only the secret lines** and leaves
`meta-data` alone — deliberately. See "The boot-partition credential problem"
below for why deleting the whole file is the wrong move.

A provisioning file that is present but **unreadable** blocks the all-clear: BOB
reports it as *not established* rather than assuming it is empty.

### Cross-cutting checks that behave differently on a Pi

These are not in the `raspberry_pi` section, but v0.18.1 taught them the board:

- **AppArmor built into the kernel but off at boot** (`mac_policy.apparmor_off_in_kernel`):
  BOB reads the kernel's own answer, not `aa-status`, and points the remedy at
  the kernel command line.
- **Reverse-path filtering per interface** (`hardening.rp_filter_*`): the kernel
  enforces `max(conf/all, conf/<iface>)`, so BOB reports the weakest interface's
  effective posture instead of `conf/all` alone.
- **Swap on zram**: recognised as compressed RAM, not judged as swap on a slow
  disk, and never handed an SSD-wear warning.
- **Kernel flavours**: reboot-pending and package cleanup reason within the
  running kernel's flavour, so an ARMv6 board is never told to boot an arm64
  kernel.
- **Socket-activated services**: a service that is inactive but has an active
  `.socket` is reported as available on demand, not as a stopped daemon.
- **SSH authentication under `sshd-session`** (OpenSSH ≥ 9.8): brute-force and
  successful-login detection read the right journal identifier.

---

## The boot-partition credential problem

On the validated board, the day after flashing, the cloud-init seed on the FAT
partition held live secrets that any local account could read:

- `user-data` contained the sudo account's **yescrypt password hash**,
  byte-identical to its `/etc/shadow` entry;
- `network-config` contained the **64-hex-digit Wi-Fi PSK**;
- both were mode **0755**, readable by every local user, because the vfat mount
  applies `fmask=0022` — FAT cannot store anything tighter.

**Why remove only the secret lines and not the file.** cloud-init runs its
per-instance modules **once per instance-id**, which lives in `meta-data`. If you
strip the `passwd`/`hashed_passwd`/`plain_text_passwd` lines from `user-data` and
the `password:` line from `network-config` but keep `meta-data`, cloud-init sees
the same instance on the next boot and skips those modules — Wi-Fi, `/etc/shadow`,
netplan and the hostname stay exactly as they are. Deleting the seed files hands
cloud-init the `None` datasource — a *new* instance — and it re-runs everything,
which is not what you want on a configured board.

BOB's `--fix --apply` will do this for you and re-audit afterwards, or you can run
the `sed` commands above by hand.

---

## Turning AppArmor on (Pi kernel)

The stock Pi kernel compiles AppArmor in but does not start it: `aa-status` exits
non-zero and the kernel reports `parameters/enabled = N`. To enable it, add two
parameters to the kernel command line and reboot:

```bash
# append to the single line in /boot/firmware/cmdline.txt (do not add a newline)
apparmor=1 security=apparmor
sudo reboot
```

> Measured on the Pi Zero W: after this change the kernel loaded **121 profiles,
> 22 enforcing**. The **first** boot afterwards is about a minute and a half
> slower while the profiles are compiled and cached; every boot after that is no
> slower. Where your board's bootloader keeps the kernel command line elsewhere,
> BOB names the parameter and offers no blind command.

---

## Validated on real hardware — Pi Zero W

**Board:** Raspberry Pi Zero W (ARMv6) · Raspberry Pi OS 13 (trixie) · OpenSSH
10.0. This is the first audit of BOB on physical Raspberry Pi hardware; it drove
the ten fixes released in **v0.18.1**. Each was reproduced on the board, fixed,
and the fix verified there.

| # | What BOB 0.18.0 said (wrong) | What was true on the board | Fixed in 0.18.1 |
|---|---|---|---|
| 1 | *OK — no successful SSH logins* | 71 failed attempts, 29 accepted logins in the journal | reads `sshd-session` (OpenSSH ≥ 9.8) |
| 2 | *No provisioning credentials on the boot partition* | `user-data` held the sudo account's live yescrypt hash | reads the cloud-init seed |
| 3 | (Wi-Fi key not seen) | `network-config` held the Wi-Fi PSK, mode 0755 | reports the seed Wi-Fi key |
| 4 | *AppArmor active, profiles unreadable* | AppArmor built in, **off** at boot | reads the kernel; remedy is the kernel cmdline |
| 5 | *Reverse path filtering disabled* | `conf/all=0` but `wlan0=2` — filtering | reports the weakest interface's effective value |
| 6 | *service enabled but not running* (−1) | `cups.service` inactive, `cups.socket` **active** | socket-activated = available on demand |
| 7 | *reboot into a newer kernel* | offered the **arm64** kernel to an ARMv6 board | reasons within the running kernel's flavour |
| 8 | *swappiness too aggressive, set vm.swappiness=1* | swap is **zram** (compressed RAM) | recognises zram, no disk-tuning advice |
| 9 | *security service enabled but not running* (−1) | `apparmor.service` skipped by an unmet condition | reads `ConditionResult=no` — not a gap |
| 10 | `--check=raspberry_pi --fix` also ran `apt install ufw` | the firewall fix is outside the selected scope | `--fix` applies only the selected sections |

The cloud-init seed remedy (finding 2/3) was proven on the board before it was
written into BOB: removing only the secret lines and rebooting kept Wi-Fi,
`/etc/shadow`, netplan and the hostname unchanged. BOB then ran the whole round
trip itself — two warnings, `--fix --apply --yes`, re-audit, all-clear.

**What this does *not* establish.** One board, one architecture (ARMv6), one OS
release (trixie). A Pi 4/5 on arm64, or an older image that still uses
`userconf.txt`, may surface differences this pass never saw. Field reports from
other models are worth more than emulation — if you run BOB on one, the results
help build the matrix.

---

## See also

- [Tutorial — getting started](TUTORIAL.md)
- [Full technical reference](README_TECH.md)
- [Changelog](../CHANGELOG.md) — the v0.18.1 entry details each Pi fix

---

© 2026 Cédric Clauzel
