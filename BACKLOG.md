*[Lire en français](BACKLOG_FR.md)* · *[Changelog](CHANGELOG.md)*

# BOB — Backlog

What is planned or waiting, sorted by severity. Each line is one item of the maintainer's backlog; its ID never changes (missing numbers are items already dealt with: see the [changelog](CHANGELOG.md)). **Planned** names the version it is scheduled for, or `pending` when none is set.

Last updated: 2026-11-27.

## Severity

| Severity | What it means |
|---|---|
| 🔴 HIGH | BOB may give a wrong score: points taken or granted wrongly. |
| 🟠 MEDIUM | BOB may state something false or too reassuring, with no point at stake. |
| 🟡 LOW | Imprecise wording, presentation, robustness: the verdict stays right. |
| 🔵 LIMIT | What BOB does not read, and says so (the score becomes a ceiling). |
| ⚪ EXTERNAL | Waits on someone else. |
| 🟢 ENHANCEMENT | Asked for or to be decided: not a defect of the current verdict. |
| ⚫ LONG TERM | Useful, with no deadline. |

## Open items

| Severity | ID | Description | Planned |
|---|---|---|---|
| 🟡 LOW | B-053 | Align the help's and screens' "ceiling" with the changelog's "retention threshold". | 0.44.0 |
| 🟡 LOW | B-054 | A guard against a per-test mktemp and against the host's accounts in screen tests. | 0.44.0 |
| 🟡 LOW | B-057 | README: the team-perimeters link says "who may do what", more than perimeters do. | 0.44.0 |
| 🟡 LOW | B-026 | A CI test that fails on purpose when an image reaches end of support (next deadline: 1 May 2027). | pending |
| 🟡 LOW | B-056 | Language parity: DISTRO_MATRIX.md and SNAPSHOT.md have no French version yet. | pending |
| ⚪ EXTERNAL | B-016 | Wait for CIS Fedora (draft) and Ubuntu 26.04 level 2 at ComplianceAsCode. | pending |
| 🟢 ENHANCEMENT | B-050 | A settable size ceiling for the journals, with chained rotation (the reports' part shipped in 0.43.0). | 0.44.0 |
| 🟢 ENHANCEMENT | B-051 | Switch from one wizard to another with a shortcut (function keys). | 0.44.0 |
| 🟢 ENHANCEMENT | [B-055](#annex--b-055) | Rethink running as root under sudo: a minimal privileged collection, everything else as the calling user, perimeters enforced by Linux; steps 0 and 1 in 0.44.0, the rest later. | 0.44.0 |
| 🟢 ENHANCEMENT | B-052 | Team notepads in --manage-team: one open to all, one per account, each account's read and write rights towards the others set by Linux ACLs. | 0.45.0 |
| 🟢 ENHANCEMENT | B-045 | Mail the master about actions outside a perimeter (base shipped in 0.43.0); waits for B-055 step 3. | pending |
| 🟢 ENHANCEMENT | B-046 | Files with no recorded digest: done for Debian in 0.43.0, the rpm equivalent remains. | pending |
| 🟢 ENHANCEMENT | B-047 | A secret team notepad through a plugin to a proven tool (pass). | pending |
| 🟢 ENHANCEMENT | B-048 | A screen to edit configuration files (SSH, then Samba), with validation and copies. | pending |
| 🟢 ENHANCEMENT | B-049 | Hand over the master role, then co-masters; waits for B-055 step 3. | pending |
| ⚫ LONG TERM | B-018 | Run other Raspberry Pi models on real hardware. | pending |

No item at 🔴 HIGH, 🟠 MEDIUM or 🔵 LIMIT today.

Annex below: [B-055](#annex--b-055).

## Annex — B-055

**Status (27 November 2026, 0.44.0): steps 0 and 1 below are done and measured in 0.44.0;
steps 2 to 4 have no version yet.** The points under "What the code shows" describe 0.44.0, from
reading its code, the plugin points measured; until the design changes further, treat them as
true.

### What the code shows

- **An audit runs as root from start to finish.** `sudo bob` is required, and BOB never gives
  up root's rights afterwards.
- **Root also does work that does not need it**: reading and parsing files that ordinary users
  can write, writing into users' home directories, sending the webhook and the emails, drawing
  the screens when they are opened with `sudo`. Two past security fixes came from this family:
  0.26.1 (as root, BOB followed a symlink in the user's home) and 0.38.0 (a configuration owned
  by a user, now inspected before root reads it).
- **Plugins no longer run as root (0.44.0).** Under `sudo`, BOB loads the plugins found in the
  calling user's `~/.config/bob/checks.d/`. Until 0.43.0 its sandbox child kept root's rights
  (**measured**: a plugin reported its own user id as 0). Since 0.44.0 the child takes the
  calling user's uid and groups before reading the plugin (**measured** on Linux Mint 22.3,
  Fedora 44 and Alpine 3.24), and root no longer follows a symbolic link to open one. BOB's own
  source still states that this sandbox is not a security boundary.
- **So allowing someone to run `sudo bob` amounts to giving them root.** A sudoers rule that
  allows only `bob` does not limit that person to auditing.
- **Team perimeters (0.43.0) are not access control.** They announce, ask and record an action
  outside a declared perimeter; they prevent nothing. As long as every member runs `sudo bob`,
  no perimeter can be enforced.
- **The journals are local witnesses.** Root can rewrite a journal and the local system log
  alike; logs kept on another host are needed against that.
- **Scheduled audits run as root** (a `root` line in `/etc/cron.d`, or root's crontab where
  there is no `/etc/cron.d`).
- **Most installs are not confined.** Only the Debian packaging carries an AppArmor profile; an
  install with pip or pipx has none.

### First measurement: BOB without root (26 November 2026)

On a test machine, the same audit run as root, then as two ordinary accounts (one in the `adm`
group, one in no group). Without root, BOB already says "not read" in most places: 12 more
items say so, and the score's range widens (7–8 as root, 2–8 without) instead of hiding what it
could not see. Three places did not, and were fixed in 0.44.0 (step 1): the UFW log was called "not
found" when it exists but could not be read; root's `~/.ssh` was called "not found" for the same
reason; and GRUB's password went unsaid when `grub.cfg` could not be read. Measured since on
Fedora 44 and Alpine 3.24 too: one more place there — the authentication journal, seen only in
part, read as "no login" — fixed as well. These runs without root served to find such places;
the audit itself stays root's (decided on 27 November 2026): without root it was incomplete, and
on Fedora misleading — two whole domains unread, the score up from 8 to 9.

### What to do until it changes

- Allow `sudo bob` only to people you would trust with root.
- Before running `sudo bob`, look at the plugins in your `~/.config/bob/checks.d/`: only code
  you trust belongs there.
- Use team perimeters as a record of who did what, not as a barrier.
- Report anything you find on this through [SECURITY.md](SECURITY.md).

### What is planned

The direction: root only to read what requires it; everything else under the calling user's
account; the team's rights carried by Linux itself (groups, file owners, sudoers), which BOB
reads and reports instead of imitating them.

- **Step 0 — a measured inventory** *(done, 0.44.0)*: for each section, what it reads and why it
  needs root; the plugin point above, measured.
- **Step 1 — a refused read is not an absence, and plugins without root** *(done, 0.44.0)*: a file
  that exists but cannot be read is reported unread, never treated as absent; plugins run with the
  calling account's uid and groups (behind sudo or doas), not root's, and are never opened through
  a link. The audit itself stays root's.
- **Step 2 — privilege separation**: a minimal root collector; analysis, score, reports,
  screens and network under the calling user's account. The scores and exit codes of `sudo bob`
  stay the same.
- **Step 3 — the team carried by Linux**: attributes as Linux groups, reports shared by group,
  `--fix --apply` through the person's own `sudo`. A perimeter becomes enforced, not only
  declared.
- **Step 4 — confinement**: scheduled audits through a systemd unit with bounded capabilities;
  an AppArmor profile outside the Debian packaging; SELinux to study.

Steps 2 and 3 will probably change where reports, scheduled jobs and journals live: that will be
announced as BREAKING when it comes.

---

© 2026 Cédric Clauzel
