*[Lire en français](BACKLOG_FR.md)* · *[Changelog](CHANGELOG.md)*

# BOB — Backlog

What is planned or waiting, sorted by severity. Each line is one item of the maintainer's backlog; its ID never changes (missing numbers are items already dealt with: see the [changelog](CHANGELOG.md)). **Planned** names the version it is scheduled for, or `pending` when none is set.

Last updated: 2026-11-26.

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
| 🟡 LOW | B-026 | A CI test that fails on purpose when an image reaches end of support (next deadline: 1 May 2027). | pending |
| 🟡 LOW | B-056 | Language parity: DISTRO_MATRIX.md and SNAPSHOT.md have no French version yet. | pending |
| ⚪ EXTERNAL | B-016 | Wait for CIS Fedora (draft) and Ubuntu 26.04 level 2 at ComplianceAsCode. | pending |
| 🟢 ENHANCEMENT | B-045 | Mail the master about actions outside a perimeter (the base shipped in 0.43.0). | 0.44.0 |
| 🟢 ENHANCEMENT | B-049 | Hand over the master role, then co-masters. | 0.44.0 |
| 🟢 ENHANCEMENT | B-050 | A settable size ceiling for the journals, with chained rotation (the reports' part shipped in 0.43.0). | 0.44.0 |
| 🟢 ENHANCEMENT | B-051 | Switch from one wizard to another with a shortcut (function keys). | 0.44.0 |
| 🟢 ENHANCEMENT | B-052 | A plain-text team notepad, one entry per account, in --manage-team. | 0.44.0 |
| 🟢 ENHANCEMENT | B-046 | Files with no recorded digest: done for Debian in 0.43.0, the rpm equivalent remains. | pending |
| 🟢 ENHANCEMENT | B-047 | A secret team notepad through a plugin to a proven tool (pass). | pending |
| 🟢 ENHANCEMENT | B-048 | A screen to edit configuration files (SSH, then Samba), with validation and copies. | pending |
| 🟢 ENHANCEMENT | [B-055](#annex--b-055) | Rethink running as root under sudo: a minimal privileged collection, everything else as the calling user, team perimeters enforced by Linux permissions. | pending |
| ⚫ LONG TERM | B-018 | Run other Raspberry Pi models on real hardware. | pending |

No item at 🔴 HIGH, 🟠 MEDIUM or 🔵 LIMIT today.

Annex below: [B-055](#annex--b-055).

## Annex — B-055

**Status: nothing below is measured yet.** It comes from reading BOB's code (version 0.43.0).
The measurement is in progress. Until it is done and the design has changed, treat every point
as true. No version is set for the change yet (`pending`).

### What the code shows

- **An audit runs as root from start to finish.** `sudo bob` is required, and BOB never gives
  up root's rights afterwards.
- **Root also does work that does not need it**: reading and parsing files that ordinary users
  can write, writing into users' home directories, sending the webhook and the emails, drawing
  the screens when they are opened with `sudo`. Two past security fixes came from this family:
  0.26.1 (as root, BOB followed a symlink in the user's home) and 0.38.0 (a configuration owned
  by a user, now inspected before root reads it).
- **Plugins run as root.** Under `sudo`, BOB loads the plugins found in the calling user's
  `~/.config/bob/checks.d/` and runs them in a child process that keeps root's rights. BOB's
  own source states that this sandbox is not a security boundary.
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

- **Step 0 — a measured inventory** *(in progress)*: for each section, what it reads and why it
  needs root; the plugin point above, measured.
- **Step 1 — without root, honestly**: `bob` without `sudo` audits what it can and says "not
  read" for the rest; plugins run with the calling user's rights even when BOB is root.
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
