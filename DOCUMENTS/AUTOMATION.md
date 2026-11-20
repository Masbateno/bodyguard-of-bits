*[Lire en français](AUTOMATION_FR.md)*

# Automation — BOB

This document explains how to configure BOB to run automatically on a schedule and notify you of any issues.

---

## Quick setup

```bash
sudo bob --install-cron
```

The wizard guides you through 7 steps:

1. **Name** — a short label for this cron job (e.g. `nightly`, `weekly`). Press Enter to use the suggested name.
2. **Schedule** — choose from:
   - Every day
   - Certain days of the week (e.g. `1 3 5` for Mon/Wed/Fri)
   - Certain days of the month (e.g. `1 15` for the 1st and 15th)
   - Custom cron expression (e.g. `0 3 * * 1`)
3. **Time** — execution time in `HH:MM` format (default: `03:00`). Not shown for custom expressions.
4. **Email** — optional notification address(es): pick saved ones from the address book, type a new one, or `0` for none (see *Multiple notification emails* below).
5. **Profile** — `server`, `desktop`, `workstation` or `container`.
6. **Language** — English or French, for both the report and the notification email.
7. **Outbound probes** — enabled, or disabled (`--offline`).

A plain-language preview is shown before confirmation:
```
  → Schedule: every Monday, Wednesday, Friday at 02:30
```

`y` applies it and `Esc` goes back; since v0.39.0 no other key does anything there (`Enter` applied it, any other key abandoned it, neither announced). When a job of that name already exists, the wizard asks before overwriting it, in the wording every confirmation uses: *Press y to confirm, any other key to cancel* — a refusal steps back.

### What the scheduled audit runs

Steps 5 to 7 exist because **a cron runs as root**. Before v0.16.1 the generated
script ran a fixed `bob --quiet --detailed`, so the scheduled audit read *root's*
saved profile — not yours — and cron's bare environment, where `$LANG` is
usually unset, so the report came out in English whatever you had chosen.

That mattered beyond cosmetics: the profile decides which findings deduct,
therefore the warning count, therefore the exit code, therefore whether the
notification email is sent at all.

Each of the three screens opens on the value given to the command installing
the cron — its `-p`, its language (`--french` / `--lang`, else the detected
`$LANG`) and its `--offline` — so `sudo bob -p desktop --french --install-cron`
needs three keystrokes. Without `-p` the profile screen opens on your saved
profile (since 0.25.1; it opened on `server` before), else on `server`.
The resulting command line is printed before anything is written:

```
  Scheduled command: bob --quiet --detailed --profile desktop --french
```

`--quiet` and `--detailed` are structural rather than preferences: cron has no
terminal, and the notification email *is* the `.log` that `--detailed` writes.
Since v0.18.0 that file carries each finding's explanation, its command and its
key. Before, the `--quiet` path wrote a level and a message and nothing else, so
a scheduled report named every problem and none of the fixes the same audit
printed on a terminal.

Existing cron jobs are untouched by an upgrade — their script keeps the command
line it was generated with. Re-run `sudo bob --install-cron` with the same name
to regenerate one.

### Hosts without `/etc/cron.d`

BOB writes its jobs to `/etc/cron.d`, the directory cronie, cron and Vixie-cron derivatives read. BusyBox crond (Alpine) reads one file per user in `/etc/crontabs/` and has no `/etc/cron.d`. Since 0.26.0 a job there is a block of root's crontab, `/etc/crontabs/root`, between two marker lines:

```
# BEGIN BOB cron bob-NAME
# BOB cron — generated YYYY-MM-DD by bob --install-cron
# name: NAME
# email: 
0 3 * * *  /usr/local/bin/bob-NAME
# END BOB cron bob-NAME
```

Only that block is ever rewritten — by `--manage-cron` (schedule, e-mail) and on removal; the lines the system or you put in the crontab stay as they are. Each change ends by writing `root` to `/etc/crontabs/cron.update`, which is what makes BusyBox crond re-read the file (measured on Alpine 3.24: without it, an edit was not picked up in three minutes; with it, within a minute). 0.25.1 refused the wizard on such a host.

### Files created

- `/usr/local/bin/bob-{name}` — wrapper script
- `/etc/cron.d/bob-{name}` — system cron entry (BusyBox crond: a `# BEGIN/END BOB cron bob-{name}` block of `/etc/crontabs/root` instead)

---

## Managing cron jobs

```bash
sudo bob --manage-cron
```

Lists all installed cron jobs with their schedule and notification email. In a
terminal this is a curses screen (the shared keys below, plus `Enter` to edit a
job, `Space` / `a` to mark one or all, `d` to delete jobs by their numbers — the
prompt starts with the marked ones, else the one under the cursor, and takes
`3`, `1,3`, `2-5` or `all` (CONVENTIONS.md) — `m` for the address book, `l` for the language and `q` to quit); when stdout is not a
terminal, the plain menu below is used instead. Both loop until you quit:

```
  1. nightly              every day at 03:00
     → email: you@example.com
  2. weekly-monday        every Monday at 02:00

  Manage your cron jobs:

    1        edit cron job #1
    e:1      edit notification email for cron #1
    d:1      delete cron #1
    d:1,3    delete crons #1 and #3
    d:1-3    delete crons #1 through #3
    d:all    delete all cron jobs
    m        manage the email address book

  Press Enter or 'q' to quit.
  >
```

| Command | Action |
|---------|--------|
| `N` | Edit cron N — choose between schedule or notification email |
| `e:N` | Edit the notification email of cron N directly |
| `d:N` | Delete cron N and its associated script |
| `d:1,3` | Delete cron jobs 1 and 3 (comma list) |
| `d:1-3` | Delete cron jobs 1 through 3 (range) |
| `d:all` | Delete all installed cron jobs |
| `m` | Open the email address book (see below) |
| Enter / `q` | Quit |

After each action the menu redisplays so you can chain multiple operations.

---

## Removing a cron job

In the plain menu, enter `d:N` to delete a single job, or use a comma list, range, or `all` for bulk deletion:

```
  > d:1
  Delete cron 'nightly'? [y/N] y
  ✔ Cron 'nightly' deleted

  > d:1,2
  Delete 2 cron jobs (nightly, weekly)? [y/N] y
  ✔ 2 cron jobs deleted

  > d:all
  Delete ALL 2 cron jobs? [y/N] y
  ✔ 2 cron jobs deleted
```

---

## Email address book

The email address book (`m`) lets you manage saved notification addresses independently of any cron job. It is available even when no cron jobs are installed:

```
  ╔════════════════════════════════════════════════════════════╗
  ║  EMAIL ADDRESS BOOK                                        ║
  ╚════════════════════════════════════════════════════════════╝

  1. you@example.com
  2. admin@example.com

  Manage your saved email addresses:

    1        delete address #1
    1,3      delete addresses #1 and #3
    1-3      delete addresses #1 through #3
    all      delete all addresses
    a        add a new address

  Press Enter or 'q' to quit.
  >
```

In a terminal the address book is a curses screen too: `Space` / `a` mark one or all, `n` adds an address, `d` deletes addresses by their numbers (the prompt starts with the marked ones, else the one under the cursor; `3`, `1,3`, `2-5` or `all`), `Esc` goes back. Since v0.39.0 the addresses and the jobs are numbered, and every deletion is confirmed.

| Command | Action |
|---------|--------|
| `a` | Add a new validated email address |
| `N` | Delete address N |
| `1,3` | Delete addresses 1 and 3 |
| `1-3` | Delete addresses 1, 2 and 3 |
| `all` | Delete all saved addresses |

Since v0.39.0 every deletion here asks first (`[y/N]`; it deleted without asking), and the numbers follow the rule of every list of numbers in BOB (CONVENTIONS.md): a range takes the addresses there are between its bounds, a number given alone — on its own or in a list — must be an address, or nothing is deleted and that number is named; forms mix (`1,3-5`).

| Enter / `q` | Return to the cron management menu |

Addresses saved here are offered as suggestions whenever `--install-cron` or `--manage-cron` asks for a notification email.

---

## Multiple notification emails 

`--install-cron` supports multiple recipients. After each selection, you are asked whether to add another:

```
  Notification email(s):
    → Selected so far: admin@example.com
    0. (none / done)
    1. admin@example.com ✔
    2. security@example.com
    3. Enter a new address...
  > 2
  Add another email address? [y/N] n
```

All selected addresses are stored comma-separated and each receives an individual email when the audit detects issues.

> **Postfix note:** No additional configuration is needed for multiple recipients. Postfix always sends as the single account configured in `sasl_passwd` (the sender). Recipients can be any valid email addresses — on the same domain or different ones — without any extra setup.

---

## Email requirements

Notifications require `sendmail` — provided by any standard MTA:

```bash
# Local MTA (recommended for servers):
sudo apt install postfix

# Relay-only MTA (for desktops relaying via Gmail, Outlook, etc.):
sudo apt install msmtp-mta
```

The commands above are Debian's. `postfix` and `msmtp` carry the same package
name on most distributions; the `-mta` companion that installs the `sendmail`
binary does not, so check your own package manager for it.

`--install-cron` detects your MTA (Postfix, Exim, msmtp, ssmtp) and says which
one it found. **Detection is not delivery.** All it establishes is that a
`sendmail` binary exists, which a Postfix installed and never configured also
satisfies while delivering nothing — see the relay setup below, which is the
part that actually makes mail leave the host.

```bash
bob --test-email                 # send a real message through the cron transport
```

This is the only way to know before the first scheduled run. It uses the same
code path the cron script does and exits non-zero when `sendmail` refuses the
message. A zero exit means the MTA *accepted* it — a relay or a spam filter can
still drop it, so check the inbox once.

Email is sent **only when the audit exits non-zero** — warnings, alerts, a technical error, or a missed `--target`. If your configuration is healthy, you receive nothing, so silence alone does not prove the mail route works: that is what `bob --test-email` is for.

---

## Cron file format

Each cron file includes metadata comments for identification. Multiple emails are stored comma-separated:

```
# BOB cron — generated 2026-10-16 by bob --install-cron
# name: nightly
# email: admin@example.com,security@example.com
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 3 * * *  root  /usr/local/bin/bob-nightly
```

---

## Webhooks

In addition to (or instead of) email notifications, BOB can POST the audit summary to a webhook URL. Two formats are supported: Slack-compatible payloads and a generic JSON envelope.

```bash
sudo bob --webhook https://hooks.slack.com/services/T00.../B00.../XX...
sudo bob --webhook https://my-internal-endpoint.example.com/audit
```

### Format auto-detection

BOB inspects the URL to pick the payload format:

| URL pattern | Payload format |
|-------------|----------------|
| `hooks.slack.com/services/...` | Slack (rich attachment with color-coded blocks) |
| anything else | Generic JSON envelope |

Force a specific format with `--webhook-format`:

```bash
sudo bob --webhook URL --webhook-format=slack    # force Slack format
sudo bob --webhook URL --webhook-format=generic  # force generic JSON
```

### Slack payload

The Slack message includes:

- A summary line: BOB version, host, score, risk level, and the alert and warning counts
- The list of ALERT and WARN findings, each with its detail, cut at 2500 characters (an ellipsis marks the cut)
- A colour-coded attachment: red when there is an alert, orange when there are only warnings, green otherwise

It carries no per-domain scores, and its score is the plain number — it does not show the `≤` of a score that is only a ceiling; the generic envelope below has the fields that say so.

### Generic JSON envelope

The generic payload is intentionally minimal and stable:

```json
{
  "source": "bob",
  "version": "0.25.0",
  "host": "example.local",
  "timestamp": "2026-06-11T18:42:01+00:00",
  "score": 8,
  "score_is_upper_bound": false,
  "score_low": 8,
  "score_high": 8,
  "unscored_domains": [],
  "unverified": [],
  "max_score": 10,
  "risk": "low",
  "alerts": 1,
  "warnings": 2,
  "profile": "server",
  "degraded_sections": [],
  "domain_scores": {"firewall_network": 10, "exposure_services": 9, "access_control": 7, "system_hardening": 8, "health_resilience": 9, "detection": 8},
  "findings": [
    {"level": "ALERT", "key": "ssh.permit_root_login", "message": "Root login allowed via SSH", "qualified_by": [], "detail": "", "note": ""}
  ]
}
```

This generic envelope is its **own** flat contract (distinct from the `bob --json` audit schema): top-level `source`/`max_score`/`timestamp` and a flat `domain_scores` map of `{domain: score}` over the six domain keys. `alerts` and `warnings` are **counts (integers)**; the `findings` array always enumerates the ALERT- and WARN-level findings (each with `level`/`key`/`message`/`qualified_by`/`detail`/`note`). `risk` is the **effective** (posture-escalated) level, lowercase (`"low"` / `"medium"` / `"high"` / `"critical"`). Note: the webhook keeps the `alerts`/`warnings` names — only the `bob --json` audit schema renamed them to `alert_count`/`warning_count` in v0.12.0 (F9).

**Fields added since v0.14.1**, all additive — existing receivers are unaffected:

  - **`profile`** — the audit profile that produced these numbers. Since v0.14.0 the profile changes finding severities, `warnings` and therefore the exit code, so two payloads from the same host can legitimately disagree; without this field nothing explains why. Use it to group or compare hosts.
  - **`degraded_sections`** — the sections whose check raised and were degraded in place instead of aborting the audit (empty list on a healthy run). **This is the field to alert on.** A receiver seeing `score: 9, alerts: 0` cannot otherwise tell a clean host from one where two sections never ran; the exit code deliberately stays driven by the real findings (unless `--target` is set), so a receiver sees the incompleteness here — the `<section>.unavailable` INFO findings are not in the envelope, which carries ALERT and WARN only.
  - **`score_is_upper_bound`** — true when a check could not read its input. The deductions it did not make are **unknown, not zero**, so `score` is a ceiling. An audit run without the privileges it needs reads *higher* than a full one, which is why a monitoring rule on `score` alone can go green on a blinder run. **`unverified`** lists the finding keys behind it, and (v0.16.2) `score_low` / `score_high` bound the true score while `unscored_domains` names the domains blindness removed from the average. Since v0.16.0 `--target N` also fails closed on a bounded score: a gate cannot be satisfied by a ceiling.

A reasonable monitoring rule is therefore *"page on `alerts > 0`, and warn separately whenever `degraded_sections` is non-empty"* — the second condition means the audit itself is unhealthy, not the host.

### Behaviour

- The webhook is POSTed **every time a webhook URL is configured** (CLI flag or `webhook_url` in config). It is *not* conditional on alerts/warnings being present — see `bob/__main__.py` `if _webhook_url and not config.offline:`. A clean audit still triggers a delivery; you can filter on the receiving side by inspecting `alerts`/`warnings`/`score`.
- `--offline` (or `-o`) disables webhook delivery entirely. Use it for distro build sandboxes and air-gapped environments.
- A failed webhook POST does **not** affect the audit exit code — it's a best-effort notification, not a gate. Errors are written to stderr.
- Each webhook URL is hit with a **10-second timeout** (`bob.webhook._TIMEOUT_SECONDS = 10`).

### Combining with cron

The cron wrapper script generated by `--install-cron` does not include a `--webhook` flag. A scheduled audit runs as root and fires the webhook saved in **root's** configuration (`/root/.config/bob/config.conf`); `sudo bob --webhook=URL` does not put it there — under `sudo` BOB saves the URL in the invoking user's configuration. The direct way is to edit the generated wrapper at `/usr/local/bin/bob-{name}` and append the flag to the `bob` invocation:

```bash
sudo nano /usr/local/bin/bob-nightly
# change:  /usr/local/bin/bob --quiet --detailed --profile server --english
# to:      /usr/local/bin/bob --quiet --detailed --profile server --english --webhook https://hooks.slack.com/...
```

Re-running `--install-cron` with the same name regenerates the script and drops the edit.

---

## Monitoring and follow-up

Beyond scheduled audits, BOB offers a handful of flags that help operators look at the system state over time. They are not "automation" in the cron sense but they fit the same operational toolbox.

### `--watch=N` — live monitoring mode

Re-runs the audit every `N` seconds until interrupted with `Ctrl-C`:

```bash
sudo bob --watch=60
```

Each pass prints one line — time, score, score bar and risk level — then *No changes detected since last audit* or the findings that appeared or were resolved since the previous pass, then the time of the next pass; the first pass only sets the comparison point. The output scrolls; nothing is redrawn in place. The interval is 10 s at least. Use cases:

- Watching a hardening change take effect (`sudo sysctl -w ...` → next pass shows the WARN disappear)
- Demoing the audit live in a meeting
- Verifying a fail2ban / firewall change without manually rerunning

`--watch` is incompatible with `--json`, `--output=csv`, `--output=markdown`, and `--html` (it uses interactive terminal output).

### `--diff` — show only what changed

Compares the current audit against the previous one and prints only the delta:

```bash
sudo bob --diff
```

After the score and count lines, one line per ALERT/WARN key that appeared or was resolved — or that could not be compared because its section was not read this time (*Not re-evaluated*):

```
⚠ [WARNING] New finding: clamav.scan_old
✔ [OK] Resolved: hardening.send_redirects_enabled
✔ [OK] Resolved: ssh.x11.forwarding.server
```

The baseline file lives at `~/.config/bob/last_baseline.json` (mode `0600`) and is rewritten at the end of every full audit run. A file passed to `--diff` that carries no `timestamp` and `score` is refused as *not a BOB baseline* (exit 3) rather than compared against as a baseline of zero. To wipe the baseline and start fresh:

```bash
sudo bob --reset-baseline
```

### `--history` — score trend over time

Renders a sparkline over the last 50 audit scores from
`~/.config/bob/history.jsonl`, then a table of the ten most recent with their
trend arrow:

```bash
bob --history
```

```
  Score History
  ────────────────────────────────────────────
  ▅▅▆▆▇▇▇▇

  2026-05-17 00:00   8/10  →  low
  2026-05-16 00:00   8/10  →  low
  2026-05-15 00:00   8/10  ↑  low
  2026-05-14 00:00   7/10  →  medium
  2026-05-13 00:00   7/10  ↑  medium
  2026-05-12 00:00   6/10  →  medium
```

The sparkline covers up to 50 entries; the table below it lists 10.

The history file appends one line per audit (timestamp + score + level) and rotates at 1000 entries. A line whose score or timestamp cannot be read is skipped rather than repaired, so a damaged file shortens the table instead of drawing a trend that never happened. No sudo required for `--history` alone.

### `--breakdown` (`-B`) — score computation transparency

Prints the full score computation after the audit summary: every deduction, every cap, and the per-domain raw scores before they were averaged.

```bash
sudo bob --breakdown
sudo bob -B                       # short form
```

Use this when the displayed score doesn't match your intuition and you want to know *which* deductions added up to it. The output is human-readable but quite verbose — typically used once after a configuration change rather than in routine audits.

---

## Report management

To list and delete generated reports:

```bash
sudo bob --manage-logs
```

In an interactive terminal, a full curses TUI opens. A plain text fallback is used when stdout is not a TTY (pipes, scripts).

### TUI mode (interactive terminal)

It opens on a **folder picker**: the current report directory and every earlier one BOB still tracks, each with what it holds. `Enter` browses a folder, `c` changes (or adds) the directory new reports go to, `d` forgets a tracked folder (its files are kept). Inside a folder, the list shows each report with its date, size and score, under a score history chart.

**The shared floor** — since v0.16.3 every curses screen in BOB accepts the
same navigation, and an **orange banner** across the bottom of the screen always
lists exactly what that screen accepts, in the interface language. It mirrors
the cyan header, and wraps onto a second row rather than truncating when the
hints do not fit the terminal — cutting from the right would take the exit hint
first. The line immediately above it is **reserved for prompts and status**: a
delete confirmation or a text field appears there, and the key banner stays
visible underneath instead of being painted over. Since v0.39.0 the banner lists
**exactly** the keys the screen accepts — no key that is not shown does
anything, and a key that acts only in some states (say `u`, once something is
marked) is shown only then; a numbered menu shows its own digits (`1-4 by
number`). Every deletion, overwrite, withdrawal or purge is confirmed one way:
the question, then *Press y to confirm, any other key to cancel*, over a banner
that shows `y` alone. And that line takes
the colour of what it says, as the text output does: a **prompt** or a question
waiting for an answer in **yellow**; an action that took effect in **green**,
`✔`; an action refused or failed — nothing was changed — in **red**, `✖`;
information (an action you cancelled) in **cyan**, `ℹ`. The same in every
wizard: `--manage-logs`, `--manage-cron`, `--install-cron`, `--explain`.

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Move cursor |
| `PgUp` / `PgDn` | Page |
| `g` / `G` | Jump to top / bottom |
| `Enter` | Select |

**Text fields.** Where a screen asks you to type something — a job name, an
e-mail address, a time — the prompt sits on the reserved line and the banner
below it shows `⏎ submit` and `Esc back` — and `Tab complete` where the field
completes a path (a new report directory). All of these prompts are translated;
before v0.16.3 they were English on a French wizard.

**Exits.** `q` quits, and only from a wizard's **first page** — deeper in, `Esc`
steps back one screen and nothing leaves outright, so a single keystroke cannot
abandon a half-entered cron job from three screens down.

**`l` switches the interface language**, on first pages only. It exists because
these wizards run under `sudo` and sudo resets the environment: an operator
whose shell is French can land in an English wizard through no choice of their
own. The hint names the language it switches *to* — `l Français` in English,
`l English` in French — and the whole screen flips live.

**What the report list adds** (it is nested: `Esc` goes back to the folder picker):

| Key | Action |
|-----|--------|
| `Space` | Mark / unmark report for deletion (marked rows read red) |
| `a` | Mark all reports |
| `d` | Delete marked reports (confirmation required) |
| `u` | Unmark all — shown only once something is marked |

### Report preview viewer

Pressing `Enter` on a report opens a scrollable read-only viewer. It is a
nested screen, so `Esc` returns to the list and `q` does not quit:

| Key | Action |
|-----|--------|
| `↑` / `↓` / `j` / `k` / `PgUp` / `PgDn` / `g` / `G` | Scroll (the shared floor) |
| `←` / `→` | Older / newer report, without going back to the list (since v0.32.0) |
| `s` | Toggle between full log and summary view (score + ALERT/WARN findings only) |
| `n` | Show / hide the notes block — offered when the report has notes |
| `a` | Manage the notes (add, edit, withdraw, purge, journal) |
| `c` | Show / hide the comparison with the previous report |
| `h` | Show / hide the history of this host's reports |
| `#` | Number the report's lines (full log only) |
| `Esc` | Return to report list |

**Blocks above the report** (since v0.39.0). The notes, the comparison and the
history are blocks of their own, shown above the report and never part of it,
in that order. When the viewer opens, the notes are open (if the report has
any), the comparison and the history closed, the line numbers off. A block you
open or close stays so while `←` / `→` move to another report, and shows that
report's content (or says there is none); it changes only when you press its
key again. Leaving the viewer and opening it again starts over.

**Line numbers** (`#`) number the report's own lines, never the blocks, so a
number always names a line of the file. They are offered on the full log only:
the summary's lines are not consecutive.

#### Notes on a report

Notes record what was done after an audit — *"UFW re-enabled after the
audit"* — beside the report, never inside it: the report is evidence and is
never rewritten. `a` opens their actions; every prompt and confirmation is on
the context line, and `Esc` returns to the viewer:

| Key | Action |
|-----|--------|
| `a` | Add a note — you type the text; the date and time are added |
| `e` | Edit a note — it is marked *edited*, with when and by whom; its earlier text stays in the journal |
| `r` | Withdraw notes — one, several (`1,3`, `2-5`) or `all`; they leave the block; their text stays in the journal |
| `p` | Purge notes — one, several or `all`; their text is removed from every version, a reason is required; who, when and why are kept |
| `v` | Show / hide the journal: every action on the notes, oldest first |

The notes an action is for are read first — before a reason or a
confirmation is asked — by the rule every list of numbers follows
(CONVENTIONS.md): a range takes the notes there are between its bounds (`2-4`
over notes 1, 2 and 4 takes 2 and 4); a number given alone must be a note, and
one that is not refuses the selection and is named. Several notes are withdrawn
or purged in one write, all of them or none. Every withdrawal and purge is confirmed on
the context line: the question, then *Press y to confirm, any other key to
cancel.* (the wording every confirmation uses, CONVENTIONS.md).

**Edit or purge.** Editing corrects a note and keeps every version, so that on
a server several operators share nobody rewrites a note without a trace. A
secret pasted by mistake is **purged**: its text leaves every line of the
journal, its earlier versions included, and only *"purged on … by … (reason)"*
remains.

**Who did it.** Every action records its author and its time. On a shared
server everyone runs `sudo bob`, so "root" would say nothing: BOB records the
account the kernel's login uid names — on the test host it survived `sudo`,
`sudo -i`, `sudo su -` and `sudo env -i` (measured) — and the
`SUDO_USER`/`DOAS_USER` claim beside it, shown as `alice (sudo: bob)` when the
two differ. The login uid is the session's identity as the kernel keeps it,
not a proof of who sits at the keyboard. With no login uid — measured for a
systemd service — the claim names the author, else the effective account.
Times are stored with their offset from UTC and shown in the reader's local
time.

**Who can write it.** Notes are written by BOB run as root
(`sudo bob --manage-logs`): the journal belongs to root, mode `0640`, in the
report's group, so the report's owner can read it and only root can change
its content. Owned by the report's owner, as first designed, that account
rewrote it without root and BOB read it back as intact (measured on the test
host). Whoever owns the report's directory can still delete the file or put
another in its place: a notes file not owned by root is said not to be BOB's,
and BOB writes nothing more to it; a link in its place is not followed.

**What the journal can and cannot show.** It is tamper-evident, not
tamper-proof. Each line carries the digest of the one before it, computed over
the line without the note's text and salt — so over the text's salted digest,
which checks the text while it is there. A text changed (its salted digest no
longer matches) or an author changed, a line removed from the middle or
reordered outside BOB, or a journal copied beside another report, shows: the
block says *"journal changed outside BOB at line N"*, and BOB writes nothing
more to it. The digests are no signature: whoever can write the file — root —
can recompute the whole chain and leave no trace in it. Lines removed from the
**end**, or the file deleted by whoever owns the report's directory, leave no
trace in the file itself. On the test host (a Linux Mint 22.3 whose audit
setting does not make the login uid immutable) root could rewrite its own
login uid: nothing in a file root can write stops root from lying about who it
is. A purge removes the text and its salt from the journal — the digest left
behind can no longer be tested against candidate texts; copies made outside
BOB — backups, filesystem snapshots — keep what they hold.

#### Comparison and history

**`c` — comparison** with the previous report **of the same host** in the
folder (a shared folder can hold several hosts), said exactly as `--diff`
says it: score, findings that appeared or were resolved, ports, services.
**`h` — history** of that host's reports in the folder, up to the one shown,
drawn as `--history` draws it. Both come from a small state file BOB writes
beside each `-d` report since v0.39.0; a report written before has none, and
the block says so — no comparison is guessed from the report's text.
The history shows each audit's end in UTC, as `--history` does; a report's
name carries its start, in local time.

#### Files beside each report

Three files, two levels of trust:

| File | Owner, mode | Who can change it |
|------|-------------|-------------------|
| `bob_<date>.log` — the report | the report's owner, `0600` | its owner |
| `bob_<date>.log.state` — its state, for the comparison and the history | the report's owner, `0600` | its owner — so the comparison and history drawn from it are only as trustworthy as the report |
| `bob_<date>.log.note` — its notes | root, `0640`, the report's group | root's content; the directory's owner can delete or replace the file, and BOB says so |

The two companion files are never listed — every list shows `bob_*.log` only —
and are moved and deleted with their report.

### Plain text fallback (non-TTY)

Used automatically when stdout is not a terminal:

| Input | Action |
|-------|--------|
| `1`, `3`, `1,3`, `2-5` | Delete report(s) by number (confirmation required, `[y/N]`, since v0.39.0; a number with no report is refused and named, a range takes the reports there are) |
| `all` | Delete all visible reports (confirmation required) |
| `c` | Change storage location |
| Enter / `q` | Quit |

### Changing the storage location

Press `c` to enter a new path. If reports exist in the current directory, you will be prompted:

```
Move 28 report(s) to the new location? [y/N]
```

- **y** — all visible reports are moved to the new path, each with its notes and its state, through checked descriptors of both directories (since v0.26.1, a directory under your home that resolves outside it is refused)
- **n / Enter** — reports stay in the old directory; the old path is remembered

### Multi-directory view

In the plain fallback, if you previously changed the storage location without moving the reports, all known directories are displayed together in a single unified list (the curses screen shows them as folders in its picker instead):

```
  Reports in: /var/log/bob-audits  [current]

  ℹ No reports found

  ─── Previous location: /home/user/.local/share/bob/logs ───

  [ 1]  bob_20260416_053234.log  (20 KB)  2026-04-16 05:32
  ...
  [28]  bob_20260413_124813.log  (19 KB)  2026-04-13 12:48
```

All entries share a continuous index — you can delete, select, or use `all` regardless of which directory the file is in. Old directories that become empty are automatically removed from the list.

---

## Postfix configuration for HTML emails

Cron reports are sent as HTML (MIME multipart/alternative) rather than plain text. Postfix must be installed and configured to relay these emails through an external SMTP server.

### Step 1 — Install Postfix and mailutils

```bash
sudo apt install postfix mailutils
```

During installation, an interactive wizard appears:
- **General type of mail configuration** → choose **"Internet Site"**
- **System mail name** → your hostname or domain (e.g. `myserver.com`)

### Step 2 — Configure an SMTP relay

A desktop or home server usually cannot send mail directly to the internet: many ISPs block outbound port 25. Relay through an external SMTP provider.

**Example with Mailo:**

```bash
sudo postconf -e "relayhost = [smtp.mailo.com]:587"
sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_security_options = noanonymous"
sudo postconf -e "smtp_tls_security_level = encrypt"
sudo postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
sudo postconf -e "inet_interfaces = loopback-only"
```

> `inet_interfaces = loopback-only` prevents Postfix from listening on external network interfaces — recommended for desktops and workstations.

**Example with Gmail** (requires an [App Password](https://myaccount.google.com/apppasswords) — 2FA must be enabled):

```bash
sudo postconf -e "relayhost = [smtp.gmail.com]:587"
sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_security_options = noanonymous"
sudo postconf -e "smtp_tls_security_level = encrypt"
sudo postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
sudo postconf -e "inet_interfaces = loopback-only"
```

### Step 3 — Save SMTP credentials

Use a text editor to avoid issues with special characters in passwords:

```bash
sudo nano /etc/postfix/sasl_passwd
```

Add one line in this format:
```
[smtp.mailo.com]:587 you@mailo.com:YOUR_PASSWORD
```

Then secure and compile the file:

```bash
sudo chmod 600 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd
```

### Step 4 — Rewrite the sender address

Postfix sends mail using the local system address (e.g. `root@hostname.lan`), which is rejected by external SMTP servers. Rewrite it to your real address:

```bash
sudo bash -c 'cat > /etc/postfix/sender_canonical << EOF
/^.*@/ you@mailo.com
EOF'

sudo postmap /etc/postfix/sender_canonical
sudo postconf -e "sender_canonical_maps = regexp:/etc/postfix/sender_canonical"
```

### Step 5 — Apply and test

```bash
sudo systemctl restart postfix

echo "Test BOB" | mail -s "Test Postfix" you@mailo.com
sudo tail -10 /var/log/mail.log
```

Expected output in the log:
```
status=sent (250 Message to be delivered)
```

### Common issues

#### Error: "553 bad address format"

The sender rewriting in Step 4 was not applied. Check that `sender_canonical_maps` is active:

```bash
sudo postconf sender_canonical_maps
# Expected: sender_canonical_maps = regexp:/etc/postfix/sender_canonical
```

#### Error: "530 Authentication required" or "535 Authentication failed"

The credentials in `/etc/postfix/sasl_passwd` are incorrect or the file was not compiled. Re-edit the file with `sudo nano`, then rerun:

```bash
sudo postmap /etc/postfix/sasl_passwd
sudo systemctl restart postfix
```

For Gmail, make sure you are using an **App Password**, not your regular Google account password.

### Technical notes

- The generated script exports `PYTHONPATH` only when the `bob` package cannot be imported without it (an install outside pip; since v0.16.2)
- SMTP envelope uses `sendmail -t -f` for sender address control
- No external dependencies (HTML generated in pure Python)

---

© 2026 Cédric Clauzel
