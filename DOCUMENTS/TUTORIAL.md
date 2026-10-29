*[Lire en français](TUTORIAL_FR.md)*

# Tutorial — getting started with BOB

This tutorial walks you through your first BOB audit, from installation to understanding the output, applying fixes, and setting up recurring audits. It's the **end-to-end first-time-user path** — for command reference see [`README_TECH.md`](README_TECH.md); for automation specifics see [`AUTOMATION.md`](AUTOMATION.md).

---

## What BOB does (in one sentence)

BOB reads your system's hardening configuration (SSH, firewall, services, kernel parameters, …) and prints a score with prioritised findings plus fix suggestions.

What BOB **is not** : it is not a threat-modelling engine, not an active vulnerability scanner, not an autonomous verdict system. The score is conditioned by the profile you pick and the network context BOB detects — interpret it that way. See the *What BOB is* section of [`../SECURITY.md`](../SECURITY.md) for the full framing.

---

## Step 1 — install

The recommended install path is `pipx` (isolates BOB in its own venv, no impact on your system Python):

```bash
sudo apt install pipx                       # Debian/Ubuntu/Mint
pipx install bodyguard-of-bits
pipx ensurepath                             # adds ~/.local/bin to PATH if needed
exec bash                                   # reload shell
```

For Fedora : `sudo dnf install pipx`. For Arch : `sudo pacman -S python-pipx`. Elsewhere, look `pipx` up in your distribution's repositories: its package name and the repository that carries it vary.

Verify :

```bash
bob --version                               # prints "bob X.Y.Z" (bare SemVer, no "v")
```

### Make `sudo bob` work

By default `sudo` uses a restricted `PATH` that does not include `~/.local/bin`. Two options :

**Option A — install completion (also fixes `sudo bob`)**

```bash
sudo /home/$USER/.local/bin/bob --install-completion
exec bash
```

The completion installer also creates a symlink in `/usr/local/bin/bob`, which is on the default `sudo` `PATH`. After this, `sudo bob` works directly and tab-completion is enabled for `--check=<TAB>`, `--explain <TAB>`, `--profile=<TAB>`, etc.

**Option B — call with full path** (no install)

```bash
sudo /home/$USER/.local/bin/bob
```

**On a host that uses `doas` instead of `sudo`** (Alpine, for example), use `doas` wherever this tutorial writes `sudo`, with BOB's full path until Option A has created the link (`doas /home/$USER/.local/bin/bob --install-completion`). BOB finds your home through sudo's `SUDO_USER` and, since 0.25.1, doas's `DOAS_USER`, so your settings, ignore list, baseline and history stay in your own `~/.config/bob`. (Before 0.25.1 they went to `/root/.config/bob` under doas, and no link was created; measured on Alpine 3.24.) One more Alpine difference: BusyBox crond reads `/etc/crontabs/` and there is no `/etc/cron.d`, so `--install-cron` (Step 7) writes the job as a marked block of root's crontab, `/etc/crontabs/root`, and leaves the rest of that file alone (since 0.26.0; 0.25.1 refused).

---

## Step 2 — your first audit

```bash
sudo bob
```

An audit takes from a few seconds to a few minutes: the time depends on the disk, the CPU and how many services are installed. The summary box prints the duration of the run, so you need not guess. You will see :

1. **A header per domain** (`FIREWALL & NETWORK`, `EXPOSURE & SERVICES`, `ACCESS CONTROL`, …), a box per section beneath it, and one line per finding marked `✔ [OK]`, `ℹ [INFO]`, `⚠ [WARNING]` or `✖ [ALERT]`
2. **A summary box** at the end: the score out of 10 (written `≤ N/10` when a section could not be read in full — the score is then a ceiling), the risk level (`LOW`, `MEDIUM`, `HIGH` or `CRITICAL`), the network context BOB detected, the audit profile and the duration; then the findings to handle first (*Action required*), the *Possible improvements* and the score breakdown
3. **Below the box**, a reminder that the verdict depends on the profile and network context shown above it, the score of each domain, and an attack-surface summary

BOB reads UFW, firewalld, and a raw nftables or iptables ruleset. When none of them filters inbound traffic, it raises *"No active firewall"* and suggests the front-end of your distribution family — `ufw` on Debian, Ubuntu, Arch and Alpine, `firewalld` on Fedora, RHEL and openSUSE — with commands that allow SSH before the firewall starts filtering. On Alpine with awall installed, BOB names awall instead: it says which policies are enabled, or that none is, and prints no command, since choosing a policy is yours (0.26.0).

### Read the score

Each domain starts at 10/10 and loses the points of its findings; the headline score is the average of the domains that have a finding other than INFO, rounded, and held at 9 as soon as anything was deducted (10/10 is kept for an audit with nothing to fix). Two findings also cap their domain outright: an installed but inactive UFW, and no active firewall at all, hold *Firewall & Network* at 3/10 (the second since 0.26.0). Each finding has :

- A **level** : OK (✔, green) / INFO (ℹ, cyan — reported, costs no points) / WARNING (⚠, yellow) / ALERT (✖, red)
- A **key** (e.g. `ssh.password_auth`) — stable identifier for scripting, `--explain` and `--ignore`; the summary box prints it on the `? bob --explain KEY` line
- A short message and, in the summary box, the command BOB suggests — after `→` for a fix, after `ℹ` for a command that only checks something

The verdict depends on your profile: `server` by default, or `desktop` when no profile is set and BOB finds an active display manager — it says so in an INFO line before the audit starts. The desktop profile downgrades to INFO findings that weigh less on a personal machine, such as a missing backup or auditd rules. See Step 5 for profiles.

---

## Step 3 — understand any finding

If a finding does not make sense, ask BOB to explain it :

```bash
bob --explain ssh.password_auth
```

No `sudo` needed — `--explain` is a standalone, profile-aware lookup. The output shows :

- **Why it is a risk** — the concrete impact
- **How to fix** — commands (when known) or manual steps
- **One line per profile** — whether it counts the finding in full or downgrades it to INFO (keys with profile-specific prose get a section per profile instead)
- **Scoring** — the domain the finding counts in, the cap for the three tool families (rootkit, ClamAV, file integrity: at most 1 point in all for each), and a pointer to `sudo bob --breakdown` for its current contribution

You can list every explainable key :

```bash
bob --explain list                          # 235 keys at v0.28.x, grouped by CIS family
bob --explain                               # interactive picker (↑↓/jk, PgUp/PgDn, g/G, Enter, Esc back; l language and q quit on the first screen)
```

Tab-completion on `bob --explain <TAB>` suggests canonical keys.

---

## Step 4 — apply fixes safely

BOB can preview and apply fixes for findings that come with a fix command. Always preview first :

```bash
sudo bob --fix                              # dry-run — shows what would be applied
```

The preview lists each fix BOB can apply — the finding, then the command after `→` — and, apart, the commands it only shows (checks you run yourself) and the findings that need a manual fix. The dry-run never modifies your system.

When you are ready :

```bash
sudo bob --fix --apply                      # interactive confirmation per fix
sudo bob --fix --apply -y                   # no prompts — lists the commands it applied at the end
```

Re-run `sudo bob` to see what changed. The score usually rises, but not
always: installing a package can *reveal* a finding that was hidden behind
its absence. With no firewall at all, BOB raises "No active firewall" — an
ALERT that costs no points; once `sudo apt install -y ufw` has run, the
finding becomes "UFW firewall is disabled", which holds the *Firewall &
Network* domain at 3/10. Both put the risk level at `HIGH` or above. The drop comes
from that cap, not from a fix that failed: enabling UFW is the next step.

---

## Step 5 — pick the right profile

BOB ships 4 profiles :

| Profile | When to use | What changes |
|---|---|---|
| `server` (default) | servers, and any host you want judged at full weight | every finding at its full severity |
| `desktop` | personal laptop or desktop — chosen automatically when no profile is set and a display manager is active | 35 findings downgraded to INFO, among them a missing backup, auditd, AppArmor without an enforcing profile, Secure Boot, automatic updates, the freshness of rootkit / ClamAV / file-integrity scans, and SSH password authentication and forwarding; the firewall state and SSH root login keep their full severity |
| `workstation` | shared or business workstation | the same 30 downgrades as `desktop`, without the five on backup, auditd and AppArmor enforcement, which keep their full severity |
| `container` | an audit inside a container | extends `desktop` and skips 17 host-level sections: sysctl hardening, kernel modules, kernel hardening, Secure Boot, Raspberry Pi, auditd, SUID audit, Docker hardening, rootkit, file integrity, disk, memory, fail2ban, ClamAV, NTP, MAC policy and backup |

Pick once per host :

```bash
sudo bob -p desktop                         # also SAVES desktop as your default
sudo bob -p desktop -d                      # same, and save the full report to a log file
sudo bob                                    # later runs reuse the saved profile
```

**BOB remembers your choice.** A valid `-p NAME` is written to
`~/.config/bob/config.conf` as `audit_profile=` and becomes the default for
every later `sudo bob` — you do not need to repeat the flag. A cron job does
not read it: the job runs as root, so the wizard asks for its profile and
writes it into the job's script (Step 7), pre-selecting the `-p` you pass to
`--install-cron`, else your saved profile, else `server`. Change the saved profile by passing `-p`
again; check the current one on the `Audit profile:` line at the top of a
normal audit, or with `sudo bob --format=json | jq -r .profile`.

An invalid name is *not* saved: BOB warns and runs that audit with `server`,
leaving your saved profile untouched.

---

## Step 6 — silence noisy findings

If a finding does not apply to your environment, suppress it instead of ignoring the warning :

```bash
bob --ignore ssh.x11.forwarding.server      # add to ~/.config/bob/ignore.yml
bob --unignore ssh.x11.forwarding.server    # remove
sudo bob --show-ignored                     # see muted findings in grey alongside normal output
```

An ignored finding deducts zero points **and disappears from the output** —
that is the point of the flag. Pass `--show-ignored` to list the muted ones in
grey alongside the normal output. This is preferred over `--skip=`, which
removes the entire section's audit rather than one finding.

(Before v0.14.1 the score and the JSON counts honoured `--ignore` but the
finding kept printing in full; if you remember it that way, it is fixed.)

---

## Step 7 — automate recurring audits

```bash
sudo bob --install-cron
```

The wizard walks you through name → schedule → time → optional email → profile → language → outbound probes. Files created :

- `/usr/local/bin/bob-{name}` — wrapper script that calls BOB with the profile, language and network stance you chose. Those three are asked because a cron runs as root: before v0.16.1 the script read *root's* saved config, not yours, so a `desktop` operator's nightly audit silently graded as `server` — and since the profile drives the exit code, it also decided whether the email was sent
- `/etc/cron.d/bob-{name}` — system cron entry (BusyBox crond: a block of `/etc/crontabs/root`)

The script calls the `bob` you are running when you install the job — `/usr/local/bin/bob` once Option A of Step 1 is done, `~/.local/bin/bob` under Option B — since that version writes the script's options. Started another way (`python3 -m bob`), it calls the `bob` root's `PATH` finds; with none, it writes `/usr/local/bin/bob` and the wizard warns that the path does not exist.

### Make sure the notification can actually arrive

After the last question, the wizard tells you who will hear from this job.
Read it: three of its five answers are *nobody*.

The generated script notifies **by email and by nothing else**, and only when
the audit exits non-zero — a warning, an alert, an error or a missed target; a
clean audit sends nothing. If you skip the address, the audit still runs and
still writes its report to your log directory — but nothing comes to you, and
until v0.17.0 nothing said so. A webhook saved in **root's** config is the
other way out, and a scheduled audit does fire it, but `--offline` suppresses
the POST.

If you did give an address, the wizard tells you whether a `sendmail` binary
exists. That is all it can tell you, and it is not enough: a Postfix installed
from the distribution and never configured satisfies the check and still
delivers nothing. Establish the rest by sending one:

```bash
bob --test-email                            # a real message to your first saved address, through the cron transport
```

It uses the same code path as the scheduled job, so a success here means the
job's mail would take the same route. It exits non-zero when `sendmail` refuses
the message — the failure that is otherwise invisible, because the way you find
out is the mail that never comes.

*Accepted is not delivered.* Exit 0 means the MTA took the message; a relay or
a spam filter can still drop it. Check the inbox once. After that, remember
that a clean audit sends no mail at all: silence means a clean host or a broken
route, and `bob --test-email` tells them apart.

**No MTA on the host?** Two honest options:

| | |
|---|---|
| `postfix` | A full mail server. Choose *"Internet Site"* if the host can send directly, or *"Satellite system"* and name your provider's relay if port 25 is blocked outbound, as many home connections and cloud providers do. |
| `msmtp` + `msmtp-mta` | Relays through an existing mail account (a `~/.msmtprc` with your SMTP host, user and an app password). Much smaller than Postfix, and the right answer for a laptop or a small VPS that only ever sends. |

Package names vary by distribution, and so does the relay configuration — the
Postfix walkthrough in [`AUTOMATION.md`](AUTOMATION.md) is the long version,
including the part most people actually need, which is relaying through a
provider because port 25 is blocked outbound.

Or skip mail entirely and use a webhook, which needs none of this. A scheduled audit runs as root, so it reads the webhook saved in **root's** configuration (`/root/.config/bob/config.conf`) — while `sudo bob --webhook=URL` saves the URL in *yours*, since under `sudo` BOB writes to the invoking user's configuration. To give a job a webhook, append `--webhook URL` to the `bob` line of its script, as [`AUTOMATION.md`](AUTOMATION.md) shows.

For your own runs, save a webhook and test it :

```bash
sudo bob --webhook=https://hooks.slack.com/services/T00/B00/XXXX   # audits, POSTs the result, saves the URL
bob --test-webhook                          # POST a smoke-test payload (no audit) and exit
```

`--test-webhook` checks that the saved URL and its receiver answer, without running an audit. The smoke payload is tagged `bob_smoke_test` so your receiver can filter it.

See [`AUTOMATION.md`](AUTOMATION.md) for the full cron + webhook setup.

---

## Step 8 — track changes over time

Every audit saves its state as the baseline for the next one (`~/.config/bob/last_baseline.json`) and appends its score to `~/.config/bob/history.jsonl` :

```bash
sudo bob --diff                             # only show what changed since the last audit
sudo bob --history                          # sparkline of the last 50 scores, table of the last 10
sudo bob --reset-baseline                   # delete the baseline (the score history is kept)
```

`--watch` re-runs a silent audit every N seconds and prints, each time, a score line and what changed since the previous run :

```bash
sudo bob --watch                            # every 60 s
sudo bob --watch=30                         # every 30 s (10 s minimum)
```

`Ctrl+C` exits.

---

## Step 9 — output formats for machine consumers

BOB can emit JSON / CSV / Markdown / HTML for pipelines :

```bash
sudo bob --format=json | jq '.score'        # score as JSON
sudo bob --format=csv  > audit.csv          # spreadsheet-friendly
sudo bob --format=markdown > /tmp/audit.md  # human-readable .md (stdout)
sudo bob --format=html     > /tmp/audit.html # HTML report (stdout)
```

The CSV carries one row per finding, and since v0.18.0 its last column is
`key` — the same identifier `--explain` and `--ignore` take, and the one a
baseline is keyed on. Use it rather than `message`, which is translated
prose and changes with the locale and with rewordings:

```bash
sudo bob --format=csv | awk -F, 'NR>1 && $10=="alert" {print $NF}'
```

That `awk` holds because `level` sits before every free-text column and a
finding key never contains a comma — for anything touching `message` or
`detail`, use a real CSV reader. The fifteen columns that preceded `key`
keep their positions, so a consumer written against v0.17.1 is unaffected.


`-J` and `-j` are shorthands for `--format=json-full` / `--format=json`. Combine with `--min-level=warn` to filter.

Two JSON fields are worth knowing if you pipe this anywhere (both since v0.14.1):

```bash
sudo bob --format=json | jq -r .profile              # which profile produced these numbers
sudo bob --format=json | jq -r '.degraded_sections'  # [] on a healthy run
```

`degraded_sections` lists any section whose check failed and was skipped rather
than aborting the whole audit; `unverified` lists the keys of the findings
that say a check could not read all its input, which makes the score a ceiling
(`score_is_upper_bound`, `score_low` / `score_high`). Without `--target` the
exit code stays driven by the findings alone, so these fields are where a
pipeline sees that the audit was **incomplete**.

---

## Common scenarios

### "I just want a score with no noise"

```bash
sudo bob -q                                 # silent — exit code tells you the verdict
echo $?                                     # 0=OK / 1=WARN / 2=ALERT / 3=error / 4=--target missed or unverifiable
```

Wire `-q` into a cron job + exit-code check for the simplest possible alerting.

### "I want to lock in a minimum score"

```bash
sudo bob --target=8                         # show gap or success in summary
# exit code 4 if the score is below 8, or only a ceiling (a section could not be read in full)
```

Useful in CI to fail a build if a system drops below your bar.

### "I want a French audit"

```bash
sudo bob --french                           # shortcut for --lang=fr
sudo bob --lang=fr                          # explicit
```

All output (terminal, `--help`, .log, JSON detail messages, webhook payloads, explain entries) is localised — 3090 keys × 2 locales — except three things, described below. `--help` joined the list in v0.15.3: it had returned English under `--french` since v0.1.0.

Three things stay English on purpose, and a bilingual diff of the audit output in v0.15.4 confirmed they are the only ones: **shell commands** in remediation lines (a command is not prose), **CIS benchmark references** that carry a numbered code (v0.11.2 decision — the uncoded "Best practice" ones *are* translated), and the **38 service labels**, such as `Samba (Windows file sharing)` or `Apache Web Server`, treated as product names even when they carry English words. The labels also key the `service_risk.*` entries and go into the audit baseline, so translating them at the source would rename 114 locale entries and make `--diff` report phantom changes on a locale switch.

---

## What to read next

- [`README_TECH.md`](README_TECH.md) — complete command reference with every flag + exit codes
- [`AUTOMATION.md`](AUTOMATION.md) — cron + webhook + email notification deep-dive
- [`../SECURITY.md`](../SECURITY.md) — threat model, what BOB is / is NOT, trap-door env vars
- [`../CHANGELOG.md`](../CHANGELOG.md) — release history with per-version highlights
- `bob --explain list` — every finding BOB knows how to explain, grouped by CIS benchmark family (CIS Ubuntu, CIS Docker, Best practice, …); browsable in the curses picker

If you hit a bug or want a finding added, open an issue at [https://github.com/Masbateno/bodyguard-of-bits](https://github.com/Masbateno/bodyguard-of-bits).

---

© 2026 Cédric Clauzel
