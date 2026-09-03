*[Lire en français](TUTORIAL_FR.md)*

# Tutorial — getting started with BOB

This tutorial walks you through your first BOB audit, from installation to understanding the output, applying fixes, and setting up recurring audits. It's the **end-to-end first-time-user path** — for command reference see [`README_TECH.md`](README_TECH.md); for automation specifics see [`AUTOMATION.md`](AUTOMATION.md).

---

## What BOB does (in one sentence)

BOB reads your system's hardening configuration (SSH, firewall, services, kernel parameters, …) and prints a score with prioritised findings plus fix suggestions.

What BOB **is not** : it is not a threat-modelling engine, not an active vulnerability scanner, not an autonomous verdict system. The score is conditioned by the profile you pick and the network context BOB detects — interpret it that way. See `## What BOB is / is NOT` in [`../SECURITY.md`](../SECURITY.md) for the full framing.

---

## Step 1 — install

The recommended install path is `pipx` (isolates BOB in its own venv, no impact on your system Python):

```bash
sudo apt install pipx                       # Debian/Ubuntu/Mint
pipx install bodyguard-of-bits
pipx ensurepath                             # adds ~/.local/bin to PATH if needed
exec bash                                   # reload shell
```

For Fedora/RHEL : `sudo dnf install pipx`. For Arch : `sudo pacman -S python-pipx`.

Verify :

```bash
bob --version                               # prints "BOB v0.13.x"
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

---

## Step 2 — your first audit

```bash
sudo bob
```

BOB runs ~30 seconds (longer the first time, faster after). You will see :

1. **Section headers** as each domain is checked (`SSH`, `Firewall`, `Services`, …) with `✔` / `⚠` / `✖` per finding
2. **A summary box** at the end with the score (`/10`), the verdict (`hardening`, `acceptable`, `at risk`, `warning`, `critical`), the profile used, and the network context BOB detected
3. **A first-line "Hypotheses" footer** that makes explicit which profile + context produced this score

If `sudo bob` complains the firewall is not detectable, install `ufw` (BOB targets the Ubuntu/Debian default firewall ; firewalld is not a substitute). On Fedora/Arch you can install ufw alongside firewalld.

### Read the score

The score starts at 10/10 and deducts based on findings. Each finding has :

- A **level** : OK (✔, green) / WARN (⚠, yellow) / ALERT (✖, red)
- A **key** (e.g. `ssh.password_auth_enabled`) — stable identifier for scripting + `--explain` lookups
- A short message + optionally a `cmd=` hint if BOB knows how to fix it

The verdict is conditioned by your profile (`server` by default) — desktop profiles deduct less aggressively on certain server-only concerns (backup, auditd, MAC policy). See Step 5 for profiles.

---

## Step 3 — understand any finding

If a finding does not make sense, ask BOB to explain it :

```bash
bob --explain ssh.password_auth_enabled
```

No `sudo` needed — `--explain` is a standalone, profile-aware lookup. The output shows :

- **Why it is a risk** — concrete impact + threat model assumptions
- **How to fix** — exact commands (when known) or manual steps
- **Scoring** — domain + tool cap (the worst your score can deduct from this finding)

You can list every explainable key :

```bash
bob --explain list                          # 187 keys at v0.15.x
bob --explain                               # interactive picker (↑↓ navigate, Enter view, q quit)
```

Tab-completion on `bob --explain <TAB>` suggests canonical keys.

---

## Step 4 — apply fixes safely

BOB can preview and apply fixes for findings that carry a `cmd=` template. Always preview first :

```bash
sudo bob --fix                              # dry-run — shows what would be applied
```

Each row is either ✓ (will be applied) or ✗ (manual — BOB declines to auto-fix). The dry-run never modifies your system.

When you are ready :

```bash
sudo bob --fix --apply                      # interactive confirmation per fix
sudo bob --fix --apply -y                   # batch mode (audit trail saved to ~/.config/bob/fix-audit.log)
```

Re-run `sudo bob` to confirm the score went up.

---

## Step 5 — pick the right profile

BOB ships 4 profiles :

| Profile | When to use | Deducts on |
|---|---|---|
| `server` (default) | production servers, edge nodes | full hardening expectations including backup, auditd, MAC policy |
| `desktop` | personal laptop, workstation | relaxes backup + audit logging requirements ; SSH + firewall still strict |
| `workstation` | shared/multi-user business workstation | strict on backup + auditd + MAC policy ; relaxed on personal-use ergonomics |
| `container` | containerised audit (e.g. Docker base images) | skips kernel-hardening checks irrelevant inside a container |

Pick once per host :

```bash
sudo bob -p desktop                         # also SAVES desktop as your default
sudo bob -p desktop -d                      # same, with a detailed report
sudo bob                                    # later runs reuse the saved profile
```

**BOB remembers your choice.** A valid `-p NAME` is written to
`~/.config/bob/config.conf` as `audit_profile=` and becomes the default for
every later run — you do not need to repeat the flag, in cron or anywhere
else. Change it by passing `-p` again; check the current one with
`bob --format=json | jq -r .profile`, or read the `Audit profile:` line at the
top of a normal audit.

An invalid name is *not* saved: BOB warns and falls back to the default,
leaving your real profile untouched.

---

## Step 6 — silence noisy findings

If a finding does not apply to your environment, suppress it instead of ignoring the warning :

```bash
bob --ignore ssh.x11_forwarding             # add to ~/.config/bob/ignore.yml
bob --unignore ssh.x11_forwarding           # remove
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

The wizard walks you through name → schedule → time → optional email. Files created :

- `/usr/local/bin/bob-{name}` — wrapper script that calls BOB with your saved config
- `/etc/cron.d/bob-{name}` — system cron entry

For incident-response automation, configure a webhook in `~/.config/bob/config.conf` :

```bash
bob --webhook=https://hooks.slack.com/services/T00/B00/XXXX
bob --test-webhook                          # POST a smoke-test payload (no audit) and exit
```

`--test-webhook` verifies the URL + receiver are reachable before the next scheduled audit fires. The smoke payload is tagged `bob_smoke_test` so your receiver can filter it.

See [`AUTOMATION.md`](AUTOMATION.md) for the full cron + webhook setup.

---

## Step 8 — track changes over time

After your first audit, BOB stores a baseline at `~/.config/bob/baseline.json`. Subsequent audits compare against it :

```bash
sudo bob --diff                             # only show what changed since the last audit
sudo bob --history                          # sparkline of the last 10 scores
sudo bob --reset-baseline                   # reset (next audit starts a new history)
```

Combined with `--watch` you get a live-refresh view :

```bash
sudo bob --watch                            # re-run every 60 s
sudo bob --watch=30                         # custom interval
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

`-J` and `-j` are shorthands for `--format=json-full` / `--format=json`. Combine with `--min-level=warn` to filter.

Two JSON fields are worth knowing if you pipe this anywhere (both since v0.14.1):

```bash
sudo bob --format=json | jq -r .profile              # which profile produced these numbers
sudo bob --format=json | jq -r '.degraded_sections'  # [] on a healthy run
```

`degraded_sections` lists any section whose check failed and was skipped rather
than aborting the whole audit. The exit code stays driven by the real findings,
so this is the only place a pipeline can see that the audit was **incomplete**.

---

## Common scenarios

### "I just want a score with no noise"

```bash
sudo bob -q                                 # silent — exit code tells you the verdict
echo $?                                     # 0=OK / 1=WARN / 2=ALERT / 3=error / 4=below --target
```

Wire `-q` into a cron job + exit-code check for the simplest possible alerting.

### "I want to lock in a minimum score"

```bash
sudo bob --target=8                         # show gap or success in summary
# exit code 4 if score < 8
```

Useful in CI to fail a build if a system drops below your bar.

### "I want a French audit"

```bash
sudo bob --french                           # shortcut for --lang=fr
sudo bob --lang=fr                          # explicit
```

All output (terminal, `--help`, .log, JSON detail messages, webhook payloads, explain entries) is localised — 2237 keys × 2 locales as of v0.15.3 — **with one exception you will see on screen: the 27 service labels that carry English prose** (`Samba (Windows file sharing)`, `Apache Web Server`, …) stay English by design, as explained below. `--help` joined the list in v0.15.3: it had returned English under `--french` since v0.1.0.

Three things stay English on purpose, and a bilingual diff of the audit output in v0.15.4 confirmed they are the only ones: **shell commands** in remediation lines (a command is not prose), **CIS benchmark references** that carry a numbered code (v0.11.2 decision — the 60 uncoded ones *are* translated), and the **38 service labels** — 27 of which carry descriptive English prose, such as `Samba (Windows file sharing)` or `Apache Web Server` — treated as product names. The labels also key the `service_risk.*` entries and go into the audit baseline, so translating them at the source would rename 114 locale entries and make `--diff` report phantom changes on a locale switch.

---

## What to read next

- [`README_TECH.md`](README_TECH.md) — complete command reference with every flag + exit codes
- [`AUTOMATION.md`](AUTOMATION.md) — cron + webhook + email notification deep-dive
- [`../SECURITY.md`](../SECURITY.md) — threat model, what BOB is / is NOT, trap-door env vars
- [`../CHANGELOG.md`](../CHANGELOG.md) — release history with per-version highlights
- `bob --explain list` — every finding BOB knows how to explain, browsable in the curses picker

If you hit a bug or want a finding added, open an issue at [https://github.com/Masbateno/bodyguard-of-bits](https://github.com/Masbateno/bodyguard-of-bits).

---

© 2026 Cédric Clauzel
