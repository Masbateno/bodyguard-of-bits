*[Lire en français](AUTOMATION_FR.md)*

# Automation — BOB

This document explains how to configure BOB to run automatically on a schedule and notify you of any issues.

---

## Quick setup

```bash
sudo bob --install-cron
```

The wizard guides you through 4 steps:

1. **Name** — a short label for this cron job (e.g. `nightly`, `weekly`). Press Enter to use the suggested name.
2. **Schedule** — choose from:
   - Every day
   - Certain days of the week (e.g. `1 3 5` for Mon/Wed/Fri)
   - Certain days of the month (e.g. `1 15` for the 1st and 15th)
   - Custom cron expression (e.g. `0 3 * * 1`)
3. **Time** — execution time in `HH:MM` format (default: `03:00`). Not shown for custom expressions.
4. **Email** — optional notification address. Leave empty to disable.

A plain-language preview is shown before confirmation:
```
  → Schedule: every Monday, Wednesday, Friday at 02:30
```

### Files created

- `/usr/local/bin/bob-{name}` — wrapper script
- `/etc/cron.d/bob-{name}` — system cron entry

---

## Managing cron jobs

```bash
sudo bob --manage-cron
```

Lists all installed cron jobs with their schedule and notification email. The menu loops until you explicitly quit:

```
  1. nightly              every day at 03:00
     → email: you@example.com
  2. weekly-monday        every Monday at 02:00

  Number to edit, 'e:N' to edit email, 'd:N' / 'd:1,3' / 'd:1-3' / 'd:all' to delete, 'm' for email book, Enter to quit
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

Enter `d:N` to delete a single job, or use a comma list, range, or `all` for bulk deletion:

```
  1. nightly              every day at 03:00
  2. weekly               every Monday at 02:00

  Number to edit, 'e:N' to edit email, 'd:N' / 'd:1,3' / 'd:1-3' / 'd:all' to delete, 'm' for email book, Enter to quit
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

  Number to delete, '1,3' or '1-3' for a selection, 'all' to delete all, 'a' to add, Enter to quit
  >
```

| Command | Action |
|---------|--------|
| `a` | Add a new validated email address |
| `N` | Delete address N |
| `1,3` | Delete addresses 1 and 3 |
| `1-3` | Delete addresses 1, 2 and 3 |
| `all` | Delete all saved addresses |
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

Notifications use the `mail` command (from `mailutils` package):

```bash
sudo apt install mailutils
```

Email is sent **only if the audit detects alerts or warnings** (exit code > 0). If your configuration is healthy, you receive nothing.

---

## Cron file format

Each cron file includes metadata comments for identification. Multiple emails are stored comma-separated:

```
# BOB cron — generated 2026-03-24 by bob --install-cron
# name: nightly
# email: admin@example.com,security@example.com
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 3 * * *  root  /usr/local/bin/bob-nightly
```

---

## Report management

To list and delete generated reports:

```bash
sudo bob --manage-logs
```

In an interactive terminal, a full curses TUI opens. A plain text fallback is used when stdout is not a TTY (pipes, scripts).

### TUI mode (interactive terminal)

The cursor-based interface shows all reports with their date, size and score. A score history chart is displayed at the top.

**Navigation and actions:**

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move cursor |
| `Enter` | Preview the selected report (scrollable viewer) |
| `Space` | Mark / unmark report for deletion |
| `a` | Mark all reports |
| `d` | Delete marked reports (confirmation required) |
| `u` | Unmark all |
| `c` | Change storage location |
| `q` | Quit |

### Report preview viewer

Pressing `Enter` on a report opens a scrollable read-only viewer:

| Key | Action |
|-----|--------|
| `↑` / `↓` / `PgUp` / `PgDn` | Scroll |
| `g` | Go to top |
| `G` | Go to bottom |
| `s` | Toggle between full log and summary view (score + ALERT/WARN findings only) |
| `Esc` | Return to report list |

### Plain text fallback (non-TTY)

Used automatically when stdout is not a terminal:

| Input | Action |
|-------|--------|
| `1`, `3`, `1,3`, `2-5` | Delete report(s) by number |
| `all` | Delete all visible reports (confirmation required) |
| `c` | Change storage location |
| Enter / `q` | Quit |

### Changing the storage location

Press `c` to enter a new path. If reports exist in the current directory, you will be prompted:

```
Move 28 report(s) to the new location? [y/N]
```

- **y** — all visible reports are moved to the new path via `shutil.move`
- **n / Enter** — reports stay in the old directory; the old path is remembered

### Multi-directory view

If you previously changed the storage location without moving the reports, all known directories are displayed together in a single unified list:

```
  Reports in: /home/user/ufwauditlogs  [current]

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

Postfix cannot send mail directly to the internet from a desktop or home server (ISPs block port 25). You need to relay through an external SMTP provider.

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

- The generated script automatically exports `PYTHONPATH` for Python imports
- SMTP envelope uses `sendmail -t -f` for sender address control
- No external dependencies (HTML generated in pure Python)
