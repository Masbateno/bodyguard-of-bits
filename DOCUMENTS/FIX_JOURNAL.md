*[Lire en français](FIX_JOURNAL_FR.md)*

# BOB — the journal of `--fix --apply`, and how a falsification shows

`--fix --apply` changes the system. Since 0.40.0 every command it launches
leaves an entry in a journal kept for the host — who launched it, which finding
it answered, the exact command, what came of it — and anyone may add a note to
an entry, never change one.

A journal is only worth the trust you can put in it, so this document says
exactly what that trust rests on, and shows it. The short version:

> **BOB cannot make this journal impossible to falsify.** It lives on the
> machine it describes, and root can rewrite any file there. What BOB does is
> make a falsification **show**, and hand you **the proof**: the line changed,
> and what the system log recorded when that line was written.

Everything below was measured on a real machine (Linux Mint 22.3, systemd 255,
ext4) on 20 November 2026, with two operators; the outputs are BOB's own,
shortened only where a digest runs past the page.

---

## 1. What is recorded

One entry per command `--fix --apply` **launches**, whatever came of it:

| Field | What it holds |
|---|---|
| when | the date and time the command started, and the time it ended |
| who | the account the kernel's **login uid** names — it survives `sudo` — and the `SUDO_USER`/`DOAS_USER` claim beside it, the same measure as the notes on a report. In the raw line, `by={"login":"bobop2","sudo":"bobop2","uid":0}` reads: logged in as `bobop2`, claiming `bobop2` through `sudo`, and BOB itself running with effective uid 0 — the `uid` is the process's, never the operator's |
| finding | the finding the command answered (its key and its message) |
| command | the exact command; for a fix BOB carries out in its own code (sysctl), the action it carried out too |
| outcome | applied · failed · timed out · ran without its effect being confirmed — with the exit code, the duration and the error output (bounded) |
| notes | added afterwards, dated, their author recorded; never edited, never withdrawn |

A command the operator declines, or one BOB refuses to run (shell operators),
is not launched and leaves no entry.

Each entry is written in **two lines**: one before the command starts, one with
its outcome. Two writes, not a promise of two lines: when the second is
missing, the entry reads *no outcome recorded*, for one of two reasons the
journal cannot tell apart — BOB stopped during the command (the firewall fix
that cuts the SSH session BOB runs in, a power cut), or its outcome could not be
written, which BOB said on screen at the time. Either way the command still
shows, and what it did is not claimed.

**No command runs without its entry.** Before the first command, BOB opens the
journal for writing; if it cannot (a link at its name, a journal or a directory
root does not own), it stops there and runs nothing. A command whose first line
cannot be written (a full disk) is not run, and BOB says why.

## 2. Where it lives, who writes it, who reads it

| | |
|---|---|
| File | `/var/log/bob/fixes.journal` — one for the host, whoever ran BOB |
| Owner | `root:adm`, mode `0640`; the directory `root:adm`, `0750` |
| Written by | root only — the only account that runs `--fix --apply`, or adds a note |
| Read by | root, and the members of `adm` (the group that reads the system's logs) |
| Opened | without following a link, under a lock; a journal or directory not owned by root is said not to be BOB's, and nothing is written to it |

Where to read it: `sudo bob --manage-logs`, second choice on the landing screen
(*Journal of fixes*), or `bob --fix-journal` in text.

## 3. How a falsification shows — four measures

None of these is enough alone; each covers what the others cannot.

### 3.1 The chain

Each line carries the digest (SHA-256) of the line before it. A line changed,
removed from the middle, or moved breaks the chain at that line.

*Limit:* the digests are no signature. Whoever rewrites the file can recompute
every digest after the line they changed, and the chain alone then shows
nothing. Lines cut from the end, or the file deleted, leave no trace in the
file itself.

### 3.2 The witness in the system log

Each line, as it is written, is also sent to the system log (`/dev/log`,
journald or syslog) under the name `bob-fix`, with **two digests**: the digest
of the whole line, and the digest of what it says without its link to the line
before. BOB reads them back (`journalctl SYSLOG_IDENTIFIER=bob-fix`) and holds
the journal against them:

* a line that **differs** from what its witness recorded — **falsified**, chain
  recomputed or not;
* a line that says what it said but whose link was recomputed after an earlier
  change — **re-chained**: the chain was rewritten;
* a witness with **no line** in the journal — lines **cut** from the end, or
  the journal deleted;
* one line, **two witnesses that disagree** — a witness forged beside the real
  one;
* a line with no witness though the system log covers its date — **not
  demonstrated**: nothing proves a falsification, nothing proves the line;
* a line older than anything the system log still holds — its witness went
  with the log's own rotation: **said, never called a falsification**.

Only what **root** sent counts. journald records the sender's uid (`_UID`) from
the socket's credentials, not from the sender: an ordinary account can write
`logger -t bob-fix "…"`, but its line carries its own uid and BOB leaves it
aside (measured, §5.3).

That `_UID` says *who* sent a line — an account with root's privileges — not
*what program* wrote it: any process running as root can send a line under the
name `bob-fix`. Such a line, with no journal line of its id, shows as a line cut;
beside a real one, as two witnesses that disagree — both **falsified**, which is
true: something with root's rights wrote in BOB's name.

*Limit:* root can rewrite the system log too — unless it is sealed (§3.4) or
copied to another machine (§6).

### 3.3 The append-only attribute

BOB sets `chattr +a` on the journal. The kernel then refuses to rewrite it,
truncate it or delete it — root included — until the attribute is taken off
(measured, §5.1). Taking it off is a deliberate act, and each line records
whether the attribute was set when it was written: found missing since, BOB
says so.

*Limit:* root can take it off, rewrite, and set it back. It raises the bar and
leaves a mark; the witness is what proves.
Where the file system has no such attribute (tmpfs, overlayfs) or BOB lacks the
right to set it (in a container), the screen says *not available*.

### 3.4 journald's own sealing

journald can seal its own files (Forward Secure Sealing): set up with
`journalctl --setup-keys`, it gives a verification key to keep **off the
machine**; `journalctl --verify --verify-key=…` then shows a system log
rewritten after the fact. BOB says whether sealing is set up; it never sets it
up for you. With it, the witness of §3.2 can no longer be rewritten without
showing.

## 4. Reading the verdict

The verdict heads the screen and the text, in its own colour:

| Verdict | Meaning | Exit code of `bob --fix-journal` |
|---|---|---|
| ✔ **INTACT** | the chain holds and every line BOB could check matches its witness | 0 |
| ⚠ **NOT DEMONSTRATED** | nothing shows a falsification, but not everything could be checked: a line without a witness, the system log unreadable by this account, the append-only attribute taken off | 4 |
| ✖ **FALSIFIED** | a falsification is shown: chain broken, a line differs from its witness, a chain recomputed, lines cut, a forged witness, a journal not owned by root | 2 |

Under the verdict, each finding is listed with the number of lines it concerns;
under each entry the witness contradicts, the lines the system log recorded
when it was written — the proof, ready to be copied into a ticket. In
`--manage-logs`, a day holding a falsified entry is marked, the entry is
marked, and `r` lists the lines cut.

The exit code makes it a monitoring check:

```bash
bob --fix-journal >/dev/null; case $? in 0) ;; 2) echo "fix journal FALSIFIED";; *) echo "fix journal not demonstrated";; esac
```

## 5. Demonstration

Measured on the test machine, 20 November 2026. Two operators applied a fix
each: `root` logged in directly (login uid 0), and `bobop2` through `sudo`
(login uid 1001). Each added a note to the first entry through
`sudo bob --manage-logs`. The journal then read:

```text
✔ INTACT — the chain holds and 6 line(s) match their witness in the system log
  Witness: the system log (journald), read back
  journald sealing (FSS): not set up — root could rewrite the system log too (journalctl --setup-keys)
  Append-only attribute (chattr +a): set — the kernel refuses to rewrite the journal, root included

Friday 2026-11-20 — 2 command(s): 2 applied, 0 failed, 0 other
  21:47:25  ✔ applied      root             sudo sysctl -w net.ipv4.conf.all.accept_redirects=0 …
      2026-11-20 21:49  root: verifie par root : sysctl relu
      2026-11-20 21:49  bobop2: vu par bobop2
  21:48:22  ✔ applied      bobop2           sudo sysctl -w net.ipv6.conf.all.accept_redirects=0 …
[exit code: 0]
```

### 5.1 Rewriting the journal, as root

With the attribute set, the kernel refuses — root included:

```text
$ sed -i s/bobop2/root/ /var/log/bob/fixes.journal
sed: cannot rename /var/log/bob/sedWPWjzp: Operation not permitted
$ truncate -s 0 /var/log/bob/fixes.journal
truncate: cannot open '/var/log/bob/fixes.journal' for writing: Operation not permitted
$ rm -f /var/log/bob/fixes.journal
rm: cannot remove '/var/log/bob/fixes.journal': Operation not permitted
```

### 5.2 Taking the attribute off, attributing bobop2's command to root, recomputing the chain

The attempt to hide who did what: `chattr -a`, then every line written by
`bobop2` rewritten as `root`'s — his command, its outcome, his note — and every
digest recomputed so that the chain holds. The chain alone shows nothing; the
witness does:

```text
✖ FALSIFIED — this journal was changed outside BOB (proof below)
  3 line(s) differ from their witness: what they say was changed
  1 line(s) say what they said but were re-chained after a changed line: the chain was recomputed
  the append-only attribute was taken off since the last entry (chattr -a): a deliberate act the content may have followed
  …
Friday 2026-11-20 — 2 command(s): 2 applied, 0 failed, 0 other   [✖ falsified]
  21:47:25  ✔ applied      root             sudo sysctl -w net.ipv4… [✖ changed]
    What the system log recorded when its lines were written:
    2026-11-20 21:49  note id=51e459a65d78 sha256=037eee… of=04322d19283d by={"login":"root","uid":0}
    2026-11-20 21:49  note id=75a48b385f90 sha256=d024c9… of=04322d19283d by={"login":"bobop2","sudo":"bobop2","uid":0}
      2026-11-20 21:49  root: verifie par root : sysctl relu
      2026-11-20 21:49  root: vu par bobop2
  21:48:22  ✔ applied      root             sudo sysctl -w net.ipv6… [✖ changed]
    What the system log recorded when its lines were written:
    2026-11-20 21:48  run id=eb87e0cef2eb sha256=2954bb… by={"login":"bobop2","sudo":"bobop2","uid":0} …
    2026-11-20 21:48  result id=7feacb20c2b0 sha256=845953… of=eb87e0cef2eb status=ok rc=0
[exit code: 2]
```

The journal now says `root`; the system log, written when the command ran,
says `bobop2` — side by side. The first note (`root`'s) is listed because it
was re-chained after the forged one.

### 5.3 A witness forged by an ordinary account

`bobop2`, without `sudo`, sends a line in the witness's name, with the id of
one of the entries:

```text
$ logger -t bob-fix 'run id=eb87e0cef2eb sha256=0000… body=0000… by={} finding=x cmd=x'
$ journalctl -t bob-fix -o verbose -n 1
    _UID=1001
    MESSAGE=run id=eb87e0cef2eb sha256=000000000000000000000000000000000000000000000000000
```

journald recorded `_UID=1001`. BOB leaves the line aside: the verdict stays
**✔ INTACT**, exit code 0.

### 5.4 Cutting the end of the journal

The two notes removed, the chain recomputed over what is left:

```text
✖ FALSIFIED — this journal was changed outside BOB (proof below)
  2 line(s) differ from their witness: what they say was changed
  2 line(s) of the system log are missing from the journal: cut from its end, or the journal deleted (proof below)
  …
Lines the system log holds and the journal no longer does (2):
  2026-11-20 21:49  note id=51e459a65d78 sha256=037eee… of=04322d19283d by={"login":"root","uid":0}
  2026-11-20 21:49  note id=75a48b385f90 sha256=d024c9… of=04322d19283d by={"login":"bobop2","sudo":"bobop2","uid":0}
[exit code: 2]
```

### 5.5 Deleting the journal

```text
✖ FALSIFIED — this journal was changed outside BOB (proof below)
  6 line(s) of the system log are missing from the journal: cut from its end, or the journal deleted (proof below)
  …
Lines the system log holds and the journal no longer does (6):
  2026-11-20 21:47  run id=04322d19283d … by={"login":"root","uid":0} finding=hardening.redirects_enabled …
  2026-11-20 21:47  result id=6fabb6389019 … of=04322d19283d status=ok rc=0
  2026-11-20 21:48  run id=eb87e0cef2eb … by={"login":"bobop2","sudo":"bobop2","uid":0} …
  …
[exit code: 2]
```

What was deleted can still be read, from the system log.

### 5.6 A reader without the right

`bobop2` without `sudo`, not in `adm`:

```text
⚠ The journal /var/log/bob/fixes.journal could not be read: permission denied — read it as root or as a member of the adm group
[exit code: 4]
```

A member of `adm` reads the journal and its witness without `sudo`, and gets
the same verdict as root.

### 5.7 And the journal put back exactly

Copied back byte for byte from before §5.1, the journal reads **✔ INTACT**
again: what BOB vouches for is what the journal says, line by line, against
what was recorded when it was written — and it says again exactly that.

### 5.8 The system log rotated away

`journalctl --rotate`, then `journalctl --vacuum-time=1s`: the system log's
older files go, and with them all eight witness lines. Not a falsification —
said as what it is:

```text
✔ Chain intact — no line could be held against its witness (gone with the system log's rotation, or unreadable): only the chain vouches for the journal
  6 line(s) are older than anything the system log still holds: their witness went with its rotation
[exit code: 0]
```

The first wording, measured here before release, read *INTACT — … 0 line(s)
match their witness*: true, and misleading. It now says that only the chain
vouches for those lines.

### 5.9 Sealing set up

Before `journalctl --setup-keys`, BOB said *not set up*; after it (and a
rotation, so that journald starts sealing), *set up*, and
`journalctl --verify` passes. BOB looks for the sealing key journald keeps
beside its files; it does not hold the verification key — that one stays off
the machine, with you.

### Replaying it

On a **throwaway virtual machine**, never on a machine whose journal you want
to keep: the witness lines stay in the system log, and once the journal is
falsified or deleted, BOB will report them as missing until journald rotates
them out — which is the point.

```bash
sudo bob --fix --apply                     # apply one or two fixes (answer y)
bob --fix-journal                          # ✔ INTACT (as root or a member of adm)
sudo sed -i 's/"login":"[a-z]*"/"login":"x"/' /var/log/bob/fixes.journal   # refused: chattr +a
sudo chattr -a /var/log/bob/fixes.journal
sudo sed -i 's/"login":"[a-z]*"/"login":"x"/' /var/log/bob/fixes.journal   # changed, chain broken
bob --fix-journal; echo $?                 # ✖ FALSIFIED, 2 — and the recorded lines
sudo rm /var/log/bob/fixes.journal
bob --fix-journal; echo $?                 # ✖ FALSIFIED, 2 — every line, from the system log
```

## 6. What stays out of reach

Said plainly, because it is where the trust ends:

* **root rewriting both** the journal and the system log, consistently — or
  deleting both — on a host where the system log is neither sealed (§3.4) nor
  copied to another machine. The only real defence against root is a copy root
  does not hold: forward the system log to a log server (rsyslog, journald's
  `systemd-journal-upload`), and seal it.
* **lines older than the system log's retention**: their witness is gone with
  journald's rotation; only the chain vouches for them, and BOB says so.
* **a system log kept in memory only** (`/run/log/journal`, `Storage=volatile`):
  the witness is lost at reboot; BOB says so.
* **a host without journald** (Alpine's busybox syslog): the witness is written
  but cannot be read back there; BOB says so.
* **a journal restored exactly** (§5.7) leaves nothing to see — and then there is
  nothing hidden.

The digests prove that the journal changed, not who changed it. A chain or a
witness is evidence to put in front of someone, not a signature.

---

© 2026 Cédric Clauzel
