*[Lire en français](CHANGELOG_FR.md)* · *[Full changelog](DOCUMENTS/CHANGELOG_FULL.md)*

# BOB — Changelog

| Version | Date | Summary |
|---------|------|---------|
| [v0.15.0](#v0150) | unreleased | **First v0.15.x release — verdict accuracy (in progress, unreleased).** The v0.15.0 objective is the correctness of what BOB *says*, before any new deduction is added: a wrong verdict discredits the tool more than a missing one. Each fix in this cycle is differential-tested against the tool's own parser — `sshd -T` / `ssh -G` for SSH, `cvtsudoers -f json` for sudoers — so the expectations record what the system actually does rather than what the configuration line looks like. **One defect class dominates**: a check's patterns were written against the tidy form of a line and stopped matching the moment an operator added a trailing comment — so the more disciplined the administrator, the likelier the miss. Found so far in `sshd_config`/`ssh_config` (server and client), in `ufw status` (a commented `allow from anywhere` wildcard was **completely undetected**, ALERT and 2-point deduction both gone), in `sudoers` (`NOPASSWD: ALL # temporary` silently downgraded from WARN −2 to a scoreless INFO), and — the inverse and more dangerous direction — in `apt.conf` (a commented-out `Unattended-Upgrade "1"` was reported as **enabled**, a reassurance for a control apt does not read at all). **Also**: the audit's main loop had never been executed by a test — three files inspect `run_checks` with `ast`, none ran it — and the first live run found five findings constructed **without a key**, unreachable by `--explain` and anonymous in the JSON. **And**: the always-on core still aborted the whole audit on any failure — seven of eight injected faults lost it, one after 29 962 bytes had already reached the operator. Ten of the twelve core collections are leaves and now degrade in place; the two that are not stay unguarded on purpose, because an empty port table would render as *"nothing is listening"*. **Password policy**: login.defs and pwquality.conf are last-one-wins, so appending the hardened value to the end of the file — what every guide writes — left BOB reporting the value the operator had just overridden; `pwquality.conf.d/` was never opened; and a wrapped PAM line lost its `minlen=`. **Kernel hardening**: an unreadable sysctl fell back to a *hardened* default, so a kernel built without Yama got `[OK] ptrace restricted` for a protection that did not exist — "not read" is now a distinct answer from any value. A sweep found the same pattern ten knobs wide in the SYSTEM HARDENING section, where an unreadable `/proc/sys` produced ten passes for ten parameters BOB never read; the JSON `hardening` block now reports an unread parameter as `null`. The same sweep found that with `UseDNS` on, sshd logs a hostname rather than an IP, which `auth_log` filed as *private* — so a host accepting SSH logins from the internet reported none. **Disk**: the partition filter matched on the device path starting with `/dev/`, which no ZFS dataset does — a Proxmox or Ubuntu-on-ZFS root at 93% produced no finding at all — and a mount point containing a space was truncated to its first word. **systemd**: `systemctl list-units` prefixes a not-ok unit with a status glyph that shifts every column, so `services_state` read the glyph as the unit name and `loaded` as its state — a failed security service was invisible to the check whose whole purpose is to report one. **Accounts**: an account expiring *today* is already locked out per `chage(1)`, and BOB's strict `<` called it fine; an expiry field of `0` is ambiguous per `shadow(5)` and is now reported as such rather than skipped. **TLS**: `days_left` is a floored timedelta, so `days <= 0` covered the whole final day of a *valid* certificate — one with 23 hours left was reported EXPIRED with a 2-point deduction, against `openssl x509 -checkend 0` calling it valid. **Cron and timers**: the "download piped into a shell" rule existed twice with different blind spots — `curl … | sudo bash`, the published and root-running form, matched neither, while `curl … | ssh host` matched one of them because "ssh" ends in "sh". **UFW coverage**: rules written as an application profile (`ufw allow OpenSSH`, the documented way), as a range (`6000:6007/tcp`) or as a list (`80,443/tcp`) were read as covering one port or none, so a correctly configured host was told its ports had no firewall rule. **Containers**: an unreadable seccomp status produced the same silence as an active filter, and `/proc/self/status` omits that line exactly on a kernel built without `CONFIG_SECCOMP` — the case where it matters most. **IPv6**: `/proc/sys/net/ipv6` is missing entirely when the kernel boots with `ipv6.disable=1`, and the reader answered "assume enabled if unreadable", so a host with no IPv6 stack was reported `[OK] IPv6 configuration is consistent`. **Tests** 6719 → **7084**. |
| [v0.14.1](#v0141) | 2026-08-30 | **First v0.14.x patch — "privileged" now means what it says.** Correctness only: the container surface is INFO-only, so no score, output field or exit code changes; one additive finding key. **The defect** ([bob/checks/container_security.py](bob/checks/container_security.py)): `privileged` was computed as `cap_bnd & (1 << CAP_SYS_ADMIN)` — literally "CAP_SYS_ADMIN is present". A container started with `--cap-add SYS_ADMIN` (one targeted grant, commonly for FUSE mounts or nested containers, with seccomp still enforcing) was therefore reported as **PRIVILEGED** under the headline *"full Linux capability set available"*. Measured on real podman containers, that claim is false: bounding set **2149844475** for the targeted grant against **2199023255551** — `(1 << 41) - 1`, every capability the kernel knows — for a genuinely privileged one. The detail line was already careful (*"or one granted CAP_SYS_ADMIN"*); only the headline lied. **The fix**: `privileged` now means the **full** bounding set, derived from `/proc/sys/kernel/cap_last_cap` (with a bounds-checked fallback, since a nonsense value would shift the mask and make every container look unprivileged), and a lone CAP_SYS_ADMIN gets its own finding — new additive key `container_security.cap_sys_admin` — stating plainly that the container is **not** privileged but holds the most escape-prone capability. Both messages rewritten in EN and FR. **Why it matters beyond wording**: the container deduction planned for v0.15.0 was to be keyed on `privileged`, so shipping it against the old semantics would have penalised a FUSE-scoped container exactly as hard as a fully privileged one — and the backlog lists `privileged` and `CAP_SYS_ADMIN` as *distinct* conditions. **Why it survived**: the existing tests set `privileged=True/False` directly on the snapshot and never derived it from a realistic bounding set. The new guards drive the real `from_system()` with the bitmasks measured on podman; an earlier draft of them reimplemented the mask logic locally and **passed when the old buggy line was restored** — it was rewritten until both a reverted classification and a removed emission branch fail it. **Plus** a date correction: the v0.14.0 release surfaces were frozen at 28 Aug but it shipped on the 29th (its publish workflow is stamped `2026-08-29T16:46:08Z`); corrected on the v0.14.0 surfaces only — v0.13.3 and v0.13.4 genuinely shipped on the 28th and keep their dates — with the weekday moving to Saturday and the guard added in v0.14.0 confirming it. **Plus — a robustness batch from a local stress campaign** (1 209 hostile argv combinations, corrupted state files, every check swept inside a restricted user namespace, 8-way concurrency, broken pipe, symlink and encoding attacks). Three of the seven defects cost the operator the entire audit. **(1) One failing check destroyed the whole audit 🔴** ([bob/runner.py](bob/runner.py)): `_sec` had no exception handling, so any exception from a snapshot collector or a check function propagated out of `run_checks` to the broad handler in `__main__` — **exit 3, zero bytes of stdout**, no score, no findings, no report, because one section could not read one file. Reproduced live: a single latin-1 byte in an `/etc/passwd` GECOS field (`José García`, ordinary on legacy systems) killed the run. A failing section is now **degraded in place** — the audit completes, the failure surfaces as a `<section>.unavailable` INFO finding in every output format and in the `-d` report, and the section is listed in the new top-level JSON field **`degraded_sections`** (additive within schema v3, no bump) so a pipeline can tell "score 9 with every section evaluated" from "score 9 with two sections never run". Exit codes are deliberately **unchanged**: routing a degraded section to exit 3 would collide with `--target`'s exit 4 — the very reachability v0.14.0 just restored — and would destroy the existing distinction between "BOB is broken" and "one file was unreadable". **The barrier was inert at first**: 29 of the 34 `_sec` call sites collected their snapshot eagerly *one line above* the call, outside the try — and snapshot collection is exactly where the file reads happen. Converting them to lazy factories was a prerequisite, and incidentally delivers the performance win deferred since v0.13.3 (`--check=ssh` no longer pays for 29 snapshots). **Scope, deliberately bounded**: the always-on core (`firewall` → `virtualization`) is *not* guarded — it is a data pipeline, not a set of sections (`fw_status`, `ports_snapshot`, `network_context`, `audited_ports` flow into one another and into the `_sec` calls), so swallowing a failure there would leave downstream code reading names that were never bound, strictly worse than aborting. If the firewall core cannot be read there is genuinely no audit to render. **(2) A non-UTF-8 byte escaped 33 `except OSError` guards 🔴**: `UnicodeDecodeError` is a `ValueError`, not an `OSError`. Two live reproductions — the GECOS field above, and an accented comment in `~/.config/bob/ignore.yml` written with a latin-1 editor, which **bricked every subsequent run** for that user with an untranslated Python codec error. Every guarded text read now declares `errors="replace"`, pinned by an AST guard sweeping the whole package. (The first sweep reported 66 sites and was **wrong** — it ignored the `errors=` keyword, and three of its "fixes" passed `errors=` to `file.read()`, which takes only a size; corrected to 33 real sites.) **(3) `bob --history` died on one malformed line**: `load_history` catches `JSONDecodeError`/`ValueError` per line, but a line holding valid JSON that is not an object (`null`, `[1,2]`, `"str"`) reached `_clamp_entry`, which calls `.get` on it → uncaught `AttributeError`. The loop exists to skip malformed lines; it now does so for every malformed shape. **(4) `--lang` accepted an absolute path**: it went straight to `i18n.init()`, which builds `_LOCALES_DIR / f"{lang}.json"` — and pathlib replaces the base when the right-hand side is absolute, so `--lang=/tmp/x` loaded `/tmp/x.json` as the translation table, read as root under sudo. Shape validation only, so a well-formed unknown code (`--lang=de`) still falls back to English exactly as before; the same discipline already applied to `SUDO_USER`. **(5) Report files were opened without `O_NOFOLLOW`**: the name is fully predictable (`bob_%Y%m%d_%H%M%S.log`), the open runs as root with `O_CREAT|O_TRUNC`, and the follow-up `chown` follows symlinks. Not exploitable at the default location (the invoking user's own `~/.local/share/bob/logs`), but `--output-dir` lets an operator point it at a shared directory. Now `O_NOFOLLOW`, plus a new `chown_fd_to_sudo_user` operating on the descriptor already held, closing the TOCTOU window. **(6) CSV formula injection**: `csv.DictWriter` quotes per RFC 4180, but Excel and LibreOffice still evaluate a quoted cell beginning with `=` `+` `-` `@`. Report text that merely passes *through* BOB — a cron command line, a container name, a SUID path — could execute when the operator opens the export. Leading formula characters in `message` / `detail` / `fix_cmd` / `note` are prefixed with `'`, the standard mitigation, the value preserved verbatim after it. **Minor CSV format change** for consumers reading those columns. **(7) Three options never received the v0.7.3 M-4 dash guard**: `bob -p --quiet`, `--check --quiet` and `--skip --quiet` took the flag as their value *and swallowed it*, while `--check ""` and `--check ","` produced an empty (falsy) filter that silently ran the **full** audit — where `--check=` correctly raised. All four now error. **Plus** the `domain_scores` unmapped-prefix debug log fired ~40 times per run for prefixes that are catch-all by design, drowning the drift signal it exists to carry; the deliberate ones are now listed, with a guard that fails if any of them ever becomes mapped. **Verified clean** by the same campaign and worth not re-auditing: the argv parser (1 209 hostile combinations, zero crashes), all 46 sections swept under a restricted user namespace, 8-way concurrent runs (no corruption, 0600 preserved), broken pipe and closed stdout, webhook scheme enforcement (`file://`, `gopher://`, `javascript:` rejected), HTML and Markdown escaping, `SUDO_USER` handling, `--explain` coverage of actionable findings, and v0.14.1's own `cap_last_cap` parser against 13 hostile inputs. **Guards** +64, each mutation-tested — nine defects injected, nine confirmed failures, files restored. **Plus — a second stress campaign, aimed at the first one's own fixes.** Seven more defects, and the first target was the v0.14.1 fault barrier itself: `_degrade_section` did its rendering (`report.write_raw`, `t()`, `output.sanitize`, `add_finding`) *outside* its inner try, so an exception there escaped **from inside the handler**, reproducing exit 3 with zero bytes of stdout one level up. Four probes got through; two were genuine (a raising `t()`, and an exception whose `__str__` raises). It now records the section first — the one step that cannot fail — then renders best-effort with every step individually guarded. **Report writes were unguarded entirely** ([bob/report.py](bob/report.py)): `_writeln` did a bare `write()` + `flush()` reachable from ~200 call sites, and `close()` flushed buffered data unguarded at the very last step. Reproduced on a real 64 KB tmpfs — `sudo bob -d --output-dir=<full fs>` returned **exit 3 and no audit at all**, and a full `/var` is precisely when an operator reaches for a hardening audit. The report is a side artifact: it now disables itself on the first I/O error, says so once on stderr, and the audit completes. **`--ignore` did not actually hide anything** ([bob/scoring.py](bob/scoring.py)): `display_result()` renders the raw `CheckResult`, not `engine.findings`, so an ignored finding kept printing in full. Measured: `--ignore fail2ban.no_jails` took `warning_count` from 14 to 13 and left the `⚠ [WARNING]` line exactly where it was — the score and the JSON honoured the flag, the operator still saw the finding, which is the entire point of the flag. Pre-existing for as long as the feature has shipped; `--show-ignored` is unaffected. **Terminal escape sequences reached the terminal**: finding text interpolates system-derived values and only 7 call sites in the whole codebase sanitized theirs. Demonstrated with a world-writable script in `/etc/cron.daily` whose *filename* carried `\033]0;HIJACKED\007` — rendered verbatim, it rewrote the window title and corrupted the summary box; with cursor-movement sequences the same vector can overwrite already-printed audit lines, i.e. make the report lie about other findings. Now sanitized in `Finding.__post_init__`, which every construction path goes through by definition, so terminal, JSON, CSV, Markdown and HTML are covered at once — including the plugin path, where `bob/_sandbox.py` rebuilds a `Finding` straight from the JSON a plugin returned and would otherwise have bypassed the guarantee entirely (`cmd` keeps its newlines). Measured no-op on well-behaved content: 119 findings, zero control characters. **Unbounded reads on paths that are not regular files**: the plugin loader enforced its 64 KB cap via `stat().st_size`, and a character device reports 0 — `ln -s /dev/zero ~/.config/bob/checks.d/p.py` sailed through and read until the OOM killer stepped in. The same class ran through every state reader: `--diff=/dev/zero` exhausted memory, `ignore.yml` / `last_baseline.json` / `history.jsonl` symlinked to it made **every run fatal**, and `--diff=<fifo>` **blocked forever** — the worst of the set, because a cron job hangs instead of failing, and does so again every run. `--diff=PATH` takes an arbitrary operator-supplied path, so a plain typo reaches it. New shared `bob._atomic.read_text_capped()` refuses non-regular files and caps the read; a missing file still raises `FileNotFoundError` so v0.9.2's distinct "baseline not found" message survives. **Ctrl-C** printed a raw Python traceback on the most ordinary way to stop a long audit; it now prints one localised line and returns the conventional 130. **Verified clean** by this campaign: 12 000 argv combinations (zero crashes, zero contradictory states — conflicting output formats are properly rejected), `--fix` dry-run (instrumented: **zero** subprocess calls), audit determinism (three byte-identical structural runs), SIGINT/SIGTERM/SIGHUP/SIGPIPE, `HOME` unset / missing / read-only, `--watch`, a 34 MB 300 000-line UFW log (3.5 s), `sanitize()` against 16 escape payloads, 6 of 7 adversarial plugins already handled, and corrupted package data (clear fail-fast errors). **Guards** +32 in `tests/test_v0141_hostile_io.py`, each mutation-tested — six defects re-injected, six confirmed kills, including one that manifests as the production hang itself. **Plus — a third campaign, aimed at what the tool *says* rather than what it does.** **The active audit profile appeared in the terminal and nowhere else** — not in JSON, Markdown, HTML or CSV. Since v0.14.0 the profile genuinely changes finding severities, `warning_count` and therefore the exit code, so two JSON payloads for the same host could differ in their counts with nothing in either explaining why, and an archived Markdown or HTML report never said what it had been audited against. A `profile` field is now emitted in JSON (additive within schema v3, like `degraded_sections`) and rendered in the Markdown and HTML headers; **CSV is deliberately left alone** — adding a column would shift index-based readers a second time in one release, and the `'`-prefix change above already touches that format. **`-p NAME` silently becomes your permanent default**: `__main__` persists a valid profile via `set_profile` — real since v0.12.1, deliberate, and documented in neither `--help` nor the READMEs. A one-off `sudo bob -p container` to check something rewrote the operator's saved profile for every later run; it caught this very campaign, which spent ten minutes confused by an audit that reported `container` on a desktop. Stated now in `--help` and in both README usage blocks. **Both READMEs documented `-d` as "French output"** — `-d` is `--detailed` (save the full report to a log file); `--french` is the language flag. A factual error that survived the v0.13.4 documentation-accuracy pass, now fixed in EN and FR with a guard that rejects any usage example claiming French output without a language flag, and another that parses every README example through the real `parse_args`. **Plus** the release surfaces moved to **2026-08-30**: v0.14.1 was still dated the 29th, which is no longer reachable — the same drift v0.14.0 was corrected for, caught here before publication rather than after. **Verified clean** by this campaign: the whole i18n key space — 966 literal keys plus 637 runtime-built expansions (`sections.*`, `groups.*`, `domain_scores.*`, `scoring.level.*`, `explain.*.{title,why,how}`, `service_risk.*`) all resolve in **both** locales, so nothing can render as a bracketed `[key]` to an operator, and `cli.py` calls `t()` nowhere (the v0.9.1 hotfix class stays closed); scoring invariants over **6 000 random engine states** (score and every domain score in range, counts matching the findings, no negative deduction, the F1 "no 10/10 when a deduction applied" rule, domain caps enforced); the profile loader against circular, self-referential, 15-deep, malformed, path-traversing and `/dev/zero`-symlinked profiles (every one degrades to the default with a visible warning); JSON schema conformance across **16 payloads** (4 profiles × 2 formats × 2 locales — no missing, undeclared or misplaced key); and `--watch` over repeated iterations with no file-descriptor leak. **Guards** +16, each mutation-tested. **Plus a full documentation pass** across the whole corpus — the READMEs, SECURITY, AUTOMATION, TESTING, TUTORIAL, the technical and developer references and the SNAPSHOT — bringing them in line with this release and reconciling EN/FR parity. The SNAPSHOT was additionally verified claim-by-claim against the code it describes. **Tests** 6590 → **6719**. Upgrade: `pipx upgrade bodyguard-of-bits` — no migration action; container audits report the accurate finding. |
| [v0.14.0](#v0140) | 2026-08-29 | **First v0.14.x release — BREAKING contract-fix bundle.** The "teeth" this version was originally reserved for (container `privileged` / nftables scoring deductions) **stay deferred**: calibrating them needs a real container and a real cloud instance, neither available, and the project's own rule is not to guess. What ships instead are three contract defects, each found by auditing the tool against itself. **(1) The audit profile never reached 12 of the 14 check-result paths 🔴** ([bob/scoring.py](bob/scoring.py), [bob/runner.py](bob/runner.py)). Callers were responsible for invoking `apply_profile()` before `engine.apply()`, and only the generic `_sec` helper and the plugin path did — the 12 hand-rolled always-on sections (`firewall`, `firewall_rules`, `ufw_logging`, `firewall_iptables`, `firewall_drivers`, `network_context`, `services`, `ports`, `logs`, `ddns`, `docker`, `virtualization`) never did. So **8 overrides shipped in `desktop.conf` and `workstation.conf` were inert**: `ddns.warn`, `services.exposed.avahi`, `services.exposure.open_local` and `firewall_drivers.ip_forward_enabled`, all declared `= info`, stayed at their default severity on every profile. The consequence is worse than cosmetic: `warning_count` counts by *level*, and `bob/__main__.py` maps `warning_count > 0` to `EXIT_WARNINGS`, so a host running Samba restricted to the LAN by a UFW rule — **the recommended configuration** — returned exit 1 permanently, making the documented `exit 0` ("No issues detected", part of the stable exit-code API) unreachable. `ScoreEngine` now takes `profile=` and applies the overrides inside `apply()`, the single choke point every result passes through; the alternative of repeating the call at each site was rejected as being exactly the design that drifted. **BREAKING** on desktop/workstation (measured live: `warning_count` 4 → 2, score unchanged); `server` is untouched, it ships zero overrides by design. **(2) Colour was emitted unconditionally (BREAKING)** ([bob/output.py](bob/output.py)). `bob > report.txt` wrote ANSI escape codes into the file and `bob \| less` showed them raw. `output.supports_color()` had existed since early on — correct, and called from nowhere. It is now wired, with resolution order `--no-color` → `NO_COLOR` → **`FORCE_COLOR`** (new escape hatch) → `isatty()`. `print_help` hardcoded its own `\033[1m`, so `bob --no-color --help` printed bold regardless — it now obeys the same decision, pinned by a guard that forbids literal escapes in `bob/cli.py`. **(3) `--help` wording** (deferred here from v0.13.4 on purpose, so the text describes the final behaviour rather than being patched twice): "`NO_COLOR=` also work" read either as the assignment `NO_COLOR=1` or as the empty value — and the empty value is precisely the case that does *not* disable colour. Replaced by an explicit two-line entry. **Plus** `B904`/`B905`, deferred through v0.13.x because their fixes change runtime behaviour: `from None` in `bob/cli.py` (the `int()` `ValueError` is an implementation detail the user should not see under `BOB_DEBUG`), `from exc` in [bob/_sandbox.py](bob/_sandbox.py) (which `OSError`, and where the `SyntaxError` landed, is exactly what a plugin author needs), and `zip(strict=True)` in [bob/cron/_parse.py](bob/cron/_parse.py) documenting an invariant the regex above already guarantees. `.ruff.toml` now ignores nothing. **Plus** 8 wrong weekdays across the debian and rpm changelogs (`lintian debian-changelog-has-wrong-day-of-week`), with a guard that recomputes the day from the date. **Guards** (+43 across four files), all mutation-tested — a real defect is injected, the failure confirmed, the file restored. The profile guards are deliberately **behavioural, not structural**: the previous design was "correct" at every call site that remembered, which is why the full suite passed *before* the fix too — there was no test of the wiring at all, only of `apply_profile` in isolation. **Tests** 6547 → **6590**. A second validation pass (profile `skip` / ignore ordering / `--watch` / plugins / machine-output purity) found no defect; `server` is byte-identical to v0.13.4 and only `services.exposure.open_local` changes level elsewhere. **Explicitly not validated**: cloud *runtime* findings (only DMI detection, via test fixtures), 3 of the 4 resurrected overrides (covered by targeted tests, not seen live on this host), and the `docker` checks (podman was chosen so the host posture stays comparable). **Two findings recorded for the teeth, not fixed here**: `container_security.privileged` says "full capability set" for a mere `--cap-add SYS_ADMIN`, and nftables parity turns out never to have been hardware-blocked. Field-tested live on 4 profiles × 2 locales. Upgrade: `pipx upgrade bodyguard-of-bits` — **BREAKING**: desktop/workstation audits report fewer warnings (and may now exit 0 where they always exited 1); piped output loses its colour unless you set `FORCE_COLOR=1`. |
| [v0.13.4](#v0134) | 2026-08-28 | **Documentation accuracy pass — factual corrections only, no code behaviour change (one `--help` text addition aside).** A machine audit of the whole doc corpus (21 markdown files, 3 man pages, ~26 kLines) against the code found **seven real defects, two of them introduced by v0.13.3 itself**. **(1) `SECURITY_FR.md` "Plugin checks" was factually inverted 🔴** — not merely abridged (83 words against 562 in English, 15 %): it stated that plugins **"NE SONT PAS sandboxés"** and referred to *"la ligne 0.6.x"*. The sandbox shipped in **v0.7.0** — the French security policy had been telling readers the opposite of the truth for **seven minor releases**, and the entire threat model (in-process sandboxing is *defence-in-depth, not a security boundary*; PEP 416; the `__globals__` escape is expected and pinned by test; AppArmor is the real boundary; **code-review your plugins**) existed only in English. Fully translated — **15 % → 121 %** of the English word count, in line with the other 15 sections. **(2) five working CLI flags appeared nowhere in `--help`** ([bob/cli.py](bob/cli.py)): `--json`, `--json-full`, `--html`, `--output=FORMAT` and `--no-colour` all parse correctly but were undiscoverable — the same "silent feature gap" class hunted in v0.8.0. Now documented, with `--output=FORMAT` explicitly distinguished from `--output-dir`. **(3) 29 broken or leaked markdown links** — 17 in `DOCUMENTS/CHANGELOG_FULL.md` written `](bob/…)` instead of `](../bob/…)` (they 404 on GitHub; the FR twin had **zero**, which is why symmetry never caught it), 8 pointing at Claude's **internal memory store** (`](memory)`) that had leaked into the public changelogs, and 4 stale targets (`bob/checks/ssh.py`, split into a package in v0.6.0, and a `::method` suffix inside a URL). **(4) `SNAPSHOT.md` contradicted itself** after v0.13.3: the new header paragraph said `NO_COLOR` is honoured while line 633 still read *"**NOT honored**: `NO_COLOR` env var"*. Resolved, and the still-unwired TTY auto-detection (`output.supports_color()` exists, is correct, and is called from nowhere) now stated explicitly with its v0.14.0 `FORCE_COLOR` plan. **(5) `BOB_DEBUG` was documented as traceback-only** in `SECURITY.md` + `SECURITY_FR.md`; it has printed tracebacks since v0.6.1, and v0.13.3 additionally made it install a logging handler **without updating the table**. Both entries corrected, and `NO_COLOR` added to the env tables (EN+FR) where it was missing entirely. **(6) `README_DEV{,_FR}.md` was missing the four v0.13.x check modules** (`systemd_hardening`, `container_security`, `socket_units`, `cloud_context` — 0 occurrences against 3–4 in `SNAPSHOT.md`), added to both the module table and the tree. **(7) `--english`** (added v0.12.1) was absent from `README_TECH{,_FR}.md` and `man/bob.1`. **Three anti-drift guards** ([tests/test_v0134_docs_accuracy.py](tests/test_v0134_docs_accuracy.py)), each closing a *class*: every relative link must resolve (plus no `](bob/` from `DOCUMENTS/`, no link to the memory store); **per-section** EN/FR word ratio ≥ 55 % — a whole-file ratio would have missed defect 1 entirely, since `SECURITY_FR.md` sat at **92 %** overall; and every flag `parse_args()` accepts must appear in `--help`, with the reverse check that `--help` promises no flag the parser rejects. **Verified healthy and deliberately left untouched:** 5 of 6 doc pairs at 106–113 % EN/FR ratio (translations complete, French is simply more verbose), `CHANGELOG_FULL` carrying all **65 releases in both locales**, and `README_DEV`'s module inventory otherwise complete (no ghost, no missing root module). **Tests** 6533 → **6545** (+12). 0 regression. **v0.12.x remains EOL**; v0.13.x is the only supported line. Upgrade: `pipx upgrade bodyguard-of-bits` — documentation and `--help` only; no audit behaviour, score, output field or exit code changed. |
| [v0.13.3](#v0133) | 2026-08-28 | **First v0.13.x hardening patch after the branch's scope growth — logging hygiene, filtered-run performance, doc-counter drift (additive, non-BREAKING, no score change).** **(1) `logger.warning` leaked raw to stderr 🔴** ([bob/__init__.py](bob/__init__.py)): BOB never configured logging, so all ~45 `logger.warning`/`logger.error` sites in the package fell through to Python's *lastResort* handler and printed an un-prefixed, un-i18n'd line on stderr — **bypassing `--quiet`** (documented as "suppress all output"), emitting English inside a French audit, and **doubling** the profile warning (`bob --profile=typo` printed the same sentence twice: once via `output.print_warn`, once via `profiles.py`'s logger). A `NullHandler` on the `bob` logger stops lastResort **without cutting propagation** — verified that pytest's `caplog` and any downstream handler still receive every record. New **`BOB_DEBUG=1`** turns on a real handler and, as a bonus, surfaces the 23 `logger.debug` calls (including `_run()`'s per-subprocess failure trace) that were unreachable before. Deliberately wired in `bob/__init__.py`, not `__main__.py`: `bob/i18n.py` and `bob/registry.py` call `resolve_share_dir()` at **import time** and that helper logs, so configuring any later would drop exactly the records the switch exists to show. **(2) `--check`/`--skip` bought no time** ([bob/runner.py](bob/runner.py)): every `XxxSnapshot.from_system()` was evaluated **at the call site**, i.e. before `_sec` consulted `_section_enabled`, so a filtered run still paid for all 47 checks' subprocesses. `_sec` now also accepts a **factory** and invokes it *after* the gate and *before* `skip_if`, preserving semantics exactly (a gated-out section already returned before `engine.apply`, so the behavioural delta is nil by construction). The five most expensive snapshots are converted (`updates`, `services_health`, `socket_units`, `systemd_hardening`, `disk` — ~2.9 s of a 5.4 s audit); the 29 remaining sites are deferred to v0.13.4. **Measured: `--check=ssh` 5.40 s → 2.57 s (−52 %)**, full audit unchanged at 5.4 s. Equivalence proven with an A/B/A/B alternating run comparing the structural finding signature `(key, level, nature)` — identical across `--check=ssh`, `--skip=updates,disk`, `-p desktop`, `--check=updates`. Note: a raw JSON diff is *not* a valid equivalence test here (live UFW block counters drift between runs and produce false positives). **(3) `NO_COLOR`** ([bob/output.py](bob/output.py)): the [no-color.org](https://no-color.org) variable now reaches the same state as `--no-color`, with spec-correct semantics (any non-empty value disables; an empty value is ignored). Strictly additive — it can only ever turn colour *off*. The TTY auto-detection that `output.supports_color()` was written for but never wired is **BREAKING** (it would strip colour from `bob \| less -R`) and stays in the v0.14.0 bundle. **(4) doc-counter drift** — five counters had gone stale, one of them **by six minor releases**: correlation rules 5 → **6** (the enumeration was also missing `corr.stale_unmonitored`), explain keys 116 → **169**, "29 groups" → **45 prefixes**, runner "29 sections" → **38 filterable + 10 always-on**, locale keys 1401 → **2008**. Corrected across README_TECH + README_DEV (EN+FR). The existing doc guards covered *versions*, *profiles* and retired flags but never *counters*; the new [tests/test_v0133_release.py](tests/test_v0133_release.py) closes the **class**, matching claims against values computed from the code and skipping lines that narrate past releases (`README_TECH.md:776`'s "Baseline history: v0.7.0 audit = 117 keys / 30 prefixes" is legitimately historical and must not be rewritten). **(5) correctness-only lint gate** — new `.ruff.toml` + CI job running `ruff check bob/` at **zero findings**, restricted to `E9`/`F`/`B` with **no style rules** (no line-length, import-sorting, naming or pyupgrade — that would be hundreds of cosmetic diffs for no defect caught). Scoped to `bob/`: `tests/` carries ~140 unused-import findings whose cleanup is pure churn and would drown the signal. Justified by reproducing the **v0.8.3** `UnboundLocalError` that shipped to PyPI — ruff flags it as *"redefinition of unused 'UserConfig' from line 1"*, which is only visible if the baseline is at zero. `B904`/`B905` are **documented as deferred, not waived**: their fixes change exception chaining and `zip` strictness, which does not belong in a patch. Cleanup: 6 dead imports + 8 redundant `f` prefixes + 1 discarded `ast.parse` result. **Three `_run` imports were restored after the test suite caught the removal** — they are **monkeypatch seams** (`monkeypatch.setattr(module, "_run", …)`), not dead code, and are now annotated as such. **Tests** 6511 → **6533** (+22). 0 regression. **v0.12.x remains EOL**; v0.13.x is the only supported line. Upgrade: `pipx upgrade bodyguard-of-bits` — no migration action; scripts that parsed BOB's stray stderr logger lines (there is no reason to) will see them gone. |
| [v0.13.2](#v0132) | 2026-06-21 | **Same-day finding-command safety/coherence patch (additive, non-BREAKING, no score change).** A sub-agent semantic-coherence pass over all ~144 finding commands (prompted by a user observation that an `apt purge` was shown under a "Verify:" label) found a small cluster of *presentation* defects — a command's form mismatching its meaning. **(1) docker `userns_not_configured` 🔴** ([bob/checks/docker_audit.py](bob/checks/docker_audit.py)): the suggested remediation `echo '{...}' \| sudo tee /etc/docker/daemon.json && systemctl restart docker` **overwrote the whole `daemon.json`** (clobbering any existing log-driver / registry-mirrors / iptables keys) with no warning — a silent data-loss footgun behind benign wording. The command is now **create-if-absent only** (`test -f … || { … }`, never clobbers, no human-language text that could leak a locale) and the detail (EN+FR) explicitly warns to back up + merge an existing file. **(2) kernel `kernels_obsolete`** ([bob/checks/kernel_modules.py](bob/checks/kernel_modules.py)): the destructive `apt purge` was emitted under `cmd_type="check"` (the "Verify:" ℹ label, contractually read-only) — re-typed to `cmd_type="fix"` so it renders under "What to do? →" where an action belongs (the boots-first caution stays in the detail). **(3) kernel `kernels_update_available`**: used an invalid `cmd_type="action"` (not a real cmd_type — "action" is a *nature* value) that rendered as fix only by accident — corrected to `"fix"`. **(4) contract guard**: `CheckResult.add_finding` now raises on any `cmd_type` outside `("fix","check")`, making this class of label drift impossible going forward (it would have caught #3). **Tests** 6504 → **6511** (+7). 0 regression. Validated live EN+FR (the kernel purge now renders under "→ What to do?", no destructive command remains under "Verify:"). **v0.12.x remains EOL**; v0.13.x is the only supported line. Upgrade: `pipx upgrade bodyguard-of-bits` — only remediation-command wording/placement changes; no score, JSON field, or exit code changed. |
| [v0.13.1](#v0131) | 2026-06-21 | **First v0.13.x hardening patch — additive runtime-context checks (INFO-only, non-BREAKING, no score change).** Continues the runtime turn opened by v0.13.0, in-branch: everything here is additive and carries **no deduction** (the teeth — container/nftables scoring — are reserved for the planned v0.14.0 BREAKING bundle). **Orphan systemd socket units** ([bob/checks/socket_units.py](bob/checks/socket_units.py)) — new section `socket_units` at the systemd × listening-sockets intersection: flags a `.socket` unit that is still active while its backing `.service` is **broken** — gone (masked / not-found) *or* present but crashed (`ActiveState=failed`, e.g. a bad `ExecStart`) — or the socket itself is in a `failed` state; when a socket declares several trigger services it is orphaned if any of them is broken; marks ones bound to a non-loopback address. Carefully false-positive-free: a socket with an *empty* `Triggers=` (systemd internals such as `systemd-coredump.socket`) is never flagged, and a merely *inactive* backing service (the normal at-rest state of socket activation) is not treated as broken. **Host-side cloud context** ([bob/checks/cloud_context.py](bob/checks/cloud_context.py)) — new section `cloud_context`, suppressed off-cloud via `skip_if`; on a cloud instance it surfaces strictly host-visible exposure: the instance metadata service reachable *on-link* (a link-scoped route, not merely routed via the gateway — with an IMDSv2 reminder) and a world-readable persisted user-data file. Detection is **conservative** — a SMBIOS/DMI-identified provider, or cloud-init corroborated by an on-link metadata route; a bare cloud-init install on a Proxmox/VMware/homelab VM is *not* flagged. **Strictly host-side** — no cloud API, IAM, buckets, security groups or credentials (that stays Scout Suite / Prowler territory). **Robustness fixes (ddns + ssh)** — a path under a directory the auditor cannot search (a hardened `/root`, or a user namespace where root maps to an unprivileged uid) made `Path.exists()` / `is_dir()` / `is_symlink()` raise `PermissionError`. In [bob/checks/ddns.py](bob/checks/ddns.py) it crashed the whole audit; the new `_config_present()` degrades the path to "absent". A live field test then surfaced the same class in [bob/checks/ssh/_snapshot.py](bob/checks/ssh/_snapshot.py) — `~/.ssh` under an unsearchable home (`/root/.ssh` in a user namespace) made `is_dir()` raise and leak the error string into the report; the user-side `~/.ssh` probe is now guarded the same way (degrades to "no `~/.ssh`"). Section count **36 → 38**. **Tests** 6461 → **6504** (+43: 21 socket + 18 cloud + 3 ddns + 1 ssh). 0 regression. Validated live EN+FR (socket-units negative + positive on real units; cloud negative path live + positive on a crafted instance; ddns EACCES reproduced with a mode-000 directory). **v0.12.x remains EOL**; v0.13.x is the only supported line. Upgrade: `pipx upgrade bodyguard-of-bits` — fully backwards-compatible (three INFO-only additions; no existing output field, score, or exit code changed). |
| [v0.13.0](#v0130) | 2026-06-20 | **First v0.13.x release — scope expansion: two new INFO-only hardening checks (`systemd-analyze security` + container self-posture).** BOB's first real coverage growth after a long internal-hardening cycle — both additions are **additive, non-BREAKING, and carry no score deduction** by design. **Service hardening (`systemd-analyze security`)** ([bob/checks/systemd_hardening.py](bob/checks/systemd_hardening.py)) surfaces the systemd exposure score of the host's *running* services (parsed from `systemd-analyze security --json=short`, scoped to running units via `systemctl list-units`): a summary line (counts by predicate — UNSAFE / EXPOSED / OK) plus the least-hardened running services and a pointer to `systemd-analyze security <unit>`. **No deduction** — most units ship unhardened by default (systemd's own docs call the exposure score a *relative* guide, not a vulnerability verdict), so flagging them would be noise and would violate the "audit config, don't over-claim" framing; calibrating a deduction (e.g. for an admin-authored UNSAFE unit) is deferred to real-world signal. **Container security posture** ([bob/checks/container_security.py](bob/checks/container_security.py)) runs only when BOB is *inside* a container (the whole section is suppressed on a normal host via `skip_if`); it reads the container's own isolation from documented, offline kernel interfaces — the capability bounding set (`/proc/self/status` CapBnd → **privileged / CAP_SYS_ADMIN** detection + dangerous-capability list), seccomp mode, user-namespace mapping (`/proc/self/uid_map`), and whether the root filesystem is writable. INFO-only in this first version; a real WARN deduction for a privileged container is a fast-follow once it accrues runtime signal. Detection covers `systemd-detect-virt`, `/.dockerenv`, `/run/.containerenv`, and `/proc/1/cgroup`. **Validation**: the systemd check was field-tested live (EN+FR) on a real host; the container check was validated against **real kernel `/proc` data inside Linux user namespaces** (`unshare`) — privileged + non-privileged + the subtle "userns active suppresses the root-maps-to-host warning" branch all confirmed on real data, EN+FR. Section count **35 → 36**. **Tests** 6442 → **6461** (+19: 7 systemd + 12 container). 0 regression. **v0.12.x is now declared EOL** (per the "latest minor line only" policy); v0.8.x–v0.11.x likewise EOL; **v0.13.x is the only supported line**. v0.7.x / v0.6.x remain EOL. Upgrade: `pipx upgrade bodyguard-of-bits` — fully backwards-compatible (two added INFO-only sections; no existing output field, score, or exit code changed). |
| [v0.12.2](#v0122) | 2026-06-12 | **Branch-closing hardening cleanup — a deep-audit pass (whole-tool sub-agent review) + an "unexplored angles" sweep before sealing the v0.12.x line.** The audit returned **0 critical / 0 important**; the surface it verified clean is worth recording: `_atomic.py` (mkstemp + fchmod + fsync + cleanup-on-error), `webhook.py` (http/https-only + credential redaction + finite timeout, no SSRF beyond the operator's own URL), subprocess usage (no `shell=True`, forced `LC_ALL=C`, the `authorized_keys → /etc/shadow` symlink-escape guard), the log/`sshd_config` parsers (anchored regexes, no ReDoS), EN/FR locale parity (1975/1975 keys), no renamed-away key-literal drift, and the profile `.conf` parser (extends depth bounded at 8, graceful fallback). Two small items were fixed to seal clean. **M-1 — `_DOMAIN_SECTIONS` held finding-key prefixes (`virt`, `logs`) instead of the real runner section names (`virtualization`, `ufw_logging`)** ([bob/domain_scores.py](bob/domain_scores.py)); both differing sections are always-on so the mismatch was behaviourally unreachable, but it made `domain_inactive_reason`'s `_section_enabled` check rely on names that don't exist, and the comment claimed the prefixes *were* section names. Now mapped correctly via `_PREFIX_TO_SECTION`, pinned by a drift guard that asserts every name in `_DOMAIN_SECTIONS` is a real runner section. **Cron name defense-in-depth** ([bob/cron/_install.py](bob/cron/_install.py)) — the cron name is slugged for the file path (no traversal) but written verbatim into the `# name:` comment of the root `/etc/cron.d` file. `input()` is line-based so an interactively-entered name *cannot* contain a newline today (this is **not** an exploitable injection), but a hardening tool must not rely on that as the sole guard for a root cron write: control characters are now stripped so a name can never inject a second cron line regardless of how it was obtained — consistent with the already-strict `_validate_custom_cron`. **Tests** 6437 → **6442** (+5: domain-section drift guard + cron-name sanitisation). 0 regression. **v0.7.x remains EOL** (v0.8.1); **v0.6.x remains EOL** (v0.7.2). **Closes the v0.12.x branch.** Upgrade: `pipx upgrade bodyguard-of-bits` — no behaviour change, no migration action. |
| [v0.12.1](#v0121) | 2026-06-12 | **First v0.12.x hardening patch — domain-display completeness + naive/advanced-audit fixes (additive, non-BREAKING).** Implements the v0.12.0-deferred request to **show all 7 score domains, even inactive ones, with the precise reason** — never counted in the average (preserves scores + the F1 cap + the v0.4.5 inversion guard). An inactive domain is shown without a score and tagged: `not installed` (component absent), `not assessed (<profile> profile)` (skipped by the active profile — e.g. `disk` under `container`, which is **never** "not installed"), `not assessed (--check/--skip)` (filtered out this run), or `no action needed` (only informational notices). Surfaced in **text, JSON (`--json`/`--json-full`), Markdown and HTML** — all four EN+FR. **Then a naive-user + 4-round advanced-user audit campaign found and fixed:** **(A)** `--check=ssh` mislabelled filtered domains as "not installed" → now `--check/--skip`-aware via the shared `_section_enabled` gate; **(B)** `--profile=typo` **persisted the invalid name to config**, silently losing the user's real saved profile — now only valid profiles are saved; **(C)** an unknown `--profile` is now reported **before** the root gate (mirrors F6) instead of demanding sudo first; **(E)** added `--english` (symmetry with `--french`), `--output=html`, `--output=json-full` (so `--output` is a complete alias of `--format`), and case-insensitive `--check`/`--skip`/`--explain`/`--output`; **(ADV-1)** JSON `domain_scores[d]` gains `active` (bool) + `reason` (stable enum) so a machine consumer can **reproduce the headline** (`mean(active scores)` then F1 cap) and tell an absent component from a real 10/10 — **additive within schema v3, no version bump**; **(ADV-G2)** `history.jsonl` is healed to `0600` on every write (a legacy world-readable file created before I-5 stayed `0644` — a hardening tool must not leak its own state); **(ADV-B1)** the per-domain breakdown is now in the **Markdown + HTML** reports too (they previously carried only score + findings). `--output`/`--check`/`--explain` are now case-insensitive. **Tests** 6401 → **6437** (+36). 0 regression, green under deterministic + random ordering. Bilingual field test on a live host (text/markdown/html/json-full × EN/FR + every CLI fix) clean. **v0.7.x remains EOL** (v0.8.1); **v0.6.x remains EOL** (v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits` — fully backwards-compatible (JSON additions only; new CLI flags are additive). |
| [v0.12.0](#v0120) | 2026-06-11 | **First v0.12.x release — planned BREAKING UX bundle (F1/F2/F4/F6/F9).** The five findings from the deep bilingual live test of v0.11.x that could not ride a patch because each changes a contract, an exit code, or the score. Scope frozen before implementation (the validated "planned BREAKING bundle" pattern, cf. v0.9.0 / v0.11.0). **F1 — the score model erased deductions (BREAKING, score).** The headline score is the mean of the active domain scores ([bob/domain_scores.py](bob/domain_scores.py)); rounding that average up could erase a real deduction — a host with one pending firmware update (raw 9/10) averaged to `(6×10 + 9)/7 = 9.86 → 10/10`, reading as a *perfect* audit while the summary still said "Action required". Now **"10/10 means a flawless audit"**: when ANY deduction exists (`engine.raw_score < MAX_SCORE`) the headline is capped at 9/10, reserving a perfect 10 for an audit with nothing to fix. `--breakdown` shows the domain average → cap as two explicit steps (new `ScoreEngine.domain_average_precap` + locale key `breakdown.f1_cap`), and the JSON `score` reflects the capped value. The equal-weight domain average itself is unchanged; only the round-up-erases-a-deduction case is corrected. **F2 — body↔summary severity mismatch (presentation)** ([bob/display.py](bob/display.py)). The summary grouped findings by *nature* (Action required / Possible improvements) and hardcoded the section's bullet onto every item, while the body shows each finding's *severity*. A WARN-level action item (e.g. `firmware.fwupd_updates`) therefore showed `✖` in the summary but `⚠` in the body — one item, two severity symbols. The per-item bullet now reflects the finding's severity (`⚠` WARN / `✖` ALERT) to match the body; the section header still groups by nature. **F4 — `--explain <unknown>` exited 0 (BREAKING, exit code)** ([bob/explain.py](bob/explain.py), [bob/__main__.py](bob/__main__.py)). A typo'd or non-existent key printed an error but returned exit 0, indistinguishable from success — and the exit codes are a stable public API. `run_explain` now returns a bool; an unknown key maps to `EXIT_ERROR` (3) while a valid key / `list` / the interactive browser stay `EXIT_OK` (0). Additive: a `difflib.get_close_matches` "did you mean: ssh.password_auth?" suggestion (new key `explain.ui.did_you_mean`, EN+FR) for near-miss typos. **F6 — root gate jumped ahead of `--check`/`--skip` validation** ([bob/__main__.py](bob/__main__.py)). `bob --check=typo` without sudo printed *"must be run as root"*, forcing the operator to sudo + re-run only to then learn the token was wrong. The (unprivileged) token validation now runs **before** the root gate, so an all-invalid `--check` reports the unknown token and exits 3 without ever demanding root; a partial match warns then proceeds to the gate. Static AST guard pins the ordering. **F9 — JSON count-key naming + schema v2 → v3 (BREAKING, schema)** ([bob/json_output.py](bob/json_output.py)). The v2 schema exposed integer counts under `alerts` / `warnings` while the sibling was `info_count`; a consumer iterating `data["alerts"]` (expecting a list, like the `findings` array in `--json-full`) got an int and broke. Renamed to `alert_count` / `warning_count` for symmetry. A key rename is breaking, so — per the documented versioning rule (SNAPSHOT.md) and the clean-cut precedent (v1 fully retired in v0.9.0, no deprecation cruft) — **schema_version bumps v2 → v3** rather than mutating `"2"` in place; `SUPPORTED_SCHEMA_VERSIONS = {"3"}` and the v2 constants/builder became v3. The **webhook generic payload keeps `alerts`/`warnings`** (it has no `info_count`, so no internal inconsistency to fix, and it is a separate flat contract — the AUTOMATION webhook example, which had long mis-documented it as the `--json` schema, is corrected to the real `build_generic_payload` shape). README_TECH / SNAPSHOT / AUTOMATION JSON sections updated EN+FR with a v1/v2 → v3 migration guide. **Test isolation fix:** the watch score-bar tests now force monochrome output explicitly (`output.init(no_color=True)`) instead of relying on a leaked global colour state that only happened to be set by an unrelated test under random ordering. **Pre-ship sub-agent audit:** 0 critical / 0 important code findings; flagged the AUTOMATION.md JSON example drift (fixed) — SHIP. **Tests** 6381 → **6401** (+20: 6 F1 + 3 F2 + 6 F4 + 2 F6 + 3 F9). 0 regression. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits` — **BREAKING**: JSON consumers must read `alert_count`/`warning_count` (and check `schema_version == "3"`); `--explain` typo scripts now see exit 3; target-gated CI on a host with any deduction now caps at 9. |
| [v0.11.2](#v0112) | 2026-06-11 | **Second v0.11.x hardening patch — i18n completeness (F8 + F8b).** Closes the two remaining French-audit gaps found by a **deep bilingual live test** of v0.11.1 (the other UX-audit items — F1 score model, F2 presentation, F4 explain exit code, F6 root-gate ordering, F9 JSON naming — are BREAKING/design and stay in the planned v0.12.0 bundle). **F8 — the 60 BOB-authored "Best practice — …" reference lines were English-only** ([bob/data/cis_refs.json](bob/data/cis_refs.json)). Entries with `code: null` (best-practice guidance, no formal CIS code) had only an English `ref`, so they rendered in **English inside a French audit** (revealed by a live FR run). Each now carries a French `ref_fr` translation; [bob/cis_refs.py::get_cis_ref](bob/cis_refs.py) is locale-aware (lazy `i18n.current_lang()`, no import cycle) and returns `ref_fr` when the active locale is French. The **114 CIS-coded entries keep their canonical English benchmark titles in every locale by design** (CIS publishes titles in English; translating them would risk drift). **F8b — two inline `# …` comments in `cmd=` command suggestions were hardcoded English** ([bob/checks/ipv6.py](bob/checks/ipv6.py) `# set IPV6=yes, then: sudo ufw reload`; [bob/checks/log_rotation.py](bob/checks/log_rotation.py) `# add: SystemMaxUse=500M`). Both leaked English into French audits — the **same class as the v0.11.1 `disk.py` fix, which was incomplete**; these were the two remaining instances. Both are now locale keys (`ipv6.cmd_comment_enable`, `log_rotation.cmd_comment_maxuse`). A scan confirmed there are no others — every `message`/`detail`/`reason` already goes through `_t()`. **Anti-drift guard** ([tests/test_v0112_i18n_refs_and_cmd_comments.py](tests/test_v0112_i18n_refs_and_cmd_comments.py)): no check may build a `cmd=` string literal with a hardcoded `  # <text>` comment (localised comments use `# {_t(...)}`). **Two deep-test observations were verified to be NON-bugs and left unchanged**: `--unignore` of the last key leaves a residual `ignore:` header (deliberate operator-comment preservation, I-1 v0.8.1), and box-border alignment (every box line is exactly 80 chars — any visual offset is an emoji display-width effect, not a char-count bug). **Tests** 6369 → **6381** (+12: all in `test_v0112_i18n_refs_and_cmd_comments.py` — 9 for F8 [ref_fr present/french/non-copy, get_cis_ref locale resolution, CIS-coded stays EN] + 3 for F8b [keys present EN+FR + the cmd-comment anti-drift guard]). 0 regression. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits` — French users now see the "Best practice" reference lines and the two command comments in French. |
| [v0.11.1](#v0111) | 2026-06-11 | **First v0.11.x hardening patch — two minors from the post-v0.11.0 whole-tool deep audit.** The 20th deep-audit pass swept the whole tool and returned **0 critical + 0 important + 2 minor** (cmd construction, atomic-write, HTML escaping, and the v0.10.2-class literal-key contracts all verified clean). Conservative filter selected both minors — they are small contract-consistency fixes that bundle cleanly. **M-1 — i18n must not crash on a malformed locale template** ([bob/i18n.py](bob/i18n.py)). `i18n.t()` caught only `KeyError` from `str.format()`; a malformed template (unbalanced brace → `ValueError`, positional `{0}` field → `IndexError`) would propagate uncaught and crash the audit for the affected locale. `t()` now degrades to the raw template on `(KeyError, IndexError, ValueError)`; `try_t()` gains the `IndexError`/`ValueError` guard while preserving its intentional `KeyError` propagation (a forgotten kwarg is a caller error, distinct from a corrupt template). The locale linter gains [`TestTemplateWellFormed`](tests/test_locale_coverage.py), which rejects unbalanced braces + positional fields in `en.json`/`fr.json` at CI time so a malformed string can never ship — the stronger guard, protecting every reader (`t`, `try_t`, `t_or_hardcoded`). Current locales are clean; this closes a crash-on-future-edit class consistent with the i18n bracketed-fallback "never crash" contract. **M-2 — `--test-webhook` now honors `--offline`** ([bob/__main__.py](bob/__main__.py)). `--offline` is a global no-egress guard for air-gapped environments. The audit-time webhook path already gated on `not config.offline`, but the explicit `--test-webhook` command did not, so `bob --test-webhook --offline` still issued a POST — violating the offline guarantee in exactly the environment where an unexpected egress is most harmful. The offline guard now wins (the more restrictive flag): the test is skipped cleanly with a clear stderr notice and `EXIT_OK`, before any URL resolution or network import. New locale key `cli.test_webhook.offline_skipped` (EN+FR). **Plus three trivially-safe polish fixes from a follow-on functional / perceived-quality (UX) audit** — the no-contract-change subset (the score-model **F1**, severity-presentation **F2**, explain exit-code **F4**, and root-gate-ordering **F6** items are deferred to the planned v0.12.0 bundle). **F3 — fwupd device-name parsing leaked connector junk** ([bob/checks/firmware.py](bob/checks/firmware.py)). Under the default `LC_ALL=C` (forced for stable English parsing), `fwupdmgr get-updates` renders its device-tree connectors (├ └ ─ │) as `?`, so tree detection failed, the parser fell into flat mode, and harvested `?` / `??UEFI dbx:` / the system-container header as "device names" (observed live: *"3 pending firmware update(s): ASUSTeK ... , ?, ??UEFI dbx:"*). Fix: run fwupd under `C.UTF-8` via a new `_C_UTF8_LOCALE_ENV` (English text, UTF-8 charset) so the existing tree parser receives correct input — plus a defense-in-depth guard rejecting candidate names that don't start with an alphanumeric. Live result is now the clean *"1 pending firmware update(s): UEFI dbx"* (correct name **and** count). **F5 — the unknown-key explain hint wrongly told the user to use sudo** ([bob/locales](bob/locales)). `--explain list` needs no sudo (the help marks the whole explain surface "no sudo required"), yet the `explain.ui.unknown_hint` string said *"Run 'sudo bob --explain list'"*. Dropped the `sudo` (EN+FR), matching the already-correct sibling `invalid_key_hint`. **F7 — protocol-unspecified UFW orphan rules displayed a bare port** ([bob/checks/firewall.py](bob/checks/firewall.py)). A rule with no protocol (UFW applies it to both tcp+udp) showed as `57621` next to proto-qualified siblings like `41681/tcp`. Now rendered as `57621/tcp+udp` — consistent and explicit that it covers both — while the `ufw delete allow 57621` remediation keeps the bare port (UFW's only accepted form). **Plus a documentation accuracy pass** (DOC-A…G — a full doc audit, folding in its no-risk corrections): `--json-v1` (retired v0.9.0) removed from TUTORIAL / README_TECH / SECURITY; the `workstation` profile reconciled to first-class business-tier (it was self-contradicting — README called it an alias, man said "not consumed") and added to the `--help` line + `--profile` error; stale EXPLAIN_KEYS counts (116 / 168 → **169 keys / 45 prefixes**) and "43 checks" (→ **34 check sections**) corrected; `UFW_AUDIT_SHARE` (removed v0.5.4) corrected to `BOB_SHARE`; man dates → 2026-06-11. Pinned by [tests/test_v0111_doc_accuracy.py](tests/test_v0111_doc_accuracy.py) (6 anti-drift guards: every `profiles/*.conf` appears in `--help`; no doc shows a runnable `bob --json-v1`). **Plus a reverse i18n leak** ([bob/checks/disk.py](bob/checks/disk.py)): five `smartctl` self-test command suggestions had hardcoded French inline comments that leaked French into **English** audits (surfaced by comparing live EN vs FR runs) — now locale keys `disk.smart_cmd.*` (EN+FR); a clear wrong-language bug, shipped now rather than with the v0.12.0-deferred F8 (untranslated-English "Best practice" refs). **Tests** 6336 → **6369** (+33: 9 in [tests/test_v0111_i18n_format_and_offline_webhook.py](tests/test_v0111_i18n_format_and_offline_webhook.py) + 2 locale-linter cases + 16 in [tests/test_v0111_ux_audit_fixes.py](tests/test_v0111_ux_audit_fixes.py) (F3/F5/F7 + disk SMART comment i18n) + 6 in test_v0111_doc_accuracy.py). 0 regression. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits` — no migration action required. |
| [v0.11.0](#v0110) | 2026-06-10 | **First v0.11.x release — BREAKING bundle: hygiene + design fix.** Opens the v0.11.x branch. Two BREAKING items; **F-1 parallel checks stay deferred indefinitely** (zero user signal on perf, high thread-safety risk — per [[feedback_conservative_refactor]], not re-proposed each cycle). **M-3 — ssh `~/.ssh/config` Host scope semantics** ([bob/checks/ssh/_subchecks.py::_check_client_config](bob/checks/ssh/_subchecks.py)). Pre-v0.11.0 the client-config check flattened every entry: a directive inside a restricted `Host pattern` block fired exactly as if it were global (`Host *`). This contradicted BOB's own remediation advice for the forwarding directives ("restrict it per-Host"), shipped in the v0.10.1 explain text — an operator who followed that advice still got WARNed with a point deduction. v0.11.0 makes the two forwarding directives scope-aware: `ForwardX11 yes` / `ForwardAgent yes` scoped to a non-global Host block now emit an **INFO note with no deduction** (new keys `ssh.x11.forwarding.client_scoped` + `ssh.client_forward_agent_scoped`, EN+FR with a `{host}` placeholder); global scope keeps WARN+deduction. `StrictHostKeyChecking no` + `UserKnownHostsFile /dev/null` stay **ALERT in any scope** — disabling host-key verification is a MITM exposure even for one host. A multi-pattern Host line containing a bare `*` (`Host gitlab *`) is correctly treated as **global** (OpenSSH applies the block when any pattern matches; `*` matches every host) — the `scoped = "*" not in entry.host.split()` test, caught and hardened by the pre-ship audit before tag. A bounded subdomain wildcard (`Host *.example.com`) stays scoped. **BREAKING**: a scoped forwarding directive previously deducted 1 point (WARN); now it is INFO with no deduction, so the score goes up. **D-4 Rank 2-8 KILL** ([bob/_v100_subcheck_renames.py](bob/_v100_subcheck_renames.py)). v0.10.0 shipped `SUBCHECK_RENAMES_V100` as a foundation for a planned 8-rank D-4 split; only Rank 1 (`ssh.x11_forwarding`, shipped v0.10.1) was ever implemented. Ranks 2-8 were **inert** — their canonical patterns (`ssh.dsa.host_key`, `ssh.weak.cipher.*`, `auditd.missing.*`, …) were emitted by nothing, so the shim entries never fired and the still-live monolithic keys (`ssh.weak_ciphers`, `ssh.host_key_dsa`, …) were covered by the plain exact-match ignore path. With zero user signal across 5+ majors (kill-dormant rule, cf. v0.8.4 `compare-breakdown-diff`), the 13 dead entries were removed. The map is now `{ssh.x11_forwarding: ssh.x11.forwarding.*}`. **Behaviour-preserving**: nothing emitted the canonical patterns the dead entries mapped to (verified by the pre-ship audit grepping every removed pattern across `bob/`). **CI guard** ([tests/test_v0110_legacy_key_drift_guard.py](tests/test_v0110_legacy_key_drift_guard.py)). AST sweep over production `bob/` source forbidding string literals that reference a renamed-away key (the v0.9.0 D-1 prefixes from `SECTION_RENAMES_V090` + the v0.10.1 Rank 1 key), with the migration/alias modules (`_v090_renames.py`, `_v100_subcheck_renames.py`, `compare.py`, `explain.py`) allowlisted and docstrings skipped. Generalises the v0.10.2 static guard to every historical rename so the next cross-module rename drift fails CI instead of shipping silently — the exact class of bug that left the v0.10.2 I-1 posture escalation dead for 3 majors. **Posture matrix** ([tests/test_v0110_posture_matrix.py](tests/test_v0110_posture_matrix.py)). Exhaustive 2×2×2 = 8-cell UFW × iptables × firewall-domain-score matrix pinning every `set_posture_from_engine` escalation outcome, plus branch-isolation tests (each trigger fires in isolation) and priority-resolution tests (firewall_inactive > iptables > domain_low). Closes the masking-branch test debt that let v0.10.2 I-1 hide. **SNAPSHOT.md** refreshed v0.10.0 → v0.10.2 (+ v0.11.0 in preparation). **Pre-ship sub-agent audit**: 1 important (multi-pattern Host scope evasion) fixed before tag, 2 minor (`Match`-block parsing fails safe, loop-hoist no-op) deferred. **Tests** 6268 → **6336** (+68: 15 posture matrix + 4 drift guard + 37 D-4 kill pin + 12 ssh Host scope). 0 regression. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits` — operators who scoped a ForwardX11/ForwardAgent directive per-Host see the finding move from WARN to INFO (score improves); no migration action required. |
| [v0.10.2](#v0102) | 2026-06-10 | **Second v0.10.x hardening patch — I-1 fix from the post-v0.10.1 deep hardening audit.** Same-day sub-agent audit on the post-v0.10.1 surface returned 4 findings (1 important + 3 minor); the conservative "gain × risque = STOP" filter ([[feedback_conservative_refactor]]) selected I-1 only. **The bug**: [bob/scoring.py::set_posture_from_engine](bob/scoring.py) looked for findings with `f.key == "iptables_nft.input_accept"` to flip the `iptables_input_accept` posture flag (which forces risk floor to HIGH when UFW is up but iptables still has an INPUT ACCEPT passthrough rule). The `iptables_nft.*` prefix was renamed to `firewall_iptables.*` in v0.9.0 D-1 (see [bob/_v090_renames.py::SECTION_RENAMES_V090](bob/_v090_renames.py)), so the string-literal comparison stopped matching anything. **The iptables-only posture escalation has been silently dead since v0.9.0** (3 majors). Masked in practice by the `firewall_inactive` branch (UFW down + iptables ACCEPT both escalate to HIGH for the same physical host), but UFW-active hosts with a legacy-allowed iptables passthrough rule regressed silently from HIGH to LOW. No user signaled because the masking branch was permissive enough to surface the same risk floor on the most common deployment shape (UFW disabled / iptables passthrough). **The fix**: update the literal in [bob/scoring.py:739](bob/scoring.py#L739) to `firewall_iptables.input_accept` to match the v0.9.0+ canonical key emitted by [bob/checks/iptables_nftables.py:174](bob/checks/iptables_nftables.py#L174). Covers both call sites in one change — `bob/__main__.py::audit` and `bob/watch.py` both go through `set_posture_from_engine` (single source of truth since v0.7.3 M-10). **Tests** ([tests/test_v0102_posture_iptables_key.py](tests/test_v0102_posture_iptables_key.py), NEW, 7 tests across 2 classes + 1 parametrize): `TestPostureIptablesKey` pins the canonical contract (canonical key triggers escalation with UFW active; legacy key does NOT — v0.9.2 baseline shim handles legacy at load time, live findings always emit canonical; UFW active + zero findings → no escalation; UFW inactive → `firewall_inactive` branch still fires independently). `TestNoLegacyKeyInLiveCheck` is a static AST-style guard: a regex sweep over `bob/` forbids live comparisons against `iptables_nft.input_accept` (the v0.9.2 migration shim files `_v090_renames.py` + `compare.py` are explicitly allowlisted because they document the rename, but production code is locked). The parametrize pins the EXPLAIN_KEYS contract: any key the posture check matches against must be present in `EXPLAIN_KEYS` so `bob --explain` works on the upgrade path. **Tests** 6261 → **6268** (+7). 0 regression. **Conservative-workflow record kept**: 4 audit findings, 1 shipped, 3 deferred. M-1 (duplicate `Host` blocks triple-deduct on the new client X11 check) is pre-existing for 4 client directives (`forwardx11`/`forwardagent`/`stricthostkeychecking`/`userknownhostsfile`); zero user signal across 5+ majors. M-2 (`client_config_q` hoist out of loop) is pure cosmetic with no measurable user gain. M-3 (`_check_client_config` ignores `entry.host` so directives in restricted `Host trusted-jumpbox` blocks fire as if global) is a real contract leak — particularly because the v0.10.1 explain text just shipped recommends "restrict it per-Host block" as remediation — but the fix needs design work (which `Host` scopes WARN vs INFO?) and applies to 4 directives at once. Deferred to v0.11.x as a real D-4-style refinement; revisit if a user signals on a per-Host scoping false positive. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits` — no migration action required from v0.10.1. |
| [v0.10.1](#v0101) | 2026-06-10 | **First v0.10.x hardening patch — D-4 Rank 1 `ssh.x11_forwarding` split + NEW client-side ForwardX11 detection.** Per the v0.10.x conservative workflow ("risque mesuré + gain mesurable + suffisant"), this single curated split was chosen because it adds **new detection capability** (zero client-side X11 detection pre-v0.10.1) — not just cosmetic key renaming. The other 7 D-4 ranks and F-1 parallel checks stay deferred until user signal per [[feedback_conservative_refactor]] "gain × risque = STOP". **Server-side rename** ([bob/checks/ssh/_directives.py](bob/checks/ssh/_directives.py)) — the existing `_BadDirective` row for `x11forwarding` picks up the renamed canonical key `ssh.x11.forwarding.server` (was `ssh.x11_forwarding` pre-v0.10.1). sshd_config parsing logic unchanged. **NEW client-side detection** ([bob/checks/ssh/_subchecks.py::_check_client_config](bob/checks/ssh/_subchecks.py)) — new `elif k == "forwardx11" and v == "yes"` branch sits next to the existing `forwardagent` branch in the `~/.ssh/config` parsing loop. Emits `ssh.x11.forwarding.client` with `points=1` warn + detail + cmd remediation. Pattern mirrors the existing `client_forward_agent` shape. **Pre-v0.10.1 BOB had ZERO detection of client-side X11 forwarding** — this is the security value justifying the v0.10.1 ship. **Back-compat — ignore.yml**: pre-v0.10.1 entries with `ssh.x11_forwarding` continue to suppress BOTH new sub-keys via the v0.10.0 [SUBCHECK_RENAMES_V100](bob/_v100_subcheck_renames.py) shim (the `ssh.x11.forwarding.*` fnmatch glob covers both `.server` and `.client`). No operator action required. **Back-compat — `--explain`**: pre-v0.10.1 `bob --explain ssh.x11_forwarding` resolves to the server-side content via the new EXPLAIN_KEY_ALIASES entry `ssh.x11_forwarding → ssh.x11.forwarding.server` (first live alias after the v0.9.0 D-3 retrait emptied the dict — the v0.9.0 D-3 rationale "keep the dict + lookup so a future rename has a one-line migration path" lands its first user in v0.10.1). **Locale**: `ssh.x11_forwarding` namespace migrated to `ssh.x11.forwarding.server` in both [en.json](bob/locales/en.json) + [fr.json](bob/locales/fr.json). New `ssh.x11.forwarding.client` + `client_detail` entries with the client-side-specific risk wording ("forwarding your display INTO a remote host"). New `explain.ssh.x11.forwarding.client.{title,why,how}` entries with dedicated client-side explanation (untrusted remote can capture screenshots, inject keystrokes, read clipboard via the X protocol's wide-open security model + 4-step remediation including `ForwardX11Trusted no` SECURITY extension). **EXPLAIN_KEYS**: 168 → **169** (+1 for the new `ssh.x11.forwarding.client`). The `test_total_keys_match_audit_count` constant was bumped; the canonical_pattern regex was extended with a new `_SSH_X11_FORWARDING_RE` exception covering the 4-segment form (sister to the existing `_FILE_PERMS_MULTI_RE` and `_SERVICES_MULTI_RE` exceptions). **CIS refs**: `ssh.x11.forwarding.server` keeps the legacy CIS:5.2.6 reference (CIS Ubuntu 22.04 L1 "Ensure SSH X11 forwarding is disabled"); `ssh.x11.forwarding.client` gets a Best practice reference (no formal CIS code for client-side ForwardX11 today). Profile overrides ([desktop.conf](bob/data/profiles/desktop.conf), [workstation.conf](bob/data/profiles/workstation.conf)) renamed accordingly. Bash completion `_EXPLAIN_KEYS` list regenerated from runtime. **Tests** 6242 → **6261** (+19): 10 dedicated tests in new [tests/test_v0101_ssh_x11_client.py](tests/test_v0101_ssh_x11_client.py) across 3 classes (`TestServerSideRename` — directive row pins canonical key + no legacy emit anywhere; `TestClientSideDetection` — new branch present + locale keys present in EN+FR + explain.* leaves present in EN+FR; `TestBackCompat` — SUBCHECK_RENAMES entry + matches_legacy_ignore covers both sub-keys + EXPLAIN_KEY_ALIASES legacy lookup + canonical pass-through). +9 elsewhere from test_total_keys / test_canonical_pattern / test_freeze_policy / test_code_format / test_ssh / test_profiles updates. 0 regression. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits` — no migration action required from v0.10.0 or v0.9.x. |
| [v0.10.0](#v0100) | 2026-06-09 | **First v0.10.x release — preparation release** opening the next BREAKING bundle window. Ships the **D-4 sub-check migration shim foundation** ([bob/_v100_subcheck_renames.py](bob/_v100_subcheck_renames.py)) so the actual D-4 splits (8 ranked candidates per the v0.10.0 sub-agent audit) can land as v0.10.1+ hardening patches without needing a second BREAKING bump. The shim ships `SUBCHECK_RENAMES_V100` mapping 14 legacy v0.9.x finding keys to `fnmatch` glob patterns: Rank 1 `ssh.x11_forwarding` → `ssh.x11.forwarding.*` (server + new client detection), Rank 2 DSA family unification (4 × 1-to-1 simple renames: `ssh.host_key_dsa` → `ssh.dsa.host_key`, `ssh.dsa_key` → `ssh.dsa.private_key`, `ssh.authorized_keys_dsa` → `ssh.dsa.authorized_key`, `ssh.known_hosts_deprecated` → `ssh.dsa.known_host`), Rank 3 `auditd.missing_sensitive_rules` → `auditd.missing.*` (4 file-family buckets), Rank 4 `samba.guest_{writable,readonly}` → `samba.share.guest_{writable,readonly}.*` (per-share-name wildcards), Rank 5 `log_rotation.journald_volatile` → `log_rotation.journald.*` (volatile vs storage_unknown), Rank 6 `firewall_rules.duplicate_found` → `firewall_rules.duplicate.*` (exact vs proto_implicit detection algos), Rank 7 `kernel_modules.risky_{fs,net}` → `kernel_modules.risky.*` (per-module-name wildcards with cap), Rank 8 `ssh.weak_{ciphers,macs,kex}` → `ssh.weak.{cipher,mac,kex}.*` (per-algorithm wildcards). The shim exposes `matches_legacy_ignore(finding_key, ignore_entry)` and `any_legacy_ignore_matches(finding_key, ignore_keys)` helpers; [bob/scoring.py::ScoreEngine.apply](bob/scoring.py) consults `any_legacy_ignore_matches` alongside the existing exact-match `finding_key in self.ignore_keys` path so a v0.9.x `ignore.yml` with the umbrella legacy name continues to silence the about-to-be-split sub-keys when v0.10.1+ ships the actual emit-site changes. **D-4 split implementations (Rank 1-8) and the F-1 parallel-check refactor (Option B per the F-1 thread-safety audit: Phase 0 sequential firewall/ports/network_context + Phase 1 `ThreadPoolExecutor(max_workers=min(8, cpu_count()))` snapshot+check fan-out with apt slot serialization + Phase 2 sequential merge in canonical `_SECTIONS` order) are intentionally deferred to v0.10.1+** hardening patches. Both sub-agent audits were run on 2026-06-08 and produced concrete file:line citations + ranked candidate lists + effort estimates: D-4 ≈ 20 h across 8 splits (the wildcard shim is the chief novelty vs the v0.9.2 simple `str → str` baseline shim), F-1 ≈ 6-8 h runner.py refactor + 4 new determinism test files (`test_v0100_parallel_determinism.py`, `_parallel_flake.py`, `_parallel_json_stable.py`, `_apt_slot.py`). The audit reports are recorded verbatim in the project session transcript and the [DOCUMENTS/SNAPSHOT.md](DOCUMENTS/SNAPSHOT.md) v0.10.0 paragraph. **`DOCUMENTS/SNAPSHOT.md` refresh** v0.7.4 → v0.9.2 + the v0.10.0 preparation paragraph — three majeures of drift documented in one paragraph each (the v0.8.x cycle: v0.8.0 drift batch + framing actions A1+A2 + silent-feature-gap audit closing v0.7.x, v0.8.1 deep-hardening 26 tiers across 3 sub-agent passes including workstation alias retrait BREAKING, v0.8.2 conservative bundle + `bob/_i18n_safe.py` consolidation, v0.8.3 hotfix UnboundLocalError audit path, v0.8.4 cleanup `is_unit_enabled` + new `DOCUMENTS/TUTORIAL{,_FR}.md`; the v0.9.x cycle: v0.9.0 BREAKING bundle closing D-1/D-2/D-3/TD-1/F-2/F-3 + bash completion `cur="="` fix, v0.9.1 hotfix F-3 message UX, v0.9.2 BaselineLoadError i18n + cross-version baseline migration shim). **Tests** 6242 → **6242** (no delta in this preparation release — the D-4 shim foundation does not change visible behavior on existing `ignore.yml` entries because the legacy keys are not yet emitted as canonical sub-keys; the shim becomes load-bearing as soon as v0.10.1 ships the first split). 0 regression. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits` — no migration action required from v0.9.x; legacy `ignore.yml` entries continue to work via the shim. |
| [v0.9.2](#v092) | 2026-06-08 | **Closes the two i18n / UX gaps documented in the v0.9.1 CHANGELOG as "deferred to v0.10.0+"** — both surfaced by the v0.9.0 cross-distro field test campaign. Both are purely additive (no BREAKING wire-format change, no risk to the golden audit path), so they fit naturally as a v0.9.x patch rather than waiting for v0.10.0. **BaselineLoadError i18n** ([bob/compare.py](bob/compare.py) + new locale namespace `compare.baseline_load.*`) — pre-v0.9.2, the four ``BaselineLoadError`` raise sites used hardcoded English messages even on FR systems (only the "Erreur :" prefix was FR via the locale key `cli.error.prefix`). Unlike the v0.9.0 F-3 issue, these raises happen AFTER ``i18n.init()`` (load_baseline is invoked from the audit path, not from ``parse_args``), so the messages CAN be properly i18n'd. Wires four new locale keys ``compare.baseline_load.{not_found, invalid_json, v1_schema, bad_shape}`` (EN + FR) via the ``bob._i18n_safe.t_or_hardcoded`` helper, with the EN baseline preserved as the fallback when i18n is not initialised. FR users now see ``Erreur : Baseline introuvable : /tmp/X — vérifie le chemin et que le fichier existe sur cette machine.`` instead of the previous EN body. **Cross-version baseline migration shim** ([bob/_v090_renames.py](bob/_v090_renames.py) `remap_finding_key` + [bob/compare.py::load_baseline](bob/compare.py)) — pre-v0.9.2, a baseline written by v0.7.x / v0.8.x carried finding keys with prefixes renamed in v0.9.0 D-1 (e.g. ``iptables_nft.input_accept``). The v0.9.0+ audit emits the canonical prefixes (``firewall_iptables.input_accept``), so the diff surfaced the SAME physical issue as both *resolved* (old key) AND *new* (new key) on the first audit post-upgrade — observed deterministically on Ubuntu 26.04 during the v0.9.0 field test campaign (see [v0.9.1 CHANGELOG entry](DOCUMENTS/CHANGELOG_FULL.md#v091) for the repro details). v0.9.2 remaps legacy prefixes via the new ``remap_finding_key`` helper at baseline load time so the comparison is clean from the first audit post-upgrade. Covers all 7 D-1 renames (``cron_audit.*`` → ``cron.*``, ``docker_audit.*`` → ``docker_hardening.*``, ``services_state.*`` → ``services_health.*``, ``ports_analysis.*`` → ``ports.*``, ``rules.*`` → ``firewall_rules.*``, ``iptables_nft.*`` → ``firewall_iptables.*``, ``firewall_stack.*`` → ``firewall_drivers.*``). Self-contained: does not modify the on-disk baseline file, does not affect baselines already written by v0.9.0+ (the remap is idempotent on canonical input). **Shared map extraction** ([bob/_v090_renames.py](bob/_v090_renames.py)) — the legacy → canonical map ``SECTION_RENAMES_V090`` was extracted from [bob/runner.py](bob/runner.py) so [bob/compare.py](bob/compare.py) can consume it without forming a circular import (runner already imports from compare). [bob/runner.py](bob/runner.py) keeps the legacy name ``_RENAMED_SECTIONS_V090`` as a back-compat re-export pointing at the shared dict (same object identity, asserted by [tests/test_v092_baseline_i18n_and_shim.py::TestV090RenamesSharedModule](tests/test_v092_baseline_i18n_and_shim.py)). **Tests** 6212 → **6242** (+30 across 4 classes: `TestV090RenamesSharedModule` (shared-map back-compat + 7-entry contract), `TestRemapFindingKey` (8 legacy → canonical parametrize + 6 canonical pass-through + 4 unaffected edge cases), `TestLoadBaselineMigrationShim` (v0.7.x / v0.8.x baselines remapped, v0.9.x pass-through, pre-v1.22 absent-field guard), `TestBaselineLoadErrorI18n` (FR rendering for 3 of the 4 messages + locale-key presence sanity)). 0 regression. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits`. |
| [v0.9.1](#v091) | 2026-06-08 | **Hotfix for the v0.9.0 F-3 message UX regression** surfaced by the cross-distro field test campaign on 5 distributions (Mint desktop / Debian 13 / Kali Rolling / Mint server FR / Ubuntu 26.04 FR). **The bug**: the ``--json-v1`` retrait error path called ``i18n.t("cli.error.json_v1_retired")`` from inside ``parse_args()`` ([bob/cli.py:282](bob/cli.py#L282)), but ``parse_args`` runs BEFORE ``i18n.init()`` in [bob/__main__.py](bob/__main__.py), so the lookup hit ``i18n.t()`` pre-init and surfaced the bracketed-fallback to the user instead of the real actionable message: `Error: [cli.error.json_v1_retired]`. Reproduced deterministically 5/5 distros × 2 locales (EN + FR) — the bracketed-fallback fires independently of system locale because the lookup itself is what fails before any translation can happen. **The fix**: inline a plain English string in the ``CLIError`` raise. Matches the convention used by every other ``CLIError`` raise in [bob/cli.py](bob/cli.py) (the other 18 raises all use English literals — the F-3 ship was the lone i18n.t() consumer in parse_args). The user now sees: *"--json-v1 was retired in v0.9.0. Schema v2 is the only supported format (v2 has been the default since v0.7.0). See CHANGELOG.md v0.9.0 entry for the field-by-field migration table from v0.6.x v1 to v2."* The now-unused locale keys ``cli.error.json_v1_retired`` (EN + FR) are removed. **Regression guards** ([tests/test_v091_cli_i18n_safety.py](tests/test_v091_cli_i18n_safety.py)): ``test_parse_args_does_not_call_i18n_t`` is an AST scan over ``parse_args()`` body — fails when any ``i18n.t(...)`` call lives inside the function. ``test_json_v1_retired_emits_actionable_message`` is a direct guard that asserts the raised message contains "v0.9.0" and one of "json-v1" / "schema", and is NOT a bracketed-fallback. Both guards prevent the bug class from recurring. **Note**: v0.9.0 is NOT yanked from PyPI — the F-3 bug only affects users who explicitly pass the retired ``--json-v1`` flag (legacy v0.6.x JSON consumers); the golden audit path is unaffected. Users on v0.9.0 hitting the bracketed-fallback can either upgrade to v0.9.1 or stop using ``--json-v1`` (the flag is retired either way). **Tests** 6210 → **6212** (+2 guards). 0 regression. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits`. |
| [v0.9.0](#v090) | 2026-06-07 | **First v0.9.x release — BREAKING bundle that closes the v0.7.0 → v0.8.x deferred architectural cleanup.** **D-1 BREAKING — 7 section renames with hard migration error path** ([bob/runner.py::_RENAMED_SECTIONS_V090](bob/runner.py)) — `cron_audit` → `cron` (drop redundant `_audit` suffix), `docker_audit` → `docker_hardening` (resolves collision with always-on `docker`), `services_state` → `services_health` (resolves collision with always-on `services`), `ports_analysis` → `ports`, `rules` → `firewall_rules` (was too generic), `iptables_nft` → `firewall_iptables` (unifies firewall_* namespace), `firewall_stack` → `firewall_drivers` ("drivers" is what the check audits). The validator `validate_check_filters` emits a fatal "renamed in v0.9.0 — use X" error when `--check` or `--skip` tokens match a legacy name; the error path fires BEFORE the generic "did you mean" suggestion so users see the precise canonical replacement. Finding key prefixes, locale namespaces (167+ keys × 2 locales), EXPLAIN_KEYS entries, [bob/data/cis_refs.json](bob/data/cis_refs.json) (20 keys), profile severity overrides ([bob/data/profiles/{container,desktop,workstation}.conf](bob/data/profiles/)), [bob/data/bob.bash-completion](bob/data/bob.bash-completion) `_SECTIONS` list, and ~167 test prefixes all migrated. Section header titles (locale-rendered, shown to the user during audit) are unchanged; the breaking surface is the script-visible token name only. **F-3 BREAKING — `--json-v1` retired** ([bob/cli.py:265-273](bob/cli.py#L265) + [bob/json_output.py](bob/json_output.py)) — the v0.6.x legacy JSON schema (default before v0.7.0) is removed. `--json-v1` raises a `CLIError` pointing at the CHANGELOG migration guide; `SCHEMA_V1_REQUIRED_KEYS` / `SCHEMA_V1_FULL_KEYS` constants + `_build_v1` + `_populate_v1_full_blocks` helpers deleted; `SUPPORTED_SCHEMA_VERSIONS = {"2"}`. v2 has been the default since v0.7.0 (4 majeures); v0.6.x was EOL since v0.7.2 (5 majeures); consumers reading the v1 layout have had ample notice. Field-by-field migration table for v1 → v2: `timestamp` → `timestamp_utc` (B-3), `info_count` field added (B-7), `network_context` is now a dict in both modes (A-2, fixes v1 type inconsistency), new `posture_escalation` block (A-4), `firewall_drivers` block replaces v1's `firewall_stack` (BREAKING name + D-1), in full mode additionally `open_ports_all` (B-5) + `deductions_raw` (B-4). **TD-1 BREAKING — `BOB_SANDBOX_LEGACY=1` trap door retired** ([bob/_sandbox.py](bob/_sandbox.py)) — announced for retrait in [SECURITY.md](SECURITY.md) since v0.7.0 + v0.8.0. Plugins always execute in the spawn'd subprocess sandbox; setting the env var has no effect. The flashy stderr WARNING + CRITICAL log machinery (`_legacy_active` / `_emit_legacy_warning` / `_run_legacy`) removed alongside. Two retirement guards in [tests/test_plugin_sandbox.py::TestLegacyTrapDoorRetired](tests/test_plugin_sandbox.py) catch any resurfacing. **D-3 cleanup — `EXPLAIN_KEY_ALIASES` retired** ([bob/explain.py:346-373](bob/explain.py#L346)) — the sole v0.5.5 alias (`services_state.service_inactive` → `enabled_inactive`, became `services_health.*` after D-1) was a bridge over a source-side drift: `services_state.py` emitted `.service_inactive` while the EXPLAIN_KEYS entry was named `.enabled_inactive`. v0.9.0 resolves the drift at the source (renamed EXPLAIN_KEYS entry to match what the check emits) and clears the alias dict + removes the one-shot deprecation warning machinery added in v0.8.2 (`_warn_alias_deprecation` + `_WARNED_ALIASES`). The empty `EXPLAIN_KEY_ALIASES` dict + the `normalize_key` lookup are kept so a future rename has a one-line migration path. **D-2 internal — `_ALL_SECTIONS` + `_ALWAYS_ON_SECTIONS` fusion** ([bob/runner.py::_SECTIONS](bob/runner.py)) — new `_SECTIONS: tuple[_Section(name, always_on), ...]` is the single source of truth (adding a section means one entry instead of remembering which of two tuples). The legacy `_ALL_SECTIONS` / `_ALWAYS_ON_SECTIONS` are derived views built once at import time for back-compat; external consumers ([bob/__main__.py](bob/__main__.py) + tests) keep using the legacy names unchanged. **F-2 NEW — `--diff [PATH]` cross-machine compare** ([bob/cli.py](bob/cli.py) + [bob/compare.py::load_baseline](bob/compare.py)) — the `-D / --diff` flag now optionally takes a baseline JSON file path. With `--diff=PATH` or `--diff PATH`, the compare loads the file in strict mode (missing/broken/v1-schema = `BaselineLoadError` → `CLIError` with actionable message) instead of the silent v0.8.x "no baseline yet" fallback. `AuditBaseline.hostname` (new field) is captured at `build_baseline` time so cross-machine compare surfaces a friendly "ℹ Baseline was recorded on 'X'; comparing against current host 'Y'" notice; pre-v0.9.0 baselines without the field cause no notice. Bare `--diff` / `-D` keeps the v0.8.x local auto-managed baseline behaviour. Unlocks: cross-machine drift compare (audit on host A → save → `scp` to host B → `sudo bob --diff hostA.json` on host B), historical compare against retained baselines (`baseline-2026-01-01.json`), prod vs staging compare from one machine. **Bug fix — `bob --check=<TAB><TAB>` without sudo** ([bob/data/bob.bash-completion](bob/data/bob.bash-completion)) — companion to the v0.8.2 sudo-dispatcher walk-back guard. Some bash versions place the completion cursor on the literal `=` token (giving `cur="="`, `prev="--check"`) instead of on a trailing empty word; the script now normalises `cur="="` → `cur=""` before the prefix-match branches, restoring TAB×2 list display under non-sudo invocations. **Tests** 6246 → **6210** (net −36 — 53 v1 baseline + v0.8.2 deprecation-warning tests retired, 17 new F-2 tests). 0 regression. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). Upgrade with manual review: `pipx upgrade bodyguard-of-bits`; users with scripts using `--check=<old_name>`, `--json-v1`, or `BOB_SANDBOX_LEGACY=1` must migrate per the tables above. |
| [v0.8.4](#v084) | 2026-06-06 | **Final v0.8.x release — cleanup batch before the v0.9.0 BREAKING bundle.** **Dead code retirement** ([bob/checks/_run.py](bob/checks/_run.py)) — ``is_unit_enabled(name, timeout)`` was added in v0.5.0 (Phase 1 #7) as the symmetric mirror of ``is_unit_active`` and documented in the monitoring list as "no immediate consumer — to be reviewed each v0.5.x release". 7 months and 4 minor versions later (v0.5.x → v0.6.x → v0.7.x → v0.8.x), the grep is unchanged: still zero consumers in ``bob/`` or ``tests/``, and ``services.py::_detect_single_unit_state`` continues to use its own ``_run`` call as designed. The API-symmetry argument has not held — removed. Historical CHANGELOG v0.5.0 entries (English + French + FULL mirrors) are preserved as-is — they accurately describe what shipped at the time. **New tutorial** ([DOCUMENTS/TUTORIAL.md](DOCUMENTS/TUTORIAL.md) + [DOCUMENTS/TUTORIAL_FR.md](DOCUMENTS/TUTORIAL_FR.md)) — 269 lines × 2 locales, end-to-end first-time-user walkthrough covering: what BOB does (one sentence) + what BOB is NOT, ``pipx install`` + ``sudo bob`` PATH gotcha + ``--install-completion``, first audit + reading the score + the hypotheses footer, ``--explain KEY`` + picker + tab-completion, ``--fix`` dry-run + ``--fix --apply`` contract, profile selection (server / desktop / workstation / container), ``--ignore`` + ``--unignore`` + ``--show-ignored`` no-noise path, ``--install-cron`` + ``--webhook=`` + ``--test-webhook`` smoke, ``--diff`` + ``--history`` + ``--watch`` baseline workflows, JSON / CSV / Markdown / HTML formats + ``-q`` exit codes + ``--target=N``, common scenarios + pointers to README_TECH / AUTOMATION / SECURITY / CHANGELOG. Linked from [README.md](README.md) + [README_FR.md](README_FR.md) "See also" / "Voir aussi" sections as the first entry so first-time readers land here before the technical reference. The deferred ``tutorial`` item from the v0.9.0 backlog moved into v0.8.4 because it is pure docs with zero code surface — no point parking pure documentation behind a BREAKING bundle. **Roadmap closures** — the v0.5.0 release-monitoring list ([[feedback_release_monitoring]] memory) is closed: ``is_unit_enabled`` DELETED, ``width=62`` parameter of ``print_titled_box`` KEPT off-monitor (4 sites use the default, 7 months of stability = API stable de facto, removal would break the public API without gain). The compare-breakdown-diff feature roadmap ([[project_future_compare_breakdown_diff]] memory) is also killed — opened in v0.3.0 (2026-05-08), zero user signal across 5 majeures (v0.4 / v0.5 / v0.6 / v0.7 / v0.8). The pattern: if a feature stays dormant 5 majeures without signal, the market has spoken — kill rather than keep indefinitely. **Tests** 6246 → **6246** (no delta — the deleted helper had no test coverage to delete). 0 regression. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). **Next**: **v0.9.0 BREAKING bundle** — D-1 sections renumber + ``emit_section()`` naming, D-2 fusion ``_ALL_SECTIONS`` + ``_ALWAYS_ON_SECTIONS``, D-4 sub-checks granulaires (rename keys → breaks ignore.yml entries), ``BOB_SANDBOX_LEGACY`` trap door retrait, parallel checks (``concurrent.futures``), ``--diff <baseline.json>`` cross-machine compare. v0.8.x is closed; further v0.8.x patches will only ship for security regressions. Upgrade: ``pipx upgrade bodyguard-of-bits``. |
| [v0.8.3](#v083) | 2026-06-06 | **HOTFIX — v0.8.2 audit path crashed with `UnboundLocalError` on every non `--test-webhook` invocation.** Root cause: the v0.8.2 `--test-webhook` handler did `from bob.config import UserConfig` *inside* `main()` ([bob/__main__.py:213](bob/__main__.py#L213)). Python's local-scope analyzer treated `UserConfig` as a function-local name for the entire body, so line 298 (audit path) raised `UnboundLocalError: cannot access local variable 'UserConfig' where it is not associated with a value` on every regular `bob` invocation. The smoke-plugin-on-CI guard caught it but only AFTER v0.8.2 was already published on PyPI. The same shadowing pattern existed for `os` and `traceback` inside the top-level except handler. **Fix**: removed the redundant local imports of `UserConfig` + `os`; promoted `traceback` to a module-scope import. The module-level `from bob.config import UserConfig` (line 26) is now the single binding. **Regression guard**: new [tests/test_v083_main_scope_guard.py](tests/test_v083_main_scope_guard.py) (2 tests) statically asserts via `ast` that `main()` does not shadow any name imported at module scope — a future contributor who adds another defensive re-import inside `main()` fails this test before the audit path crashes for users. **Lesson**: unit tests (6244 verts on v0.8.2) didn't catch this because they exercise either the `--test-webhook` branch (which goes through the local import and binds `UserConfig`) OR the audit path (mocked at `UserConfig.load` so the name resolves via the mock). The integration smoke is what surfaced the real crash. The new static guard would have caught it before ship. **v0.8.2 is broken on PyPI — users must `pipx upgrade bodyguard-of-bits` immediately.** Tests 6244 → **6246** (+2 guard). 0 regression. **v0.7.x remains EOL** (declared in v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). |
| [v0.8.2](#v082) | 2026-06-06 | **YANKED 2026-06-06 — audit path crash, see [v0.8.3](#v083).** **Conservative-bundle patch — 6 user-facing + DX items, no BREAKING.** **Bash completion v0.8.2** ([bob/data/bob.bash-completion](bob/data/bob.bash-completion)) — `_SECTIONS` + `_EXPLAIN_KEYS` lists auto-synced with runtime, added `--unignore=KEY` / `--ignore=KEY` / `--explain KEY` value completions (was generic / missing), `--json-v1` + `--test-webhook` in long_opts, stale workstation alias comment retired, **sudo-dispatcher `=` fix** (commit `2a62bf3` — user-reported: `sudo bob --check=s<TAB>` returned zero candidates because bash-completion's sudo dispatcher invokes `_bob` with `$prev` set to the literal `=` instead of the option name when `=` stays in COMP_WORDBREAKS; defensive walk-back guard restores value-narrowing under both `sudo` and non-`sudo` for every `--<option>=<partial>`). Plus 21 sync-guard + functional tests in [tests/test_v082_bash_completion.py](tests/test_v082_bash_completion.py) including the EN/FR `_SECTIONS` ↔ `_ALL_SECTIONS` parity guard so a new check section that ships without updating the completion script fails CI. **i18n consolidation** ([bob/_i18n_safe.py](bob/_i18n_safe.py)) — new module exposes `make_fallback_t(labels)` factory + `t_or_hardcoded(key, fallback)` helper, replaces 4 hand-rolled `_fallback_t` bodies + 1 `_t_or_hardcoded` across `config.py` + `webhook.py` + `markdown_output.py` + `html_output.py` + `__main__.py`. Pre-v0.8.2 the bodies had drifted (markdown_output skipped `.format()` entirely, html_output conditioned on kwargs presence, config / webhook always formatted) — single source of truth + consistent format-or-keep-template-on-error semantics across all 5 modules. **`--test-webhook` smoke command** ([bob/webhook.py::test_webhook](bob/webhook.py) + [bob/__main__.py:190-220](bob/__main__.py#L190)) — POST a minimal `bob_smoke_test`-tagged payload to the configured webhook URL and exit. Reuses every URL-validation guard from `send_webhook` (scheme + plain-http + `BOB_WEBHOOK_ALLOW_INSECURE` escape hatch) so a passing smoke test proves the audit-time POST will reach the receiver. 4 new locale keys EN+FR under `cli.test_webhook.*`. Pre-v0.8.2 the only way to validate a fresh `bob --webhook=URL` setup was to run a full audit (~30 s + needs sudo). **`--check=list` section descriptions** ([bob/__main__.py:115-152](bob/__main__.py#L115) + `sections.descriptions.*` locale) — each of the 44 sections (34 filterable + 10 always-on) renders with a one-line technical description sourced from the new `sections.descriptions.<name>` namespace. EN + FR descriptions added for all 44. Pre-v0.8.2 `bob --check=list` dumped raw section names with no context, leaving operators guessing what `hardening` vs `kernel_hardening` actually audit. Tests pin the namespace ↔ `_ALL_SECTIONS ∪ _ALWAYS_ON_SECTIONS` parity so a new section without description fails CI. **D-3 deprecation warning on `EXPLAIN_KEY_ALIASES` use** ([bob/explain.py:368-432](bob/explain.py#L368)) — hitting a legacy alias key in `normalize_key()` emits a one-shot `logger.warning` pointing at the canonical name + the planned v0.9.0 retrait timeline. The warning is logger-only (no stdout pollution) so machine-readable JSON / CSV / Markdown outputs stay clean — operators see it in `--detailed` `.log` reports + journald when scheduled via cron. Sets up the documented v0.9.0 alias retrait path described in `SECURITY.md` (back-compat contract). Tests pin one-warning-per-alias-per-process semantics so a watch-mode session doesn't spam the log stream. **Locale linter** ([scripts/lint_locales.py](scripts/lint_locales.py) — dev tool, not shipped at runtime) catches the drift classes audit passes 7 + 8 surfaced before they hit the runtime guards: strict EN/FR key parity (1941 keys × 2 locales, 0 drift), placeholder-set parity (every `{name}` in EN appears in FR and vice-versa — protects `str.format(**kwargs)` from KeyError crashes), trailing-whitespace contract for the `cli.error.*_prefix` keys (I-2 pass 7 invariant — bumped from runtime test guard to standalone tool), empty/long value sanity (catches copy-paste mistakes like accidentally pasted documents). Linter runs in `tests/test_v082_items.py::TestLocaleLinterSmoke` so a drift fails CI even without running the script directly. **Tests** 6198 → **6244** (+46 net). 0 regression. **D-1 / D-2 / D-4 + BOB_SANDBOX_LEGACY retrait + parallel checks + `--diff <baseline.json>` + tutorial** explicitly deferred to **v0.9.0** as a BREAKING-bundle architectural cleanup (D-1 / D-2 / D-4 affect script-visible names, parallel checks touches threading invariants, retrait removes a documented env-var trap door). **v0.7.x remains EOL** (formal declaration in [SECURITY.md](SECURITY.md) since v0.8.1); **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits`. User-facing wins: `bob --check=list` now self-documenting; `bob --test-webhook` works; bash completion of `--unignore` + `--ignore` + `--explain` keys now suggests canonical EXPLAIN_KEYS entries; profile parity guard surfaces alias deprecation in the log stream. |
| [v0.8.1](#v081) | 2026-06-05 | **Minor maintenance + deep-hardening audit cycle.** Closes **26 gap tiers** across 3 sub-agent audit passes (6/7/8) + an initial drift / framing / silent-feature-gap sweep. **Initial cycle (12 tiers)** — **T6** profile severity coverage audit ([desktop.conf](bob/data/profiles/desktop.conf) +24 overrides, [workstation.conf](bob/data/profiles/workstation.conf) +28 overrides, 30% coverage of actionable warn/alert keys); **T10** i18n exceptions in webhook/config/__main__ (14 new locale keys EN+FR + fallback dict pattern from v0.7.2 M-4); **workstation alias retrait BREAKING** ([bob/profiles.py:123-124](bob/profiles.py#L123)) — the v0.1.0 alias that silently redirected `bob -p workstation` to the desktop profile has been retired so workstation.conf is now a first-class business-context profile (keeps `backup.no_backup` / `auditd.*` / `mac_policy.apparmor_no_enforce` at WARN while relaxing personal-use ergonomics). Users on the alias see different severity output for those 3 finding families — migration: drop a copy of `desktop.conf` at `~/.config/bob/profiles/workstation.conf` to restore v0.8.0 semantics. **T11** Finding.detail field parity across CSV + JSON v1/v2 ([bob/csv_output.py:25-44](bob/csv_output.py#L25) + [bob/json_output.py:240-251 + 448-460](bob/json_output.py#L240) — additive, no schema break). **T26** explain dispatch for `services.exposed.<id>` ([bob/explain.py:433-510](bob/explain.py#L433)) via existing `service_risk.<label_transform>.{level,exposure,threat}` locale content (38 services auto-explainable, zero per-service maintenance). **T27** webhook payload `detail` + `note` parity ([bob/webhook.py:150-159 + 185-187](bob/webhook.py#L150) — generic + Slack inline). **T31/T37** nature backfill 90 warn/alert sites so `bob --fix --apply` (filtered by `f.nature == "action"`) actually picks up the actionable findings — pre-fix 88% were silently invisible to fix mode. **T32** profile typo validation ([bob/profiles.py::_recognised_override_keys](bob/profiles.py)) with `logger.warning` on unknown override keys + canonical exposure set. **T39** orphan `service_risk.ollama_llm_server` cleanup (replaced by `ollama_local_llm` in v0.8.0 T2). **T57** `--unignore` CLI path + `remove_ignore_key` helper + 2 locale keys ([bob/ignore.py:127-184](bob/ignore.py#L127) + man page entry). **T60** `_t_or_hardcoded` helper wires `cli.error.*` prefixes through `main()` catch-all + `parse_args` error path without breaking pre-init scenarios. **T74** webhook URL credential redaction ([bob/webhook.py::redact_url_credentials](bob/webhook.py) strips `user:pass@` before display on stdout / on-disk `.log` / WebhookError messages). **Pass 6 audit (5 findings)** — I-1 ignore.yml comment preservation in remove_ignore_key (walk lines instead of canonical rewrite); M-1 T32 regex accepts digit-containing keys (`fail2ban.ssh_jail_active`, `ipv6.ufw_disabled_no_listeners`) + `file_perms.*` permissive prefix; M-2 services.exposure canonical enum set + bogus `services.exposure.<svc_id>` rejection; M-3 `service_label_to_subkey` transform consolidated in `bob/registry.py` (single source of truth across explain.py + 2 display.py sites — closes 3-way drift surfaced by T26 docstring claim); M-4 --unignore documented in `man/bob.1` + mutual-exclusion guard with `--ignore`. **Pass 7 audit (3 findings)** — I-1 `remove_ignore_key` regex matches loader grammar (multi-space, tab between `-` and `key:` now removable — pre-fix the misleading "Key not present" message); **I-2 FR colon typography drift on T10/T60 prefixes** — colon-space now embedded in locale values (FR `"Erreur : "`, EN `"Error: "`) so no more `"Avertissement : échec du webhook: …"` double-colon mixed style; M-1 `man/bob.1 --show-ignored` description rewrite (was claiming "list keys and exit", actually displays muted findings inline during the audit). **Pass 8 audit (5 findings)** — I-1 `_KEY_LINE_RE` unified (drop `\s*$` anchor so loader sees inline-commented entries; the pass-7 sibling regex was dead code masked by the defensive `load_ignore_keys` guard); I-2 `runner.py` 3 hardcoded `Warning:` prefix sites i18n'd via new `cli.error.warning_prefix` + `cli.runner.*` namespace (6 new locale keys EN+FR); M-1 `--webhook-secret` phantom removed from `_VALUE_TAKING_OPTS` (1-line dead-code cleanup, fixes inconsistent errors between `--opt val` / `--opt=val` forms); M-2 `_ufw_inactive` variants narrowed to `(no_rule, loopback_no_rule)` only (the runtime emits them ONLY for those 2 exposures — pre-pass-8 permissive registration leaked the same false-positive class M-2 pass 6 was meant to close); M-3 `t()` trailing-whitespace contract test pin (defends I-2 pass 7 against future locale-normaliser scripts). **Plus** — `tests/conftest.py` autouse `_ensure_i18n_initialised_for_tests` mirrors the production invariant (i18n.init before runner.py is reached) in the test environment, with opt-out for `test_i18n.py` (which exercises the pre-init bracketed-fallback contract). **Tests** 5521 → **6198** (+677 net). 0 regression. ~190 dedicated v0.8.1 tests across `test_t10_exception_i18n` / `test_t11_t26_v081` / `test_t27_t31_t32_v081` / `test_t39_t57_t60_v081` / `test_t74_v081` / `test_v081_audit_fixes` / `test_v081_audit_pass7` / `test_v081_audit_pass8`. **v0.7.x is now end-of-life as of 2026-06-05** (formal declaration in [SECURITY.md](SECURITY.md), mirroring the pattern that retired v0.6.x in v0.7.2). No security fixes will be backported. Users on v0.7.x must `pipx upgrade bodyguard-of-bits` to v0.8.x for security patches. **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits`. User-facing behavioural shifts: workstation profile is now distinct from desktop (backup / auditd / mac_policy stay at WARN); 4 findings that were OK at 10/10 may now deduct (T3 v0.8.0 + T31 v0.8.1 — `--fix --apply` covers 100% instead of 12% of actionable findings); `bob --explain services.exposed.<svc_id>` produces real content for the 38 registered services; webhook URLs with embedded credentials display redacted form `https://[REDACTED]@host/path`; FR audits no longer mix `:` and ` : ` typography across error/warning prefixes; profile overrides with typos in keys emit a `logger.warning` instead of silently no-op'ing. |
| [v0.8.0](#v080) | 2026-06-04 | **Minor major — drift batch + framing actions + silent-feature-gap audit.** Closes the v0.7.x cycle (4 hardening patches v0.7.1→v0.7.4) and opens v0.8.x. **Drift batch (11 items, anti-drift)** — `CHANGELOG_FR.md` + `DOCUMENTS/CHANGELOG_FULL_FR.md` backfill of v0.7.0→v0.7.4 (5 entries previously missing — FR readers saw the project frozen at v0.7.0b2 while PyPI was at v0.7.4); man pages `.TH` bumped to current version + date; `DOCUMENTS/README_TECH{,_FR}.md` shields.io version badge bumped; `debian/changelog` backfilled with full v0.7.x + v0.6.x history; `packaging/rpm/bob.spec` `%changelog` mirrors; `DOCUMENTS/TESTING.md` per-version table backfilled; `README.md` + `README_FR.md` Install section synced with the 4-substep `README_TECH.md` flow (Prereq / Install / Enable sudo + bash completion / Uninstall). **Framing actions (anti-sur-claim)** — **A1** ([bob/display.py:581](bob/display.py#L581) + new locale key `summary.context_disclaimer`): `print_audit_summary` appends one `ℹ` footer line after the existing scope notes — *"Verdict conditioned by the profile and network context above. BOB is a hardening auditor, not a threat-modeling engine — interpret accordingly."* The profile + network context are already shown in the box (rows `Profile` + `Network context`), so the disclaimer rides on those instead of re-emitting a templated header. Pure UI, makes the *conditioning* of the score visible alongside the verdict. **A2** ([README.md](README.md) + [SECURITY.md](SECURITY.md) + FR mirrors): new "What BOB is / is NOT" section — BOB audits configuration hardening under a chosen profile, is NOT a threat-modeling engine, NOT an active reachability scanner, NOT an autonomous verdict system. Pre-empts the ChatGPT-class "BOB sur-claims" misreading. **Silent feature-gap audit (8 tiers, post-drift sweep)** — **T1** +51 `--explain` entries for previously-uncovered WARN/ALERT findings, opens 15 new EXPLAIN prefixes (`backup, ddns, docker, fail2ban, firewall_stack, iptables_nft, log_rotation, logs, mac_policy, network_context, ntp, ports, rootkit, services, smtp`); EXPLAIN_KEYS baseline 117 keys / 30 prefixes → **168 keys / 45 prefixes**. **T1bis** ([bob/checks/ssh/_directives.py](bob/checks/ssh/_directives.py)) `_BadDirective` dataclass gains `cmd_template: str = ""` field; 8 directives now ship cmd= (PermitEmptyPasswords / X11Forwarding / IgnoreRhosts / HostbasedAuthentication / PermitUserEnvironment / StrictModes / AllowTcpForwarding / PubkeyAuthentication) so `bob --fix --apply` suggests a sed-line instead of dumping "manual fix required". **T2** ([bob/data/services.json](bob/data/services.json)) registry 32 → **38** with 6 modern services (Tailscale, Caddy, AdGuard Home, Vaultwarden Password Manager, Ollama, Authelia) — full schema entries (id+label+packages+services+ports+risk+config_key+detection). **T3** ([bob/checks/services.py](bob/checks/services.py) + [bob/checks/firewall.py](bob/checks/firewall.py) + [bob/checks/virtualization.py](bob/checks/virtualization.py)) `warn_with_deduction` backfill: `services.state.installed_inactive_critical` +1pt, `services.state.active_disabled` +1pt, `firewall.policy_unknown` +2pts, `virt.snap_network` capped 2pts cumulative. Pre-fix these surfaced as bare WARN with zero scoring impact while documented as "improvement" findings. **T4** ([bob/locales/{en,fr}.json](bob/locales/en.json)) 5 missing `service_risk.<id>.{level,exposure,threat}` blocks backfilled (SMTP / NFS / Jenkins / OpenVPN / Squid — had IDs in services.json since v0.5.x but zero locale coverage). **T7** ([bob/data/profiles/desktop.conf](bob/data/profiles/desktop.conf) + [workstation.conf](bob/data/profiles/workstation.conf)) rename `hardening.auto_updates_missing` → `updates.unattended_not_configured` (the actually-emitted key). Pre-fix the profile override didn't match the runtime key, so users overriding severity on desktop/workstation profiles saw the override silently no-op. **T9** ([bob/markdown_output.py](bob/markdown_output.py) + [bob/html_output.py](bob/html_output.py) + new `markdown_output.{note,detail}_label` / `html_output.{note,detail}_label` keys) Markdown + HTML now surface `Finding.detail` and `Finding.note` — pre-v0.8.0 those two fields were terminal+JSON+text-only despite both formats being declared format-parity sinks. **New test guards (4 files)** — [tests/test_runner.py](tests/test_runner.py) (smoke on `_sec()` orchestrator — `bob/runner.py` was the highest out-degree module without a dedicated test), [tests/test_explain_coverage.py](tests/test_explain_coverage.py) (each actionable finding key has an `--explain` entry), [tests/test_fix_coverage.py](tests/test_fix_coverage.py) (each actionable finding has `cmd=` OR sits in `_MANUAL_BY_DESIGN` whitelist with inline rationale OR `_HELPER_DISPATCH_SITES` for non-literal keys emitted from helpers), [tests/test_doc_version_consistency.py](tests/test_doc_version_consistency.py) (5th CI guard — man × 3 + shields × 2 + debian top + rpm Version + CHANGELOG × 2 top row + CHANGELOG_FULL × 2 top section vs pyproject.toml; pattern from v0.7.0b2 release-engineering lesson, broader scope). **Cleanup** — orphan `__version__ = "1.14.0"` removed from `bob/checks/__init__.py` (copy-paste from v0.1.0, unused). `BOB_DEBUG` env var documented in `SECURITY.md` trap-door inventory (was undocumented alongside `BOB_SHARE` / `BOB_WEBHOOK_ALLOW_INSECURE` / `BOB_SANDBOX_LEGACY`). **Deferred to v0.8.1**: Tier 6 (profile severity coverage audit — 94% of findings use default severity, ~20-30 keys are candidates for profile overrides), Tier 10 (i18n 27 hardcoded English exception messages in `webhook.py` + `config.py`). **D-1..D-4 contract** (sections renumber / fusion `_ALL_SECTIONS`+`_ALWAYS_ON_SECTIONS` / `EXPLAIN_KEY_ALIASES` retraits / sub-checks granulaires) remains open for v0.8.x continuation. Tests: 5521 → **~6008** (+487 net). 0 regression. Upgrade: `pipx upgrade bodyguard-of-bits`. User-facing behavioural shifts: summary box now leads with the "Hypotheses:" line on every audit, 8 SSH directives drop the "manual fix required" footer and ship cmd= instead, 4 audit findings that were OK at score 10/10 now deduct points (services inactive+critical, services active+disabled, firewall policy unknown, snap network virt), and 6 modern services (Tailscale/Caddy/etc.) get full detection + risk classification. **v0.6.x remains EOL** (declared in v0.7.2). |
| [v0.7.4](#v074) | 2026-06-02 | **Fourth v0.7.x hardening patch** — second deep-audit pass after v0.7.3, same bundle-aggressive pattern (6I + 8M ship, no defer). **I-1 `--quiet` output leaks** ([bob/runner.py:467](bob/runner.py#L467) + [bob/display.py:206](bob/display.py#L206)): Docker exposed-ports block, `display_ports_overview`, `display_geoip_notice`, `display_log_results` all printed unconditionally even with `-q`. Contract break — `bob -q | cat` was non-empty when geoip2 was unavailable or Docker exposed ports. Now all four sites honour `config.quiet`; `.log` report unaffected. **I-2 `--explain` UI labels i18n** ([bob/explain.py](bob/explain.py) + new `explain.ui.*` keys): `WHY IT IS A RISK`, `HOW TO FIX`, `SCORING`, `Domain`, `Tool cap`, `Impact`, curses picker/detail headers, "No explanation available for", "Run 'sudo bob --explain list'…" — all hardcoded English on a `--french` audit. 18 new locale keys land under `explain.ui.*`. **I-3 `__main__` CLI flows i18n** ([bob/__main__.py](bob/__main__.py) + new `cli.list.*` / `cli.ignore.*` / `cli.baseline.*` / `compare.no_baseline_yet` keys): `--check=list`, `--ignore=KEY` invalid + success feedback, `--reset-baseline` deleted/not-found, `--diff` no-baseline-yet. All localised. **I-4 webhook scheme symmetry with `config.py`** ([bob/config.py:261](bob/config.py#L261)): v0.7.3 I-5 made `webhook.py::send_webhook` case-insensitive (`url.lower()`); the sister `UserConfig.set_webhook_url` stayed case-sensitive. Result: `bob --webhook HTTPS://...` sent OK at runtime then silently failed to persist (the swallowed `ValueError` left the saved config unchanged, next cron audit posted nowhere). Mirrors the v0.7.3 fix. **I-5 services.py `_PRIVATE_ADDR` → sysinfo helpers** ([bob/checks/services.py:38](bob/checks/services.py#L38)): the v0.5.6 architectural unification of private-IP detection retired the hand-rolled regex in `bob/checks/logs.py` but left a duplicate in `services.py`. Drift risk on every future CGNAT/ULA range update. Now delegates to `sysinfo._is_private_or_loopback_ipv4`/`_ipv6` — single source of truth. **I-6 CSV `risk` aligned to JSON v1 (BREAKING)** ([bob/csv_output.py:55](bob/csv_output.py#L55)): pre-v0.7.4 CSV `risk` used `engine.effective_level.value` (posture-escalated) while JSON v1 `risk` was restored to `engine.level.value` (score-only) by v0.7.1 I-3. Consumers comparing CSV and JSON v1 on the same posture-escalated audit saw different `risk` values. CSV now matches JSON v1 — **wire-format break** for CSV consumers relying on the escalated value. **M-1 `recurrence.py` dead `.tmp` cleanup** ([bob/recurrence.py:67](bob/recurrence.py#L67)): post-v0.7.2 M-7 tmp names are random (`tempfile.mkstemp`), so `dest.with_name(name+".tmp").unlink(missing_ok=True)` was dead code. `_atomic.atomic_write` cleans tmp leftovers itself. **M-2 CLI value-missing UX** ([bob/cli.py:533](bob/cli.py#L533)): `bob -l` (no value) previously fell through to "Unknown option: '-l'" because the value-form check's `i+1 < len(argv)` failed and every later elif missed. Now distinguishes "value-taking option with missing value" from "truly unknown option" via a `_VALUE_TAKING_OPTS` frozenset — `-e/--explain` and `--watch` are intentionally absent because they have documented no-arg forms. **M-3 cron wrapper PYTHONPATH trailing-colon footgun** ([bob/cron/_io.py:45](bob/cron/_io.py#L45)): `export PYTHONPATH=path:"$PYTHONPATH"` produced `path:` (trailing colon) when `$PYTHONPATH` was unset (cron default). Python interprets the trailing colon as "also search CWD" — under cron the CWD is /root for a root-launched job, so anything in `/root/foo.py` would shadow stdlib. Now `path${PYTHONPATH:+:$PYTHONPATH}` — no trailing colon when unset, semantically equivalent when set. **M-4 `_sandbox.py` + `plugin_checks.py` warn i18n + `key=`** ([bob/_sandbox.py:800](bob/_sandbox.py#L800) + [bob/plugin_checks.py:175](bob/plugin_checks.py#L175)): 7 sandbox WARN paths (timeout / no_result / bad_payload / error / rejected / runner_error / missing_run_check / bad_return / crashed) emitted English hardcoded messages AND no `key=`, so `bob --ignore plugin.sandbox.timeout` had no key to match. Now each WARN carries a stable `key=` + an optional `t` callable falls back to English when locales aren't wired. 9 new locale keys under `plugin.sandbox.*`. **M-5 `report.py::write_header` banner.* labels** ([bob/report.py:219](bob/report.py#L219)): the `--detailed` `.log` report begins with hardcoded English `[SYSTEM INFORMATION]` + `System` / `Host` / `Kernel` / `Firewall` / `User` / `Language` / `Port config` — same Frenglish gap as v0.7.3 M-5 fixed for write_summary. Now accepts an optional `labels=` dict (pattern from v0.7.3 M-5). 4 new locale keys (`banner.system_information` / `firewall` / `language` / `port_config`); the 3 pre-existing `banner.system` / `host` / `kernel` / `user` are reused. **M-6 `fixes.py` Frenglish parenthetical** ([bob/fixes.py:108](bob/fixes.py#L108)): `print(f"  ✖ {t('fixes.manual')} (unsafe shell syntax in command)")` — the parenthetical was hardcoded English. New `fixes.skipped_unsafe_shell` key. **M-7 `json_output` uses `engine.domain_scores` cache** ([bob/json_output.py:215](bob/json_output.py#L215) + [bob/json_output.py:418](bob/json_output.py#L418)): pre-v0.7.4 the JSON v1/v2 builders called `compute_domain_scores(engine)` to assemble the `domain_scores` block while the engine already held the cached values from `apply_domain_score_override`. Today equivalent; future drift risk eliminated. Cache-first with a fresh-compute fallback for engines without override applied. **M-8 `set_posture_from_engine` bool subclass-of-int reject** ([bob/scoring.py:706](bob/scoring.py#L706)): `isinstance(True, int)` is True (bool is a subclass of int), so a `firewall: True` in `domain_scores` would slip past the `elif isinstance(int)` branch and TypeError-fail in `set_posture`'s explicit-bool guard. The helper claimed to "centralise the dict-vs-int guard" — now genuinely defensive against bool too. **Skipped per `feedback-conservative-refactor`** (none this cycle — every triaged candidate shipped). Tests: 5502 → **5521** (+19 net): 1 CSV/JSON v1 risk parity pin (I-6), 1 webhook scheme symmetry pin (I-4), 4 display-quiet pins (I-1 geoip), 9 CLI value-missing UX pins (M-2 incl. --explain / --watch no-arg sanity), 1 cron PYTHONPATH safe-form pin (M-3), 3 set_posture_from_engine bool/int/dict normalisation pins (M-8). 0 regression. **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits`. User-facing behavioural shifts: CSV column `risk` is now score-derived (BREAKING for posture-aware CSV consumers — migrate to JSON v2 `posture_escalation.score_level` for the escalated value); `--explain`, `--check=list`, `--ignore=KEY`, `--reset-baseline`, `--diff` no-baseline are now fully French in FR locale; `bob -l` (and other value-taking flags) now error with "requires a value" instead of "Unknown option"; webhook URL scheme matching is case-insensitive on persist as well as send; cron wrappers regenerated via `sudo bob --install-cron` no longer produce a `PATH:` trailing-colon. |
| [v0.7.3](#v073) | 2026-06-02 | **Third v0.7.x hardening patch** — full deep-audit pass (sub-agent + 14 confirmed fixes + 5 justified skips). Next-day patch following the same-day v0.7.0+v0.7.1+v0.7.2 cycle. **I-1 FR locale "finding" → "découverte"** ([bob/locales/fr.json](bob/locales/fr.json) `html_output.no_findings` / `findings_count`): the v0.7.2 M-4 extraction left the English word "finding" in two FR entries. Now consistent with the rest of the codebase. **I-2 `completion.py` SUDO_USER not validated** ([bob/completion.py:36-37](bob/completion.py#L36-L37)): `pwd.getpwnam(sudo_user)` raised unhandled `KeyError` on a malformed/spoofed value. Now guarded via the same regex pattern + `try/except KeyError` used in `sysinfo.get_user_home`. **I-3 CSV column `section` → `nature` (BREAKING)** ([bob/csv_output.py:26](bob/csv_output.py#L26)): pre-v0.7.3 the CSV had a column labelled `section` that actually carried `Finding.nature` (`"action"` / `"improvement"` / `"structural"` / `""`). Tests baked in the mislabel. External CSV consumers parsing the `section` column receive nature strings, not audit section names. Renamed the header to match the content. CSV has no `schema_version` field so this is a wire-format break for consumers — see CHANGELOG. **I-4 `manage_logs.py` 3 bare `input()` → `safe_input()`** ([bob/manage_logs.py:104, 365, 388](bob/manage_logs.py#L104)): violated project convention #2 (every interactive prompt through `bob._tty.safe_input`). Line 104 retains bare `input()` because of readline integration; lines 365/388 had no such excuse. **I-5 webhook URL scheme case-insensitive** ([bob/webhook.py:206](bob/webhook.py#L206)): `HTTPS://example.com` was rejected with the bogus "must start with http(s)://" error instead of falling through to the legitimate http-insecure guard. RFC 3986 allows any case; normalised via `url.lower()` for the scheme check. **I-6 markdown/html level guard convergence** ([bob/markdown_output.py:131-138](bob/markdown_output.py#L131-L138)): the two M-4 extractions in v0.7.2 used different idioms for the `effective_level` fallback (markdown silently treated empty `.value` as unknown; html only branched on `is None`). Converged on the safer html idiom. **M-2 `--lang VALUE` space-separated form accepted** ([bob/cli.py:236-243](bob/cli.py#L236-L243)): pre-v0.7.3 only `--lang=VALUE` was accepted, but every other value-taking option supports both forms. **M-3 `bob -e ""` empty key rejected** ([bob/cli.py:308-313](bob/cli.py#L308-L313)): pre-v0.7.3 the empty arg was silently consumed (skipping the interactive picker AND the explain branch). **M-4 argv hardening on `-w` / `--ignore` / `--output-dir`** ([bob/cli.py](bob/cli.py)): the space-form check now requires the next arg to not start with `-`, so typos like `bob -w --quiet` error at parse time instead of silently setting `webhook_url="--quiet"`. **M-5 `report.py` field labels i18n** ([bob/report.py:333-360](bob/report.py#L333-L360)): the 6 hardcoded English labels ("OK", "Warning", "Alert", "Score", "Risk", "Context") in the on-disk `.txt` report are now translated via the `labels=` dict. New keys under `report.field_*` + `report.summary_title` in `en.json` + `fr.json`. **M-6 `_inline_format` double-escape URL chars fix** ([bob/report_markdown.py:469-481](bob/report_markdown.py#L469-L481)): URLs containing `&` `<` `>` `"` were double-escaped (parent `html.escape` + `_safe_url`'s `html.escape(quote=True)`), producing `&amp;amp;` in `href="..."`. Fixed via `html.unescape(m.group(2))` before passing to `_safe_url`. Latent (no current BOB-emitted Markdown triggers this) but real. **M-10 `set_posture_from_engine` helper extract** ([bob/scoring.py:683-720](bob/scoring.py#L683-L720)): the posture-escalation setup duplicated in `bob/__main__.py` (audit summary) and `bob/watch.py` (watch loop) consolidated into a single helper. Also adds the dict-vs-int guard on `domain_scores["firewall"]` (Phase 1 4ed2e3b lesson) so a future entry point can't accidentally pass the wrong shape. **M-11 `send_html_email` defensive CRLF stripping** ([bob/report_markdown.py:565-578](bob/report_markdown.py#L565-L578)): `\r\n` stripped from `recipient`, `subject`, `from_email` headers. Defence-in-depth against future tainted callers; current callers are BOB-internal. **M-12 html_output risk label translated** ([bob/html_output.py:140-152](bob/html_output.py#L140-L152)): pre-v0.7.3 the summary header's risk badge displayed `LOW`/`HIGH` regardless of locale while the finding badges below used translated keys. Now both surfaces use the same i18n contract. New keys `html_output.risk_low/medium/high/critical` in `en.json` + `fr.json` (FR: `FAIBLE`/`MOYEN`/`ÉLEVÉ`/`CRITIQUE`). **Skipped per `feedback-conservative-refactor`** (5): M-1 f-string without interpolation (registry.py), M-7 CSV timestamp on every row (by-design self-contained CSV), M-8 `formatter.py` zero in-tree consumers (documented stub future-API), M-9 `_atomic.py` `BaseException` width (intentional — catches Ctrl+C for tmp cleanup), M-13 EXPLAIN_KEYS list→frozenset (cosmetic perf). Tests: 5490 → **5502** (+12 net): 1 CSV rename pin, 3 webhook scheme case-insensitivity pins, 6 CLI argv hardening pins, 2 HTML risk-level translation pins. 0 regression. **v0.6.x remains EOL** (declared in v0.7.2). Upgrade: `pipx upgrade bodyguard-of-bits`. The only user-facing behavioural shifts: CSV column rename (external consumers must update), French audit `.txt` reports now have French field labels (no more mixed-language), and HTML reports have French risk badges in French locale. Webhook URL scheme matching is now case-insensitive. |
| [v0.7.2](#v072) | 2026-06-01 | **Second v0.7.x hardening patch** — closes the 6 minors deferred by v0.7.1's sub-agent audit + formalises v0.6.x EOL. **M-4 i18n extraction on Markdown / HTML exports** — `bob/markdown_output.py` + `bob/html_output.py` now route every user-facing string through an optional ``t(key, **kwargs)`` translation function; when ``t=None`` (legacy callers / tests), an English fallback dict `_FALLBACK_LABELS` in each module supplies the v0.7.1 strings unchanged. `__main__.py` callers pass the audit's bound ``t`` + ``lang`` so the exports inherit the operator's locale. New locale entries shipped: 24 keys under `markdown_output.*` + 22 keys under `html_output.*` in both `en.json` and `fr.json` — `html_output.findings_count` uses `{count}` template var. Test coverage `test_locale_coverage.py` AST scan validates the 46 new keys resolve in both locales. **M-6 sysinfo accepts IPv6 public IP** — `bob/sysinfo.py:199` regex `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$` replaced by `ipaddress.ip_address()` validation; v6-only hosts now report their actual public address instead of empty string. Edge case visible only on hosts where the provider HTTPS request travels over v6. **M-7 `_atomic.py` tmp-file collision under concurrent writers** — `tmp = path.with_suffix(path.suffix + ".tmp")` replaced by `tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))`. Two concurrent `bob` invocations (cron + manual + watch loop coïncident) no longer race on the same tmp path; A's bytes can't be overwritten by B before A's `os.replace`. Best-effort tmp cleanup on any failure path (the previous code left orphan `.tmp` files when the rename failed). **M-8 `SCHEMA_*_KEYS` wired as enforced invariants** — `bob/json_output.py` exports `SCHEMA_V1_REQUIRED_KEYS` / `SCHEMA_V1_FULL_KEYS` / `SCHEMA_V2_REQUIRED_KEYS` / `SCHEMA_V2_FULL_KEYS` frozensets that documented the v1+v2 contract but were never enforced (anticipated API pattern). New test class `TestSchemaConstantsPinActualOutput` asserts each frozenset matches what the producer actually emits in short + full modes for both schemas; the test fires the moment a producer adds/renames/removes a top-level key without updating the matching frozenset. **M-9 `--json-full --json-v1` help text** — `bob/cli.py:604` now mentions the combination explicitly. **M-10 `display.py` posture-detection paths deduped** — extracted `_compute_posture_annotation(engine, t) -> tuple` helper replacing the duplicated `getattr(engine, "effective_level", ...)` + `unpack_posture_escalation(...)` + conditional `t(key)` pattern that landed twice during v0.7.0 hotfix. Single source of truth for the terminal box AND the on-disk `.txt` report annotation. Conservative-refactor reviewed: bundled with M-4 in the same commit so the touch amortises across multiple file edits. **v0.6.x officially declared EOL in `SECURITY.md` + `SECURITY_FR.md`** + the v0.6.2 GitHub Release notes carry a prominent EOL banner. The v0.6.x branch will not receive security backports; users on v0.6.x must `pipx upgrade bodyguard-of-bits` to v0.7.x. The v0.7.x line is backwards-compatible with the v0.6.x public API via `__init__.py` re-exports + the `--json-v1` flag for legacy JSON consumers — upgrading is transparent for the vast majority of users. Tests: 5479 → **5490** (+11 net): 4 SCHEMA_*_KEYS pin tests (M-8), 3 Markdown i18n routing pins (M-4 fallback + custom t + fallback-completeness), 4 HTML i18n routing pins (M-4 + `lang` attr). 0 regression. **M-11 (Iterator import cosmétique) was NOT shipped** per `feedback-conservative-refactor` — skip-forever item. No new deferred contract; v0.7.x audit cycle is now fully closed. Upgrade: `pipx upgrade bodyguard-of-bits`. Webhook `BOB_WEBHOOK_ALLOW_INSECURE=1` (v0.7.1 I-5) remains the only opt-in env var. |
| [v0.7.1](#v071) | 2026-06-01 | **First v0.7.x hardening patch** — same-day follow-up to v0.7.0 final. Sub-agent deep-audit on the full v0.7.0 codebase surfaced 0C + 5I + 11M findings; v0.7.1 ships 4 important + 3 minor (the rest deferred to v0.7.2). **I-1 watch-mode contract drift** — `bob --watch` created a fresh `ScoreEngine()` per iteration but never called `engine.set_posture(...)` and never set `engine.ignore_keys = load_ignore_keys()`. Result: a host whose UFW just went down kept showing "LOW risk" in watch mode even though the next non-watch audit correctly escalated to HIGH; user-ignored findings reappeared on every iteration and inflated visible deductions. Fixed by propagating both the ignore list and the v0.7.0 posture-escalation rules per iteration, and displaying `engine.effective_level.value` next to the score bar. Also added the explicit `bool` rejection guard on `_score_bar` (Phase 2.1 I-3 pattern). **I-2 `MarkdownReport.write_summary` signature drift** — `display.print_audit_summary` (called only on `AuditReport` today) passes `posture_annotation=...` to `report.write_summary`. The `Report` Protocol in `bob/report.py` and the `MarkdownReport.write_summary` impl in `bob/report_markdown.py` did NOT accept the kwarg. Today the bug doesn't fire because `MarkdownReport` is never wired into the audit summary path — but it's a landmine for the next time it would be. Fixed by adding `posture_annotation: str = ""` to both the Protocol and `MarkdownReport.write_summary` (rendered inline next to the Risk row, same shape as `AuditReport`). **I-3 JSON v1 `risk` field wire-format break** — v0.7.0 Phase 1 silently shifted `risk` in the v1 JSON schema from `engine.level.value` (score-derived) to `engine.effective_level.value` (posture-escalated). That broke the documented "v1 layout matches v0.6.x EXACTLY" contract: a v0.6.x consumer doing `if data["risk"]=="low": green` now sees "high" on a freshly broken firewall even though the score is 9. v0.7.1 reverts the shift; v1 consumers stay frozen at v0.6.x semantics. Consumers that need the escalated value migrate to v2's `posture_escalation.score_level` and top-level `risk_level`. **I-5 Webhook plaintext URL accepted** — `send_webhook(url, ...)` accepted both `http://` and `https://`. The audit payload contains hostname + public_ip + score + alerts — that leaks audit posture in plaintext on any network path. SECURITY.md "Network surface" documents webhook as HTTPS-only. v0.7.1 rejects `http://` by default; opt out via new env var `BOB_WEBHOOK_ALLOW_INSECURE=1` (offline labs / private network testing only). **M-1 unused import** — `from typing import Any` in `bob/plugin_checks.py` left over after the T3 Step 3 removal of the `_module: Any` field. **M-2 `_atomic.py` did not fsync** — docstring promised crash-safe persistence ("power loss between start and return leaves the destination in its previous state") but the implementation skipped both `fsync(fd)` before close AND `fsync(dir_fd)` after rename. On ext4 default `data=ordered`, the rename metadata could commit before the data, leaving a zero-byte state file on power loss. Now fsyncs both the tmp fd and the parent directory's fd; parent-dir fsync failure is best-effort (some filesystems don't support directory fsync). **M-5 `--ignore=KEY` did not validate the key pattern** — `add_ignore_key("anything goes here")` silently accepted, the YAML writer split on whitespace and truncated to the first word, and the loader couldn't match the key on the next audit. Users saw "added" but no actual ignore. v0.7.1 validates against the canonical EXPLAIN_KEYS pattern (`<prefix>.<finding_id>` snake_case — same shape enforced by `tests/test_explain_naming_convention.py` on the 117 keys) before the write; bad keys return `EXIT_ERROR=3` with a hint to run `bob --explain list`. Tests: 5466 → 5479 (+13 net): 5 ignore-validation pins, 1 atomic fsync spy, 2 webhook http rejection pins (with + without escape hatch), 3 MarkdownReport signature parity pins, 2 watch-mode propagation pins. JSON contract test renamed + body inverted (`test_v1_risk_pins_score_only_level_not_effective_level`) to pin the I-3 revert against future re-shifts. Bool-on-`_score_bar` test inverted to TypeError. **Deferred to v0.7.2**: I-4 (cosmetic-defensive same-pattern as I-4 here but on a different path), M-4 (HTML/Markdown export builders ship hardcoded English — needs the locale extraction pass), M-6 IPv4-only public-IP detection, M-7 atomic tmp-file collision under concurrent writers, M-8 unused SCHEMA_*_KEYS public constants, M-9 `--json-full --json-v1` help text completeness, M-10 `display.py` duplicated posture detection paths, M-11 trivial cosmetic import. Upgrade: `pipx upgrade bodyguard-of-bits`. No CLI contract change; v1 JSON consumers may see `risk` revert from posture-escalated back to score-derived (intentional — this is the I-3 fix). |
| [v0.7.0](#v070) | 2026-06-01 | **Major bump** — opens the v0.7.x stable branch. Rolls up the b1+b2+b3+b4 beta cycle (15+ commits) with three thematic phases and four release-engineering guards added in flight. **Phase 1 (T1 Foundation)** — Python 3.14 added to the CI matrix (ladder step 1, `requires-python>=3.10` retained per upstream EOL 2026-10); new `ScoreEngine.set_posture()` API + `effective_level` property + `posture_escalation` block computing `max(score_level, posture_floor)` where `posture_floor` is raised by `firewall_inactive` / `iptables_input_accept` / `firewall_domain_score ≤ 3`; new EXPLAIN key `risk.escalated_posture`; box-score now annotates "(majoré par posture: X)" when the posture floor is active; M-1 `parse_cron_file` time_simple flag + log normalization; M-7 `--check`/`--skip` recognise the 10 always-on section names. **Phase 2 (T2 Schema v2)** — `build_json_data(..., schema_version="2")` is the new default, `--json-v1` flag preserves the legacy v0.6.x layout exactly for migration; v2 fixes `network_context` type inconsistency (P1), renames `timestamp`→`timestamp_utc`, adds `info_count` + `posture_escalation` block + `deductions_raw`/`open_ports_all` in full mode + `domain_scores[d].deductions`; new file `tests/test_json_schema_v2.py` (30 tests written before impl per integration-first rule); **EXPLAIN_KEYS audit baseline** = 117 keys / 30 prefixes / 100% conformance with canonical `<prefix>.<finding_id>` snake_case pattern pinned by `tests/test_explain_naming_convention.py` (+710 parametrized assertions); `DOCUMENTS/README_TECH.md` rewritten with v2 + v1 schema + migration guide. **Phase 2.1 hotfix** — sub-agent pre-T3 audit surfaced 5 important + 6 minor findings; 5/5 important + 4/6 minor shipped: I-1+I-4 `effective_level` propagation to HTML / Markdown / `history.jsonl` (3 missed sinks added + `level_score_only` field for trend analysis); I-2 extracted `bob.scoring.unpack_posture_escalation` helper consolidating the defensive `getattr`+`try/except` pattern; I-3 `set_posture` rejects bool explicitly with clear TypeError; I-5 vacuous test rewritten to assert the explicit divergence shape; M-1 `--check=list` lists the 10 always-on section names; M-3 `report.write_summary` (.txt) surfaces the same posture annotation as the terminal. **Phase 3 (T3 Plugin Sandbox Runner)** — new `bob/_sandbox.py` (484 LoC) implements a restricted-mode plugin runner: process isolation via `multiprocessing.get_context("spawn")`, 5s wall-clock timeout + `RLIMIT_AS=256MiB` + `RLIMIT_CPU=10s` enforced in the worker, import allowlist (`bob.scoring` + curated stdlib subset), restricted `__builtins__` (`_ImmutableBuiltins` dict subclass — no `eval`/`exec`/`compile`/`__import__`/`input`/`breakpoint`), `open()` wrapper rejecting write modes AND denying reads on `/etc/shadow` / `~/.ssh/id_*` / `/dev/mem` etc., `pathlib.Path` write methods monkey-patched, extensive `os` module attribute strip (84 dangerous attrs including all `exec*`/`spawn*`/`posix_spawn*`/`fork*`/raw fd I/O/FS writes/privilege changes/env mutations), CheckResult ships via JSON-safe dict round-trip through the queue (no pickle of plugin-controlled objects → no parent-process RCE via malicious `__reduce__`), `BOB_SANDBOX_LEGACY=1` deprecated trap door with hardened CRITICAL log + stderr write per-run. `bob/plugin_checks._load_one()` is now AST read-only — the parent process NEVER exec's plugin module code, closing the legacy `importlib.exec_module` escape. Threat model recadré honest in `SECURITY.md` — **in-process Python sandboxing is NOT a security boundary** (PEP 416 consensus); the sandbox catches accidents + naïve attacks; AppArmor profile shipped with BOB is the real boundary. Two known-limitation tests (`TestKnownInProcessLimitation`) pin the architectural escape via `json.dumps.__globals__["__builtins__"]["__import__"]` and the I-1 `dict.__setitem__` unbound bypass as INTENTIONALLY out of scope so future contributors recognize them as expected. **Four release-engineering guards added in flight** — (1) **integration-first** caught Phase 1 4ed2e3b dict-vs-int crash before the first beta; (2) **smoke-after-commit** caught v0.6.2 packaging discovery class; (3) **version-consistency** test (`tests/test_version_consistency.py`) caught v0.7.0b1 `__version__` drift in b2; (4) **smoke-plugin-on-CI** added in 5e0739e/cb4108b after the v0.7.0b3 ship pattern (MappingProxyType regression invisible to maintainer's 5/5 VM smoke because no VM had any plugin installed — closed by dropping a benign plugin in `~/.config/bob/checks.d/` on every Python × distro × install mode combination in CI). 5391 → **5466 tests** across the v0.7.0 cycle, 0 regression. Sub-agent adversarial review pattern proven 2 times during v0.7.0 (Phase 2.1 + T3 Step 4). **Deferred to v0.8.0**: D-1 sections renumbering, D-2 fusion `_ALL_SECTIONS`+`_ALWAYS_ON_SECTIONS`, D-3 retrait aliases EXPLAIN_KEYS obsolètes, D-4 sub-checks granulaires, `BOB_SANDBOX_LEGACY=1` trap door removal. **Upgrade**: `pipx upgrade bodyguard-of-bits`. Users with plugins in `~/.config/bob/checks.d/` get the sandbox automatically; users without plugins see the new posture escalation + JSON schema v2 output. v0.6.x branch officially EOL. |
| [v0.7.0b4](#v070b4) | 2026-06-01 | **CI compatibility hotfix for v0.7.0b3.** No threat-model or audit behaviour change vs b3 — but the b3 ship used `types.MappingProxyType` as the plugin sandbox's restricted `__builtins__` (the I-1 closure), and CPython rejects non-dict mappings as `exec()` builtins on every Python version in the CI matrix EXCEPT 3.12.3: every plugin run on 3.10 / 3.11 / 3.13 / 3.14 raised `SystemError: Objects/dictobject.c:1490: bad argument to internal function` from C-level dict fast-paths the worker exec'd through. Caught by `publish.yml` test matrix immediately after the b3 tag push — the 5/5 VM smoke validation that gated b3 only exercised the audit chain (no `~/.config/bob/checks.d/` plugins on any VM) and missed the regression because no actual plugin code reached the worker. **Fix:** revert `_build_restricted_builtins` to return the original `_ImmutableBuiltins` dict subclass shipped in v0.7.0b2 (overrides `__setitem__` / `update` / `clear` / `pop` / `popitem` / `setdefault` to raise TypeError). This blocks the natural-Python mutation path `bins["eval"] = real_eval` that adversarial plugin 12 (globals_pollute) uses, but is bypassable via the unbound `dict.__setitem__(bins, "eval", real_eval)` call — same I-1 sub-agent finding the b3 attempted to close. The trade-off: I-1 unbound-bypass moves from "closed" back to "known limitation" alongside the architectural escape, because every fully-immutable alternative (`MappingProxyType`, `frozendict`, custom C type) triggers the same `SystemError` from CPython's dict fast paths that the b3 hit. Documented in `SECURITY.md` "What it does NOT stop" + new pinning test `TestKnownInProcessLimitation::test_i1_known_limitation_unbound_dict_setitem_bypass` so future contributors see this is intentional, not an oversight. The other 6 b3 hardening fixes — C-1 extended os strip (84 entries), C-2 JSON round-trip queue transport, I-2 queue close, I-3 shared AST `has_run_check`, I-5 read-path deny-list, M-4 RLIMIT_CPU, M-6/M-7 hardened LEGACY warning — all preserved unchanged. **The 4th release-engineering bug on the v0.7.x branch** (after v0.6.2 packaging discovery, Phase 1 4ed2e3b dict-vs-int crash, and v0.7.0b1 __version__ drift) — same class as the b1→b2 gap: smoke-test-VMs that don't exercise the changed code path. New guard for v0.7.0 final: a smoke-CI step that loads a benign plugin on every Python matrix version before tagging. 5466 tests (was 5465 + new known-limitation pin). Testers on b3: `pipx upgrade --pip-args="--pre" bodyguard-of-bits-beta` to get b4; if you ran b3 without plugins you saw no symptom. |
| [v0.7.0b3](#v070b3) | 2026-05-31 | **Sandbox hardening + threat-model recadrage** following T3 Phase 3 sub-agent adversarial audit (3C + 5I + 7M). 3 PoC locally confirmed before the fix pass: **C-1** `from pathlib import os` smuggled a live `os` module past the import allowlist; the strip list missed `posix_spawn` / `open` / `write` / `chmod` / `unlink` / `environ` / `chdir` — a plugin wrote `/tmp/bob_c1_escape` via `os.open + os.write`. **C-2** parent-process RCE through `mp.Queue` pickle: plugin obtained real `eval` via `json.dumps.__globals__["__builtins__"]` (allowlisted stdlib leaks unrestricted builtins), built `Evil = type("Evil", (), {"__reduce__": ...})` (bypassing `__build_class__` strip), attached to `findings[0].template_vars`, parent's `q.get()` unpickled and ran `os.system` under sudo (`/tmp/bob_c2_parent_pwned` created **by the parent**). **Architectural escape** `real_import = json.dumps.__globals__["__builtins__"]["__import__"]` then `real_import("subprocess")` — bypasses every hook in 5 lines, consensus communauté Python depuis PEP 416 retiré (2012). Strategic decision: **Option B — défense-en-profondeur honnête + AppArmor real boundary**. Hardening shipped: extended `_OS_DANGEROUS_ATTRS` from 21 → 84 entries (closes C-1 + collateral on arch escape via stripped `os.pipe` which breaks `subprocess.run` internally) · `_serialize_check_result` / `_deserialize_check_result` JSON-safe dict round-trip through the queue (closes C-2 — worker flattens all `template_vars` values via `_sanitize_for_transport` before put, parent rebuilds fresh CheckResult from dict, no plugin-controlled `__reduce__` ever reaches parent unpickle) · `_ImmutableBuiltins` dict subclass replaced by `types.MappingProxyType` (closes I-1 — C-level read-only proxy, no `dict.__setitem__(unbound, k, v)` bypass possible) · `q.close()` + `q.join_thread()` in `try/finally` (I-2 — fd + feeder thread cleanup) · read-path deny-list on `open()` blocks `/etc/shadow` / `~/.ssh/id_*` / `/dev/mem` / `/proc/kcore` (I-5) · `_apply_resource_limits` now sets `RLIMIT_CPU = 10s` in addition to `RLIMIT_AS = 256MiB` (M-4 — defends against CPU-bound infinite loops resistant to SIGTERM) · `BOB_SANDBOX_LEGACY=1` warning via `logger.critical` + stderr write, re-emitted per-run instead of singleton-cached (M-6 + M-7) · shared `bob._sandbox.has_run_check(source)` AST helper used by both `_load_one` and `SandboxRunner.run` (I-3 — accepts `def run_check` AND `run_check = ...` consistently, no more substring false-positives on comments). Tests: 7 new (TestHardeningPins ×5 + TestKnownInProcessLimitation ×2) — the 2 known-limitation tests pin the architectural escape as INTENTIONALLY out-of-scope per SECURITY.md "Threat model" section so future contributors know it's expected not regression. 5458 → 5465 tests, 0 régression. SECURITY.md rewritten with honest threat model: **"In-process Python sandboxing is not a security boundary"** — sandbox catches accidents + naïve attacks, AppArmor catches adversaries. Memory entries: `project_v070_t3_sandbox_threat_model` saves the architectural learning. **Anyone running plugins from untrusted sources must enforce the BOB AppArmor profile** — code review remains mandatory regardless. |
| [v0.7.0b2](#v070b2) | 2026-05-31 | **Release-engineering hotfix for v0.7.0b1.** No code/contract/audit change — but `bob/__init__.py::__version__` was not bumped alongside `pyproject.toml` in the v0.7.0b1 ship commit, so the wheel correctly identified as `bodyguard-of-bits-0.7.0b1` on PyPI while every running-code output (terminal banner, `--version`, JSON `version` field, webhook payload, report header) reported `BOB v0.6.2` — exactly the lie the new banner was supposed to fix. Caught on the so6 Debian 13 VM during v0.7.0b1 beta validation (2026-05-31). PyPI does not allow re-uploading the same version → ship as v0.7.0b2 with both files in sync. New invariant test `tests/test_version_consistency.py::test_init_version_matches_pyproject_version` reads both values on every CI run + every local pre-ship pytest, asserting equality — any future single-file bump fails the suite before tag push. This is the 3rd release-engineering bug on v0.7.x after the v0.6.2 packaging discovery (wheels missing ssh/+cron/ subpackages) and the Phase 1 4ed2e3b crash (dict-vs-int from `engine.domain_scores`), and the third complementary guard pattern: integration-first + smoke-after-commit + version-consistency. Testers on v0.7.0b1: `pipx upgrade --pip-args="--pre" bodyguard-of-bits-beta` to get v0.7.0b2; `sudo bob-beta --version` should print `0.7.0b2`. All v0.7.0b1 testing observations remain valid — the misreport was UX-only, the audit logic was already v0.7.0 code. |
| [v0.7.0b1](#v070b1) | 2026-05-31 | **First pre-release of v0.7.0** — opt-in via `pipx install --pip-args="--pre" bodyguard-of-bits`. Stable users on v0.6.2 are NOT impacted. Bundles 15 commits across **Phase 1** (Python 3.14 ladder step 1; M-1 `parse_cron_file` time_simple flag + log; M-7 `--check`/`--skip` recognise always-on sections; **posture escalation** = new `ScoreEngine.set_posture()` + `effective_level` + `posture_escalation` property — a host with UFW OFF + score 8/10 now displays `HIGH risk (raised by posture: firewall inactive)` instead of misleading `LOW`; new EXPLAIN key `risk.escalated_posture`; CI publish.yml handles PEP 440 pre-release tags), **Phase 2** (**JSON schema v2 dispatch** = `build_json_data(..., schema_version="2")` is the new default, `--json-v1` flag preserves the legacy v0.6.x layout exactly; v2 fixes `network_context` type inconsistency P1, renames `timestamp`→`timestamp_utc`, adds `info_count`, `posture_escalation` block `{applied, reason_key, score_level}`, `deductions_raw`/`open_ports_all` in full mode, `domain_scores[d].deductions`; new file `tests/test_json_schema_v2.py` (30 tests written before impl per integration-first rule); **EXPLAIN_KEYS audit baseline** = 117 keys / 30 prefixes / 100% conformance with canonical `<prefix>.<finding_id>` snake_case pattern pinned by `tests/test_explain_naming_convention.py` (+710 parametrized assertions); B-2 retired during Step 1 of T2 because integration-first writing of the test revealed `firewall_stack.input_bypasses`/`forward_bypasses` are `list[str]` of rule descriptions and the plural naming was already correct; `DOCUMENTS/README_TECH.md` rewritten with v2 + v1 documentation + migration guide), and **Phase 2.1 hotfix** (sub-agent pre-T3 audit surfaced 5 important + 6 minor findings; 5/5 important + 4/6 minor shipped: **I-1+I-4** `effective_level` propagation to HTML, Markdown, history.jsonl was incomplete after Phase 1 — added the 3 missed sinks + `level_score_only` field in `history.jsonl` for trend analysis; **I-2** extracted `bob.scoring.unpack_posture_escalation` helper consolidating the defensive `getattr`+`try/except` pattern that was duplicated in display and missing in json_output — single source of truth ready for T3 plugin runner; **I-3** `set_posture` now rejects bool explicitly with a clear TypeError message (`isinstance(x, int)` returned True for bool, slipping through); **I-5** vacuous `assert ... or True` in `test_v2_posture_escalation_consistent_with_top_level_risk` rewritten to assert the explicit divergence shape; **M-4** dead `_SCHEMA_VERSION` alias removed (zero consumers via grep); **M-5** v1 risk test now pins the post-Phase-1 silent semantic shift against accidental revert; **M-1** `--check=list` output now lists the 10 always-on section names so the help text matches what M-7 accepts as input; **M-3** `report.write_summary` (.txt on-disk report) now surfaces the same posture annotation as the terminal summary box). 5391 → 5409 tests across the 15 commits, 0 regression. Smoke validated on so6desktop (Linux Mint 22.3) — audit completes end-to-end with score 8/10 + posture clean (UFW active), JSON v2 shows `posture_escalation.applied=false`, JSON v1 (`--json-v1`) preserves legacy layout exactly. Phase 3 (T3 plugin sandbox runner) is the next chunk and will bundle into v0.7.0 final ship. **Deferred to v0.8.0**: D-1 sections renumbering, D-2 fusion `_ALL_SECTIONS`+`_ALWAYS_ON_SECTIONS`, D-3 retrait aliases EXPLAIN_KEYS obsolètes, D-4 sub-checks granulaires. Beta testers welcome — `pipx install --pip-args="--pre" --suffix=-beta bodyguard-of-bits` keeps your stable v0.6.2 intact. |
| [v0.6.2](#v062) | 2026-05-29 | **Critical packaging hotfix.** Every wheel shipped since v0.6.0 was missing `bob/checks/ssh/` and `bob/cron/` — the two subpackages introduced by the v0.6.0 splits. Anyone who `pipx upgrade`d to v0.6.0 or v0.6.1 hit `ModuleNotFoundError: No module named 'bob.checks.ssh'` at startup. Root cause: `[tool.setuptools.packages.find].include` was a literal list `["bob", "bob.checks", "bob.tui"]` from a v0.4.x packaging audit — when v0.6.0 added `bob.checks.ssh` and `bob.cron`, the list wasn't updated. The wheel built but excluded both packages silently. Why undetected: tests + the pre-ship `sudo python3 -m bob` smoke ran from the working tree (where the source directories are visible regardless of packaging config); the `.github/workflows/integration.yml` step used `pip install -e .` (editable mode) which puts the repo root on `sys.path` and bypasses the packaging discovery entirely. Fix: changed `include` to the glob `["bob*"]` so any future subpackage is auto-discovered. CI hardened: integration jobs now use `pip install .` (non-editable, builds + installs a real wheel) AND a new explicit smoke step `python3 -c "import bob.checks.ssh; from bob.cron import CronEntry; from bob._atomic import atomic_write; from bob._tty import safe_input"` that fails fast if any v0.6.x-added module is missing from the wheel. No code changes other than the packaging config + workflow guard. 4600 tests unchanged. **Anyone running v0.6.0 or v0.6.1 via pipx must `pipx upgrade bodyguard-of-bits` to v0.6.2 to get a working install.** |
| [v0.6.1](#v061) | 2026-05-29 | First hardening release on the v0.6.x branch. Deep audit sub-agent surfaced 14 findings (0 critical + 6 important + 8 minor); 6 important + 4 minor shipped. **Atomic-write contract enforcement**: extracted `bob/_atomic.py::atomic_write(path, content, *, mode=)` as the single source of truth; migrated `bob/config.py` (2 sites), `bob/compare.py`, `bob/history.py`, `bob/recurrence.py` from their 5 hand-rolled implementations; **I-1** fixed the cron install paths (`bob/cron/_install.py`, `bob/tui/cron.py`) that were using raw `os.open(O_WRONLY \| O_CREAT \| O_TRUNC) + fdopen.write` on fresh installs — power-loss between truncate and write left the cron file empty (v0.5.7 #I-3 had closed the mutation path but missed the creation path); **I-6** fixed `bob/ignore.py` writing non-atomically — power-loss / OOM corrupted ignore.yml. `bob/cron/_io.py::_atomic_write` kept as a backwards-compat alias for the test patch target. **I-2 EOF contract completion**: new `bob/_tty.safe_input(prompt)` wrapper + `prompt_wizard()` now catches `EOFError` (was raising); 11 bare `input()` sites in `bob/cron/_install.py` (5), `bob/cron/_manage.py` (5), and `bob/fixes.py` (1) migrated to `safe_input`. **I-3** `bob/cron/_parse.py::_validate_cron_field` now rejects step values exceeding the field range (`*/200` for minute 0-59 was previously accepted → cron interpreted as "every 200 minutes" = never fires). **I-4** `shlex.quote()` applied to 8 `cmd=f"..."` sites in `bob/checks/ssh/_subchecks.py` (4) + `bob/checks/file_perms.py` (3) + `bob/checks/firmware.py` (1) where paths from `pwd.getpwnam(SUDO_USER).pw_dir`, filesystem scans, or `dpkg-query` output could contain spaces and silently mis-target `--fix --apply`. **I-5** `bob/history.py::save_score` first-write now creates `history.jsonl` with explicit mode `0o600` via `os.open(O_WRONLY \| O_APPEND \| O_CREAT)` instead of inheriting the default umask (typically 0o644 → world-readable score timestamps). **Minor fixes shipped**: M-2 redundant double-`.lower()` in `_apply_bad_directive`; M-3 `MaxAuthTries=-1` now falls back to default 6 (was accepted); M-6 `bob/__main__.py` fatal-error handler now hints "Set BOB_DEBUG=1 for full traceback" and prints traceback when set; M-8 `--watch=N` error wording aligned ("integer ≥ 10" instead of misleading "positive integer"). +17 regression tests in `tests/test_atomic_v061.py` (12) + `tests/test_cron.py::TestStepBoundedToFieldRange` (5). 4583 → 4600. JSON contract, EXPLAIN_KEYS, keybindings, no-curses fallback, exit codes — all preserved. |
| [v0.6.0](#v060) | 2026-05-25 | **Major bump** — opens the v0.6.x branch. Two architectural splits + one sunset, all contract-preserving via package re-exports. **#13 split `bob/checks/ssh.py` (1296 LoC monolith) → `bob/checks/ssh/` package** with 4 modules: `_directives` (165L: `_BadDirective` table + `_BAD_DIRECTIVES` + `_apply_bad_directive` + weak crypto reference sets), `_snapshot` (198L: 5 dataclasses + `SSHSnapshot` + `SSHSnapshot.from_system`), `_parsers` (446L: pure parsers for sshd_config / authorized_keys / known_hosts / client config + key-type / RSA-bits helpers + `_collect_host_keys` + `_detect_ssh_install_cmd` + `_parse_time_seconds`), `_subchecks` (529L: `check_ssh` entry point + all `_check_*` per-area helpers). **#14 split `bob/cron.py` (1204 LoC monolith) → `bob/cron/` package** with 4 modules: `_parse` (330L: `CronEntry` + `parse_cron_file` + `list_installed_crons` + `cron_to_human` + `build_schedule_expr` + validators + day helpers + MTA detection + constants), `_io` (164L: `_atomic_write` + `build_script_content` + `apply_cron_schedule` + `apply_cron_email`), `_install` (319L: `prompt_emails` / `prompt_email` + `_run_install_cron_plain` + `run_install_cron` + `_CronQuit` exception), `_manage` (445L: `_manage_email_store` + `edit_cron_email` + `edit_cron_schedule` + `_run_manage_cron_plain` + `run_manage_cron`). Both packages preserve the full v0.5.x public API via `__init__.py` re-exports — `from bob.checks.ssh import check_ssh, SSHSnapshot, …` and `from bob.cron import CronEntry, run_install_cron, _EMAIL_RE, datetime, …` continue to work unchanged. **Sunset: `UFW_AUDIT_SHARE` legacy env var removed** (announced "REMOVED in v0.6.0" in v0.5.4 deprecation warning — honored). Only `BOB_SHARE` is now accepted; installers still setting the legacy alias will see no effect. Two AST-scanning tests (`tests/test_template_vars_migration.py`, `tests/test_domain_scores_mapping_complete.py`) updated to recurse into check packages (one-line `glob` → `rglob` shift). One regression test (`TestApplyCronScheduleAtomic`) updated to patch the new `bob.cron._io._atomic_write` site instead of the package-level re-export. 4583 tests inchangés (zero net delta — splits + sunset are wire-equivalent). LoC: ssh.py 1296L → 4 modules (max 529L), cron.py 1204L → 4 modules (max 445L). Largest check module is now `ssh/_subchecks.py` at 529L, well below the project's soft 1000-LoC ceiling. JSON contract (`schema_version="1"`), 116 EXPLAIN_KEYS, keybindings, no-curses fallback, exit codes — all preserved. **Closes the deferred architectural roadmap from v0.5.x.** |
| [v0.5.8](#v058) | 2026-05-25 | Cleanup of the 5 cosmetic minors explicitly deferred by v0.5.7. **M-2** `manage_logs.py` cursor shift after delete now only counts deletions ≤ cursor (pre-fix: `cursor -= deleted` shifted by the full count even when most deleted items sat AFTER the cursor — visible cursor displacement on multi-selection deletes mixing items before+after the active position). **M-5** schedule wizard constants promoted from local `_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4` tuple unpack to a module-level `_Schedule(IntEnum)` with explicit `DAILY`/`WEEKDAYS`/`MONTHDAYS`/`CUSTOM` names — 3 call sites updated, IntEnum preserves `choice == _Schedule.WEEKDAYS` semantics so wire-equivalent. **M-6** `_extract_summary_view` `summary_start: int \| None = None` sentinel replaces `summary_start = 0` falsy check — handles the (unreachable in practice but semantically wrong) edge case where the SEP62 separator sits at line 0. **M-7** new `_is_finding_continuation(line)` helper stops the 4-space-indent grouping at any boundary that obviously belongs to a different finding (`[ALERT]`/`[WARN]`/`[OK]`/`[INFO]` markers) or a section delimiter (`┌`/`└`/`│`/`━`/`╔`/`╠`/`╚`/`║`) — defends against over-greedy grouping of subsequent indented content. **M-8** `from datetime import datetime` lifted to module-level in both `bob/cron.py` and `bob/tui/cron.py`; 3 local imports removed (`_run_install_cron_plain`, `build_script_content`, install cron curses path). +12 regression tests across `tests/test_cron.py` (TestScheduleIntEnum, TestDatetimeImportLifted) and `tests/test_manage_logs.py` (TestCursorShiftAfterDelete, TestSummaryStartSentinel, TestIsFindingContinuation). 4571 → 4583 tests. JSON wire format unchanged, EXPLAIN_KEYS unchanged, keybindings unchanged, no public API removals. **Closes the v0.5.x deep-audit campaign — branch fully audited (25 modules deep-audit + ~25 spot-checked, 0 critical findings outstanding).** Next minor (v0.6.0) reserved for #13 (ssh.py split) and #14 (cron.py split) — the two deliberately-deferred architectural refactors. |
| [v0.5.7](#v057) | 2026-05-24 | Targeted hardening pass on curses TUI (`bob/manage_logs.py` 999 LoC + `bob/tui/cron.py` 920 LoC = ~1920 LoC) — the bucket explicitly deferred by the v0.5.5 / v0.5.6 audits. 11 findings from a focused sub-agent: 0 critical, 3 important (I-1 `_curses_readline` accepted curses `KEY_*` keypad codes via `chr(ch_i)` — pressing arrows or function keys inserted Greek/Unicode glyphs like `Ι` / `Ω` into name/email/days/time/custom-expression input buffers; no security impact thanks to downstream `_EMAIL_RE` / `_validate_custom_cron` / digit-only filtering, but visibly corrupted UX. New `_is_printable_input_char(ch_i)` helper bounds inputs to printable Latin-1 only · I-2 three `input()` sites in `prompt_path` + move-logs confirmation + delete-all confirmation didn't catch `EOFError` so Ctrl-D dumped a Python traceback on cancel — now matches the `_rl()` convention treating EOF as empty input · I-3 `apply_cron_schedule` used raw `os.open(O_WRONLY \| O_CREAT \| O_TRUNC) + fdopen.write` instead of the project's `_atomic_write` helper. Power loss or `SIGKILL` between `open(O_TRUNC)` and `write` would leave the cron file empty → cron silently drops the entry, no notification. Asymmetric with `apply_cron_email` which already used `_atomic_write`. Same `mode=0o640` enforced), 3 minor (M-1 status `manage_logs.deleted_one` displayed `pending_delete[0].name` even when index 0 failed to delete and only a different index succeeded under selective permission errors — now tracks the first successfully-deleted name · M-3 dead-code `if ch_i == ord("1"): chosen = 0 elif chosen = 1` inside `_curses_edit_sub` simplified, elif guard rewritten with explicit parentheses · M-4 duplicate `from bob.cron import apply_cron_schedule, apply_cron_email` consolidated into the main import block). +11 regression tests across `tests/test_cron.py` (TestApplyCronScheduleAtomic, TestIsPrintableInputChar) and `tests/test_manage_logs.py` (TestEOFErrorOnPromptPath, TestEOFErrorOnMoveConfirm, TestEOFErrorOnDeleteAllConfirm, TestDeletedOneCorrectName). 4560 → 4571 tests. JSON wire format unchanged, EXPLAIN_KEYS unchanged, no public API additions. UX-visible deltas: clean Ctrl-D exit (no traceback), arrow/function keys no longer print garbage into TUI prompts. Deferred to v0.5.8 (5 cosmetic findings not worth churn now): M-2 cursor-shift assumes deletions sit before cursor · M-5 schedule wizard local-scoped constants → module-level / IntEnum · M-6 `summary_start` falsy check misses index 0 (unreachable in practice) · M-7 over-greedy continuation grouping in `_extract_summary_view` · M-8 local `from datetime import` lifted to module top. After v0.5.7, v0.5.x branch fully audited (22 core + logs.py + 2 TUI = 25 modules deep-audited + ~25 spot-checked). |
| [v0.5.6](#v056) | 2026-05-24 | Targeted hardening pass on `bob/checks/logs.py` (662 LoC UFW log parser) — module explicitly deferred by the v0.5.5 audit because of regex density. 10 findings from a focused sub-agent: 0 critical, 2 important (I-1 private-IP regex inconsistent with `sysinfo.py` — missed CGNAT 100.64/10 + IPv6 link-local fe80::/10 + false positives on any string starting with `fc`/`fd`; I-2 year-rollover silently dropped near-realtime syslog events 1s ahead of wall-clock by rolling back a full year), 8 minor (M-1 `[UFW BLOCK6]` IPv6 variant silently ignored — anchored regex now catches both; M-2 `_count_available_days` regex restricted to English month names; M-3 GeoIP path order City-before-Country across all dirs; M-4 `geoip2_status()` accepts symlinks like `_geo_via_geoip2` does; M-5 `_GEO_CACHE` bounded at 2048 with FIFO eviction; M-6 binary-mode `tell()`/`seek()` arithmetic (TextIOBase opaque-cookie compliance); M-7 redundant `subprocess.TimeoutExpired` dropped from except tuple; M-8 `proto` normalised to upper at parse time so a downstream lowercase build can't silently split a bruteforce campaign). +15 regression tests in `tests/test_logs.py` covering each fix class. Single-module pass, single commit. 4545 → 4560 tests. JSON contract preserved. Wire output unchanged on hosts with standard UFW configs; visible only on hosts emitting `[UFW BLOCK6]` (previously dropped — now counted) or with non-English locale syslog logs (previously inflated days_available — now accurate). |
| [v0.5.5](#v055) | 2026-05-24 | Hardening pass — 4 real bugs (C-1 to C-4) + 4 security smells (I-1 to I-4) + 11 minor cleanups (M-1 to M-11) from a deep audit sub-agent. **C-1**: `apply_cron_email()` was rewriting wrapper scripts via `_atomic_write()` which forced mode `0o600` — scripts lost their `0o755` executable bit and cron silently stopped running the audit. `_atomic_write()` now takes `mode=` explicitly; cron file rewrites pass `0o640`, scripts pass `0o755`. **C-2 + C-3 + M-11**: 3 finding `cmd=` values contained `&&` (shell operator rejected by `_has_shell_ops`) or a decorative Unicode arrow → `--fix --apply` rejected them silently. Demoted `password_policy.no_quality_module` + `password_policy.weak_minlen` from `nature="action"` to `nature="improvement"` (visible in summary box under "Améliorations possibles" instead of "À corriger") + split `services_state.service_inactive` cmd to drop the `&&` chained `journalctl` (moved to `note=` guidance). **C-4**: `bob/checks/services_state.py` emits `services_state.service_inactive` but `EXPLAIN_KEYS` declared `services_state.enabled_inactive` — `bob --explain` returned "key not found". Fixed via `EXPLAIN_KEY_ALIASES` (conservative — preserves JSON output contract). **I-1**: `recurrence.py` + `ignore.py` wrote state files with process umask (typically world-readable `0o644`) instead of `0o600` like every other `~/.config/bob/` file. **I-2**: post-`finalize()` calls to `_apply_deduction` silently bypassed score caps — now logs WARNING and discards. **I-3**: `_safe_url` in markdown email HTML didn't re-escape attribute context — a crafted URL containing `"` could break out of `href=""`. Now uses `html.escape(..., quote=True)`. **I-4**: `sysinfo._PRIVATE_IPV4_RE` brittle regex (with `removeprefix("^")` hack) replaced by explicit `ipaddress.ip_network` membership checks; works around Python 3.12+ widening `is_private` to include documentation ranges. **M-1**: 3 duplicate email regex sites unified via `bob.config._EMAIL_RE`. **M-2**: `bob/watch.py:_NullReport` removed in favour of canonical `bob.report.NullReport` (Protocol type introduced in v0.5.0 #10). **M-3**: 3 dead locale keys removed (`_meta.lang`, `_meta.version`, `ignored.hint`). **M-4**: `corr.fully_blind` rule was asymmetric — required `fail2ban.not_installed` but ignored equally-blind `fail2ban.service_inactive`. Widened to fire when any detection layer is blind. **M-7**: extract `_has_actionable_findings()` helper in `updates.py` (clearer than inline-key-blacklist of `apt_cache_age`). **M-8 + M-9**: clarifying comments in ssh.py (Match block Include skip) and ports.py (process/iface empty semantics). **M-10**: `apply_cron_schedule` regex tightened with first-field cron-token anchor so comment lines containing "root /path" are no longer rewritten. **M-6 (separate commit)**: `Optional[X]` / `List[X]` → `X \| None` / `list[X]` sweep across 18 modules — Python 3.10+ syntax. 4538 → 4545 tests (+7 regression coverage). Net diff: 23 code files, +312 / −112 = +200 LoC. Score on dev host unchanged (8/10); the password_policy `nature` change visibly shrinks the "À corriger" block on hosts without pwquality. |
| [v0.5.4](#v054) | 2026-05-23 | Refactor v0.5.x Phase 5 of 5 (final) — **#6 + #9 + #15b + cache APT option C**. **#6 `prompt_wizard()` helper** in `bob/_tty.py` (translation-agnostic wrapper around `input()` with uniform `q`/`quit` cancel + default-on-Enter) replaces 10 raw `input()` sites in `bob/cron.py` install + edit wizards. **#9 UFW_AUDIT_SHARE sunset** — `bob/_paths.py:resolve_share_dir()` upgraded `logger.info(...)` → `logger.warning(...)` with explicit "DEPRECATED since v0.5.4, will be REMOVED in v0.6.0" message; legacy env var still functional today. **#15b explicit `_PREFIX_TO_DOMAIN` mapping** — three v0.4.x silent catch-all fallbacks moved out of the firewall catch-all: `fail2ban` → `ssh` (primary purpose is SSH anti-bruteforce), `virt` → `hardening` (KVM/bridge bypass is kernel/system surface), `docker_audit` → `hardening` (container hardening / daemon.json security). `smtp` and `desktop_apps` stay catch-all by design (no clean domain fit). **Cache APT option C** (new metier feature) — `bob/checks/updates.py` adds an INFO `updates.apt_cache_age` line when no security/regular updates are pending AND the cache age is below the stale threshold, giving permanent transparency about how fresh the "system is up to date" verdict actually is. Surfaced by Ubuntu VM terrain testing on 2026-05-22 where a dormant VM returned "à jour" despite 8 pending LTS security updates upstream. **#13 (ssh.py split, 1324 LoC) and #14 (cron.py split, 1223 LoC) deferred to v0.6.0** — per conservative-refactor principle, splitting >1000-LoC files for marginal readability gain doesn't pass the gain × risk test in a contract-preserving release. Net diff: 12 files changed, +118 / −69 = +49 lines (cron.py +1 net, _tty.py +24, updates.py +20, domain_scores.py +10, _paths.py +5, locales +4 keys, tests −6 net). 4538/4538 tests unchanged. Wire output diff vs v0.5.3 is intentional: new INFO line in section MISES À JOUR SYSTÈME on hosts with cache + no pending updates, and per-domain score reshuffle on hosts emitting `fail2ban.*` / `virt.*` / `docker_audit.*` findings. Closes the v0.5.x audit (15/15 findings addressed, 2 deferred with justification). |
| [v0.5.3](#v053) | 2026-05-22 | Refactor v0.5.x Phase 4 — **#5 + #12 + #8**. **#5 `_LEVEL_DISPATCH` table** in `bob/display.py` collapses the 4-branch OK/WARN/ALERT/INFO cascade in `display_result()` to a single dispatch loop driven by a frozen `_LevelTraits(report_label, threshold_key, print_fn, has_recurrence, has_body, detail_unconditional, show_note, show_cis)` dataclass. The 4-row table captures per-level behaviour declaratively; the special-case ALERT path that prints detail unconditionally (even without `--verbose`) is now expressed as `detail_unconditional=True` rather than an imperative branch. **#12 `print_audit_summary` split** — the 142-line function is broken into 3 focused helpers (`_summary_header_lines`, `_summary_findings_lines`, `_summary_breakdown_lines`) plus `_add_finding_lines` extracted from inner-function to module-level. The orchestrator becomes a 3-line assembler. **#8 `CheckResult.log_data` removed** — the typed-dict escape hatch on `CheckResult` is replaced by a tuple return from `check_logs(...) -> (CheckResult, LogReportData | None)`. New frozen dataclass `LogReportData(log_days, days_available, total, brute_hits, top_ips, top_ports, svc_hits)` in `bob/checks/logs.py`. `runner.py` unpacks the tuple; `display_log_results` takes the report as an explicit arg. **Net diff: 5 files changed, +109 / −69 = +40 lines** (display.py +23 for explicit helper signatures, logs.py +19 for `LogReportData`, scoring.py −1 for removed field). 4538/4538 tests unchanged — 3 tests renamed (`test_log_data_*` → `test_report_data_*`), ~20 test sites use tuple unpack. Wire output bit-identical to v0.5.2. |
| [v0.5.2](#v052) | 2026-05-22 | Refactor v0.5.x Phase 3 — **#4 + #3**. **#4 SSH directive table** : nouvelles `_BadDirective` dataclass + `_BAD_DIRECTIVES` table (8 entrées) + helper `_apply_bad_directive()` dans `bob/checks/ssh.py`. Migre les 8 directives `sshd_config` uniformes (PermitEmptyPasswords, X11Forwarding, IgnoreRhosts, HostbasedAuthentication, PermitUserEnvironment, StrictModes, AllowTcpForwarding, PubkeyAuthentication) d'une cascade de `if value == "yes"`/`"no"` blocs vers une boucle `for rule in _BAD_DIRECTIVES`. Le helper expose deux styles de prédicats (`bad_values` tuple ou `safe_values` tuple) — `safe_values` couvre le cas AllowTcpForwarding où `"local"` est acceptable en plus de `"no"`. Cas spéciaux préservés en impératif : PermitRootLogin (4-way branch avec sous-états OK), PasswordAuthentication (dépend de `ssh_exposed`), MaxAuthTries (seuil entier), LoginGraceTime (INFO-only), AllowUsers/AllowGroups (info-only), Match block (info-only), weak ciphers/macs/kex (helper `_check_weak_algo` séparé). Net `_check_sshd_config` : ~180 → ~50 LoC, ssh.py total +56 (cost de la dataclass + 8 entrées). **#3 runner._sec extension** avec keyword-only params `skip_if=Callable[[snapshot], bool]` et `post_display=Callable[[snapshot, result], None]`. Permet de remplacer 4 blocs inline par des appels `_sec` 1-liner : `samba` (`skip_if=not s.installed`), `docker_audit` (`skip_if=not s.docker_installed`), `desktop_apps` (`skip_if=not s.detected`), `disk` (`post_display=display_disk_partitions`). Net runner.py : −29 lignes. **#13 (ssh.py split) déféré à Phase 5** — estimation audit (-150 LoC pour #4) trop optimiste, ssh.py reste à 1324 LoC (cible <1000 non atteinte). Tests 4538/4538 inchangés — comportement bit-identique à v0.5.1, c'est purement un re-shape interne. |
| [v0.5.1](#v051) | 2026-05-22 | Refactor v0.5.x Phase 2 — **the big LoC win** (audit finding #1). New `CheckResult.warn_with_deduction(key, *, message, points, reason=None, ...)` and `.alert_with_deduction(...)` helpers in `bob/scoring.py` collapse the paired `result.warn(...) + result.add_deduction(...)` idiom that recurred across ~130 sites in `bob/checks/*.py`. **120 sites migrated** in 27 files: firewall (4), fail2ban (2), clamav (5), ntp (2), ddns (1), updates (2), ssh (24 — the big one), backup (1), log_rotation (3), auditd (3), file_integrity (3), kernel_hardening (3), rootkit (3), hardening (8), samba (6), mac_policy (6), disk (5), iptables_nftables (5), firewall_stack (4), file_perms (1), suid_audit (1), smtp (1), memory (1), network_context (1), cron_audit (2), docker_audit (2), kernel_modules (2), umask (2), user_accounts (2), password_policy (2), secure_boot (2), systemd_timers (2), logs (1), firmware (2), ipv6 (1), ports (1). **13 sites intentionally not migrated** — patterns where the deduction is conditional on a different predicate than the finding (caps via local counter: `services_state`, `ssl_certs` x3, `file_perms` x3, `ipv6.port_no_v6_rule`), or where finding-level branches `warn`/`alert` on a separate condition than the deduction (`docker` x2, `services.exposure`, `ports.uncovered_public`). The `reason=` override handles cases where the deduction uses a `_reason` suffix translation key distinct from the finding message (e.g. `ssh.host_key_dsa_reason` ≠ `ssh.host_key_dsa`). **Net diff: 37 files changed, +483 / −1002 = −519 lines.** Tests unchanged: 4538/4538 pass (helpers are additive, no behaviour change). JSON `schema_version="1"`, the 7 score domains, the 116 EXPLAIN_KEYS, and the 34 filterable sections are all preserved. |
| [v0.5.0](#v050) | 2026-05-21 | Refactor v0.5.x Phase 1 (opens the v0.5.x branch) — **6 audit findings from refactor pass + 1 latent bug found via new test coverage**. **#7** new `is_unit_active()`/`is_unit_enabled()` helpers in `bob.checks._run` migrate 9 sites (`auditd`, `fail2ban`, `clamav`, `ntp`, `ddns`, `updates`, `ssh`, `backup`, `log_rotation`) replacing the repeated `_run("systemctl", "is-active", ...).strip() == "active"` idiom; defensive `.lower()` added centrally to guard against non-canonical distro output. **#2** new `bob.output.print_titled_box(title, width=62)` migrates 4 sites (3× `cron.py` + 1× `manage_logs.py`) and **closes the `--no-color` leak** where those sites bypassed `_c` and printed raw `\033[1;34m` literals. **#10** new `bob.report.Report` `typing.Protocol` (PEP 544 structural type) captures the shared write-method contract between `AuditReport`, `NullReport`, and `MarkdownReport` (which were two duck-typed implementations); `runner.run_checks` now type-hints `report: Report`. **#11** new `emit_section()` + `emit_group()` closures in `runner.py` collapse the `if not config.quiet: print_section(t(...)); report.write_section(t(...))` 3-line idiom into 1-line calls at 20 sites (5 group headers + 15 section headers); `_sec()` itself dogfoods the helper. **#15a** new `tests/test_domain_scores_mapping_complete.py` (+4 tests) AST-scans `bob/checks/*.py` for every literal `key="X.Y"` and asserts each prefix is either explicit in `_PREFIX_TO_DOMAIN` or whitelisted in `_CATCH_ALL_BY_DESIGN` with a justification (the v0.4.x state — `smtp`/`fail2ban`/`desktop_apps`/`virt`/`docker_audit`/`ddns` etc. still fall to the firewall catch-all, deferred to Phase 5 #15b). **Cron coverage pass** (+35 tests) covering the 5 pure helpers untouched by previous test sweeps: `_validate_cron_field` (out-of-range, reversed range, steps, list, empty entry), `_validate_custom_cron` (full 5-field with bounds per field), `build_script_content` (shebang, shlex quoting), `apply_cron_schedule`, `apply_cron_email` (legacy `NOTIFY_EMAIL=` parity). **Latent bug fixed (found by the new cron tests):** `apply_cron_schedule()` called `_os.open(...)` — but `_os` is only locally aliased in 3 *other* functions, never at module level. The v0.4.8 cron-deduplication extraction missed renaming this. The helper had been silently dead since v0.4.8 ship. Fix: `_os` → `os`. 4499 → **4538 tests** (+39: +4 mapping / +35 cron). |
| [v0.4.8](#v048) | 2026-05-21 | Code-quality audit pass 4 (sub-agent) — **I4 real bug** `sudo bob -d` log files were `root:root 0600` and unreadable to the invoking user afterwards (now chowned back via `chown_to_sudo_user` in `bob/report.py` + `bob/manage_logs.py::get_or_prompt_log_dir`, same pattern as the 7 already-chowned config modules) · **dead-field cleanup** 8 dataclass fields removed across 5 checks (`SSHSnapshot.config_source_files`, `FirewallStatus.ipv4_rules_count`+`ipv6_rules_count`, `SambaSnapshot.min_protocol`, `ClamAVSnapshot.last_scan_log_path`+`db_path`, `SecureBootSnapshot.method`) all populated but never read — same bug class as v0.4.3 C1 · `_C_LOCALE_ENV` added to 3 stray `subprocess.check_output` sites (`desktop_apps.py::ps`, `smtp.py::ps`, `smtp.py::ss/netstat`) for locale-consistency · `log_rotation._service_active` inlined to `_run("systemctl", "is-active", ...)` (was an 11-line reinvention) · `apply_cron_schedule()` + `apply_cron_email()` promoted from private helpers to `bob.cron` public API, `bob/tui/cron.py` now imports them — fixes the asymmetric `NOTIFY_EMAIL=` legacy support that was plain-only · `SCORE_BAR_WIDTH = 10` exported from `bob.output` (de-duplicates the `_BAR_WIDTH` constant across `breakdown.py` + `domain_scores.py`) · auth_log 90-day `max_days` documented as intentional (independent of `--log-days` which is for UFW logs) · **pyproject.toml hardening**: `Development Status :: 4 - Beta` → `5 - Production/Stable`, `authors` + `maintainers` added (PyPI was showing UNKNOWN), `[project.optional-dependencies] geoip = ["geoip2>=4.0"]` for `pipx install "bodyguard-of-bits[geoip]"`, `wheel` dropped from build-system requires (auto-resolved since setuptools 70), Source + Documentation URLs added, explicit `dependencies = []` and `include = ["bob", "bob.checks", "bob.tui"]` · 4499/4499 tests (-1: removed `test_default_method_is_none` from test_secure_boot since `method` field is gone) |
| [v0.4.7](#v047) | 2026-05-21 | Doc audit pass + cosmetic gauges + release automation — exhaustive cross-doc audit (24 corrections across 8 files: README/FR · README_TECH/FR · README_DEV/FR · SECURITY_FR · `man/bob.1` · `man/bob-profile.5` · AUTOMATION/FR) · `DOCUMENTS/SNAPSHOT.md` added (~640L internal cartography, 20 correction passes) · gauge bars harmonized via `bob.output.score_bar()` (green ≥8, yellow 5–7, red 0–4 — same colour logic as the disk partition bars) · bash completion comprehensive overhaul (function rename, dead code removed, **critical fix** to `--check=`/`--skip=`/`--format=`/etc. value completion that was silently failing due to `COMP_WORDBREAKS` `=` split) · `publish.yml` auto-creates GitHub Release from `CHANGELOG_FULL.md` on tag push · 4500/4500 tests (unchanged) |
| [v0.4.6](#v046) | 2026-05-17 | Terrain test pass v0.4.5 fixes — **Bug 1** `kernel_modules.py` dpkg-query did not filter on `ii` (installed) state, so kernels removed by `apt remove` / `autoremove` (left in `rc` config-files state) were still listed as "installé". Reproduced on Mint test VM + so6desktop production. Now uses `${db:Status-Abbrev}` and keeps only lines whose 2nd char is `i` (covers `ii`, `hi`). **Bug 2** scoring inversion: after `apt upgrade` resolved a `updates.security_pending` WARN, the only finding left was `updates.ok` → `active_domains_from_engine` dropped the domain → global score *decreased* (denominator shrank). Reproduced on Debian 13 VM (7/10 → 6/10 after remediation). `_actionable` widened from `(WARN, ALERT)` to `(OK, WARN, ALERT)`; INFO-only domains stay hidden by design. 4500/4500 tests (+11) |
| [v0.4.5](#v045) | 2026-05-16 | Test infrastructure hardening — `tests/test_locale_coverage.py` switched from regex scanning to **AST parsing** (`ast.walk` + `ast.Call` + `ast.Name` checks) · eliminates three classes of false positive that the regex form could produce (docstring matches, multi-line call site misparses, `obj._t(...)` attribute calls) · `_KEY_EXCLUSIONS` allowlist deleted entirely · same 9 tests, same external contract, more robust foundation · 4489/4489 tests (unchanged) |
| [v0.4.4](#v044) | 2026-05-15 | Cross-distro terrain hardening — **critical `updates.py` bug** (4/4 Debian-family VMs: 21 Ubuntu LTS security updates undetected): `apt-get -s upgrade` → `dist-upgrade` · stale APT cache detection · cross-check vs `apt list --upgradable` · "Surface d'attaque" propagates `updates_unknown` instead of false "à jour" · AppArmor "0 profil chargé" dedicated key · SMART skip on all-virtual disks · DDNS ports inline in WARN · S4 redesign `_is_safe_user_path` home-bounded · M4 refactor `_parse_ufw_covered_ports` (1 parse + O(1) lookup) · I2 wave-2 `key=` on services/virtualization · new locale-coverage test (catches `[xxx.yyy]` sentinel regressions) · 4489/4489 tests (+21) |
| [v0.4.3](#v043) | 2026-05-15 | Doc catch-up + post-audit hardening pass — 4 firewall keys promoted to `EXPLAIN_KEYS` · `--json --json-full` crash fix (5 dead HardeningSnapshot attrs) · `strptime("%b…")` made locale-independent (ssl_certs + logs) · `_is_covered_by_ufw` false-positive killed · email markdown links no longer escaped · cron range validator now rejects out-of-bounds · `key=` on ~30 findings (docker, firewall_stack, network_context, ports) · 7 dead locale keys removed · i18n concat anti-pattern resolved (ddns, logs) · CIS refs added · CHANGELOG short corrected for v0.4.2 · 4468/4468 tests (+4 regression) |
| [v0.4.2](#v042) | 2026-05-14 | Phase 3 distro-ready (packaging discipline) — `SECURITY.md` threat model · 3 man pages (`bob(1)`, `bob.conf(5)`, `bob-profile(5)`) · `debian/` folder with pybuild + DEP-5 + 3 binary packages (`bob-core`, `bob-tui`, `bob` meta) · `packaging/rpm/bob.spec` Fedora COPR-ready · AppArmor complain profile (`debian/apparmor.d/bob`) · pre-release hardening pass: 2 critical + 5 important + 4 minor + 1 suggestion fixes from agent audit · 4452/4452 tests (+3 in new `test_template_vars_migration.py`) |
| [v0.4.1](#v041) | 2026-05-14 | Phase 2 distro-ready (architectural decoupling) — `bob/tui/` extracted (curses optional) · `Finding.template_vars` / `Deduction.template_vars` additive fields for locale-independent reconstruction · new `bob.formatter` module + post-review hardening pass (`lang=` removed, `i18n.try_t()`, narrowed `except KeyError`) · 3 pilot checks migrated (ssh, hardening, firewall) · template_vars exposed in JSON output · `--offline` mode verified + integration tests · 4449/4449 tests (+19) |
| [v0.4.0](#v040) | 2026-05-14 | Phase 1 distro-ready — exit codes / locale auto-detect (POSIX `$LANG`) / JSON output contract (`schema_version`, `key` fields) / `--explain` alias map / `services.json` formal JSON Schema (with post-review hardening pass #1: strict 1–65535 port regex · `$defs` factorization · `if/then` business constraints · plugin-file `schema_version` wrapper) · pass #2: schema descriptions, `services-list.minItems`, real-class fixtures replacing MagicMock, RefResolver→referencing compat shim · `= N` redundant suffix on stable score removed · 4430/4430 tests (+82) |
| [v0.3.6](#v036) | 2026-05-09 | Code-review pass — `Path.home()` → `get_user_home()` (sudo-aware) in 7 modules · IPv6 ULA/link-local in `_is_private_or_loopback` · SSH `AllowTcpForwarding local` accepted · UFW logging header skipped when UFW inactive · `NOTIFY_EMAIL` legacy regex · 22 unused imports cleaned · 47 dead locale keys removed · 4348/4348 tests |
| [v0.3.5](#v035) | 2026-05-08 | Refactoring — `runner.py` `_sec` closure (−295L) · `ssh.py` `_check_weak_algo` helper · locale fix 4× `UFW-AUDIT` → `BOB` · 4348/4348 tests |
| [v0.3.4](#v034) | 2026-05-08 | Hotfix — `user_config` not passed to `run_checks()` → `NameError` at end of every audit (v0.3.2 regression) · 4348/4348 tests |
| [v0.3.3](#v033) | 2026-05-07 | Architectural refactoring — `cron.py` split · `compute_domain_scores()` pure tuple return · `domain_scores` public API · `_draw`/`_read_key` curses helpers · 4348/4348 tests (+1) |
| [v0.3.2](#v032) | 2026-05-06 | User-configurable SUID whitelist in `config.conf` · 14 code-review fixes (i18n, quiet mode, engine idempotency, dead code) · 4347/4347 tests (+19) |
| [v0.3.1](#v031) | 2026-05-06 | Banner version fix · DDNS context propagation · `was_capped` on Deduction · engine cached properties · 4328/4328 tests (+6) |
| [v0.3.0](#v030) | 2026-05-06 | `--breakdown` score transparency · score-aware `--explain` · kernel -unsigned retention fix · report header relics removed · score delta display · 4322/4322 tests (+48) |
| [v0.2.4](#v024) | 2026-05-05 | Debian -unsigned kernel UX · deduction_total None sentinel · TranslationFunc alias (42 signatures) · _has_shell_ops() via shlex · profile fallback warning · 4274/4274 tests (+12) |
| [v0.2.3](#v023) | 2026-05-03 | Multi-VM audit fixes: NOT_LISTENING WARN→INFO · IoT deduction removed · heredoc display · completion symlink guard · Python 3.9 dropped · compare deduction delta · SSH exposure label split · active_disabled label · 4262/4262 tests (+1) |
| [v0.2.2](#v022) | 2026-05-02 | Scoring refinements: `ScoreCap.key` · INFO domains excluded · ClamAV 1pt · logging uniformity · contract documented · orphan-rule fix · domain cap fix (UFW inactive) · SSH detail locale fix · scoring invariant tests · 4261/4261 tests (+23) |
| [v0.2.1](#v021) | 2026-05-02 | Hotfix — defensive programming pass: crash fix in `--manage-logs` · 8 bare `except Exception` narrowed · 5 regex moved to module level · email regex deduplicated · `getattr` removed from domain scoring |
| [v0.2.0](#v020) | 2026-05-01 | Scoring refactoring (domain average · tool caps) · cron MTA detection · kernel `-unsigned` false positive fix · IoT log dominance WARN · orange banner · 4238/4238 tests |
| [v0.1.1](#v011) | 2026-04-29 | Hotfix — fwupd tree-format parser · `--install-completion` guidance · panorama column rename · 4206/4206 tests |
| [v0.1.0](#v010) | 2026-04-26 | Initial release — 46 checks · 9 domains · 32 services · CIS benchmark mapping · EN/FR · 4200/4200 tests |

---

## [v0.6.2] — 2026-05-29

**Critical packaging hotfix.** Every wheel shipped since v0.6.0 (so v0.6.0 + v0.6.1) was missing `bob/checks/ssh/` and `bob/cron/` — the two subpackages introduced by the v0.6.0 splits. Users who `pipx upgrade`d hit a hard crash at startup:

```
$ sudo bob -v -d --french
Traceback (most recent call last):
  File "/usr/local/bin/bob", line 3, in <module>
    from bob.__main__ import main
  File ".../bob/__main__.py", line 38, in <module>
    from bob.runner import (
  File ".../bob/runner.py", line 46, in <module>
    from bob.checks.ssh import SSHSnapshot, check_ssh
ModuleNotFoundError: No module named 'bob.checks.ssh'
```

### Root cause

`pyproject.toml::[tool.setuptools.packages.find]` had a literal `include = ["bob", "bob.checks", "bob.tui"]` inherited from a v0.4.x packaging audit. When v0.6.0 split `bob/checks/ssh.py` → `bob/checks/ssh/` package and `bob/cron.py` → `bob/cron/` package, this list was not updated. setuptools' `find_packages()` therefore EXCLUDED both subpackages from the wheel — they exist in the source tree but never make it into the distribution.

### Why three test layers missed it

1. **Unit tests** import from the source tree (`from bob.checks.ssh import …` resolves via `sys.path` containing the repo root). The packaging config is irrelevant.
2. **Pre-ship `sudo python3 -m bob` smoke** ran from the working tree (`~/github/bodyguard-of-bits/`). Same source-tree resolution — wheel never involved.
3. **CI `integration.yml`** used `pip install -e .` (editable mode), which adds the repo root to `site-packages` via a `.pth` file. Editable installs DELIBERATELY bypass `find_packages()` discovery for fast iteration — masking exactly this bug class.

The first signal came from a user `pipx upgrade` on a clean system, which builds and installs a real wheel.

### Fix

**`pyproject.toml`**:
```diff
 [tool.setuptools.packages.find]
 where = ["."]
-include = ["bob", "bob.checks", "bob.tui"]
+include = ["bob*"]
```

The glob `bob*` matches `bob`, `bob.checks`, `bob.checks.ssh`, `bob.cron`, `bob.tui`, and any future `bob.*` subpackage. It still excludes the original guard's target (top-level `bob_something/` non-bob dirs).

**`.github/workflows/integration.yml`**:
- Changed `pip install -e .` → `pip install .` (builds + installs a real wheel on each distro)
- Added explicit smoke step that imports every v0.6.x-added module:

```yaml
- name: Smoke — packaging includes all subpackages
  run: |
    python3 -c "import bob.checks.ssh; from bob.checks.ssh import check_ssh, SSHSnapshot"
    python3 -c "import bob.cron; from bob.cron import CronEntry, run_install_cron, _atomic_write"
    python3 -c "from bob._atomic import atomic_write"
    python3 -c "from bob._tty import safe_input, prompt_wizard, read_line"
```

This second guard fails fast on a missing module *at install-time on the CI*, not at runtime on a user system.

### Compatibility

- **JSON contract**, EXPLAIN_KEYS, all wire output — unchanged.
- **Code changes**: zero. Only `pyproject.toml` (1 line) and `.github/workflows/integration.yml` (~15 lines) modified.
- **Tests**: 4600 unchanged. (Test code didn't touch packaging; this bug is not unit-testable without spawning a venv build, which is the new CI step.)
- **Upgrade path**: `pipx upgrade bodyguard-of-bits` on any pipx-installed system to fix the broken install.

### Action required

If you upgraded to v0.6.0 or v0.6.1 via pipx, you currently have a broken install (the binary `bob` crashes on every invocation). Run:

```bash
pipx upgrade bodyguard-of-bits
```

to get the working v0.6.2 wheel.

### Lessons logged

- **Editable installs hide packaging bugs.** All future CI integration jobs use `pip install .` (non-editable).
- **Explicit import smoke step** for every new subpackage is now part of the integration matrix. Adding a new `bob/foo/` subpackage in the future requires adding it to the smoke list — visible in code review.
- **Memory note**: this bug class is a recurring risk for projects that pin package-discovery lists. Glob > literal list for `setuptools.packages.find.include`.

---

## [v0.6.1] — 2026-05-29

**First hardening release on the v0.6.x branch.** Deep audit sub-agent pass produced 14 findings (0 critical + 6 important + 8 minor); 6 important + 4 minor shipped. The audit revealed two **half-applied contracts** from v0.5.x — atomic-write (mutation paths fixed in v0.5.7 #I-3 but not creation paths) and EOF handling (`manage_logs.py` fixed in v0.5.7 #I-2 but not cron wizards or `fixes.py`) — plus one **untested validator branch** in the cron step parser. All addressed with localized fixes.

### Important (6)

**I-1 + atomic-write contract consolidation** — Extracted `bob/_atomic.py::atomic_write(path, content, *, mode=)` as the single source of truth for crash-safe persistence. Migrated 5 sites that were hand-rolling the temp+rename pattern (`bob/config.py:UserConfig._save` + `EmailStore._save`, `bob/compare.py:save_baseline`, `bob/history.py:_rotate_if_needed`, `bob/recurrence.py:save_recurrence`). Fixed 4 sites that were NOT atomic at all:
- `bob/cron/_install.py:261, 280` (script + cron file fresh install)
- `bob/tui/cron.py:731, 749` (same paths in curses install)
- `bob/ignore.py:93` (ignore.yml — I-6)
- `bob/history.py:58` (first-write mode 0o600 — I-5, see below)

`bob/cron/_io.py::_atomic_write` kept as an alias (`from bob._atomic import atomic_write as _atomic_write`) — the existing `TestApplyCronScheduleAtomic` test patches that name directly.

**I-2 — EOF contract completion** — `bob/_tty.py` gained a `safe_input(prompt)` wrapper that catches `EOFError` and returns `""`. `prompt_wizard()` now also catches `EOFError` and returns `None` (consistent with `read_line()`). Migrated 11 bare `input()` sites: `bob/cron/_install.py` (5), `bob/cron/_manage.py` (5), `bob/fixes.py` (1). Ctrl-D no longer crashes any plain-text wizard.

**I-3 — `_validate_cron_field` step bounds** — `*/200` for minute (0-59) was accepted by validation; cron then interpreted it as "every 200 minutes" → never fires (rolls over hourly). Added `if int(step_s) > (hi - lo + 1)` check after the existing `>= 1` validation. Now `*/200 minute` returns `"minute step '200' exceeds field range (60)"`.

**I-4 — `shlex.quote()` on `cmd=` paths** — 8 sites where `--fix --apply` would `shlex.split()` paths containing spaces and apply chmod to the wrong file:
- `bob/checks/ssh/_subchecks.py:117, 281, 306, 369` (host key removal, `~/.ssh` dir, private key, authorized_keys — paths from `pwd.getpwnam(SUDO_USER).pw_dir`)
- `bob/checks/file_perms.py:228, 238, 257` (world-writable / over-permissive / sensitive paths from filesystem scan)
- `bob/checks/firmware.py:186` (microcode package name)

`bob/checks/ssl_certs.py:176` was already quoted at the variable definition (`_cert_name = shlex.quote(...)`).

**I-5 — `history.jsonl` mode `0o600` on first write** — `_HISTORY_FILE.open("a")` used the process umask (typically `0o644` → world-readable). Score timestamps are privacy-sensitive on shared systems. Switched to `os.open(O_WRONLY | O_APPEND | O_CREAT, 0o600)` which sets mode only on creation; existing-file mode is preserved.

**I-6 — `ignore.py` atomic write** — `bob/ignore.py:93` wrote `ignore.yml` via raw `os.open(O_TRUNC)`. Power-loss / OOM corrupted the file. Migrated to `atomic_write(path, content, mode=0o600)` (single helper from I-1 consolidation).

### Minor (4 shipped)

| # | Fix |
|---|---|
| **M-2** | `bob/checks/ssh/_directives.py::_apply_bad_directive` was calling `.lower()` twice (`is_bad` already lower-cases internally). Dropped the outer call. |
| **M-3** | `bob/checks/ssh/_subchecks.py` `MaxAuthTries=-1` / `=0` was previously accepted. Now treated as the default 6 (sshd treats `<=0` as "no retry" which is also misconfiguration). |
| **M-6** | `bob/__main__.py:405` `Fatal error: …` one-line print made bug reports useless. Now hints `Set BOB_DEBUG=1 for full traceback` and prints the traceback when the env var is set. |
| **M-8** | `bob/cli.py` `--watch=N` error wording: `"positive integer"` → `"integer ≥ 10"` (matches the actual constraint). |

### Minor (4 deferred / judgment-call)

- **M-1** `parse_cron_file` silent downgrade of non-numeric hour/minute to `0` — only used as wizard default, low-impact, kept as-is
- **M-4** Module-level path constants computed at import time — DOCUMENTED as intentional (M7 lazy resolution discarded in SNAPSHOT.md)
- **M-5** fd leak window in install paths — addressed transitively by I-1 atomic_write migration
- **M-7** `--check/--skip` warning vs always-on sections mismatch — judgment call, deferred to a UX review pass

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4600 passed in ~7s
```

**4583 → 4600 (+17).** New test class structure:

`tests/test_atomic_v061.py` (12 tests):
- `TestAtomicWritePublicAPI` (4) — pins the `atomic_write(path, content, *, mode=)` contract (mode preserved, content overwritten cleanly, original survives on simulated failure)
- `TestCronLegacyAliasStillWorks` (1) — `bob.cron._io._atomic_write is bob._atomic.atomic_write`
- `TestHistoryFileMode` (2) — I-5 first-write 0o600, mode preserved on append
- `TestIgnoreAtomic` (2) — I-6 atomic write + crash-safety
- `TestSafeInput` (3) — I-2 `safe_input()` + `prompt_wizard()` EOFError handling

`tests/test_cron.py::TestStepBoundedToFieldRange` (5 tests) — I-3 step bounds for minute / hour / boundary / zero / full expression.

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — unchanged.
- **Per-domain score**: unchanged. Global score unchanged.
- **Wire output**: unchanged. `--watch=N` error wording is the only user-visible string change.
- **External Python API**: `bob._atomic.atomic_write` is a new module-level helper (semi-public via `_` prefix on module name). `bob._tty.safe_input` is new public. Both additive.
- **Backwards-compat**: `bob.cron._io._atomic_write` still exists as an alias — existing test patches keep working. The 5 migrated atomic-write sites preserve the exact same wire-output (just routed through the central helper).
- **Keybindings**, **no-curses fallback**, **exit codes** — unchanged.

### Audit campaign tracking

| Release | Findings | Tests |
|---|---|---|
| v0.5.5 | 19 (4C + 4I + 11M) | +7 |
| v0.5.6 | 10 (0C + 2I + 8M) | +15 |
| v0.5.7 + v0.5.8 | 11 (0C + 3I + 8M) | +23 |
| **v0.6.1** | **14 (0C + 6I + 8M)** | **+17** |

**Cumulative**: 30 modules deep-audited, 0 critical findings outstanding. Two contracts (atomic-write, EOF handling) now uniformly enforced across the codebase.

---

## [v0.6.0] — 2026-05-25

**Major bump opening the v0.6.x branch.** Two architectural splits (#13 + #14) deliberately deferred across the entire v0.5.x cycle, plus one sunset honored. All three changes are contract-preserving via package `__init__.py` re-exports — every `from bob.checks.ssh import …` or `from bob.cron import …` call site in the codebase and in user scripts continues to work unchanged.

### #13 — `bob/checks/ssh.py` → `bob/checks/ssh/` package

The 1296-line SSH check module split into 4 focused submodules:

| Module | LoC | Content |
|---|---|---|
| `_directives.py` | 165 | `_BadDirective` declarative table + `_BAD_DIRECTIVES` tuple + `_apply_bad_directive` helper + weak crypto reference sets (`_WEAK_CIPHERS`, `_WEAK_MACS`, `_WEAK_KEX`) |
| `_snapshot.py` | 198 | 5 dataclasses (`HostKeyInfo`, `PrivateKeyInfo`, `AuthorizedKeyEntry`, `KnownHostEntry`, `ClientConfigEntry`) + `SSHSnapshot` + `SSHSnapshot.from_system` |
| `_parsers.py` | 446 | Pure parsers: `_parse_config_file`, `_collect_private_keys`, `_detect_private_key_type`, `_key_type_from_algo`, `_rsa_bits_from_*`, `_has_passphrase`, `_parse_authorized_keys`, `_parse_client_config`, `_parse_known_hosts`, `_collect_host_keys`, `_detect_ssh_install_cmd`, `_parse_time_seconds` |
| `_subchecks.py` | 529 | `check_ssh` entry point + all `_check_*` per-area helpers (`_check_host_keys`, `_check_sshd_config`, `_check_weak_algo`, `_check_ssh_dir`, `_check_private_keys`, `_check_authorized_keys`, `_check_client_config`, `_check_known_hosts`) |
| `__init__.py` | 64 | Public re-exports |

**Cycle break**: `_parsers` imports dataclasses from `_snapshot` at module level; `_snapshot.SSHSnapshot.from_system` uses a function-local `from . import _parsers` import to avoid the otherwise-circular dep. Clean and intention-revealing.

### #14 — `bob/cron.py` → `bob/cron/` package

The 1204-line cron module split into 4 focused submodules:

| Module | LoC | Content |
|---|---|---|
| `_parse.py` | 330 | `CronEntry` dataclass + `parse_cron_file` + `list_installed_crons` + `cron_to_human` + `build_schedule_expr` + `make_slug` + `suggest_name` + `_validate_cron_field` + `_validate_custom_cron` + `_parse_day_names` + `_parse_dom` + `_ordinal` + `_detect_mta` + constants (`CRON_DIR`, `SCRIPT_DIR`, `LEGACY_*`, `_DAYS_EN`, `_DAYS_FR`, `_CRON_FIELD_BOUNDS`) |
| `_io.py` | 164 | `_atomic_write` + `build_script_content` + `apply_cron_schedule` + `apply_cron_email` (all file-mutation helpers) |
| `_install.py` | 319 | `prompt_emails` + `prompt_email` + `_run_install_cron_plain` + `run_install_cron` + `_CronQuit` exception (shared with `_manage`) |
| `_manage.py` | 445 | `_manage_email_store` + `edit_cron_email` + `edit_cron_schedule` + `_run_manage_cron_plain` + `run_manage_cron` |
| `__init__.py` | 101 | Public re-exports incl. `datetime` + `_EMAIL_RE` for backwards-compat |

**Note on `build_script_content` path resolution**: the function uses `Path(__file__).parent.parent.parent` to derive `PYTHONPATH` for the generated cron script — post-split `__file__` resolves to `bob/cron/_io.py` so we now walk THREE parents (`_io.py` → `cron/` → `bob/` → repo root) instead of two. Verified by the existing smoke test (`tests/test_cron.py::TestDatetimeImportLifted::test_build_script_content_still_stamps_date`).

### Sunset: `UFW_AUDIT_SHARE` legacy env var

Announced "REMOVED in v0.6.0" by the deprecation warning shipped in v0.5.4 (`bob/_paths.py:60`). Honored. Only `BOB_SHARE` is now accepted by `resolve_share_dir()`. Installers still setting `UFW_AUDIT_SHARE` will see no effect — update them to use `BOB_SHARE`. The deprecation chain:

- v0.4.2: `BOB_SHARE` becomes the documented contract; `UFW_AUDIT_SHARE` accepted as legacy alias
- v0.5.4: `logger.info(...)` upgraded to `logger.warning(...)` with explicit "REMOVED in v0.6.0" message
- **v0.6.0**: Removed (this release)

3-line drop in `bob/_paths.py` (the `_ENV_LEGACY` constant, the fallback read, and the legacy warning branch) plus 2 docstring updates in `bob/i18n.py` and `bob/registry.py`.

### Backwards compatibility

Every public symbol from the v0.5.x monoliths is re-exported by the new packages' `__init__.py`:

```python
# Still works in v0.6.0:
from bob.checks.ssh import SSHSnapshot, check_ssh, AuthorizedKeyEntry  # and 8+ more
from bob.cron import CronEntry, run_install_cron, apply_cron_schedule, _EMAIL_RE, datetime, _CronQuit
```

This was the deciding factor for the conservative split — the alternative (forcing user-visible import-path changes) would be a true breaking change and is not warranted for an internal refactor. The packaging keeps the option open for v0.7+ if a deeper API redesign is wanted later.

### Test infrastructure updates (2 trivial AST scan fixes)

The check-module discovery in two introspection tests needed to recurse into the new package directories:

- **`tests/test_template_vars_migration.py`**: `_check_modules()` (now `_module_paths()`) walks `iterdir()` and returns either single `.py` files or package directories; `_module_has_template_vars(path)` does `rglob("*.py")` for package targets. Pilot list converted from `frozenset({"ssh.py", "hardening.py", "firewall.py"})` to module-name form `frozenset({"ssh", "hardening", "firewall"})`.
- **`tests/test_domain_scores_mapping_complete.py`**: single-line change — `_CHECKS_DIR.glob("*.py")` → `_CHECKS_DIR.rglob("*.py")` with `__pycache__` filter, so the AST scan picks up `bob/checks/ssh/_subchecks.py` and all sibling submodule key emissions.

One regression test (`tests/test_cron.py::TestApplyCronScheduleAtomic`) was updated to spy on `bob.cron._io._atomic_write` rather than the package-level re-export — because `apply_cron_schedule` now lives in `_io.py` and calls the local `_atomic_write` directly. The spy needs to be set on the module where the call site reads it.

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — unchanged.
- **Per-domain score**: unchanged. Global score unchanged.
- **Wire output**: unchanged.
- **External Python API**: all v0.5.x public symbols re-exported from the new packages. No removals.
- **Environment variables**: `UFW_AUDIT_SHARE` removed (announced for 12+ months). Only `BOB_SHARE` accepted.
- **Keybindings**, **no-curses fallback**, **exit codes** — unchanged.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4583 passed in ~7s
```

**4583 unchanged.** No new tests, no removed tests — the splits + sunset are structural and don't change behaviour. The 3 test files updated (template_vars_migration, domain_scores_mapping_complete, test_cron) shift assertion targets to accommodate the new module layout but keep the same coverage scope.

### Net diff

| File | Delta |
|---|---|
| `bob/checks/ssh.py` (deleted) | −1296L |
| `bob/checks/ssh/__init__.py` + 4 submodules | +1402L (165 + 198 + 446 + 529 + 64) |
| `bob/cron.py` (deleted) | −1204L |
| `bob/cron/__init__.py` + 4 submodules | +1359L (330 + 164 + 319 + 445 + 101) |
| `bob/_paths.py` | −20L (legacy alias path + warning) |
| `bob/i18n.py`, `bob/registry.py` | −2L (docstring updates) |
| 2 test file updates | +20L net (rglob + path-not-stem migration) |
| 1 test patch-target fix | +2L net (cron_io vs cron_mod) |
| Version bump + changelogs | standard ~17 files |

Overhead: +331L total across both packages vs the monolithic equivalent. That's the cost of `__init__.py` re-exports + module-level imports + per-file docstrings. Worth it for the modularity.

### Roadmap

v0.6.0 closes the architectural-split backlog from v0.5.x. The v0.6.x branch will host:
- **Maintenance** of the now-modular structure
- **Field bug reports** from cross-distro testing
- **TUI prompt unification** (`_curses_readline` / `prompt_wizard` / `_rl` → flatter hierarchy) — was listed as v0.6.0 candidate but punted to maintain release focus
- **JSON schema v2 cadence planning** (preparation for breaking changes in v1.0)
- **Python 3.10 EOL preparation** (will become minimum-version bump candidate in v0.7+)

No deep-audit campaign planned for v0.6.x — the v0.5.x campaign closed comprehensively (25 modules deep-audited + ~25 spot-checked, 0 critical findings outstanding).

---

## [v0.5.8] — 2026-05-25

**Cleanup release.** Clears the 5 cosmetic minors explicitly deferred by v0.5.7 (M-2, M-5, M-6, M-7, M-8). All five are layout / readability / explicit-naming improvements with zero behaviour change in normal operation. **This closes the v0.5.x deep-audit campaign.**

### Fixes (5)

**M-2 — `manage_logs.py` cursor shift after delete**

`cursor = max(0, cursor - deleted)` assumed all deletions sat at or before the cursor. With multi-selection where some marked items were AFTER the active cursor position, the cursor still shifted left by the full deletion count → it ended up on the wrong file. Now:

```python
deleted_before_cursor = 0
for li in sorted(pending_delete, reverse=True):
    ...
    if li <= cursor:
        deleted_before_cursor += 1
...
cursor = max(0, cursor - deleted_before_cursor)
```

**M-5 — Schedule wizard constants → module-level `IntEnum`**

The wizard had a local tuple-unpack `_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4` (note the throwaway `_` for DAILY = 1). Promoted to:

```python
class _Schedule(IntEnum):
    DAILY = 1
    WEEKDAYS = 2
    MONTHDAYS = 3
    CUSTOM = 4
```

`IntEnum` preserves `choice == _Schedule.WEEKDAYS` semantics where `choice` is a plain int derived from menu position. Three call sites updated (`if choice == _Schedule.WEEKDAYS:` etc.).

**M-6 — `_extract_summary_view` sentinel `None`**

`summary_start = 0` + `if summary_start: break` treated index 0 as "not found". If the `SEP62` separator sat on line 0 (unreachable in practice — logs always start with header lines), the loop would mis-detect. Replaced with:

```python
summary_start: int | None = None
...
if summary_start is not None:
    break
```

**M-7 — `_extract_summary_view` over-greedy continuation grouping**

`while ... lines[j].startswith("    ")` swallowed ANY 4-space-indented line as continuation of the previous ALERT/WARN finding, including unrelated body lines from other sections. Extracted helper:

```python
def _is_finding_continuation(line: str) -> bool:
    if not line.startswith("    "):
        return False
    stripped = line.lstrip()
    if any(m in stripped for m in ("[ALERT]", "[WARN]", "[OK]", "[INFO]")):
        return False
    if stripped[:1] in ("┌", "└", "│", "━", "╔", "╠", "╚", "║"):
        return False
    return True
```

Stops on finding markers and on section delimiters even if the line happens to be 4-space indented. Layout-only fix; no security impact.

**M-8 — `from datetime import datetime` lifted to module top**

Three local imports inside function bodies (`bob/cron.py:_run_install_cron_plain`, `bob/cron.py:build_script_content`, `bob/tui/cron.py:_run_install_cron_curses`) → one module-level import in each file. Also removes a redundant local `import os` and `from pathlib import Path` (both already imported at top of `bob/cron.py`).

### Tests

`tests/test_cron.py`:
- `TestScheduleIntEnum` (2) — values match menu indices; IntEnum compares equal to plain int (preserves existing call-site semantics).
- `TestDatetimeImportLifted` (3) — `bob.cron.datetime` and `bob.tui.cron.datetime` are exposed at module level + smoke test `build_script_content` still stamps today's date.

`tests/test_manage_logs.py`:
- `TestCursorShiftAfterDelete` (2) — mixed before/after deletion shifts cursor only by the before-count; all-after deletions leave cursor unchanged.
- `TestSummaryStartSentinel` (1) — synthetic SEP62-at-index-0 edge case correctly detected.
- `TestIsFindingContinuation` (4) — accepts indented body lines; rejects non-indented; rejects indented `[ALERT]`/`[WARN]`/`[OK]`/`[INFO]` markers; rejects indented section delimiters.

4571 → **4583 tests** (+12).

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — unchanged.
- **Score**: unchanged. No score-engine changes.
- **Wire output**: unchanged.
- **External API**: `_Schedule(IntEnum)` and `_is_finding_continuation()` are new module-level symbols in `bob.tui.cron` and `bob.manage_logs` respectively. No removals. Three local `from datetime import datetime` statements deleted from function bodies (not part of any public surface).
- **Keybindings**: unchanged.

### v0.5.x deep-audit campaign — CLOSED

After v0.5.8, the v0.5.x branch is at its final maintenance state:

| Release | Scope | Findings shipped |
|---|---|---|
| v0.5.5 | 22 core modules (deep) + ~15 spot-checked | 19 (4C + 4I + 11M) |
| v0.5.6 | `bob/checks/logs.py` (662L) | 10 (0C + 2I + 8M) |
| v0.5.7 | `bob/manage_logs.py` + `bob/tui/cron.py` (~1920L) | 6 shipped + 5 deferred |
| **v0.5.8** | **The 5 v0.5.7-deferred minors** | **5 (all minor)** |

**Total**: 25 modules deeply audited + ~25 spot-checked. 0 critical findings outstanding on the branch.

### What's next

- **v0.6.0** (major bump) reserved for the deliberately-deferred architectural refactors:
  - **#13**: split `bob/checks/ssh.py` (1324 LoC after the v0.5.2 `_BadDirective` table consolidation)
  - **#14**: split `bob/cron.py` (1223 LoC after the v0.4.8 file-patching helper extraction + v0.5.8 import lift)
  - Other architectural decisions (TUI prompt unification, JSON schema v2 cadence, etc.)

Both files exceed the project's soft 1000-LoC ceiling. The splits were deferred because gain × risk did not justify the churn in a contract-preserving minor release.

---

## [v0.5.7] — 2026-05-24

**Targeted hardening pass on curses TUI.** The v0.5.5 and v0.5.6 audits explicitly deferred `bob/manage_logs.py` (999 LoC) and `bob/tui/cron.py` (920 LoC) — the two main interactive curses modules — to a dedicated future pass. This release closes that bucket. A focused sub-agent produced 11 findings; 6 ship in v0.5.7 (3 important + 3 trivial minors), 5 cosmetic minors are documented for v0.5.8.

### Important (3)

**I-1 — `_curses_readline` accepted curses `KEY_*` codes as input characters**

`_read_key` collapses `stdscr.get_wch()` output into a single int regardless of whether the underlying type was `str` (printable) or `int` (keypad). Downstream, `_curses_readline` filtered on `ch_i >= ord(" ")` — but special keys like `curses.KEY_UP = 259`, `KEY_F1 = 265`, `KEY_RIGHT = 261` all pass that gate. `chr(259)` is `Ι` (Greek capital iota), `chr(265)` is `Ω`. Pressing arrow keys or function keys in name/email/days/time/custom-expression prompts inserted Greek glyphs into the input buffer.

No security impact — every downstream consumer validates: `_EMAIL_RE` rejects garbage, `_validate_custom_cron` rejects malformed cron expressions, `re.split` + `isdigit()` filtering drops non-digits, `make_slug` whitelist-regex strips everything outside `[a-z0-9]`. But UX-visibly corrupted (`Mon Audit│Ι Ω`).

Fix: extracted `_is_printable_input_char(ch_i)` helper at module scope bounding inputs to `32 <= ch_i < 256 and chr(ch_i).isprintable()`. Pure Latin-1 printable range; explicitly rejects all `curses.KEY_*` constants (all ≥ 256).

**I-2 — Bare `input()` sites raised on Ctrl-D**

Three `input()` calls inside `manage_logs.py` propagated `EOFError` directly: the path prompt in `prompt_path()` (line 104), the move-logs `[y/N]` confirmation in the change-location branch (line 360), and the delete-all `[y/N]` confirmation (line 378). All other interactive read sites in the codebase route through `bob._tty.read_line` which already maps `EOFError` to empty string. Ctrl-D at any of these three prompts dumped a Python traceback to the user.

Fix: wrapped each `input()` in `try/except EOFError` matching the `_rl()` convention — EOF treated as empty string, which falls through to "use default" for path prompts and "no" for confirmations. `KeyboardInterrupt` deliberately not caught (Python's default exit 130 is correct).

**I-3 — `apply_cron_schedule` not atomic**

Lives in `bob/cron.py` (technically out of the TUI scope strictly speaking) but the curses cron-edit flow is its primary caller via `_apply_cron_schedule` (`bob/tui/cron.py:135`). The function did:

```python
fd = os.open(str(entry.cron_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
with os.fdopen(fd, "w") as fh:
    fh.write(new_text)
```

Power loss, `SIGKILL`, or process crash between `open(O_TRUNC)` and `write` completing would leave the cron file empty. `cron` and `crond` then silently drop the entry — no warning, no failed notification, the scheduled audit just stops running. Asymmetric with the sister function `apply_cron_email` which already used `_atomic_write` (introduced in v0.5.5 #C-1).

Fix: switched to `_atomic_write(entry.cron_path, new_text, mode=0o640)`. Mode `0o640` preserved (cron skips files with wrong mode). One-line change; existing `TestApplyCronSchedule` tests still pass.

### Minor (3 shipped + 5 deferred to v0.5.8)

| # | Status | Fix |
|---|---|---|
| **M-1** | shipped | `manage_logs.deleted_one` status flashed `pending_delete[0].name` even when index 0 failed to unlink (permission denied) and only a different index succeeded — visible filename mismatched the deletion. Now tracks the FIRST successfully-deleted name explicitly |
| **M-3** | shipped | Dead-code elif body in `_curses_edit_sub` (`if ch_i == ord("1"): chosen = 0 elif ord("2"): chosen = 1` — guard already constrained `chosen == sel`). Simplified to single `chosen = sel`, elif rewritten with explicit parentheses for readability |
| **M-4** | shipped | Duplicate `from bob.cron import apply_cron_schedule, apply_cron_email` at line 132 (after a section comment) consolidated into the main import block at the top. Section comment trimmed |
| **M-2** | deferred v0.5.8 | Cursor shift after delete assumes all deletions sit before cursor — cosmetic |
| **M-5** | deferred v0.5.8 | Local-scoped schedule wizard constants (`_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4`) → promote to module-level `IntEnum` |
| **M-6** | deferred v0.5.8 | `_extract_summary_view` `summary_start` falsy check misses index 0 (unreachable in practice; sentinel `None` would be cleaner) |
| **M-7** | deferred v0.5.8 | Continuation-line grouping in `_extract_summary_view` over-greedy — swallows any 4-space-indented line, including unrelated body lines from other sections. Layout-only artifact |
| **M-8** | deferred v0.5.8 | Local `from datetime import datetime` inside cron build block — lift to module top |

### Cross-cutting observations (informational, not findings)

- **No `datetime.now()` comparison vulnerabilities** found across the 1920 LoC scope — only one `datetime.now()` site exists (cron header timestamp generation, no comparison). The v0.5.6 #I-2 bug class is contained to `logs.py`.
- **No `os.system`, `shell=True`, or unsanitized subprocess calls** in either module. Cron generation in `bob/cron.py::build_script_content` already uses `shlex.quote` for all user-controlled fields (notify_email, log_dir, audit_bin, bob_path).
- **No path-traversal opening** — `prompt_path` calls `_resolve_path` which does `Path(raw).expanduser().resolve()` (normalizes `..`, follows symlinks once).
- **`raw_name` cannot inject crontab lines** despite being written verbatim into `# name: {raw_name}` cron header comments: `_curses_readline` filters `\n`/`\r`/`\t` (< 32), and terminal pasting collapses multi-line input to single-line.

### Bug class lineage

- **I-3** mirrors **v0.5.5 #C-1** (`_atomic_write` mode regression) and **v0.5.5 #I-1** (`recurrence.py` / `ignore.py` mode 0o600 enforcement) — atomic-write contract enforcement is now uniform across all file mutations in the codebase.
- **I-2** mirrors **v0.5.5 #C-2/C-3** (defensive UX) — Ctrl-D / Ctrl-C handling is now uniform across all interactive read sites (`_rl`, `prompt_path`, both confirm prompts).

### Test coverage

- `tests/test_cron.py`: +6 tests (`TestApplyCronScheduleAtomic`, `TestIsPrintableInputChar`)
- `tests/test_manage_logs.py`: +5 tests (`TestEOFErrorOnPromptPath`, `TestEOFErrorOnMoveConfirm`, `TestEOFErrorOnDeleteAllConfirm`, `TestDeletedOneCorrectName`)
- 4560 → **4571 tests** (+11)

### What's NOT in this release

- The 5 deferred minors (M-2, M-5, M-6, M-7, M-8) — explicitly tracked for v0.5.8
- No man-page changes (TUI keybindings unchanged)
- No locale changes (no user-facing string churn)
- No `bob/data/services.json` changes
- No score-engine changes
- No new public APIs

### Roadmap

After v0.5.7, the v0.5.x branch has been deeply audited end-to-end (22 core modules in v0.5.5 + `checks/logs.py` in v0.5.6 + the 2 curses TUI modules in v0.5.7 = 25 modules deep-audit + ~25 others spot-checked). v0.5.8 will clear the 5 deferred TUI minors. The next minor-version cap (v0.6.0) is reserved for #13 (`ssh.py` 1324 LoC split) and #14 (`cron.py` 1223 LoC split), the two deliberately-deferred architectural refactors from the v0.5.x roadmap.

---

## [v0.5.6] — 2026-05-24

**Targeted hardening pass on `bob/checks/logs.py`.** The v0.5.5 audit explicitly deferred this module ("not deeply audited") because of its regex density — UFW log parser + systemd-journald fallback + GeoIP2 integration + bruteforce detection in 662 LoC. A focused sub-agent audit produced 10 findings: 0 critical, 2 important, 8 minor. All ship in this single-module release.

### Important (2)

**I-1 — `_PRIVATE_IP` regex inconsistent with `sysinfo.py`**

The hand-rolled `^(10\.|172\.…|192\.168\.|127\.|::1$|fc|fd)` regex had three problems vs the canonical `sysinfo._is_private_or_loopback_ipv4/_ipv6` helpers (rewritten in v0.5.5 #I-4):
- **Missed CGNAT** (`100.64.0.0/10`, RFC 6598) — sources behind carrier-grade NAT got GeoIP-looked-up instead of labelled "local"
- **Missed IPv6 link-local** (`fe80::/10`) — local IoT noise mis-classified as public
- **False positive on any string starting `fc`/`fd`** — e.g. `"fcsa"`, `"fdgarbage"` matched as "local" (lucky harmless today because the SRC field is always an IP, but inconsistent with the model)

Same finding class as v0.5.5 #I-4 (`sysinfo._PRIVATE_IPV4_RE`). Fix: new `_is_private_ip(ip)` helper in `logs.py` dispatches by `:` and delegates to `sysinfo._is_private_or_loopback_ipv4/_ipv6`. Single source of truth across the codebase.

**I-2 — Year-rollover dropped near-realtime syslog events**

`_parse_timestamp` falls back to `current_year` for syslog format (no year in the line). The rollback heuristic was:
```python
if ts > datetime.now():
    ts = ts.replace(year=ts.year - 1)
```

A syslog event timestamped `12:00:01` parsed at wall-clock `12:00:00` (1s in the future from NTP jitter / log buffer flush / clock skew) was rolled back a full year → fell outside `cutoff_dt = now - timedelta(days=log_days)` → **silently dropped**. Real impact on busy systems with high UFW BLOCK rates.

Bonus subtle bug: `current_year` and `datetime.now()` are called at different points in the parse loop, so the year-rollover decision could disagree with `current_year` if the parse straddles midnight Dec 31.

Fix: snapshot `now` once at the top of `_parse_log`, pass it to `_parse_timestamp`, and use `if ts > now + timedelta(minutes=5)` to absorb skew while still catching genuine year-end Dec entries parsed in Jan.

### Minor (8)

| # | Fix |
|---|---|
| **M-1** | Anchored `r"\[UFW BLOCK6?\]"` matcher — accepts the `[UFW BLOCK6]` IPv6 variant (silently dropped pre-v0.5.6) and rejects substring spoofing |
| **M-2** | `_count_available_days` regex restricted to English month names — was inflated by non-date leading tokens (e.g. `"mai 23"`, kernel boot facility names) |
| **M-3** | `_GEOIP2_DB_PATHS` reordered: all City entries first across all dirs, then all Country — `_geo_via_geoip2` returns on first hit, so City always wins richer data when both DBs exist |
| **M-4** | `geoip2_status()` now accepts symlinks (`Path.resolve(strict=True)`) — matching `_geo_via_geoip2` which already does. Fixes contradictory "no database installed" notice on `geoipupdate` setups using symlinks |
| **M-5** | `_GEO_CACHE` bounded at 2048 entries with FIFO eviction via `_geo_cache_put()` helper — prevents unbounded growth in long-lived embedders |
| **M-6** | `LogsSnapshot.from_system` reads in binary mode (`open("rb")` + `.decode("utf-8", errors="ignore")`) — `TextIOBase.tell()` returns an opaque number per docs; the byte-offset arithmetic worked by accident on CPython |
| **M-7** | `except (OSError, subprocess.SubprocessError)` — dropped redundant `subprocess.TimeoutExpired` (subclass of SubprocessError) |
| **M-8** | `proto.upper()` at parse time — a downstream patched UFW emitting lowercase `proto` would silently split a single bruteforce campaign into two sub-groups under threshold |

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4560 passed in ~6s
```

**4545 → 4560 (+15).** New `tests/test_logs.py` classes:
- `TestPrivateIPDispatch` (8 tests) — pins CGNAT, IPv6 link-local, ULA, public IPv4, invalid-string edge cases (I-1)
- `TestParseTimestampYearRollover` (3 tests) — current-year, 1s-skew, genuine December rollback (I-2)
- `TestBlockPrefixMatcher` (3 tests) — `[UFW BLOCK]`, `[UFW BLOCK6]`, `[UFW ALLOW]` rejection (M-1)
- `TestProtoNormalisation` (1 test) — lowercase proto upper-cased at parse (M-8)

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — unchanged.
- **Wire output**: unchanged on standard UFW configs. Visible delta only on:
  - Hosts emitting `[UFW BLOCK6]` (previously silently dropped — now counted in `total` and `top_ips`)
  - Hosts with mixed-locale syslog content (previously inflated `days_available` count — now accurate)
- **External API**: `_is_private_ip(ip)` is a new semi-public helper. `_PRIVATE_IP` constant removed (was undocumented; one downstream `pipx`-installed user might import it — unlikely).
- **Per-domain score**: unchanged. Global score unchanged.
- **i18n**: no locale key changes.

### Coverage

Single-module pass: `bob/checks/logs.py` audited in full. No other module touched.

Remaining queue (per audit roadmap): **v0.5.7** = `manage_logs.py` + `bob/tui/cron.py` curses TUI (~1920 LoC combined). After that, the v0.5.x line is fully audited.

---

## [v0.5.5] — 2026-05-24

**Hardening pass — post-v0.5.4 audit by a deep sub-agent.** 4 real bugs + 4 security smells + 11 minor cleanups = **19 findings** addressed (17 with code/test changes, 2 with doc comments). Companion cosmetic commit migrates `Optional[X]` / `List[X]` typing on 18 modules.

### Critical bugs (4)

**C-1 — `apply_cron_email()` silently broke scheduled audits**
`bob/cron.py:apply_cron_email()` rewrote both cron files and wrapper scripts via `_atomic_write()`, which always opened the temp file with mode `0o600`. After `os.replace()` the new file inherited that mode — so the wrapper script (originally `0o755`) lost its executable bit. Cron continued reading the cron file but **could no longer exec the script**, and the scheduled audit silently never ran. Anyone who used `bob --manage-cron` to change their notification email entered this state.

`_atomic_write(path, content, mode=0o600)` now takes an explicit mode. Callers in `apply_cron_email` pass `0o640` (cron file) and `0o755` (script). Regression test added to `tests/test_cron.py::TestApplyCronEmail::test_preserves_script_executable_mode`.

**C-2 — `password_policy.no_quality_module` cmd unfixable**
`cmd="sudo apt install libpam-pwquality && sudo pam-auth-update"` emitted with `nature="action"` → `--fix --apply` rejected it via `fixes._has_shell_ops` (the `&&` is correctly flagged as unsafe shell syntax). User saw the cmd in the summary but pressing `y` did nothing.

Fix: demoted to `nature="improvement"`. The cmd still appears in the audit output as guidance — it just doesn't enter the fix-mode queue. Two-step `apt install … && pam-auth-update` isn't safely chainable in a single exec anyway.

**C-3 — `password_policy.weak_minlen` cmd is decorative, not executable**
`cmd="sudo nano /etc/security/pwquality.conf  →  minlen = 8"` — the Unicode arrow makes `shlex.split` tokenize this into junk arguments. Like C-2, demoted to `nature="improvement"`.

**C-4 — `EXPLAIN_KEYS` drift for `services_state`**
`bob/checks/services_state.py` emits findings with `key="services_state.service_inactive"`, but `EXPLAIN_KEYS` (in `bob/explain.py`) declared the canonical name `services_state.enabled_inactive`. `bob --explain services_state.service_inactive` returned "key not found".

Fix: added `"services_state.service_inactive": "services_state.enabled_inactive"` to `EXPLAIN_KEY_ALIASES`. The JSON output contract is preserved (still emits `service_inactive`), and `--explain` lookups resolve via the alias. Option (b) over option (a) (renaming the emitted key would have been a JSON output breaking change — reserved for v0.6.0).

### Important issues (4)

**I-1 — `recurrence.json` + `ignore.yml` written with default umask**
Both files relied on process umask (typically `0o644` on Debian/Ubuntu — world-readable). Every other persistent state file in BOB (`config.conf`, audit reports, score history) opens with explicit `0o600`. Fixed both to use `os.open(..., 0o600)` + `os.fdopen()`.

**I-2 — `_apply_deduction` bypassed score cap after `finalize()`**
The orchestrator contract is one-way: `finalize()` bakes in the cap then sets `_finalized=True`. A late `engine.apply(result)` would mutate `_raw_score` after the cap was applied — silently bypassing it. Added defensive guard with WARNING log; the deduction is discarded.

**I-3 — `_safe_url` allowed `"` injection in HTML email href attributes**
The pipeline html-escapes text first (with default `quote=False`), then re-substitutes `[label](url)` into `<a href="url">label</a>`. The URL was inserted into attribute context without re-escaping — a crafted `[label](https://x.com" onclick="alert(1))` could break out of the href. `_safe_url` now calls `html.escape(url, quote=True)` to encode `"`/`'`/`<`/`>`.

Realistic attack surface is narrow (a malicious `services.d/*.json` plugin emitting markdown links with crafted strings, rendered in user mail clients) but the fix is cheap and the email report is unparseable XSS-safe ground.

**I-4 — `sysinfo._PRIVATE_IPV4_RE` brittle + Python 3.12+ break**
Two problems: (1) the call site at line 192 did `re.search(r"via\s+" + _PRIVATE_IPV4_RE.pattern.removeprefix("^"), …)` — manipulating a compiled pattern's `.pattern` attribute and dropping flags; (2) `ipaddress.IPv4Address.is_private` widened in Python 3.12.4+ to include documentation/reserved ranges like `203.0.113.0/24`, so a naive switch to stdlib would mis-classify those as "private" and break `detect_network_context()`.

Fix: explicit `_PRIVATE_IPV4_NETS` + `_PRIVATE_IPV6_NETS` tuples of `ipaddress.ip_network` objects, with `_is_private_or_loopback_ipv4()` / `_is_private_or_loopback_ipv6()` helpers using `addr in net` membership. Covers RFC 1918, loopback (127/8 + ::1), link-local (169.254/16 + fe80::/10), CGNAT (100.64/10), and IPv6 ULA (fc00::/7). Documentation ranges stay "public" so they don't trigger "local" context.

### Minor cleanups (11)

| # | Fix | Files |
|---|---|---|
| **M-1** | Email regex unified via `bob.config._EMAIL_RE` (was duplicated 3×) | `bob/cron.py` |
| **M-2** | `bob/watch.py:_NullReport` removed → use `bob.report.NullReport` (Report Protocol from v0.5.0 #10) | `bob/watch.py`, `tests/test_watch.py` |
| **M-3** | 3 dead locale keys removed: `_meta.lang`, `_meta.version`, `ignored.hint` | `bob/locales/{en,fr}.json`, `tests/test_ignore.py` |
| **M-4** | `corr.fully_blind` rule widened: fail2ban-stopped or auditd-stopped both qualify as "blind" (was asymmetric — only fired when both layers fully missing) | `bob/correlation.py`, `tests/test_correlation.py` |
| **M-7** | Extract `_has_actionable_findings()` helper in `updates.py` (replaces fragile inline `f.key != "updates.apt_cache_age"` filter) + `_TRANSPARENCY_KEYS` frozenset for future-proofing | `bob/checks/updates.py` |
| **M-8** | Comment-only — clarifies why `_parse_config_file` stops at Match blocks (also skips subsequent Include directives, intentional) | `bob/checks/ssh.py` |
| **M-9** | Comment-only — clarifies `ListeningPort.process`/`iface` empty fields mean "unknown" not "no process" (when `ss -p` lacks privilege) | `bob/checks/ports.py` |
| **M-10** | `apply_cron_schedule` regex tightened: first field must be a cron-token (`[0-9*,\-/]…`) so comment lines starting with `#` aren't matched | `bob/cron.py`, `tests/test_cron.py` |
| **M-11** | `services_state.service_inactive` cmd: dropped `&& sudo journalctl …` shell chain (moved to `note=` guidance) so `--fix --apply` accepts it | `bob/checks/services_state.py` |

### M-6 (separate commit) — `Optional[X]` / `List[X]` → `X | None` / `list[X]`

Mechanical sweep across 18 modules. Python 3.10+ syntax. Pure cosmetic, zero behaviour change. Isolated commit for revert-chirurgical-on-typo safety.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4545 passed in ~7s
```

**4538 → 4545 (+7).** Regression coverage for C-1 (cron mode), C-2 + C-3 (`nature` assertion), C-4 (alias resolution), I-2 (post-finalize guard), I-3 (XSS attr-escape, 9 tests in new `tests/test_report_markdown_safety.py`), M-4 (fail2ban-only blind), M-10 (cron comment-line skipped). 8 tests deleted (obsolete `_NullReport.__getattr__` magic from M-2, dead `ignored.hint` test from M-3). 2 tests renamed for clarity (`test_nature_is_action` → `test_nature_is_improvement` on `password_policy`).

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — **unchanged**. C-4 uses `EXPLAIN_KEY_ALIASES` (additive) to preserve the emitted key while routing `--explain` to the canonical name.
- **Wire output**: Visible delta on hosts without `pam_pwquality` installed — the password_policy finding moves from "À corriger" (action) to "Améliorations possibles" (improvement) in the summary box. Global score unchanged.
- **i18n**: 3 keys removed (`_meta.lang`, `_meta.version`, `ignored.hint`). Locale-coverage test still green.
- **External API**: no breaking change. `prompt_wizard` (v0.5.4 #6) and `_atomic_write` (now takes `mode`) gain optional parameters.

---

## [v0.5.4] — 2026-05-23

**Refactor v0.5.x — Phase 5 of 5 (final).** Three audit findings closed (`#6`, `#9`, `#15b`) + one user-requested metier feature (cache APT option C). Two findings (`#13` ssh.py split, `#14` cron.py split) explicitly deferred to v0.6.0.

### #6 — `prompt_wizard()` helper for plain-text wizards

`bob/_tty.py` exposes a new `prompt_wizard(label, *, default="")` helper that wraps `input()` with the wizard-step boilerplate every plain-text wizard had to repeat:

```python
def prompt_wizard(label: str, *, default: str = "") -> "str | None":
    """Plain-text wizard prompt with uniform cancel + default handling.

    Returns:
        None — user typed 'q' or 'quit' (case-insensitive).
        str  — trimmed input, or default when Enter was pressed bare.
    """
    raw = input(label).strip()
    if raw.lower() in ("q", "quit"):
        return None
    return raw or default
```

10 sites migrated in `bob/cron.py`:

- `_run_install_cron_plain()` (5 sites): name, schedule type, weekdays, monthdays, custom expr, time
- `edit_cron_schedule()` (4 sites): weekdays, monthdays, custom expr, time
- (the schedule-type prompt in `edit_cron_schedule` keeps `read_line()` for raw-mode Esc support — intentional asymmetry between the two wizards)

Yes/no confirmation prompts (4 sites in `prompt_emails`, 1 in install_cron overwrite, 1 in email_store_enter) are NOT migrated — they don't fit the `default-on-Enter` semantic of `prompt_wizard` (they need explicit `y` vs anything-else).

### #9 — `UFW_AUDIT_SHARE` env var deprecation

`bob/_paths.py:resolve_share_dir()` previously logged an `INFO` when only the legacy `UFW_AUDIT_SHARE` env var was set (without `BOB_SHARE`). The message politely said "the legacy name will be dropped in a future major release" without committing to a version.

v0.5.4 commits to a sunset version:

- Level bumped `logger.info(...)` → `logger.warning(...)`
- Message rewritten: "Using legacy env var %s — DEPRECATED since v0.5.4, will be REMOVED in v0.6.0. Update your installer to %s …"
- Module docstring updated to match.

`SECURITY.md` / `SECURITY_FR.md` (updated in v0.5.3) already declared the support matrix that v0.4.x is end-of-life. Packagers seeing the warning have a clear timeline to update installer scripts.

### #15b — Explicit `_PREFIX_TO_DOMAIN` mapping (medium-risk re-attribution)

`bob/domain_scores.py:_PREFIX_TO_DOMAIN` gains three new explicit entries that were previously silent catch-all fallbacks to the `firewall` domain:

| Prefix | Old (catch-all) | New (explicit) | Rationale |
|---|---|---|---|
| `fail2ban` | firewall | **ssh** | Primary purpose is SSH anti-bruteforce — most jails target the sshd jail |
| `virt` | firewall | **hardening** | KVM/libvirt bridge can insert iptables rules bypassing UFW FORWARD — that's a kernel/system attack-surface concern, not a firewall config concern |
| `docker_audit` | firewall | **hardening** | Container hardening (daemon.json iptables=false setting, running container audit) is system hardening, not network surface |

`smtp` and `desktop_apps` stay in the firewall catch-all: no clean domain fit (smtp local exposure has some firewall semantics; desktop_apps is INFO-only inventory).

Per-domain score impact: on hosts emitting findings under these prefixes, the score breakdown shifts. The **global score is unchanged** (deductions are the same, just re-bucketed). Observed on the dev host: virt.bypass_risk WARN moved from `Pare-feu & Services` (3/10 → 10/10 with other intra-firewall finding clean-up) to `Durcissement` (6/10 → 5/10).

`tests/test_domain_scores_mapping_complete.py:_CATCH_ALL_BY_DESIGN` updated to remove the 3 migrated entries; the remaining `smtp` / `desktop_apps` / `prerequisites` entries get refreshed justifications (no longer "review in v0.5.4" — that's done).

### Cache APT option C — Permanent INFO on cache age

User-requested metier feature. Surfaces the APT cache age when the audit reports "system is up to date" so the user knows whether that verdict reflects a fresh read or a stale snapshot:

```python
if (
    cache_age is not None
    and not security
    and not regular
    and cache_age * 86400 < _APT_CACHE_STALE_THRESHOLD
):
    result.info(
        message=_t("updates.apt_cache_age", days=cache_age),
        detail=_t("updates.apt_cache_age_detail"),
        key="updates.apt_cache_age",
    )
```

Triggered when:
- APT available
- No security packages pending
- No regular packages pending
- Cache age known
- Cache age below the 7-day stale threshold (the stale-cache WARNING already covers the > 7-day case; this INFO covers the silent "fresh-enough but not zero" range)

New locale keys (EN + FR):
- `updates.apt_cache_age`: "APT cache age: {days} day(s) — run `sudo apt update` for a fresher read"
- `updates.apt_cache_age_detail`: explains BOB is read-only by design, points to unattended-upgrades.

Surfaced by Ubuntu VM terrain testing on 2026-05-22 where a dormant VM returned "à jour" despite 8 pending LTS security updates upstream. The cache wasn't stale enough to trigger the `apt_cache_stale` WARNING (< 7 days), but was old enough to be desynchronized from upstream. The new INFO closes that observability gap.

### Deferrals: `#13` (ssh.py split) and `#14` (cron.py split) → v0.6.0

The original v0.5.x audit (2026-05-21) flagged both files as candidates for split:
- `ssh.py`: 1387 LoC at audit time. Targeted < 1000 after Phases 2 + 3. Actual end of v0.5.x: **1324 LoC** (target missed by 32%).
- `cron.py`: 1223 LoC at audit time. Stays at **1223 LoC** end of v0.5.x.

Decision: defer both to v0.6.0. Per the *conservative refactor* rule (no cosmetic churn: low gain × non-zero risk = STOP) — splitting a file is medium-risk for marginal reader gain; doing it inside a contract-preserving release line adds noise without clear payoff. v0.6.0 is the natural place: a major-version bump typically already perturbs imports and tests, so the split lands alongside other structural shifts.

`#15a` test coverage (added in v0.5.0) still pins all current key prefixes against `_PREFIX_TO_DOMAIN` and `_CATCH_ALL_BY_DESIGN`; whatever the v0.6.0 split decision is, the test will catch unhandled prefixes before they regress.

### Net diff

| File | Delta | Notes |
|---|---|---|
| `bob/_tty.py` | +24 | `prompt_wizard()` + docstring rewrite |
| `bob/cron.py` | +1 | 10 `input()` sites migrated to `prompt_wizard` |
| `bob/checks/updates.py` | +20 | Cache APT option C logic + commentary |
| `bob/domain_scores.py` | +10 | 3 new entries in `_PREFIX_TO_DOMAIN` + 6-line comment block |
| `bob/_paths.py` | +5 | log level bump + DEPRECATED message + docstring update |
| `bob/locales/{en,fr}.json` | +4 | 2 new keys × 2 locales |
| `tests/test_domain_scores_mapping_complete.py` | −6 | 3 entries removed from `_CATCH_ALL_BY_DESIGN` + simplified comments |

**Net +49 LoC across 12 code files.** All changes are contract-preserving (no new score domains, no new finding levels, no breaking signature change). Wire output gains 1 new INFO line on idle hosts (cache APT C) and reshuffles per-domain scores on hosts with `fail2ban.*` / `virt.*` / `docker_audit.*` findings — the **global score is unchanged**.

### v0.5.x audit closure: 13/15 findings shipped, 2 deferred

| # | Phase | Outcome |
|---|---|---|
| #1 | v0.5.1 | `warn_with_deduction()` / `alert_with_deduction()` — 120 sites |
| #2 | v0.5.0 | `print_titled_box()` — 4 sites + `--no-color` leak fix |
| #3 | v0.5.2 | `_sec()` skip_if= / post_display= — 4 sites |
| #4 | v0.5.2 | `_BAD_DIRECTIVES` table for sshd_config — 8 directives |
| #5 | v0.5.3 | `_LEVEL_DISPATCH` table for `display_result` |
| #6 | **v0.5.4** | `prompt_wizard()` helper — 10 sites in cron.py |
| #7 | v0.5.0 | `is_unit_active()` / `is_unit_enabled()` — 9 sites |
| #8 | v0.5.3 | `CheckResult.log_data` escape hatch removed — tuple return |
| #9 | **v0.5.4** | `UFW_AUDIT_SHARE` sunset (REMOVED in v0.6.0) |
| #10 | v0.5.0 | `bob.report.Report` `typing.Protocol` |
| #11 | v0.5.0 | `emit_section()` / `emit_group()` — 20 sites |
| #12 | v0.5.3 | `print_audit_summary` split into 3 helpers |
| #13 | **deferred v0.6.0** | ssh.py split (1324 LoC) |
| #14 | **deferred v0.6.0** | cron.py split (1223 LoC) |
| #15a | v0.5.0 | `test_domain_scores_mapping_complete.py` AST scan |
| #15b | **v0.5.4** | `_PREFIX_TO_DOMAIN` explicit mapping for `fail2ban` / `virt` / `docker_audit` |

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in ~6s
```

**4538 → 4538 (unchanged).** Phase 5 is contract-preserving — all changes either internal helper extraction (#6) or display-only refinements (cache APT C, #15b score re-bucketing) or non-functional log messaging (#9).

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — **unchanged**.
- **Per-domain score**: re-bucketed on hosts with `fail2ban.*` / `virt.*` / `docker_audit.*` findings. **Global score unchanged.**
- **Wire output**: 1 new INFO line on idle hosts (cache APT C). Reshuffle of per-domain breakdown when `#15b` prefixes are emitted. WARNING on hosts using legacy `UFW_AUDIT_SHARE` (previously was INFO).
- **External API**: no breaking change.
- **i18n**: 2 new locale keys (`updates.apt_cache_age` + `..._detail`) in EN + FR.

---

## [v0.5.3] — 2026-05-22

**Refactor v0.5.x — Phase 4 of 5.** Three audit findings: **#5 dispatch table**, **#12 summary helpers**, **#8 `log_data` escape hatch removal**. Zero behaviour change — 4538/4538 tests unchanged, wire output bit-identical to v0.5.2.

### #5 — `_LEVEL_DISPATCH` table for `display_result`

`display_result()` in `bob/display.py` had a 4-branch OK/WARN/ALERT/INFO cascade. Each branch repeated the same pattern (write to report, check threshold, print the message, optionally print recurrence/detail/cmd/note/CIS) with subtle per-level variations that drifted over time.

New `_LevelTraits` frozen dataclass + 4-row dispatch dict expresses each variation as a boolean trait:

```python
@dataclass(frozen=True)
class _LevelTraits:
    report_label:         str
    threshold_key:        str
    print_fn:             Callable[[str], None]
    has_recurrence:       bool
    has_body:             bool
    detail_unconditional: bool   # ALERT-only: prints detail without --verbose
    show_note:            bool   # ALERT only
    show_cis:             bool   # WARN + ALERT
```

The single trait that captures the ALERT specialness (detail prints even without `--verbose`) is `detail_unconditional=True`, replacing an opaque `elif detail: print_recommendation(detail)` branch that lived under the `if finding.cmd and verbose:` chain. `_emit_finding_body()` is a new module-level helper that consumes the traits.

### #12 — `print_audit_summary` split into 3 helpers

The 142-line `print_audit_summary()` mixed three responsibilities (header lines, finding block lines, breakdown lines) with an inner `_add_finding_lines()` closure. Now:

- `_summary_header_lines(engine, network_context, config, t, profile_name, prev_score)` — score/level/network/profile/target lines + the score trend arrow.
- `_summary_findings_lines(engine, t, inner)` — the action + improvement blocks (with the disclaimer line).
- `_summary_breakdown_lines(engine, t, inner)` — deductions + cap_info.
- `_add_finding_lines(icon_prefix, item, inner)` — promoted from inner closure to module-level helper, returns a list of `(content, val)` tuples instead of mutating the enclosing `lines` list.

`print_audit_summary` becomes a 3-line `lines.extend(...)` assembler, then `print_summary_box(lines)`, then the footer (verdict line + implicit_svcs + scope lines + `report.write_summary()`).

One side-fix: the original `report.write_summary(score=score, risk_level=level_str, network_context=ctx_str, ...)` referenced local variables that were no longer in scope after the header extraction. Replaced with direct expressions on `engine.score` and re-evaluated `t(f"scoring.level.{engine.level.value}")` / `t(f"scoring.context.{network_context}")`.

### #8 — `CheckResult.log_data` escape hatch removed

`CheckResult` had a `log_data: dict | None = field(default=None)` field used only by `bob/checks/logs.py` to attach structured aggregations (top IPs, top ports, brute hits, svc hits) for the orchestrator to display. Untyped, single-use, and indistinguishable from regular finding output in the dataclass surface.

Replaced by:

- New frozen `LogReportData` dataclass in `bob/checks/logs.py`:
  ```python
  @dataclass(frozen=True)
  class LogReportData:
      log_days:       int
      days_available: int
      total:          int
      brute_hits:     list[BruteforceHit]
      top_ips:        list[tuple[str, int]]
      top_ports:      list[tuple[str, int]]
      svc_hits:       dict[str, int]
  ```
- `check_logs(...)` now returns `tuple[CheckResult, LogReportData | None]`. `None` when no log file was found or the log was empty (the result still carries an info/ok finding).
- `bob/runner.py:408` unpacks the tuple: `logs_result, logs_report = check_logs(...)`.
- `display_log_results(logs_result, snapshot, log_report, config, t, report)` — `log_report` is now an explicit positional arg instead of being read from `logs_result.log_data`.
- `CheckResult.log_data` field deleted from `bob/scoring.py`.

Test churn: 3 tests renamed (`test_log_data_attached` → `test_report_data_attached`, `test_top_ips_in_log_data` → `test_top_ips_in_report_data`, `test_service_hits_in_log_data` → `test_service_hits_in_report_data`) and rewritten to read `report_data.total` / `report_data.top_ips` / `report_data.svc_hits` instead of dict-key access. ~20 other test sites in `tests/test_logs.py` + `tests/test_degraded.py` use `result, _ = check_logs(...)` tuple unpack since they don't care about the report data.

### Net diff

| File | Delta | Notes |
|---|---|---|
| `bob/display.py` | +23 | `_LevelTraits` + `_emit_finding_body` + 3 summary helpers + `_add_finding_lines` module-level |
| `bob/checks/logs.py` | +19 | `LogReportData` dataclass + tuple return |
| `bob/runner.py` | 0 | 1 line migrated to tuple unpack |
| `bob/scoring.py` | −1 | `log_data` field removed |
| `tests/test_logs.py` + `tests/test_degraded.py` | +3 | tuple unpack + 3 renamed tests |

**Net +40 LoC.** Like Phases 2–3, the LoC delta on its own undersells the structural win: the 4-branch display cascade becomes a single declarative loop, the 142-line summary function becomes a 3-line assembler, and the `dict | None` escape hatch is replaced by a typed frozen dataclass.

### #13 / #14 / #15b still deferred to Phase 5

ssh.py reaches 1324 LoC at v0.5.3 entry, unchanged from v0.5.2. cron.py + `_PREFIX_TO_DOMAIN` re-attribution untouched in Phase 4. All three decisions stay queued for v0.5.4 with explicit `wc -l` re-check.

### Garde-fou observable diff

`sudo python3 -m bob -v --french -n` and `sudo python3 -m bob --format=json --french` snapshots captured before Phase 4 implementation, diffed at intermediate (#5 + #12) and final (#5 + #12 + #8) milestones. All deltas confined to state drift (timestamps, UFW block counts, ephemeral VSCode TCP ports, rkhunter age). Zero structural change to the rendered audit, the JSON tree, or the score breakdown.

---

## [v0.5.2] — 2026-05-22

**Refactor v0.5.x — Phase 3 of 5.** Two audit findings (#4 SSH directive table + #3 `runner._sec` callbacks). Zero behaviour change — 4538/4538 tests unchanged, wire output bit-identical to v0.5.1.

### #4 — `_BAD_DIRECTIVES` table for `sshd_config`

`_check_sshd_config` had ~9 near-identical if-blocks: read directive from `cfg.get()`, check value against a "bad" enum, emit finding + deduction with fixed points/key/nature. Now collapsed into a declarative table.

New in `bob/checks/ssh.py`:

```python
@dataclass(frozen=True)
class _BadDirective:
    name: str          # cfg key (lowercase)
    default: str       # default value if missing
    level: str         # "warn" or "alert"
    key: str           # i18n key
    points: int
    bad_values: tuple[str, ...] = ()    # values that trigger finding
    safe_values: tuple[str, ...] = ()   # alternative: anything not in this set is bad
    nature: str = ""
    detail_key: str = ""
```

`bad_values` and `safe_values` are mutually exclusive — `safe_values` style covers cases like `AllowTcpForwarding` where multiple values (`"no"`, `"local"`) are acceptable. Wrong combinations are caught at class instantiation by `__post_init__`.

Migrated directives (8): `PermitEmptyPasswords`, `X11Forwarding`, `IgnoreRhosts`, `HostbasedAuthentication`, `PermitUserEnvironment`, `StrictModes`, `AllowTcpForwarding`, `PubkeyAuthentication`.

Sites kept imperative (5+ patterns that don't fit):
- **`PermitRootLogin`** — 4-way branch with OK sub-states (`no`/`prohibit-password`/`forced-commands-only` are all OK with different messages)
- **`PasswordAuthentication`** — depends on the orchestrator-level `ssh_exposed` flag (warn vs info)
- **`MaxAuthTries`** — integer threshold (`>3`), not enum
- **`LoginGraceTime`**, **`AllowUsers/AllowGroups`**, **Match block** — INFO-only, no deduction
- **Weak Ciphers/MACs/KexAlgorithms** — set-intersection logic handled by `_check_weak_algo`

`_check_sshd_config` body: ~180 → ~50 LoC. The dataclass + table + helper add ~130 LoC, so net ssh.py +56. The audit's estimate (-150 LoC) was overly optimistic — Python dataclass verbosity offsets the deduplication gain. The win is structural (declarative > imperative cascade), not LoC.

### #3 — `runner._sec` extension with `skip_if=` and `post_display=` callbacks

`_sec` previously couldn't handle two orthogonal cases:
- **Snapshot-conditional gating** — `if samba_snapshot.installed`, `if docker_audit.docker_installed`, `if desktop_snapshot.detected`. Forced inline blocks duplicating the `_sec` body.
- **Post-check display calls** — `display_disk_partitions(snapshot, ...)`, `display_ports_overview(...)` etc.

Now `_sec` accepts two keyword-only callbacks:

```python
def _sec(
    section: str,
    snapshot,
    check_fn,
    *,
    skip_if=None,           # Callable[[snapshot], bool] — skip without emitting header
    post_display=None,      # Callable[[snapshot, result], None] — after display_result
    **check_kwargs,
) -> None: ...
```

4 inline blocks migrated:

| Section | Inline pattern | After |
|---|---|---|
| `samba` | `if samba_snapshot.installed:` then 8 lines | `_sec("samba", ..., skip_if=lambda s: not s.installed)` |
| `docker_audit` | `if docker_audit_snapshot.docker_installed:` then 8 lines | `_sec("docker_audit", ..., skip_if=lambda s: not s.docker_installed)` |
| `desktop_apps` | `if desktop_snapshot.detected:` then 8 lines | `_sec("desktop_apps", ..., skip_if=lambda s: not s.detected)` |
| `disk` | `_sec`-shaped block + `display_disk_partitions` call after | `_sec("disk", ..., post_display=lambda snap, _r: display_disk_partitions(snap, t, output))` |

Net runner.py: −29 LoC.

### #13 (ssh.py split) — deferred to Phase 5

The audit's prediction (#4 saves ~150 LoC → ssh.py descends under 1000 LoC → #13 becomes unnecessary) didn't hold. Phase 2 (#1) saved 119 LoC on ssh.py; Phase 3 (#4) added 56 net. ssh.py is at 1324 LoC, well above the 1000-LoC threshold. Per the the *conservative refactor* rule principle, ssh.py split is medium-risk surgery — to be decided in Phase 5 alongside #14 (cron.py split) once final state is known.

### Tests

```
$ python3 -m pytest tests/ -q
4538 passed in ~6s
```

`4538 → 4538` (unchanged). Both #4 and #3 are pure structural refactors. The full `test_ssh.py` suite (122 tests) passed before, during, and after the `_BAD_DIRECTIVES` migration — the table produces bit-identical `Finding` and `Deduction` entries to the previous if-blocks.

### Compatibility

- **JSON contract**: `schema_version="1"`, 116 EXPLAIN_KEYS, 34 filterable sections — **unchanged**.
- **Wire output**: bit-identical to v0.5.1. Identical messages, deduction reasons, points, levels.
- **Per-domain scores**: unchanged.
- **External API**: no breaking change. `_BadDirective` and `_BAD_DIRECTIVES` are module-private (underscore prefix); the `_sec` signature change is keyword-only (existing call sites unaffected).

### Files changed

- `bob/checks/ssh.py` — +`_BadDirective` dataclass + `_BAD_DIRECTIVES` table + `_apply_bad_directive` helper; `_check_sshd_config` body rewritten
- `bob/runner.py` — `_sec` signature extended with keyword-only params; 4 inline blocks migrated
- `bob/__init__.py`, `pyproject.toml`, schemas, man pages, READMEs — version bump
- `CHANGELOG.md`, `CHANGELOG_FR.md`, `DOCUMENTS/CHANGELOG_FULL.md`, `DOCUMENTS/CHANGELOG_FULL_FR.md`, `DOCUMENTS/TESTING.md`, `DOCUMENTS/TESTING_FR.md` — this entry
- `debian/changelog`, `packaging/rpm/bob.spec` — packaging stanzas

---

## [v0.5.1] — 2026-05-22

**Refactor v0.5.x — Phase 2 of 5.** The biggest LoC win in the refactor roadmap. Audit finding #1: the paired `result.warn(...) + result.add_deduction(...)` idiom that recurred ~130 times across `bob/checks/*.py` is now centralised behind two helper methods. **No behaviour change** — the helpers compose the existing `warn`/`alert` and `add_deduction` methods one-to-one. Tests stay at 4538/4538 because the wire output (findings + deductions emitted by `CheckResult`) is bit-identical.

### New API

Two methods added to `CheckResult` in `bob/scoring.py`:

```python
def warn_with_deduction(
    self,
    key: str,
    *,
    message: str,
    points: int,
    reason: str | None = None,
    context: str = "local",
    detail: str = "",
    nature: str = "improvement",
    cmd: str = "",
    cmd_type: str = "fix",
    note: str = "",
    template_vars: dict | None = None,
) -> None: ...

def alert_with_deduction(self, ...) -> None: ...   # mirror, nature default = "action"
```

The `reason=` override handles the cases where the finding message uses one translation key and the deduction reason uses a `_reason` suffix variant (e.g. `ssh.host_key_dsa_reason` differs from `ssh.host_key_dsa`).

### Sites migrated (120 across 27 files)

| File | Sites | Notes |
|---|---|---|
| `bob/checks/ssh.py` | 24 | The big one — sshd_config directives (PermitRootLogin, PasswordAuthentication, X11Forwarding, PermitEmptyPasswords, MaxAuthTries, IgnoreRhosts, HostbasedAuthentication, PermitUserEnvironment, StrictModes, AllowTcpForwarding, PubkeyAuthentication), host keys, weak algos (`_check_weak_algo`), `~/.ssh` dir, private keys, authorized_keys, client config, known_hosts. ssh.py: −146 lines. |
| `bob/checks/hardening.py` | 8 | All sysctl branches: rp_filter, ICMP redirects (v4 + v6), tcp_syncookies, accept_source_route, send_redirects, protected_hardlinks, protected_symlinks. |
| `bob/checks/samba.py` | 6 | SMB1, null passwords, server signing, map_to_guest, guest writable/readonly shares. |
| `bob/checks/mac_policy.py` | 6 | AppArmor (no profiles, no enforce, inactive), SELinux (permissive, disabled), no_mac. |
| `bob/checks/clamav.py` | 5 | freshclam_missing, db_not_found, db_very_outdated, db_outdated, scan_very_old/scan_old. |
| `bob/checks/disk.py` | 5 | smart_failed, reallocated_sectors, pending_sectors, uncorrectable_errors, partition_critical. |
| `bob/checks/iptables_nftables.py` | 5 | no_backend, input_accept, no_loopback, no_conntrack, forward_accept. |
| `bob/checks/firewall.py` | 4 | duplicate_found x2 (regex + proto-less), ipv6_missing, logging_off. (5e site `open_any_found` non migré — `rule=""` ≠ `rule=clean` entre finding et reason.) |
| `bob/checks/firewall_stack.py` | 4 | iptables_bypass, iptables_forward_bypass, nftables_parallel, ip_forward_enabled. |
| `bob/checks/log_rotation.py` | 3 | logrotate_missing, journald_volatile x2 (volatile + unknown). |
| `bob/checks/auditd.py` | 3 | service_inactive, no_rules (server), missing_sensitive_rules (server). |
| `bob/checks/file_integrity.py` | 3 | no_db, no_check, check_old. |
| `bob/checks/kernel_hardening.py` | 3 | aslr_disabled, ptrace_unrestricted, suid_dump_all. |
| `bob/checks/rootkit.py` | 3 | db_outdated, no_scan, scan_old. |
| Other files | 35 | fail2ban, ntp, ddns, updates, backup, smtp, memory, network_context, cron_audit, docker_audit, kernel_modules, umask, user_accounts, password_policy, secure_boot, systemd_timers, logs, firmware, ipv6, ports, suid_audit, file_perms — each with 1-2 site migrations. |
| **Total** | **120** | |

### Sites intentionally not migrated (13)

These patterns don't fit the 1:1 helper API:

| Case | Files | Why |
|---|---|---|
| Capped deduction (local counter) | `services_state` (1), `ssl_certs` (3), `file_perms` (2 of 3), `ipv6.port_no_v6_rule` (1) | The finding always emits; the deduction is gated on `if X_deductions < CAP`. Cannot collapse to one helper call. |
| Branching level (warn OR alert) | `services.exposure` (1), `ports.uncovered_public` (1), `docker.exposed_port`/`exposed_bypass_ufw` (2) | The `result.warn(...)` vs `result.alert(...)` choice depends on a snapshot field, while the `add_deduction` runs unconditionally afterwards. The helper merges level + deduction, so the branching has to stay in the caller. |
| Conditional deduction with different predicate | `docker.iptables_bypass` (1), `firewall.rules.open_any_found` (1) | The deduction has a `points = 0 or 1` calculation, or different `template_vars` between finding (`rule=clean`) and reason (`rule=""`). |

For each skip, the audit's recommendation was "keep the old 2-call form" — covered.

### Why this is low-risk

- **Helpers are additive on `CheckResult`.** The existing `warn`/`alert`/`add_deduction` methods are unchanged; the helpers are thin wrappers that call them in sequence.
- **No test changes required.** Every test still asserts on `len(result.findings)`, `len(result.deductions)`, and finding/deduction attributes — the helper produces a `Finding` and a `Deduction` per call, identical to the pre-migration sequence. 4538 → 4538 tests.
- **No behaviour change in the audit pipeline.** Field-tested on 5 distros (Mint, Debian 13, Kali Rolling, Ubuntu 26.04 LTS) for v0.5.0 — the same scoring logic, the same key prefixes, the same `template_vars`.
- **Migration was per-file, with full test suite run after each wave.** Each of the 6 waves (1-site files → 2-site → 3-site → 4-6 site → hardening → ssh.py) passed 4538/4538 before moving on.

### Net diff

```
37 files changed, 483 insertions(+), 1002 deletions(-)
```

**−519 lines net** — a ~5% reduction in `bob/checks/*.py` total LoC. Per the original audit estimate ("~800 LoC removed"), this is conservative because of the 13 skipped sites and because the helper signature is verbose (keyword-only kwargs) — but the goal was eliminating the drift surface, not minimising line count, and that's achieved.

### Tests

`4538 → 4538` (unchanged). Full suite passes in ~6s on Python 3.12 / Linux Mint 22.3.

### Compatibility

- **JSON contract**: `schema_version="1"`, all 116 EXPLAIN_KEYS, all 34 filterable sections — **unchanged**.
- **CLI surface**: no flag added, no flag removed.
- **Per-domain score breakdown**: unchanged.
- **Wire output** (terminal + report file + JSON): bit-identical to v0.5.0.

---

## [v0.5.0] — 2026-05-21

**Refactor v0.5.x — Phase 1 of 5.** This release opens the v0.5.x branch with 6 low-risk, additive refactor findings from a sub-agent audit (general-purpose) briefed with `DOCUMENTS/SNAPSHOT.md`. **Zero behaviour change in the audit pipeline:** JSON `schema_version="1"` contract preserved, 7 score domains unchanged, 116 EXPLAIN_KEYS frozen, 34 filterable sections intact.

The remaining 4 phases (v0.5.1–v0.5.4) will tackle the bigger LoC wins (`warn_with_deduction` helper across ~130 sites), the SSH directive table, the display refactor, the cron wizard refactor, and the `UFW_AUDIT_SHARE` sunset.

### Audit findings addressed

**#7 — `is_unit_active()` / `is_unit_enabled()` centralized.** Added to `bob/checks/_run.py`. Migrates the 9 sites that repeated `out = (_run("systemctl", "is-active", X) or "").strip(); if out == "active"`: `auditd.py`, `clamav.py`, `fail2ban.py`, `ntp.py`, `ddns.py`, `updates.py`, `ssh.py`, `backup.py`, `log_rotation.py` (the last one keeps its explicit `timeout=5`). `services.py::_detect_single_unit_state` keeps its richer enum return per the audit recommendation. Defensive `.lower()` added to the helper (canonical systemd output is always `"active\n"` but a downstream fork could theoretically emit `"Active\n"` — restored after review).

**#2 — `bob.output.print_titled_box()` extracted.** A 3-line ASCII box header was open-coded 4 times across `cron.py` (install wizard, manage wizard, email store sub-menu) and `manage_logs.py` (plain-text fallback). All 4 sites bypassed `_c` (the colour palette respecting `--no-color`) by inlining `\033[1;34m` literals — **this leak is now closed**. `fixes.py` was *not* migrated: its box is a streaming `╔ ║ ╠` continuation, different shape, and already routes through `_c`.

**#10 — `bob.report.Report` Protocol.** PEP 544 structural type with 12 method/attribute members. Captures the shared contract between `AuditReport` (plain-text), `NullReport` (no-op), and `MarkdownReport` (separately implemented, not in the inheritance tree). `runner.run_checks(report: Report, ...)` now type-hints the abstract Protocol; concrete classes still expose richer methods (`MarkdownReport.write_services_panorama` is unique to Markdown). No `@runtime_checkable` — static type-checking only, no runtime overhead.

**#11 — `emit_section()` + `emit_group()` closures in `runner.py`.** The 3-line `if not config.quiet: print_section(t(...)); report.write_section(t(...))` motif collapses to 1 line at 20 sites: 5 group headers (firewall_network, exposure_services, access_control, system_hardening, detection_health) + 15 section headers. `_sec()` itself is refactored to use `emit_section` internally. Net: runner.py shrinks 65 lines / +37 lines = **−28 lines**, single source of truth for section emission. Two sites intentionally NOT migrated: `print_section(t("sections.logs"))` at line 373 (no matching `report.write_section` — pre-existing anomaly out of scope) and the plugin loop at line 648 (`plugin.name` is not a translation key).

**#15a — `tests/test_domain_scores_mapping_complete.py`.** AST-scans `bob/checks/*.py` for every literal `key="X.Y"` argument to emitting methods (`add_deduction`, `warn`, `alert`, `info`, `ok`). Extracts unique prefixes and asserts each is either explicit in `_PREFIX_TO_DOMAIN` (bob/domain_scores.py) or whitelisted in `_CATCH_ALL_BY_DESIGN` with a one-line justification. The whitelist captures the v0.4.x state: `smtp`, `fail2ban`, `desktop_apps`, `virt`, `docker_audit`, `ddns`, and the legitimate firewall-domain prefixes (`firewall`, `rules`, `ports`, `services`, `ipv6`, `iptables_nft`, `firewall_stack`, `network_context`, `docker`). Re-attribution to more semantic domains is deferred to Phase 5 #15b (medium risk: changes scoring outputs). +4 tests. The test will fail on any new check that adds a prefix without explicit handling — closes the silent miscategorization class noted by the audit.

### Cron coverage pass (preliminary for Phase 5)

cron.py had the worst test ratio of the codebase per SNAPSHOT (0.60×). Phase 5 will refactor the wizards (#6: extract `_prompt` helper, dedupe 3 wizards) — adding coverage *before* the refactor is the safety net. **+35 tests** across 5 new classes:

- `TestValidateCronField` (13 tests) — wildcard, integer, range, step, list, out-of-range, reversed range, empty entry, garbage
- `TestValidateCustomCron` (7 tests) — 5-field discipline, per-field bounds (minute 0-59, hour 0-23, etc.)
- `TestBuildScriptContent` (7 tests) — shebang, `shlex.quote()` behaviour for email + log_dir, `--quiet --detailed` invocation
- `TestApplyCronSchedule` (3 tests) — schedule replacement + email-comment preservation + OSError surfacing
- `TestApplyCronEmail` (5 tests) — email comment + `NOTIFY_EMAILS=` script line + **legacy `NOTIFY_EMAIL=` (no S) regex parity** + missing-script tolerance + `shlex.quote()` quoting

### Latent bug fixed — `_os.open` in `apply_cron_schedule` (discovered by the new tests)

The v0.4.8 cron deduplication promoted `apply_cron_schedule()` from a curses-TUI private helper to a public `bob.cron` API. The extraction missed renaming `_os.open(...)` to `os.open(...)`. `_os` is a local alias used only inside three *other* functions in `cron.py` (line 649, 931, 1215 — each does `import os as _os`); at the module level, only `os` is imported. The bug was masked because the public helper was wired to the curses TUI which was not exercised by automated tests. **The new `TestApplyCronSchedule` tests surfaced the `NameError: name '_os' is not defined` immediately.** Fix: `_os.open` / `_os.fdopen` / `_os.O_*` → `os.*` (3 references on 2 lines).

### Monitoring list (release-watch)

Two APIs were added without immediate consumers — kept for symmetry / future flexibility, monitored at each release:

- `bob.checks._run.is_unit_enabled(name, timeout)` — mirror of `is_unit_active`. `services.py::_detect_single_unit_state` keeps its own `_run` call for the active/enabled state machine and is not migrated.
- `bob.output.print_titled_box(title, width=62)` — `width` parameter not exercised at any call site (all 4 sites pass the default 62).

If neither is consumed by v0.5.4, remove them.

### Tests

`4499 → 4538` (+39). Full suite passes in 7.77s on Python 3.12 / Linux Mint 22.3 / `so6desktop`.

### Compatibility notes

- **JSON contract:** `schema_version="1"`, all 116 EXPLAIN_KEYS, all 34 filterable sections — **unchanged**.
- **CLI surface:** no new flags, no flag removals.
- **Per-domain score breakdown:** unchanged (no `_PREFIX_TO_DOMAIN` modifications in this release — see #15b deferred to Phase 5).
- **Config files (`config.conf`, `services.json`, profiles):** unchanged.
- **Locale keys:** unchanged.

---

## [v0.4.8] — 2026-05-21

Code-quality audit pass 4 — performed by a `general-purpose` sub-agent briefed with `DOCUMENTS/SNAPSHOT.md` as primary cartography. The pass focused on four bug patterns from previous audits: dead dataclass fields, reinvented helpers, timeout inconsistencies, and dead code from refactors. **4 IMPORTANT + 5 MINOR + 3 SUGGESTION findings** — all addressed in this release. 4499/4499 tests passing.

### Real bug fixed (I4) — `sudo bob -d` log files were root-owned

**Reproduced**: running `sudo bob -d` on any Linux box creates the detailed audit report at `~/.local/share/bob/logs/bob_YYYYMMDD_HHMMSS.log` with mode `0o600` (already correct — confidential audit output) but owned by `root:root` because the `open()` happens inside the sudo context. The invoking user can neither `cat` nor `rm` their own audit reports afterwards. Same applies to the `logs/` directory itself when first created via `mkdir(parents=True)`.

**Why it survived**: the chown-back pattern (`bob.sysinfo.chown_to_sudo_user(path)`) was already established in 7 modules covering `~/.config/bob/` (`bob/config.py`, `bob/history.py`, `bob/ignore.py`, `bob/compare.py`, `bob/recurrence.py`, `bob/profiles.py`, `bob/registry.py`) — but the report file and log directory in `~/.local/share/bob/logs/` were never wired up. The user impact only becomes visible after the audit finishes and the user tries to read their own report.

**Fix**: 
- `bob/report.py::AuditReport.__init__` calls `chown_to_sudo_user(path)` right after `os.open(..., 0o600)`.
- `bob/manage_logs.py::get_or_prompt_log_dir` calls `chown_to_sudo_user(d)` after each of the 4 `d.mkdir(parents=True, exist_ok=True)` branches.

When BOB is not running under sudo, `chown_to_sudo_user` is a silent no-op (`os.environ.get("SUDO_USER", "")` returns `""`) — zero behavior change in non-sudo contexts.

### Dead dataclass fields removed (I1-I3 + M4-M5)

Eight dataclass fields populated by `from_system()` but never read by any consumer — same bug class as the v0.4.3 C1 fix (5 dead `HardeningSnapshot` attrs that crashed `--json-full`).

| Check / dataclass | Removed field(s) | Detection |
|---|---|---|
| `bob/checks/ssh.py::SSHSnapshot` | `config_source_files: List[str]` | Set by `_parse_config_file` recursive Include-chain walker; never read by `check_ssh`, `display`, `json_output`, or any test |
| `bob/checks/firewall.py::FirewallStatus` | `ipv4_rules_count: int` + `ipv6_rules_count: int` | Computed via `sum(1 for ln in ...)` regex passes on every audit; only consumers were test fixtures setting them to satisfy the dataclass constructor |
| `bob/checks/samba.py::SambaSnapshot` | `min_protocol: str` | Captured from `min protocol` smb.conf directive; `check_samba` consumes only the derived `smb1_enabled` bool |
| `bob/checks/clamav.py::ClamAVSnapshot` | `last_scan_log_path: str` + `db_path: str` | `_find_last_scan_date()` returned `(date, log_path)` tuple but only `date` was used; `db_path` set in the DB-existence loop but unused |
| `bob/checks/secure_boot.py::SecureBootSnapshot` | `method: str` | "mokutil" / "efivars" / "bootctl" / "none" — detection method internal to `from_system`; only `state` is consumed |

`_find_last_scan_date()` simplified to return `Optional[str]` instead of `(Optional[str], str)`. `_parse_config_file()` in ssh.py loses its now-unused `sources` parameter.

Tests updated to stop passing the removed kwargs. `tests/test_secure_boot.py::test_default_method_is_none` removed (it tested only that the field exists). Net: -1 test (4500 → 4499).

### Reinvented helpers consolidated (M1 + M3)

**M1 — `_C_LOCALE_ENV` consistency**. Three subprocess sites in `bob/checks/desktop_apps.py` (line 111: `ps -eo comm`) and `bob/checks/smtp.py` (line 58: `ps -eo comm`; line 102: `ss -tlnp` / `netstat -tlnp`) called `subprocess.check_output` without passing `env=_C_LOCALE_ENV`. Today this is benign because the output happens to be locale-independent on tested systems, but a future `ss` localising "LISTEN" or `ps` localising column headers would silently break detection. Every other subprocess site in BOB passes `env=_C_LOCALE_ENV` — fixed for consistency.

**M3 — `log_rotation._service_active` was a 12-line reinvention** of `_run("systemctl", "is-active", name)`. The other checks (clamav, fail2ban, auditd, ssh) use the one-liner form. Replaced; the local `subprocess` and now-unused `_C_LOCALE_ENV` imports also cleaned up.

### Cron management de-duplication (M2 + S2)

`bob/cron.py::edit_cron_schedule` (plain-text wizard) and `bob/tui/cron.py::_apply_cron_schedule` (curses TUI) duplicated the same regex `r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+root\s+\S+.*$"` + atomic-write pattern `os.open(..., O_WRONLY|O_CREAT|O_TRUNC, 0o640)`. Same for `edit_cron_email` vs `_apply_cron_email_str`, with the additional asymmetry that the plain branch accepted the legacy `NOTIFY_EMAIL=` (no S) regex while the curses branch required `NOTIFY_EMAILS=` only — meaning users upgrading from pre-v0.3 BOB cron files could edit their email via the plain wizard but not via the curses TUI.

**Fix**: `apply_cron_schedule(entry, schedule_expr) -> str` and `apply_cron_email(entry, new_email) -> tuple[str, int]` promoted to public helpers in `bob/cron.py`. `bob/tui/cron.py` now imports them and exposes thin wrappers under the original private names for the existing call sites. The legacy `NOTIFY_EMAILS?=` regex is now shared — both branches handle pre-v0.3 cron files identically.

### Other minor changes (S1 + S3)

**S1**: `bob/checks/auth_log.py::_read_auth_from_journald` hardcodes `max_days=90` for SSH brute-force history. The audit flagged the asymmetry with `--log-days` (default 7, for UFW logs). This is **intentional** — SSH brute-force attempts can be slow and sporadic over months, while UFW logs are noisy and a narrow 7-day window avoids burying the report. Documented in the function docstring so future audits don't re-flag it.

**S3**: `_BAR_WIDTH = 10` was duplicated as a module-level constant in 3 places (`bob/breakdown.py`, `bob/domain_scores.py`, `bob/display.py`). Promoted `SCORE_BAR_WIDTH = 10` in `bob/output.py` (public; private alias kept for backward-compat). `breakdown.py` and `domain_scores.py` now import it. `display.py::_BAR_WIDTH` is left alone — it's for the disk percent-bar (different semantic unit) and happens to also be 10 by coincidence.

### pyproject.toml hardening (queued from v0.4.7 analysis, applied here)

A deep pyproject.toml audit done during v0.4.7 prep had identified 6 improvements that were deferred. All 6 applied + 1 bonus:

| # | Fix |
|---|---|
| 1 | `Development Status :: 4 - Beta` → `5 - Production/Stable` (4500 tests + 7 distros CI + production hardware audited — not Beta anymore) |
| 2 | `authors` + `maintainers` fields added (PyPI was displaying "Author: UNKNOWN") |
| 3 | `[project.optional-dependencies] geoip = ["geoip2>=4.0"]` added — enables `pipx install "bodyguard-of-bits[geoip]"` for the GeoIP IP geolocation in UFW log analysis |
| 4 | `wheel` removed from `build-system.requires` (setuptools.build_meta auto-resolves wheel since setuptools 70) |
| 5 | `Source` + `Documentation` URLs added (PyPI displays icons for these) |
| 6 | Explicit `dependencies = []` with a "zero runtime deps — preserve at all costs" comment |
| bonus | `include = ["bob", "bob.checks", "bob.tui"]` explicit package list (replaces the `bob*` glob — guards against accidental top-level `bob_*` directories leaking into the wheel) |

### Tests

4499 passing (net -1 vs v0.4.7's 4500). The removed test is `tests/test_secure_boot.py::TestSecureBootSnapshot::test_default_method_is_none` — it asserted only that the `method` field defaults to `"none"`, and `method` is gone. No test depended on the removed dataclass fields beyond fixture kwargs (cleaned up).

---

## [v0.4.7] — 2026-05-21

Maintenance release — cross-documentation audit, UI cosmetic harmonization, bash completion overhaul, and release automation. No behavior change in the audit pipeline; 4500/4500 tests unchanged.

### Cross-documentation audit (24 corrections across 8 files)

Exhaustive audit catching stale claims that drifted between code state and user-facing docs since v0.4.6:

- **`README.md` / `README_FR.md`** — "9 domains" → "7 score domains" (the 9-domain count was historical from v0.1.0 and stale since v0.2.x); profile table corrected: `docker` profile listed but doesn't exist (the real profile is `container`), and `workstation` is a backward-compat alias loading `desktop` (not a separate profile).
- **`DOCUMENTS/README_TECH.md` + FR** — same "9 domains" drift; "17 profile-specific explain keys" → 19 (verified by walking `en.json::explain.{key}.server.why`).
- **`DOCUMENTS/README_DEV.md` + FR** — same "17 keys × 3 profiles" → 19; "~1500 locale keys" → exactly 1401 (verified by Python flatten with strict EN ↔ FR parity).
- **`man/bob.1`** — `--list-checks` flag documented but **doesn't exist** (real form is `--check=list`); `--min-level=info` listed as valid but the CLI parser rejects `info` (only `warn`/`alert` accepted; `info` would be a no-op since INFO is the implicit floor); `--format=text` listed but `text` is the implicit default, not a valid value of `--format=` (rejected at CLI parse).
- **`man/bob-profile.5`** — `--list-profiles` flag references removed (doesn't exist); "Up to 5 levels of inheritance" → 8 (`_MAX_EXTENDS_DEPTH = 8` in `bob/profiles.py`); SHIPPED PROFILES section gained the `workstation` entry with explicit alias status note.
- **`DOCUMENTS/AUTOMATION.md` + FR** — JSON webhook sample was completely wrong: `alerts`/`warnings` shown as arrays of `{key, message}` objects, but the real JSON top-level has them as integer counts (`engine.alert_count` / `engine.warn_count`). `risk` field shown as `"LOW"` uppercase but `engine.level.value` returns `"low"` lowercase. Sample was missing the fields `version`, `score_max`, `network_context`, `public_ip`, `deductions`, `domain_scores` that the real payload includes. Behavior claim also wrong: "POSTed only if alerts/warnings present" → actually POSTed on every audit when a URL is configured (no count threshold; filter on the receiving side). Timeout "5 seconds" → 10 seconds (`_TIMEOUT_SECONDS = 10` in `bob/webhook.py`).
- **`SECURITY_FR.md`** — untranslated `## Threat model` header → `## Modèle de menace`.

### `DOCUMENTS/SNAPSHOT.md` — new internal cartography

New ~640-line internal document providing a single-page bird's-eye view of the codebase: ASCII architecture diagram, module index for `bob/` root + `bob/checks/` with LoC and roles, dependency graph (centrality, fan-out), hotspots, patterns/conventions, 7 frozen contracts (JSON schema, exit codes, EXPLAIN_KEYS, domains, sections, plugin schema, CIS refs), CLI surface, file paths & env vars, tests-to-source mapping, architectural decisions (kept / discarded / deferred), CI matrix, numbers at a glance.

Designed to be loaded once before a refactor pass or audit so the structure does not need to be re-discovered module-by-module. Underwent 20 correction passes against the actual code state. 100% English (internal doc, not user-facing — not shipped in `debian/bob-core.docs` or `bob.spec %doc`).

### Gauge bars cosmetic harmonization (`bob/output.py::score_bar`)

All score-based progress bars (the `--watch` live display, `--breakdown` score path, per-domain scores in the audit summary, history sparkline in `--manage-logs`) now use a shared `bob.output.score_bar(score)` helper with the same colour logic as `display._disk_bar`, inverted for "high score = good":

- score ≥ 8 → **green** (healthy)
- score 5–7 → **yellow** (moderate)
- score 0–4 → **red** (critical)

Previously these bars rendered as plain monochrome `█░░░░░░░░░`. The disk partition bars (already coloured by usage threshold) are unchanged — the new helper just brings the rest of the UI into line.

Affected renderers (one-line delegation each): `bob/watch.py::_score_bar`, `bob/breakdown.py::_bar`, `bob/domain_scores.py::render_domain_scores`, `bob/manage_logs.py::display_history`. The `--no-color` flag still neutralises colours (empty ANSI strings).

### Bash completion comprehensive overhaul (`bob/data/bob.bash-completion`)

**Critical fix — value completion was silently failing**: `bob --check=<TAB>` (and all other `--xxx=<TAB>` value completions: `--skip=`, `--min-level=`, `--format=`, `--profile=`, `--lang=`, `--target=`, `--webhook-format=`, `--output=`) returned no suggestions. The completion function read `${COMP_WORDS[COMP_CWORD]}` for the current word, but with the default `COMP_WORDBREAKS` containing `=`, bash splits `--check=` into words `[--check, =]` with `COMP_WORDS[CWORD]="="`. `compgen` filtered with `"="` matched nothing. **Fix**: use the bash-completion positional-argument convention — `$2` is the "clean" current word stripped of any `=` word-break prefix, `$3` is the previous word. The handlers `[[ "${prev}" == "--check" ]]` then match correctly.

Diagnosed via `set -x` tracing of the completion function in the user's interactive session (Bash 5.2.21 on Linux Mint 22.3).

**Other fixes bundled:**

- Function renamed `_ufw_audit` → `_bob` (legacy name from before the project rename; binding updated).
- Dead code removed: `_ufw_audit_install()` + `complete -F _ufw_audit_install install.sh` registered completion for an installer script (`install.sh`) that no longer exists in the repo.
- Section list factored to `_SECTIONS` variable matching `bob --check=list` output exactly (34 entries from `bob/runner.py::_ALL_SECTIONS`). The old list had `firewall` (a core check that always runs — not filterable, misleading suggestion) and was missing `iptables_nft`, `samba`, `desktop_apps`.
- Long-options list now matches `cli.py` exactly (parity verified by diff): added `--check=`, `--skip=`, `--output-dir=`, `--breakdown`, `--no-colour`. Short-options list adds `-B` (`--breakdown`). Total: 21 short, ~40 long options — full parity with `cli.py::parse_args`.
- New `--skip=` value handler (mirror of `--check=` minus the `list` special value).
- All value handlers now support both forms: `--xxx=value<TAB>` (equals split) and `--xxx value<TAB>` (space split).

### CI — automatic GitHub Release on tag push (`.github/workflows/publish.yml`)

Adds a fourth job `github-release` after PyPI publish. Pipeline becomes:

```
git push --tags
  → test (Python 3.10/3.11/3.12/3.13)
  → build (sdist + wheel)
  → publish (PyPI via OIDC Trusted Publishing)
  → github-release  ← NEW
       • Extract title from CHANGELOG.md table row (text before " — ")
       • Extract body from DOCUMENTS/CHANGELOG_FULL.md section
         between "## [vX.Y.Z]" and next "## [v"
       • Create release via softprops/action-gh-release@v2
       • Attach wheel + sdist as release assets
       • Mark as latest
```

If PyPI publish fails, the GitHub release is not created (`needs: publish` dependency). If `CHANGELOG_FULL.md` lacks the matching section, the workflow fails explicitly. Permission: `contents: write` only.

Previously the GitHub release was created manually with `gh release create` after each PyPI publish.

### Tests

No new tests. 3 tests in `tests/test_breakdown.py::TestBar` adapted to strip ANSI escape sequences before asserting visible bar content (the bars are now ANSI-coloured strings rather than plain `█░░░░░░░░░`). 4500/4500 tests still passing.

---

## [v0.4.6] — 2026-05-17

Terrain test pass v0.4.5 produced two reproducible bugs across 13 audits on 6 distinct systems (5 VMs + 1 production workstation). v0.4.6 fixes both — narrowly scoped hotfix, no behavior change outside the two reported scenarios.

### Bug 1 — Kernel listing included removed packages (`rc` state)

**Reproduced on**: Mint test VM after `apt dist-upgrade` + `apt autoremove`; production Linux Mint 22.3 workstation after the same workflow. Confirms this is not a VM edge case — it is the standard outcome of any user running `apt remove` (or its transitive form `apt dist-upgrade`) on an obsolete kernel image.

**What happened**: `bob/checks/kernel_modules.py` listed installed kernels via `dpkg-query -W -f='${Package}\n' linux-image-[0-9]*`. `dpkg-query` returns every package matching the pattern *regardless of installation state*, including those in `rc` state (removed but config files in `/etc` still present). `apt remove` (without `--purge`) leaves a package in `rc` — the kernel binary in `/boot` is gone, but the package name still appears in BOB's listing. Result: "Installés : …, 6.17.0-20-generic, …" for a kernel that was already uninstalled.

**Fix**: the dpkg-query format string is now `${db:Status-Abbrev}|${Package}\n`. `${db:Status-Abbrev}` is a two-character code describing desired action + current status (`ii` = installed, `rc` = remove-configfiles, `pn` = purge-not-installed, `iU` = install-unpacked, etc.). `_parse_installed_kernels` keeps only lines whose 2nd character is `i` (current status = installed), which covers `ii` and `hi` (held-installed) while excluding `rc`, `pn`, `un`, `iU`, and transient states where binaries may or may not exist. Backward compatibility preserved: the parser still accepts plain `linux-image-…` lines (no prefix, no `|`) for test fixtures and any caller that doesn't pre-prefix.

**Severity**: cosmetic in the BOB output — no scoring impact — but high reach (every Debian-family user who has ever cleaned an old kernel).

### Bug 2 — Score dropped after remediation (domain disappeared from active set)

**Reproduced on**: Debian 13 VM. Pre-`apt upgrade`: `updates.security_pending` WARN present → score 7/10. Post-`apt upgrade`: only `updates.ok` emitted → score *dropped* to 6/10. User-observed effect: making the system more secure produced a worse score, the exact opposite of intuition.

**Why**: `bob/domain_scores.py::active_domains_from_engine()` selected which domains contributed to the global average. The selection filter was `(WARN, ALERT)` only — domains where every finding was OK or INFO were excluded. When `apt upgrade` resolved the WARN, the `updates` domain switched to emitting only `updates.ok`, dropped out of `active_domains`, and the global average was recomputed over a smaller set:

```
Before remediation: avg(updates=8, hardening=4, …) / N        = 7
After  remediation: avg(            hardening=4, …) / (N-1)   = 6   ← BUG
With fix          : avg(updates=10, hardening=4, …) / N       = ~7+ ← CORRECT
```

**Fix**: `_actionable` widened from `(WARN, ALERT)` to `(OK, WARN, ALERT)`. A domain becomes active as soon as any check from it emits a recognisable signal (clean OK or actionable WARN/ALERT). INFO findings remain excluded from promotion — terrain Mint test confirms this is the correct line (INFO-only domains intentionally stay hidden, no transition observed there).

This widening cascades cleanly: domains with only OK findings now appear at 10/10 in the global average, so well-secured aspects of the system are visible in the score instead of being implicit.

### Test additions

- `tests/test_kernel_modules.py`: 5 new tests covering `ii` keep, `rc` exclude, mixed `ii`+`rc`+`pn`+`un`+`iU` filtering, `hi` (hold) keep, and legacy/prefixed format mixed parsing.
- `tests/test_domain_scores.py`: 6 new tests under `TestActiveDomainsIncludesOK`, including the exact Debian 13 remediation scenario asserting the global goes from 8 to 9 when the resolved domain stays visible.

### Verification

- 4500/4500 tests (+11 vs v0.4.5). No regression in the rest of the suite.
- Bug 1 reproduced and now fixed on Mint test VM (post-autoremove kernel listing accurate) and so6desktop (linux-image-6.17.0-20-generic no longer appears after `apt remove`).
- Bug 2 reproduced and now fixed on Debian 13 VM (score now goes up after `apt upgrade`).

---

## [v0.4.5] — 2026-05-16

Test infrastructure hardening release. The new locale-coverage test introduced in v0.4.4 worked correctly but rested on a regex scan of the source code, which has known structural limits. v0.4.5 replaces the regex pipeline with proper AST parsing, eliminating three classes of false positive in one go and removing the `_KEY_EXCLUSIONS` allowlist that was the symptom of the underlying limitation.

### What changed

`tests/test_locale_coverage.py` no longer reads source files as text. It uses `ast.parse` per `bob/**/*.py`, walks the tree, and treats only nodes matching `ast.Call(func=ast.Name(id="t" | "_t"), args=[ast.Constant(str), ...])` as translation call sites. The first positional argument is the literal key.

### What this fixes (vs the regex form)

- **Docstring matches.** The regex matched any `t("...")` literal in source text, including documentation examples. v0.4.4 had to allowlist `samba.open_world` and `log.blocked_attempts` because they appear as examples inside docstrings in `bob/i18n.py`. With AST parsing, docstrings are inert string constants without a calling site — they cannot produce a false positive. The allowlist is gone.
- **Multi-line call site misparses.** The regex required the opening parenthesis and the opening quote to be near each other on the same matched window. Calls split across lines or wrapped over `,` could occasionally trip the pattern. AST is whitespace-independent — the same `ast.Call` is recognised regardless of formatting.
- **Attribute call false positives.** `obj._t("foo.bar")` matched the regex (the negative lookbehind v0.4.4 added on `.` covered most but not all edge cases). With AST, `obj._t` resolves to `ast.Attribute`, not `ast.Name` — the type check rejects it cleanly.

### What's preserved

The external test contract is identical: same 9 tests (`TestLocaleCoverage` + `TestExplainNamespaceCoverage` + `TestPlaceholderParity`), same fixtures, same assertions. Only `_all_t_keys()` and its helpers were refactored. Test count stays at 4489.

### Performance note

AST parsing is ~5× slower than regex on this codebase (300 ms vs 60 ms for `tests/test_locale_coverage.py`). Negligible in absolute terms — the whole test suite still runs in ~6.5 s.

### Tests

4489/4489 — unchanged from v0.4.4. This release is pure refactoring of an existing test file. No source code in `bob/` was modified.

### Deferred to a later release

Items that were already on the roadmap remain there:

- Phase 2 Option A — `Finding.template_vars` migration on ~37 non-pilot checks (still tracked for v0.5.0+).
- M3 cosmetic cleanup (`os.path` → `pathlib`).
- Multi-distro CI matrix and AUR PKGBUILD.

---

## [v0.4.4] — 2026-05-15

Cross-distro terrain hardening release. Four fresh VM tests (Debian 13, Kali Rolling, Linux Mint 22.3, Ubuntu 26.04 LTS — all installed from PyPI via `pipx upgrade`) surfaced **one critical bug, three minor bugs, and confirmed the v0.4.3 fixes work in the wild**. All fixes plus the audit-deferred items from v0.4.3 are bundled here.

### 🔴 Critical — `updates.py` reports "0 pending" on every fresh Debian-family install

Reproduced on **4/4** vanilla VMs:

| Distro | apt-reported pending | of which security | BOB v0.4.3 |
|---|---|---|---|
| Debian 13 | 59 | unknown | 0 |
| Kali Rolling | 868 | unknown | 0 |
| Mint 22.3 (test VM) | 33 | unknown | 0 |
| **Ubuntu 26.04 LTS** | **23** | **21 LTS security** | **0** |

Two compounding causes:

1. **Conservative `apt-get -s upgrade`.** `upgrade` (not `dist-upgrade`) refuses any pending package that would require installing a new one or removing another. On Debian/Ubuntu this hides every security update bundled with a kernel transition or a new soname.
2. **Stale APT cache.** BOB reads `/var/cache/apt/pkgcache.bin`; if `apt update` hasn't run recently the cache reports an outdated state.

Three layered fixes:

- Switched `apt-get -s upgrade` → `apt-get -s dist-upgrade` in [`bob/checks/updates.py:_collect_pending_updates`](bob/checks/updates.py).
- Added `apt_cache_age_days` to `UpdatesSnapshot`. When > 7 days old → new WARN `updates.apt_cache_stale` with `cmd="sudo apt update"`.
- Added `upgradable_count` (from `apt list --upgradable`) cross-check. When `dist-upgrade` returns 0 but `apt list` returns N > 0 → new WARN `updates.dist_upgrade_inconsistent`.

**Cascade** to [`bob/exposure.py`](bob/exposure.py) — the "Surface d'attaque" summary previously displayed `✔ Mises à jour sécurité à jour` even when the snapshot was unreliable. Now displays `⚠ état inconnu — cache APT obsolète ou incohérent` when either of the two new WARNs is present. False reassurance on a security check is worse than admitting we don't know.

### 🟡 Minor — three cosmetic regressions from cross-distro VMs

- **AppArmor "0 profile loaded" case** (Kali). v0.4.3 emitted `AppArmor active but no profiles in enforce mode (0 in complain)` — the parenthetical contradicted itself when Kali had literally 0 profiles total. New dedicated path in [`bob/checks/mac_policy.py`](bob/checks/mac_policy.py): when enforce == 0 AND complain == 0 → new key `mac_policy.apparmor_no_profiles` with message "AppArmor active but no profiles loaded — the framework is running with nothing to enforce" and recommendation to install `apparmor-profiles` / `apparmor-profiles-extra`.
- **SMART "all passed" on VM-only systems** (Kali). On a VM with `/dev/vda`, BOB displayed `ℹ /dev/vda — SMART not applicable` immediately followed by `✔ All disks passed SMART`. Misleading — no real SMART read had been performed. [`bob/checks/disk.py`](bob/checks/disk.py) now only emits `disk.ok` when at least one **real** (non-virtual) SMART check actually ran.
- **DDNS open-ports list rendered as orphan sub-items** (Mint test VM). The `→ 22/tcp` / `→ 80/tcp` lines appeared visually as actions of the INFO advice, but they were the list of ports targeted by the WARN. Now interpolated inline in the WARN message: `DDNS actif avec port(s) ouverts sans restriction (22/tcp, 80/tcp) — ...`. The display-side print loop in [`bob/runner.py`](bob/runner.py) is gone.

### Items deferred from the v0.4.3 audit pass

These were flagged by the agent audit on v0.4.2 and explicitly deferred. All applied here:

- **S4 redesign — symlink-safe ssh reads.** v0.4.3 deliberately did NOT apply `_is_safe_config_path()` to `~/.ssh/authorized_keys` or `~/.ssh/config` because that would break legitimate dotfile setups (configs symlinked from a git repo). New helper [`_is_safe_user_path(path, owner_home)`](bob/checks/_run.py) accepts symlinks that resolve **inside** the owner's home, rejects those pointing outside. Applied in [`bob/checks/ssh/`](bob/checks/ssh/) to `authorized_keys`, `~/.ssh/config`, and `known_hosts`. Closes the SECURITY.md trust-boundary gap on user-controlled config files.
- **M4 refactor — `_parse_ufw_covered_ports`.** Previously `_is_covered_by_ufw` recompiled a regex for every port checked against the same UFW rules text. Now [`bob/checks/ports.py`](bob/checks/ports.py) parses the rules **once** into a `set[(port, proto)]`, and lookups are O(1). Carries the v0.4.3 I4 fix (anchored "To"-column matching) cleanly. The old text-based API is preserved for backward compatibility.
- **I2 wave 2 — `key=` on remaining findings.** v0.4.3 covered `docker.py`, `firewall_stack.py`, `network_context.py`, `ports.py` (4 files). This release finishes the pattern on [`bob/checks/services.py`](bob/checks/services.py) (10 added) and [`bob/checks/virtualization.py`](bob/checks/virtualization.py) (2 added). `disk.py`, `docker_audit.py`, `desktop_apps.py`, `memory.py`, `suid_audit.py` were already at 100% coverage.
- **i18n coverage test.** v0.4.3 had a near-miss when `logs.attempts` was removed from both locales but still referenced by 7 sites in `display.py`. Only the terrain test caught the resulting `[logs.attempts]` sentinel. New [`tests/test_locale_coverage.py`](tests/test_locale_coverage.py) scans all `bob/**/*.py` for `t("KEY")` / `_t("KEY")` calls and asserts each resolves in **both** en.json and fr.json, plus EN/FR structural parity. Any future removal of a still-referenced key fails CI.

### Skipped from the v0.4.3 audit report

- **M3** (`os.path` → `pathlib` in 4 files). Cosmetic, no impact.
- **M7** (lazy `_PLUGIN_DIR` resolution). Already discarded in v0.4.3 — the gotcha was speculative and the attempt broke 20 tests. **Decision permanent.**

### Tests

4489/4489 — +21 vs v0.4.3:
- +10 in [`tests/test_updates.py`](tests/test_updates.py) — 5 cache-stale cases, 5 dist-upgrade-inconsistency cases.
- +2 in [`tests/test_mac_policy.py`](tests/test_mac_policy.py) — desktop INFO and server WARN paths for the new `apparmor_no_profiles` key.
- +9 in [`tests/test_locale_coverage.py`](tests/test_locale_coverage.py) — full corpus scan, EN+FR locale resolution, parity, dynamic-prefix coverage, sanity baseline (5 tests); plus exhaustive `explain.*` coverage generated from `EXPLAIN_KEYS` + non-empty-string check (3 tests, closes a blind spot the previous bypass had) and placeholder parity between EN/FR (1 test, guards against the `{count}` vs `{cnt}` runtime crash class).

### Validated cross-distro

The v0.4.3 fixes confirmed working in the wild on **5 different systems**:
- Linux Mint 22.3 (dev box + test VM): UFW active, DDNS scenario, full audit
- Debian 13 (VM): minimal, smoke test
- Kali Rolling (VM): 15 unexpected SUID (kismet_cap_*), NOPASSWD:ALL, COMPOUND risk detection
- Ubuntu 26.04 LTS (VM): UFW inactive → `firewall.inactive` ALERT correctly triggered with CIS ref + `--explain` link (validates the v0.4.2 C1 + v0.4.3 EXPLAIN_KEYS chain in production)

### Deferred to a later release

- M3 cosmetic cleanup (`os.path` → `pathlib`) — to be included in an eventual "consistency pass" release.
- Phase 2 Option A — systematic `Finding.template_vars` migration on the ~37 remaining checks. Still on track for v0.5.0+.
- Multi-distro CI matrix and AUR PKGBUILD (still community-contribution-welcome).

---

## [v0.4.3] — 2026-05-15

Doc catch-up release that grew into a hardening pass. A fresh agent audit on top of the v0.4.2 codebase found **1 critical + 5 important + 8 minor + 6 suggestion** issues — all applied here. Highlights:

- **C1 (critical)** — `bob --json --json-full` crashed with `AttributeError` whenever a `HardeningSnapshot` was passed. Five field reads in `bob/json_output.py` (`fail2ban_active`, `auto_updates_enabled`, `apparmor_mode`, `apparmor_enforced`, `apparmor_complain`) targeted attributes that had migrated to `mac_policy.py`. The dead reads were removed and the JSON output now exposes the actual fields of the dataclass. **A regression test covers the full+snapshot path.**
- **I1** — `datetime.strptime("%b ...")` is locale-dependent on the **Python process** itself (subprocess `LC_ALL=C` doesn't help). Under `LC_TIME=fr_FR.UTF-8`, `strptime("May 14 ...")` raised `ValueError`, so `_read_cert_expiry` returned "could not parse notAfter" for every cert and `_parse_timestamp` silently dropped every syslog UFW log line. New helper `_parse_english_month_day()` in `bob/checks/_run.py` is locale-independent.
- **I4** — `_is_covered_by_ufw` regex matched the port number anywhere on a UFW status line, so an IP source like `192.168.1.22` "covered" port 22. Anchored the match to the "To" column (right after `[ N]`).
- **I3** — HTML email reports rendered `[label](url)` markdown links as **literal `<a>` tags escaped**. Order of operations reversed in `_inline_format()`.
- **I5** — `_validate_custom_cron` only sanity-checked plain-integer fields. `0-1000 * * * *` and `*/200 * * * *` slipped through silently and were rejected later by cron, losing the schedule. Now validates ranges, lists, and step values across all 5 fields.
- **I2** — Roughly 30 `result.alert()/.warn()/.info()/.ok()/.add_deduction()` calls in `docker.py`, `firewall_stack.py`, `network_context.py`, `ports.py` lacked `key=`. Without it, `--ignore` / audit profiles / JSON consumers cannot match the findings. Same class of bug as the v0.4.2 C1 fix, but generalised to the next 4 most-affected files.

Plus the originally-planned doc catch-up:

1. **4 firewall keys promoted to `EXPLAIN_KEYS`** — `prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`, `firewall.policy_unknown` were wired as `Finding.key` in v0.4.2 (so `--ignore` / profiles / JSON consumers matched them) but `bob --explain firewall.policy_open` still returned "not found". This release writes the full title / why / how content in both `en.json` and `fr.json` plus CIS references.

2. **CHANGELOG.md (short) corrected for v0.4.2** — the section had read "**No code changes** · 4449/4449 tests (unchanged)" which was wrong: the hardening pass shipped with v0.4.2 modified 11 Python files and added 3 tests. The section has been rewritten with the full hardening pass detail (C1, C2, I1-I5, M1-M5, S1-S3).

### Minor + suggestions

- **M1** — Removed 7 dead locale keys (vestiges of the AppArmor migration from `hardening.py` to `mac_policy.py`, plus `services.port_auto`, `services.port_from_config`, `services.state.inactive_enabled`).
- **M2** — `ntp.py:103` `subprocess.run(["ntpstat"])` now passes `env=_C_LOCALE_ENV` for consistency with the rest of the codebase.
- **M5** — `disk.py` dropped the redundant `_SKIP_TYPES_RE` (already covered by `not device.startswith("/dev/")`).
- **M6** — Replaced i18n concatenation anti-pattern in `ddns.py` (`_t("ddns.found") + f": {client}"`) and `logs.py` (`_t("logs.brute_found") + ...`) with proper `{placeholder}` keys. `_identity_t` now performs placeholder substitution to mirror production behaviour in tests.
- **M8** — `services_state.py` now strips `@instance` from systemd unit names so future template units like `auditd@daily.service` map to `auditd`.
- **S1+S2** — `bob/sysinfo.py` 3 subprocess calls (`ufw --version`, `ip route`, `ip addr`) now pass `env=_C_LOCALE_ENV` for consistency.
- **S3** — `bob/checks/cron_audit.py` `_read_cron_file()` now skips symlinks under user-controlled directories (SECURITY.md trust boundary — prevents an attacker with write access to `/var/spool/cron/crontabs/` from materialising arbitrary file contents in audit reports).
- **S5** — `bob/domain_scores.py` `_domain_for_key()` now logs at DEBUG when falling back to "firewall" for unmapped prefixes (helps catch new check keys missing from `_PREFIX_TO_DOMAIN`).
- **S6** — `bob/__init__.py` defines `__all__`.

### Skipped from the audit report

- **M3** — `os.path` → `pathlib` cleanup in 4 files. Pure cosmetic, no impact.
- **M4** — Regex compilation in `_is_covered_by_ufw` per call. Python `re` module caches the last 512 patterns, so negligible.
- **M7** — Lazy `_PLUGIN_DIR` resolution. Reverted because converting the module-level constant to a function broke 20 tests that `patch("bob.registry._PLUGIN_DIR", ...)`. The "gotcha" was speculative; BOB runs one-shot per audit.
- **S4** — Symlink check on `~/.ssh/authorized_keys` and `~/.ssh/config`. Users may legitimately use symlinks in `~/.ssh/`. Deferred pending design discussion.

### Verified

- `bob --explain firewall.inactive` (EN + FR) — title, WHY IT IS A RISK, HOW TO FIX, CIS ref all present.
- `bob --explain firewall.policy_open` / `firewall.policy_unknown` / `prerequisites.ufw_missing` — same.
- `bob --explain firewall.logging_off` — unchanged (pre-existing key, regression-tested).
- `bob --explain list` — shows "Firewall" group with all 5 keys.
- `LC_TIME=fr_FR.UTF-8 python3 -c "from datetime import datetime; ..."` — `_parse_english_month_day` succeeds where `strptime("%b ...")` failed.
- `_is_covered_by_ufw(22, "tcp", ...)` — returns `False` when port 22 only appears inside an IP source like `192.168.1.22`.
- `build_json_data(full=True, hardening_snapshot=HardeningSnapshot())` — no longer raises `AttributeError`.

### Tests

4468/4468 — +16 vs v0.4.2:
- +12 parametrised invocations from the 4 new EXPLAIN_KEYS entries (3 parametrised checks × 4 keys: title, WHY/HOW headers, CIS reference).
- +4 new regression tests in `tests/test_json_schema.py::TestFullModeWithOptionalSnapshots` covering the `full=True` + `hardening_snapshot`/`ipv6_snapshot` paths (the lacuna that let C1 slip into v0.4.2).

### Deferred to a later release

- Systematic migration of the remaining ~37 non-pilot checks to `Finding.template_vars` (Phase 2 Option A). Still on track for **v0.5.0+** per the original roadmap.
- Multi-distro CI matrix and AUR PKGBUILD (still community-contribution-welcome).
- `~/.ssh/*` symlink protection (S4 above).

---

## [v0.4.2] — 2026-05-14

Phase 3 of the distro-ready roadmap — packaging discipline. Ships packaging artefacts and policy documents that downstream distro maintainers need, plus a pre-release hardening pass that closed 2 critical + 5 important + 4 minor + 1 suggestion findings from an agent audit. 4452/4452 tests (+3 from `tests/test_template_vars_migration.py`).

The repository now contains everything a packager needs to produce a distribution-ready BOB without patching the source.

### New artefacts

- **`SECURITY.md`** — formal threat model and vulnerability disclosure policy. Documents what BOB defends against, what's out of scope (pre-existing root compromise, kernel-level attacks), the three trust boundaries (user-controlled config, system file content, subprocess output) and their respective defenses, the network surface (2 outbound HTTPS calls disabled by `--offline`), and the data handling guarantees (file permissions, auto-chown to `SUDO_USER`).
- **`man/bob.1`** (~280 lines) — the main user-facing man page. Documents every CLI option grouped by purpose (audit control, output formats, configuration, comparison, remediation, network, periodic audits, filters), exit codes as stable public API, the JSON output contract, file paths under `~/.config/bob/`, environment variables (`SUDO_USER`, `LC_ALL/LC_MESSAGES/LANG`), and the security model with a `SEE ALSO` cross-reference to companion pages.
- **`man/bob.conf(5)`** (~80 lines) — config file format reference (`~/.config/bob/config.conf`): custom service ports, `log_dir`, `suid_whitelist` patterns, webhook defaults, email address book.
- **`man/bob-profile(5)`** (~100 lines) — audit profile file format: `[profile]` metadata, `[overrides]` per-key severity (`info`/`warn`/`alert`/`skip`), the `extends` chain, profile discovery order, and the three shipped profiles (`server` / `desktop` / `container`).
- **`debian/`** — full Debian source package directory:
  - `control` — 3 binary packages: `bob-core` (audit engine, no curses), `bob-tui` (curses TUI), `bob` (meta-package). Build-Depends on `debhelper-compat (= 13)` and `pybuild-plugin-pyproject`. Rules-Requires-Root: no.
  - `copyright` — DEP-5 format, MIT throughout, distinct stanzas for `bob/data/`, `bob/locales/`, `bob/data/schemas/`, `debian/`.
  - `changelog` — initial Debian changelog entry `0.4.2-1`.
  - `rules` — pybuild-based, installs man pages and `SECURITY.md` into `bob-core`.
  - `source/format` — `3.0 (quilt)`.
  - `bob-core.install` / `bob-tui.install` — explicit file lists per binary package (curses confined to `bob-tui`, everything else under `bob-core`).
  - `bob-core.docs` / `bob-core.manpages` — doc installations.
- **`debian/apparmor.d/bob`** — AppArmor profile (~140 lines). Shipped in `complain` mode by default with an opt-in `enforce` path. Allows read on `/etc/`, `/proc/`, `/sys/`, `/var/log/`, `~/.config/bob/`, `~/.ssh/`. Whitelists ~30 system binaries that BOB exec's (`ufw`, `ss`, `iptables`, `systemctl`, `journalctl`, `openssl`, `smartctl`, `fwupdmgr`, `apt-cache`, `aa-status`, etc.). Outbound TCP allowed but gated at the application level by `--offline`.
- **`packaging/rpm/bob.spec`** — Fedora COPR / RHEL RPM spec built on `pyproject-rpm-macros`. Single binary `bob` package (no split bob-core/bob-tui — Fedora typically doesn't split that way for Python packages). `%check` runs the full pytest suite. Man pages and `SECURITY.md` installed.

### Policy documentation

- **`DOCUMENTS/README_TECH.md` + FR** — new "Python support policy" section formalizing the **N and N-2** support window. As of v0.4.2: Python 3.10 / 3.11 / 3.12 (and 3.13 when released). 3.9 is end-of-life since v0.2.3. The drop procedure is documented: a Python version drop spans at least 3 minor BOB releases (validate / announce / remove) for a minimum 6-month notice — packagers can rely on this to plan rebuilds.
- **`DOCUMENTS/README_TECH.md` + FR** — new "Packaging (since v0.4.2)" section pointing distro maintainers at the relevant artefacts.

### Roadmap context — Phase 3 status

| Item | Status |
|---|---|
| `SECURITY.md` threat model | ✅ done |
| Man pages (`bob(1)`, `bob.conf(5)`, `bob-profile(5)`) | ✅ done |
| `debian/` source package | ✅ done |
| RPM spec (Fedora COPR) | ✅ done |
| AppArmor profile (complain mode) | ✅ done |
| Python support policy | ✅ done |
| Multi-distro CI matrix | ⏳ deferred (v0.4.x) |
| AUR PKGBUILD | ⏳ deferred — community contribution welcome |
| Lintian-clean + rpmlint-clean verification | ⏳ ongoing (initial pass clean, real packaging test pending) |

### Distro readiness assessment after v0.4.2

- **AUR / COPR community packaging** — viable now (was viable since v0.4.0, this release makes it trivial).
- **Debian unstable** — target window opens: source package builds with `dpkg-buildpackage`; remaining work is lintian-clean verification and an upstream maintainer sponsorship.
- **Fedora COPR official** — same: spec builds; remaining work is COPR account + rpmlint clean.
- **Debian main / Fedora main** — still 12–18 months minimum, as the policy commits to 12 months of contract stability before request.

### Hardening pass (pre-release audit)

A full pre-release code audit surfaced 2 critical + 5 important + 4 minor + 1 suggestion issues — all fixed in the same release:

- **C1** — `firewall.py`: 4 `result.alert()` / `result.add_deduction()` calls lacked `key=`. Without it, `--ignore` / profiles / JSON consumers could not match the most critical alerts. Fixed with `key="prerequisites.ufw_missing"`, `"firewall.inactive"`, `"firewall.policy_open"` on the relevant calls.
- **C2** — `debian/apparmor.d/bob`: 10 binaries BOB actually exec's were missing from the profile (`df`, `lsblk`, `dpkg-query`, `getenforce`, `apt-get`, `find`, `ps`, `netstat`, `ntpstat`, `docker`) + line declared `/usr/local/sbin/bob-*` rw whereas `cron.py` writes to `/usr/local/bin/bob-{slug}`. Both fixed.
- **I1+I2** — `ssl_certs.py` + `virtualization.py`: 3 subprocess calls missing `env=_C_LOCALE_ENV`, breaking date parsing on French locale.
- **I3** — `bob/_paths.py`: renamed `UFW_AUDIT_SHARE` → `BOB_SHARE` env var (legacy name still honored).
- **I4** — RPM spec: `Recommends: firewalld` was wrong (BOB only reads ufw). Fixed to `Recommends: ufw`. **M5** adds `Suggests: apparmor`.
- **I5** — `bob/watch.py`: `run_checks()` called without `user_config=`, silently losing user's SUID whitelist on every `--watch` tick.
- **M1** — Removed untracked `microsoft.gpg` (residue).
- **M2** — `bob/formatter.py` docstring clarified (public API, no internal caller in v0.4.x).
- **M4** — Exposed `bob.compare.BASELINE_PATH` as public symbol.
- **S1** — New `tests/test_template_vars_migration.py` (3 tests) makes Phase 2 migration debt visible.
- **S2** — Documented the timeout policy block at the top of `bob/checks/_run.py`.
- **S3** — Sorted imports in `bob/cron.py` (PEP 8 grouping).

Note: 4 keys are referenced by Findings (`prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`) but not yet in `EXPLAIN_KEYS` — adding them requires writing full title/why/how/CIS content, deferred to v0.4.3.

### Tests

4452/4452 (+3 from `tests/test_template_vars_migration.py`). Validated:
- All 3 man pages render with `man -l` and `groff -man -Tutf8` without errors.
- 3 schema JSON files remain valid (only the `$id` URL was version-bumped from `v0.4.1` → `v0.4.2`).
- The 3 ChatGPT-style external reviews of Phase 2 still hold (no contract changes).

---

## [v0.4.1] — 2026-05-14

Phase 2 of the distro-ready roadmap — architectural decoupling. Three zones tackled: `--offline` mode finalization, curses isolation via `bob/tui/`, and locale-independent representation of findings via additive `template_vars`. Plus a post-review hardening pass on `bob/formatter.py` (4 edge-case tests + tightened API). All changes are non-breaking (additive). 4449/4449 tests (+19).

### Zone 2.1 — `--offline` strict mode verified

The `-o` / `--offline` flag (already present since v0.4.0) was audited end-to-end: all network-touching sites are either already gated (HTTP `get_public_ip`, webhook POST) or are local-only (apt-cache, fwupdmgr get-updates, journalctl, openssl x509). Added 2 integration tests in `tests/test_webhook.py` that pin the offline contract: webhook is NOT sent when `config.offline=True` even with a webhook URL set, and `get_public_ip(offline=True)` short-circuits before any `urllib` call.

### Zone 2.2 — `bob/tui/` curses subpackage

`bob/cron_ui.py` (952 lines) moved to `bob/tui/cron.py` under a new `bob.tui` subpackage. Curses imports were already lazy (inside functions) — this release makes the separation physical. The 2 call sites in `bob/cron.py` updated to `from bob.tui.cron import ...`. The rest of `bob.*` (audit pipeline, checks, scoring, JSON output) remains importable on systems without curses, which is the prerequisite for a future `bob-core` Debian package separate from `bob-tui`.

### Zone 2.3 — Locale-independent findings (additive)

Two new optional fields on `Finding` and `Deduction`:

```python
@dataclass
class Finding:
    ...
    key:           str  = ""    # already since v0.3.7
    template_vars: dict = field(default_factory=dict)   # new in v0.4.1
```

`template_vars` is the mapping of variables that the check passed to its i18n template (e.g. `{"ciphers": "aes128-cbc, des-cbc"}` for `ssh.weak_ciphers`). When non-empty, an external client can rebuild the localized message from `(key, template_vars, locale)` without depending on the pre-formatted `message` string.

New module `bob.formatter` exposes `format_finding(finding, lang=None)` and `format_deduction(deduction, lang=None)`. Resolution order: `key + template_vars` → `key` alone → fallback to pre-formatted `message` (legacy path, fully backward compatible).

`CheckResult.warn/alert/info/ok/add_finding/add_deduction` helpers accept an optional `template_vars=` kwarg. The 3 pilot checks (`bob/checks/ssh.py`, `hardening.py`, `firewall.py`) demonstrate the migration: same `message=_t("key", **vars)` is kept (legacy compat) and `template_vars={...vars...}` is added in parallel. JSON output now exposes `template_vars` on every deduction and finding (additive field — empty dict for legacy checks).

### Roadmap context

This release closes Zone 2.1 + 2.2 + 2.3 (Option B additive) of the Phase 2 plan. Three pilot checks demonstrate the pattern; the remaining 40 checks can be migrated incrementally without breaking changes. Option A (full breaking refactor — `Finding.message` removed in favor of `Finding.template_vars` mandatory) is deferred to v0.5.0+ together with the schema v2 plugin contracts.

### Tests

4449/4449 (+19):
- 3 new in `tests/test_webhook.py` for offline mode (skip POST, urllib short-circuit, CLI compat)
- 14 new in `tests/test_formatter.py` (10 base: resolution order, locale roundtrip, backward compat; +4 post-review edge cases: partial template_vars, mismatch key/message, empty inputs)
- 2 new in `tests/test_json_schema.py` (`template_vars` exposed in JSON for every deduction and finding)

### Field validation

End-to-end audit on so6desktop: `bob.tui.cron` loads cleanly, the 3 pilot checks emit `template_vars` correctly, `bob --json` exposes the new field on every entry, `--offline` skips the webhook.

---

## [v0.4.0] — 2026-05-14

Phase 1 of the distro-ready roadmap — five public-API contracts frozen so that scripts, dashboards and downstream packagers can rely on stable behavior. No new features, no breaking changes (additive only). 4405/4405 tests (+57).

### Stable contract — Exit codes documented as public API (`bob/__main__.py`, `bob/cli.py`, `DOCUMENTS/README_TECH.md`)

The 5 exit codes (`EXIT_OK=0`, `EXIT_WARNINGS=1`, `EXIT_ALERTS=2`, `EXIT_ERROR=3`, `EXIT_TARGET_MISSED=4`) are now formally promoted to BOB's public API: their values and semantics will not change within a major version. Documented in `--help` (with the missing exit-code 4 mention added) and in a dedicated section of README_TECH. Constants exported from `bob.__main__` for programmatic access.

### Stable contract — Locale auto-detection from POSIX `$LANG` (`bob/i18n.py`, `bob/cli.py`, `tests/conftest.py`)

`bob.i18n.detect_system_lang()` (new) probes `$LC_ALL` / `$LC_MESSAGES` / `$LANG` in standard POSIX order and resolves to `"fr"` for `fr_*` locales or `"en"` otherwise (incl. `C`, `POSIX`, `C.UTF-8`, unsupported languages). `parse_args()` calls it as the default when neither `--lang=` nor `--french` is passed; explicit flags always override. New autouse fixture in `tests/conftest.py` forces `LANG=C` for deterministic tests regardless of host locale.

### Stable contract — JSON output schema documented + `key` field exposed (`bob/json_output.py`, `bob/scoring.py`)

`schema_version="1"` was already present; this release formalizes the contract: top-level keys never disappear/rename within v1, additions are free, breaking changes bump to v2. New constants `SCHEMA_V1_REQUIRED_KEYS` and `SCHEMA_V1_FULL_KEYS` make the contract testable. `Finding.key` and `Deduction.key` are now serialized as `key` field on each entry — clients can match findings via stable dotted keys without depending on the localized `message`/`reason`. Full schema reference added to README_TECH (table of every top-level key, structure of nested objects, locale-independent matching example).

### Stable contract — `--explain` alias map + freeze policy (`bob/explain.py`)

`EXPLAIN_KEY_ALIASES: dict[str, str]` introduced (empty for now) so future renames have a documented migration path: old name → new name, alias never expires within the same major schema version. `normalize_key()` consults the map after path-segment stripping. Module docstring states the freeze policy explicitly: no removal, no rename, no semantic shift, additions free. 16 load-bearing keys explicitly tested as frozen.

### Stable contract — Plugin services formal JSON Schema (`bob/data/schemas/`, `pyproject.toml`)

Two Draft 2020-12 JSON Schema files (`service.schema.json`, `services-list.schema.json`) describe the shape of `services.json` and user `*.json` plugins. Bundled list (`bob/data/services.json`) is verified to validate against the schema. Schemas are shipped via `package_data` so distro packagers can validate user plugins externally with `check-jsonschema` / `ajv`. Python validation in `Service.from_dict()` remains the runtime source of truth (zero added runtime dependency); the JSON Schema mirrors it for external tooling.

### Bonus UX — `= N` redundant suffix on unchanged score removed (`bob/display.py`)

When the score was unchanged vs the previous audit, the summary box showed `Security score : 8/10  = 8` — the `= 8` was a vestige of an earlier delta marker. Removed: stable score now displays simply `8/10` (the score is already shown). Test renamed `test_stable_shows_equal` → `test_stable_shows_no_annotation`.

### Tests

4430/4430 (+82): 16 new in `test_i18n.py` (12 `detect_system_lang` + 4 CLI integration), 17 in new `test_json_schema.py` (top-level invariants, field types, stable-key exposure, strict-set + constants-drift defense-in-depth from post-review pass #2), 6 in `test_explain.py` (alias map + freeze policy), 43 in new `test_services_schema.py` (schema valid, bundled services match, sample valid/invalid plugins, Python ↔ Schema parity, plus `$defs` factorization / strict 1–65535 port regex / business `if/then` constraints / plugin-file `schema_version` wrapper / `minItems: 1` from post-review passes #1+#2).

### Field validation

End-to-end audit on so6desktop (Linux Mint 22.3) — score 8/10, all sections render correctly, locale auto-detected as French via `$LANG=fr_FR.UTF-8`.

---

## [v0.3.6] — 2026-05-09

Code-review pass following a deep audit of the codebase. No new features, no behaviour changes — bug fixes, hygiene, and consistency. 4348/4348 tests.

### Fix — `Path.home()` resolves to `/root` under sudo (`bob/config.py`, `bob/recurrence.py`, `bob/history.py`, `bob/registry.py`, `bob/compare.py`, `bob/profiles.py`, `bob/plugin_checks.py`, `bob/ignore.py`)

Seven modules used `Path.home()` at module import to compute config/plugin/baseline directories. Under `sudo`, this resolves to `/root/.config/bob/` instead of the invoking user's home — silently breaking user profiles, service plugins, check plugins, baseline, and recurrence/history persistence. The correct helper `bob.sysinfo.get_user_home()` (which honours `SUDO_USER`) already existed but was used in only two places. All seven modules now import and use `get_user_home()`. `bob/ignore.py` had its own duplicated logic — replaced with a call to the shared helper.

To complete the fix, a new helper `bob.sysinfo.chown_to_sudo_user(path)` is called after each user-config directory/file is created or written under sudo, so the invoking user retains read/write access in non-sudo sessions (no-op when not running under sudo). Applied in `config.py`, `compare.py`, `recurrence.py`, `history.py`, `ignore.py` after `mkdir(parents=True)` and after each atomic `replace`/`write_text`. The `registry.py`, `profiles.py`, and `plugin_checks.py` lookups gain a `PermissionError` guard so a directory inaccessible at read time (legacy state from a pre-fix sudo run) gracefully falls back to "no plugin found" instead of crashing.

### Fix — `AllowTcpForwarding local` flagged as a warning (`bob/checks/ssh.py`)

The check accepted only `AllowTcpForwarding no` as safe. Setting `local` (which is more restrictive than the default `yes` and explicitly recommended in BOB's own remediation text) was incorrectly counted as an issue and deducted 1 point. Now both `no` and `local` are accepted.

### Fix — UFW logging section header shown when UFW inactive (`bob/runner.py`)

When UFW was inactive, `check_ufw_logging()` returned an empty `CheckResult` but `runner.py` still printed the section header (`UFW LOGGING`), producing a header followed by no findings. The header is now only printed when `fw_status.active`.

### Fix — IPv6 ULA and link-local treated as external (`bob/checks/network_context.py`)

`_is_private_or_loopback()` covered IPv4 loopback, RFC-1918, and IPv6 `::1` but missed `fc00::/7` (Unique Local Addresses) and `fe80::/10` (link-local). Connections within those ranges were classified as external, producing spurious warnings. Rewritten using `ipaddress.ip_network()` with the same network list as `bob/checks/auth_log.py`.

### Fix — `NOTIFY_EMAIL` legacy regex silently skipped (`bob/cron.py`, `bob/locales/{en,fr}.json`)

`edit_cron_email()` matched only `NOTIFY_EMAILS=` (plural — current format) but not `NOTIFY_EMAIL=` (singular — pre-v0.x scripts). Old scripts saw a "successful" email update that didn't actually patch anything. Now matches both `NOTIFY_EMAILS?=` and warns when no line was matched (new locale key `manage_cron.email_not_found_in_script`).

### Refactor — `_check_weak_algo` moved to sub-check section (`bob/checks/ssh.py`)

The helper was placed in the `# Parsing helpers` section but is logically a sub-check (writes to `result`, calls `_t`). Moved next to the other `_check_*` functions for consistency with project convention.

### Cleanup — 22 unused imports removed (pyflakes)

Vestiges from successive refactorings: `dataclasses.field` in 6 modules where no field defaults exist; `typing.Optional` in 4 modules; `pathlib.Path` in 2; `bob.scoring.{ScoreEngine, Finding, FindingLevel}` in `report.py`; `shutil`, `_C_LOCALE_ENV`, `prompt_emails`, `WebhookError`, etc. Variable shadowing of `dataclasses.field` by parameter `field` in `_extract_field()` resolved by renaming to `field_name`. Dead variable `found_issue` in `check_hardening()` (never read) removed along with all 8 assignments.

### Cleanup — 47 dead locale keys removed (`bob/locales/{en,fr}.json`)

Audit of every key against actual `t()` and `_t()` call sites (including dynamic `f"prefix.{var}"` patterns). Removed: entire `cli.help_*` (14 keys, replaced by hardcoded `print_help` in `cli.py`), entire `errors.*`, `geo.*`, `profile.*` objects, plus orphans in `report`, `manage_cron`, `install_cron`, `prerequisites`, `network_context`, `ddns`, `logs`, `ports`, `summary`, `fixes`, `risk_context`, `log_dir`, `config`, `deduction`, `status`. Both files stay key-synchronised: 1435 → 1388 keys (−47), 2049 → 1994 lines per file.

### Tests

4348/4348 (no change vs v0.3.5). All fixes covered by existing tests; no regression introduced. Validated end-to-end on so6desktop (Linux Mint 22.3) — full audit completes with score 8/10 and renders all sections correctly.

---

## [v0.3.5] — 2026-05-08

Pure internal refactoring and locale fix — no new features, no behaviour changes. 4348/4348 tests.

### Refactoring — `runner.py` `_sec` closure (`bob/runner.py`)

`run_checks()` (951L) contained ~29 identical 7–13 line blocks: `_section_enabled` guard + `print_section` + `report.write_section` + `check_fn` call + `apply_profile` + `engine.apply` + `display_result` + trailing `print()`. Extracted as a `_sec(section, snapshot, check_fn, **kwargs)` closure that captures `config`, `profile`, `engine`, `report`, `t`, `_pr` from the outer scope. All standard sections use `_sec`; exceptions kept manual: firewall/network headers, ports, logs, DDNS, docker, virtualisation, samba, docker_audit, desktop_apps, iptables_nft, disk (extra display call). Net: 951L → 656L (−295 lines). `_pname` pre-computed for the 8 sections that accept `profile_name=`.

`auth_log` previously omitted `apply_profile` — now consistent with all other sections (no-op in practice as no profile currently defines auth_log overrides).

### Refactoring — `ssh.py` `_check_weak_algo` helper (`bob/checks/ssh.py`)

`_check_sshd_config()` had three structurally identical 16-line blocks for weak Ciphers, MACs, and KexAlgorithms. Extracted as `_check_weak_algo(cfg, result, _t, cfg_key, weak_set, t_key, param, points) -> bool`. The three blocks collapse to three one-liner calls. Net: −26 lines.

### Fix — locale strings `UFW-AUDIT` → `BOB` (`bob/locales/en.json`, `bob/locales/fr.json`)

Four translation keys still referenced the former tool name `UFW-AUDIT` instead of `BOB`: `install_cron.title`, `manage_cron.title`, `manage_cron.no_crons`, `report.title`. Replaced in both locale files.

---

## [v0.3.4] — 2026-05-08

Hotfix for a regression introduced in v0.3.2. `user_config` was referenced inside `run_checks()` but never passed as a parameter — every audit crashed with `Fatal error: name 'user_config' is not defined` immediately after the kernel hardening section. 4348/4348 tests.

### Fix — `user_config` not passed to `run_checks()` (`bob/runner.py`, `bob/__main__.py`)

`run_checks()` gained `user_whitelist=user_config.get_suid_whitelist()` in v0.3.2 but `user_config` was never added to the function signature. Fix: `user_config: UserConfig | None = None` parameter added; `__main__.py` passes `user_config=user_config` at the call site. Fallback is `[]` when `None` (no whitelist applied).

---

## [v0.3.3] — 2026-05-07

Pure internal refactoring — no new features, no behaviour changes. Four related cleanup tasks driven by a code-review pass on the codebase. 4348/4348 tests (+1).

### Refactoring — `cron.py` split (`bob/cron.py`, `bob/cron_ui.py`)

`bob/cron.py` (2181L) was split into two modules. `bob/cron.py` retains all data types, parsers, logic, and plain-text interactive flows. `bob/cron_ui.py` (new, 955L) holds all curses TUI code. Dispatchers `run_install_cron()` / `run_manage_cron()` use a lazy-import pattern: check `sys.stdout.isatty()` → plain-text flow; otherwise `curses.wrapper(curses_fn)` with `curses.error` fallback to plain-text.

`build_script_content(notify_email, log_dir) -> str` extracted from both install flows into `cron.py` as a pure function, eliminating a 40-line duplication.

### Refactoring — `compute_domain_scores()` pure return (`bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`)

`Deduction.was_capped: bool` field removed. `compute_domain_scores()` now returns `tuple[dict[str, dict], frozenset[int]]` — the second element is the set of indices in `engine.breakdown` that were reduced by a tool cap. `ScoreEngine` caches these indices via `set_domain_scores()` (new `capped_indices` parameter) and exposes them through a `capped_indices` property. `breakdown.py` reads `engine.capped_indices` directly.

### Refactoring — `domain_scores.py` public API

`_LABELS → LABELS`, `_TOOL_CAPS → TOOL_CAPS`, `_key_to_domain → key_to_domain`. Callers updated: `breakdown.py`, `explain.py`, `tests/test_domain_scores.py`.

### Refactoring — `cron_ui.py` curses helpers

`_WizardEntry(name, hour=3, minute=0)` NamedTuple replaces `class _FakeEntry: pass` stub. `_draw(stdscr, row, col, text, attr=0)` absorbs 30+ `try: addstr(…) except curses.error: pass` blocks. `_read_key(stdscr) -> int` absorbs 9 `try: get_wch() / except curses.error: continue` + ch-normalisation blocks. Schedule type magic indices replaced by `_SCHEDULE_DAILY/WEEKDAYS/MONTHDAYS/CUSTOM` constants. Net reduction: 1104L → 955L (−149 lines).

### Tests

4348/4348 (+1 from v0.3.2): `TestWasCapped` replaced by `TestCappedIndices` (7 tests) covering the frozenset return contract of `compute_domain_scores()`.

---

## [v0.3.2] — 2026-05-06

User-configurable SUID whitelist: patterns declared in `~/.config/bob/config.conf` suppress known-legitimate binaries from the "unexpected SUID" warning. No new warnings — only noise reduction for environments like Kali that ship extra SUID tools. Plus 14 code-review fixes covering i18n labels, quiet-mode bypass, engine idempotency, dead code, and minor bad practices. 4347/4347 tests (+19).

### Feature — `suid_whitelist` in `config.conf` (`bob/config.py`, `bob/checks/suid_audit.py`, `bob/runner.py`)

Users can now declare glob patterns for approved SUID binaries directly in `~/.config/bob/config.conf`:

```
# ~/.config/bob/config.conf
suid_whitelist = kismet_cap_*, my_custom_tool
```

Patterns are matched against the **basename** of each detected SUID binary using `fnmatch`. Matched paths are removed from the "unexpected SUID" list, eliminating false positives on Kali (15+ Kismet capture binaries), enterprise environments, or systems with custom in-house tools.

When at least one binary is suppressed, an INFO finding `suid_audit.whitelisted` reports the count and paths, so users can confirm the whitelist is working without silently hiding everything.

Implementation: `UserConfig.get_suid_whitelist() -> list[str]` reads and parses the comma-separated key. `SuidSnapshot.from_system()` gains a `user_whitelist` parameter; the runner passes `user_config.get_suid_whitelist()` at call time. The suppressed paths are stored in `SuidSnapshot.whitelisted_suid` for transparent reporting.

### Fixes — code review (14 items)

| ID | File | Fix |
|----|------|-----|
| BUG-2 | `domain_scores.py` | `compute_domain_scores()` reset `was_capped=False` before recomputing — idempotent now |
| BUG-3 | `runner.py` | `"samba"` and `"desktop_apps"` added to `_ALL_SECTIONS` — visible to `--check`/`--skip`/`--list-checks` |
| BUG-4 | `output.py` | `_print_status()` and `print_risk_context()` use `_p()` — quiet mode now respected |
| BUG-1 | `output.py` | `[ATTENTION]`/`[ALERTE]` → `t("status.warn")`/`t("status.alert")` — i18n wired |
| BUG-5 | `scoring.py`, `logs.py`, `display.py` | `result._log_data` → proper `CheckResult.log_data` field (no more `# type: ignore`) |
| BUG-6 | `checks/logs.py` | Bruteforce `warn()` and `add_deduction()` gain `key="logs.brute_found"` — visible to `--ignore` and profiles |
| SF-1 | `checks/ssh.py` | `sshd_config` parse emits `ssh.match_block_skipped` INFO when a `Match` block truncates parsing |
| SF-2 | `__main__.py` | `curr_baseline = None` initialised before `with` block — no `UnboundLocalError` risk |
| SEC-1 | `fixes.py` | Raw `\033[...]` literals replaced by `output._c.*` — respects `--no-color` |
| BP-2 | `scoring.py`, `domain_scores.py` | `engine.set_domain_scores()` public method — no more direct `_private` attribute writes |
| BP-3 | `checks/ssh.py` | `f.level.value in (...)` → `f.level != FindingLevel.OK` — enum-safe comparison |
| BP-1 | `__main__.py` | `open(os.devnull, "w", encoding="utf-8")` — explicit encoding |
| INC-2 | `runner.py` | `SambaSnapshot`/`DesktopAppsSnapshot.from_system()` moved inside `_section_enabled()` guard — no subprocess on `--skip` |
| DC-1 | `checks/suid_audit.py` | `_is_root_owned()` deleted — private dead code duplicating inline logic |

### Tests

4347/4347 (+19 net from v0.3.1):

| File | Change |
|------|--------|
| `tests/test_suid_audit.py` | +21 across `TestFromSystemUserWhitelist` (8), `TestGetSuidWhitelist` (7), `TestGlobMatching` (7) — −2 `TestIsRootOwned` (deleted with DC-1) |
| `tests/test_logs.py` | 3 assertions updated `_log_data` → `log_data` (BUG-5) |

---

## [v0.3.1] — 2026-05-06

Two targeted bug fixes found during multi-VM validation, plus two architectural refactors in the score breakdown pipeline. No new features. 4328/4328 tests (+6).

### Fix — `__version__` banner stuck at `0.2.4` (`bob/__init__.py`)

After the v0.3.0 release, `bob/__init__.py` still declared `__version__ = "0.2.4"`. The banner and `bob -V` both displayed the wrong version on all platforms. Fixed.

### Fix — DDNS network context not propagated to score header (`bob/runner.py`, `bob/__main__.py`)

When DDNS was active and open ports were detected, `run_checks()` upgraded `network_context` from `"local"` to `"ddns"` internally — but `ChecksResult` (a NamedTuple) did not include a `network_context` field, so the caller always saw `"local"`. The score summary header showed "Local network only" even on machines with an active DDNS client. Fix: `network_context: str = "local"` added to `ChecksResult`; `__main__.py` reads `result.network_context` immediately after `run_checks()`.

### Refactor — `was_capped: bool` on `Deduction` (`bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`)

`breakdown.py` previously re-simulated the tool-cap accounting to determine which deductions were absorbed by a cap — duplicating logic from `compute_domain_scores()` and violating the module's "nothing is computed here" contract. Fix: `Deduction` gains `was_capped: bool = False`; `compute_domain_scores()` sets it when a deduction is partially or fully absorbed. `breakdown.py` reads `d.was_capped` directly.

### Refactor — `engine.domain_scores` / `engine.active_domains` cached properties (`bob/scoring.py`, `bob/domain_scores.py`)

Display modules (`__main__.py`, `breakdown.py`) previously called `compute_domain_scores()` and `active_domains_from_engine()` independently, risking double computation. Fix: `apply_domain_score_override()` caches results on the engine; two `@property` methods expose them as `engine.domain_scores` and `engine.active_domains`. All callers read from the cache.

### Tests

4328/4328 (+6 new):

| File | Change |
|------|--------|
| `tests/test_domain_scores.py` | +6 `TestWasCapped`: uncapped / fully absorbed / partially absorbed deductions · non-tool-cap keys never marked · cached domain scores on engine · engine state before override |

---

## [v0.3.0] — 2026-05-06

Scoring transparency milestone: `--breakdown` (`-B`) shows the full score computation path — deductions, tool caps, engine cap, raw score, per-domain scores, domain-average override, and final score. `--explain <key>` gains a SCORING section showing domain membership and tool cap. Three targeted fixes: kernel `-unsigned` asymmetry in retention logic, orphan `→` in the score delta line, and "UFW-AU" ASCII art relics in the detailed report. 4322/4322 tests (+48).

### Feature — `--breakdown` / `-B` flag (`bob/breakdown.py`, `bob/cli.py`, `bob/__main__.py`, locales)

New post-audit view that prints the complete score computation path without re-running checks. Shows: all deductions (key · domain · points · context), which deductions were absorbed by tool caps, whether the engine cap applied, raw score before domain averaging, per-domain scores with progress bars, whether the domain-average override fired, and the final score color-coded by severity.

Implemented using `_silent_mode`: audit output is redirected to `/dev/null` via `redirect_stdout`, then breakdown is displayed after stdout is restored. This suppresses all bare `print()` calls (not just `output.*` calls), giving a clean view.

i18n: `breakdown.*` keys added to both `bob/locales/en.json` and `bob/locales/fr.json`.

### Feature — Score-aware `--explain` (`bob/explain.py`)

`bob --explain <key>` now appends a SCORING section after the remediation text, showing the key's domain and any applicable tool cap. Ends with a hint to run `sudo bob --breakdown` to see the live score contribution.

### Fix — Kernel `-unsigned` retention asymmetry (`bob/checks/kernel_modules.py`)

On Debian systems with signed/unsigned kernel pairs (e.g. `6.12.74+deb13+1-amd64` and `6.12.74+deb13+1-amd64-unsigned`), the unsigned variant sorted alphabetically last and consumed one retention slot, leaving the signed variant incorrectly marked as obsolete. Fixed: after the retention loop, the keep-set is expanded to include both signed and unsigned variants of every kept base version. The obsolete detail message also now uses `recent=running` instead of `recent=most_recent` so the boot-verification hint always names the kernel the system is actually running.

### Fix — Score delta orphan arrow (`bob/display.py`)

When the score was identical between two consecutive audits, the score line showed `6/10  →` with no value after the arrow. Changed to `6/10  = 6` (equals sign + repeated score) for clarity.

### Fix — "UFW-AU" relics in detailed report (`bob/report.py`, `bob/report_markdown.py`)

The detailed report file opened with `--detailed` contained an ASCII art banner spelling "UFW-AU" (from the former tool name "ufw-audit") and a header field "UFW: v...". Replaced with BOB ASCII art (same style as the terminal banner) and "Firewall: ufw ...". Markdown report updated: "UFW:" → "Firewall (UFW):".

### Tests

4322/4322 (+48 new):

| File | Change |
|------|--------|
| `tests/test_breakdown.py` | New file — 16 tests: bar helper, clean engine, deductions, tool cap, engine cap, domain override, French labels |
| `tests/test_golden_scenarios.py` | New file — 32 tests: end-to-end scoring scenarios across 9 test classes (clean, hardened, desktop, poorly configured, firewall inactive, Debian minimal, tool caps, stability, multi-domain) |
| `tests/test_min_level.py` | Renamed `test_stable_shows_right_arrow` → `test_stable_shows_equal` to match `= N` format |

---

## [v0.2.4] — 2026-05-05

Post-audit codebase hardening pass: two Debian `-unsigned` kernel UX bugs, `deduction_total` None sentinel, `TranslationFunc` type alias across all check signatures, shlex-based shell operator detection, and profile fallback visibility. No new features. 4274/4274 tests (+12).

### Bug fixes — Debian kernel UX (`bob/checks/kernel_modules.py`)

**Fix 1 — `kernels_up_to_date` names running kernel, not -unsigned sibling** — When running `6.12.74+deb13+1-amd64` with its `-unsigned` sibling also installed as the most recently sorted kernel, the "kernel up to date" message displayed the `-unsigned` variant's name instead of the running kernel's name. Root cause: `version=most_recent` was passed to the i18n key instead of `version=running`. Fixed: `version=running`. New test: `test_up_to_date_names_running_kernel_not_unsigned_sibling`.

**Fix 2 — Correct message template for unsigned pair** — When the running kernel and the most recently sorted kernel form a signed/unsigned pair, the cleanup message should use `kernels_obsolete_same` (no "running / latest" pair in text) rather than `kernels_obsolete`. The comparison `running == most_recent` was literal, returning `False` for the pair. Fixed: `_strip_unsigned(running) == _strip_unsigned(most_recent)`. New test: `test_debian_signed_unsigned_pair_uses_obsolete_same_message`.

### Regression fix — `deduction_total` sentinel (`bob/compare.py`)

**Fix 3 — False "+N pt(s)" on first run after upgrade** — v0.2.3 added `deduction_total: int = 0` to `AuditBaseline`. Pre-v0.2.3 baselines lack the field; `raw.get("deduction_total", 0)` returned `0`, then `deduction_delta = curr − 0` displayed "Déductions variables +N pt(s)" on the very next audit even though nothing had changed. Fixed: `int | None = None` (mirrors the existing `finding_keys` sentinel). `load_baseline()` returns `None` when the field is absent; `compute_delta()` skips delta computation when either side is `None`. +10 new tests in `TestDisplayDelta` and `TestDeductionTracking`.

### Code quality — codebase audit pass

**Type hygiene — `TranslationFunc` alias** (`bob/checks/_run.py`, 40 check files, `bob/history.py`, `bob/plugin_checks.py`) — `TranslationFunc = Callable[..., str]` defined in `_run.py` (already imported by all checks). All 42 `check_*` function signatures updated: `t=None` → `t: TranslationFunc | None = None`.

**Shell safety — `_has_shell_ops()` via `shlex`** (`bob/fixes.py`) — Shell operator detection replaced naive substring matching (`any(op in cmd for op in _SHELL_OPS)`) with tokenization via `shlex.split()`. The old method would falsely match `>` inside argument values or file paths. `_has_shell_ops()` checks tokens against a frozenset, treating only standalone tokens as operators. Malformed quoting safely returns `True` (treat as shell).

**UX — profile fallback now visible** (`bob/__main__.py`, locales) — When `--profile=X` was given but profile X did not exist, `load_profile()` silently fell back to `server`. Users had no indication the requested profile was not found. Fixed: `output.print_warn(t("audit.profile_not_found", …))` added when the loaded profile name differs from the requested one. New i18n keys `audit.profile_not_found` in EN and FR.

### Tests

4274/4274 (+12 new):

| File | Change |
|------|--------|
| `tests/test_kernel_modules.py` | +2: `test_up_to_date_names_running_kernel_not_unsigned_sibling` · `test_debian_signed_unsigned_pair_uses_obsolete_same_message` |
| `tests/test_compare.py` | +10: 4 in `TestDisplayDelta` (variable deduction show/suppress cases) · 6 in new `TestDeductionTracking` (None sentinel, load/save, delta computation) |

---

## [v0.2.3] — 2026-05-03

Eight fixes identified during a multi-VM audit round (Linux Mint, Debian 13, Kali, Ubuntu 26.04). Three behavioural bug fixes, two infrastructure fixes, three UX precision fixes. 4262/4262 tests (+1).

### Bug fixes — multi-VM audit (`bob/checks/services.py`, `bob/checks/logs.py`, `bob/display.py`)

**Fix 1 — NOT_LISTENING always INFO** — Ports in the service registry but not actively listening (e.g. Mosquitto 8883 when only 1883 is bound) were shown as `⚠ [ATTENTION]` for HIGH/CRITICAL services, appearing in the summary box. Fixed: `NOT_LISTENING` now always emits `result.info()` regardless of service severity. Tests renamed: `test_not_listening_critical_adds_info`, `test_not_listening_high_adds_info`.

**Fix 2 — IoT local dominance: deduction removed** — When a single private IP dominated UFW block logs (typical of IoT devices), the tool emitted `result.warn(nature="improvement")` and deducted 1 point. Benign traffic from a known private source should not reduce the security score. Fixed: demoted to `result.info()` with no deduction. Tests: `test_finding_is_info_level`, `test_no_score_deduction`.

**Fix 3 — Heredoc commands no longer mangled** — Multi-line commands (heredoc blocks in `auditd` remediation steps) were passed to `_wrap_for_box()` via `text.split()`, which stripped all newlines. Fixed: `_add_finding_lines()` now iterates `item.cmd.splitlines()` and calls `_wrap_for_box()` per line, preserving the heredoc structure visually.

### Infrastructure

**`bob/completion.py` — circular symlink guard** — `--install-completion` created a circular symlink (`~/.local/bin/bob → itself`) when pipx was installed system-wide and the user path was already a link into the system path. Fixed: `candidate.resolve() != dst_bin.resolve()` guard added. `exists()` already returns `False` for broken symlinks; the resolve check prevents the circular case.

**Python 3.9 dropped** (`pyproject.toml`, `.github/workflows/tests.yml`, `.github/workflows/publish.yml`) — Python 3.9 reached EOL in October 2025. `requires-python` bumped to `">=3.10"`. Classifier and CI matrix entries removed.

### UX precision fixes — cross-distro testing

**Compare: variable deduction delta** (`bob/compare.py`) — When a score changed between audits without new/resolved finding keys (e.g. log activity varying between runs), the CHANGEMENTS section showed only "Score dégradé de N point(s)" with no further context. Added `deduction_total: int` to `AuditBaseline` and `deduction_delta: int` to `AuditDelta`. When `deduction_delta != 0` and no structural changes (alert/warn count, finding keys) explain the score move, displays "Déductions variables ±N pt(s) (logs, trafic réseau)". Old baselines (field absent) default to `deduction_total=0` and produce no false delta. Found on: Debian 13 VM, Kali VM.

**Exposure: SSH state label split** (`bob/exposure.py`) — The attack-surface table used a single i18n key (`ssh_not_running` = "non installé / non démarré") for both "SSH not installed" and "SSH installed but stopped". When SSH was installed but inactive (e.g. Kali), the label was factually incorrect. Split into `ssh_not_installed` ("non installé") and `ssh_stopped` ("installé — non démarré"), used by the respective code branches. New test: `test_not_active_shows_stopped_text`. Found on: Kali VM.

**Services: `active_disabled` message now includes service label** (`bob/checks/services.py`) — "Le service est actif en ce moment, mais ne redémarrera pas automatiquement." appeared in the summary box without identifying which service. The service name is clear in the full audit under the `▶ Service` section header, but is lost when the finding is promoted to the summary. Fixed: `{label}` added to the i18n string; `label=snap.label` passed at the call site. Found on: Linux Mint test VM (Redis).

### Tests

4262/4262 (+1 new, 4 renamed/updated):

| File | Change |
|------|--------|
| `tests/test_services.py` | Renamed: `test_not_listening_critical_adds_warn` → `_adds_info` · `test_not_listening_high_adds_warn` → `_adds_info` · assertions updated to `info` level |
| `tests/test_logs.py` | Renamed: `test_finding_is_warn_level` → `_info_level` · `test_score_deduction_one_point` → `test_no_score_deduction` · assertions updated |
| `tests/test_exposure.py` | Updated `test_not_installed_info_is_ok` and `test_not_installed_overrides_password_auth` to assert `ssh_not_installed` key · +1 new `test_not_active_shows_stopped_text` |

---

## [v0.2.2] — 2026-05-03

Five targeted scoring fixes, a locale fix, logging uniformity pass, test coverage for the v0.2.1 race condition fix, scoring invariant tests, equal-weight domain documentation, and a firewall orphan-rule fix. 4261/4261 tests (+23).

### Scoring fixes (`bob/scoring.py`, `bob/domain_scores.py`, `bob/checks/clamav.py`)

**Fix 1 — `ScoreCap.key` propagation** — `ScoreCap` gains `key: str = ""`. The `set_cap()`, `cap()`, `apply()`, and `finalize()` methods all propagate it. The synthetic `Deduction` emitted when a cap fires now carries `key=self._cap.key` instead of `key=""`, enabling correct domain attribution for cap-triggered deductions. Updated: `bob/checks/firewall.py` passes `key="firewall.inactive"` to `result.set_cap()`.

**Fix 2 — INFO findings no longer inflate active domain set** — `active_domains_from_engine()` now counts only WARN and ALERT findings when determining which domains are "active" for the global average. An INFO-only domain (service installed, nothing actionable) is no longer pulled into the average. `FindingLevel` imported directly from `bob.scoring`.

**Fix 3 — `clamav.db_very_outdated` 2pt → 1pt** — Deduction was 2 pts but the `clamav` tool cap is 1 pt. The excess point only affected `engine._raw_score`, creating a silent asymmetry between raw and domain scores. Lowered to 1 pt to eliminate the ghost point.

### Observability — logging uniformity (`bob/history.py`, `bob/ignore.py`, `bob/sysinfo.py`)

Bare `except … pass` replaced with `_log.debug()` in 6 locations across 3 modules. `import logging` + `_log = logging.getLogger(__name__)` added to each. Failures remain non-fatal; visible under `--debug`.

| Module | Function | Exception | Message |
|--------|----------|-----------|---------|
| `bob/history.py` | `save_score()` | `OSError` | `"Failed to save score to history: …"` |
| `bob/history.py` | `_rotate_if_needed()` | `OSError` | `"Failed to rotate history file: …"` |
| `bob/ignore.py` | `load_ignore_keys()` | `OSError` | `"Cannot read ignore file …: …"` |
| `bob/sysinfo.py` | `get_user_home()` | `KeyError` | `"SUDO_USER … not found in password database, falling back to Path.home()"` |
| `bob/sysinfo.py` | `collect_system_info()` | `OSError` | `"Cannot read /etc/os-release: …"` |
| `bob/sysinfo.py` | `detect_network_type()` ×2 | `subprocess.TimeoutExpired / FileNotFoundError / OSError` | `"ip route failed …"` / `"ip addr failed …"` |

### Scoring contract documented (`bob/scoring.py`)

`finalize()` docstring documents the required orchestrator sequence: `engine.finalize()` → `apply_domain_score_override(engine)`. `set_global_score()` marked "do not call directly". Clarifies that `engine._raw_score` is accessible for debugging.

### Fix 4 — Domain score cap not applied when global raw score is already below threshold (`bob/domain_scores.py`)

`compute_domain_scores()` computes each domain's score from the list of deductions in `engine.breakdown`. When a cap fires (e.g. `firewall.inactive` → max 3/10), `finalize()` appends a delta deduction to `breakdown` **only if** `raw_global_score > cap.maximum`. On systems with many deductions across domains, the global raw score can already be below the cap threshold — the delta is never appended, so the target domain score is not capped and the score bar shows the pre-cap value (e.g. 6/10 instead of 3/10 for firewall when UFW is inactive).

Fix: after accumulating domain deductions from the breakdown, `compute_domain_scores()` now explicitly reads `engine.cap_info` and, if its key maps to a domain, enforces the cap directly on that domain's deduction total. The fix is idempotent (if the delta was already in the breakdown, the domain score already equals the cap and the guard condition `raw_domain > cap.maximum` is false).

Found by running the tool on an Ubuntu 26.04 VM with UFW inactive and several hardening issues: the score detail showed "Score plafonné à 3 (pare-feu inactif)" but the domain bar still displayed 6/10.

### Fix 5 — Orphan-rule check misses protocol-unspecified UFW rules (`bob/checks/firewall.py`)

`_check_orphan_rules()` used `_PORT_PROTO_RE` (`\d{1,5}/(?:tcp|udp)`) to parse the "To" field of UFW rules. A rule written without explicit protocol (e.g. `57621 ALLOW IN 192.168.1.0/24`) didn't match and was silently skipped with the incorrect comment "open-any rules". UFW applies protocol-unspecified port rules to both TCP and UDP.

New constant `_PORT_BARE_RE` (`^\[\s*\d+\]\s+(\d{1,5})\s`) handles the fallback case: if neither `port/tcp` nor `port/udp` is in the listening set, the rule is flagged as an orphan. Found by running the tool on a real machine where `57621` (Spotify Connect) was flagged for `41681/tcp` but not for its sibling rule `57621`.

### Fix 6 — SSH "not running" detail duplicated the remediation command (`bob/locales/fr.json`, `bob/locales/en.json`)

`ssh.not_active_detail` was `"Activer avec : sudo systemctl enable --now ssh"` (FR) / `"Enable with: sudo systemctl enable --now ssh"` (EN). Since the `cmd` field separately displays the same command as a `→` line, the "Que faire?" block showed the command twice. Fixed: the detail now provides context (`"Le service est désactivé — activez-le si l'accès SSH est nécessaire."`) and the `cmd` line displays the command alone. Found by running the tool on Kali Linux where SSH is installed but intentionally stopped.

### Scoring invariants — new test classes (`tests/test_scoring.py`, `tests/test_domain_scores.py`)

`TestScoringInvariants` added to both files — 12 new tests covering properties that must hold regardless of input:

| Class | File | Invariants |
|-------|------|------------|
| `TestScoringInvariants` | `test_scoring.py` | Score floor = 0 · Score ceiling = MAX · Deductions monotone · Cap above score is no-op · Domain override in range |
| `TestScoringInvariants` | `test_domain_scores.py` | INFO findings don't activate domain · WARN/ALERT do · Deduction alone activates · Global avg ∈ [min, max] of active · All domain scores in [0, 10] · Global avg always in [0, 10] |

### Tests

4261/4261 (+23 new, 2 updated):

| File | Change | Coverage |
|------|--------|----------|
| `tests/test_domain_scores.py` | +6 `TestEngineLevelDomainCap` | Cap applied when few deductions · cap applied when many global deductions (delta not in breakdown) · no over-cap when already at cap · score never exceeds cap · cap doesn't bleed to other domains · all scores in range |
| `tests/test_firewall.py` | +3 `TestOrphanRules` | Bare-port rule flagged when nothing listening · not flagged when TCP listening · not flagged when UDP listening |
| `tests/test_scoring.py` | +5 `TestScoringInvariants` | Score floor/ceiling · monotone deductions · cap no-op · domain override in range |
| `tests/test_domain_scores.py` | +7 `TestScoringInvariants` | INFO/WARN/ALERT activation · deduction path · global avg bounds · domain scores in range |
| `tests/test_manage_logs.py` | +2 `TestStatFallback` | `.stat()` `OSError` in `cur_logs` loop → `(0, "?")` fallback · `.stat()` `OSError` in `extra_sections` loop → `(0, "?")` fallback |
| `tests/test_clamav.py` | renamed + updated | `test_db_very_outdated_deducts_1` (was `_deducts_2`) · `test_worst_case`: 3 pts total (was 4) |

---

## [v0.2.1] — 2026-05-02

Defensive programming hotfix — 17 targeted improvements found by dual-agent code audit. No new features, no behavior changes. 4238/4238 tests unchanged.

### Crash fix — `--manage-logs` plain-text mode (`bob/manage_logs.py`)

**Problem:** `.stat()` calls on log file paths were unguarded in the plain-text rendering loop. If a file disappeared between directory scan and display, `--manage-logs` crashed with `OSError`. The curses mode already had the correct `try/except OSError` guard; the plain-text mode did not.

**Fix:** both loops (`cur_logs` and `extra_sections`) now wrap `.stat()` in `try/except OSError` with fallback values `(size_kb=0, mtime="?")`, matching the curses implementation.

### Exception handling narrowed (8 locations)

All `except Exception` handlers replaced with the specific exceptions that can actually be raised:

| File | Function | Before | After |
|------|----------|--------|-------|
| `bob/cis_refs.py` | `_load()` | `Exception` | `(OSError, json.JSONDecodeError)` |
| `bob/manage_logs.py` | `_get_extra_dirs()` | `Exception` | `(json.JSONDecodeError, ValueError, TypeError)` |
| `bob/manage_logs.py` | curses fallback | `Exception` | `(curses.error, OSError)` |
| `bob/explain.py` | curses fallback | `Exception` | `(curses.error, OSError)` |
| `bob/cron.py` | `run_install_cron()` | `Exception` | `(_curses.error, OSError)` |
| `bob/cron.py` | `run_manage_cron()` | `Exception` | `(_curses.error, OSError)` |
| `bob/checks/ssh.py` | `_rsa_bits_from_blob()` | `Exception` | `(struct.error, ValueError)` |
| `bob/checks/ssh.py` | `_has_passphrase()` | `Exception` | `(binascii.Error, ValueError)` |

### Regex patterns moved to module level (3 files)

Patterns that were re-compiled on every function call are now module-level constants:

| File | Constants |
|------|-----------|
| `bob/checks/firewall.py` | `_OPEN_ANY_RE`, `_ALLOW_IN_RE`, `_PORT_PROTO_RE` |
| `bob/checks/cron_audit.py` | `_PATH_RE` |
| `bob/checks/firmware.py` | `_FLAT_SKIP_RE` |

### Code quality (3 fixes)

- **Email regex deduplicated** (`bob/cron.py`) — `_EMAIL_RE` was defined identically inside 3 local functions; now a single module-level constant.
- **`_resolve_path()` helper extracted** (`bob/manage_logs.py`) — `Path(raw).expanduser().resolve() if raw else default` was duplicated at two call sites.
- **Direct attribute access in `domain_scores.py`** — `getattr(engine, "findings", [])` / `getattr(deduction, "key", None)` etc. replaced with direct access. `ScoreEngine` always initializes these attributes.

### Observability (2 fixes)

- **`recurrence.py`** — `except … pass` replaced with `_log.debug()` so load failures are visible under `--debug`.
- **`__main__.py`** — webhook failures now emit `_log.warning()` in addition to the stderr print.

### Tests

4238/4238 (unchanged — no new tests; no behavior changes introduced)

---

## [v0.2.0] — 2026-05-01

Five improvements: scoring refactoring, cron MTA detection, kernel false positive fix, IoT log dominance fix, and orange ASCII banner.

### Scoring refactoring (`bob/scoring.py`, `bob/domain_scores.py`)

**Problem:** the global score was the raw sum of all deductions from 10. Eight minor hardening issues on an otherwise well-configured machine (SSH 10/10, firewall 10/10, updates 10/10) could produce 2/10 CRITICAL — a score that did not reflect the real security posture.

Two targeted fixes:

- **Tool caps** — `rootkit`, `clamav`, and `file_integrity` each contribute at most 1 deduction point to their domain, regardless of how many individual findings exist. Eliminates the double-penalty pattern "stale rkhunter database + no recorded scan = −2".
- **Global score = mean of active domain scores** — the global score is now the rounded average of all domain scores that have at least one finding (domains with no installed service excluded). A degraded Hardening domain no longer collapses the global score when SSH, firewall, and updates are all 10/10.

**Effect on the Debian 13 reference case:** 8 deductions → was 2/10 CRITICAL, now reflects the real range of 6–9/10 depending on active domains.

New API: `ScoreEngine.set_global_score()`, `compute_global_from_domains()`, `apply_domain_score_override()`.

### Cron MTA detection (`bob/cron.py`)

**Problem:** the cron setup wizard warned `'mail' not available — install mailutils` when `mail` was missing, but actual delivery uses `sendmail`, not `mail`. The advice was incorrect and incomplete.

New helper `_detect_mta()`:
- Checks for `sendmail` (the binary actually used for delivery)
- Identifies the provider: Postfix, Exim, msmtp, ssmtp
- Displays `✔ Mail transport: Postfix` when available
- Displays clear install instructions when absent: `sudo apt install postfix` (local MTA) or `sudo apt install msmtp-mta` (relay via Gmail/SMTP)

### Kernel `-unsigned` false positive fix (`bob/checks/kernel_modules.py`)

**Problem:** on Debian with Secure Boot enabled, `linux-image-X-amd64` (signed) and `linux-image-X-amd64-unsigned` are both installed. The system boots the signed kernel correctly, but BOB flagged `-unsigned` as "newer installed" and warned "reboot required".

New helper `_strip_unsigned()`: the `-unsigned` suffix is stripped before version comparison. Running the signed kernel while only the unsigned variant of the same version is also installed no longer triggers the warning.

### IoT log dominance: WARN −1 pt (`bob/checks/logs.py`)

**Problem:** when a single private IP accounted for ≥ 70 % of blocked UFW traffic (≥ 50 entries), BOB emitted an INFO finding with no score deduction. The feature was documented as WARN −1 pt but the implementation used `result.info()` without calling `add_deduction()`.

**Fix:** `result.info()` replaced by `result.warn()` + `result.add_deduction(points=1, key="logs.local_dominance")`. New locale key `deduction.local_dominance` added in `en.json` and `fr.json`. Three existing tests in `tests/test_logs.py` corrected to assert WARN level and a 1-point deduction (total unchanged).

### Orange ASCII banner (`bob/output.py`)

The `BOB` ASCII art in the terminal banner is now rendered in orange bold (`\033[1;38;5;208m`). Border characters remain blue.

### Tests

4238/4238 (3 tests corrected in `tests/test_logs.py` — IoT dominance: INFO→WARN + deduction assertion; total unchanged)

| File | New tests | Coverage |
|------|-----------|----------|
| `tests/test_kernel_modules.py` | +6 | `_strip_unsigned` helper · Debian signed/unsigned variants · genuine reboot still detected |
| `tests/test_cron.py` | +6 | `_detect_mta` — no sendmail, Postfix, Exim, msmtp, ssmtp, unknown |
| `tests/test_scoring.py` | +6 | `set_global_score` — override, clamp, level, raw score unchanged |
| `tests/test_domain_scores.py` | +14 | Tool caps (rootkit/clamav/file_integrity) · `compute_global_from_domains` · `apply_domain_score_override` · Debian 13 scenario |
| `tests/test_logs.py` | 0 (+3 corrected) | IoT dominance: WARN level · 1 pt deduction · below threshold unchanged |

---

## [v0.1.1] — 2026-04-29

Three targeted fixes found during first runs on Ubuntu 26.04 LTS and Debian 13.

### Fixes

- **fwupd tree-format parser** (`bob/checks/firmware.py`) — fwupd 1.9+ (Ubuntu 26.04+) changed its output format to a tree structure using `├─`, `└─`, `│` drawing characters. The previous parser captured these as device names, producing garbled output like `│, ├─UEFI CA: (+7)`. Device names are now correctly extracted from `├─`/`└─` lines only.
- **`--install-completion` error message** (`bob/__main__.py`) — users who ran `sudo bob --install-completion` saw `sudo: 'bob': command not found` because sudo uses a restricted PATH that excludes pipx binaries. The error message now explicitly warns that `sudo bob` will not work and instructs to copy-paste the exact full-path command shown.
- **Services panorama column header** (`bob/locales/en.json`, `bob/locales/fr.json`) — renamed `UFW` → `SCOPE` (EN) / `PORTÉE` (FR). The column reflects whether a service has internet exposure, not whether an active UFW rule exists — the previous label created a false impression.

### Tests

4206/4206 (+4 regression tests for fwupd tree-format parser in `tests/test_firmware.py`)

---

## [v0.1.0] — 2026-04-26

Initial release of **BOB — Bodyguard Of Bits**.

Linux hardening auditor with CIS benchmark mapping. Runs as root, requires no agent or daemon.

### Security checks

46 checks across 9 domains:

- **Firewall** — UFW rules audit, iptables/nftables audit (when UFW inactive), IPv6 consistency, firewall stack analysis, port exposure analysis
- **SSH** — 12+ configuration parameters (PermitRootLogin, PasswordAuthentication, key strength, etc.)
- **Kernel hardening** — 20+ sysctl parameters; kernel module audit; Secure Boot; firmware/microcode
- **Services** — 32 known services with risk classification; service state audit; Docker firewall bypass detection
- **File permissions** — SUID/SGID audit; sensitive files; sudoers
- **User accounts** — expired accounts; password policy; login.defs; PAM
- **System** — apt security updates; unattended-upgrades; UFW logging level; log rotation; auth.log analysis; NTP sync; Fail2ban; rootkit scan; auditd; file integrity (AIDE/Tripwire); ClamAV; AppArmor/SELinux; backup; disk health (SMART); memory/swap; TLS/SSL cert expiry; systemd timers; desktop apps; Samba; cron jobs; DDNS
- **Network** — public IP context; network type detection (server/LAN/VPN); GeoIP optional
- **Docker** — daemon configuration; privileged containers; host mounts

### CIS benchmark mapping

133 entries: 99 CIS Ubuntu 22.04 · 4 CIS Docker · 34 best-practice.
Each finding with a formal CIS code displays `[CIS:X.Y.Z]` inline. Full reference shown in `--verbose`.
`--explain KEY` shows WHY the finding matters, HOW to fix it, and its CIS reference.

### Output formats

Terminal (colored) · JSON · CSV · Markdown · HTML

### Audit profiles

`server` · `workstation` · `desktop` · `docker` — tune severity and skip irrelevant checks per environment.

### Automation

- **Cron** — `--install-cron` wizard; `--manage-cron` TUI; named jobs in `/etc/cron.d/bob-{name}`
- **Webhooks** — generic JSON + Slack (auto-detected by URL)
- **Score history** — sparkline trend across runs (`--history`)
- **Domain scores** — per-domain 0–10 scores (firewall · SSH · hardening · updates · file_perms)
- **Diff mode** — `--diff` shows only changes since last baseline
- **Watch mode** — `--watch[=N]` reruns every N seconds

### CLI highlights

```
sudo bob [OPTIONS]
bob --explain [KEY]   # no sudo required
```

Key options: `--verbose` · `-d` (French) · `--offline` · `--fix` · `--apply` · `--check=LIST` · `--skip=LIST`
`--output-dir` · `--format` · `--target N` · `--min-level LEVEL`

Bash completion: `sudo bob --install-completion`

### i18n

English and French (`--french` / `-d`).

### Install

```
pipx install bodyguard-of-bits
sudo bob
```

---

© 2026 Cédric Clauzel
