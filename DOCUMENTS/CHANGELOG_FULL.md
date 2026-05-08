*[Lire en français](CHANGELOG_FULL_FR.md)* · *[TL;DR](../CHANGELOG.md)*

# BOB — Bodyguard Of Bits — Changelog

All notable changes to this project are documented here.

---

## [v0.3.3] — 2026-05-07

Pure internal refactoring — no new features, no behaviour changes. Four cleanup tasks driven by a code-review pass: `cron.py` split, `compute_domain_scores()` pure return, `domain_scores` public API, and `cron_ui.py` curses helpers. 4348/4348 tests (+1).

---

### Refactoring — `cron.py` split

**Files:** `bob/cron.py`, `bob/cron_ui.py` (new)

#### Problem

`bob/cron.py` had grown to 2 181 lines combining heterogeneous concerns: data types, parsers, cron-logic, plain-text interactive flows, and an entire curses TUI. The curses code imported `curses` at module level, so any test that imported `cron` without a TTY triggered a `_curses.error` on import. The install and manage flows each contained an independent 40-line bash-script generation block — identical logic copy-pasted.

#### Implementation

**Split**

`bob/cron.py` retains all data types, parsers, domain logic, and plain-text interactive flows. `bob/cron_ui.py` (new, 955L) holds all curses TUI code. The dispatchers `run_install_cron()` / `run_manage_cron()` use a lazy-import pattern:

```python
if sys.stdout.isatty():
    try:
        import curses
        curses.wrapper(_run_install_cron_curses)
    except curses.error:
        _run_install_cron_plain(...)
else:
    _run_install_cron_plain(...)
```

The `import curses as _c` inside `cron_ui.py` functions is intentional: moving it to module level would break test imports that run without a terminal.

**`build_script_content(notify_email, log_dir) -> str`**

Pure function extracted from both install flows into `cron.py`, eliminating a 40-line duplication. Returns the full bash script string. Called from both `_run_install_cron_plain()` and `_run_install_cron_curses()`.

---

### Refactoring — `compute_domain_scores()` pure return

**Files:** `bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`

#### Problem

`compute_domain_scores()` communicated which deductions were capped by setting `deduction.was_capped = True` as a side-effect on live `Deduction` objects. This was non-idempotent (fixed in v0.3.2 by resetting at the top), but the root cause remained: a function mutating its inputs to pass information to callers. `breakdown.py` iterated `engine.breakdown` and checked `was_capped` to annotate the breakdown table.

#### Implementation

`Deduction.was_capped: bool` field removed from the dataclass.

`compute_domain_scores()` now returns `tuple[dict[str, dict], frozenset[int]]` — the second element is the set of indices in `engine.breakdown` that were reduced by a domain cap. The function computes this frozenset purely from the comparison `effective < raw` without touching any object.

`ScoreEngine.set_domain_scores()` gains a `capped_indices: frozenset[int]` parameter, stored as `_capped_indices`. New `capped_indices` property exposes it. `breakdown.py` reads `engine.capped_indices` instead of inspecting `was_capped` on each deduction.

#### Design decisions

- **`frozenset[int]` not `set[Deduction]`**: indices are stable within a single `compute_domain_scores()` call; the frozenset is immutable and safe to cache. References to `Deduction` objects would create an implicit dependency on object identity.
- **Returning the frozenset rather than storing it inside `compute_domain_scores()`**: the function now has no side-effects, which makes it trivially testable with a direct `return_value` assertion.

---

### Refactoring — `domain_scores.py` public API

**Files:** `bob/domain_scores.py`, `bob/breakdown.py`, `bob/explain.py`, `tests/test_domain_scores.py`

#### Problem

Three module-level names — `_LABELS`, `_TOOL_CAPS`, `_key_to_domain` — were effectively public: used directly by `breakdown.py` and `explain.py`. The leading underscore implied they were private internals, but external callers depended on them. This was a false signal: any caller seeing `from bob.domain_scores import _LABELS` had to know they were importing a private name.

#### Implementation

Simple rename: `_LABELS → LABELS`, `_TOOL_CAPS → TOOL_CAPS`, `_key_to_domain → key_to_domain`. All callers updated (`breakdown.py`, `explain.py`, `tests/test_domain_scores.py`). No logic changed.

---

### Refactoring — `cron_ui.py` curses helpers

**Files:** `bob/cron_ui.py`

#### Problem

`cron_ui.py` had three categories of structural duplication:

1. **Script generation**: 40-line bash script duplicated between plain-text and curses install flows (covered above by `build_script_content`).
2. **Safe `addstr`**: every screen-write was wrapped in `try: stdscr.addstr(...) except _c.error: pass` — 30+ identical 3-line blocks.
3. **Keypress reading**: every interactive loop contained `try: ch = stdscr.get_wch() / except _c.error: continue` followed by `isinstance(ch, int)` / `isinstance(ch, str)` normalisation — 9 separate duplications.
4. **Magic schedule indices**: `if choice == 2 / 3 / 4` scattered across `_curses_schedule_wizard` with no explanation of what 2, 3, 4 meant.
5. **`_FakeEntry` stub**: a bare `class _FakeEntry: pass` with `entry.name = raw_name` attribute set at runtime — untyped, undocumented.

#### Implementation

**`_WizardEntry(name, hour=3, minute=0)` NamedTuple**

Replaces `_FakeEntry`. Created at `STEP_SCHEDULE` with `_WizardEntry(raw_name)`, passed to `_curses_schedule_wizard`. Typed, documented, immutable.

**`_draw(stdscr, row, col, text, attr=0) -> None`**

```python
def _draw(stdscr, row: int, col: int, text: str, attr: int = 0) -> None:
    try:
        stdscr.addstr(row, col, text, attr)
    except Exception:
        pass
```

Absorbs all 30+ `try/except curses.error` blocks. Uses `except Exception` (not `except _c.error`) because `curses` is not imported at module level — `_c` is a local alias inside each function.

**`_read_key(stdscr) -> int`**

```python
def _read_key(stdscr) -> int:
    try:
        ch = stdscr.get_wch()
    except Exception:
        return -1
    if isinstance(ch, int):
        return ch
    if isinstance(ch, str) and len(ch) == 1:
        return ord(ch)
    return -1
```

Returns -1 on error or unrecognised input. Callers that previously `continue`d on error now fall through all `if/elif` chains without matching — same loop-restart behaviour. The single edge case where `-1` could be mistakenly matched (`_run_manage_cron_curses` confirm-delete) was audited: the `if key in (ord("y"), ord("Y"))` guard means `-1` simply cancels, which is the documented "any key: cancel" behaviour.

**`_SCHEDULE_DAILY/WEEKDAYS/MONTHDAYS/CUSTOM = 1, 2, 3, 4`**

Named constants replace magic indices in `_curses_schedule_wizard`.

#### Net result

1 104L → 955L (−149 lines, −13 %).

---

### Tests

4 348 / 4 348 (+1 from v0.3.2).

`TestWasCapped` (checked the `was_capped` flag) replaced by `TestCappedIndices` (7 tests) covering the frozenset return contract of `compute_domain_scores()`: empty set when no cap is hit, correct indices when caps fire, immutability of the returned frozenset.

---

## [v0.3.2] — 2026-05-06

User-configurable SUID whitelist: patterns declared in `~/.config/bob/config.conf` suppress known-legitimate binaries from the "unexpected SUID" warning. Plus 14 code-review fixes covering i18n, quiet-mode bypass, engine idempotency, and dead-code removal. 4347/4347 tests (+19).

---

### Feature — `suid_whitelist` in `config.conf`

**Files:** `bob/config.py`, `bob/checks/suid_audit.py`, `bob/runner.py`, locales

#### Problem

On Kali Linux and other security-focused distributions, legitimate tools ship with the SUID bit set (Kismet ships 15+ `kismet_cap_*` capture helpers, all root-owned SUID). These appear as "unexpected" SUID binaries in BOB's report — generating 15 noisy warnings per run. A global hard-coded whitelist would be incorrect: those binaries have no business on a production server. Per-user configuration is the only clean solution.

#### Implementation

**`bob/config.py` — `UserConfig.get_suid_whitelist() -> list[str]`**

New helper that reads the `suid_whitelist` key from `~/.config/bob/config.conf`, splits on commas, and returns a list of stripped glob pattern strings. Returns `[]` when the key is absent or empty. Follows the existing `get_profile()` / `get_webhook_url()` helper pattern.

```
# ~/.config/bob/config.conf
suid_whitelist = kismet_cap_*, my_enterprise_tool
```

**`bob/checks/suid_audit.py` — `SuidSnapshot`**

- `SuidSnapshot` gains a new field `whitelisted_suid: list[str]` (default `[]`), storing paths suppressed by user patterns.
- `SuidSnapshot.from_system()` gains a `user_whitelist: list[str] | None = None` parameter.
- After filtering against `_KNOWN_SUID`, a second pass applies `fnmatch.fnmatch(basename, pattern)` for each user pattern. Matching paths move from `unexpected_suid` to `whitelisted_suid`.
- `check_suid_audit()` emits `suid_audit.whitelisted` (INFO) when `snapshot.whitelisted_suid` is non-empty, with count and paths. This is intentionally visible — the user should see that suppression happened.

**`bob/runner.py`**

`SuidSnapshot.from_system(user_whitelist=user_config.get_suid_whitelist())` — whitelist is loaded from `user_config` (already in scope) and passed at call time.

#### Design decisions

- **Glob on basename only**: matching on full path would let patterns like `*/opt/*` suppress everything under `/opt`. Basename matching is predictable and safe.
- **INFO, not invisible**: whitelisted paths are reported as INFO rather than silently dropped. If the user accidentally whitelists `*`, they'll see all their SUID binaries listed as "suppressed by whitelist" and know something is wrong.
- **Comma-separated patterns**: consistent with how the existing `_KNOWN_SUID` whitelist works conceptually, and trivially editable in a plain text file.

---

### Fixes — code review pass (14 items)

A systematic review of the codebase identified and fixed the following issues:

**BUG-2 — `compute_domain_scores()` non-idempotent (`domain_scores.py`)**
The function mutated `deduction.was_capped = True` on live `Deduction` objects. A second call would flip additional flags spuriously. Fix: reset all `was_capped = False` at the start of `compute_domain_scores()` before recomputing.

**BUG-3 — `samba` and `desktop_apps` invisible to `--check`/`--skip` (`runner.py`)**
Both sections were gated by `_section_enabled()` but absent from `_ALL_SECTIONS`. `--list-checks` never showed them; `--check samba` was a silent no-op. Fix: both names added to `_ALL_SECTIONS`.

**BUG-4 — Quiet mode bypassed by all status lines (`output.py`)**
`_print_status()` and `print_risk_context()` used bare `print()` instead of the `_p()` wrapper that checks `_quiet`. Every `print_warn` / `print_alert` / `print_ok` / `print_info` call reached stdout even in `--quiet` mode. Fix: replaced all `print()` calls with `_p()` in both functions.

**BUG-1 — French labels hardcoded in `output.py`**
`print_warn()` emitted `[ATTENTION]` and `print_alert()` emitted `[ALERTE]` unconditionally, even on English installs. The i18n keys `status.warn = "WARNING"` and `status.alert = "ALERT"` existed in `locales/en.json` but were never called. Fix: both functions now call `t("status.warn")` / `t("status.alert")` via a local import of `bob.i18n`.

**BUG-5 — `result._log_data` dynamic attribute on a dataclass (`scoring.py`, `checks/logs.py`, `display.py`)**
`check_logs()` set an undeclared `result._log_data` attribute with `# type: ignore`. If an early-return path was hit, `display_log_results()` silently showed nothing. Fix: `CheckResult` gains a proper `log_data: dict | None = field(default=None)` field; `logs.py` and `display.py` updated accordingly.

**BUG-6 — Bruteforce deductions missing `key=` (`checks/logs.py`)**
`result.warn()` and `result.add_deduction()` in the bruteforce loop had no `key=`, making them invisible to `--ignore` and profiles. Fix: `key="logs.brute_found"` added to both calls.

**SF-1 — `sshd_config` parse silently truncated at `Match` blocks (`checks/ssh.py`)**
When a `Match` block appeared in `sshd_config`, subsequent global directives were silently discarded. The check could report a false OK for options defined after the block. Fix: `_parse_config_file()` sets `config["_match_block"] = True`; `_check_sshd_config()` emits `ssh.match_block_skipped` (INFO) to warn the user.

**SF-2 — `curr_baseline` potentially unbound (`__main__.py`)**
`curr_baseline` was assigned inside a `with redirect_stdout(...)` block. In a future refactor that breaks the `diff_mode` coupling, an `UnboundLocalError` would occur at runtime. Fix: `curr_baseline = None` initialised before the block.

**SEC-1 — `fixes.py` ignores `--no-color` (`fixes.py`)**
All `\033[...]` escape literals in `fixes.py` bypassed the `--no-color` flag and the `output._c` infrastructure. Piping fix output to a file produced raw escape sequences. Fix: all literals replaced with `output._c.*` attributes.

**BP-2 — External module wrote to `_private` engine attributes (`scoring.py`, `domain_scores.py`)**
`apply_domain_score_override()` directly set `engine._domain_scores` and `engine._active_domains`, coupling `domain_scores.py` to `ScoreEngine` internals. Fix: `ScoreEngine.set_domain_scores(scores, active)` public method added; `domain_scores.py` calls it instead.

**BP-3 — String comparison against enum value (`checks/ssh.py`)**
`f.level.value in ("warn", "alert", "info")` would silently break if any `FindingLevel` member was renamed. Fix: `f.level != FindingLevel.OK`.

**BP-1 — `open(os.devnull)` without `encoding=` (`__main__.py`)**
Text-mode file open without explicit encoding relies on locale default. Fix: `encoding="utf-8"` added.

**INC-2 — `snapshot.from_system()` ran before `_section_enabled()` check (`runner.py`)**
`SambaSnapshot.from_system()` and `DesktopAppsSnapshot.from_system()` (which run `dpkg`/subprocess queries) were called unconditionally, even when the section was skipped via `--skip`. Fix: `from_system()` calls moved inside the `_section_enabled()` guard.

**DC-1 — `_is_root_owned()` dead code (`checks/suid_audit.py`)**
Private helper never called in production code; inline logic at line 165 already performed the same check. Fix: function deleted; its two unit tests removed.

---

## [v0.3.1] — 2026-05-06

Two targeted bug fixes found during multi-VM validation, plus two architectural refactors in the score breakdown pipeline. No new features. 4328/4328 tests (+6).

---

### Fix 1 — `__version__` banner stuck at `0.2.4` (`bob/__init__.py`)

#### Problem

After the v0.3.0 release, `bob/__init__.py` still declared `__version__ = "0.2.4"`. The ASCII banner printed by `print_banner()` and the `bob -V` / `bob --version` output both read the version from this module attribute, so all platforms showed `BOB v0.2.4` instead of `BOB v0.3.0`. Found immediately on the first post-v0.3.0 VM audit.

#### Fix

`__version__ = "0.2.4"` → `"0.3.1"`. No other code changes — the version string is the single source of truth for the banner, the version flag, and the JSON output `meta.version` field.

---

### Fix 2 — DDNS network context not propagated to score header (`bob/runner.py`, `bob/__main__.py`)

#### Problem

`run_checks()` calls `ddns_effective_context()` internally to upgrade `network_context` from `"local"` to `"ddns"` when an active DDNS client is detected alongside open unrestricted ports. The function returned correctly, but `ChecksResult` — the NamedTuple returned by `run_checks()` — did not include a `network_context` field. `__main__.py` therefore always used its initial value (`"local"`) for the score summary header and exposure display, regardless of what the DDNS check found.

The effect: machines running ddclient/inadyn/No-IP/DuckDNS with open ports showed "Local network only" in the score header instead of "Public exposure via DDNS". The score computation itself was correct (the exposure penalty is applied inside `run_checks()` before the context value matters for display), so only the header label was wrong.

Found during Kali VM validation with an active DDNS client.

#### Fix

`network_context: str = "local"` added as the last field of `ChecksResult`. The `return ChecksResult(...)` statement in `run_checks()` now includes `network_context=network_context`. In `__main__.py`, `network_context = result.network_context` is assigned immediately after `result = run_checks(...)`, replacing the stale local variable.

---

### Refactor 1 — `was_capped: bool` on `Deduction` (`bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`)

#### Problem

`bob/breakdown.py` declares at its module docstring: *"Nothing is computed here — all data comes from the already-finalized engine."* However, the tool-cap summary section re-implemented the cap accounting from scratch, maintaining a local `tool_contributed` dict and iterating the breakdown twice to identify capped entries. This duplicated the logic in `compute_domain_scores()` and was a latent source of divergence.

#### Fix

`Deduction` (in `bob/scoring.py`) gains `was_capped: bool = False`. `compute_domain_scores()` (in `bob/domain_scores.py`) sets `deduction.was_capped = True` in two places:

- When `allowed <= 0` (fully absorbed — the deduction contributes nothing to its domain).
- When `allowed < points` (partially absorbed — only part of the deduction is counted).

`breakdown.py` reads `d.was_capped` directly in the deduction table loop (for the `[capped]` annotation) and uses a set comprehension over `d.was_capped` to build the `capped_prefixes` set for the tool-cap summary. The local `tool_contributed` and `capped_entries` tracking is removed entirely.

---

### Refactor 2 — `engine.domain_scores` / `engine.active_domains` cached properties (`bob/scoring.py`, `bob/domain_scores.py`, `bob/__main__.py`, `bob/breakdown.py`)

#### Problem

After `apply_domain_score_override()`, the per-domain scores and active domain set are stable — they will not change. Yet `__main__.py` and `breakdown.py` each imported and called `compute_domain_scores()` and `active_domains_from_engine()` separately, meaning the computation ran twice per audit. Any future divergence between the two call sites would produce inconsistent display.

#### Fix

`ScoreEngine.__init__()` initializes two private caches: `_domain_scores: dict | None = None` and `_active_domains: frozenset | None = None`. `apply_domain_score_override()` assigns to them after computing:

```python
engine._domain_scores  = scores
engine._active_domains = active
```

Two `@property` methods expose them:

```python
@property
def domain_scores(self) -> dict:
    return self._domain_scores or {}

@property
def active_domains(self) -> frozenset:
    return self._active_domains or frozenset()
```

`__main__.py` and `breakdown.py` both switch to `engine.domain_scores` and `engine.active_domains`. The direct imports of `compute_domain_scores` and `active_domains_from_engine` are removed from `__main__.py`.

---

### Tests

4328/4328 (+6 new):

| File | Class | Test | Coverage |
|------|-------|------|----------|
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_uncapped_deduction_not_marked` | Deduction within cap → `was_capped` stays `False` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_fully_absorbed_deduction_marked` | Deduction after cap exhausted → `was_capped = True` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_partially_absorbed_deduction_marked` | Deduction exceeds remaining cap → `was_capped = True` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_non_tool_cap_key_never_marked` | Key with no tool cap prefix → `was_capped` always `False` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_cached_domain_scores_on_engine` | After override, `engine.domain_scores` matches `compute_domain_scores()` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_engine_domain_scores_empty_before_override` | Before override, `engine.domain_scores` returns `{}` |

---

## [v0.3.0] — 2026-05-06

Scoring transparency milestone. New `--breakdown` (`-B`) flag shows the complete score computation path after an audit. `--explain <key>` gains a SCORING section. Three targeted fixes: kernel `-unsigned` asymmetry in retention logic, orphan `→` on stable score deltas, and "UFW-AU" ASCII art relics in the detailed report. 4322/4322 tests (+48).

---

### Feature 1 — `--breakdown` / `-B` flag (`bob/breakdown.py`, `bob/cli.py`, `bob/__main__.py`, `bob/locales/en.json`, `bob/locales/fr.json`)

#### Motivation

BOB's scoring uses a multi-layer pipeline: per-check deductions → tool caps → engine cap → domain average override. The final score was visible but its derivation was not. Users seeing a 6/10 had no way to understand which deductions contributed, whether a cap had fired, or how domain averaging changed the number.

#### Implementation

New module `bob/breakdown.py` — `display_breakdown(engine, t, output_mod)` — reads the already-finalized `ScoreEngine` and prints:

1. **Deductions** — full table (key · domain · points · context), with `[capped]` annotation for entries that were absorbed by a tool cap.
2. **Tool caps** — one `[INFO]` line per tool where total raw deductions exceeded the cap.
3. **Engine cap** — `[WARN]` line if `engine.cap_info` is set (e.g. "firewall inactive — cap at 3").
4. **Raw score** — `engine._raw_score` before domain averaging.
5. **Per-domain scores** — each active domain with score, deductions, and a 10-character bar chart.
6. **Domain-average override** — `[INFO]` line showing the computed average and number of active domains, when `engine._global_override is not None`.
7. **Final score** — color-coded: green (≥ 8), yellow (≥ 5), red (< 5).

Domain labels are translated via `_domain_label(domain_id, t)` — tries `t(f"domain_scores.{domain_id}")` first (same pattern as `render_domain_scores`), falls back to `_LABELS` then `domain_id.capitalize()`. This ensures French labels (e.g. "Durcissement") appear when running with `--french`.

**stdout management** — `breakdown_mode` is added to `_silent_mode` in `__main__.py`. The entire audit runs inside `with redirect_stdout(devnull)`, suppressing all bare `print()` calls (not just `output.*` calls, which are already suppressed by `quiet=True`). After the `with` block, stdout is restored and `display_breakdown` is called with `output` re-initialized without `quiet`. This is the same pattern used by `diff_mode` and the machine-readable formats.

#### i18n

New `breakdown.*` section in both locale files:

| Key | Purpose |
|-----|---------|
| `breakdown.section_title` | Section header |
| `breakdown.no_deductions` | OK message when no deductions |
| `breakdown.deductions_header` | "N deduction(s):" sub-header |
| `breakdown.capped` | Annotation for capped entries |
| `breakdown.tool_cap_applied` | Tool cap info line |
| `breakdown.engine_cap_applied` | Engine cap warn line |
| `breakdown.raw_score` | Raw score line |
| `breakdown.domain_scores_header` | Domain scores sub-header |
| `breakdown.domain_average` | Domain average override line |
| `breakdown.final_score` | Final score line |

#### CLI

`-B` / `--breakdown` added to `bob/cli.py` as a boolean flag. `_silent_mode` in `__main__.py` extended: `_machine_mode or config.breakdown_mode or config.diff_mode`.

---

### Feature 2 — Score-aware `--explain` (`bob/explain.py`)

#### Problem

`bob --explain <key>` showed remediation steps but gave no indication of how the key contributed to the score — which domain it belonged to, whether a tool cap limited its deductions, or how to see its live impact.

#### Fix

New `_explain_scoring(key, t)` function appended at the end of every `run_explain()` call. Reads `_key_to_domain(key)` and `_TOOL_CAPS.get(prefix)` from `bob/domain_scores.py` and prints:

```
SCORING
────────────────────────────────────────
  Domain   : Hardening
  Tool cap : max 2 pt total for 'hardening' deductions in this domain
  Impact   : run 'sudo bob --breakdown' to see this key's current score contribution
```

Keys with no domain mapping (e.g. generic info keys) silently skip the section.

---

### Fix 1 — Kernel `-unsigned` retention asymmetry (`bob/checks/kernel_modules.py`, `tests/test_kernel_modules.py`)

#### Problem

On Debian systems, both signed and unsigned kernel packages are installed side by side:

```
linux-image-6.12.74+deb13+1-amd64
linux-image-6.12.74+deb13+1-amd64-unsigned
```

`_kernel_sort_key()` produces identical numeric tuples for both (same `MAJOR.MINOR.PATCH+ABI`). When tuples are equal, Python's sort is stable, meaning the unsigned variant (appearing later in dpkg output) ends up last in the sorted list and becomes `most_recent`.

The retention loop fills slots from newest down. With three kernels installed and `keep_count=3` (server profile), the loop fills: `running`, `most_recent` (unsigned), and one earlier kernel. The signed variant of the same version as `most_recent` gets no slot and lands in `to_remove` — incorrectly marked as obsolete.

#### Fix

After the retention loop, expand the keep-set to include both variants of every kept base version:

```python
kernel_set = set(kernels)
for k in list(to_keep):
    base = _strip_unsigned(k)
    if base in kernel_set:
        to_keep.add(base)
    unsigned = f"{base}-unsigned"
    if unsigned in kernel_set:
        to_keep.add(unsigned)
```

`_strip_unsigned()` already existed in the module. This expansion is O(keep_count) and runs once after the loop.

Additionally, the obsolete detail message was changed from `recent=most_recent` to `recent=running`. The boot-verification hint ("verify the system boots correctly before removing older kernels") should reference the kernel the system is actually running, not the `-unsigned` sibling that happens to sort last.

---

### Fix 2 — Score delta orphan `→` (`bob/display.py`)

#### Problem

In `print_audit_summary()`, the score line is built as:

```python
score_str = f"{score}/10"
if prev_score is not None:
    delta = score - prev_score
    if delta > 0:
        score_str += f"  ↑ +{delta}"
    elif delta < 0:
        score_str += f"  ↓ {delta}"
    else:
        score_str += f"  →"
```

When the score was unchanged (`delta == 0`), the line displayed `6/10  →` with nothing after the arrow. The arrow was intended as a "stable" indicator but looked like a truncated line inside the box display.

#### Fix

```python
    else:
        score_str += f"  = {score}"
```

"= 6" is unambiguous: the score equals the previous value.

---

### Fix 3 — "UFW-AU" relics in detailed report (`bob/report.py`, `bob/report_markdown.py`)

#### Problem

`AuditReport.write_header()` contained hardcoded ASCII art letter arrays spelling "UFW-AU" — the acronym of the former tool name "ufw-audit". The letter group list was `[U, F, W, DASH, A, U]`. The header also printed `Firewall : ufw {version}` preceded by the label `UFW`.

In `report_markdown.py`, the firewall entry was labelled `**UFW:**`.

#### Fix

`bob/report.py` — letter groups replaced with `[B, O, B]` using the same Doom block font already used in `output.py`'s terminal banner. Header label changed to `Firewall : ufw {info.ufw_version}`.

`bob/report_markdown.py` — label changed to `**Firewall (UFW):**`.

---

### Tests

4322/4322 (+48 new):

#### `tests/test_breakdown.py` (new file, +16)

| Class | Test | Coverage |
|-------|------|----------|
| `TestBar` | `test_full_score_all_filled` | Score 10 → all filled blocks |
| `TestBar` | `test_zero_score_all_empty` | Score 0 → all empty blocks |
| `TestBar` | `test_five_half_filled` | Score 5 → half filled |
| `TestDisplayBreakdownClean` | `test_no_deductions_message` | No deductions → `no_deductions` key printed |
| `TestDisplayBreakdownClean` | `test_section_title_printed` | Section header printed |
| `TestDisplayBreakdownClean` | `test_final_score_ten_shown` | Score 10 → `breakdown.final_score` key printed |
| `TestDisplayBreakdownWithDeductions` | `test_deductions_header_shown` | Deductions present → header shown |
| `TestDisplayBreakdownWithDeductions` | `test_deduction_keys_shown` | Each deduction key appears in output |
| `TestDisplayBreakdownWithDeductions` | `test_raw_score_shown` | `breakdown.raw_score` key printed |
| `TestDisplayBreakdownWithDeductions` | `test_domain_scores_header_shown` | Active domains → header shown |
| `TestDisplayBreakdownWithDeductions` | `test_domain_average_shown` | Global override set → `breakdown.domain_average` printed |
| `TestDisplayBreakdownWithDeductions` | `test_final_score_shown` | `breakdown.final_score` key printed |
| `TestDisplayBreakdownToolCap` | `test_tool_cap_message_shown_when_exceeded` | Total deductions > cap → tool cap info line shown |
| `TestDisplayBreakdownToolCap` | `test_no_tool_cap_message_when_within_limit` | Total deductions ≤ cap → no tool cap message |
| `TestDisplayBreakdownEngineCap` | `test_engine_cap_message_shown` | `engine.cap_info` set → `breakdown.engine_cap_applied` shown |
| `TestDisplayBreakdownEngineCap` | `test_engine_cap_message_not_shown_when_absent` | No cap → no cap message |

#### `tests/test_golden_scenarios.py` (new file, +32)

| Class | Tests | Coverage |
|-------|-------|----------|
| `TestCleanMachine` | 4 | Score 10/10; no breakdown; no active domains; INFO findings excluded from domain activation |
| `TestHardenedServer` | 3 | 2 hardening deductions → score 8; domain deductions count; raw breakdown assertions |
| `TestDefaultDesktop` | 3 | 4 deductions across 3 domains → score 9; per-domain deduction exact counts |
| `TestPoorlyConfiguredServer` | 3 | Raw score 3; domain average 8; domain average improves over raw |
| `TestFirewallInactive` | 3 | Engine cap enforced at 3; domain average can exceed capped raw; `cap_info` stored |
| `TestDebian13Minimal` | 4 | Raw score 2; domain average 6; rootkit tool cap; 6 total hardening deductions after cap |
| `TestToolCapInvariants` | 4 | rootkit/clamav/file_integrity each capped at 1pt; uncapped tool (ssh) accumulates normally |
| `TestScoreStability` | 5 | Order independence; same-domain monotonicity; domain independence; score ∈ [0, MAX_SCORE]; raw floor 0 |
| `TestMultiDomainMachine` | 3 | 5 active domains exact frozenset; each domain deducted once; score 9 |

#### `tests/test_min_level.py` (updated, 0 net new)

`test_stable_shows_right_arrow` renamed to `test_stable_shows_equal`; assertion updated from `"→" in val` to `"= 7" in val`. Module docstring updated accordingly.

---

## [v0.2.4] — 2026-05-05

Post-audit codebase hardening pass triggered by a systematic review of the full codebase after the v0.2.3 multi-VM audit tour. Two Debian `-unsigned` kernel UX bugs fixed, a regression in the `deduction_total` sentinel pattern corrected, type annotations propagated to all check signatures, shell operator detection hardened, and profile fallback made visible. No new checks or behavioural changes. 4274/4274 tests (+12).

---

### Fix 1 — `kernels_up_to_date` names running kernel, not `-unsigned` sibling (`bob/checks/kernel_modules.py`, `tests/test_kernel_modules.py`)

#### Problem

On Debian systems with both a signed and an unsigned kernel package installed (e.g. `linux-image-6.12.74+deb13+1-amd64` and `linux-image-6.12.74+deb13+1-amd64-unsigned`), `_kernel_sort_key()` sorts them alphabetically after matching on the same numeric prefix. The unsigned variant sorts last and becomes `most_recent`.

In `_check_installed_kernels()`, the "kernel up to date" OK message passed `version=most_recent`:

```python
result.ok(
    message=_t("kernel_modules.kernels_up_to_date", version=most_recent),
    ...
)
```

When `running = "6.12.74+deb13+1-amd64"` and `most_recent = "6.12.74+deb13+1-amd64-unsigned"`, the displayed message named the `-unsigned` sibling rather than the kernel the system was actually booted into.

#### Fix

```python
result.ok(
    message=_t("kernel_modules.kernels_up_to_date", version=running),
    ...
)
```

The message now always names the running kernel, regardless of which variant sorts last.

---

### Fix 2 — Correct message template for signed/unsigned pair (`bob/checks/kernel_modules.py`, `tests/test_kernel_modules.py`)

#### Problem

`_check_installed_kernels()` selects between two i18n message templates:

- `kernels_obsolete_same` — used when `running == most_recent` (running is on the latest kernel; some older kernels can be cleaned up). No "running / latest" pair in the text.
- `kernels_obsolete` — used when `running != most_recent` (reboot would upgrade the running kernel). Includes both versions in the text.

The comparison was literal:

```python
if running == most_recent:
    _msg = _t("kernel_modules.kernels_obsolete_same", ...)
else:
    _msg = _t("kernel_modules.kernels_obsolete", ...)
```

On Debian with a signed/unsigned pair, `running = "6.12.74+deb13+1-amd64"` and `most_recent = "6.12.74+deb13+1-amd64-unsigned"`. They are semantically the same kernel version (same ABI, same security level), but the literal comparison returns `False`. The tool incorrectly used `kernels_obsolete`, implying the user needed to reboot to apply a newer kernel — factually wrong.

`_strip_unsigned()` already existed in the module for exactly this normalisation but was not applied in this code path.

#### Fix

```python
if _strip_unsigned(running) == _strip_unsigned(most_recent):
    _msg = _t("kernel_modules.kernels_obsolete_same", ...)
else:
    _msg = _t("kernel_modules.kernels_obsolete", ...)
```

Both sides are stripped before comparison. A signed/unsigned pair now correctly selects `kernels_obsolete_same`.

---

### Fix 3 — `deduction_total` None sentinel prevents false delta on upgrade (`bob/compare.py`, `tests/test_compare.py`)

#### Problem

v0.2.3 introduced `deduction_total: int = 0` in `AuditBaseline` and displayed a "Déductions variables ±N pt(s)" message in `display_delta()` when `deduction_delta != 0`. The default was `0`, and `load_baseline()` used:

```python
deduction_total=int(raw.get("deduction_total", 0))
```

Pre-v0.2.3 baseline JSON files do not contain the `"deduction_total"` key. The call returned `0`. On the very next audit, `deduction_delta = curr.deduction_total - 0`. Since `curr.deduction_total` is almost always positive (there are nearly always some deductions), the variable-deductions message appeared on every first run after upgrading from a pre-v0.2.3 baseline — a false positive: nothing had actually changed, the field simply didn't exist in the old baseline.

This is the exact same failure mode that was already solved for `finding_keys` with the `list[str] | None = None` sentinel.

#### Fix

```python
# AuditBaseline
deduction_total: int | None = None   # None = pre-v0.2.3 baseline (field absent)

# load_baseline()
deduction_total=int(raw["deduction_total"]) if isinstance(raw.get("deduction_total"), int) else None,

# compute_delta()
deduction_delta=(
    curr.deduction_total - prev.deduction_total
    if prev.deduction_total is not None and curr.deduction_total is not None
    else 0
),
```

`None` means "the previous audit predates the field". Delta computation is skipped for those baselines, producing `deduction_delta = 0` and suppressing the message. New baselines always write an integer; subsequent comparisons behave normally.

---

### Fix 4 — `TranslationFunc` type alias across all check signatures (`bob/checks/_run.py`, 42 files)

#### Problem

The translation function `t` was passed as a keyword argument to all `check_*` functions with the annotation `t=None` (untyped default). Type checkers could not infer the callable signature, and IDEs offered no completion for calls like `_t("key", param=value)`. There was also no single place to document what the function contract was.

#### Fix

`bob/checks/_run.py` (already imported by every check module) gains:

```python
from typing import Callable

TranslationFunc = Callable[..., str]
"""Type alias for BOB's translation function: t(key, **kwargs) -> str."""
```

All 42 `check_*` function signatures across 40 check files, `bob/history.py`, and `bob/plugin_checks.py` updated:

```python
# Before
def check_firewall(snapshot, *, t=None, ...):

# After
def check_firewall(snapshot, *, t: TranslationFunc | None = None, ...):
```

The two remaining `t=None` occurrences are private helper functions (`_check_installed_kernels`, `_check_exposure`) where the annotation would add noise without benefit.

---

### Fix 5 — `_has_shell_ops()` via `shlex` tokenization (`bob/fixes.py`)

#### Problem

`_run_fix()` used substring matching to decide whether a remediation command needed `shell=True`:

```python
_SHELL_OPS = ("&&", "||", "|", ";", ">", ">>")

if any(op in cmd for op in _SHELL_OPS):
    subprocess.run(cmd, shell=True, ...)
else:
    subprocess.run(shlex.split(cmd), shell=False, ...)
```

`op in cmd` matches anywhere in the string, including inside quoted arguments and file paths. A command like `sudo chmod 644 /etc/app/config.d/module>2` (hypothetical path containing `>`) or a command with a `--format=json>output` flag would be incorrectly routed to `shell=True`, introducing an unnecessary shell injection surface.

#### Fix

```python
def _has_shell_ops(cmd: str) -> bool:
    """Return True if cmd contains shell operators requiring shell=True."""
    _SHELL_TOKENS = frozenset({"&&", "||", ";", "|", ">", ">>", "<", "&"})
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return True   # malformed quoting — treat as unsafe
    return any(tok in _SHELL_TOKENS or tok.startswith("`") or tok.startswith("$(")
               for tok in tokens)
```

`shlex.split()` tokenizes the command the same way a POSIX shell would, stripping quotes and expanding nothing. Operators are only matched as complete tokens. Malformed quoting (unclosed quotes) safely falls through to `shell=True` rather than raising.

---

### Fix 6 — Profile fallback now visible (`bob/__main__.py`, locales)

#### Problem

`load_profile()` silently returns the default `server` profile when the requested profile name is not found. When a user passed `--profile=laptop` (a non-existent profile), the audit ran with the `server` profile and there was no indication in the output that the requested profile had not been applied. The user could not distinguish "profile active" from "profile silently ignored".

#### Fix

```python
active_profile = load_profile(profile_name)
if profile_name not in ("", "default", "server") and active_profile.name != profile_name:
    output.print_warn(t("audit.profile_not_found", profile=profile_name))
```

The guard excludes the default aliases (`""`, `"default"`, `"server"`) to avoid spurious warnings when no profile is specified. New i18n keys:

- `en.json`: `"profile_not_found": "Profile '{profile}' not found — using default (server)"`
- `fr.json`: `"profile_not_found": "Profil '{profile}' introuvable — utilisation du profil par défaut (server)"`

---

### Tests

4274/4274 (+12 new, all passing):

| File | Tests added |
|------|-------------|
| `tests/test_kernel_modules.py` | `test_up_to_date_names_running_kernel_not_unsigned_sibling` — asserts running kernel name in OK message, not `-unsigned` sibling |
| `tests/test_kernel_modules.py` | `test_debian_signed_unsigned_pair_uses_obsolete_same_message` — asserts `kernels_obsolete_same` key when signed/unsigned pair at top |
| `tests/test_compare.py` | `test_variable_deductions_increased_shown_without_structural_change` |
| `tests/test_compare.py` | `test_variable_deductions_decreased_shown_without_structural_change` |
| `tests/test_compare.py` | `test_variable_deductions_suppressed_when_warn_delta` |
| `tests/test_compare.py` | `test_variable_deductions_suppressed_when_new_finding_key` |
| `tests/test_compare.py` | `test_deduction_total_none_in_new_baseline_defaults` — `AuditBaseline()` default is `None` |
| `tests/test_compare.py` | `test_load_baseline_returns_none_when_field_absent` — old JSON without field → `None` |
| `tests/test_compare.py` | `test_load_baseline_returns_int_when_field_present` — new JSON with field → integer |
| `tests/test_compare.py` | `test_deduction_delta_zero_when_prev_is_old_baseline` — None prev → delta = 0 |
| `tests/test_compare.py` | `test_deduction_delta_computed_when_both_tracked` — both int → correct delta |
| `tests/test_compare.py` | `test_deduction_delta_zero_when_unchanged` — same value both sides → 0 |

---

## [v0.2.3] — 2026-05-03

Eight fixes identified during a systematic multi-VM audit round (Linux Mint desktop, Debian 13, Kali, Linux Mint test VM, Ubuntu 26.04). Three behavioural bug fixes in the check layer, two infrastructure fixes, and three UX precision fixes found by cross-distro comparison. No new features. 4262/4262 tests (+1).

---

### Fix 1 — NOT_LISTENING always INFO (`bob/checks/services.py`, `tests/test_services.py`)

#### Problem

`_check_exposure()` in `services.py` had a severity-based branch for `Exposure.NOT_LISTENING`:

```python
elif exposure == Exposure.NOT_LISTENING:
    if snap.service.is_high_or_critical:
        result.warn(message=port_msg, nature="improvement")
    else:
        result.info(message=port_msg)
```

For HIGH/CRITICAL services (e.g. Mosquitto, Redis, SSH) with a registered port that was not actively bound, this produced a `⚠ [ATTENTION]` finding with `nature="improvement"`. That finding appeared in the summary box under "⚠ Améliorations possibles", even though a non-listening port is a neutral state — the service is not exposing the port, which is good.

The original intent was to flag services that should be listening but aren't. In practice, services legitimately bind only a subset of their registered ports (Mosquitto 1883 only, Nginx 80 only, etc.), making this a systematic false positive for HIGH/CRITICAL services.

Found on: Linux Mint desktop (Telnet NOT_LISTENING in summary despite not being installed) and Linux Mint test VM (Mosquitto 8883 as WARN when only 1883 was bound).

#### Fix

```python
elif exposure == Exposure.NOT_LISTENING:
    result.info(message=port_msg)
```

The severity branch is removed. `NOT_LISTENING` is informational on all services.

---

### Fix 2 — IoT local dominance: deduction removed (`bob/checks/logs.py`, `tests/test_logs.py`)

#### Problem

`_check_local_dominance()` detects when a single private IP dominates UFW block logs — a pattern caused by IoT devices broadcasting UDP on the local network. Previously:

```python
result.warn(
    message=_t("logs.local_dominance", ...),
    key="logs.local_dominance",
    nature="improvement",
)
result.add_deduction(
    reason=_t("deduction.local_dominance", ...),
    points=1,
    key="logs.local_dominance",
)
```

Deducting 1 point for benign IoT traffic was incorrect. The function already identifies the source as a private address and labels it as a low-severity pattern; penalising the score was contradictory.

Found on: Linux Mint desktop (score lower than expected; IoT broadcast from a smart plug reducing score by 1 pt).

#### Fix

```python
result.info(
    message=_t("logs.local_dominance", ...),
    key="logs.local_dominance",
)
```

Demoted to `result.info()`, no deduction. The informational message still surfaces in the full audit output.

---

### Fix 3 — Heredoc commands no longer mangled (`bob/display.py`)

#### Problem

`_add_finding_lines()` passed the full `item.cmd` string to `_wrap_for_box()`:

```python
for content, val in _wrap_for_box(cmd_prefix, item.cmd, inner):
    lines.append(...)
```

`_wrap_for_box()` calls `text.split()` internally, which splits on all whitespace including `\n`. Multi-line commands (heredoc blocks used in `auditd` remediation steps) were collapsed into a single continuous line, making them unreadable.

Found on: Linux Mint desktop (auditd heredoc rule block displayed as one line in the summary box).

#### Fix

```python
cont_prefix = " " * len(cmd_prefix)
for i, cmd_line in enumerate(item.cmd.splitlines()):
    pfx = cmd_prefix if i == 0 else cont_prefix
    for content, val in _wrap_for_box(pfx, cmd_line, inner):
        lines.append((f"{_oc.violet_bold}{content}{_oc.reset}", val))
```

Each line of `item.cmd` is processed independently by `_wrap_for_box()`. Continuation lines use an aligned prefix (indented to match the first line's `→ ` or `ℹ ` marker).

---

### Fix 4 — Circular symlink guard in `--install-completion` (`bob/completion.py`)

#### Problem

`_install_completion()` checked:

```python
candidate = home / ".local" / "bin" / "bob"
if candidate.exists():
    bin_src = candidate
```

When pipx was installed system-wide (`/usr/local/bin/bob`) and `--install-completion` was run as the user, `~/.local/bin/bob` was already a symlink pointing at the system binary. Using it as `bin_src` caused the completion installer to create a new symlink at the same path pointing back at itself, producing a circular chain (`~/.local/bin/bob → itself`).

Found on: user's desktop after running `--install-completion`; `pipx upgrade` then printed a circular symlink warning.

#### Fix

```python
if candidate.exists() and candidate.resolve() != dst_bin.resolve():
    bin_src = candidate
```

`resolve()` follows all symlinks to the canonical path. If `candidate` and `dst_bin` resolve to the same path, the candidate is skipped and the system binary is used directly. `exists()` already returns `False` for broken or circular symlinks, so the combined check covers all failure modes.

---

### Fix 5 — Python 3.9 dropped (`pyproject.toml`, `.github/workflows/tests.yml`, `.github/workflows/publish.yml`)

#### Problem

Python 3.9 reached end-of-life in October 2025. `Path.stat()` does not accept `follow_symlinks` as a keyword argument until Python 3.10, causing `TypeError` in `tests/test_manage_logs.py` on the 3.9 CI runner.

#### Fix

- `requires-python = ">=3.10"` in `pyproject.toml` (was `">=3.9"`).
- Python 3.9 classifier removed from `pyproject.toml`.
- CI matrix in `tests.yml` and `publish.yml` changed from `["3.9", "3.10", "3.12"]` to `["3.10", "3.12"]`.

---

### Fix 6 — Compare: variable deduction delta (`bob/compare.py`, locales)

#### Problem

`AuditBaseline` stored `score`, `alert_count`, `warn_count`, and `finding_keys`, but not the total raw deduction points. When the score changed between audits without any structural change (same finding keys, same alert/warn counts — e.g. because log-based deductions varied with network activity), `display_delta()` showed only:

```
⚠ Score dégradé de N point(s)
```

with no further explanation, leaving the user unable to understand why the score moved.

Found on: Debian 13 VM and Kali VM (score delta without structural explanation).

#### Fix

`AuditBaseline` gains `deduction_total: int = 0` (default `0` keeps old baselines loadable without error). `AuditDelta` gains `deduction_delta: int = 0`. `build_baseline()` computes `sum(d.points for d in engine.breakdown)`. `load_baseline()` reads `raw.get("deduction_total", 0)`.

`display_delta()` shows the variable-deductions message when:
- `deduction_delta != 0`, AND
- no structural explanation exists (`alert_delta == 0`, `warn_delta == 0`, `new_finding_keys` empty, `resolved_finding_keys` empty).

New i18n keys: `compare.variable_deductions_increased`, `compare.variable_deductions_decreased`.

---

### Fix 7 — Exposure: SSH state label split (`bob/exposure.py`, locales, `tests/test_exposure.py`)

#### Problem

`compute_exposure()` used a single i18n key for two distinct SSH states:

```python
if "ssh.not_installed" in all_keys or "ssh.not_active" in bad_keys:
    detail=t("exposure.ssh_not_running")  # "non installé / non démarré"
```

When SSH was installed but its service was stopped (e.g. Kali Linux, where `sshd` is intentionally inactive), the attack-surface table displayed "non installé / non démarré" — factually incorrect, as the package was present.

Found on: Kali VM (SSH installed but stopped; label claimed "non installé").

#### Fix

```python
if "ssh.not_installed" in all_keys:
    detail=t("exposure.ssh_not_installed")   # "non installé"
elif "ssh.not_active" in bad_keys:
    detail=t("exposure.ssh_stopped")          # "installé — non démarré"
```

The `ssh_not_running` key is replaced by two distinct keys: `ssh_not_installed` and `ssh_stopped`. New test: `test_not_active_shows_stopped_text`.

---

### Fix 8 — Services: `active_disabled` message includes service label (`bob/checks/services.py`, locales)

#### Problem

When a service was active but not enabled at boot (`ServiceState.ACTIVE_DISABLED`), the finding message was:

```
"Le service est actif en ce moment, mais ne redémarrera pas automatiquement."
```

In the full audit output this was contextually clear (it appeared under the `▶ ServiceName` section header). In the summary box the service name was absent, leaving the user unable to identify which service was concerned without scrolling through the full output.

Found on: Linux Mint test VM (Redis active but not enabled; summary box showed the message without "Redis").

#### Fix

i18n string: `"{label} est actif en ce moment, mais ne redémarrera pas automatiquement."` (FR/EN both updated). Call site: `_t("services.state.active_disabled", label=snap.label)`.

---

### Tests

4262/4262 (+1 new, 4 renamed/updated):

| File | Change |
|------|--------|
| `tests/test_services.py` | `test_not_listening_critical_adds_warn` → `_adds_info` · `test_not_listening_high_adds_warn` → `_adds_info` · assertions changed to `has_level(result, "info")` and `not has_level(result, "warn")` |
| `tests/test_logs.py` | `test_finding_is_warn_level` → `test_finding_is_info_level` (asserts `FindingLevel.INFO`) · `test_score_deduction_one_point` → `test_no_score_deduction` (asserts `len(local_deductions) == 0`) |
| `tests/test_exposure.py` | `test_not_installed_info_is_ok` and `test_not_installed_overrides_password_auth` assert `exposure.ssh_not_installed` key · +1 `test_not_active_shows_stopped_text` asserts `exposure.ssh_stopped` key |

---

## [v0.2.2] — 2026-05-03

Five targeted scoring fixes, a locale fix, a logging uniformity pass across three modules, a firewall orphan-rule fix for protocol-unspecified UFW rules, scoring invariant tests, and equal-weight domain documentation. No new features outside scoring. 4261/4261 tests (+23).

---

### Fix 1 — `ScoreCap.key` propagation (`bob/scoring.py`, `bob/checks/firewall.py`)

#### Problem

`ScoreCap` had no `key` field. When a cap fired, `finalize()` appended a synthetic `Deduction` to `engine.breakdown` with `key=""`:

```python
self.breakdown.append(
    Deduction(reason=self._cap.reason, points=delta, context="structural")
)
```

`compute_domain_scores()` skips deductions with `key=""` (`_key_to_domain()` returns `None` for empty keys). A firewall-inactive cap that reduced the score by several points contributed zero to the `firewall` domain deductions — the cap was invisible to per-domain scoring.

#### Fix

`ScoreCap` gains `key: str = ""`:

```python
@dataclass
class ScoreCap:
    maximum: int
    reason:  str
    key:     str = ""
```

`CheckResult.set_cap()`, `ScoreEngine.cap()`, and `ScoreEngine.apply()` all propagate the key. `finalize()` uses `self._cap.key` in the synthetic deduction:

```python
self.breakdown.append(
    Deduction(reason=self._cap.reason, points=delta, context="structural", key=self._cap.key)
)
```

`bob/checks/firewall.py` updated:

```python
result.set_cap(maximum=3, reason=_t("firewall.inactive"), key="firewall.inactive")
```

---

### Fix 2 — INFO findings no longer inflate active domain set (`bob/domain_scores.py`)

#### Problem

`active_domains_from_engine()` iterated over all findings regardless of level:

```python
for finding in engine.findings:
    domain = _key_to_domain(finding.key)
    if domain:
        active.add(domain)
```

An INFO-only domain — a service installed with no actionable issues (e.g. ClamAV installed, db fresh, scan recent) — was included in `active_domains` and therefore in the global average. This could either dilute scores from genuinely degraded domains or pad the average when a high-score INFO-only domain was included.

#### Fix

`FindingLevel` imported directly from `bob.scoring`. The findings loops now filter to WARN and ALERT only:

```python
_actionable = (FindingLevel.WARN, FindingLevel.ALERT)
for finding in engine.findings:
    if finding.level not in _actionable:
        continue
    domain = _key_to_domain(finding.key)
    if domain:
        active.add(domain)
```

The deduction loop is unchanged — a domain with deductions but no WARN/ALERT findings (edge case) is still counted as active via the deduction path.

---

### Fix 3 — `clamav.db_very_outdated` 2pt → 1pt (`bob/checks/clamav.py`)

#### Problem

`check_clamav()` emitted a 2-point deduction for `clamav.db_very_outdated` (database ≥ 30 days old). The `clamav` entry in `_TOOL_CAPS` caps the tool's contribution to 1 point per domain. The second point only affected `engine._raw_score` before domain averaging, creating a silent asymmetry: the raw score punished this finding twice as hard as the domain score did.

#### Fix

```python
# before
result.add_deduction(
    reason=_t("clamav.db_very_outdated", days=snapshot.db_age_days),
    points=2, context="local", key="clamav.db_very_outdated",
)

# after
result.add_deduction(
    reason=_t("clamav.db_very_outdated", days=snapshot.db_age_days),
    points=1, context="local", key="clamav.db_very_outdated",
)
```

Worst-case ClamAV deduction total: `freshclam:1 + db_very_outdated:1 + scan_very_old:1 = 3` (was 4).

---

### Observability — logging uniformity (`bob/history.py`, `bob/ignore.py`, `bob/sysinfo.py`)

Six `except … pass` handlers replaced with `_log.debug()`. `import logging` and `_log = logging.getLogger(__name__)` added to all three modules. Failures remain non-fatal; visible under `--debug`.

#### `bob/history.py`

```python
# save_score() — before
except OSError:
    pass

# save_score() — after
except OSError as exc:
    _log.debug("Failed to save score to history: %s", exc)

# _rotate_if_needed() — before
except OSError:
    pass

# _rotate_if_needed() — after
except OSError as exc:
    _log.debug("Failed to rotate history file: %s", exc)
```

#### `bob/ignore.py`

```python
# load_ignore_keys() — before
except OSError:
    pass

# load_ignore_keys() — after
except OSError as exc:
    _log.debug("Cannot read ignore file %s: %s", path, exc)
```

#### `bob/sysinfo.py`

`get_user_home()`: SUDO_USER set but not found in the password database — the fallback to `Path.home()` is now logged, which explains unexpected config paths when running under exotic sudo configurations.

`collect_system_info()`: `/etc/os-release` read failure now logged.

`detect_network_type()`: both `ip route` and `ip addr` subprocess failures now logged. Previously these failed silently and the function fell through to `get_public_ip()` with no trace.

```python
# detect_network_type() — before (both locations)
except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
    pass

# detect_network_type() — after
except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
    _log.debug("ip route failed during network type detection: %s", exc)
    # (and separately for ip addr)
    _log.debug("ip addr failed during network type detection: %s", exc)
```

---

### Scoring contract documented (`bob/scoring.py`)

`ScoreEngine.finalize()` docstring updated:

```
Required call sequence (orchestrator contract):
    engine.finalize()
    apply_domain_score_override(engine)   # from bob.domain_scores

After finalize() but before apply_domain_score_override(), engine.score
returns the raw deduction-based score.  The domain-averaged global score
is only available after apply_domain_score_override() sets the override.
```

`ScoreEngine.set_global_score()` docstring updated:

```
Do not call this directly — use apply_domain_score_override(engine)
from bob.domain_scores, which computes the correct domain average.
The raw pre-override score remains accessible as engine._raw_score.
```

---

### Fix 4 — Domain score cap not applied when global raw score is already below threshold (`bob/domain_scores.py`)

#### Problem

`compute_domain_scores()` derives each domain's score by summing the deductions in `engine.breakdown` that map to that domain. When a cap fires during `finalize()` (e.g. `firewall.inactive` → max 3/10), a synthetic delta `Deduction` is appended to `breakdown` **only if** `_raw_score > cap.maximum`:

```python
# scoring.py — ScoreEngine.finalize()
if self._cap is not None and self._raw_score > self._cap.maximum:
    delta = self._raw_score - self._cap.maximum
    self.breakdown.append(
        Deduction(reason=self._cap.reason, points=delta, key=self._cap.key)
    )
    self._raw_score = self._cap.maximum
```

On systems with many deductions spread across domains (firewall + hardening + …), the global `_raw_score` can fall below `cap.maximum` before `finalize()` runs. In that case the `if` guard is false, no delta is appended, and `compute_domain_scores()` never sees the cap. The target domain score remains at its raw pre-cap value (e.g. 6/10 for the firewall domain from `-3` INPUT + `-1` FORWARD) instead of the intended capped value (3/10).

The cap note `"Score plafonné à 3 (pare-feu inactif)"` is always shown in the display whenever `engine.cap_info` is set (registered caps are stored in `engine._cap` independently of whether they triggered), so the UI contradicts itself: the note says the score was capped but the domain bar still shows 6/10.

**Found by:** running the tool on an Ubuntu 26.04 VM with UFW inactive and several hardening issues (3× ICMP deductions, no backup, pending firmware updates). The global raw score (10 − 9 = 1) was already below the firewall cap of 3, so the cap delta was never appended and the firewall domain kept its raw 6/10 score.

#### Fix

After accumulating domain deductions from the breakdown, `compute_domain_scores()` now explicitly enforces the engine-level cap on its target domain:

```python
# domain_scores.py — compute_domain_scores()
engine_cap = engine.cap_info
if engine_cap and engine_cap.key:
    cap_domain = _key_to_domain(engine_cap.key)
    if cap_domain and cap_domain in domain_deductions:
        raw_domain = MAX_SCORE - domain_deductions[cap_domain]
        if raw_domain > engine_cap.maximum:
            domain_deductions[cap_domain] += raw_domain - engine_cap.maximum
```

The fix is **idempotent**: if the cap delta was already appended to the breakdown (the normal case where `raw_global > cap`), that delta increased `domain_deductions[cap_domain]`, bringing `raw_domain` down to exactly `cap.maximum`. The guard `raw_domain > cap.maximum` is then false, and nothing extra is added. No double-counting.

#### Impact

- Firewall domain (UFW inactive, few other firewall deductions): **6/10 → 3/10**
- Global score on the Ubuntu test VM: unchanged (8/10 either way — the two paths coincide due to banker's rounding on 8.5)
- All other domains: unaffected

---

### Fix 5 — Orphan-rule check misses protocol-unspecified UFW rules (`bob/checks/firewall.py`)

#### Problem

`_check_orphan_rules()` parsed the UFW "To" field with `_PORT_PROTO_RE` which requires an explicit protocol suffix (`/tcp` or `/udp`). A rule written as a bare port number — valid UFW syntax meaning "apply to both TCP and UDP" — produced `m = None` and fell through to `continue`:

```python
m = _PORT_PROTO_RE.search(line)  # e.g. "57621 ALLOW IN ..." → no match
if not m:
    continue  # ← incorrectly labelled "open-any rules"
```

In practice, `57621 ALLOW IN 192.168.1.0/24` (Spotify Connect) was present in the UFW rules alongside `41681/tcp ALLOW IN 192.168.1.0/24`. BOB correctly flagged `41681/tcp` as an orphan rule (no service listening) but silently skipped `57621`. Found by running the tool on a real machine and comparing the two Spotify Connect rules.

#### Fix

New module-level constant `_PORT_BARE_RE = re.compile(r"^\[\s*\d+\]\s+(\d{1,5})\s", re.IGNORECASE)` matches a bare port in the UFW numbered-status "To" position. When `_PORT_PROTO_RE` fails to match, `_check_orphan_rules` now falls through to `_PORT_BARE_RE`:

```python
m = _PORT_PROTO_RE.search(line)
if not m:
    m2 = _PORT_BARE_RE.match(line)
    if not m2:
        continue  # genuine open-any rule
    port = m2.group(1)
    if f"{port}/tcp" not in listening_ports and f"{port}/udp" not in listening_ports:
        orphans.add(port)
    continue
```

A bare-port rule is flagged as orphan only if **neither** `port/tcp` nor `port/udp` is currently listening — consistent with UFW's TCP+UDP semantics. The delete command generated (`sudo ufw delete allow 57621`) is also correct for protocol-unspecified rules.

### Scoring invariant tests (`tests/test_scoring.py`, `tests/test_domain_scores.py`)

`TestScoringInvariants` classes added to both test files — 12 new tests for structural properties that must hold regardless of input. This is the property-based testing layer for the scoring pipeline, covering monotonicity, boundedness, and activation semantics.

#### `tests/test_scoring.py` — `TestScoringInvariants` (+5)

```python
class TestScoringInvariants:
    def test_score_floor_is_zero_on_huge_deduction(self):
        engine = ScoreEngine()
        engine.deduct("flood", 999)
        assert engine.score == 0

    def test_score_ceiling_is_max_on_no_deductions(self):
        engine = ScoreEngine()
        engine.finalize()
        assert engine.score == MAX_SCORE

    def test_deductions_are_monotone_decreasing(self):
        engine = ScoreEngine()
        prev = engine.score
        for pts in (3, 1, 2, 1, 4):
            engine.deduct("step", pts)
            assert engine.score <= prev
            prev = engine.score

    def test_cap_above_current_score_is_noop(self):
        engine = ScoreEngine()
        engine.deduct("reason", 3)   # score = 7
        score_before = engine.score
        engine.cap(maximum=9, reason="lenient cap")
        engine.finalize()
        assert engine.score == score_before

    def test_score_after_domain_override_in_valid_range(self):
        from bob.domain_scores import apply_domain_score_override
        engine = ScoreEngine()
        engine.deduct("reason", 5)
        engine.finalize()
        apply_domain_score_override(engine)
        assert 0 <= engine.score <= MAX_SCORE
```

#### `tests/test_domain_scores.py` — `TestScoringInvariants` (+7)

Key tests:

- **INFO-only → domain inactive:** a finding with `level=INFO` and no deduction does not mark the domain as "active" for the global average.
- **WARN/ALERT → domain active:** these levels do activate the domain, even without a paired deduction.
- **Deduction alone activates:** `add_deduction(key=...)` without any finding still marks the domain active via the deduction path in `active_domains_from_engine()`.
- **Global average bounded:** `compute_global_from_domains` result is always `≥ min(active_scores)` and `≤ max(active_scores)`.
- **Domain scores in range:** `compute_domain_scores` result always in `[0, MAX_SCORE]` for every domain.
- **Global always in range:** `compute_global_from_domains` always returns a value in `[0, 10]`.

The deduction-only activation test is particularly important: it confirms that `active_domains_from_engine()` checks both the findings path (WARN/ALERT filter) and the deductions path (no filter), and that the two paths are intentionally asymmetric.

---

### Fix 6 — SSH "not running" detail duplicated the remediation command (`bob/locales/fr.json`, `bob/locales/en.json`)

#### Problem

`ssh.not_active_detail` was set to `"Activer avec : sudo systemctl enable --now ssh"` (FR) / `"Enable with: sudo systemctl enable --now ssh"` (EN). The display layer renders both `detail` and `cmd` as separate `→` lines under the "Que faire ?" heading. Since the `cmd` field already contains `"sudo systemctl enable --now ssh"`, the block displayed the command twice:

```
    Que faire ?
    → Activer avec : sudo systemctl enable --now ssh   ← detail (contains command)
    → sudo systemctl enable --now ssh                  ← cmd (same command again)
```

The `detail` field is intended to explain *why* or provide context; the `cmd` field is the copy-pasteable command. Having the command text in both fields is redundant.

**Found by:** running the tool on Kali Linux, where SSH is installed by default but the daemon is intentionally stopped. The double-command display was visible in the verbose output.

#### Fix

`ssh.not_active_detail` changed to context-only text in both locales:
- FR: `"Le service est désactivé — activez-le si l'accès SSH est nécessaire."`
- EN: `"The service is disabled — enable it if SSH access is needed."`

The `cmd` field (`"sudo systemctl enable --now ssh"`) is unchanged and continues to display the actionable command.

### Tests

4261/4261 (+23 new, 2 updated):

#### `tests/test_domain_scores.py` — `TestEngineLevelDomainCap` (+6)

Six new cases in a new class covering the domain-level cap fix:

| Test | Coverage |
|------|----------|
| `test_firewall_domain_capped_when_few_deductions` | INPUT −3, FORWARD −1 → raw domain = 6, capped to 3 |
| `test_firewall_domain_capped_when_many_global_deductions` | 9-point global deductions push raw_score below cap threshold (delta not in breakdown) → domain still capped to 3 |
| `test_firewall_domain_not_overcapped_when_already_at_cap` | Domain already at cap.maximum → score stays at 3, not pushed below |
| `test_firewall_domain_score_never_exceeds_cap` | Property: score ≤ 3 for any number of firewall deductions (0–4 extra) |
| `test_cap_does_not_affect_other_domains` | Cap on `firewall.inactive` leaves hardening domain at MAX_SCORE |
| `test_all_domain_scores_in_valid_range_with_cap` | All 7 domains in [0, MAX_SCORE] when cap is applied |

#### `tests/test_firewall.py` — `TestOrphanRules` (+3)

Three new cases in the existing `TestOrphanRules` class:

| Test | Coverage |
|------|----------|
| `test_bare_port_rule_flagged_when_nothing_listening` | `57621 ALLOW IN` with no TCP or UDP listener → flagged as orphan with `ufw delete allow 57621` |
| `test_bare_port_rule_not_flagged_when_tcp_listening` | `57621/tcp` present in listening set → not flagged |
| `test_bare_port_rule_not_flagged_when_udp_listening` | `57621/udp` present in listening set → not flagged |

#### `tests/test_manage_logs.py` — `TestStatFallback` (+2)

Regression for the v0.2.1 `.stat()` race condition fix. The plain-text display loops in `_run_manage_logs_plain()` were updated in v0.2.1 to wrap `.stat()` in `try/except OSError` — but no test covered the fallback path.

A `_stat_raises_for_logs` helper is defined at module level (captured before any test run) that raises `OSError` only for `.log` files, passing through to the real `Path.stat` for directories. This is necessary because Python 3.12's `Path.exists()` calls `self.stat()` internally — a global mock would break `exists()` on directories and cause test failures.

```python
_real_path_stat = Path.stat

def _stat_raises_for_logs(self, *, follow_symlinks=True):
    if self.suffix == ".log":
        raise OSError("race: file disappeared between scan and display")
    return _real_path_stat(self, follow_symlinks=follow_symlinks)
```

| Test | Coverage |
|------|----------|
| `test_cur_logs_stat_oserror_uses_fallback` | `.stat()` raises in `cur_logs` loop → `"(0 "` and `"?"` in output |
| `test_extra_logs_stat_oserror_uses_fallback` | `.stat()` raises in `extra_sections` loop → same |

#### `tests/test_clamav.py` (2 updated)

| Test | Before | After |
|------|--------|-------|
| `test_db_very_outdated_deducts_1` (was `_deducts_2`) | asserted `pts == 2` | asserts `pts == 1` |
| `test_worst_case` | asserted total == 4 | asserts total == 3 |

---

## [v0.2.1] — 2026-05-02

Defensive programming hotfix — 17 targeted improvements identified by a dual-agent code audit (independent runs by Claude and Copilot). No new features, no behavior changes, no new tests. 4238/4238 unchanged.

### `bob/manage_logs.py` — crash fix: unguarded `.stat()` in plain-text mode

#### Problem

The plain-text rendering loops in `_run_manage_logs_plain()` called `f.stat()` directly:

```python
size_kb = max(1, f.stat().st_size // 1024)
mtime = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
```

If a log file was deleted between the directory scan and the display loop (e.g. by a parallel `logrotate` run), this raised `OSError` and crashed `--manage-logs`. The curses mode (lines 792–796) already had the correct guard:

```python
try:
    size_kb = max(1, f.stat().st_size // 1024)
    mtime   = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
except OSError:
    size_kb, mtime = 0, "?"
```

#### Fix

Both loops in the plain-text path (`cur_logs` and `extra_sections`) now wrap `.stat()` identically to the curses path, using `(0, "?")` as fallback values.

---

### Exception handling narrowed — 8 locations

All `except Exception` handlers (which also catch programming errors and make debugging harder) replaced with the specific exception types that can actually be raised at each site.

#### `bob/cis_refs.py` — `_load()`

`_load()` reads and parses a JSON file. The only failures are I/O (`OSError`) and malformed JSON (`json.JSONDecodeError`).

```python
# before
except Exception:
    return {}

# after
except (OSError, json.JSONDecodeError):
    return {}
```

#### `bob/manage_logs.py` — `_get_extra_dirs()`

Parses a JSON-encoded list of strings from user config. Failures: malformed JSON, unexpected value types.

```python
# before
except Exception:
    return []

# after
except (json.JSONDecodeError, ValueError, TypeError):
    return []
```

#### `bob/manage_logs.py` + `bob/explain.py` + `bob/cron.py` — curses fallbacks

Three `curses.wrapper()` calls that fall back to plain-text mode on terminal failure. The `curses.error` exception covers all terminal initialization and rendering failures; `OSError` covers I/O-level terminal errors.

```python
# before (all three sites)
except Exception:
    return _run_*_plain(...)

# after
except (curses.error, OSError):          # manage_logs.py, explain.py
    return _run_*_plain(...)

except (_curses.error, OSError):         # cron.py (curses imported as _curses)
    return _run_*_plain(...)
```

#### `bob/checks/ssh.py` — binary key parsing

`_rsa_bits_from_blob()`: decodes base64 and unpacks a binary SSH wire format. Failures: invalid base64 (`binascii.Error`, subclass of `ValueError`) and malformed struct data (`struct.error`).

```python
# before
except Exception:
    return None

# after
except (struct.error, ValueError):
    return None
```

`_has_passphrase()`: decodes base64 OpenSSH key data. Only `binascii.Error` (invalid base64, subclass of `ValueError`) can be raised inside the try block.

```python
# before
except Exception:
    return None

# after
except (binascii.Error, ValueError):
    return None
```

`import binascii` added at top of `ssh.py`.

---

### Regex patterns moved to module level — 3 files

Patterns that were `re.compile()`d inside function bodies — recompiled on every call — moved to module-level constants. Python does not cache `re.compile()` results automatically when called inside functions.

#### `bob/checks/firewall.py`

```python
# moved to module level
_OPEN_ANY_RE = re.compile(
    r"Anywhere(?:/\w+)?(?:\s+\(v6\))?\s+ALLOW\s+IN\s+Anywhere(?:/\w+)?(?:\s+\(v6\))?\s*$",
    re.IGNORECASE,
)
_ALLOW_IN_RE   = re.compile(r"\bALLOW\s+IN\b", re.IGNORECASE)
_PORT_PROTO_RE = re.compile(r"\b(\d{1,5}/(?:tcp|udp))\b", re.IGNORECASE)
```

`_check_open_any()` and `_check_orphan_rules()` updated to reference the module-level constants.

#### `bob/checks/cron_audit.py`

```python
_PATH_RE = re.compile(r"(/[^\s;|&<>]+\.sh)\b")
```

Moved from inside `_find_world_writable_scripts()` to module level alongside the existing `_PIPE_TO_SHELL_RE`.

#### `bob/checks/firmware.py`

```python
_FLAT_SKIP_RE = re.compile(
    r"^(Update|Version|Summary|Description|Requires|Urgency|Remote|Size|"
    r"Flags|Status|GUID|Device|AppStream|Release|\[|WARNING|Error|\s)",
    re.IGNORECASE,
)
```

Moved from inside `_parse_fwupd_updates()` to module level alongside `_TREE_ITEM_RE`.

---

### `bob/cron.py` — email regex deduplicated

`_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")` was defined identically inside three separate functions: `_select_emails_plain()` (line 325), `_curses_email_list_sub()` (line 1273), `_curses_email_store_sub()` (line 1398). Moved to a single module-level constant (line 20). The same pattern exists independently in `bob/config.py` for config validation; both are intentionally kept as each module owns its own constraint.

---

### `bob/manage_logs.py` — `_resolve_path()` helper extracted

```python
def _resolve_path(raw: str, default: Path) -> Path:
    """Expand, resolve and return *raw* as a Path, or *default* if empty."""
    return Path(raw).expanduser().resolve() if raw else default
```

The one-liner `Path(raw).expanduser().resolve() if raw else default` appeared at two call sites: inside `_prompt_path()` (return statement) and inside the change-directory flow. Both now call `_resolve_path()`. The security comment (`resolve() normalises ".." components…`) is kept at the first call site.

---

### `bob/domain_scores.py` — direct attribute access

`active_domains_from_engine()` and `compute_domain_scores()` used `getattr(engine, "findings", [])`, `getattr(finding, "key", None)`, and `getattr(deduction, "points", 0)` as defensive guards. `ScoreEngine.__init__` always initializes `findings`, `ignored_findings`, and `breakdown` as empty lists; `Finding` and `Deduction` are dataclasses with `key` and `points` as required fields. The `getattr` calls hid potential API drift instead of surfacing it. Replaced with direct access throughout.

---

### `bob/recurrence.py` — debug log on load failure

```python
# before
except (OSError, json.JSONDecodeError, ValueError):
    pass

# after
except (OSError, json.JSONDecodeError, ValueError) as exc:
    _log.debug("Failed to load recurrence data from %s: %s", src, exc)
```

`import logging` and `_log = logging.getLogger(__name__)` added. Failures are still non-fatal (recurrence tracking is best-effort) but now surface under `--debug` log level.

---

### `bob/__main__.py` — webhook failure logging

```python
# before
except Exception as _exc:  # noqa: BLE001
    print(f"Warning: webhook failed: {_exc}", file=sys.stderr)

# after
except Exception as _exc:  # noqa: BLE001
    _log.warning("Webhook failed: %s", _exc)
    print(f"Warning: webhook failed: {_exc}", file=sys.stderr)
```

`import logging` and `_log = logging.getLogger(__name__)` added. Webhook failures are now captured by the logging system in addition to the user-visible stderr print.

---

### Tests

4238/4238 — no new tests, no behavior changes. All existing tests pass unmodified.

---

## [v0.2.0] — 2026-05-01

Five improvements found during first-run analysis on Ubuntu 26.04 LTS and Debian 13.

### `bob/scoring.py` + `bob/domain_scores.py` — scoring refactoring

#### Problem

The global score was computed as `10 − sum(all_deductions)`. On Debian 13 with 8 deductions of −1 each, this produced a 2/10 CRITICAL rating even though SSH, firewall, updates, and file permissions were all perfect. The score did not represent the actual security posture of the machine.

Two additional issues:
- **Double penalty on single tools** — rkhunter emitting both `rootkit.db_outdated` and `rootkit.no_scan` deducted 2 points from the global score, punishing a single misconfiguration twice.
- **Disconnection between global and domain scores** — domain scores were computed independently but the global score was not derived from them, creating a contradiction in the output.

#### Fix 1 — Tool caps in `compute_domain_scores()`

New `_TOOL_CAPS` dict in `domain_scores.py`:

```python
_TOOL_CAPS: dict[str, int] = {
    "rootkit":        1,   # rkhunter/chkrootkit — db age + scan age
    "clamav":         1,   # ClamAV — db age + scan frequency
    "file_integrity": 1,   # AIDE/Tripwire — presence + freshness
}
```

When `compute_domain_scores()` accumulates deductions per domain, each tool prefix is capped at its maximum contribution. A second deduction from `rootkit.*` when the cap is already reached contributes 0 points to the domain score. Uncapped prefixes (e.g. `hardening.*`, `ssh.*`) accumulate normally.

#### Fix 2 — Global score = mean of active domain scores

New `compute_global_from_domains(domain_scores, active_domains) -> int` in `domain_scores.py`:

```python
active = [d for d in DOMAINS if d in active_domains and d in domain_scores]
return max(0, min(MAX_SCORE, round(total / len(active))))
```

New `apply_domain_score_override(engine)` calls `compute_domain_scores`, `active_domains_from_engine`, and `compute_global_from_domains`, then calls `engine.set_global_score()` with the result.

New `ScoreEngine.set_global_score(score: int)` stores the domain-averaged value in `_global_override`. The `score` property returns `_global_override` when set, falling back to `_raw_score` otherwise. The internal raw score is never modified — it remains available at `engine._raw_score` for debugging.

`apply_domain_score_override(engine)` is called immediately after `engine.finalize()` in both `bob/__main__.py` and `bob/watch.py`.

#### Effect

Debian 13 reference case (8 deductions, all domains otherwise healthy):
- Before: 2/10 CRITICAL (raw sum)
- After: 6/10 (hardening=4, disk=9, average of 2 active domains in the test scenario; 9/10 in real use with SSH/firewall/updates active at 10/10)

### `bob/cron.py` — MTA detection (`_detect_mta()`)

#### Problem

The cron wizard checked `shutil.which("mail")` and warned `'mail' not available — install mailutils`. Email delivery in `report_markdown.py` uses `sendmail -t -f`, not `mail`. The check was testing the wrong binary and recommending an unnecessary package.

#### Fix

New `_detect_mta() -> tuple[bool, str]` helper:

```python
def _detect_mta() -> tuple[bool, str]:
    import shutil
    if not shutil.which("sendmail"):
        return False, ""
    for name, check in [
        ("Postfix", lambda: Path("/etc/postfix/main.cf").exists()),
        ("Exim",    lambda: bool(shutil.which("exim4") or shutil.which("exim"))),
        ("msmtp",   lambda: bool(shutil.which("msmtp"))),
        ("ssmtp",   lambda: bool(shutil.which("ssmtp"))),
    ]:
        if check():
            return True, name
    return True, ""
```

Both call sites in `_run_install_cron_plain` and `_run_install_cron_curses` now use `_detect_mta()`. When an email is configured:
- MTA found: `✔ Mail transport: Postfix (sendmail available — notifications will be delivered)`
- MTA missing: `⚠ No sendmail found — notification emails won't be delivered. Install: sudo apt install postfix  or  sudo apt install msmtp-mta`

Locale keys `mail_missing` replaced by `mta_missing` and `mta_found` in `bob/locales/en.json` and `bob/locales/fr.json`.

### `bob/checks/kernel_modules.py` — Debian `-unsigned` false positive

#### Problem

On Debian with Secure Boot enabled, apt installs both:
- `linux-image-6.12.74+deb13+1-amd64` — signed kernel (booted when Secure Boot is active)
- `linux-image-6.12.74+deb13+1-amd64-unsigned` — unsigned variant (same version, different package)

`_check_installed_kernels()` sorted all installed kernels by `_kernel_sort_key()`. Both variants produce the same numeric sort key `(6, 12, 74, 0)`. Python's stable sort then falls back to lexicographic order, placing `-amd64-unsigned` after `-amd64`. `most_recent` was set to the unsigned variant, making `running != most_recent` evaluate to `True` — triggering a spurious reboot warning.

#### Fix

New `_strip_unsigned(version: str) -> str` helper:

```python
def _strip_unsigned(version: str) -> str:
    return version[:-len("-unsigned")] if version.endswith("-unsigned") else version
```

`reboot_pending` now compares stripped versions:

```python
reboot_pending = running in kernels and _strip_unsigned(running) != _strip_unsigned(most_recent)
```

A genuine version difference (e.g. `6.12.63+deb13-amd64` running while `6.12.74+deb13+1-amd64` is installed) still triggers the reboot warning correctly.

### Tests

- `tests/test_kernel_modules.py` — +6 tests:
  - `TestKernelRebootPending.test_no_reboot_pending_debian_signed_plus_unsigned_same_version`
  - `TestKernelRebootPending.test_reboot_still_pending_when_genuinely_newer_debian_kernel`
  - `TestStripUnsigned` — 4 unit tests for `_strip_unsigned()`
- `tests/test_cron.py` — +6 tests in `TestDetectMta`: no sendmail, Postfix (via config file), Exim, msmtp, ssmtp, unknown MTA
- `tests/test_scoring.py` — +6 tests in `TestSetGlobalScore`: override replaces raw, no override by default, clamp above max, clamp below zero, level reflects override, raw score unchanged
- `tests/test_domain_scores.py` — +14 tests:
  - `TestToolCaps` (7 tests) — rootkit/clamav/file_integrity capped at 1; uncapped prefixes accumulate; caps don't bleed across tools; partial deduction respects cap
  - `TestComputeGlobalFromDomains` (4 tests) — average, empty domains, clamp max, clamp zero
  - `TestApplyDomainScoreOverride` (3 tests) — override applied, valid range, Debian 13 scenario
- **Total: 4238 tests** (4206 → 4238, +32)

### `bob/checks/logs.py` — IoT local dominance: WARN −1 pt

#### Problem

When a single private IP accounted for ≥ 70 % of all blocked UFW traffic over ≥ 50 log entries, BOB emitted an `INFO` finding with no score deduction. The feature was documented as WARN −1 pt in README_TECH.md but the implementation called `result.info()` with no `add_deduction()` call — the deduction was never applied.

Discovered during first local test run on `so6desktop`: `192.168.1.50` accounted for 2267/2415 blocks (93 %) with no WARN or deduction emitted.

#### Fix

`bob/checks/logs.py`:
```python
result.warn(
    message=_t("logs.local_dominance", ip=local_ip, count=local_count,
               total=snapshot.total, pct=local_pct),
    key="logs.local_dominance",
    nature="improvement",
)
result.add_deduction(
    reason=_t("deduction.local_dominance", ip=local_ip, pct=local_pct),
    points=1,
    key="logs.local_dominance",
)
```

New locale key `deduction.local_dominance` added in `bob/locales/en.json` and `bob/locales/fr.json`.

Three existing tests in `tests/test_logs.py` corrected to assert the now-correct behaviour:
- `test_check_logs_emits_warn_finding` (was `test_check_logs_emits_info_finding`)
- `test_finding_is_warn_level` (was `test_finding_is_info_level`)
- `test_score_deduction_one_point` (was `test_no_score_deduction`)

Test count unchanged at 4238.

### `bob/output.py` — Orange ASCII banner

The `BOB` ASCII art rendered inside the terminal banner box is now coloured orange bold (`_c.orange_bold` = `\033[1;38;5;208m`). Border characters (`║`, `╔`, `╠`, `╚`) retain their existing blue bold colour. No output format or log file impact — terminal rendering only.

---

## [v0.1.1] — 2026-04-29

Hotfix release. Three targeted fixes found during first runs on Ubuntu 26.04 LTS and Debian 13.

### Fixes

#### `bob/checks/firmware.py` — fwupd 1.9+ tree-format parser

`fwupdmgr get-updates` changed its output format in fwupd 1.9+ (shipped with Ubuntu 26.04 LTS). The previous flat-format assumed device names at column 0 with metadata indented; the new format uses a tree structure:

```
QEMU Ubuntu 24.04 PC (Q35 + ICH9, 2009)
│
├─UEFI CA:
│   New version: 2024.01
│
└─QEMU DVD-ROM:
    New version: 2.5
```

The previous `_parse_fwupd_updates()` parser captured `│` and `├─UEFI CA:` as device names, producing garbled output: `10 pending firmware updates: QEMU Ubuntu 24.04 PC (Q35 + ICH9, 2009), │, ├─UEFI CA: (+7)`.

Fix: tree format auto-detected (any `├─`/`└─` line present); in tree mode, device names extracted from `├─`/`└─` lines by stripping the prefix and trailing colon; `│` lines and top-level container lines skipped. Flat format unchanged.

New module-level constant: `_TREE_ITEM_RE = re.compile(r"^[├└]─\s*")`.

#### `bob/__main__.py` — `--install-completion` error message

When `bob --install-completion` is run without root, the error message showed the correct full-path command (`sudo /path/to/bob --install-completion`) but users naturally typed `sudo bob --install-completion` instead, which fails because sudo's restricted PATH does not include pipx's `~/.local/bin`.

New message explicitly explains that `sudo bob` will not work (pipx PATH restriction) and instructs to copy-paste the exact command shown.

#### `bob/locales/en.json`, `bob/locales/fr.json` — services panorama column header

`services.panorama.header_ufw`: `"UFW"` → `"SCOPE"` (EN) / `"PORTÉE"` (FR).

The column uses `Exposure.OPEN_WORLD` to determine the indicator — it reflects whether a service has internet-scope exposure, not whether an active UFW rule covers it. With UFW inactive, LAN-scoped services (Avahi, CUPS) correctly showed `✔` but the `UFW` label implied firewall protection was active. The renamed label eliminates this ambiguity.

### Tests

- `tests/test_firmware.py` — 4 new regression tests covering the tree-format parser:
  - `test_tree_format_extracts_device_names` — `├─`/`└─` lines yield correct device names
  - `test_tree_format_excludes_container_line` — top-level container not captured
  - `test_tree_format_excludes_tree_connectors` — `│`, `├`, `└` chars absent from results
  - `test_tree_format_strips_trailing_colon` — names from `├─Name:` have no trailing colon
- **Total: 4206 tests** (4202 → 4206, +4)

---

## [v0.1.0] — 26-04-2026

Initial release of BOB — Bodyguard Of Bits.

### Architecture

- **Module** `bob/` — Python package; CLI entry point `bob` via `bob.__main__:main`
- **46 checks** organised across 9 security domains; each check produces typed `Finding` objects consumed by the scoring engine
- **Scoring engine** (`bob/scoring.py`) — weighted deductions per finding, clamped 0–10; 5 domain sub-scores (firewall, ssh, hardening, updates, file_perms)
- **i18n** (`bob/i18n.py`, `bob/locales/en.json`, `bob/locales/fr.json`) — all user-facing strings externalised; `--french` / `-d` switches locale at runtime
- **Audit profiles** (`bob/profiles.py`, `bob/data/profiles/`) — `server`, `workstation`, `desktop`, `docker`; each profile declares severity overrides and skipped sections
- **Plugin API** (`bob/plugin_checks.py`, `bob/registry.py`) — custom checks via `~/.config/bob/checks.d/`; custom service definitions via `~/.config/bob/services.d/`

### Security checks

#### Firewall
- `bob/checks/firewall.py` — UFW rules: duplicate rules, open-any rules, IPv6 coverage, default deny policy awareness
- `bob/checks/iptables_nftables.py` — CHECK 46: iptables/nftables audit when UFW is inactive; INPUT/FORWARD/OUTPUT policy; conntrack detection; nftables ruleset parsing
- `bob/checks/ipv6.py` — IPv6 consistency between UFW rules and sysctl
- `bob/checks/firewall_stack.py` — firewall stack detection (UFW/iptables/nftables/none); active stack reported in banner
- `bob/checks/ports.py` — port exposure analysis: public vs LAN vs loopback; service identification; ephemeral port filtering

#### SSH
- `bob/checks/ssh.py` — PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, X11Forwarding, MaxAuthTries, ClientAliveInterval, UsePAM, AllowTcpForwarding, key algorithm quality, ListenAddress, Banner

#### Kernel hardening
- `bob/checks/kernel_hardening.py` — 20+ sysctl parameters (net.ipv4/ipv6, fs.*, kernel.*); randomize_va_space, dmesg_restrict, kptr_restrict, ptrace_scope, etc.
- `bob/checks/kernel_modules.py` — risky filesystem and network modules (cramfs, freevxfs, jffs2, hfs, udf, dccp, sctp, rds, tipc)
- `bob/checks/secure_boot.py` — Secure Boot state via mokutil/efibootmgr
- `bob/checks/firmware.py` — fwupd pending updates; microcode package presence

#### Services
- `bob/checks/services.py` — 32 known services with risk classification; listens on expected ports; risk context shown per active service
- `bob/checks/services_state.py` — enabled+active systemd service audit; CRITICAL/HIGH installed-but-inactive → warning
- `bob/checks/docker.py` — Docker installation detection; UFW firewall bypass via iptables DOCKER chain
- `bob/checks/docker_audit.py` — daemon.json hardening; privileged containers; host network/pid/ipc; sensitive volume mounts; no-new-privileges
- `bob/checks/smtp.py` — SMTP server exposure; inet_interfaces; open relay risk

#### File permissions
- `bob/checks/file_perms.py` — world-writable files; /etc/passwd /etc/shadow /etc/sudoers permissions
- `bob/checks/suid_audit.py` — SUID/SGID audit with whitelist; targeted roots for performance

#### User accounts
- `bob/checks/user_accounts.py` — expired accounts (UID≥1000); locked accounts with recent logins
- `bob/checks/password_policy.py` — /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE); PAM pam_cracklib/pam_pwquality; PAM password history
- `bob/checks/umask.py` — system umask (/etc/profile, /etc/bash.bashrc, /etc/login.defs)

#### System
- `bob/checks/updates.py` — apt pending security updates (−2 flat); regular updates (INFO); unattended-upgrades compound (−1); kernel apt update check
- `bob/checks/logs.py` — UFW logging level (off/low/medium/high/full)
- `bob/checks/log_rotation.py` — logrotate configuration; /var/log/ufw.log size; log retention
- `bob/checks/auth_log.py` — failed login count from auth.log/journald; repeated failure patterns
- `bob/checks/ntp.py` — NTP sync state (systemd-timesyncd / chrony / ntpd)
- `bob/checks/fail2ban.py` — Fail2ban active; sshd jail enabled
- `bob/checks/rootkit.py` — rkhunter / chkrootkit presence and last scan age
- `bob/checks/auditd.py` — auditd active; audit rules present; key rules (privileged commands, sudoers changes)
- `bob/checks/file_integrity.py` — AIDE / Tripwire presence and last run
- `bob/checks/clamav.py` — ClamAV package; freshclam DB age; last scan age
- `bob/checks/mac_policy.py` — AppArmor (profiles loaded, enforce vs complain) / SELinux (enforcing vs permissive)
- `bob/checks/backup.py` — backup solution detection (restic, duplicati, borgbackup, rsync cron, timeshift)
- `bob/checks/disk.py` — SMART health (smartctl); partition usage; NVMe wear level
- `bob/checks/memory.py` — swap present; SSD swap wear; swappiness tuning
- `bob/checks/ssl_certs.py` — TLS/SSL certificate expiry scan (≤30 days → WARN, ≤7 → ALERT)
- `bob/checks/systemd_timers.py` — active system timers; missed timers; timer-unit security options
- `bob/checks/desktop_apps.py` — installed desktop applications (browsers, mail, etc.) on server profile
- `bob/checks/samba.py` — Samba hardening (map to guest, null passwords, min protocol, signing)
- `bob/checks/cron_audit.py` — world-writable cron scripts; pipe-to-shell patterns; /etc/cron.d format
- `bob/checks/ddns.py` — DDNS client activity (ddclient); reflected in internet exposure analysis

#### Network
- `bob/sysinfo.py` — public IP detection (3-provider fallback: ipify → ifconfig.me → icanhazip); IPv6 public address; network context (server/LAN/CGNAT/VPN); GeoIP2 optional
- `bob/checks/network_context.py` — network type classification; exposure context shown per finding
- `bob/checks/virtualization.py` — virtualization detection (KVM/VirtualBox/VMware/LXC/Docker)

### CIS benchmark mapping

- `bob/cis_refs.json` — 133 entries: `{"ref": "...", "code": "CIS:X.Y.Z"|null}`
  - 99 CIS Ubuntu 22.04 benchmarks (with `code: "CIS:X.Y.Z"`)
  - 4 CIS Docker benchmarks (with `code: "CIS Docker:X.Y"`)
  - 34 best-practice entries (with `code: null`)
- `bob/cis_refs.py` — `get_cis_ref(key)` / `get_cis_code(key)` — `_load()` with `lru_cache(maxsize=1)`
- `bob/display.py` — `[CIS:X.Y.Z]` injected inline in summary box per finding; full ref shown in `--verbose`
- `bob/explain.py` — `--explain KEY` TUI and direct-key mode; calls `get_cis_ref()` directly

### Output and formatting

- `bob/output.py` — terminal colored output; summary box; domain score bar chart; services panorama
- `bob/display.py` — finding line rendering; CIS code injection; score color; scope qualifiers (`[CRITICAL • INTERNET]`)
- `bob/json_output.py` — `--format=json` / `--json`
- `bob/csv_output.py` — `--format=csv`
- `bob/markdown_output.py` — `--format=markdown`
- `bob/report_markdown.py` — full markdown report
- `bob/html_output.py` — `--html` standalone HTML report

### Automation and scheduling

- `bob/cron.py` — `--install-cron` curses wizard; `--manage-cron` TUI; named jobs (`/etc/cron.d/bob-{name}`); email notification on exit code > 0; legacy cron detection
- `bob/manage_logs.py` — `--manage-logs` TUI; log directory management; score history sparkline
- `bob/webhook.py` — generic JSON webhook + Slack (auto-detected); non-fatal; UTC timestamps; domain scores included
- `bob/history.py` — score history appended to `~/.config/bob/history.jsonl`; `--history` sparkline
- `bob/domain_scores.py` — 5-domain 0–10 scores; bar chart; included in JSON/webhook output
- `bob/watch.py` — `--watch[=N]` polling loop; reruns full audit every N seconds (default 60)
- `bob/compare.py` — `--diff` baseline diff; delta-only display; baseline at `~/.config/bob/last_baseline.json`
- `bob/recurrence.py` — recurring finding tracker; consecutive appearance count per key

### CLI and configuration

- `bob/cli.py` — argument parser; 7 sections; short options (-V -v -d -j -C -p -e -D -w -o); `--check`/`--skip`; `--format`; `--output-dir`; `--target`; `--min-level`
- `bob/completion.py` — `--install-completion`; bash completion script at `/etc/bash_completion.d/bob`
- `bob/config.py` — persistent key=value store at `~/.config/bob/config.conf`
- `bob/ignore.py` — `--ignore`/`--show-ignored`; `~/.config/bob/ignore.yml`
- `bob/fixes.py` — `--fix` dry-run UI; `--apply` execution

### Tests

4200 tests across 65 test files.

| File | Coverage |
|------|----------|
| `test_cis_refs.py` | `cis_refs.py` / `cis_refs.json` — 39 tests |
| `test_iptables_nftables.py` | CHECK 46 — iptables/nftables |
| `test_firewall.py` | UFW rules audit |
| `test_ssh.py` | SSH configuration checks |
| `test_hardening.py` | Kernel hardening sysctl |
| `test_kernel_modules.py` | Kernel module audit |
| `test_services.py` | Service registry + risk |
| `test_services_state.py` | Service state audit |
| `test_docker.py` · `test_docker_audit.py` | Docker checks |
| `test_ports.py` · `test_exposure.py` | Port exposure |
| `test_scoring.py` · `test_domain_scores.py` | Scoring engine |
| `test_explain.py` · `test_display_explain_hint.py` | --explain TUI |
| `test_cli.py` · `test_exit_codes.py` | CLI + exit codes |
| `tests/helpers.py` | Shared test utilities |
| *(+ 50 additional test files)* | Full coverage across all modules |
