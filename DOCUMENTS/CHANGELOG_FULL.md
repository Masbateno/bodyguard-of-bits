*[Lire en français](CHANGELOG_FULL_FR.md)* · *[TL;DR](../CHANGELOG.md)*

# BOB — Bodyguard Of Bits — Changelog

All notable changes to this project are documented here.

---

## [v0.4.1] — 2026-05-14

**Phase 2 of the distro-ready roadmap — architectural decoupling.** Three zones tackled: `--offline` finalization, curses isolation under `bob/tui/`, and locale-independent finding/deduction representation via additive `template_vars`. Plus a post-review hardening pass on `bob/formatter.py` (API tightened, edge-case tests). All changes are non-breaking (additive). 4449/4449 tests (+19).

The Phase 2 roadmap targets a `bob-core` Debian package that can be installed without curses and without locale text baked into the JSON output. This release lays the groundwork without breaking the existing API.

---

### Zone 2.1 — `--offline` strict mode finalized

**Files:** `tests/test_webhook.py`

#### Problem

The `-o` / `--offline` flag has been present since v0.4.0 and was already gating the two network-touching sites (`bob.sysinfo.get_public_ip` HTTP, `bob.webhook.send_webhook` POST). What was missing for a real distro-ready audit:

- An end-to-end inventory of all subprocess and library calls that could conceivably touch the network, with explicit "this is local, no gating needed" / "this is gated by `--offline`" classification.
- Integration tests that pin the contract: if a future refactor accidentally drops the offline gate, the test suite fails immediately.

#### Implementation

Network audit (no code changes — survey only):

| Site | Verdict |
|---|---|
| `bob/sysinfo.py:158` `urllib.request.urlopen` (`get_public_ip`) | ✅ gated by `offline=True` |
| `bob/webhook.py:send_webhook` HTTP POST | ✅ gated by `__main__.py:277 if _webhook_url and not config.offline` |
| `bob/checks/kernel_modules.py` `apt-cache policy` / `apt list --upgradable` | ✅ local cache reads, no network |
| `bob/checks/firmware.py` `fwupdmgr get-updates` | ✅ local cache read |
| `bob/checks/auth_log.py` `journalctl` | ✅ local |
| `bob/checks/ssl_certs.py` `openssl x509 -in <file>` | ✅ local file |
| `bob/checks/firewall_stack.py`, `bob/checks/ports.py`, etc. | ✅ all local (`ss`, `iptables`, `nft`, …) |

Conclusion: no missed network sites, the existing `--offline` plumbing is complete.

New tests in `tests/test_webhook.py`:

- `TestCLIWebhookParsing.test_webhook_with_offline_flag_parses` — CLI parser accepts `--offline --webhook=URL` together (they are not mutually exclusive at parse time; the offline gate is enforced at runtime).
- `TestOfflineModeNetworkContract.test_offline_skips_webhook_send` — mirrors the `__main__.py:277` decision branch to lock in the behavior; if the condition changes, the test fails.
- `TestOfflineModeNetworkContract.test_get_public_ip_offline_skips_urllib` — monkeypatches `sysinfo.urllib` with an exploding stub; if any `urlopen` is reached in `offline=True` mode, the test raises AssertionError.

#### Design notes

Why "mirror the decision branch" rather than test the full `_run()` orchestration: the audit pipeline pulls dozens of dependencies (filesystem, subprocess, locale, ScoreEngine, …) — testing the integration end-to-end would mock half the universe. Mirroring the 2-line offline gate as a smoke test gives the same coverage at a fraction of the maintenance cost. If the `__main__.py:277` line ever changes, both the production line AND the test will be touched in the same commit, surfacing the contract change explicitly.

---

### Zone 2.2 — `bob/tui/` curses subpackage

**Files:** new `bob/tui/__init__.py`, `bob/cron_ui.py` → `bob/tui/cron.py` (git mv), `bob/cron.py` (import sites), `DOCUMENTS/README_DEV.md` (FR + EN)

#### Problem

For a `bob-core` Debian package that runs in minimal containers (no curses), the rest of `bob.*` must remain importable without curses installed. The `import curses` calls were already lazy (inside functions) but the file `bob/cron_ui.py` lived at the top level of `bob.*`, suggesting it was part of the core module list. A packager reading the project structure could not tell that `cron_ui` was optional.

#### Implementation

- New `bob/tui/__init__.py` documents the subpackage's policy: curses imports allowed at top of module here (we're in TUI-land), the rest of `bob.*` must NEVER import from `bob.tui.*` at module load time — only lazily inside functions.
- `git mv bob/cron_ui.py bob/tui/cron.py` (history preserved).
- `bob/cron.py` updated:
  - Module docstring `Curses TUI code lives in bob.cron_ui.` → `Curses TUI code lives in bob.tui.cron.`
  - 2 lazy import sites: `from bob.cron_ui import _run_install_cron_curses` / `_run_manage_cron_curses` → `from bob.tui.cron import ...`
- `setuptools.packages.find` config (`include = ["bob*"]`) already covers `bob.tui` automatically — no `pyproject.toml` change needed.
- `DOCUMENTS/README_DEV.md` + FR: structure tree updated, `cron_ui.py` row replaced with `tui/cron.py` row carrying a note about the v0.4.1 extraction.

#### Tests

No new tests required — the existing 4430 tests already exercise the import path. The full suite remained 4430/4430 after the move (before adding Zone 2.3 tests), proving the rename is transparent.

#### Design notes

- **Why a subpackage rather than a separate distribution.** Splitting into `bob-core` + `bob-tui` distributions on PyPI is a packaging concern, not a code concern. The current `bob` distribution still ships everything; the subpackage layout is the foundation that lets a future Debian packager split the two without touching the code.
- **`explain.py`, `manage_logs.py`, `cron.py` not moved.** Those modules mix business logic and TUI bits with curses imports already lazy. Moving them would require a bigger split (separate the curses sections per-file). Out of scope for this release — they remain in `bob/` for now.

---

### Zone 2.3 — Locale-independent findings via additive `template_vars`

**Files:** `bob/scoring.py`, `bob/json_output.py`, new `bob/formatter.py`, `bob/checks/ssh.py`, `bob/checks/hardening.py`, `bob/checks/firewall.py`, new `tests/test_formatter.py`, `tests/test_json_schema.py`

#### Problem

Until v0.4.0, BOB's `Finding.message` and `Deduction.reason` were strings already formatted in the active locale (`message=_t("ssh.weak_ciphers", ciphers="aes128-cbc")`). External consumers of the JSON output had no way to:
- Render the same finding in a different locale.
- Match findings by their stable semantic key without parsing the localized message string.

`Finding.key` (added in Phase 1) gave a stable name, but the variable values that were interpolated into the i18n template were lost: only the rendered string survived. A client wanting "the list of ciphers reported as weak" had to parse the localized `message`.

The Phase 2 goal is `bob.core` *pure* — no `print()`, no `_t()`, no curses. This release takes the additive first step: expose `(key, template_vars)` everywhere alongside the legacy `message`/`reason`, so external clients can reconstruct the localized text from the structured parts without touching the formatted string.

#### Implementation

##### Two new dataclass fields

```python
@dataclass
class Deduction:
    reason:        str
    points:        int
    context:       str  = "local"
    key:           str  = ""
    template_vars: dict = field(default_factory=dict)   # NEW

@dataclass
class Finding:
    level:         FindingLevel
    message:       str
    detail:        str = ""
    nature:        str = ""
    cmd:           str = ""
    cmd_type:      str = "fix"
    note:          str = ""
    key:           str = ""
    template_vars: dict = field(default_factory=dict)   # NEW
```

The name `template_vars` is deliberate: it documents that the dict contains the variables passed to the i18n template's `.format(**kwargs)` call. We avoided `context` (already taken by `Deduction.context: str` meaning network scope — `"local"` / `"public"`) and `vars`/`params` (too generic).

##### Convenience helpers accept `template_vars=`

`CheckResult.add_finding`, `.ok`, `.info`, `.warn`, `.alert`, `.add_deduction` all gain an optional `template_vars=None` kwarg. When None, the dataclass field defaults to `{}` (empty dict). Legacy call sites need ZERO changes; new call sites can opt into structured representation.

##### New module `bob.formatter`

`format_finding(finding, lang=None) -> str` and `format_deduction(deduction, lang=None) -> str` implement the locale-independent rendering. Resolution order:

1. If `key` is set AND `template_vars` is non-empty → render `_t(key, **template_vars)`.
2. If `key` is set but no template_vars → render `_t(key)` if it resolves cleanly.
3. Otherwise fall back to `finding.message` / `deduction.reason` (legacy path).

The fallback in step 3 makes the formatter 100% backward-compatible: a check that hasn't been migrated still works exactly as before.

The `lang` parameter is reserved (`_ = lang`) for a future API where callers can render the same finding in multiple locales without flipping the process-wide locale. Today, `bob.i18n.init()`'s active locale is used. Defining the parameter now keeps a future enhancement non-breaking.

##### Three pilot checks migrated

To demonstrate the pattern and verify that the field plays well with real data, three call sites in three different check files were migrated:

- **`bob/checks/ssh.py`** — `_check_host_keys` (4 sites): `ssh.host_key_dsa` (DSA host key), `ssh.host_key_dsa_reason` (matching deduction), `ssh.host_key_rsa_short` (RSA < 4096 bits with `bits=hk.rsa_bits`), `ssh.host_key_ok` (algorithm fine, with `type=hk.key_type.upper()`).
- **`bob/checks/hardening.py`** — `tcp_syncookies_ok` with `value=snapshot.tcp_syncookies`.
- **`bob/checks/firewall.py`** — `firewall.logging_ok` and `firewall.logging_verbose` with `level=level`.

In every case, the existing `message=_t("key", **vars)` is preserved (backward compat) and `template_vars={...vars...}` is added in parallel. Both paths now coexist: the legacy `message` is what the terminal displays today, the new `template_vars` is what a future locale-independent client (or v1.0 `bob.core` without `_t()`) will use.

##### `template_vars` exposed in JSON output

`bob/json_output.py` now serializes `template_vars` on every deduction and every finding (full mode):

```json
{
  "deductions": [
    {
      "reason": "DSA host key: ssh_host_dsa_key",
      "points": 1,
      "key": "ssh.host_key_dsa",
      "template_vars": {"name": "ssh_host_dsa_key"}
    }
  ]
}
```

The field is always present (empty dict for legacy checks that don't fill it). This is additive — the existing `SCHEMA_V1_REQUIRED_KEYS` strict-set test was extended (not rewritten) to verify the new field's presence.

#### Tests

`tests/test_formatter.py` (new, 10 tests):

| Class | Coverage |
|---|---|
| `TestFormatFinding` | 5 tests: key + template_vars renders via i18n, key alone returns template, no key falls back to message, unknown key falls back, empty input edge case |
| `TestFormatDeduction` | 2 tests: key + template_vars renders, no key falls back to reason |
| `TestLocaleRoundtrip` | 1 test: same `(key, template_vars)` yields different text in `fr` vs `en` — the whole point of the refactor |
| `TestBackwardCompatibility` | 2 tests: legacy findings (no key, no template_vars) pass through unchanged |

`tests/test_json_schema.py` (+2): `test_each_deduction_has_template_vars_field`, `test_each_finding_has_template_vars_field`.

`tests/test_webhook.py` (+3): offline mode network contract (covered in Zone 2.1 above).

Total: **+15 tests** (4430 → 4445).

#### Design notes

- **Option B vs Option A.** Option B is what this release ships: additive new field, full backward compat, both `message` and `template_vars` coexist. Option A (full breaking: drop `message`, only `template_vars` allowed) is deferred to v0.5.0+ when all 40 checks have been migrated and the JSON schema can ship a v2. The Phase 1 plugin-file wrapper (`schema_version` field) already pre-empts that migration.
- **Why three pilots, not all 40 at once.** Migrating every check would be ~500 lines mechanical edits — possible but error-prone, and the JSON schema test now enforces `template_vars` is always present so a botched migration would show up immediately. The pattern is documented through the pilots; the rest can come incrementally in subsequent point releases (v0.4.2, v0.4.3, …).
- **Empty dict ≠ None.** We chose `field(default_factory=dict)` rather than `Optional[dict]` to keep JSON output uniform: every entry has `template_vars`, the difference between "legacy check" and "migrated check" is the dict's size, not its presence/absence. Simpler client logic.

---

### Hardening pass — `bob/formatter.py` review

**Files:** `bob/formatter.py`, `bob/i18n.py`, `tests/test_formatter.py`

#### Problem

A post-implementation review of `formatter.py` (external ChatGPT analysis prompted by the user) flagged four legitimate API/architecture issues on a module that is about to become a stable public contract for downstream packagers:

1. **Mendacious `lang=` parameter.** `format_finding(finding, lang=None)` exposed a locale-override parameter that was a silent no-op (`_ = lang` — the global `bob.i18n.t()` state always won). External callers passing `lang="fr"` would still get the process locale and have no indication. Trap for distro packagers who pipe outputs through their own pipeline.
2. **Fragile `startswith("[")` missing-key detection.** `_render_key` returned `"[key]"` (the `bob.i18n.t()` sentinel for missing keys) and the caller checked `startswith("[")` to detect that. Couples the formatter to an undocumented `t()` convention; a future change to that sentinel would silently break the formatter.
3. **`except (KeyError, TypeError, ValueError)` too broad.** Catching `TypeError` and `ValueError` hides real Python bugs (e.g. an `_t()` API change). Should only swallow what's truly expected (placeholder mismatch from `str.format`).
4. **"Reproducible" wording in docstring overpromises** what the module can deliver while ~40 checks still use the legacy `message=`-only path.

#### Implementation

1. **`lang=` parameter removed** (Option A from the review). Adding it back when `bob.i18n` becomes pure (v0.5.x along with full `bob.core` extraction) is preferable to keeping a lying signature today. The signature for v0.4.1 is now `format_finding(finding) -> str` and `format_deduction(deduction) -> str`.

2. **New `bob.i18n.try_t(key, **kwargs) -> str | None`** added: clean missing-key detection without parsing the `"[key]"` sentinel. Behavior:
   - Returns `None` for missing keys (in active locale and EN fallback).
   - Returns rendered string on success.
   - Propagates `KeyError` from `str.format()` when a required placeholder is missing — caller responsibility, not a runtime degradation.
   The legacy `bob.i18n.t()` keeps returning `"[key]"` for the rest of the codebase that relies on that contract; only `formatter` uses the new function.

3. **Exception handling narrowed in `_try_render`**: no more catch-all. `try_t` returns `None` for missing keys cleanly; `KeyError` from `str.format()` (missing placeholder = check-side bug) propagates so the bug surfaces immediately instead of silently degrading to `finding.message`.

4. **Docstrings rewritten**: "reproducible" → "progressively reconstructible" + a "Current state (v0.4.1)" section spelling out exactly what's reproducible today and what isn't. The coupling between `Finding.key` / `--explain` key / i18n key / JSON matching key (= a textual ABI) is now explicitly acknowledged with a pointer to `bob/explain.py`'s freeze policy.

#### Tests

`tests/test_formatter.py` extended from 10 to 14 tests (+4 in new `TestFormatterEdgeCases` class):

| Test | Coverage |
|---|---|
| `test_empty_template_vars_with_placeholder_template_returns_raw` | Edge case: empty `template_vars` + key whose template has placeholders → raw template returned with literal `{placeholders}` intact (consistent with `i18n.t()` behavior, surfaces the bug visually) |
| `test_partial_template_vars_raises_keyerror` | Non-empty `template_vars` missing a required placeholder → `KeyError` propagates (no silent fallback) |
| `test_mismatched_key_vs_message_uses_key` | Key path wins when it resolves cleanly, even if `message` says something different (the structured representation is authoritative once populated) |
| `test_empty_finding_message_with_no_key` | Returns `""` (not `None`) when neither key nor message is set — preserves the documented "always returns a string" contract |

Total v0.4.1 test count: **4445 → 4449** (+4 from hardening pass).

#### Design notes

- **Why surface `KeyError` instead of falling back to `message`.** A missing placeholder means the check declared a key whose template needs a variable the check did not provide. Silently using `finding.message` would hide a check-side bug and leave clients with no signal. Raising forces the bug to be visible in the test suite where it should be caught.
- **Why `try_t` and not refactoring `t()`.** The legacy `t()` returning `"[key]"` is relied upon throughout the codebase for "show but don't crash" rendering. Changing its return contract would ripple through 600+ call sites. Adding `try_t` as a sibling function gives the formatter a clean missing-key signal without disturbing existing semantics.
- **Why remove `lang=` rather than fix it.** Properly implementing per-call locale switching requires making `bob.i18n` reentrant (an instance object rather than module-level state) — work that belongs in v0.5.x with the full `bob.core` refactor. Exposing a parameter today that lies about being implemented is worse than not exposing it.

---

### Roadmap context

After v0.4.1, the Phase 2 plan stands at:

| Item | Status |
|---|---|
| 2.1 `--offline` strict | ✅ done (verified + tested) |
| 2.2 curses isolation (`bob/tui/`) | ✅ done (cron_ui moved, lazy imports kept) |
| 2.3 core / i18n decoupling — Option B (additive) | ✅ done (3 pilot checks + formatter + JSON) |
| 2.3 core / i18n decoupling — Option A (breaking) | ⏳ v0.5.0+ |
| Vague 2 schema (typed ports, `port_resolution`, etc.) | ⏳ v0.5.0+ |
| Phase 3 (man pages, debian/, AppArmor profile, SECURITY.md) | ⏳ future |

Distro readiness levels:

- **AUR / COPR community packaging** — viable now (v0.4.0 already qualified)
- **Debian unstable / Fedora COPR official** — target ~6 months post-v0.4.1
- **Debian main / Fedora main** — 12–18 months minimum (requires sustained contract stability + Phase 3)

---

## [v0.4.0] — 2026-05-14

Phase 1 of the distro-ready roadmap (see `project_distro_roadmap` memory) — five public-API contracts frozen so that scripts, dashboards, and downstream packagers can rely on stable behavior across versions. No new features, no breaking changes — additive only. 4405/4405 tests (+57). Plus a small UX fix on the unchanged-score display.

The roadmap targets in order of difficulty:
- AUR / COPR community packaging — viable now
- Debian unstable / Fedora COPR official — ~6 months post-v0.4.0
- Debian main / Fedora main — 12–18 months minimum (requires sustained contract stability)

This release ticks the first 5 boxes of Phase 1: exit codes, locale fallback, JSON output contract, --explain key freeze, and plugin schema. Phase 2 (architectural decoupling: pure `bob.core`, isolated `bob.tui`, strict `--offline`) is next on the roadmap.

---

### Stable contract — Exit codes documented as public API

**Files:** `bob/__main__.py`, `bob/cli.py`, `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problem

The 5 exit codes (`0`/`1`/`2`/`3`/`4`) were defined as constants in `bob/__main__.py` and used consistently in `_run()`, but had no formal API status. The `--help` text documented `0`/`1`/`2`/`3` but **omitted `4`** (`EXIT_TARGET_MISSED`). README_TECH had a table but didn't promise stability.

External scripts (CI pipelines, cron wrappers, monitoring agents) need a contract: a code's value and meaning must not drift across versions.

#### Implementation

- Added a "STABLE PUBLIC API" docstring block above the exit-code constants explicitly stating they are part of BOB's public contract — no removal, no semantic shift within a major version, additions only.
- Added missing `4` to `--help` ("EXIT CODES" section) along with a pointer to README_TECH.
- Promoted the README_TECH section: added a quote block stating the stability promise, expanded the table with the constant names (`EXIT_OK`, …), and added a code snippet showing how to import them programmatically.
- Mirrored in README_TECH_FR.

The 18 existing tests in `tests/test_exit_codes.py` already lock in the values and the decision logic — they now serve as the contract enforcement.

#### Design notes

The `_run()` function's exit-code decision (target → alerts → warnings → ok) is unit-tested via `_decide_exit()`, a faithful copy isolated from the audit pipeline. This is the canonical mapping: any future change must update both copies and bump tests deliberately.

---

### Stable contract — Locale auto-detection from POSIX `$LANG`

**Files:** `bob/i18n.py`, `bob/cli.py`, `tests/conftest.py`, `tests/test_i18n.py`, `tests/test_cli.py`, `bob/cli.py` (--help), `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problem

BOB's interface defaulted to English unless `--french` or `--lang=fr` was explicitly passed. Any other Unix tool (`man`, `git`, `apt`, `gcc`, …) honors `$LANG` / `$LC_*` automatically. A French user lab-typing `sudo bob` got English; this was surprising and didn't match POSIX expectations.

For distro packaging, this matters even more: a Debian package shipping BOB must integrate seamlessly with the system locale. A user with `LANG=fr_FR.UTF-8` should get French output without flag gymnastics.

#### Implementation

New function `bob.i18n.detect_system_lang() -> str`:

```python
def detect_system_lang() -> str:
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(var, "").strip()
        if not value or value in ("C", "POSIX", "C.UTF-8", "C.utf8"):
            continue
        prefix = value.split(".", 1)[0].split("@", 1)[0]
        lang = prefix.split("_", 1)[0].lower()
        if lang in SUPPORTED_LANGS:
            return lang
        return DEFAULT_LANG
    return DEFAULT_LANG
```

Probe order matches POSIX (`LC_ALL` overrides `LC_MESSAGES` overrides `LANG`). Empty values fall through to the next candidate. `C` / `POSIX` / `C.UTF-8` / unsupported languages → fallback to `DEFAULT_LANG = "en"`.

`bob.cli.parse_args()` now tracks whether the user passed `--lang=` / `--french` via a local `lang_explicit` flag. After argv parsing, if the flag is still `False`, `config.lang = detect_system_lang()`. Explicit flags always win — the detection is a default, not an override.

`tests/conftest.py` (new): an autouse fixture sets `LC_ALL=C`/`LANG=C` before every test, so locale-dependent CLI defaults resolve predictably regardless of the developer's host locale. Tests that need a specific locale set it explicitly with `monkeypatch.setenv()`.

#### Tests

- 12 new tests in `TestDetectSystemLang` class: empty env, `C`, `POSIX`, `C.UTF-8`, `fr_FR.UTF-8`, `fr_BE`, `fr_FR@euro`, `en_US.UTF-8`, unsupported `ja_JP`/`de_DE`/`es_ES`/`zh_CN`, `LC_ALL` overrides, `LC_MESSAGES` overrides, empty `LC_ALL` falls through.
- 4 integration tests in `tests/test_cli.py`: `--french` overrides system locale, `--lang=en` overrides system locale, default uses `fr` when system locale is French, default uses `en` when `LANG=C`.

#### Design notes

The decision to default to system locale (instead of always `en`) is a UX improvement, not a breaking change for any documented contract — `--lang=en` continues to work and forces English explicitly. The change is documented in `--help` ("default: detected from $LANG, fallback en") and in both README_TECH variants. Existing CI/scripts that don't set `LC_ALL` see no change because `LANG=C` falls back to `en`.

---

### Stable contract — JSON output schema documented + `key` field exposed

**Files:** `bob/json_output.py`, `tests/test_json_schema.py` (new), `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problem

The `--json` output had `"schema_version": "1"` since v0.2.x but no formal contract: top-level keys could disappear or rename without notice, the schema had no test enforcement, and clients had to match findings via the localized `message` / `reason` strings (which differ between `en` and `fr`).

For distro adoption this is a blocker: a Debian-packaged dashboard parsing BOB output cannot be expected to switch matching logic per-locale, nor can it survive silent schema drift across BOB releases.

#### Implementation

Added stability docstring at the top of `bob/json_output.py` formalizing the rules:

> - Top-level keys never disappear, never get renamed, never change semantics within a given major `schema_version`.
> - New top-level keys MAY be added in any release; clients should ignore unknown keys.
> - Nested dicts follow the same rule.
> - Breaking changes bump `schema_version` to a new major (`"2"`, `"3"`…).

Two new module-level constants make the contract testable:

```python
SCHEMA_V1_REQUIRED_KEYS = frozenset({
    "schema_version", "version", "host", "timestamp", "score", "score_max",
    "risk", "network_context", "public_ip", "alerts", "warnings",
    "deductions", "domain_scores",
})
SCHEMA_V1_FULL_KEYS = frozenset({
    "findings", "services", "open_ports", "firewall_stack",
    "hardening", "ipv6",
})
```

Added `"key": d.key` to each `deductions[]` entry and `"key": f.key` to each `findings[]` entry. These are stable dotted i18n keys (`firewall.logging_off`, `ssh.password_auth`, …) that never change across locales and never rename without an alias entry — clients should match on `key`, not on `reason`/`message`.

`DOCUMENTS/README_TECH.md` (and FR) gain a full "JSON output schema" section: stability promise quoted, complete top-level key table with types and descriptions, structure of `deductions[]` / `domain_scores` / full-mode keys, locale-independent matching example with `jq`.

#### Tests

`tests/test_json_schema.py` (new, 15 tests, 4 classes):

- `TestSchemaVersion` — schema_version is a string, currently `"1"`.
- `TestRequiredKeysAlwaysPresent` — required keys in short and full mode, no full-only keys leak into short mode.
- `TestFieldTypes` — `score`/`score_max`/`alerts`/`warnings` are int, `risk` is string, `timestamp` is ISO 8601.
- `TestStableKeysExposed` — every deduction and finding has a `key` field, dotted-path format.
- `TestDomainScoresStructure` — `domain_scores` is a dict-of-dicts with `score` (int) and `label` (str).

#### Design notes

The `key` field exposure is the foundation for the Phase 2 architectural decoupling: once `Finding.message` is decoupled from `_t()` (planned next phase), the JSON output will become fully locale-independent — clients can format messages themselves from the keys.

---

### Stable contract — `--explain` alias map + freeze policy

**Files:** `bob/explain.py`, `tests/test_explain.py`

#### Problem

The 112 `--explain` keys (e.g. `ssh.password_auth`, `firewall.logging_off`, `kernel_hardening.aslr_disabled`) are also used as `Finding.key` and `Deduction.key` — they form a public namespace that scripts and dashboards match on. Renaming any key was a silent breaking change.

#### Implementation

Added an explicit "STABLE PUBLIC API — `--explain` KEY FREEZE POLICY" section to the module docstring stating four rules: no removal, no semantic shift, renames go through `EXPLAIN_KEY_ALIASES`, additions are free.

Introduced `EXPLAIN_KEY_ALIASES: dict[str, str]` as the migration mechanism for renames. Currently empty — no key has been renamed yet. The map exists so any future rename has a documented, tested path: add `"old_name": "new_name"` here and clients calling `bob --explain old_name` (or matching `Finding.key == "old_name"` in JSON) keep working indefinitely.

`normalize_key()` was extended to consult the alias map after path-segment stripping:

```python
def normalize_key(key: str) -> str:
    m = _NORMALIZE_RE.match(key)
    if m:
        key = f"{m.group(1)}.{m.group(2)}"
    return EXPLAIN_KEY_ALIASES.get(key, key)
```

#### Tests

6 new tests in `tests/test_explain.py`:

- `TestExplainKeyAliases` (5 tests): alias map is dict, alias targets are valid canonical keys, alias keys are NOT in the canonical set (no overlap), `normalize_key()` resolves aliases, passthrough when no alias.
- `TestExplainKeyFreezePolicy` (1 test): a frozen subset of 16 load-bearing keys (`ssh.password_auth`, `ssh.permit_root_login`, `firewall.logging_off`, `kernel_hardening.aslr_disabled`, …) must always be in `EXPLAIN_KEYS` — failure points to either restoring them or registering an alias.

#### Design notes

The freeze policy is intentionally per-key (not per-group): groups can be reorganised in `_EXPLAIN_GROUPS` without breaking any contract, only individual keys are sticky.

---

### Stable contract — Plugin services formal JSON Schema

**Files:** `bob/data/schemas/service.schema.json` (new), `bob/data/schemas/services-list.schema.json` (new), `pyproject.toml`, `bob/registry.py`, `tests/test_services_schema.py` (new), `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problem

Service definitions (`bob/data/services.json` + user plugins in `~/.config/bob/services.d/`) had a hand-rolled validator in `Service.from_dict()` (Python-only, distributed across 36 lines). Distro packagers and plugin authors had no machine-readable contract: the rules (required fields, regex for ports, enum for risk, identifier rules for `config_key`) had to be reverse-engineered from the Python code or by trial and error.

#### Implementation

Two Draft 2020-12 JSON Schema files:

- **`service.schema.json`** describes a single service entry (the dict passed to `Service.from_dict()`):
  - `additionalProperties: false` (no unknown fields)
  - 7 required fields (`id`, `label`, `packages`, `services`, `ports`, `risk`, `config_key`)
  - Strict patterns: `id` is `^[a-zA-Z][a-zA-Z0-9_-]*$`, ports are `^[1-9][0-9]{0,4}/(tcp|udp)$`, `config_key` is a Python identifier
  - `risk` is enum `{low, medium, high, critical}`
  - Conditional via `allOf` / `if/then`: when `config_key="fixed"`, `ports` must have `minItems: 1`
  - `detection` (optional) with `binary` / `snap` / `config_files` arrays
- **`services-list.schema.json`** wraps the array form (the entire `services.json` file or a user plugin file).

Schemas shipped via `package_data` so they're available at `bob/data/schemas/*.json` after pip install — any external tooling (`check-jsonschema`, `ajv`, IDE plugins) can validate user plugins.

The Python validator in `Service.from_dict()` remains the runtime source of truth — **zero added runtime dependency**. The JSON Schema mirrors it for external tooling.

`bob/registry.py` `Service` class docstring now points to the schema file as the formal contract.

`DOCUMENTS/README_TECH.md` (and FR) gains a "Service plugin schema" subsection with a complete example and an explanation of required vs optional fields. The pre-fix note about `Path.home()` resolving to `/root` is also updated to reflect v0.3.6's `get_user_home()` fix.

#### Tests

`tests/test_services_schema.py` (new, 20 tests, 5 classes):

- `TestSchemasAreWellFormed` — schemas pass Draft 2020-12 self-validation, have proper `$id`/`title`.
- `TestBundledServicesMatchSchema` — bundled `services.json` validates entry-by-entry, IDs are unique.
- `TestValidPluginSamples` — 3 sample valid plugins (minimal fixed, with detection block, user config_key).
- `TestInvalidPluginSamples` — 8 rejection cases (missing required field, invalid risk, malformed port, port 0, port > 65535 via Python, unknown field, fixed without ports, ID with spaces, empty binary string).
- `TestSchemaPythonParity` — what the schema accepts is also accepted by `Service.from_dict()`, what fails Python is also caught by the schema.

`jsonschema` is a test-only dependency, not runtime — uses `pytest.importorskip` so the test file simply skips on systems where it's not installed.

#### Design notes

The port-range constraint (1–65535) is enforced by Python only — the schema's regex permits 1–99999 for simplicity. Documented in the schema's `description`. Acceptable trade-off: the `Service.from_dict()` parity test ensures invalid ports are rejected at runtime; external linters get a "good enough" warning that catches obvious mistakes (port 0, decimals, non-numeric strings).

The `binary` field accepts both binary names (resolved via `$PATH`) and absolute paths — the bundled `services.json` uses both forms (e.g. `"in.telnetd"` for telnet, `"/usr/sbin/postfix"` would also be valid).

---

### Hardening — Plugin schema rewritten after external review

**Files:** `bob/data/schemas/service.schema.json`, `bob/data/schemas/services-list.schema.json`, `bob/data/schemas/plugin-file.schema.json` (new), `bob/data/services.json`, `bob/registry.py`, `tests/test_services_schema.py`

#### Problem

An external review (ChatGPT analysis prompted by the user) flagged 10 issues with the JSON Schema introduced earlier in this release. Five of them were real contract leaks that would mislead distro packagers and external linters; this section addresses them. The remaining five (typed `ports: [{port,proto}]`, `port_resolution` object replacing `config_key` enum-vs-identifier mix, multi-PM `packages: {apt:[],dnf:[]}`, typed `binary` union, plugin-file metadata wrapper) are breaking changes deferred to schema v2 (planned for v0.5.0).

The five fixed in this release:

1. **Description promises that the schema can't validate.** The previous version stated "must be unique across all loaded services" and "mirrors `Service.from_dict()` validation" — both lies. JSON Schema cannot enforce cross-document uniqueness, and the schema only mirrored a *subset* of Python validation (notably missing the reserved-keyword check and the strict 1–65535 port range).
2. **Port regex deliberately lax** (`^[1-9][0-9]{0,4}/(tcp|udp)$` permitted `99999/tcp`). A schema-valid plugin could fail at runtime — broke the "schema-valid == application-valid" contract.
3. **No `$defs` factorization** — repeated string patterns scattered across properties.
4. **Missing business constraints** — `config_key="auto"` without `config_files` was valid, an empty `detection: {}` was valid, and a plugin with `packages: []`, `services: []`, no `detection` was valid (and undetectable at runtime).
5. **No `schema_version` in plugin files** — impossible to gate future schema migrations cleanly.
6. **`$id` pointed at `github.com/.../blob/main/...`** — unstable URL (HTML page, branch-dependent, not raw, not versioned).

#### Implementation

**`service.schema.json`** rewritten with:

- **`$defs` block** factorizing 6 reusable sub-schemas: `Identifier`, `PythonIdentifier`, `PackageName`, `SystemdUnit`, `PortProto`, `BinaryRef`, `AbsolutePath`. Each carries an explicit description noting v2-planned changes (typed ports, typed binary union).
- **Strict port regex** `^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})/(tcp|udp)$` enforcing exactly 1–65535. Schema-valid now equals Python-valid.
- **Clear scope description** stating which invariants the schema enforces vs which are runtime-only (cross-service uniqueness, Python reserved-keyword exclusion).
- **3 `allOf` business constraints** via `if/then` and `anyOf`:
  1. `config_key="fixed"` requires `ports.minItems: 1` (already present).
  2. `config_key="auto"` requires `detection.config_files.minItems: 1` (new — without it, auto-detection has nothing to parse).
  3. Service must be detectable: at least one of `packages`, `services`, or `detection.{binary|snap}` non-empty (new — prevents loading invisible services).
- **`detection.minProperties: 1`** — empty detection blocks (`detection: {}`) rejected.
- **Versioned `$id`** pointing at `raw.githubusercontent.com/.../v0.4.0/...` — stable, raw, version-pinned.

**`plugin-file.schema.json`** (new) describes the two accepted shapes for `~/.config/bob/services.d/*.json`:

```json
[ { ...service... }, { ... } ]
```

…or:

```json
{
  "schema_version": 1,
  "services": [ { ...service... } ]
}
```

The wrapper exists so future schema migrations (v2 typed ports, etc.) can be gated explicitly via `schema_version`. Currently only `schema_version: 1` is accepted; reserved fields like `metadata` / `disabled` are rejected today and earmarked for future versions.

**`bob/registry.py`**: new helper `_extract_plugin_entries(raw, plugin_name) -> list | None` consumes either shape. The constant `_CURRENT_PLUGIN_SCHEMA_VERSION = 1` gates: higher versions are rejected with a "upgrade BOB or downgrade the plugin" warning so users get a clear hint instead of silent half-loading. Lower or non-integer versions are also rejected. The legacy raw-array path is unchanged — backward compatibility preserved.

**`bob/data/services.json`**: 4 bundled services had a `detection: {binary: [], snap: [], config_files: []}` block that added zero signal. Removed entirely. `postgresql` and `syncthing` had `config_key="auto"` without `config_files` (functionally equivalent to `fixed`) — migrated to `config_key="fixed"` to match reality.

#### Tests

`tests/test_services_schema.py` extended from 20 to 42 tests (+22):

- `TestInvalidPluginSamples` updated: `test_port_above_65535_rejected_by_schema` (no longer Python-only), plus boundary tests `test_port_65535_accepted` / `test_port_65536_rejected`.
- `TestBusinessConstraints` (new, 7 tests): `auto` without `config_files` rejected, `auto` with empty array rejected, `auto` with paths accepted, undetectable service rejected, binary-only / snap-only detection accepted, empty `detection: {}` rejected.
- `TestPluginFileWrapper` (new, 6 tests): legacy array accepted, wrapped v1 accepted, missing `schema_version` rejected, missing `services` rejected, v2 currently rejected, extra fields rejected.
- `TestRegistryAcceptsBothShapes` (new, 7 tests): Python `_extract_plugin_entries` accepts both shapes, rejects unknown / zero / non-int / missing services, rejects non-array/non-dict.

`jsonschema.RefResolver` used for cross-file `$ref` resolution (kept for compatibility with jsonschema 4.10+; the modern `referencing` Registry from 4.18+ would also work).

#### Design notes

- **Schema v2 deferred deliberately.** Refactoring `ports: ["22/tcp"]` → `ports: [{port: 22, proto: "tcp"}]` impacts `bob/data/services.json` (32 services), the `Service` dataclass, `_PORT_RE`, every check that iterates `service.ports`, plus extensive test fixture rewrites. That work belongs in v0.5.0 with explicit migration documentation, not bundled into this release.
- **The wrapper pre-empts the v2 problem.** Today `schema_version: 1` is the only accepted value, but the field exists in the file format from now on. When v2 ships, plugin files declaring `schema_version: 2` get the new validator; v1 plugins keep working through a compat path.
- **Empty `detection` blocks were silently broken.** Some bundled services carried them as boilerplate; removing them surfaces actual detection signal and prevents future copy-paste of dead config.

---

### Hardening pass #2 — schema descriptions, test fixtures, RefResolver compat

**Files:** `bob/data/schemas/services-list.schema.json`, `bob/data/schemas/plugin-file.schema.json`, `tests/conftest.py`, `tests/test_json_schema.py`, `tests/test_services_schema.py`

#### Problem

A second external review pass on the freshly hardened schema and test files surfaced a smaller round of legitimate issues — none structural this time, but worth fixing before shipping the v0.4.0 contract:

1. **`services-list.schema.json`**: an empty array `[]` was structurally valid (no `minItems`). A user creating a plugin file and forgetting to add entries got a silently-loaded zero-services file.
2. **`plugin-file.schema.json`**: the description used "schema_version: 1 implicit fallback" wording that wasn't reflected in the schema itself, and didn't explain *why* `maximum: 1` was deliberate or *why* `additionalProperties: false` rejects the very fields the description calls "reserved". Risk: a packager reads the description and thinks the schema misbehaves.
3. **`tests/conftest.py`**: `import os` was unused (pyflakes warning), and the docstring promised more than the fixture delivers (sets env vars only, doesn't call `setlocale()` for libc/ICU consumers).
4. **`tests/test_json_schema.py`**: heavy `MagicMock` injection in fixtures meant a renamed attribute in `build_json_data`'s real argument types (e.g. `sys_info.fqdn` instead of `sys_info.hostname`) would pass silently — mocks invent attributes on access. The timestamp validator was a substring check (`"T" in ts`) that accepts plenty of non-ISO strings. The contract had a single source (the production constants `SCHEMA_V1_REQUIRED_KEYS` / `SCHEMA_V1_FULL_KEYS`) so a bad edit to the constants left tests tautological.
5. **`tests/test_services_schema.py`**: `RefResolver` is deprecated in jsonschema ≥ 4.18 (we're on 4.10 today; CI runners on newer images would emit `DeprecationWarning`). The four per-class `validator` fixtures duplicated the same one-liner. The duplicate-id check used `ids.count(x)` per element (O(n²)). Several `assert errors` checks didn't pin which field the error was about — a regression elsewhere in the schema could mask a missing test.

#### Implementation

**Schemas:**

- `services-list.schema.json`: added `"minItems": 1`. Description rewritten to clarify it is the canonical bundled-list shape and to point users to `plugin-file.schema.json` for new plugin files. Explicit note that cross-service `id` uniqueness is runtime-only (consistent with `service.schema.json` SCOPE clause).
- `plugin-file.schema.json`: title gains `— schema v1` suffix to make versioning explicit. Top-level description restructured into three sections:
  - **Why `maximum: 1`**: each major schema bump ships its OWN `plugin-file.schema.json` at a NEW `$id`. A v2 plugin file MUST be validated against the v2 schema, not this one.
  - **Why `additionalProperties: false` rejects "reserved" fields**: rejecting today prevents collision with the meaning v2/v3 will give them.
  - **Runtime fallback `[…] → schema_version: 1`**: explicitly noted as an `_extract_plugin_entries` convenience, NOT a schema rule.

**conftest.py:** removed unused `import os`. Docstring explicitly states "only sets process environment variables. It does NOT call `setlocale()`" and justifies the explicit triple `LC_ALL`/`LC_MESSAGES`/`LANG` (POSIX precedence makes the last two redundant when `LC_ALL` is set, but the explicit triple documents the intent and is robust against downstream code probing any single var directly).

**test_json_schema.py:** complete rewrite of the fixtures:
- `MagicMock` replaced by real `SystemInfo`, `PortsSnapshot`, `FirewallStackSnapshot`, `NetworkContextSnapshot`, `CheckResult` instances. A renamed attribute in `bob.json_output.build_json_data` now raises `AttributeError` instead of getting auto-mocked.
- Timestamp test uses `datetime.fromisoformat(ts)` (strict ISO 8601) and asserts `tzinfo is not None`.
- Contract source duplicated: a hard-coded `EXPECTED_REQUIRED_KEYS_V1` / `EXPECTED_FULL_KEYS_V1` set in the test file matches against the production constants, so an edit to either side without the other is caught (`test_constants_match_expected_set`).
- New `test_short_mode_strict_set` rejects unexpected keys leaking into short mode — additive changes must be explicit (move to full mode or bump schema_version).
- Engine creation lifted into a pytest fixture (was duplicated 12+ times via `_make_engine()` calls).

**test_services_schema.py:**
- New helper `_make_resolved_validator(root, extra_schemas)` tries the modern `referencing.Registry` path first (jsonschema ≥ 4.18) and falls back to legacy `RefResolver` (4.10–4.17). Single migration point when the legacy branch eventually goes.
- Module-scope `service_validator` fixture replaces four per-class duplicates; the per-class `validator` fixtures become single-line delegates.
- `test_bundled_services_have_unique_ids` switched to `Counter` (O(n)).
- Targeted asserts using `e.absolute_path` instead of message substring matching on the most informative tests: `test_invalid_port_format`, `test_port_zero_rejected`, `test_port_above_65535_rejected_by_schema`, `test_id_with_spaces_rejected`, `test_empty_binary_string_rejected`. `absolute_path` is stable across jsonschema versions; `e.message` is not.

#### Tests

Total **4430/4430** (was 4427 before this pass — net +3, all defense-in-depth):
- `test_json_schema.py`: 15 → 17 (+`test_short_mode_strict_set`, +`test_constants_match_expected_set`).
- `test_services_schema.py`: 42 → 43 (+`test_services_list_rejects_empty_array` — verifies the new `minItems: 1`).
- All existing tests pass after the MagicMock-to-real refactor — proof that the production code accesses exactly the attributes the dataclasses expose (no hidden divergence).

#### Design notes

- **Why two hardening passes instead of one cleanly factored release.** Each pass was prompted by a separate external review (ChatGPT) over the user's IDE-selected files. Splitting them in the changelog preserves the "what was missed first time" trace, which is useful for postmortems and for understanding the iterative tightening.
- **`assert errors` vs `assert errors[i].absolute_path == [...]`** — kept `assert errors` on the trivial cases (e.g. `test_unknown_field_rejected`, `test_fixed_without_ports_rejected`) where the failure mode is "any error". Tightened only on tests where multiple distinct violations could mask each other.
- **Defense in depth via duplicated key list.** The `EXPECTED_REQUIRED_KEYS_V1` set in the test file is intentionally a copy of `SCHEMA_V1_REQUIRED_KEYS`. The test `test_constants_match_expected_set` is the safety net: an unintended edit to the production constant flips the test red, forcing the editor to acknowledge the contract change.

---

### Bonus UX — `= N` redundant suffix on unchanged score removed

**Files:** `bob/display.py`, `tests/test_min_level.py`

#### Problem

Field test on so6desktop showed:

```
║  Score de sécurité : 8/10  = 8                                               ║
```

The `= 8` was a vestige of a v0.3.0 fix ("score delta orphan arrow: stable score shows = N instead of bare →") — the original intent was to avoid a bare `→` when the score was unchanged, but the `= N` form ended up redundant: the score `8/10` is already two characters earlier on the same line.

#### Implementation

In `bob/display.py:print_audit_summary()`, the `delta == 0` branch is removed entirely:

```python
score_str = f"{score}/10"
if prev_score is not None:
    delta = score - prev_score
    if delta > 0:
        score_str += f"  {_c.green}↑ +{delta}{_c.reset}"
    elif delta < 0:
        score_str += f"  {_c.yellow}↓ {delta}{_c.reset}"
    # delta == 0: score unchanged, no annotation needed
```

`tests/test_min_level.py:TestScoreTrend::test_stable_shows_equal` renamed to `test_stable_shows_no_annotation` and inverted: now asserts that no `↑`/`↓` arrow appears and the value is exactly `"7/10"` (no suffix).

---

### Tests summary — 4430/4430 (+82)

| Test file | Class | New | Existing |
|---|---|----:|----:|
| `tests/test_exit_codes.py` | (existing) | 0 | 18 |
| `tests/test_i18n.py` | `TestDetectSystemLang` | +12 | — |
| `tests/test_cli.py` | `TestParse::test_*_locale` | +4 | — |
| `tests/test_json_schema.py` (new) | 4 classes | +17 | — |
| `tests/test_explain.py` | `TestExplainKeyAliases`, `TestExplainKeyFreezePolicy` | +6 | — |
| `tests/test_services_schema.py` (new) | 9 classes | +43 | — |
| `tests/test_min_level.py` | `TestScoreTrend::test_stable_shows_no_annotation` | renamed | — |
| `tests/conftest.py` (new) | autouse fixture forces `LANG=C` | — | — |

Notes on the trajectory of these counts during v0.4.0 development:
- `test_services_schema.py`: 20 (initial) → 42 (post-review hardening pass #1) → 43 (pass #2 added `test_services_list_rejects_empty_array` for the new `minItems: 1`).
- `test_json_schema.py`: 15 (initial) → 17 (pass #2 added `test_short_mode_strict_set` and `test_constants_match_expected_set` as defense-in-depth against silent contract drift).

### Field validation

End-to-end audit on so6desktop (Linux Mint 22.3) confirms:
- v0.4.0 banner correctly displayed
- Locale auto-detected as French via `$LANG=fr_FR.UTF-8`
- All sections render correctly; UFW logging shown (UFW active), IPv6 link-local correctly classified, plugins/profiles loaded from `/home/so6/.config/bob/`
- Score 8/10, delta tracked from previous audit, "Score inchangé" line shown without redundant `= 8` suffix
- 4405 tests green, pyflakes clean (one intentional `# noqa: F401`)

---

## [v0.3.6] — 2026-05-09

Code-review pass after a deep audit of the codebase. No new features, no behaviour changes, no new tests — only bug fixes, hygiene cleanup, and consistency improvements. Eight related fixes covering sudo-aware path resolution, IPv6 private-range coverage, SSH check semantics, UFW section rendering, cron legacy compatibility, sub-check placement, dead imports, and dead locale keys. 4348/4348 tests.

---

### Fix — `Path.home()` resolves to `/root` under sudo (+ chown helper for files written under sudo)

**Files:** `bob/config.py`, `bob/recurrence.py`, `bob/history.py`, `bob/registry.py`, `bob/compare.py`, `bob/profiles.py`, `bob/plugin_checks.py`, `bob/ignore.py`, `bob/sysinfo.py`

#### Problem

Seven modules computed module-level path constants using `Path.home()`:

```python
_DEFAULT_CONFIG_DIR = Path.home() / ".config" / "bob"        # config.py
_PLUGIN_DIR        = Path.home() / ".config" / "bob" / "services.d"  # registry.py
_USER_PROFILES_DIR = Path.home() / ".config" / "bob" / "profiles"    # profiles.py
# ... and 4 more
```

`Path.home()` consults `$HOME`. Under `sudo`, `$HOME` is typically `/root` (preserved across the sudo boundary on most distros). Result: BOB looked for user profiles at `/root/.config/bob/profiles/`, plugins at `/root/.config/bob/services.d/`, baseline at `/root/.config/bob/last_baseline.json`, etc. — never reading the invoking user's actual configuration.

A correct helper already existed: `bob.sysinfo.get_user_home()` honours `SUDO_USER` and falls back to `Path.home()`:

```python
def get_user_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user and re.match(r"^[a-zA-Z0-9_.-]{1,256}$", sudo_user):
        import pwd
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            ...
    return Path.home()
```

…but it was used in only two places (`sysinfo.py:91`, `manage_logs.py:155`).

#### Implementation

All seven modules import `get_user_home` from `bob.sysinfo` and replace `Path.home()` with `get_user_home()` in the affected constants. Resolution still happens at import time (preserving the existing API surface — many callers reference these constants directly), but now correctly points at the invoking user's home. `bob/ignore.py` had its own duplicated `SUDO_USER` lookup — replaced with a call to the shared helper.

#### Companion fix — `chown_to_sudo_user(path)` helper

Pointing the config to `~/.config/bob/` under sudo is only half the fix: writes happen as root, so each newly created file ends up owned by root. In a subsequent non-sudo session the user can no longer read or edit their own config.

A new helper `bob.sysinfo.chown_to_sudo_user(path)` chowns a path back to `SUDO_USER`'s uid/gid. No-op when:
- `SUDO_USER` is unset (i.e. running as a real root login or a regular user)
- `SUDO_USER` fails the validation regex
- The chown call itself fails (best-effort — the helper swallows `OSError`)

Applied at every user-config write site:
- `bob/config.py` — after `mkdir(parents=True, mode=0o700)` and after each atomic `replace` (UserConfig + EmailStore)
- `bob/compare.py` — after `mkdir(parents=True)` and after `tmp.replace(dest)` for the baseline
- `bob/recurrence.py` — after `mkdir(parents=True)` and after `tmp.replace(dest)`
- `bob/history.py` — after `mkdir(parents=True)`, after the first `open("a")` if the file did not pre-exist, and after every rotation `os.replace`
- `bob/ignore.py` — after `mkdir(parents=True)` and after `write_text`

#### Companion fix — `PermissionError` guards on plugin reads

Existing installations may have a `~/.config/bob/services.d/` or `checks.d/` directory created by root from a pre-fix sudo run. After the fix, the user session tries to read these directories and gets `PermissionError`. Three lookup sites gain a guard so the audit gracefully falls back to "no plugin loaded" instead of crashing:

- `bob/registry.py:_load_plugins` — `_PLUGIN_DIR.is_dir()` and `_PLUGIN_DIR.glob()` wrapped in try/except PermissionError
- `bob/plugin_checks.py:load_plugin_checks` — same pattern on `_PLUGIN_CHECKS_DIR`
- `bob/profiles.py:_resolve_path` — `candidate.is_file()` wrapped per directory, falls through to the next one

#### Design notes

- The helper validates `SUDO_USER` against a strict regex before looking it up via `pwd.getpwnam` — defends against env-var injection.
- No circular import risk: `bob.sysinfo` only imports from stdlib at module level (`bob.report` and `bob.output` are imported lazily inside `collect_system_info()`).
- The `Path.home()` fallback inside `get_user_home()` preserves behaviour when invoked outside a sudo context.
- `chown_to_sudo_user` is best-effort — failures are logged at debug level and never propagate. The fallback (file owned by root) is the pre-fix behaviour, so failure mode equals previous behaviour.

#### Migration for existing users

Users who ran a pre-fix BOB version under sudo may have a root-owned `~/.config/bob/`. To restore access:

```
sudo chown -R "$USER:$USER" ~/.config/bob/
```

Future sudo runs will automatically chown new files via the helper.

---

### Fix — `AllowTcpForwarding local` flagged as a warning

**Files:** `bob/checks/ssh.py:553`

#### Problem

The SSH check accepted only `AllowTcpForwarding no` as safe:

```python
atf = cfg.get("allowtcpforwarding", "yes").lower()
if atf not in ("no",):
    result.warn(message=_t("ssh.allow_tcp_forwarding"), ...)
    result.add_deduction(reason=..., points=1, ...)
```

OpenSSH supports a third value — `local` — which permits port forwarding only between processes on the SSH server itself, not between the client and arbitrary hosts. It is more restrictive than `yes` and is explicitly recommended in BOB's own remediation text (`how` field in `locales/en.json`):

> "If specific users need port forwarding, use: `AllowTcpForwarding local`"

Setting `local` was therefore both *more secure than the default* and *contradicted by BOB's own scoring*: it triggered the warning and deducted 1 point.

#### Implementation

```python
if atf not in ("no", "local"):
```

Both `no` and `local` are now accepted. `yes` (default) and `all` continue to trigger the warning.

---

### Fix — UFW logging section header shown when UFW inactive

**Files:** `bob/runner.py:233`

#### Problem

```python
# ---- CHECK 40 — UFW logging level ----
if not config.quiet:
    print_section(t("sections.ufw_logging"))
report.write_section(t("sections.ufw_logging"))

ufw_logging_result = check_ufw_logging(fw_status, t=t)
engine.apply(ufw_logging_result)
display_result(ufw_logging_result, report, ...)
```

`check_ufw_logging()` returns an empty `CheckResult` when UFW is inactive (line 407–408 of `firewall.py`), since the case is already covered by `check_firewall`. But the section header is printed unconditionally, producing this on screen and in the report when UFW is off:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  UFW LOGGING                                                                 │
└──────────────────────────────────────────────────────────────────────────────┘

```

…followed immediately by the next section. Visually noisy.

#### Implementation

Wrap the entire block in `if fw_status.active:`. When UFW is inactive, the header is not printed and the (empty) result is not displayed.

---

### Fix — IPv6 ULA and link-local treated as external

**Files:** `bob/checks/network_context.py:297`

#### Problem

`_is_private_or_loopback()` recognized:
- IPv4 loopback (`127.0.0.0/8`)
- IPv4 RFC-1918 (`10/8`, `172.16/12`, `192.168/16`)
- IPv6 loopback (`::1`)

But missed two important IPv6 ranges:
- `fc00::/7` — Unique Local Addresses (RFC-4193, the IPv6 equivalent of RFC-1918)
- `fe80::/10` — link-local addresses (typically used for neighbour discovery, not external connectivity)

A connection between two `fe80::` addresses on the same link, or two `fc00::` addresses on a private network, was classified as *external* — leading to spurious warnings and miscategorised exposure.

The same module previously used a hand-rolled string-prefix check. By contrast, `bob/checks/auth_log.py` already used `ipaddress.ip_network()` with the correct list:

```python
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)
```

#### Implementation

`network_context.py` now uses the same `_PRIVATE_NETWORKS` tuple and the same `ipaddress.ip_address()`-based check:

```python
def _is_private_or_loopback(addr: str) -> bool:
    bare = addr.split("%", 1)[0]   # strip IPv6 zone-id (e.g. "fe80::1%eth0")
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETWORKS)
```

Aligned with `auth_log.py`. The `%`-stripping handles zone identifiers in link-local addresses, which `ipaddress.ip_address()` doesn't accept directly.

---

### Fix — `NOTIFY_EMAIL` legacy regex silently skipped

**Files:** `bob/cron.py:820`, `bob/locales/en.json`, `bob/locales/fr.json`

#### Problem

`edit_cron_email()` patches the `NOTIFY_EMAILS=` line in BOB-installed cron scripts:

```python
text = re.sub(
    r"^NOTIFY_EMAILS=.*$",
    lambda _: f"NOTIFY_EMAILS={shlex.quote(new_email)}",
    text, flags=re.MULTILINE,
)
```

Pre-v0.x scripts used the singular `NOTIFY_EMAIL=` (no S). Users who installed crons with an early version saw the function report success — but no line matched, so nothing changed. Silent failure.

#### Implementation

```python
text, n = re.subn(
    r"^NOTIFY_EMAILS?=.*$",   # match both forms
    lambda _: f"NOTIFY_EMAILS={shlex.quote(new_email)}",   # always rewrite to current form
    text, flags=re.MULTILINE,
)
if n == 0:
    print(f"  ⚠ {t('manage_cron.email_not_found_in_script')}")
```

`subn()` returns the substitution count. When zero, a warning is printed using a new locale key:
- EN: `"No NOTIFY_EMAIL line found in the script — email not patched (script may be outdated)."`
- FR: `"Aucune ligne NOTIFY_EMAIL trouvée dans le script — email non mis à jour (script obsolète ?)."`

Old scripts are migrated to the new key (`NOTIFY_EMAILS=`) on next edit.

---

### Refactor — `_check_weak_algo` moved to sub-check section

**Files:** `bob/checks/ssh.py`

#### Problem

`bob/checks/ssh.py` is organised by section comment headers:
- `# Sub-check functions` — `_check_host_keys`, `_check_sshd_config`, …
- `# Parsing helpers` — `_parse_config_file`, `_collect_private_keys`, …

`_check_weak_algo` (introduced in v0.3.5 to deduplicate weak-cipher / weak-MAC / weak-kex logic) was placed under `# Parsing helpers`. But it accepts a `CheckResult` and writes findings via `result.warn()` / `result.add_deduction()` — by every relevant signal it is a sub-check, not a parsing helper.

#### Implementation

Moved to immediately follow `_check_sshd_config` (its only caller), ahead of `_check_ssh_dir`. The `# Parsing helpers` section now contains only true parsing functions.

---

### Cleanup — 22 unused imports removed

**Files:** `bob/__main__.py`, `bob/cron_ui.py`, `bob/output.py`, `bob/explain.py`, `bob/exposure.py`, `bob/registry.py`, `bob/report.py`, `bob/cron.py`, `bob/watch.py`, `bob/checks/iptables_nftables.py`, `bob/checks/firmware.py`, `bob/checks/ports.py`, `bob/checks/log_rotation.py`, `bob/checks/auth_log.py`, `bob/checks/logs.py`, `bob/checks/virtualization.py`, `bob/checks/smtp.py`, `bob/checks/disk.py`, `bob/checks/auditd.py`, `bob/checks/ddns.py`, `bob/checks/hardening.py`

#### Problem

`pyflakes bob/` reported 22 unused imports — vestiges of successive refactorings (v0.3.0 → v0.3.5):
- `dataclasses.field` in 6 modules where no `field()` calls remain
- `typing.{Optional, List, Tuple, Dict}` in 4 modules
- `pathlib.Path` in 2 modules
- `bob.scoring.{ScoreEngine, Finding, FindingLevel}` in `report.py` (TYPE_CHECKING block)
- `shutil` in `output.py` and `cron.py` (local re-import)
- `bob.checks._run._C_LOCALE_ENV` in `iptables_nftables.py`
- `bob.cron.prompt_emails`, `pathlib.Path` in `cron_ui.py`
- `bob.config.UserConfig` in `watch.py`
- `bob.webhook.WebhookError` in `__main__.py` (replaced by `Exception` catch)
- `bob.runner._ALL_SECTIONS` re-imported locally in `__main__.py:91`

Plus three structural issues:
1. `bob/checks/logs.py:633` — parameter name `field` shadowed `dataclasses.field` from line 25, triggering both the unused-import warning and a redefinition warning. Renamed to `field_name`.
2. `bob/checks/hardening.py:114` — local variable `found_issue = False` was assigned at 8 sites (`found_issue = True`) but never read. All 8 assignments and the initialiser removed.
3. `bob/output.py:351` — `bar = "─" * inner` calculated but unused; `bob/cron_ui.py:244` — `_SCHEDULE_DAILY` unpacked from a tuple but never referenced (replaced by `_`).

#### Implementation

Each import was traced (grep for the symbol in the file) before removal. Where a TYPE_CHECKING block became empty (`bob/report.py`), the entire block including `if TYPE_CHECKING:` was removed.

The single remaining pyflakes warning is `bob/__main__.py:24` — an intentional `# noqa: F401` re-export of `AuditConfig` for callers that do `from bob.__main__ import AuditConfig`.

---

### Cleanup — 47 dead locale keys removed

**Files:** `bob/locales/en.json`, `bob/locales/fr.json`

#### Problem

Both locale files had grown to 2049 lines / 1435 keys each. An audit of every key against actual `t()` and `_t()` call sites — including dynamic patterns like `t(f"services.exposure.{name}")` and indirect references via `t_key` parameters in helpers — revealed 47 truly orphaned keys.

#### Implementation

Removed (grouped by parent):

| Parent | Keys removed | Reason |
|--------|-----|--------|
| `cli.help_*` | 14 | Old help system replaced by hardcoded `print_help()` in `cli.py:555` |
| `errors.*` | 3 | Entire object: `must_be_root`, `unknown_option`, `ufw_not_found` (all replaced by exceptions) |
| `geo.*` | 1 | Entire object: `local_network` |
| `profile.*` | 3 | Entire object: `active`, `not_found`, `section_skipped` |
| `report.*` | 3 | `title`, `next_steps`, `system_info` |
| `cli.help`, `errors`, `geo`, `profile` | (objects) | Entire empty objects deleted |
| Various leaves | 20 | `prerequisites.{ss_available, ss_missing}`, `network_context.{interfaces_found, no_connections, connections_found}`, `ports.ephemeral_ignored`, `logs.{geo_unavailable, local_network}`, `ddns.{ports_title, high_warn}`, `summary.block_normal`, `fixes.done`, `risk_context.level`, `log_dir.{default_hint, use}`, `install_cron.{prompt_email, done}`, `manage_cron.edit_schedule`, `config.{port_prompt, port_saved}`, `deduction.local_dominance`, `status.{ok, info}` |

Preserved despite no usage:
- `_meta.lang`, `_meta.version` — reserved metadata keys

Both files stay synchronised (1388 keys each, EN/FR parity verified).

#### Design notes

Audit performed by extracting every flattened key, then grepping for both static (`t("key.subkey")`) and dynamic (`f"key.{var}"`) usage. Conservative approach: any key with even a remote possibility of dynamic reference was kept.

Lines saved: 2049 → 1994 (−55 per file, −110 total).

---

### Tests

4348/4348 — no test changes. All fixes are covered by existing tests; no regression introduced. Pyflakes is clean (one intentional `# noqa: F401` remains for `AuditConfig` re-export).

Validated end-to-end on so6desktop (Linux Mint 22.3) — full audit completes with score 8/10 (Pare-feu & Services 10/10, SSH 7/10, Durcissement 6/10) and renders all sections correctly. UFW logging section appears (UFW active); IPv6 consistency section indicates "link-local only"; profiles, plugins, and baselines are correctly loaded from `/home/so6/.config/bob/`.

---

## [v0.3.5] — 2026-05-08

Pure internal refactoring and locale fix — no new features, no behaviour changes, no new tests. Two independent cleanup tasks plus a content fix: `runner.py` repetitive section blocks replaced by a `_sec` closure (−295 lines), `ssh.py` triplicated weak-algo logic replaced by a `_check_weak_algo` helper (−26 lines), and four translation keys still referencing the former tool name `UFW-AUDIT` corrected to `BOB`. 4348/4348 tests.

---

### Refactoring — `runner.py` `_sec` closure

**Files:** `bob/runner.py` (951 L → 656 L, −295 lines)

#### Problem

`run_checks()` contained 29 nearly-identical 7–13 line blocks, one per audit section:

```python
if _section_enabled("kernel_modules", config, profile):
    if not config.quiet:
        print_section(t("sections.kernel_modules"))
    report.write_section(t("sections.kernel_modules"))
    result = check_kernel_modules(km_snapshot, t=t, profile_name=_pname)
    if profile is not None:
        apply_profile(result, profile)
    engine.apply(result)
    display_result(result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    if not config.quiet:
        print()
```

951 lines total. The repetition made it impossible to apply a cross-cutting change (e.g. add a hook between every section) without editing 29 sites.

#### Implementation

**`_pname` pre-computed once** after `_pr`:

```python
_pname = profile.name if profile is not None else "server"
```

Used by the 7 sections that accept `profile_name=`: `kernel_modules`, `mac_policy`, `updates`, `memory`, `backup`, `auditd`, `secure_boot`. `check_firmware` does not accept `profile_name` — it was intentionally excluded.

**`_sec` closure** defined immediately after:

```python
def _sec(section: str, snapshot, check_fn, **check_kwargs) -> None:
    if not _section_enabled(section, config, profile):
        return
    if not config.quiet:
        print_section(t(f"sections.{section}"))
    report.write_section(t(f"sections.{section}"))
    result = check_fn(snapshot, t=t, **check_kwargs)
    if profile is not None:
        apply_profile(result, profile)
    engine.apply(result)
    display_result(result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    if not config.quiet:
        print()
```

29 standard blocks replaced by single-line calls:

```python
_sec("kernel_modules", km_snapshot,  check_kernel_modules,  profile_name=_pname)
_sec("ssh",           ssh_snapshot,  check_ssh,             ssh_exposed=_ssh_exposed)
_sec("ipv6",          ipv6_snapshot, check_ipv6,            ufw_active=fw_status.active)
# …and 26 more
```

Sections kept manual (not converted): firewall, rules, ufw_logging, network groups/display, samba, docker_audit, desktop_apps, iptables_nft (all have conditional logic around `.installed`, `.detected`, or `not fw_status.active` that cannot be abstracted into the closure without added complexity).

**`apply_profile` now applied to `auth_log`** — previously omitted by oversight. No-op in practice (no current profile defines auth_log-specific overrides), but now consistent with all other sections.

#### Design decisions

- **Closure over module-level helper**: `_sec` captures `config`, `profile`, `engine`, `report`, `t`, `_pr` from the enclosing scope. A module-level helper would require passing all six as parameters on every call — more verbose, no benefit.
- **`check_fn(snapshot, t=t, **check_kwargs)` not `check_fn(snapshot, **{"t": t, **check_kwargs})`**: `t` is always positional-keyword; keyword-splat form is correct and explicit.

---

### Refactoring — `ssh.py` `_check_weak_algo` helper

**Files:** `bob/checks/ssh.py` (1406 L → 1380 L, −26 lines)

#### Problem

`_check_sshd_config()` contained three identical 16-line blocks to check for weak Ciphers, MACs, and KexAlgorithms:

```python
cipher_str = cfg.get("ciphers", "")
if cipher_str:
    configured = {c.strip().lower() for c in cipher_str.split(",")}
    weak = sorted(configured & _WEAK_CIPHERS)
    if weak:
        joined = ", ".join(weak)
        result.warn(
            message=_t("ssh.weak_ciphers", ciphers=joined),
            nature="improvement", cmd="", key="ssh.weak_ciphers",
        )
        result.add_deduction(
            reason=_t("ssh.weak_ciphers", ciphers=joined),
            points=2, context="local", key="ssh.weak_ciphers",
        )
        found_issue = True
```

Repeated for `macs` and `kexalgorithms` with only the variable names, set names, translation keys, and point values differing.

#### Implementation

Module-level helper `_check_weak_algo` extracted before `_parse_config_file`:

```python
def _check_weak_algo(
    cfg: dict, result: "CheckResult", _t,
    cfg_key: str, weak_set: "frozenset[str]", t_key: str, param: str, points: int,
) -> bool:
    """Flag weak crypto algorithm entries; return True if any found."""
    algo_str = cfg.get(cfg_key, "")
    if not algo_str:
        return False
    configured = {a.strip().lower() for a in algo_str.split(",")}
    weak = sorted(configured & weak_set)
    if not weak:
        return False
    joined = ", ".join(weak)
    result.warn(
        message=_t(t_key, **{param: joined}),
        nature="improvement", cmd="", key=t_key,
    )
    result.add_deduction(
        reason=_t(t_key, **{param: joined}),
        points=points, context="local", key=t_key,
    )
    return True
```

Three call sites in `_check_sshd_config`:

```python
found_issue |= _check_weak_algo(cfg, result, _t, "ciphers",       _WEAK_CIPHERS, "ssh.weak_ciphers", "ciphers", 2)
found_issue |= _check_weak_algo(cfg, result, _t, "macs",          _WEAK_MACS,    "ssh.weak_macs",    "macs",    1)
found_issue |= _check_weak_algo(cfg, result, _t, "kexalgorithms", _WEAK_KEX,     "ssh.weak_kex",     "kex",     1)
```

#### Design decision

**Module-level (not closure)**: unlike `_sec`, this helper takes all its inputs as parameters and has no dependency on outer scope. A module-level function makes it independently testable and visible to future callers.

---

### Fix — locale strings `UFW-AUDIT` → `BOB`

**Files:** `bob/locales/en.json`, `bob/locales/fr.json`

#### Problem

Four translation keys in both locale files still referenced the former tool name `UFW-AUDIT` instead of `BOB`:

| Key | Before (EN) | After (EN) |
|-----|-------------|------------|
| `install_cron.title` | `UFW-AUDIT CRON SETUP` | `BOB CRON SETUP` |
| `manage_cron.title` | `UFW-AUDIT CRON MANAGEMENT` | `BOB CRON MANAGEMENT` |
| `manage_cron.no_crons` | `No UFW-AUDIT cron jobs installed.` | `No BOB cron jobs installed.` |
| `report.title` | `UFW-AUDIT REPORT` | `BOB REPORT` |

These strings appeared in the cron setup and management screens, and in the report section title. Other `UFW` references in the locale files are legitimate — they refer to the UFW firewall tool itself, not the former tool name.

#### Implementation

Simple string replacement in both `en.json` and `fr.json`. No logic changes.

---

## [v0.3.4] — 2026-05-08

Hotfix release — no new features, no behaviour changes, no new tests. Fixes a fatal `NameError` introduced in v0.3.2: `user_config` was not passed to `run_checks()`. 4348/4348 tests.

---

### Fix — `user_config` not passed to `run_checks()`

**Files:** `bob/runner.py`, `bob/__main__.py`

#### Problem

v0.3.2 added SUID user whitelisting. `run_checks()` was extended with a call to `user_config.get_suid_whitelist()` inside the SUID check block (CHECK 37), but `user_config` was never added as a parameter to `run_checks()`. The call site in `__main__.py` therefore did not pass it.

Result: every audit run that reached CHECK 37 (SUID/SGID audit) crashed with:

```
NameError: name 'user_config' is not defined
```

This was a fatal regression on all machines — the audit always reaches CHECK 37.

#### Implementation

`runner.py` — added parameter and guarded access:

```python
def run_checks(
    ...
    user_config: UserConfig | None = None,   # added
) -> ChecksResult:
    ...
    suid_snapshot = SuidSnapshot.from_system(
        user_whitelist=user_config.get_suid_whitelist() if user_config is not None else []
    )
```

`__main__.py` — updated call site to pass `user_config`.

#### Validation

Tested on 5 VMs (Linux Mint 22.3, Debian 13, Ubuntu 26.04, Kali, so6desktop) — full audit completes without error on all.

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
