*[Lire en français](TESTING_FR.md)*

# BOB — Test plan: dangerous UFW rules

Manual regression tests using deliberately dangerous UFW rules.
Each test verifies that BOB correctly detects (and fixes) a specific misconfiguration.

---

## Unit test history

| Version | Tests | Notes |
|---------|-------|-------|
| v0.4.6 | 4500 | Terrain test pass v0.4.5 fixes (+11): `TestParseInstalledKernels` (+5 — `ii`/`rc`/`pn`/`un`/`iU` status filtering, `hi` hold kept, mixed legacy+prefixed format) · `TestActiveDomainsIncludesOK` (+6 in test_domain_scores — OK promotes, INFO doesn't, full Debian 13 remediation scenario asserted at global=9 instead of 8). Multi-distro integration CI added (purely additive, not counted as unit tests). |
| v0.4.5 | 4489 | Test infrastructure hardening (0 new tests, pure refactor of `tests/test_locale_coverage.py`): regex scanning → AST parsing (`ast.walk` + `ast.Call` + `ast.Name`). Eliminates docstring false positives, multi-line call site fragility, and `obj._t(...)` attribute call edge cases. `_KEY_EXCLUSIONS` allowlist deleted. Same 9 tests, same external contract. |
| v0.4.4 | 4489 | Cross-distro terrain hardening (+21): coverage for `updates.py` critical bug (`-s dist-upgrade` semantics, stale cache detection, cross-check vs `apt list --upgradable`); AppArmor 0-profile key; all-virtual SMART skip; DDNS ports inline; new `test_locale_coverage.py` in initial regex form (catches `[xxx.yyy]` sentinel regressions class). |
| v0.4.3 | 4468 | Doc catch-up + post-audit hardening pass (+16): firewall EXPLAIN_KEYS regression, `--json-full` HardeningSnapshot dead-attr coverage, `strptime("%b…")` locale independence (ssl_certs + logs), `_is_covered_by_ufw` IP false-positive, cron range validator out-of-bounds, email markdown not HTML-escaped. |
| v0.4.2 | 4452 | Phase 3 distro-ready (packaging discipline) + pre-release hardening pass — 2 critical + 5 important + 4 minor fixes from agent audit. +3 tests in new `test_template_vars_migration.py` |
| v0.4.1 | 4449 | Phase 2 distro-ready (+19): `bob/tui/cron` extraction (0 new tests — covered by existing) · `--offline` integration (+3 in `test_webhook.py`) · `test_formatter.py` (14 new — locale-independent reconstruction + 4 edge cases post-review) · `test_json_schema.py` (+2 — `template_vars` field exposure) |
| v0.4.0 | 4430 | Phase 1 distro-ready (+82): `TestDetectSystemLang` (12) · `TestExplainKeyAliases` + `TestExplainKeyFreezePolicy` (6) · `test_json_schema.py` (17 — incl. strict-set + constants-drift defense in depth) · `test_services_schema.py` (43 — incl. `$defs`, strict 1–65535 port regex, business constraints, plugin-file wrapper, `minItems: 1` on services-list) · 4 CLI locale integration |
| v0.3.6 | 4348 | No new tests — code-review pass (sudo-aware `Path.home()`, IPv6 ULA, SSH `local`, dead imports/locales) |
| v0.3.5 | 4348 | No new tests — pure refactoring (`runner.py` `_sec` closure, `ssh.py` `_check_weak_algo`) |
| v0.3.4 | 4348 | No new tests — hotfix only (`user_config` NameError) |
| v0.3.3 | 4348 | +7 new −6 removed (TestWasCapped → TestCappedIndices): `TestCappedIndices` in test_domain_scores |
| v0.3.2 | 4347 | +21 new (user whitelist) −2 removed (DC-1 dead code): `TestFromSystemUserWhitelist` · `TestGetSuidWhitelist` · `TestGlobMatching` in test_suid_audit |
| v0.3.1 | 4328 | +6 new tests: `TestWasCapped` in test_domain_scores · was_capped flag · engine cached properties |
| v0.3.0 | 4322 | +48 new tests: `--breakdown` display · golden scoring scenarios · 16 in test_breakdown · 32 in test_golden_scenarios · 1 renamed in test_min_level |
| v0.2.4 | 4274 | +12 new tests: Debian -unsigned kernel UX · deduction_total None sentinel · 2 in test_kernel_modules · 10 in test_compare |
| v0.2.3 | 4262 | +1 new · 4 renamed: NOT_LISTENING INFO · IoT no deduction · SSH stopped label split |
| v0.2.2 | 4255 | +17 new tests · 2 updated: `TestStatFallback` · `TestScoringInvariants` · orphan-rule bare-port fix · ClamAV 1pt · ScoreCap.key · INFO domains excluded |
| v0.2.0 | 4238 | +32 new tests · 3 corrected: scoring refactoring · cron MTA detection · kernel `-unsigned` false positive · IoT log dominance WARN |
| v0.1.1 | 4206 | +4 regression tests: fwupd 1.9+ tree-format output (`├─`/`└─` parser) — bug found on Ubuntu 26.04 LTS |
| post-v0.1.0 | 4202 | +2 regression tests: exposure surface INFO-level findings (`ssh.not_installed`, `fail2ban.not_installed`) — bugs found on Ubuntu 26.04 LTS |
| v0.1.0  | 4200  | Initial release — 65 test files; 39 new tests in `test_cis_refs.py` (CIS benchmark mapping); full coverage across all 46 checks |

---

### v0.4.2 — 4452/4452 (2026-05-14)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4452 passed in 5.25s
```

**Net: +3.** Phase 3 distro-ready (packaging discipline) ships packaging artefacts — no Python code changes there. A separate pre-release hardening pass (agent audit) added small code fixes (firewall keys, `_C_LOCALE_ENV` on 3 sites, `watch.py` user_config threading, AppArmor binary list, `BOB_SHARE` rename with fallback) and one new test file `test_template_vars_migration.py` (3 tests) that tracks Phase 2 migration debt visibly.

Separate validation:

| Artefact | Validation command | Result |
|---|---|---|
| `man/bob.1` | `groff -man -Tutf8 man/bob.1 >/dev/null && man -l man/bob.1` | ✓ |
| `man/bob.conf.5` | same | ✓ |
| `man/bob-profile.5` | same | ✓ |
| `bob/data/schemas/*.json` | `python3 -c "import json; json.load(open(f))"` × 3 | ✓ |
| `debian/control` | manual review, syntax matches dh-make output | ✓ |
| `debian/copyright` | DEP-5 format, manual review | ✓ |
| `debian/rules` | executable (`chmod +x`), valid Makefile syntax | ✓ |
| `debian/apparmor.d/bob` | manual review, paths cross-checked against `bob/checks/*` exec sites | ✓ |
| `packaging/rpm/bob.spec` | manual review, `pyproject-rpm-macros` patterns | ✓ |

Full `dpkg-buildpackage` + `lintian` + `rpmbuild` + `rpmlint` validation is deferred to the first community packaging attempt (AUR/COPR or first Debian unstable upload). Upstream commits to fixing any lintian/rpmlint issues reported in subsequent patch releases.

---

### v0.4.1 — 4449/4449 (2026-05-14)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4449 passed in 5.07s
```

**Net: +19 (no removals).** Phase 2 distro-ready (architectural decoupling): `bob/tui/` extraction, `--offline` integration tests, locale-independent finding/deduction representation via `template_vars`, plus a post-review hardening pass on `bob/formatter.py` (4 edge-case tests).

#### `tests/test_formatter.py` (new, +14)

`bob.formatter` — locale-independent message reconstruction:

| Class | Tests | Coverage |
|---|---:|---|
| `TestFormatFinding` | 5 | Resolution order: key + template_vars renders via i18n, key alone returns template, no key falls back to message, unknown key falls back, empty input edge case |
| `TestFormatDeduction` | 2 | Same resolution order applied to `Deduction.key` + `template_vars` → `reason` |
| `TestLocaleRoundtrip` | 1 | Same `(key, template_vars)` yields different text in `fr` vs `en` — the whole point of the decoupling |
| `TestBackwardCompatibility` | 2 | Legacy findings (no key, no template_vars) pass through unchanged |
| `TestFormatterEdgeCases` (post-review) | 4 | Empty template_vars on placeholder template returns raw, partial template_vars raises KeyError, key wins over mismatched message, empty message + no key returns "" |

#### `tests/test_webhook.py` (+3)

`--offline` strict mode contract:

| Test | Coverage |
|---|---|
| `test_webhook_with_offline_flag_parses` | CLI parser accepts `--offline --webhook=URL` together (not mutually exclusive at parse time) |
| `test_offline_skips_webhook_send` | Mirrors `__main__.py:277` decision branch — fails if the offline gate is ever dropped |
| `test_get_public_ip_offline_skips_urllib` | Monkeypatches `sysinfo.urllib` with an exploding stub; raises AssertionError if any urlopen reached in offline mode |

#### `tests/test_json_schema.py` (+2)

`template_vars` field exposed in JSON output:

| Test | Coverage |
|---|---|
| `test_each_deduction_has_template_vars_field` | Every deduction exposes `template_vars` dict (empty for legacy checks) |
| `test_each_finding_has_template_vars_field` | Every finding (full mode) exposes `template_vars` dict |

#### `bob/tui/cron.py` (extraction — no new tests)

`bob/cron_ui.py` (952 lines) moved to `bob/tui/cron.py` via `git mv`. The 4430 existing tests already exercise the import path; the full suite remained 4430/4430 after the move, proving the rename is transparent.

---

### v0.4.0 — 4430/4430 (2026-05-14)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4430 passed in 5.52s
```

**Net: +82 (no removals).** Phase 1 distro-ready contracts frozen, plus two post-review hardening passes:
- **Pass #1** (+22 tests in `test_services_schema.py`): strict 1–65535 port regex, `$defs` factorization, `if/then`/`anyOf` business constraints, plugin-file `schema_version` wrapper.
- **Pass #2** (+3 tests, defense-in-depth): `services-list.minItems: 1` (rejects empty arrays), real-class fixtures replacing `MagicMock` in `test_json_schema.py` (so renamed attributes raise `AttributeError` instead of being auto-mocked), `EXPECTED_REQUIRED_KEYS_V1` duplicated as a drift-detection contract, `RefResolver`→`referencing` compat shim for jsonschema 4.18+, asserts via `e.absolute_path` instead of brittle message matching.

#### `tests/test_i18n.py` — `TestDetectSystemLang` (+12)

POSIX locale auto-detection (`$LC_ALL` / `$LC_MESSAGES` / `$LANG`):

| Test | Coverage |
|---|---|
| `test_no_env_returns_default` | All env vars unset → `"en"` |
| `test_lang_c_returns_default` | `LANG=C` → `"en"` |
| `test_lang_posix_returns_default` | `LANG=POSIX` → `"en"` |
| `test_lang_c_utf8_returns_default` | `LANG=C.UTF-8` → `"en"` |
| `test_fr_fr_returns_fr` | `LANG=fr_FR.UTF-8` → `"fr"` |
| `test_fr_be_returns_fr` | `LANG=fr_BE` → `"fr"` |
| `test_fr_with_modifier_returns_fr` | `LANG=fr_FR.UTF-8@euro` → `"fr"` |
| `test_en_us_returns_en` | `LANG=en_US.UTF-8` → `"en"` |
| `test_unsupported_lang_falls_back_to_default` | `ja_JP`/`de_DE`/`es_ES`/`zh_CN` → `"en"` |
| `test_lc_all_overrides_lang` | `LC_ALL=fr` overrides `LANG=en` |
| `test_lc_messages_overrides_lang` | `LC_MESSAGES=fr` overrides `LANG=en` |
| `test_empty_lc_all_falls_through_to_lang` | `LC_ALL=""` → consults `LANG` |

#### `tests/test_cli.py` — locale integration (+4)

| Test | Coverage |
|---|---|
| `test_french_overrides_system_locale` | `--french` wins on `LANG=ja_JP` |
| `test_lang_explicit_overrides_system_locale` | `--lang=en` wins on `LANG=fr_FR` |
| `test_default_uses_system_locale_when_fr` | Default → `fr` when `LANG=fr_FR.UTF-8` |
| `test_default_uses_en_when_lang_c` | Default → `en` when `LANG=C` |

#### `tests/test_json_schema.py` (new, +17)

JSON output schema invariants — public API contract:

| Class | Tests |
|---|---:|
| `TestSchemaVersion` | 2 |
| `TestRequiredKeysAlwaysPresent` | 6 |
| `TestFieldTypes` | 5 |
| `TestStableKeysExposed` | 3 |
| `TestDomainScoresStructure` | 1 |

Verifies `schema_version="1"`, required top-level keys, field types, locale-independent `key` field on each finding/deduction.

**Pass #2 hardening:** all `MagicMock` injections in fixtures replaced by real BOB dataclasses (`SystemInfo`, `PortsSnapshot`, `FirewallStackSnapshot`, `NetworkContextSnapshot`, `CheckResult`) so a renamed attribute in `bob.json_output.build_json_data` raises `AttributeError` instead of being silently auto-mocked. Timestamp test now uses `datetime.fromisoformat()` (strict ISO 8601). Two new defense-in-depth tests: `test_short_mode_strict_set` (rejects unexpected keys leaking into short mode) and `test_constants_match_expected_set` (catches drift between production constants and the test-side hard-coded contract).

#### `tests/test_explain.py` — alias map + freeze (+6)

| Test | Coverage |
|---|---|
| `test_alias_map_is_dict` | `EXPLAIN_KEY_ALIASES` is a dict |
| `test_alias_targets_resolve_to_valid_keys` | Every alias target exists in canonical set |
| `test_alias_keys_are_not_in_canonical_set` | Aliases don't shadow real keys |
| `test_normalize_key_resolves_aliases` | Registered alias gets resolved |
| `test_normalize_key_passthrough_when_no_alias` | Unknown keys pass through unchanged |
| `test_core_keys_present_in_canonical_set` | 16 frozen "load-bearing" keys must remain in `EXPLAIN_KEYS` |

#### `tests/test_services_schema.py` (new, +43)

Plugin services formal JSON Schema (Draft 2020-12), extended after two post-review hardening passes:

| Class | Tests | Coverage |
|---|---:|---|
| `TestSchemasAreWellFormed` | 4 | Schemas pass Draft 2020-12 self-validation; `services-list` rejects empty array (pass #2: `minItems: 1`) |
| `TestBundledServicesMatchSchema` | 3 | Bundled `services.json` validates entry-by-entry; unique IDs (`Counter` O(n)) |
| `TestValidPluginSamples` | 3 | Sample valid plugins (minimal fixed, with detection, user config_key) |
| `TestInvalidPluginSamples` | 10 | Rejection cases: missing field, bad risk, bad port, port 0/65536, unknown field, fixed without ports, ID with spaces, empty binary string. Pass #2: 5 of these now assert via `e.absolute_path` (stable across jsonschema versions) instead of message-substring matching. |
| `TestSchemaPythonParity` | 2 | Schema-valid ↔ Python-valid alignment |
| `TestBusinessConstraints` (new pass #1) | 7 | `auto` requires `config_files`, undetectable service rejected, empty `detection: {}` rejected |
| `TestPluginFileWrapper` (new pass #1) | 6 | Legacy array + wrapped `{schema_version, services}` accepted; v2 / extras rejected. Pass #2: cross-file `$ref` resolution via the `_make_resolved_validator` compat shim (modern `referencing` first, legacy `RefResolver` fallback). |
| `TestRegistryAcceptsBothShapes` (new pass #1) | 7 | Python `_extract_plugin_entries` parity with the meta-schema |
| Boundary tests | 2 | Port 65535 accepted, 65536 rejected (strict regex) |

A module-scope `service_validator` fixture is shared across all classes (pass #2 — replaces 4 duplicated per-class one-liners).

`jsonschema` is a test-only dependency (uses `pytest.importorskip`).

#### `tests/test_min_level.py` — score display

`TestScoreTrend::test_stable_shows_equal` renamed to `test_stable_shows_no_annotation` and inverted: stable score now displays `"7/10"` exactly (no `= 7` suffix).

#### `tests/conftest.py` (new)

Autouse fixture forces `LC_ALL=C`/`LANG=C` for every test, making locale-dependent CLI defaults deterministic regardless of the developer's host locale.

---

### v0.3.6 — 4348/4348 (2026-05-09)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.04s
```

**No new tests — code-review pass.** Eight related fixes: `Path.home()` → `get_user_home()` in 7 modules · IPv6 ULA/link-local in `_is_private_or_loopback` · SSH `AllowTcpForwarding local` accepted · UFW logging header skipped when UFW inactive · `NOTIFY_EMAIL` legacy regex · `_check_weak_algo` moved to sub-check section · 22 unused imports removed (pyflakes clean except for one intentional `noqa`) · 47 dead locale keys removed.

**Field validation:** Full audit on so6desktop (Linux Mint 22.3) completed with score 8/10. UFW logging section header now hidden when UFW inactive; IPv6 link-local correctly classified as private; profiles/plugins/baselines correctly loaded from `/home/so6/.config/bob/` (not `/root/.config/bob/`).

---

### v0.3.5 — 4348/4348 (2026-05-08)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.22s
```

**No new tests — pure refactoring (`runner.py` `_sec` closure −295 lines, `ssh.py` `_check_weak_algo` −26 lines)**

---

### v0.3.4 — 4348/4348 (2026-05-08)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.17s
```

**No new tests — hotfix only (pass `user_config` to `run_checks()` — `NameError` on SUID whitelist)**

---

### v0.3.3 — 4348/4348 (2026-05-07)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.21s
```

**Net: +1 from v0.3.2 (+7 new capped_indices tests, −6 was_capped tests removed)**

#### `tests/test_domain_scores.py` — `TestCappedIndices` replaces `TestWasCapped` (+7, −6)

`TestWasCapped` tested the `deduction.was_capped` bool flag (removed in v0.3.3). Replaced by `TestCappedIndices` which tests the `frozenset[int]` return value of `compute_domain_scores()`.

| Test | Coverage |
|------|----------|
| `test_no_cap_returns_empty_frozenset` | No tool cap triggered → second return value is `frozenset()` |
| `test_single_capped_deduction_returns_index` | One deduction exceeds cap → index `0` in returned frozenset |
| `test_uncapped_deduction_not_in_frozenset` | Deduction within cap → index absent from frozenset |
| `test_multiple_deductions_only_capped_indices` | Two deductions, one capped → only the capped index returned |
| `test_frozenset_is_immutable` | Returned object is a `frozenset`, not a `set` |
| `test_engine_capped_indices_matches_return_value` | `engine.capped_indices` equals the frozenset returned by `compute_domain_scores()` |
| `test_non_tool_cap_key_never_capped` | Key with no tool-cap prefix → never in capped frozenset |

---

### v0.3.2 — 4347/4347 (2026-05-07)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4347 passed in 5.23s
```

**Net: +19 from v0.3.1 (+21 new whitelist tests, −2 dead-code tests removed)**

**New tests (+21):**

#### `tests/test_suid_audit.py` — `TestFromSystemUserWhitelist` (+8)

| Test | Coverage |
|------|----------|
| `test_whitelisted_suid_emits_info` | Snapshot with whitelisted paths → `suid_audit.whitelisted` INFO finding |
| `test_whitelisted_suid_no_deduction` | Whitelisted paths → no deduction applied |
| `test_whitelisted_suid_ok_result_when_no_unexpected` | All suppressed → `suid_audit.ok` still present |
| `test_whitelisted_suid_warn_result_when_unexpected_remain` | Mix of whitelisted + unexpected → both findings present |
| `test_whitelisted_count_in_info_message` | 2 whitelisted paths → "2" appears in INFO message |
| `test_no_whitelisted_finding_when_list_empty` | Empty `whitelisted_suid` → no INFO finding |
| `test_whitelisted_truncation_at_10` | 11 whitelisted paths → "+1 more" suffix |

#### `tests/test_suid_audit.py` — `TestGetSuidWhitelist` (+7)

| Test | Coverage |
|------|----------|
| `test_returns_empty_list_when_key_absent` | Missing key → `[]` |
| `test_single_pattern` | `kismet_cap_*` → `["kismet_cap_*"]` |
| `test_multiple_patterns_comma_separated` | `a, b, c` → `["a", "b", "c"]` |
| `test_strips_whitespace_around_patterns` | `  foo_*  ,  bar  ` → `["foo_*", "bar"]` |
| `test_empty_value_returns_empty_list` | Empty string value → `[]` |
| `test_commas_only_returns_empty_list` | ` , , ` → `[]` |
| `test_persists_and_reloads` | Written and reloaded → same list |

#### `tests/test_suid_audit.py` — `TestGlobMatching` (+7)

| Test | Coverage |
|------|----------|
| `test_glob_matches_kismet_cap_prefix` | `kismet_cap_*` matches 3 Kismet paths |
| `test_exact_name_match` | Exact basename pattern whitelists matching path |
| `test_non_matching_pattern_leaves_unexpected` | Non-matching pattern → path stays unexpected |
| `test_empty_patterns_leaves_all_unexpected` | Empty patterns → all paths unexpected |
| `test_wildcard_star_matches_all` | `*` pattern → everything whitelisted |
| `test_partial_glob_mix` | Mixed: one matched, one not |
| `test_multiple_patterns_any_match_whitelists` | Two exact patterns → each matches its target |

**Removed tests (−2, DC-1):**

`tests/test_suid_audit.py` — `TestIsRootOwned` deleted along with `_is_root_owned()` dead code:
- `test_nonexistent_path_returns_false`
- `test_current_user_file_not_root_owned_when_not_root`

---

### v0.3.1 — 4328/4328 (2026-05-06)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4328 passed in 4.33s
```

**New tests (+6):**

#### `tests/test_domain_scores.py` — `TestWasCapped` (+6)

| Test | Coverage |
|------|----------|
| `test_uncapped_deduction_not_marked` | Deduction within tool cap → `was_capped` stays `False` |
| `test_fully_absorbed_deduction_marked` | Second deduction after cap exhausted → `was_capped = True` |
| `test_partially_absorbed_deduction_marked` | Deduction partially exceeds remaining cap → `was_capped = True` |
| `test_non_tool_cap_key_never_marked` | Key with no tool-cap prefix → `was_capped` always `False` |
| `test_cached_domain_scores_on_engine` | After `apply_domain_score_override()`, `engine.domain_scores` matches direct call |
| `test_engine_domain_scores_empty_before_override` | Before override, `engine.domain_scores` returns `{}` |

---

### v0.3.0 — 4322/4322 (2026-05-06)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4322 passed in 4.45s
```

**New tests (+48):**

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

#### `tests/test_min_level.py` (renamed, +0 net)

`test_stable_shows_right_arrow` → `test_stable_shows_equal` — assertion updated from `"→" in val` to `"= 7" in val`.

---

### v0.2.4 — 4274/4274 (2026-05-05)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4274 passed in 4.65s
```

**New tests (+12):**

#### `tests/test_kernel_modules.py` (+2)

| Test | Coverage |
|------|----------|
| `test_up_to_date_names_running_kernel_not_unsigned_sibling` | Running `amd64` with `-unsigned` sibling sorted as `most_recent` → OK message names the running kernel, not the unsigned sibling |
| `test_debian_signed_unsigned_pair_uses_obsolete_same_message` | Signed/unsigned pair at the top of the kernel list → `kernels_obsolete_same` key selected (no "running / latest" pair in text), not `kernels_obsolete` |

#### `tests/test_compare.py` — `TestDisplayDelta` (+4)

| Test | Coverage |
|------|----------|
| `test_variable_deductions_increased_shown_without_structural_change` | `deduction_delta > 0`, no structural change (no alert/warn delta, no new/resolved keys) → variable-deductions message shown |
| `test_variable_deductions_decreased_shown_without_structural_change` | `deduction_delta < 0`, no structural change → variable-deductions decrease message shown |
| `test_variable_deductions_suppressed_when_warn_delta` | `deduction_delta != 0` but `warn_delta != 0` → message suppressed (structural change explains score move) |
| `test_variable_deductions_suppressed_when_new_finding_key` | `deduction_delta != 0` but `new_finding_keys` non-empty → message suppressed |

#### `tests/test_compare.py` — `TestDeductionTracking` (new class, +6)

| Test | Coverage |
|------|----------|
| `test_deduction_total_none_in_new_baseline_defaults` | `AuditBaseline()` default `deduction_total` is `None` (not `0`) |
| `test_load_baseline_returns_none_when_field_absent` | Old JSON without `"deduction_total"` key → `None` after `load_baseline()` |
| `test_load_baseline_returns_int_when_field_present` | New JSON with `"deduction_total": 5` → `5` (int) after `load_baseline()` |
| `test_deduction_delta_zero_when_prev_is_old_baseline` | `prev.deduction_total is None` → `compute_delta()` returns `deduction_delta == 0` |
| `test_deduction_delta_computed_when_both_tracked` | Both sides have int `deduction_total` → correct signed delta computed |
| `test_deduction_delta_zero_when_unchanged` | Same value on both sides → `deduction_delta == 0` |

---

### v0.2.3 — 4262/4262 (2026-05-03)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4262 passed in 4.53s
```

**New tests (+1):**

#### `tests/test_exposure.py` (+1)

| Test | Coverage |
|------|----------|
| `test_not_active_shows_stopped_text` | SSH installed but service stopped → attack-surface table uses `exposure.ssh_stopped` key ("installé — non démarré"), not the merged `ssh_not_running` key |

**Updated/renamed tests (4):**

| File | Test | Change |
|------|------|--------|
| `tests/test_services.py` | `test_not_listening_critical_adds_warn` → `test_not_listening_critical_adds_info` | `NOT_LISTENING` demoted to INFO regardless of service severity |
| `tests/test_services.py` | `test_not_listening_high_adds_warn` → `test_not_listening_high_adds_info` | Same — also asserts no WARN finding present |
| `tests/test_logs.py` | `test_finding_is_warn_level` → `test_finding_is_info_level` | IoT local dominance demoted to INFO — asserts `FindingLevel.INFO` |
| `tests/test_logs.py` | `test_score_deduction_one_point` → `test_no_score_deduction` | IoT local dominance: no deduction — asserts `len(local_deductions) == 0` |

---

### v0.2.2 — 4255/4255 (2026-05-02)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4255 passed in 4.42s
```

**New tests (+17):**

#### `tests/test_firewall.py` — `TestOrphanRules` (+3)

| Test | Coverage |
|------|----------|
| `test_bare_port_rule_flagged_when_nothing_listening` | `57621 ALLOW IN` with no TCP or UDP listener → flagged as orphan |
| `test_bare_port_rule_not_flagged_when_tcp_listening` | `57621/tcp` in listening set → not flagged |
| `test_bare_port_rule_not_flagged_when_udp_listening` | `57621/udp` in listening set → not flagged |

#### `tests/test_scoring.py` — `TestScoringInvariants` (+5)

Structural invariants for the scoring engine — properties that must hold regardless of input:

| Test | Invariant |
|------|-----------|
| `test_score_floor_is_zero_on_huge_deduction` | Score never goes below 0 even with 999-point deduction |
| `test_score_ceiling_is_max_on_no_deductions` | Score equals MAX_SCORE when no deductions |
| `test_deductions_are_monotone_decreasing` | Each deduction never increases the score |
| `test_cap_above_current_score_is_noop` | A cap above the current score does not alter it |
| `test_score_after_domain_override_in_valid_range` | After `apply_domain_score_override()`, score ∈ [0, 10] |

#### `tests/test_domain_scores.py` — `TestScoringInvariants` (+7)

Structural invariants for the domain scoring pipeline:

| Test | Invariant |
|------|-----------|
| `test_info_only_findings_do_not_activate_domain` | INFO findings with no deductions do not mark a domain active |
| `test_warn_finding_activates_domain` | A WARN finding marks the corresponding domain active |
| `test_alert_finding_activates_domain` | An ALERT finding marks the corresponding domain active |
| `test_deduction_alone_activates_domain` | A deduction (no finding) still activates the domain |
| `test_global_average_bounded_by_active_domain_scores` | Global average ∈ [min, max] of active domain scores |
| `test_all_domain_scores_in_valid_range` | Every domain score always in [0, MAX_SCORE] |
| `test_compute_global_always_in_valid_range` | `compute_global_from_domains` always returns a value in [0, 10] |

#### `tests/test_manage_logs.py` — `TestStatFallback` (+2)

Regression tests for the v0.2.1 `.stat()` race condition fix. A log file can disappear between the directory scan and the display loop (e.g. logrotate running concurrently). The mock targets only `.log` files to avoid breaking `Path.exists()` on directories (Python 3.12: `exists()` calls `self.stat()` internally).

| Test | Coverage |
|------|----------|
| `TestStatFallback.test_cur_logs_stat_oserror_uses_fallback` | `.stat()` raises `OSError` in `cur_logs` loop → output shows `(0 KB)` and `"?"` without crash |
| `TestStatFallback.test_extra_logs_stat_oserror_uses_fallback` | `.stat()` raises `OSError` in `extra_sections` loop → same fallback output |

**Updated tests (2):**

| File | Test | Change |
|------|------|--------|
| `tests/test_clamav.py` | `test_db_very_outdated_deducts_1` (was `_deducts_2`) | `clamav.db_very_outdated` deduction lowered from 2pt to 1pt (Fix 3) |
| `tests/test_clamav.py` | `test_worst_case` | Total deductions 4→3 (freshclam:1 + db_very_outdated:1 + scan_very_old:1) |

---

### v0.2.0 — 4238/4238 (2026-05-01)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4238 passed in 4.88s
```

**New tests (+32):**

#### `tests/test_kernel_modules.py` (+6)

| Test | Coverage |
|------|----------|
| `TestKernelRebootPending.test_no_reboot_pending_debian_signed_plus_unsigned_same_version` | Running `amd64` with `amd64-unsigned` installed → no reboot warning |
| `TestKernelRebootPending.test_reboot_still_pending_when_genuinely_newer_debian_kernel` | Genuine newer version still triggers reboot pending |
| `TestStripUnsigned.test_strips_unsigned_suffix` | `-unsigned` suffix removed |
| `TestStripUnsigned.test_no_change_without_suffix` | String without suffix unchanged |
| `TestStripUnsigned.test_no_change_ubuntu_style` | Ubuntu-style kernel unchanged |
| `TestStripUnsigned.test_no_change_empty` | Empty string safe |

#### `tests/test_cron.py` (+6)

| Test | Coverage |
|------|----------|
| `TestDetectMta.test_no_sendmail_returns_false` | No sendmail → `(False, "")` |
| `TestDetectMta.test_postfix_detected_via_config_file` | `/etc/postfix/main.cf` present → `(True, "Postfix")` |
| `TestDetectMta.test_exim_detected` | `exim4` in PATH → `(True, "Exim")` |
| `TestDetectMta.test_msmtp_detected` | `msmtp` in PATH → `(True, "msmtp")` |
| `TestDetectMta.test_ssmtp_detected` | `ssmtp` in PATH → `(True, "ssmtp")` |
| `TestDetectMta.test_unknown_mta_returns_empty_name` | sendmail found, unknown provider → `(True, "")` |

#### `tests/test_scoring.py` (+6)

| Test | Coverage |
|------|----------|
| `TestSetGlobalScore.test_override_replaces_raw_score` | Override value returned by `engine.score` |
| `TestSetGlobalScore.test_no_override_by_default` | Raw score used when no override set |
| `TestSetGlobalScore.test_override_clamps_above_max` | Values > 10 clamped to 10 |
| `TestSetGlobalScore.test_override_clamps_below_zero` | Values < 0 clamped to 0 |
| `TestSetGlobalScore.test_level_reflects_overridden_score` | `engine.level` derived from override |
| `TestSetGlobalScore.test_raw_score_unchanged_after_override` | `engine._raw_score` untouched |

#### `tests/test_domain_scores.py` (+14)

**TestToolCaps (7 tests)**

| Test | Coverage |
|------|----------|
| `test_rootkit_two_findings_capped_at_one` | 2×`rootkit.*` deductions → domain gets 1 |
| `test_clamav_two_findings_capped_at_one` | 2×`clamav.*` deductions → domain gets 1 |
| `test_file_integrity_two_findings_capped_at_one` | 2×`file_integrity.*` → domain gets 1 |
| `test_uncapped_prefix_accumulates_fully` | `hardening.*` accumulates without cap |
| `test_caps_do_not_bleed_across_tools` | rootkit cap does not reduce clamav allowance |
| `test_cap_respects_first_deduction_points` | Single 2-pt deduction against cap of 1 → contributes 1 |
| `test_tool_caps_dict_contains_expected_keys` | `_TOOL_CAPS` has rootkit, clamav, file_integrity |

**TestComputeGlobalFromDomains (4 tests)**

| Test | Coverage |
|------|----------|
| `test_average_of_two_active_domains` | Mean of two domain scores, rounded |
| `test_no_active_domains_returns_max` | Empty active set → MAX_SCORE |
| `test_result_clamped_to_max` | Result ≤ 10 |
| `test_result_non_negative` | Result ≥ 0 |

**TestApplyDomainScoreOverride (3 tests)**

| Test | Coverage |
|------|----------|
| `test_engine_score_changes_after_override` | `engine.score` differs from raw after override |
| `test_score_in_valid_range` | Override within [0, 10] |
| `test_debian13_scenario` | 8 deductions raw=2, domain average ≥ 5 |

#### `tests/test_logs.py` (0 new, 3 corrected)

Three tests were corrected to assert the actual intended behaviour (WARN −1 pt for IoT dominance). The previous assertions were verifying the wrong behaviour (INFO, no deduction).

| Test | Before | After |
|------|--------|-------|
| `test_check_logs_emits_warn_finding` | asserted INFO key present | asserts WARN key present |
| `test_finding_is_warn_level` | asserted `FindingLevel.INFO` | asserts `FindingLevel.WARN` |
| `test_score_deduction_one_point` | asserted no deductions | asserts 1 deduction of 1 pt |

---

### v0.1.1 — 4206/4206 (2026-04-29)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4206 passed in 4.19s
```

**New tests — `tests/test_firmware.py` (+4):**

Regression tests for the fwupd 1.9+ tree-format output bug found on Ubuntu 26.04 LTS. fwupdmgr changed its output format from a flat list to a tree structure using `├─`, `└─`, `│` drawing characters. The previous parser captured these as device names, producing garbled output (`│, ├─UEFI CA: (+7)`).

| Test | Coverage |
|------|----------|
| `test_tree_format_extracts_device_names` | `├─` and `└─` lines yield correct device names |
| `test_tree_format_excludes_container_line` | Top-level container name is not captured |
| `test_tree_format_excludes_tree_connectors` | Raw `│`, `├`, `└` characters do not appear as device names |
| `test_tree_format_strips_trailing_colon` | Device names from `├─Name:` lines have no trailing colon |

---

### post-v0.1.0 — 4202/4202 (2026-04-27)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4202 passed in 4.38s
```

**Bugs found during Ubuntu 26.04 LTS first run (`so6ubuntutest`):**

**Root cause fixed — exposure surface: `ssh.not_installed` and `fail2ban.not_installed` not detected:**
Both keys are emitted at `INFO` level by their respective checks. `compute_exposure()` in `exposure.py` only looked in `bad_keys` (ALERT+WARN), so neither key was ever matched — SSH was shown as "key only, root disabled" and fail2ban as "active" even when neither was installed.
Fix: added `all_keys = bad_keys | info_keys`; `ssh.not_installed` and `fail2ban.not_installed` now checked against `all_keys`. (commit `3fa43b5`)

**Root cause fixed — SUID false positive: `sudo.ws` flagged on Ubuntu 26.04:**
`/usr/bin/sudo.ws` is a legitimate binary shipped by the `sudo` package on Ubuntu 26.04 (`dpkg -S` confirmed). Added to `_KNOWN_SUID` whitelist in `suid_audit.py`. (commit `3fa43b5`)

---

### v0.1.0 — 4200/4200 (2026-04-26)

**Platform:** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4200 passed in 4.93s
```

#### Test files (65 total)

| File | Tests | Domain |
|------|-------|--------|
| `test_cis_refs.py` | 39 | CIS benchmark mapping |
| `test_iptables_nftables.py` | 51 | Firewall stack (CHECK 46) |
| `test_firewall.py` | — | UFW rules audit |
| `test_ssh.py` | — | SSH configuration |
| `test_hardening.py` | — | Kernel hardening sysctl |
| `test_kernel_hardening.py` | — | Kernel hardening extended |
| `test_kernel_modules.py` | — | Kernel module audit |
| `test_services.py` | — | Service registry + risk |
| `test_services_state.py` | — | Service state audit |
| `test_docker.py` | — | Docker UFW bypass |
| `test_docker_audit.py` | — | Docker daemon hardening |
| `test_ports.py` | — | Port classification |
| `test_exposure.py` | — | Port exposure analysis |
| `test_scoring.py` | — | Scoring engine |
| `test_domain_scores.py` | — | Domain scores |
| `test_explain.py` | — | --explain TUI |
| `test_display_explain_hint.py` | — | CIS hint display |
| `test_cli.py` | — | CLI argument parsing |
| `test_exit_codes.py` | — | Exit code logic |
| `test_correlation.py` | — | Signal correlation |
| `test_recurrence.py` | — | Recurring findings |
| `test_compare.py` | — | Diff/baseline |
| `test_history.py` | — | Score history |
| `test_ignore.py` | — | Ignore list |
| `test_fixes.py` | — | --fix / --apply |
| `test_auth_log.py` | — | Auth log analysis |
| `test_ufw_logging.py` | — | UFW logging level |
| `test_log_rotation.py` | — | Log rotation |
| `test_cron.py` | — | Cron scheduling |
| `test_cron_audit.py` | — | Cron job security |
| `test_manage_logs.py` | — | Log management TUI |
| `test_webhook.py` | — | Webhook notifications |
| `test_profiles.py` | — | Audit profiles |
| `test_registry.py` | — | Service registry |
| `test_config.py` | — | Configuration store |
| `test_sysinfo.py` | — | System information |
| `test_network_context.py` | — | Network context |
| `test_degraded.py` | — | Degraded mode (ss/rules/log absent) |
| `test_output.py` | — | Terminal output |
| `test_markdown_output.py` | — | Markdown output |
| `test_html_output.py` | — | HTML output |
| `test_csv_output.py` | — | CSV output |
| `test_report.py` | — | Report generation |
| `test_min_level.py` | — | --min-level filter |
| `test_watch.py` | — | --watch mode |
| `test_check_rules.py` | — | Rule validation |
| `test_file_perms.py` | — | File permissions |
| `test_suid_audit.py` | — | SUID/SGID audit |
| `test_user_accounts.py` | — | User accounts |
| `test_password_policy.py` | — | Password policy |
| `test_umask.py` | — | System umask |
| `test_updates.py` | — | System updates |
| `test_ntp.py` | — | NTP sync |
| `test_fail2ban.py` | — | Fail2ban |
| `test_rootkit.py` | — | Rootkit scan |
| `test_auditd.py` | — | Audit daemon |
| `test_secure_boot.py` | — | Secure Boot |
| `test_file_integrity.py` | — | File integrity |
| `test_clamav.py` | — | ClamAV |
| `test_mac_policy.py` | — | AppArmor/SELinux |
| `test_backup.py` | — | Backup detection |
| `test_disk.py` | — | Disk health |
| `test_memory.py` | — | Memory/swap |
| `test_ssl_certs.py` | — | TLS cert expiry |
| `test_systemd_timers.py` | — | Systemd timers |
| `test_desktop_apps.py` | — | Desktop apps |
| `test_samba.py` | — | Samba hardening |
| `test_ddns.py` | — | DDNS detection |
| `test_firmware.py` | — | Firmware/microcode |
| `test_smtp.py` | — | SMTP exposure |
| `test_ipv6.py` | — | IPv6 consistency |
| `test_virtualization.py` | — | Virtualization detection |
| `test_email_store_mgmt.py` | — | Email store management |
| `test_recurrence.py` | — | Recurrence tracking |
| `tests/helpers.py` | — | Shared test utilities |

---


**Test VM:** Linux Mint 22.3 — `so6minttest`
**Reference state** (clean baseline after each test):

```bash
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80
sudo ufw enable
```

---

## Category A — Open-any wildcards

Rules that open all ports to all sources — highest severity.

### A1 — Full wildcard `Anywhere ALLOW IN Anywhere`

```bash
sudo ufw allow from any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.1.0.0 |
| `-2` score deduction | ✔ |
| Fix proposed: `sudo ufw --force delete N` | ✔ |
| Fix applied correctly | ✔ v0.1.0 |
| **IPv6 rule also detected and fixed** (`Anywhere (v6) ALLOW IN Anywhere (v6)`) | ✔ v0.1.0 |

**Root cause fixed :** `ufw status numbered` pads lines with trailing spaces — the `$` anchor in the regex never matched. Fixed: `Anywhere$` → `Anywhere\s*$`. (commit `8ccd9b6`)

**Root cause fixed :** IPv6 wildcard rules (`Anywhere (v6) ALLOW IN Anywhere (v6)`) escaped detection — `open_any_pattern` did not account for the `(v6)` suffix. Fixed: pattern extended with `(?:\s+\(v6\))?` on both sides. Both IPv4 and IPv6 rules are now flagged and fixed independently.

---

### A2 — TCP wildcard `Anywhere/tcp ALLOW IN Anywhere/tcp`

```bash
sudo ufw allow proto tcp from any to any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.1.0 |
| `-2` score deduction | ✔ v0.1.0 |
| Fix applied correctly | ✔ v0.1.0 |
| **IPv6 variant also detected** (`Anywhere/tcp (v6) ALLOW IN Anywhere/tcp (v6)`) | ✔ v0.1.0 |

**Root cause fixed :** Pattern extended to `Anywhere(?:/\w+)?` on both sides to cover `/tcp`, `/udp` variants. (commit `1dd9ede`)

**v0.1.0:** Same IPv6 fix as A1 applies here.

---

### A3 — UDP wildcard `Anywhere/udp ALLOW IN Anywhere/udp`

```bash
sudo ufw allow proto udp from any to any
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Rule allowing all incoming connections without port restriction | ✔ v0.1.0 |
| `-2` score deduction | ✔ v0.1.0 |
| Fix applied correctly | ✔ v0.1.0 |
| **IPv6 variant also detected** | ✔ v0.1.0 |

---

### A4 — All three wildcards simultaneously

```bash
sudo ufw allow from any
sudo ufw allow proto tcp from any to any
sudo ufw allow proto udp from any to any
```

| Expected | Result |
|----------|--------|
| 3 distinct `✖ [ALERT]` findings (IPv4 only, IPV6=no) | ✔ v0.1.0 |
| 6 distinct `✖ [ALERT]` findings (IPv4 + IPv6, IPV6=yes) | ✔ v0.1.0 |
| Score: 1/10 (IPV6=no), Risk level: CRITICAL | ✔ v0.1.0 |
| 6 fixes proposed and applied in reverse index order (avoids renumbering) | ✔ v0.1.0 |

---

### A5 — False positive: source-restricted rule

```bash
sudo ufw allow from 192.168.1.0/24
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` No 'allow from any' rule without port restriction detected | ✔ v0.1.0 |
| Source-restricted rule is NOT flagged as open-any | ✔ |

> `ufw status numbered` shows `Anywhere ALLOW IN 192.168.1.0/24` — destination is `Anywhere` but source is restricted. Pattern correctly requires BOTH sides to be `Anywhere` to flag.

---

## Category B — Duplicate rules

### B1 — Exact duplicate

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/tcp   # UFW says: "Skipping adding existing rule"
```

| Expected | Result |
|----------|--------|
| UFW natively prevents true exact duplicates | ✔ confirmed |
| Not testable via CLI — would require direct file manipulation | noted |

> **Note:** Exact duplicates can only arise from direct `/etc/ufw/` file editing or external tools (Ansible, scripts). UFW's CLI prevents them.

---

### B2 — Same rule, different comments

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (no proto) already present in baseline
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Duplicate UFW rule detected: `80/tcp ALLOW IN Anywhere` | ✔ v0.1.0 |
| Comment stripped before comparison — `# test2` ignored | ✔ v0.1.0 |
| Redundant `80/tcp` deleted, `80` kept | ✔ v0.1.0 |

**Root cause fixed:** Comparison now uses comment-stripped, whitespace-normalized text. (commit `b7a285a`)

---

### B3 — Semantic duplicate: `PORT/proto` redundant when `PORT` exists

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (no proto) already present → 80/tcp is redundant
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Duplicate UFW rule detected: `80/tcp ALLOW IN Anywhere` | ✔ v0.1.0 |
| `-1` score deduction | ✔ v0.1.0 |
| Fix deletes the protocol-specific rule, keeps the broader one | ✔ v0.1.0 |

**Root cause fixed:** Two-pass detection — first pass collects all protocol-less rules, second pass checks if `PORT/proto` is a subset of an existing `PORT` rule. (commit `b7a285a`)

---

### B4 — Semantic duplicate: UDP variant

```bash
sudo ufw allow 53/udp
sudo ufw allow 53
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` `53/udp` detected as redundant | ✔ unit test |

> Validated via unit test only (DNS port — not in services registry, no practical risk on the VM).

---

### B5 — No false positive: `PORT/tcp` + `PORT/udp` without `PORT`

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/udp
# No bare "80" rule
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` No duplicate UFW rules detected | ✔ v0.1.0 |
| `80/tcp` and `80/udp` are complementary — not flagged | ✔ v0.1.0 |

> Also note: when baseline has `80` (bare), adding `80/tcp` + `80/udp` correctly flags BOTH as semantic duplicates of `80`. Verified live.

---

## Category C — Critical services exposed

### C1 — SSH exposed (baseline state)

SSH is always present in the reference state (`ufw allow 22/tcp`). This scenario documents the expected behaviour for a critical service with an unrestricted UFW ALLOW rule.

```bash
# Baseline state — SSH already exposed
sudo bob
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 22/tcp — open to internet — no source restriction in UFW | ✔ v0.1.0.0 |
| Risk context CRITICAL displayed | ✔ v0.1.0.0 |
| `-2` score deduction (NAT/local context) | ✔ v0.1.0.0 |
| Panorama: SSH `⚠` (OPEN_WORLD) | ✔ v0.1.0.0 |
| DDNS `→ 22/tcp` | ✔ v0.1.0.0 |
| **Remediation:** source-restrict → switches to OPEN_LOCAL (WARN not ALERT, no deduction) | ✔ v0.1.0.0 |

> **Note:** `openssh-server` must be installed and active (`sudo apt install openssh-server && sudo systemctl enable --now ssh`). If inactive/disabled, the service is INFO-only with no port exposure check.

---

### C3 — Redis exposed on all interfaces (service installed and active)

```bash
sudo ufw allow 6379
# Redis configured to bind 0.0.0.0 (not the default)
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 6379/tcp — open to internet (Action required) | ✔ v0.1.0 |
| Risk context CRITICAL displayed | ✔ v0.1.0 |
| `-2` score deduction (NAT context) | ✔ v0.1.0 |
| Panorama: Redis `⚠` | ✔ v0.1.0 |
| DDNS cross-check: `→ 6379/tcp` | ✔ v0.1.0 (`6379/udp` filtered — no UDP listener) |

**Root cause fixed (obs 1):** CRITICAL/HIGH services with `OPEN_WORLD` exposure now raise `alert()` instead of `warn()`, moving them to "Action required". (commit `e01b24b`)

---

### C3b — Redis loopback only — false positive fix 

Default Redis configuration: binds to `127.0.0.1` only, but a permissive UFW rule exists.

```bash
sudo ufw allow 6379
# Redis default: bind 127.0.0.1 (loopback only)
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 6379/tcp — bound to localhost only — UFW rule has no effect on external access | ✔ v0.1.0 |
| No ALERT, no score deduction | ✔ v0.1.0 |
| Panorama: Redis `✔` (rule exists, exposure = LOOPBACK) | ✔ v0.1.0 |
| DDNS: `6379/tcp` NOT in exposed ports (loopback only) | ✔ v0.1.0 |
| DDNS: `6379/udp` NOT in exposed ports (no UDP listener) | ✔ v0.1.0 |

**Root cause fixed :** `_classify_exposure()` was UFW-only and did not cross-check actual socket bindings. Fix: `PortsSnapshot` is now collected before CHECK 3; ports where all `ss` bindings are loopback get `Exposure.LOOPBACK` (INFO, no deduction). `_find_open_ports()` in `ddns.py` now also receives the `loopback_ports` and `active_ports` sets. (commits `2bfc85b`, `64311be`)

---

### C2 — MySQL exposed (service not installed)

```bash
sudo ufw allow 3306
```

| Expected | Result |
|----------|--------|
| No service alert (MySQL not installed) | ✔ v0.1.0 |
| Port 3306 open in UFW but unmatched to any installed service | ✔ v0.1.0 |
| DDNS: `3306/tcp` and `3306/udp` NOT in exposed ports (no active listener) | ✔ v0.1.0 |

> **Behaviour updated :** `_find_open_ports()` now cross-checks against actual non-loopback listeners (`active_ports` set from `ss`). Orphan UFW rules (port open, no service running) are excluded from the DDNS exposed ports list. `3306/tcp` and `3306/udp` no longer appear in DDNS findings when MySQL is not installed.

---

### C4 — Nginx exposed (medium-risk service, installed and active)

```bash
sudo apt install nginx
sudo ufw allow 80
sudo bob
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` Port 80/tcp — open to internet — no source restriction in UFW | ✔ v0.1.0.0 |
| Risk context MEDIUM displayed | ✔ v0.1.0.0 |
| `-1` score deduction | ✔ v0.1.0.0 |
| Panorama: Nginx `⚠` | ✔ v0.1.0.0 |
| Finding appears in *Possible improvements* (not *Action required*) | ✔ v0.1.0.0 |

> Medium-risk services (`warn()` not `alert()`) — distinction from critical services like SSH or Redis.

---

### C5 — Samba exposed (critical service, installed and active)

```bash
sudo apt install samba
sudo ufw allow 445
sudo ufw allow 139
sudo bob
```

| Expected | Result |
|----------|--------|
| `✖ [ALERT]` Port 445/tcp — open to internet — no source restriction in UFW | ✔ v0.1.0.0 |
| `✖ [ALERT]` Port 139/tcp — open to internet | ✔ v0.1.0.0 |
| Risk context CRITICAL displayed (ransomware vector, EternalBlue) | ✔ v0.1.0.0 |
| `-2` deduction × 2 ports (−4 total) | ✔ v0.1.0.0 |
| Panorama: Samba `⚠` (OPEN_WORLD) | ✔ v0.1.0.0 |
| Both ports in *Action required* block | ✔ v0.1.0.0 |
| DDNS `→ 445/tcp`, `→ 139/tcp` | ✔ v0.1.0.0 |

> **Cleanup:** `sudo apt remove --purge samba && sudo ufw delete allow 445 && sudo ufw delete allow 139`

---

### C6 — Ports open in UFW, services not installed (multiple services)

For each entry below: open the port in UFW with no matching service installed. Expected behaviour: **no service-level alert**, port may appear as an unmatched open rule.

```bash
sudo ufw allow <PORT>
sudo bob
```

| Service | Port | Expected behaviour | Result |
|---------|------|--------------------|--------|
| VNC Server | 5900/tcp | No service alert — VNC not detected | ✔ v0.1.0.0 |
| FTP Server | 21/tcp | No service alert — FTP not detected | ✔ v0.1.0.0 |
| PostgreSQL | 5432/tcp | No service alert — PostgreSQL not detected | ✔ v0.1.0.0 |
| Mosquitto (MQTT) | 1883/tcp | `ℹ [INFO]` 1883/tcp loopback — UFW rule has no effect; 8883/tcp not listening — no message; Panorama ✔ | ✔ v0.1.0.0 ² |
| WireGuard | 51820/udp | `ℹ [INFO]` WireGuard installed but stopped/disabled — no port exposure check (INACTIVE early return) | ✔ v0.1.0.0 ¹ |
| Gitea | 3000/tcp | No service alert — Gitea not detected | ✔ v0.1.0.0 |
| Jellyfin | 8096/tcp | No service alert — Jellyfin not detected | ✔ v0.1.0.0 |
| Home Assistant | 8123/tcp | No service alert — HASS not detected | ✔ v0.1.0.0 |
| Cockpit | 9090/tcp | No service alert — Cockpit not detected | ✔ v0.1.0.0 |

> For all above: the port should appear in **UFW RULES ANALYSIS** if an active listener exists, but since the service is not installed there is no listener — no ALERT in NETWORK SERVICES ANALYSIS.
> DDNS cross-check: none of these ports should appear in DDNS exposed list (no active listener — v0.1.0).

> ¹ WireGuard was already installed (but inactive) on the test VM. The "not installed" path for WireGuard remains untested — behaviour confirmed: INACTIVE service with an open UFW rule → INFO only, no ALERT, no score deduction.

> ² Mosquitto was installed and ACTIVE on the test VM (not matching the "not installed" C6 scenario). Test revealed a bug: registry ports not actively listening (8883/tcp) incorrectly triggered `Exposure.NO_RULE` → panorama ✖. Fixed in beta (commit `67743ca`): `Exposure.NOT_LISTENING` for non-listening registry ports → panorama ✔.

> **Already validated:** MySQL / MariaDB (3306) → C2

---

### C7 — CUPS exposed (low-risk service, usually pre-installed on desktop Linux)

CUPS (print server) listens on `127.0.0.1:631` by default. This test verifies behaviour when CUPS is active and a UFW rule exists.

```bash
# CUPS is often pre-installed on Linux Mint
sudo ufw allow 631
sudo bob
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 631/tcp — bound to localhost only — UFW rule has no effect | ✔ v0.1.0.0 |
| No ALERT, no score deduction (loopback binding) | ✔ v0.1.0.0 |
| Panorama: CUPS `✔` (rule exists, loopback → INFO) | ✔ v0.1.0.0 |

> If CUPS binds to `0.0.0.0`: `⚠ [WARNING]` Port 631/tcp — open to internet (low risk, nature=improvement).

---

## Category D — IPv6 consistency

### D1 — IPv4 rules present, no IPv6 equivalent (warning expected)

```bash
# From baseline: 22/tcp and 80 are present, no (v6) rules
sudo ufw status numbered
```

> **Note:** Some distributions (or VMs with `IPV6=no` in `/etc/default/ufw`) do not add IPv6 rules. If all rules are already paired (IPv4 + IPv6), use `sudo ufw --force reset` and re-add only IPv4 rules:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   # Do NOT let UFW create (v6) rules — requires IPV6=no
sudo ufw enable
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` IPv6 rules missing — only IPv4 rules present | ✔ v0.1.0 live (IPV6=no VM) |
| `-1` score deduction | ✔ v0.1.0 live |
| Live test | ✔ v0.1.0 |

---

### D2 — IPv4 and IPv6 rules both present (no warning)

```bash
# Baseline with IPV6=yes (default): 22/tcp and 22/tcp (v6) both present
sudo bob
```

| Expected | Result |
|----------|--------|
| `✔ [OK]` IPv4 and IPv6 rules both present | ✔ v0.1.0 live (IPV6=yes, A1 test) |
| No deduction | ✔ v0.1.0 live |
| Live test | ✔ v0.1.0 |

---

## Category E — Loopback-only ports 

### C8 — SSH restricted to LAN (OPEN_LOCAL path)

```bash
sudo ufw delete allow 22/tcp
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp
sudo bob
```

| Expected | Result |
|----------|--------|
| `⚠ [WARNING]` Port 22/tcp — restricted to local network by UFW rule | ✔ v0.1.0 |
| No score deduction (OPEN_LOCAL ≠ OPEN_WORLD) | ✔ v0.1.0 |
| Panorama: SSH `✔` (LAN restriction = correct config) | ✔ v0.1.0 |
| DDNS: `ℹ` Port 22/tcp restricted to local network (not ALERT) | ✔ v0.1.0 |
| Risk context CRITICAL still displayed | ✔ v0.1.0 |

> **Cleanup:** `sudo ufw delete allow from 192.168.1.0/24 to any port 22 proto tcp && sudo ufw allow 22/tcp`

---



### E1 — Port listening on localhost only, no UFW rule — INFO not ALERT

```bash
# Any process bound exclusively to 127.0.0.1 without a UFW rule
# Example: netcat listening on loopback (or rely on Redis default config)
# Redis default: bind 127.0.0.1 — no UFW rule needed
sudo bob
```

| Expected | Result |
|----------|--------|
| `ℹ [INFO]` Port 6379/tcp — bound to localhost only — no UFW rule needed (covered by default deny) | ✔ v0.1.0.0 |
| No ALERT, no score deduction | ✔ v0.1.0.0 |
| Redis panorama ✔ | ✔ v0.1.0.0 |
| Message uses `services.exposure.loopback_no_rule` locale key (added with `Exposure.LOOPBACK_NO_RULE` fix) | ✔ v0.1.0.0 |

> **Note:** The original expected message referenced `ports.uncovered_local`. In practice, Redis on loopback with no UFW rule is handled by the services check path (`Exposure.LOOPBACK_NO_RULE`), not the ports check. The `ports.uncovered_local` key (`"Port {port} — bound to localhost only — no external exposure"`) applies to the ports section for processes not covered by the service registry.

---

## Additional observations

### Obs — Avahi panorama shows ✖ despite INFO message (v0.1.0)

Avahi binds on `0.0.0.0:5353/udp` (mDNS multicast). No UFW rule exists for 5353 → `Exposure.NO_RULE` → panorama ✖. The service check correctly emits `ℹ [INFO]` "covered by default deny policy", but the panorama symbol is set by the `NO_RULE` enum value regardless of the INFO severity.

**Root cause:** `NO_RULE` on a non-loopback, non-listening-externally port (multicast/LAN-only in practice) is treated identically to `NO_RULE` on a genuinely exposed port. A future fix could introduce `Exposure.NO_RULE_MULTICAST` or a broader mechanism to distinguish locally-scoped `NO_RULE` from truly exposed `NO_RULE`.

**Impact:** cosmetic only — no false ALERT, no score deduction.

---



### Obs — DDNS does not detect protocol-less rules (fixed)

With `80 ALLOW IN Anywhere` (no `/tcp`), the DDNS cross-check previously showed nothing for port 80.

**Root cause fixed:** `_find_open_ports()` now handles bare port rules — adds both `PORT/tcp` and `PORT/udp` to the open ports list. (commit `e01b24b`)

**Validated (v0.1.0):** Bare rule `80 ALLOW` with Nginx listening on `0.0.0.0:80` → DDNS correctly lists `→ 80/tcp` only (`80/udp` filtered — no UDP listener on port 80).

---

### Obs — DDNS false positives: system ports and orphan rules 

```bash
sudo ufw allow 53
sudo ufw allow 3306
sudo ufw allow 6379
# Redis on 127.0.0.1 only, MySQL not installed
```

| Expected | Result |
|----------|--------|
| DDNS: `53/tcp`, `53/udp` NOT listed (system port filter) | ✔ v0.1.0.0 |
| DDNS: `3306/tcp`, `3306/udp` NOT listed (no active listener) | ✔ v0.1.0.0 |
| DDNS: `6379/tcp`, `6379/udp` NOT listed (loopback only / no UDP listener) | ✔ v0.1.0.0 |

**Root cause fixed :** Added `_DDNS_SYSTEM_PORTS` constant (53, 67, 68, 546, 547, 5353) and `active_ports` cross-check in `_find_open_ports()`. Only ports with an actual non-loopback listener in `ss` output are included in the DDNS exposed list. (commit `64311be`)

---

### Obs — UFW allows wildcard rules after specific rules without error

```
Anywhere/tcp    ALLOW IN    Anywhere/tcp
22/tcp          ALLOW IN    Anywhere
```

UFW does not warn that `Anywhere/tcp` makes `22/tcp` redundant. bob correctly flags the wildcard.

---

## B1 note — exact duplicates via file manipulation

To test exact duplicates that UFW's CLI prevents, rules can be injected directly:

```bash
sudo cp /etc/ufw/user.rules /etc/ufw/user.rules.bak
# Manually duplicate a rule line in user.rules
sudo ufw reload
sudo bob
# Cleanup:
sudo cp /etc/ufw/user.rules.bak /etc/ufw/user.rules
sudo ufw reload
```

Not yet tested — low practical priority since UFW CLI prevents this.
