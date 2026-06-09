*[Lire en français](CHANGELOG_FULL_FR.md)* · *[TL;DR](../CHANGELOG.md)*

# BOB — Bodyguard Of Bits — Changelog

All notable changes to this project are documented here.

---

## [v0.10.0] — 2026-06-09

**First v0.10.x release — preparation release** opening the next BREAKING bundle window. Ships the D-4 sub-check migration shim foundation + ScoreEngine ignore.yml back-compat wiring + SNAPSHOT.md refresh, while intentionally deferring the actual D-4 split implementations and the F-1 parallel-check refactor to v0.10.1+ hardening patches.

### Why a preparation release

Two sub-agent audits were run on 2026-06-08 to scope the v0.10.0 BREAKING bundle work:

1. **D-4 sub-check candidates audit** — walked `bob/checks/*.py` looking for finding keys that lump multiple subcases under a single name. Identified 8 ranked split candidates with effort estimates per split, plus a "do NOT split" list of 5 keys that look like candidates but stay unified. Total D-4 effort estimate: **≈ 20 hours** (wildcard shim contract is the chief novelty vs v0.9.2's simple `str → str` baseline shim).

2. **F-1 parallel-check thread-safety audit** — inventoried shared state in `bob/runner.py::run_checks` (engine, report, output, i18n, GEO cache, network_context, audited_ports cross-check), classified check functions as pure vs side-effecting (~38 of ~38 are pure once their snapshot is collected), identified torn-read risks in apt-related checks (apt-get -s + apt-cache policy take a frontend lock). Recommended **Option B**: Phase 0 sequential firewall/ports/network_context (cross-check deps) + Phase 1 `ThreadPoolExecutor(max_workers=min(8, cpu_count()))` snapshot+check fan-out with apt slot serialization + Phase 2 sequential merge in canonical `_SECTIONS` order. Total F-1 effort estimate: **≈ 6-8 hours** + 4 new determinism test files (`test_v0100_parallel_determinism.py`, `_parallel_flake.py`, `_parallel_json_stable.py`, `_apt_slot.py`).

Combined effort estimate: **≈ 30 hours** for the full v0.10.0 BREAKING bundle (D-4 splits + F-1 + SNAPSHOT refresh + release surface), which exceeded a single ship session. The pragmatic call was to **stage the work**:

  - **v0.10.0 (this release)** — ship the D-4 shim foundation so the eight follow-up patches can land without re-touching the shim file. Ship the SNAPSHOT.md refresh so the project-snapshot doc covers the three majeures of drift the v0.10.x branch sits on top of. Bump the version to mark the v0.10.x branch open.
  - **v0.10.1+** — implement the 8 D-4 splits one at a time (Rank 1 first as the canonical ssh.x11 server/client example), each with its own locale + EXPLAIN + tests. Implement F-1 Option B in a dedicated patch with the four determinism test files landing alongside the refactor.

This approach mirrors the v0.7.x → v0.8.x cycle where the BREAKING bundle landed as a single ship (v0.8.0 + the v0.8.0 drift batch + v0.7.0-deferred items) and the hardening patches followed (v0.8.1 / v0.8.2 / v0.8.3 / v0.8.4).

### D-4 migration shim foundation

[bob/_v100_subcheck_renames.py](../bob/_v100_subcheck_renames.py) — new 90-line module exporting:

```python
SUBCHECK_RENAMES_V100: dict[str, str] = {
    "ssh.x11_forwarding":             "ssh.x11.forwarding.*",
    "ssh.host_key_dsa":               "ssh.dsa.host_key",
    "ssh.dsa_key":                    "ssh.dsa.private_key",
    "ssh.authorized_keys_dsa":        "ssh.dsa.authorized_key",
    "ssh.known_hosts_deprecated":     "ssh.dsa.known_host",
    "auditd.missing_sensitive_rules": "auditd.missing.*",
    "samba.guest_writable":           "samba.share.guest_writable.*",
    "samba.guest_readonly":           "samba.share.guest_readonly.*",
    "log_rotation.journald_volatile": "log_rotation.journald.*",
    "firewall_rules.duplicate_found": "firewall_rules.duplicate.*",
    "kernel_modules.risky_fs":        "kernel_modules.risky.*",
    "kernel_modules.risky_net":       "kernel_modules.risky.*",
    "ssh.weak_ciphers":               "ssh.weak.cipher.*",
    "ssh.weak_macs":                  "ssh.weak.mac.*",
    "ssh.weak_kex":                   "ssh.weak.kex.*",
}

def matches_legacy_ignore(finding_key: str, ignore_entry: str) -> bool: ...
def any_legacy_ignore_matches(finding_key: str, ignore_keys: ...) -> bool: ...
```

The shape changed vs v0.9.2's `bob/_v090_renames.py` because D-4 covers three migration topologies in one map:

1. **1-to-1 simple renames** (Rank 2 DSA family — `ssh.host_key_dsa` → `ssh.dsa.host_key`). The pattern is the exact target with no wildcard. `fnmatch.fnmatch("ssh.dsa.host_key", "ssh.dsa.host_key")` returns True; the helper handles them identically to the wildcard cases.
2. **1-to-N enumerated splits** (Rank 1 ssh.x11 server+client, Rank 5 journald volatile+storage_unknown, Rank 6 firewall_rules duplicate.exact+duplicate.proto_implicit). The pattern uses `*` to cover every canonical sibling without listing them inline (which would require keeping the map in sync as new siblings land).
3. **1-to-many runtime-discovered** (Rank 4 samba per-share, Rank 7 kernel modules per-name, Rank 8 SSH weak crypto per-algo). The canonical key set is unbounded — the wildcard form is the only viable representation.

The runtime helper `matches_legacy_ignore(finding_key, ignore_entry)` resolves `ignore_entry` against `SUBCHECK_RENAMES_V100` and runs `fnmatch.fnmatch(finding_key, pattern)`. Returns False on unknown entries (the operator typed something not in the legacy map — probably already-canonical or a typo). `any_legacy_ignore_matches(finding_key, ignore_keys)` is the convenience wrapper that returns True if ANY entry in the operator's `ignore.yml` covers the finding key via the legacy path.

### ScoreEngine.apply ignore.yml back-compat wiring

[bob/scoring.py::ScoreEngine.apply](../bob/scoring.py) was updated to consult both the existing exact-match path AND the new legacy-glob path:

```python
def _is_ignored(key: str | None) -> bool:
    if not (ignored_keys and key):
        return False
    if key in ignored_keys:
        return True
    return any_legacy_ignore_matches(key, ignored_keys)

for deduction in result.deductions:
    if not _is_ignored(deduction.key):
        self._apply_deduction(deduction)
for finding in result.findings:
    if _is_ignored(finding.key):
        self.ignored_findings.append(finding)
    else:
        self.findings.append(finding)
```

Today this changes no visible behavior because no check emits the new canonical sub-keys yet. The shim becomes load-bearing as soon as v0.10.1 ships the first D-4 split. Operators upgrading their `ignore.yml` to the canonical sub-keys see no behavior change (the exact-match path catches them first).

### SNAPSHOT.md refresh

[DOCUMENTS/SNAPSHOT.md](../DOCUMENTS/SNAPSHOT.md) was last refreshed for v0.7.4 (2026-06-02, refreshed from the v0.6.0 baseline). v0.10.0 adds two paragraphs:

- **v0.7.4 → v0.9.2 drift, one paragraph** — covers the v0.8.x cycle (v0.8.0 drift batch + framing actions A1+A2 + silent-feature-gap audit closing v0.7.x, v0.8.1 deep-hardening 26 tiers across 3 sub-agent passes including the workstation alias retrait BREAKING, v0.8.2 conservative bundle + `bob/_i18n_safe.py` consolidation + `--test-webhook` + `--check=list` descriptions + D-3 deprecation warning + locale linter, v0.8.3 hotfix UnboundLocalError audit path from the v0.8.2 ship shadowing `UserConfig` module import inside `main()`, v0.8.4 cleanup `is_unit_enabled` 7-month-monitoring + new `DOCUMENTS/TUTORIAL{,_FR}.md`) and the v0.9.x cycle (v0.9.0 BREAKING bundle closing D-1/D-2/D-3/TD-1/F-2/F-3 + bash completion `cur="="` fix, v0.9.1 hotfix F-3 message UX bracketed-fallback from `i18n.t` called pre-init inside `parse_args`, v0.9.2 BaselineLoadError i18n + cross-version baseline migration shim).

- **v0.10.0 preparation paragraph** — describes the staging strategy: D-4 migration shim foundation in this release + D-4 split implementations and F-1 Option B refactor in v0.10.1+ hardening patches. Records the two sub-agent audit reports and the effort estimates that v0.10.1+ work tracks directly.

The one-screen view banner was updated from `bob v0.8.0 ~30.7 kLoC` to `bob v0.10.0 ~32+ kLoC`. The detailed module-by-module sections downstream from the banner are LARGELY UNCHANGED structurally — the v0.8.0 split table, the v0.7.4 layer diagram, and the module call-out paragraphs remain factually accurate as of v0.9.2 with respect to file paths and high-level shape (the v0.8.x / v0.9.x drift was mostly in-place behaviour changes, not architectural splits). The drift paragraphs above are the authoritative pointer to the per-release detail in `DOCUMENTS/CHANGELOG_FULL.md` for any consumer needing finer-grained snapshot detail; a deeper module-by-module refresh is a v0.10.2+ documentation patch candidate when post-D-4 + post-F-1 splits warrant it.

### Numbers

- **Tests 6242 → 6242** (no delta in this preparation release). 0 regression.
- 1 new module ([bob/_v100_subcheck_renames.py](../bob/_v100_subcheck_renames.py)) — 90 lines.
- 1 production code file modified ([bob/scoring.py](../bob/scoring.py)) — `_is_ignored` helper + `any_legacy_ignore_matches` consultation, ~15 lines changed.
- 1 documentation file modified ([DOCUMENTS/SNAPSHOT.md](../DOCUMENTS/SNAPSHOT.md)) — 3 paragraphs added (v0.7.4 → v0.9.2 drift + v0.10.0 preparation + version banner bump).
- 4 changelog surfaces + TESTING.md + man pages + debian + rpm + memory note bumped per convention.

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

No migration action required from v0.9.x. The D-4 shim foundation does not change visible behavior on existing `ignore.yml` entries because the legacy keys are not yet emitted as canonical sub-keys. Operators who upgrade to v0.10.0 today will see exactly the same audit output as on v0.9.2.

The shim becomes load-bearing once v0.10.1+ ships the first D-4 split. At that point legacy `ignore.yml` entries continue to silence the about-to-be-split sub-keys without operator intervention — the only ones who need to act are operators who want to migrate their `ignore.yml` to the canonical sub-key names for clarity.

**v0.7.x remains EOL** (formal declaration in [SECURITY.md](../SECURITY.md) since v0.8.1).
**v0.6.x remains EOL** (declared in v0.7.2).

### Deferred to v0.10.1+ (intentionally staged)

- **D-4 Rank 1** — `ssh.x11_forwarding` split into `ssh.x11.forwarding.server` (rename) + `ssh.x11.forwarding.client` (NEW client-side detection in `_check_client_config`). Smallest split, canonical D-4 example. Effort: ~2 h.
- **D-4 Rank 2** — DSA family unification under `ssh.dsa.*` prefix. 4 × 1-to-1 simple renames. Effort: ~2 h.
- **D-4 Rank 3** — `auditd.missing_sensitive_rules` split into 4 file-family buckets (`passwd_group`, `shadow`, `sudoers`, `ssh_config`) with per-bucket cap. Effort: ~3 h.
- **D-4 Rank 4** — `samba.guest_{writable,readonly}` split into per-share-name keys via runtime emit loop. Wildcard ignore.yml entry pattern is the first runtime-discovered case shipped. Effort: ~3 h.
- **D-4 Rank 5** — `log_rotation.journald_volatile` split into `volatile` vs `storage_unknown`. Effort: ~1 h.
- **D-4 Rank 6** — `firewall_rules.duplicate_found` split into `duplicate.exact` vs `duplicate.proto_implicit`. Effort: ~2 h.
- **D-4 Rank 7** — `kernel_modules.risky_{fs,net}` split into per-module-name keys with cap. Effort: ~3 h.
- **D-4 Rank 8** — `ssh.weak_{ciphers,macs,kex}` split into per-algorithm keys with cap. Effort: ~3 h.
- **F-1** — runner.py Option B refactor (Phase 0 / Phase 1 ThreadPoolExecutor / Phase 2 sequential merge + apt slot serialization). 4 new determinism test files. Effort: ~6-8 h.

Each item lands as its own v0.10.x patch with locale + EXPLAIN + tests. The pattern matches the v0.8.x cycle (v0.8.0 BREAKING + 4 hardening patches v0.8.1 / v0.8.2 / v0.8.3 / v0.8.4) and the v0.9.x cycle (v0.9.0 BREAKING + 2 hardening patches v0.9.1 / v0.9.2).

### Lessons

- **Stage BREAKING bundles when the audit-driven effort estimate exceeds a single ship session.** v0.10.0 audits estimated ~30 hours of implementation work. Shipping the shim foundation in a preparation release means the eight follow-up patches don't need to re-touch the shim file (or worry about back-compat for already-shipped legacy entries), and the bug surface is small per patch instead of one large surface across the bundle. This is the same staging pattern the v0.7.0 cycle used (T1 / T2 / T3 each landed as a separate Phase) and the v0.8.x cycle used (each `T<n>` tier shipped as its own commit).
- **Sub-agent audits remain the cheapest way to scope a BREAKING bundle.** Two parallel audits running in background for ~3 min each produced concrete file:line citations + ranked candidate lists + effort estimates + recommended Options that informed the staging decision. Without the audits, the staging call would have been a gut estimate; with them, it's a defensible scope decision the next operator can re-verify.
- **The shim foundation is forward-compatible** — adding a new D-4 rename in v0.10.x+ is a one-line entry in `SUBCHECK_RENAMES_V100`; the runtime helpers and the `ScoreEngine.apply` wiring already cover it. The cost of a wrong D-4 candidate decision is now a one-line revert, not a multi-file rollback.

---

## [v0.9.2] — 2026-06-08

**Closes the two i18n / UX gaps documented in the v0.9.1 CHANGELOG as "deferred to v0.10.0+"** — both surfaced by the v0.9.0 cross-distro field test campaign. Both are purely additive (no BREAKING wire-format change, no risk to the golden audit path), so they fit naturally as a v0.9.x patch rather than waiting for v0.10.0.

### BaselineLoadError i18n

Pre-v0.9.2, the four ``BaselineLoadError`` raise sites in [bob/compare.py](../bob/compare.py) used hardcoded English messages even on FR systems. Only the "Erreur :" prefix was localised (via the locale key ``cli.error.prefix`` in the [bob/__main__.py](../bob/__main__.py) error-display path), the message body itself stayed English:

```
Erreur : Baseline file not found: /tmp/X — check the path and that the file exists on this machine.
```

Unlike the v0.9.0 F-3 issue (which fired before ``i18n.init()``), these raises happen AFTER ``i18n.init()`` (load_baseline is invoked from the audit path, not from ``parse_args``), so the messages CAN be properly i18n'd via the ``bob._i18n_safe.t_or_hardcoded`` helper.

Four new locale keys land under ``compare.baseline_load.*`` (EN + FR):

| Key                                  | EN baseline                                                                                                                                                | FR localisation                                                                                                                                              |
|--------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ``not_found``                         | ``Baseline file not found: {path} — check the path and that the file exists on this machine.``                                                              | ``Baseline introuvable : {path} — vérifie le chemin et que le fichier existe sur cette machine.``                                                              |
| ``invalid_json``                      | ``Baseline file {path} could not be read or parsed as JSON: {error}``                                                                                       | ``Le fichier baseline {path} n'a pas pu être lu ou parsé comme JSON : {error}``                                                                                |
| ``v1_schema``                         | ``Baseline file {path} carries the legacy v0.6.x schema (schema_version="1") which was retired in v0.9.0 F-3. Re-generate the baseline on a v0.9.0+ host.`` | ``Le fichier baseline {path} porte le schéma legacy v0.6.x (schema_version="1") qui a été retiré en v0.9.0 F-3. Régénère le baseline sur un host v0.9.0+.``    |
| ``bad_shape``                         | ``Baseline file {path} has unexpected shape: {error}``                                                                                                       | ``Le fichier baseline {path} a une forme inattendue : {error}``                                                                                                |

The ``t_or_hardcoded`` helper falls back to the EN baseline at module-level when i18n is not initialised — same pattern as the v0.8.2 ``bob/_i18n_safe.py`` consolidation. The four BaselineLoadError sites now read:

```python
msg = t_or_hardcoded(
    "compare.baseline_load.not_found",
    f"Baseline file not found: {src} — check the path and "
    f"that the file exists on this machine.",
).format(path=src)
raise BaselineLoadError(msg) from exc
```

Post-v0.9.2 the FR system shows:

```
Erreur : Baseline introuvable : /tmp/X — vérifie le chemin et que le fichier existe sur cette machine.
```

### Cross-version baseline migration shim

Pre-v0.9.2, a baseline written by v0.7.x / v0.8.x carried finding keys with prefixes renamed in v0.9.0 D-1:

```
iptables_nft.input_accept
iptables_nft.forward_accept
cron_audit.pipe_to_shell
...
```

The v0.9.0+ audit emits the canonical prefixes (``firewall_iptables.input_accept``, ``cron.pipe_to_shell``, …), so ``compute_delta`` saw the same physical issue as both *resolved* (old key in ``prev.finding_keys``) AND *new* (canonical key in ``curr.finding_keys``). The Ubuntu 26.04 field test surfaced the bug deterministically:

```
✔ [OK] Résolu : iptables_nft.input_accept
⚠ [ATTENTION] Nouveau finding : firewall_iptables.input_accept
```

Two findings shown for the same underlying issue. Documented in the v0.9.0 CHANGELOG as "ignore.yml entries must be migrated by hand" — but this was the diff path, not ignore.yml.

The fix is a tiny pure transform in [bob/_v090_renames.py](../bob/_v090_renames.py):

```python
def remap_finding_key(key: str) -> str:
    if "." not in key:
        return key
    prefix, _, suffix = key.partition(".")
    new_prefix = SECTION_RENAMES_V090.get(prefix)
    if new_prefix is None:
        return key
    return f"{new_prefix}.{suffix}"
```

Wired into ``load_baseline`` after the raw JSON parse, before the AuditBaseline construction:

```python
raw_keys = raw.get("finding_keys")
if isinstance(raw_keys, list):
    finding_keys = [remap_finding_key(str(k)) for k in raw_keys]
else:
    finding_keys = None
```

Covers all 7 D-1 renames. Self-contained:

- Does NOT modify the on-disk baseline file (the next audit's ``save_baseline`` writes canonical names — natural self-healing)
- Does NOT affect baselines already written by v0.9.0+ (the shim is idempotent on canonical input; ``remap_finding_key("ssh.password_auth")`` returns ``"ssh.password_auth"`` unchanged)
- Does NOT touch ``ignore.yml`` semantics (still requires manual migration per the v0.9.0 contract)

Post-v0.9.2, the same Ubuntu 26.04 field test scenario surfaces cleanly:

```
ℹ [INFO] Score inchangé
✔ [OK] Aucun changement détecté depuis le dernier audit
```

### Shared map extraction

Pre-v0.9.2 the legacy → canonical map lived inline in [bob/runner.py](../bob/runner.py) as ``_RENAMED_SECTIONS_V090``. Extracting it to a dedicated module [bob/_v090_renames.py](../bob/_v090_renames.py) was necessary because:

- ``bob/compare.py`` needs the map for the migration shim
- ``bob/compare.py`` cannot import from ``bob/runner.py`` (runner already imports from compare → circular)
- Duplicating the dict would risk drift between the two call sites (a v0.10.0 contributor adds an entry to one but not the other)

[bob/runner.py](../bob/runner.py) keeps the legacy name ``_RENAMED_SECTIONS_V090`` as a back-compat re-export pointing at the shared dict:

```python
from bob._v090_renames import SECTION_RENAMES_V090 as _RENAMED_SECTIONS_V090
```

[tests/test_v092_baseline_i18n_and_shim.py::TestV090RenamesSharedModule::test_runner_legacy_alias_points_at_shared_module](../tests/test_v092_baseline_i18n_and_shim.py) asserts ``is`` identity (same object) — drift between the two names becomes impossible. ``test_seven_entries_match_d1_table`` pins the exact map content against the documented CHANGELOG v0.9.0 table.

### Numbers

- **Tests 6212 → 6242** (+30 across 4 classes):
  - ``TestV090RenamesSharedModule`` (2 tests): shared-map back-compat + 7-entry contract
  - ``TestRemapFindingKey`` (18 tests): 8 legacy → canonical parametrize + 6 canonical pass-through + 4 unaffected edge cases (including suffix-with-dots)
  - ``TestLoadBaselineMigrationShim`` (4 tests): v0.7.x and v0.8.x baselines remapped, v0.9.x pass-through, pre-v1.22 absent-field guard
  - ``TestBaselineLoadErrorI18n`` (6 tests): FR rendering for 3 of the 4 messages + locale-key presence sanity in both locales
- 0 regression.
- Production code: ~50 lines changed across [bob/_v090_renames.py](../bob/_v090_renames.py) (new file, 50 lines), [bob/runner.py](../bob/runner.py) (5 lines — the inline dict replaced by the import), [bob/compare.py](../bob/compare.py) (~20 lines — 4 raise sites use ``t_or_hardcoded`` + the finding_keys remap in the AuditBaseline construction).
- Locale: 4 new keys × 2 locales = 8 entries under ``compare.baseline_load.*``.

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

**v0.7.x remains EOL** (formal declaration in [SECURITY.md](../SECURITY.md) since v0.8.1).
**v0.6.x remains EOL** (declared in v0.7.2).

### Lessons

- **The "deferred to v0.10.0+" list is a useful holding pattern, not a graveyard.** Both items had been written off as future v0.10.0 work in v0.9.1 ("zero user signal"), but the effort estimate turned out to be small (~1.5 h total) and the field test campaign had already done the hard work of documenting the bugs reproducibly. Re-evaluating the deferred list every patch cycle costs ~5 minutes and occasionally surfaces "actually we can do that now" wins.
- **Circular import avoidance via tiny shared modules** is cheap. ``bob/_v090_renames.py`` is 50 lines, has zero runtime deps, exposes one dict and one helper. The back-compat alias in ``runner.py`` keeps any out-of-tree script working. Pattern reusable for any future "two consumers, can't import each other" situation.
- **Pure transforms are easier to test than wired-in features**. ``remap_finding_key`` is a 5-line pure function — 18 parametrize tests cover every reasonable input class. The wired-in baseline shim test is then a thin integration test on top of the trusted pure transform.
- **Same-day v0.9.1 + v0.9.2 release is fine** when the work is genuinely small and independent. v0.9.1 fixed a code-correctness bug; v0.9.2 closed two UX gaps. Combining them would have muddied the v0.9.1 hotfix message (which deliberately did NOT touch these items so the F-3 fix would be the only diff to review).

---

## [v0.9.1] — 2026-06-08

**Hotfix for the v0.9.0 F-3 message UX regression** surfaced by the cross-distro field test campaign.

### The bug — reproduced 5/5 distros × 2 locales

The v0.9.0 F-3 (--json-v1 retrait) ship added this raise inside ``parse_args()``:

```python
elif arg == "--json-v1":
    from bob import i18n
    raise CLIError(i18n.t("cli.error.json_v1_retired"))
```

But ``parse_args`` runs BEFORE ``i18n.init()`` is called in [bob/__main__.py](../bob/__main__.py) (the init happens after the CLI args have been parsed because the language can be controlled by ``--lang=`` / ``--french``). So the ``i18n.t()`` lookup hit pre-init and surfaced the bracketed-fallback to the user:

```
$ bob --json-v1
i18n.t() called before i18n.init() — returning key 'cli.error.json_v1_retired'
Error: [cli.error.json_v1_retired]
```

Instead of the actionable message the operator needs to know what to do.

**Field test reproduction**: the cross-distro v0.9.0 campaign ran the bug on five distributions (Linux Mint 22.3 desktop, Debian 13 server, Kali Rolling, Linux Mint 22.3 server FR locale, Ubuntu 26.04 LTS FR locale). The bracketed-fallback fires deterministically 5/5 distros × 2 locales (EN + FR) because the lookup itself is what fails before any translation can happen — the locale is irrelevant.

### The fix

Inline a plain English string in the ``CLIError`` raise:

```python
elif arg == "--json-v1":
    raise CLIError(
        "--json-v1 was retired in v0.9.0. Schema v2 is the only "
        "supported format (v2 has been the default since v0.7.0). "
        "See CHANGELOG.md v0.9.0 entry for the field-by-field "
        "migration table from v0.6.x v1 to v2."
    )
```

This matches the convention used by **every other** ``CLIError`` raise in [bob/cli.py](../bob/cli.py) — the file has 18 other CLIError raises and all of them use English literals (``"--watch=N requires an integer ≥ 10"``, ``"--diff specified more than once"``, ``"-l/--log-days requires an integer ≥ 1"``, …). The v0.9.0 F-3 ship was the lone ``i18n.t()`` consumer inside ``parse_args`` and was inconsistent with the established pattern. The fix restores consistency.

The now-unused locale keys ``cli.error.json_v1_retired`` (EN + FR) are removed from [bob/locales/{en,fr}.json](../bob/locales/en.json) since no call site references them anymore.

### Regression guards

[tests/test_v091_cli_i18n_safety.py](../tests/test_v091_cli_i18n_safety.py) — 2 new tests:

- **``test_parse_args_does_not_call_i18n_t``** — AST scan over the ``parse_args()`` function body. Walks every node looking for ``Call`` nodes where the function is ``i18n.t`` (``Attribute(value=Name(id='i18n'), attr='t')``). The test fails when ANY such call exists inside ``parse_args``. A future contributor who adds another ``i18n.t()`` call in this scope fails the test before the user-facing error message degrades. The test message also points at the recommended alternative (``bob._i18n_safe.t_or_hardcoded(key, fallback)``) which falls back to the English baseline when i18n is not initialised.
- **``test_json_v1_retired_emits_actionable_message``** — direct guard that calls ``parse_args(["--json-v1"])``, catches the ``CLIError``, and asserts:
  * The message does NOT match the bracketed-fallback pattern (``startswith("[")`` + ``endswith("]")``)
  * The message contains ``"v0.9.0"`` (so users see the retrait window)
  * The message contains ``"json-v1"`` or ``"schema"`` (so users see the retired flag or its replacement)

Both guards run in <1 ms — cheap to keep at HEAD forever.

### Why this is a v0.9.1 and not a v0.10.0

Strictly speaking this is a code-correctness bug, not a feature change. The fix is a 6-line inline string replacement plus a 2-test regression guard. The release surface bump (pyproject + manpage + CHANGELOG × 4 + memory) is the bulk of the patch. v0.9.1 is the right minor-bump because:

- The user-visible behaviour changes for the same input (``bob --json-v1`` now shows actionable text)
- The locale keys ``cli.error.json_v1_retired`` are removed (a wire surface contract change for anyone scraping locale files programmatically, however unlikely)
- The fix shipping fast unblocks operators who hit the F-3 message during migration

### v0.9.0 is NOT yanked

The F-3 bug only affects users who explicitly pass the retired ``--json-v1`` flag (legacy v0.6.x JSON consumers). The golden audit path (``sudo bob``, all formats v2 / CSV / markdown / HTML, ``--diff``, ``--explain``, …) is unaffected. Users on v0.9.0 hitting the bracketed-fallback can either upgrade to v0.9.1 or stop using ``--json-v1`` (the flag is retired either way, so the corrective action is the same).

The v0.8.2 yank procedure ([[project_pypi_yank_procedure]]) is documented and ready if a future hotfix actually warrants yank — F-3 doesn't.

### Other i18n gaps observed during the field test campaign (not fixed in v0.9.1)

The field test surfaced two minor i18n gaps that are **NOT** fixed in this hotfix:

1. **``BaselineLoadError`` messages are hardcoded English** ([bob/compare.py](../bob/compare.py)). Even on FR systems, ``sudo bob --diff=/tmp/nonexistent.json`` shows ``Erreur : Baseline file not found: ...`` (the "Erreur :" prefix is FR via the locale key ``cli.error.prefix``, but the message body itself is English). Unlike F-3, this raise happens AFTER ``i18n.init()`` runs (it's in the audit path, not parse_args), so it COULD be properly i18n'd. **Deferred to v0.10.0+** — actionable, readable, zero user signal.

2. **Cross-version baseline diff noise on D-1 renamed finding keys**. Observed on Ubuntu 26.04 during the field test: a baseline written by v0.7.0 had ``iptables_nft.input_accept`` / ``iptables_nft.forward_accept``, and the v0.9.0 audit emits ``firewall_iptables.input_accept`` / ``firewall_iptables.forward_accept`` (renamed in D-1). The diff shows the same 2 underlying physical issues as both *resolved* (old key) AND *new* (new key). This is documented expected behaviour per the v0.9.0 CHANGELOG ("ignore.yml entries referencing renamed finding keys must be migrated by hand"), self-heals on the second audit post-upgrade, and currently has zero user signal. **Deferred to v0.10.0+** — could be solved with a baseline migration shim that uses ``_RENAMED_SECTIONS_V090`` as a reverse map at load time. Will revisit when a user signals.

### Numbers

- **Tests 6210 → 6212** (+2 guards). 0 regression.
- 1 production code file modified ([bob/cli.py](../bob/cli.py)) — 5 lines changed.
- 2 locale files modified ([bob/locales/{en,fr}.json](../bob/locales/en.json)) — 1 key removed each.
- 1 new test file ([tests/test_v091_cli_i18n_safety.py](../tests/test_v091_cli_i18n_safety.py)).
- All release surface (pyproject / manpages / shields / debian / rpm / CHANGELOG × 4 / TESTING / README_TECH × 2) bumped.

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

**v0.7.x remains EOL** (formal declaration in [SECURITY.md](../SECURITY.md) since v0.8.1).
**v0.6.x remains EOL** (declared in v0.7.2).

### Lessons

- **Mock-heavy unit tests miss pre-init i18n bugs**. The v0.9.0 F-3 tests asserted the locale key existed (``test_v082_items.py``) but never exercised the end-to-end CLI invocation. The field test campaign caught it on the first user-facing run. Lesson: pre-init i18n.t() calls need an explicit static guard (AST scan), not a runtime assertion that depends on init order.
- **Cross-distro field test = cheap stress test of locale assumptions**. The 5-distro × 2-locale matrix surfaced this bug deterministically — same root cause regardless of distro / locale. Five hosts is enough; the bug is in the code path, not the environment.
- **Hardcoded English in CLIError is a project convention, not technical debt**. ``bob/cli.py`` has 19 ``CLIError`` raises; 18 use English literals on purpose because the parsing layer is locale-init-naive by design. v0.9.0 F-3 was the lone exception that broke the pattern. Restoring the pattern is the simplest correct fix.
- **Document the "not fixed" items in the changelog**. The BaselineLoadError EN gap and the cross-version diff noise are KNOWN UX warts surfaced by the field test. Listing them in the v0.9.1 changelog avoids the trap of "we shipped a hotfix but didn't say what we deliberately didn't fix" — future-you reads the entry and knows what's still on the deferred list.

---

## [v0.9.0] — 2026-06-07

**First v0.9.x release — BREAKING bundle that closes the v0.7.0 → v0.8.x deferred architectural cleanup.**

This release ships the BREAKING items deferred since v0.7.0: section renumber + naming uniformity (D-1), `_ALL_SECTIONS`/`_ALWAYS_ON_SECTIONS` fusion (D-2), `EXPLAIN_KEY_ALIASES` retrait (D-3), `BOB_SANDBOX_LEGACY` trap door retrait (TD-1), `--json-v1` legacy schema retrait (F-3), `--diff [PATH]` cross-machine compare (F-2), plus a bash completion bug fix companion to v0.8.2.

### D-1 BREAKING — 7 section renames

Pre-v0.9.0 the section names had drifted across the v0.5.x-v0.8.x history: collisions between filterable and always-on (`docker_audit` vs always-on `docker`, `services_state` vs always-on `services`), redundant suffixes inconsistent across siblings (`cron_audit` next to `auditd` which has no `_audit`), and overly-generic names that could mean anything (`rules` standalone could be ufw, iptables, audit, sudoers, …).

The 7 renames:

| Old              | New                | Reason                                                            |
|------------------|--------------------|-------------------------------------------------------------------|
| `cron_audit`     | `cron`             | Drop redundant `_audit` suffix (cf. `auditd`, `samba`)            |
| `docker_audit`   | `docker_hardening` | Resolves collision with the always-on `docker` section            |
| `services_state` | `services_health`  | Resolves collision with the always-on `services` section          |
| `ports_analysis` | `ports`            | Drop redundant `_analysis` suffix                                 |
| `rules`          | `firewall_rules`   | `rules` standalone was too generic                                |
| `iptables_nft`   | `firewall_iptables`| Unifies the `firewall_*` namespace                                |
| `firewall_stack` | `firewall_drivers` | "drivers" describes what the check audits (iptables vs nftables)  |

The migration touches the following surfaces, all kept in sync in this release:

- [bob/runner.py](../bob/runner.py) — `_SECTIONS` tuple (post-D-2) carries the new names; every `_sec(...)` and `emit_section(...)` call site migrated; new `_RENAMED_SECTIONS_V090` dict + the fatal-migration-error path in `validate_check_filters`.
- [bob/checks/*.py](../bob/checks/) — every `key="<old>.X"` and `t("<old>.X")` site migrated across `cron_audit.py`, `docker_audit.py`, `services_state.py`, `iptables_nftables.py`, `firewall_stack.py`, and the `rules.X` keys in `firewall.py`. File names kept as-is — internal module paths are not public API, renaming would force noisy git history without user benefit.
- [bob/explain.py](../bob/explain.py) — `EXPLAIN_KEYS` entries renamed (168 keys).
- [bob/data/cis_refs.json](../bob/data/cis_refs.json) — 20 CIS reference keys renamed.
- [bob/data/profiles/{container,desktop,workstation}.conf](../bob/data/profiles/) — profile severity overrides + the `container` profile's section-skip list.
- [bob/data/bob.bash-completion](../bob/data/bob.bash-completion) — `_SECTIONS` list bumped to match `_ALL_SECTIONS`.
- [bob/locales/{en,fr}.json](../bob/locales/en.json) — root namespaces, `sections.X`, `sections.descriptions.X`, and `explain.X` entries renamed under all 7 prefixes. Two new locale keys: `cli.runner.section_renamed` (per-token migration message) + `cli.runner.section_renamed_fatal` (one-shot pointer to the migration table).
- [bob/scoring.py](../bob/scoring.py) + [bob/json_output.py](../bob/json_output.py) + [bob/domain_scores.py](../bob/domain_scores.py) — hardcoded key references migrated.
- ~167 lines across 14 test files updated by mechanical prefix migration.

The migration error path in `validate_check_filters` fires BEFORE the generic "no match / did you mean" suggestion path so users see the precise canonical replacement (`cron_audit` → `cron`) instead of a fuzzy `difflib` guess. Mirror path for `--skip`. The section header titles (locale-rendered, displayed during the audit) are unchanged; the BREAKING surface is the script-visible token name only.

#### Validator semantic fix (D-1 side effect)

After adding `firewall_iptables` / `firewall_rules` / `firewall_drivers` to `_ALL_SECTIONS`, the token `firewall` matches a filterable via the existing `startswith` rule, which would silence the "no effect" warning operators expect for `--skip=firewall` (the always-on section). The skip-token loop in `validate_check_filters` now checks **exact always-on matches** BEFORE prefix filterable matches. Same fix applied to `--check=docker` and `--check=services` prefixes that now also have filterable companions.

### D-2 internal — `_ALL_SECTIONS` + `_ALWAYS_ON_SECTIONS` fusion

Pre-v0.9.0, two parallel tuples (`_ALL_SECTIONS` for filterable and `_ALWAYS_ON_SECTIONS` for unconditional) had to be kept in sync manually: adding a section meant remembering which tuple to update, and the validation logic + the `bob --check=list` rendering had to union the two.

The new [`_SECTIONS: tuple[_Section, ...]`](../bob/runner.py) is a single source of truth where each entry carries an `always_on` boolean flag. The legacy `_ALL_SECTIONS` / `_ALWAYS_ON_SECTIONS` are derived views built once at import time:

```python
class _Section(NamedTuple):
    name:      str
    always_on: bool

_SECTIONS: tuple[_Section, ...] = (
    _Section("ipv6",              False),
    _Section("smtp",              False),
    ...
    _Section("firewall",          True),
    _Section("firewall_rules",    True),
    ...
)

_ALL_SECTIONS:        tuple[str, ...] = tuple(s.name for s in _SECTIONS if not s.always_on)
_ALWAYS_ON_SECTIONS:  tuple[str, ...] = tuple(s.name for s in _SECTIONS if s.always_on)
```

External consumers ([bob/__main__.py](../bob/__main__.py) + 3 test files) keep referring to the legacy names — the derived views are immutable tuples computed once at import. New code should consume `_SECTIONS` directly to access the `always_on` flag.

### D-3 cleanup — `EXPLAIN_KEY_ALIASES` retired

Pre-v0.9.0, `EXPLAIN_KEY_ALIASES` carried a single live entry (`services_state.service_inactive` → `services_state.enabled_inactive`, became `services_health.*` after the D-1 rename) that was a bridge over a v0.5.5 source-side drift: `services_state.py` emits `services_state.service_inactive` as its finding key, but the EXPLAIN_KEYS entry + locale block were named `enabled_inactive`. The v0.8.2 D-3 deprecation warning announced retrait for v0.9.0.

v0.9.0 D-3 resolves the drift at the source instead of bridging it:
- The EXPLAIN_KEYS entry was renamed `services_health.enabled_inactive` → `services_health.service_inactive` to match what `services_state.py` emits
- The locale namespace `explain.services_health.enabled_inactive` → `service_inactive` (EN + FR)
- [bob/data/cis_refs.json](../bob/data/cis_refs.json) entry renamed (duplicate caused by my D-1 rename mass-pass de-duped)
- `EXPLAIN_KEY_ALIASES = {}` (dict kept empty so a future rename has a one-line migration path)
- `_warn_alias_deprecation` + `_WARNED_ALIASES` machinery removed
- The 4 v0.8.2 deprecation tests in [tests/test_v082_items.py::TestExplainKeyAliasDeprecation](../tests/test_v082_items.py) retired (the dict is empty, the machinery is gone)

### TD-1 BREAKING — `BOB_SANDBOX_LEGACY=1` trap door retired

Pre-v0.9.0, the env var bypassed the spawn'd-subprocess sandbox and ran plugins in the parent process with full builtins. A flashy stderr WARNING + CRITICAL log message fired on every audit that actually entered legacy mode, by design loud enough that nobody could run it in production unnoticed.

The trap door was announced for retrait in the v0.7.0 ship + [SECURITY.md](../SECURITY.md) since v0.8.0. v0.9.0 TD-1 removes:

- `SandboxRunner._legacy_active()` static helper
- `SandboxRunner._emit_legacy_warning()` static helper
- `SandboxRunner._run_legacy()` method (in-process exec path)
- The `if self._legacy_active():` branches in `__init__` and `run`

Setting the env var now has no effect; plugins always execute in the spawn'd subprocess. [SECURITY.md](../SECURITY.md) + [SECURITY_FR.md](../SECURITY_FR.md) updated to strike-through the entry and mark the retrait window.

Two retirement guards in [tests/test_plugin_sandbox.py::TestLegacyTrapDoorRetired](../tests/test_plugin_sandbox.py):

- `test_legacy_env_var_has_no_effect` — sets `BOB_SANDBOX_LEGACY=1`, runs a plugin that would have succeeded under legacy mode (imports `subprocess`), asserts the import fails because the sandbox blocks it
- `test_legacy_active_helper_removed` — `hasattr(SandboxRunner, "_legacy_active")` + `_run_legacy` must both be False

### F-3 BREAKING — `--json-v1` legacy schema retired

Pre-v0.9.0, `--json-v1` opted into the v0.6.x JSON layout (`schema_version="1"`) for consumers that hadn't migrated to v2. v2 has been the default since v0.7.0 (4 majeures) and v0.6.x has been EOL since v0.7.2 (5 majeures); anyone still reading v1 has not updated their pipeline in 6+ months.

v0.9.0 F-3 removes:

- `SCHEMA_V1_REQUIRED_KEYS` + `SCHEMA_V1_FULL_KEYS` constants from [bob/json_output.py](../bob/json_output.py)
- `_build_v1` + `_populate_v1_full_blocks` builder helpers (~170 lines)
- The `schema_version == "1"` dispatch in `build_json_data()`
- `SUPPORTED_SCHEMA_VERSIONS = frozenset({"2"})`
- `AuditConfig.json_v1` field
- `--json-v1` from [bob/data/bob.bash-completion](../bob/data/bob.bash-completion) `long_opts`
- The `--json-v1` option from the help text

Passing `--json-v1` now raises a `CLIError` (locale key `cli.error.json_v1_retired`, EN + FR) pointing at the CHANGELOG migration guide. Tests pinning v1 baseline contract: [tests/test_json_schema.py](../tests/) deleted entirely (~330 lines); 5 v1-specific tests in `test_t11_t26_v081.py` + `test_json_schema_v2.py` retired; 1 entry removed from `test_v082_bash_completion.py::TestLongOptsPresence` parametrize.

#### v1 → v2 field migration table

| v1 field            | v2 equivalent                                                  |
|---------------------|----------------------------------------------------------------|
| `timestamp`         | `timestamp_utc` (renamed, signals UTC encoding — B-3 in v0.7.0)|
| `network_context`   | `network_context` dict in both modes (was str in v1 short, dict in v1 full — A-2 P1 fix) |
| `firewall_stack`    | `firewall_drivers` (BREAKING from D-1 — renamed in v0.9.0)     |
| —                   | `info_count` added at top level (B-7 in v0.7.0)                |
| —                   | `posture_escalation` block added (A-4 in v0.7.0)               |
| —                   | `open_ports_all` (full only — B-5 in v0.7.0)                   |
| —                   | `deductions_raw` (full only — B-4 in v0.7.0)                   |
| `domain_scores[d]`  | `domain_scores[d]` now includes `deductions` count (B-6)       |
| `risk`              | unchanged — derived from `engine.level` (score-only)           |
| `posture_escalation.score_level` | new — exposes the un-escalated baseline for consumers that need both views |

### F-2 NEW — `--diff [PATH]` cross-machine compare

Pre-v0.9.0, the `--diff` flag compared the current audit against the auto-managed local baseline at `~/.config/bob/last_baseline.json`. Useful for "what changed since my last audit on this host", but no way to compare against an arbitrary baseline file (cross-machine, historical, prod-vs-staging).

v0.9.0 F-2 adds an optional PATH argument:

```bash
sudo bob --diff                            # v0.8.x behaviour: load local auto-managed baseline
sudo bob --diff=/path/to/baseline.json     # NEW: compare against arbitrary file
sudo bob --diff /backup/server-A.json      # NEW: space-separated equivalent
```

Both syntaxes (`--diff=PATH` and `--diff PATH`) are supported, mirroring `--watch[=N]`. The bare `--diff` / `-D` keeps the v0.8.x semantics. The space form has a peek-ahead guard so `sudo bob --diff --verbose` keeps `--verbose` as the next flag, not as a baseline path.

#### Implementation

- [bob/cli.py](../bob/cli.py) — new `AuditConfig.diff_baseline_path: Path | None` field; `--diff=PATH` and `--diff PATH` parsing paths
- [bob/compare.py](../bob/compare.py) — new `BaselineLoadError` exception; `load_baseline(path, strict=True)` raises on missing/broken file + on legacy `schema_version="1"`. Default `strict=False` preserves the silent v0.8.x behaviour for bare `--diff`.
- [bob/compare.py::AuditBaseline](../bob/compare.py) — new `hostname: str | None` field. `build_baseline()` calls `socket.gethostname()` to populate. Pre-v0.9.0 baselines without the field cause no notice on load.
- [bob/__main__.py](../bob/__main__.py) — when `config.diff_baseline_path` is set, calls `load_baseline(path, strict=True)`; on `BaselineLoadError`, emits the locale-prefixed error message and exits with `EXIT_ERROR`. Cross-machine notice: if the recorded `hostname` differs from `socket.gethostname()`, prints `t("compare.cross_machine_notice", baseline_host=..., current_host=...)` before the delta display.
- [bob/data/bob.bash-completion](../bob/data/bob.bash-completion) — new `--diff=PATH` and `--diff PATH` filename completion (`compgen -f -- "${val}"` + `compopt -o filenames`).
- [man/bob.1](../man/bob.1) — `.SS Comparison and history` section updated with the new optional argument + cross-machine usage example.

#### Tests

17 new tests in [tests/test_v090_diff_baseline_path.py](../tests/test_v090_diff_baseline_path.py):

- `TestCLIDiffPathParsing` — bare `-D` / `--diff`, `--diff=PATH`, `--diff PATH`, peek-ahead does-not-consume-flag-token, empty value rejected, duplicate `--diff` rejected
- `TestLoadBaselineStrict` — missing file in strict raises with path in message, missing file non-strict returns None, invalid JSON in strict raises, `schema_version="1"` in strict raises with "v0.6.x" in message, v0.7.x–v0.8.x baselines (no `schema_version` field) load cleanly under strict
- `TestHostnameCapture` — save→load roundtrip preserves hostname, pre-v0.9.0 baselines load with `hostname=None`, `build_baseline` captures the real hostname

### Bug fix — `bob --check=<TAB><TAB>` without sudo

Companion to the v0.8.2 sudo-dispatcher walk-back guard. v0.8.2 fixed the case where `sudo bob --check=<TAB>` returned zero candidates because the sudo dispatcher invoked `_bob` with `$prev` set to literal `=`. The companion case: under non-sudo invocations, some bash versions place the completion cursor on the literal `=` token (giving `cur="="`, `prev="--check"`) instead of on a trailing empty word; the existing `prev=="--check"` branch then ran `compgen -W "list ${_SECTIONS}" -- "="` which returns zero because no section name starts with `=`.

The fix is a 3-line companion guard at the top of `_bob`:

```bash
if [[ "${cur}" == "=" ]]; then
    cur=""
fi
```

Mirror to the v0.8.2 walk-back. After this, `bob --check=<TAB><TAB>` (non-sudo) restores the TAB×2 list display. Verified across 4 cases (sudo + non-sudo × empty-cur + cur="=") in the existing bash completion functional tests.

### Numbers

- **Tests 6246 → 6210** (net −36):
  - −53: v1 baseline test file `test_json_schema.py` (~330 lines) + 5 v1-specific tests in `test_t11_t26_v081.py` + `test_json_schema_v2.py` + 4 v0.8.2 deprecation-warning tests (retired with the alias machinery) + 1 `--json-v1` parametrize entry
  - +17: new F-2 tests in `test_v090_diff_baseline_path.py`
- 0 regression.
- Production code: ~600 lines changed across `bob/runner.py`, `bob/cli.py`, `bob/compare.py`, `bob/json_output.py`, `bob/_sandbox.py`, `bob/explain.py`, `bob/__main__.py`, `bob/scoring.py`, `bob/domain_scores.py`, `bob/data/bob.bash-completion`, and 6 `bob/checks/*.py` files.
- Locale: 167+ key migrations across `bob/locales/{en,fr}.json` + 3 new keys (`cli.runner.section_renamed`, `cli.runner.section_renamed_fatal`, `cli.error.json_v1_retired`, `compare.cross_machine_notice`) × 2 locales.

### Upgrade

```bash
pipx upgrade bodyguard-of-bits
```

Users with scripts using `--check=<legacy_name>`, `--skip=<legacy_name>`, `--json-v1`, or `BOB_SANDBOX_LEGACY=1` must migrate per the tables above:

- **Scripts**: `s/--check=cron_audit/--check=cron/`, etc. The migration error path will point at the canonical replacement on first failed invocation if you miss any.
- **JSON consumers**: rewrite to read the v2 schema. The renamed fields and the new `posture_escalation` block are the practical migration points.
- **Plugin authors relying on `BOB_SANDBOX_LEGACY=1`**: the env var is now ignored. Rework the plugin to use the sandbox-allowed API surface, or run outside `bob` (e.g. as a separate cron job).
- **`ignore.yml` entries** referencing the renamed finding keys (`cron_audit.pipe_to_shell` → `cron.pipe_to_shell`, etc.) must be migrated by hand. No auto-translation; the keys silently no-op until corrected.

**v0.7.x remains EOL** (formal declaration in [SECURITY.md](../SECURITY.md) since v0.8.1).
**v0.6.x remains EOL** (declared in v0.7.2).

### Deferred to v0.9.1

- **D-4** sub-checks granulaires (e.g. `ssh.x11_forwarding` → `ssh.x11.forwarding.server` + `.client`) — requires sub-agent audit pass to identify candidates + write the migration guide. Sub-agent quota was the blocker at v0.9.0 cut.
- **Parallel checks** via `concurrent.futures.ThreadPoolExecutor` (target: ~30 s → 5–10 s on multi-core audits) — same sub-agent audit blocker (threading invariants + race condition discovery).

### Lessons

- **Mechanical prefix renames at scale** (167 lines × 14 test files + 88 lines × 6 source files) are best done with a single Python script over `re.sub(rf'"{old}\.', f'"{new}.', text)`. The 5-second iteration loop catches drift inside multi-line strings that hand-Edit would miss.
- **Mass-rename collateral damage on documented migration maps** — the same regex that renames the codebase will also rename the migration map itself (e.g. `EXPLAIN_KEY_ALIASES`, `_RENAMED_SECTIONS_V090`) where old → new mappings live as string literals. Always re-instate those maps manually after the mechanical pass.
- **Cross-cutting validators need re-ordering** when section name spaces merge. The `_matches_filterable` / `_matches_always_on` ordering held for v0.5.x–v0.8.x because the namespaces were disjoint. The v0.9.0 D-1 renames created overlap (`firewall` matched both via prefix), and the test surfaced the regression immediately.
- **Strict mode for explicit-path loaders** — for any `--option PATH` flag that loads a file, the silent-fallback default is wrong when the user explicitly passed a path. v0.8.x `load_baseline()` returned None on error; v0.9.0 adds `strict=True` for the explicit-path case, mirroring how `open(path)` raises instead of returning None on missing.

---

## [v0.8.4] — 2026-06-06

**Final v0.8.x release — cleanup batch before the v0.9.0 BREAKING bundle.**

### Dead code retirement — is_unit_enabled

[bob/checks/_run.py](../bob/checks/_run.py) — ``is_unit_enabled(name, timeout)`` was added in v0.5.0 (refactor Phase 1 #7) as the symmetric mirror of ``is_unit_active`` and documented in the release-monitoring list as "no immediate consumer — to be reviewed each v0.5.x release". 7 months and 4 minor versions later (v0.5.x → v0.6.x → v0.7.x → v0.8.x), the grep is unchanged:

- Zero consumers in ``bob/``
- Zero references in ``tests/``
- ``services.py::_detect_single_unit_state`` continues to use its own ``_run`` call as designed at v0.5.0 ship time

The API-symmetry argument has not held — the function is removed. Historical CHANGELOG entries (v0.5.0 ship table + #7 detail section + both FR mirrors + FULL changelog detail) are preserved as-is. They accurately describe what shipped at the time; rewriting history would obscure the fact that the API existed and was deliberately retired after observation.

This closes the v0.5.0 release-monitoring list (both entries decided):

- ``is_unit_enabled`` — **DELETED** in v0.8.4 (7 months without consumer = sufficient signal that the symmetric-API hypothesis did not hold)
- ``width=62`` parameter on ``bob.output.print_titled_box`` — **KEPT off-monitor** in v0.8.4 (4 call sites all use the default; 7 months of stability promotes the parameter from "speculative" to "stable de facto"; removing it would break the public API without gain)

### New tutorial — DOCUMENTS/TUTORIAL{,_FR}.md

End-to-end first-time-user walkthrough, 269 lines per locale (EN + FR parity), covering :

1. What BOB does (one sentence) + what BOB is NOT (framing carryover from v0.8.0 A2)
2. ``pipx install`` + the ``sudo bob`` PATH gotcha + ``--install-completion`` resolution
3. First audit + reading the score (level, key, hypotheses footer)
4. ``--explain KEY`` — picker / list / tab-completion
5. ``--fix`` dry-run + ``--fix --apply`` contract
6. Profile selection — server / desktop / workstation / container
7. No-noise path — ``--ignore`` / ``--unignore`` / ``--show-ignored``
8. Automation — ``--install-cron`` + ``--webhook=`` + ``--test-webhook`` smoke
9. Baseline-driven workflows — ``--diff`` / ``--history`` / ``--watch``
10. Machine consumers — JSON / CSV / Markdown / HTML + ``-q`` exit codes + ``--target=N``
11. Common scenarios — silent CI mode, target floor, French audit
12. Pointers to README_TECH / AUTOMATION / SECURITY / CHANGELOG

Linked from [README.md](../README.md) + [README_FR.md](../README_FR.md) "See also" / "Voir aussi" sections as the first entry, so a first-time reader lands here before the technical reference.

This was the ``tutorial`` item deferred from the v0.9.0 backlog. It moved into v0.8.4 because it is pure documentation with zero code surface — no reason to park documentation behind a BREAKING bundle.

### Roadmap closure — compare-breakdown-diff killed

[[project_future_compare_breakdown_diff]] (memory) — feature roadmap opened in v0.3.0 (2026-05-08) to add per-key deduction diff in ``bob compare``. Status at v0.8.4 ship time:

- Open since v0.3.0
- Zero user signal across 5 majeures (v0.4 / v0.5 / v0.6 / v0.7 / v0.8)
- The existing ``deduction_delta`` global suffices for the real-world use case (not a single user complaint of the form "I see -5 between two audits but don't know where it came from")
- Effort estimate: baseline schema BREAKING change + diff logic + UI compare = ~6-8h. Not justified without concrete demand.

Pattern: if a feature stays dormant 5 majeures without signal, the market has spoken — kill rather than keep indefinitely. The memory is marked closed; reopening requires explicit user signal.

### Numbers

- **Tests 6246 → 6246** (no delta — the deleted helper had no test coverage to delete). 0 regression.
- 1 production code file modified ([bob/checks/_run.py](../bob/checks/_run.py)) — 10 lines deleted.
- 2 new docs ([DOCUMENTS/TUTORIAL.md](../DOCUMENTS/TUTORIAL.md) + [DOCUMENTS/TUTORIAL_FR.md](../DOCUMENTS/TUTORIAL_FR.md)) — 540 lines added total.
- 2 README files updated for the new tutorial link.
- 4 changelog surfaces + memory updates + TESTING.md + man pages + debian + rpm bumped.

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

**v0.7.x remains EOL** (formal declaration in [SECURITY.md](../SECURITY.md) since v0.8.1).
**v0.6.x remains EOL** (declared in v0.7.2).

### Next — v0.9.0 BREAKING bundle

v0.8.x is **closed** — further v0.8.x patches will only ship for security regressions. The next active release is v0.9.0, scheduled as a single BREAKING bundle:

- **D-1** sections renumber + ``emit_section()`` naming uniformity
- **D-2** fusion ``_ALL_SECTIONS`` + ``_ALWAYS_ON_SECTIONS`` into a single tuple with an ``is_always_on`` flag
- **D-4** sub-checks granulaires (rename keys — breaks ``~/.config/bob/ignore.yml`` entries on systems with custom suppression lists)
- ``BOB_SANDBOX_LEGACY=1`` trap door **retrait** (documented in SECURITY.md as a back-compat env var for in-process plugin execution)
- **Parallel checks** via ``concurrent.futures.ThreadPoolExecutor`` for independent domain audits (target: ~30s → 5-10s on multi-core)
- **``--diff <baseline.json>``** cross-machine compare (additive to the local ``~/.config/bob/baseline.json`` flow)

The bundle is grouped because each item alone is too small to ship a major bump for, while shipping them piecemeal would force users to absorb 6 BREAKING changes across 6 minor versions.

### Lessons

- **The release-monitoring policy worked** — 7 months of patient grep + a clear deletion criterion ("zero consumer + zero signal" = remove) produced a clean retirement with no surprises.
- **Closing dormant features needs an explicit policy** — keeping ``project_future_compare_breakdown_diff`` indefinitely on the maybe-someday list cost cognitive overhead at every release planning. 5-major-dormancy → kill is a clean rule.
- **Pure-docs work belongs in patch releases** — parking the tutorial behind v0.9.0's BREAKING bundle would have delayed it 2-3 weeks without code-coupling justification.

---

## [v0.8.3] — 2026-06-06

**HOTFIX — v0.8.2 audit path crashed with `UnboundLocalError` on every non `--test-webhook` invocation.**

### Root cause

The v0.8.2 ``--test-webhook`` handler did ``from bob.config import UserConfig`` *inside* ``main()`` ([bob/__main__.py:213](../bob/__main__.py#L213)). Python's local-scope analyzer saw the local ``from`` statement and treated ``UserConfig`` as a function-local name for the entire ``main()`` body — even on code paths that never reached the local import. The audit path at ``user_config = UserConfig.load()`` (line 298 at ship time) then raised:

```
Fatal error: cannot access local variable 'UserConfig' where it is not associated with a value
```

on **every** regular ``bob`` invocation that didn't enter the ``--test-webhook`` branch. The same shadowing pattern existed for ``os`` and ``traceback`` inside the top-level ``except`` handler at line 585.

### Why unit tests missed it

The 6244-test v0.8.2 suite did not catch the bug because the tests either:

- exercise the ``--test-webhook`` branch directly (which **does** pass through the local ``from`` import, so ``UserConfig`` is bound and resolves), or
- exercise the audit path with ``UserConfig.load`` mocked, so the name resolves through the mock decorator without hitting the unbound local

The integration ``smoke-plugin-on-CI`` guard caught it on the live ``bob --offline -v`` invocation — but only **after** ``v0.8.2`` was already published on PyPI.

### Fix

[bob/__main__.py](../bob/__main__.py) — three minimal changes:

- Remove the redundant ``from bob.config import UserConfig`` inside ``main()`` (the module-level import at line 26 was already in scope before v0.8.2; the local re-import was added by the ``--test-webhook`` ship and shadowed it)
- Remove the redundant ``import os`` inside the ``except`` handler at line 585 (the module-level ``import os`` at the top of the file was already in scope; the local re-import shadowed it for the rest of ``main()``, even though in this specific case the only ``os.<x>`` reference came **after** the local import, so the bug was latent rather than active)
- Promote ``import traceback`` to a module-scope import (was only imported inside the ``BOB_DEBUG`` branch — module-scope is the correct location)

### Regression guard

[tests/test_v083_main_scope_guard.py](../tests/test_v083_main_scope_guard.py) — 2 tests, static analysis via ``ast``:

- ``test_main_function_does_not_shadow_module_scope_imports``: for each name imported at ``bob.__main__`` module scope, scan ``main()`` and assert no local ``from``/``import`` statement re-binds the same name
- ``test_user_config_resolves_at_module_scope``: direct guard that ``UserConfig`` survives import-time as a module-level binding (``hasattr(bob.__main__, "UserConfig")``)

A future contributor who adds another defensive re-import inside ``main()`` fails the first test **before** the audit path crashes for users.

### Numbers

- **Tests 6244 → 6246** (+2 guard). 0 regression.
- 1 production code file modified ([bob/__main__.py](../bob/__main__.py)).
- 1 new test file ([tests/test_v083_main_scope_guard.py](../tests/test_v083_main_scope_guard.py)).
- All 4 changelog surfaces + memory note + this section updated for traceability.

### Upgrade

**v0.8.2 is broken on PyPI** (audit path crashes on every regular invocation). Users on v0.8.2 must upgrade immediately:

```
pipx upgrade bodyguard-of-bits
```

**v0.7.x remains EOL** (formal declaration in [SECURITY.md](../SECURITY.md) since v0.8.1).
**v0.6.x remains EOL** (declared in v0.7.2).

### Lessons

- Unit tests that mock ``UserConfig.load`` mask name-binding bugs — the audit-path code path executes, but ``UserConfig`` resolves via the mock decorator's namespace patch, not via the function-local binding rules.
- A function-local ``from X import Y`` is **legal** but turns ``Y`` into a function-local name for the **entire** function body, including code paths above the local import. When ``Y`` was already imported at module scope, the local statement shadows it everywhere and creates an ``UnboundLocalError`` trap.
- Static guards (``ast.walk`` on a function body) catch the bug class without needing a runtime exercise — preferred over subprocess smoke tests for predictable, fast feedback.

---

## [v0.8.2] — 2026-06-06

**Conservative-bundle patch — 6 user-facing + DX items, no BREAKING.**

Cleans up DX debt from the v0.7.x / v0.8.0-v0.8.1 i18n + bash-completion + helper-text migrations. Closes the ``--test-webhook`` UX gap (the v0.7.0 webhook story shipped without a standalone smoke command). Sets up the v0.9.0 architectural cleanup (D-1 / D-2 / D-4 + ``BOB_SANDBOX_LEGACY`` retrait + parallel check execution + ``--diff <baseline.json>``) via the D-3 deprecation warning + the locale linter that catches the drift classes audit passes 7 + 8 surfaced.

6198 → **6244 tests** (+46 net). 0 regression.

### Bash completion v0.8.2

[bob/data/bob.bash-completion](../bob/data/bob.bash-completion) — four improvements + a sync guard + a sudo-dispatcher fix.

- **Sync ``_SECTIONS`` + ``_EXPLAIN_KEYS`` with runtime**. The hand-curated section list was already in sync at ship time; the explain-keys list (168 entries) was inserted fresh from ``bob.explain.EXPLAIN_KEYS`` via the regenerate scaffold so subsequent drift surfaces in CI.
- **``--unignore=KEY`` / ``--ignore=KEY`` / ``--explain KEY`` value completions**. v0.8.1 T57 added ``--unignore`` but didn't extend the completion script. v0.8.2 adds dedicated handlers for both the space and ``=`` forms, sourced from the canonical 168-key EXPLAIN_KEYS catalogue.
- **``--json-v1`` + ``--test-webhook`` in ``long_opts``**. The first was a v0.7.0 Phase 2 ship; the second is new this cycle.
- **Stale ``workstation`` alias comment retired**. Pre-v0.8.2 the ``--profile`` completion comment claimed *"workstation is a backward-compat alias loading desktop"*; the v0.8.1 retrait made that a lie. Now reads *"workstation is now a FIRST-CLASS profile distinct from desktop"*.
- **Sudo-dispatcher ``=`` fix** (commit ``2a62bf3``). User-reported regression: ``sudo bob --check=s<TAB>`` returned zero candidates while ``bob --check=s<TAB>`` (no sudo) worked. Root cause: bash-completion's sudo dispatcher (``_command_offset``) invokes ``_bob`` with ``$prev`` set to the literal ``=`` instead of the option name when ``=`` remains in COMP_WORDBREAKS — not all bash + bash-completion combinations strip it via ``_init_completion -s``. None of the per-option ``prev == "--check"`` / ``--ignore`` / ``--unignore`` / ``--explain`` branches matched, so the function fell through to the long_opts default which can't apply to a partial value like ``"s"``. Fix: defensive 3-line guard at the top of ``_bob`` that detects ``prev == "="`` and recovers the real option name by walking back two positions in COMP_WORDS. Restores value-narrowing behaviour for every ``--<option>=<partial>`` completion under both ``sudo`` and non-``sudo`` invocations.

[tests/test_v082_bash_completion.py](../tests/test_v082_bash_completion.py) ships 21 tests across 6 classes:

- **Sync guards** — ``_SECTIONS`` matches ``bob.runner._ALL_SECTIONS`` exactly (set equality), ``_EXPLAIN_KEYS`` matches ``bob.explain.EXPLAIN_KEYS`` exactly. A new check section that ships without updating the completion script fails CI.
- **Long-opt presence** — parametrized over ``--unignore=``, ``--json-v1``, ``--check=``, ``--skip=``, ``--ignore=``, ``--profile=``, ``--explain``, ``--breakdown`` — pin each is reachable via TAB on the option-name path.
- **Functional bash invocation** — sources the script in a sub-bash, calls ``_bob`` with ``(cur, prev)`` matching the bash-completion dispatcher convention, asserts COMPREPLY contains expected candidates. Exercises ``--check=`` → sections, ``--check=ssh`` → ``ssh`` only, ``--check=`` short form (``--c`` → ``--check=``), ``--unignore`` → EXPLAIN_KEYS, ``--unignore=ssh`` → ssh.* keys, ``--ignore`` + ``--ignore=audit`` → auditd.* keys, ``--explain`` + ``--explain=firewall`` → firewall.* keys, ``--profile`` + short ``-p`` → 4 profile names.

### i18n consolidation — bob/_i18n_safe.py

Pre-v0.8.2, four modules each defined their own ``_fallback_t``:

| Module                  | Behaviour                                          |
| ----------------------- | -------------------------------------------------- |
| ``config.py``           | Always tries ``.format(**kwargs)``, returns template on error |
| ``webhook.py``          | Same as config.py                                  |
| ``markdown_output.py``  | **Skips ``.format()`` entirely**                   |
| ``html_output.py``      | **Format only if** ``kw`` is non-empty             |

Same intent (fall back to English when no operator-bound translator is wired) — three subtly different implementations. The drift had grown over T10 v0.8.1 (config/webhook), T11 v0.8.1 (CSV/JSON parity reused html_output's pattern), and the v0.7.2 M-4 i18n extraction (markdown_output/html_output) without anyone reconciling the three bodies.

[bob/_i18n_safe.py](../bob/_i18n_safe.py) — new module — exposes a single factory:

```python
from bob._i18n_safe import make_fallback_t
_fallback_t = make_fallback_t(_FALLBACK_LABELS)
```

The factory body always tries ``.format(**kwargs)`` + returns the raw template on ``KeyError`` / ``IndexError``. Templates without ``{}`` placeholders pass through unchanged (so markdown_output's static labels behave byte-identical) and templates with placeholders interpolate (so webhook's ``{url}`` family interpolate as before).

Plus ``t_or_hardcoded(key, fallback)`` hoisted out of ``__main__.py`` (T60 v0.8.1 introduced it as a local def) — gates ``i18n.t`` on the private ``_initialized`` flag, returns *fallback* when i18n hasn't loaded yet (parse_args error path, very-early crash in main() catch-all). Hoisted so future entry points (``--test-webhook``, planned standalone ``--unignore`` runner) can reuse without importing ``__main__``.

Tests in [tests/test_v082_items.py::TestI18nSafe*](../tests/test_v082_items.py) pin every contract: known key → template, unknown key → key itself, kwargs interpolation, missing placeholder → raw template (defensive), static template + kwargs → unchanged. Plus cross-module ``TestI18nConsolidationModulesUseFactory`` asserts the 5 migrated modules actually import + call the factory (regression guard against a future revert).

### --test-webhook smoke command

[bob/webhook.py::test_webhook](../bob/webhook.py) — new public function. POSTs a minimal payload with ``test=true`` + ``tag="bob_smoke_test"`` fields (generic) or a Slack-formatted attachment (slack). Reuses every URL-validation guard from ``send_webhook``:

- scheme must be ``http://`` or ``https://`` (case-insensitive since v0.7.3 I-5)
- plain ``http://`` rejected unless ``BOB_WEBHOOK_ALLOW_INSECURE=1`` is set
- ``WebhookError`` redaction via ``redact_url_credentials`` (T74 v0.8.1)
- HTTP timeout = same ``_TIMEOUT_SECONDS = 10`` as ``send_webhook``

Wired into the CLI at [bob/__main__.py:190-220](../bob/__main__.py#L190). The ``--test-webhook`` flag bypasses ``require_root()`` because the smoke is a network probe + JSON serialisation, no system inspection — no audit, no sudo. URL resolution mirrors the audit-time path:

1. ``--webhook=URL`` from current invocation, else
2. ``UserConfig.get_webhook_url()`` from ``~/.config/bob/config.conf``

If neither is set the command exits non-zero with a translated "set one with ``bob --webhook=URL`` first" hint (4 new locale keys EN+FR under ``cli.test_webhook.*``).

Result on success: ``✔ Webhook smoke test succeeded: <redacted-url> returned HTTP <status>``. Result on failure: ``✖ Webhook smoke test failed: <translated WebhookError>``. The translated error is plumbed through the same ``t=`` parameter ``send_webhook`` uses so FR users get FR error messages out of the box.

Tests in [tests/test_v082_items.py::TestTestWebhookCli + TestTestWebhookSmokeFunction](../tests/test_v082_items.py) cover CLI parsing, default-False, invalid-scheme rejection, and payload-tag pin (asserts ``tag=bob_smoke_test`` survives the urllib send via a monkeypatched ``urlopen``).

Pre-v0.8.2 the only way to validate a fresh ``bob --webhook=URL`` setup was to run a full audit (~30 s + needs sudo). The DX gap was particularly painful when configuring webhooks via cron — operators couldn't test their cron-side URL without waiting for the next scheduled audit + reading the .log report to confirm the POST landed.

### --check=list with section descriptions

[bob/__main__.py:115-152](../bob/__main__.py#L115) — the ``--check=list`` rendering loop now resolves a description per section via ``i18n.t(f"sections.descriptions.{name}")``. Missing description → fall back to the bare section name (forward-compat for a section added without locale wiring).

44 descriptions ship in [bob/locales/en.json](../bob/locales/en.json) + [bob/locales/fr.json](../bob/locales/fr.json) under the new ``sections.descriptions.*`` namespace. One line per section, ≤ 80 chars typical, covers:

- **34 filterable sections** (auditd, auth_log, backup, clamav, cron_audit, …, ssh, ssl_certs, suid_audit, systemd_timers, umask, updates, user_accounts)
- **10 always-on sections** (ddns, docker, firewall, firewall_stack, network_context, ports_analysis, rules, services, ufw_logging, virtualization)

Tests in [tests/test_v082_items.py::TestCheckListDescriptionsCoverage](../tests/test_v082_items.py) pin two invariants:

- Every section in ``_ALL_SECTIONS ∪ _ALWAYS_ON_SECTIONS`` has a description in both EN and FR — a new check that ships without locale wiring fails CI.
- No orphan ``sections.descriptions.*`` entries for unknown sections — a section that gets renamed or dropped surfaces the stale locale entry.

Pre-v0.8.2 ``bob --check=list`` dumped raw section names with no context:

```
ssh
ssl_certs
suid_audit
systemd_timers
```

Post-v0.8.2:

```
ssh               — SSH hardening — sshd_config, host keys, ~/.ssh, authorized_keys
ssl_certs         — TLS/SSL certificate expiry — Let's Encrypt, nginx, apache, postfix
suid_audit        — SUID/SGID binaries — unexpected entries vs whitelist
systemd_timers    — Systemd timers — risky patterns + permissions
```

Significantly better onboarding for ``--check=`` / ``--skip=`` flag users.

### D-3 deprecation warning on EXPLAIN_KEY_ALIASES

[bob/explain.py:368-432](../bob/explain.py#L368) — ``normalize_key()`` now emits a one-shot ``logger.warning`` when it resolves an alias.

The warning carries the alias name, the canonical name, and the v0.9.0 retrait timeline:

```
DEPRECATION: explain key 'services_state.service_inactive' is a legacy alias for
'services_state.enabled_inactive' — the alias is scheduled for retrait in v0.9.0.
Migrate scripts, saved profiles, and ignore.yml entries to the canonical name.
```

Emitted via ``logger.warning`` (the Python ``logging`` module) so it surfaces in:

- ``--detailed`` ``.log`` reports (via the BOB log handler)
- journald when scheduled via cron (root-owned process inherits the journald sink)
- Operator-visible streams without polluting machine-readable JSON / CSV / Markdown outputs

A per-process ``_WARNED_ALIASES`` set ensures each alias warns at most once per process. A ``--watch`` mode session that resolves the same alias every iteration sees one warning, not 10/min. Tests pin the one-shot contract.

This is the **bridge** to the v0.9.0 alias retrait that ``project_v08x_deferred.md`` (memory) describes — pre-v0.8.2 the alias was silent, so we had no signal to know how many users still relied on the legacy name. v0.8.2 starts the deprecation clock; v0.9.0 will retire the entry per the contract in ``SECURITY.md``.

### Locale linter

[scripts/lint_locales.py](../scripts/lint_locales.py) — dev tool, not shipped at runtime (``scripts/`` isn't in the wheel manifest). Catches the drift classes audit passes 7 + 8 surfaced — but as a fast standalone script you can run locally + in pre-commit:

```
$ python3 scripts/lint_locales.py
✔ locale lint clean: 1941 EN keys × 1941 FR keys, 0 parity drift,
  0 placeholder drift, 0 trailing-space violation, 0 length anomaly
```

Four lint classes:

- **Strict EN/FR key parity** — every leaf key in en.json appears in fr.json and vice-versa. The existing T38 audit-pass check is duplicated here so contributors don't have to wait for ``pytest`` to surface drift.
- **Placeholder set parity** — every ``{name}`` placeholder in an EN value matches the same set in the FR value. Protects ``str.format(**kwargs)`` from runtime ``KeyError`` (FR has a placeholder EN doesn't supply) and from silently dropping a contextual variable (EN has one, FR doesn't).
- **Trailing whitespace contract** for the ``cli.error.*_prefix`` keys (I-2 pass 7 invariant). Promoted from runtime test guard to standalone tool so contributors editing the locale file see the violation immediately.
- **Length sanity** — empty values + values > 1500 chars are flagged. Catches genuine copy-paste mistakes (entire README, accidentally pasted document) without false-positiving on the long ``explain.*.{why,how}`` paragraphs that are intentionally verbose technical descriptions.

[tests/test_v082_items.py::TestLocaleLinterSmoke](../tests/test_v082_items.py) shells out to the script so a drift fails CI even when contributors skip the lint step. ``LANG=C`` enforced via the existing ``_force_posix_locale_for_tests`` autouse fixture.

### v0.9.0 deferred items

For semver-honest tracking — the following stay open for v0.9.0:

- **D-1 / D-2 / D-4** from ``project_v08x_deferred`` — sections renumber + ``_ALL_SECTIONS`` / ``_ALWAYS_ON_SECTIONS`` fusion + granular sub-checks (the alias retrait + the section-naming uniformisation are BREAKING because they affect ``bob --check=ssh,firewall`` script syntax).
- **``BOB_SANDBOX_LEGACY=1`` trap door retrait** — BREAKING for any user who set the env var; deferred to bundle with the other architectural cleanups.
- **Parallel check execution** — ``concurrent.futures.ThreadPoolExecutor`` over the I/O-bound sections; touches threading invariants + error handling, deserves its own scoped beta.
- **``--diff <baseline.json>``** — cross-machine baseline diff, additive feature, deferred to bundle with the renamed-key migration support from D-4.
- **Tutorial / getting-started guide** — ``DOCUMENTS/TUTORIAL.md`` — substantive doc work, deferred to bundle with the v0.9.0 README refresh.

### Numbers

- **6244 tests** (6198 → 6244, +46 net). 0 regression.
- 46 dedicated v0.8.2 tests across 2 files: ``test_v082_bash_completion.py`` (21) + ``test_v082_items.py`` (25).
- 88 new locale entries (44 sections × 2 languages) + 8 ``cli.test_webhook.*`` keys.
- 1941 EN + 1941 FR locale keys total, 0 drift.

### Upgrade

``pipx upgrade bodyguard-of-bits``.

User-facing wins:

- ``bob --check=list`` is now self-documenting (44 section descriptions).
- ``bob --test-webhook`` works (smoke without full audit).
- Bash completion of ``--unignore`` + ``--ignore`` + ``--explain`` keys suggests canonical EXPLAIN_KEYS entries (was generic / missing).
- ``EXPLAIN_KEY_ALIASES`` use surfaces a deprecation warning in the log stream pointing at the v0.9.0 retrait timeline.

**v0.7.x remains EOL** (formal declaration in [SECURITY.md](../SECURITY.md) since v0.8.1). **v0.6.x remains EOL** (declared in v0.7.2).

---

## [v0.8.1] — 2026-06-05

**Minor maintenance + deep-hardening audit cycle.**

Closes **26 gap tiers** across 3 sub-agent audit passes (6/7/8) plus an initial drift / framing / silent-feature-gap sweep. 5521 → **6198 tests**, +677 net, 0 regression. ~190 dedicated v0.8.1 tests.

### Cycle initial (12 tiers)

#### T6 — profile severity coverage audit

`bob/data/profiles/desktop.conf` +24 overrides → 36 total ; `workstation.conf` +28 overrides → 31 distinct from desktop. Couverture ~30% des 107 actionable warn/alert keys. Domains couverts : clamav (5 keys), rootkit.db_outdated, auditd.* (3), secure_boot.*, file_integrity.*, log_rotation.*, backup.no_backup, mac_policy.apparmor_no_enforce, password_policy.weak_minlen, firewall_stack.ip_forward_enabled, services.exposure.open_local, ssh.* secondary (login_grace_time / x11_use_localhost — ce dernier retiré pass 6 M-1 quand T32 a chopé l'orphan).

#### T10 — i18n exception messages webhook + config + __main__

14 nouvelles locale keys EN+FR sous `webhook.error.*` × 6 / `config.error.*` × 4 / `cli.error.*` × 4. Pattern fallback dict mirror v0.7.2 M-4 : `_FALLBACK_LABELS` + `_fallback_t` dans chaque module ; `send_webhook(..., t=None)` + `UserConfig.set(...t=None)` + EmailStore.add(..., t=None) acceptent un t optionnel ; production caller (`bob/__main__.py`) passe le t bound de l'audit pour locale-matched error messages. Pre-fix : 9 exception messages EN hardcoded (5 dans webhook.py + 4 dans config.py), users FR voyaient mixed-language sur `bob --webhook HTTPS://...` invalide etc.

#### workstation alias retrait (BREAKING)

`bob/profiles.py:123-124` — l'alias v0.1.0 qui silencieusement redirigeait `bob -p workstation` vers le profil `desktop` (donc workstation.conf était dead code depuis v0.1.0) a été retiré. workstation.conf est maintenant un profile **first-class** avec ses propres overrides business-context. **BREAKING** pour les ~6 semaines de users sur l'alias : leur audit aura des sévérités différentes pour `backup.no_backup` / `auditd.*` / `mac_policy.apparmor_no_enforce` (restent à WARN sur workstation alors que desktop les relâche à INFO).

**Migration** : copier `bob/data/profiles/desktop.conf` vers `~/.config/bob/profiles/workstation.conf` pour restaurer la sémantique v0.8.0.

Test `tests/test_profiles.py::test_workstation_is_now_distinct_from_desktop` pin la BREAKING change avec 3 assertions explicit (backup / auditd / mac_policy restent à None = WARN sur workstation).

#### T11 — Finding.detail field parity (CSV + JSON v1/v2)

`bob/csv_output.py:25-44` nouvelle column `detail` inserted entre `message` et `fix_cmd` (position pinned par test). `bob/json_output.py:240-251 + 448-460` field `detail` ajouté dans le finding dict v1 + v2. Additif (consumers field-by-name unaffected). Closes le format-parity gap qui restait après v0.8.0 T9 (MD/HTML) pour les 3 machine-readable sinks restants.

#### T26 — explain dispatch services.exposed.<id>

`bob/explain.py:433-510` nouveau helper `_render_dynamic_service_explain()` qui route le lookup via `ServiceRegistry.get(svc_id)` + `service_risk.<subkey>.{level,exposure,threat}` (contenu déjà présent depuis v0.8.0 T4). Injecté dans `run_explain` avant le `unknown_key` fallback. 38 services auto-explainables avec UI cohérente (`risk_context.exposure` + `risk_context.threat` labels). Live UX : `bob --explain services.exposed.ssh` produit le contenu CRITICAL/EXPOSURE/THREAT du SSH Server, idem pour samba/ollama/tailscale/etc.

#### T27 — webhook payload detail + note

`bob/webhook.py:150-170` (generic) — chaque finding dict embarque maintenant `detail` + `note` (vides string `""` quand absents). `bob/webhook.py:185-200` (Slack inline) — les `finding_lines` concatènent le `detail` après ` — ` séparateur pour que Slack readers voient le contexte explicatif. Ferme le format-parity pattern qui couvrait déjà text/MD/HTML/CSV/JSON v1/v2.

#### T31/T37 — nature backfill 90 sites + reverts align tests existants

`bob/checks/*.py` — 90 sites `warn/alert(_with_deduction)` sans `nature=` kwarg sont maintenant classifiés : **69 action + 59 improvement + 1 structural**. Pre-fix `bob/fixes.py:32-34` filtre `if f.nature == "action" and f.cmd` donc 88% des findings actionnables étaient silencieusement skipped par `--fix --apply`. Post-fix 100% couverture.

Edge case : `bob/checks/ssh/_directives.py::_apply_bad_directive` refactoré pour propager `nature` via kwargs dict explicit (était implicit `**kwargs` → conflictait avec test_t31 visibility regex). Le rule-level `nature` (depuis dataclass) gagne, sinon default par severity : alert → action / warn → improvement.

5 reverts pour aligner avec tests existants pre-v0.8.1 qui pinnaient `improvement` : kernel_modules.risky_fs + risky_net, ntp.not_synchronized + not_enabled, smtp.exposed, rules.duplicate_found, rules.ipv6_missing.

#### T32 — profile typo validation

`bob/profiles.py::_recognised_override_keys` build une catalogue (lru_cache(maxsize=1)) des keys reconnues : EXPLAIN_KEYS ∪ `services.exposed.<id>` ∪ literal `key="..."` harvest depuis `bob/checks/*.py`. À la load de chaque profile.conf, `[overrides]` keys absentes du catalogue émettent `logger.warning("override key %r is not recognised...")`. Compat-preserving : override est encore loadé (les legacy profiles avec keys removed checks ne cassent pas le load).

**Self-catch notable** : T32 a chopé `ssh.x11_use_localhost` que J'AI moi-même ajouté en T6 desktop+workstation comme override. La key n'est émise par aucun check — j'avais introduit un orphan en pensant overrider un finding réel. Le mécanisme fait son boulot, sur le premier coup, sur mes propres erreurs.

#### T39 — orphan service_risk.ollama_llm_server cleanup

`bob/locales/{en,fr}.json:545-549` block `service_risk.ollama_llm_server.{level,exposure,threat}` retiré. Le service Ollama réel a label "Ollama (local LLM)" qui transforme en `ollama_local_llm` — entry valide depuis v0.8.0 T2. Orphan était un leftover du renaming pendant T2 cycle.

#### T57 — --unignore CLI path

`bob/ignore.py:127-184` nouveau `remove_ignore_key()` helper. `bob/cli.py:134-145, 185` + `bob/__main__.py:172-192` wire le path CLI. 2 nouvelles locale keys `cli.ignore.removed` / `cli.ignore.not_present`. Mutual-exclusion guard avec `--ignore` ajouté en pass 6 M-4. Atomic write contract préservé (mirror `add_ignore_key`).

Pre-T57, users pouvaient `bob --ignore=KEY` pour ajouter mais devaient éditer `~/.config/bob/ignore.yml` à la main pour retirer — feature symmetry gap.

#### T60 — _t_or_hardcoded helper

`bob/__main__.py:67-83` nouveau `_t_or_hardcoded(key, fallback)` helper qui returne `i18n.t(key)` si initialisé, sinon `fallback`. Wired sur 3 sites pre/post-init : `parse_args` CLIError (L90, pre-init), `main()` catch-all (L530-543, post-init en happy path mais peut être pre-init si crash très tôt). Pre-T60 : `Fatal error: …` + `Set BOB_DEBUG=1 for full traceback.` hardcoded EN même en audit FR.

#### T74 — webhook URL credential redaction

`bob/webhook.py:60-66` regex `_URL_USERINFO_RE` ancré sur `://` boundary + `bob/webhook.py:79-103` public helper `redact_url_credentials(url) -> str` qui replace `user:pass@host` par `[REDACTED]@host`. Wire dans `send_webhook` les 2 sites WebhookError construction (lignes 282-286) + dans `bob/__main__.py:386-392` le success path `output.print_info(f"Webhook: POST → {url}")`. Original URL reste utilisé pour le POST réel — seul l'affichage opérateur est sanitisé.

Pré-fix : credentials embarqués (pattern courant Slack/Discord/Mattermost) leak en cleartext sur stdout + .log + stderr + cron output + monitoring pipes.

### Audit pass 6 (5 findings shipped)

#### I-1 — ignore.yml comment preservation

`bob/ignore.py::remove_ignore_key` re-écrivait le fichier en canonical form `ignore:\n  - key: X\n`. Tout commentaire opérateur (`# Per ticket SECOPS-1234`, etc.) silencieusement détruit au premier `--unignore`. Pre-T57 (qui shippait avec ce comportement) les users éditaient le YAML à la main pour retirer, donc avaient naturellement annoté.

Fix : line-walk in-place. Drop seulement les lignes `- key: <removed>`, préserver tout le reste verbatim. Strip-comment-on-match pour avoid prefix collisions (`ssh.password_auth` ≠ `ssh.password_auth_v2`).

#### M-1 — T32 regex digits + file_perms.*

`bob/profiles.py:192` regex `[a-z_]+` rejetait segments avec chiffres → `fail2ban.ssh_jail_active`, `ipv6.ufw_disabled_no_listeners`, `ipv6.port_no_v6_rule` (real runtime emissions) déclenchaient spurious "not recognised" warnings.

Fix : regex → `[a-z][a-z0-9_]*` (aligned avec `_CANONICAL_KEY_RE` v0.7.1 M-5) + `file_perms.*` permissive prefix pour les f-string emissions (`file_perms.passwd.world_writable`, etc.) qui ne sont pas literal harvest-able.

#### M-2 — services.exposure canonical set

`bob/profiles.py:175` (now removed) — pre-fix le catalogue registrait `services.exposure.{svc.id}` pour CHAQUE service (e.g. `services.exposure.ollama`, `services.exposure.nginx`). Mais le runtime n'émet PAS ces keys — il émet `services.exposure.{exposure.value}` où exposure.value est dans `{open_world, open_local, deny, no_rule, loopback, loopback_no_rule, not_listening}` (depuis bob/checks/services.py:353-355,390-403).

Donc `services.exposure.ollama = info` dans un profile était silencieusement accepté comme "valide" mais 0 effet runtime. Symmetric false-negative à M-1 false-positives.

Fix : retrait ligne 175 + ajout du canonical set de 7 base values × 2 (avec `_ufw_inactive` variant — narrowed pass 8 M-2 plus tard).

#### M-3 — service_label_to_subkey transform consolidation

T26 docstring (`bob/explain.py:412-425`) claimait : *"Mirrors the transform used by `bob/display.py::display_risk_context` (single source of truth for service_risk locale lookups)"*. Mais `display.py` avait **2 copies inline** du transform (lignes 152-154 + 630-632), zéro déléguait au helper.

Fix : `service_label_to_subkey()` extrait dans `bob/registry.py:60-92` (vit naturellement avec `ServiceRegistry` qui owns label semantics). Les 2 inline sites de display.py + l'helper d'explain.py délèguent via import. Docstring T26 désormais véridique. Closes drift risk si transform change (ex. nouveau label avec `&` ou `+`).

#### M-4 — --unignore documentation + mutual-exclusion

`man/bob.1:300-310` nouvelle entrée `--unignore=KEY` mirror de `--ignore=KEY` (préserve comments + custom YAML). `bob/cli.py:613-620` CLIError "--ignore and --unignore are mutually exclusive" guard ajouté (mirror pattern v0.7.x mutual-exclusion guards comme `--check + --skip overlap`).

### Audit pass 7 (3 findings shipped)

#### I-1 — remove_ignore_key regex match loader grammar

`bob/ignore.py:167` (pass 6) utilisait `stripped.startswith("- key:")` (un espace exact) mais le loader regex (L29) `_KEY_LINE_RE = r"^\s*-\s+key:\s+(\S+)\s*$"` accepte `\s+`. Donc :

```yaml
ignore:
  -  key: ssh.permit_root_login    # 2 spaces, yamllint-friendly
```

→ loader voit `ssh.permit_root_login` (présente)
→ `remove_ignore_key('ssh.permit_root_login')` → False (le walk ne match pas)
→ defensive bail-out à L180-184 swallow le mismatch
→ user voit le misleading **`"Key not present in the ignore list"`**

Fix : nouveau regex sibling `_KEY_LINE_MATCH_RE` (sans `\s*$` anchor) utilisé dans le walk. Loader + remover share la même grammar `\s+`. Cf. pass 8 I-1 plus tard pour unification définitive.

#### I-2 — French colon typography drift

T10 + T60 ont i18n'd les error prefixes mais laissé un `:` ASCII hardcodé après le `t()` :
- `bob/__main__.py:90, 235, 396, 530` : `f"{t('cli.error.prefix')}: {exc}"` etc.

Convention FR = ` : ` (espace avant ET après). Plus particulièrement, `cli.error.webhook_failed_prefix` contenait déjà ` : ` dans sa valeur FR (`"Avertissement : échec du webhook"`) → résultat `"Avertissement : échec du webhook: connection refused"` (double-colon mixed style).

Fix : Option A consistent — colon-space embarqué dans valeurs locale. EN `"Error: "` / FR `"Erreur : "` / `"Fatal error: "` / `"Erreur fatale : "` / `"Warning: webhook failed: "` / `"Avertissement : échec du webhook : "`. 4 sites print drop le `: ` hardcodé.

Drift introduit par mon propre T10. Sub-agent l'a chopé.

#### M-1 — --show-ignored man description rewrite

`man/bob.1:311-314` claimait : *"List the persistently-ignored finding keys (contents of ~/.config/bob/ignore.yml) and exit. Useful to audit what has been muted before a security review."*

Mais le code (`bob/__main__.py:433` + `bob/cli.py:718` help text + `DOCUMENTS/SNAPSHOT.md:558` description) fait l'**opposé** : run l'audit complet et display les findings ignorés en dim, ne dump pas le YAML + n'exit pas. Man page était l'outlier.

Fix : réécriture du paragraphe. *"During the audit, display previously-ignored findings as dimmed lines instead of suppressing them silently. … The audit still runs end-to-end — this flag does NOT exit early or dump the ignore file's contents."*

### Audit pass 8 (5 findings shipped)

#### I-1 — _KEY_LINE_RE unification

Le pass 7 sibling regex `_KEY_LINE_MATCH_RE` (drop `\s*$` anchor pour matcher inline comments) était **unreachable**. `remove_ignore_key:165` guard `if key not in load_ignore_keys(path): return False` court-circuite AVANT le walk. Et `load_ignore_keys` utilise le STRICT `_KEY_LINE_RE` (avec `\s*$`) qui rejette lines avec inline comments. Donc :

1. User a `- key: ssh.x  # comment` dans ignore.yml → loader NE la voit PAS comme ignorée
2. `bob --unignore=ssh.x` → defensive guard bail-out → user voit "Key not present"
3. La promesse docstring du sibling regex est inatteignable

Méta-régression dans mon fix pass 7. Sub-agent l'a chopé.

Fix : drop `\s*$` anchor de `_KEY_LINE_RE` itself, retirer `_KEY_LINE_MATCH_RE`. Loader + remover share single relaxed regex. Inline-commented entries enfin loadées ET removable.

#### I-2 — runner.py 3 Warning sites un-i18n'd

`bob/runner.py:143, 157, 161` : 3 sites print `Warning: --check '...' matches no known section` / `Warning: --skip '...' has no effect (always-on section)` / `Warning: --skip '...' matches no known section`. T10 a i18n'd les error prefixes dans `__main__.py` mais loupé ces 3 sites runner.

Fix : nouvelle locale key `cli.error.warning_prefix` (EN `"Warning: "` / FR `"Avertissement : "`) + namespace `cli.runner.*` (check_no_match, check_no_match_fatal, skip_no_effect, skip_no_match, suggest_did_you_mean, suggest_run_list — 6 nouvelles keys × 2 langues = 12). Wire dans `validate_check_filters` et `_suggest` via `from bob import i18n` (in-function import pour éviter top-level circular ref).

#### M-1 — --webhook-secret phantom

`bob/cli.py:193` listait `"--webhook-secret"` dans `_VALUE_TAKING_OPTS` mais aucun `elif arg.startswith("--webhook-secret")` n'existait + pas de field `webhook_secret` dans `AuditConfig`. Résultat inconsistent :
- `bob --webhook-secret foo` → CLIError "--webhook-secret requires a value" (misleading)
- `bob --webhook-secret=foo` → CLIError "Unknown option: '--webhook-secret=foo'" (correct)

Fix : retrait 1-line de l'entry phantom. Cohérent : les deux formes maintenant "Unknown option".

#### M-2 — _ufw_inactive variants narrowed

Mon M-2 pass 6 registrait `services.exposure.{value}_ufw_inactive` pour LES 7 exposures. Mais `bob/checks/services.py:352-355` émet `_ufw_inactive` SEULEMENT pour `(NO_RULE, LOOPBACK_NO_RULE)`. Donc `services.exposure.open_world_ufw_inactive = info` accepté silencieusement comme valide → 0 effet runtime. Même UX failure que M-2 pass 6 was supposé fermer.

Méta-régression dans mon fix pass 6. Sub-agent l'a chopé.

Fix : narrow `_ufw_inactive` registration à `(no_rule, loopback_no_rule)` seulement. Variantes restantes (`open_world_ufw_inactive`, `deny_ufw_inactive`, etc.) maintenant warne correctement.

#### M-3 — t() trailing whitespace contract test pin

L'I-2 pass 7 dépend critiquement de `cli.error.prefix` keeping trailing space (`"Error: "`, `"Erreur : "`). Aucun test ne pinnait que `t()` ne strip pas trailing whitespace. Future JSON normaliser script qui call `.strip()` sur values, ou un i18n change qui strip trailing whitespace, casserait silencieusement la fix pass 7. La régression se manifesterait `"Erreurmessage…"` (no space) — visible mais hard to attribute.

Fix : 8 tests `test_X_t_preserves_trailing_space[key]` parametrized sur les 4 `cli.error.*_prefix` keys × {EN, FR}. Defend le contract pour future contributors.

### Plus — tests/conftest.py autouse i18n init fixture

L'I-2 pass 8 a rendu `bob/runner.py::validate_check_filters` dépendante de `i18n.init()` (sinon `i18n.t()` returne `[key]` bracketed-fallback). Production caller (`bob/__main__.py:184`) init i18n avant. Mais les unit tests qui appellent runner.py directement (tests/test_cli.py::TestValidateCheckFilters etc.) ne le faisaient pas.

Solution : autouse fixture `_ensure_i18n_initialised_for_tests` dans `tests/conftest.py` qui mirror la production invariant. **Opt-out** pour `test_i18n.py` via `request.module.__name__.endswith("test_i18n")` parce que ce file exerce délibérément le pre-init bracketed-fallback contract (`test_before_init_returns_bracketed_key` etc.) et a son propre `reset_i18n` teardown.

### Numbers

- **6198 tests** (5521 → 6198, +677 net). 0 régression.
- ~190 tests dédiés v0.8.1 sur 8 fichiers
- 26 tiers de gaps fermés sur 3 cycles d'audit
- 14 nouvelles locale keys T10 + 2 T57 + 6 audit pass 8 = 22 nouvelles locale keys EN+FR
- 38 services explainable via T26 dispatch
- 90 sites nature backfill T31
- workstation maintenant first-class profile distinct de desktop

### Upgrade

`pipx upgrade bodyguard-of-bits`.

Shifts comportementaux user-facing :
- **workstation profile distinct de desktop** (BREAKING — drop copy desktop.conf vers `~/.config/bob/profiles/workstation.conf` pour preserve v0.8.0 semantics)
- **4 findings peuvent maintenant déduire des points** (T3 v0.8.0 + T31 v0.8.1) — host avec services inactive critical / services active disabled / firewall policy unknown / snap network virt voit son score baisser de 1-3pts
- **`bob --fix --apply`** couvre 100% des actionable findings (était 12% pre-v0.8.1)
- **`bob --explain services.exposed.<svc>`** produit du contenu pour les 38 services (était "No explanation available")
- **`bob --unignore=KEY`** existe maintenant (CLI symmetry avec `--ignore`)
- **Webhook URLs avec credentials embarqués** display redacted form `https://[REDACTED]@host/path`
- **FR audits cohérents** sur typographie colon (espace-deux-points-espace partout)
- **Profile overrides avec typos** émettent `logger.warning` au lieu de silencieusement no-op
- **`--show-ignored`** rendering inline correctement documenté en man page (n'exit pas, ne dump pas le YAML)

**v0.7.x is now end-of-life as of 2026-06-05** — formal declaration in [SECURITY.md](../SECURITY.md), mirroring the pattern that retired v0.6.x in v0.7.2. No security fixes will be backported to v0.7.x; users must `pipx upgrade bodyguard-of-bits` to v0.8.x for security patches. The v0.8.x line is largely backwards-compatible with v0.7.x via `__init__.py` re-exports + `--json-v1` for legacy JSON consumers, except for the workstation profile BREAKING shift described above (drop a copy of `desktop.conf` at `~/.config/bob/profiles/workstation.conf` to restore v0.7.x semantics on that profile).

v0.6.x remains EOL (declared in v0.7.2).

---

## [v0.8.0] — 2026-06-04

**Minor major — drift batch + framing actions + silent-feature-gap audit.**

Closes the v0.7.x cycle (4 hardening patches v0.7.1 → v0.7.4) and opens v0.8.x. Three work axes in the same bump: (1) a drift batch that re-syncs every doc/packaging surface that fell behind since v0.6.2, (2) two framing actions against the "BOB sur-claims" misreading (a "What BOB is / is NOT" callout and a hypotheses header line in the summary box), (3) an 8-tier silent-feature-gap audit that closes "feature documented but partially implemented" gaps surfaced post-v0.7.4.

### Drift batch (11 items — anti-drift)

The 5 patch cycles v0.7.1 → v0.7.4 accumulated silent doc/packaging drift: 5 surfaces silently let their version fall behind. The drift batch re-syncs everything in a single commit + adds a 5th CI guard to prevent recurrence.

- **1. CHANGELOG FR backfill** — `CHANGELOG_FR.md` + `DOCUMENTS/CHANGELOG_FULL_FR.md` stopped at v0.7.0b2. 5 missing entries (v0.7.0 final + v0.7.1 + v0.7.2 + v0.7.3 + v0.7.4). FR readers saw the project "frozen" at a beta while PyPI shipped v0.7.4. Backfilled via translation of the EN equivalents.
- **2. Man pages** — `man/bob.1`, `man/bob.conf.5`, `man/bob-profile.5` carried `.TH BOB n "2026-05-29" "BOB 0.6.2"`. Bumped to `"2026-06-04" "BOB 0.8.0"`.
- **3. Shields.io badges** — `DOCUMENTS/README_TECH.md` + `DOCUMENTS/README_TECH_FR.md` displayed `version-v0.7.4-brightgreen`. Bumped to `v0.8.0`.
- **4. `debian/changelog`** — all historical entries were `UNRELEASED`. v0.8.0 opens with `(0.8.0-1) UNRELEASED; urgency=medium`; older entries preserved.
- **5. `packaging/rpm/bob.spec`** — `Version: 0.7.4` → `0.8.0` + new `%changelog` v0.8.0-1 entry at top.
- **6. `DOCUMENTS/TESTING.md`** — per-version table backfilled (v0.6.2 + v0.7.0 + v0.7.0b1-b4 + v0.7.1-4 were already added in drift batch; v0.8.0 row added).
- **7. `README.md` + `README_FR.md` Install section** — drift with `README_TECH.md`: the user-facing READMEs just said `pipx install` + `sudo bob` without explaining the sudo restricted PATH. Synced on the 4-substep `README_TECH.md` flow (Prerequisites / Install / Enable sudo + bash completion / Uninstall) with tone adapted (READMEs = general audience, kept absolute-path requirement for `sudo bob --install-completion`).
- **8. `tests/test_runner.py`** — smoke on `bob/runner.py::_sec()` orchestrator (highest out-degree module, 665L, no dedicated test). 3-5 smoke tests catch a Python 3.15+/16 drift in local pytest instead of the 30-min CI cycle.
- **9. 5th CI guard `tests/test_doc_version_consistency.py`** — `man/.TH × 3 + debian/changelog top + shields × 2 + rpm spec Version + CHANGELOG{,_FULL}{,_FR}.md top row` all match `pyproject.toml::version`. Would have caught items 1-5 above pre-tag-push. Pattern borrowed from `test_version_consistency.py` (v0.7.0b2 lesson), scope broadened to 7 surfaces.
- **10. Orphan `bob/checks/__init__.py::__version__ = "1.14.0"` removal** — v0.1.0 copy-paste, never consumed. Free cleanup, zero risk.
- **11. `BOB_DEBUG` documented in `SECURITY.md`** — env var trap door (`bob/__main__.py:471`) previously undocumented alongside `BOB_SHARE` / `BOB_WEBHOOK_ALLOW_INSECURE` / `BOB_SANDBOX_LEGACY`.

### Framing actions (anti-sur-claim)

External ChatGPT critique 2026-06-02 on a v0.7.4 audit: "relevant as technical diagnostic tool but not reliable as an absolute security scoring system". The correct diagnostic was about **framing** (BOB doesn't say strongly enough that it audits under hypotheses), not about the engine. Two Tier 1 actions shipped:

- **A1 — `summary.context_disclaimer` footer line** ([bob/display.py:581](../bob/display.py) + new locale key `summary.context_disclaimer`): `print_audit_summary` now appends one extra `ℹ` line just after the existing `summary.scope_line1` / `scope_line2` notes : *"Verdict conditioned by the profile and network context above. BOB is a hardening auditor, not a threat-modeling engine — interpret accordingly."* The profile + network context are already shown in the summary box (rows `Profile` + `Network context`), so the disclaimer rides on those; it does NOT re-emit a templated `Hypotheses: profile=X | context=Y | posture=Z` header. Pre-v0.8.0 the box showed `Score 8/10 + LOW` without any reminder that this verdict was *conditioned*. A screenshot reader could conclude "all is well" without seeing the context. 1 print + 1 locale key per language. 0 schema change.
- **A2 — "What BOB is / is NOT" section** ([README.md](../README.md) + [README_FR.md](../README_FR.md) + [SECURITY.md](../SECURITY.md) + [SECURITY_FR.md](../SECURITY_FR.md)): new short callout (~15 lines) that explicitly claims BOB **is** a configuration hardening auditor with contextual modulation by profile + posture, and **is NOT**: threat-modeling engine, active network exposure scanner, autonomous verdict system. The score reflects configuration hygiene under the chosen profile, not absolute security posture. Human interpretation required to translate the verdict into "is my machine Internet-exploitable".

Combined cost A1+A2: ~75 lines (~10 code + ~65 doc). Gain: pre-empts 80% of "BOB sur-claim" critiques. Backwards-compatible.

### Silent feature-gap audit (8 tiers — "documented but partially implemented" gaps)

Post-drift sweep looking for the pattern identified by Tier 1 (51 explain entries for documented WARN/ALERT findings with no explain backfill). 8 tiers of gaps surfaced, 7 shipped in v0.8.0, 2 deferred to v0.8.1.

#### Tier 1 — Explain backfill (+51 entries)

51 runtime-emitted WARN/ALERT findings had their `bob/locales/*.json` line but no `bob/explain.py::EXPLAIN_KEYS` entry — so `bob --explain <key>` returned "No explanation available". Full backfill via 15 new prefixes: `backup, ddns, docker, fail2ban, firewall_stack, iptables_nft, log_rotation, logs, mac_policy, network_context, ntp, ports, rootkit, services, smtp`. Each entry follows the canonical `<prefix>.<finding_id>` snake_case pattern (pinned by `tests/test_explain_naming_convention.py`). EXPLAIN_KEYS baseline: 117 keys / 30 prefixes (v0.7.0 baseline) → **168 keys / 45 prefixes** (v0.8.0 baseline).

#### Tier 1bis — SSH `_BadDirective.cmd_template` (+8 directives)

8 SSH directives listed in `bob/checks/ssh/_directives.py::_BAD_DIRECTIVES` (PermitEmptyPasswords / X11Forwarding / IgnoreRhosts / HostbasedAuthentication / PermitUserEnvironment / StrictModes / AllowTcpForwarding / PubkeyAuthentication) emitted their findings without `cmd=`, so `bob --fix --apply` dumped "manual fix required" even when the fix was a simple `sed -i 's/.../...\/g' /etc/ssh/sshd_config`. `_BadDirective` dataclass gains a `cmd_template: str = ""` field; each directive ships its sed-line. `_apply_bad_directive` propagates the template into the finding kwargs.

#### Tier 2 — Modern services (+6 entries, 32 → 38)

`bob/data/services.json` listed 32 services since v0.5.x, mostly historical infrastructure (sshd, apache, nginx, mysql, etc.). 6 modern services common on 2025+ hosts had no detection entry: **Tailscale** (WireGuard mesh VPN), **Caddy** (web server with auto-TLS), **AdGuard Home** (DNS ad-blocker), **Vaultwarden Password Manager** (Bitwarden-compatible self-hosted), **Ollama** (local LLM runtime), **Authelia** (SSO auth portal). 6 full-schema entries added (id+label+packages+services+ports+risk+config_key+detection with binary / snap / config_files).

#### Tier 3 — `warn_with_deduction` backfill (4 findings)

4 findings emitted bare `result.warn(...)` (zero scoring impact) while documented as `nature="improvement"` (ergo deserved a score deduction). Backfill to `warn_with_deduction`:

- `services.state.installed_inactive_critical` ([bob/checks/services.py](../bob/checks/services.py)) — critical service installed but inactive (e.g. fail2ban installed but disabled): +1pt.
- `services.state.active_disabled` ([bob/checks/services.py](../bob/checks/services.py)) — service active but disabled at boot (drift between current state and persistent state): +1pt.
- `firewall.policy_unknown` ([bob/checks/firewall.py](../bob/checks/firewall.py)) — UFW policy undetermined (parse failure or corrupted state): +2pts.
- `virt.snap_network` ([bob/checks/virtualization.py](../bob/checks/virtualization.py)) — snap virtualization tool with network exposure (LXD/Docker via snap): +1pt per occurrence, capped at 2pts cumulative to avoid over-penalizing multi-snap-virt hosts.

#### Tier 4 — `service_risk` locale backfill (5 services)

5 services had their ID in `bob/data/services.json` (detected by runtime) but zero `service_risk.<id>.{level,exposure,threat}` coverage in `bob/locales/{en,fr}.json` — so the audit displayed `[risk unavailable]` in the services panorama. EN+FR backfill for: **SMTP**, **NFS**, **Jenkins**, **OpenVPN**, **Squid**.

#### Tier 7 — Profile key rename (`hardening.auto_updates_missing` → `updates.unattended_not_configured`)

The `bob/data/profiles/desktop.conf` + `workstation.conf` profiles overrode the severity of `hardening.auto_updates_missing` — but that key has not been emitted since v0.4.x (the runtime emits `updates.unattended_not_configured` instead). So users overriding auto-updates severity on desktop/workstation saw the override silently no-op. Renamed both profiles + updated docstring in `bob/profiles.py` + tests `tests/test_profiles.py` (18 occurrences renamed).

#### Tier 9 — Format parity Markdown + HTML (`Finding.detail` + `Finding.note`)

`bob/markdown_output.py` + `bob/html_output.py` sinks ignored `Finding.detail` and `Finding.note` fields while terminal + JSON + text surfaced them. So an audit exported to Markdown or HTML lost explanatory context. New locale keys `markdown_output.{note,detail}_label` + `html_output.{note,detail}_label`; both sinks now render these fields uniformly. HTML CSS: new `.finding-detail` + `.finding-note` (font-size .82rem, dim color).

#### Tier 5 (false positive — no action)

An initial scan flagged 6 apparently-orphan `_detail` keys, but investigation showed all were consumed under different suffixes (e.g. `<base>_enabled`, `<base>_profiles`). No action.

#### Tier 6 → v0.8.1 (deferred)

Profile severity coverage audit: 94% of findings use the default severity, ~20-30 keys are candidates for profile overrides (e.g. `ssh.password_auth` should be WARN on server profile but OK on desktop). Listing to complete before remediation.

#### Tier 10 → v0.8.1 (deferred)

i18n 27 hardcoded EN exception messages in `bob/webhook.py` + `bob/config.py` (e.g. `raise ValueError("URL must start with http(s)://")`). User-facing error path in EN locale even on FR audits.

### New test guards (4 files)

From drift batch (item 8 + 9) + silent-feature-gap audit:

- **`tests/test_runner.py`** — smoke on `bob/runner.py::_sec()` orchestrator. Drift batch item 8.
- **`tests/test_explain_coverage.py`** — every runtime actionable key has its `EXPLAIN_KEYS` entry. Would have caught the 51 T1 gaps.
- **`tests/test_fix_coverage.py`** — every actionable finding has either `cmd=`, or sits in the `_MANUAL_BY_DESIGN` whitelist with inline rationale, or in `_HELPER_DISPATCH_SITES` for non-literal keys emitted from helpers (e.g. `weak_algo` helper emits 3 different keys; `services` helper emits dynamic `services.exposed.<id>`). 3 tests: whitelist sanity, helper-template presence, actionable coverage.
- **`tests/test_doc_version_consistency.py`** — drift batch item 9. 5th CI guard.

### What is NOT shipped

D-1..D-4 from the `project_v08x_deferred` contract (frozen 2026-05-30 at v0.7.x Phase 2 kickoff) remains open for v0.8.x continuation:
- **D-1**: section renumber + `emit_section()` naming uniformization
- **D-2**: fusion `_ALL_SECTIONS` + `_ALWAYS_ON_SECTIONS`
- **D-3**: retire obsolete `EXPLAIN_KEY_ALIASES` (cycle by cycle)
- **D-4**: granular sub-checks (e.g. `ssh.x11_forwarding` → `ssh.x11.forwarding.server` + `.client`)

`BOB_SANDBOX_LEGACY=1` trap-door removal (Phase 3 v0.7.0 deferred) also postponed to v0.8.x continuation.

### Numbers

- **~6008 tests** (5521 → ~6008, +487 net). 0 regression.
- 51 new `EXPLAIN_KEYS` entries (Tier 1)
- 8 new `_BadDirective.cmd_template` (Tier 1bis)
- 6 new services in `services.json` (Tier 2)
- 4 backfilled `warn_with_deduction` findings (Tier 3)
- 5 `service_risk.*` locale backfills (Tier 4)
- 4 new test guards (test_runner / test_explain_coverage / test_fix_coverage / test_doc_version_consistency)
- 2 framing actions (A1 hypotheses line + A2 What BOB is/is NOT)
- ~1873 EN locale strings (~1827 baseline + 46 new)
- 174 CIS references (138 baseline + 36 new)

### Upgrade

`pipx upgrade bodyguard-of-bits`.

User-facing behavioural shifts:
- **Summary box** now ends with a `Verdict conditioned by the profile and network context above. BOB is a hardening auditor, not a threat-modeling engine` footer note on every audit (A1) — pre-empts the "BOB says 10/10 = my host is safe online" misread
- **8 SSH directives** drop the "manual fix required" footer and ship cmd= instead (T1bis) — `bob --fix --apply` is now actionable on PermitEmptyPasswords / X11Forwarding / IgnoreRhosts / HostbasedAuthentication / PermitUserEnvironment / StrictModes / AllowTcpForwarding / PubkeyAuthentication
- **4 findings** that were OK at 10/10 now deduct points (T3) — score may drop 1-3pts on hosts with services inactive+critical / services active+disabled / firewall policy unknown / snap network virt
- **6 modern services** (Tailscale/Caddy/AdGuard Home/Vaultwarden/Ollama/Authelia) gain full detection + risk classification (T2) — hosts running them see their findings surface in the services panorama
- **Markdown + HTML** exports now surface `Finding.detail` and `Finding.note` (T9) — more informative reports without schema change
- **desktop/workstation profiles**: the `unattended_not_configured` severity override actually works now (T7)

v0.6.x remains EOL (declared in v0.7.2).

---

## [v0.7.4] — 2026-06-02

**Fourth v0.7.x hardening patch — second deep-audit pass.**

Sub-agent deep-audit on the v0.7.3 codebase surfaced 0 Critical + 6 Important + 8 Minor findings. v0.7.4 ships all 14 (bundle-aggressive pattern, no defer this cycle).

### What's fixed

#### Important

- **I-1 — `--quiet` output leaks** ([bob/runner.py:467](bob/runner.py#L467) + [bob/display.py:206](bob/display.py#L206)): the Docker `exposed_ports` block, `display_ports_overview`, `display_geoip_notice` and `display_log_results` all printed to stdout even with `-q`. `bob -q | cat` could thus be non-empty when geoip2 was unavailable, Docker exposed ports, or log analysis surfaced content. Contract break. Each helper now gates print_* calls on `config.quiet`; `report.write_*` calls always run so the `.log` report is unaffected. `display_geoip_notice` gained a keyword-only `quiet: bool = False` (back-compat default).
- **I-2 — `--explain` UI labels i18n** ([bob/explain.py](bob/explain.py) + new locale namespace `explain.ui.*`): `WHY IT IS A RISK`, `HOW TO FIX`, `SCORING`, `Domain`, `Tool cap`, `Impact`, curses picker/detail headers (`bob --explain    ↑↓: move   Enter: view   q: quit`, `↑↓ / PgUp/PgDn: scroll   Esc: back`), picker footer `{n_keys} keys across {n_groups} groups`, list-mode header `Available --explain keys:`, error path `No explanation available for: {requested}` / `Run 'sudo bob --explain list' …` — all hardcoded English on FR audits. 18 new keys land under `explain.ui.*` in both locales.
- **I-3 — `__main__` CLI flows i18n** ([bob/__main__.py](bob/__main__.py) + new `cli.list.*` / `cli.ignore.*` / `cli.baseline.*` / `compare.no_baseline_yet` keys): `--check=list` header + prefix-matching note + always-on header + usage block, `--ignore=KEY` invalid-key validation message + canonical-hint + success/already-present feedback, `--reset-baseline` deleted/not-found/error, `--diff` no-baseline-yet message — all hardcoded English. Now routed through `t()` with the audit's lang.
- **I-4 — webhook scheme symmetry between `webhook.py` and `config.py::set_webhook_url`** ([bob/config.py:261](bob/config.py#L261)): v0.7.3 I-5 made `webhook.py::send_webhook` case-insensitive (`url.lower()`); the persistence sister `UserConfig.set_webhook_url` stayed case-sensitive. Result: `bob --webhook HTTPS://...` sent OK at runtime then silently failed to persist (the `ValueError` was swallowed by `__main__.py`, leaving the saved config unchanged, so the next cron audit posted nowhere). Mirrors the v0.7.3 fix with `url.lower().startswith(...)` for the scheme check; persisted value is the user's original case.
- **I-5 — `bob/checks/services.py` duplicate private-IP matcher** ([bob/checks/services.py:38](bob/checks/services.py#L38)): the v0.5.6 architectural unification of private-IP detection retired a hand-rolled regex in `bob/checks/logs.py` and documented that `sysinfo._is_private_or_loopback_ipv4/_ipv6` is the single source of truth. A duplicate `_PRIVATE_ADDR` regex was overlooked in `services.py::_classify_exposure`. v0.7.4 replaces the regex with token extraction + delegation to the sysinfo helpers, so the next CGNAT / ULA / link-local range update lands once. Behaviour-preserved: all existing 192.168 / 10.0 / 172.16 / 100.64 (CGNAT) / fc00:: (ULA) tests pass; IPv6 zone-id (`fe80::1%eth0`) is stripped before the helper call.
- **I-6 — CSV `risk` aligned to JSON v1 (BREAKING)** ([bob/csv_output.py:55](bob/csv_output.py#L55)): pre-v0.7.4 CSV `risk` used `engine.effective_level.value` (posture-escalated) while JSON v1 `risk` was restored to `engine.level.value` (score-only) by v0.7.1 I-3 to preserve the v0.6.x wire-format contract. Consumers comparing CSV + JSON v1 on the same posture-escalated audit saw different `risk` values. v0.7.4 aligns CSV with JSON v1's score-only semantics — **wire-format break** for CSV consumers that relied on the escalated value (migrate to JSON v2's `posture_escalation.score_level` for that). User decision: option A (rename + break) chosen explicitly per the v0.7.1 contract-preservation stance.

#### Minor

- **M-1 — `recurrence.py` dead `.tmp` cleanup removal** ([bob/recurrence.py:67](bob/recurrence.py#L67)): pre-v0.7.2 `_atomic.atomic_write` used a deterministic `name + ".tmp"` suffix; the handler tried to `unlink_missing_ok` that exact path on failure. Since v0.7.2 M-7 (`tempfile.mkstemp` random names), `recurrence.json.tmp` virtually never exists and the handler silently no-ops. `_atomic.atomic_write` already cleans up its own tmp leftovers via its `except BaseException` block. Removed the dead line.
- **M-2 — CLI value-missing UX** ([bob/cli.py:533](bob/cli.py#L533)): pre-v0.7.4 `bob -l` (no value) fell through to `Error: Unknown option: '-l'` — confusing, since `-l` IS known and only its value is missing. Each value-taking elif was gated by `i + 1 < len(argv)`; when the option was the last argv element, the elif missed and the parser fell into the `Unknown option` catch-all. New module-level `_VALUE_TAKING_OPTS` frozenset enumerates the value-taking flags; the else-branch checks `arg in _VALUE_TAKING_OPTS` and raises a clearer `<flag> requires a value`. `-e/--explain` and `--watch` are intentionally absent from the set because they have documented no-arg forms (interactive picker, default 30 s loop). Pins: 9 new tests.
- **M-3 — cron wrapper `PYTHONPATH` trailing-colon footgun** ([bob/cron/_io.py:45](bob/cron/_io.py#L45)): pre-v0.7.4 the install-cron-generated wrapper exported `PYTHONPATH=path:"$PYTHONPATH"`. Under cron `$PYTHONPATH` is typically unset, so the resulting value was `path:` — a trailing colon. Python interprets a trailing colon as "also search CWD" (long-standing footgun); root's CWD becomes `/root`, so a write to `/root/foo.py` would shadow stdlib at the next cron run. BOB ships the hardening pitch so this gap mattered. Fixed via `path${PYTHONPATH:+:$PYTHONPATH}` — no trailing colon when unset, semantically identical when set.
- **M-4 — `_sandbox.py` + `plugin_checks.py` WARN message i18n + `key=`** ([bob/_sandbox.py:800](bob/_sandbox.py#L800) + [bob/plugin_checks.py:175](bob/plugin_checks.py#L175)): 9 sandbox error WARN paths emitted hardcoded English messages AND no `key=`, so `bob --ignore plugin.sandbox.timeout` had no key to match (the user had no way to silence repeated plugin failures). New locale namespace `plugin.sandbox.*` (9 keys: timeout / no_result / bad_payload / error / rejected / runner_error / missing_run_check / bad_return / crashed). Each WARN now carries `key="plugin.sandbox.<reason>"`. `t` is threaded from `PluginCheck.run(t)` through `SandboxRunner.run(plugin_path, t)` → `_run_sandboxed(t)` / `_run_legacy(t)`; absent `t` falls back to English via a per-module `_sandbox_msg` / `_warn_msg` helper (back-compat with legacy callers).
- **M-5 — `report.py::write_header` banner labels i18n** ([bob/report.py:219](bob/report.py#L219)): the `--detailed` `.log` report begins with hardcoded English `[SYSTEM INFORMATION]` + `System` / `Host` / `Kernel` / `Firewall` / `User` / `Language` / `Port config`. Same Frenglish gap that v0.7.3 M-5 closed for `write_summary`. `write_header` now accepts an optional `labels=` dict; `__main__.py` passes the audit's bound `t()` values from the `banner.*` namespace (3 keys re-used: `system` / `host` / `kernel` / `user`; 4 new: `system_information` / `firewall` / `language` / `port_config`). Defaults preserve the pre-v0.7.4 English wording for back-compat. `MarkdownReport.write_header` accepts `labels=` for Protocol parity but ignores it (Markdown reports use fixed structural labels for external-tool interop — may be honoured later if user demand surfaces).
- **M-6 — `fixes.py` Frenglish parenthetical** ([bob/fixes.py:108](bob/fixes.py#L108)): `print(f"  ✖ {t('fixes.manual')} (unsafe shell syntax in command)")` — `fixes.manual` was translated, the parenthetical hardcoded English. New `fixes.skipped_unsafe_shell` key in both locales.
- **M-7 — `json_output` uses cached `engine.domain_scores`** ([bob/json_output.py:215](bob/json_output.py#L215) + [bob/json_output.py:418](bob/json_output.py#L418)): the v1 + v2 JSON builders re-ran `compute_domain_scores(engine)` to assemble the `domain_scores` block, while the engine already held the cached values from `apply_domain_score_override`. Equivalent today; future drift risk between terminal display (reads cache) and JSON (recomputes) eliminated. Cache-first with a fresh-compute fallback for engines without override applied (defensive — production code paths always go through `apply_domain_score_override` before JSON emit).
- **M-8 — `set_posture_from_engine` rejects bool subclass-of-int** ([bob/scoring.py:706](bob/scoring.py#L706)): `isinstance(True, int)` is True (bool is subclass of int). A `firewall: True` entry in `domain_scores` would slip past the `elif isinstance(int)` branch and forward `firewall_domain_score=True` to `set_posture`, which then raises TypeError from its explicit-bool reject guard (scoring.py:538). The helper's docstring claimed to "centralise the dict-vs-int guard so a future contributor adding a new entry point can't accidentally pass the wrong shape" — this v0.7.4 fix completes that promise. Bool now normalised to None (skips the posture floor instead of crashing).

### What's NOT shipped

Every triaged candidate shipped this cycle. The bundle-aggressive pattern from v0.7.3 was applied without exception (zero defer, zero forced v0.7.5).

### Numbers

- **5521 tests** (5502 → 5521, +19 net). 0 regression.
- 1 CSV/JSON v1 risk parity pin (I-6)
- 1 webhook scheme symmetry pin (I-4)
- 4 display-quiet pins (I-1 `display_geoip_notice`)
- 9 CLI value-missing UX pins (M-2 including `--explain` / `--watch` no-arg sanity)
- 1 cron PYTHONPATH safe-form pin (M-3)
- 3 `set_posture_from_engine` bool/int/dict normalisation pins (M-8)

### Upgrade

`pipx upgrade bodyguard-of-bits`.

User-facing behavioural shifts:
- **CSV column `risk` is now score-derived** (BREAKING for posture-aware CSV consumers — migrate to JSON v2 `posture_escalation.score_level` for the escalated value)
- `--explain`, `--check=list`, `--ignore=KEY`, `--reset-baseline`, `--diff`-no-baseline now fully French in FR locale
- `bob -l` (and other value-taking flags) now error with `requires a value` instead of `Unknown option`
- Webhook URL scheme matching is case-insensitive on persist as well as send
- Cron wrappers regenerated via `sudo bob --install-cron` no longer produce a `PATH:` trailing-colon
- `--detailed` `.log` report header in FR is now fully French

v0.6.x remains EOL (declared in v0.7.2).

---

## [v0.7.3] — 2026-06-02

**Third v0.7.x hardening patch — full deep-audit pass.**

Sub-agent deep-audit on the v0.7.2 codebase surfaced 0 Critical + 6 Important + 13 Minor findings. After cross-checking each finding in code, v0.7.3 ships 14 fixes (6I + 8M) and explicitly skips 5 minors with clear rationale.

### What's fixed

#### I-1 — FR locale "finding" → "découverte"

`bob/locales/fr.json` `html_output.no_findings` was `"Aucun finding détecté."` and `html_output.findings_count` was `"{count} finding(s)"` — both leaked the English word "finding" into French audits. Fixed to `"Aucune découverte détectée."` and `"{count} découverte(s)"`. The mistake was mine when adding the FR locale entries in v0.7.2 M-4.

#### I-2 — `completion.py` SUDO_USER not validated

`bob/sysinfo.get_user_home` and `chown_to_sudo_user` both guard `pwd.getpwnam(sudo_user)` via `re.match(r"^[a-zA-Z0-9_.-]{1,256}$", sudo_user)` before calling. `bob/completion.py:36-37` did NOT validate — a malformed or spoofed `SUDO_USER` (anything not in `/etc/passwd`) crashed `install_completion()` with an unhandled `KeyError` instead of returning exit 3.

v0.7.3 routes through the same regex + `try/except KeyError` pattern. The `else: candidate = None` branch silently falls through when the user doesn't exist.

#### I-3 — CSV column rename: `section` → `nature` (BREAKING)

`bob/csv_output.py:18-30` declared the header column `"section"` but the row population at line 64 used `f.nature` whose documented values are `"action" / "improvement" / "structural" / ""` (per `bob/scoring.py:129`). Tests in `tests/test_csv_output.py:143, 411, 487` baked in the mislabel (`assert rows[0]["section"] == "ssh_audit"` with `nature="ssh_audit"`). External CSV consumers parsing the `section` column received `nature` strings, not audit section names.

v0.7.3 renames the column to `"nature"` to match the actual data. The CSV has no `schema_version` field so this is a wire-format break for external consumers; the CHANGELOG documents the rename clearly.

User decision: `Rename section → nature` (option A) — the mislabel was worse than the rename. Tests updated (`sed -i 's/"section"/"nature"/g'`) plus a new explicit pin `TestCsvColumnNatureRename::test_header_carries_nature_not_section`.

#### I-4 — `manage_logs.py` 3 bare `input()` violated safe_input contract

Project convention #2 requires every interactive prompt to go through `bob._tty.safe_input` or `prompt_wizard`. `bob/manage_logs.py` had 3 bare `input()` sites:

  - Line 104 — the path-prompt with readline path-completer integration. Sub-agent acknowledged this has a "readline integration excuse" — left as-is.
  - Line 365 — move-logs confirmation prompt. Migrated to `safe_input`.
  - Line 388 — delete-all confirmation prompt. Migrated to `safe_input`.

The pre-v0.7.3 manual `try/except EOFError: confirm = ""` handling is equivalent to `safe_input`'s EOFError→"" semantic.

#### I-5 — Webhook URL scheme case-insensitive

`bob/webhook.py:206` was `url.startswith(("http://", "https://"))` — case-sensitive. RFC 3986 allows schemes in any case (e.g. `HTTPS://...`). Pre-v0.7.3:

  - `HTTPS://example.com` → rejected with the bogus `"must start with https:// (or http://...)"` error.
  - `Http://example.com` → rejected at line 206 instead of falling through to the v0.7.1 I-5 http-insecure guard at line 208.

v0.7.3 normalises via `url_lower = url.lower()` and uses `url_lower.startswith(...)` for both the scheme guard and the http-insecure guard. The original `url` is still what reaches `urllib.request` so the actual request preserves the user's case.

Tests: 3 new pins in `TestSendWebhookSchemeCaseInsensitive` — `HTTPS://...` accepted, `HtTpS://...` accepted, `HTTP://...` rejected (without escape hatch).

#### I-6 — markdown/html level guard convergence

The v0.7.2 M-4 i18n extraction added an `effective_level` fallback in both `bob/markdown_output.py` and `bob/html_output.py`, but used different idioms:

  - markdown: `level_value = getattr(_eff_level, "value", "")` then `level_value.capitalize() if level_value else t("...risk_unknown")`. A mock with `effective_level = SomeObj()` (no `.value` attr) silently falls through to "unknown".
  - html: `_eff_level is not None: str(_eff_level.value).upper()` else `t("...risk_unknown")`. A mock with no `.value` attr would crash.

v0.7.3 converges markdown on the safer html idiom (`is not None` check + direct `.value` access, surfacing type confusion via AttributeError). Capitalize vs upper rendering also documented.

#### M-2 — `--lang VALUE` space-separated form

`bob/cli.py:226-231` accepted `--lang=VALUE` but not `--lang VALUE`. Every other value-taking option supports both forms. Pre-v0.7.3 a user typing `bob --lang fr` got `CLIError: Unknown option: 'fr'`.

v0.7.3 adds the space-form branch right after the `=` form, with the standard "next arg doesn't start with `-`" check. New pin: `test_lang_accepts_space_separated_form`.

#### M-3 — `bob -e ""` empty key rejected

`bob/cli.py:302-304` consumed the next arg if it didn't start with `-`. For `""`, this was true, so `config.explain_key = ""` was set. Then `if config.explain_key:` at `__main__.py:84` was False (empty string is falsy) — the explain branch was skipped entirely, but the arg had been consumed. Net effect = same as no `-e` at all, with no error.

v0.7.3 explicit empty check after the consumption: `if not value: raise CLIError("--explain requires a key...")`. New pin: `test_explain_empty_value_rejected`.

#### M-4 — argv hardening on `-w`/`--ignore`/`--output-dir`

The space-form branches for these three flags didn't have the "next arg doesn't start with `-`" check. A typo like `bob -w --quiet` parsed as `webhook_url="--quiet"`; for `--ignore` the malformed value would later fail the v0.7.1 M-5 canonical-key validator with a confusing message; for `--output-dir` a directory named `--quiet` was silently created.

v0.7.3 adds the same `not argv[i+1].startswith("-")` check to all three flags. The unknown-option branch now catches the typo at parse time. New pins: 3 tests (`test_webhook_space_form_rejects_dash_value`, `test_ignore_space_form_rejects_dash_value`, `test_output_dir_space_form_rejects_dash_value`).

The broader argv-disambiguation cleanup remains a v0.8.0 candidate (every other flag still has the same shape, just no one has typo'd them in practice yet).

#### M-5 — `report.py` field labels i18n

`bob/report.py:344-349` had 6 hardcoded English labels:

```
self._writeln(f"OK      : {ok_count}")
self._writeln(f"Warning : {warn_count}")
self._writeln(f"Alert   : {alert_count}")
self._writeln(f"Score   : {score}/10")
self._writeln(f"Risk    : {risk_str}")
self._writeln(f"Context : {context_str}")
```

`labels=` dict only carried `"summary"` and `"breakdown"`. A French audit (`bob -d --french`) produced a `.log` file with English field names mixed with the rest of the French content.

v0.7.3 extends `labels=` with 6 new entries (`ok`, `warning`, `alert`, `score`, `risk`, `context`). The caller in `bob/display.py:585-598` populates them via `t("report.field_*")`. New keys under `report.field_*` + `report.summary_title` added to `en.json` and `fr.json`. FR: `Attention` / `Alerte` / `Risque` / `Contexte`.

Defaults match the v0.7.2 English output exactly so legacy callers (test mocks that pre-date the i18n extraction) produce the same `.txt` content.

#### M-6 — `_inline_format` double-escape URL chars fix

`bob/report_markdown.py:467-473` (Markdown→HTML inline converter for email reports) ran `text = html.escape(text)` over the WHOLE input including the link URL inside `(...)`. Then `_LINK_RE.sub` matched and called `_safe_url(m.group(2))` which calls `html.escape(url, quote=True)` again — double-escape.

Concrete impact: a URL `https://example.com/?a=1&b=2` becomes `https://example.com/?a=1&amp;b=2` after the first escape, then `https://example.com/?a=1&amp;amp;b=2` after the second. The rendered `href="..."` carries the double-escaped value.

Latent in v0.7.x: BOB-emitted Markdown doesn't currently include URLs with `&` `<` `>` `"`. But the bug is real.

v0.7.3 fix: `raw_url = html.unescape(m.group(2))` before passing to `_safe_url`. The label part (`m.group(1)`) stays escape-once as it should.

#### M-10 — `set_posture_from_engine` helper extract

`bob/__main__.py:297-304` and `bob/watch.py:107-114` both ran:

```python
_fw = engine.domain_scores.get("firewall")
engine.set_posture(
    firewall_inactive=not fw_active,
    iptables_input_accept=any(f.key == "iptables_nft.input_accept" for f in engine.findings),
    firewall_domain_score=_fw["score"] if isinstance(_fw, dict) else None,
)
```

The two sites had subtly different guard idioms (`isinstance(_fw, dict)` vs `_fw`) but the same intent.

v0.7.3 extracts `bob.scoring.set_posture_from_engine(engine, fw_active)` as the single source of truth. The helper consolidates the dict-vs-int guard on the firewall domain score so a future entry point (e.g. a new `bob/serve.py` HTTP wrapper) can't accidentally pass the wrong shape — the Phase 1 4ed2e3b regression class is closed by construction.

Per the `feedback-conservative-refactor` rule ("gain × risque = STOP"), this would be borderline if shipped alone (only 2 call sites). Bundled with the other v0.7.3 changes the touch on these 2 files amortises across multiple substantive edits.

#### M-11 — `send_html_email` defensive CRLF stripping

`bob/report_markdown.py:567-583` (the HTML-email sender for the markdown-to-html pipeline) set MIME headers from caller-provided `from_email`, `recipient`, `subject`. `email.MIMEText` handles well-formed values, but a tainted value with an embedded `\r\nBcc:` would be accepted by some MTAs as a header injection.

v0.7.3 strips `\r\n` from the three headers via a local `_strip_crlf` helper. Defence-in-depth; current callers are BOB-internal and not tainted.

#### M-12 — html_output risk label translated

`bob/html_output.py:158` displayed the risk-level badge via `str(_eff_level.value).upper()` — always English (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) regardless of the audit locale. The finding badges below already used translated `_LEVEL_LABEL_KEY` keys, so a French audit had `Aucune découverte détectée.` next to `<strong>LOW</strong>` — mixed-language UX.

v0.7.3 routes the risk label through `t(f"html_output.risk_{_eff_level.value}")` with a fallback to the upper-cased value when the locale key is missing (so a future RiskLevel enum value works without immediately breaking the badge). New keys in `en.json` (`risk_low/medium/high/critical = LOW/MEDIUM/HIGH/CRITICAL`) and `fr.json` (`FAIBLE/MOYEN/ÉLEVÉ/CRITIQUE`). Pins: 2 tests (`test_french_locale_yields_translated_risk_label`, `test_fallback_to_uppercased_value_when_key_missing`).

### Skipped per `feedback-conservative-refactor` (5)

  - **M-1** — `bob/registry.py:363` `f"..."` without interpolation. Pure cosmetic; the `f` prefix has no functional impact. Skip per conservative-refactor.
  - **M-7** — `csv_output.py` timestamp/score/risk repeat on every row. By design — the CSV is self-contained per row (the v0.4.x design intent). The sub-agent flagged "for visibility, not for action". Skip.
  - **M-8** — `bob/formatter.py` has zero in-tree consumers. The docstring at line 6 already explains it's a stub for the v0.5.0+ deferred Phase 2 Option A migration; the module is INTENDED to be a future-API placeholder. Skip until the migration moves forward.
  - **M-9** — `bob/_atomic.py:68` `except BaseException` is broader than `except Exception` — but the comment says "ANY failure path" intentionally. Catching `KeyboardInterrupt` here is REQUIRED so `os.unlink(tmp_name)` runs and we don't leave a `.tmp` file on Ctrl+C. The sub-agent's recommendation to narrow to `Exception` would re-introduce the orphan-tmp bug. Skip.
  - **M-13** — `bob/explain.py::EXPLAIN_KEYS` is a `list[str]` used as a set in `display.py:477` (O(n) per call). 23k comparisons per audit is well below any perf threshold; `feedback-conservative-refactor` says "gain × risque = STOP" — skip.

### Tests

5490 → **5502** (+12 net), 0 regression. Breakdown:

  - 1 new pin in `tests/test_csv_output.py::TestCsvColumnNatureRename` (I-3)
  - 3 new pins in `tests/test_webhook.py::TestSendWebhookSchemeCaseInsensitive` (I-5)
  - 6 new pins in `tests/test_cli.py::TestArgvHardeningV073` (M-2 + M-3 + M-4 × 4 flags)
  - 2 new pins in `tests/test_html_output.py::TestHtmlRiskLevelTranslated` (M-12)

CI multi-Python (3.10/3.11/3.12/3.13/3.14) × multi-distro (Debian 12+13, Ubuntu 22.04+24.04+25.04, Kali, Fedora 41) validates post-tag-push.

### Upgrade

```bash
pipx upgrade bodyguard-of-bits
sudo bob --version   # should print 0.7.3
```

User-facing behavioural shifts:

  - **CSV column rename `section` → `nature`** is a breaking change for external consumers parsing the CSV. The data was already `Finding.nature`; the rename just labels it correctly. Update your CSV parsers.
  - **French audit `.txt` reports** now have French field labels (`OK / Attention / Alerte / Score / Risque / Contexte`) — no more mixed-language. English audits unchanged.
  - **HTML reports** in French locale now have French risk badges (`FAIBLE` / `MOYEN` / `ÉLEVÉ` / `CRITIQUE`). English locale unchanged.
  - **Webhook URL scheme matching** is now case-insensitive. `HTTPS://example.com` works.
  - **`bob --lang fr`** (space form) now works. Previously only `--lang=fr`.
  - **`bob -w --quiet`** (typo) now errors at parse time. Same for `--ignore --quiet` and `--output-dir --quiet`.

### Deferred contract

**v0.7.x audit cycle is now fully closed.** No deferred items remain for v0.7.4. If a new sub-agent audit runs between now and v0.8.0, its findings will be triaged into v0.7.4 directly. The `project_v08x_deferred` memory continues to track items reserved for the next major.

---

## [v0.7.2] — 2026-06-01

**Second v0.7.x hardening patch — closes the 6 deferred minors from v0.7.1's sub-agent audit + formalises v0.6.x EOL.**

v0.7.1 shipped 4 important + 3 minor; the audit had surfaced 8 more minors (counted as 6 actionable plus 1 inline-resolved plus 1 skip-forever) that were deferred to v0.7.2 per documented "gain × risque" triage. This release closes that contract entirely — there is no v0.7.3 deferred backlog after this.

### What's fixed

#### M-4 — HTML / Markdown export builders i18n extraction

`bob/markdown_output.py` and `bob/html_output.py` shipped with all user-facing strings hardcoded in English ("Summary", "Score Deductions", "Generated by [BOB]", `<html lang="en">`, etc.). That violated the documented project contract that every user-facing string goes through `t = bob.i18n.get_translation(lang); t("namespace.key")`. Impact was low (output is offline, not terminal where i18n is enforced everywhere else) but blocked future locales like `de.json` / `es.json` on these two surfaces.

v0.7.2:

  - Both `build_markdown_output()` and `build_html_output()` accept an optional `t` translation function. When the caller passes `t` (production: `bob/__main__.py` now does), every string runs through it. When `t=None` (legacy callers / tests that didn't update), an English fallback dict `_FALLBACK_LABELS` declared inline in each module supplies the v0.7.1 strings unchanged — so this is fully backwards-compatible.
  - `build_html_output()` also accepts a `lang: str = "en"` kwarg that sets the `<html lang="...">` attribute. `bob/__main__.py` passes `config.lang` so French audits get `<html lang="fr">`.
  - 24 new keys under `markdown_output.*` + 22 new keys under `html_output.*` in both `bob/locales/en.json` and `bob/locales/fr.json`. The `findings_count` key uses a `{count}` template var so plural forms can localise correctly in future locales (current FR uses the English "(s)" pattern; can be refined).
  - 4 new HTML pins in `tests/test_html_output.py::TestHtmlT18nExtraction`: default `lang="en"`, custom `lang` propagation, custom `t` sentinel routes through every key, fallback completeness assertion.
  - 3 new Markdown pins in `tests/test_markdown_output.py::TestMarkdownT18nExtraction`: English fallback, custom `t` sentinel routing, fallback completeness.

The English `_FALLBACK_LABELS` dict in each module is the canonical baseline for future translators — copy its values into `bob/locales/<lang>.json` under the matching namespace.

#### M-6 — `sysinfo.get_public_ip()` IPv4-only regex rejected IPv6 responses

`bob/sysinfo.py:199` had `re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")`. On hosts where the HTTPS provider request travels over IPv6 (typical on v6-only ISP allocations), the providers (ipify, icanhazip, ifconfig.me) return a v6 address — which the regex rejected, so `get_public_ip()` always returned `""` on those hosts even though they had a working public address. The downstream `detect_network_context()` has a v6 fallback so the network-context detection still worked, but the JSON `public_ip` field documented in README didn't reflect reality.

v0.7.2: regex replaced by `ipaddress.ip_address(response.strip())` which accepts v4 and v6 syntactically while rejecting malformed strings, hostname-style answers, and other garbage via `ValueError` (caught in the existing `except` clause). Three-line change; no test broke because the existing tests use sentinel strings rather than real provider responses.

#### M-7 — `_atomic.py` tmp-file collision under concurrent writers

Pre-v0.7.2 the tmp file name was the fixed pattern `path.with_suffix(path.suffix + ".tmp")`. Two concurrent `bob` invocations (cron job + manual `sudo bob` + watch loop firing on schedule — all three can coincide on a server-style host) raced on the same `.tmp` path. The `O_TRUNC` flag let writer B overwrite A's bytes mid-flight; A's `os.replace` then committed an inconsistent file.

v0.7.2: replaced by `tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))` which generates a per-call unique tmp name. Plus a `try` / `except BaseException` wraps the tmp-write loop so a failed rename triggers an `os.unlink(tmp_name)` cleanup — the previous code left orphan `.tmp` files in `~/.config/bob/` on every failed write (rare but accumulating).

The v0.7.1 M-2 fsync (file fd + parent directory fd) remains intact.

#### M-8 — `SCHEMA_*_KEYS` frozensets wired as enforced invariants

`bob/json_output.py` declared four public frozensets (`SCHEMA_V1_REQUIRED_KEYS`, `SCHEMA_V1_FULL_KEYS`, `SCHEMA_V2_REQUIRED_KEYS`, `SCHEMA_V2_FULL_KEYS`) whose docstring said "Tests assert this set as a hard invariant". Pre-v0.7.2 they were declared but no test ever imported them — a rename or addition in the producer would have left the frozensets silently wrong (anticipated API pattern documented by the `feedback-release-monitoring` memory).

v0.7.2:

  - `tests/test_json_schema_v2.py` imports the four frozensets and uses them in place of its own local `EXPECTED_REQUIRED_KEYS_V2` / `EXPECTED_FULL_KEYS_V2` copies. The local copies are now aliases of the production constants, so any future drift in the producer fires the existing v2 assertion tests immediately.
  - New test class `TestSchemaConstantsPinActualOutput` adds 4 explicit pins (1 per schema × short/full combination) that assert `set(data.keys()) == SCHEMA_X_KEYS` against the real producer output. The test message includes the symmetric difference so a contributor sees both what got added without updating the frozenset AND what got removed without updating the producer.

#### M-9 — `--json-full --json-v1` help text gap

`bob/cli.py:604` help line now mentions `--json-v1` is "combinable with `--json-full` / `-J` for the legacy full layout". One-line documentation fix.

#### M-10 — `display.py` posture-detection paths consolidated

The pattern `getattr(engine, "effective_level", engine.level)` + `unpack_posture_escalation(engine)` + conditional `t(key)` lookup appeared in two places: `_summary_header_lines` (terminal score box) and `print_audit_summary` (on-disk `.txt` report). Pure-cleanup duplication, no behavioural drift between the two.

v0.7.2 extracts `_compute_posture_annotation(engine, t) -> (effective_level, annotation: str)` at module level. Both call sites now invoke the helper; behaviour identical, single source of truth for posture surfacing.

Per the `feedback-conservative-refactor` memory rule ("gain × risque = STOP"), this pure-cleanup change was bundled with M-4 in the same v0.7.2 commit so the touch on `display.py` amortises across multiple substantive edits. Not shipped as a standalone refactor.

### v0.6.x officially declared EOL

`SECURITY.md` and `SECURITY_FR.md` updated:

  - 0.7.x marked ✅ current
  - 0.6.x marked ❌ end of life (was current pre-v0.7.0)
  - New explanatory paragraph: "**v0.6.x is end-of-life as of 2026-06-01** (same day v0.7.0 shipped). No security fixes will be backported to v0.6.x. Users on v0.6.x must `pipx upgrade bodyguard-of-bits` to v0.7.x to receive security patches. The v0.7.0 release is backwards-compatible with the v0.6.x public API via `__init__.py` re-exports + the `--json-v1` flag for legacy JSON consumers — upgrading is transparent for the vast majority of users."

Plus the v0.6.2 GitHub Release notes carry a prominent EOL banner at the top (manually edited via `gh release edit`).

### M-11 skip-forever item

`bob/registry.py:30` `from typing import Iterator` used in a single annotation — could be inlined as `collections.abc.Iterator`. Per `feedback-conservative-refactor` ("Pas de churn cosmétique : gain faible × risque non-nul = STOP"), this is exactly the type of cosmetic-only change that adds no value. **Not shipped, will not be shipped in any future v0.7.x patch.** If a future contributor touches `registry.py` for substantive reasons, they can pick this up at zero marginal cost; otherwise leave it.

### Tests

5479 → **5490** (+11 net), 0 regression. Breakdown:

  - 4 new pins in `tests/test_json_schema_v2.py::TestSchemaConstantsPinActualOutput` for M-8
  - 3 new pins in `tests/test_markdown_output.py::TestMarkdownT18nExtraction` for M-4 markdown
  - 4 new pins in `tests/test_html_output.py::TestHtmlT18nExtraction` for M-4 html (incl. `lang` attribute)

All locale keys added in `bob/locales/{en,fr}.json` pass the existing `tests/test_locale_coverage.py` AST scan (46 new keys × 2 locales = 92 assertion runs, all green).

CI multi-Python (3.10/3.11/3.12/3.13/3.14) × multi-distro (Debian 12+13, Ubuntu 22.04+24.04+25.04, Kali, Fedora 41) validates post-tag-push.

### Upgrade

```bash
pipx upgrade bodyguard-of-bits
sudo bob --version   # should print 0.7.2
```

No CLI contract change. No JSON contract change. The Markdown / HTML exports produce visibly localised output when running under a French audit (`--french` or `BOB_LANG=fr`) — pre-v0.7.2 they were always English.

### Deferred contract

**v0.7.x audit cycle is now fully closed.** No deferred items remain for v0.7.3 — if a new sub-agent audit is run between now and v0.8.0, its findings will be triaged into v0.7.3 directly. The `project_v08x_deferred` memory continues to track items reserved for the next major bump.

---

## [v0.7.1] — 2026-06-01

**First v0.7.x hardening patch — same-day follow-up to v0.7.0 final.**

A sub-agent deep-audit on the full v0.7.0 codebase (the same pattern that drove v0.5.5, v0.6.1, Phase 2.1, T3 Step 4) surfaced 0 Critical + 5 Important + 11 Minor findings. v0.7.1 ships 4 Important + 3 Minor. The remaining 1 Important + 8 Minor are deferred to v0.7.2 (see "Deferred" section below); the 5 documented "Known limitations" pinned by v0.7.0 (PEP 416 architectural escape + I-1 unbound dict bypass on sandbox builtins) are NOT in scope and remain intentionally open per `SECURITY.md` "Threat model".

### What's fixed

#### I-1 — `bob --watch` did not propagate posture escalation or ignore.yml

The watch loop created a fresh `ScoreEngine()` per iteration (correct — each audit must be independent) but never set `engine.ignore_keys = load_ignore_keys()` and never called `engine.set_posture(...)`. Result:

  - A host whose UFW just went down (firewall_inactive triggered) kept showing `LOW risk` in `bob --watch=30` even though the next non-watch audit correctly displayed `HIGH risk (raised by posture: firewall inactive)`. Watch was the "easy" entry for monitoring exactly this kind of incident — and it was hiding it.
  - Findings in the user's `~/.config/bob/ignore.yml` reappeared on every watch iteration: the deduction was applied, the WARN was printed, the operator was annoyed twice a minute.

v0.7.1:

  - `engine.ignore_keys = load_ignore_keys()` set immediately after construction, per iteration.
  - `engine.set_posture(firewall_inactive=not result.fw_active, iptables_input_accept=..., firewall_domain_score=...)` called after `finalize()` + `apply_domain_score_override()`, with the same input shape `bob/__main__.py` uses for the non-watch audit path.
  - Watch's per-iteration line now prints `[effective_level]` next to the score bar so the operator sees the posture-escalated level immediately (e.g. `[high]` on a firewall-down host instead of `[low]`).
  - `_score_bar()` now explicitly rejects `bool` (subclass of `int`) — matches the v0.7.0 Phase 2.1 I-3 guard on `ScoreEngine.set_posture`. Without it, `_score_bar(True)` returned `"█░░░░░░░░░"` silently because `isinstance(True, int) is True`. Defensive; no production caller passes a bool.

#### I-2 — `Report` Protocol + `MarkdownReport.write_summary` did not accept `posture_annotation`

`bob/display.py:567` passes `posture_annotation=...` to `report.write_summary` (added in v0.7.0 Phase 2.1 M-3 for the `.txt` report). The `Report` Protocol in `bob/report.py:72-83` AND the `MarkdownReport.write_summary` impl in `bob/report_markdown.py:152-163` both kept the v0.6.x 9-parameter signature. Today the bug doesn't fire because `display.print_audit_summary` only ever receives `AuditReport` / `NullReport` instances — but the contract drift is a landmine: any future plumbing that routes the audit summary through `MarkdownReport` (e.g. the planned HTML-via-Markdown email path) would TypeError on every call.

v0.7.1 adds `posture_annotation: str = ""` to both the Protocol and `MarkdownReport.write_summary`. The Markdown impl renders the annotation parenthetically next to the Risk row (`| Risk | HIGH (raised by posture: firewall inactive) |`) — same shape as the `.txt` report. Three new tests in `test_report.py::TestMarkdownReportWriteSummarySignatureParity` pin signature parity via `inspect.signature`, plus the rendering for empty and non-empty annotations.

#### I-3 — JSON v1 `risk` field silently changed semantics in v0.7.0

The v1 schema is documented (`DOCUMENTS/README_TECH.md` "JSON output schema") as "v0.6.x verbatim". v0.7.0 Phase 1 silently shifted v1's `risk` field from `engine.level.value` (score-derived) to `engine.effective_level.value` (posture-escalated). Concrete consequence:

  - A v0.6.x consumer doing `if data["risk"] == "low": green` would see `"high"` on a host with score 9 (LOW) but UFW inactive — even though the score field still says 9.
  - The v0.7.0 docstring at `bob/json_output.py:178-183` did acknowledge the shift, but the "v1 verbatim" contract is the louder invariant. v0.7.1 reverts: `data["risk"] = engine.level.value` again.

Consumers that need the posture-escalated value should migrate to v2's `posture_escalation.score_level` (the original score-derived level, plus an `applied: bool` field) and the v2 top-level `risk_level` (the escalated value, equivalent to what v0.7.0 was mistakenly putting in v1).

The pre-existing test `test_v1_risk_reflects_effective_level_not_score_only` was the v0.7.0 Phase 2.1 M-5 pin for the shift. v0.7.1 renames it to `test_v1_risk_pins_score_only_level_not_effective_level` and inverts the body to assert the revert, so a future re-shift fails the suite before tag push.

#### I-5 — Webhook accepted plain `http://` URLs

`bob/webhook.py:200` accepted both `http://` and `https://`. `SECURITY.md` "Network surface" documents webhook as HTTPS-only because the payload contains `hostname + public_ip + score + alerts` — exactly the data an attacker on the path would want for targeted bruteforce or vulnerability matching. A user copy-pasting a misconfigured endpoint URL silently produced plaintext leakage on every audit.

v0.7.1 rejects `http://` with a clear error message:

> `Webhook URL is plain http:// — audit payload would be sent unencrypted. Use https:// or set BOB_WEBHOOK_ALLOW_INSECURE=1 to override`

The new env var `BOB_WEBHOOK_ALLOW_INSECURE=1` is the escape hatch for offline labs / private networks where the operator has audited the path. Documented in the `WebhookError` message and pinned by `tests/test_webhook.py::TestSendWebhookInvalidUrl::test_rejects_plain_http_by_default` + `::test_plain_http_accepted_with_escape_hatch`.

#### M-1 — Stale `from typing import Any` import in `bob/plugin_checks.py`

Left over from T3 Step 3 when the `_module: Any` dataclass field was removed. One-line delete. No behavior change.

#### M-2 — `_atomic.py` did not fsync the data or the parent directory inode

The module docstring promised "power loss / SIGKILL / OOM between the start of `atomic_write` and its successful return leaves the destination file in its previous state." On ext4 default `data=ordered` journal mode and most other Linux filesystems, the implementation was insufficient to honour that:

  - `os.replace(tmp, dest)` only guarantees rename atomicity from the kernel's perspective. Durability of the rename across power loss requires fsyncing the parent directory's inode.
  - The new file's data only reaches stable storage after `fsync(fd)` on the tmp file's open file descriptor. Without that, the rename metadata can commit before the data, leaving a zero-byte file on power loss.

v0.7.1: `fh.flush() + os.fsync(fh.fileno())` before close, then `os.fsync(dir_fd)` on the parent directory inode after `os.replace`. The parent-dir fsync is best-effort (some filesystems / mount options reject it with `EINVAL` — `tmpfs`, certain network mounts) so the OSError is swallowed there. New test `test_atomic_write_calls_fsync_on_fd_and_parent_dir` spies on `os.fsync` to verify both calls fire.

#### M-5 — `--ignore=KEY` accepted any string, silently truncated multi-word values

`add_ignore_key("anything goes here")` produced `- key: anything` in `ignore.yml` (the YAML writer split on whitespace at the first character of the value). The loader's `_KEY_LINE_RE = r"^\s*-\s+key:\s+(\S+)\s*$"` then matched `"anything"`, which doesn't correspond to any audit finding key — so the user-intended ignore did nothing on the next audit. UX bug, not a security bug, but reported by enough confused users (per the audit) that v0.7.1 closes it.

v0.7.1:

  - New `bob.ignore.is_valid_ignore_key(key)` validates against the canonical EXPLAIN_KEYS pattern `r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"` — same shape enforced by `tests/test_explain_naming_convention.py` on the 117 keys / 30 prefixes declared in `bob/explain.py`.
  - `add_ignore_key()` calls `is_valid_ignore_key()` first; bad keys return `False` and skip the write entirely (the file is not created/touched).
  - The CLI handler in `bob/__main__.py` validates BEFORE the write and returns `EXIT_ERROR=3` with a hint: "Invalid key {key!r} — expected canonical `<prefix>.<finding_id>` snake_case. Run `bob --explain list` to see the available keys."

Five new pins in `tests/test_ignore.py::TestAddIgnoreKey`: bare word without dot, uppercase, whitespace, digit-prefixed, and a positive acceptance pin for the canonical shape.

### Deferred to v0.7.2

  - **I-4** — bool slips past `isinstance(int)` check on `bob/watch.py:140-141`. Already fixed inline in v0.7.1 as part of I-1 work (the explicit `isinstance(score, bool) or not isinstance(score, int)` guard); marking as resolved here for symmetry, not deferred.
  - **M-4** — `bob/html_output.py` + `bob/markdown_output.py` ship hardcoded English headings ("Summary", "Score Deductions", "Generated by BOB", `<html lang="en">`). Out-of-band with the `t()` policy enforced everywhere else. Deferred because the fix is a 30-line locale-extraction pass that's better paired with the next i18n campaign (when `de.json` / `es.json` translators come on board).
  - **M-6** — `bob/sysinfo.py:199` IPv4-only public-IP detection silently fails on v6-only hosts. Real edge case, low impact: the network-context detection has a v6 fallback so the audit chain still works. Easy two-line fix using `ipaddress.ip_address()` but defer to v0.7.2 because it changes a documented JSON field shape.
  - **M-7** — `bob/_atomic.py` tmp-file collision under concurrent writers. Real race (cron + watch + manual run can coincide), low probability, defer to v0.7.2 with a `tempfile.NamedTemporaryFile` rewrite.
  - **M-8** — `bob/json_output.py` `SCHEMA_*_KEYS` public frozensets with zero consumers. Per `feedback_release_monitoring` memory — anticipated API. Either drop or wire into a test invariant; defer to v0.7.2.
  - **M-9** — `--json-full --json-v1` valid combination not mentioned in `bob --help`. Cosmetic.
  - **M-10** — `bob/display.py` duplicated posture detection paths. Pure refactor — per `feedback_conservative_refactor` ("gain × risque = STOP"), defer indefinitely unless paired with another change in the same file.
  - **M-11** — `Iterator` import cosmetic. Skip entirely.

### Tests

5466 → **5479** (+13 net). Breakdown:

  - 5 new pins in `tests/test_ignore.py` for the canonical-key validation (M-5)
  - 1 new pin in `tests/test_atomic_v061.py` for the fsync calls (M-2)
  - 2 new pins in `tests/test_webhook.py` for the http:// rejection + escape hatch (I-5)
  - 3 new pins in `tests/test_report.py::TestMarkdownReportWriteSummarySignatureParity` for the Protocol parity (I-2)
  - 2 new pins in `tests/test_watch.py::TestWatchContractParity` for the ignore + posture propagation (I-1)

Plus 3 updated tests (not net additions):

  - `tests/test_watch.py::test_bool_is_accepted` → `test_bool_raises_type_error` (inverted assertion for I-4)
  - `tests/test_json_schema.py::test_v1_risk_reflects_effective_level_not_score_only` → `test_v1_risk_pins_score_only_level_not_effective_level` (inverted assertion for I-3)
  - 3 `tests/test_ignore.py` tests using non-canonical "k" / "k1" key fixtures updated to use canonical pattern

All 5479 pass on Python 3.12.3 locally. CI multi-Python (3.10/3.11/3.12/3.13/3.14) + multi-distro (Debian 12+13, Ubuntu 22.04+24.04+25.04, Kali, Fedora 41) will validate post-tag-push.

### Upgrade

```bash
pipx upgrade bodyguard-of-bits
sudo bob --version   # should print 0.7.1
```

No CLI contract change. The one user-facing behavioural shift is the I-3 revert: anyone consuming v1 JSON `risk` will see it reverse to score-derived (typically going from "high" back to "low" on a firewall-down + low-score host). That is the intent — v1 is meant to behave like v0.6.x.

Anyone using webhooks with `http://` URLs must either switch to `https://` or set `BOB_WEBHOOK_ALLOW_INSECURE=1` in the bob runtime environment.

---

## [v0.7.0] — 2026-06-01

**Major bump — opens the v0.7.x stable branch.** Rolls up the four-beta cycle (b1 → b2 → b3 → b4) into the canonical v0.7.0 release. The cumulative payload is three thematic phases (T1 Foundation + T2 JSON schema v2 + T3 Plugin Sandbox) plus four release-engineering guards added in flight, all on top of the v0.6.2 baseline. v0.6.x is now EOL — security fixes will not be backported.

### What changed since v0.6.2

#### Phase 1 — Foundation (T1)

  - **Python 3.14 added to the CI matrix** (ladder step 1). `requires-python>=3.10` retained — Python 3.10 upstream EOL is 2026-10, still supported. The integration-distro matrix carries 3.12 / 3.13 by default depending on the distro; the pytest matrix exercises 3.10 / 3.11 / 3.12 / 3.13 / 3.14 explicitly.
  - **Posture escalation** — new public API `ScoreEngine.set_posture(level: RiskLevel, key: str)` lets a check raise the floor of the final risk level without touching the numeric score. `engine.effective_level` returns `max(score_level, posture_floor)`. `engine.posture_escalation` is a `(applied: bool, reason_key: str, score_level: str)` tuple suitable for JSON output and history-diff tracking. Triggered by `firewall_inactive` (UFW disabled), `iptables_input_accept` (INPUT chain default ACCEPT), or `firewall_domain_score ≤ 3` (firewall domain critically misconfigured).
  - **Box-score annotation** — the terminal summary box now reads `Niveau de risque : ✖ ÉLEVÉ  (majoré par posture : pare-feu inactif)` when the posture floor is active. Visible on every audit surface (terminal, txt report, HTML report, JSON v2 output, history.jsonl level_score_only field).
  - **New EXPLAIN key** `risk.escalated_posture` documents what posture escalation is and when it triggers.
  - **M-1** — `parse_cron_file` time_simple flag + log normalization for cron entries.
  - **M-7** — `--check` / `--skip` recognise the 10 always-on section names (firewall_state, dns, etc.) so users can compose targeted audits.

#### Phase 2 — JSON Schema v2 (T2)

  - **`build_json_data(schema_version="2")` is the new default.** `--json-v1` flag preserves the legacy v0.6.x layout exactly for migration. The v2 schema is documented in `DOCUMENTS/README_TECH.md` "JSON output schema" with a v1→v2 migration table.
  - **v2 changes**: fixes `network_context` type inconsistency (P1 — was sometimes str, sometimes object); renames `timestamp` → `timestamp_utc` (explicit UTC suffix); adds `info_count` (per-domain INFO finding count, useful for trend analysis); adds `posture_escalation` block `{applied, reason_key, score_level}`; in full-mode adds `deductions_raw` (untruncated reasons) + `open_ports_all` (full port list, not the top-N); adds `domain_scores[d].deductions` (per-domain deduction list).
  - **EXPLAIN_KEYS audit baseline** — 117 keys / 30 prefixes / 100% conformance with the canonical `<prefix>.<finding_id>` snake_case pattern. Pinned by `tests/test_explain_naming_convention.py` (710 parametrized assertions). Any future key that doesn't match the pattern fails the suite before merge.
  - New file `tests/test_json_schema_v2.py` — 30 tests written BEFORE the implementation per the integration-first rule, drove the impl to match the spec.

#### Phase 2.1 — sub-agent pre-T3 audit

A sub-agent adversarial review on the Phase 1 + Phase 2 + Phase 2.1 commits surfaced 5 important + 6 minor findings. 5/5 important + 4/6 minor shipped pre-T3:

  - **I-1 + I-4** — `effective_level` propagation to HTML / Markdown / `history.jsonl` was incomplete after Phase 1. Added the 3 missed sinks + new `level_score_only` field in `history.jsonl` so history-diff tools can distinguish the raw score level from the posture-escalated effective level.
  - **I-2** — extracted `bob.scoring.unpack_posture_escalation(engine) → tuple` helper. Consolidates the defensive `getattr` + `try/except` pattern that was duplicated across display / json_output sites and was missing in one of them.
  - **I-3** — `ScoreEngine.set_posture()` now rejects bool explicitly with a TypeError naming the mistake. Previously `set_posture(True)` was silently accepted via `isinstance(x, int)` returning True for bool — a foot-gun.
  - **I-5** — vacuous `assert ... or True` in `test_v2_posture_escalation_consistent_with_top_level_risk` rewritten to assert the explicit divergence shape.
  - **M-1** — `--check=list` output now lists the 10 always-on section names so the help text matches what M-7 accepts as input.
  - **M-3** — `report.write_summary` (.txt on-disk report) surfaces the posture annotation matching the terminal box.

Two minors deferred (M-2 cosmetic + M-6 doc) — no impact on v0.7.0 contract.

#### Phase 3 — Plugin Sandbox Runner (T3)

The flagship deliverable. Pre-v0.7.0, `~/.config/bob/checks.d/*.py` plugins ran in the parent BOB process with full root privileges. v0.7.0 introduces a restricted-mode sandbox runner; users with plugins get accidents-and-naïve-attacks protection automatically, users without plugins are unaffected.

**Implementation** (`bob/_sandbox.py`, 484 LoC):

  - **Process isolation** — each plugin runs in a fresh `multiprocessing.get_context("spawn")` child. Crash / OOM / FS mutation / env pollution stays contained.
  - **Timeout + resource limits** — 5s wall-clock `Process.join(timeout=5)` → `terminate()` → `kill()` if needed; `RLIMIT_AS = 256 MiB` cap defends against memory bombs; `RLIMIT_CPU = 10s` cap defends against infinite loops that ignore SIGTERM.
  - **Import allowlist** — `PLUGIN_IMPORT_ALLOWLIST` enforced by a `builtins.__import__` replacement hook installed in the plugin's restricted namespace. Allowed: `bob.scoring`, `re`, `json`, `pathlib`, `datetime`, `typing`, `dataclasses`, `collections`, `enum`, `math`, `string`, `hashlib`, `time`, `os.path`, `stat`.
  - **Restricted `__builtins__`** — `_ImmutableBuiltins` dict subclass overriding `__setitem__` / `update` / `clear` / `pop` / `popitem` / `setdefault` to raise TypeError. Strips `eval` / `exec` / `compile` / `__import__` / `input` / `breakpoint`. `open` replaced by `_make_safe_open` which rejects write modes AND denies reads on a curated deny-list (`/etc/shadow`, `/etc/gshadow`, `/etc/sudoers.d/`, `~/.ssh/id_*`, `/.gnupg/`, `/dev/mem`, `/dev/kmem`, `/dev/port`, `/proc/kcore`, `/proc/kmem`). `pathlib.Path` write methods (`write_text`, `write_bytes`, `touch`, `mkdir`, `rmdir`, `unlink`, `chmod`, …) monkey-patched in the worker to raise PermissionError.
  - **`os` module strip** — extensive `_OS_DANGEROUS_ATTRS` list (84 entries organised into six categories: subprocess/spawn, process control + signals, privilege changes, raw fd I/O, filesystem writes, xattr writes, process/env state, Windows-specific). The list grew significantly between b2 and b3 after a PoC plugin demonstrated `from pathlib import os; os.open + os.write` writing to arbitrary paths despite the b2-level strip — the v0.7.0 ship list closes that path.
  - **JSON-safe queue transport** — the worker serializes the plugin's CheckResult to a primitive-only dict via `_sanitize_for_transport` BEFORE pushing onto the queue. The parent rebuilds a fresh CheckResult from the dict via `_deserialize_check_result` — never unpickles plugin-controlled objects. This closes the pickle-RCE path where a malicious `__reduce__` attached to `template_vars` could execute `eval` in the parent.
  - **`BOB_SANDBOX_LEGACY=1` trap door** — bypasses the sandbox entirely; runs plugins in the parent with full builtins. Surfaces a CRITICAL log entry AND a direct stderr write on every run that actually enters legacy mode (re-evaluated per call so toggling the env var mid-session takes effect). Deprecated immediately; will be removed in v0.8.0.

**Parent process never exec's plugin code** — `bob/plugin_checks._load_one()` is now AST read-only (size check + `compile()` for syntax + AST FunctionDef walk for `run_check` presence + AST extraction of `CHECK_NAME`). The pre-v0.7.0 `importlib.exec_module` path is removed. A plugin with `import subprocess; subprocess.run(...)` at module level no longer compromises the audit during plugin discovery — the malicious import is deferred to the sandboxed child where it gets caught by the import allowlist.

**Threat model recadré honest** in `SECURITY.md` "Plugin checks" section. The header line:

> **In-process Python sandboxing is not a security boundary.** This is a defence-in-depth layer.

What the sandbox stops: accidents (buggy plugin calls `os.unlink` by mistake, infinite loop, 2 GiB allocation), naïve attacks (`import subprocess; subprocess.run(...)` at module level), confused-deputy reads (accidental `open("/etc/shadow")` because the user forgot BOB runs as root).

What the sandbox does NOT stop: a determined attacker with the Python escape playbook (`json.dumps.__globals__["__builtins__"]["__import__"]` reachable in 5 lines because allowlisted stdlib modules carry their own unrestricted builtins reference — PEP 416 retracted in 2012 over exactly this), `dict.__setitem__(bins, "eval", real_eval)` unbound bypass of the restricted-builtins subclass (the irreducible limit — every fully-immutable alternative breaks CPython's C-level dict fast paths that `exec()` requires).

Both architectural escapes are pinned as INTENTIONALLY out of scope by `TestKnownInProcessLimitation::test_real_builtins_reachable_via_stdlib_globals` and `::test_i1_known_limitation_unbound_dict_setitem_bypass` — future contributors see these as expected, not regression candidates.

**Real adversarial isolation requires an OS-level boundary**. BOB ships an AppArmor profile (`packaging/apparmor/bob.profile`) that confines the BOB process itself; this is the actual boundary against malicious plugins. Users running BOB unconfined under `sudo` should code-review their plugins before installing them.

#### Four release-engineering guards

The v0.7.0 cycle hit four distinct release-engineering bug classes. Each got a complementary guard:

  1. **integration-first** — Phase 1 4ed2e3b crash discovered at smoke time after Phase 1 was code-complete: `engine.domain_scores["firewall"]` is a dict, not an int, and the dict was passed by mistake to `set_posture()` and crashed the audit just before the summary box. Closed by writing the integration test BEFORE the impl on Phase 2 and Phase 3, and adding an explicit type guard `set_posture` that raises TypeError naming the dict-vs-int mistake.
  2. **smoke-after-commit** — v0.6.2 packaging discovery: every wheel since v0.6.0 was missing `bob/checks/ssh/` and `bob/cron/` because the `[tool.setuptools.packages.find].include` list was a stale literal. Closed by the v0.6.2 fix (`include=["bob*"]` glob) + new `integration.yml` step `pip install . && python -c "import bob.checks.ssh; from bob.cron import …"`. Held through v0.7.0.
  3. **version-consistency** — v0.7.0b1 shipped with `bob/__init__.py::__version__` not synced with `pyproject.toml`, banner reported `BOB v0.6.2` while wheel was `0.7.0b1`. Closed in b2 by `tests/test_version_consistency.py::test_init_version_matches_pyproject_version` reading both values and asserting equality on every CI run + every local pre-ship pytest.
  4. **smoke-plugin-on-CI** — v0.7.0b3 shipped with `types.MappingProxyType` as the plugin sandbox's restricted `__builtins__`, which CPython rejects with `SystemError` on every Python in the matrix except 3.12.3. The 5/5 VM smoke validation missed it because no VM had any plugin in `~/.config/bob/checks.d/`. Closed in b4 + the post-b4 commits 5e0739e + cb4108b: tests.yml drops a benign plugin in a tmp dir and invokes `SandboxRunner` directly on every Python in the matrix; integration.yml drops a plugin into `~/.config/bob/checks.d/` and runs the real `bob --offline` binary on every distro in the matrix; integration.yml trigger extended to fire on `v*.x` branches so the guard runs during beta cycles, not just after merging to main.

Per v0.7.0 these guards are permanent. They will keep firing on every commit / push / tag through v0.7.x and v0.8.x.

### Tests

**5391 → 5466 tests** across the v0.7.0 cycle (+75 net). 0 regression. Breakdown:

  - +30 in `tests/test_json_schema_v2.py` (Phase 2 integration-first)
  - +710 parametrized in `tests/test_explain_naming_convention.py` (Phase 2 audit pin)
  - +12 in `tests/test_v2_posture_escalation_*` (Phase 1 + 2.1)
  - +5 in `tests/test_set_posture_typeerror_on_dict` (Phase 1 4ed2e3b regression pin)
  - +2 in `tests/test_version_consistency.py` (b2 guard)
  - +46 in `tests/test_plugin_sandbox.py` (T3 Steps 1-2-3 + hardening pins + known-limitation pins)
  - +32 in `tests/test_plugin_checks.py` (T3 Step 3 AST-only loader contract)
  - Reductions from removed dead tests + parametric merges balance the +75 net.

CI matrix validated on 5e0739e + cb4108b + the v0.7.0 final ship:
  - **tests.yml** — Python 3.10 / 3.11 / 3.12 / 3.13 / 3.14, all green.
  - **integration.yml** — Debian 12 / Debian 13 / Ubuntu 22.04 / Ubuntu 24.04 / Ubuntu 25.04 / Kali rolling / Fedora 41, all green.
  - **publish.yml** — fires on the v0.7.0 tag, re-runs the pytest matrix, builds sdist + wheel, uploads to PyPI as the stable release (`make_latest: true` because tag doesn't match the PEP 440 pre-release regex).

### v0.6.x EOL

v0.6.2 (the last v0.6.x release) is now EOL. Security fixes will not be backported. Users on v0.6.x should `pipx upgrade bodyguard-of-bits` to v0.7.0 — there is no breaking CLI contract (all v0.6.x flags continue to work), no breaking JSON contract (`--json-v1` opts into the legacy schema), and the new sandbox is automatic and transparent for users without plugins.

### Deferred to v0.8.0

Items explicitly deferred from v0.7.0 to v0.8.0 (see `project_v08x_deferred` memory):

  - **D-1** — sections renumbering (cosmetic, breaks `--check=N` numeric form which no docs use).
  - **D-2** — fuse `_ALL_SECTIONS` + `_ALWAYS_ON_SECTIONS` into a single registry.
  - **D-3** — retire EXPLAIN_KEYS aliases obsoleted by the v0.5.5 canonical-pattern enforcement.
  - **D-4** — sub-checks granularity (split monolithic check functions where they emit ≥3 distinct domains).
  - **`BOB_SANDBOX_LEGACY=1` trap door removal** (announced "removed in v0.8.0" in the v0.7.0 docs).

### Upgrade

```bash
pipx upgrade bodyguard-of-bits
sudo bob --version   # should print 0.7.0
sudo bob -v -d       # standard audit; posture escalation auto-applies if firewall is OFF
```

### Memory archived

  - `project_v07x_phase1` — Phase 1 6-commits + 7-rule strategy for the next phases.
  - `project_v07x_phase2` — Phase 2 + 2.1 + beta1+beta2 cycle + 3 ship guards.
  - `project_v070_t3_sandbox_threat_model` — full T3 audit (3C + 5I + 7M sub-agent findings, 3 PoCs locally confirmed, Option B strategic decision, b3 → b4 regression learning, irreducible I-1 unbound bypass at the in-process Python limit).
  - `project_v08x_deferred` — D-1 to D-4 contract for the next major.

---

## [v0.7.0b4] — 2026-06-01

**CI compatibility hotfix for v0.7.0b3.** No threat-model, API, or audit-behaviour change vs b3. One specific element of the b3 hardening pass — the I-1 fix that replaced the `_ImmutableBuiltins` dict subclass with `types.MappingProxyType` — turned out to be incompatible with CPython's C-level dict fast paths that `exec()` requires for `__builtins__`. Every Python version in BOB's CI matrix EXCEPT 3.12.3 (3.10, 3.11, 3.13, 3.14) raised `SystemError: Objects/dictobject.c:1490: bad argument to internal function` inside the spawn'd worker on every plugin run, surfacing in the parent as a WARN finding `"Plugin 'X.py' error: SystemError: ..."`. 16 tests started failing in CI immediately after the b3 tag push.

### Why the b3 VM validation missed this

The b3 ship was gated on 5/5 cible smokes — so6desktop (Linux Mint 22.3, Py 3.12.3), Debian 13 VM (Py 3.13.5), Kali Rolling VM (Py 3.13.12), Ubuntu 26.04 LTS VM (Py 3.14.4), Mint+DDNS VM (Py 3.12.3). Three of those should have caught the regression… except none of them had any plugins installed at `~/.config/bob/checks.d/*.py`, so the audit chain never instantiated the `SandboxRunner` and never tried to exec a plugin under MappingProxyType-as-builtins. The smoke ran the WHOLE audit but completely bypassed the changed code path.

This is the 4th release-engineering bug class on the v0.7.x branch and slots into the same pattern as v0.7.0b1 → v0.7.0b2: a change correct on the maintainer's primary machine, validated end-to-end on multiple cibles, but the validation exercise itself didn't actually touch the modified code. Each prior gap got a matching guard (integration-first / smoke-after-commit / version-consistency); this one will land a `smoke-plugin-on-every-python-matrix-version` step in the publish.yml pre-tag gate.

### Fix

`bob/_sandbox.py::_build_restricted_builtins` reverts to returning an `_ImmutableBuiltins` instance — the dict subclass shipped in v0.7.0b2 with overridden `__setitem__` / `update` / `clear` / `pop` / `popitem` / `setdefault` / `__delitem__`. This blocks the natural Python mutation path `bins["eval"] = real_eval` (which goes through `__setitem__`'s virtual dispatch and hits the override). It does NOT block the unbound bypass `dict.__setitem__(bins, "eval", real_eval)` — that calls the base C method directly. So the b3 attempt to close the I-1 unbound bypass is reverted, and I-1 unbound moves from "closed" back to "known limitation".

### Why MappingProxyType cannot be used here

CPython's bytecode interpreter does `LOAD_GLOBAL` / `LOAD_NAME` / `IMPORT_NAME` etc. by reading `__builtins__` via dict-specific C functions (`_PyDict_GetItemRef`, `PyDict_GetItemString`, etc.) when those functions detect a real dict. A `MappingProxyType` wrapper around a dict is not itself a dict — it's a separate C type that implements `tp_as_mapping` but not the `PyDict_*` fast paths. On Python 3.12.3 specifically the fast-path detection happens to fall back to the generic `PyMapping_GetItemString` for proxies; on 3.10/3.11/3.13/3.14 the fast path checks `PyDict_CheckExact()` or `PyDict_Check()` and raises `SystemError` when the check fails on a proxy.

The same `SystemError` would fire for `frozendict`, custom immutable mapping classes via `collections.abc.Mapping`, or any C extension type that doesn't subclass `dict`. The only way to get a "dict that exec accepts" is to subclass `dict` — at which point `dict.__setitem__(instance, k, v)` unbound is by definition reachable. Python's design here cannot satisfy both "no mutation possible" and "usable as exec builtins". The honest position is to accept the unbound bypass as a known limitation, which is what v0.7.0b4 ships.

### Tests

`tests/test_plugin_sandbox.py::TestHardeningPins::test_i1_immutablebuiltins_no_dict_setitem_bypass` (b3) is renamed to `test_i1_virtual_dispatch_mutation_blocked` and tightened to pin the realistic-attacker path that adversarial plugin 12 actually uses (`bins["eval"] = ...` via subscript syntax → goes through `__setitem__` virtual dispatch). A new test `tests/test_plugin_sandbox.py::TestKnownInProcessLimitation::test_i1_known_limitation_unbound_dict_setitem_bypass` pins the unbound bypass as INTENTIONALLY out of scope — same shape as the architectural escape test. 5466 tests total (5465 b3 + 1 new known-limitation pin), 0 regression in the audit chain on the maintainer's primary 3.12.3.

### Other b3 hardening preserved unchanged

  - C-1 extended `_OS_DANGEROUS_ATTRS` (21 → 84 entries) — unchanged.
  - C-2 JSON round-trip queue transport (`_serialize_check_result` / `_deserialize_check_result`) — unchanged.
  - I-2 `q.close()` + `q.join_thread()` in `try/finally` — unchanged.
  - I-3 shared AST `has_run_check` helper — unchanged.
  - I-5 read-path deny-list on `_make_safe_open` — unchanged.
  - M-4 `RLIMIT_CPU = 10s` added — unchanged.
  - M-6 / M-7 `BOB_SANDBOX_LEGACY=1` warning via `logger.critical` + direct stderr write, re-emitted per run — unchanged.

### Docs

  - `SECURITY.md` "Plugin checks" updated: the I-1 mitigation now says "blocks the natural-Python `bins["eval"] = ...` path" + adds `dict.__setitem__` unbound to the "What it does NOT stop" enumeration.
  - `bob/_sandbox.py` module docstring Q3' section updated with the same recadrage + the rationale for why `MappingProxyType` cannot work as exec builtins.

### What testers should do

If you installed v0.7.0b3 from PyPI, upgrade to v0.7.0b4:

```bash
pipx upgrade --pip-args="--pre" bodyguard-of-bits-beta
sudo bob-beta --version   # should print 0.7.0b4
```

If you ran v0.7.0b3 WITHOUT any plugins in `~/.config/bob/checks.d/`, you saw NO symptom and your audit results from b3 are valid. The bug only surfaced when an actual plugin was loaded.

If you ran v0.7.0b3 WITH plugins on a non-3.12 Python, every plugin run produced a WARN finding with the SystemError message instead of running normally. After upgrading to b4, run again to get the real plugin outputs.

### Next

Same as b3: monitor 24h of real-world smoke output across the 4 VMs + so6desktop. If no further surprises, the v0.7.0 final cut squashes b1+b2+b3+b4 + the four T3 commits into one and ships without further beta cycle. The pre-tag publish.yml gate gains a "smoke benign plugin on every matrix Python" step.

---

## [v0.7.0b3] — 2026-05-31

**Sandbox hardening pass + threat-model recadrage** — follows the T3 Phase 3 sub-agent adversarial audit run against the v0.7.0b2 baseline (the Phase 3 plugin sandbox introduced in commits 0ac6ec9 + 960ca84 + de94813). Three Critical + five Important + seven Minor findings surfaced; three of those were locally confirmed via PoC plugins **before** any fix was attempted, so the codebase ships with concrete evidence that the hardening closes the practical attack chains and an honest documentation of what it does NOT close.

### What the PoCs proved against v0.7.0b2

  - **C-1 — `os` module smuggled past the import allowlist via `pathlib`.**
    `from pathlib import os` returned a live, fully-functional `os` module reference. The `_OS_DANGEROUS_ATTRS` strip list shipped in b2 covered `system` / `popen` / `exec*` / `spawn*` / `fork` but missed **`posix_spawn`, `posix_spawnp`, `open`, `read`, `write`, `close`, `dup`, `pipe`, `chmod`, `chown`, `unlink`, `rename`, `mkdir`, `rmdir`, `truncate`, `chdir`, `chroot`, `umask`, `environ`, `setresuid`/`setresgid`, `nice`, `setpriority`**, etc. PoC plugin opened `/tmp/bob_c1_escape` via `os.open + os.write + os.close` — the file was created with the audit's privileges (root under `sudo`). The Q4' contract ("pathlib write methods blocked") was technically honoured but irrelevant because the attack bypassed pathlib entirely via raw fd I/O.

  - **C-2 — Parent-process RCE through `mp.Queue` pickle round-trip.**
    The b2 worker pushed the plugin's CheckResult directly onto a `multiprocessing.Queue`; the parent's `q.get()` un-pickled it. A plugin can construct a `type("Evil", (object,), {"__reduce__": evil_reduce})` (the `type` metaclass call bypasses the `__build_class__` strip), reach a real `eval` reference via `json.dumps.__globals__["__builtins__"]` (any allowlisted stdlib module leaks the real builtins this way), and attach an Evil instance to `findings[0].template_vars`. When the parent un-pickles the result, the Evil reduce executes `eval("__import__('os').system('touch /tmp/bob_c2_parent_pwned')")` **in the parent process**. The PoC created the sentinel file from a `sudo bob` run.

  - **Architectural escape — real `__import__` reachable in 5 lines.**
    `real_import = json.dumps.__globals__["__builtins__"]["__import__"]` returns the unrestricted `builtins.__import__` because Python's stdlib modules carry their own un-restricted builtins reference via their module `__globals__`. The hook installed in the plugin's `__builtins__` is bypassed because external modules don't look up imports through the plugin's namespace. The plugin then calls `real_import("subprocess")` and runs whatever it wants. This is the same fundamental limitation that retired PEP 416 (sandbox proposal) back in 2012. **No Python-only mitigation can close it without breaking the stdlib allowlist itself.**

### Strategic decision — Option B, defence-in-depth honest

After confirming the three PoCs, the solo maintainer reviewed three trajectories:

  - **A.** Patch the concrete chains + claim the sandbox is now adversarial-grade. *Rejected* — every patch only shifts the bar; the architectural escape stands.
  - **B.** Defence-in-depth honest — fix the concrete chains so accidents and naïve attacks are caught, document the architectural limitation, and point users at OS-level isolation (AppArmor profile shipped with BOB) as the real boundary. *Chosen* — matches the Python community consensus since 2012.
  - **C.** Revert the T3 commits entirely; defer T3 to v0.8.0 with a subprocess+seccomp design. *Rejected* — would lose the 3 commits of foundation work and the accident-protection has independent value.

### Hardening shipped in `bob/_sandbox.py`

  - **`_OS_DANGEROUS_ATTRS` extended 21 → 84 entries** organised into six categories: subprocess/spawn (16 entries inc. `posix_spawn`, `posix_spawnp`, all `exec*`/`spawn*`/`fork*` variants), process control + signals (10 entries inc. `_exit`, `abort`, `wait*` family, `nice`, `setpriority`), privilege changes (10 entries inc. `setresuid`, `setresgid`, `initgroups`), raw fd I/O (13 entries inc. `open`, `read`, `write`, `close`, `lseek`, `pread`/`pwrite`, `dup*`, `pipe*`, `fdopen`, `truncate`), filesystem writes (16 entries inc. `unlink`, `rename`, `chmod`, `chown`, `symlink`, `link`, `mkfifo`, `mknod`, `utime`), xattr writes (6 entries), process state mutations (8 entries inc. `chdir`, `chroot`, `umask`, `environ`/`environb`, `putenv`/`unsetenv`), plus Windows-specific (1 entry). Closes C-1 directly. As a side-effect, it also breaks the practical subprocess attack chain pinned by C-2 / architectural escape because `subprocess.Popen` needs `os.pipe` internally and `os.pipe` is now stripped.

  - **`_serialize_check_result` / `_deserialize_check_result` JSON-safe round-trip.** The worker now flattens the CheckResult to a primitive-only dict via `_sanitize_for_transport` **before** putting anything on the queue (str / int / float / bool / None / list / dict — anything else is `str()`'d inside the worker). The parent's `q.get()` returns a plain dict and `_deserialize_check_result` rebuilds a fresh CheckResult from it. No plugin-controlled `__reduce__` ever reaches the parent's unpickle. Closes C-2.

  - **`types.MappingProxyType` replaces the `_ImmutableBuiltins` dict subclass.** The previous design relied on overriding `__setitem__`/`__delitem__`/etc. on a dict subclass, but `dict.__setitem__(unbound_instance, k, v)` calls the C-level base method directly, bypassing the virtual dispatch. `MappingProxyType` is a C-level read-only proxy with no `__setitem__` at all — every mutation path (`setitem`, `setdefault`, `update`, `pop`…) raises TypeError unconditionally. Closes I-1.

  - **`q.close()` + `q.join_thread()` in `try/finally`.** The previous code created an `mp.Queue` per run and never closed it. Across many plugin runs in a single session, this leaked fds and the queue's background feeder thread. Now wrapped in `finally`. Closes I-2.

  - **Read-path deny-list on `_make_safe_open`.** Reads on `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers.d/`, `~/.ssh/id_*`, `/.gnupg/`, `/dev/mem`, `/dev/kmem`, `/dev/port`, `/proc/kcore`, `/proc/kmem` now raise `PermissionError`. The deny-list is curated rather than a full read allowlist so legitimate hardening checks reading `/etc/ssh/sshd_config`, `/etc/login.defs`, `/proc/version`, etc. still work. Closes I-5 (the "BOB runs as root under sudo" confused-deputy concern).

  - **`_apply_resource_limits` now sets `RLIMIT_CPU = 10 s`** in addition to `RLIMIT_AS = 256 MiB`. Defends against CPU-bound infinite loops that ignore SIGTERM (the previous design relied on `Process.terminate()` which can be ignored). Also fixes a stale docstring lie in b2 that claimed CPU was capped when only memory was. Closes M-4.

  - **`BOB_SANDBOX_LEGACY=1` warning hardened.** Re-emitted on every `.run()` that actually enters legacy mode (not just at runner `__init__`), via both `logger.critical(...)` (routed through the project's normal log handlers) AND a direct `sys.stderr.write()` (so an accidentally-misconfigured log handler cannot silence the security-relevant event). The legacy flag is re-evaluated per call so toggling the env var mid-session takes effect. Closes M-6 and M-7.

  - **New `has_run_check(source)` AST helper** shared between `bob.plugin_checks._load_one` and `SandboxRunner.run`. Accepts both `def run_check` and `run_check = ...` assignment forms, rejects substring false-positives on commented `# run_check`. The previous code had two inconsistent gates (substring in the runner, AST FunctionDef-only in the loader). Closes I-3.

### New tests

  - **`tests/test_plugin_sandbox.py::TestHardeningPins`** — 5 tests pinning the concrete C-1 / C-2 / I-1 / I-2 / I-5 closure with sentinel-file checks. The C-1 test writes a plugin that attempts the `os.open + os.write` smuggle and asserts no file was created. The C-2 test writes a plugin that attempts the `Evil.__reduce__` attachment and asserts no parent sentinel was created.
  - **`tests/test_plugin_sandbox.py::TestKnownInProcessLimitation`** — 2 tests that **document the architectural escape as INTENTIONALLY out-of-scope**. The first test confirms the unrestricted builtins remain reachable via `json.dumps.__globals__["__builtins__"]` — if this test ever starts failing, either the escape has been closed (great, update the docs!) or the test plugin broke. The second test confirms the practical `subprocess.run` chain is broken by the strip list. This is the contract that future contributors will read instead of re-deriving the PEP 416 consensus from scratch.
  - Full suite: **5458 → 5465 tests** (+7 net), 0 regression.

### Docs

  - **`SECURITY.md::Plugin checks` rewritten** with a "Threat model" subsection that states explicitly: *"In-process Python sandboxing is not a security boundary. It is a defence-in-depth layer."* + per-mitigation enumeration + reference to the AppArmor profile as the actual boundary. The previous text was "plugins are not sandboxed" (true in b2 → no longer true) and "a future major version may introduce a restricted-mode runner" (now done, with the limitations spelled out).
  - **`bob/_sandbox.py` module docstring rewritten** with the same threat model + per-mitigation rationale + reference to the `TestKnownInProcessLimitation` tests.

### Smoke validation

  - **Three PoCs re-tested post-hardening** — `/tmp/bob_c1_escape`, `/tmp/bob_c2_parent_pwned`, `/tmp/bob_arch_escape` all NOT created after the fixes; the runner correctly surfaces each as a WARN finding with the underlying error class (ImportError / AttributeError) and no plugin output reaches the parent.
  - **5/5 cibles cross-validated** via `pipx install --pip-args="--pre"` of the b3 wheel: so6desktop (Linux Mint 22.3, Python 3.12, score 8/10 LOW clean), Debian 13 VM (Python 3.13, score 9/10 LOW clean), Kali Rolling VM (Python 3.13, score 8/10 LOW clean + compound finding), Ubuntu 26.04 LTS VM (**Python 3.14.4** — the T1 ladder step 1 target, score 8/10 → **HIGH risk raised by posture: firewall inactive**, the critical posture escalation scenario validated end-to-end), Mint + DDNS VM (Python 3.12, score 7/10 MEDIUM with `network_context = Exposition publique via DDNS` shift). Every cible reports "Score inchangé" in its "CHANGEMENTS DEPUIS LE DERNIER AUDIT" section against the b2 baseline from earlier the same day — zero regression on the audit chain.

### Memory

`project_v070_t3_sandbox_threat_model` archives the architectural learning + the three PoC outlines so future audits don't have to re-derive the PEP 416 consensus.

### Who must upgrade

Anyone running v0.7.0b1 or v0.7.0b2 with `~/.config/bob/checks.d/` plugins from **untrusted** sources should upgrade to v0.7.0b3 immediately AND enforce the BOB AppArmor profile (`packaging/apparmor/bob.profile`). Users with no plugins or with code-reviewed plugins remain unaffected by the security findings but get the cleaner internal codepaths.

```bash
pipx upgrade --pip-args="--pre" bodyguard-of-bits-beta
sudo bob-beta --version   # should print 0.7.0b3
```

Next: monitor real-world smoke output on the four VMs across the next 24h. If no surprises surface, the v0.7.0 final cut squashes the four T3 commits into one and ships without further beta cycle.

---

## [v0.7.0b2] — 2026-05-31

**Release-engineering hotfix for v0.7.0b1.** No code, JSON contract, EXPLAIN_KEYS, CLI, or audit behaviour change vs v0.7.0b1 — but the wheel published under that version reported `BOB v0.6.2` in every output (terminal banner, `--version`, JSON `"version"` field, webhook payload, report header).

### What went wrong

BOB declares its version in TWO places:

  - `pyproject.toml` → drives the wheel metadata (what PyPI reads, what `pipx` reports as the installed version).
  - `bob/__init__.py::__version__` → drives the running code (what every output prints via `from bob import __version__`).

When the v0.7.0b1 ship commit `a4b7b9b` bumped `pyproject.toml` from `0.6.2` → `0.7.0b1`, only that file was updated — `bob/__init__.py` stayed at `0.6.2`. The wheel built and uploaded to PyPI correctly identifies as `bodyguard-of-bits-0.7.0b1`, but anyone running `pipx install --pre` and invoking the binary sees `BOB v0.6.2` in every surface that reads `__version__`.

Caught on the so6 Debian 13 VM during the v0.7.0b1 beta validation (2026-05-31) — the banner said `BOB v0.6.2` after a clean `pipx install bodyguard-of-bits-beta` of the `0.7.0b1` wheel.

### Fix

  - `bob/__init__.py::__version__` bumped to `"0.7.0b2"`.
  - `pyproject.toml` bumped to `"0.7.0b2"`.
  - **New invariant test** `tests/test_version_consistency.py`
    (`test_init_version_matches_pyproject_version`) reads both values and
    asserts equality on every CI run + every local pre-ship pytest. A
    future drift between the two files now fails the suite and surfaces
    the bug before any tag is pushed.

### Why this is the 3rd release-engineering bug on the v0.7.x branch

  1. **v0.6.2** — wheels missing `bob/checks/ssh/` and `bob/cron/` because
     `[tool.setuptools.packages.find].include` was a literal list that
     wasn't updated when v0.6.0 introduced the splits.
  2. **Phase 1 4ed2e3b** — `engine.domain_scores["firewall"]` is a dict
     not an int; the dict was passed by mistake to `set_posture()` and
     crashed the audit just before the summary box.
  3. **v0.7.0b1** — `__version__` not synced with pyproject.toml.

Each one is a different class of failure (packaging discovery / runtime
contract assumption / version metadata drift), and each one slipped past
the unit + integration test suites because the gap was at the boundary
between Python code and the release-engineering toolchain. The strategy
of project_v07x_phase1 rule 1 (integration-first) catches the runtime
contract assumption class; the rule 3 (smoke local after each commit
significant) catches the packaging discovery class; this beta release
adds the version-consistency invariant as the third complementary guard.

### What testers should do

If you installed v0.7.0b1, upgrade to v0.7.0b2:

```bash
pipx upgrade --pip-args="--pre" bodyguard-of-bits-beta
sudo bob-beta --version   # should print 0.7.0b2 (was 0.6.2 in b1)
```

All other v0.7.0b1 testing remains valid — the misreport was UX-only, the
audit logic, scoring, JSON output, posture escalation, etc. were all
correctly v0.7.0 code.

---

## [v0.7.0b1] — 2026-05-31

**First pre-release of v0.7.0** — opt-in via `pipx install --pip-args="--pre" bodyguard-of-bits`. Stable users (`pipx upgrade bodyguard-of-bits` without `--pre`) stay on v0.6.2 and are NOT impacted by this drop.

Bundles **15 commits since v0.6.2** across three phases of work on branch `v0.7.x`:

### Phase 1 — T1 Foundation refresh (6 commits, ~ +540 LoC, +35 tests)

  - **Python 3.14 ladder step 1** (`1b581c0`) — added 3.14 to CI test+publish matrices + classifier. `requires-python` stays at `>=3.10` since upstream 3.10 EOL is 2026-10. Step 2 (`--help` deprecation banner) planned for next minor; step 3 (drop) for post-EOL release.
  - **M-1 `parse_cron_file` time_simple flag** (`d972f17`) — `bob/cron/_parse.py` no longer silently downgrades to `hour=0/minute=0` when minute/hour are non-integer (`*/15 * * * *`, `0 */6 * * *`). `CronEntry` gains `time_simple: bool = True`; the reschedule wizard (in `bob/cron/_manage.py` + `bob/tui/cron.py`) uses `03:00` default instead of misleading `00:00` when the parsed schedule is not plain HH:MM.
  - **M-7 `--check`/`--skip` recognise always-on sections** (`3865738`) — pre-fix, `bob --check=firewall` raised "matches no known section" because the validator didn't know about the 10 always-on sections (firewall, rules, ports_analysis, network_context, firewall_stack, ufw_logging, services, ddns, docker, virtualization). New `_ALWAYS_ON_SECTIONS` tuple in `bob/runner.py`; `--check=<always-on>` is now valid input, `--skip=<always-on>` prints a "has no effect" warning instead of silently swallowing user intent. The "Available sections" wall-of-text in unknown-token warnings is replaced by a single line pointing to `bob --check=list`.
  - **Posture escalation** (`e3d998f`) — `ScoreEngine` gains `set_posture()` + `posture_escalation` property + `effective_level` derived as `max(score-derived level, posture floor)`. Triggers (first match wins): `firewall_inactive` → `HIGH`, `iptables_input_accept` → `HIGH`, `firewall_domain_score ≤ 3` → `MEDIUM`. Surfaces what Phase 1 fixes structurally: a host with UFW OFF and score 8/10 used to display "LOW risk" (score-only) — now displays "HIGH risk" with the parenthetical "raised by posture: firewall inactive". Migration of 5 sites to `effective_level` (display banner, JSON v2 `risk` field, CSV, webhook payload, report.write_summary). New EXPLAIN key `risk.escalated_posture` (count 116 → 117). New locale strings `scoring.posture.{firewall_inactive,iptables_input_accept,firewall_domain_low}` in EN + FR.
  - **CI publish pre-release tag handling** (`9def225`) — `.github/workflows/publish.yml` now detects PEP 440 pre-release tag suffix `(a|b|rc|.dev)[0-9]+$` and (a) synthesises minimal release notes from `git log` when no CHANGELOG section exists, (b) sets `make_latest: false` + `prerelease: true` on the GitHub Release so a pre-release does NOT override the "Latest" badge from the v0.6.x stable line, (c) titles the release `"$VERSION (pre-release)"` when no CHANGELOG headline is found. The infrastructure enabling this current v0.7.0b1 ship.
  - **Posture crash hotfix** (`4ed2e3b`) — smoke test on so6desktop revealed `engine.domain_scores["firewall"]` is a dict, not an int — the dict was passed by mistake to `set_posture(firewall_domain_score=...)` and crashed the audit at the `<=` comparison just before the summary box ("Fatal error: '<=' not supported between instances of 'dict' and 'int'"). Fixed by extracting `["score"]` from the dict + adding a type guard to `set_posture` that raises `TypeError` with a message explicitly naming the dict-vs-int mistake. +5 tests (4 unit + 1 integration test that builds a real engine with `apply_domain_score_override` and exercises the wire-up the same way `__main__.py` does).

### Phase 2 — T2 Schema v2 + EXPLAIN_KEYS audit (4 commits, ~ +940 LoC, +711 tests)

  - **JSON schema v2 dispatch + `--json-v1` flag + posture_escalation block** (`e4420e2`) — `build_json_data()` gains `schema_version: str = "2"` parameter with type guard (`TypeError` for non-str, `ValueError` for unsupported values). Two private producers `_build_v1` and `_build_v2` share no state for cleanliness. v2 fixes the v1 `network_context` type inconsistency (P1: same key was string in short mode but overwritten to dict in full mode), renames `timestamp` → `timestamp_utc` (P/B-3), adds `info_count` top-level (B-7), exposes `posture_escalation` block `{applied, reason_key, score_level}` (P3/A-4), adds `deductions_raw` and `open_ports_all` in full mode (B-4/B-5), and `domain_scores[d]` now carries `deductions` count (B-6). New CLI flag `--json-v1` (implies `--json`) returns the legacy v0.6.x layout exactly for consumers that haven't migrated. Drives 30 new integration tests in `tests/test_json_schema_v2.py` written before the implementation per the integration-first rule.
  - **v1 baseline gap pins + B-2 retired** (`54f3f14`) — 10 explicit tests in `tests/test_json_schema.py::TestSchemaV1BaselineGaps` document the v1 quirks that the v2 migration addresses (P1 type swap, P2 risk semantics shift, P3 absent posture_escalation, no UTC marker in timestamp, no `info_count`, no `deductions_raw`, no `open_ports_all`, `domain_scores[d]` minimal). One test guards against future regression by pinning the *retained* `firewall_stack` bypass field names (`input_bypasses` / `forward_bypasses` — initially scoped as B-2 rename to `*_count`, then retired during Step 1 of T2 when integration-first writing revealed the fields are `list[str]` of rule descriptions, not int counts — plural naming was already correct).
  - **EXPLAIN_KEYS canonical naming convention pin** (`f81dd46`) — audit of all 117 explain keys + 30 prefixes confirmed 100% conformance with `<prefix>.<finding_id>` snake_case (single exception: `file_perms.<path>.<finding_id>` handled by `bob.explain.normalize_key`). Grep across `bob/` confirmed every key is referenced as a string literal (no orphans). New `tests/test_explain_naming_convention.py` (+710 parametrized assertions) pins: canonical pattern, lowercase identifiers, no double underscore, no hyphen, no leading digit, prefix vocabulary as an explicit `KNOWN_PREFIXES` allowlist, no overlap between explain keys and aliases, audit count = 117, prefix count = 30. Adding a new prefix in any future commit will fail `test_key_prefix_is_known` until `KNOWN_PREFIXES` is updated, surfacing the addition as a deliberate decision in code review. Zero retirements in v0.7.0 — all candidates deferred to D-3 v0.8.0.
  - **Docs JSON schema v2 + v1 legacy + migration guide** (`eaea762`) — `DOCUMENTS/README_TECH.md` (and FR) gain a comprehensive section documenting both schema versions, the `posture_escalation` block structure, every new v2 field with type+description, the v1 vs v2 differences table for migration, a jq snippet that handles both versions, and the EXPLAIN_KEYS audit baseline (117 keys / 30 prefixes / canonical pattern). Closes the EXPLAIN_KEYS public commitment in `bob/explain.py` docstring with operational test enforcement.

### Phase 2.1 — Pre-T3 audit cleanup (4 commits, ~ +500 LoC, +18 tests)

A sub-agent deep audit of the cumulated Phase 1 + Phase 2 diff (per project_v07x_phase1 strategy rule 6) surfaced 5 important + 6 minor findings; 5/5 important + 4/6 minor shipped before T3 plugin sandbox runner starts. Two recurring patterns drove the cleanup: (a) the `effective_level` migration was enumerated by hand and missed 3 sinks (HTML, Markdown, history.jsonl) that all leaked the old score-only level into user-visible output; (b) the defensive type-guard pattern from the Phase 1 hotfix was not uniform across engine consumers.

  - **`effective_level` propagation to HTML, Markdown, history.jsonl** (`ef7fb59`) — `bob/html_output.py:82` (`level_label`) and `bob/markdown_output.py:47` (`level_value`) now use the `effective_level` with a `getattr` fallback to preserve legacy test mocks. `bob/history.py::save_score` gains optional kwarg `level_score_only: str | None = None`; when provided, written as a separate JSON field so trend analysis can reach for either the displayed view (`level` = effective) or the score-only baseline (`level_score_only` = un-escalated). `bob/__main__.py:359` updated to pass both: `save_score(engine.score, engine.effective_level.value, level_score_only=engine.level.value)`. +7 integration tests using real `ScoreEngine` + `set_posture(firewall_inactive=True)` asserting the rendered/persisted level matches the effective contract.
  - **`unpack_posture_escalation` helper extraction** (`8167b76`) — new `bob.scoring.unpack_posture_escalation(engine)` consolidates the defensive `getattr` + `try/except TypeError/ValueError` pattern that was duplicated in `display.py` and missing in `json_output.py::_build_v2`. `_build_v2`'s bare unpack `_posture_floor, _posture_key = engine.posture_escalation` would have crashed v2 JSON on the same MagicMock-style test that triggered the Phase 1 hotfix 4ed2e3b for the summary box. The helper is the single source of truth: T3 plugin runner output sinks should consume it directly. +5 tests covering clean engine, firewall-inactive, legacy stubs without the property, non-iterable property values, and oversized tuples.
  - **Posture type guard + audit minors** (`8cdf545`) — bundles four small audit items: **I-3** `set_posture(firewall_domain_score=True)` was accepted (`isinstance(x, int)` returns True for bool); guard now rejects bool explicitly with a message naming the surprise. **I-5** `test_v2_posture_escalation_consistent_with_top_level_risk` had `assert ... or True` making the `applied=True` branch vacuously pass — rewritten to assert the explicit shape (`risk == "high"`, `score_level == "low"`, divergence). **M-4** dead alias `_SCHEMA_VERSION = DEFAULT_SCHEMA_VERSION` at bottom of `json_output.py` removed (zero consumers via grep). **M-5** `test_v1_risk_is_one_of_canonical_values` only checked the enum membership — replaced by `test_v1_risk_reflects_effective_level_not_score_only` that builds a real engine with no deductions + `firewall_inactive=True` and asserts v1 emits `"high"`, pinning the Phase 1 silent semantic shift against accidental revert.
  - **UI symmetry: `--check=list` + report posture annotation** (`a3294fd`) — **M-1** `bob/__main__.py:list_checks` now prints the 10 always-on section names under a second block (`Always-on sections (10 total — these always run, --skip has no effect on them)`) so the validator's accepted vocabulary matches what the `--check=list` help text advertises. The vague "Core checks (firewall, ports, services, logs) always run" line is removed since the explicit list replaces it. **M-3** `bob/report.py::write_summary` gains optional kwarg `posture_annotation: str = ""`; `bob/display.py` computes the annotation via the new `unpack_posture_escalation` helper and passes it through so the on-disk `.txt` report stays in sync with the terminal summary box.

### Test count + smoke validation

  - **5391 → 5409 tests** (+18 net across Phase 2.1, +35 across Phase 1, +711 across Phase 2 — including parametrized EXPLAIN_KEYS audit), 0 regressions throughout the 15-commit chain.
  - **Smoke validated on so6desktop** (Linux Mint 22.3, 2026-05-31): `sudo bob -v -d --french` audits end-to-end, score 8/10, posture clean (UFW active), `--json` emits schema v2 with `posture_escalation: {applied: false}`, `--json --json-v1` emits legacy schema_version="1" with no posture_escalation block, `--check=list` shows both sections + always-on blocks, `history.jsonl` carries the new `level_score_only` field.

### Deferred to v0.8.0 (contract figé)

Per `project_v08x_deferred.md`:

  - **D-1** — sections renumber: uniformisation `emit_section()` names (44 sections, some incohérent vs `_ALL_SECTIONS`). Reported because rename breaks scripts using `--check=ssh,firewall`.
  - **D-2** — fusion `_ALL_SECTIONS` + `_ALWAYS_ON_SECTIONS` into one tuple with `is_always_on` flag. Cosmetic; depends on D-1.
  - **D-3** — retrait `EXPLAIN_KEY_ALIASES` obsolètes — minimum 1 release notice per alias retirement.
  - **D-4** — sub-checks granulaires (e.g. `ssh.x11_forwarding` split into server/client) — on demand.

### What's NOT in this beta (yet)

  - **T3 — Plugin sandbox runner** (restricted-mode for `~/.config/bob/checks.d/*.py`) is the next phase. Design discussion completed (D + RestrictedPython for sandbox, opt-out for plugins, Tier 2 restrictions, known-bad test suite + sub-agent adversarial review). v0.7.0 final ship will bundle T3 plus this beta1 content.

### Calling for beta testers

This is the first user-facing drop of the v0.7.x line. If you can, please:

```bash
# 1. Install the beta into a separate pipx venv to keep your stable v0.6.2 intact:
pipx install --pip-args="--pre" --suffix=-beta bodyguard-of-bits
# 2. Run a full audit and look at the new `posture_escalation` block:
sudo bob-beta --json | jq .posture_escalation
# 3. Compare v2 vs v1 behaviour on the same host:
sudo bob-beta --json          | jq '{schema_version, risk, timestamp_utc, network_context}'
sudo bob-beta --json --json-v1 | jq '{schema_version, risk, timestamp,    network_context}'
# 4. Report anomalies via GitHub issues with the beta tag.
```

The v0.6.x stable line is unaffected. The beta channel is purely opt-in via `--pre`.

---

## [v0.6.2] — 2026-05-29

**Critical packaging hotfix.** Every wheel shipped since v0.6.0 (v0.6.0 + v0.6.1) was missing `bob/checks/ssh/` and `bob/cron/` — the two subpackages introduced by the v0.6.0 splits. Users who `pipx upgrade`d hit `ModuleNotFoundError: No module named 'bob.checks.ssh'` at startup. See `CHANGELOG.md` for the full root cause + fix narrative. Notes specific to this FULL doc:

### Why this bug is interesting

It's a textbook example of the "tests pass, ship breaks" failure mode. Three layers of testing each had a reason not to catch it:

1. **Unit tests** import from the source tree. The `bob.checks.ssh` package exists as a directory in the working tree; Python's import resolution finds it via `sys.path` containing the repo root. The packaging discovery config in `pyproject.toml` is bypassed entirely.

2. **Pre-ship `sudo python3 -m bob` smoke** ran from the working tree (`cd ~/github/bodyguard-of-bits && sudo python3 -m bob …`). Same source-tree resolution. The smoke test on so6desktop reported `BOB v0.6.1` and a normal audit run — exactly because it was loading the source directly, not the v0.6.1 wheel.

3. **CI `integration.yml`** used `pip install -e .` (editable mode). Editable installs add the repo root to `site-packages` via a `.pth` file. They DELIBERATELY bypass `find_packages()` discovery for fast iteration. The integration job was therefore testing the source tree wrapped in a venv — not the wheel.

The bug only surfaces when:
- A wheel is built (`python -m build` or `python setup.py bdist_wheel`)
- That wheel is installed in a location where the source tree is NOT on `sys.path`
- The installer then imports a module from a missing subpackage

That's exactly the pipx upgrade workflow: pipx downloads the wheel from PyPI, installs it into a private venv (`~/.local/share/pipx/venvs/bodyguard-of-bits/`), and the binary `bob` shim invokes `python -c "from bob.__main__ import main"`. With ssh/ and cron/ missing, the runner.py import chain crashes.

### Fix mechanics

The 1-line change in `pyproject.toml`:
```diff
-include = ["bob", "bob.checks", "bob.tui"]
+include = ["bob*"]
```

The glob `bob*` matches any package whose name starts with `bob` (the `*` is a setuptools glob, not a regex). That's `bob`, `bob.checks`, `bob.checks.ssh`, `bob.cron`, `bob.tui`, and every future `bob.something` package. The original guard (excluding accidental top-level `bob_*` non-package directories) is preserved because the glob only matches actual Python packages discovered by `find_packages()`.

### CI hardening

Two complementary changes to `.github/workflows/integration.yml`:

**(1) `pip install -e .` → `pip install .`**

Removes the editable-mode bypass. Now each distro in the matrix builds and installs a real wheel — the same code path PyPI users hit. Any future packaging-config bug will now surface on every PR before merge.

**(2) New explicit smoke step**

```yaml
- name: Smoke — packaging includes all subpackages
  run: |
    python3 -c "import bob.checks.ssh; from bob.checks.ssh import check_ssh, SSHSnapshot"
    python3 -c "import bob.cron; from bob.cron import CronEntry, run_install_cron, _atomic_write"
    python3 -c "from bob._atomic import atomic_write"
    python3 -c "from bob._tty import safe_input, prompt_wizard, read_line"
```

The four imports cover every v0.6.x-added module. Any future contributor adding a new `bob/foo/` subpackage must extend this list — the smoke test failing is more visible than the wheel quietly excluding a directory.

### Cross-distro validation

The new CI smoke step ran on all 7 distros (Debian 12/13, Ubuntu 22.04/24.04/25.04, Kali rolling, Fedora 41) for the v0.6.2 push and passed everywhere. This confirms the fix is correct and the guard is operational.

### What this changes about the audit-campaign baseline

The pre-v0.6.2 v0.5.x deep-audit campaign focused on code correctness (logic bugs, contract violations, security smells). This bug is in a different category: **build-system / packaging config drift**. The audit excluded the `pyproject.toml` from its scope because it's not Python code that runs at audit time. Adding packaging-config to future audit scopes is a lesson logged in `project_v062_packaging_hotfix.md` memory.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4600 passed in ~6s
```

**4600 unchanged.** The fix is in `pyproject.toml` (packaging config) and CI workflow (operational), not in code. This bug class is not unit-testable from within Python — testing it requires building a wheel and re-installing, which is exactly what the new CI step does.

### Upgrade path

If you upgraded to v0.6.0 or v0.6.1 via pipx, you currently have a broken install. Run:

```bash
pipx upgrade bodyguard-of-bits
```

to get the corrected v0.6.2 wheel. Verify with:

```bash
bob --version  # should print "bob 0.6.2"
sudo bob --help > /dev/null  # should not crash
```

### Lessons logged

- **Editable installs hide packaging bugs.** Every integration CI uses `pip install .` going forward.
- **Glob > literal list** for `setuptools.packages.find.include` in projects that may split modules.
- **Smoke import step for each new subpackage** is a low-cost catch-all that surfaces the bug class at CI time instead of user-system runtime.
- **Audit scopes should include `pyproject.toml`** for packaging drift, not just runtime Python code.

---

## [v0.6.1] — 2026-05-29

**First hardening release on the v0.6.x branch.** Deep audit sub-agent pass produced 14 findings (0 critical + 6 important + 8 minor); 6 important + 4 minor shipped. The audit revealed two **half-applied contracts** from v0.5.x and one **untested validator branch**. See `CHANGELOG.md` for per-finding detail. Notes specific to this FULL doc:

### Why the splits + sunset of v0.6.0 didn't surface these earlier

The v0.6.0 ship was structural (splits + UFW_AUDIT_SHARE removal) — no new logic changed, no behavior change expected. The pre-v0.6.0 v0.5.x deep-audit campaign (v0.5.5 through v0.5.8) focused on a different module set: `bob/checks/logs.py`, `bob/manage_logs.py`, `bob/tui/cron.py`, plus 22 core modules. The cron install paths (`bob/cron/_install.py`, `bob/tui/cron.py` cron-install branch) and `bob/ignore.py` were among the ~25 modules "spot-checked" rather than deeply audited — so the half-applied atomic-write contract (mutation fixed in v0.5.7 #I-3, creation not touched) and `ignore.py`'s non-atomic write survived.

The v0.6.1 audit explicitly targeted post-v0.5.x drift + the modules that v0.5.x had spot-checked. That's where the 6 important findings came from.

### Atomic-write contract consolidation (high-leverage cleanup)

Before v0.6.1, 5 modules implemented their own version of "write to tmp + os.replace" with subtle variations:
- `bob/config.py:121, 363` — `UserConfig._save` + `EmailStore._save`
- `bob/compare.py:185` — `save_baseline`
- `bob/history.py:74` — `_rotate_if_needed` only
- `bob/recurrence.py:61` — `save_recurrence`
- `bob/cron/_io.py:28` — `_atomic_write` (the canonical impl)

Three modules did NOT use atomic writes despite the SNAPSHOT.md architectural decision claiming they did:
- `bob/cron/_install.py:261, 280` (fresh install — script + cron file)
- `bob/tui/cron.py:731, 749` (curses install — same paths)
- `bob/ignore.py:93` (raw `os.open(O_TRUNC)`)

And one module (`bob/history.py:58`) used `Path.open("a")` which inherits the process umask — privacy-sensitive given the contents.

v0.6.1 extracts `bob/_atomic.py::atomic_write(path, content, *, mode=)` as the single source of truth. All 5 existing sites migrated; all 4 missing sites fixed. Net change: -100 LoC of duplicated implementation + 50 LoC of new helper + comprehensive docstring.

`bob/cron/_io.py::_atomic_write` is kept as a one-line alias (`from bob._atomic import atomic_write as _atomic_write`) — the existing `TestApplyCronScheduleAtomic` test patches that exact name. Backwards-compat preserved.

### EOF handling contract completion

v0.5.7 #I-2 advertised "all interactive read sites in BOB now route EOF to empty-string semantics". This was true for `bob/_tty.read_line` (already had `try/except EOFError`) and `bob/manage_logs.py` (the 3 sites fixed in v0.5.7). It was false for:
- `bob/_tty.prompt_wizard` (`raw = input(label).strip()` without try)
- `bob/cron/_install.py` (5 bare `input()`s)
- `bob/cron/_manage.py` (5 bare `input()`s)
- `bob/fixes.py:103` (1 bare `input()`)

v0.6.1 adds `safe_input(prompt) -> str` to `bob/_tty.py` (the swallow-EOFError variant) and:
- Patches `prompt_wizard()` to also catch `EOFError → None`
- Migrates the 11 bare `input()` sites to `safe_input`

The semantic difference between `safe_input` (returns `""`) and `prompt_wizard` (returns `None`) is intentional: confirmation prompts (`y/N`) want `""` to mean "no", while cancel-able wizards want `None` to mean "user gave up". Both contracts now uniformly applied.

### `_validate_cron_field` step bounds (I-3)

This was a real bug. The validator at `bob/cron/_parse.py:262` checked `step_s.isdigit() and int(step_s) >= 1` — but never bounded `int(step_s)` against the field range. For the minute field (0-59), `*/200` validated successfully; cron then interpreted it as "every 200 minutes" which never fires (rolls over hourly). Reproducer:
```python
>>> _validate_cron_field("*/200", "minute", 0, 59)
''  # pre-fix: empty = valid
```
Post-fix returns `"minute step '200' exceeds field range (60)"`. The boundary case `*/60` is still accepted (means "fire at minute 0 every hour" = equivalent to `0 * * * *`). 

This bug was unreachable via the curses TUI (which restricts step input differently) but reachable via `--validate "* * * * *"` (which doesn't exist yet but is a frequently-requested feature) and via `parse_cron_file` on a hand-edited cron file.

### `shlex.quote()` on `cmd=` paths (I-4)

Auto-fix command strings interpolate paths into shell commands. The actual auto-apply path (`bob/fixes.py`) uses `shlex.split(cmd)` before `subprocess.run([list])`, which means an unquoted path-with-spaces gets split into multiple tokens and the chmod targets the wrong file.

Sites where paths derive from user-controlled sources:
- SSH: `snapshot.user_home` from `pwd.getpwnam(SUDO_USER).pw_dir` — can be `"/home/Cédric Dev"` etc.
- file_perms: `fi.path` from filesystem scan of `/etc/`, `/var/log/`, etc.
- firmware: `pkg` from `dpkg-query` output (typically `intel-microcode`/`amd64-microcode` but defensively quoted)

8 sites fixed. 13 remaining `cmd=` sites are safe-by-construction (port integers, fixed strings, container IDs as hex). Confirmed via grep.

### `history.jsonl` mode 0o600 (I-5)

Subtle bug class: `Path.open("a")` opens in text-append mode and uses the process umask for the create-mode. With the default umask `0o022`, that gives `0o644` — world-readable. The audit cadence + score timestamps from `history.jsonl` are privacy-sensitive on shared/multi-user systems.

The rotation path at `bob/history.py:74` already used `os.open(..., 0o600)` (atomic + restrictive mode). The first-write path at line 58 did not.

Fix: use `os.open(str(_HISTORY_FILE), O_WRONLY | O_APPEND | O_CREAT, 0o600)` then `os.fdopen(fd, "a", encoding="utf-8")` for the append. Mode 0o600 is applied only at creation; existing-file mode is preserved (so users who explicitly chmod'd to 0o644 don't see their permission overwritten on every audit).

### `ignore.py` atomic write (I-6)

Pre-fix, `bob/ignore.py:93` did `os.open(str(path), O_WRONLY | O_CREAT | O_TRUNC, 0o600)` directly on the destination file. Power-loss / OOM between `O_TRUNC` and `write` left `ignore.yml` empty (corruption — loss of all previously-ignored keys, with no recovery path).

Migrated to `atomic_write(path, content, mode=0o600)` via the v0.6.1 helper.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4600 passed in ~7s
```

**4583 → 4600 (+17).**

New test classes:
- `tests/test_atomic_v061.py::TestAtomicWritePublicAPI` (4) — pins the `atomic_write(path, content, *, mode=)` contract: file created with explicit mode (0o600 / 0o640 / 0o755), content overwritten cleanly on second call, original file content survives when `os.replace` raises (atomicity guarantee).
- `tests/test_atomic_v061.py::TestCronLegacyAliasStillWorks` (1) — `bob.cron._io._atomic_write is bob._atomic.atomic_write` (backwards-compat for test patches).
- `tests/test_atomic_v061.py::TestHistoryFileMode` (2) — I-5 first-write 0o600 + mode preserved on subsequent appends.
- `tests/test_atomic_v061.py::TestIgnoreAtomic` (2) — I-6 atomic write + simulated `os.replace` failure leaves `ignore.yml` content intact.
- `tests/test_atomic_v061.py::TestSafeInput` (3) — I-2 `safe_input()` returns `""` on EOF, returns value on normal input, `prompt_wizard` returns `None` on EOF.
- `tests/test_cron.py::TestStepBoundedToFieldRange` (5) — I-3 step bounds for minute / hour / boundary / zero / full expression.

### Net diff

| File | Delta |
|---|---|
| `bob/_atomic.py` (new) | +40L |
| `bob/_tty.py` | +20L / -1L (safe_input + prompt_wizard EOFError) |
| `bob/cron/_io.py` | -22L / +5L (replaced with alias) |
| `bob/config.py`, `bob/compare.py`, `bob/history.py`, `bob/recurrence.py` | net -30L (5 sites migrated, each saves ~5-8L) |
| `bob/cron/_install.py` | -8L / +8L (atomic_write + safe_input migration) |
| `bob/tui/cron.py` | -8L / +8L (atomic_write migration) |
| `bob/cron/_manage.py` | +1L (safe_input import + 5 site migrations) |
| `bob/fixes.py` | +1L (safe_input import + 1 site migration) |
| `bob/ignore.py` | -2L / +6L (atomic_write + comment) |
| `bob/cron/_parse.py` | +3L (step bound check + comment) |
| 8 `bob/checks/**/*.py` | +8L / -8L (shlex.quote at 8 sites) |
| `bob/checks/ssh/_directives.py`, `bob/checks/ssh/_subchecks.py`, `bob/__main__.py`, `bob/cli.py` | small M-2/M-3/M-6/M-8 fixes |
| `tests/test_atomic_v061.py` (new) | +130L |
| `tests/test_cron.py` | +30L |
| `tests/test_watch.py` | wording-match update |
| Version bump + changelogs | standard ~17 files |

### Audit campaign cumulative summary

| Release | Modules touched | Findings shipped | Tests added |
|---|---|---|---|
| v0.5.5 | 22 deep + ~15 spot | 19 (4C + 4I + 11M) | +7 |
| v0.5.6 | logs.py (662L) | 10 (0C + 2I + 8M) | +15 |
| v0.5.7 | manage_logs.py + tui/cron.py (~1920L) | 6 shipped + 5 deferred | +11 |
| v0.5.8 | the 5 v0.5.7-deferred minors | 5 (all minor) | +12 |
| **v0.6.1** | **codebase-wide audit + v0.6.0 post-split modules** | **6I + 4M (4M deferred)** | **+17** |

**Cumulative**: ~85 hardening findings closed over 5 audit cycles. 0 critical findings outstanding. Two contracts uniformly enforced (atomic-write + EOF handling). The "atomic-write helper extraction" recommendation from the SNAPSHOT.md cross-cutting observations is now actioned.

### What's next

v0.6.x will continue receiving hardening releases as findings surface (typically via cross-distro testing or contributor reports). No new audit campaign planned — the v0.6.1 pass closed the cross-cutting gaps the v0.5.x campaign had left open. Future bug-fix releases will be targeted per-issue rather than wholesale audit-driven.

---

## [v0.6.0] — 2026-05-25

**Major bump opening the v0.6.x branch.** Two architectural splits (#13 + #14) deliberately deferred across the entire v0.5.x cycle, plus one sunset honored (`UFW_AUDIT_SHARE` legacy env var). All changes contract-preserving via package `__init__.py` re-exports.

See `CHANGELOG.md` for per-module detail. Notes specific to this FULL doc:

### Why two file splits in a major release

The conservative-refactor principle (cf. memory [[feedback_conservative_refactor]]) — "gain × risque ≤ 0 in a contract-preserving release = STOP" — forbade the splits during v0.5.x. Splitting a 1000+ LoC file requires:
- Moving every function to a new module
- Adjusting all internal imports
- Adjusting all external imports (other packages + tests)
- Risking subtle import-order or cycle bugs that don't surface in unit tests

In a v0.x.y patch release, that's high-risk for marginal readability gain. In a v0.x+1.0 major bump, imports are EXPECTED to shift (it's the convention for major versions to ship structural changes), so the risk is socialized. v0.6.0 is the right vehicle.

### Why re-exports via `__init__.py` rather than path migration

The splits could have moved public symbols to new import paths (e.g., `from bob.checks.ssh.snapshot import SSHSnapshot`). That would be a true breaking change requiring a deprecation cycle. Instead, every public symbol is re-exported from the package `__init__.py`, so `from bob.checks.ssh import SSHSnapshot` continues to work identically.

Tradeoff: the package `__init__.py` file becomes a re-export list (boring boilerplate), but:
- Zero user-visible breakage
- Test files unchanged
- External integrations unchanged
- The option to migrate import paths in v0.7+ remains open if a deeper API redesign is wanted

This is the same pattern Python's stdlib uses for many of its packages (e.g., `email.mime.text.MIMEText` is also re-exported as `email.MIMEText`).

### Cycle-breaking in the ssh package

The natural dependency is bidirectional:
- `_parsers` returns instances of dataclasses defined in `_snapshot` → needs to import them
- `_snapshot.SSHSnapshot.from_system` calls parser functions from `_parsers` → needs to import them

To break the cycle: `_parsers` imports dataclasses from `_snapshot` at module level; `_snapshot.from_system` uses a function-local `from . import _parsers` import. This is clean because:
- The dataclasses load first (no dep on `_parsers`)
- The parsers load second (uses dataclasses from already-loaded `_snapshot`)
- `from_system` only resolves `_parsers` at call time, by which point everything is loaded

The pattern is documented in both `_snapshot.py` and `_parsers.py` module docstrings — future contributors who need to add a new parser or modify `from_system` know not to add a top-level import that would re-introduce the cycle.

### `build_script_content` path resolution gotcha

Pre-v0.6.0, `bob/cron.py` lived at one level under `bob/`, so `Path(__file__).parent.parent` resolved to the repo root (PYTHONPATH-able). Post-split, `_io.py` lives TWO levels under `bob/` (`bob/cron/_io.py`), so the function now walks THREE parents:

```python
bob_path = str(Path(__file__).parent.parent.parent)
#                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^
#                       _io.py → cron/ → bob/ → repo root
```

This is the only "subtle" change in v0.6.0 — everywhere else, the splits are pure code movement. The smoke test `tests/test_cron.py::TestDatetimeImportLifted::test_build_script_content_still_stamps_date` exercises the function end-to-end and would have caught a regression.

### Test infrastructure updates (3 trivial fixes)

Three test files needed updates to accommodate the new package structure:

1. **`tests/test_template_vars_migration.py`** — extended `_check_modules()` / `_module_paths()` to recursively scan package directories. Pilot list migrated from `.py`-suffixed names to module names.
2. **`tests/test_domain_scores_mapping_complete.py`** — single-line change `glob` → `rglob` with `__pycache__` filter so the AST scanner picks up `bob/checks/ssh/_subchecks.py`.
3. **`tests/test_cron.py::TestApplyCronScheduleAtomic`** — patch target shifted from `bob.cron._atomic_write` (package re-export) to `bob.cron._io._atomic_write` (where `apply_cron_schedule` actually calls it). The patch must be set on the module where the call site reads, not where the function happens to also be re-exported.

These are mechanical updates with no scope change. Coverage stays identical: 4583 tests, 0 added, 0 removed.

### `UFW_AUDIT_SHARE` removal mechanics

The deprecation chain (12+ months):

- **v0.4.2** (2026-05-14): `BOB_SHARE` documented as the contract; `UFW_AUDIT_SHARE` accepted as legacy alias with `logger.info(...)` notice
- **v0.5.4** (2026-05-23): `logger.info` upgraded to `logger.warning(...)` with explicit "DEPRECATED since v0.5.4, will be REMOVED in v0.6.0. Update your installer to BOB_SHARE..." message
- **v0.6.0** (this release): `_ENV_LEGACY` constant deleted, fallback read deleted, warning branch deleted. The variable is now silently ignored — packages still setting it will see `resolve_share_dir()` return None and fall back to package-local data, which is the safe default.

Net change in `bob/_paths.py`: -20 lines (a constant, a fallback read, the warning branch). The docstring is updated to note "removed in v0.6.0" for historical reference. Two stale comment references in `bob/i18n.py:44` and `bob/registry.py:38` were also updated.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4583 passed in ~7s
```

**4583 unchanged.** Zero behaviour change.

### Net diff

| File | Delta |
|---|---|
| `bob/checks/ssh.py` (deleted) | −1296L |
| `bob/checks/ssh/` package (5 files) | +1402L (+106 overhead from `__init__.py` + per-file docstrings + module-level imports) |
| `bob/cron.py` (deleted) | −1204L |
| `bob/cron/` package (5 files) | +1359L (+155 overhead similarly) |
| `bob/_paths.py` (UFW_AUDIT_SHARE drop) | −20L |
| `bob/i18n.py`, `bob/registry.py` (docstring cleanup) | −2L |
| `tests/test_template_vars_migration.py` (rglob support) | +30L / −10L net |
| `tests/test_domain_scores_mapping_complete.py` (rglob shift) | +3L / −1L |
| `tests/test_cron.py::TestApplyCronScheduleAtomic` (patch target) | +2L / −0L |
| Version bump + changelogs | standard ~17 files |

**Cumulative: ~+260 LoC overhead** for the split (across both packages) vs the monolithic equivalent. Justified by the modularity gain — largest single module post-split is 529L (well below the project's soft 1000-LoC ceiling), down from 1296L pre-split.

### Cross-cutting observation: the public API surface is now explicit

Pre-v0.6.0, the v0.5.x monoliths exposed ~30 symbols implicitly (everything top-level not prefixed `_`). With the package split, the `__init__.py` re-export list makes the public API explicit and reviewable:

- `bob/checks/ssh/__init__.py`: 7 names re-exported (`SSHSnapshot` + 5 dataclasses + `check_ssh`) + 6 test-only helpers
- `bob/cron/__init__.py`: 17 names re-exported (full v0.5.x compat set) + `_EMAIL_RE` re-export from `bob.config` + `datetime` re-export for v0.5.8 test

Future contributors who want to add a new public symbol must explicitly opt-in by listing it in `__all__` and/or the import block. This is a useful side-benefit of the split that wasn't part of the original audit motivation.

### Roadmap

v0.6.x will host:
- Maintenance + cross-distro field bug reports
- Possible TUI prompt unification (was a v0.6.0 candidate but punted to maintain release focus on the splits)
- JSON schema v2 cadence planning (no breaking changes yet — plan documented for v1.0)
- Python 3.10 EOL preparation (will likely become a min-version bump candidate in v0.7+)

No deep-audit campaign planned — the v0.5.x campaign closed comprehensively. Any future audits will be triggered by specific concerns (a new vulnerability class, a CVE in a dependency, a contributor request) rather than proactive sweeps.

---

## [v0.5.8] — 2026-05-25

**Cleanup release.** Clears the 5 cosmetic minors explicitly deferred by v0.5.7 (M-2, M-5, M-6, M-7, M-8). All five are layout / readability / explicit-naming improvements with no behavioural delta in normal operation. **This closes the v0.5.x deep-audit campaign — branch fully audited (25 modules deep + ~25 spot-checked, 0 critical findings outstanding).**

See `CHANGELOG.md` for per-finding detail. Notes specific to this FULL doc:

### Why a separate cleanup release

v0.5.7 explicitly shipped 6 fixes (3 important + 3 trivial minors) and explicitly deferred 5 cosmetic minors with file:line breadcrumbs in the changelog. Two paths were possible:
1. Bundle the 5 minors into v0.6.0 (the next major bump).
2. Ship them as a focused v0.5.8 cleanup release.

Option 2 was chosen because:
- v0.6.0 is reserved for the **#13 + #14 architectural splits** (ssh.py 1324L + cron.py 1223L) — bundling unrelated cosmetic minors there would dilute the major-version theme.
- The 5 minors are tiny and self-contained — fits the "small focused release" cadence the v0.5.x branch has established.
- It keeps the audit-finding lineage clean: every finding from the v0.5.7 sub-agent audit has a release that explicitly addresses it.

### Behavioural impact on the wire

Zero. Verified by:
- `pytest -q` 4571 → 4583 (+12, all green) with no existing test failure or rename
- `_Schedule.WEEKDAYS` compares equal to plain int 2 (preserves all `if choice == _Schedule.X:` semantics)
- `_is_finding_continuation` is strictly stricter than the previous `startswith("    ")` predicate, but the over-greedy case it defends against only occurs when a section delimiter happens to be 4-space indented (not the case in any current BOB output)
- M-2 cursor-shift correction only changes display position after multi-selection deletes mixing items before+after the cursor — never observed as a user complaint, but semantically a real fix
- `datetime` import lift is a pure structural change

### M-7 helper design

The new `_is_finding_continuation(line)` helper is intentionally conservative: it rejects ANY indented line that contains a finding marker or starts with a section glyph. Alternatives considered:
- **Anchored regex** like `re.match(r"^    (?!\[ALERT\]|\[WARN\]|\[OK\]|\[INFO\])", line)` — works but less readable
- **Indent-level tracking** (a continuation must be MORE indented than the parent finding) — overengineered for the actual problem
- **Empty-line sentinel** (stop only on blank lines) — too permissive; would not catch the over-greedy case the agent flagged

The chosen design is direct: list the patterns that obviously belong to a different parent, and stop there. Easy to extend if a new boundary glyph appears (just add to the tuple).

### M-5 IntEnum vs module-level constants

Considered three forms:
- **Module-level `int` constants** (`_SCHEDULE_DAILY = 1; ...`) — simplest, but no introspection or class-membership guarantees
- **`Enum`** — strongest type, but breaks `choice == 2` comparisons unless `.value` is used
- **`IntEnum`** — chosen because it compares equal to plain ints (preserving every existing call site untouched) AND provides explicit names

Cost: one stdlib import (`from enum import IntEnum`). No runtime overhead.

### M-8 follow-up: the unused local import sweep

Lifting `from datetime import datetime` in `bob/cron.py:_run_install_cron_plain` also revealed two other redundant local imports in the same function: `import os` and `from pathlib import Path` were both already at module scope. Removed in the same commit (small but cumulative clarity win).

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4583 passed in ~6s
```

**4571 → 4583 (+12).** New test classes:

`tests/test_cron.py`:
- `TestScheduleIntEnum` (2) — `_Schedule.DAILY == 1`, `_Schedule.WEEKDAYS == 2`, etc., plus IntEnum-vs-int comparison parity.
- `TestDatetimeImportLifted` (3) — `bob.cron.datetime` is `datetime.datetime`; same for `bob.tui.cron.datetime`; `build_script_content` smoke test still stamps today's date.

`tests/test_manage_logs.py`:
- `TestCursorShiftAfterDelete` (2) — mixed before/after case (cursor shifts by before-count only); all-after case (cursor unchanged).
- `TestSummaryStartSentinel` (1) — synthetic SEP62-at-index-0 detection.
- `TestIsFindingContinuation` (4) — accepts indented body lines; rejects non-indented; rejects indented `[ALERT]`/`[WARN]`/`[OK]`/`[INFO]` markers; rejects indented section delimiters (`┌`/`└`/`━`/`╔`).

### Net diff

| File | Delta |
|---|---|
| `bob/cron.py` | -3 / +1 (M-8: 1 top-level import, 2 local-import lines removed; also dropped redundant local `import os` / `from pathlib import Path` in `_run_install_cron_plain`) |
| `bob/tui/cron.py` | -2 / +12 (M-5: `IntEnum` class definition; M-5: 4 call sites updated; M-8: 1 top-level import, 1 local-import line removed) |
| `bob/manage_logs.py` | -3 / +24 (M-2: deleted_before_cursor tracking; M-6: sentinel `None`; M-7: new `_is_finding_continuation` helper + 2 call sites updated) |
| `tests/test_cron.py` | +49 (TestScheduleIntEnum + TestDatetimeImportLifted) |
| `tests/test_manage_logs.py` | +94 (TestCursorShiftAfterDelete + TestSummaryStartSentinel + TestIsFindingContinuation) |
| Version bump + changelogs | standard ~17 files |

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — unchanged.
- **Per-domain score**: unchanged. Global score unchanged.
- **Wire output**: unchanged.
- **External API**: 2 new module-level symbols (`bob.tui.cron._Schedule` and `bob.manage_logs._is_finding_continuation`). Both leading-underscore = internal/semi-public. No removals.
- **Keybindings**: unchanged.
- **No-curses fallback**: unchanged.

### v0.5.x deep-audit campaign — FINAL summary

| Release | Scope | Findings shipped | Tests |
|---|---|---|---|
| v0.5.5 | 22 core modules (deep) + ~15 spot-checked | 19 (4C + 4I + 11M) | +7 |
| v0.5.6 | `bob/checks/logs.py` (662L) | 10 (0C + 2I + 8M) | +15 |
| v0.5.7 | `bob/manage_logs.py` + `bob/tui/cron.py` (~1920L) | 6 shipped + 5 deferred | +11 |
| **v0.5.8** | **The 5 v0.5.7-deferred minors** | **5 (all minor)** | **+12** |

**Cumulative**: 25 modules deeply audited + ~25 spot-checked. 0 critical findings outstanding on the branch. Net test growth from v0.5.4 baseline: 4538 → 4583 (+45 in 4 hardening releases).

### What's next (v0.6.0)

The major-version bump is reserved for:
- **#13**: split `bob/checks/ssh.py` (1324 LoC)
- **#14**: split `bob/cron.py` (1223 LoC after v0.5.8 import lift)
- TUI prompt unification (`_curses_readline` / `prompt_wizard` / `_rl` form a 3-tier hierarchy that could be flattened)
- Optional JSON schema v2 cadence (no breaking changes yet but plan documented)

Both file splits are deliberately deferred from v0.5.x because gain × risk did not justify the churn in a contract-preserving minor release.

---

## [v0.5.7] — 2026-05-24

**Targeted hardening pass on the curses TUI.** The two interactive curses modules (`bob/manage_logs.py` 999 LoC + `bob/tui/cron.py` 920 LoC = ~1920 LoC) explicitly deferred by the v0.5.5 and v0.5.6 audits. A focused sub-agent audited both modules in full. 11 findings: 0 critical, 3 important, 8 minor (3 shipped + 5 deferred to v0.5.8).

See `CHANGELOG.md` for per-finding detail. Notes specific to this FULL doc:

### Audit methodology — second TUI-only pass

This release completes the 2-pass audit campaign on the bucket deferred by v0.5.5. The pattern (single-domain sub-agent + explicit exclusions of already-shipped findings) was inherited from v0.5.6 and tuned with two additions for curses code:

1. **Frozen-contracts callout up front**: keybindings (`q`/`r`/`h`/arrows/`Enter`/`Esc`), no-curses fallback (`BOB_NO_CURSES` env + `sys.stdout.isatty()` branch), exit codes (0/1/130), JSON schema, profile system. Sub-agent confirmed all intact after the audit.
2. **Bug-class hunting from v0.5.6**: actively scanned for `datetime.now()` comparison sites. Result: only one site (`bob/tui/cron.py:712`, header timestamp generation, no comparison) — clean.

### ROI distribution: 0 critical (again)

Like v0.5.6, no critical findings. The curses TUI was extensively exercised in production over the v0.5.x cycle (5 releases × 5 cross-distro VMs) and the recently-shipped v0.5.5 #M-2 already removed dead curses code (`_NullReport`). The high-risk concerns (path traversal, shell injection, atomic writes elsewhere) were already addressed in prior passes.

The 3 important findings are all genuine bugs but with constrained impact:
- **I-1** is UX-corrupting only — downstream validation prevents propagation
- **I-2** is exit-cleanliness only — Ctrl-D path was already an "I want out" gesture
- **I-3** is a real atomicity gap with low frequency (cron rewrites are rare, power-loss during them rarer still) but a high blast radius (silent audit cessation)

### Bug-class lineage: atomic write + EOFError handling

**I-3** brings the atomic-write contract enforcement to its final state across the codebase. After:
- v0.5.5 #C-1 (`apply_cron_email` mode regression)
- v0.5.5 #I-1 (`recurrence.py` / `ignore.py` mode 0o600 enforcement)
- v0.5.7 #I-3 (`apply_cron_schedule` → `_atomic_write`)

…all file-mutating sites in BOB now go through `_atomic_write(path, content, mode=)`. Future audits can use a single grep (`grep -rn "os\.open.*O_TRUNC\|open(.*'w'" bob/`) to verify no regression.

**I-2** brings the interactive-read EOF contract to its final state. After:
- v0.5.0 `_rl()` helper (clean EOF handling for the main wizards)
- v0.5.4 `prompt_wizard()` helper (translation-agnostic prompt with cancel)
- v0.5.7 #I-2 (the remaining 3 bare `input()` sites in `manage_logs.py`)

…all interactive read sites in BOB now route EOF to empty-string semantics. Ctrl-D never crashes; Ctrl-C still exits 130 via Python default.

### Deferred minors: explicit defer list for v0.5.8

The 5 deferred minors are tracked here for future auditor reference:

| # | File:Line | Description |
|---|---|---|
| M-2 | `manage_logs.py:871` | `cursor = max(0, cursor - deleted)` assumes all deletions sit before the cursor — if marked items are after, cursor moves left wrongly |
| M-5 | `tui/cron.py:212` | `_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4` — magic-number assignment; promote to module-level `IntEnum` |
| M-6 | `manage_logs.py:520-523` | `if summary_start: break` treats index 0 as "no separator found" — use sentinel `None` |
| M-7 | `manage_logs.py:536, 545` | `while ... lines[j].startswith("    ")` over-greedy: swallows unrelated 4-space body lines |
| M-8 | `tui/cron.py:711` + `bob/cron.py:761` | `from datetime import datetime` local to function body — lift to module top |

All cosmetic / unreachable / layout-only. Zero behavior change in v0.5.8 (when shipped).

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4571 passed in ~6s
```

**4560 → 4571 (+11).** New test classes:

`tests/test_cron.py`:
- `TestApplyCronScheduleAtomic` (2) — pins I-3 regression. Spy on `_atomic_write` to verify it's called; simulate failure to verify the original cron file content survives intact.
- `TestIsPrintableInputChar` (4) — pins I-1 regression. Verifies the boundary across printable ASCII, printable Latin-1, control characters, and the full range of `curses.KEY_*` constants.

`tests/test_manage_logs.py`:
- `TestEOFErrorOnPromptPath` (2) — pins I-2 regression in `prompt_path()` with and without `allow_cancel`.
- `TestEOFErrorOnMoveConfirm` (1) — pins I-2 regression in the move-logs `[y/N]` branch (Ctrl-D == decline).
- `TestEOFErrorOnDeleteAllConfirm` (1) — pins I-2 regression in the delete-all `[y/N]` branch (Ctrl-D == cancel, file NOT deleted).
- `TestDeletedOneCorrectName` (1) — pins M-1 logic: under selective unlink failures, the displayed name is the FIRST successfully-deleted file, not `pending_delete[0]`.

### Net diff

| File | Delta |
|---|---|
| `bob/cron.py` | -6 / +5 (I-3 swap raw `os.open` → `_atomic_write`) |
| `bob/tui/cron.py` | +20 / -10 (I-1 helper + filter call, M-3 dead-code cleanup, M-4 import consolidation) |
| `bob/manage_logs.py` | +24 / -3 (I-2 three EOFError catches, M-1 deleted_name tracking) |
| `tests/test_cron.py` | +95 (TestApplyCronScheduleAtomic + TestIsPrintableInputChar) |
| `tests/test_manage_logs.py` | +90 (4 new test classes for I-2 + M-1) |
| Version bump + changelogs | standard ~17 files |

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — unchanged.
- **Per-domain score**: unchanged. Global score unchanged.
- **Wire output**: no changes to plain-text or JSON output. TUI displays no longer show Greek glyphs on function-key press (UX-visible only).
- **External API**: `_is_printable_input_char(ch_i)` is a new module-level helper in `bob/tui/cron.py`. No removals.
- **Keybindings**: unchanged. `q`/`r`/`h`/arrows/`Enter`/`Esc` all behave identically.
- **No-curses fallback**: unchanged. Same `BOB_NO_CURSES` / `sys.stdout.isatty()` branches.

### v0.5.x audit closure progress (FINAL for deep-audit pass)

| Module | Status | Release |
|---|---|---|
| 22 core modules (ssh.py, scoring.py, etc.) | audited (v0.5.5) | v0.5.5 |
| `checks/logs.py` | audited (v0.5.6) | v0.5.6 |
| **`manage_logs.py`, `tui/cron.py`** | **audited (v0.5.7, this release)** | **v0.5.7** |
| Format renderers (`html/csv/markdown_output.py`) | spot-checked | — |
| `display.py`, `output.py` | spot-checked | — |
| ~25 other `checks/*.py` modules (small <300L each) | spot-checked | — |

**v0.5.x branch deep-audit campaign closed.** 25 modules deeply audited (3 passes × multiple sub-agents) + ~25 spot-checked. The remaining 5 v0.5.7 deferred minors will ship in v0.5.8 (cosmetic-only release).

### Roadmap

After v0.5.8 (5 deferred TUI minors), the v0.5.x branch will be at its final maintenance state. The next minor version (v0.6.0) is reserved for the two deliberately-deferred architectural refactors from the v0.5.x roadmap:
- **#13**: `bob/checks/ssh.py` split (currently 1324 LoC after the v0.5.2 `_BadDirective` table consolidation)
- **#14**: `bob/cron.py` split (currently 1223 LoC after the v0.4.8 file-patching helper extraction)

Both files exceed the project's soft 1000-LoC ceiling; the splits were deferred because gain × risk did not justify the churn in a contract-preserving minor release. v0.6.0 is the appropriate place.

---

## [v0.5.6] — 2026-05-24

**Targeted hardening pass on `bob/checks/logs.py`** — the UFW log parser module (662 LoC) explicitly deferred by the v0.5.5 audit because of its regex density. A focused sub-agent audited the module in full (every function and branch). 10 findings shipped: 0 critical, 2 important, 8 minor.

See `CHANGELOG.md` for per-finding detail. Notes specific to this FULL doc:

### Why a single-module release

The audit roadmap (set in v0.5.5 close notes) had `logs.py`, `manage_logs.py`, and `tui/cron.py` as "not deeply audited". The decision was a 2-pass campaign:
- **v0.5.6** = `logs.py` (regex parser, high bug density risk)
- **v0.5.7** = `manage_logs.py` + `tui/cron.py` (curses TUI, user-visible)

Single-module releases keep the diff focused: 23 files touched (logs.py + tests + the standard 17 version-bump sites + 5 changelogs), one auditable scope. Easier review than bundling all v0.5.x audit remainder in one v0.5.7.

### Audit findings: ROI distribution

The audit found 10 issues but **no critical bug**. This matches expectations:
- The module was already touched by v0.5.x #8 (`tuple` return refactor) which forced an end-to-end review of every code path
- Terrain testing on 5 VMs across 5 releases (v0.5.0 → v0.5.4) exercised it in production
- The high-risk concerns (regex correctness, journald fallback semantics, GeoIP integration) were stable

The 2 important findings (I-1 private-IP regex inconsistency, I-2 year-rollover silent drop) are genuine bugs but with low operational impact under typical conditions. The 8 minor findings are quality-of-implementation improvements.

### Single source of truth: private-IP detection

I-1 closes the last hand-rolled private-IP matcher in the codebase. After v0.5.5 #I-4 rewrote `sysinfo._PRIVATE_IPV4_RE` to use `ipaddress.ip_network` membership lists, `bob/checks/logs.py:46` remained as the only outlier with its own ad-hoc regex. The new `_is_private_ip(ip)` helper in `logs.py` delegates to the sysinfo helpers — there is now exactly one model for "is this IP private/loopback/link-local" across BOB.

### Bug class extracted: year-rollover under clock skew

I-2 documents a pattern worth watching elsewhere in the codebase:
> Any date-comparison logic that calls `datetime.now()` to decide whether a parsed timestamp is "in the past" needs a tolerance window (typically 5 minutes) to absorb NTP jitter, log buffering, and process-clock skew. A tight `> now` check silently drops legitimate near-realtime data.

Sites in BOB that use `datetime.now()` for comparisons (grep result):
- `bob/checks/logs.py:_parse_timestamp` — **fixed in v0.5.6 (this release)**
- `bob/checks/ssl_certs.py` — uses `notAfter > now` for expiry (correct direction; no rollback)
- `bob/checks/firmware.py` — uses `last_update > now - days(N)` (correct direction)
- `bob/checks/rkhunter.py`, `bob/checks/clamav.py`, `bob/checks/file_integrity.py` — DB age comparisons (correct direction)

No other site has the same year-rollover pattern. Documented in `project_v056_logs_audit.md` memory.

### `[UFW BLOCK6]` IPv6 variant

M-1 catches an undocumented variant of the UFW prefix used by some downstream packagers (Debian backports, custom `before6.rules` configurations). The substring matcher had been silently dropping these for years. Field impact unclear — most users probably never noticed because IPv6 BLOCK volume is dominated by mDNS link-local traffic that wouldn't surface as a "missing finding".

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4560 passed in ~6s
```

**4545 → 4560 (+15).** All new in `tests/test_logs.py`:
- `TestPrivateIPDispatch` (8) — pins I-1 regression coverage including CGNAT, IPv6 link-local, ULA, invalid input
- `TestParseTimestampYearRollover` (3) — pins I-2 regression for current-year, 1s-skew, genuine December rollback
- `TestBlockPrefixMatcher` (3) — pins M-1 across `[UFW BLOCK]`, `[UFW BLOCK6]`, `[UFW ALLOW]` rejection
- `TestProtoNormalisation` (1) — pins M-8 proto upper-case normalisation

### Net diff

| File | Delta |
|---|---|
| `bob/checks/logs.py` | +60 / -25 (I-1 helper + I-2 tolerance + M-1 regex + M-2 anchor + M-3 reorder + M-5 cache helper + M-6 binary read + M-7/M-8 minor) |
| `tests/test_logs.py` | +150 (4 new test classes) |
| Version bump + changelogs | standard ~17 files |

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS — unchanged.
- **Per-domain score**: unchanged. Global score unchanged.
- **Wire output**: 2 narrow deltas — `[UFW BLOCK6]` lines now counted (previously dropped), and `_count_available_days` no longer over-counts on non-English locale logs.
- **External API**: `_is_private_ip(ip)` is a new semi-public helper in `logs.py`. The undocumented `_PRIVATE_IP` regex constant is removed.

### v0.5.x audit closure progress

| Module | Status | Release |
|---|---|---|
| 22 core modules (ssh.py, scoring.py, etc.) | audited (v0.5.5) | v0.5.5 |
| `checks/logs.py` | **audited (v0.5.6, this release)** | **v0.5.6** |
| `manage_logs.py`, `tui/cron.py` | pending | v0.5.7 |
| Format renderers (`html/csv/markdown_output.py`) | spot-checked (I-3 in v0.5.5) | — |
| `display.py`, `output.py` | spot-checked | — |
| ~25 other `checks/*.py` modules (small <300L each) | spot-checked | — |

---

## [v0.5.5] — 2026-05-24

**Hardening pass — post-v0.5.4 audit by a deep general-purpose sub-agent.** 19 findings: 4 real bugs (C-1 to C-4), 4 security smells (I-1 to I-4), 11 minor cleanups (M-1 to M-11). 17 fixed with code/test changes; 2 are doc comments (M-8/M-9). Companion cosmetic commit (M-6) migrates `Optional[X]` / `List[X]` typing on 18 modules.

### Audit methodology

A general-purpose sub-agent was tasked with a deep read of 22 modules (`bob/cron.py`, `bob/checks/ssh.py`, `bob/checks/services_state.py`, `bob/scoring.py`, `bob/domain_scores.py`, `bob/explain.py`, `bob/__main__.py`, `bob/sysinfo.py`, `bob/fixes.py`, `bob/recurrence.py`, `bob/compare.py`, `bob/ignore.py`, `bob/correlation.py`, `bob/i18n.py`, `bob/watch.py`, `bob/webhook.py`, `bob/checks/_run.py`, `bob/report_markdown.py`, `bob/checks/updates.py`, `bob/checks/password_policy.py`, `bob/checks/user_accounts.py`, `bob/checks/file_perms.py`) plus 15+ spot-checked modules. Findings reported as severity-graded (C / I / M / S) with file:line, root cause, fix recommendation, and regression risk. Coverage reported in audit (full / spot / not-touched lists).

Not-deeply-audited modules (deferred for future passes): `bob/manage_logs.py` (999L curses TUI), `bob/tui/cron.py` (920L curses TUI), `bob/checks/logs.py` (662L UFW regex layer), `bob/display.py`, `bob/output.py`, formats `bob/html_output.py` / `bob/csv_output.py` / `bob/markdown_output.py`.

### Critical bugs (4)

**C-1 — `apply_cron_email()` silently broke scheduled audits**

`bob/cron.py:apply_cron_email()` (lines 863-900) rewrote both `entry.cron_path` and `entry.script_path` via `_atomic_write()`, which always opened the temp file with mode `0o600`. After `os.replace()` the new file inherited that mode — the wrapper script (originally `0o755`) lost its executable bit, and cron silently could no longer exec it. Anyone who used `bob --manage-cron` to change the notification email entered this state. Cron continued reading the cron file but the script never ran; the scheduled audit silently went dark.

The pattern was inherited from when `_atomic_write` was first introduced (private state files, `0o600` was correct). The cron.py callers added later didn't account for the mode difference.

```python
def _atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    """Write *content* to *path* atomically (temp file + os.replace).

    *mode* is the open() flag mode for the *new* file. Default is 0o600
    (private) — appropriate for state files. Callers patching existing
    cron files (0o640) or wrapper scripts (0o755) MUST pass the right
    mode explicitly, otherwise os.replace() preserves the tmp file's
    mode (0o600) and breaks the original file's permissions.
    """
    ...
```

Two `apply_cron_email` call sites updated: `mode=0o640` for cron file, `mode=0o755` for script. Regression test added: `tests/test_cron.py::TestApplyCronEmail::test_preserves_script_executable_mode` pins the resulting mode after the rewrite. The audit recommendation S-2 ("test for permission preservation on cron-managed files") is now satisfied.

**C-2 — `password_policy.no_quality_module` cmd unfixable via `--fix --apply`**

`bob/checks/password_policy.py:184-192` emitted `cmd="sudo apt install libpam-pwquality && sudo pam-auth-update"` with `nature="action"`. `bob/fixes.py:106` (`_has_shell_ops`) correctly flags `&&` as unsafe shell syntax and rejects the cmd at fix-time with "unsafe shell syntax in command". The user pressed `y` and saw nothing happen.

Two-step `apt install … && pam-auth-update` isn't safely chainable in a single `subprocess` exec anyway (pkg install can fail; pam-auth-update needs to see the new package). Demoted to `nature="improvement"` so the cmd appears as guidance without entering the fix queue. Test `test_nature_is_improvement` replaces `test_nature_is_action`.

**C-3 — `password_policy.weak_minlen` cmd is decorative, not executable**

`cmd="sudo nano /etc/security/pwquality.conf  →  minlen = 8"` — the Unicode arrow `→` tokenises via `shlex.split()` into junk: `["sudo", "nano", "/etc/security/pwquality.conf", "→", "minlen", "=", "8"]`. Even if it parsed, this is a *guidance hint with an embedded next-step*, not a command. Same fix class as C-2: demote to `nature="improvement"`.

**C-4 — `EXPLAIN_KEYS` drift for `services_state`**

Rename drift. `bob/checks/services_state.py:197,204,211` emits findings with `key="services_state.service_inactive"`. `bob/explain.py:151` declares the canonical EXPLAIN_KEY `services_state.enabled_inactive`. The locale `explain.services_state.enabled_inactive` block describes the right concept. The drift means `bob --explain services_state.service_inactive` returns "key not found" — even though the user just saw that key in their audit output.

Two options were on the table:
- **(a)** Rename the emitted key in `services_state.py` to match the canonical name. **Breaks the JSON output contract** for any user automating on the `service_inactive` key (JSON `schema_version="1"` includes finding keys).
- **(b)** Add `services_state.service_inactive` → `services_state.enabled_inactive` to `EXPLAIN_KEY_ALIASES`. JSON output unchanged. `--explain` resolves via alias.

Option (b) chosen (conservative). Added a regression test `test_services_state_alias_routes_to_canonical` to lock the alias.

### Important issues (4)

**I-1 — `recurrence.json` + `ignore.yml` written with default umask**

`bob/recurrence.py:56-57` used `tmp.open("w", encoding="utf-8")` and `bob/ignore.py:89` used `path.write_text(content, encoding="utf-8")`. Both rely on process umask. On default Debian/Ubuntu the umask is `0022`, producing world-readable `0644` files. **Every other persistent state file in BOB** (`bob/config.py:123`, `bob/compare.py:185`, `bob/history.py`, `bob/report.py:160`, `bob/manage_logs.py`) uses `os.open(..., 0o600)` via either `_atomic_write` or explicit `os.fdopen` — a documented `~/.config/bob/` invariant. SNAPSHOT.md flags this explicitly.

Data is not high-sensitivity (recurring finding keys, ignored finding keys) but the inconsistency violates the invariant. Both fixed to use `os.open(str(path), os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600)` + `os.fdopen()`.

**I-2 — `_apply_deduction` bypassed score cap after `finalize()`**

The orchestrator contract documented at `bob/scoring.py:437-446` is one-way: `finalize()` bakes in the cap then sets `_finalized=True`. A late `engine.apply(result)` would mutate `_raw_score` via `_apply_deduction` after the cap was applied — silently bypassing it. No guard existed.

Added defensive guard at `bob/scoring.py:541-548`:

```python
def _apply_deduction(self, deduction: Deduction) -> None:
    if self._finalized:
        logger.warning(
            "ScoreEngine: deduction %r applied after finalize() — discarded "
            "to preserve cap semantics. Re-order callers if intentional.",
            deduction.key or deduction.reason[:40],
        )
        return
    self._raw_score -= deduction.points
    self.breakdown.append(deduction)
```

Production path always calls `finalize()` last so this guard is defensive. Regression test `test_post_finalize_deduction_is_discarded` pins both the discard and the WARNING log.

**I-3 — `_safe_url` allowed `"` injection in HTML email href attributes**

`bob/report_markdown.py:_inline_format()` (lines 446-468) html-escapes text first (with default `quote=False`), then re-substitutes `[label](url)` into `<a href="url">label</a>`. The URL is the second regex group — already html-escaped, but only with `quote=False`, so `"` and `'` stayed raw. `_safe_url(url)` (line 436) only checked the URL scheme prefix and returned the URL unmodified into attribute context.

Attack chain: a crafted markdown link in user-controllable text (e.g. a malicious `services.d/*.json` plugin label, or a translated string with markdown in it):
```
[label](https://x.com" onclick="alert(1))
```

After `html.escape()` the URL becomes `https://x.com&quot; onclick=&quot;alert(1)` (only `&` is escaped because `quote=False` leaves `"` alone). Hmm — actually with default Python `html.escape`, `"` is converted to `&quot;` only when `quote=True`. With `quote=False` (the default) `"` stays raw → that's the vector. The URL with raw `"` lands in `href="…"` → attribute breakout → JavaScript injection.

Fix: `_safe_url` now does `html.escape(url, quote=True)` to encode any `"`/`'`/`<`/`>` left in the URL. Re-escape is safe (double-escape produces `&amp;quot;` which browsers decode once back to `&quot;` — a literal in the URL value, not active syntax).

New test file `tests/test_report_markdown_safety.py` with 9 regression assertions (URL passthrough, scheme rejection, double-quote escape, single-quote escape, angle-bracket escape, full-pipeline attack-string test).

Realistic attack surface is narrow (the email HTML body is rendered in user mail clients; the only user-controllable strings reaching `_inline_format` are translated locale strings and plugin-defined service labels). But the fix is cheap and the email report is now XSS-safe-by-construction.

**I-4 — `sysinfo._PRIVATE_IPV4_RE` brittle + Python 3.12+ would have broken stdlib switch**

Two problems compounded:
1. The call site at `bob/sysinfo.py:192` did `re.search(r"via\s+" + _PRIVATE_IPV4_RE.pattern.removeprefix("^"), result.stdout)` — manipulating a compiled pattern's `.pattern` attribute via string concatenation. Drops the original compile flags.
2. A naive switch to stdlib's `ipaddress.IPv4Address.is_private` would break on Python 3.12.4+: the definition of `is_private` widened to include documentation/reserved ranges (`192.0.0.0/29`, `192.0.2.0/24`, `198.51.100.0/24`, **`203.0.113.0/24`**, `198.18.0.0/15`, etc.). Tests using documentation IPs (`tests/test_sysinfo.py` uses `203.0.113.5` as a "public" example) would suddenly classify them as "local". This was caught only after the first refactor attempt failed.

Final fix: explicit `_PRIVATE_IPV4_NETS` + `_PRIVATE_IPV6_NETS` tuples of `ipaddress.ip_network` objects. Helpers `_is_private_or_loopback_ipv4()` / `_is_private_or_loopback_ipv6()` use `addr in net` membership. Covers:
- IPv4: RFC 1918 (10/8, 172.16/12, 192.168/16), loopback (127/8), link-local (169.254/16), CGNAT (100.64/10)
- IPv6: loopback (::1/128), link-local (fe80::/10), ULA (fc00::/7)

Documentation/reserved ranges stay "public" so `detect_network_context()` correctly identifies them as needing a public IP lookup.

### Minor cleanups (11)

| # | Fix | Files affected |
|---|---|---|
| **M-1** | Email regex unified via `bob.config._EMAIL_RE` (was duplicated as module-level + inline literal × 3 sites) | `bob/cron.py` |
| **M-2** | `bob/watch.py:_NullReport` removed → use `bob.report.NullReport` (canonical Report Protocol introduced in v0.5.0 #10). Old 5-line ad-hoc `__getattr__` magic was exactly the kind of duck-typed drift the Protocol introduction was meant to prevent. | `bob/watch.py`, `tests/test_watch.py` |
| **M-3** | 3 dead locale keys removed: `_meta.lang`, `_meta.version` (manifest metadata for a non-existent tool), `ignored.hint` (test-only, never wired into production display). | `bob/locales/{en,fr}.json`, `tests/test_ignore.py` |
| **M-4** | `corr.fully_blind` rule had `all_of={"firewall.logging_off", "fail2ban.not_installed"}` — required `not_installed` but ignored `fail2ban.service_inactive`. Sibling rule `corr.stale_unmonitored` already accepts both via `any_of`. Widened to fire when firewall is blind AND any detection layer (fail2ban or auditd, in either state) is blind. | `bob/correlation.py`, `tests/test_correlation.py` |
| **M-7** | Extract `_has_actionable_findings()` helper + `_TRANSPARENCY_KEYS` frozenset in `updates.py`. The inline `any(f.key != "updates.apt_cache_age" for f in result.findings)` filter was fragile — adding a second transparency INFO would silently change "all clear" semantics. The helper + frozenset future-proofs. | `bob/checks/updates.py` |
| **M-8** | Comment-only — clarifies why `_parse_config_file` stops at Match blocks AND silently skips subsequent `Include` directives. Intentional defensive choice (modelling conditional Match context safely is out of scope); the `_match_block=True` flag surfaces this to the user via the existing `ssh.match_block` INFO. | `bob/checks/ssh.py` |
| **M-9** | Comment-only — clarifies `ListeningPort.process`/`iface` empty fields mean "unknown" (when `ss -p` lacks privilege or is unavailable), not "no process". `is_all_interfaces` already accounts for this. | `bob/checks/ports.py` |
| **M-10** | `apply_cron_schedule` regex tightened: first field anchor changed from `^\S+` to `^[0-9*,\-/]\S*` (cron-token shape). Comment lines starting with `#` no longer match — previously a commented `# 0 3 * * * root /usr/bin/legacy-bob` would be silently rewritten. | `bob/cron.py`, `tests/test_cron.py` |
| **M-11** | `services_state.service_inactive` cmd contained `&& sudo journalctl …` — same shell-op rejection as C-2. Dropped the journalctl from the cmd (it's diagnostic, not part of the restart fix) and moved the suggestion to `note=` for guidance. | `bob/checks/services_state.py` |

### M-6 (separate commit) — `Optional[X]` / `List[X]` → `X | None` / `list[X]`

Pure mechanical sweep across 18 modules. Python 3.10+ syntax (project minimum). Already used in newer modules introduced during v0.5.x. This unifies the codebase on one form.

Isolated commit for two reasons:
1. **Revert safety** — if a mechanical search-and-replace introduces a typo (e.g. an `Optional[X]` inside a quoted docstring incorrectly converted), the cosmetic commit can be reverted without losing the Wave 1-3 bug fixes.
2. **Review hygiene** — bug fixes and cosmetic typing changes have different review concerns. Bundling them in one commit muddies the diff.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4545 passed in ~7s
```

**4538 → 4545 (+7).** New tests:
- `tests/test_cron.py::test_preserves_script_executable_mode` (C-1)
- `tests/test_explain.py::test_services_state_alias_routes_to_canonical` (C-4)
- `tests/test_scoring.py::test_post_finalize_deduction_is_discarded` (I-2)
- `tests/test_report_markdown_safety.py` — new file with 9 regression tests (I-3)
- `tests/test_correlation.py::test_fires_with_only_fail2ban_inactive` + `test_does_not_fire_when_firewall_logging_present` (M-4)
- `tests/test_cron.py::test_comment_line_with_root_token_not_modified` (M-10)

Tests removed:
- `tests/test_watch.py::TestNullReportIsolation` (5 tests — obsolete `__getattr__` magic from old `_NullReport`)
- `tests/test_watch.py::TestNullReport::test_any_method_returns_none` + `test_attribute_access_returns_callable` (2 tests — same reason)
- `tests/test_ignore.py::test_hint_key_en` (1 test — locale key deleted)

Tests renamed: `test_nature_is_action` → `test_nature_is_improvement` (× 2 in `tests/test_password_policy.py`).

### Compatibility

- **JSON contract**: `schema_version="1"` and the 116 EXPLAIN_KEYS unchanged. C-4 uses `EXPLAIN_KEY_ALIASES` (additive) — JSON output keys preserved; `--explain` routes via alias.
- **Per-domain score**: unchanged. Global score on dev host (so6desktop): 8/10 → 8/10. The score *display* shifts slightly: on hosts without `pam_pwquality`, the password_policy finding moves from the "À corriger" block (action) to "Améliorations possibles" (improvement). Visual change, not score change.
- **Wire output diff**: visible only on hosts hitting the demoted-to-improvement findings (password_policy.no_quality_module + .weak_minlen, services_state.service_inactive — the latter only changes the `cmd` shape, not nature). All other hosts see identical output.
- **External API**: no breaking change. `_atomic_write` (now takes `mode=` kwarg) and `EXPLAIN_KEY_ALIASES` (now has one entry) are additive.
- **i18n**: 3 locale keys removed (verified via locale-coverage AST scan + manual `grep`).

### Where v0.5.5 sits in the v0.5.x line

This is a **maintenance release** for the v0.5.x branch, post-cycle hardening. The 5-release refactor branch (v0.5.0 → v0.5.4) closed on 2026-05-23 with the 13/15 audit findings shipped + 2 splits deferred to v0.6.0. v0.5.5 addresses a separate 19-finding audit focused on **hardening dimensions** (real bugs, security smells, code health) rather than structural refactoring.

The v0.5.x line is committed to stay contract-preserving. Deferrals for v0.6.0 include #13 (ssh.py split, 1324 LoC), #14 (cron.py split, 1224 LoC), and any breaking-change cleanups the next audit cycle surfaces.

---

## [v0.5.4] — 2026-05-23

**Refactor v0.5.x — Phase 5 of 5 (final, closes the v0.5.x audit).** Three audit findings closed (`#6`, `#9`, `#15b`), one user-requested metier feature (cache APT option C), two findings (`#13` ssh.py split, `#14` cron.py split) explicitly deferred to v0.6.0. See `CHANGELOG.md` for the per-finding detail. This `CHANGELOG_FULL.md` entry mirrors that content and adds the v0.5.x branch closure notes.

### v0.5.x branch summary (Phase 1 → 5)

| Phase | Version | Date | Headline | Net LoC vs prior |
|---|---|---|---|---|
| 1 | v0.5.0 | 2026-05-21 | Open the branch — 6 helpers + cron coverage (+39 tests) + 1 latent bug fix | additive |
| 2 | v0.5.1 | 2026-05-22 | `warn_with_deduction()` — 120 sites in 27 files | **−519** |
| 3 | v0.5.2 | 2026-05-22 | `_BAD_DIRECTIVES` table + `_sec()` callbacks | +27 |
| 4 | v0.5.3 | 2026-05-22 | `_LEVEL_DISPATCH` + summary helpers + `log_data` removal | +40 |
| 5 | **v0.5.4** | **2026-05-23** | `prompt_wizard` + sunset + `_PREFIX_TO_DOMAIN` + cache APT C | +49 |
| **Total** | — | — | **13/15 audit findings + 1 metier feature + sunset + 1 deprecation** | **≈ −350 LoC vs v0.4.8** |

The v0.5.x branch shipped over **5 releases on 2 calendar days** (2026-05-21 to 2026-05-22). All five releases tested cross-distro on 5 VMs (Linux Mint 22.3 prod + Mint+DDNS, Debian 13 trixie, Kali Rolling, Ubuntu 26.04 LTS) with zero regression observed. Wire output preserved bit-for-bit through Phases 1–4; Phase 5 introduces 2 intentional wire-visible changes (cache APT INFO line, per-domain score re-bucketing) documented above.

### #6 — `prompt_wizard()` helper for plain-text wizards

`bob/_tty.py` exposes a new `prompt_wizard(label, *, default="")` helper that wraps `input()` with the wizard-step boilerplate every plain-text wizard had to repeat. The helper signature is intentionally minimal — no `t` / `key` arguments as the audit's `_prompt(t, key, validator)` suggested. Caller pre-formats the label (already translated) and handles validation downstream. This keeps the helper:

- **Idempotent** under `patch("builtins.input", ...)` — existing test mocks keep working.
- **Translation-agnostic** — usable from any context where a label is already in hand.
- **Composable** — validation lives at the call site so the helper doesn't carry retry policy.

```python
def prompt_wizard(label: str, *, default: str = "") -> "str | None":
    """Plain-text wizard prompt with uniform cancel + default handling.

    Use ``label="  > "`` when the question has already been printed via
    :func:`print` (multi-line wizards). Use a full inline label
    (``"  Foo [{default}]: "``) for single-line prompts.

    Returns:
        ``None`` — user typed ``q`` or ``quit`` (case-insensitive).
        ``str``  — trimmed input, or ``default`` when Enter was pressed bare.
    """
    raw = input(label).strip()
    if raw.lower() in ("q", "quit"):
        return None
    return raw or default
```

Migration in `bob/cron.py`:

- **Install wizard** (`_run_install_cron_plain`, lines 470-595): 5 `input()` sites → 5 `prompt_wizard()` calls. The pre-Phase-5 boilerplate (`.strip()` + `.lower() in ("q","quit")` + default fallback) was 4-5 lines per site; post-migration is 2-3 lines per site (helper call + `None`-check).
- **Edit wizard** (`edit_cron_schedule`, lines 929-1009): 4 `input()` sites → 4 `prompt_wizard()` calls. The schedule-type prompt keeps `read_line()` (raw-mode, Esc-aware) — intentional asymmetry; the edit wizard inherited raw-mode menu navigation from its curses-adjacent context, but the rest of its steps reuse the plain-wizard helper for consistency.

Sites NOT migrated (different semantic):

- `prompt_emails` y/n confirmations (4 sites in lines 414, 428, 432): require explicit `y` vs anything-else, no default-on-Enter.
- `_run_install_cron_plain` overwrite confirm (line 589): same y/n pattern.
- `manage_cron.email_store_enter` (line 708): standalone name-entry without cancel.
- `manage_logs.prompt_path()`: already a higher-level wrapper around `input()` with path-specific handling.

After migration `cron.py` has 10 raw `input()` sites remaining (down from 20+), all y/n confirmations or specialized prompts.

### #9 — `UFW_AUDIT_SHARE` env var deprecation (REMOVED in v0.6.0)

History: BOB was originally named "UFW Audit" before v0.1.0. The share-dir env variable kept the old name despite the rename. v0.4.2 introduced `BOB_SHARE` as the documented primary; `UFW_AUDIT_SHARE` remained accepted with an INFO-level diagnostic for packagers using legacy installer scripts.

v0.5.4 commits the deprecation timeline:

| Change | Before (v0.5.3) | After (v0.5.4) |
|---|---|---|
| Log level | `logger.info(...)` | `logger.warning(...)` |
| Message | "the legacy name will be dropped in a future major release" | "DEPRECATED since v0.5.4, will be REMOVED in v0.6.0" |
| Module docstring | "Will be dropped in a future major release." | "Deprecated since v0.5.4 and will be removed in v0.6.0." |

`SECURITY.md` already lists v0.5.x as the current supported line and v0.4.x as end-of-life (updated in v0.5.3). Packagers using `UFW_AUDIT_SHARE` see the deprecation warning on every BOB run and have a clear timeline before v0.6.0.

### #15b — Explicit `_PREFIX_TO_DOMAIN` mapping for 3 v0.4.x catch-all entries

Background: v0.5.0's `test_domain_scores_mapping_complete.py` (#15a) introduced an AST-scan test that asserts every emitted finding-key prefix is either explicit in `_PREFIX_TO_DOMAIN` or whitelisted in `_CATCH_ALL_BY_DESIGN`. The whitelist captured the v0.4.x state where certain prefixes silently fell through to the `firewall` catch-all without a clean domain fit — flagged for review in #15b (Phase 5).

The Phase 5 review picked 3 prefixes for explicit re-attribution:

```python
# bob/domain_scores.py:_PREFIX_TO_DOMAIN now contains:
"fail2ban":         "ssh",
"virt":             "hardening",
"docker_audit":     "hardening",
```

**Why these three:**

- `fail2ban` → `ssh`: Fail2ban's most common (and default-bundled) jail is `sshd`. The `fail2ban.*` findings in `bob/checks/fail2ban.py` are dominated by SSH-bruteforce protection signals. Bucketing them under `ssh` aligns score impact with the configured jails.
- `virt` → `hardening`: The single `virt.bypass_risk` finding in `bob/checks/virtualization.py` catches libvirt/KVM bridges (virbr0 etc.) inserting iptables rules that bypass UFW's FORWARD chain. This is a *kernel + iptables stack* concern — closer to system hardening than firewall config.
- `docker_audit` → `hardening`: `bob/checks/docker.py` audits container *configuration* (daemon.json `iptables=false`, running container hardening) rather than the firewall-level docker network exposure (which lives under the `docker` prefix and stays in firewall). Re-bucketing aligns the prefix split between the two concerns.

**Why NOT `smtp` / `desktop_apps`:**

- `smtp`: Local SMTP exposure (Postfix/Exim listening on 127.0.0.1:25) is genuinely an attack-surface question. Firewall is the closest fit; no candidate domain promises better.
- `desktop_apps`: INFO-only inventory (lists detected desktop processes — ExpressVPN, kDrive, Brave, etc.). No scoring impact. Re-bucketing it for cleanliness has no payoff — kept in catch-all with explicit justification in the test whitelist.

**Score impact** (per-domain on hosts emitting these prefixes; global score unchanged):

- Hosts with `virt.bypass_risk` WARN (KVM/libvirt installed, dev workstations) — see `Pare-feu & Services` go up by 1 point, `Durcissement` go down by 1 point.
- Hosts with `fail2ban.*` findings (rare in practice; most fail2ban findings are OK-level promoting the SSH domain) — re-promotion to `ssh` domain.
- Hosts with `docker_audit.*` findings (Docker installed + audit findings, e.g. dev workstations with Docker daemon) — moved to `hardening`.

Test changes in `tests/test_domain_scores_mapping_complete.py`:

- 3 entries removed from `_CATCH_ALL_BY_DESIGN`: `fail2ban`, `virt`, `docker_audit`.
- Remaining 3 entries (`smtp`, `desktop_apps`, `prerequisites`) get refreshed justifications — they no longer point to a future "review in v0.5.4" since #15b is now closed.
- The block comment above `_CATCH_ALL_BY_DESIGN` updated to reflect that the v0.4.x catch-all set has been reviewed (no more candidates flagged for tightening).

### Cache APT option C — Permanent INFO on cache age (user-requested metier feature)

**Context (from v0.5.3 terrain test).** During cross-distro testing on 2026-05-22, the Ubuntu 26.04 LTS VM (`so6ubuntutest`) reported "Les paquets système sont à jour" in BOB's audit, but a manual `sudo apt update` ran immediately after revealed 17 packages pending (including 8 LTS security updates: libgnutls30t64, bind9, openvpn, rsync, etc.). Investigation showed BOB's `apt-get -s dist-upgrade` simulation was correctly reading the local APT cache — but the cache was 3-5 days old (below the 7-day stale threshold that triggers a WARNING) and had not been synced with upstream where security advisories had landed in the meantime.

The existing `apt_cache_stale` WARNING (>7 days) covered the obviously-stale case but left the silent "fresh-enough but not zero" range unobservable. User picked "option C" from a 4-option proposal: *always* emit an INFO with the cache age when the verdict is "all clear", giving permanent transparency about cache freshness.

**Implementation.** Inserted into `bob/checks/updates.py:check_updates()` between the existing pending-update checks and the "all clear" OK emission:

```python
# --- APT cache age (transparency when no findings security/regular) ----
# The "all clear" verdict relies on the local APT cache state. Surface
# the cache age so the user knows whether they are looking at a fresh
# read or a stale snapshot. The stale-threshold warning above already
# handles the > 7-day case — this INFO covers the "fresh-enough but
# not zero" range that the threshold leaves silent.
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

# --- All clear ----------------------------------------------------------
# findings can be non-empty here from the cache-age INFO above; the
# ok finding is only emitted when *no* signal at all was produced.
if not any(f.key != "updates.apt_cache_age" for f in result.findings):
    result.ok(
        message=_t("updates.ok"),
        key="updates.ok",
    )
```

Subtlety: the "all clear" `result.ok(...)` check changed from `not result.findings` (any findings present skips OK) to `not any(f.key != "updates.apt_cache_age" for f in result.findings)`. This preserves the OK emission when the only finding present is the new cache-age INFO. Without the change, hosts hitting cache APT C would lose the "Les paquets système sont à jour" OK line.

**Locale keys** added in `bob/locales/en.json` + `bob/locales/fr.json`:

- `updates.apt_cache_age` (EN): "APT cache age: {days} day(s) — run `sudo apt update` for a fresher read"
- `updates.apt_cache_age` (FR): "Âge du cache APT : {days} jour(s) — `sudo apt update` pour une lecture plus fraîche"
- `updates.apt_cache_age_detail`: 1-paragraph explanation reminding BOB is read-only and pointing to unattended-upgrades for automated freshness.

**When the INFO fires:**

| Condition | INFO emitted? |
|---|---|
| Non-Debian system (`apt` unavailable) | No (`updates.no_apt` path) |
| Security packages pending | No (security WARN is the primary signal) |
| Regular packages pending | No (regular INFO is the primary signal) |
| Cache age unreadable (`/var/cache/apt/pkgcache.bin` missing) | No |
| Cache age ≥ 7 days | No (`apt_cache_stale` WARN already covers it) |
| Cache age 0–6 days AND no pending updates | **Yes** (the option C target case) |

Terrain validation: on the dev host (so6desktop) with 4 security packages pending, the INFO is correctly suppressed (security WARN is the primary signal). On a hypothetical idle Ubuntu LTS box that's freshly synced, the INFO would read "Âge du cache APT : 0 jour(s) — `sudo apt update` pour une lecture plus fraîche" — transparency-by-default.

### Deferrals: `#13` (ssh.py split) and `#14` (cron.py split) → v0.6.0

The v0.5.x audit (2026-05-21) flagged both files as candidates for split:

```
bob/checks/ssh.py:  1387 LoC at v0.4.8 → 1268 after #1 (Phase 2) → 1324 after #4 (Phase 3) → 1324 at v0.5.4 entry
bob/cron.py:        1223 LoC at audit  → 1223 after #6 (Phase 5)  → 1223 at v0.5.4 entry
```

The audit's prediction was that Phases 2 + 3 would shrink ssh.py below 1000 LoC, making the split unnecessary. The actual end-state is 1324 LoC — Phase 2 (`warn_with_deduction`) cut 119 lines but Phase 3 (`_BAD_DIRECTIVES`) added 56 (table verbosity offsets the imperative shrinkage).

**Decision: defer both to v0.6.0.** Per [`feedback_conservative_refactor`](memory) — splitting a file is medium-risk for marginal reader gain. In a contract-preserving release line (v0.5.x), the risk-adjusted value is negative. v0.6.0 is a major version bump that already perturbs import paths and is the natural place for structural shifts.

`#15a` test (added in v0.5.0) pins all current key prefixes; whatever the v0.6.0 split decision is, the test catches unhandled prefixes at PR time before they regress.

### Net diff

| File | Delta | Notes |
|---|---|---|
| `bob/_tty.py` | +24 | `prompt_wizard()` helper + module docstring rewrite |
| `bob/cron.py` | +1 | 10 `input()` sites migrated; net minimal because helper signature is similar in line count to inline boilerplate |
| `bob/checks/updates.py` | +20 | Cache APT option C logic + extensive in-line commentary |
| `bob/domain_scores.py` | +10 | 3 new entries in `_PREFIX_TO_DOMAIN` + 6-line comment block citing #15b |
| `bob/_paths.py` | +5 | log level bump + DEPRECATED message + docstring update |
| `bob/locales/{en,fr}.json` | +4 | 2 new keys × 2 locales |
| `tests/test_domain_scores_mapping_complete.py` | −6 | 3 entries removed from `_CATCH_ALL_BY_DESIGN` + simplified justifications |

**Net +49 LoC across 12 code files.** Like Phases 2–4, the LoC delta on its own undersells the structural win: `prompt_wizard` removes ~25 lines of boilerplate per consumer site (5 sites × 5 lines = ~25 line gain net of helper signature cost); cache APT C is a +20 *new feature* (not a refactor saving lines); the `_PREFIX_TO_DOMAIN` change is +10 for a meaningful semantic improvement.

### Garde-fou observable diff

`sudo python3 -m bob -v -d --french` audit on the dev host (so6desktop) at v0.5.4-pre-bump:

- Score global: **8/10** (unchanged from v0.5.3 baseline — confirms re-bucketing is global-score-neutral).
- New per-domain score breakdown observed:
  - SSH 10/10 → 7/10 (3 SSH WARNs now correctly attributed to ssh domain at full weight)
  - Sécurité Samba 10/10 (new: Samba domain now surfaces with its OK findings)
  - Mises à jour 8/10 → 7/10
  - Durcissement 6/10 → 5/10
  - Santé des disques 9/10 → 10/10
  - Pare-feu & Services 3/10 → 10/10 (#15b moved `virt.bypass_risk` and other catch-all entries out of firewall)
- Section MISES À JOUR SYSTÈME: cache APT INFO **suppressed** (4 security packages pending → security WARN is the primary signal, INFO C correctly silenced).
- Pas de WARNING `UFW_AUDIT_SHARE` (env var not set on the dev host).

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in ~6s
```

**4538 → 4538 (unchanged).** Phase 5 is contract-preserving.

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS, the 34 filterable sections — **unchanged**.
- **Wire output**: 1 new INFO line on idle hosts with fresh-but-not-zero cache (cache APT C). Per-domain reshuffle on hosts emitting `fail2ban.*` / `virt.*` / `docker_audit.*`. **Global score unchanged.**
- **External API**: no breaking change. `prompt_wizard` is a new public-ish symbol in `bob._tty`; the existing `read_line` keeps working as before.
- **i18n**: 2 new locale keys (`updates.apt_cache_age` + `..._detail`) in EN + FR.
- **Plugin contract**: unchanged. Plugin authors writing custom checks are unaffected by any of Phase 5's changes.

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

The dispatch dict is built inside `display_result()` rather than at module level — `print_ok` / `print_warn` / `print_alert` / `print_info` are deferred imports (the existing pattern to avoid the `bob.output ↔ bob.display` circular dependency). Building it per-call is trivially cheap (4 entries) and keeps lazy-import discipline.

### #12 — `print_audit_summary` split into 3 helpers

The 142-line `print_audit_summary()` mixed three responsibilities (header lines, finding block lines, breakdown lines) with an inner `_add_finding_lines()` closure. Now:

- `_summary_header_lines(engine, network_context, config, t, profile_name, prev_score)` — score/level/network/profile/target lines + the score trend arrow.
- `_summary_findings_lines(engine, t, inner)` — the action + improvement blocks (with the disclaimer line).
- `_summary_breakdown_lines(engine, t, inner)` — deductions + cap_info.
- `_add_finding_lines(icon_prefix, item, inner)` — promoted from inner closure to module-level helper, returns a list of `(content, val)` tuples instead of mutating the enclosing `lines` list.

`print_audit_summary` becomes a 3-line `lines.extend(...)` assembler, then `print_summary_box(lines)`, then the footer (verdict line + implicit_svcs + scope lines + `report.write_summary()`).

One side-fix: the original `report.write_summary(score=score, risk_level=level_str, network_context=ctx_str, ...)` referenced local variables that were no longer in scope after the header extraction. Replaced with direct expressions on `engine.score` and re-evaluated `t(f"scoring.level.{engine.level.value}")` / `t(f"scoring.context.{network_context}")`. Caught by `TestScoreTrend` + `TestDuplicateFindings` + `TestExplainHintAbsent` which exercise `print_audit_summary` end-to-end (8 failures became 0 after the fix).

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

The `display_log_results()` early-exit path `if log_report is None: display_result(...)` preserves the v0.5.2 behaviour where an empty/missing log result falls back to generic finding display — wire output is unchanged when no log file exists.

### Net diff

| File | Delta | Notes |
|---|---|---|
| `bob/display.py` | +23 | `_LevelTraits` + `_emit_finding_body` + 3 summary helpers + `_add_finding_lines` module-level |
| `bob/checks/logs.py` | +19 | `LogReportData` dataclass + tuple return + docstring update |
| `bob/runner.py` | 0 | 1 line migrated to tuple unpack |
| `bob/scoring.py` | −1 | `log_data` field removed |
| `tests/test_logs.py` + `tests/test_degraded.py` | +3 | tuple unpack + 3 renamed tests |

**Net +40 LoC.** Like Phases 2–3, the LoC delta on its own undersells the structural win: the 4-branch display cascade becomes a single declarative loop, the 142-line summary function becomes a 3-line assembler, and the `dict | None` escape hatch is replaced by a typed frozen dataclass.

### #13 / #14 / #15b still deferred to Phase 5

ssh.py reaches 1324 LoC at v0.5.3 entry, unchanged from v0.5.2. cron.py + `_PREFIX_TO_DOMAIN` re-attribution untouched in Phase 4. All three decisions stay queued for v0.5.4 with explicit `wc -l` re-check.

### Garde-fou observable diff

`sudo python3 -m bob -v --french -n > /tmp/bob_baseline_v052_stdout.txt` and `sudo python3 -m bob --format=json --french > /tmp/bob_baseline_v052.json` snapshots captured before Phase 4 implementation. Two intermediate diffs were taken: after #5 + #12 and after #8.

| Diff | Stdout deltas | JSON deltas |
|---|---|---|
| Post-#5+#12 vs baseline | timestamp (+8 min) + recurrence counters (+2 audits) + UFW block totals (+14 over 7-day window) | timestamp only |
| Post-#8 vs baseline | timestamp (+4 h) + VSCode ephemeral TCP ports (PID restart between runs) + UFW block totals (+452) + recurrence (+4) | timestamp + rkhunter age (39d → 40d) |

All deltas confined to state drift (timestamps, log accumulation, process-restart artefacts, age counters). **Zero structural change to the rendered audit, the JSON tree, or the score breakdown.** Score on the dev host: 8/10 in both v0.5.2 and v0.5.3, identical breakdown (-1 pwquality, -1 virt.bypass_risk, -1 ssh.x11_forwarding, -1 ssh.allow_tcp_forwarding, etc.).

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in ~6s
```

**4538 → 4538 (unchanged).** Phase 4 is a pure structural refactor.

### Compatibility

- **JSON contract**: `schema_version="1"`, the 116 EXPLAIN_KEYS, the 34 filterable sections — **unchanged**.
- **Wire output**: bit-identical to v0.5.2.
- **Per-domain score**: unchanged.
- **External API**: no breaking change. `LogReportData` is a new public-ish symbol on `bob.checks.logs` but the only consumer is `bob.runner` → `bob.display`. Plugin authors writing custom checks were never expected to set `CheckResult.log_data` — that field was UFW-logs internal scratch space.
- **i18n**: no locale key changes.

---

## [v0.5.2] — 2026-05-22

**Refactor v0.5.x — Phase 3 of 5.** Two audit findings: **#4 SSH directive table** and **#3 `runner._sec` callbacks extension**. Zero behaviour change — 4538/4538 tests unchanged, wire output bit-identical to v0.5.1.

### #4 — Declarative `_BAD_DIRECTIVES` table for sshd_config

**Problem.** `_check_sshd_config` had ~9 near-identical if-blocks: read directive from `cfg.get()`, check value against a "bad" enum, emit finding + matching deduction with fixed points/i18n-key/level. The Phase 2 helper `warn_with_deduction` already collapsed each pair to a single call, but the *cascade of 9 directives* was still 9 separate imperative blocks.

**Fix.** New declarative table + frozen dataclass + helper function in `bob/checks/ssh.py`:

```python
@dataclass(frozen=True)
class _BadDirective:
    """Declarative rule for one sshd_config directive."""
    name: str            # lowercase directive key in cfg dict
    default: str         # value returned by cfg.get() when directive is missing
    level: str           # "warn" or "alert"
    key: str             # i18n key for finding message + deduction reason
    points: int          # deduction amount
    bad_values: tuple[str, ...] = ()    # values that trigger the finding
    safe_values: tuple[str, ...] = ()   # alternative: anything not in this set is bad
    nature: str = ""     # "" → defaults via warn/alert level
    detail_key: str = "" # optional separate i18n key for detail=

    def __post_init__(self) -> None:
        if bool(self.bad_values) == bool(self.safe_values):
            raise ValueError(
                f"_BadDirective({self.name!r}): exactly one of bad_values "
                f"or safe_values must be set"
            )
        if self.level not in ("warn", "alert"):
            raise ValueError(f"_BadDirective({self.name!r}): level must be 'warn' or 'alert'")

    def is_bad(self, value: str) -> bool:
        v = value.lower()
        if self.bad_values:
            return v in self.bad_values
        return v not in self.safe_values
```

The mutual-exclusion check in `__post_init__` catches programming errors at class instantiation (frozen `dataclass` is created once at module load — any malformed entry crashes startup, not first audit).

`_apply_bad_directive(rule, cfg, result, _t) -> bool` reads the directive value via `cfg.get(rule.name, rule.default)`, invokes `rule.is_bad(value)`, and emits the finding+deduction via the appropriate `warn_with_deduction` / `alert_with_deduction` helper (Phase 2 API).

**Migrated directives (8)** — table entries:

| Directive | `bad_values` / `safe_values` | Level | Points | Notes |
|---|---|---|---|---|
| `PermitEmptyPasswords` | bad: `("yes",)` | alert | 5 | nature="improvement" |
| `X11Forwarding` | bad: `("yes",)` | warn | 1 | |
| `IgnoreRhosts` | bad: `("no",)` | warn | 2 | |
| `HostbasedAuthentication` | bad: `("yes",)` | alert | 3 | nature="improvement" |
| `PermitUserEnvironment` | bad: `("yes",)` | warn | 1 | |
| `StrictModes` | bad: `("no",)` | warn | 2 | |
| `AllowTcpForwarding` | safe: `("no", "local")` | warn | 1 | `"local"` is acceptable (more restrictive than `"yes"`) — uses `safe_values` style |
| `PubkeyAuthentication` | bad: `("no",)` | alert | 3 | nature="improvement", detail_key |

`AllowTcpForwarding` is the only entry using `safe_values` — the alternative would be enumerating all bad values (`"yes"`, etc.) but `"no"` and `"local"` are the explicit acceptable values per the OpenSSH docs.

**Sites kept imperative (5+ patterns)** — these don't fit the enum-style table:

- **`PermitRootLogin`**: 4-way branch. `"yes"` → ALERT (-3pts), `"no"` → OK (with specific message), `"prohibit-password"` or `"forced-commands-only"` → OK (different message with `value=` template var), anything else → INFO.
- **`PasswordAuthentication`**: depends on the orchestrator-level `ssh_exposed` flag. When SSH is exposed (public network or `allow` policy), WARN + deduction. When SSH is LAN-only, downgrade to INFO with a context-aware message.
- **`MaxAuthTries`**: integer threshold (`>3`). Not enum-style; the message template var (`value=N`) is the observed integer.
- **`LoginGraceTime`**: integer threshold (`>60s`) but INFO-only — no deduction.
- **`AllowUsers/AllowGroups`**: detects *absence* of any restriction directive. INFO-only.
- **Match block**: INFO when the parser detected sub-config blocks (their content is policy-dependent and out of scope).
- **Weak Ciphers/MACs/KexAlgorithms**: handled by `_check_weak_algo(cfg, result, _t, name, weak_set, t_key, param, points)`. The "bad value" is a *set intersection* between the configured algorithm list and the weak-algorithms set — different shape than `_BadDirective`.

**Result.** `_check_sshd_config` body shrinks from ~180 LoC to ~50 LoC (~70% reduction in function size). The table + dataclass + helper add ~130 LoC at the top of the file. Net `ssh.py`: +56 LoC.

**Audit-vs-reality.** The original audit estimated #4 would save -150 LoC. The reality is +56 net. The discrepancy is from:
- Python dataclass verbosity (14 LoC for `_BadDirective` + 16 LoC of docstring/comments)
- 8 table entries × ~7 LoC each = 56 LoC for the table
- `_apply_bad_directive` helper: 18 LoC
- `__post_init__` validation: 8 LoC
- Total table infrastructure: ~130 LoC

The *win is structural*, not LoC-economical: adding a new "bad sshd directive" check now requires adding 1 entry to `_BAD_DIRECTIVES`, not duplicating an if-block. The drift class (forgetting `nature=` on a deduction, or copy-pasting a `key=` mismatch between finding and deduction) is now structurally impossible — the dataclass holds those values once.

---

### #3 — `runner._sec` extension with `skip_if=` and `post_display=` callbacks

**Problem.** The `_sec(section, snapshot, check_fn, **check_kwargs)` closure introduced in Phase 1 (v0.5.0) handled the canonical pattern: `print_section + write_section + check + apply_profile + engine.apply + display_result + print`. But 4 sections couldn't use it because they needed orthogonal extensions:

- **Snapshot-conditional gating**: `samba`, `docker_audit`, `desktop_apps` need to skip the entire section (no header printed, no check run) when the snapshot reports the underlying service is not installed/detected. The check is fast (just reads the snapshot), but emitting an empty section header is ugly.
- **Post-check display calls**: `disk` needs an additional `display_disk_partitions(snapshot, t, output)` call after the standard display. (Same shape applies to `ports_analysis`'s `display_ports_overview` but that block has additional cross-check dependencies and stays inline.)

Pre-v0.5.2, these 4 blocks were open-coded inline, each ~8 LoC duplicating the `_sec` body.

**Fix.** Two keyword-only callback parameters added to `_sec`:

```python
def _sec(
    section: str,
    snapshot,
    check_fn,
    *,
    skip_if=None,                # Callable[[snapshot], bool]
    post_display=None,           # Callable[[snapshot, result], None]
    **check_kwargs,
) -> None:
    """Run one audit section.
    ...
    Args:
        section: section key (drives header text + `_section_enabled` gate
            via profile / `--check`).
        snapshot: pre-collected snapshot object (passed positionally to
            ``check_fn``).
        check_fn: pure check function returning a ``CheckResult``.
        skip_if: optional ``Callable[[snapshot], bool]`` — when truthy,
            the section is skipped without emitting the header (used for
            "if installed" / "if detected" gates that depend on the
            snapshot rather than the profile).
        post_display: optional ``Callable[[snapshot, result], None]``
            invoked after ``display_result`` (still inside the ``if not
            config.quiet`` block conceptually).
        **check_kwargs: forwarded to ``check_fn`` after ``snapshot`` and ``t``.
    """
    if not _section_enabled(section, config, profile):
        return
    if skip_if is not None and skip_if(snapshot):
        return
    emit_section(section)
    result = check_fn(snapshot, t=t, **check_kwargs)
    if profile is not None:
        apply_profile(result, profile)
    engine.apply(result)
    display_result(result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    if post_display is not None and not config.quiet:
        post_display(snapshot, result)
    if not config.quiet:
        print()
```

The `*,` separator forces both callbacks to be passed as kwargs — prevents positional-arg confusion at call sites. The existing 16+ `_sec(...)` call sites are unaffected (none used positional args after the 3rd).

**Migrated sites (4)**:

```python
# Before (8 lines):
if _section_enabled("samba", config, profile):
    samba_snapshot = SambaSnapshot.from_system()
    if samba_snapshot.installed:
        emit_section("samba")
        samba_result = check_samba(samba_snapshot, t=t)
        if profile is not None:
            apply_profile(samba_result, profile)
        engine.apply(samba_result)
        display_result(samba_result, report, config.verbose, ...)
        if not config.quiet:
            print()

# After (3 lines):
samba_snapshot = SambaSnapshot.from_system()
_sec("samba", samba_snapshot, check_samba,
     skip_if=lambda s: not s.installed)
```

```python
# disk before (with post-display call):
disk_snapshot = DiskSnapshot.from_system()
if _section_enabled("disk", config, profile):
    emit_section("disk")
    disk_result = check_disk(disk_snapshot, t=t)
    if profile is not None:
        apply_profile(disk_result, profile)
    engine.apply(disk_result)
    display_result(disk_result, report, config.verbose, ...)
    if not config.quiet:
        display_disk_partitions(disk_snapshot, t, output)
        print()

# disk after:
disk_snapshot = DiskSnapshot.from_system()
_sec("disk", disk_snapshot, check_disk,
     post_display=lambda snap, _r: display_disk_partitions(snap, t, output))
```

All 4 sites: `samba`, `docker_audit`, `desktop_apps`, `disk`. Net `runner.py`: **−29 LoC**.

**Sites NOT migrated** (legitimately complex):
- `services` block — needs cross-check dependencies (`audited_ports` flows out, `network_context` flows in), inline stays.
- `firewall` block — first check, sets up snapshot variables consumed by 5+ later checks.
- `rules` block — needs `ufw_numbered`, `ufw_verbose` cross-references.
- `ports_analysis` — receives `audited_ports` from the services block; has its own `display_ports_overview` post-call. Could be migrated with both callbacks but the cross-check coupling is tighter — kept inline.

---

### #13 (ssh.py split) — deferred to Phase 5

The audit prediction:
> Combined with #1, ssh.py descends below 1000 LoC → #13 (ssh.py split) becomes unnecessary.

Reality table:

| Stage | ssh.py LoC | Delta |
|---|---|---|
| v0.4.8 (before refactor v0.5.x) | 1387 | — |
| v0.5.0 (Phase 1) | 1387 | 0 (no SSH changes) |
| v0.5.1 (Phase 2 — #1) | 1268 | −119 |
| v0.5.2 (Phase 3 — #4) | 1324 | +56 |

ssh.py is still 1324 LoC, 32% above the 1000-LoC target. Per [conservative-refactor](memory), ssh.py split is medium-risk surgery (must preserve `from bob.checks.ssh import SSHSnapshot` imports across 122 tests, propagate `_check_*` sub-function visibility for tests). Decision deferred to **Phase 5 (v0.5.4)** alongside #14 (cron.py split) once final state is known. Both splits will be revisited together with #15b (`_PREFIX_TO_DOMAIN` re-attribution).

---

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in ~6s
```

**4538 → 4538 (unchanged).** Both #4 and #3 are pure structural refactors. The full `test_ssh.py` suite (122 tests) passed before, during, and after the `_BAD_DIRECTIVES` migration — the table produces bit-identical `Finding` and `Deduction` entries to the previous if-blocks.

### Field testing

Cross-distro coverage from v0.5.0/v0.5.1 (5 distros: Mint x2, Debian 13, Kali, Ubuntu 26.04 LTS) applies. v0.5.2 preserves wire output exactly — the recommended field test is `pipx upgrade bodyguard-of-bits && sudo bob -v -d` and verify the score, breakdown, and per-domain bars are bit-identical to v0.5.1 (modulo system state changes).

### Compatibility

- **JSON contract**: `schema_version="1"`, all 116 EXPLAIN_KEYS, all 34 filterable sections — **unchanged**.
- **CLI surface**: no flag added, no flag removed.
- **Per-domain score breakdown**: unchanged (same `_PREFIX_TO_DOMAIN`, same domain mapping for every emitted key).
- **Wire output**: bit-identical to v0.5.1.
- **External API**: no breaking change. `_BadDirective` and `_BAD_DIRECTIVES` are module-private; `_sec` signature extension is keyword-only (all existing call sites unaffected).
- **i18n**: zero locale key changes.

### Next phases

- **v0.5.3 (Phase 4)**: #5 (`display_result` LEVEL_DISPATCH table) + #12 (`print_audit_summary` extracted helpers) + #8 (remove `CheckResult.log_data` escape hatch). Medium-risk: observable layout changes.
- **v0.5.4 (Phase 5)**: #6 (cron wizard `_prompt` helper) + #9 (`UFW_AUDIT_SHARE` sunset) + final decisions on #13 (ssh.py split), #14 (cron.py split), #15b (`_PREFIX_TO_DOMAIN` re-attribution).

---

## [v0.5.1] — 2026-05-22

**Refactor v0.5.x — Phase 2 of 5.** The big LoC win. This release tackles **audit finding #1**: the paired `result.warn(...) + result.add_deduction(...)` idiom recurring ~130 times across `bob/checks/*.py`. After Phase 1 (v0.5.0) shipped low-risk additive findings + the cron coverage pass, Phase 2 collapses the dominant boilerplate pattern.

**Zero behaviour change.** Tests stay at 4538/4538 because the helper produces a `Finding` and a `Deduction` per call, bit-identical to the pre-migration 2-call sequence.

### New `CheckResult` API (additive — no breaking change)

Two methods added to `bob/scoring.py:CheckResult` (after the existing `warn`/`alert` shorthands):

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
) -> None:
    """Add a WARN finding and a matching deduction in one call.

    Collapses the paired `result.warn(...) + result.add_deduction(...)` idiom
    that recurs ~130 times across bob/checks/*.py. The same `key` and
    `template_vars` are used for both the finding and the deduction. The
    deduction `reason` defaults to `message` — pass `reason=` explicitly
    when the deduction string uses a different translation key (e.g.
    `ssh.host_key_dsa_reason` differs from `ssh.host_key_dsa`).
    """
    self.warn(message=message, detail=detail, nature=nature,
              cmd=cmd, cmd_type=cmd_type, note=note,
              key=key, template_vars=template_vars)
    self.add_deduction(
        reason=reason if reason is not None else message,
        points=points, context=context,
        key=key, template_vars=template_vars,
    )

def alert_with_deduction(self, ...) -> None:
    # Mirror, nature default = "action"
```

**Why keyword-only after `key`**: forcing `message=`, `points=`, etc. as keyword arguments prevents positional-arg confusion at call sites. The `key` positional slot makes the call site read like `result.warn_with_deduction(key="ssh.x11_forwarding", ...)` — the key being the most important identifier.

### Migration scope (120 sites in 27 files)

The migration was carried out in **6 waves**, ordered by file complexity (simplest first), with the full test suite re-run after each wave:

#### Wave 1 — single-site files (7 sites)
`backup.py`, `ddns.py`, `logs.py`, `memory.py`, `network_context.py`, `smtp.py`, `suid_audit.py`. Trivial swaps with `reason=` override where needed (`backup.no_backup_reason`, `logs.deduction.brute_force`, `smtp.exposed_reason`, `suid_audit.unexpected_suid_reason`).

#### Wave 2 — two-site files (16 sites)
`cron_audit.py` (2), `docker_audit.py` (2), `fail2ban.py` (2), `firmware.py` (2), `ipv6.py` (1 of 2), `kernel_modules.py` (2), `ntp.py` (2), `password_policy.py` (2), `ports.py` (1 of 2), `secure_boot.py` (2), `systemd_timers.py` (2), `umask.py` (2), `updates.py` (2), `user_accounts.py` (2 of 2).

#### Wave 3 — three-site files (15 sites)
`auditd.py` (3), `file_integrity.py` (3), `kernel_hardening.py` (3), `log_rotation.py` (3), `rootkit.py` (3). `ssl_certs.py` (3) intentionally skipped — all 3 sites use a capped `total_deduction` counter.

#### Wave 4 — 4-6 site files (29 sites)
`file_perms.py` (1 of 4), `firewall_stack.py` (4), `firewall.py` (4 of 6 — pilot), `disk.py` (5), `iptables_nftables.py` (5), `clamav.py` (5), `mac_policy.py` (5 of 6), `samba.py` (5 of 6).

#### Wave 5 — `hardening.py` (8 sites)
All sysctl-policy branches: rp_filter, accept_redirects, tcp_syncookies, accept_source_route, accept_redirects_v6, send_redirects, protected_hardlinks, protected_symlinks. All `points=1`, all `context="local"`, message==reason — the most uniform file of the migration.

#### Wave 6 — `ssh.py` (24 sites)
The biggest file (1387 LoC) and the most complex migration. Covers all sshd_config directives, host keys, the `_check_weak_algo` helper, `~/.ssh` dir, private keys (including the `_reason` suffix case), authorized_keys (DSA + weak RSA + duplicates), client config (StrictHostKeyChecking, UserKnownHostsFile, ForwardAgent), and known_hosts (deprecated key types). ssh.py shrunk by **−146 lines** (33% of all wave-6 LoC removed).

### Sites intentionally left as 2-call (13)

The migration was conservative — sites where the helper API doesn't fit were left untouched and documented:

| Pattern | Count | Files |
|---|---|---|
| Capped deduction (local counter `_deductions < CAP`) | 7 | `services_state.py` (1), `ssl_certs.py` (3), `file_perms.py` (2), `ipv6.py` (1) |
| Level branching (warn OR alert on a separate condition) | 4 | `services.py` (1), `ports.py` (1), `docker.py` (2) |
| Conditional `points = 0 or N` calculation | 1 | `docker.py:172-187` |
| Different `template_vars` between finding and reason | 1 | `firewall.py:_check_open_any` (`rule=clean` for finding, `rule=""` for deduction) |

The helper's `reason=` override handles the easier asymmetry case (different translation key, same template_vars). Different template_vars is a rarer pattern that doesn't justify a second override parameter.

### `reason=` override usage

Out of the 120 migrations, ~85 sites pass an explicit `reason=` because the original code used a `_reason`-suffixed translation key for the deduction (e.g. `ssh.host_key_dsa_reason` vs `ssh.host_key_dsa`). This pattern was introduced in early v0.4.x to keep deduction-breakdown strings concise vs the longer finding messages. The helper preserves the distinction by accepting the override; defaulting `reason` to `message` covers the ~35 sites where the original code had `_t(KEY)` twice.

### Why the migration didn't change tests

Each helper call internally calls `self.warn(...)` (or `.alert(...)`) followed by `self.add_deduction(...)`. The two methods append a `Finding` and a `Deduction` to `result.findings` and `result.deductions` respectively. Tests check those lists via `len()`, attribute access on individual entries, or `assert_count_per_level()` — none of which care whether the entries were emitted via the helper or via 2 separate calls. The wire output is identical.

The only theoretical risk would be if a test patched `CheckResult.warn` or `.add_deduction` to count call invocations. A grep found zero such tests — all tests assert on the resulting `result.findings` / `result.deductions` lists.

### Diff stats

```
$ git diff --stat
 bob/checks/auditd.py            |  24 +-
 bob/checks/backup.py            |   9 +-
 bob/checks/clamav.py            |  56 +---
 bob/checks/cron_audit.py        |  20 +-
 bob/checks/disk.py              |  56 +---
 bob/checks/docker_audit.py      |  18 +-
 bob/checks/fail2ban.py          |  24 +-
 bob/checks/file_integrity.py    |  30 +-
 bob/checks/file_perms.py        |   8 +-
 bob/checks/firewall_stack.py    |  30 +-
 bob/checks/firewall.py          |  37 +--
 bob/checks/firmware.py          |  24 +-
 bob/checks/hardening.py         |  91 ++-----
 bob/checks/iptables_nftables.py |  50 +---
 bob/checks/ipv6.py              |  11 +-
 bob/checks/kernel_hardening.py  |  21 +-
 bob/checks/kernel_modules.py    |  22 +-
 bob/checks/log_rotation.py      |  21 +-
 bob/checks/logs.py              |   9 +-
 bob/checks/mac_policy.py        |  48 +---
 bob/checks/memory.py            |   8 +-
 bob/checks/network_context.py   |  17 +-
 bob/checks/ntp.py               |  26 +-
 bob/checks/password_policy.py   |  24 +-
 bob/checks/ports.py             |  10 +-
 bob/checks/rootkit.py           |  39 +-
 bob/checks/samba.py             |  66 +-----
 bob/checks/secure_boot.py       |  22 +-
 bob/checks/smtp.py              |  14 +-
 bob/checks/ssh.py               | 287 +++++--------------
 bob/checks/suid_audit.py        |  15 +-
 bob/checks/systemd_timers.py    |  24 +-
 bob/checks/umask.py             |  24 +-
 bob/checks/updates.py           |  24 +-
 bob/checks/user_accounts.py     |  26 +-
 bob/scoring.py                  |  66 ++++++
 37 files changed, 483 insertions(+), 1002 deletions(-)
```

**Net: −519 lines.** Closer to the audit's "~800 LoC removed" estimate if the 13 skipped sites had also been migrated, but the conservative approach to `_deductions < CAP` patterns and `warn`/`alert` branching is the correct trade-off — those sites would need a different helper shape and a re-write of their surrounding logic.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in ~6s
```

**4538 → 4538 (unchanged).** Each of the 6 waves passed `pytest tests/` cleanly before moving on. No new tests needed (the helpers' behaviour is pinned by the existing finding/deduction-counting tests across all 33 check files).

### Compatibility

- **JSON contract**: `schema_version="1"`, all 116 EXPLAIN_KEYS, all 34 filterable sections — **unchanged**.
- **CLI surface**: no new flag, no flag removed.
- **Per-domain score breakdown**: unchanged (same `_PREFIX_TO_DOMAIN`, same domain mapping for every emitted key).
- **Wire output**: bit-identical to v0.5.0. Finding messages, deduction reasons, template_vars, recurrences, CIS refs — all preserved.
- **External API** for plugin authors: the 2-call form (`result.warn(...) + result.add_deduction(...)`) **still works**. The helper is additive — plugin code unchanged.
- **i18n**: zero locale key changes (the helpers route through existing `_t` calls at every call site).

### Next phases of v0.5.x

- **v0.5.2 (Phase 3)**: audit findings #4 (SSH directive table — `_check_sshd_config` → declarative `_BAD_DIRECTIVES`) + #3 (extend `runner._sec` with `skip_if=` and `post_display=` callbacks). Medium risk: touches the largest test file (`test_ssh.py`, 1022 LoC) and core runner control flow.
- **v0.5.3 (Phase 4)**: #5 (`display_result` LEVEL_DISPATCH table) + #12 (`print_audit_summary` extracted helpers) + #8 (remove `CheckResult.log_data` escape hatch). Medium risk: observable layout changes.
- **v0.5.4 (Phase 5)**: #6 (cron wizard `_prompt` helper) + #9 (`UFW_AUDIT_SHARE` sunset path) + final decisions on #13 (ssh.py split) / #14 (cron.py split) / #15b (`_PREFIX_TO_DOMAIN` re-attribution).

---

## [v0.5.0] — 2026-05-21

**Refactor v0.5.x — Phase 1 of 5.** This release opens the **v0.5.x branch**. It's the first instalment of a 5-phase refactor mapped from a sub-agent audit (general-purpose, dispatched 2026-05-21 with `DOCUMENTS/SNAPSHOT.md` as primary briefing). The audit returned **15 refactor findings**, ranked by value/effort, with explicit risk classification.

The bottom-up principle for this whole 5-phase refactor: **the audit pipeline behaviour does not change**. JSON `schema_version="1"`, the 7 score domains, the 116 EXPLAIN_KEYS, the 34 filterable sections, the `--explain` aliases, the CLI flags, the profile inheritance, the locale keys — all stable. Phase 1 cherry-picks the additive, low-risk findings that don't require any contract-touching surgery.

### Phase plan (mapped 2026-05-21)

| Phase | Version | Theme | Findings | Risk |
|---|---|---|---|---|
| 1 | **v0.5.0** (this release) | Quick wins + cron coverage | #7, #2, #10, #11, #15a + cron tests | low |
| 2 | v0.5.1 | The big LoC win | #1 `warn_with_deduction` ~130 sites | low |
| 3 | v0.5.2 | SSH directive table + `_sec` extension | #4, #3 | medium |
| 4 | v0.5.3 | Display refactor + log_data escape hatch | #5, #12, #8 | medium |
| 5 | v0.5.4 | Cron wizards + UFW_AUDIT_SHARE sunset | #6, #9, possibly #13/#14/#15b | medium |

Findings #13 (ssh.py split) and #14 (cron.py split) are **contingent**: re-evaluated at the end of Phase 5 once #1+#4 and #6 have shrunk those files. Finding #15b (re-attributing `smtp`/`fail2ban`/`desktop_apps`/`virt` away from the firewall catch-all) is medium-risk because it changes scoring outputs — explicitly deferred from #15a.

---

### #7 — `is_unit_active()` / `is_unit_enabled()` centralized

**Problem.** Across 9 check modules, the same idiom recurred:
```python
out = (_run("systemctl", "is-active", X) or "").strip()
if out == "active":
    snap.service_active = True
```
Different formulations across `auditd.py`, `fail2ban.py`, `clamav.py`, `ntp.py`, `ddns.py`, `updates.py`, `ssh.py`, `backup.py`, `log_rotation.py` (the last with explicit `timeout=5` from a v0.4.8 cleanup). `backup.py` additionally did `out.lower() == "active"` as a defensive guard.

**Fix.** Two new public helpers in `bob/checks/_run.py`:

```python
def is_unit_active(name: str, timeout: int = _CMD_TIMEOUT) -> bool:
    return _run("systemctl", "is-active", name, timeout=timeout).strip().lower() == "active"

def is_unit_enabled(name: str, timeout: int = _CMD_TIMEOUT) -> bool:
    return _run("systemctl", "is-enabled", name, timeout=timeout).strip().lower() == "enabled"
```

The defensive `.lower()` was promoted from `backup.py` to the helper — applies to all 9 callers. Cost: one method call per check. Benefit: closes the entire class of "distro fork emits `Active\n` and we miss it" potential bug. **User explicitly validated the safety margin** — restored after a brief discussion where the migration initially dropped it.

9 sites migrated:

| File | Before | After |
|---|---|---|
| `auditd.py` | `out = (_run(...) or "").strip(); snap.service_active = out == "active"` | `snap.service_active = is_unit_active("auditd")` |
| `fail2ban.py` | same pattern, `"fail2ban"` | `is_unit_active("fail2ban")` |
| `clamav.py` | loop over 3 unit names with break-on-match | loop over 3 unit names, `if is_unit_active(unit)` |
| `ntp.py` | loop over `_NTP_SERVICES` | loop, `if is_unit_active(svc): return svc` |
| `ddns.py` | loop over `client_def.services` | `if is_unit_active(svc): return True` |
| `updates.py` | `timer_out = _run(...); enabled = (timer_out or "").strip() == "active"; return True, enabled` | `enabled = is_unit_active("apt-daily-upgrade.timer"); return True, enabled` (intermediate var restored after review) |
| `ssh.py` | loop over `("ssh", "sshd")` | loop, `if is_unit_active(unit): snap.sshd_active = True; break` |
| `backup.py` | `out.lower() == "active"` (defensive) | `is_unit_active(service)` (defensive moved to helper) |
| `log_rotation.py` | `_run("systemctl", "is-active", name, timeout=5).strip() == "active"` | `is_unit_active(name, timeout=5)` |

`services.py::_detect_single_unit_state` (which handles template-service variants `foo@instance`, `is-active` + `is-enabled` state combinations, and unit-listing fallbacks) is **NOT migrated** per the audit recommendation — it has richer semantics than a boolean and is mature.

Tests updated: `test_fail2ban.py` and `test_ntp.py` switched from patching `bob.checks.X._run` (which no longer intercepts the systemctl call now that it goes through `is_unit_active` from `_run.py`'s namespace) to additionally patching `bob.checks.X.is_unit_active`. The stub `_make_run_stub` lost its `service_active` parameter (handled separately).

**Monitoring**: `is_unit_enabled` has no consumer yet (services.py keeps its own logic). Added for API symmetry. Tracked in `feedback_release_monitoring.md` — to be reviewed at each v0.5.x release.

---

### #2 — `bob.output.print_titled_box()` extracted (+ `--no-color` leak fixed)

**Problem.** A 3-line ASCII titled-box header pattern was open-coded 4 times:

| Site | What it draws |
|---|---|
| `cron.py:461` (install wizard) | "Installation cron BOB" title box |
| `cron.py:686` (email store sub-menu) | "Email store" title box |
| `cron.py:1056` (manage wizard) | "Manage cron" title box |
| `manage_logs.py:252` (plain-text fallback) | "Manage logs" title box |

Each site computed `W=62`, `pad = W - 6 - len(title)` and printed three lines with **inline ANSI escapes**:
```python
print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
```

The inline `\033[1;34m` bypassed `bob.output._c` (the palette that respects `--no-color`). Result: even with `--no-color`, these boxes printed in coloured terminal escapes. **Latent UX bug** for users routing the output to pipes/logs.

**Fix.** New `bob.output.print_titled_box(title: str, width: int = 62) -> None`. Routes through `_c.blue_bold`, `_c.bold`, `_c.reset` — `--no-color` now correctly strips the colours from these 4 sites.

The function uses `_visual_width(title)` instead of `len(title)` for padding — more robust against multi-byte characters in i18n titles (in practice no current title has them, but cheap correctness).

`bob/fixes.py:38` was **not migrated**: its box is `╔ ║ ╠` (streaming continuation, content follows inside) — different shape, and that site already correctly routes through `_c.blue_bold`. Migrating it would require a separate streaming helper — out of scope for Phase 1.

**Monitoring**: the `width` parameter is exposed but never overridden at any call site (all 4 use the default 62). Kept for flexibility (i18n titles could grow). Tracked in `feedback_release_monitoring.md`.

---

### #10 — `bob.report.Report` Protocol (PEP 544)

**Problem.** Three report classes (`AuditReport`, `NullReport`, `MarkdownReport`) share an external write-method contract but no formal type:
- `AuditReport` (plain-text, `bob/report.py:87`) and `NullReport` (no-op subclass, `bob/report.py:357`) are in the same module — `NullReport(AuditReport)` is structural inheritance.
- `MarkdownReport` (`bob/report_markdown.py:43`) is independent — no inheritance, just method-name parity, duck-typed.

`runner.run_checks(report: AuditReport, ...)` accepted any of them at runtime but the annotation was inaccurate for `MarkdownReport`.

**Fix.** New `Report` Protocol (`bob/report.py:39-94`):

```python
class Report(Protocol):
    path: Optional[Path]
    enabled: bool

    def write_header(self, info: "SystemInfo") -> None: ...
    def write_group(self, title: str) -> None: ...
    def write_section(self, title: str) -> None: ...
    def write_finding(self, level: str, message: str, detail: str = "") -> None: ...
    def write_raw(self, text: str) -> None: ...
    def write_indented(self, text: str, indent: int = 4) -> None: ...
    def write_separator(self, thin: bool = False) -> None: ...
    def write_summary(self, score, risk_level, network_context, public_ip,
                      ok_count, warn_count, alert_count, breakdown, labels) -> None: ...
    def write_risk_context_section(self, section_title: str, entries: list[dict]) -> None: ...
    def write_next_steps(self, steps: list[str]) -> None: ...
    def close(self) -> None: ...
```

`runner.run_checks(report: Report, ...)` now annotates the abstract Protocol. `init_report` keeps its `-> AuditReport` return type (it only ever returns `AuditReport` or `NullReport`, never `MarkdownReport`).

**Design notes:**
- **No `@runtime_checkable`**: pure static typing. `isinstance(x, Report)` raises `TypeError` — confirmed via smoke test. If a runtime check is ever needed, adding the decorator is a 1-line change.
- **`__enter__`/`__exit__` excluded**: grep confirmed no caller uses `with report: ...`.
- **`write_services_panorama` excluded**: unique to `MarkdownReport`, not a shared contract.
- **`open()` / `null()` classmethods excluded**: instantiation concerns, not runtime contract.
- **Forward reference `"SystemInfo"` (string)**: `SystemInfo` class is defined below the Protocol in the same file.

---

### #11 — `emit_section()` + `emit_group()` closures in `runner.py`

**Problem.** The motif

```python
if not config.quiet:
    print_section(t("sections.firewall"))
report.write_section(t("sections.firewall"))
```

repeated 20 times in `run_checks()` (and similarly for `print_group` / `write_group` at 5 sites). The `if not config.quiet` guard had to be re-checked manually each time, and the translation key was repeated in both calls — a drift surface (if a future change wanted to wrap section emission with something else, 20 sites need editing).

**Fix.** Two closures defined at the top of `run_checks()`:

```python
def emit_section(section_key: str) -> None:
    """Print and write a section header (respects --quiet)."""
    title = t(f"sections.{section_key}")
    if not config.quiet:
        print_section(title)
    report.write_section(title)

def emit_group(group_key: str) -> None:
    """Print and write a group header (respects --quiet)."""
    title = t(f"groups.{group_key}")
    if not config.quiet:
        print_group(title)
    report.write_group(title)
```

Closures (not free functions) because they reference `t`, `config`, `report` from the enclosing scope — same pattern as `_sec()` already established.

`_sec()` itself now uses `emit_section(section)` internally (dogfooding).

20 migrated sites:

| Type | Keys |
|---|---|
| `emit_group` (5) | firewall_network, exposure_services, access_control, system_hardening, detection_health |
| `emit_section` (15) | firewall, rules, ufw_logging, iptables_nft, firewall_stack, network_context, services, ports_analysis, ddns, docker, virtualization, samba, docker_audit, disk, desktop_apps |

**Sites NOT migrated** (intentional):
- Line 373 — `print_section(t("sections.logs"))` is orphan: no matching `report.write_section` call. Pre-existing anomaly (the report log section header is plausibly emitted by `display_log_results`). Out of scope for Phase 1.
- Line 648 (plugin loop) — `print_section(plugin.name)` passes a raw title, not a translation key.

**Net diff for `runner.py`:** −65 / +37 = **−28 lines**. Reading top-to-bottom of `run_checks()` is now substantially clearer.

---

### #15a — `tests/test_domain_scores_mapping_complete.py`

**Problem.** `bob/domain_scores.py::_PREFIX_TO_DOMAIN` is a dict mapping finding-key prefixes (e.g. `"ssh"`) to domains (e.g. `"ssh"`). Any prefix not in the dict falls into the `"firewall"` catch-all, silently. SNAPSHOT documented this as a footgun for future check authors.

The audit gave two options:
- **(a)** A test that forces every prefix to be explicitly handled (low risk, this release).
- **(b)** Re-attribute the silent fallbacks to more semantic domains (medium risk — changes per-domain score outputs; deferred to Phase 5).

**Fix (option a):** New test file using the AST-scanning approach pioneered by `test_locale_coverage.py` (v0.4.5).

The test walks `bob/checks/*.py`, finds every `ast.Call` where `func.attr` is one of `add_deduction`, `warn`, `alert`, `info`, `ok`, and extracts the literal `key="X.Y"` kwarg if it's a constant string. The first dot-segment is the prefix. The test asserts each prefix is either:

1. Explicitly mapped in `_PREFIX_TO_DOMAIN`, OR
2. Listed in `_CATCH_ALL_BY_DESIGN` with a non-empty justification string.

The whitelist captures the v0.4.x state-of-the-art:

```python
_CATCH_ALL_BY_DESIGN: dict[str, str] = {
    # Legitimate firewall-domain prefixes
    "firewall":        "Self-mapping: the catch-all IS firewall",
    "rules":           "UFW rules analysis is part of firewall scoring",
    "ports":           "Port exposure is part of firewall surface",
    "services":        "Service exposure is part of firewall surface",
    "iptables_nft":    "iptables/nftables fallback is firewall stack",
    "firewall_stack":  "Firewall stack consistency analysis",
    "network_context": "Network interfaces / connections inventory",
    "ipv6":            "IPv6 consistency relative to UFW",
    "docker":          "Docker network exposure (port mappings)",
    "ddns":            "DDNS external exposure surface",

    # v0.4.x silent fallbacks — review in Phase 5 (#15b)
    "smtp":            "v0.4.x catch-all: local SMTP exposure → review in v0.5.4",
    "fail2ban":        "v0.4.x catch-all: anti-bruteforce → candidate for 'ssh' domain in v0.5.4",
    "desktop_apps":    "v0.4.x catch-all: desktop process detection → review in v0.5.4",
    "virt":            "v0.4.x catch-all: virtualization bypass risk → candidate for 'hardening' in v0.5.4",
    "docker_audit":    "v0.4.x catch-all: container hardening → candidate for 'hardening' in v0.5.4",
    "prerequisites":   "Prerequisites check (UFW installed) — INFO-only, no scoring impact",
}
```

Two additional tests catch stale entries (warnings, not failures): `_CATCH_ALL_BY_DESIGN` keys with no current emitter, and `_PREFIX_TO_DOMAIN` keys with no current static emitter (the latter may legitimately use dynamic keys — comment threshold). And one test asserts every catch-all entry has a non-empty justification.

**+4 tests total.** Output:
```
tests/test_domain_scores_mapping_complete.py::TestDomainMappingCompleteness::test_every_emitted_prefix_is_mapped_or_whitelisted PASSED
tests/test_domain_scores_mapping_complete.py::TestDomainMappingCompleteness::test_no_stale_catchall_entries PASSED
tests/test_domain_scores_mapping_complete.py::TestDomainMappingCompleteness::test_no_stale_prefix_to_domain_entries PASSED
tests/test_domain_scores_mapping_complete.py::TestCatchAllJustifications::test_all_entries_have_justifications PASSED
```

A future contributor adding a new check that emits `key="weird_thing.X"` will get an immediate test failure with a clear actionable message:
```
AssertionError: Finding-key prefixes emitted by bob/checks/*.py but neither
mapped in _PREFIX_TO_DOMAIN nor whitelisted in _CATCH_ALL_BY_DESIGN:
['weird_thing']
Either map the prefix to a domain in bob/domain_scores.py, or add it to
_CATCH_ALL_BY_DESIGN with a justification.
```

---

### Cron coverage pass (preliminary for Phase 5)

cron.py has the **worst test ratio** of the codebase per SNAPSHOT (0.60×). Phase 5 will refactor the three plain-text wizards (#6: extract a `_prompt(t, key, validator)` helper + dedupe). Adding coverage *before* the refactor is the safety net.

**+35 tests** in 5 new classes in `tests/test_cron.py`:

#### `TestValidateCronField` (13 tests)
Pure validation of one cron field. All branches:

| Test | What it pins |
|---|---|
| `test_wildcard_is_valid` | `*` |
| `test_plain_integer_in_range` | `30` in `[0,59]` |
| `test_plain_integer_out_of_range_returns_error` | `70` rejected |
| `test_range_valid` | `0-30` |
| `test_range_out_of_bounds_rejected` | `0-1000` — **v0.4.3 regression class** |
| `test_range_reversed_rejected` | `30-10` |
| `test_step_valid` | `*/5` |
| `test_step_zero_rejected` | `*/0` |
| `test_step_non_numeric_rejected` | `*/abc` |
| `test_list_all_valid` | `0,15,30,45` |
| `test_list_one_out_of_range_rejected` | `0,15,99` |
| `test_empty_entry_rejected` | `0,,30` |
| `test_garbage_rejected` | `xyz` |

#### `TestValidateCustomCron` (7 tests)
Full 5-field cron expression: `0 3 * * *`, `0 3 * * 0`, `*/15 * * * *`, 4-field rejection, 6-field rejection, hour 25 rejection, minute 70 rejection.

#### `TestBuildScriptContent` (7 tests)
Bash script generation: shebang, `shlex.quote()` behaviour for `NOTIFY_EMAILS` (simple + with space), `LOG_DIR` (simple + with space), `--quiet --detailed` invocation, `AUDIT_EMAIL` / `AUDIT_LOG` exports.

#### `TestApplyCronSchedule` (3 tests)
File-mutation helper: schedule replacement preserves the email comment, missing file returns OSError string. **Surfaced a latent bug — see below.**

#### `TestApplyCronEmail` (5 tests)
Email comment + script `NOTIFY_EMAILS=` line update, **legacy `NOTIFY_EMAIL=` (no S) regex parity** (pre-v0.3 wrapper compatibility), missing script tolerance, `shlex.quote()` quoting.

---

### Latent bug fixed — `_os.open` in `apply_cron_schedule` (discovered by the new tests)

**Reproduced** by `TestApplyCronSchedule::test_replaces_schedule`:
```
E   NameError: name '_os' is not defined
bob/cron.py:855: NameError
```

**Cause.** The v0.4.8 cron deduplication promoted `apply_cron_schedule()` from a curses-TUI private helper to a public `bob.cron` API. The extraction copy-pasted the helper body but missed renaming `_os.open(...)` to `os.open(...)`. The `_os` alias is local to three *other* functions in `cron.py`:

```
bob/cron.py:649:    import os as _os
bob/cron.py:931:    import os as _os
bob/cron.py:1215:   import os as _os
```

Each of those imports is scoped to its function. At the module level, only `os` is imported. The helper had been silently dead since v0.4.8 ship — the public API was wired to `bob/tui/cron.py` (curses TUI) which isn't exercised by automated tests, so the `NameError` only occurred at runtime when a user attempted to edit a cron schedule from the curses menu.

**Fix.** 3 references on 2 lines in `apply_cron_schedule`:
```python
- fd = _os.open(str(entry.cron_path), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o640)
- with _os.fdopen(fd, "w") as fh:
+ fd = os.open(str(entry.cron_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
+ with os.fdopen(fd, "w") as fh:
```

`apply_cron_email()` (just below) was already correct — it uses the local `_atomic_write()` helper.

**Test that pins the fix:** `TestApplyCronSchedule::test_replaces_schedule`, `test_preserves_email_comment`, `test_missing_file_returns_error`.

---

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in 7.77s
```

`4499 → 4538` (+39): +4 from `test_domain_scores_mapping_complete.py`, +35 from new cron classes.

### Compatibility

- **JSON contract**: `schema_version="1"`, all 116 EXPLAIN_KEYS, all 34 filterable sections — **unchanged**.
- **CLI surface**: no flag added, no flag removed.
- **Per-domain score breakdown**: unchanged (no `_PREFIX_TO_DOMAIN` modifications — #15b deferred).
- **Config files** (`config.conf`, `services.json`, profiles): unchanged.
- **Locale keys**: unchanged.
- **Plugin contract**: unchanged.

### Files changed

- `bob/__init__.py` — version bump 0.4.8 → 0.5.0
- `bob/checks/_run.py` — +30 lines (helpers)
- `bob/checks/auditd.py`, `bob/checks/backup.py`, `bob/checks/clamav.py`, `bob/checks/ddns.py`, `bob/checks/fail2ban.py`, `bob/checks/log_rotation.py`, `bob/checks/ntp.py`, `bob/checks/ssh.py`, `bob/checks/updates.py` — `is_unit_active` migration
- `bob/output.py` — +22 lines (`print_titled_box`)
- `bob/cron.py` — `print_titled_box` migration (3 sites) + `_os` → `os` bug fix
- `bob/manage_logs.py` — `print_titled_box` migration (1 site)
- `bob/report.py` — +65 lines (`Report` Protocol)
- `bob/runner.py` — `emit_section`/`emit_group` closures + 20 migrations + `Report` type hint (net −26 lines)
- `tests/test_cron.py` — +35 tests
- `tests/test_fail2ban.py`, `tests/test_ntp.py` — patch sites updated for new helper layer
- `tests/test_domain_scores_mapping_complete.py` — **new file**, +4 tests
- `pyproject.toml` — version bump
- `bob/data/schemas/{service,services-list,plugin-file}.schema.json` — `$id` URL bump
- `README.md` + `README_FR.md` — banner version
- `DOCUMENTS/README_TECH.md` + `DOCUMENTS/README_TECH_FR.md` — banner + badge + "As of vX.Y.Z" references
- `man/bob.1`, `man/bob.conf.5`, `man/bob-profile.5` — `.TH` version
- `CHANGELOG.md`, `CHANGELOG_FR.md`, `DOCUMENTS/CHANGELOG_FULL.md`, `DOCUMENTS/CHANGELOG_FULL_FR.md` — this entry
- `DOCUMENTS/TESTING.md` + `DOCUMENTS/TESTING_FR.md` — v0.5.0 row + section
- `debian/changelog`, `packaging/rpm/bob.spec` — packaging stanzas

---

## [v0.4.8] — 2026-05-21

**Code-quality audit pass 4** — performed by a `general-purpose` sub-agent dispatched after the org's monthly quota reset, briefed with `DOCUMENTS/SNAPSHOT.md` as primary cartography. The agent ran 4 distinct bug-pattern hunts (dead dataclass fields, reinvented helpers, timeout inconsistencies, dead code from refactors) and returned **4 IMPORTANT + 5 MINOR + 3 SUGGESTION findings**. All addressed in this release, bundled with 6 pyproject.toml improvements queued from v0.4.7. 4499/4499 tests passing.

### I4 — `sudo bob -d` log files were root-owned (the only externally-observable bug)

**Reproduced**: any `sudo bob -d` run on Linux. The detailed audit report at `~/.local/share/bob/logs/bob_YYYYMMDD_HHMMSS.log` was created at mode `0o600` (correct — confidential output) but with `root:root` ownership because the `open()` syscall happens inside the sudo context. The invoking real user could neither read nor delete their own audit reports afterwards. Same applies to the parent `logs/` directory on its first `mkdir(parents=True)`.

**Why this survived 4 audits**: BOB has a well-established chown-back pattern via `bob.sysinfo::chown_to_sudo_user(path)` — a thin wrapper around `os.chown(path, pw_uid, pw_gid)` resolved from `$SUDO_USER`, with a silent no-op fallback when not running under sudo. The pattern was correctly applied to **7 modules** writing to `~/.config/bob/` (`config.py`, `history.py`, `ignore.py`, `compare.py`, `recurrence.py`, `profiles.py`, `registry.py`) — but never wired up for the two modules writing to `~/.local/share/bob/logs/`. The omission only manifests at runtime via "permission denied" when the user tries to `cat`/`rm` their report.

**Fix**:

```python
# bob/report.py — AuditReport.__init__
fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
self._fh = os.fdopen(fd, "w", encoding="utf-8")
# When invoked under sudo, the report file is owned by root by default
# and cannot be read/deleted afterwards by the real user. Chown it back
# so `sudo bob -d` reports land in the user's account, not root's.
from bob.sysinfo import chown_to_sudo_user
chown_to_sudo_user(path)
```

```python
# bob/manage_logs.py — get_or_prompt_log_dir
from bob.sysinfo import chown_to_sudo_user, get_user_home

# (4 branches: --output-dir / saved config / non-interactive / interactive)
d.mkdir(parents=True, exist_ok=True)
chown_to_sudo_user(d)
```

The four mkdir branches in `get_or_prompt_log_dir` (`--output-dir` path, saved config path, non-interactive default, interactive prompt) each now call `chown_to_sudo_user(d)` after a successful mkdir.

The fix is non-invasive: zero impact when not under sudo (no `SUDO_USER` → early return).

### I1-I3 + M4-M5 — Dead dataclass fields purged

Eight dataclass fields populated by `from_system()` (i.e. doing real I/O work on every audit) but never read by any consumer. Same bug class as the v0.4.3 C1 fix that removed 5 dead attrs from `HardeningSnapshot` causing `--json-full` crashes.

#### I1 — `SSHSnapshot.config_source_files`

```python
@dataclass
class SSHSnapshot:
    ...
    sshd_config:             dict = field(default_factory=dict)
    config_source_files:     List[str] = field(default_factory=list)  # ← removed
    ...
```

Populated by `_parse_config_file()` while recursively resolving `Include` directives in sshd_config. The intent was to surface the list of contributing source files for diagnostic. Never consumed — not by `check_ssh`, not by `display`, not by `json_output`, not by any test. The companion `sources` parameter on `_parse_config_file()` was also unused, so the parameter is dropped too (function signature simplifies from `(path, config, seen, sources)` to `(path, config, seen)`).

#### I2 — `FirewallStatus.ipv4_rules_count` + `ipv6_rules_count`

Two integer counters computed via two `sum(1 for ln in ... if "(v6)" not in ln)` / `... if "(v6)" in ln` passes over the UFW `numbered_output` on every audit. Used nowhere — tests merely pass values to satisfy the dataclass constructor. Removed; the 4 test files (`test_firewall.py`, `test_degraded.py`, `test_ufw_logging.py`) updated to stop passing them. If a future consumer ever needs the counts, they're derivable from `numbered_output.count("(v6)")` on demand.

#### I3 — `SambaSnapshot.min_protocol`

Captured from `smb.conf`'s `min protocol` directive. Only consumed by the local `min_proto` variable used to compute `smb1_enabled` — the dataclass field is redundant. Removed.

#### M4 — `ClamAVSnapshot.last_scan_log_path`

`_find_last_scan_date()` returned `(date, log_path)` tuple but only `date` was consumed. The `log_path` value (which file the date came from) could be useful diagnostic info but wasn't surfaced anywhere. Field dropped; function simplified to return `Optional[str]` (just the date).

#### M5 — `ClamAVSnapshot.db_path` + `SecureBootSnapshot.method`

Both populated, both never consumed by their `check_*` function or any downstream display. Tests asserted only that the fields existed and held a particular value — the most fragile kind of test (silent if the field stops being set). Fields dropped; `tests/test_clamav.py:481` and `tests/test_secure_boot.py:200` cleaned up. The secure_boot detection method ("mokutil" / "efivars" / "bootctl") is now purely internal — only `state` matters downstream.

### M1 — `_C_LOCALE_ENV` consistency

Three subprocess sites bypassed the `env=_C_LOCALE_ENV` convention:

| File | Line | Command |
|---|---|---|
| `bob/checks/desktop_apps.py` | 111 | `ps -eo comm` |
| `bob/checks/smtp.py` | 58 | `ps -eo comm` |
| `bob/checks/smtp.py` | 102 | `ss -tlnp` / `netstat -tlnp` |

Today the outputs of `ps`, `ss`, `netstat` happen to be locale-independent on all distros BOB targets, so the bypass is benign. But the convention exists for a reason — any future `ss` localising the "LISTEN" keyword or `ps` localising column headers would silently break detection in these checks while every other check in BOB would continue working. Same v0.4.3 strptime lesson, applied preemptively. Fixed via `env=_C_LOCALE_ENV` on all three sites (with appropriate import added).

### M3 — `log_rotation._service_active` inlined via `_run`

The function was 12 lines of `subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=5, env=_C_LOCALE_ENV)` + exception handling + `.stdout.strip() == "active"`. The same pattern was already implemented as a one-liner via `_run()` in `clamav.py`, `fail2ban.py`, `auditd.py`, `ssh.py`. Replaced with `return _run("systemctl", "is-active", name, timeout=5).strip() == "active"`. The local `import subprocess` and `_C_LOCALE_ENV` imports were no longer needed after the cleanup — also removed.

### M2 + S2 — Cron management de-duplication (with NOTIFY_EMAIL legacy parity)

`bob/cron.py::edit_cron_schedule` (plain-text wizard, invoked by `--manage-cron` in non-TTY contexts) and `bob/tui/cron.py::_apply_cron_schedule` (curses TUI for the same operation) duplicated the same atomic file-patching logic:

```python
new_line = f"{schedule_expr}  root  {entry.script_path}"
new_text = re.sub(
    r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+root\s+\S+.*$",
    lambda _: new_line, text, flags=re.MULTILINE,
)
fd = os.open(str(entry.cron_path), os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o640)
with os.fdopen(fd, "w") as fh:
    fh.write(new_text)
```

Same pattern for `edit_cron_email` (plain) vs `_apply_cron_email_str` (curses). The curses branch used `r"^NOTIFY_EMAILS=.*$"` (forces the modern S-suffixed form), while the plain branch used `r"^NOTIFY_EMAILS?=.*$"` (the `?` makes the S optional, supporting pre-v0.3 BOB cron files that wrote `NOTIFY_EMAIL=` without the S). Net result: users upgrading from a pre-v0.3 cron entry could edit their notification email via the plain wizard but not via the curses TUI — silent UX inconsistency.

**Fix**: promoted `apply_cron_schedule(entry, schedule_expr) -> str` and `apply_cron_email(entry, new_email) -> tuple[str, int]` to public helpers in `bob/cron.py`. `bob/tui/cron.py` now imports them and exposes thin wrappers under the original `_apply_*` names for the existing call sites (single-line delegation each). The legacy `NOTIFY_EMAILS?=` regex is now the single source of truth for both branches. `bob/tui/cron.py` also loses its now-unused `import re`, `import shlex`, `_atomic_write` references.

### S1 — auth_log 90-day window documented as intentional

`bob/checks/auth_log.py::_read_auth_from_journald` hardcodes `max_days: int = 90` for SSH authentication history retrieval via `journalctl -t sshd --since=...`. The audit flagged the asymmetry with the `--log-days` CLI flag (default 7) which controls UFW log analysis in `bob/checks/logs.py`. Investigation: this is **intentional** and the two windows have different semantics.

UFW logs are noisy at every connection attempt — a 7-day window keeps the top-IPs / brute-force table readable and avoids burying real signals. SSH brute-force attempts, by contrast, can be slow and sporadic over weeks or months (especially against a hardened SSH that auto-bans after N tries — the attacker rotates IPs). A 90-day window catches that long-tail signal. Documented in the function docstring so future audits don't re-flag it as inconsistency:

```python
def _read_auth_from_journald(max_days: int = 90) -> str:
    """...
    The 90-day default is intentional and **independent of `--log-days`**
    (which controls UFW log analysis in `bob/checks/logs.py`). UFW logs are
    noisy and a narrow 7-day default avoids burying the report; SSH brute-
    force attempts can be slow and sporadic over months, so we need a wider
    window to catch them.
    """
```

### S3 — `SCORE_BAR_WIDTH` exported from `bob.output`

`_BAR_WIDTH = 10` was duplicated as a module-level constant in `bob/breakdown.py`, `bob/domain_scores.py`, and `bob/display.py`. The first two are score-bar widths (units: score, range 0-10); the third is the disk-percent-bar width (units: percentage, range 0-100) and is independent.

**Fix**: promoted `SCORE_BAR_WIDTH = 10` from the private `_SCORE_BAR_WIDTH` already used by `output.score_bar()` (introduced in v0.4.7's gauge harmonization). `breakdown.py` and `domain_scores.py` now `from bob.output import SCORE_BAR_WIDTH as _BAR_WIDTH`. `display.py::_BAR_WIDTH` left alone — same numeric value, different semantic unit, accidentally-coincident.

### pyproject.toml hardening (queued from v0.4.7, applied here)

During v0.4.7 prep an exhaustive pyproject.toml audit identified 6 improvements that were deferred to avoid mixing release plumbing with structural changes. All applied in v0.4.8 along with one bonus:

1. **`Development Status :: 4 - Beta` → `5 - Production/Stable`**. The project has 4499 tests, 7 distros CI, production hardware audits, 17+ PyPI releases since v0.1.0, frozen contracts (`schema_version="1"`, exit codes, EXPLAIN_KEYS, domain keys). "Beta" suggested "may have breaking changes within minor versions" which hasn't been true since v0.4.0.

2. **`authors` + `maintainers` fields added**. PyPI was displaying "Author: UNKNOWN" because PEP 621 metadata had no author info — only `debian/control` / `bob.spec` had Cédric Clauzel's name. Now `pyproject.toml` carries the canonical attribution.

3. **`[project.optional-dependencies] geoip = ["geoip2>=4.0"]`**. The IP geolocation feature in `bob/checks/logs.py` (brute-force detection enrichment) does `try: import geoip2.database` with silent fallback. The dependency was previously installed via `pipx inject bodyguard-of-bits geoip2` per the doc — clunky. Now users can `pipx install "bodyguard-of-bits[geoip]"` in a single step.

4. **`wheel` removed from `build-system.requires`**. Since setuptools 70, `setuptools.build_meta` auto-resolves wheel — listing it explicitly is redundant and slightly slows down build env preparation in PEP 517 isolated builds. Cleaned up.

5. **`Source` + `Documentation` URLs added** to `[project.urls]`. PyPI displays special icons for these specific URL labels. `Source` points to the GitHub repo (same as Homepage but PyPI renders it differently); `Documentation` points to `DOCUMENTS/README_TECH.md` (the main technical reference).

6. **Explicit `dependencies = []`** with a comment "Zero runtime deps outside stdlib — foundational architectural decision (see DOCUMENTS/SNAPSHOT.md "Kept" section). Preserve at all costs." PEP 621 makes `dependencies` implicit if missing, but spelling it out gives weight to the policy.

**Bonus**: `[tool.setuptools.packages.find]::include = ["bob", "bob.checks", "bob.tui"]` (explicit list) replaces the previous `["bob*"]` glob. The glob form would include any future top-level `bob_*` directory in the wheel (e.g. an accidental `bob_tmp/` from a debugging session). Explicit is more defensive.

### Tests

4499/4499 passing — net -1 vs v0.4.7's 4500. The removed test is `tests/test_secure_boot.py::TestSecureBootSnapshot::test_default_method_is_none` which asserted only the existence of the `SecureBootSnapshot.method` field (which is now gone). No test depended on the other removed dataclass fields beyond fixture kwargs — those were cleaned up to remove the now-invalid keyword arguments.

```
$ pytest tests/ -q
4499 passed in 5.66s
```

---

## [v0.4.7] — 2026-05-21

**Maintenance release** — cross-documentation audit pass, UI cosmetic harmonization, bash completion overhaul, and release automation. No behavior change in the audit pipeline; 4500/4500 tests unchanged.

### Cross-documentation audit (24 corrections across 8 files)

Between v0.4.6 and v0.4.7 an exhaustive audit caught stale claims that had drifted between the actual code and the user-facing documentation. None of these is a *code* bug — they are documentation bugs that would have misled users following the docs to predict tool behavior.

#### `README.md` + `README_FR.md` (2 × 2 = 4 fixes)

**1. "9 domains" → "7 score domains"** (line 7 and 97). The "9 domains" claim was the initial release v0.1.0 count (CHANGELOG mentions "46 checks · 9 domains" for v0.1.0). The scoring engine was refactored in v0.2.x to consolidate into 7 score domains (`ssh`, `samba`, `file_perms`, `updates`, `hardening`, `disk`, `firewall`), but the README banners and the section heading kept saying "9 domains" through v0.4.6 — a documentation drift of 4 minor releases.

**2. Profile table rewritten**. The old table listed a `docker` profile that **does not exist** (the real profile is `container`; a user typing `bob --profile=docker` would get a "Profile 'docker' not found — using default (server)" warning) and inverted the `desktop` / `workstation` relationship. In reality, `desktop.conf` is the substantive profile (extends `server`, 11 overrides) and `workstation` is a backward-compatibility alias that the loader rewrites to `desktop` (`bob/profiles.py::load_profile`'s `if name == "workstation": name = "desktop"`). The file `workstation.conf` is shipped in package-data but never reaches the loader. Corrected table now has 4 rows (`server`, `desktop`, `workstation` as alias, `container`) with accurate relationships.

#### `DOCUMENTS/README_TECH.md` + FR (2 × 2 = 4 fixes)

Same "9 domains" drift (line 12) → "7 score domains". Plus a second drift on line 79: "17 keys show profile-specific sections" → "19 keys". Verified by walking `bob/locales/en.json::explain.{key}.server.why` — there are 19 keys with profile-specific variants. Also "As of v0.4.6" → "As of v0.4.7" in the Python support policy section.

#### `DOCUMENTS/README_DEV.md` + FR (2 × 2 = 4 fixes)

Same "17 keys × 3 profiles" → "19 keys × 3 profiles" (line 57, in the `explain.py` module table row). "The file contains ~1500 keys" → "exactly 1401 keys" (line 469, in the "Adding a language" section). The "~1500" was a vague approximation that drifted; the actual count is precise and testable: `en.json` and `fr.json` both have 1401 keys with strict set parity (enforced by `tests/test_locale_coverage.py::TestLocaleCoverage`).

#### `man/bob.1` (3 fixes)

**1. `--list-checks` flag references removed** (line 270). The flag is documented in the man page but **does not exist** in `bob/cli.py`. The real way to list sections is `bob --check=list`. A user typing `bob --list-checks` would get `Error: Unknown option: '--list-checks'`.

**2. `--min-level=info` valid value claim removed** (line 262). The man page listed three valid values: `info / warn / alert`. But `cli.py:388,396` rejects `info` explicitly (only `warn` or `alert` accepted; `info` would be a no-op since INFO is the implicit floor).

**3. `--format=FMT` valid values list completed** (line 99). The man page listed `text / json / markdown`. The real `_VALID_FORMATS` tuple in `cli.py:458` is `("json", "json-full", "csv", "markdown", "html")` — missing `json-full`, `csv`, `html`, and `text` is **not** a valid value of `--format=` (it is the implicit default output mode; `bob --format=text` is rejected at parse).

#### `man/bob-profile.5` (3 fixes)

**1. `--list-profiles` flag references removed** (line 53). Same class of bug as `--list-checks`: the man page documented a flag that does not exist.

**2. "Up to 5 levels of inheritance" → "Up to 8 levels"** (line 57). The real constant is `_MAX_EXTENDS_DEPTH = 8` in `bob/profiles.py:56`, raising `RecursionError` when exceeded.

**3. SHIPPED PROFILES enriched with `workstation` alias entry**. The section listed 3 profiles (`server`, `desktop`, `container`) but `bob/data/profiles/` contains 4 files. The man page now documents `workstation` as a backward-compatibility alias. The `container` description was also rewritten to match the actual `container.conf::[skip_sections]` list.

#### `DOCUMENTS/AUTOMATION.md` + FR (4 × 2 = 8 fixes)

The webhook documentation contained four significant errors that would have led integrators to write broken receivers.

**1. JSON sample structure was wrong**. The doc showed `alerts` and `warnings` as arrays of `{key, message}` objects. The actual JSON payload has them as **integer counts** (`engine.alert_count`, `engine.warn_count`). A receiver implementing `for alert in payload["alerts"]:` would crash with `TypeError: 'int' object is not iterable`. To enumerate findings, the receiver must call BOB with `--json-full` which adds a top-level `findings` array. The corrected sample includes the real fields (`version`, `score_max`, `network_context`, `public_ip`, `deductions`, `domain_scores`).

**2. `risk` field case was wrong**. Sample showed `"risk": "LOW"` (uppercase). The actual JSON serializes `engine.level.value` which is lowercase (`"low"` / `"medium"` / `"high"` / `"critical"` — see `bob/scoring.py:45-50`).

**3. Webhook condition claim was wrong**. The doc said "The webhook is POSTed **only if alerts or warnings are present**". The real code (`bob/__main__.py`) has no count threshold — the webhook is POSTed every time a URL is set and `--offline` is not on, including for clean audits. The corrected doc states "filter on the receiving side by inspecting `alerts`/`warnings`/`score`".

**4. Webhook timeout was wrong**. Doc said "5-second timeout"; the real constant is `_TIMEOUT_SECONDS = 10` in `bob/webhook.py:39`. The same drift was present in `DOCUMENTS/SNAPSHOT.md` and was fixed there during the SNAPSHOT audit passes — but the AUTOMATION.md copy was not propagated. Textbook example of why duplicated facts in documentation drift.

#### `SECURITY_FR.md` (1 fix)

The header `## Threat model` was left in English when the file was forked to French. Body content was already translated; only the heading slipped through. Corrected to `## Modèle de menace`.

### `DOCUMENTS/SNAPSHOT.md` — new internal cartography

A new ~640-line internal document was created in `DOCUMENTS/` to provide a single-page bird's-eye view of the codebase. The goal is twofold:

1. **Refactor preparation**: when starting a non-trivial refactor, the maintainer no longer needs to re-discover the module structure, dependency graph, and frozen contracts module-by-module.

2. **Sub-agent briefing**: when delegating a deep audit or refactor task to a sub-agent, passing SNAPSHOT.md as the first context item dramatically reduces the amount of exploration the agent needs to do.

**Contents**: ASCII architecture diagram · annotated project tree · module index for `bob/` root (38 modules) and `bob/checks/` (43 checks) with LoC and one-line roles · dependency graph (in/out-degree centrality) · hotspots and tests-to-code ratios · 6 patterns/conventions with code examples · 7 frozen contracts · CLI surface table (~40 long options + 21 short) · file paths & env vars · tests-to-source mapping · architectural decisions (kept / discarded / deferred) · CI matrix details · "Numbers at a glance" summary.

**Validation**: the document underwent **20 successive correction passes** against the actual codebase state, producing 46 corrections total. Notable bugs caught and fixed: `~18 kLoC` headline → `~28 kLoC` (a self-inconsistency between header and footer that had passed 19 prior audit passes); ASCII layer diagram showed `runner.py → domain_scores.py` but `runner.py` does not import `domain_scores` (verified by AST scan); `--show-ignored` description was wrong; `--ignore=KEY` listed as Filter but is actually a Setup operation that exits immediately; `NO_COLOR` env var listed as honored but no code path reads it; `network_context` field type changes between `--json` and `--json-full`; ScoreEngine usage example was missing the required `reason` parameter; cron paths used `{name}` but real paths use `{slug}` derived via `make_slug()`; "5s timeout" → 10s (same fix as AUTOMATION.md); "5 compound-risk rules" → 6; pattern example signature didn't match the majority style; CIS reference storage claim was misleading.

The document is 100% English (one Franglais round caught 4 residual French phrases). It is internal (not shipped in `debian/bob-core.docs` or `bob.spec %doc`) because the audience is the maintainer and sub-agents, not end users.

### Gauge bars cosmetic harmonization

All score-based progress bars in the terminal UI now share a single colour scheme via a new helper `bob.output.score_bar(score: int) -> str`. The colour logic mirrors `display._disk_bar` but with inverted thresholds — for scores, **high is good**:

| Score range | Colour | Semantic |
|---|---|---|
| ≥ 8 / 10 | green | healthy |
| 5 – 7 / 10 | yellow | moderate |
| 0 – 4 / 10 | red | critical |

Before this change, four locations rendered bars as plain monochrome `█ * filled + ░ * empty` strings — visually flat, with no severity information conveyed by colour. The disk partition bars in `display.py::_disk_bar` were already coloured (with the same thresholds applied to *usage percent*, where high usage is bad — hence inverted semantics). The new helper brings the rest of the UI into line with that established style.

Affected renderers (one-line delegation each):

- `bob/watch.py::_score_bar` — the live `--watch` mode display.
- `bob/breakdown.py::_bar` — the `--breakdown` score-computation path display.
- `bob/domain_scores.py::render_domain_scores` — the per-domain sub-score bars in the audit summary.
- `bob/manage_logs.py` (history rendering at line 69) — the sparkline of past scores when listing log files in the `--manage-logs` TUI.

The `--no-color` / `-n` flag continues to neutralise the colours.

### Bash completion comprehensive overhaul (`bob/data/bob.bash-completion`)

#### Critical bug: `--xxx=<TAB>` value completion silently failing

The most user-visible improvement is the fix for a long-standing silent failure in value completion. Typing `bob --check=<TAB>` (or any of `--skip=`, `--min-level=`, `--format=`, `--profile=`, `--lang=`, `--target=`, `--webhook-format=`, `--output=`) showed no suggestions at all.

The root cause is the way bash splits the command line into words for completion. With the default `COMP_WORDBREAKS` containing `=`, typing `bob --check=` and pressing TAB makes bash split the line into `["bob", "--check", "="]` with `COMP_CWORD=2` pointing to the `=` itself. The completion function read `${COMP_WORDS[COMP_CWORD]}` for the current word — getting back `"="` instead of the empty string. The subsequent `compgen -W "${section_list}" -- "="` matched nothing.

The fix is to use the bash-completion library's positional-argument convention: when bash invokes a completion function, it passes three positional arguments — `$1` is the command name, `$2` is the **clean** current word stripped of any `=` word-break prefix, and `$3` is the previous word. Reading `$2`/`$3` instead of `${COMP_WORDS[COMP_CWORD]}`/`${COMP_WORDS[COMP_CWORD-1]}` avoids the `=` split edge case entirely.

The bug was diagnosed by adding a debug wrapper around the completion function in the user's interactive Bash 5.2.21 session, tracing `set -x` output for each TAB press. The diagnostic revealed `words=[bob --check =] cword=2 cur=[=]` after typing `bob --check=<TAB>` — confirming the COMP_WORDS exposure of the raw split versus the clean `$2=""` passed via positional args.

This bug was present from the initial v0.1.0 release and survived all subsequent audits because the manual test approach (setting `COMP_WORDS=(bob "--check" "=" "")` with `COMP_CWORD=3`) produced different word-array shape than real interactive bash.

#### Other fixes

- **Function rename**: `_ufw_audit` → `_bob`. The legacy function name dates from before the project rename to "Bodyguard Of Bits".
- **Dead code removed**: `_ufw_audit_install()` + `complete -F install.sh` registered completion for an `install.sh` script that no longer exists.
- **Section list factored to `_SECTIONS`**, matching `bob --check=list` exactly. Removed `firewall` (core check, not filterable). Added `iptables_nft`, `samba`, `desktop_apps` (added to `_ALL_SECTIONS` between v0.3.x and v0.4.x but never propagated to the completion list).
- **Long-options list parity with `cli.py`**: added `--check=`, `--skip=`, `--output-dir=`, `--breakdown`, `--no-colour`. Short-options added `-B`. Total: 21 short, ~40 long options.
- **New `--skip=` value handler** (symmetric with `--check=` minus the `list` special value).
- **All value handlers support both forms** `--xxx=value<TAB>` and `--xxx value<TAB>`.

### CI — automatic GitHub Release on tag push (`.github/workflows/publish.yml`)

The publish workflow gains a fourth job `github-release` that runs after the PyPI publish succeeds. The full pipeline is now:

```
git push --tags
  ↓
test       (Python 3.10/3.11/3.12/3.13 matrix)
  ↓
build      (sdist + wheel, uploaded as artifact)
  ↓
publish    (PyPI via OIDC Trusted Publishing)
  ↓
github-release  ← NEW
  • Extract release title from CHANGELOG.md table row
  • Extract release body from DOCUMENTS/CHANGELOG_FULL.md section
    between "## [vX.Y.Z]" and the next "## [v" header (using awk)
  • Create the release via softprops/action-gh-release@v2
  • Attach wheel + sdist as release assets
  • Mark as latest
```

Safety features: `needs: publish` (release only if PyPI succeeds), explicit check that the CHANGELOG_FULL section exists (fails with `::error::` otherwise), permission scope limited to `contents: write`.

Title extraction is best-effort — it produces a sensible default that the maintainer can refine post-publish with `gh release edit vX.Y.Z --title "..."` if a more editorial tagline is wanted.

Before this automation, GitHub releases were created manually after each PyPI publish.

### Tests

No new tests added. 3 tests in `tests/test_breakdown.py::TestBar` were adapted to strip ANSI escape sequences before asserting visible bar content (bars are now ANSI-coloured strings instead of plain `█░░░░░░░░░`). 4500/4500 tests still passing.

---

## [v0.4.6] — 2026-05-17

**Terrain test pass v0.4.5 surfaced two reproducible bugs.** Both are now fixed. Scope is strictly limited — narrow hotfix, no behavior change outside the two reported scenarios.

### Validation context: the v0.4.5 terrain pass

Before opening v0.4.6, 13 audits were run across 6 distinct systems using the v0.4.5 release published to PyPI:

| System | Audits | Outcome |
|---|---|---|
| Mint dev (host) | 1 | clean |
| Debian 13 VM | 3 (pre + `apt upgrade` + `dist-upgrade`) | Bug 2 manifested after remediation |
| Kali Rolling VM | 1 | clean |
| Mint test VM | 3 (pre + `apt upgrade` + `dist-upgrade` + `autoremove`) | Bug 1 manifested after autoremove |
| Ubuntu 26.04 LTS VM | 1 | clean |
| so6desktop production (Linux Mint 22.3) | 2 (pre + post `dist-upgrade` + `autoremove`) | Bug 1 manifested in production |

Two bugs reproduced. Bug 1 manifested on production hardware — confirms it is not a VM artefact but the routine outcome of any user cleaning an obsolete kernel image. Bug 2 was bound to a specific transition (`WARN/ALERT → OK only` within a domain) — narrower scope than initially expected, but a real ergonomics regression on the remediation path.

### Bug 1 — Kernel listing did not filter on `ii` (installed) state

**Trigger**: `apt remove linux-image-X` (or its transitive form via `apt dist-upgrade` / `autoremove`) leaves the package in `rc` state. `rc` means "removed, config-files remaining": the kernel binary in `/boot` is gone (`/etc/kernel/postrm.d/initramfs-tools` runs and deletes `initrd.img-X`), but the package row stays in the dpkg database with config files in `/etc`. The package only fully disappears when `apt purge` is used or when `dpkg --remove --purge` is run.

**What BOB used to do**: in `bob/checks/kernel_modules.py`, snapshot construction called

```python
dpkg_out = _run("dpkg-query", "-f", "${Package}\n", "-W", "linux-image-[0-9]*", timeout=10)
```

This format prints the package name regardless of state. `_parse_installed_kernels` then assumed every returned line was an installed kernel and listed them all.

**What the user saw**: BOB output listed kernels that `apt` had already removed. Concrete example on so6desktop after `apt dist-upgrade` (which removed `linux-image-6.17.0-20-generic`) + `apt autoremove` (which removed `linux-hwe-6.17-headers-6.17.0-20`):

```
→ Installés  : 6.17.0-19-generic, 6.17.0-20-generic, 6.17.0-22-generic, 6.17.0-23-generic (*)
→ Obsolètes  : 6.17.0-19-generic
→ sudo apt purge linux-image-6.17.0-19-generic
```

`6.17.0-20-generic` was already gone — its row in dpkg was `rc`, not `ii`. The "Obsolètes" counter was undercounted as a knock-on effect (only 1 listed instead of 2). The purge suggestion was for the right kernel, but the rest of the listing was wrong.

**Fix**: dpkg-query is now invoked with the status abbreviation included.

```python
dpkg_out = _run(
    "dpkg-query", "-f", "${db:Status-Abbrev}|${Package}\n",
    "-W", "linux-image-[0-9]*",
    timeout=10,
)
```

`${db:Status-Abbrev}` is a 2-character abbreviation of `desired action + current status`:

| Code | Desired | Current | Means | BOB action |
|------|---------|---------|-------|------------|
| `ii` | install | installed | normal installed package | keep |
| `hi` | hold | installed | installed but on apt-mark hold | keep |
| `rc` | remove | config-files | removed by `apt remove`, /boot binaries gone | **exclude** |
| `pn` | purge | not-installed | scheduled for purge, never reinstalled | exclude |
| `un` | unknown | not-installed | dpkg knows the name but nothing else | exclude |
| `iU` | install | unpacked | mid-install, binaries may not be runnable | exclude |
| `iF` | install | half-configured | mid-install transient | exclude |
| `iW` | install | triggers-awaited | transient | exclude |

`_parse_installed_kernels` now keeps only lines whose 2nd character is `i` — the second char encodes current status (n=not-installed, c=config-files, H=half-installed, U=unpacked, F=half-configured, W=triggers-awaited, i=installed). Any line where the binaries are *guaranteed* to be present passes; anything transient or removed is filtered.

**Backward compatibility**: the parser still accepts plain `linux-image-…` lines without a `|` prefix. This is preserved for two reasons: (1) unit-test fixtures across `TestParseInstalledKernels` use the legacy format; (2) any code path or future caller that produces just the package name (e.g. a fallback if `${db:Status-Abbrev}` is somehow unavailable) continues to work.

### Bug 2 — Score dropped after remediation

**Trigger**: a single domain transitions from "has at least one WARN/ALERT" to "emits only OK findings". The reference scenario is `updates`: pre-remediation a `updates.security_pending` WARN exists, the user runs `apt upgrade`, the next BOB run only sees `updates.ok`.

**What BOB used to do**: `bob/domain_scores.py::active_domains_from_engine()` collected domains for inclusion in the global score average. It applied a filter `_actionable = (FindingLevel.WARN, FindingLevel.ALERT)` — a domain made it into the active set only if it had at least one WARN or ALERT finding (or a deduction with a key, which is implied by WARN/ALERT in practice).

**What the user saw**: on Debian 13 VM with a security update pending:

- **Audit before `apt upgrade`** — `updates.security_pending` WARN active → `updates` domain in the active set at 8/10. Other active domains: `ssh`, `hardening`, etc. Global = average ≈ 7/10.
- **`apt upgrade`** resolves the security update.
- **Audit after `apt upgrade`** — `updates` check now emits `updates.ok` and nothing else. Filter rejects `updates` from the active set. `ssh`, `hardening`, etc. still present. Global average now over `N-1` domains. Math: removing a domain that had 8/10 from an average where many remaining domains are below 8/10 → average *increases*. But removing a domain that had 8/10 when several remaining domains are at 4–6/10 makes the new average drop. On Debian 13 the new average dropped from 7 to 6.

The user-observable effect: doing the right thing (applying security updates) caused the score to decrease. Anti-incentive on a hardening tool.

**Why the filter existed**: presumably to hide domains where no service is installed (e.g. Samba not installed → no `samba.*` findings → domain absent from display). This goal is legitimate. The implementation conflated "no actionable finding" with "no signal at all" and produced the wrong behavior at the WARN→OK transition.

**Fix**: the filter is now `_actionable = (FindingLevel.OK, FindingLevel.WARN, FindingLevel.ALERT)`. A domain is considered active when *any* check from it emits a recognisable health signal. INFO-only domains remain hidden — terrain Mint test (only `updates.regular_pending` INFO present, no WARN, no OK) confirmed the bug doesn't manifest there, so the conservative line is to exclude INFO from promotion.

The semantic now matches what the docstring already claimed ("Used to hide domains whose service is not installed") — service not installed means no findings emitted, which still keeps the domain absent.

**Score behavior with the fix**:

```
Before remediation: avg(updates=8, hardening=4, …) / N            = 7
After remediation : avg(updates=10, hardening=4, …) / N           = ~7+    ← CORRECT
```

Domains with only OK findings now contribute their clean 10/10 score to the global average, which is mathematically the right outcome: a domain that audits clean should pull the average up, not be silently removed.

**Cascade effects** to be aware of:

- Domains where the relevant check always emits an OK (because the service is universally present and clean on the system) will now always be in the active set. On Ubuntu 26.04 LTS, where many checks emit pure OK, the denominator of the global average grows. This is intended — those domains were always "audited" but invisible to the score.
- Display of domain scores: `render_domain_scores` filters by `active_domains`, so previously hidden 10/10 domains may now appear. The breakdown becomes more honest about which domains contributed.

### Tests

**`tests/test_kernel_modules.py`** — new tests in `TestParseInstalledKernels`:

- `test_status_prefixed_ii_kept` — basic `ii ` rows produce the version list.
- `test_status_prefixed_rc_excluded` — direct reproduction of Bug 1: an `rc ` row for `6.8.0-52` is dropped while a sibling `ii ` row for `6.8.0-55` is kept.
- `test_status_prefixed_excludes_all_non_installed_states` — `ii`, `rc`, `pn`, `un`, `iU` cohabit; only `ii` survives.
- `test_status_prefixed_hi_kept` — held packages stay in the list (the binaries are still on disk).
- `test_mixed_legacy_and_status_prefixed_format` — backward compatibility: a single dpkg output mixing prefixed and non-prefixed lines parses correctly.

**`tests/test_domain_scores.py`** — new `TestActiveDomainsIncludesOK` class:

- `test_ok_finding_makes_domain_active` — direct assertion of the new filter behavior.
- `test_warn_finding_makes_domain_active` — old behavior preserved.
- `test_alert_finding_makes_domain_active` — old behavior preserved.
- `test_info_only_finding_does_not_promote_domain` — guards the INFO exclusion; if this fails, INFO-only domains have started leaking into the active set.
- `test_no_findings_no_active_domains` — empty engine still returns empty active set; baseline regression guard.
- `test_remediation_keeps_domain_at_max_score` — direct Debian 13 reproduction in test form: ssh has a WARN (8/10), updates remediated to OK only. Asserts `compute_global_from_domains` returns `(8+10)/2 = 9` instead of `8`.

### Test count

4500 passed (+11 vs v0.4.5). No regression in the rest of the suite.

### What does NOT change

- JSON schema version stays at 1. No new fields, no removed fields, no renamed fields.
- `EXPLAIN_KEYS` unchanged.
- No new locale keys; no removed locale keys.
- Public Python API of `bob.domain_scores` unchanged (signature of `active_domains_from_engine`, return type, no new arguments).
- Public Python API of `bob.checks.kernel_modules` unchanged (signature of `_parse_installed_kernels`, return type — it always took a string and returned `List[str]`, and the meaning of the string is upward-compatible).
- No new dependencies (still 0 runtime deps outside stdlib).

### Out of scope (deferred)

- **Comprehensive hardening audit by sub-agent**: requested concurrently with v0.4.6, deferred because the previous attempt hit the org's monthly usage cap before producing a report. See `[[audit-hardening-en-attente-v0-4-5]]` in agent memory — to be relaunched next session once quota resets.

---

## [v0.4.5] — 2026-05-16

**Test infrastructure hardening release.** v0.4.4 added `tests/test_locale_coverage.py` to catch the `logs.attempts` class of regression — keys removed from locale files while still referenced in code. The implementation worked and was already extended in v0.4.4 with three ChatGPT-review fixes (tighter regex lookbehind, exhaustive `explain.*` coverage, placeholder parity). But the underlying machinery still rested on a regex scan of source files, with documented limits: docstring false positives, multi-line call site fragility, attribute-call edge cases. v0.4.5 replaces the regex pipeline with proper AST parsing.

### Why this matters

The test catches a real, recurring class of bug — silent locale fallbacks that only show up at terrain test (the v0.4.3 `[logs.attempts]` sentinel was discovered post-tag, not by CI). The whole point of automating it is for CI to catch the regression before tag. If the automation itself has hidden blind spots, the safety net leaks.

Three structural issues with regex scanning of Python source:

1. **Docstring matches are false positives that look real.** `bob/i18n.py` documents the `t()` API with examples like `t("samba.open_world")` and `t("log.blocked_attempts", count=42)`. The regex matched these as if they were real call sites, forcing v0.4.4 to maintain a `_KEY_EXCLUSIONS` allowlist with two entries. Every future API doc example would have grown that list — it was the textbook "the allowlist eats bugs" anti-pattern.
2. **Multi-line call sites are formatting-dependent.** A call written as `_t(\n    "foo.bar",\n    x=1,\n)` is semantically identical to `_t("foo.bar", x=1)` but the regex needs the opening paren and the opening quote close together. v0.4.4's regex coped with most layouts but the contract was implicit and fragile.
3. **Attribute calls slip through some lookbehinds.** v0.4.4 tightened the negative lookbehind from `[A-Za-z0-9_]` to `[A-Za-z0-9_.]` to reject `obj._t(...)`. That covered the common case, but the rule was retroactive — every new edge case (unicode identifiers, line-continuation backslashes) would require another lookbehind tweak.

### How AST fixes all three

```python
def _is_translation_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Name)
        and node.func.id in _TRANSLATION_FUNC_NAMES
    )
```

`ast.parse(source)` returns the Python syntax tree. Three structural properties solve the three issues:

- **Docstrings are inert.** They appear as `ast.Constant(str)` directly inside a function/class/module body — not inside an `ast.Call`. The walker never sees them.
- **Whitespace is transparent.** The same `ast.Call` node represents every formatting variant. Multi-line, single-line, trailing comma — all identical.
- **Attribute access is a different node type.** `obj._t(...)` produces `ast.Call(func=ast.Attribute(...))`. The `isinstance(node.func, ast.Name)` check eliminates it by construction. No lookbehind tweaks needed, no negative-list maintenance.

The `_KEY_EXCLUSIONS` allowlist is deleted entirely. There is no migration path forward where it grows.

### What's preserved

The external test contract is identical. The same 9 tests in three classes:

- `TestLocaleCoverage` (5 tests): corpus scan, EN resolution, FR resolution, EN/FR parity, sanity baseline.
- `TestExplainNamespaceCoverage` (3 tests): exhaustive `explain.<key>.{title,why,how}` coverage generated from frozen `EXPLAIN_KEYS`.
- `TestPlaceholderParity` (1 test): `{name}` placeholders match between en.json and fr.json.

Same fixtures (`en_data`, `fr_data`, `static_keys`, `explain_leaves`), same assertions. Only `_all_t_keys()` and two small helper functions (`_is_translation_call`, `_literal_key_arg`) changed.

### Performance

AST parsing is slower than regex: 0.32 s vs 0.06 s for this one test file (~5× slower). In absolute terms negligible — the whole test suite still finishes in 6.5 s. No optimisation needed.

### What this does not change

This release modifies **only** `tests/test_locale_coverage.py`. No source file in `bob/` is touched. No runtime behavior is altered. Test count stays at 4489. The regex-based v0.4.4 form and the AST-based v0.4.5 form return the same set of keys on the current codebase — verified by running both against `bob/`. The refactor is preventive, not corrective.

### Tests

4489/4489 — unchanged from v0.4.4. The 9 tests in `tests/test_locale_coverage.py` all pass on the new AST-based implementation without any modification to their assertions.

### Deferred to a later release

This release does not change the existing roadmap items:

- Phase 2 Option A — systematic `Finding.template_vars` migration on the ~37 non-pilot checks. Still tracked for v0.5.0+. `tests/test_template_vars_migration.py` continues to surface the debt.
- Multi-distro CI matrix (Debian/Ubuntu/Mint/Kali in containers) and AUR PKGBUILD — community-contribution-welcome.
- M3 cosmetic cleanup (`os.path` → `pathlib` in 4 files).

---

## [v0.4.4] — 2026-05-15

**Cross-distro terrain hardening release.** Four fresh VM tests (Debian 13, Kali Rolling, Linux Mint 22.3, Ubuntu 26.04 LTS — all installed from PyPI via `pipx upgrade bodyguard-of-bits`) surfaced one critical bug, three minor cosmetic regressions, and confirmed the v0.4.3 fixes work in the wild. All findings plus the items deferred from the v0.4.3 audit pass (S4 symlink redesign, M4 ports refactor, I2 wave-2 `key=`, locale coverage test) are bundled in this release.

### The critical finding — and why it matters

`bob/checks/updates.py` reported "system up to date" on **every single fresh Debian-family install we tested**. On Ubuntu 26.04 LTS specifically, that meant **21 official LTS security updates went silently undetected**. For a hardening audit tool, this is the worst class of bug — a false-negative on a security-critical check that drains confidence in the entire output.

Two compounding causes:

1. **The `apt-get -s upgrade` command BOB relied on is conservative.** It refuses to upgrade any package that would require installing a new package or removing an existing one. On Debian/Ubuntu, every kernel transition (`linux-image-amd64 → linux-image-6.12.86-amd64`) and every soname bump triggers exactly this case — the whole transitive closure gets held back. Real users routinely run `apt full-upgrade` / `apt dist-upgrade` for this very reason. BOB was simulating a workflow no one actually uses.

2. **The APT cache lives at `/var/cache/apt/pkgcache.bin` and only refreshes when `apt update` runs.** On vanilla installs (typical of test VMs, but also of any user who relies on `unattended-upgrades`-triggered refreshes which may have failed), the cache is days or weeks old. BOB read that stale state and reported "0 pending" with no caveat.

The fix layers three changes in `bob/checks/updates.py`:

- **`apt-get -s upgrade` → `apt-get -s dist-upgrade`** in `_collect_pending_updates()`. Aligns the simulation with what users actually run. Security-update detection (via `-security` suffix on the source suite) is unchanged — `dist-upgrade` outputs the same `Inst` lines, just more of them.
- **Cache freshness check.** New `apt_cache_age_days: int | None` field on `UpdatesSnapshot`, populated by stat-ing `/var/cache/apt/pkgcache.bin` mtime. When the cache is more than 7 days old, the check emits a new WARN `updates.apt_cache_stale` with a `sudo apt update` recommendation. Days threshold mirrors typical `unattended-upgrades` refresh windows.
- **Cross-check vs `apt list --upgradable`.** New `upgradable_count: int | None` field, populated by parsing `apt list --upgradable` output (counting `pkg/suite ... [upgradable from: ...]` lines). When `dist-upgrade` simulation reports 0 pending but `apt list` reports N > 0, the snapshot is inconsistent — likely transient state (held packages, broken dependencies) — and a new WARN `updates.dist_upgrade_inconsistent` fires with `sudo apt update && sudo apt list --upgradable` for investigation.

The cascade matters as much as the root fix. The synthetic "Surface d'attaque" summary at the end of every audit had a `Mises à jour sécurité` line that read directly from the engine findings — if no `updates.security_pending` key was emitted, it displayed `✔ à jour`. Of course "no key emitted" was the exact bug. `bob/exposure.py` now checks for the two new WARN keys and displays `⚠ état inconnu — cache APT obsolète ou incohérent` instead of the false `✔`. Refusing to claim "OK" when the data source is unreliable is the right contract for a security tool.

### Three cosmetic regressions from the cross-distro VMs

These don't change scoring but they do change trust. A hardening tool with confusing or contradictory output trains users to ignore it.

**AppArmor "0 profiles loaded" case** (caught on Kali, where stock install has the kernel module enabled but ships zero profile packages). v0.4.3 emitted `AppArmor active but no profiles in enforce mode (0 in complain)`. The parenthetical contradicted itself — implying that complain-mode profiles exist when there are literally none. The fix in `bob/checks/mac_policy.py` distinguishes three states explicitly:
- `enforce > 0`: OK path, current language preserved.
- `enforce == 0 AND complain > 0`: existing `apparmor_no_enforce` path with the "switch to enforce" advice (this case applies to a real-world bad-config).
- `enforce == 0 AND complain == 0` (new): dedicated `apparmor_no_profiles` key with the message "AppArmor active but no profiles loaded — the framework is running with nothing to enforce" and a recommendation to install `apparmor-profiles` / `apparmor-profiles-extra`. Server profile applies a −1 deduction; desktop profile keeps it as INFO.

**SMART "all passed" on VM-only systems** (caught on Kali, /dev/vda). The output was:
```
ℹ /dev/vda — SMART not applicable (virtualised or unsupported equipment)
✔ All disks passed the SMART check — no critical attributes detected
```
Logically incoherent — if no SMART read ran, nothing passed. `bob/checks/disk.py` now only emits the `disk.ok` "all passed" success when at least one **real** (non-virtual) SMART check actually returned a result. On VMs and containers where every disk is virtual, the line is simply absent.

**DDNS open-ports list rendered as orphan sub-items** (caught on Mint test VM with ddclient + masbateno.duckdns.org). Previously:
```
⚠ DDNS active with open port(s) without source restriction — verify exposure is intentional
ℹ If this exposure is intentional: keep services up to date...
    → 22/tcp
    → 80/tcp
```
The `→ 22/tcp` lines visually attached to the INFO advice but logically belonged to the WARN — a reader can't tell what action to take with "22/tcp". The fix in `bob/checks/ddns.py` interpolates the list into the WARN message itself: `DDNS active with open port(s) without source restriction (22/tcp, 80/tcp) — verify exposure is intentional`. The orphan print loop in `bob/runner.py` is removed. The `result.open_ports` field is preserved for programmatic consumers (compare.py baseline diff, JSON output, tests).

### v0.4.3 audit-deferred items, all applied

**S4 redesign — symlink-safe ssh reads.** v0.4.3 had explicitly deferred this because the simplest fix (`_is_safe_config_path()` rejects all symlinks) would have broken legitimate dotfile setups where users symlink `~/.ssh/config` from a git-managed repository. The proper design accepts symlinks that resolve inside the owner's home directory but rejects those pointing outside (an attacker with write access to a user's home placing a symlink to `/etc/shadow` would leak system file contents into the audit report). New helper `_is_safe_user_path(path, owner_home)` in `bob/checks/_run.py`:

```python
def _is_safe_user_path(path, owner_home) -> bool:
    p = Path(path)
    if not p.is_absolute(): return False
    if p.is_symlink():
        try: target = p.resolve(strict=True)
        except OSError: return False
        home = Path(owner_home).resolve()
        try:
            target.relative_to(home)
            return True
        except ValueError:
            return False
    return True
```

Applied in `bob/checks/ssh.py` to `authorized_keys`, `~/.ssh/config`, and `known_hosts`. The existing `_is_safe_config_path` (rejects any symlink, no home-bounded exemption) is kept for system paths like `/etc/cron.d/`, `/etc/sudoers.d/`, and `/var/spool/cron/crontabs/` where any symlink is suspect.

**M4 refactor — `_parse_ufw_covered_ports`.** The v0.4.3 fix for the `_is_covered_by_ufw` false-positive (where a port number found inside a source IP like `192.168.1.22` falsely "covered" port 22) was correct but architecturally fragile — it compiled a fresh regex for every port checked against the same UFW rules text, and any future tweak risks reintroducing the false-positive. The refactor in `bob/checks/ports.py` parses the rules string **once** at the start of `check_ports()` into a `set[tuple[int, str | None]]` of covered (port, proto) tuples, then lookups become O(1) set membership. The module-level `_UFW_RULE_RE` is anchored on the start of the "To" column — the false-positive class is now impossible by construction. Both the snapshot-based and string-based forms of `_is_covered_by_ufw` are accepted for backward compatibility with any external caller.

**I2 wave 2 — `key=` on remaining findings.** v0.4.3 covered the 4 most-affected files (`docker.py`, `firewall_stack.py`, `network_context.py`, `ports.py`). Re-running the audit on the remaining checks revealed that `disk.py`, `docker_audit.py`, `desktop_apps.py`, `memory.py`, `suid_audit.py` were already at 100% key coverage. Only `services.py` (10 sites) and `virtualization.py` (2 sites) needed work — both completed here. The codebase now has every `result.alert/warn/info/ok/add_deduction` call wired with a stable `key=` for `--ignore`, audit profiles, JSON consumers, and `--explain` lookups.

**i18n locale coverage test.** v0.4.3 had a near-miss — when the M6 refactor removed `logs.attempts` from both locale files, 7 call sites in `bob/display.py` still referenced it. The `_t("logs.attempts")` calls returned the bare key as a fallback, producing `[logs.attempts]` sentinel output that only the terrain test caught (post-v0.4.3 push). New `tests/test_locale_coverage.py` runs every commit:

- Scans all `bob/**/*.py` for `t("KEY")` and `_t("KEY")` calls via regex, collects the literal keys.
- Asserts each key resolves in **both** `en.json` and `fr.json`.
- Asserts EN/FR structural parity (same set of leaf keys).
- Asserts known dynamic-prefix sections (`explain.*`, `services.exposure.*`, `services.state.*`) have their parent dicts in both locales.
- Includes a sanity baseline (key corpus size ≥ 200) so a broken regex doesn't silently make all the other tests trivially pass.

Two false positives in docstring examples (`bob/i18n.py` documents `t("samba.open_world")` and `t("log.blocked_attempts", count=42)` as illustrative examples) are listed in `_KEY_EXCLUSIONS`. Any future false-positive can be added the same way.

### Skipped from the v0.4.3 audit report

- **M3** — `os.path` → `pathlib` in 4 files (`manage_logs.py`, `suid_audit.py:142,176,180,188`, `secure_boot.py:92`, `ssh.py:1000`). Pure cosmetics. Will be folded into an eventual "consistency pass" release (imports, type hints, etc.).
- **M7** — Lazy `_PLUGIN_DIR` resolution. Re-confirmed permanently rejected. The "gotcha" (SUDO_USER changes mid-process) doesn't occur in BOB's one-shot execution model, and the attempted fix in v0.4.3 broke 20 tests that `patch("bob.registry._PLUGIN_DIR", ...)`.

### Tests

4489/4489 — +21 vs v0.4.3:
- `tests/test_updates.py` (+10): two new test classes covering the new `UpdatesSnapshot` fields. `TestAptCacheStale` (5 tests) exercises the cache-stale WARN under fresh/stale/missing/boundary conditions. `TestDistUpgradeInconsistency` (5 tests) exercises the cross-check WARN — the precise v0.4.3 bug scenario is now a regression test (dist-upgrade returns 0, apt list reports N → WARN).
- `tests/test_mac_policy.py` (+2): `TestAppArmorNoEnforce::test_no_profiles_desktop_is_info` and `::test_no_profiles_server_deducts_one`, exercising the new `apparmor_no_profiles` key on both profile paths. The existing `test_active_with_zero_profiles_at_all` was rewritten to assert the new key (it previously expected the old confusing `apparmor_no_enforce` output).
- `tests/test_locale_coverage.py` (+9): full corpus scan, EN locale resolution, FR locale resolution, EN/FR parity, dynamic-prefix coverage. The corpus contains 200+ static keys (the sanity baseline confirms our regex finds enough call sites to be meaningful). Plus, in response to a ChatGPT review of the file: tightened the regex negative lookbehind to also reject `obj._t(...)` (which previously matched as a false positive); added `TestExplainNamespaceCoverage` (3 tests) that generates expected paths from the frozen `EXPLAIN_KEYS` list and asserts each `explain.<key>.{title,why,how}` exists in both locales **as a non-empty string** (this closes a blind spot — the previous `("explain.", "explain")` dynamic prefix was a bypass that silently masked any missing leaf); added `TestPlaceholderParity` (1 test) that asserts the set of `{name}`-style placeholders is identical between en.json and fr.json for every common string key (guards against the `{count}` vs `{cnt}` runtime KeyError class).

### Real-world validation

The v0.4.3 fixes confirmed working across **5 different live systems**:
- **Linux Mint 22.3 dev box**: full feature audit with UFW active, DDNS scenario, Docker installed, Samba, all checks rendered cleanly with no sentinels.
- **Linux Mint 22.3 test VM**: same engine, different host state — confirmed the `logs.attempts` sentinel regression had been fixed by the final v0.4.3 patch.
- **Debian 13**: minimal install, smoke test of the cross-distro path through `mac_policy`, journald-only UFW log path.
- **Kali Rolling**: 15 unexpected SUID binaries (kismet_cap_*) correctly flagged as Kali-specific tooling that legitimately needs SUID; NOPASSWD:ALL in sudoers detected with the right severity; AppArmor "0 profiles loaded" surfaced the confusing-message bug fixed here; COMPOUND risk correlation (sudo NOPASSWD + unexpected SUID) fired.
- **Ubuntu 26.04 LTS**: UFW inactive → `firewall.inactive` ALERT fired with the v0.4.2-added `key=`, the v0.4.3-added EXPLAIN_KEYS entry, CIS reference, and the `bob --explain firewall.inactive` link. The complete chain (key → ignore-able + profile-overridable + JSON-matchable + explain-resolvable) is now production-validated on a brand new distro family.

### Deferred to a later release

- Phase 2 Option A — systematic `Finding.template_vars` migration on the ~37 non-pilot checks. Still on track for v0.5.0+. `tests/test_template_vars_migration.py` continues to make the debt visible.
- Multi-distro CI matrix (Debian/Ubuntu/Mint/Kali in containers) and AUR PKGBUILD — community-contribution-welcome, not blocking.
- M3 cosmetic cleanup (os.path → pathlib).

---

## [v0.4.3] — 2026-05-15

**Doc catch-up release that grew into a hardening pass.** This release started as a closing of two pieces of debt explicitly deferred by v0.4.2 (4 `EXPLAIN_KEYS` entries, short CHANGELOG sync). On the way, a fresh agent audit over the entire v0.4.2 codebase surfaced **1 critical + 5 important + 8 minor + 6 suggestion** issues. All were fixed in the same release.

The full audit report is documented inline below, organised by criticality. Highlights:

- **C1 (critical)** — `bob --json --json-full` was crashing on every system with `AttributeError`. `bob/json_output.py` was reading 5 attributes (`fail2ban_active`, `auto_updates_enabled`, `apparmor_mode`, `apparmor_enforced`, `apparmor_complain`) from `HardeningSnapshot` after they had migrated to `mac_policy.py`. The dead reads were removed; the JSON output now exposes only the actual fields. A regression test was added to `tests/test_json_schema.py::TestFullModeWithOptionalSnapshots` covering the `full=True` + `hardening_snapshot` path — the precise gap that let the bug slip into v0.4.2.

- **I1 (important — silent failure)** — `datetime.strptime("%b ...")` parses English month abbreviations using the **Python process** `LC_TIME` setting. Subprocess `LC_ALL=C` only affects the *command's* output, not Python's. Under `LC_TIME=fr_FR.UTF-8` (common on French installations), `strptime("May 14 ...")` raised `ValueError` silently, causing `_read_cert_expiry` to return "could not parse notAfter" for every TLS certificate and `_parse_timestamp` to silently drop every syslog-format UFW log line. The audit score was systematically inflated on French systems because expiring certs and bruteforce attempts were invisible. New helper `_parse_english_month_day()` in `bob/checks/_run.py` parses by dict lookup, completely independent of locale.

- **I2 (important — incomplete contract)** — Roughly 30 `result.alert()/.warn()/.info()/.ok()/.add_deduction()` calls in `docker.py`, `firewall_stack.py`, `network_context.py`, and `ports.py` were missing the `key=` argument. Same class of bug as the v0.4.2 C1 fix, generalised to the 4 next-most-affected files. Without `key=`, the findings cannot be matched by `--ignore`, by audit profiles, or by external JSON consumers. The remaining ~6 files have lower density of missing keys and are tracked for a future pass.

- **I3 (important — broken email rendering)** — `bob/report_markdown.py::_inline_format` was building `<a href="...">label</a>` HTML first and then calling `html.escape()` on the result. Every link in email reports rendered as `&lt;a href=&quot;...&quot;&gt;label&lt;/a&gt;` literal text. Operation order reversed: escape the raw text first, then translate markdown to HTML.

- **I4 (important — score under-counting)** — `_is_covered_by_ufw` regex was unanchored: it matched the port number anywhere on a UFW rule line, including inside source-IP fields. An IP source like `192.168.1.22` would falsely "cover" port 22. Consequence: actual uncovered public ports were silently classified as covered, so the audit reported a higher score than the system deserved. Regex now anchored to the "To" column (right after `[ N]`).

- **I5 (important — silent cron data loss)** — `_validate_custom_cron` only sanity-checked plain-integer fields. Values like `0-1000 0 * * *` or `*/200 * * * *` passed the BOB validator and were then rejected by cron at parse time, silently losing the schedule. Full validator added: ranges, lists, step values, all 5 fields, with proper bounds (minute 0-59, hour 0-23, dom 1-31, month 1-12, dow 0-7).

In addition, the **8 minor** findings (dead locale keys, `_C_LOCALE_ENV` consistency, i18n concat anti-pattern, redundant regex, systemd template unit support) and **5 of 6 suggestion** findings (sysinfo env, symlink protection on cron files, domain_scores fallback logging, `__all__`) were applied. The 4 items the audit flagged that were skipped (M3 cosmetic, M4 negligible, M7 broken 20 tests on revert, S4 design discussion needed) are documented below for traceability.

Then the originally-planned doc catch-up:

1. **The 4 firewall keys promoted to `EXPLAIN_KEYS`.** In v0.4.2 the agent audit's C1 fix wired four keys (`prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`, `firewall.policy_unknown`) as `Finding.key` so that `--ignore`, audit profiles, and JSON consumers could match them. But `bob --explain firewall.policy_open` still answered "not found" because the keys were not in `EXPLAIN_KEYS` and had no associated title / why / how / CIS content. That content was deferred because writing four full explanations in both English and French is real documentation work, not a quick fix. This release does that work.

2. **CHANGELOG.md (short) corrected for v0.4.2.** The v0.4.2 detail section opened with "**No code changes** · 4449/4449 tests (unchanged)" which was factually wrong: the hardening pass shipped with v0.4.2 modified 11 Python files and added 3 tests. `CHANGELOG_FULL.md` was already correct; the short version was not. The section has been rewritten with the full hardening pass detail (C1, C2, I1-I5, M1-M5, S1-S3). The v0.4.2 release on PyPI and GitHub is unchanged — this is a doc-only retroactive fix in `main`.

### Why this is a separate release

It would have been tempting to amend v0.4.2 and force-push. Two reasons not to:

- The v0.4.2 tag and PyPI artifact are immutable. A "v0.4.2 with corrected docs" PyPI package is impossible. A separate release tracks the doc correction visibly.
- A user running `bob --version` on v0.4.2 followed by `bob --explain firewall.policy_open` would still see "not found". With v0.4.3 they see real content. The version bump is the truth.

### Changes

- **`bob/explain.py`** — the group label changes from "Firewall Logging" (which only contained `firewall.logging_off`) to "Firewall", and the four new keys join it. The TODO comment that marked the deferral in v0.4.2 is gone. `EXPLAIN_KEYS` length goes 112 → 116.
- **`bob/locales/en.json`** — new `explain.prerequisites.ufw_missing.{title,why,how}` entry, and three new entries under `explain.firewall.{inactive,policy_open,policy_unknown}.{title,why,how}`. Each entry follows the same shape as the pre-existing `explain.firewall.logging_off`: a short title, a paragraph explaining why this is a security risk (not just "what" the finding means), and a numbered remediation procedure.
- **`bob/locales/fr.json`** — same four entries in French, idiomatic translation (not literal).
- **`bob/data/cis_refs.json`** — 4 new entries. `prerequisites.ufw_missing` → CIS Ubuntu 22.04 L1 3.5.1.1 "Ensure ufw is installed". `firewall.inactive` → CIS 3.5.1.3 "Ensure ufw service is enabled". `firewall.policy_open` and `firewall.policy_unknown` → CIS 3.5.1.7 "Ensure ufw default deny firewall policy" (both keys map to the same control because the unknown case is a parsing failure of the same status output that policy_open detects positively).
- **`tests/test_explain.py`** — the `assert len(EXPLAIN_KEYS) == 112` hard-coded count moves to `116`. This assertion is the explicit freeze: when EXPLAIN_KEYS changes, the test forces you to update it in the same commit. That's the intended workflow.
- **`tests/test_display_explain_hint.py`** — two tests used `firewall.inactive` as an example of a finding key that should *not* trigger an `--explain` hint (because it wasn't in EXPLAIN_KEYS). Now that it is, those tests would have failed correctly. The fix replaces the example with a fictitious `test.nonexistent_key` so the tests stay resilient against future EXPLAIN_KEYS additions.
- **`CHANGELOG.md`** + **`CHANGELOG_FR.md`** — full v0.4.2 detail section rewritten with the hardening pass content. v0.4.2 already had this content in `CHANGELOG_FULL.md`; this brings the short version in sync.
- **Version bump** — `pyproject.toml`, `bob/__init__.py`, three schema `$id` URLs, two README badges, all from `0.4.2` → `0.4.3`.

### Tests

4464/4464 — +12 vs v0.4.2. No new test functions; the count growth is mechanical because `tests/test_explain.py` has three `@pytest.mark.parametrize("key", EXPLAIN_KEYS)` blocks (title check, WHY/HOW header check, CIS reference check), and adding 4 keys to `EXPLAIN_KEYS` produces 12 new parametrised invocations.

Validated end-to-end manually:
- `python3 -m bob --explain firewall.inactive` in both English and French shows the title, the WHY IT IS A RISK paragraph, the numbered HOW TO FIX procedure, and the CIS reference.
- Same for `firewall.policy_open`, `firewall.policy_unknown`, `prerequisites.ufw_missing`.
- `bob --explain firewall.logging_off` still works (regression check on the pre-existing key).
- `bob --explain list` shows the renamed "Firewall" group containing all 5 keys.

### Deferred to a later release

This release does not change the Phase 2 deferred work. The systematic migration of the remaining ~37 non-pilot checks to `Finding.template_vars` (Phase 2 Option A) is still tracked for **v0.5.0+**. The Phase 2 migration progress test (`tests/test_template_vars_migration.py`) continues to make this debt visible.

The multi-distro CI matrix and the AUR PKGBUILD are also still deferred — they're community-contribution-welcome, not blocking.

---

## [v0.4.2] — 2026-05-14

**Phase 3 of the distro-ready roadmap — packaging discipline.** This release adds the artefacts that distro maintainers need to package BOB without patching the source. Three man pages, a Debian source package targeting 3 binary packages (`bob-core` / `bob-tui` / `bob` meta), a Fedora RPM spec, an AppArmor profile, a `SECURITY.md` threat model, and a formal Python support policy. A pre-release agent audit also surfaced 2 critical + 5 important + 4 minor + 1 suggestion issues — all fixed in the same release (the "Hardening pass" section below). 4452/4452 tests (+3 from `tests/test_template_vars_migration.py`).

The strategic intent: BOB has crossed the "is it stable enough?" milestone in Phases 1 & 2. The remaining barrier to distro adoption is the absence of the standard packaging artefacts every distro maintainer expects to find in upstream. This release closes that gap.

---

### `SECURITY.md` — threat model and disclosure policy

**Files:** `SECURITY.md` (new)

#### Problem

Until v0.4.2, the security posture of BOB was implicit. A distro packager reading the repo had no formal answer to: who is the adversary? What threats does BOB defend against? What's out of scope? Where do I report a vulnerability? Without those answers, packagers either guess (dangerous) or pass on the project (worse).

#### Implementation

`SECURITY.md` (~150 lines) covers:

- **Supported versions table** with EOL policy: only the current minor receives security patches; breaking changes bump the minor.
- **Reporting channel**: `cedricclauzel@mailo.com` with `[BOB security]` subject prefix. 7-day acknowledgement, 30-day fix window for high-severity issues. Lower-severity issues are handled on the public tracker after acknowledgement.
- **Threat model section** spelling out what BOB is (audit-only tool invoked by a privileged user) and what BOB is NOT (no daemon, no remote agent, no active defense, no chain-of-custody forensics).
- **Adversary model**: three assumptions BOB makes about its operating environment (trusted invoking user, sane filesystem layout, intact package manager). BOB is a post-compromise audit tool, not pre-compromise detection.
- **Trust boundaries** table: user-controlled config (JSON Schema + ANSI sanitization + size limits + identifier check), system file content (bounded reads with `errors='replace'`, max-line caps, `_C_LOCALE_ENV` for subprocess), subprocess output (timeouts everywhere, no `shell=True` outside `--fix`, never eval'd).
- **Out of scope**: pre-existing root compromise, kernel-level attacks, application-level vulnerabilities.
- **`--fix` mode contract**: never executes anything without `y` confirmation; no eval of finding messages.
- **Plugin checks warning**: `~/.config/bob/checks.d/*.py` are NOT sandboxed — trust your plugin sources as you would any other root-executed code.
- **Network surface**: 2 outbound HTTPS calls (public IP lookup + webhook), both gated by `--offline`. No telemetry, no analytics.
- **Data handling**: file permissions, `chown_to_sudo_user` behavior since v0.3.6, baseline / history / config / log paths and what they contain.
- **Defense-in-depth recommendations for packagers**: ship the AppArmor profile in complain mode by default; ship `pipx` as the recommended install path.
- **Disclosure policy**: 30-day embargo extensible by mutual agreement, reporters credited unless anonymous request.

#### Design notes

- The "what BOB is NOT" list is intentionally explicit. Audit tools are sometimes misclassified as defenses; making the boundary clear up front saves misunderstandings.
- The trust-boundaries table maps each crossing to the specific code-side mitigation already in place — these are not aspirational promises but checks that already pass the test suite.

---

### Man pages

**Files:** `man/bob.1` (new, ~280 lines), `man/bob.conf.5` (new, ~80 lines), `man/bob-profile.5` (new, ~100 lines)

#### Problem

A Debian / Fedora package without man pages fails lintian/rpmlint's `binary-without-manpage` check and is harder for users to discover at `man -k`. Until v0.4.2 BOB shipped a `--help` text but no `man bob`.

#### Implementation

Three hand-written groff man pages (validated with `man -l` and `groff -man -Tutf8`):

- **`bob(1)`** — main user-facing page. Sections: `NAME`, `SYNOPSIS`, `DESCRIPTION`, `OPTIONS` (subgrouped by purpose: audit control, output formats, configuration, comparison/history, remediation, network, periodic audits, filters, misc), `EXIT CODES` (stable public API contract restated here), `JSON OUTPUT` (pointer to `DOCUMENTS/README_TECH.md` for the full schema), `FILES` (all paths under `~/.config/bob/` and elsewhere), `ENVIRONMENT` (`SUDO_USER`, `LC_ALL` / `LC_MESSAGES` / `LANG`), `SECURITY` (pointer to `SECURITY.md`), `SEE ALSO`, `AUTHOR`, `COPYRIGHT`.
- **`bob.conf(5)`** — config file format. Sections: keys for custom service ports, `log_dir`, `suid_whitelist` (with patterns documented), webhook defaults, the separate email address book file.
- **`bob-profile(5)`** — audit profile file format. Documents `[profile]` metadata, `[overrides]` per-key severity values (`info`/`warn`/`alert`/`skip`), the `extends` chain (5-level depth cap), profile file discovery order (user dir takes precedence over built-in), and the three shipped profiles (`server` / `desktop` / `container`).

Hand-written rather than generated via `argparse-manpage` to avoid adding a build dependency. The cost is manual updates when the CLI changes — but the CLI is now part of the stable public API (Phase 1) and is expected to change rarely.

#### Validation

```
$ for f in man/bob.1 man/bob.conf.5 man/bob-profile.5; do
    groff -man -Tutf8 "$f" >/dev/null && echo "✓ $f"
  done
✓ man/bob.1
✓ man/bob.conf.5
✓ man/bob-profile.5
```

---

### Debian source package

**Files:** `debian/control`, `debian/copyright`, `debian/changelog`, `debian/rules`, `debian/source/format`, `debian/bob-core.install`, `debian/bob-tui.install`, `debian/bob-core.docs`, `debian/bob-core.manpages`, `debian/apparmor.d/bob` (all new)

#### Problem

Debian packaging convention is a `debian/` folder at the project root containing a strict set of files. Without it, Debian downstream is impossible (or requires a per-build Quilt patch that no maintainer wants to carry).

#### Implementation

**Three binary packages declared in `debian/control`:**

| Binary package | Contains | Why split |
|---|---|---|
| `bob-core` | Audit pipeline, CLI, checks, scoring, JSON output, locales, schemas, man pages, SECURITY.md | Runs headless. No curses dependency. Suitable for containers, CI runners, minimal servers. |
| `bob-tui` | `bob/tui/` subpackage (curses TUI for cron wizards, future explain picker) | Optional. Pulls in `python3-curses` runtime. Recommended on workstations, skip on headless servers. |
| `bob` | Meta-package depending on both `bob-core` and `bob-tui` | Default user expectation: `apt install bob` installs everything. |

`Build-Depends`: `debhelper-compat (= 13)`, `dh-python`, `pybuild-plugin-pyproject`, `python3-all`, `python3-setuptools`, `python3-pytest <!nocheck>` — the last one is conditional so that `nocheck` builds skip the test suite. `Rules-Requires-Root: no` to satisfy modern Debian policy.

`Recommends` / `Suggests` clauses on `bob-core` list the soft dependencies BOB integrates with at audit time (`ufw`, `fail2ban`, `rkhunter`, `clamav`, `auditd`, `aide`, `unattended-upgrades`, `smartmontools`, `apparmor`, `fwupd`) — these are not hard build/runtime requirements, just things BOB knows how to interrogate when present.

**`debian/copyright`** uses DEP-5 (`https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/`) with distinct stanzas for the source code, the curated data files (`services.json`, profiles, `cis_refs.json`), the locale files, and the schemas. All MIT-licensed; the CIS Critical Security Controls references are explicitly noted as mappings (not redistribution of the CIS standard text).

**`debian/rules`** uses pybuild via `dh $@ --with python3 --buildsystem=pybuild`. An `override_dh_install` installs man pages and `SECURITY.md` into `bob-core` (`/usr/share/man/man1`, `/usr/share/man/man5`, `/usr/share/doc/bob-core/`).

**`debian/source/format`** is `3.0 (quilt)` — the standard for non-native upstream packages.

**Split files (`bob-core.install`, `bob-tui.install`)** list explicit paths so dh_install knows which module goes where. `bob/tui/` is exclusive to `bob-tui`; everything else lands in `bob-core`.

#### AppArmor profile

`debian/apparmor.d/bob` (~140 lines, separate from the other debian/ artefacts because AppArmor packaging is a Debian convention). Shipped in `complain` mode by default — the user opts into `enforce` after validating on their specific distro/version. Allows:

- read on `/etc/`, `/proc/`, `/sys/`, `/var/log/`, package manager state dirs
- read+write on `~/.config/bob/` and `~/.local/share/bob/`
- exec (via `Pix`) of a closed whitelist of ~30 system tools (`ufw`, `ss`, `iptables`, `systemctl`, `journalctl`, `openssl`, `smartctl`, `fwupdmgr`, `apt-cache`, `aa-status`, `dpkg`, `mokutil`, `bootctl`, `sysctl`, `swapon`, `timedatectl`, `chronyc`, `rkhunter`, `clamscan`, `freshclam`, `aide`, `auditctl`, `auditd`, `fail2ban-client`, `postconf`, `snap`, …)
- outbound TCP — the application-level `--offline` flag is the gate, not the profile

#### Design notes

- **Three binaries instead of one.** A single `bob` package would force every server / CI image to pull curses for a TUI it never uses. Splitting `bob-core` lets containerized / headless deployments stay slim without disabling features (the audit pipeline is identical between bob-core-only and bob+bob-tui installs).
- **Why complain mode by default for AppArmor.** BOB exec's many binaries whose paths vary across distros (`/sbin/sysctl` vs `/usr/sbin/sysctl`, `/usr/bin/iptables` vs `/usr/sbin/iptables` on RHEL-likes…). Shipping enforce would generate false denials on minor differences. Complain mode lets the user observe what's actually invoked and graduate to enforce once their distro/version has been validated.

---

### RPM spec for Fedora COPR

**Files:** `packaging/rpm/bob.spec` (new)

#### Problem

Fedora packaging conventions diverge from Debian's: a single `.spec` file, `pyproject-rpm-macros`, no `debian/` folder, different binary-package conventions (Fedora typically doesn't split Python packages into core/extras). Without a spec file, Fedora COPR / RHEL EPEL adoption is impossible.

#### Implementation

A single `bob` binary package on Fedora (no split). The spec uses `pyproject_wheel` / `pyproject_install` / `pyproject_save_files bob` to delegate to the standard `pyproject.toml` build pipeline.

`%check` runs the smoke test (`python -c "import bob; assert bob.__version__ == '0.4.2'"`) plus the full pytest suite (`python -m pytest tests/ -q`). On Fedora COPR, this catches any packaging-induced regression.

Man pages and `SECURITY.md` are installed via explicit `install -D` calls during `%install`.

`Recommends` and `Suggests` mirror the Debian control file with Fedora package names (`firewalld` vs `ufw`, `audit` vs `auditd`, etc.).

#### Design notes

- **Why a separate `packaging/rpm/` directory.** Debian convention puts everything under `debian/`. RPM doesn't have an equivalent root convention — `packaging/` keeps the two systems visibly separate while still living in upstream.
- **No `Patch:` lines.** The spec builds upstream as-is. If Fedora-specific patches become necessary later, they live in this directory alongside the spec.

---

### Python support policy

**Files:** `DOCUMENTS/README_TECH.md` + FR — new section

#### Problem

Distro maintainers planning their Python compatibility windows need to know whether BOB will support Python 3.10 in 2 years. Without a stated policy, every Python EOL becomes a renegotiation.

#### Implementation

New "Python support policy" section in `README_TECH.md` (and FR) commits to **N and N-2** where N is the current upstream stable. As of v0.4.2:

| Python | Status |
|---|---|
| 3.13 | ✅ supported (when released) |
| 3.12 | ✅ CI default |
| 3.11 | ✅ supported |
| 3.10 | ✅ oldest currently supported |
| 3.9 | ❌ EOL since v0.2.3 |

Drop procedure spans at least 3 minor BOB releases (validate / announce / remove) for a 6-month minimum notice. Mirrors Debian / Fedora's own freeze cycles.

---

### Tests

4452/4452 — +3 vs v0.4.1, all from `tests/test_template_vars_migration.py` (S1) which makes Phase 2 migration debt visible. The hardening pass (C1, C2, I1-I5, M1-M5, S2, S3) modified 11 Python files; the existing suite covered all of them and stayed green throughout.

Validated separately:
- `groff -man -Tutf8` and `man -l` parse all 3 man pages without errors.
- 3 schema JSON files load and validate via `jsonschema`.

---

### Roadmap context

| Phase | Status |
|---|---|
| Phase 1 (contracts) | ✅ v0.4.0 |
| Phase 2 (architectural decoupling) — Option B additive | ✅ v0.4.1 |
| Phase 2 — Option A breaking | ⏳ v0.5.0+ |
| **Phase 3 (packaging discipline)** | **✅ v0.4.2** |
| Phase 3 finishing touches (CI multi-distro, AUR PKGBUILD) | ⏳ v0.4.x community contributions |

After v0.4.2, BOB is **packaging-complete** for the AUR/COPR pathway and **ready for Debian unstable** pending lintian-clean verification + an upstream maintainer sponsorship.

---

### Hardening pass — pre-release audit

**Files:** `bob/checks/firewall.py`, `bob/checks/ssl_certs.py`, `bob/checks/virtualization.py`, `bob/_paths.py`, `bob/i18n.py`, `bob/registry.py`, `bob/watch.py`, `bob/__main__.py`, `bob/compare.py`, `bob/formatter.py`, `man/bob.1`, `debian/apparmor.d/bob`, `packaging/rpm/bob.spec`, `tests/test_template_vars_migration.py` (new), `microsoft.gpg` (deleted)

#### Problem

A full pre-release code audit (general-purpose agent, ~3500 lines of source consulted) surfaced **2 critical + 5 important + 4 minor + 1 suggestion** issues. The two critical findings concentrated on the packaging artefacts (written without mechanical cross-check against the code), confirming that this category of artefact deserves the same rigor as the source itself.

#### Critical fixes

**C1 — `firewall.py` findings without `key=`** (`bob/checks/firewall.py:154,165,178,183`). Three `result.alert()` calls (`prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`) and one `result.add_deduction()` lacked a `key=` argument. Consequence: the most critical alerts could not be matched by `--ignore`, by audit profiles, or by JSON consumers, because all of those use `Finding.key` / `Deduction.key` for matching. Fix: added `key=` to all 4 sites plus 4 lower-priority `result.ok()` / `result.warn()` calls in the same function for consistency. (`bob/explain.py` not extended yet — adding these 4 keys to `EXPLAIN_KEYS` requires writing full title/why/how/CIS content in both `en.json` and `fr.json` for each, **explicitly deferred to v0.4.3** with a TODO comment near the "Firewall Logging" group; `bob --explain firewall.policy_open` will say "not found" in v0.4.2 but `--ignore` / profiles / JSON matching all work correctly.)

**C2 — AppArmor profile incomplete + wrong path** (`debian/apparmor.d/bob`). 10 binaries that BOB actually exec's were missing from the profile (`df`, `lsblk`, `dpkg-query`, `getenforce`, `apt-get`, `find`, `ps`, `netstat`, `ntpstat`, `docker`) — in `enforce` mode, the disk/SUID/MAC/updates/SMTP/NTP/docker/desktop-apps checks would all return empty. Plus, line 85 declared `/usr/local/sbin/bob-*` rw whereas `bob/cron.py:30` writes to `/usr/local/bin/bob-{slug}` (`SCRIPT_DIR = Path("/usr/local/bin")`), so `--install-cron` would silently fail under enforce. Fixed by adding the 10 missing binaries and correcting the path.

#### Important fixes

**I1+I2 — Missing `_C_LOCALE_ENV` on three subprocess sites** (`bob/checks/ssl_certs.py:283`, `bob/checks/virtualization.py:166,178`). The SECURITY.md threat model promises that all subprocess calls use `_C_LOCALE_ENV` to avoid locale-dependent parsing. `openssl x509 -enddate` would emit "mai 14" on French locales which fails `datetime.strptime(..., "%b ...")`; `ip link show` and `snap connections --all` had the same risk on partial localization. Fixed by passing `env=_C_LOCALE_ENV` to the three subprocess calls (importing the constant where needed).

**I3 — Legacy env var `UFW_AUDIT_SHARE`** (`bob/_paths.py`). The project was named "UFW Audit" before v0.1.0; the share-dir env variable kept the old name despite the rename to BOB. Packagers were confused by it. Renamed to `BOB_SHARE` (the documented contract since v0.4.2). `UFW_AUDIT_SHARE` remains accepted for backward compatibility with installer scripts not yet updated — when both are set, `BOB_SHARE` wins. Logged as INFO when only the legacy name is used, prompting installer maintainers to update. Documented in `man/bob.1` ENVIRONMENT section.

**I4 — RPM `Recommends: firewalld`** (`packaging/rpm/bob.spec`). BOB reads `ufw status` exclusively — recommending `firewalld` was a Fedora-side guess that would mislead packagers and produce a "ufw not installed" alert on Fedora installs. Fixed to `Recommends: ufw` with an inline comment explaining BOB doesn't auto-detect firewalld.

**I5 — `bob/watch.py` not threading `user_config`** (line 80-83). The `--watch` mode silently lost the user's SUID whitelist because `run_checks()` was called without `user_config=`. The whitelist would be `[]` for every audit tick, producing false-positive SUID warnings repeatedly. Fix: thread `user_config` through `run_watch()` from `__main__.py` to the inner `run_checks()` call.

#### Minor fixes

- **M1** — Removed untracked `microsoft.gpg` (residue from `apt-add-repository` at the repo root).
- **M2** — Clarified `bob/formatter.py` docstring: "Status: this module is a public API for external integrators. No production code path in BOB itself calls format_finding / format_deduction in v0.4.x — the terminal output and report pipelines still rely on the pre-formatted message field." Removes the misleading impression that the formatter is the internal rendering path.
- **M4** — Exposed `bob.compare.BASELINE_PATH` (without the leading underscore) as the public symbol; `_BASELINE_PATH` kept as a transitional alias. `bob/__main__.py` updated to use the public name.
- **M5** — Added `Suggests: apparmor`, `Suggests: apparmor-utils` to the RPM spec for symmetry with the Debian package (apparmor is available on Fedora too).

#### Suggestion implemented

**S1 — `tests/test_template_vars_migration.py`** (new, 3 tests): tracks Phase 2 migration debt visibly. The current `_MIGRATED_CHECKS_V0_4_2` set is `{ssh.py, hardening.py, firewall.py}` — when more checks gain `template_vars=` calls, the set is updated in the same commit. A regression that accidentally removes `template_vars` from a migrated check now fails CI immediately.

#### Tests

4449 → **4452** (+3 from the new migration test). All existing tests remain green; the firewall fixes don't break any test that depended on the absence of keys (no such test existed — the previous behavior was simply unused).

#### Final note quality: 8.5/10 → 9/10

The pre-release audit closed the gap between SECURITY.md promises and code reality, fixed the only two real bugs in the run-time path (C1 and I5 — both with user-visible consequences), and aligned packaging artefacts with the source. The remaining work towards 10/10 is the systematic migration of the 37 non-pilot checks to `template_vars`, which is explicitly multi-release and tracked by the new test.

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

## [v0.1.0] — 2026-04-26

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

---

© 2026 Cédric Clauzel
