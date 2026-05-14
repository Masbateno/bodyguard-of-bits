*[Read in English](TESTING.md)*

# BOB — Plan de test : règles UFW dangereuses

Tests de régression manuels utilisant des règles UFW délibérément dangereuses.
Chaque test vérifie que BOB détecte (et corrige) correctement une mauvaise configuration spécifique.

---

## Historique des tests unitaires

| Version | Tests | Notes |
|---------|-------|-------|
| v0.4.0 | 4430 | Phase 1 distro-ready (+82) : `TestDetectSystemLang` (12) · `TestExplainKeyAliases` + `TestExplainKeyFreezePolicy` (6) · `test_json_schema.py` (17 — incl. strict-set + defense-in-depth contre dérive des constantes) · `test_services_schema.py` (43 — incl. `$defs`, regex port stricte 1–65535, contraintes métier, wrapper plugin-file, `minItems: 1` sur services-list) · 4 intégration locale CLI |
| v0.3.6 | 4348 | Aucun nouveau test — passe code review (`Path.home()` sudo-aware, ULA IPv6, SSH `local`, imports/locales morts) |
| v0.3.5 | 4348 | Aucun nouveau test — refactoring pur (`runner.py` closure `_sec`, `ssh.py` helper `_check_weak_algo`) |
| v0.3.4 | 4348 | Aucun nouveau test — hotfix uniquement (`user_config` NameError sur whitelist SUID) |
| v0.3.3  | 4348  | +7 nouveaux −6 supprimés (TestWasCapped → TestCappedIndices) : `TestCappedIndices` dans test_domain_scores |
| v0.3.2  | 4347  | +21 nouveaux (whitelist utilisateur) −2 supprimés (DC-1 code mort) : `TestFromSystemUserWhitelist` · `TestGetSuidWhitelist` · `TestGlobMatching` dans test_suid_audit |
| v0.3.1  | 4328  | +6 nouveaux tests : `TestWasCapped` dans test_domain_scores · flag was_capped · propriétés moteur en cache |
| v0.3.0  | 4322  | +48 nouveaux tests : affichage `--breakdown` · scénarios golden scoring · 16 dans test_breakdown · 32 dans test_golden_scenarios · 1 renommé dans test_min_level |
| v0.2.4  | 4274  | +12 nouveaux tests : UX kernel Debian -unsigned · sentinel None deduction_total · 2 dans test_kernel_modules · 10 dans test_compare |
| v0.2.3  | 4262  | +1 nouveau · 4 renommés : NOT_LISTENING INFO · IoT sans déduction · label SSH arrêté scindé |
| v0.2.2  | 4255  | +17 nouveaux tests · 2 mis à jour : `TestStatFallback` · `TestScoringInvariants` · fix règle UFW sans protocole · ClamAV 1pt · `ScoreCap.key` · domaines INFO exclus |
| v0.2.0  | 4238  | +32 nouveaux tests · 3 corrigés : `_strip_unsigned` · `_detect_mta` · `set_global_score` · plafonds par outil · dominance IoT WARN |
| v0.1.1  | 4206  | +4 tests de régression : parser fwupd 1.9+ format arbre (`├─`/`└─`) — bug trouvé sur Ubuntu 26.04 LTS |
| post-v0.1.0 | 4202 | +2 tests de régression : findings INFO non détectés en surface d'attaque (`ssh.not_installed`, `fail2ban.not_installed`) — bugs trouvés sur Ubuntu 26.04 LTS |
| v0.1.0  | 4200  | Version initiale — 65 fichiers de test ; 39 nouveaux tests dans `test_cis_refs.py` (mapping benchmarks CIS) ; couverture complète des 46 vérifications |

---

### v0.4.0 — 4430/4430 (14-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4430 passed in 5.52s
```

**Net : +82 (aucune suppression).** Contrats Phase 1 distro-ready figés, plus deux passes de hardening post-revue :
- **Passe #1** (+22 tests dans `test_services_schema.py`) : regex port stricte 1–65535, factorisation `$defs`, contraintes métier `if/then`/`anyOf`, wrapper `schema_version` plugin-file.
- **Passe #2** (+3 tests, defense-in-depth) : `services-list.minItems: 1` (rejette les tableaux vides), fixtures à classes réelles remplaçant `MagicMock` dans `test_json_schema.py` (les attributs renommés lèvent `AttributeError` au lieu d'être auto-mockés), `EXPECTED_REQUIRED_KEYS_V1` dupliqué pour détecter la dérive du contrat, compat shim `RefResolver`→`referencing` pour jsonschema 4.18+, asserts via `e.absolute_path` au lieu du matching de message fragile.

#### `tests/test_i18n.py` — `TestDetectSystemLang` (+12)

Détection automatique de locale POSIX (`$LC_ALL` / `$LC_MESSAGES` / `$LANG`) :

| Test | Couverture |
|---|---|
| `test_no_env_returns_default` | Aucune var env définie → `"en"` |
| `test_lang_c_returns_default` | `LANG=C` → `"en"` |
| `test_lang_posix_returns_default` | `LANG=POSIX` → `"en"` |
| `test_lang_c_utf8_returns_default` | `LANG=C.UTF-8` → `"en"` |
| `test_fr_fr_returns_fr` | `LANG=fr_FR.UTF-8` → `"fr"` |
| `test_fr_be_returns_fr` | `LANG=fr_BE` → `"fr"` |
| `test_fr_with_modifier_returns_fr` | `LANG=fr_FR.UTF-8@euro` → `"fr"` |
| `test_en_us_returns_en` | `LANG=en_US.UTF-8` → `"en"` |
| `test_unsupported_lang_falls_back_to_default` | `ja_JP`/`de_DE`/`es_ES`/`zh_CN` → `"en"` |
| `test_lc_all_overrides_lang` | `LC_ALL=fr` prime sur `LANG=en` |
| `test_lc_messages_overrides_lang` | `LC_MESSAGES=fr` prime sur `LANG=en` |
| `test_empty_lc_all_falls_through_to_lang` | `LC_ALL=""` → consulte `LANG` |

#### `tests/test_cli.py` — intégration locale (+4)

| Test | Couverture |
|---|---|
| `test_french_overrides_system_locale` | `--french` gagne sur `LANG=ja_JP` |
| `test_lang_explicit_overrides_system_locale` | `--lang=en` gagne sur `LANG=fr_FR` |
| `test_default_uses_system_locale_when_fr` | Défaut → `fr` quand `LANG=fr_FR.UTF-8` |
| `test_default_uses_en_when_lang_c` | Défaut → `en` quand `LANG=C` |

#### `tests/test_json_schema.py` (nouveau, +17)

Invariants du schéma de sortie JSON — contrat d'API publique :

| Classe | Tests |
|---|---:|
| `TestSchemaVersion` | 2 |
| `TestRequiredKeysAlwaysPresent` | 6 |
| `TestFieldTypes` | 5 |
| `TestStableKeysExposed` | 3 |
| `TestDomainScoresStructure` | 1 |

Vérifie `schema_version="1"`, clés top-level requises, types de champs, champ `key` indépendant de la locale sur chaque finding/deduction.

**Hardening passe #2 :** toutes les injections `MagicMock` dans les fixtures remplacées par les vraies dataclasses BOB (`SystemInfo`, `PortsSnapshot`, `FirewallStackSnapshot`, `NetworkContextSnapshot`, `CheckResult`) — un attribut renommé dans `bob.json_output.build_json_data` lève `AttributeError` au lieu d'être silencieusement auto-mocké. Le test de timestamp utilise désormais `datetime.fromisoformat()` (ISO 8601 strict). Deux nouveaux tests defense-in-depth : `test_short_mode_strict_set` (rejette les clés inattendues qui fuiraient en mode short) et `test_constants_match_expected_set` (attrape la dérive entre les constantes de production et le contrat hard-codé côté test).

#### `tests/test_explain.py` — alias map + freeze (+6)

| Test | Couverture |
|---|---|
| `test_alias_map_is_dict` | `EXPLAIN_KEY_ALIASES` est un dict |
| `test_alias_targets_resolve_to_valid_keys` | Chaque cible d'alias existe dans le set canonique |
| `test_alias_keys_are_not_in_canonical_set` | Les alias ne shadowent pas les vraies clés |
| `test_normalize_key_resolves_aliases` | Alias enregistré est résolu |
| `test_normalize_key_passthrough_when_no_alias` | Clés inconnues passent inchangées |
| `test_core_keys_present_in_canonical_set` | 16 clés "load-bearing" figées doivent rester dans `EXPLAIN_KEYS` |

#### `tests/test_services_schema.py` (nouveau, +43)

JSON Schema formel pour les plugins services (Draft 2020-12), étendu après deux passes de hardening post-revue :

| Classe | Tests | Couverture |
|---|---:|---|
| `TestSchemasAreWellFormed` | 4 | Les schémas passent l'auto-validation Draft 2020-12 ; `services-list` rejette les tableaux vides (passe #2 : `minItems: 1`) |
| `TestBundledServicesMatchSchema` | 3 | `services.json` bundled valide entrée par entrée ; IDs uniques (`Counter` O(n)) |
| `TestValidPluginSamples` | 3 | Plugins valides échantillons (minimal fixed, avec detection, user config_key) |
| `TestInvalidPluginSamples` | 10 | Cas de rejet : champ manquant, mauvais risk, mauvais port, port 0/65536, champ inconnu, fixed sans ports, ID avec espaces, string binary vide. Passe #2 : 5 d'entre eux assert désormais via `e.absolute_path` (stable entre versions de jsonschema) au lieu du matching de substring de message. |
| `TestSchemaPythonParity` | 2 | Alignement Schema-valid ↔ Python-valid |
| `TestBusinessConstraints` (nouveau passe #1) | 7 | `auto` requiert `config_files`, service indétectable rejeté, `detection: {}` vide rejeté |
| `TestPluginFileWrapper` (nouveau passe #1) | 6 | Array legacy + wrapped `{schema_version, services}` acceptés ; v2 / extras rejetés. Passe #2 : résolution cross-file `$ref` via le compat shim `_make_resolved_validator` (`referencing` moderne d'abord, fallback `RefResolver` legacy). |
| `TestRegistryAcceptsBothShapes` (nouveau passe #1) | 7 | Parité Python `_extract_plugin_entries` avec le méta-schéma |
| Tests aux bornes | 2 | Port 65535 accepté, 65536 rejeté (regex stricte) |

Une fixture module-scope `service_validator` est partagée entre toutes les classes (passe #2 — remplace 4 duplications par-classe d'un one-liner).

`jsonschema` est une dépendance test-only (utilise `pytest.importorskip`).

#### `tests/test_min_level.py` — affichage du score

`TestScoreTrend::test_stable_shows_equal` renommé `test_stable_shows_no_annotation` et inversé : un score stable affiche désormais exactement `"7/10"` (sans suffixe `= 7`).

#### `tests/conftest.py` (nouveau)

Fixture autouse force `LC_ALL=C`/`LANG=C` pour chaque test, rendant les défauts CLI dépendants de la locale déterministes indépendamment de la locale hôte du dev.

---

### v0.3.6 — 4348/4348 (09-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.04s
```

**Aucun nouveau test — passe de code review.** Huit correctifs liés : `Path.home()` → `get_user_home()` dans 7 modules · ULA/link-local IPv6 dans `_is_private_or_loopback` · SSH `AllowTcpForwarding local` accepté · header journalisation UFW masqué quand UFW inactif · regex legacy `NOTIFY_EMAIL` · `_check_weak_algo` déplacé dans la section sub-check · 22 imports inutilisés supprimés (pyflakes propre sauf un `noqa` intentionnel) · 47 clés de locales mortes supprimées.

**Validation terrain :** Audit complet sur so6desktop (Linux Mint 22.3) terminé avec score 8/10. L'en-tête de section journalisation UFW est désormais masqué quand UFW est inactif ; les link-local IPv6 sont correctement classés privés ; les profils/plugins/baselines sont correctement chargés depuis `/home/so6/.config/bob/` (et non `/root/.config/bob/`).

---

### v0.3.5 — 4348/4348 (08-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.22s
```

**Aucun nouveau test — refactoring pur (`runner.py` closure `_sec` −295 lignes, `ssh.py` helper `_check_weak_algo` −26 lignes)**

---

### v0.3.4 — 4348/4348 (08-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.17s
```

**Aucun nouveau test — hotfix uniquement (passage de `user_config` à `run_checks()` — `NameError` sur la whitelist SUID)**

---

### v0.3.3 — 4348/4348 (07-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.21s
```

**Bilan : +1 par rapport à v0.3.2 (+7 nouveaux tests capped_indices, −6 tests was_capped supprimés)**

#### `tests/test_domain_scores.py` — `TestCappedIndices` remplace `TestWasCapped` (+7, −6)

`TestWasCapped` testait le flag booléen `deduction.was_capped` (supprimé en v0.3.3). Remplacé par `TestCappedIndices` qui teste la valeur de retour `frozenset[int]` de `compute_domain_scores()`.

| Test | Couverture |
|------|------------|
| `test_no_cap_returns_empty_frozenset` | Aucun cap déclenché → second retour est `frozenset()` |
| `test_single_capped_deduction_returns_index` | Une déduction dépasse le cap → indice `0` dans le frozenset retourné |
| `test_uncapped_deduction_not_in_frozenset` | Déduction dans le cap → indice absent du frozenset |
| `test_multiple_deductions_only_capped_indices` | Deux déductions, une cappée → seul l'indice cappé est retourné |
| `test_frozenset_is_immutable` | L'objet retourné est un `frozenset`, pas un `set` |
| `test_engine_capped_indices_matches_return_value` | `engine.capped_indices` égale le frozenset retourné par `compute_domain_scores()` |
| `test_non_tool_cap_key_never_capped` | Clé sans préfixe tool-cap → jamais dans le frozenset cappé |

---

### v0.3.2 — 4347/4347 (07-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4347 passed in 5.23s
```

**Net : +19 depuis v0.3.1 (+21 nouveaux tests whitelist, −2 tests code mort supprimés)**

**Nouveaux tests (+21) :**

#### `tests/test_suid_audit.py` — `TestFromSystemUserWhitelist` (+8)

| Test | Couverture |
|------|------------|
| `test_whitelisted_suid_emits_info` | Snapshot avec chemins whitelistés → résultat INFO `suid_audit.whitelisted` |
| `test_whitelisted_suid_no_deduction` | Chemins whitelistés → aucune déduction |
| `test_whitelisted_suid_ok_result_when_no_unexpected` | Tout supprimé → `suid_audit.ok` toujours présent |
| `test_whitelisted_suid_warn_result_when_unexpected_remain` | Mix whitelisté + inattendu → les deux résultats présents |
| `test_whitelisted_count_in_info_message` | 2 chemins whitelistés → "2" dans le message INFO |
| `test_no_whitelisted_finding_when_list_empty` | `whitelisted_suid` vide → pas de résultat INFO |
| `test_whitelisted_truncation_at_10` | 11 chemins whitelistés → suffixe "+1 more" |

#### `tests/test_suid_audit.py` — `TestGetSuidWhitelist` (+7)

| Test | Couverture |
|------|------------|
| `test_returns_empty_list_when_key_absent` | Clé absente → `[]` |
| `test_single_pattern` | `kismet_cap_*` → `["kismet_cap_*"]` |
| `test_multiple_patterns_comma_separated` | `a, b, c` → `["a", "b", "c"]` |
| `test_strips_whitespace_around_patterns` | `  foo_*  ,  bar  ` → `["foo_*", "bar"]` |
| `test_empty_value_returns_empty_list` | Valeur chaîne vide → `[]` |
| `test_commas_only_returns_empty_list` | ` , , ` → `[]` |
| `test_persists_and_reloads` | Écrit puis rechargé → même liste |

#### `tests/test_suid_audit.py` — `TestGlobMatching` (+7)

| Test | Couverture |
|------|------------|
| `test_glob_matches_kismet_cap_prefix` | `kismet_cap_*` correspond à 3 chemins Kismet |
| `test_exact_name_match` | Pattern basename exact → chemin correspondant whitelisté |
| `test_non_matching_pattern_leaves_unexpected` | Pattern sans correspondance → chemin reste inattendu |
| `test_empty_patterns_leaves_all_unexpected` | Patterns vides → tous les chemins restent inattendus |
| `test_wildcard_star_matches_all` | Pattern `*` → tout whitelisté |
| `test_partial_glob_mix` | Mix : un correspondant, un non |
| `test_multiple_patterns_any_match_whitelists` | Deux patterns exacts → chacun correspond à sa cible |

**Tests supprimés (−2, DC-1) :**

`tests/test_suid_audit.py` — `TestIsRootOwned` supprimée avec la fonction `_is_root_owned()` (code mort) :
- `test_nonexistent_path_returns_false`
- `test_current_user_file_not_root_owned_when_not_root`

---

### v0.3.1 — 4328/4328 (06-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4328 passed in 4.33s
```

**Nouveaux tests (+6) :**

#### `tests/test_domain_scores.py` — `TestWasCapped` (+6)

| Test | Couverture |
|------|------------|
| `test_uncapped_deduction_not_marked` | Déduction dans le plafond outil → `was_capped` reste `False` |
| `test_fully_absorbed_deduction_marked` | Deuxième déduction après épuisement du plafond → `was_capped = True` |
| `test_partially_absorbed_deduction_marked` | Déduction dépasse partiellement le plafond restant → `was_capped = True` |
| `test_non_tool_cap_key_never_marked` | Clé sans préfixe de plafond outil → `was_capped` toujours `False` |
| `test_cached_domain_scores_on_engine` | Après `apply_domain_score_override()`, `engine.domain_scores` correspond à l'appel direct |
| `test_engine_domain_scores_empty_before_override` | Avant surcharge, `engine.domain_scores` retourne `{}` |

---

### v0.3.0 — 4322/4322 (06-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4322 passed in 4.45s
```

**Nouveaux tests (+48) :**

#### `tests/test_breakdown.py` (nouveau fichier, +16)

| Classe | Test | Couverture |
|--------|------|------------|
| `TestBar` | `test_full_score_all_filled` | Score 10 → tous les blocs remplis |
| `TestBar` | `test_zero_score_all_empty` | Score 0 → tous les blocs vides |
| `TestBar` | `test_five_half_filled` | Score 5 → moitié remplie |
| `TestDisplayBreakdownClean` | `test_no_deductions_message` | Aucune déduction → clé `no_deductions` affichée |
| `TestDisplayBreakdownClean` | `test_section_title_printed` | En-tête de section affiché |
| `TestDisplayBreakdownClean` | `test_final_score_ten_shown` | Score 10 → clé `breakdown.final_score` affichée |
| `TestDisplayBreakdownWithDeductions` | `test_deductions_header_shown` | Déductions présentes → en-tête affiché |
| `TestDisplayBreakdownWithDeductions` | `test_deduction_keys_shown` | Chaque clé de déduction apparaît dans la sortie |
| `TestDisplayBreakdownWithDeductions` | `test_raw_score_shown` | Clé `breakdown.raw_score` affichée |
| `TestDisplayBreakdownWithDeductions` | `test_domain_scores_header_shown` | Domaines actifs → en-tête affiché |
| `TestDisplayBreakdownWithDeductions` | `test_domain_average_shown` | Surcharge globale définie → `breakdown.domain_average` affiché |
| `TestDisplayBreakdownWithDeductions` | `test_final_score_shown` | Clé `breakdown.final_score` affichée |
| `TestDisplayBreakdownToolCap` | `test_tool_cap_message_shown_when_exceeded` | Déductions totales > plafond → ligne info plafond outil affichée |
| `TestDisplayBreakdownToolCap` | `test_no_tool_cap_message_when_within_limit` | Déductions totales ≤ plafond → pas de message plafond outil |
| `TestDisplayBreakdownEngineCap` | `test_engine_cap_message_shown` | `engine.cap_info` défini → `breakdown.engine_cap_applied` affiché |
| `TestDisplayBreakdownEngineCap` | `test_engine_cap_message_not_shown_when_absent` | Pas de plafond → pas de message plafond |

#### `tests/test_golden_scenarios.py` (nouveau fichier, +32)

| Classe | Tests | Couverture |
|--------|-------|------------|
| `TestCleanMachine` | 4 | Score 10/10 ; pas de breakdown ; aucun domaine actif ; findings INFO exclus de l'activation des domaines |
| `TestHardenedServer` | 3 | 2 déductions durcissement → score 8 ; déductions par domaine ; assertions breakdown brut |
| `TestDefaultDesktop` | 3 | 4 déductions sur 3 domaines → score 9 ; déductions exactes par domaine |
| `TestPoorlyConfiguredServer` | 3 | Score brut 3 ; moyenne domaines 8 ; moyenne supérieure au score brut |
| `TestFirewallInactive` | 3 | Plafond moteur appliqué à 3 ; moyenne domaine peut dépasser le brut plafonné ; `cap_info` stocké |
| `TestDebian13Minimal` | 4 | Score brut 2 ; moyenne domaines 6 ; plafond outil rootkit ; 6 déductions durcissement après plafond |
| `TestToolCapInvariants` | 4 | rootkit/clamav/file_integrity plafonnés à 1pt chacun ; outil non-plafonné (ssh) s'accumule normalement |
| `TestScoreStability` | 5 | Indépendance d'ordre ; monotonicité même-domaine ; indépendance des domaines ; score ∈ [0, MAX_SCORE] ; plancher brut à 0 |
| `TestMultiDomainMachine` | 3 | 5 domaines actifs exact (frozenset) ; chaque domaine déduit une fois ; score 9 |

#### `tests/test_min_level.py` (renommé, +0 net)

`test_stable_shows_right_arrow` → `test_stable_shows_equal` — assertion mise à jour de `"→" in val` vers `"= 7" in val`.

---

### v0.2.4 — 4274/4274 (05-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4274 passed in 4.65s
```

**Nouveaux tests (+12) :**

#### `tests/test_kernel_modules.py` (+2)

| Test | Couverture |
|------|------------|
| `test_up_to_date_names_running_kernel_not_unsigned_sibling` | Kernel courant `amd64` avec sibling `-unsigned` trié en `most_recent` → le message OK nomme le kernel courant, pas le sibling non-signé |
| `test_debian_signed_unsigned_pair_uses_obsolete_same_message` | Paire signé/non-signé en tête de la liste → clé `kernels_obsolete_same` sélectionnée (sans paire "courant / récent" dans le texte), pas `kernels_obsolete` |

#### `tests/test_compare.py` — `TestDisplayDelta` (+4)

| Test | Couverture |
|------|------------|
| `test_variable_deductions_increased_shown_without_structural_change` | `deduction_delta > 0`, aucun changement structurel (pas de delta alertes/warns, pas de clés nouvelles/résolues) → message déductions variables affiché |
| `test_variable_deductions_decreased_shown_without_structural_change` | `deduction_delta < 0`, aucun changement structurel → message de diminution des déductions affiché |
| `test_variable_deductions_suppressed_when_warn_delta` | `deduction_delta != 0` mais `warn_delta != 0` → message supprimé (changement structurel explique le mouvement de score) |
| `test_variable_deductions_suppressed_when_new_finding_key` | `deduction_delta != 0` mais `new_finding_keys` non vide → message supprimé |

#### `tests/test_compare.py` — `TestDeductionTracking` (nouvelle classe, +6)

| Test | Couverture |
|------|------------|
| `test_deduction_total_none_in_new_baseline_defaults` | Valeur par défaut de `AuditBaseline().deduction_total` est `None` (pas `0`) |
| `test_load_baseline_returns_none_when_field_absent` | Ancien JSON sans clé `"deduction_total"` → `None` après `load_baseline()` |
| `test_load_baseline_returns_int_when_field_present` | Nouveau JSON avec `"deduction_total": 5` → entier `5` après `load_baseline()` |
| `test_deduction_delta_zero_when_prev_is_old_baseline` | `prev.deduction_total is None` → `compute_delta()` retourne `deduction_delta == 0` |
| `test_deduction_delta_computed_when_both_tracked` | Les deux côtés ont un `deduction_total` entier → delta signé correct calculé |
| `test_deduction_delta_zero_when_unchanged` | Même valeur des deux côtés → `deduction_delta == 0` |

---

### v0.2.3 — 4262/4262 (03-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4262 passed in 4.53s
```

**Nouveaux tests (+1) :**

#### `tests/test_exposure.py` (+1)

| Test | Couverture |
|------|------------|
| `test_not_active_shows_stopped_text` | SSH installé mais service arrêté → tableau de surface d'attaque utilise la clé `exposure.ssh_stopped` ("installé — non démarré"), pas la clé fusionnée `ssh_not_running` |

**Tests mis à jour / renommés (4) :**

| Fichier | Test | Changement |
|---------|------|------------|
| `tests/test_services.py` | `test_not_listening_critical_adds_warn` → `test_not_listening_critical_adds_info` | `NOT_LISTENING` rétrogradé en INFO quelle que soit la sévérité du service |
| `tests/test_services.py` | `test_not_listening_high_adds_warn` → `test_not_listening_high_adds_info` | Idem — asserte aussi l'absence de finding WARN |
| `tests/test_logs.py` | `test_finding_is_warn_level` → `test_finding_is_info_level` | Dominance locale IoT rétrogradée en INFO — asserte `FindingLevel.INFO` |
| `tests/test_logs.py` | `test_score_deduction_one_point` → `test_no_score_deduction` | Dominance locale IoT sans déduction — asserte `len(local_deductions) == 0` |

---

### v0.2.2 — 4255/4255 (02-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4255 passed in 4.42s
```

**Nouveaux tests (+17) :**

#### `tests/test_firewall.py` — `TestOrphanRules` (+3)

| Test | Couverture |
|------|------------|
| `test_bare_port_rule_flagged_when_nothing_listening` | `57621 ALLOW IN` sans TCP ni UDP en écoute → signalé comme orphelin |
| `test_bare_port_rule_not_flagged_when_tcp_listening` | `57621/tcp` dans les ports en écoute → non signalé |
| `test_bare_port_rule_not_flagged_when_udp_listening` | `57621/udp` dans les ports en écoute → non signalé |

#### `tests/test_scoring.py` — `TestScoringInvariants` (+5)

Invariants structurels du moteur de scoring — propriétés devant tenir quel que soit l'input :

| Test | Invariant |
|------|-----------|
| `test_score_floor_is_zero_on_huge_deduction` | Le score ne descend jamais sous 0, même avec 999 points de déduction |
| `test_score_ceiling_is_max_on_no_deductions` | Le score vaut MAX_SCORE sans déductions |
| `test_deductions_are_monotone_decreasing` | Chaque déduction ne peut qu'abaisser ou maintenir le score |
| `test_cap_above_current_score_is_noop` | Un plafond supérieur au score actuel ne le modifie pas |
| `test_score_after_domain_override_in_valid_range` | Après `apply_domain_score_override()`, score ∈ [0, 10] |

#### `tests/test_domain_scores.py` — `TestScoringInvariants` (+7)

Invariants structurels pour le pipeline de scoring par domaine :

| Test | Invariant |
|------|-----------|
| `test_info_only_findings_do_not_activate_domain` | Findings INFO sans déduction n'activent pas le domaine |
| `test_warn_finding_activates_domain` | Un finding WARN active le domaine correspondant |
| `test_alert_finding_activates_domain` | Un finding ALERT active le domaine correspondant |
| `test_deduction_alone_activates_domain` | Une déduction seule (sans finding) active le domaine |
| `test_global_average_bounded_by_active_domain_scores` | Moyenne globale ∈ [min, max] des scores de domaines actifs |
| `test_all_domain_scores_in_valid_range` | Chaque score de domaine toujours dans [0, MAX_SCORE] |
| `test_compute_global_always_in_valid_range` | `compute_global_from_domains` retourne toujours une valeur dans [0, 10] |

#### `tests/test_manage_logs.py` — `TestStatFallback` (+2)

Tests de régression pour le fix race condition `.stat()` de v0.2.1. Un fichier log peut disparaître entre le scan du répertoire et la boucle d'affichage (ex. logrotate en parallèle). Le mock cible uniquement les fichiers `.log` pour ne pas casser `Path.exists()` sur les répertoires (Python 3.12 : `exists()` appelle `self.stat()` en interne).

| Test | Couverture |
|------|------------|
| `TestStatFallback.test_cur_logs_stat_oserror_uses_fallback` | `.stat()` lève `OSError` dans la boucle `cur_logs` → sortie affiche `(0 KB)` et `"?"` sans crash |
| `TestStatFallback.test_extra_logs_stat_oserror_uses_fallback` | `.stat()` lève `OSError` dans la boucle `extra_sections` → même sortie de repli |

**Tests mis à jour (2) :**

| Fichier | Test | Changement |
|---------|------|------------|
| `tests/test_clamav.py` | `test_db_very_outdated_deducts_1` (était `_deducts_2`) | Déduction `clamav.db_very_outdated` réduite de 2pt à 1pt (Fix 3) |
| `tests/test_clamav.py` | `test_worst_case` | Total déductions 4→3 (freshclam:1 + db_very_outdated:1 + scan_very_old:1) |

---

### v0.2.0 — 4238/4238 (01-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4238 passed in 4.31s
```

**Nouveaux tests (+32) :**

| Fichier | Nouveaux tests | Couverture |
|---------|----------------|-----------|
| `tests/test_kernel_modules.py` | +6 | Helper `_strip_unsigned` · variantes Debian signé/non-signé · vrai redémarrage toujours détecté |
| `tests/test_cron.py` | +6 | `_detect_mta` — sans sendmail, Postfix, Exim, msmtp, ssmtp, inconnu |
| `tests/test_scoring.py` | +6 | `set_global_score` — override, clamp, niveau, score brut inchangé |
| `tests/test_domain_scores.py` | +14 | Plafonds (rootkit/clamav/file_integrity) · `compute_global_from_domains` · `apply_domain_score_override` · scénario Debian 13 |
| `tests/test_logs.py` | 0 (+3 corrigés) | Dominance IoT : niveau WARN · déduction 1 pt · sous le seuil inchangé |

**3 tests corrigés dans `tests/test_logs.py` :**

| Test | Avant | Après |
|------|-------|-------|
| `test_check_logs_emits_warn_finding` | vérifiait la présence de la clé INFO | vérifie la présence de la clé WARN |
| `test_finding_is_warn_level` | vérifiait `FindingLevel.INFO` | vérifie `FindingLevel.WARN` |
| `test_score_deduction_one_point` | vérifiait l'absence de déduction | vérifie 1 déduction de 1 pt |

---

### v0.1.1 — 4206/4206 (29-04-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4206 passed in 4.19s
```

**Nouveaux tests — `tests/test_firmware.py` (+4) :**

Tests de régression pour le bug du format arbre fwupd 1.9+, trouvé sur Ubuntu 26.04 LTS. fwupdmgr a changé son format de sortie — d'une liste plate vers une structure en arbre avec les caractères `├─`, `└─`, `│`. L'ancien parser capturait ces caractères comme noms d'appareils, produisant une sortie corrompue (`│, ├─UEFI CA: (+7)`).

| Test | Couverture |
|------|------------|
| `test_tree_format_extracts_device_names` | Les lignes `├─` et `└─` produisent les bons noms d'appareils |
| `test_tree_format_excludes_container_line` | Le nom du conteneur parent n'est pas capturé |
| `test_tree_format_excludes_tree_connectors` | Les caractères bruts `│`, `├`, `└` n'apparaissent pas comme noms d'appareils |
| `test_tree_format_strips_trailing_colon` | Les noms extraits de `├─Nom:` ne conservent pas les deux-points finaux |

---

### post-v0.1.0 — 4202/4202 (2026-04-27)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4202 passed in 4.38s
```

**Bugs trouvés lors du premier run sur Ubuntu 26.04 LTS (`so6ubuntutest`) :**

**Correction — surface d'attaque : `ssh.not_installed` et `fail2ban.not_installed` non détectés :**
Ces deux clés sont émises au niveau `INFO` par leurs vérifications respectives. `compute_exposure()` dans `exposure.py` ne consultait que `bad_keys` (ALERT+WARN), donc aucune des deux n'était jamais détectée — SSH s'affichait comme "clé uniquement, root désactivé" et fail2ban comme "actif", même quand aucun des deux n'était installé.
Correction : ajout de `all_keys = bad_keys | info_keys` ; `ssh.not_installed` et `fail2ban.not_installed` sont désormais vérifiés dans `all_keys`. (commit `3fa43b5`)

**Correction — faux positif SUID : `sudo.ws` signalé sur Ubuntu 26.04 :**
`/usr/bin/sudo.ws` est un binaire légitime livré par le paquet `sudo` sur Ubuntu 26.04 (confirmé par `dpkg -S`). Ajouté à la whitelist `_KNOWN_SUID` dans `suid_audit.py`. (commit `3fa43b5`)

---

### v0.1.0 — 4200/4200 (2026-04-26)


**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4200 passed in 4.93s
```

#### Fichiers de test (65 au total)

| Fichier | Tests | Domaine |
|------|-------|--------|
| `test_cis_refs.py` | 39 | Mapping CIS benchmark |
| `test_iptables_nftables.py` | 51 | Pile firewall (CHECK 46) |
| `test_firewall.py` | — | Audit des règles UFW |
| `test_ssh.py` | — | Configuration SSH |
| `test_hardening.py` | — | Sysctl de renforcement kernel |
| `test_kernel_hardening.py` | — | Renforcement kernel étendu |
| `test_kernel_modules.py` | — | Audit des modules kernel |
| `test_services.py` | — | Registre de services + risque |
| `test_services_state.py` | — | Audit de l'état des services |
| `test_docker.py` | — | Contournement UFW Docker |
| `test_docker_audit.py` | — | Renforcement du démon Docker |
| `test_ports.py` | — | Classification des ports |
| `test_exposure.py` | — | Analyse de l'exposition des ports |
| `test_scoring.py` | — | Moteur de scoring |
| `test_domain_scores.py` | — | Scores par domaine |
| `test_explain.py` | — | --explain TUI |
| `test_display_explain_hint.py` | — | Affichage des hints CIS |
| `test_cli.py` | — | Parsing des arguments CLI |
| `test_exit_codes.py` | — | Logique des codes de sortie |
| `test_correlation.py` | — | Corrélation des signaux |
| `test_recurrence.py` | — | Détections récurrentes |
| `test_compare.py` | — | Diff/baseline |
| `test_history.py` | — | Historique des scores |
| `test_ignore.py` | — | Liste d'ignorés |
| `test_fixes.py` | — | --fix / --apply |
| `test_auth_log.py` | — | Analyse des logs d'authentification |
| `test_ufw_logging.py` | — | Niveau de log UFW |
| `test_log_rotation.py` | — | Rotation des logs |
| `test_cron.py` | — | Planification cron |
| `test_cron_audit.py` | — | Sécurité des jobs cron |
| `test_manage_logs.py` | — | TUI de gestion des logs |
| `test_webhook.py` | — | Notifications webhook |
| `test_profiles.py` | — | Profils d'audit |
| `test_registry.py` | — | Registre de services |
| `test_config.py` | — | Stockage de configuration |
| `test_sysinfo.py` | — | Informations système |
| `test_network_context.py` | — | Contexte réseau |
| `test_degraded.py` | — | Mode dégradé (ss/règles/log absents) |
| `test_output.py` | — | Sortie terminal |
| `test_markdown_output.py` | — | Sortie Markdown |
| `test_html_output.py` | — | Sortie HTML |
| `test_csv_output.py` | — | Sortie CSV |
| `test_report.py` | — | Génération de rapports |
| `test_min_level.py` | — | Filtre --min-level |
| `test_watch.py` | — | Mode --watch |
| `test_check_rules.py` | — | Validation des règles |
| `test_file_perms.py` | — | Permissions de fichiers |
| `test_suid_audit.py` | — | Audit SUID/SGID |
| `test_user_accounts.py` | — | Comptes utilisateurs |
| `test_password_policy.py` | — | Politique de mot de passe |
| `test_umask.py` | — | Umask système |
| `test_updates.py` | — | Mises à jour système |
| `test_ntp.py` | — | Synchronisation NTP |
| `test_fail2ban.py` | — | Fail2ban |
| `test_rootkit.py` | — | Scan rootkit |
| `test_auditd.py` | — | Démon audit |
| `test_secure_boot.py` | — | Secure Boot |
| `test_file_integrity.py` | — | Intégrité des fichiers |
| `test_clamav.py` | — | ClamAV |
| `test_mac_policy.py` | — | AppArmor/SELinux |
| `test_backup.py` | — | Détection de sauvegarde |
| `test_disk.py` | — | Santé disque |
| `test_memory.py` | — | Mémoire/swap |
| `test_ssl_certs.py` | — | Expiration des certificats TLS |
| `test_systemd_timers.py` | — | Timers systemd |
| `test_desktop_apps.py` | — | Applications desktop |
| `test_samba.py` | — | Renforcement Samba |
| `test_ddns.py` | — | Détection DDNS |
| `test_firmware.py` | — | Firmware/microcode |
| `test_smtp.py` | — | Exposition SMTP |
| `test_ipv6.py` | — | Cohérence IPv6 |
| `test_virtualization.py` | — | Détection virtualisation |
| `test_email_store_mgmt.py` | — | Gestion stockage email |
| `test_recurrence.py` | — | Suivi de récurrence |
| `tests/helpers.py` | — | Utilitaires de test partagés |

----

**VM de test :** Linux Mint 22.3 — `so6minttest`
**État de référence** (baseline propre après chaque test) :

```bash
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80
sudo ufw enable
```

----

## Catégorie A — Wildcards open-any

Règles ouvrant tous les ports à toutes les sources — sévérité majeure.

### A1 — Wildcard complet `Anywhere ALLOW IN Anywhere`

```bash
sudo ufw allow from any
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle autorisant toutes connexions entrantes sans restriction port | ✔ v0.1.0.0 |
| Déduction score `-2` | ✔ |
| Correction proposée : `sudo ufw --force delete N` | ✔ |
| Correction appliquée correctement | ✔ |
| **Règle IPv6 aussi détectée et corrigée** (`Anywhere (v6) ALLOW IN Anywhere (v6)`) | ✔ v0.1.0 |

**Cause racine corrigée  :** `ufw status numbered` remplit lignes avec espaces trailing — l'ancre `$` dans regex ne correspondait jamais. Corrigé : `Anywhere$` → `Anywhere\s*$`. (commit `8ccd9b6`)

**Cause racine corrigée  :** Règles wildcard IPv6 (`Anywhere (v6) ALLOW IN Anywhere (v6)`) échappaient à la détection — `open_any_pattern` ne prenait pas en compte le suffixe `(v6)`. Corrigé : motif étendu avec `(?:\s+\(v6\))?` des deux côtés. Règles IPv4 et IPv6 sont maintenant signalées et corrigées indépendamment.

---

### A2 — Wildcard TCP `Anywhere/tcp ALLOW IN Anywhere/tcp`

```bash
sudo ufw allow proto tcp from any to any
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle autorisant toutes connexions entrantes sans restriction port | ✔ v0.1.0.0 |
| Déduction score `-2` | ✔ |
| Correction appliquée correctement | ✔ |
| **Variante IPv6 aussi détectée** (`Anywhere/tcp (v6) ALLOW IN Anywhere/tcp (v6)`) | ✔ v0.1.0 |

**Cause racine corrigée  :** Motif étendu à `Anywhere(?:/\w+)?` des deux côtés pour couvrir variantes `/tcp`, `/udp`. (commit `1dd9ede`)

**v0.1.0 :** Même correction IPv6 que A1 s'applique ici.

---

### A3 — Wildcard UDP `Anywhere/udp ALLOW IN Anywhere/udp`

```bash
sudo ufw allow proto udp from any to any
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle autorisant toutes connexions entrantes sans restriction port | ✔ v0.1.0.0 |
| Déduction score `-2` | ✔ |
| Correction appliquée correctement | ✔ |
| **Variante IPv6 aussi détectée** | ✔ v0.1.0 |

---

### A4 — Les trois wildcards simultanément

```bash
sudo ufw allow from any
sudo ufw allow proto tcp from any to any
sudo ufw allow proto udp from any to any
```

| Attendu | Résultat |
|----------|----------|
| 3 résultats `✖ [ALERTE]` distincts (IPv4 uniquement) | ✔ v0.1.0.0 |
| **6 résultats `✖ [ALERTE]` distincts (IPv4 + IPv6)** | ✔ v0.1.0 |
| Score : 0/10 (plafonné), Niveau risque : CRITIQUE | ✔ |
| 6 corrections proposées et appliquées en ordre index inverse | ✔ v0.1.0 |

---

### A5 — Faux positif : règle source restreinte

```bash
sudo ufw allow from 192.168.1.0/24
```

| Attendu | Résultat |
|----------|----------|
| `✔ [OK]` Aucune règle 'allow from any' sans restriction de port détectée | ✔ v0.1.0 |
| Règle source-restreinte NON signalée comme open-any | ✔ |

> `ufw status numbered` montre `Anywhere ALLOW IN 192.168.1.0/24` — destination est `Anywhere` mais source est restreinte. Le motif requiert correctement que LES DEUX côtés soient `Anywhere` pour déclencher.

---

## Catégorie B — Règles dupliquées

### B1 — Duplication exacte

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/tcp   # UFW dit: "Skipping adding existing rule"
```

| Attendu | Résultat |
|----------|----------|
| UFW nativement prévient vrais doublons exacts | ✔ confirmé |
| Non testable via CLI — requirerait manipulation directe fichiers | noté |

> **Note :** Doublons exacts peuvent seulement résulter édition directe `/etc/ufw/` ou outils externes (Ansible, scripts). CLI UFW les prévient.

---

### B2 — Même règle, commentaires différents

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (pas proto) déjà présent dans baseline
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle UFW dupliquée détectée : `80/tcp ALLOW IN Anywhere` | ✔ v0.1.0.0 |
| Commentaire supprimé avant comparaison — `# test2` ignoré | ✔ |
| `80/tcp` redondant supprimé, `80` gardé | ✔ |

**Cause racine corrigée :** Comparaison utilise maintenant texte stripé-commentaires, normalisé-espaces. (commit `b7a285a`)

---

### B3 — Duplication sémantique : `PORT/proto` redondant quand `PORT` existe

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (pas proto) déjà présent → 80/tcp est redondant
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle UFW dupliquée détectée : `80/tcp ALLOW IN Anywhere` | ✔ v0.1.0.0 |
| Déduction score `-1` | ✔ |
| Correction supprime la règle protocol-spécifique, garde la plus large | ✔ |

**Cause racine corrigée :** Détection deux-passes — première passe collecte toutes règles sans-protocole, deuxième passe vérifie si `PORT/proto` est subset d'existant `PORT`. (commit `b7a285a`)

---

### B4 — Duplication sémantique : variante UDP

```bash
sudo ufw allow 53/udp
sudo ufw allow 53
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` `53/udp` détecté comme redondant | ✔ unit test |

> Validé via unit test uniquement (port DNS — pas dans registry services, pas risque pratique sur VM).

---

### B5 — Pas faux positif : `PORT/tcp` + `PORT/udp` sans `PORT`

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/udp
# Pas règle nulle "80"
```

| Attendu | Résultat |
|----------|----------|
| `✔ [OK]` Pas règles UFW dupliquées détectées | ✔ v0.1.0.0 |
| `80/tcp` et `80/udp` sont complémentaires — pas signalés | ✔ |

> Aussi noter : quand baseline a `80` (nu), ajouter `80/tcp` + `80/udp` correctement signale TOUTES DEUX comme doublons sémantiques de `80`. Vérifié en direct.

---

## Catégorie C — Services critiques exposés

### C1 — SSH exposé (état de la baseline)

SSH est toujours présent dans l'état de référence (`ufw allow 22/tcp`). Ce scénario documente le comportement attendu pour un service critique avec une règle UFW ALLOW non restreinte.

```bash
# État de la baseline — SSH déjà exposé
sudo bob
```

| Attendu | Résultat |
|---------|----------|
| `✖ [ALERTE]` Port 22/tcp — ouvert à internet — aucune restriction source dans UFW | ✔ v0.1.0.0 |
| Contexte risque CRITIQUE affiché | ✔ v0.1.0.0 |
| Déduction score `-2` (contexte NAT/local) | ✔ v0.1.0.0 |
| Panorama : SSH `⚠` (OPEN_WORLD) | ✔ v0.1.0.0 |
| DDNS `→ 22/tcp` | ✔ v0.1.0.0 |
| **Remédiation :** restriction source → passe en OPEN_LOCAL (WARN non ALERTE, sans déduction) | ✔ v0.1.0.0 |

> **Note :** `openssh-server` doit être installé et actif (`sudo apt install openssh-server && sudo systemctl enable --now ssh`). Si inactif/désactivé, le service est en INFO uniquement sans vérification d'exposition des ports.

> **Remédiation à tester :** `sudo ufw delete allow 22/tcp && sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp` → passe en OPEN_LOCAL (AVERTISSEMENT et non ALERTE, sans déduction).

---

### C3 — Redis exposé sur toutes les interfaces (service installé et actif)

```bash
sudo ufw allow 6379
# Redis configuré pour écouter sur 0.0.0.0 (pas la configuration par défaut)
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Port 6379/tcp — ouvert à internet (Action requise) | ✔ v0.1.0.0 |
| Contexte risque CRITIQUE affiché | ✔ |
| Déduction score `-2` (contexte NAT) | ✔ |
| Panorama : Redis `✖` → `⚠` | ✔ |
| Vérification croisée DDNS : `→ 6379/tcp` | ✔ v0.1.0.0 (`6379/udp` filtré — pas de listener UDP) |

**Cause racine corrigée (obs 1) :** Services CRITIQUE/ÉLEVÉS avec exposition `OPEN_WORLD` lèvent maintenant `alert()` au lieu `warn()`, les déplaçant à « Action requise ». (commit `e01b24b`)

---

### C3b — Redis loopback uniquement — correction faux positif 

Configuration Redis par défaut : écoute sur `127.0.0.1` uniquement, mais une règle UFW permissive existe.

```bash
sudo ufw allow 6379
# Redis par défaut : bind 127.0.0.1 (loopback uniquement)
```

| Attendu | Résultat |
|----------|----------|
| `ℹ [INFO]` Port 6379/tcp — lié uniquement sur localhost — la règle UFW n'a aucun effet sur l'accès externe | ✔ v0.1.0.0 |
| Pas d'ALERTE, pas de déduction de score | ✔ |
| Panorama : Redis `✔` (règle existe, exposition = LOOPBACK) | ✔ |
| DDNS : `6379/tcp` absent de la liste exposée (loopback uniquement) | ✔ |
| DDNS : `6379/udp` absent de la liste exposée (pas de listener UDP) | ✔ |

**Cause racine corrigée  :** `_classify_exposure()` se basait uniquement sur UFW et ne vérifiait pas les bindings réels des sockets. Correction : `PortsSnapshot` est collecté avant le CHECK 3 ; les ports dont tous les bindings `ss` sont en loopback reçoivent `Exposure.LOOPBACK` (INFO, sans déduction). `_find_open_ports()` dans `ddns.py` reçoit également les ensembles `loopback_ports` et `active_ports`. (commits `2bfc85b`, `64311be`)

---

### C2 — MySQL exposé (service non installé)

```bash
sudo ufw allow 3306
```

| Attendu | Résultat |
|----------|----------|
| Pas d'alerte service (MySQL non installé) | ✔ v0.1.0.0 |
| Port 3306 ouvert dans UFW mais non-correspondant à aucun service installé | confirmé |
| DDNS : `3306/tcp` et `3306/udp` absents de la liste exposée (aucun listener actif) | ✔ v0.1.0.0 |

> **Comportement mis à jour  :** `_find_open_ports()` effectue maintenant une vérification croisée avec les listeners non-loopback réels (ensemble `active_ports` depuis `ss`). Les règles UFW orphelines (port ouvert, aucun service actif) sont exclues de la liste d'exposition DDNS. `3306/tcp` et `3306/udp` n'apparaissent plus dans les résultats DDNS quand MySQL n'est pas installé.

---

### C4 — Nginx exposé (service à risque moyen, installé et actif)

```bash
sudo apt install nginx
sudo ufw allow 80
sudo bob
```

| Attendu | Résultat |
|---------|----------|
| `⚠ [AVERTISSEMENT]` Port 80/tcp — ouvert à internet — aucune restriction source dans UFW | ✔ v0.1.0.0 |
| Contexte risque MOYEN affiché | ✔ v0.1.0.0 |
| Déduction score `-1` | ✔ v0.1.0.0 |
| Panorama : Nginx `⚠` | ✔ v0.1.0.0 |
| Résultat dans *Améliorations possibles* (et non *Action requise*) | ✔ v0.1.0.0 |

> Les services à risque moyen utilisent `warn()` et non `alert()` — distinction par rapport aux services critiques comme SSH ou Redis.

---

### C5 — Samba exposé (service critique, installé et actif)

```bash
sudo apt install samba
sudo ufw allow 445
sudo ufw allow 139
sudo bob
```

| Attendu | Résultat |
|---------|----------|
| `✖ [ALERTE]` Port 445/tcp — ouvert à internet — aucune restriction source dans UFW | ✔ v0.1.0.0 |
| `✖ [ALERTE]` Port 139/tcp — ouvert à internet | ✔ v0.1.0.0 |
| Contexte risque CRITIQUE affiché (vecteur ransomware, EternalBlue) | ✔ v0.1.0.0 |
| Déduction `-2` × 2 ports (−4 total) | ✔ v0.1.0.0 |
| Panorama : Samba `⚠` (OPEN_WORLD) | ✔ v0.1.0.0 |
| Les deux ports dans le bloc *Action requise* | ✔ v0.1.0.0 |
| DDNS `→ 445/tcp`, `→ 139/tcp` | ✔ v0.1.0.0 |

> **Nettoyage :** `sudo apt remove --purge samba && sudo ufw delete allow 445 && sudo ufw delete allow 139`

---

### C6 — Ports ouverts dans UFW, services non installés (services multiples)

Pour chaque entrée ci-dessous : ouvrir le port dans UFW sans service correspondant installé. Comportement attendu : **aucune alerte service**, le port peut apparaître comme règle UFW orpheline.

```bash
sudo ufw allow <PORT>
sudo bob
```

| Service | Port | Comportement attendu | Résultat |
|---------|------|---------------------|----------|
| Serveur VNC | 5900/tcp | Pas d'alerte service — VNC non détecté | ✔ v0.1.0.0 |
| Serveur FTP | 21/tcp | Pas d'alerte service — FTP non détecté | ✔ v0.1.0.0 |
| PostgreSQL | 5432/tcp | Pas d'alerte service — PostgreSQL non détecté | ✔ v0.1.0.0 |
| Mosquitto (MQTT) | 1883/tcp | `ℹ [INFO]` 1883/tcp loopback — règle UFW sans effet ; 8883/tcp non en écoute — aucun message ; Panorama ✔ | ✔ v0.1.0.0 ² |
| WireGuard | 51820/udp | `ℹ [INFO]` WireGuard installé mais arrêté/désactivé — pas de vérification d'exposition (retour anticipé INACTIVE) | ✔ v0.1.0.0 ¹ |
| Gitea | 3000/tcp | Pas d'alerte service — Gitea non détecté | ✔ v0.1.0.0 |
| Jellyfin | 8096/tcp | Pas d'alerte service — Jellyfin non détecté | ✔ v0.1.0.0 |
| Home Assistant | 8123/tcp | Pas d'alerte service — HASS non détecté | ✔ v0.1.0.0 |
| Cockpit | 9090/tcp | Pas d'alerte service — Cockpit non détecté | ✔ v0.1.0.0 |

> Pour tous les cas ci-dessus : le port n'a pas de listener actif — aucune ALERTE dans ANALYSE DES SERVICES RÉSEAU.
> Vérification croisée DDNS : aucun de ces ports ne doit apparaître dans la liste exposée DDNS (aucun listener actif — correction v0.1.0).

> ¹ WireGuard était déjà installé (mais inactif) sur la VM de test. Le chemin « non installé » reste non testé — comportement confirmé : service INACTIVE avec une règle UFW ouverte → INFO uniquement, pas d'ALERTE, pas de déduction.

> ² Mosquitto était installé et ACTIF sur la VM de test (ne correspond pas au scénario C6 « non installé »). Le test a révélé un bug : les ports du registre non en écoute (8883/tcp) déclenchaient incorrectement `Exposure.NO_RULE` → panorama ✖. Corrigé en beta (commit `67743ca`) : `Exposure.NOT_LISTENING` pour les ports du registre non en écoute → panorama ✔.

> **Déjà validé :** MySQL / MariaDB (3306) → C2

---

### C7 — CUPS exposé (service à faible risque, souvent pré-installé sur desktop Linux)

CUPS (serveur d'impression) écoute sur `127.0.0.1:631` par défaut. Ce test vérifie le comportement quand CUPS est actif et une règle UFW existe.

```bash
# CUPS est souvent pré-installé sur Linux Mint
sudo ufw allow 631
sudo bob
```

| Attendu | Résultat |
|---------|----------|
| `ℹ [INFO]` Port 631/tcp — lié uniquement sur localhost — la règle UFW n'a aucun effet | ✔ v0.1.0.0 |
| Pas d'ALERTE, pas de déduction de score (binding loopback) | ✔ v0.1.0.0 |
| Panorama : CUPS `✔` (règle existe, loopback → INFO) | ✔ v0.1.0.0 |

> Si CUPS écoute sur `0.0.0.0` : `⚠ [AVERTISSEMENT]` Port 631/tcp — ouvert à internet (risque faible, nature=improvement).

---

## Catégorie D — Cohérence IPv6

### D1 — Règles IPv4 présentes, aucun équivalent IPv6 (avertissement attendu)

```bash
# Depuis la baseline : 22/tcp et 80 sont présents, aucune règle (v6)
sudo ufw status numbered
```

> **Note :** Certaines distributions (ou VMs avec `IPV6=no` dans `/etc/default/ufw`) n'ajoutent pas de règles IPv6. Si toutes les règles sont déjà couplées (IPv4 + IPv6), utiliser `sudo ufw --force reset` et re-ajouter uniquement les règles IPv4.

| Attendu | Résultat |
|----------|----------|
| `⚠ [AVERTISSEMENT]` Règles IPv6 manquantes — seules des règles IPv4 présentes | ✔ unit test |
| Déduction score `-1` | ✔ unit test |
| Test direct | ✔ v0.1.0.0 |

---

### D2 — Règles IPv4 et IPv6 toutes deux présentes (pas d'avertissement)

| Attendu | Résultat |
|----------|----------|
| `✔ [OK]` Règles IPv4 et IPv6 toutes deux présentes | ✔ unit test |
| Aucune déduction | ✔ unit test |
| Test direct | ✔ v0.1.0.0 |

---

## Observations supplémentaires

### Obs — Avahi affiche ✖ au panorama malgré message INFO (v0.1.0)

Avahi écoute sur `0.0.0.0:5353/udp` (multicast mDNS). Aucune règle UFW pour 5353 → `Exposure.NO_RULE` → panorama ✖. Le check service émet correctement `ℹ [INFO]` "couvert par la politique deny par défaut", mais le symbole panorama est déterminé par la valeur enum `NO_RULE` indépendamment de la sévérité INFO.

**Cause racine :** `NO_RULE` sur un port non-loopback, non exposé publiquement (multicast/LAN uniquement en pratique) est traité identiquement à `NO_RULE` sur un port réellement exposé. Un fix futur pourrait introduire `Exposure.NO_RULE_MULTICAST` ou un mécanisme plus large pour distinguer les `NO_RULE` à portée locale des `NO_RULE` réellement exposés.

**Impact :** cosmétique uniquement — pas de fausse ALERTE, pas de déduction de score.

---



### Obs — DDNS ne détecte pas règles sans-protocole (corrigé)

Avec `80 ALLOW IN Anywhere` (pas `/tcp`), la vérification croisée DDNS n'affichait précédemment rien pour le port 80.

**Cause racine corrigée :** `_find_open_ports()` gère maintenant les règles ports nus — ajoute `PORT/tcp` et `PORT/udp` à la liste des ports ouverts. (commit `e01b24b`)

**Validé (v0.1.0) :** Règle nue `80 ALLOW` avec Nginx écoutant sur `0.0.0.0:80` → DDNS liste correctement `→ 80/tcp` uniquement (`80/udp` filtré — aucun listener UDP sur le port 80).

---

### Obs — Faux positifs DDNS : ports système et règles orphelines 

```bash
sudo ufw allow 53
sudo ufw allow 3306
sudo ufw allow 6379
# Redis sur 127.0.0.1 uniquement, MySQL non installé
```

| Attendu | Résultat |
|----------|----------|
| DDNS : `53/tcp`, `53/udp` absents (filtre ports système) | ✔ v0.1.0.0 |
| DDNS : `3306/tcp`, `3306/udp` absents (aucun listener actif) | ✔ v0.1.0.0 |
| DDNS : `6379/tcp`, `6379/udp` absents (loopback uniquement / pas de listener UDP) | ✔ v0.1.0.0 |

**Cause racine corrigée  :** Ajout de la constante `_DDNS_SYSTEM_PORTS` (53, 67, 68, 546, 547, 5353) et vérification croisée `active_ports` dans `_find_open_ports()`. Seuls les ports avec un listener non-loopback réel dans la sortie `ss` sont inclus dans la liste d'exposition DDNS. (commit `64311be`)

---

### Obs — UFW permet règles wildcard après règles spécifiques sans erreur

```
Anywhere/tcp    ALLOW IN    Anywhere/tcp
22/tcp          ALLOW IN    Anywhere
```

UFW n'avertit pas que `Anywhere/tcp` rend `22/tcp` redondant. bob correctement signale le wildcard.

---

## Note B1 — doublons exacts via manipulation fichiers

Pour tester doublons exacts que CLI UFW prévient, règles peuvent être injectées directement :

```bash
sudo cp /etc/ufw/user.rules /etc/ufw/user.rules.bak
# Manuellement dupliquer ligne règle dans user.rules
sudo ufw reload
sudo bob
# Nettoyage :
sudo cp /etc/ufw/user.rules.bak /etc/ufw/user.rules
sudo ufw reload
```

Pas encore testé — priorité pratique basse car CLI UFW le prévient.

---

## Catégorie E — Ports loopback uniquement 

### C8 — SSH restreint au LAN (chemin OPEN_LOCAL)

```bash
sudo ufw delete allow 22/tcp
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp
sudo bob
```

| Attendu | Résultat |
|---------|----------|
| `⚠ [AVERTISSEMENT]` Port 22/tcp — restreint au réseau local par règle UFW | ✔ v0.1.0 |
| Pas de déduction score (OPEN_LOCAL ≠ OPEN_WORLD) | ✔ v0.1.0 |
| Panorama : SSH `✔` (restriction LAN = config correcte) | ✔ v0.1.0 |
| DDNS : `ℹ` Port 22/tcp restreint au réseau local (pas d'ALERTE) | ✔ v0.1.0 |
| Contexte risque CRITIQUE toujours affiché | ✔ v0.1.0 |

> **Nettoyage :** `sudo ufw delete allow from 192.168.1.0/24 to any port 22 proto tcp && sudo ufw allow 22/tcp`

---



### E1 — Port écoutant sur localhost uniquement, sans règle UFW — INFO pas ALERTE

```bash
# Tout processus lié exclusivement à 127.0.0.1 sans règle UFW
# Redis par défaut : bind 127.0.0.1 — aucune règle UFW nécessaire
sudo bob
```

| Attendu | Résultat |
|----------|----------|
| `ℹ [INFO]` Port 6379/tcp — lié uniquement à localhost — aucune règle UFW requise (couvert par refus par défaut) | ✔ v0.1.0.0 |
| Pas d'ALERTE, pas de déduction de score | ✔ v0.1.0.0 |
| Panorama Redis ✔ | ✔ v0.1.0.0 |
| Message utilise la clé locale `services.exposure.loopback_no_rule` (ajoutée avec le fix `Exposure.LOOPBACK_NO_RULE`) | ✔ v0.1.0.0 |

> **Note :** Le message attendu initialement référençait `ports.uncovered_local`. En pratique, Redis sur loopback sans règle UFW est traité par le chemin services (`Exposure.LOOPBACK_NO_RULE`), pas le chemin ports. La clé `ports.uncovered_local` s'applique aux ports de processus non couverts par le registre de services.
